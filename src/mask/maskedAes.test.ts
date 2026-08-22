import { describe, expect, it } from 'vitest';
import { bytesToHex, encryptBlock, expandKey, hexToBytes, round1Probes, SBOX } from '../aes/aes';
import { BLOCK_VECTORS } from '../aes/vectors';
import { Rng } from '../leakage/rng';
import {
  drawRoundMasks,
  encryptMasked,
  type MaskSource,
  maskedRound,
  maskedRound1Probes,
  recomputeSboxTable,
  remaskDelta,
} from './maskedAes';

describe('the recomputed masked S-box table', () => {
  it("satisfies S'[x ^ mIn] === SBOX[x] ^ mOut for every x, exhaustively", () => {
    // The defining property of table recomputation. Checked over a spread of
    // mask pairs across all 256 inputs each, so a table built with the XOR on
    // the wrong side cannot survive.
    for (const mIn of [0x00, 0x01, 0x5c, 0xa7, 0xff]) {
      for (const mOut of [0x00, 0x03, 0x7e, 0xf0, 0xff]) {
        const t = recomputeSboxTable(mIn, mOut);
        for (let x = 0; x < 256; x++) {
          expect(t[(x ^ mIn) & 0xff]).toBe(SBOX[x] ^ mOut);
        }
      }
    }
  });

  it('is still a permutation — masking must not collapse the S-box', () => {
    for (const [mIn, mOut] of [
      [0x00, 0x00],
      [0x9c, 0x41],
    ] as const) {
      expect(new Set(recomputeSboxTable(mIn, mOut)).size).toBe(256);
    }
  });

  it('with zero masks it is exactly the plain S-box', () => {
    expect(Array.from(recomputeSboxTable(0, 0))).toEqual(Array.from(SBOX));
  });
});

describe('re-masking never unmasks', () => {
  it('remaskDelta is a function of mask material only', () => {
    // The delta depends on the two MASKS and on nothing else, so XORing it into
    // the masked state can never produce the unmasked value for any state.
    for (let cur = 0; cur < 256; cur++) {
      for (const mIn of [0x00, 0x3c, 0xff]) {
        expect(remaskDelta(cur, mIn)).toBe(cur ^ mIn);
      }
    }
  });

  it('moves a masked byte onto the new mask without exposing the value', () => {
    for (let x = 0; x < 256; x += 7) {
      for (const cur of [0x11, 0x8e]) {
        for (const mIn of [0x00, 0x5a]) {
          const masked = x ^ cur;
          const moved = masked ^ remaskDelta(cur, mIn);
          expect(moved).toBe(x ^ mIn);
          // And the intermediate value it passed through is never x itself,
          // unless the new mask is genuinely zero — which is the degenerate
          // case the frozen-mask act is about.
          if (mIn !== 0) expect(moved).not.toBe(x);
        }
      }
    }
  });
});

describe('masked AES-128 is still AES-128 (KAT)', () => {
  for (const v of BLOCK_VECTORS) {
    it(`${v.name}: masked ciphertext equals the published ciphertext, over 64 mask draws`, () => {
      const pt = hexToBytes(v.plaintext);
      const key = hexToBytes(v.key);
      for (let seed = 1; seed <= 64; seed++) {
        const r = encryptMasked(pt, key, new Rng(seed));
        expect(bytesToHex(r.ciphertext)).toBe(v.ciphertext);
      }
    });
  }

  it('agrees with the unmasked implementation on 200 random blocks', () => {
    const rng = new Rng(20260822);
    for (let t = 0; t < 200; t++) {
      const pt = Uint8Array.from({ length: 16 }, () => rng.byte());
      const key = Uint8Array.from({ length: 16 }, () => rng.byte());
      const masked = encryptMasked(pt, key, rng);
      expect(bytesToHex(masked.ciphertext)).toBe(bytesToHex(encryptBlock(pt, key)));
    }
  });

  it('a FROZEN mask still produces the correct ciphertext, for every constant', () => {
    // The lesson of act 4: broken randomness collapses the protection while the
    // countermeasure remains intact on paper. Correctness is not the tell.
    const v = BLOCK_VECTORS[0];
    const pt = hexToBytes(v.plaintext);
    const key = hexToBytes(v.key);
    for (let c = 0; c < 256; c++) {
      const r = encryptMasked(pt, key, new Rng(1), { kind: 'frozen', constant: c });
      expect(bytesToHex(r.ciphertext)).toBe(v.ciphertext);
    }
  });

  it('the masked state before unmasking is NOT the ciphertext unless the mask is zero', () => {
    const v = BLOCK_VECTORS[1];
    const r = encryptMasked(hexToBytes(v.plaintext), hexToBytes(v.key), new Rng(7));
    expect(bytesToHex(r.maskedStateBeforeUnmask)).not.toBe(v.ciphertext);
    expect(
      bytesToHex(Uint8Array.from(r.maskedStateBeforeUnmask, (b, i) => b ^ r.finalMask[i]))
    ).toBe(v.ciphertext);
  });

  it('rejects malformed inputs fail-closed', () => {
    const key = hexToBytes(BLOCK_VECTORS[0].key);
    expect(() => encryptMasked(new Uint8Array(15), key, new Rng(1))).toThrow(/16 bytes/);
    expect(() => encryptMasked(new Uint8Array(16), new Uint8Array(17), new Rng(1))).toThrow(
      /16-byte key/
    );
  });
});

describe('the round-1 probes match the real cipher', () => {
  const v = BLOCK_VECTORS[0];
  const pt = hexToBytes(v.plaintext);
  const key = hexToBytes(v.key);
  const rk = expandKey(key);

  it('unmasking the probes recovers the plain AES intermediates', () => {
    // The bench measures masked registers. Unmask them and they must be exactly
    // the values the unmasked cipher computes — which is what makes the masked
    // trace a trace OF AES rather than of an unrelated random walk.
    const plain = round1Probes(pt, rk[0]);
    for (let seed = 1; seed <= 32; seed++) {
      const p = encryptMasked(pt, key, new Rng(seed)).round1;
      for (let j = 0; j < 16; j++) {
        expect(p.sboxInMasked[j] ^ p.maskIn).toBe(plain.sboxIn[j]);
        expect(p.sboxOutMasked[j] ^ p.maskOut).toBe(plain.sboxOut[j]);
      }
    }
  });

  it('the round-1-only path produces the SAME probes as the full encryption', () => {
    // There is one masked round in the source; this proves the streaming bench
    // and the full cipher really are calling it identically, so a fast bench
    // can never drift into measuring a different computation.
    for (let seed = 1; seed <= 32; seed++) {
      const full = encryptMasked(pt, key, new Rng(seed)).round1;
      const fast = maskedRound1Probes(pt, rk[0], rk[1], new Rng(seed), { kind: 'fresh' });
      expect(fast.maskIn).toBe(full.maskIn);
      expect(fast.maskOut).toBe(full.maskOut);
      expect(Array.from(fast.sboxOutMasked)).toEqual(Array.from(full.sboxOutMasked));
      expect(Array.from(fast.sboxInMasked)).toEqual(Array.from(full.sboxInMasked));
    }
  });

  it('with a frozen mask, the masked probe is a deterministic function of the secret', () => {
    // The whole failure in one assertion: no fresh randomness left, so the same
    // plaintext byte always produces the same masked register value.
    const source: MaskSource = { kind: 'frozen', constant: 0x01 };
    const a = maskedRound1Probes(pt, rk[0], rk[1], new Rng(11), source);
    const b = maskedRound1Probes(pt, rk[0], rk[1], new Rng(99), source);
    expect(Array.from(a.sboxOutMasked)).toEqual(Array.from(b.sboxOutMasked));
    expect(a.maskOut).toBe(0x01);
    const plain = round1Probes(pt, rk[0]);
    for (let j = 0; j < 16; j++) expect(a.sboxOutMasked[j]).toBe(plain.sboxOut[j] ^ 0x01);
  });

  it('with a fresh mask it is NOT deterministic', () => {
    const a = maskedRound1Probes(pt, rk[0], rk[1], new Rng(11), { kind: 'fresh' });
    const b = maskedRound1Probes(pt, rk[0], rk[1], new Rng(99), { kind: 'fresh' });
    expect(Array.from(a.sboxOutMasked)).not.toEqual(Array.from(b.sboxOutMasked));
  });
});

describe('mask sourcing', () => {
  it('fresh masks vary and frozen masks do not', () => {
    const rng = new Rng(3);
    const fresh = Array.from({ length: 20 }, () => drawRoundMasks({ kind: 'fresh' }, rng));
    expect(new Set(fresh.map((m) => `${m.mIn}:${m.mOut}`)).size).toBeGreaterThan(1);
    const frozen = Array.from({ length: 20 }, () =>
      drawRoundMasks({ kind: 'frozen', constant: 0x0f }, rng)
    );
    expect(new Set(frozen.map((m) => `${m.mIn}:${m.mOut}`))).toEqual(new Set(['15:15']));
  });

  it('maskedRound with zero masks reduces to a plain AES round', () => {
    // A degenerate but useful oracle: masking with (0, 0) must be the identity
    // on top of the ordinary round, so the masked path and the plain path are
    // provably the same computation.
    const key = hexToBytes(BLOCK_VECTORS[1].key);
    const rk = expandKey(key);
    const pt = hexToBytes(BLOCK_VECTORS[1].plaintext);
    const state = pt.slice();
    const mask = new Uint8Array(16);
    for (let i = 0; i < 16; i++) state[i] ^= rk[0][i];
    const probes = maskedRound(state, mask, rk[1], { mIn: 0, mOut: 0 }, false);
    const plain = round1Probes(pt, rk[0]);
    expect(Array.from(probes.sboxOutMasked)).toEqual(Array.from(plain.sboxOut));
  });
});
