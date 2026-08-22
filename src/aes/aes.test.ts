import { describe, expect, it } from 'vitest';
import {
  addRoundKey,
  bytesToHex,
  deriveSbox,
  encryptBlock,
  expandKey,
  ginv,
  gmul,
  hexToBytes,
  INV_SBOX,
  mixColumns,
  round1Probes,
  SBOX,
  shiftRows,
  subBytes,
} from './aes';
import {
  BLOCK_VECTORS,
  FIPS197_SBOX_HEX,
  KEY_SCHEDULE_VECTOR,
  ROUND1_INTERMEDIATES,
} from './vectors';

describe('GF(2^8) arithmetic', () => {
  it('multiplies per the AES polynomial', () => {
    // FIPS-197 4.2 worked example: {57} * {83} = {c1}.
    expect(gmul(0x57, 0x83)).toBe(0xc1);
    // 4.2.1: xtime chain 57 -> ae -> 47 -> 8e (each is a reduction step).
    expect(gmul(0x57, 0x02)).toBe(0xae);
    expect(gmul(0xae, 0x02)).toBe(0x47);
    expect(gmul(0x47, 0x02)).toBe(0x8e);
  });

  it('inverts every non-zero element, and fixes zero', () => {
    expect(ginv(0)).toBe(0);
    for (let a = 1; a < 256; a++) expect(gmul(a, ginv(a))).toBe(1);
  });
});

describe('S-box (KAT: FIPS-197 Figure 7)', () => {
  it('the derivation reproduces the published table byte for byte', () => {
    expect(bytesToHex(deriveSbox())).toBe(FIPS197_SBOX_HEX);
  });

  it('is a permutation, and INV_SBOX inverts it', () => {
    expect(new Set(SBOX).size).toBe(256);
    for (let a = 0; a < 256; a++) expect(INV_SBOX[SBOX[a]]).toBe(a);
  });

  it('is NOT linear — which is the whole reason masking needs a recomputed table', () => {
    // If S were GF(2)-linear, S(a ^ b) would equal S(a) ^ S(b) ^ S(0) for all a, b.
    // Find a counterexample rather than asserting the property in prose.
    let counterexamples = 0;
    for (let a = 0; a < 256; a++) {
      for (let b = 0; b < 256; b++) {
        if (SBOX[a ^ b] !== (SBOX[a] ^ SBOX[b] ^ SBOX[0])) counterexamples++;
      }
    }
    expect(counterexamples).toBeGreaterThan(0);
  });
});

describe('key expansion (KAT: FIPS-197 A.1)', () => {
  it('matches the published round keys 1 and 10', () => {
    const rk = expandKey(hexToBytes(KEY_SCHEDULE_VECTOR.key));
    expect(rk).toHaveLength(11);
    expect(bytesToHex(rk[0])).toBe(KEY_SCHEDULE_VECTOR.key);
    expect(bytesToHex(rk[1])).toBe(KEY_SCHEDULE_VECTOR.round1);
    expect(bytesToHex(rk[10])).toBe(KEY_SCHEDULE_VECTOR.round10);
  });

  it('rejects a key that is not 16 bytes', () => {
    expect(() => expandKey(new Uint8Array(15))).toThrow(/16-byte key/);
  });
});

describe('block encryption (KAT: FIPS-197 + SP 800-38A)', () => {
  for (const v of BLOCK_VECTORS) {
    it(`${v.name} — ${v.source}`, () => {
      const ct = encryptBlock(hexToBytes(v.plaintext), hexToBytes(v.key));
      expect(bytesToHex(ct)).toBe(v.ciphertext);
    });
  }

  it('rejects a block that is not 16 bytes', () => {
    expect(() => encryptBlock(new Uint8Array(8), hexToBytes(BLOCK_VECTORS[0].key))).toThrow(
      /16 bytes/
    );
  });
});

describe('round-1 intermediates (KAT: FIPS-197 Appendix B trace)', () => {
  const key = hexToBytes(ROUND1_INTERMEDIATES.key);
  const pt = hexToBytes(ROUND1_INTERMEDIATES.plaintext);
  const rk = expandKey(key);

  it('walks the published round-1 trace step by step', () => {
    const state = pt.slice();
    addRoundKey(state, rk[0]);
    expect(bytesToHex(state)).toBe(ROUND1_INTERMEDIATES.afterAddRoundKey0);
    subBytes(state);
    expect(bytesToHex(state)).toBe(ROUND1_INTERMEDIATES.afterSubBytes);
    shiftRows(state);
    expect(bytesToHex(state)).toBe(ROUND1_INTERMEDIATES.afterShiftRows);
    mixColumns(state);
    expect(bytesToHex(state)).toBe(ROUND1_INTERMEDIATES.afterMixColumns);
    addRoundKey(state, rk[1]);
    expect(bytesToHex(state)).toBe(ROUND1_INTERMEDIATES.afterAddRoundKey1);
  });

  it('the leakage probes ARE those published intermediates', () => {
    // This is what makes a simulated trace honest: the probe values are not
    // re-derived by the trace generator, they come from the cipher, and the
    // cipher's own round-1 trace is published.
    const p = round1Probes(pt, rk[0]);
    expect(bytesToHex(p.sboxIn)).toBe(ROUND1_INTERMEDIATES.afterAddRoundKey0);
    expect(bytesToHex(p.sboxOut)).toBe(ROUND1_INTERMEDIATES.afterSubBytes);
  });
});

describe('linear layers', () => {
  it('ShiftRows is a permutation of the 16 byte positions', () => {
    const s = Uint8Array.from({ length: 16 }, (_, i) => i);
    shiftRows(s);
    expect(new Set(s).size).toBe(16);
    // Column-major AES: row 0 unmoved, row 1 left by one, row 2 by two, row 3 by three.
    expect(Array.from(s)).toEqual([0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]);
  });

  it('MixColumns is GF(2)-linear: MC(x ^ m) === MC(x) ^ MC(m)', () => {
    // Masking's entire free ride through the linear layers rests on this, so it
    // is measured over pseudo-random inputs rather than asserted in a comment.
    let seed = 0x9e3779b9;
    const nextByte = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return (seed >>> 16) & 0xff;
    };
    for (let trial = 0; trial < 200; trial++) {
      const x = Uint8Array.from({ length: 16 }, nextByte);
      const m = Uint8Array.from({ length: 16 }, nextByte);
      const xm = Uint8Array.from(x, (v, i) => v ^ m[i]);
      const a = x.slice();
      const b = m.slice();
      mixColumns(a);
      mixColumns(b);
      mixColumns(xm);
      expect(Array.from(xm)).toEqual(Array.from(a, (v, i) => v ^ b[i]));
    }
  });

  it('ShiftRows commutes with masking too', () => {
    const x = Uint8Array.from({ length: 16 }, (_, i) => (i * 37 + 11) & 0xff);
    const m = Uint8Array.from({ length: 16 }, (_, i) => (i * 91 + 5) & 0xff);
    const xm = Uint8Array.from(x, (v, i) => v ^ m[i]);
    shiftRows(x);
    shiftRows(m);
    shiftRows(xm);
    expect(Array.from(xm)).toEqual(Array.from(x, (v, i) => v ^ m[i]));
  });
});

describe('hex helpers', () => {
  it('round-trips', () => {
    const b = hexToBytes('00ff10a5');
    expect(Array.from(b)).toEqual([0, 255, 16, 165]);
    expect(bytesToHex(b)).toBe('00ff10a5');
  });

  it('rejects malformed hex fail-closed', () => {
    expect(() => hexToBytes('abc')).toThrow(/not hex/);
    expect(() => hexToBytes('zz')).toThrow(/not hex/);
  });
});
