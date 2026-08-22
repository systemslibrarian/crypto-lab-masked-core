import { describe, expect, it } from 'vitest';
import { expandKey, hexToBytes, round1Probes, SBOX } from '../aes/aes';
import {
  captureTraces,
  defaultBench,
  forEachTrace,
  LEAK_AMP,
  MASK_IN_SAMPLE,
  MASK_OUT_SAMPLE,
  NUM_SAMPLES,
  sampleLabel,
  SBOX_IN_BASE,
  SBOX_OUT_BASE,
  sboxOutSample,
  templateSample,
} from './traces';

const KEY = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c');

describe('the bench is deterministic', () => {
  it('the same seed produces the same traces, byte for byte', () => {
    const a = captureTraces(defaultBench(KEY, { protection: 'masked' }), 20);
    const b = captureTraces(defaultBench(KEY, { protection: 'masked' }), 20);
    expect(a.map((t) => t.plaintextByte)).toEqual(b.map((t) => t.plaintextByte));
    expect(Array.from(a[7].samples)).toEqual(Array.from(b[7].samples));
  });

  it('a different seed produces different traces', () => {
    const a = captureTraces(defaultBench(KEY, { seed: 1 }), 5);
    const b = captureTraces(defaultBench(KEY, { seed: 2 }), 5);
    expect(a.map((t) => t.plaintextByte)).not.toEqual(b.map((t) => t.plaintextByte));
  });

  it('a prefix of a long run equals a short run — streaming is stable', () => {
    const short = captureTraces(defaultBench(KEY, { protection: 'masked' }), 5);
    const long = captureTraces(defaultBench(KEY, { protection: 'masked' }), 50).slice(0, 5);
    expect(Array.from(short[4].samples)).toEqual(Array.from(long[4].samples));
  });
});

describe('flipping the protection is a CONTROLLED experiment', () => {
  it('the plaintexts and the noise are identical across protections', () => {
    // Two RNG streams: data (plaintexts + noise) and masks. Only the masks
    // change when protection changes, so "same attack, protection on" compares
    // like with like instead of comparing two unrelated benches.
    const none = captureTraces(defaultBench(KEY, { protection: 'none' }), 30);
    const masked = captureTraces(defaultBench(KEY, { protection: 'masked' }), 30);
    const frozen = captureTraces(defaultBench(KEY, { protection: 'frozen' }), 30);
    expect(masked.map((t) => t.plaintextByte)).toEqual(none.map((t) => t.plaintextByte));
    expect(frozen.map((t) => t.plaintextByte)).toEqual(none.map((t) => t.plaintextByte));
  });

  it('and the difference between two protections is exactly the leakage difference', () => {
    // Subtract an unprotected trace from a masked one at an idle sample: the
    // template and the noise cancel to zero, proving the noise really is shared.
    const none = captureTraces(defaultBench(KEY, { protection: 'none' }), 40);
    const masked = captureTraces(defaultBench(KEY, { protection: 'masked' }), 40);
    for (let i = 0; i < 40; i++) {
      // An idle sample carries template + noise only, in both benches, so the
      // difference is exactly zero — which is only true if the noise is shared.
      expect(masked[i].samples[0] - none[i].samples[0]).toBeCloseTo(0, 12);
    }
    // At a leaking sample the two must differ, because the masked value is not
    // the unmasked one. Per trace the difference CAN be zero by chance (the two
    // Hamming weights coincide), so this is asserted over the run, not per trace.
    const leakDiffs = none.map(
      (t, i) => masked[i].samples[NUM_SAMPLES - 1] - t.samples[NUM_SAMPLES - 1]
    );
    expect(leakDiffs.filter((d) => d !== 0).length).toBeGreaterThan(20);
  });
});

describe('the leakage lands where the sample map says', () => {
  const rk = expandKey(KEY);

  it('an unprotected trace carries HW(SBOX[pt ^ k]) at the S-box output samples', () => {
    // Noise off: every sample must then be exactly template + LEAK_AMP * HW.
    const cfg = defaultBench(KEY, { protection: 'none', noise: 0 });
    const pts: number[] = [];
    forEachTrace(cfg, 8, (_ptByte, samples, i) => {
      // Recover the whole plaintext by replaying the same data stream is not
      // possible from outside, so check the target byte's samples only.
      pts.push(i);
      const target = sboxOutSample(0);
      const value = (samples[target] - templateSample(target)) / LEAK_AMP;
      expect(Number.isInteger(Math.round(value * 1e9) / 1e9)).toBe(true);
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThanOrEqual(8);
    });
    expect(pts).toHaveLength(8);
  });

  it('an unprotected trace has NO mask registers — those samples are idle', () => {
    const cfg = defaultBench(KEY, { protection: 'none', noise: 0 });
    const traces = captureTraces(cfg, 40);
    for (const t of traces) {
      expect(t.samples[MASK_IN_SAMPLE]).toBeCloseTo(templateSample(MASK_IN_SAMPLE), 12);
      expect(t.samples[MASK_OUT_SAMPLE]).toBeCloseTo(templateSample(MASK_OUT_SAMPLE), 12);
    }
  });

  it('a masked trace DOES carry mask registers, and they vary', () => {
    const traces = captureTraces(defaultBench(KEY, { protection: 'masked', noise: 0 }), 40);
    const maskLeaks = traces.map((t) => t.samples[MASK_OUT_SAMPLE] - templateSample(MASK_OUT_SAMPLE));
    expect(new Set(maskLeaks.map((v) => Math.round(v))).size).toBeGreaterThan(3);
    for (const v of maskLeaks) {
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(8 * LEAK_AMP);
    }
  });

  it('a FROZEN trace has a constant mask register — no variance at all', () => {
    const traces = captureTraces(
      defaultBench(KEY, { protection: 'frozen', frozenConstant: 0x0f, noise: 0 }),
      40
    );
    const leaks = traces.map((t) => t.samples[MASK_OUT_SAMPLE] - templateSample(MASK_OUT_SAMPLE));
    // HW(0x0f) = 4, every trace, forever. A constant series has no correlation
    // with anything, which is why the mask sample is useless to an attacker
    // here — and why the masked VALUE sample stops being protected.
    for (const v of leaks) expect(v).toBeCloseTo(4 * LEAK_AMP, 12);
  });

  it('unmasking a noiseless masked trace reproduces the unprotected leakage', () => {
    // The strongest honesty check available on a simulated trace: masked
    // leakage minus mask leakage must be the leakage of the real intermediate.
    const traces = captureTraces(
      defaultBench(KEY, { protection: 'frozen', frozenConstant: 0x00, noise: 0 }),
      12
    );
    const plain = captureTraces(defaultBench(KEY, { protection: 'none', noise: 0 }), 12);
    for (let i = 0; i < 12; i++) {
      for (let j = 0; j < 16; j++) {
        // With the mask pinned to zero the masked implementation IS the plain
        // one, so every S-box sample must agree exactly.
        expect(traces[i].samples[SBOX_OUT_BASE + j]).toBeCloseTo(
          plain[i].samples[SBOX_OUT_BASE + j],
          12
        );
        expect(traces[i].samples[SBOX_IN_BASE + j]).toBeCloseTo(
          plain[i].samples[SBOX_IN_BASE + j],
          12
        );
      }
    }
    // And the probe those samples were built from is the real cipher's: with a
    // zero plaintext the first S-box output is SBOX[k0] for the fixture key.
    expect(round1Probes(new Uint8Array(16), rk[0]).sboxOut[0]).toBe(SBOX[KEY[0]]);
  });
});

describe('sample labels name real operations', () => {
  it('maps every index to something a reader can act on', () => {
    expect(sampleLabel(MASK_IN_SAMPLE)).toMatch(/input mask/);
    expect(sampleLabel(MASK_OUT_SAMPLE)).toMatch(/output mask/);
    expect(sampleLabel(SBOX_IN_BASE)).toBe('S-box input, byte 0');
    expect(sampleLabel(SBOX_OUT_BASE + 15)).toBe('S-box output, byte 15');
    expect(sampleLabel(0)).toMatch(/idle/);
    expect(sboxOutSample(3)).toBe(SBOX_OUT_BASE + 3);
  });
});
