import { describe, expect, it } from 'vitest';
import { hexToBytes } from '../aes/aes';
import { defaultBench, forEachTrace, NUM_SAMPLES, sboxOutSample } from '../leakage/traces';
import { bitDpaDifference } from '../mask/combining';
import { BitDpaAtSample, BitDpaSampleScan } from './dpa';
import { rankOf } from './stats';

const KEY = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c');
const TRUE = KEY[0];
const S = sboxOutSample(0);

/**
 * How far the measured difference may sit from the exact +-1.
 *
 * Calibrated, not guessed. With sigma = 6 model units and 16,000 traces split
 * roughly evenly, the standard error of a difference of two group means is
 * about 6 * sqrt(4 / 16000) = 0.095, so 0.4 is a little over four standard
 * errors — tight enough that a broken partition (which lands near 0) fails, and
 * loose enough that no seed produces a false red. Measured across four
 * independent seeds the bit-3 estimate ranged 0.75 to 0.96 against a true 1.0,
 * which is what set this number.
 */
const TOLERANCE = 0.4;

function run(over: Parameters<typeof defaultBench>[1], n: number, bit = 0): BitDpaAtSample {
  const d = new BitDpaAtSample(S, bit);
  forEachTrace(defaultBench(KEY, over), n, (p, s) => d.add(p, s));
  return d;
}

describe('single-bit DPA against a frozen mask', () => {
  it('recovers the key for every constant, with the SIGN the identity predicts', () => {
    // `bitDpaDifference` is checked exhaustively and noise-free in
    // ../mask/combining.test.ts; here it is the prediction the noisy bench has
    // to match. The sign is the interesting half — it is bit 0 of the frozen
    // constant, showing up in a measurement.
    for (const c of [0x00, 0x01, 0x0f, 0x55, 0xfe, 0xff]) {
      const d = run({ protection: 'frozen', frozenConstant: c }, 16000);
      expect(rankOf(d.scores(), TRUE), `constant 0x${c.toString(16)}`).toBe(1);
      expect(Math.sign(d.difference(TRUE))).toBe(bitDpaDifference(c, 0));
      expect(Math.abs(d.difference(TRUE) - bitDpaDifference(c, 0))).toBeLessThan(TOLERANCE);
    }
  }, 300_000);

  it('works on all eight bits, each with its own predicted sign', () => {
    // c = 0x0f sets bits 0-3 and clears 4-7, so the difference must be negative
    // on the low nibble and positive on the high one. A single sign flip in the
    // wrong place would mean the partition is not tracking the bit it claims to.
    for (let bit = 0; bit < 8; bit++) {
      const d = run({ protection: 'frozen', frozenConstant: 0x0f }, 16000, bit);
      expect(rankOf(d.scores(), TRUE), `bit ${bit}`).toBe(1);
      expect(Math.sign(d.difference(TRUE)), `bit ${bit}`).toBe(bitDpaDifference(0x0f, bit));
      expect(Math.abs(d.difference(TRUE) - bitDpaDifference(0x0f, bit)), `bit ${bit}`).toBeLessThan(
        TOLERANCE
      );
    }
  }, 300_000);
});

describe('single-bit DPA against a fresh mask', () => {
  it('collapses — both groups have the same mean once the mask is random', () => {
    const d = run({ protection: 'masked' }, 20000);
    // Well inside the tolerance the frozen case has to CLEAR — the two cases
    // are separated by roughly a full model unit, not by a hair.
    expect(Math.abs(d.difference(TRUE))).toBeLessThan(0.2);
    expect(rankOf(d.scores(), TRUE)).toBeGreaterThan(1);
  }, 120_000);
});

describe('single-bit DPA against unprotected AES', () => {
  it('recovers the key, as Kocher-Jaffe-Jun 1999 did', () => {
    const d = run({ protection: 'none' }, 6000);
    expect(rankOf(d.scores(), TRUE)).toBe(1);
    expect(d.difference(TRUE)).toBeGreaterThan(0.75);
  }, 60_000);
});

describe('shape and guards', () => {
  it('rejects a bit index outside 0..7', () => {
    expect(() => new BitDpaAtSample(S, 8)).toThrow(/bit must be 0\.\.7/);
    expect(() => new BitDpaAtSample(S, -1)).toThrow(/bit must be 0\.\.7/);
  });

  it('reports zero rather than NaN before either group is populated', () => {
    const d = new BitDpaAtSample(S, 0);
    expect(Array.from(d.scores())).toEqual(new Array(256).fill(0));
  });

  it('the sample scan peaks at the S-box output sample, unprotected', () => {
    const scan = new BitDpaSampleScan(NUM_SAMPLES, 0);
    forEachTrace(defaultBench(KEY, { protection: 'none' }), 4000, (p, s) => scan.add(p, s));
    const peaks = scan.peakPerSample();
    let argmax = 0;
    for (let t = 0; t < NUM_SAMPLES; t++) if (peaks[t] > peaks[argmax]) argmax = t;
    expect(argmax).toBe(S);
  }, 60_000);
});
