import { describe, expect, it } from 'vitest';
import { HW, HW_MEAN } from '../leakage/model';
import { SBOX } from '../aes/aes';
import {
  bitDpaDifference,
  centredProduct,
  conditionalMeanByMaskWeight,
  predictedConditionalMean,
  exhaustiveCombinedMean,
  frozenMaskCorrelation,
  predictedCombinedMean,
  shareHistogram,
} from './combining';

/** Pearson r over two equal-length series, written out here so the identity
 *  tests do not lean on the same code the attack uses. */
function refPearson(x: number[], y: number[]): number {
  const n = x.length;
  const mx = x.reduce((a, b) => a + b, 0) / n;
  const my = y.reduce((a, b) => a + b, 0) / n;
  let cov = 0;
  let vx = 0;
  let vy = 0;
  for (let i = 0; i < n; i++) {
    cov += (x[i] - mx) * (y[i] - my);
    vx += (x[i] - mx) ** 2;
    vy += (y[i] - my) ** 2;
  }
  return cov / Math.sqrt(vx * vy);
}

describe('first-order security is exact, not statistical', () => {
  it('every secret value gives the SAME distribution of the masked share', () => {
    // Over all 256 masks, {v ^ m} is the whole byte space for every v. So the
    // masked share's Hamming-weight histogram is the binomial, identically, and
    // one probe cannot distinguish v = 0x00 from v = 0xff.
    const binomial = [1, 8, 28, 56, 70, 56, 28, 8, 1];
    for (let v = 0; v < 256; v++) {
      expect(shareHistogram(v, 'masked')).toEqual(binomial);
      expect(shareHistogram(v, 'mask')).toEqual(binomial);
    }
  });

  it('the mask share is independent of the secret by construction', () => {
    for (let v = 0; v < 256; v++) {
      expect(shareHistogram(v, 'mask')).toEqual(shareHistogram(0, 'mask'));
    }
  });
});

describe('the joint dependence the mechanism panel plots', () => {
  it('E[HW(v ^ m) | HW(m) = k] === HW(v) + k(1 - HW(v)/4), exhaustively', () => {
    for (let v = 0; v < 256; v++) {
      const measured = conditionalMeanByMaskWeight(v);
      for (let k = 0; k <= 8; k++) {
        expect(measured[k]).toBeCloseTo(predictedConditionalMean(v, k), 12);
      }
    }
  });

  it('the slope reads the secret weight off directly, and vanishes at weight 4', () => {
    // The line's slope is 1 - HW(v)/4: +1 for an all-zero secret, -1 for
    // all-ones, and exactly flat for any balanced byte.
    const slope = (v: number): number =>
      conditionalMeanByMaskWeight(v)[8] - conditionalMeanByMaskWeight(v)[0];
    expect(slope(0x00) / 8).toBeCloseTo(1, 12);
    expect(slope(0xff) / 8).toBeCloseTo(-1, 12);
    expect(slope(0x0f) / 8).toBeCloseTo(0, 12);
    expect(slope(0x01) / 8).toBeCloseTo(0.75, 12);
  });

  it('but each MARGINAL is the same binomial for those same secrets', () => {
    // Side by side, this is the whole first-order story: the marginals cannot
    // tell 0x00 from 0xff, and the joint distribution can.
    for (const v of [0x00, 0x01, 0x0f, 0xff]) {
      expect(shareHistogram(v, 'masked')).toEqual(shareHistogram(0x5a, 'masked'));
    }
  });
});

describe('the second-order identity (exhaustive over all 256 masks)', () => {
  it('E[(HW(m) - 4)(HW(v ^ m) - 4)] === -(1/2)(HW(v) - 4) for every v', () => {
    for (let v = 0; v < 256; v++) {
      expect(exhaustiveCombinedMean(v)).toBeCloseTo(predictedCombinedMean(v), 12);
    }
  });

  it('re-derives the same value a second way — by summing per-bit terms', () => {
    // Independent route: the per-bit derivation says each bit contributes
    // (1/4 - v_i/2). Summing that must reproduce the whole-byte expectation.
    for (let v = 0; v < 256; v++) {
      let perBit = 0;
      for (let i = 0; i < 8; i++) perBit += 0.25 - ((v >> i) & 1) / 2;
      expect(perBit).toBeCloseTo(exhaustiveCombinedMean(v), 12);
    }
  });

  it('is a straight line in HW(v) with slope exactly -1/2', () => {
    const hw: number[] = [];
    const mean: number[] = [];
    for (let v = 0; v < 256; v++) {
      hw.push(HW[v]);
      mean.push(exhaustiveCombinedMean(v));
    }
    expect(refPearson(hw, mean)).toBeCloseTo(-1, 12);
    // slope = cov / var
    const mh = hw.reduce((a, b) => a + b, 0) / 256;
    const mm = mean.reduce((a, b) => a + b, 0) / 256;
    let cov = 0;
    let varh = 0;
    for (let i = 0; i < 256; i++) {
      cov += (hw[i] - mh) * (mean[i] - mm);
      varh += (hw[i] - mh) ** 2;
    }
    expect(cov / varh).toBeCloseTo(-0.5, 12);
  });

  it('centredProduct is what the identity averages', () => {
    for (const v of [0x00, 0x5c, 0xff]) {
      let sum = 0;
      for (let m = 0; m < 256; m++) {
        sum += centredProduct(HW[m], HW[(v ^ m) & 0xff], HW_MEAN, HW_MEAN);
      }
      expect(sum / 256).toBeCloseTo(predictedCombinedMean(v), 12);
    }
  });
});

describe('the bit-level difference-of-means identity', () => {
  it('is exactly +-1 for every constant and every bit, exhaustively', () => {
    // No sampling anywhere: for a fixed key byte, sweep all 256 plaintext bytes,
    // partition on the predicted bit, and take the exact difference of the two
    // group means. It must be the constant's bit, and nothing else.
    const key = 0x2b;
    for (let c = 0; c < 256; c++) {
      for (let bit = 0; bit < 8; bit++) {
        let s1 = 0;
        let n1 = 0;
        let s0 = 0;
        let n0 = 0;
        for (let pt = 0; pt < 256; pt++) {
          const v = SBOX[pt ^ key];
          const leak = HW[v ^ c];
          if ((v >> bit) & 1) {
            s1 += leak;
            n1++;
          } else {
            s0 += leak;
            n0++;
          }
        }
        expect(s1 / n1 - s0 / n0).toBeCloseTo(bitDpaDifference(c, bit), 12);
      }
    }
  });

  it('never goes to zero — unlike the Hamming-weight correlation', () => {
    // The whole reason this is the frozen-mask act's primary distinguisher.
    for (let c = 0; c < 256; c++) {
      for (let bit = 0; bit < 8; bit++) expect(Math.abs(bitDpaDifference(c, bit))).toBe(1);
    }
    // Whereas the HW correlation vanishes for all 70 balanced constants.
    let vanishing = 0;
    for (let c = 0; c < 256; c++) if (frozenMaskCorrelation(c) === 0) vanishing++;
    expect(vanishing).toBe(70);
  });
});

describe('the frozen-mask correlation identity', () => {
  it('rho(HW(v ^ c), HW(v)) === 1 - HW(c)/4 for every constant c', () => {
    const vs = Array.from({ length: 256 }, (_, v) => v);
    for (let c = 0; c < 256; c++) {
      const measured = refPearson(
        vs.map((v) => HW[(v ^ c) & 0xff]),
        vs.map((v) => HW[v])
      );
      expect(measured).toBeCloseTo(frozenMaskCorrelation(c), 12);
    }
  });

  it('a BALANCED constant drives the Hamming-weight correlation to exactly zero', () => {
    // The trap the frozen-mask act exists to show: protection entirely gone,
    // and a Hamming-weight CPA sees nothing at all.
    for (let c = 0; c < 256; c++) {
      if (HW[c] === 4) expect(frozenMaskCorrelation(c)).toBe(0);
    }
    expect(frozenMaskCorrelation(0x0f)).toBe(0);
    expect(frozenMaskCorrelation(0x55)).toBe(0);
  });

  it('a low-weight constant leaves it nearly intact, a high-weight one inverts it', () => {
    expect(frozenMaskCorrelation(0x00)).toBe(1);
    expect(frozenMaskCorrelation(0x01)).toBe(0.75);
    expect(frozenMaskCorrelation(0x03)).toBe(0.5);
    expect(frozenMaskCorrelation(0xfe)).toBe(-0.75);
    expect(frozenMaskCorrelation(0xff)).toBe(-1);
  });
});
