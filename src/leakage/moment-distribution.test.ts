import { describe, expect, it } from 'vitest';
import { distributionDistance, rawMoment, shareSumDistribution } from './moment-distribution';

describe('four-share population comparison', () => {
  it('matches independently counted binomial coefficients and hand-calculated moments', () => {
    const a = shareSumDistribution(0, 0);
    const b = shareSumDistribution(1, 0);
    expect(a.probabilities).toEqual([1 / 8, 0, 6 / 8, 0, 1 / 8]);
    expect(b.probabilities).toEqual([0, 1 / 2, 0, 1 / 2, 0]);
    expect([1, 2, 3, 4].map(k => rawMoment(a, k))).toEqual([2, 5, 14, 44]);
    expect([1, 2, 3, 4].map(k => rawMoment(b, k))).toEqual([2, 5, 14, 41]);
    expect(distributionDistance(a, b)).toBe(1);
  });
  it('preserves mass and common moments under independent centered noise, with less distinguishability', () => {
    let previous = 1;
    for (let coins = 0; coins <= 8; coins++) {
      const a = shareSumDistribution(0, coins);
      const b = shareSumDistribution(1, coins);
      for (const d of [a, b]) {
        expect(d.probabilities.reduce((sum, p) => sum + p, 0)).toBe(1);
        expect(d.probabilities.every(p => p >= 0)).toBe(true);
        expect(rawMoment(d, 1)).toBe(2);
        expect(rawMoment(d, 2)).toBe(5 + coins / 4);
        expect(rawMoment(d, 3)).toBe(14 + 1.5 * coins);
      }
      expect(rawMoment(a, 4) - rawMoment(b, 4)).toBe(3);
      const distance = distributionDistance(a, b);
      expect(distance).toBeLessThanOrEqual(previous);
      expect(distance).toBeGreaterThan(0);
      expect(distributionDistance(a, a)).toBe(0);
      previous = distance;
    }
  });
  it('rejects parameters outside the declared model', () => {
    for (const s of [-1, 2, NaN]) expect(() => shareSumDistribution(s, 0)).toThrow();
    for (const n of [-1, 9, 0.5, Infinity]) expect(() => shareSumDistribution(0, n)).toThrow();
    expect(() => rawMoment(shareSumDistribution(0, 0), 0)).toThrow();
    expect(() => distributionDistance(shareSumDistribution(0, 0), shareSumDistribution(1, 2))).toThrow();
  });
});
