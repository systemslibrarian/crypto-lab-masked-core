import { describe, expect, it } from 'vitest';
import { bestExcluding, pearson, pearsonFromSums, rankingOf, rankOf } from './stats';

describe('pearson', () => {
  it('is 1 for a perfectly increasing relation and -1 for a decreasing one', () => {
    expect(pearson([1, 2, 3, 4], [2, 4, 6, 8])).toBeCloseTo(1, 12);
    expect(pearson([1, 2, 3, 4], [8, 6, 4, 2])).toBeCloseTo(-1, 12);
  });

  it('is 0 without variance, and 0 for mismatched lengths', () => {
    expect(pearson([1, 1, 1], [1, 2, 3])).toBe(0);
    expect(pearson([1, 2, 3], [1, 2])).toBe(0);
    expect(pearson([], [])).toBe(0);
  });

  it('matches a textbook worked value', () => {
    // cov/sd*sd computed by hand for this small set.
    const x = [43, 21, 25, 42, 57, 59];
    const y = [99, 65, 79, 75, 87, 81];
    expect(pearson(x, y)).toBeCloseTo(0.5298, 4);
  });
});

describe('pearsonFromSums agrees with the two-pass form', () => {
  it('over pseudo-random series of many lengths', () => {
    let seed = 12345;
    const rand = (): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    for (const n of [2, 3, 17, 100, 999]) {
      const x: number[] = [];
      const y: number[] = [];
      let sx = 0;
      let sy = 0;
      let sxx = 0;
      let syy = 0;
      let sxy = 0;
      for (let i = 0; i < n; i++) {
        const xi = rand() * 10;
        const yi = rand() * 3 + xi * 0.4;
        x.push(xi);
        y.push(yi);
        sx += xi;
        sy += yi;
        sxx += xi * xi;
        syy += yi * yi;
        sxy += xi * yi;
      }
      expect(pearsonFromSums(n, sx, sy, sxx, syy, sxy)).toBeCloseTo(pearson(x, y), 9);
    }
  });

  it('returns 0 rather than NaN when a series is constant', () => {
    expect(pearsonFromSums(5, 5, 15, 5, 55, 15)).toBe(0);
    expect(pearsonFromSums(1, 1, 1, 1, 1, 1)).toBe(0);
  });
});

describe('ranking helpers', () => {
  const scores = Float64Array.from([0.1, 0.9, 0.5, 0.9]);

  it('sorts descending', () => {
    expect(rankingOf(scores)[0]).toBe(1);
    expect(rankingOf(scores).at(-1)).toBe(0);
  });

  it('gives rank 1 only when nothing scores strictly higher', () => {
    expect(rankOf(scores, 1)).toBe(1);
    expect(rankOf(scores, 3)).toBe(1); // a tie at the top is still rank 1
    expect(rankOf(scores, 2)).toBe(3);
    expect(rankOf(scores, 0)).toBe(4);
  });

  it('bestExcluding skips the named guess', () => {
    expect(bestExcluding(scores, 1)).toBeCloseTo(0.9, 12);
    expect(bestExcluding(scores, 0)).toBeCloseTo(0.9, 12);
    expect(bestExcluding(Float64Array.from([0.4]), 0)).toBe(-Infinity);
  });
});
