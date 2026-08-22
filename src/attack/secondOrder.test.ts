import { describe, expect, it } from 'vitest';
import { hexToBytes, SBOX } from '../aes/aes';
import { HW } from '../leakage/model';
import {
  captureTraces,
  defaultBench,
  forEachTrace,
  MASK_IN_SAMPLE,
  MASK_OUT_SAMPLE,
  SBOX_IN_BASE,
  sboxOutSample,
} from '../leakage/traces';
import { conditioningOffset, SecondOrderCpa } from './secondOrder';
import { pearson, rankOf } from './stats';

const KEY = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c');
const TRUE = KEY[0];
const S = sboxOutSample(0);

/** The attack written the slow, obvious way: centre both samples on the means
 *  of the traces in hand, multiply, then correlate. Two passes, no algebra. */
function directSecondOrder(
  traces: { plaintextByte: number; samples: Float64Array }[],
  a: number,
  b: number,
  guess: number
): number {
  const ua = traces.map((t) => t.samples[a]);
  const ub = traces.map((t) => t.samples[b]);
  const ma = ua.reduce((x, y) => x + y, 0) / ua.length;
  const mb = ub.reduce((x, y) => x + y, 0) / ub.length;
  const combined = traces.map((_, i) => (ua[i] - ma) * (ub[i] - mb));
  const pred = traces.map((t) => HW[SBOX[(t.plaintextByte ^ guess) & 0xff]]);
  return pearson(pred, combined);
}

describe('the incremental algebra is exact', () => {
  it('matches the direct two-pass attack at EVERY prefix length', () => {
    // This is the assertion that earns the expansion in secondOrder.ts its
    // place. The streaming form re-centres on each prefix's own means, which
    // is what the two-pass form does explicitly; if the expanded Sum(y^2) or
    // Sum(x*y) were wrong, the two would diverge as soon as the means moved.
    const traces = captureTraces(defaultBench(KEY, { protection: 'masked' }), 1200);
    const acc = new SecondOrderCpa(MASK_OUT_SAMPLE, S);
    const checkAt = new Set([2, 3, 10, 137, 500, 1199]);
    for (let i = 0; i < traces.length; i++) {
      acc.add(traces[i].plaintextByte, traces[i].samples);
      if (!checkAt.has(i)) continue;
      const prefix = traces.slice(0, i + 1);
      for (const g of [TRUE, 0x00, 0x91]) {
        expect(acc.correlation(g)).toBeCloseTo(
          directSecondOrder(prefix, MASK_OUT_SAMPLE, S, g),
          8
        );
      }
    }
  });

  it('the conditioning offset is a genuine no-op', () => {
    // The offset only keeps the running sums small. Shifting a sample by a
    // constant shifts its prefix mean by the same constant, so the centred
    // product is unchanged — asserted by running the attack against traces
    // that have been bodily shifted and getting the identical answer.
    const traces = captureTraces(defaultBench(KEY, { protection: 'masked' }), 600);
    const base = new SecondOrderCpa(MASK_OUT_SAMPLE, S);
    for (const t of traces) base.add(t.plaintextByte, t.samples);

    const shifted = traces.map((t) => {
      const s = t.samples.slice();
      s[MASK_OUT_SAMPLE] += 1000;
      s[S] -= 250;
      return { plaintextByte: t.plaintextByte, samples: s };
    });
    const moved = new SecondOrderCpa(MASK_OUT_SAMPLE, S);
    for (const t of shifted) moved.add(t.plaintextByte, t.samples);
    expect(moved.correlation(TRUE)).toBeCloseTo(base.correlation(TRUE), 8);
  });

  it('offsets are per sample and finite', () => {
    expect(Number.isFinite(conditioningOffset(MASK_OUT_SAMPLE))).toBe(true);
    expect(conditioningOffset(MASK_OUT_SAMPLE)).not.toBe(conditioningOffset(S));
  });

  it('reports zero rather than NaN before it has two traces', () => {
    const acc = new SecondOrderCpa(MASK_OUT_SAMPLE, S);
    expect(Array.from(acc.scores())).toEqual(new Array(256).fill(0));
  });
});

describe('the second-order attack recovers the key through the mask', () => {
  it('ranks the true byte first, with a NEGATIVE correlation', () => {
    const acc = new SecondOrderCpa(MASK_OUT_SAMPLE, S);
    forEachTrace(defaultBench(KEY, { protection: 'masked' }), 30000, (p, s) => acc.add(p, s));
    expect(rankOf(acc.scores(), TRUE)).toBe(1);
    expect(acc.correlation(TRUE)).toBeLessThan(0);
  }, 120_000);

  it('fails on every WRONG sample pairing', () => {
    // Only the pair that genuinely is (a mask, a value masked by THAT mask)
    // combines to anything. The S-box input is masked by mIn, not mOut, so
    // pairing it with mOut is as useless as pairing with an idle cycle — and
    // pairing mIn with the S-box input recovers HW(pt ^ k), which this
    // attack's S-box-output prediction does not model.
    for (const [a, b] of [
      [MASK_IN_SAMPLE, S],
      [MASK_OUT_SAMPLE, SBOX_IN_BASE],
      [MASK_OUT_SAMPLE, 2],
      [MASK_IN_SAMPLE, SBOX_IN_BASE],
    ] as const) {
      const acc = new SecondOrderCpa(a, b);
      forEachTrace(defaultBench(KEY, { protection: 'masked' }), 30000, (p, s) => acc.add(p, s));
      expect(rankOf(acc.scores(), TRUE), `pair ${a} x ${b} should not recover`).toBeGreaterThan(10);
    }
  }, 300_000);

  it('the combined series has variance — the attack is not correlating against a constant', () => {
    const acc = new SecondOrderCpa(MASK_OUT_SAMPLE, S);
    forEachTrace(defaultBench(KEY, { protection: 'masked' }), 2000, (p, s) => acc.add(p, s));
    expect(acc.combinedVariance()).toBeGreaterThan(1);
  });
});
