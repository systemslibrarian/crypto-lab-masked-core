import { describe, expect, it } from 'vitest';
import { CpaAtSample } from '../attack/cpa';
import { BitDpaAtSample } from '../attack/dpa';
import { SecondOrderCpa } from '../attack/secondOrder';
import { runDisclosure } from '../attack/ttd';
import { frozenMaskCorrelation } from '../mask/combining';
import {
  defaultBench,
  MASK_OUT_SAMPLE,
  sboxOutSample,
  type BenchConfig,
} from '../leakage/traces';
import {
  COST_RATIO_FLOOR,
  DISCLOSURE_CLAIMS,
  FIXTURE,
  FIXTURE_KEY,
  FROZEN_FIXTURE,
  NON_DISCLOSURE_CLAIMS,
  SCHEDULES,
  TRUE_KEY_BYTE,
} from './bands';

const S = sboxOutSample(FIXTURE.targetByte);

function bench(over: Partial<BenchConfig> = {}): BenchConfig {
  return defaultBench(FIXTURE_KEY, {
    targetByte: FIXTURE.targetByte,
    noise: FIXTURE.noise,
    seed: FIXTURE.seed,
    ...over,
  });
}

/** The exact bench each claim id names. Kept here so a claim can never quietly
 *  be checked against a different configuration than the one it describes. */
const RUNS: Record<string, () => ReturnType<typeof runDisclosure>> = {
  'act1-unprotected-cpa': () =>
    runDisclosure(bench({ protection: 'none' }), new CpaAtSample(S), SCHEDULES.firstOrder, TRUE_KEY_BYTE),
  'act3-masked-second-order-cpa': () =>
    runDisclosure(
      bench({ protection: 'masked' }),
      new SecondOrderCpa(MASK_OUT_SAMPLE, S),
      SCHEDULES.secondOrder,
      TRUE_KEY_BYTE
    ),
  'act4-frozen-low-weight-cpa': () =>
    runDisclosure(
      bench({ protection: 'frozen', frozenConstant: FIXTURE.frozenConstant }),
      new CpaAtSample(S),
      SCHEDULES.firstOrder,
      TRUE_KEY_BYTE
    ),
  'act4-frozen-balanced-bitdpa': () =>
    runDisclosure(
      bench({ protection: 'frozen', frozenConstant: FIXTURE.balancedConstant }),
      new BitDpaAtSample(S, FIXTURE.dpaBit),
      SCHEDULES.bitDpa,
      TRUE_KEY_BYTE
    ),
  'act2-masked-first-order-cpa': () =>
    runDisclosure(
      bench({ protection: 'masked' }),
      new CpaAtSample(S),
      SCHEDULES.maskedFirstOrder,
      TRUE_KEY_BYTE
    ),
  'act2-masked-bit-dpa': () =>
    runDisclosure(
      bench({ protection: 'masked' }),
      new BitDpaAtSample(S, FIXTURE.dpaBit),
      SCHEDULES.bitDpa,
      TRUE_KEY_BYTE
    ),
  'act4-frozen-balanced-cpa': () =>
    runDisclosure(
      bench({ protection: 'frozen', frozenConstant: FIXTURE.balancedConstant }),
      new CpaAtSample(S),
      SCHEDULES.bitDpa,
      TRUE_KEY_BYTE
    ),
};

describe('the fixture is what the claims say it is', () => {
  it('recovers key byte 0x2b of the FIPS-197 Appendix B key', () => {
    expect(TRUE_KEY_BYTE).toBe(0x2b);
  });

  it('every claim id has a run, and every run has a claim', () => {
    const claimIds = [...DISCLOSURE_CLAIMS, ...NON_DISCLOSURE_CLAIMS].map((c) => c.id).sort();
    expect(Object.keys(RUNS).sort()).toEqual(claimIds);
  });

  it('the frozen fixture is pinned to a low-weight constant, and the balanced one is balanced', () => {
    expect(FROZEN_FIXTURE.pinned).toBe(FIXTURE.frozenConstant);
    expect(frozenMaskCorrelation(FROZEN_FIXTURE.pinned)).toBe(
      FROZEN_FIXTURE.pinnedPredictedCorrelation
    );
    expect(frozenMaskCorrelation(FROZEN_FIXTURE.balanced)).toBe(0);
    expect(FROZEN_FIXTURE.offered).toContain(FROZEN_FIXTURE.pinned);
    expect(FROZEN_FIXTURE.offered).toContain(FROZEN_FIXTURE.balanced);
  });
});

describe('recorded bands cannot rot', () => {
  for (const c of DISCLOSURE_CLAIMS) {
    it(`${c.id}: the recorded measurement and every observed seed lie inside the band`, () => {
      const [lo, hi] = c.band;
      expect(lo).toBeLessThan(hi);
      expect(c.measured).toBeGreaterThanOrEqual(lo);
      expect(c.measured).toBeLessThanOrEqual(hi);
      // The band's width is justified by the seeds, so the seeds must fit it.
      for (const o of c.observed) {
        expect(o, `seed observation ${o} outside band [${lo}, ${hi}]`).toBeGreaterThanOrEqual(lo);
        expect(o).toBeLessThanOrEqual(hi);
      }
      // A band must sit inside the schedule that defines it, or it is unreachable.
      expect(hi).toBeLessThanOrEqual(c.schedule[c.schedule.length - 1]);
    });
  }

  for (const c of NON_DISCLOSURE_CLAIMS) {
    it(`${c.id}: the no-disclosure horizon is the end of its schedule`, () => {
      expect(c.noDisclosureUpTo).toBe(c.schedule[c.schedule.length - 1]);
      expect(c.seedsChecked).toBeGreaterThanOrEqual(6);
    });
  }
});

describe('the attacks actually behave as recorded (seeded, deterministic)', () => {
  for (const c of DISCLOSURE_CLAIMS) {
    it(`${c.act} — ${c.id} discloses inside [${c.band[0]}, ${c.band[1]}]`, () => {
      const run = RUNS[c.id]();
      expect(run.ttd, `${c.id} did not disclose at all`).not.toBeNull();
      const [lo, hi] = c.band;
      expect(run.ttd!, `${c.id} disclosed at ${run.ttd}`).toBeGreaterThanOrEqual(lo);
      expect(run.ttd!, `${c.id} disclosed at ${run.ttd}`).toBeLessThanOrEqual(hi);
    }, 120_000);
  }

  for (const c of NON_DISCLOSURE_CLAIMS) {
    it(`${c.act} — ${c.id} does NOT disclose up to ${c.noDisclosureUpTo}`, () => {
      const run = RUNS[c.id]();
      expect(run.ttd, `${c.id} unexpectedly disclosed at ${run.ttd}`).toBeNull();
      // Stronger than "never rank 1": the true byte must not even be
      // distinguishable at the end, or the claim is only surviving on a tie.
      const last = run.points[run.points.length - 1];
      expect(last.numTraces).toBe(c.noDisclosureUpTo);
      expect(
        last.correctScore,
        'the true key byte must not stand above the wrong-guess floor'
      ).toBeLessThanOrEqual(last.topWrongScore);
    }, 120_000);
  }
});

describe('the thesis: masking is a price, not a wall', () => {
  it('second-order recovery costs at least 20x the unprotected baseline', () => {
    const base = RUNS['act1-unprotected-cpa']();
    const second = RUNS['act3-masked-second-order-cpa']();
    expect(base.ttd).not.toBeNull();
    expect(second.ttd).not.toBeNull();
    const ratio = second.ttd! / base.ttd!;
    expect(ratio, `cost ratio was ${ratio.toFixed(1)}x`).toBeGreaterThanOrEqual(COST_RATIO_FLOOR);
  }, 180_000);

  it('the second-order peak is NEGATIVE, as the combining identity predicts', () => {
    // -(1/2)(HW(v) - 4): the centred product is a DECREASING function of the
    // predicted Hamming weight, so the correct guess correlates negatively.
    // A positive peak here would mean the attack is succeeding for some reason
    // other than the mechanism the lab teaches.
    const d = new SecondOrderCpa(MASK_OUT_SAMPLE, S);
    const run = runDisclosure(bench({ protection: 'masked' }), d, [30000], TRUE_KEY_BYTE);
    expect(run.points[0].correctRank).toBe(1);
    expect(run.points[0].correctSigned).toBeLessThan(0);
  }, 120_000);

  it('the first-order peak against unprotected AES is POSITIVE', () => {
    const d = new CpaAtSample(S);
    const run = runDisclosure(bench({ protection: 'none' }), d, [3000], TRUE_KEY_BYTE);
    expect(run.points[0].correctRank).toBe(1);
    expect(run.points[0].correctSigned).toBeGreaterThan(0);
  }, 60_000);
});
