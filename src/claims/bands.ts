/**
 * The lab's measurable claims, as a seeded traces-to-disclosure BAND per act.
 *
 * ── WHY A BAND, AND NOT "THE ATTACK SUCCEEDED" ──────────────────────────────
 *
 * The obvious CI gate for this lab is "fail the build if the second-order
 * attack stops recovering the key". That gate is flaky: a statistical attack
 * near its disclosure threshold varies run to run, so the build reddens on
 * noise and everyone learns to re-run it, which is worse than having no gate.
 *
 * The gate here instead pins the PRNG seed, pins the checkpoint schedule, and
 * records the interval the traces-to-disclosure must land in. Failing on a band
 * violation catches the thing actually worth catching: if this masked
 * implementation suddenly RESISTS second-order CPA under this leakage model,
 * the model has broken — nothing about masking improved — and a band violation
 * is what surfaces that. It equally catches the opposite drift: a second-order
 * attack that starts succeeding in a few hundred traces means the two shares
 * stopped being independent.
 *
 * This is not a weakened gate. It is the deterministic form of a statistical
 * one: nothing is skipped, no threshold is lowered, and every band below fails
 * closed. `bands.test.ts` runs every attack for real and checks it.
 *
 * ── HOW THE BANDS WERE SET ──────────────────────────────────────────────────
 *
 * Each band is wide enough to survive a re-seed and narrow enough that a broken
 * model cannot sit inside it. The `observed` field records what six different
 * seeds actually produced, so the width is evidence rather than taste, and
 * `measured` records what the PINNED seed produces today. A change that moves
 * `measured` outside `band` is a real change to the bench and must be
 * investigated, not re-recorded.
 *
 * The strongest claim here is not any single band — it is `COST_RATIO_FLOOR`.
 * Absolute trace counts depend on the noise level, which is a dial. The RATIO
 * between breaking the unprotected implementation and breaking the masked one
 * at second order is the thesis: masking is a price, not a wall.
 */
import { hexToBytes } from '../aes/aes';
import { geometricCheckpoints } from '../attack/ttd';
import { DEFAULT_FROZEN_CONSTANT, DEFAULT_NOISE, DEFAULT_SEED } from '../leakage/traces';

/** The fixture. Every band below is measured against exactly this bench. */
export const FIXTURE = {
  /** FIPS-197 Appendix B key; byte 0 is 0x2b, the byte every attack recovers. */
  keyHex: '2b7e151628aed2a6abf7158809cf4f3c',
  targetByte: 0,
  noise: DEFAULT_NOISE,
  seed: DEFAULT_SEED,
  /** Pinned, not arbitrary — see FROZEN_FIXTURE below. */
  frozenConstant: DEFAULT_FROZEN_CONSTANT,
  /** A balanced constant: HW = 4, so the Hamming-weight correlation is zero. */
  balancedConstant: 0x0f,
  dpaBit: 0,
} as const;

export const FIXTURE_KEY = hexToBytes(FIXTURE.keyHex);
export const TRUE_KEY_BYTE = FIXTURE_KEY[FIXTURE.targetByte];

/**
 * Checkpoint schedules, pinned. Traces-to-disclosure is only defined relative
 * to a schedule — the same run reports a different number under a coarser one —
 * so a band without its schedule is not a claim.
 */
export const SCHEDULES = {
  firstOrder: geometricCheckpoints(20, 4000, 6),
  maskedFirstOrder: geometricCheckpoints(200, 60000, 4),
  secondOrder: geometricCheckpoints(500, 120000, 6),
  bitDpa: geometricCheckpoints(100, 40000, 4),
} as const;

export interface DisclosureClaim {
  readonly id: string;
  readonly act: string;
  readonly headline: string;
  readonly schedule: readonly number[];
  /** Inclusive band the traces-to-disclosure must land in. */
  readonly band: readonly [number, number];
  /** What the pinned seed produces today. */
  readonly measured: number;
  /** What six different seeds produced, as evidence for the band's width. */
  readonly observed: readonly number[];
}

export interface NonDisclosureClaim {
  readonly id: string;
  readonly act: string;
  readonly headline: string;
  readonly schedule: readonly number[];
  /** The attack must NOT rank the true byte first anywhere up to this count. */
  readonly noDisclosureUpTo: number;
  /** Six seeds, all of which produced no disclosure. */
  readonly seedsChecked: number;
}

/** Attacks that DO recover the key, and roughly how expensive that is. */
export const DISCLOSURE_CLAIMS: readonly DisclosureClaim[] = [
  {
    id: 'act1-unprotected-cpa',
    act: 'Act 1',
    headline: 'First-order CPA against unprotected AES recovers key byte 0.',
    schedule: SCHEDULES.firstOrder,
    band: [50, 800],
    measured: 200,
    observed: [200, 136, 294, 93, 294, 294],
  },
  {
    id: 'act3-masked-second-order-cpa',
    act: 'Act 3',
    headline:
      'Second-order CPA, combining the mask register with the masked S-box output, recovers the same byte through the masking.',
    schedule: SCHEDULES.secondOrder,
    band: [8000, 90000],
    measured: 23208,
    observed: [23208, 29356, 63246, 63246, 43089, 29356],
  },
  {
    id: 'act4-frozen-low-weight-cpa',
    act: 'Act 4',
    headline:
      'With the mask frozen to 0x01, ordinary first-order CPA works again — the countermeasure is intact and the randomness is not.',
    schedule: SCHEDULES.firstOrder,
    band: [60, 3000],
    measured: 632,
    observed: [632, 431, 632, 136, 294, 632],
  },
  {
    id: 'act4-frozen-balanced-bitdpa',
    act: 'Act 4',
    headline:
      'With the mask frozen to a BALANCED constant, a single-bit difference of means still recovers the key, where the Hamming-weight attack sees nothing.',
    schedule: SCHEDULES.bitDpa,
    band: [400, 20000],
    measured: 3162,
    observed: [3162, 3162, 1778, 5623, 3162, 1778],
  },
];

/** Attacks that do NOT recover the key — the negative claims. */
export const NON_DISCLOSURE_CLAIMS: readonly NonDisclosureClaim[] = [
  {
    id: 'act2-masked-first-order-cpa',
    act: 'Act 2',
    headline:
      'The headline negative claim: against a fresh mask per encryption, first-order CPA does not converge on the key — more traces do not help, because the leakage of x ^ m is independent of x. It says nothing about higher-order observation, which Act 3 then performs.',
    schedule: SCHEDULES.maskedFirstOrder,
    noDisclosureUpTo: 60000,
    seedsChecked: 6,
  },
  {
    id: 'act2-masked-bit-dpa',
    act: 'Act 2',
    headline:
      'The single-bit distinguisher fails too, against a fresh mask — this is a property of the masking, not a weakness of one statistic.',
    schedule: SCHEDULES.bitDpa,
    noDisclosureUpTo: 40000,
    seedsChecked: 6,
  },
  {
    id: 'act4-frozen-balanced-cpa',
    act: 'Act 4',
    headline:
      'With the mask frozen to a BALANCED constant, Hamming-weight CPA recovers nothing — and the protection is nonetheless entirely gone. A silent attack is not a working countermeasure.',
    schedule: SCHEDULES.bitDpa,
    noDisclosureUpTo: 40000,
    seedsChecked: 6,
  },
];

/**
 * The thesis, as a number. Second-order recovery must cost at least this many
 * times more traces than the unprotected baseline.
 *
 * More robust than any absolute band, because it survives a change to the noise
 * level: the noise dial moves both counts together and leaves the ratio alone.
 * Measured today at 23208 / 200 = 116x.
 */
export const COST_RATIO_FLOOR = 20;

/**
 * The frozen-mask fixture, pinned — and WHY it is pinned.
 *
 * Under a Hamming-weight leakage model the correlation a frozen mask leaves
 * behind is exactly 1 - HW(c)/4 (derived and checked exhaustively in
 * `../mask/combining.ts`). So the choice of constant is not cosmetic: a
 * BALANCED constant drives that correlation to zero and makes the attack look
 * like it failed when the protection is in fact completely gone. Leaving the
 * constant arbitrary would make the act's lesson depend on a coin flip.
 *
 * This lab takes BOTH published resolutions, and says so on the page:
 *
 *   1. The default constant is pinned to 0x01 — low Hamming weight, so the
 *      predicted correlation 0.75 is large, visible, and printed beside the
 *      correlation the bench actually measures.
 *   2. The frozen-mask panel's primary distinguisher is the single-BIT
 *      difference of means, which recovers the key for ANY fixed constant, up
 *      to a sign flip, and therefore does not depend on which constant was
 *      chosen.
 *
 * The learner can switch the constant to a balanced one and watch the
 * Hamming-weight attack collapse to nothing while the bit-level attack keeps
 * working. That contrast IS the lesson, and it is only available because the
 * fixture is pinned rather than random.
 */
export const FROZEN_FIXTURE = {
  pinned: DEFAULT_FROZEN_CONSTANT,
  pinnedHammingWeight: 1,
  /** 1 - HW(0x01)/4 — the exact Hamming-weight correlation that survives. */
  pinnedPredictedCorrelation: 0.75,
  balanced: 0x0f,
  balancedPredictedCorrelation: 0,
  /** Constants offered in the UI, spanning weight 0 to 8. */
  offered: [0x00, 0x01, 0x03, 0x0f, 0x7f, 0xff] as const,
  /**
   * How closely the bench must track the exact identity. At the trace counts
   * the page uses, sampling error on a correlation of ~0.2 is a few percent;
   * this tolerance is the sampling error, not slack in the claim.
   */
  toleranceOfPredicted: 0.06,
} as const;

/**
 * The one thing this lab does NOT model, stated where the claims are, so it
 * cannot be read past. Everything above is measured in an idealised
 * first-order probing/Hamming-weight model.
 */
export const OUT_OF_MODEL = [
  'Glitches. A scheme proven secure in the probing model can still leak at first order in real hardware, because a combinational glitch can transiently compute a function of both shares at once. This is why threshold implementations exist. No glitch is simulated here.',
  'Transitions and coupling. Real registers leak the Hamming DISTANCE between successive values, and neighbouring wires leak into each other; either can recombine two shares that the probing model treats as separate.',
  'Imperfect randomness short of a frozen mask — a biased or correlated mask generator sits between Act 2 and Act 4 and is not modelled.',
  'Higher masking orders. Only first-order masking is implemented. A d-th order scheme is attacked at order d+1, and the trace counts grow steeply enough that a browser could not run the demonstration honestly.',
] as const;
