/**
 * Second-order CPA: the attack that gets the key back through the mask.
 *
 * Masking moves the secret out of the first moment of a single leakage point.
 * It does not remove it from the joint distribution of TWO points. Combine the
 * mask register's leakage with the masked value's leakage by the centred
 * product and, by the identity derived in `../mask/combining.ts`,
 *
 *     E[(HW(m) - 4)(HW(v ^ m) - 4)] = -(1/2)(HW(v) - 4)
 *
 * the combined series is an exactly linear (and negative) function of HW(v).
 * So: build the combined series, then run ordinary CPA on it against the same
 * HW(SBOX[pt ^ k]) prediction. The correct guess appears as a NEGATIVE peak.
 *
 * ── WHY THIS IS NOT A TWO-PASS ATTACK ───────────────────────────────────────
 *
 * The combining is defined relative to the means of the two samples, and the
 * means over the first N traces change with N — so a naive implementation needs
 * one pass per checkpoint to draw an honest traces-to-disclosure curve, which is
 * O(checkpoints * N * 256) and far too slow to run in a browser.
 *
 * It is avoidable exactly. Expand the product against the prefix means A and B:
 *
 *     y = uv - Av - Bu + AB
 *
 * so Sum(y), Sum(y^2) and Sum(x*y) are all fixed combinations of raw prefix
 * sums (Suv, Suuvv, Suvv, Suuv, ... and per-guess Sxuv, Sxu, Sxv) that a single
 * pass can accumulate. Every checkpoint then reads off the EXACT correlation for
 * its own prefix means, in one pass. `secondOrder.test.ts` checks that against a
 * direct two-pass computation rather than taking the algebra on trust.
 *
 * ── NUMERICAL CONDITIONING ──────────────────────────────────────────────────
 *
 * Raw samples sit around 20-30 model units on top of the operation template, so
 * Sum(u^2 v^2) over 60,000 traces reaches ~10^10 while Sum(y^2) is ~10^5 — four
 * digits of cancellation before anything useful is left. The fix is to subtract
 * a fixed offset from each sample first. The centred product is EXACTLY
 * invariant to a constant shift of either sample (shifting u by c shifts the
 * prefix mean A by the same c, and u - A is unchanged), so this cannot alter the
 * result; it only keeps the sums small. The offset used is the sample's known
 * data-independent template value plus the mean Hamming weight, which needs no
 * pre-pass over the data.
 */
import { HW_MEAN } from '../leakage/model';
import { LEAK_AMP, templateSample } from '../leakage/traces';
import { predictions, type Distinguisher } from './cpa';
import { pearsonFromSums } from './stats';

/** The conditioning offset for a sample. A constant shift; see the header. */
export function conditioningOffset(sample: number): number {
  return templateSample(sample) + HW_MEAN * LEAK_AMP;
}

export class SecondOrderCpa implements Distinguisher {
  private n = 0;
  // Globals over the shifted samples u (sample A) and v (sample B).
  private su = 0;
  private sv = 0;
  private suu = 0;
  private svv = 0;
  private suv = 0;
  private suuv = 0;
  private suvv = 0;
  private suuvv = 0;
  // Per guess.
  private readonly sx = new Float64Array(256);
  private readonly sxx = new Float64Array(256);
  private readonly sxu = new Float64Array(256);
  private readonly sxv = new Float64Array(256);
  private readonly sxuv = new Float64Array(256);

  private readonly pred = new Float64Array(256);
  private readonly offA: number;
  private readonly offB: number;
  private readonly signed = new Float64Array(256);

  constructor(
    readonly sampleA: number,
    readonly sampleB: number
  ) {
    this.offA = conditioningOffset(sampleA);
    this.offB = conditioningOffset(sampleB);
  }

  get count(): number {
    return this.n;
  }

  add(plaintextByte: number, samples: ArrayLike<number>): void {
    const u = samples[this.sampleA] - this.offA;
    const v = samples[this.sampleB] - this.offB;
    const uv = u * v;
    this.n++;
    this.su += u;
    this.sv += v;
    this.suu += u * u;
    this.svv += v * v;
    this.suv += uv;
    this.suuv += u * uv;
    this.suvv += v * uv;
    this.suuvv += uv * uv;
    predictions(plaintextByte, this.pred);
    for (let g = 0; g < 256; g++) {
      const p = this.pred[g];
      this.sx[g] += p;
      this.sxx[g] += p * p;
      this.sxu[g] += p * u;
      this.sxv[g] += p * v;
      this.sxuv[g] += p * uv;
    }
  }

  scores(): Float64Array {
    const n = this.n;
    const out = new Float64Array(256);
    if (n < 2) return out;
    const A = this.su / n;
    const B = this.sv / n;
    const sy = this.suv - n * A * B;
    const syy =
      this.suuvv +
      A * A * this.svv +
      B * B * this.suu -
      3 * n * A * A * B * B -
      2 * A * this.suvv -
      2 * B * this.suuv +
      4 * A * B * this.suv;
    for (let g = 0; g < 256; g++) {
      const sxy = this.sxuv[g] - A * this.sxv[g] - B * this.sxu[g] + A * B * this.sx[g];
      const r = pearsonFromSums(n, this.sx[g], sy, this.sxx[g], syy, sxy);
      this.signed[g] = r;
      out[g] = Math.abs(r);
    }
    return out;
  }

  /** Signed r for one guess. The correct key's second-order peak is NEGATIVE —
   *  that minus sign is the identity in `combining.ts` showing up on the bench. */
  correlation(guess: number): number {
    this.scores();
    return this.signed[guess];
  }

  /** The combined series' variance at the current count, for the honesty panel. */
  combinedVariance(): number {
    const n = this.n;
    if (n < 2) return 0;
    const A = this.su / n;
    const B = this.sv / n;
    const sy = this.suv - n * A * B;
    const syy =
      this.suuvv +
      A * A * this.svv +
      B * B * this.suu -
      3 * n * A * A * B * B -
      2 * A * this.suvv -
      2 * B * this.suuv +
      4 * A * B * this.suv;
    return (syy - (sy * sy) / n) / (n - 1);
  }
}
