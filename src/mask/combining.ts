/**
 * The two exact identities this lab is built on. Both are derived here and
 * checked exhaustively over all 256 mask values in `combining.test.ts` — not
 * sampled, not asserted in prose.
 *
 * ── 1. WHY ONE PROBE LEARNS NOTHING (first-order security) ──────────────────
 *
 * For a uniform 8-bit mask m, the map m -> v ^ m is a bijection on the byte
 * space, so {v ^ m : all m} is the whole byte space no matter what v is. Both
 * halves of the share pair therefore have exactly the same marginal
 * distribution for every v, and any statistic of ONE of them alone — Hamming
 * weight included — carries zero information about v. That is the entire
 * first-order claim, and it is exact rather than approximate.
 *
 * ── 2. WHY TWO PROBES GIVE IT BACK (the second-order attack) ────────────────
 *
 * Centre each leakage on the mean Hamming weight of a uniform byte (4) and
 * multiply. Take one bit first. With m uniform on {0,1} and z the secret bit,
 * the two leakages are m and z ^ m, centred at 1/2:
 *
 *     z = 0:  E[(m - 1/2)(m - 1/2)]         = +1/4
 *     z = 1:  E[(m - 1/2)((1-m) - 1/2)]     = -1/4
 *
 * so E[.] = 1/4 - z/2 = -(1/2)(z - 1/2). Now stack 8 independent bits.
 * HW(m) - 4 = sum_i (m_i - 1/2) and HW(v ^ m) - 4 = sum_i (v_i ^ m_i - 1/2);
 * cross terms i != j have independent zero-mean factors and vanish, leaving the
 * per-bit result eight times over:
 *
 *     E[(HW(m) - 4)(HW(v ^ m) - 4)] = -(1/2)(HW(v) - 4)
 *
 * The centred product of the two leakages is an unbiased, exactly linear
 * estimator of HW(v) — with a MINUS sign, which is why a correct second-order
 * key guess shows up as a negative correlation. Masking has not hidden the
 * secret; it has moved it from the first moment to the second.
 *
 * The price is variance. Each individual product carries the full noise of both
 * samples multiplied together, so the correlation is far smaller than the
 * first-order one and the trace count needed goes up steeply. That trade — a
 * price, not a wall — is the lab's thesis.
 *
 * ── 3. WHAT A FROZEN MASK DOES (act 4) ──────────────────────────────────────
 *
 * Freeze the mask to a constant c. Then HW(v ^ c) = HW(c) + sum_i s_i v_i with
 * s_i = +1 where c_i = 0 and -1 where c_i = 1, so over uniform v
 *
 *     rho( HW(v ^ c), HW(v) ) = 1 - HW(c)/4
 *
 * exactly. A low-weight constant leaves the Hamming-weight correlation almost
 * intact (c = 0x01 gives 0.75), a high-weight constant INVERTS it (c = 0xfe
 * gives -0.75), and a BALANCED constant — any c with HW(c) = 4 — drives it to
 * exactly zero. That last case is a trap: the protection is entirely gone, and
 * a Hamming-weight CPA reports nothing. `src/attack/dpa.ts` is the answer: a
 * single-bit distinguisher recovers the key for ANY fixed c, up to a sign.
 */
import { HW, HW_MEAN } from '../leakage/model';

/**
 * The centred-product combining function (Chari et al. 1999; Messerges 2000;
 * analysed by Prouff, Rivain and Bevan 2009).
 *
 * `meanA` / `meanB` are the sample means of the two leakage points over the
 * traces being combined. Centring on the measured means rather than on a
 * modelled constant is what makes this work against a real trace, where the
 * data-independent operation shape sits on top of the leakage.
 */
export function centredProduct(a: number, b: number, meanA: number, meanB: number): number {
  return (a - meanA) * (b - meanB);
}

/**
 * The exact expectation of the centred product of HW(m) and HW(v ^ m) over a
 * uniform mask: -(1/2)(HW(v) - 4). Used by the mechanism panel to draw the
 * theory line the measured points are compared against.
 */
export function predictedCombinedMean(v: number): number {
  return -0.5 * (HW[v & 0xff] - HW_MEAN);
}

/**
 * The exact correlation a Hamming-weight model retains against a mask frozen to
 * `constant`: 1 - HW(c)/4. This is what the frozen-mask panel prints beside the
 * correlation it actually measures on the bench.
 */
export function frozenMaskCorrelation(constant: number): number {
  return 1 - HW[constant & 0xff] / 4;
}

/**
 * The exact difference of means a single-bit DPA sees against a mask frozen to
 * `constant`, in Hamming-weight units: +1 where bit `bit` of the constant is
 * clear, -1 where it is set.
 *
 * Derivation. The masked value's bit i is v_i ^ c_i, and the remaining seven
 * bits average 3.5 in both partitions because v is uniform over the whole byte
 * space (the S-box is a bijection and the plaintext byte is uniform). So
 * partitioning on the predicted v_bit moves the group mean by exactly one unit,
 * and only the SIGN depends on the constant. `combining.test.ts` checks this
 * exhaustively over all 256 constants and all 8 bits, with no sampling.
 *
 * This is why the frozen-mask act uses a bit-level distinguisher as its primary
 * attack: unlike the Hamming-weight correlation 1 - HW(c)/4, it never goes to
 * zero, so it recovers the key for EVERY fixed constant rather than only for
 * the convenient ones.
 */
export function bitDpaDifference(constant: number, bit: number): number {
  return 1 - 2 * ((constant >> bit) & 1);
}

/**
 * Measure the mean centred product for one secret value by averaging over ALL
 * 256 masks. Exhaustive, so it returns the exact expectation with no sampling
 * error — the mechanism panel plots this against `predictedCombinedMean` and
 * the two must coincide.
 */
export function exhaustiveCombinedMean(v: number): number {
  let sum = 0;
  for (let m = 0; m < 256; m++) sum += (HW[m] - HW_MEAN) * (HW[(v ^ m) & 0xff] - HW_MEAN);
  return sum / 256;
}

/**
 * The mechanism, as one picture: the average Hamming weight of the MASKED share
 * given the Hamming weight of the mask.
 *
 * Each share on its own is a flat binomial for every secret (`shareHistogram`).
 * Put them side by side, though, and the conditional mean is a straight line
 * whose SLOPE reads the secret's Hamming weight straight off:
 *
 *     E[ HW(v ^ m) | HW(m) = k ]  =  HW(v) + k * (1 - HW(v)/4)
 *
 * Derivation: HW(v ^ m) = HW(v) + HW(m) - 2*|v AND m|, and over masks of fixed
 * weight k the overlap is hypergeometric with mean k*HW(v)/8. Substituting gives
 * the line above.
 *
 * So a secret of weight 0 gives slope +1, weight 8 gives slope -1, and — the
 * detail that matters for the frozen-mask act — weight 4 gives slope ZERO. The
 * dependence is real for every secret; a Hamming-weight statistic just happens
 * to be blind to the balanced ones.
 */
export function conditionalMeanByMaskWeight(v: number): number[] {
  const sum = new Array<number>(9).fill(0);
  const count = new Array<number>(9).fill(0);
  for (let m = 0; m < 256; m++) {
    const k = HW[m];
    sum[k] += HW[(v ^ m) & 0xff];
    count[k]++;
  }
  return sum.map((s, k) => s / count[k]);
}

/** The closed form the measured conditional mean is compared against. */
export function predictedConditionalMean(v: number, maskWeight: number): number {
  const h = HW[v & 0xff];
  return h + maskWeight * (1 - h / 4);
}

/**
 * The Hamming-weight histogram of one share over all 256 masks. For the masked
 * value this is the binomial C(8,w)/256 for every v — which is the first-order
 * claim made visible as a picture rather than a sentence.
 */
export function shareHistogram(v: number, which: 'mask' | 'masked'): number[] {
  const hist = new Array<number>(9).fill(0);
  for (let m = 0; m < 256; m++) {
    const byte = which === 'mask' ? m : (v ^ m) & 0xff;
    hist[HW[byte]]++;
  }
  return hist;
}
