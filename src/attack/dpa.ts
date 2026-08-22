/**
 * Differential Power Analysis (Kocher-Jaffe-Jun, 1999) — the original, carried
 * over from `crypto-lab-power-trace`'s `src/attack/dpa.ts` and narrowed to a
 * single sample so it can run over the trace counts this lab needs.
 *
 *   D_i = bit b of SBOX[pt_i ^ guess]
 *   diff = mean{ sample_i : D_i = 1 } - mean{ sample_i : D_i = 0 }
 *
 * In `power-trace` this is the historical footnote to CPA: same result, more
 * traces. HERE IT IS THE POINT. Against a mask frozen to a constant c, a
 * Hamming-weight CPA measures rho = 1 - HW(c)/4 (see `../mask/combining.ts`) —
 * which is ZERO for any balanced constant, so the Hamming-weight attack reports
 * nothing while the protection is entirely gone. The single-bit difference of
 * means does not care: the leakage of bit i of the masked value is v_i ^ c_i, so
 * partitioning on the predicted v_i separates the two groups by exactly one
 * model unit whatever c is, with only the SIGN flipping on c_i. Ranking on the
 * absolute difference therefore recovers the key byte for EVERY fixed mask.
 *
 * And it correctly fails when the masking is working: with a fresh mask per
 * trace, E[HW(v ^ m) | v_i = b] is 4 for both b, so both group means agree and
 * the difference collapses into the noise.
 */
import { SBOX } from '../aes/aes';
import type { Distinguisher } from './cpa';

export class BitDpaAtSample implements Distinguisher {
  private n = 0;
  private readonly count1 = new Int32Array(256);
  private readonly sum1 = new Float64Array(256);
  private sumAll = 0;
  private readonly signedDiff = new Float64Array(256);

  constructor(
    readonly sample: number,
    readonly bit: number = 0
  ) {
    if (bit < 0 || bit > 7) throw new Error(`bit must be 0..7, got ${bit}`);
  }

  get count(): number {
    return this.n;
  }

  add(plaintextByte: number, samples: ArrayLike<number>): void {
    const t = samples[this.sample];
    this.n++;
    this.sumAll += t;
    for (let g = 0; g < 256; g++) {
      if ((SBOX[(plaintextByte ^ g) & 0xff] >> this.bit) & 1) {
        this.count1[g]++;
        this.sum1[g] += t;
      }
    }
  }

  scores(): Float64Array {
    const out = new Float64Array(256);
    for (let g = 0; g < 256; g++) {
      const c1 = this.count1[g];
      const c0 = this.n - c1;
      if (c1 === 0 || c0 === 0) {
        this.signedDiff[g] = 0;
        continue;
      }
      const diff = this.sum1[g] / c1 - (this.sumAll - this.sum1[g]) / c0;
      this.signedDiff[g] = diff;
      out[g] = Math.abs(diff);
    }
    return out;
  }

  /** The signed difference of means — its SIGN is the frozen constant's bit. */
  difference(guess: number): number {
    this.scores();
    return this.signedDiff[guess];
  }
}

/** Bit-DPA at every sample, for the "where does it leak" curve. */
export class BitDpaSampleScan {
  private readonly cols: BitDpaAtSample[];

  constructor(
    readonly numSamples: number,
    readonly bit: number = 0
  ) {
    this.cols = Array.from({ length: numSamples }, (_, s) => new BitDpaAtSample(s, bit));
  }

  get count(): number {
    return this.cols[0]?.count ?? 0;
  }

  add(plaintextByte: number, samples: ArrayLike<number>): void {
    for (const c of this.cols) c.add(plaintextByte, samples);
  }

  peakPerSample(): Float64Array {
    const out = new Float64Array(this.numSamples);
    for (let s = 0; s < this.numSamples; s++) {
      const sc = this.cols[s].scores();
      let peak = 0;
      for (let g = 0; g < 256; g++) if (sc[g] > peak) peak = sc[g];
      out[s] = peak;
    }
    return out;
  }
}
