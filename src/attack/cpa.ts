/**
 * Correlation Power Analysis (Brier-Clavier-Olivier, 2004), following
 * `crypto-lab-power-trace`'s `src/attack/cpa.ts`.
 *
 *   for each key-byte guess k in 0..255:
 *     for each trace i: predict H_i = HW(SBOX[pt_i ^ k])
 *     correlate H against the measured power at the sample under attack
 *   the guess whose prediction best correlates with the real power IS the key.
 *
 * 255 guesses produce a wrong intermediate, so their prediction is uncorrelated
 * with the real power and stays in the noise; the one correct guess predicts the
 * real intermediate and spikes. Nothing is faked — this is real Pearson
 * correlation over real HW(SBOX[pt ^ k]).
 *
 * Two accumulators, both streaming, because this lab needs two different things
 * from the same attack:
 *   - `CpaSampleScan` correlates at EVERY sample, which is how you find the
 *     leaking point in the first place — and, when masking is on, how you see
 *     that there is no leaking point to find.
 *   - `CpaAtSample` correlates at ONE sample, cheaply enough to push tens of
 *     thousands of traces through it for a traces-to-disclosure curve.
 */
import { SBOX } from '../aes/aes';
import { HW } from '../leakage/model';
import { NUM_SAMPLES } from '../leakage/traces';
import { pearsonFromSums } from './stats';

/** HW(SBOX[pt ^ g]) for all 256 guesses — the prediction the attack correlates. */
export function predictions(plaintextByte: number, out: Float64Array): void {
  for (let g = 0; g < 256; g++) out[g] = HW[SBOX[(plaintextByte ^ g) & 0xff]];
}

/** A streaming distinguisher: absolute score per key-byte guess. */
export interface Distinguisher {
  readonly count: number;
  add(plaintextByte: number, samples: ArrayLike<number>): void;
  scores(): Float64Array;
}

/** CPA at a single sample. O(256) per trace. */
export class CpaAtSample implements Distinguisher {
  private n = 0;
  private readonly sx = new Float64Array(256);
  private readonly sxx = new Float64Array(256);
  private readonly sxt = new Float64Array(256);
  private st = 0;
  private stt = 0;
  private readonly pred = new Float64Array(256);
  /** Signed correlations at the last `scores()` call, for reporting the sign. */
  private readonly signed = new Float64Array(256);

  constructor(readonly sample: number) {}

  get count(): number {
    return this.n;
  }

  add(plaintextByte: number, samples: ArrayLike<number>): void {
    const t = samples[this.sample];
    this.n++;
    this.st += t;
    this.stt += t * t;
    predictions(plaintextByte, this.pred);
    for (let g = 0; g < 256; g++) {
      const p = this.pred[g];
      this.sx[g] += p;
      this.sxx[g] += p * p;
      this.sxt[g] += p * t;
    }
  }

  scores(): Float64Array {
    const out = new Float64Array(256);
    for (let g = 0; g < 256; g++) {
      const r = pearsonFromSums(this.n, this.sx[g], this.st, this.sxx[g], this.stt, this.sxt[g]);
      this.signed[g] = r;
      out[g] = Math.abs(r);
    }
    return out;
  }

  /** The signed correlation for one guess — CPA ranks on |r|, but the sign is
   *  itself information (a second-order peak is negative, see combining.ts). */
  correlation(guess: number): number {
    this.scores();
    return this.signed[guess];
  }
}

export interface SampleScanResult {
  readonly numTraces: number;
  /** |r| at each sample, for the best-scoring guess at that sample. */
  readonly peakPerSample: Float64Array;
  /** The signed correlation curve of one nominated guess across all samples. */
  readonly curveFor: (guess: number) => Float64Array;
  /** Per-guess peak |r| across all samples. */
  readonly scores: Float64Array;
  readonly best: number;
  readonly bestSample: number;
}

/** CPA at every sample. O(256 * numSamples) per trace — use at modest counts. */
export class CpaSampleScan {
  private n = 0;
  private readonly sx = new Float64Array(256);
  private readonly sxx = new Float64Array(256);
  private readonly st: Float64Array;
  private readonly stt: Float64Array;
  /** guess-major: [guess * numSamples + sample] */
  private readonly sxt: Float64Array;
  private readonly pred = new Float64Array(256);

  constructor(readonly numSamples: number = NUM_SAMPLES) {
    this.st = new Float64Array(numSamples);
    this.stt = new Float64Array(numSamples);
    this.sxt = new Float64Array(256 * numSamples);
  }

  get count(): number {
    return this.n;
  }

  add(plaintextByte: number, samples: ArrayLike<number>): void {
    const ns = this.numSamples;
    this.n++;
    for (let t = 0; t < ns; t++) {
      const v = samples[t];
      this.st[t] += v;
      this.stt[t] += v * v;
    }
    predictions(plaintextByte, this.pred);
    for (let g = 0; g < 256; g++) {
      const p = this.pred[g];
      this.sx[g] += p;
      this.sxx[g] += p * p;
      if (p === 0) continue;
      const base = g * ns;
      for (let t = 0; t < ns; t++) this.sxt[base + t] += p * samples[t];
    }
  }

  result(): SampleScanResult {
    const ns = this.numSamples;
    const n = this.n;
    const scores = new Float64Array(256);
    const peakPerSample = new Float64Array(ns);
    let best = 0;
    let bestSample = 0;
    let bestScore = -1;
    const rAt = (g: number, t: number): number =>
      pearsonFromSums(n, this.sx[g], this.st[t], this.sxx[g], this.stt[t], this.sxt[g * ns + t]);

    for (let g = 0; g < 256; g++) {
      let peak = 0;
      for (let t = 0; t < ns; t++) {
        const a = Math.abs(rAt(g, t));
        if (a > peak) peak = a;
        if (a > peakPerSample[t]) peakPerSample[t] = a;
      }
      scores[g] = peak;
      if (peak > bestScore) {
        bestScore = peak;
        best = g;
      }
    }
    for (let t = 0; t < ns; t++) {
      if (Math.abs(rAt(best, t)) === scores[best]) {
        bestSample = t;
        break;
      }
    }
    return {
      numTraces: n,
      peakPerSample,
      scores,
      best,
      bestSample,
      curveFor: (g: number) => {
        const curve = new Float64Array(ns);
        for (let t = 0; t < ns; t++) curve[t] = rAt(g, t);
        return curve;
      },
    };
  }
}
