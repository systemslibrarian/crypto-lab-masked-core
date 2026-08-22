/**
 * Trace generation. This is the ONE simulated part of the lab, and it is
 * labelled as such everywhere it surfaces in the UI.
 *
 * The intermediates are REAL and they are not re-derived here. An unprotected
 * trace reads `round1Probes` from `../aes/aes`; a masked trace reads
 * `maskedRound1Probes` from `../mask/maskedAes`, which runs the same
 * `maskedRound` the full ten-round masked cipher runs. So the values a probe
 * "measures" are the values the cipher actually computes, and the FIPS-197 KATs
 * on those ciphers are KATs on the bench as well.
 *
 * The power MODEL is a model: each probed register contributes
 * LEAK_AMP * HW(value) at one sample, on top of a fixed data-independent
 * operation shape and Gaussian measurement noise. What transfers to a real
 * oscilloscope bench is the model's SHAPE (power tracks bits), the statistics,
 * and the trace-count economics between orders. What does NOT transfer is the
 * noise distribution of physical silicon, and — this is the important one —
 * glitches, transitions and coupling, which are how real masked hardware leaks
 * at first order despite being provably secure in the probing model. See the
 * Scope panel; none of that is simulated here.
 *
 * ── SAMPLE LAYOUT ───────────────────────────────────────────────────────────
 * Two mask-register samples, then the sixteen S-box input samples, then the
 * sixteen S-box output samples. The mask samples correspond to the table
 * recomputation a masked build performs and an unprotected build does not, so
 * in the unprotected bench those two samples carry the operation shape and
 * noise and no data leakage at all — the cycles are there, the mask registers
 * are not.
 */
import { expandKey, round1Probes } from '../aes/aes';
import { maskedRound1Probes, type MaskSource } from '../mask/maskedAes';
import { HW } from './model';
import { Rng } from './rng';

export type Protection = 'none' | 'masked' | 'frozen';

export const NUM_SAMPLES = 40;
export const MASK_IN_SAMPLE = 3;
export const MASK_OUT_SAMPLE = 5;
export const SBOX_IN_BASE = 8;
export const SBOX_OUT_BASE = 24;
/** Model units of leakage per Hamming-weight bit. */
export const LEAK_AMP = 1.0;
export const DEFAULT_NOISE = 6;
export const DEFAULT_SEED = 20260822;
/** The pinned frozen-mask fixture — deliberately low weight. See `frozen.ts`. */
export const DEFAULT_FROZEN_CONSTANT = 0x01;

export interface BenchConfig {
  readonly key: Uint8Array;
  readonly targetByte: number;
  readonly protection: Protection;
  readonly frozenConstant: number;
  /** Gaussian sigma of the measurement noise. */
  readonly noise: number;
  readonly seed: number;
}

export function defaultBench(key: Uint8Array, over: Partial<BenchConfig> = {}): BenchConfig {
  return {
    key,
    targetByte: 0,
    protection: 'none',
    frozenConstant: DEFAULT_FROZEN_CONSTANT,
    noise: DEFAULT_NOISE,
    seed: DEFAULT_SEED,
    ...over,
  };
}

/** A human label for each sample index, used by the plot and its aria text. */
export function sampleLabel(index: number): string {
  if (index === MASK_IN_SAMPLE) return 'input mask register mIn';
  if (index === MASK_OUT_SAMPLE) return 'output mask register mOut';
  if (index >= SBOX_IN_BASE && index < SBOX_IN_BASE + 16) {
    return `S-box input, byte ${index - SBOX_IN_BASE}`;
  }
  if (index >= SBOX_OUT_BASE && index < SBOX_OUT_BASE + 16) {
    return `S-box output, byte ${index - SBOX_OUT_BASE}`;
  }
  return `idle cycle ${index}`;
}

/** The sample a first-order attack on byte `j` should be aiming at. */
export function sboxOutSample(targetByte: number): number {
  return SBOX_OUT_BASE + targetByte;
}

/**
 * Fixed, data-independent operation shape. Constant across traces at any given
 * sample, so it contributes nothing to a per-sample correlation; it exists so
 * the trace looks like a trace, and so the centred product has a real mean to
 * be centred against rather than a convenient zero.
 */
const TEMPLATE: Float64Array = (() => {
  const t = new Float64Array(NUM_SAMPLES);
  const bump = (centre: number, width: number, amp: number): void => {
    for (let i = 0; i < NUM_SAMPLES; i++) {
      const d = i - centre;
      t[i] += amp * Math.exp(-(d * d) / (2 * width * width));
    }
  };
  bump(4, 2.2, 9); // the table-recomputation window
  bump(15.5, 6, 5); // the S-box input sweep
  bump(31.5, 6, 5); // the S-box output sweep
  for (let i = 0; i < NUM_SAMPLES; i++) t[i] += 20;
  return t;
})();

export function templateSample(index: number): number {
  return TEMPLATE[index];
}

function maskSource(cfg: BenchConfig): MaskSource {
  return cfg.protection === 'frozen'
    ? { kind: 'frozen', constant: cfg.frozenConstant & 0xff }
    : { kind: 'fresh' };
}

/**
 * A resumable trace stream.
 *
 * TWO generators, from one seed. `dataRng` produces the plaintexts and the
 * measurement noise; `maskRng` produces the masks. Keeping them separate means
 * flipping the protection switch changes ONLY the masks — the same plaintexts
 * arrive in the same order under the same noise — so "same attack, protection
 * on" is a controlled experiment rather than an entirely different bench.
 *
 * It is a class rather than a plain loop so a long attack can be pulled a few
 * thousand traces at a time, letting the browser paint between chunks. A
 * 60,000-trace second-order run is a second or two of arithmetic; done in one
 * synchronous burst that is a frozen tab with no way to tell whether anything
 * is happening.
 *
 * The samples buffer is REUSED between traces. Consumers that need to keep a
 * trace must copy it; `captureTraces` does.
 */
export class TraceStream {
  private readonly rk: Uint8Array[];
  private readonly source: MaskSource;
  private readonly dataRng: Rng;
  private readonly maskRng: Rng;
  private readonly samples = new Float64Array(NUM_SAMPLES);
  private readonly pt = new Uint8Array(16);
  private emitted = 0;

  constructor(readonly cfg: BenchConfig) {
    this.rk = expandKey(cfg.key);
    this.source = maskSource(cfg);
    this.dataRng = new Rng(cfg.seed);
    this.maskRng = new Rng((cfg.seed ^ 0x9e3779b9) >>> 0);
  }

  get count(): number {
    return this.emitted;
  }

  /** Emit the next `n` traces. Returns how many were actually emitted. */
  take(n: number, visit: (plaintextByte: number, samples: Float64Array, index: number) => void): number {
    const cfg = this.cfg;
    const { samples, pt, rk } = this;
    for (let c = 0; c < n; c++) {
      for (let j = 0; j < 16; j++) pt[j] = this.dataRng.byte();

      samples.set(TEMPLATE);
      for (let t = 0; t < NUM_SAMPLES; t++) samples[t] += cfg.noise * this.dataRng.gaussian();

      if (cfg.protection === 'none') {
        // No mask registers exist; samples 3 and 5 are idle cycles.
        const p = round1Probes(pt, rk[0]);
        for (let j = 0; j < 16; j++) {
          samples[SBOX_IN_BASE + j] += LEAK_AMP * HW[p.sboxIn[j]];
          samples[SBOX_OUT_BASE + j] += LEAK_AMP * HW[p.sboxOut[j]];
        }
      } else {
        const p = maskedRound1Probes(pt, rk[0], rk[1], this.maskRng, this.source);
        samples[MASK_IN_SAMPLE] += LEAK_AMP * HW[p.maskIn];
        samples[MASK_OUT_SAMPLE] += LEAK_AMP * HW[p.maskOut];
        for (let j = 0; j < 16; j++) {
          samples[SBOX_IN_BASE + j] += LEAK_AMP * HW[p.sboxInMasked[j]];
          samples[SBOX_OUT_BASE + j] += LEAK_AMP * HW[p.sboxOutMasked[j]];
        }
      }

      visit(pt[cfg.targetByte], samples, this.emitted);
      this.emitted++;
    }
    return n;
  }
}

/**
 * Stream `count` traces, calling `visit` for each. The synchronous form, used
 * by the tests and by anything short enough not to need to yield.
 */
export function forEachTrace(
  cfg: BenchConfig,
  count: number,
  visit: (plaintextByte: number, samples: Float64Array, index: number) => void
): void {
  new TraceStream(cfg).take(count, visit);
}

export interface CapturedTrace {
  readonly plaintextByte: number;
  readonly samples: Float64Array;
}

/** Materialise a small number of traces, for the waveform display. */
export function captureTraces(cfg: BenchConfig, count: number): CapturedTrace[] {
  const out: CapturedTrace[] = [];
  forEachTrace(cfg, count, (plaintextByte, samples) => {
    out.push({ plaintextByte, samples: samples.slice() });
  });
  return out;
}
