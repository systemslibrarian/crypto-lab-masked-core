/**
 * Traces to disclosure, and the checkpoint curve behind it.
 *
 * ── THE STABILITY RULE ──────────────────────────────────────────────────────
 *
 * `power-trace`'s `minTracesToRecover` returns the FIRST checkpoint at which
 * the true key byte ranks first. That is the right answer for a demo that wants
 * to show a spike separating; it is the wrong answer for a CI gate, because
 * near the disclosure threshold the rank flickers and one lucky early
 * checkpoint moves the reported number by an order of magnitude.
 *
 * So this returns the smallest checkpoint from which the true byte ranks first
 * AND KEEPS RANKING FIRST for every later checkpoint in the schedule. It is a
 * stricter, much steadier statistic — which is what makes a recorded band
 * around it a gate rather than a coin flip.
 *
 * A null result means "no disclosure within this schedule", which is a claim in
 * its own right: it is what act 2 asserts about first-order CPA against fresh
 * masking, and a run that suddenly DID disclose would mean the leakage model
 * had broken, not that the attack got cleverer.
 */
import { forEachTrace, type BenchConfig } from '../leakage/traces';
import type { Distinguisher } from './cpa';
import { bestExcluding, rankOf } from './stats';

export interface CheckpointPoint {
  readonly numTraces: number;
  /** The distinguisher's absolute score for the true key byte. */
  readonly correctScore: number;
  /** The best score among the 255 wrong guesses — the floor it has to clear. */
  readonly topWrongScore: number;
  readonly correctRank: number;
  /** Signed correlation / difference for the true byte, where the
   *  distinguisher reports one. The SIGN carries meaning at second order. */
  readonly correctSigned: number | null;
  readonly recovered: boolean;
}

export interface DisclosureRun {
  readonly points: readonly CheckpointPoint[];
  /** Smallest checkpoint from which rank 1 holds to the end; null if never. */
  readonly ttd: number | null;
  readonly maxTraces: number;
  readonly trueKeyByte: number;
}

interface Signed {
  correlation(guess: number): number;
}
interface Differenced {
  difference(guess: number): number;
}

function signedFor(d: Distinguisher, guess: number): number | null {
  const maybeSigned = d as Partial<Signed & Differenced>;
  if (typeof maybeSigned.correlation === 'function') return maybeSigned.correlation(guess);
  if (typeof maybeSigned.difference === 'function') return maybeSigned.difference(guess);
  return null;
}

export function normaliseCheckpoints(checkpoints: readonly number[]): number[] {
  return Array.from(new Set(checkpoints.filter((n) => n >= 2))).sort((a, b) => a - b);
}

/**
 * Stream traces through `distinguisher`, reading the scoreboard at each
 * checkpoint. One pass, whatever the schedule length.
 */
export function runDisclosure(
  cfg: BenchConfig,
  distinguisher: Distinguisher,
  checkpoints: readonly number[],
  trueKeyByte: number
): DisclosureRun {
  const sorted = normaliseCheckpoints(checkpoints);
  const maxN = sorted[sorted.length - 1] ?? 0;
  const points: CheckpointPoint[] = [];
  let next = 0;

  forEachTrace(cfg, maxN, (plaintextByte, samples) => {
    distinguisher.add(plaintextByte, samples);
    while (next < sorted.length && distinguisher.count === sorted[next]) {
      const scores = distinguisher.scores();
      const rank = rankOf(scores, trueKeyByte);
      points.push({
        numTraces: distinguisher.count,
        correctScore: scores[trueKeyByte],
        topWrongScore: bestExcluding(scores, trueKeyByte),
        correctRank: rank,
        correctSigned: signedFor(distinguisher, trueKeyByte),
        recovered: rank === 1,
      });
      next++;
    }
  });

  let ttd: number | null = null;
  for (let i = points.length - 1; i >= 0; i--) {
    if (!points[i].recovered) break;
    ttd = points[i].numTraces;
  }

  return { points, ttd, maxTraces: maxN, trueKeyByte };
}

/** A geometric-ish schedule: dense where the curve moves, sparse after. */
export function geometricCheckpoints(from: number, to: number, perDecade = 8): number[] {
  const out: number[] = [];
  const ratio = Math.pow(10, 1 / perDecade);
  let n = from;
  while (n < to) {
    out.push(Math.round(n));
    n *= ratio;
  }
  out.push(to);
  return normaliseCheckpoints(out);
}
