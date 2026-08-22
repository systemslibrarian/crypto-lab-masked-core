/**
 * Real Pearson product-moment correlation, carried over from
 * `crypto-lab-power-trace` (`src/attack/stats.ts`) unchanged — this is the
 * statistic that turns a pile of noisy traces into a key, and the two labs
 * should be using literally the same one.
 */

/** Pearson r between two equal-length series. Returns 0 if either has no variance. */
export function pearson(x: ArrayLike<number>, y: ArrayLike<number>): number {
  const n = x.length;
  if (n === 0 || y.length !== n) return 0;
  let sx = 0;
  let sy = 0;
  for (let i = 0; i < n; i++) {
    sx += x[i];
    sy += y[i];
  }
  const mx = sx / n;
  const my = sy / n;
  let cov = 0;
  let vx = 0;
  let vy = 0;
  for (let i = 0; i < n; i++) {
    const dx = x[i] - mx;
    const dy = y[i] - my;
    cov += dx * dy;
    vx += dx * dx;
    vy += dy * dy;
  }
  if (vx === 0 || vy === 0) return 0;
  return cov / Math.sqrt(vx * vy);
}

/**
 * Pearson r from raw prefix sums, so a correlation can be read off at any trace
 * count in a single streaming pass:
 *
 *     r = (n*Sxy - Sx*Sy) / sqrt((n*Sxx - Sx^2)(n*Syy - Sy^2))
 *
 * Algebraically identical to the two-pass form above; `stats.test.ts` measures
 * that rather than trusting it.
 */
export function pearsonFromSums(
  n: number,
  sx: number,
  sy: number,
  sxx: number,
  syy: number,
  sxy: number
): number {
  if (n < 2) return 0;
  const denX = n * sxx - sx * sx;
  const denY = n * syy - sy * sy;
  if (denX <= 0 || denY <= 0) return 0;
  return (n * sxy - sx * sy) / Math.sqrt(denX * denY);
}

/** Guess indices sorted by score, descending. */
export function rankingOf(scores: ArrayLike<number>): number[] {
  return Array.from({ length: scores.length }, (_, i) => i).sort((a, b) => scores[b] - scores[a]);
}

/** 1-based rank of `value` in the descending score order (1 = recovered). */
export function rankOf(scores: ArrayLike<number>, value: number): number {
  let rank = 1;
  const s = scores[value];
  for (let i = 0; i < scores.length; i++) if (i !== value && scores[i] > s) rank++;
  return rank;
}

/** The best score among all guesses EXCEPT `value` — the noise floor to beat. */
export function bestExcluding(scores: ArrayLike<number>, value: number): number {
  let best = -Infinity;
  for (let i = 0; i < scores.length; i++) if (i !== value && scores[i] > best) best = scores[i];
  return best;
}
