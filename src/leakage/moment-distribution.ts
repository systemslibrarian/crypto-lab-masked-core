/** Exact, separate teaching model: four binary shares with XOR = secret.
 * Observe their JOINT Hamming-weight sum plus independent centered binomial
 * noise. This is not the AES bench's one-register/Gaussian trace model. */
export interface Distribution {
  readonly values: readonly number[];
  readonly probabilities: readonly number[];
}

export function shareSumDistribution(secret: number, noiseCoins: number): Distribution {
  if ((secret !== 0 && secret !== 1) || !Number.isInteger(noiseCoins) || noiseCoins < 0 || noiseCoins > 8) {
    throw new RangeError('Use secret 0 or 1 and 0–8 independent noise coins.');
  }
  let probabilities = Array<number>(5).fill(0);
  for (let tuple = 0; tuple < 16; tuple++) {
    let weight = 0;
    for (let bit = 0; bit < 4; bit++) weight += (tuple >> bit) & 1;
    if (weight % 2 === secret) probabilities[weight] += 1 / 8;
  }
  // Convolve exactly with N fair bits, then center their sum by N/2.
  for (let coin = 0; coin < noiseCoins; coin++) {
    const next = Array<number>(probabilities.length + 1).fill(0);
    probabilities.forEach((p, i) => { next[i] += p / 2; next[i + 1] += p / 2; });
    probabilities = next;
  }
  return { values: probabilities.map((_, i) => i - noiseCoins / 2), probabilities };
}

export function rawMoment(distribution: Distribution, order: number): number {
  if (!Number.isInteger(order) || order < 1 || order > 4) throw new RangeError('Choose moment 1–4.');
  return distribution.probabilities.reduce((sum, p, i) => sum + p * distribution.values[i] ** order, 0);
}

export function distributionDistance(a: Distribution, b: Distribution): number {
  if (a.values.length !== b.values.length || a.values.some((v, i) => v !== b.values[i])) {
    throw new RangeError('Compare distributions on the same displayed support.');
  }
  return a.probabilities.reduce((sum, p, i) => sum + Math.abs(p - b.probabilities[i]), 0) / 2;
}
