/**
 * Deterministic PRNG + Gaussian noise, carried over from `crypto-lab-power-trace`
 * (`src/leakage/rng.ts`) so the two labs' benches are directly comparable.
 *
 * Seeded on purpose. This lab's central claims are statistical — "first-order
 * CPA does not converge", "second-order CPA costs roughly this many traces" —
 * and a statistical claim measured on fresh randomness every run is a claim that
 * reddens the build on noise. A fixed seed plus a recorded traces-to-disclosure
 * BAND turns it into a deterministic gate: see `src/claims/bands.ts`.
 *
 * This randomness is the measurement-noise model AND the masks. That is not a
 * contradiction: nothing here is a security boundary, it is a bench. A real
 * masked implementation must draw its masks from a cryptographic RNG, and the
 * "Frozen mask" act is precisely what happens when that assumption fails.
 */
export class Rng {
  private a: number;
  private spare: number | null = null;

  constructor(seed: number) {
    this.a = seed >>> 0;
  }

  /** mulberry32 — a small, fast, well-distributed 32-bit generator. */
  next(): number {
    this.a = (this.a + 0x6d2b79f5) | 0;
    let t = Math.imul(this.a ^ (this.a >>> 15), 1 | this.a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  /** Uniform integer in [0, n). */
  int(n: number): number {
    return Math.floor(this.next() * n);
  }

  /** A uniform byte in [0, 256). */
  byte(): number {
    return this.int(256);
  }

  /** Standard normal via Box-Muller (mean 0, sd 1). */
  gaussian(): number {
    if (this.spare !== null) {
      const s = this.spare;
      this.spare = null;
      return s;
    }
    let u = 0;
    let v = 0;
    while (u === 0) u = this.next();
    while (v === 0) v = this.next();
    const mag = Math.sqrt(-2.0 * Math.log(u));
    this.spare = mag * Math.sin(2.0 * Math.PI * v);
    return mag * Math.cos(2.0 * Math.PI * v);
  }
}
