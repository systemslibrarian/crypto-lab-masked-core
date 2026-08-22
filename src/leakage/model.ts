/**
 * The leakage model, carried over from `crypto-lab-power-trace`
 * (`src/leakage/model.ts`).
 *
 * A CMOS gate draws current in proportion to the number of bits it drives high
 * (Hamming weight). That single assumption is the whole basis of this lab's
 * measurements, and it is an ASSUMPTION — stated on the page, persistently,
 * because every claim downstream inherits it. Real silicon leaks a noisier and
 * more complex function of its state, and glitches, coupling and transitions
 * leak things this model has no term for at all. See the Scope panel.
 */

/** Precomputed Hamming weight of every byte (popcount 0..8). */
export const HW: Uint8Array = (() => {
  const t = new Uint8Array(256);
  for (let b = 0; b < 256; b++) {
    let v = b;
    let c = 0;
    while (v) {
      c += v & 1;
      v >>= 1;
    }
    t[b] = c;
  }
  return t;
})();

/** Mean Hamming weight of a uniform byte — the centre the combining uses. */
export const HW_MEAN = 4;

export function hammingWeight(byte: number): number {
  return HW[byte & 0xff];
}
