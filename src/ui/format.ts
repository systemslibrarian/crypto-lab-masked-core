/** Display formatting. Kept in one place so the page and the claims suite
 *  parse the same shapes. */

export function hexByte(b: number): string {
  return `0x${(b & 0xff).toString(16).padStart(2, '0')}`;
}

export function bin8(b: number): string {
  return (b & 0xff).toString(2).padStart(8, '0');
}

/** Correlations are printed to four places; the claims suite parses this. */
export function r4(v: number): string {
  return v.toFixed(4);
}

export function num(v: number): string {
  return v.toLocaleString('en-US');
}

export function signWord(v: number): string {
  if (v > 0) return 'positive';
  if (v < 0) return 'negative';
  return 'zero';
}
