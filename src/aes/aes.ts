/**
 * AES-128 (FIPS-197), hand-rolled so every intermediate this lab attacks is
 * visible in source rather than buried in a library.
 *
 * Nothing here is a shortcut: the S-box is DERIVED — multiplicative inverse in
 * GF(2^8) modulo the AES polynomial x^8 + x^4 + x^3 + x + 1, then the AES affine
 * transform — rather than pasted as a magic table, because the S-box being the
 * one NON-LINEAR step is the entire reason masking needs table recomputation
 * (see ../mask/maskedAes.ts). A reader who does not believe the derivation can
 * read `deriveSbox` and check it against the FIPS-197 table, which is exactly
 * what `aes.test.ts` does.
 *
 * This is a teaching implementation. It is NOT constant-time (table lookups are
 * data-dependent, which is its own side channel — see the Timing Side-Channel
 * lab) and it is not production crypto.
 */

/** Multiply in GF(2^8) modulo the AES polynomial 0x11b. */
export function gmul(a: number, b: number): number {
  let p = 0;
  let x = a & 0xff;
  let y = b & 0xff;
  for (let i = 0; i < 8; i++) {
    if (y & 1) p ^= x;
    const hi = x & 0x80;
    x = (x << 1) & 0xff;
    if (hi) x ^= 0x1b;
    y >>= 1;
  }
  return p & 0xff;
}

/**
 * Multiplicative inverse in GF(2^8), by exponentiation: the group of non-zero
 * elements has order 255, so a^254 = a^-1. Zero has no inverse and AES maps it
 * to itself.
 */
export function ginv(a: number): number {
  if (a === 0) return 0;
  let result = 1;
  let base = a & 0xff;
  let e = 254;
  while (e > 0) {
    if (e & 1) result = gmul(result, base);
    base = gmul(base, base);
    e >>= 1;
  }
  return result;
}

/**
 * The AES S-box, derived rather than tabulated.
 *
 *   S(a) = affine( a^-1 ),  affine(x)_i = x_i ^ x_{i+4} ^ x_{i+5} ^ x_{i+6} ^ x_{i+7} ^ 0x63_i
 *
 * with the index rotations taken modulo 8. This is the single non-linear
 * component of AES; ShiftRows, MixColumns and AddRoundKey are all GF(2)-linear
 * or affine, which is why a Boolean mask passes through them untouched and jams
 * only here.
 */
export function deriveSbox(): Uint8Array {
  const s = new Uint8Array(256);
  for (let a = 0; a < 256; a++) {
    const inv = ginv(a);
    let x = inv;
    // Five rotations XORed together, then the constant 0x63.
    x ^= ((inv << 1) | (inv >>> 7)) & 0xff;
    x ^= ((inv << 2) | (inv >>> 6)) & 0xff;
    x ^= ((inv << 3) | (inv >>> 5)) & 0xff;
    x ^= ((inv << 4) | (inv >>> 4)) & 0xff;
    s[a] = (x ^ 0x63) & 0xff;
  }
  return s;
}

export const SBOX: Uint8Array = deriveSbox();

/** Inverse S-box, built by inverting the forward permutation. */
export const INV_SBOX: Uint8Array = (() => {
  const t = new Uint8Array(256);
  for (let a = 0; a < 256; a++) t[SBOX[a]] = a;
  return t;
})();

export const NUM_ROUNDS = 10;
export const BLOCK_BYTES = 16;
export const KEY_BYTES = 16;

/** AES-128 key expansion: 11 round keys of 16 bytes each (FIPS-197 5.2). */
export function expandKey(key: Uint8Array): Uint8Array[] {
  if (key.length !== KEY_BYTES) throw new Error(`AES-128 needs a 16-byte key, got ${key.length}`);
  const w = new Uint8Array(16 * (NUM_ROUNDS + 1));
  w.set(key, 0);
  let rcon = 1;
  for (let i = 4; i < 4 * (NUM_ROUNDS + 1); i++) {
    let t0 = w[(i - 1) * 4 + 0];
    let t1 = w[(i - 1) * 4 + 1];
    let t2 = w[(i - 1) * 4 + 2];
    let t3 = w[(i - 1) * 4 + 3];
    if (i % 4 === 0) {
      // RotWord then SubWord then XOR Rcon.
      const r0 = t1;
      const r1 = t2;
      const r2 = t3;
      const r3 = t0;
      t0 = SBOX[r0] ^ rcon;
      t1 = SBOX[r1];
      t2 = SBOX[r2];
      t3 = SBOX[r3];
      rcon = gmul(rcon, 2);
    }
    w[i * 4 + 0] = w[(i - 4) * 4 + 0] ^ t0;
    w[i * 4 + 1] = w[(i - 4) * 4 + 1] ^ t1;
    w[i * 4 + 2] = w[(i - 4) * 4 + 2] ^ t2;
    w[i * 4 + 3] = w[(i - 4) * 4 + 3] ^ t3;
  }
  const roundKeys: Uint8Array[] = [];
  for (let r = 0; r <= NUM_ROUNDS; r++) roundKeys.push(w.slice(r * 16, r * 16 + 16));
  return roundKeys;
}

/** ShiftRows on a column-major state (FIPS-197 5.1.2). Pure permutation. */
export const SHIFT_ROWS: readonly number[] = [
  0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11,
];

export function shiftRows(state: Uint8Array): void {
  const t = state.slice();
  for (let i = 0; i < 16; i++) state[i] = t[SHIFT_ROWS[i]];
}

/**
 * MixColumns (FIPS-197 5.1.3) — GF(2)-LINEAR, which is the property masking
 * leans on: MixColumns(x ^ m) = MixColumns(x) ^ MixColumns(m), so a masked
 * state passes straight through and the mask is simply carried along.
 * `maskedAes.test.ts` asserts that identity directly rather than assuming it.
 */
export function mixColumns(state: Uint8Array): void {
  for (let c = 0; c < 4; c++) {
    const i = c * 4;
    const a0 = state[i];
    const a1 = state[i + 1];
    const a2 = state[i + 2];
    const a3 = state[i + 3];
    state[i] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
    state[i + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
    state[i + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
    state[i + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
  }
}

export function addRoundKey(state: Uint8Array, rk: Uint8Array): void {
  for (let i = 0; i < 16; i++) state[i] ^= rk[i];
}

export function subBytes(state: Uint8Array): void {
  for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

/** Encrypt one 16-byte block with AES-128. */
export function encryptBlock(plaintext: Uint8Array, key: Uint8Array): Uint8Array {
  if (plaintext.length !== BLOCK_BYTES) {
    throw new Error(`AES block is 16 bytes, got ${plaintext.length}`);
  }
  const rk = expandKey(key);
  const state = plaintext.slice();
  addRoundKey(state, rk[0]);
  for (let r = 1; r < NUM_ROUNDS; r++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, rk[r]);
  }
  subBytes(state);
  shiftRows(state);
  addRoundKey(state, rk[NUM_ROUNDS]);
  return state;
}

/**
 * The register values a power probe would see during round 1, for every byte
 * position, taken from the SAME code path `encryptBlock` runs.
 *
 * `sboxIn[j]  = pt[j] ^ key[j]`        — the first AddRoundKey output
 * `sboxOut[j] = SBOX[pt[j] ^ key[j]]`  — the classic CPA target
 *
 * The trace generator reads these rather than re-deriving them, so a trace can
 * never disagree with the cipher: if this were wrong, the FIPS-197 KATs on
 * `encryptBlock` would be wrong too.
 */
export interface Round1Probes {
  sboxIn: Uint8Array;
  sboxOut: Uint8Array;
}

export function round1Probes(plaintext: Uint8Array, roundKey0: Uint8Array): Round1Probes {
  const sboxIn = new Uint8Array(16);
  const sboxOut = new Uint8Array(16);
  for (let j = 0; j < 16; j++) {
    sboxIn[j] = plaintext[j] ^ roundKey0[j];
    sboxOut[j] = SBOX[sboxIn[j]];
  }
  return { sboxIn, sboxOut };
}

// ── hex helpers ──────────────────────────────────────────────────────────────

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error(`not hex: ${hex}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: ArrayLike<number>): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
