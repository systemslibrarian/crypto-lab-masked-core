/**
 * First-order Boolean masking of AES-128, with a recomputed S-box table.
 *
 * THE IDEA. Carry every intermediate x as a pair (x ^ m, m) for a fresh random
 * mask m. Neither half is a function of x on its own — x ^ m is uniform for
 * uniform m, and m is uniform regardless — so a probe that sees ONE value at a
 * time learns nothing about x. That is the first-order security claim, and it
 * is a claim about the probing/leakage model, not about silicon.
 *
 * WHY THE S-BOX IS THE HARD PART. AddRoundKey, ShiftRows and MixColumns are all
 * GF(2)-linear or affine, so they commute with the mask: apply them to the
 * masked value and to the mask separately and the pair still represents the
 * same x (`aes.test.ts` measures both identities rather than asserting them).
 * The S-box is the one non-linear step: SBOX[x ^ m] is not SBOX[x] ^ anything
 * you know. The classic answer, and the one used here, is TABLE RECOMPUTATION —
 * build, per round, a fresh 256-entry table
 *
 *     S'[a] = SBOX[a ^ mIn] ^ mOut
 *
 * so that S'[x ^ mIn] = SBOX[x] ^ mOut. The lookup converts a value masked with
 * mIn into the S-box output masked with mOut, and x itself never exists in any
 * register.
 *
 * THE RULE THAT MAKES IT WORK. No step may ever compute a value that depends on
 * x without a mask on it. Re-masking is where that is easy to get wrong: to move
 * byte j from mask[j] to the round's shared mIn you must form the MASK-DOMAIN
 * difference `d = mask[j] ^ mIn` FIRST and then XOR it into the masked state.
 * Writing `state[j] ^ mask[j] ^ mIn` left to right unmasks x for one instruction
 * and hands a first-order probe the plaintext-equivalent value. `remaskDelta`
 * exists to make that ordering explicit and hard to fumble.
 *
 * WHAT THIS IS NOT. First order, one share, one table per round, and a mask
 * drawn from a seeded bench PRNG. It is not a threshold implementation, it does
 * not resist glitches, and the security argument is in the probing model only.
 * See the Scope panel and the README.
 */
import {
  addRoundKey,
  BLOCK_BYTES,
  expandKey,
  KEY_BYTES,
  mixColumns,
  NUM_ROUNDS,
  SBOX,
  shiftRows,
} from '../aes/aes';
import type { Rng } from '../leakage/rng';

/**
 * Where the round's masks come from. `fresh` is the countermeasure working as
 * designed; `frozen` is the same countermeasure with its randomness removed —
 * the mask is pinned to one constant for every encryption, so the masked value
 * becomes a deterministic function of the unmasked one. Act 4 is that failure.
 */
export type MaskSource =
  | { readonly kind: 'fresh' }
  | { readonly kind: 'frozen'; readonly constant: number };

export interface RoundMasks {
  readonly mIn: number;
  readonly mOut: number;
}

export function drawRoundMasks(source: MaskSource, rng: Rng): RoundMasks {
  if (source.kind === 'frozen') {
    // Both masks pinned to the SAME constant, every round, every encryption.
    // Nothing varies, so nothing is hidden: see `src/mask/frozen.ts`.
    return { mIn: source.constant & 0xff, mOut: source.constant & 0xff };
  }
  return { mIn: rng.byte(), mOut: rng.byte() };
}

/**
 * The recomputed masked S-box: S'[a] = SBOX[a ^ mIn] ^ mOut.
 *
 * Built by walking all 256 entries, which is what a real implementation does
 * once per round (and what makes masking expensive). The table is the object
 * the second-order attack ends up exploiting, because building it puts mOut on
 * a bus of its own.
 */
export function recomputeSboxTable(mIn: number, mOut: number): Uint8Array {
  const t = new Uint8Array(256);
  const a0 = mIn & 0xff;
  const b0 = mOut & 0xff;
  for (let a = 0; a < 256; a++) t[a] = SBOX[a ^ a0] ^ b0;
  return t;
}

/**
 * The mask-domain delta that moves byte j from its current mask to `mIn`.
 *
 * Deliberately its own function. It touches only mask material, never the
 * masked state, so no ordering of these operations can transiently unmask x.
 */
export function remaskDelta(currentMask: number, mIn: number): number {
  return (currentMask ^ mIn) & 0xff;
}

/** Register values a probe would see during one masked round, byte by byte. */
export interface MaskedRoundProbes {
  /** The round's input mask register, mIn. */
  readonly maskIn: number;
  /** The round's output mask register, mOut — the second-order attack's partner. */
  readonly maskOut: number;
  /** Masked S-box input per byte: (x_j ^ k_j) ^ mIn. */
  readonly sboxInMasked: Uint8Array;
  /** Masked S-box output per byte: SBOX[x_j ^ k_j] ^ mOut. */
  readonly sboxOutMasked: Uint8Array;
}

/**
 * One masked round, in place. `state` holds x ^ mask; `mask` holds the mask.
 * `last` omits MixColumns, as AES's final round does.
 *
 * This is the ONLY masked-round implementation in the lab: `encryptMasked`
 * calls it ten times and the trace generator calls it once. A bench that ran a
 * different, cheaper round than the cipher would be measuring a fiction, so
 * there is no second copy to drift.
 */
export function maskedRound(
  state: Uint8Array,
  mask: Uint8Array,
  roundKey: Uint8Array,
  masks: RoundMasks,
  last: boolean
): MaskedRoundProbes {
  const table = recomputeSboxTable(masks.mIn, masks.mOut);

  // Re-mask every byte onto the round's shared mIn, mask-domain first.
  for (let j = 0; j < 16; j++) {
    const d = remaskDelta(mask[j], masks.mIn);
    state[j] ^= d;
    mask[j] = masks.mIn;
  }
  const sboxInMasked = state.slice();

  // The masked substitution. x never appears; only x ^ mIn goes into the table.
  for (let j = 0; j < 16; j++) {
    state[j] = table[state[j]];
    mask[j] = masks.mOut;
  }
  const sboxOutMasked = state.slice();

  // Linear layers act on the masked value and on the mask alike.
  shiftRows(state);
  shiftRows(mask);
  if (!last) {
    mixColumns(state);
    mixColumns(mask);
  }
  addRoundKey(state, roundKey); // the key is public to the mask; it is not masked

  return { maskIn: masks.mIn, maskOut: masks.mOut, sboxInMasked, sboxOutMasked };
}

export interface MaskedResult {
  /** The unmasked ciphertext — identical to plain AES-128 or the masking is broken. */
  readonly ciphertext: Uint8Array;
  /** The masked state as it stood before the final unmask, for display. */
  readonly maskedStateBeforeUnmask: Uint8Array;
  /** The accumulated mask at that same moment. */
  readonly finalMask: Uint8Array;
  /** Round-1 probes — what the bench measures. */
  readonly round1: MaskedRoundProbes;
  /** Every round's (mIn, mOut) pair, for the construction panel. */
  readonly roundMasks: readonly RoundMasks[];
  /** The initial per-byte input mask. */
  readonly initialMask: Uint8Array;
}

/**
 * Masked AES-128 encryption. Returns the same ciphertext as `encryptBlock` for
 * every input and every mask — which is the correctness invariant the whole
 * countermeasure has to satisfy before any security claim is worth discussing,
 * and is exactly what `maskedAes.test.ts` checks against the FIPS-197 vectors
 * over hundreds of random mask draws.
 */
export function encryptMasked(
  plaintext: Uint8Array,
  key: Uint8Array,
  rng: Rng,
  source: MaskSource = { kind: 'fresh' }
): MaskedResult {
  if (plaintext.length !== BLOCK_BYTES) {
    throw new Error(`AES block is 16 bytes, got ${plaintext.length}`);
  }
  if (key.length !== KEY_BYTES) {
    throw new Error(`AES-128 needs a 16-byte key, got ${key.length}`);
  }
  const rk = expandKey(key);

  // Split the plaintext into (pt ^ m, m) before anything touches it.
  const initialMask = new Uint8Array(16);
  for (let j = 0; j < 16; j++) {
    initialMask[j] = source.kind === 'frozen' ? source.constant & 0xff : rng.byte();
  }
  const state = Uint8Array.from(plaintext, (v, j) => v ^ initialMask[j]);
  const mask = initialMask.slice();

  addRoundKey(state, rk[0]);

  const roundMasks: RoundMasks[] = [];
  let round1: MaskedRoundProbes | null = null;
  for (let r = 1; r <= NUM_ROUNDS; r++) {
    const masks = drawRoundMasks(source, rng);
    roundMasks.push(masks);
    const probes = maskedRound(state, mask, rk[r], masks, r === NUM_ROUNDS);
    if (r === 1) round1 = probes;
  }

  const maskedStateBeforeUnmask = state.slice();
  const finalMask = mask.slice();
  const ciphertext = Uint8Array.from(state, (v, j) => v ^ mask[j]);

  return {
    ciphertext,
    maskedStateBeforeUnmask,
    finalMask,
    round1: round1!,
    roundMasks,
    initialMask,
  };
}

/**
 * Round-1 probes only — what a trace of the first round measures.
 *
 * Runs the real initial AddRoundKey and the real `maskedRound`, then stops.
 * Streaming tens of thousands of traces through all ten rounds would spend 90%
 * of its time on rounds a first-round attack never looks at; stopping after
 * round 1 changes nothing about the values probed, because they are produced by
 * the same function `encryptMasked` calls.
 */
export function maskedRound1Probes(
  plaintext: Uint8Array,
  roundKey0: Uint8Array,
  roundKey1: Uint8Array,
  rng: Rng,
  source: MaskSource
): MaskedRoundProbes {
  const initialMask = new Uint8Array(16);
  for (let j = 0; j < 16; j++) {
    initialMask[j] = source.kind === 'frozen' ? source.constant & 0xff : rng.byte();
  }
  const state = Uint8Array.from(plaintext, (v, j) => v ^ initialMask[j]);
  const mask = initialMask.slice();
  addRoundKey(state, roundKey0);
  return maskedRound(state, mask, roundKey1, drawRoundMasks(source, rng), false);
}
