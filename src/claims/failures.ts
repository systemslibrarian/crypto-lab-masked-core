/**
 * Every way this lab refuses, as exported constants with the exact wording the
 * page prints.
 *
 * They live here, in one place, for two reasons. First, a failure path is only
 * useful to a learner if the page says what actually went wrong rather than
 * going blank — so each of these is a teaching sentence, not an error code with
 * a number. Second, the claims suite asserts that driving each failure path
 * produces the matching text, and a test that re-types the string it is
 * checking proves nothing; importing the same constant the renderer uses means
 * the assertion is about behaviour, not about spelling.
 *
 * Fail-closed is the rule throughout: on any of these the affected panel prints
 * the cause and shows NO result, rather than showing a stale one from the
 * previous settings. A stale verdict beside a changed input is the specific
 * dishonesty this exists to prevent.
 */

export const FAILURES = {
  keyNotHex: 'Key rejected: expected 32 hexadecimal characters (16 bytes) and got something else. Nothing was measured.',
  keyWrongLength: 'Key rejected: AES-128 needs exactly 16 bytes. Nothing was measured.',
  constantNotByte: 'Frozen constant rejected: expected a single byte, 0x00 to 0xff. Nothing was measured.',
  traceCountTooLow: 'Trace count rejected: the attack needs at least 2 traces to have any variance to correlate against. Nothing was measured.',
  traceCountTooHigh: 'Trace count rejected: this bench is capped so a browser tab stays responsive. Nothing was measured.',
  noiseOutOfRange: 'Noise level rejected: sigma must be between 0 and 20 model units. Nothing was measured.',
  samePairSamples: 'Second-order pair rejected: combining a sample with itself squares one leakage instead of joining two, which cannot recover a masked value. Pick two different samples.',
  noDisclosure: 'No disclosure: the true key byte never reached rank 1 within the traces measured. That is a result, not an error.',
  frozenNeedsFrozen: 'This panel measures a frozen mask; the bench is currently drawing a fresh mask every encryption, so there is no constant to report.',
} as const;

export type FailureId = keyof typeof FAILURES;

/** Bench limits. Exported so the UI controls, the validation and the tests all
 *  read one number rather than three copies that can drift apart. */
export const LIMITS = {
  minTraces: 2,
  // High enough that the page can reproduce the recorded second-order claim on
  // its own schedule (120,000 traces) rather than on a shortened one that would
  // report a different traces-to-disclosure and quietly mean something else.
  // Streamed, never stored, and pulled in chunks, so it costs a few seconds of
  // arithmetic and no memory.
  maxTraces: 120000,
  minNoise: 0,
  maxNoise: 20,
} as const;

export interface Validated<T> {
  readonly ok: boolean;
  readonly value: T | null;
  readonly failure: string | null;
}

const ok = <T,>(value: T): Validated<T> => ({ ok: true, value, failure: null });
const bad = <T,>(failure: string): Validated<T> => ({ ok: false, value: null, failure });

/** Strict parsing: 32 hex characters, nothing else. No whitespace tolerance,
 *  no odd-length padding, no 0x prefix — a key is 16 bytes or it is refused. */
export function validateKeyHex(raw: string): Validated<string> {
  const s = raw.trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(s)) return bad(FAILURES.keyNotHex);
  if (s.length !== 32) return bad(FAILURES.keyWrongLength);
  return ok(s);
}

export function validateConstant(raw: string): Validated<number> {
  const s = raw.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{1,2}$/.test(s)) return bad(FAILURES.constantNotByte);
  return ok(parseInt(s, 16));
}

export function validateTraceCount(raw: number): Validated<number> {
  if (!Number.isFinite(raw) || Math.floor(raw) !== raw) return bad(FAILURES.traceCountTooLow);
  if (raw < LIMITS.minTraces) return bad(FAILURES.traceCountTooLow);
  if (raw > LIMITS.maxTraces) return bad(FAILURES.traceCountTooHigh);
  return ok(raw);
}

export function validateNoise(raw: number): Validated<number> {
  if (!Number.isFinite(raw) || raw < LIMITS.minNoise || raw > LIMITS.maxNoise) {
    return bad(FAILURES.noiseOutOfRange);
  }
  return ok(raw);
}

export function validatePair(a: number, b: number): Validated<[number, number]> {
  if (a === b) return bad(FAILURES.samePairSamples);
  return ok([a, b]);
}
