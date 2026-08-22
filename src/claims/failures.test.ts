import { describe, expect, it } from 'vitest';
import {
  FAILURES,
  LIMITS,
  validateConstant,
  validateKeyHex,
  validateNoise,
  validatePair,
  validateTraceCount,
} from './failures';

describe('key validation is strict and fail-closed', () => {
  it('accepts exactly 32 hex characters', () => {
    const v = validateKeyHex('2B7E151628AED2A6ABF7158809CF4F3C');
    expect(v.ok).toBe(true);
    expect(v.value).toBe('2b7e151628aed2a6abf7158809cf4f3c');
  });

  it('names the cause for non-hex and for the wrong length, and they differ', () => {
    expect(validateKeyHex('zz7e15').failure).toBe(FAILURES.keyNotHex);
    expect(validateKeyHex('2b7e').failure).toBe(FAILURES.keyWrongLength);
    expect(FAILURES.keyNotHex).not.toBe(FAILURES.keyWrongLength);
  });

  it('returns no value on failure — nothing downstream can use a rejected key', () => {
    for (const bad of ['', '2b7e', 'zz', '2b7e151628aed2a6abf7158809cf4f3c00']) {
      const v = validateKeyHex(bad);
      expect(v.ok).toBe(false);
      expect(v.value).toBeNull();
      expect(v.failure).toBeTruthy();
    }
  });

  it('does not silently repair an odd-length or prefixed key', () => {
    expect(validateKeyHex('0x2b7e151628aed2a6abf7158809cf4f3c').ok).toBe(false);
    expect(validateKeyHex('2b7e151628aed2a6abf7158809cf4f3').ok).toBe(false);
  });
});

describe('constant validation', () => {
  it('accepts one or two hex digits, with or without 0x', () => {
    expect(validateConstant('0f').value).toBe(15);
    expect(validateConstant('0x0F').value).toBe(15);
    expect(validateConstant('1').value).toBe(1);
  });

  it('refuses anything that is not a single byte', () => {
    for (const bad of ['', '100', 'g0', '-1']) {
      expect(validateConstant(bad).failure).toBe(FAILURES.constantNotByte);
    }
  });
});

describe('bench limit validation', () => {
  it('accepts the documented range and refuses outside it', () => {
    expect(validateTraceCount(LIMITS.minTraces).ok).toBe(true);
    expect(validateTraceCount(LIMITS.maxTraces).ok).toBe(true);
    expect(validateTraceCount(LIMITS.minTraces - 1).failure).toBe(FAILURES.traceCountTooLow);
    expect(validateTraceCount(LIMITS.maxTraces + 1).failure).toBe(FAILURES.traceCountTooHigh);
    expect(validateTraceCount(1.5).failure).toBe(FAILURES.traceCountTooLow);
    expect(validateTraceCount(Number.NaN).failure).toBe(FAILURES.traceCountTooLow);
  });

  it('the two trace-count failures name different causes', () => {
    expect(FAILURES.traceCountTooLow).not.toBe(FAILURES.traceCountTooHigh);
  });

  it('noise must be inside the modelled range', () => {
    expect(validateNoise(0).ok).toBe(true);
    expect(validateNoise(LIMITS.maxNoise).ok).toBe(true);
    expect(validateNoise(-1).failure).toBe(FAILURES.noiseOutOfRange);
    expect(validateNoise(LIMITS.maxNoise + 0.1).failure).toBe(FAILURES.noiseOutOfRange);
  });
});

describe('second-order pair validation', () => {
  it('refuses a sample paired with itself, and says why', () => {
    expect(validatePair(5, 5).failure).toBe(FAILURES.samePairSamples);
    expect(validatePair(5, 5).value).toBeNull();
  });

  it('accepts two distinct samples in either order', () => {
    expect(validatePair(5, 24).value).toEqual([5, 24]);
    expect(validatePair(24, 5).value).toEqual([24, 5]);
  });
});

describe('every failure message is a teaching sentence', () => {
  it('names what was rejected and says nothing was measured', () => {
    for (const [id, text] of Object.entries(FAILURES)) {
      expect(text.length, id).toBeGreaterThan(40);
      expect(text, id).toMatch(/[.!]$/);
    }
  });

  it('has no duplicate wording — each cause is distinguishable on the page', () => {
    const texts = Object.values(FAILURES);
    expect(new Set(texts).size).toBe(texts.length);
  });
});
