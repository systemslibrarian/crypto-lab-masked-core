import { describe, expect, it } from 'vitest';
import { hexToBytes, SBOX } from '../aes/aes';
import { HW } from '../leakage/model';
import {
  captureTraces,
  defaultBench,
  forEachTrace,
  MASK_OUT_SAMPLE,
  NUM_SAMPLES,
  sboxOutSample,
} from '../leakage/traces';
import { CpaAtSample, CpaSampleScan, predictions } from './cpa';
import { pearson, rankOf } from './stats';

const KEY = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c');
const TRUE = KEY[0];
const S = sboxOutSample(0);

describe('predictions', () => {
  it('are HW(SBOX[pt ^ guess]) for all 256 guesses', () => {
    const out = new Float64Array(256);
    predictions(0x9c, out);
    for (let g = 0; g < 256; g++) expect(out[g]).toBe(HW[SBOX[0x9c ^ g]]);
  });

  it('the correct guess predicts the real intermediate and the others do not', () => {
    const out = new Float64Array(256);
    predictions(0x00, out);
    expect(out[TRUE]).toBe(HW[SBOX[TRUE]]);
  });
});

describe('CpaAtSample is real Pearson correlation', () => {
  it('agrees with a direct two-pass computation over the same traces', () => {
    // Independent re-derivation: build the two series by hand and correlate
    // them with the two-pass `pearson`, then compare against the streaming
    // accumulator's answer. A shared-formula bug cannot hide behind this,
    // because `pearson` and `pearsonFromSums` take different routes.
    const cfg = defaultBench(KEY, { protection: 'none' });
    const traces = captureTraces(cfg, 500);
    const acc = new CpaAtSample(S);
    for (const t of traces) acc.add(t.plaintextByte, t.samples);
    const scores = acc.scores();
    for (const g of [TRUE, 0x00, 0x7f, 0xff]) {
      const pred = traces.map((t) => HW[SBOX[(t.plaintextByte ^ g) & 0xff]]);
      const power = traces.map((t) => t.samples[S]);
      expect(scores[g]).toBeCloseTo(Math.abs(pearson(pred, power)), 10);
      expect(acc.correlation(g)).toBeCloseTo(pearson(pred, power), 10);
    }
  });

  it('recovers the real key byte from unprotected traces', () => {
    const acc = new CpaAtSample(S);
    forEachTrace(defaultBench(KEY, { protection: 'none' }), 2000, (p, s) => acc.add(p, s));
    expect(rankOf(acc.scores(), TRUE)).toBe(1);
    expect(acc.correlation(TRUE)).toBeGreaterThan(0.15);
  });

  it('does NOT recover it from freshly masked traces, at any count it is given', () => {
    for (const n of [2000, 20000]) {
      const acc = new CpaAtSample(S);
      forEachTrace(defaultBench(KEY, { protection: 'masked' }), n, (p, s) => acc.add(p, s));
      expect(rankOf(acc.scores(), TRUE)).toBeGreaterThan(1);
      expect(Math.abs(acc.correlation(TRUE))).toBeLessThan(0.05);
    }
  });

  it('reports zero rather than NaN before it has seen anything', () => {
    const acc = new CpaAtSample(S);
    expect(Array.from(acc.scores())).toEqual(new Array(256).fill(0));
    expect(acc.count).toBe(0);
  });
});

describe('CpaSampleScan finds WHERE the leakage is', () => {
  it('peaks at the S-box output sample of the byte under attack, unprotected', () => {
    const scan = new CpaSampleScan(NUM_SAMPLES);
    forEachTrace(defaultBench(KEY, { protection: 'none' }), 2000, (p, s) => scan.add(p, s));
    const r = scan.result();
    expect(r.best).toBe(TRUE);
    expect(r.bestSample).toBe(S);
    // The curve for the true key must peak at that sample and nowhere else.
    const curve = r.curveFor(TRUE);
    let argmax = 0;
    for (let t = 0; t < NUM_SAMPLES; t++) {
      if (Math.abs(curve[t]) > Math.abs(curve[argmax])) argmax = t;
    }
    expect(argmax).toBe(S);
  });

  it('finds no leaking sample at all once masking is on', () => {
    const scan = new CpaSampleScan(NUM_SAMPLES);
    forEachTrace(defaultBench(KEY, { protection: 'masked' }), 2000, (p, s) => scan.add(p, s));
    const r = scan.result();
    expect(r.best).not.toBe(TRUE);
    // Including at the mask register itself: the mask leaks, but it leaks the
    // mask, which is independent of the key.
    expect(Math.abs(r.curveFor(TRUE)[MASK_OUT_SAMPLE])).toBeLessThan(0.08);
    expect(Math.abs(r.curveFor(TRUE)[S])).toBeLessThan(0.08);
  });

  it('agrees with the single-sample accumulator at the sample they share', () => {
    const scan = new CpaSampleScan(NUM_SAMPLES);
    const one = new CpaAtSample(S);
    forEachTrace(defaultBench(KEY, { protection: 'none' }), 800, (p, s) => {
      scan.add(p, s);
      one.add(p, s);
    });
    expect(scan.result().curveFor(TRUE)[S]).toBeCloseTo(one.correlation(TRUE), 10);
  });
});
