import { describe, expect, it } from 'vitest';
import { hexToBytes } from '../aes/aes';
import { defaultBench, sboxOutSample } from '../leakage/traces';
import { CpaAtSample, type Distinguisher } from './cpa';
import { geometricCheckpoints, normaliseCheckpoints, runDisclosure } from './ttd';

const KEY = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c');
const TRUE = KEY[0];
const S = sboxOutSample(0);

/** A distinguisher whose scoreboard is scripted, so the stability rule can be
 *  tested on a known rank sequence instead of on a statistical accident. */
class Scripted implements Distinguisher {
  count = 0;
  constructor(private readonly rankOneAt: (n: number) => boolean) {}
  add(): void {
    this.count++;
  }
  scores(): Float64Array {
    const s = new Float64Array(256);
    s[TRUE] = this.rankOneAt(this.count) ? 1 : 0;
    s[(TRUE + 1) & 0xff] = 0.5;
    return s;
  }
}

describe('the stability rule', () => {
  const checkpoints = [10, 20, 30, 40, 50];
  const cfg = defaultBench(KEY);

  it('reports the first checkpoint from which rank 1 holds to the END', () => {
    // Rank 1 at 10, then lost at 20-30, then held from 40. `power-trace`'s
    // first-recovery rule would answer 10; near a disclosure threshold that
    // flicker is exactly what a band gate must not inherit.
    const run = runDisclosure(cfg, new Scripted((n) => n === 10 || n >= 40), checkpoints, TRUE);
    expect(run.points.map((p) => p.recovered)).toEqual([true, false, false, true, true]);
    expect(run.ttd).toBe(40);
  });

  it('is null when the last checkpoint is not rank 1', () => {
    expect(runDisclosure(cfg, new Scripted((n) => n < 50), checkpoints, TRUE).ttd).toBeNull();
  });

  it('is the first checkpoint when it holds throughout', () => {
    expect(runDisclosure(cfg, new Scripted(() => true), checkpoints, TRUE).ttd).toBe(10);
  });

  it('is null when it never recovers at all', () => {
    expect(runDisclosure(cfg, new Scripted(() => false), checkpoints, TRUE).ttd).toBeNull();
  });

  it('evaluates at every checkpoint exactly once, in order', () => {
    const run = runDisclosure(cfg, new Scripted(() => true), [50, 10, 30, 10], TRUE);
    expect(run.points.map((p) => p.numTraces)).toEqual([10, 30, 50]);
    expect(run.maxTraces).toBe(50);
  });
});

describe('checkpoint schedules', () => {
  it('normalise drops sub-2 counts, dedupes and sorts', () => {
    expect(normaliseCheckpoints([50, 1, 10, 10, 0, 30])).toEqual([10, 30, 50]);
  });

  it('geometric schedules increase and end exactly on the requested maximum', () => {
    const s = geometricCheckpoints(100, 10000, 6);
    expect(s[0]).toBe(100);
    expect(s.at(-1)).toBe(10000);
    for (let i = 1; i < s.length; i++) expect(s[i]).toBeGreaterThan(s[i - 1]);
  });
});

describe('a real run reports the numbers the page shows', () => {
  it('carries the correct byte, the wrong-guess floor, and the rank at each point', () => {
    const run = runDisclosure(
      defaultBench(KEY, { protection: 'none' }),
      new CpaAtSample(S),
      [100, 1000, 3000],
      TRUE
    );
    expect(run.trueKeyByte).toBe(TRUE);
    const last = run.points.at(-1)!;
    expect(last.numTraces).toBe(3000);
    expect(last.correctRank).toBe(1);
    expect(last.correctScore).toBeGreaterThan(last.topWrongScore);
    expect(last.correctSigned).toBeGreaterThan(0);
  }, 60_000);
});
