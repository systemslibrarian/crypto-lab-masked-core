/**
 * "Cost" — masking as a price, expressed in traces.
 *
 * The table is the recorded claim set that gates CI: a fixed seed, a fixed
 * checkpoint schedule, and a band the traces-to-disclosure has to land in. The
 * button re-runs any one of them live, on the SAME schedule the band was
 * recorded against, so the number on screen is comparable to the number in the
 * band rather than merely similar to it.
 *
 * An honest caveat sits on the axis label and is repeated here: the "order" in
 * this table is the ATTACK's order, not the masking order. Only first-order
 * masking is implemented. A d-th order scheme needs an order-(d+1) attack and
 * the trace counts climb steeply enough that a browser could not run the
 * demonstration; claiming otherwise from a first-order bench would be inventing
 * data.
 */
import { hexToBytes } from '../../aes/aes';
import { CpaAtSample } from '../../attack/cpa';
import { BitDpaAtSample } from '../../attack/dpa';
import { SecondOrderCpa } from '../../attack/secondOrder';
import { rankOf } from '../../attack/stats';
import {
  COST_RATIO_FLOOR,
  DISCLOSURE_CLAIMS,
  FIXTURE,
  NON_DISCLOSURE_CLAIMS,
  SCHEDULES,
} from '../../claims/bands';
import { FAILURES } from '../../claims/failures';
import type { Distinguisher } from '../../attack/cpa';
import {
  defaultBench,
  MASK_OUT_SAMPLE,
  sboxOutSample,
  TraceStream,
  type BenchConfig,
} from '../../leakage/traces';
import { drawChart, makeChart } from '../charts';
import { el, kv, labelled, nextFrame, pill, replace, scroller, verdict } from '../dom';
import { num } from '../format';

interface Runnable {
  readonly config: BenchConfig;
  readonly schedule: readonly number[];
  make(): Distinguisher;
}

export function renderCost(root: HTMLElement): void {
  const key = hexToBytes(FIXTURE.keyHex);
  const trueByte = key[FIXTURE.targetByte];
  const sample = sboxOutSample(FIXTURE.targetByte);
  const base = (over: Parameters<typeof defaultBench>[1]): BenchConfig =>
    defaultBench(key, {
      targetByte: FIXTURE.targetByte,
      noise: FIXTURE.noise,
      seed: FIXTURE.seed,
      ...over,
    });

  const RUNNABLE: Record<string, Runnable> = {
    'act1-unprotected-cpa': {
      config: base({ protection: 'none' }),
      schedule: SCHEDULES.firstOrder,
      make: () => new CpaAtSample(sample),
    },
    'act3-masked-second-order-cpa': {
      config: base({ protection: 'masked' }),
      schedule: SCHEDULES.secondOrder,
      make: () => new SecondOrderCpa(MASK_OUT_SAMPLE, sample),
    },
    'act4-frozen-low-weight-cpa': {
      config: base({ protection: 'frozen', frozenConstant: FIXTURE.frozenConstant }),
      schedule: SCHEDULES.firstOrder,
      make: () => new CpaAtSample(sample),
    },
    'act4-frozen-balanced-bitdpa': {
      config: base({ protection: 'frozen', frozenConstant: FIXTURE.balancedConstant }),
      schedule: SCHEDULES.bitDpa,
      make: () => new BitDpaAtSample(sample, FIXTURE.dpaBit),
    },
    'act2-masked-first-order-cpa': {
      config: base({ protection: 'masked' }),
      schedule: SCHEDULES.maskedFirstOrder,
      make: () => new CpaAtSample(sample),
    },
    'act2-masked-bit-dpa': {
      config: base({ protection: 'masked' }),
      schedule: SCHEDULES.bitDpa,
      make: () => new BitDpaAtSample(sample, FIXTURE.dpaBit),
    },
    'act4-frozen-balanced-cpa': {
      config: base({ protection: 'frozen', frozenConstant: FIXTURE.balancedConstant }),
      schedule: SCHEDULES.bitDpa,
      make: () => new CpaAtSample(sample),
    },
  };

  const claimSelect = el('select', {}) as HTMLSelectElement;
  for (const c of [...DISCLOSURE_CLAIMS, ...NON_DISCLOSURE_CLAIMS]) {
    claimSelect.appendChild(el('option', { value: c.id, text: `${c.act} — ${c.id}` }));
  }
  const runBtn = el('button', { type: 'button', class: 'primary', text: 'Reproduce this claim' });
  const status = el('p', {
    class: 'busy',
    id: 'cost-status',
    role: 'status',
    'aria-live': 'polite',
    text: 'Ready.',
  });
  const liveOut = el('div', { id: 'cost-result' });
  const chart = makeChart(1100, 340);
  let running = false;

  async function reproduce(): Promise<void> {
    if (running) return;
    const id = claimSelect.value;
    const runnable = RUNNABLE[id];
    if (!runnable) {
      replace(liveOut, verdict('fail', 'Refused.', ['No bench is registered for that claim id.']));
      return;
    }
    running = true;
    runBtn.disabled = true;
    shownClaim = id;

    const schedule = runnable.schedule;
    const maxN = schedule[schedule.length - 1];
    const dist = runnable.make();
    const stream = new TraceStream(runnable.config);
    const recovered: boolean[] = [];
    let next = 0;
    while (stream.count < maxN) {
      const want = Math.min(4000, maxN - stream.count);
      stream.take(want, (p, s) => {
        dist.add(p, s);
        while (next < schedule.length && dist.count === schedule[next]) {
          recovered.push(rankOf(dist.scores(), trueByte) === 1);
          next++;
        }
      });
      status.textContent = `Reproducing ${id} — ${num(stream.count)} of ${num(maxN)} traces…`;
      await nextFrame();
    }

    let ttd: number | null = null;
    for (let i = recovered.length - 1; i >= 0; i--) {
      if (!recovered[i]) break;
      ttd = schedule[i];
    }

    const disclosure = DISCLOSURE_CLAIMS.find((c) => c.id === id);
    const nonDisclosure = NON_DISCLOSURE_CLAIMS.find((c) => c.id === id);

    if (disclosure) {
      const inBand = ttd !== null && ttd >= disclosure.band[0] && ttd <= disclosure.band[1];
      replace(
        liveOut,
        kv([
          ['Claim', `${disclosure.act} — ${disclosure.headline}`],
          ['Recorded band', `${num(disclosure.band[0])} to ${num(disclosure.band[1])} traces`],
          ['Recorded at the pinned seed', num(disclosure.measured)],
          ['Measured just now', ttd === null ? 'no disclosure' : num(ttd)],
        ]),
        verdict(
          inBand ? 'alarm' : 'fail',
          inBand ? 'Inside the band — the key came out.' : 'BAND VIOLATION.',
          [
            inBand
              ? `The attack disclosed the key byte at ${num(ttd!)} traces, inside the recorded band. The alarm ` +
                `tone is deliberate: an attack landing where it was predicted to land means the countermeasure ` +
                `is behaving exactly as badly as documented, which is not good news, only expected news.`
              : ttd === null
                ? `${FAILURES.noDisclosure} The band says this attack should disclose between ` +
                  `${num(disclosure.band[0])} and ${num(disclosure.band[1])} traces and it did not disclose at ` +
                  `all. In this leakage model that means the model broke, not that the masking improved.`
                : `The attack disclosed at ${num(ttd!)} traces, outside the recorded band ` +
                  `${num(disclosure.band[0])} to ${num(disclosure.band[1])}. Something about the bench has changed.`,
          ]
        )
      );
    } else if (nonDisclosure) {
      const held = ttd === null;
      replace(
        liveOut,
        kv([
          ['Claim', `${nonDisclosure.act} — ${nonDisclosure.headline}`],
          ['Recorded claim', `no disclosure up to ${num(nonDisclosure.noDisclosureUpTo)} traces`],
          ['Measured just now', held ? 'no disclosure' : `disclosed at ${num(ttd!)}`],
        ]),
        verdict(held ? 'pass' : 'fail', held ? 'Held.' : 'CLAIM VIOLATION.', [
          held
            ? `${num(maxN)} traces, and the real key byte never took and held rank 1. The negative claim ` +
              `stands. Note what this is not: it is not "the attack is slow here", it is "this statistic ` +
              `cannot see the key at any trace count", which is a different and stronger statement.`
            : `The attack disclosed at ${num(ttd!)} traces, where the recorded claim says it should not ` +
              `disclose at all. That is a real finding about this bench and should be investigated, not ` +
              `re-recorded.`,
        ])
      );
    }

    status.textContent = `Done — ${num(maxN)} traces.`;
    status.setAttribute('data-run', String(Number(status.getAttribute('data-run') ?? '0') + 1));
    running = false;
    runBtn.disabled = false;
  }

  runBtn.addEventListener('click', () => void reproduce());
  let shownClaim = claimSelect.value;
  claimSelect.addEventListener('change', () => {
    // Same no-op guard as the frozen panel: re-selecting the claim already on
    // screen must leave its reproduction standing.
    if (claimSelect.value === shownClaim) return;
    shownClaim = claimSelect.value;
    status.textContent = 'Claim changed. Press Reproduce this claim.';
    replace(
      liveOut,
      verdict('info', 'Retired.', [
        'The previous measurement was for a different claim, so it has been cleared rather than left ' +
          'sitting under a heading it no longer describes.',
      ])
    );
  });

  // ── The recorded table ────────────────────────────────────────────────────
  const tbody = el('tbody');
  for (const c of DISCLOSURE_CLAIMS) {
    tbody.appendChild(
      el(
        'tr',
        {},
        el('td', { text: c.act }),
        el('td', { text: c.id }),
        el('td', { class: 'num', text: num(c.measured) }),
        el('td', { class: 'num', text: `${num(c.band[0])}–${num(c.band[1])}` }),
        el('td', {}, pill('alarm', 'KEY RECOVERED'))
      )
    );
  }
  for (const c of NON_DISCLOSURE_CLAIMS) {
    // Same rule as the frozen panel: "the attack found nothing" is good news
    // only where something was actually protecting the key. The balanced-frozen
    // row is the trap, and must not be painted the same green as Act 2.
    const guarded = !c.id.startsWith('act4-frozen');
    tbody.appendChild(
      el(
        'tr',
        {},
        el('td', { text: c.act }),
        el('td', { text: c.id }),
        el('td', { class: 'num', text: '—' }),
        el('td', { class: 'num', text: `none up to ${num(c.noDisclosureUpTo)}` }),
        el('td', {}, guarded ? pill('ok', 'no recovery') : pill('plain', 'SILENT — NOT PROTECTED'))
      )
    );
  }

  const baseline = DISCLOSURE_CLAIMS.find((c) => c.id === 'act1-unprotected-cpa')!;
  const second = DISCLOSURE_CLAIMS.find((c) => c.id === 'act3-masked-second-order-cpa')!;
  const ratio = second.measured / baseline.measured;

  const barLabels = DISCLOSURE_CLAIMS.map((c) => `${c.act} · ${num(c.measured)}`);
  const barValues = DISCLOSURE_CLAIMS.map((c) => Math.log10(c.measured));
  drawChart(
    chart,
    [{ label: 'traces to disclosure', colorVar: '--alarm', values: barValues, bars: true }],
    {
      title: 'Traces to disclosure, log scale',
      xLabel: 'claim',
      yLabel: 'log10(traces)',
      xTick: (i) => barLabels[i],
      yMin: 0,
    },
    'A bar chart on a base-ten log scale. ' +
      DISCLOSURE_CLAIMS.map((c) => `${c.act} ${c.id}: ${c.measured} traces`).join('; ') +
      `. The attacks that do not disclose at all are not plotted; they are in the table below.`
  );

  replace(
    root,
    el('h2', { text: 'What masking costs an attacker' }),
    el(
      'p',
      { class: 'lede' },
      'Masking did not make the key unreachable. It made it expensive. These are the numbers behind ' +
        'that sentence: the trace count at which each attack first ranks the real key byte first and ' +
        'keeps it there, measured on a fixed seed against a fixed checkpoint schedule.'
    ),
    verdict('alarm', `Second order costs about ${Math.round(ratio)} times the unprotected baseline.`, [
      `${num(baseline.measured)} traces against plain AES-128; ${num(second.measured)} traces against the ` +
        `masked implementation once two samples are combined. That multiplier is the honest summary of ` +
        `what first-order masking buys, in this leakage model, at this noise level — and the CI gate ` +
        `requires it to stay above ${COST_RATIO_FLOOR}x, because the ratio survives a change to the noise ` +
        `dial where the absolute counts do not.`,
    ]),
    chart,
    scroller(
      'Recorded traces-to-disclosure claims',
      el(
        'table',
        {},
        el(
          'thead',
          {},
          el(
            'tr',
            {},
            el('th', { text: 'Act' }),
            el('th', { text: 'Claim' }),
            el('th', { class: 'num', text: 'Measured' }),
            el('th', { class: 'num', text: 'Band' }),
            el('th', { text: 'Outcome' })
          )
        ),
        tbody
      )
    ),
    el(
      'p',
      { class: 'note' },
      `All rows use the FIPS-197 Appendix B key, byte 0, sample ${sample}, noise sigma ${FIXTURE.noise}, ` +
        `seed ${FIXTURE.seed}. Traces to disclosure is the first checkpoint from which the real key byte ` +
        `ranks first AND KEEPS ranking first to the end of the schedule — near a threshold the rank ` +
        `flickers, and a first-recovery rule would move these numbers by an order of magnitude run to run.`
    ),
    el(
      'div',
      { class: 'card' },
      el('h3', { text: 'Reproduce any of them here' }),
      el(
        'p',
        { class: 'note' },
        'Runs the same bench on the same schedule the band was recorded against, so the number you get ' +
          'is comparable to the band rather than merely near it. The second-order claim streams 120,000 ' +
          'traces and takes a few seconds.'
      ),
      el(
        'div',
        { class: 'controls' },
        labelled('cost-claim', 'Claim', claimSelect),
        el('div', { class: 'field' }, runBtn)
      ),
      status,
      liveOut
    ),
    el(
      'details',
      {},
      el('summary', { text: 'Why the CI gate is a band and not "the attack succeeded"' }),
      el(
        'div',
        { class: 'derivation' },
        el(
          'p',
          {},
          'The obvious gate for a lab like this is to fail the build when the second-order attack stops ' +
            'recovering the key. That gate is flaky: a statistical attack near its disclosure threshold ' +
            'varies from run to run, so the build reddens on noise and people learn to re-run it, which is ' +
            'worse than having no gate at all.'
        ),
        el(
          'p',
          {},
          'Fixing the PRNG seed makes the measurement deterministic; recording a BAND rather than a point ' +
            'keeps it meaningful across a reseed. The bands here are wide enough that six different seeds ' +
            'all land inside them and narrow enough that a broken model cannot. If the masked ' +
            'implementation suddenly resisted second-order CPA in this model, the model would have broken ' +
            '— nothing about the masking would have improved — and the band violation is what surfaces it.'
        ),
        el(
          'p',
          {},
          'The "order" in this table is the order of the ATTACK, not of the masking. Only first-order ' +
            'masking is implemented here. A d-th order scheme needs an order-(d+1) attack, and the trace ' +
            'counts grow steeply enough that a browser could not run the demonstration honestly — so this ' +
            'lab does not draw that curve rather than drawing one it cannot measure.'
        )
      )
    )
  );

  replace(
    liveOut,
    verdict('info', 'Not reproduced yet.', [
      'Pick a claim and press Reproduce this claim to run it in this tab.',
    ])
  );
}
