/**
 * "The Bench" — one attack, three protections, three distinguishers, and a
 * switch you can flip.
 *
 * Acts 1, 2 and 3 all happen here, deliberately, because the point of act 2 is
 * that it is THE SAME ATTACK as act 1 with one setting changed. Running them in
 * separate panels would let a reader believe the second one was rigged. The
 * act buttons set the controls and say what to look for; every control stays
 * live afterwards so the learner can leave the script and try combinations the
 * script does not cover — including the ones that fail.
 *
 * Fail-closed: any rejected input replaces the results with the reason and
 * shows NO scoreboard, rather than leaving the previous run's verdict standing
 * beside changed settings.
 */
import { hexToBytes } from '../../aes/aes';
import { CpaAtSample, CpaSampleScan, type Distinguisher } from '../../attack/cpa';
import { BitDpaAtSample } from '../../attack/dpa';
import { SecondOrderCpa } from '../../attack/secondOrder';
import { rankOf } from '../../attack/stats';
import { geometricCheckpoints, type CheckpointPoint } from '../../attack/ttd';
import {
  DISCLOSURE_CLAIMS,
  FIXTURE,
  NON_DISCLOSURE_CLAIMS,
} from '../../claims/bands';
import { FAILURES, LIMITS, validateKeyHex, validateNoise, validateTraceCount } from '../../claims/failures';
import {
  defaultBench,
  MASK_OUT_SAMPLE,
  NUM_SAMPLES,
  sampleLabel,
  sboxOutSample,
  TraceStream,
  type BenchConfig,
  type Protection,
} from '../../leakage/traces';
import { drawChart, makeChart } from '../charts';
import { el, kv, labelled, nextFrame, pill, replace, scroller, verdict } from '../dom';
import { hexByte, num, r4, signWord } from '../format';

type AttackKind = 'cpa1' | 'cpa2' | 'dpa';

const ATTACK_LABEL: Record<AttackKind, string> = {
  cpa1: 'First-order CPA',
  cpa2: 'Second-order CPA (centred product)',
  dpa: 'Single-bit difference of means',
};

const PROTECTION_LABEL: Record<Protection, string> = {
  none: 'None — plain AES-128',
  masked: 'Masked, fresh mask every encryption',
  frozen: 'Masked, mask FROZEN to a constant',
};

/** How many traces the per-sample scan uses. The scan costs 256 x 40 operations
 *  per trace, so it is capped well below the deep attack's count; its job is to
 *  locate a peak, not to reach a disclosure threshold. */
const SCAN_TRACES = 2500;
/** Traces pulled between paints, so a long run cannot freeze the tab. */
const CHUNK = 3000;

interface ActPreset {
  readonly id: string;
  readonly label: string;
  readonly act: string;
  readonly protection: Protection;
  readonly attack: AttackKind;
  readonly traces: number;
  readonly brief: string;
}

const ACTS: readonly ActPreset[] = [
  {
    id: 'act1',
    label: 'Unprotected baseline',
    act: 'Act 1',
    protection: 'none',
    attack: 'cpa1',
    traces: 3000,
    brief:
      'Plain AES-128, no countermeasure. Correlate the predicted Hamming weight of SBOX[pt XOR k] against the measured power at each of the 256 key guesses. The key byte separates out of the noise in a couple of hundred traces.',
  },
  {
    id: 'act2',
    label: 'Masking on',
    act: 'Act 2',
    protection: 'masked',
    attack: 'cpa1',
    traces: 40000,
    brief:
      'Exactly the same attack, with a fresh mask drawn for every encryption. Push the trace count as high as you like: the correct guess never separates, because the leakage of x XOR m is independent of x. This is the negative claim, and more data does not touch it.',
  },
  {
    id: 'act3',
    label: 'Second order',
    act: 'Act 3',
    protection: 'masked',
    attack: 'cpa2',
    traces: 30000,
    brief:
      'Same masked implementation, same key. Now combine TWO samples — the mask register and the masked S-box output — with the centred product before correlating. The key comes back. Watch the sign: a correct second-order guess correlates negatively, exactly as the identity predicts.',
  },
];

export function renderBench(root: HTMLElement): void {
  let protection: Protection = 'none';
  let attack: AttackKind = 'cpa1';
  let traces = 3000;
  let noise: number = FIXTURE.noise;
  let targetSample = sboxOutSample(FIXTURE.targetByte);
  let partnerSample = MASK_OUT_SAMPLE;
  let keyHex: string = FIXTURE.keyHex;
  let dpaBit: number = FIXTURE.dpaBit;
  let running = false;

  const protectionSelect = el('select', {}) as HTMLSelectElement;
  for (const p of ['none', 'masked', 'frozen'] as const) {
    protectionSelect.appendChild(el('option', { value: p, text: PROTECTION_LABEL[p] }));
  }
  const attackSelect = el('select', {}) as HTMLSelectElement;
  for (const a of ['cpa1', 'cpa2', 'dpa'] as const) {
    attackSelect.appendChild(el('option', { value: a, text: ATTACK_LABEL[a] }));
  }
  const tracesInput = el('input', {
    type: 'number',
    min: String(LIMITS.minTraces),
    max: String(LIMITS.maxTraces),
    step: '500',
    value: String(traces),
  }) as HTMLInputElement;
  const noiseInput = el('input', {
    type: 'number',
    min: String(LIMITS.minNoise),
    max: String(LIMITS.maxNoise),
    step: '0.5',
    value: String(noise),
  }) as HTMLInputElement;
  const keyInput = el('input', { type: 'text', value: keyHex, size: '34' }) as HTMLInputElement;

  const sampleSelect = el('select', {}) as HTMLSelectElement;
  const partnerSelect = el('select', {}) as HTMLSelectElement;
  for (let i = 0; i < NUM_SAMPLES; i++) {
    const text = `${i} — ${sampleLabel(i)}`;
    sampleSelect.appendChild(el('option', { value: String(i), text }));
    partnerSelect.appendChild(el('option', { value: String(i), text }));
  }
  const bitSelect = el('select', {}) as HTMLSelectElement;
  for (let b = 0; b < 8; b++) bitSelect.appendChild(el('option', { value: String(b), text: `bit ${b}` }));

  const runBtn = el('button', { type: 'button', class: 'primary', text: 'Run the attack' });
  const status = el('p', {
    class: 'busy',
    id: 'bench-status',
    role: 'status',
    'aria-live': 'polite',
    text: 'Ready.',
  });
  const actBrief = el('div', { id: 'bench-act-brief' });
  const resultOut = el('div', { id: 'bench-result' });
  const sampleChart = makeChart(1100, 340);
  const convergeChart = makeChart(1100, 340);
  const sampleWrap = el('div', { class: 'card', id: 'bench-sample-card', hidden: true });
  const convergeWrap = el('div', { class: 'card', id: 'bench-converge-card', hidden: true });
  const partnerField = el('div', { class: 'field' });
  const bitField = el('div', { class: 'field' });

  function syncControls(): void {
    protectionSelect.value = protection;
    attackSelect.value = attack;
    tracesInput.value = String(traces);
    noiseInput.value = String(noise);
    sampleSelect.value = String(targetSample);
    partnerSelect.value = String(partnerSample);
    bitSelect.value = String(dpaBit);
    partnerField.hidden = attack !== 'cpa2';
    bitField.hidden = attack !== 'dpa';
  }

  function currentConfig(key: Uint8Array): BenchConfig {
    return defaultBench(key, {
      targetByte: FIXTURE.targetByte,
      protection,
      frozenConstant: FIXTURE.frozenConstant,
      noise,
      seed: FIXTURE.seed,
    });
  }

  function makeDistinguisher(): Distinguisher {
    if (attack === 'cpa2') return new SecondOrderCpa(partnerSample, targetSample);
    if (attack === 'dpa') return new BitDpaAtSample(targetSample, dpaBit);
    return new CpaAtSample(targetSample);
  }

  function fail(reason: string): void {
    replace(resultOut, verdict('fail', 'Refused.', [reason]));
    sampleWrap.hidden = true;
    convergeWrap.hidden = true;
    status.textContent = 'Nothing measured.';
    status.setAttribute('data-run', String(Number(status.getAttribute('data-run') ?? '0') + 1));
  }

  async function run(): Promise<void> {
    if (running) return;
    const keyCheck = validateKeyHex(keyInput.value);
    keyInput.setAttribute('aria-invalid', keyCheck.ok ? 'false' : 'true');
    const traceCheck = validateTraceCount(Number(tracesInput.value));
    tracesInput.setAttribute('aria-invalid', traceCheck.ok ? 'false' : 'true');
    const noiseCheck = validateNoise(Number(noiseInput.value));
    noiseInput.setAttribute('aria-invalid', noiseCheck.ok ? 'false' : 'true');

    if (!keyCheck.ok) return fail(keyCheck.failure!);
    if (!traceCheck.ok) return fail(traceCheck.failure!);
    if (!noiseCheck.ok) return fail(noiseCheck.failure!);
    if (attack === 'cpa2' && partnerSample === targetSample) return fail(FAILURES.samePairSamples);

    keyHex = keyCheck.value!;
    traces = traceCheck.value!;
    noise = noiseCheck.value!;

    running = true;
    runBtn.disabled = true;
    const key = hexToBytes(keyHex);
    const trueByte = key[FIXTURE.targetByte];
    const cfg = currentConfig(key);

    // ── Per-sample scan: WHERE does it leak? ────────────────────────────────
    status.textContent = `Scanning all ${NUM_SAMPLES} samples over ${num(SCAN_TRACES)} traces…`;
    await nextFrame();
    const scan = new CpaSampleScan(NUM_SAMPLES);
    new TraceStream(cfg).take(SCAN_TRACES, (p, s) => scan.add(p, s));
    const scanResult = scan.result();

    // ── The deep attack, chunked so the tab keeps painting ──────────────────
    const checkpoints = geometricCheckpoints(Math.min(50, traces), traces, 6);
    const dist = makeDistinguisher();
    const stream = new TraceStream(cfg);
    const points: CheckpointPoint[] = [];
    let next = 0;
    while (stream.count < traces) {
      const want = Math.min(CHUNK, traces - stream.count);
      stream.take(want, (p, s) => {
        dist.add(p, s);
        while (next < checkpoints.length && dist.count === checkpoints[next]) {
          const scores = dist.scores();
          let topWrong = -Infinity;
          for (let g = 0; g < 256; g++) if (g !== trueByte && scores[g] > topWrong) topWrong = scores[g];
          const rank = rankOf(scores, trueByte);
          points.push({
            numTraces: dist.count,
            correctScore: scores[trueByte],
            topWrongScore: topWrong,
            correctRank: rank,
            correctSigned: signedOf(dist, trueByte),
            recovered: rank === 1,
          });
          next++;
        }
      });
      status.textContent = `Running ${ATTACK_LABEL[attack]} — ${num(stream.count)} of ${num(traces)} traces…`;
      await nextFrame();
    }

    let ttd: number | null = null;
    for (let i = points.length - 1; i >= 0; i--) {
      if (!points[i].recovered) break;
      ttd = points[i].numTraces;
    }

    paintResults(dist, trueByte, points, ttd, scanResult);
    status.textContent = `Done — ${num(traces)} traces, ${ATTACK_LABEL[attack]}.`;
    // A monotonically increasing token, so a test can wait for THIS run rather
    // than matching a "Done" left over from the previous one.
    status.setAttribute('data-run', String(Number(status.getAttribute('data-run') ?? '0') + 1));
    running = false;
    runBtn.disabled = false;
  }

  function signedOf(d: Distinguisher, guess: number): number | null {
    const maybe = d as Partial<{ correlation(g: number): number; difference(g: number): number }>;
    if (typeof maybe.correlation === 'function') return maybe.correlation(guess);
    if (typeof maybe.difference === 'function') return maybe.difference(guess);
    return null;
  }

  function paintResults(
    dist: Distinguisher,
    trueByte: number,
    points: CheckpointPoint[],
    ttd: number | null,
    scanResult: ReturnType<CpaSampleScan['result']>
  ): void {
    const scores = dist.scores();
    const ranking = Array.from({ length: 256 }, (_, i) => i).sort((a, b) => scores[b] - scores[a]);
    const rank = rankOf(scores, trueByte);
    const recovered = rank === 1;
    const signed = signedOf(dist, trueByte);
    const unit = attack === 'dpa' ? 'model units' : 'correlation';

    // Verdict tone tracks SYSTEM INTEGRITY, not the attack's return value.
    // A recovered key is an alarm however pleased the attacker is about it.
    const tone = recovered ? 'alarm' : protection === 'none' ? 'fail' : 'pass';
    const label = recovered
      ? `Key byte recovered: ${hexByte(ranking[0])}.`
      : protection === 'none'
        ? 'Not recovered — yet.'
        : 'Not recovered.';
    const detail = recovered
      ? `The top-ranked guess is ${hexByte(ranking[0])} and the real key byte is ${hexByte(trueByte)} — ` +
        `they match, so this attack read a secret out of power measurements alone. Its score is ` +
        `${r4(scores[trueByte])}, against ${r4(points[points.length - 1]?.topWrongScore ?? 0)} for the best ` +
        `of the 255 wrong guesses.` +
        (signed !== null
          ? ` The signed value is ${r4(signed)}, which is ${signWord(signed)}${attack === 'cpa2' ? ' — the minus sign the centred-product identity predicts' : ''}.`
          : '')
      : protection === 'none'
        ? `The real key byte ${hexByte(trueByte)} is ranked ${rank} of 256. This bench is unprotected, so ` +
          `the leakage is there — there simply are not enough traces yet. Raise the trace count and it will separate.`
        : `The real key byte ${hexByte(trueByte)} is ranked ${rank} of 256, with a score of ${r4(scores[trueByte])} ` +
          `against ${r4(points[points.length - 1]?.topWrongScore ?? 0)} for the best wrong guess — it is inside the ` +
          `noise, not above it. Raising the trace count does not change that: this attack is not slow here, it is blind.`;

    const rows = el('tbody');
    const shown = new Set<number>([...ranking.slice(0, 6), trueByte]);
    const ordered = ranking.filter((g) => shown.has(g));
    for (const g of ordered) {
      rows.appendChild(
        el(
          'tr',
          g === trueByte ? { class: 'is-true-key' } : {},
          el('td', { class: 'num', text: String(ranking.indexOf(g) + 1) }),
          el('td', { class: 'num', text: hexByte(g) }),
          el('td', { class: 'num', text: r4(scores[g]) }),
          el('td', {}, g === trueByte ? pill(recovered ? 'alarm' : 'ok', 'REAL KEY BYTE') : '')
        )
      );
    }

    const claim =
      DISCLOSURE_CLAIMS.find((c) => matchesClaim(c.id)) ?? null;
    const negClaim = NON_DISCLOSURE_CLAIMS.find((c) => matchesClaim(c.id)) ?? null;

    replace(
      resultOut,
      verdict(tone, label, [detail]),
      kv([
        ['Traces measured', num(dist.count)],
        ['Distinguisher', ATTACK_LABEL[attack]],
        [
          'Sample under attack',
          attack === 'cpa2'
            ? `${partnerSample} (${sampleLabel(partnerSample)})  x  ${targetSample} (${sampleLabel(targetSample)})`
            : `${targetSample} (${sampleLabel(targetSample)})`,
        ],
        ['Real key byte', `${hexByte(trueByte)} — from the key above, byte ${FIXTURE.targetByte}`],
        ['Rank of the real key byte', `${rank} of 256`],
        [
          'Traces to disclosure',
          ttd === null
            ? 'no disclosure within this run'
            : `${num(ttd)} — the first checkpoint from which it stays rank 1`,
        ],
        ...(claim
          ? ([
              [
                'Recorded band',
                `${num(claim.band[0])} to ${num(claim.band[1])} traces (${claim.act}, seed ${FIXTURE.seed})`,
              ],
            ] as [string, string][])
          : []),
        ...(negClaim
          ? ([
              [
                'Recorded claim',
                `no disclosure up to ${num(negClaim.noDisclosureUpTo)} traces, checked on ${negClaim.seedsChecked} seeds`,
              ],
            ] as [string, string][])
          : []),
      ]),
      scroller(
        'Ranked key-byte guesses',
        el(
          'table',
          {},
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { class: 'num', text: 'Rank' }),
              el('th', { class: 'num', text: 'Guess' }),
              el('th', { class: 'num', text: `Score (${unit})` }),
              el('th', { text: '' })
            )
          ),
          rows
        )
      )
    );

    // ── Where does it leak? ─────────────────────────────────────────────────
    sampleWrap.hidden = false;
    const peak = scanResult.curveFor(trueByte);
    const peakAt = argmaxAbs(peak);
    drawChart(
      sampleChart,
      [{ label: 'r for the real key byte', colorVar: '--accent', values: peak, bars: true }],
      {
        title: `First-order correlation at each sample, real key byte, ${num(SCAN_TRACES)} traces`,
        xLabel: 'sample index',
        yLabel: 'r',
        xTick: (i) => (i % 4 === 0 ? String(i) : null),
        rules: [{ y: 0, label: 'zero' }],
        markX: targetSample,
        markLabel: 'attacked',
      },
      `A bar chart of correlation across ${NUM_SAMPLES} samples for the real key byte. ` +
        `The largest magnitude is ${r4(peak[peakAt])} at sample ${peakAt}, which is ${sampleLabel(peakAt)}. ` +
        (protection === 'masked'
          ? 'Nothing rises above the noise anywhere, including at the mask register and the masked S-box output.'
          : `The attacked sample ${targetSample} reads ${r4(peak[targetSample])}.`)
    );
    replace(
      sampleWrap,
      el('h3', { text: 'Where does it leak?' }),
      el(
        'p',
        { class: 'note' },
        'Before attacking a sample you have to find one. This is an ordinary first-order correlation ' +
          'computed at every sample in the trace, for the real key byte, so you can see whether there ' +
          'is a point of interest at all.'
      ),
      sampleChart,
      el(
        'p',
        { class: 'note' },
        `Largest magnitude ${r4(peak[peakAt])} at sample ${peakAt} (${sampleLabel(peakAt)}). ` +
          (protection === 'masked'
            ? 'With a fresh mask there is no peak to find: not at the masked S-box output, and not at the mask register either, because the mask is independent of the key.'
            : `The sample currently under attack is ${targetSample} (${sampleLabel(targetSample)}), reading ${r4(peak[targetSample])}.`)
      )
    );

    // ── Convergence ─────────────────────────────────────────────────────────
    convergeWrap.hidden = false;
    const xs = points.map((p) => p.numTraces);
    drawChart(
      convergeChart,
      [
        { label: 'real key byte', colorVar: '--alarm', values: points.map((p) => p.correctScore) },
        { label: 'best wrong guess', colorVar: '--accent', values: points.map((p) => p.topWrongScore), dashed: true },
      ],
      {
        title: 'Does the real key separate from the noise?',
        xLabel: 'traces (log scale)',
        yLabel: `score (${unit})`,
        xTick: (i) => (i % 3 === 0 ? shortNum(xs[i]) : null),
        xValues: xs,
        logX: true,
        yMin: 0,
      },
      describeConvergence(points, ttd, unit)
    );
    replace(
      convergeWrap,
      el('h3', { text: 'Does it converge?' }),
      el(
        'p',
        { class: 'note' },
        'The real key byte’s score against the best of the 255 wrong guesses, as traces accumulate. ' +
          'An attack that works pulls the two lines apart and keeps them apart. An attack that is blind ' +
          'leaves them together no matter how much data it is given.'
      ),
      convergeChart,
      el(
        'ul',
        { class: 'legend', role: 'list' },
        el(
          'li',
          { role: 'listitem' },
          el('span', { class: 'swatch', 'aria-hidden': 'true', style: 'border-top-color: var(--alarm)' }),
          el('span', { text: 'real key byte: ' }),
          el('span', { class: 'value', text: r4(points[points.length - 1]?.correctScore ?? 0) })
        ),
        el(
          'li',
          { role: 'listitem' },
          el('span', { class: 'swatch', 'aria-hidden': 'true', style: 'border-top-color: var(--accent)' }),
          el('span', { text: 'best wrong guess: ' }),
          el('span', { class: 'value', text: r4(points[points.length - 1]?.topWrongScore ?? 0) })
        )
      ),
      el('p', { class: 'note', text: describeConvergence(points, ttd, unit) })
    );
  }

  function matchesClaim(id: string): boolean {
    if (noise !== FIXTURE.noise || keyHex !== FIXTURE.keyHex) return false;
    if (targetSample !== sboxOutSample(FIXTURE.targetByte)) return false;
    if (id === 'act1-unprotected-cpa') return protection === 'none' && attack === 'cpa1';
    if (id === 'act3-masked-second-order-cpa') {
      return protection === 'masked' && attack === 'cpa2' && partnerSample === MASK_OUT_SAMPLE;
    }
    if (id === 'act2-masked-first-order-cpa') return protection === 'masked' && attack === 'cpa1';
    if (id === 'act2-masked-bit-dpa') return protection === 'masked' && attack === 'dpa';
    return false;
  }

  runBtn.addEventListener('click', () => void run());
  protectionSelect.addEventListener('change', () => {
    protection = protectionSelect.value as Protection;
  });
  attackSelect.addEventListener('change', () => {
    attack = attackSelect.value as AttackKind;
    syncControls();
  });
  sampleSelect.addEventListener('change', () => {
    targetSample = Number(sampleSelect.value);
  });
  partnerSelect.addEventListener('change', () => {
    partnerSample = Number(partnerSelect.value);
  });
  bitSelect.addEventListener('change', () => {
    dpaBit = Number(bitSelect.value);
  });

  const actButtons = el('div', { class: 'seg', role: 'group', 'aria-label': 'Act presets' });
  for (const a of ACTS) {
    const b = el('button', {
      type: 'button',
      class: 'seg-btn',
      'data-act': a.id,
      text: `${a.act} · ${a.label}`,
    });
    b.addEventListener('click', () => {
      protection = a.protection;
      attack = a.attack;
      traces = a.traces;
      targetSample = sboxOutSample(FIXTURE.targetByte);
      partnerSample = MASK_OUT_SAMPLE;
      syncControls();
      for (const other of Array.from(actButtons.children)) {
        other.setAttribute('aria-pressed', other === b ? 'true' : 'false');
      }
      replace(
        actBrief,
        verdict('info', `${a.act} — ${a.label}.`, [a.brief])
      );
      status.textContent = 'Settings loaded. Press Run the attack.';
    });
    b.setAttribute('aria-pressed', a.id === 'act1' ? 'true' : 'false');
    actButtons.appendChild(b);
  }

  replace(
    root,
    el('h2', { text: 'The bench: same attack, one switch' }),
    el(
      'p',
      { class: 'lede' },
      'A correlation power attack guesses one key byte at a time. For each of the 256 possibilities it ' +
        'predicts how many bits the chip would have been holding, and correlates that prediction against ' +
        'the measured power. The right guess predicts reality; the other 255 predict noise. ' +
        'Everything below runs that attack for real against the implementations on this page.'
    ),
    el('div', { class: 'field' }, el('span', { class: 'group-label', text: 'Guided acts' }), actButtons),
    actBrief,
    el(
      'div',
      { class: 'controls' },
      labelled('bench-protection', 'Protection', protectionSelect),
      labelled('bench-attack', 'Distinguisher', attackSelect),
      labelled('bench-traces', 'Traces', tracesInput),
      labelled('bench-noise', 'Noise sigma', noiseInput),
      labelled('bench-sample', 'Sample under attack', sampleSelect)
    ),
    el(
      'div',
      { class: 'controls' },
      (() => {
        replace(partnerField, el('label', { for: 'bench-partner', text: 'Combine with sample' }), partnerSelect);
        partnerSelect.id = 'bench-partner';
        return partnerField;
      })(),
      (() => {
        replace(bitField, el('label', { for: 'bench-bit', text: 'Predicted bit' }), bitSelect);
        bitSelect.id = 'bench-bit';
        return bitField;
      })(),
      labelled('bench-key', 'AES-128 key (hex)', keyInput),
      el('div', { class: 'field' }, runBtn)
    ),
    status,
    resultOut,
    sampleWrap,
    convergeWrap,
    el(
      'details',
      {},
      el('summary', { text: 'What the sample map means' }),
      el(
        'div',
        { class: 'derivation' },
        el(
          'p',
          {},
          'A trace here is 40 samples of one AES round. Samples 3 and 5 are the two mask registers a ' +
            'masked build writes while it rebuilds its S-box table; an unprotected build has no such ' +
            'registers, so on that bench those cycles carry only the operation shape and the noise. ' +
            'Samples 8 to 23 are the sixteen S-box inputs and 24 to 39 the sixteen S-box outputs. ' +
            'Byte 0 is the one under attack, so sample 24 is the classic target.'
        ),
        el(
          'p',
          {},
          'The second-order attack needs a genuine PAIR: a mask, and a value masked by that same mask. ' +
            'Try pairing the output mask (5) with an S-box INPUT (8) instead — those are masked with mIn, ' +
            'not mOut — or with an idle cycle, and watch the attack fail. Getting the pair right is most ' +
            'of the work in a real second-order attack, and it is why hiding countermeasures that blur ' +
            'sample positions are worth combining with masking.'
        )
      )
    )
  );

  syncControls();
  actButtons.children[0]?.dispatchEvent(new Event('click'));
  replace(
    resultOut,
    verdict('info', 'Not run yet.', [
      'Press Run the attack. Nothing on this page is precomputed — the traces are generated and the ' +
        'correlation is worked out in this tab when you press it.',
    ])
  );
}

function argmaxAbs(v: ArrayLike<number>): number {
  let best = 0;
  for (let i = 0; i < v.length; i++) if (Math.abs(v[i]) > Math.abs(v[best])) best = i;
  return best;
}

function shortNum(n: number): string {
  if (n >= 1000) return `${Math.round(n / 1000)}k`;
  return String(n);
}

function describeConvergence(points: CheckpointPoint[], ttd: number | null, unit: string): string {
  const last = points[points.length - 1];
  if (!last) return 'No checkpoints were reached.';
  const gap = last.correctScore - last.topWrongScore;
  if (ttd === null) {
    return (
      `Two lines that never part. At ${num(last.numTraces)} traces the real key byte scores ` +
      `${r4(last.correctScore)} ${unit} against ${r4(last.topWrongScore)} for the best wrong guess — it is ` +
      `ranked ${last.correctRank} of 256, still inside the noise.`
    );
  }
  return (
    `The lines separate at ${num(ttd)} traces and stay separated. At ${num(last.numTraces)} traces the real ` +
    `key byte scores ${r4(last.correctScore)} ${unit} against ${r4(last.topWrongScore)} for the best wrong ` +
    `guess, a gap of ${r4(gap)}.`
  );
}
