/**
 * "Frozen mask" — the act where the countermeasure is intact and the
 * randomness is not.
 *
 * The fixture is PINNED, and that is a deliberate choice with a reason the
 * panel states out loud. Under a Hamming-weight leakage model, freezing the
 * mask to a constant c leaves a correlation of exactly 1 - HW(c)/4. Pick a
 * balanced constant and that is ZERO: the attack reports nothing at all while
 * the protection is completely gone. A lab that left the constant arbitrary
 * would be teaching a coin flip.
 *
 * So this panel does both published things. Its default constant is 0x01 — low
 * weight, so the surviving correlation of 0.75 is large and visible, and it is
 * printed beside the correlation the bench actually measures. And its primary
 * distinguisher is the single-BIT difference of means, which is exactly +-1 for
 * every fixed constant and therefore does not depend on which one was chosen.
 * Switching the constant to 0x0f and watching one attack die while the other
 * keeps working is the whole lesson.
 */
import { hexToBytes } from '../../aes/aes';
import { CpaAtSample } from '../../attack/cpa';
import { BitDpaAtSample } from '../../attack/dpa';
import { rankOf } from '../../attack/stats';
import { FIXTURE, FROZEN_FIXTURE } from '../../claims/bands';
import { bitDpaDifference, frozenMaskCorrelation } from '../../mask/combining';
import { HW } from '../../leakage/model';
import { defaultBench, sboxOutSample, TraceStream } from '../../leakage/traces';
import { el, kv, labelled, nextFrame, pill, replace, scroller, verdict } from '../dom';
import { bin8, hexByte, r4 } from '../format';

const TRACES = 6000;

export function renderFrozen(root: HTMLElement): void {
  let constant: number = FROZEN_FIXTURE.pinned;
  let running = false;

  const constantSelect = el('select', {}) as HTMLSelectElement;
  for (const c of FROZEN_FIXTURE.offered) {
    const h = HW[c];
    const note = h === 4 ? ' — balanced, the trap' : c === FROZEN_FIXTURE.pinned ? ' — pinned default' : '';
    constantSelect.appendChild(
      el('option', { value: String(c), text: `${hexByte(c)}  weight ${h}${note}` })
    );
  }
  constantSelect.value = String(constant);

  const runBtn = el('button', { type: 'button', class: 'primary', text: 'Measure this constant' });
  const status = el('p', {
    class: 'busy',
    id: 'frozen-status',
    role: 'status',
    'aria-live': 'polite',
    text: 'Ready.',
  });
  const out = el('div', { id: 'frozen-result' });

  async function run(): Promise<void> {
    if (running) return;
    running = true;
    runBtn.disabled = true;
    status.textContent = `Measuring ${TRACES} traces on three benches…`;
    await nextFrame();

    const key = hexToBytes(FIXTURE.keyHex);
    const trueByte = key[FIXTURE.targetByte];
    const sample = sboxOutSample(FIXTURE.targetByte);
    const base = (over: Parameters<typeof defaultBench>[1]) =>
      defaultBench(key, { targetByte: FIXTURE.targetByte, noise: FIXTURE.noise, seed: FIXTURE.seed, ...over });

    // Unprotected baseline — the scale everything else is read against.
    const plainCpa = new CpaAtSample(sample);
    new TraceStream(base({ protection: 'none' })).take(TRACES, (p, s) => plainCpa.add(p, s));

    // Frozen: the Hamming-weight attack and the bit-level attack, same traces.
    const frozenCpa = new CpaAtSample(sample);
    const frozenDpa = new BitDpaAtSample(sample, 0);
    new TraceStream(base({ protection: 'frozen', frozenConstant: constant })).take(TRACES, (p, s) => {
      frozenCpa.add(p, s);
      frozenDpa.add(p, s);
    });

    // Fresh mask — the control, so "the attack failed" can be told apart from
    // "the attack always fails here".
    const freshCpa = new CpaAtSample(sample);
    const freshDpa = new BitDpaAtSample(sample, 0);
    new TraceStream(base({ protection: 'masked' })).take(TRACES, (p, s) => {
      freshCpa.add(p, s);
      freshDpa.add(p, s);
    });

    const rBase = plainCpa.correlation(trueByte);
    const rFrozen = frozenCpa.correlation(trueByte);
    const modelRatio = frozenMaskCorrelation(constant);
    const predictedBench = modelRatio * rBase;
    const measuredRatio = rBase === 0 ? 0 : rFrozen / rBase;
    const agrees = Math.abs(measuredRatio - modelRatio) <= FROZEN_FIXTURE.toleranceOfPredicted;

    const cpaRank = rankOf(frozenCpa.scores(), trueByte);
    const dpaRank = rankOf(frozenDpa.scores(), trueByte);
    const dpaDiff = frozenDpa.difference(trueByte);
    const dpaPredicted = bitDpaDifference(constant, 0);

    // The outcome column tracks SYSTEM INTEGRITY, not the attack's return
    // value. "The attack found nothing" is good news only on the fresh-mask
    // control; on the frozen bench it is the trap itself, and painting it the
    // same calm green as a working countermeasure would be the page telling the
    // reader the opposite of what the panel exists to teach.
    interface Row {
      bench: string;
      method: string;
      value: string;
      rank: number;
      /** Is this bench actually protected? Only the fresh-mask control is. */
      guarded: boolean;
    }
    const rows: Row[] = [
      {
        bench: 'Unprotected',
        method: 'Hamming-weight CPA',
        value: r4(rBase),
        rank: rankOf(plainCpa.scores(), trueByte),
        guarded: false,
      },
      { bench: 'Frozen mask', method: 'Hamming-weight CPA', value: r4(rFrozen), rank: cpaRank, guarded: false },
      { bench: 'Frozen mask', method: 'Single-bit difference', value: r4(dpaDiff), rank: dpaRank, guarded: false },
      {
        bench: 'Fresh mask (control)',
        method: 'Hamming-weight CPA',
        value: r4(freshCpa.correlation(trueByte)),
        rank: rankOf(freshCpa.scores(), trueByte),
        guarded: true,
      },
      {
        bench: 'Fresh mask (control)',
        method: 'Single-bit difference',
        value: r4(freshDpa.difference(trueByte)),
        rank: rankOf(freshDpa.scores(), trueByte),
        guarded: true,
      },
    ];
    const tbody = el('tbody');
    for (const row of rows) {
      const recovered = row.rank === 1;
      const outcome = recovered
        ? pill('alarm', 'KEY RECOVERED')
        : row.guarded
          ? pill('ok', 'no recovery')
          : pill('plain', 'SILENT — NOT PROTECTED');
      tbody.appendChild(
        el(
          'tr',
          {},
          el('td', { text: row.bench }),
          el('td', { text: row.method }),
          el('td', { class: 'num', text: row.value }),
          el('td', { class: 'num', text: `rank ${row.rank}` }),
          el('td', {}, outcome)
        )
      );
    }

    const balanced = HW[constant] === 4;

    replace(
      out,
      kv([
        ['Frozen constant', `${hexByte(constant)}  ${bin8(constant)}  (Hamming weight ${HW[constant]})`],
        ['Closed form 1 - HW(c)/4', r4(modelRatio)],
        ['Predicted bench correlation', `${r4(predictedBench)} = ${r4(modelRatio)} x ${r4(rBase)}`],
        ['Measured bench correlation', r4(rFrozen)],
        ['Measured / unprotected', r4(measuredRatio)],
      ]),
      verdict(
        agrees ? 'pass' : 'fail',
        agrees ? 'Prediction matched.' : 'Prediction missed.',
        [
          agrees
            ? `The closed form said the Hamming-weight correlation would survive at ${r4(modelRatio)} of its unprotected value, and over ${TRACES} traces it came out at ${r4(measuredRatio)}. The two were computed by completely different routes — one is exact algebra over all 256 byte values, the other is Pearson correlation over simulated measurements.`
            : `The measurement is ${r4(measuredRatio)} where the closed form predicts ${r4(modelRatio)}; that is outside the sampling tolerance of ${FROZEN_FIXTURE.toleranceOfPredicted} and one of the two is wrong.`,
        ]
      ),
      balanced
        ? verdict('alarm', 'The trap.', [
            `This constant has Hamming weight 4, so 1 - HW(c)/4 is exactly zero and the Hamming-weight ` +
              `attack measures ${r4(rFrozen)} — nothing. It ranks the real key byte ${cpaRank} of 256 and ` +
              `looks, to anyone reading only that row, like a countermeasure doing its job. It is not. ` +
              `There is no randomness left in this implementation at all. The single-bit attack on the ` +
              `same traces ranks the real key byte ${dpaRank}, with a difference of ${r4(dpaDiff)} model ` +
              `units where the identity predicts ${dpaPredicted > 0 ? '+' : ''}${dpaPredicted}. A silent ` +
              `attack is not evidence of a working defence.`,
          ])
        : verdict(cpaRank === 1 ? 'alarm' : 'info', cpaRank === 1 ? 'Protection gone.' : 'Weakened.', [
            `With the mask pinned to ${hexByte(constant)}, the masked value is a fixed function of the ` +
              `unmasked one — ${hexByte(constant)} XOR it — so there is nothing random left to hide behind. ` +
              `Ordinary first-order CPA ranks the real key byte ${cpaRank} of 256. The countermeasure is ` +
              `still there in the source: the table is still recomputed, the state is still carried as a ` +
              `pair, and the ciphertext is still correct. Only the randomness is gone.`,
          ]),
      verdict(
        dpaRank === 1 ? 'alarm' : 'fail',
        dpaRank === 1 ? 'The bit-level attack recovers it regardless.' : 'The bit-level attack did not recover it.',
        [
          dpaRank === 1
            ? `Partitioning the traces on one predicted bit and subtracting the two averages gives ` +
              `${r4(dpaDiff)} model units, against a predicted ${dpaPredicted > 0 ? '+' : ''}${dpaPredicted}. ` +
              `The magnitude is one unit for EVERY fixed constant; only the sign changes, and it is bit 0 of ` +
              `the constant. That is why this panel leads with the bit-level attack: it does not care which ` +
              `constant you happened to freeze, so the lesson does not depend on a lucky choice.`
            : `At ${TRACES} traces the bit-level attack ranks the real key byte ${dpaRank}. It reaches rank 1 ` +
              `reliably by a few thousand traces on this bench; the recorded band is in the Cost panel.`,
        ]
      ),
      scroller(
        'Every bench and distinguisher at this constant',
        el(
          'table',
          {},
          el(
            'thead',
            {},
            el(
              'tr',
              {},
              el('th', { text: 'Bench' }),
              el('th', { text: 'Distinguisher' }),
              el('th', { class: 'num', text: 'Score' }),
              el('th', { class: 'num', text: 'Real key rank' }),
              el('th', { text: 'Outcome' })
            )
          ),
          tbody
        )
      ),
      el(
        'p',
        { class: 'note' },
        `All five rows are ${TRACES} traces of the same seeded bench with the same plaintexts and the same ` +
          `noise; only the mask source and the statistic change. The bottom two rows are the control: against ` +
          `a fresh mask BOTH attacks fail, which is what tells you the rows above are measuring broken ` +
          `randomness rather than a broken attack. Note that only those two rows are marked "no recovery" — ` +
          `on an unprotected or frozen bench an attack that finds nothing is SILENT, not safe, and this table ` +
          `refuses to paint the two the same colour.`
      )
    );

    status.textContent = `Done — ${TRACES} traces on each of three benches.`;
    status.setAttribute('data-run', String(Number(status.getAttribute('data-run') ?? '0') + 1));
    running = false;
    runBtn.disabled = false;
  }

  constantSelect.addEventListener('change', () => {
    const next = Number(constantSelect.value);
    // The no-op guard. A `change` event does not mean the value changed — a
    // programmatic re-selection of the SAME option fires one, and retiring a
    // fresh measurement because the reader picked the option it was already on
    // would be telling them something false about their own result.
    if (next === constant) return;
    constant = next;
    status.textContent = 'Constant changed. Press Measure this constant.';
    replace(
      out,
      verdict('info', 'Retired.', [
        `The previous measurement was for a different constant, so it has been cleared rather than left ` +
          `sitting beside the new setting. Press Measure this constant to run ${hexByte(constant)}.`,
      ])
    );
  });
  runBtn.addEventListener('click', () => void run());

  replace(
    root,
    el('h2', { text: 'Act 4 — the mask that stopped moving' }),
    el(
      'p',
      { class: 'lede' },
      'Masking’s security argument rests entirely on the mask being fresh and unpredictable. Take that ' +
        'away — a random number generator that was never seeded, a mask computed once at boot, a test ' +
        'harness left in a shipping build — and every line of the countermeasure is still there, the ' +
        'ciphertext is still correct, and the protection is gone. This act is about randomness, not about ' +
        'masking; the two failures are separate lessons and it is worth keeping them apart.'
    ),
    el(
      'p',
      {},
      'There is a subtlety here that makes the act easy to get wrong, so this page pins its fixture. ' +
        'A frozen constant c leaves a Hamming-weight correlation of exactly 1 minus HW(c) over 4. ' +
        'For a balanced constant that is zero — the attack sees nothing and the implementation is ' +
        'nonetheless completely unprotected. Change the constant below and watch it happen.'
    ),
    el(
      'div',
      { class: 'controls' },
      labelled('frozen-constant', 'Frozen mask constant', constantSelect),
      el('div', { class: 'field' }, runBtn)
    ),
    status,
    out,
    el(
      'details',
      {},
      el('summary', { text: 'The two identities this act rests on' }),
      el(
        'div',
        { class: 'derivation' },
        el('p', {}, 'Hamming-weight correlation against a frozen constant c, over uniform v:'),
        el('p', { class: 'mono' }, 'HW(v XOR c) = HW(c) + sum_i s_i v_i,   s_i = +1 if c_i = 0, -1 if c_i = 1'),
        el('p', { class: 'mono' }, 'rho(HW(v XOR c), HW(v)) = (1/4)(8 - 2 HW(c)) / 2 = 1 - HW(c)/4'),
        el(
          'p',
          {},
          'so weight 0 leaves it at 1, weight 8 inverts it to -1, and any of the 70 balanced bytes ' +
            'drives it to exactly 0.'
        ),
        el('p', {}, 'Single-bit difference of means on bit i, same frozen c:'),
        el('p', { class: 'mono' }, 'E[HW(v XOR c) | v_i = b] = (b XOR c_i) + 3.5'),
        el('p', { class: 'mono' }, 'difference = (1 XOR c_i) - (0 XOR c_i) = 1 - 2 c_i = +-1'),
        el(
          'p',
          {},
          'The other seven bits average 3.5 in both partitions because v is uniform over the whole byte ' +
            'space, so they cancel exactly. The magnitude is one unit whatever c is; only the sign moves. ' +
            'Both identities are checked exhaustively over all 256 constants in the unit suite, with no ' +
            'sampling involved.'
        )
      )
    ),
    el(
      'details',
      {},
      el('summary', { text: 'What this act does NOT claim' }),
      el(
        'div',
        { class: 'derivation' },
        el(
          'p',
          {},
          'The fixture here is a mask frozen ACROSS encryptions — the same constant for every trace. ' +
            'That is a clean, honest failure of randomness and it is what the panel measures.'
        ),
        el(
          'p',
          {},
          'It is not the same thing as reusing one mask across the sixteen S-box lookups WITHIN a single ' +
            'encryption, and this page does not claim first-order CPA would work against that. ' +
            'Low-randomness masking schemes that share a mask within a computation can remain first-order ' +
            'secure; the attacks that do succeed against them tend to be horizontal, collision-based, or ' +
            'second-order, and none of those is what is running here. Calling any of them "plain CPA" ' +
            'would be an overclaim.'
        )
      )
    )
  );

  replace(
    out,
    verdict('info', 'Not measured yet.', [
      `Press Measure this constant to run three benches — unprotected, frozen at ${hexByte(constant)}, and ` +
        `fresh-masked — over ${TRACES} traces each.`,
    ])
  );
}
