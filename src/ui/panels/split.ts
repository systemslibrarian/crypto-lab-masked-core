/**
 * "The Split" — the headline mechanism, shown rather than asserted.
 *
 * The whole lab turns on one fact: masking replaces a secret byte with two
 * bytes that each tell you nothing, and the secret is recoverable only from
 * BOTH TOGETHER. Prose cannot make that land. So this panel puts the two
 * pictures side by side and lets the learner drag the secret between them:
 *
 *   left  — each share's Hamming-weight distribution over all 256 masks. Drag
 *           the secret across its whole range and NEITHER BAR MOVES. That is
 *           first-order security, as a thing you watched happen.
 *   right — the average masked weight given the mask's weight. This one tilts
 *           the moment the secret moves, and its slope is 1 - HW(secret)/4.
 *           That is the second-order attack's foothold, in one line.
 *
 * Nothing here is sampled: both curves are computed over all 256 masks exactly,
 * and the closed form is drawn on top of the measurement so the two can be
 * compared rather than believed.
 */
import { HW, HW_MEAN } from '../../leakage/model';
import {
  conditionalMeanByMaskWeight,
  exhaustiveCombinedMean,
  predictedCombinedMean,
  predictedConditionalMean,
  shareHistogram,
} from '../../mask/combining';
import { Rng } from '../../leakage/rng';
import { drawChart, makeChart } from '../charts';
import { el, kv, labelled, replace, verdict } from '../dom';
import { bin8, hexByte, r4 } from '../format';

const BIN_LABELS = ['0', '1', '2', '3', '4', '5', '6', '7', '8'];

export function renderSplit(root: HTMLElement): void {
  // 0x41 has Hamming weight 2, so the joint chart arrives with a visible tilt.
  // A balanced default (weight 4) would open on a flat line and a mean product
  // of zero — the one secret for which the mechanism is invisible, which is a
  // discovery to be made by dragging, not the first thing a reader sees.
  let secret = 0x41;
  let mask = 0x3a;
  const rng = new Rng(7);

  const secretInput = el('input', {
    type: 'range',
    min: '0',
    max: '255',
    step: '1',
    value: String(secret),
  }) as HTMLInputElement;

  const marginalsChart = makeChart(900, 400);
  const jointChart = makeChart(900, 400);
  const shareOut = el('div', { id: 'split-shares' });
  const marginalsNote = el('p', { class: 'note', id: 'split-marginals-note' });
  const jointNote = el('p', { class: 'note', id: 'split-joint-note' });
  const productOut = el('div', { id: 'split-product' });
  const marginalsLegend = el('ul', { class: 'legend', role: 'list', id: 'split-marginals-legend' });
  const jointLegend = el('ul', { class: 'legend', role: 'list', id: 'split-joint-legend' });

  function legendItem(label: string, colorVar: string, value: string): HTMLElement {
    return el(
      'li',
      { role: 'listitem' },
      el('span', {
        class: 'swatch',
        'aria-hidden': 'true',
        style: `border-top-color: var(${colorVar})`,
      }),
      el('span', { text: `${label}: ` }),
      el('span', { class: 'value', text: value })
    );
  }

  function paint(): void {
    const h = HW[secret];
    const maskedByte = (secret ^ mask) & 0xff;

    // ── One concrete split, in full ─────────────────────────────────────────
    replace(
      shareOut,
      kv([
        ['Secret byte v', `${hexByte(secret)}  ${bin8(secret)}  (Hamming weight ${h})`],
        ['Mask m', `${hexByte(mask)}  ${bin8(mask)}  (weight ${HW[mask]})`],
        [
          'Masked share v XOR m',
          `${hexByte(maskedByte)}  ${bin8(maskedByte)}  (weight ${HW[maskedByte]})`,
        ],
        [
          'Recombined',
          `${hexByte(maskedByte ^ mask)} — the two shares XOR back to the secret`,
        ],
      ])
    );

    // ── Marginals: identical for every secret ───────────────────────────────
    const maskHist = shareHistogram(secret, 'mask');
    const maskedHist = shareHistogram(secret, 'masked');
    drawChart(
      marginalsChart,
      [
        { label: 'mask share', colorVar: '--accent', values: maskHist, bars: true },
        { label: 'masked share', colorVar: '--ok', values: maskedHist },
      ],
      {
        title: 'Each share on its own, over all 256 masks',
        xLabel: 'Hamming weight of the share',
        yLabel: 'count',
        xTick: (i) => BIN_LABELS[i],
        yMin: 0,
      },
      `Two overlapping distributions of Hamming weight, both the binomial 1, 8, 28, 56, 70, 56, 28, 8, 1. ` +
        `They are identical to each other and identical for every secret byte, including the current secret ${hexByte(secret)}. ` +
        `Neither share on its own carries any information about the secret.`
    );
    const same = maskHist.every((v, i) => v === maskedHist[i]);
    replace(
      marginalsLegend,
      legendItem('mask share m', '--accent', maskHist.join(', ')),
      legendItem('masked share v XOR m', '--ok', maskedHist.join(', '))
    );
    replace(
      marginalsNote,
      same
        ? 'Both counts are the binomial 1, 8, 28, 56, 70, 56, 28, 8, 1 — and they stay there for every one of the 256 secrets. Drag the secret and watch nothing move.'
        : 'The two distributions differ, which would mean one share leaks on its own.'
    );

    // ── Joint: the dependence that survives ─────────────────────────────────
    const measured = conditionalMeanByMaskWeight(secret);
    const predicted = Array.from({ length: 9 }, (_, k) => predictedConditionalMean(secret, k));
    const slope = 1 - h / 4;
    drawChart(
      jointChart,
      [
        { label: 'measured', colorVar: '--alarm', values: measured },
        { label: 'closed form', colorVar: '--accent', values: predicted, dashed: true },
      ],
      {
        title: 'Average masked weight, given the MASK weight',
        xLabel: 'Hamming weight of the mask',
        yLabel: 'mean HW(v^m)',
        xTick: (i) => BIN_LABELS[i],
      },
      `A straight line of slope ${slope.toFixed(2)}, running from ${measured[0].toFixed(2)} at mask weight 0 ` +
        `to ${measured[8].toFixed(2)} at mask weight 8, for the current secret ${hexByte(secret)} of Hamming weight ${h}. ` +
        `The closed form HW(v) + k times (1 minus HW(v)/4) is drawn over it and coincides exactly.`
    );
    replace(
      jointLegend,
      legendItem('measured over all 256 masks', '--alarm', measured.map((v) => v.toFixed(2)).join(', ')),
      legendItem('closed form HW(v) + k(1 - HW(v)/4)', '--accent', `slope ${slope.toFixed(3)}`)
    );
    replace(
      jointNote,
      slope === 0
        ? `This secret has Hamming weight 4, so the line is exactly flat — a Hamming-weight statistic cannot see this particular secret at all, even though the dependence is still there in the full joint distribution. That blind spot is what the Frozen mask act turns into a trap.`
        : `The line tilts as soon as the secret moves. Its slope is 1 minus ${h} over 4, which is ${slope.toFixed(2)} — so the mask's weight and the masked value's weight are NOT independent, and an attacker who can see both samples has something to work with.`
    );

    // ── The centred product, measured against its closed form ───────────────
    const measuredProduct = exhaustiveCombinedMean(secret);
    const predictedProduct = predictedCombinedMean(secret);
    const agrees = Math.abs(measuredProduct - predictedProduct) < 1e-9;
    replace(
      productOut,
      kv([
        [
          'Measured mean product',
          `${r4(measuredProduct)}  (averaged over all 256 masks)`,
        ],
        ['Closed form -(1/2)(HW(v) - 4)', r4(predictedProduct)],
      ]),
      verdict(
        agrees ? 'pass' : 'fail',
        agrees ? 'Identical.' : 'Disagreement.',
        [
          agrees
            ? `Multiplying the two centred leakages and averaging gives ${r4(measuredProduct)}, which is exactly what -(1/2)(HW(v) - ${HW_MEAN}) predicts for a secret of weight ${h}. The secret did not disappear when it was masked. It moved from the average of one sample to the product of two.`
            : `The measurement and the closed form disagree, which should be impossible: one of them is wrong.`,
        ]
      )
    );
  }

  secretInput.addEventListener('input', () => {
    secret = Number(secretInput.value) & 0xff;
    paint();
  });

  const newMaskBtn = el('button', { type: 'button', text: 'Draw a new mask' });
  newMaskBtn.addEventListener('click', () => {
    mask = rng.byte();
    paint();
  });

  replace(
    root,
    el('h2', { text: 'What masking actually does' }),
    el(
      'p',
      { class: 'lede' },
      'A chip leaks. Not its data over a network — its power draw over the wire feeding it. ' +
        'Because a transistor pulls more current the more bits it drives high, a cheap oscilloscope ' +
        'measuring current can tell roughly how many 1-bits a chip just handled, and a few hundred of ' +
        'those measurements are enough to work backwards to a secret key.'
    ),
    el(
      'p',
      { class: 'lede' },
      'Masking is the standard defence, and the idea is disarmingly simple: never hold the secret. ' +
        'Split every secret byte into two random-looking bytes that XOR back to it, and handle only ' +
        'those. Each half is uniformly random on its own, so a probe watching one of them learns ' +
        'nothing at all. This page is about what that promise is worth — where it holds exactly, ' +
        'what it costs an attacker, and the two ways it comes apart.'
    ),
    el(
      'div',
      { class: 'controls' },
      labelled('split-secret', 'Secret byte v', secretInput),
      el('div', { class: 'field' }, newMaskBtn)
    ),
    shareOut,
    el(
      'div',
      { class: 'grid' },
      el(
        'div',
        { class: 'card' },
        el('h3', { text: 'Either half alone: nothing' }),
        el(
          'p',
          { class: 'note' },
          'Both shares, across every one of the 256 possible masks, for the secret you have selected.'
        ),
        marginalsChart,
        marginalsLegend,
        marginalsNote
      ),
      el(
        'div',
        { class: 'card' },
        el('h3', { text: 'Both halves together: the secret' }),
        el(
          'p',
          { class: 'note' },
          'The same 256 masks, now grouped by the mask’s own Hamming weight.'
        ),
        jointChart,
        jointLegend,
        jointNote
      )
    ),
    el(
      'div',
      { class: 'card' },
      el('h3', { text: 'The number the second-order attack actually uses' }),
      el(
        'p',
        {},
        'Centre each leakage on 4, the average Hamming weight of a random byte, then multiply the two ' +
          'together. Averaged over the masks, that single number is an exactly linear function of the ' +
          'secret’s Hamming weight — which is all a correlation attack needs.'
      ),
      productOut
    ),
    el(
      'details',
      {},
      el('summary', { text: 'The derivation, one bit at a time' }),
      el(
        'div',
        { class: 'derivation' },
        el(
          'p',
          {},
          'Take a single bit first. The mask bit m is a fair coin and the secret bit is z, so the two ' +
            'leakages are m and z XOR m, each centred at 1/2:'
        ),
        el('p', { class: 'mono' }, 'z = 0:  E[(m - 1/2)(m - 1/2)]        = +1/4'),
        el('p', { class: 'mono' }, 'z = 1:  E[(m - 1/2)((1-m) - 1/2)]   = -1/4'),
        el(
          'p',
          {},
          'so the expectation is 1/4 - z/2, which is -(1/2)(z - 1/2). Now stack eight independent bits. ' +
            'HW(m) - 4 is the sum of the eight (m_i - 1/2) terms and HW(v XOR m) - 4 is the sum of the ' +
            'eight (v_i XOR m_i - 1/2) terms; every cross term with i not equal to j multiplies two ' +
            'independent zero-mean factors and vanishes, so what is left is the one-bit result eight ' +
            'times over:'
        ),
        el('p', { class: 'mono' }, 'E[(HW(m) - 4)(HW(v XOR m) - 4)] = -(1/2)(HW(v) - 4)'),
        el(
          'p',
          {},
          'Note the minus sign. It is why a correct second-order key guess shows up on the bench as a ' +
            'NEGATIVE correlation, and the bench prints the sign so you can check that rather than take it ' +
            'on trust. The price is variance: each individual product carries the noise of both samples ' +
            'multiplied together, which is why the attack still works and still costs far more traces.'
        )
      )
    )
  );

  paint();
}
