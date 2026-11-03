import { distributionDistance, rawMoment, shareSumDistribution, type Distribution } from '../../leakage/moment-distribution';
import { el, labelled, replace, scroller, verdict } from '../dom';

/** Population distributions, not a sampled significance test or a key attack. */
export function renderMomentComparison(root: HTMLElement): void {
  const comparison = el('select', {},
    el('option', { value: '1', text: 'Secret 0 versus secret 1' }),
    el('option', { value: '0', text: 'Secret 0 versus secret 0 — control' }));
  const noise = el('select', {},
    el('option', { value: '0', text: 'None — exact share sum' }),
    el('option', { value: '2', text: '2 independent fair noise bits' }),
    el('option', { value: '8', text: '8 independent fair noise bits' }));
  const statistic = el('select', {},
    ...['Mean E[L]', 'Second raw moment E[L²]', 'Third raw moment E[L³]', 'Fourth raw moment E[L⁴]']
      .map((label, i) => el('option', { value: String(i + 1), text: label })));
  const plots = el('div', { class: 'grid', id: 'moments-plots' });
  const summaries = el('div', { id: 'moments-summary' });
  const decision = el('div', { id: 'moments-decision' });

  function histogram(d: Distribution, label: string, id: string): HTMLElement {
    const rows = d.values.map((value, i) => el('li', {},
      el('span', { class: 'moment-bin', text: String(value) }),
      el('span', { class: 'moment-track', 'aria-hidden': 'true' },
        el('span', { class: 'moment-bar', style: `width:${d.probabilities[i] * 100}%;` })),
      el('span', { class: 'moment-probability', text: `${(d.probabilities[i] * 100).toFixed(3)}%` })));
    return el('div', { class: 'card' }, el('h4', { text: label }),
      el('p', { class: 'note', text: 'Observed sum L → probability (percentages rounded to three decimals; each bar spans 0–100%).' }),
      el('ul', { class: 'moment-histogram', id, role: 'list', 'aria-label': label }, ...rows));
  }

  function render(): void {
    const other = Number(comparison.value);
    const coins = Number(noise.value);
    const a = shareSumDistribution(0, coins);
    const b = shareSumDistribution(other, coins);
    const order = Number(statistic.value);
    const left = rawMoment(a, order);
    const right = rawMoment(b, order);
    const distance = distributionDistance(a, b);
    replace(plots, histogram(a, 'Group A: secret 0', 'moments-a'), histogram(b, `Group B: secret ${other}`, 'moments-b'));
    replace(summaries, scroller('Exact population moments', el('table', {},
      el('caption', { text: 'All four raw moments of the observed sum' }),
      el('thead', {}, el('tr', {}, ...['Order', 'Group A', 'Group B'].map(t => el('th', { scope: 'col', text: t })))),
      el('tbody', {}, ...[1, 2, 3, 4].map(k => el('tr', {},
        el('th', { scope: 'row', text: String(k) }),
        el('td', { text: String(rawMoment(a, k)) }), el('td', { text: String(rawMoment(b, k)) })))))));
    const label = distance === 0 ? 'Same-distribution control.' : left === right ? 'Matching summary, different distributions.' : 'This summary distinguishes the groups.';
    replace(decision, verdict('info', label, [
      `Selected moment: A = ${left}, B = ${right}. Total variation distance = ${distance.toFixed(6)} ` +
      '(half the sum of absolute probability differences). ',
      distance === 0 ? 'The two populations are identical by construction.' :
        left === right ? 'This statistic hides a population difference visible in the histograms. Matching it does not establish secrecy.' :
          'A population difference is visible in this statistic; that alone is not an AES key recovery.',
    ]));
  }
  for (const control of [comparison, noise, statistic]) control.addEventListener('change', render);
  const reset = el('button', { type: 'button', text: 'Reset comparison' });
  reset.addEventListener('click', () => { comparison.value = '1'; noise.value = '0'; statistic.value = '1'; render(); });
  replace(root,
    el('h3', { id: 'moment-distributions', text: 'When the average hides the difference' }),
    el('p', {}, 'Predict first: if two leakage distributions have the same mean, second moment and third moment, must they be identical?'),
    el('p', {}, 'Separate synthetic model: split one secret bit into four uniformly chosen bits whose XOR equals that secret. ' +
      'Observe their joint Hamming-weight sum L. With no noise, secret 0 permits sums 0, 2 and 4; secret 1 permits 1 and 3. ' +
      'This joint observation is outside the AES bench’s one-register model.'),
    el('div', { class: 'controls' }, labelled('moments-comparison', 'Compare groups', comparison),
      labelled('moments-noise', 'Additive noise', noise), labelled('moments-statistic', 'Summary statistic', statistic), reset),
    plots, summaries, decision,
    el('p', { class: 'note' }, 'Every probability is exhaustively calculated. Noise adds the sum of independent fair bits minus half their count; ' +
      'it is discrete, not Gaussian. There is no sample budget, p-value, finite-trace detection claim or hardware measurement here. ' +
      'Adding this noise is not a recommended hardware defense. The same-secret control should remain identical at every noise setting.'),
    el('p', {}, 'A raw moment of order k averages L raised to power k. The first three match here; the fourth exposes the difference. ' +
      'With finite measurements a test may miss a difference: report “not detected,” not “secure.” This comparison is secret 0 versus secret 1, not fixed-versus-random TVLA.'),
    el('p', { class: 'note' }, 'Research credit: Thorben Moos, ',
      el('a', { href: 'https://doi.org/10.13154/tches.v2019.i3.202-232', text: 'Static Power SCA of Sub-100 nm CMOS ASICs and the Insecurity of Masking Schemes in Low-Noise Environments' }),
      ' (TCHES 2019), pp. 216–221. The paper motivates comparing distributions with selected moments. ' +
      'These four-share distributions are an independently derived teaching example, not the paper’s ASIC traces or a reproduction of its attack.')
  );
  render();
}
