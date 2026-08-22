/**
 * Masked Core — mount point.
 *
 * The standardised hero, the persistent leakage-model banner, the tab shell and
 * the scripture footer. Panels render LAZILY on first activation: a tab that has
 * never been opened is not in the DOM at all, which keeps first paint cheap and
 * means a renderer that threw would leave a visibly empty region rather than a
 * plausible-looking wrong one.
 */
import './style.css';
import { el, replace } from './ui/dom';
import { renderBench } from './ui/panels/bench';
import { renderConstruction } from './ui/panels/construction';
import { renderCost } from './ui/panels/cost';
import { renderFrozen } from './ui/panels/frozen';
import { renderScope } from './ui/panels/scope';
import { renderSplit } from './ui/panels/split';

interface TabSpec {
  readonly id: string;
  readonly act: string | null;
  readonly label: string;
  readonly render: (root: HTMLElement) => void;
}

const TABS: readonly TabSpec[] = [
  { id: 'split', act: null, label: 'The split', render: renderSplit },
  { id: 'construction', act: null, label: 'Masked AES', render: renderConstruction },
  { id: 'bench', act: 'Acts 1–3', label: 'The bench', render: renderBench },
  { id: 'frozen', act: 'Act 4', label: 'Frozen mask', render: renderFrozen },
  { id: 'cost', act: null, label: 'Cost', render: renderCost },
  { id: 'scope', act: 'Act 5', label: 'Scope', render: renderScope },
];

function hero(): HTMLElement {
  return el(
    'div',
    { class: 'cl-hero' },
    el(
      'div',
      { class: 'cl-hero-main' },
      el('h1', { class: 'cl-hero-title', text: 'Masked Core' }),
      el('p', { class: 'cl-hero-sub', text: 'First-order Boolean masking · AES-128 · CPA' }),
      el('p', {
        class: 'cl-hero-desc',
        text:
          'Run correlation power analysis against a real AES-128, switch on first-order Boolean masking ' +
          'and watch the same attack go blind, then combine two leakage samples and pull the same key ' +
          'byte back out.',
      })
    ),
    el(
      'aside',
      { class: 'cl-hero-why', 'aria-label': 'Why it matters' },
      el('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
      el('p', {
        class: 'cl-hero-why-text',
        text:
          'Masking is the countermeasure smartcards, TPMs and secure elements are certified on, and it ' +
          'is usually described as if it closed the side channel. It does not: it raises the price. ' +
          'Knowing what that price is — and which two mistakes reduce it to nothing — is the difference ' +
          'between a defence you have deployed and one you are hoping for.',
      })
    )
  );
}

function modelBanner(): HTMLElement {
  return el(
    'div',
    { class: 'model-banner' },
    el('span', { class: 'glyph', 'aria-hidden': 'true', text: '⚠' }),
    el(
      'p',
      {},
      el('strong', { text: 'Idealised leakage model. ' }),
      'Every measurement on this page assumes power tracks the Hamming weight of one register at a ' +
        'time, plus Gaussian noise, and the traces are simulated from the real ciphers rather than ' +
        'captured from silicon. Real masked hardware also leaks through glitches, transitions and ' +
        'coupling, which are not modelled here — see the Scope tab. Not production crypto; a teaching ' +
        'demo.'
    )
  );
}

function mount(app: HTMLElement): void {
  const tablist = el('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Exhibits' });
  const panels = el('div');
  const buttons: HTMLButtonElement[] = [];
  const containers: HTMLElement[] = [];
  const rendered = new Set<string>();

  TABS.forEach((tab, i) => {
    const btn = el('button', {
      type: 'button',
      class: 'tab-btn',
      role: 'tab',
      id: `tab-${tab.id}`,
      'aria-controls': `panel-${tab.id}`,
      'aria-selected': i === 0 ? 'true' : 'false',
      tabindex: i === 0 ? '0' : '-1',
    });
    if (tab.act) btn.appendChild(el('span', { class: 'tab-act', text: tab.act }));
    btn.appendChild(el('span', { text: tab.label }));

    const panel = el('div', {
      class: 'panel',
      role: 'tabpanel',
      id: `panel-${tab.id}`,
      'aria-labelledby': `tab-${tab.id}`,
      tabindex: '0',
    });
    if (i !== 0) panel.hidden = true;

    buttons.push(btn);
    containers.push(panel);
    tablist.appendChild(btn);
    panels.appendChild(panel);
  });

  function activate(index: number, focus = false): void {
    TABS.forEach((tab, i) => {
      const on = i === index;
      buttons[i].setAttribute('aria-selected', on ? 'true' : 'false');
      buttons[i].setAttribute('tabindex', on ? '0' : '-1');
      containers[i].hidden = !on;
      if (on && !rendered.has(tab.id)) {
        rendered.add(tab.id);
        tab.render(containers[i]);
      }
    });
    if (focus) buttons[index].focus();
  }

  buttons.forEach((btn, i) => {
    btn.addEventListener('click', () => activate(i));
    // Arrow-key roving focus is what makes a tablist a tablist rather than a
    // row of buttons that happens to carry the roles.
    btn.addEventListener('keydown', (e) => {
      const keys: Record<string, number> = {
        ArrowRight: (i + 1) % TABS.length,
        ArrowLeft: (i - 1 + TABS.length) % TABS.length,
        Home: 0,
        End: TABS.length - 1,
      };
      const next = keys[e.key];
      if (next === undefined) return;
      e.preventDefault();
      activate(next, true);
    });
  });

  replace(app, hero(), modelBanner(), el('main', {}, tablist, panels));
  activate(0);

  const footer = el(
    'footer',
    { class: 'scripture-footer' },
    el('p', {
      text:
        'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    })
  );
  app.insertAdjacentElement('afterend', footer);
}

const app = document.getElementById('app');
if (app) mount(app);
