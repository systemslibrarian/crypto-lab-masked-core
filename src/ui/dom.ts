/**
 * Minimal DOM helpers. No framework: the point of this lab is that every
 * intermediate is inspectable, and a build with one dependency for the
 * cryptography and none for the view is easier to read straight through.
 */

type Attrs = Record<string, string | number | boolean | undefined | null>;
export type Child = Node | string | number | null | undefined | false;

/**
 * Roles and ARIA are set as ATTRIBUTES here, never as JS properties, so the
 * a11y gate's `assertListSemantics` (which asks the DOM rather than grepping
 * the source) sees what the markup actually carries.
 */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = String(v);
    else if (k === 'text') node.textContent = String(v);
    else if (k === 'html') throw new Error('refusing to set innerHTML');
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  append(node, children);
  return node;
}

export function append(parent: Node, children: Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    parent.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
  }
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

/** Replace a container's contents in one go — never leaves a half-rendered
 *  panel behind if a renderer throws part-way. */
export function replace(node: Element, ...children: Child[]): void {
  const frag = document.createDocumentFragment();
  append(frag, children);
  clear(node);
  node.appendChild(frag);
}

export type VerdictTone = 'pass' | 'fail' | 'alarm' | 'info';

const GLYPHS: Record<VerdictTone, string> = {
  pass: '✓',
  fail: '✕',
  alarm: '⚠',
  info: '·',
};

/**
 * A verdict is always glyph + label + sentence, and the glyph is
 * `aria-hidden` because the LABEL already carries the same meaning in words —
 * WCAG 1.4.1 is satisfied by the wording, not by the tint.
 *
 * The tone tracks SYSTEM INTEGRITY, not the return value. A recovered key is
 * `alarm`, never `pass`: the attack succeeding is the countermeasure failing.
 */
export function verdict(tone: VerdictTone, label: string, detail: Child[]): HTMLElement {
  return el(
    'div',
    { class: `verdict verdict-${tone}`, role: 'status', 'aria-live': 'polite' },
    el('span', { class: 'glyph', 'aria-hidden': 'true', text: GLYPHS[tone] }),
    el('span', {}, el('span', { class: 'verdict-label', text: `${label} ` }), ...detail)
  );
}

export function pill(tone: 'ok' | 'bad' | 'alarm' | 'plain', label: string): HTMLElement {
  const cls = tone === 'plain' ? 'pill' : `pill pill-${tone}`;
  return el('span', { class: cls, text: label });
}

/** A definition list of labelled readouts. */
export function kv(rows: [string, Child][]): HTMLElement {
  const dl = el('dl', { class: 'kv' });
  for (const [k, v] of rows) {
    dl.appendChild(el('dt', { text: k }));
    dl.appendChild(el('dd', {}, v));
  }
  return dl;
}

/**
 * A scrollable region needs a keyboard route and a name, or arrow-key users
 * cannot reach what is clipped (WCAG 2.1.1) — this fails on the Linux CI
 * runner even where it passes locally.
 */
export function scroller(label: string, ...children: Child[]): HTMLElement {
  return el('div', { class: 'table-wrap', role: 'group', tabindex: '0', 'aria-label': label }, ...children);
}

export function labelled(id: string, labelText: string, control: HTMLElement): HTMLElement {
  control.id = id;
  return el('div', { class: 'field' }, el('label', { for: id, text: labelText }), control);
}

/** Yield to the browser so a long attack does not freeze the tab. */
export function nextFrame(): Promise<void> {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()));
}
