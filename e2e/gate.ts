import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the gate
 * this replaces did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES this lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the rendering a reduced-motion reader actually gets was never once the
 *     rendering that got scanned. This lab declares no keyframes at all and
 *     cancels every transition inside its own reduced-motion block, so the
 *     preference genuinely changes what paints. This gate sets the
 *     preference through `emulateMedia`, asserts from inside the page that it
 *     took effect (`test.use({ reducedMotion })` silently does nothing on
 *     Playwright 1.61.1), and injects nothing.
 *
 *  2. IT FORCED EVERY PANEL VISIBLE FROM SCRIPT. The old drive stripped every
 *     `[hidden]` attribute and set every `<details>.open` by JS before its only
 *     scan. Stripping `hidden` puts all six tabpanels on screen AT ONCE — a
 *     rendering no reader can reach and axe then scans instead of the real one
 *     — and script-opening the disclosures means the SHUT state, which is what
 *     every reader arrives at, was never scanned at all. This gate switches
 *     tabs by clicking them and opens each disclosure through its `<summary>`,
 *     which is the route a reader has, and scans before and after.
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. The old drive clicked
 *     every button whose label matched a regex, swallowed every failure with
 *     `.catch(() => {})`, waited a fixed 120ms per tab, and scanned ONCE at the
 *     end — so the invalid-key rendering, the malformed-hex branch, the
 *     refusal verdicts, the frozen-mask trap and the second-order result were
 *     all overwritten before anything measured them, and a click that silently
 *     did nothing looked identical to one that worked. This drive names every
 *     control it touches, waits on a real completion signal after each — the
 *     panels' `data-run` counters, never a fixed timeout — and scans after
 *     every step, at 1280 and at 380.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. The surfaces that carry
 *     this lab's meaning — every `.verdict-*` tone, all four `.pill` states,
 *     the `.model-banner`, the hero aside and the shared top bar's ink — are
 *     `color-mix()` fills axe files under `incomplete` rather than judging. So
 *     is an `aria-label` on a role-less element.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. The old
 *     spec hand-rolled one luminance check over two input selectors, reading
 *     the DECLARED `border-top-color` and `background-color` — blind to
 *     `color-mix()`, to composited backdrops, to every `.tab-btn`, `.seg-btn`,
 *     `select` and `input`, and to all states past first paint.
 *     `nontext.ts` replaces it with a measured oracle over every control at
 *     every driven state, and `expectNoHorizontalOverflow` adds the 1.4.10
 *     check axe has no rule for.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * Under the reduced motion this gate asserts, `style.css`'s reduced-motion
 * block cancels every transition on the page, so `getAnimations()` is normally
 * empty and this returns on the sixth frame. It
 * stays because the shared top bar's `.cl-btn` transitions are declared
 * OUTSIDE the lab's `@media` block — `* { transition: none !important }` wins
 * today, but that is a property of the current stylesheet, not of the page.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * has EXACTLY that shape in miniature: `@keyframes fade` and `@keyframes
 * reveal` both start `from { opacity: 0 }`, and every tab panel and every
 * stepper line rides one of them. The reduced-motion block cancels both with
 * `animation: none`, which restores the static `opacity: 1` — correct today,
 * and this assertion is what makes that a measurement rather than a reading.
 *
 * `aria-hidden` subtrees are excluded; what this lab hides is decorative
 * verdict/pill glyphs beside their own words — see `contrast.ts`.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. Every panel here renders synchronously at first activation, so a
 * renderer that throws leaves that tabpanel EMPTY — and an empty region is
 * exactly what a scan reports as perfectly accessible. Attach before `boot`,
 * assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's own
 * hero is a `<div class="cl-hero">`, not a `<header>`, so nothing here implies
 * a second banner today — but the template's own hero snippet uses `<header>`,
 * the shared bar's `dedupeBanner()` exists because other labs in this fleet
 * shipped exactly that, and the hero is the part of this page most likely to
 * be re-templated. Asserting the OUTCOME rather than the markup catches it.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * The lists here are the chart legends and the Scope panel's inventories, all
 * styled `list-style: none` — which is exactly the declaration that makes
 * Safari and VoiceOver DROP a list's implicit role. `ui/dom.ts` compensates the
 * documented way, with an explicit `role="list"` on the container and
 * `role="listitem"` on every child, so here an explicit role on a list is the
 * fix rather than the defect. What is asserted is therefore the SHAPE of that
 * fix: any explicit role on a `ul`/`ol` must be `list` (any other value orphans
 * every `<li>` under it), and a `role="list"` must never sit on an empty
 * element, because axe applies `aria-required-children` to the explicit role
 * and fails it the day a legend renders with no entries. Roles can be assigned
 * as JS properties in an element-creation helper, so ask the DOM rather than
 * grepping the source.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
      )
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children'
  ).toEqual([]);
}

/**
 * Load the page with reduced motion actually in effect, and assert the content
 * every scan relies on is really on the page — including the lab's DEFAULTS,
 * which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.x, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. Nothing in this lab's JS branches on
 * `matchMedia`, but the CSS reduced-motion block is the only thing standing
 * between a scan and a mid-flight transition colour, so the assertion is still
 * the difference between scanning the reduced-motion rendering and merely
 * believing we did.
 *
 * Dark is the only theme here and there is no toggle, so the theme is asserted
 * rather than chosen: `index.html`'s head script writes `theme` to
 * localStorage and stamps `data-theme="dark"` before first paint, and the
 * literal is also on the `<html>` tag so it holds with JS off. Seeding
 * localStorage with `light` first is deliberate — it proves the head script
 * OVERWRITES a stale value rather than reading it, which is the specific defect
 * the fleet's theme-sync checker was widened to catch.
 *
 * The defaults are asserted at length because `main.ts` renders each tabpanel
 * lazily on first activation. A navigation that resolves proves nothing: a
 * renderer that threw would leave `#panel-split` empty, and an empty region is
 * exactly what a scan reports as perfectly accessible.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  // Seed the WRONG theme on purpose; the head script must overwrite it.
  await page.addInitScript(() => localStorage.setItem('theme', 'light'));
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  expect(
    await page.evaluate(() => localStorage.getItem('theme')),
    "the head script must overwrite a stored 'light', not read it"
  ).toBe('dark');
  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.getByRole('tab')).toHaveCount(6);

  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run
  // says nothing about.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);

  // Dark is the only theme, so the page must carry no theme control at all —
  // not the shared bar's, which was removed, and not a lab-local one. The
  // shared CSS hides any lab toggle with `display:none !important`, which would
  // leave a dead-but-known element; asserting the count at zero catches the day
  // one is added without going through that list.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]')
  ).toHaveCount(0);

  // ── The persistent model banner ─────────────────────────────────────────
  // The brief requires the leakage model to be stated on the page at all
  // times. Asserting it is OUTSIDE every tabpanel is what stops that being
  // satisfied by a tab nobody opens.
  await expect(page.locator('.model-banner')).toBeVisible();
  expect(
    await page.locator('.model-banner').evaluate((el) => el.closest('[role="tabpanel"]') === null),
    'the model statement must not live inside a tab panel'
  ).toBe(true);

  // ── The arrival state: The split, rendered; five panels unrendered ──────
  await expect(page.locator('#panel-split .verdict-pass')).toContainText('Identical');
  await expect(page.locator('#panel-split canvas')).toHaveCount(2);
  await expect(page.locator('#split-shares')).toContainText('0x41');
  for (const id of ['construction', 'bench', 'frozen', 'cost', 'scope']) {
    await expect(page.locator(`#panel-${id}`)).toBeHidden();
    await expect(page.locator(`#panel-${id}`)).toBeEmpty();
  }

  // Every canvas carries the text equivalent the charts depend on, and it is
  // not the placeholder.
  for (const c of await page.locator('#panel-split canvas').all()) {
    await expect(c).toHaveAttribute('role', 'img');
    const label = await c.getAttribute('aria-label');
    expect(label && label.length > 60 && !label.includes('not yet drawn')).toBe(true);
  }

  // ── Disclosures ship shut ───────────────────────────────────────────────
  await expect(page.locator('#panel-split details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all. This lab's long
 * values are 32-character key hex and full 16-byte block hex; those wrap via
 * `overflow-wrap: anywhere` on `.kv dd`, and the two tables live inside
 * `.table-wrap` scrollers. The shapes at risk are therefore a new unwrapped
 * `<code>` run, a `.grid` item whose automatic minimum size is the min-content
 * of a 128-character line, and — the one specific to this lab — a `<canvas>`,
 * which has an intrinsic width of over a thousand pixels and only stays inside
 * a 380px viewport because `.chart` sets `width: 100%`. At 380px that is
 * precisely what this check exists to catch.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This lab has real scrollers: every table sits in a `.table-wrap` with
 * `overflow-x: auto`, and at 380px they genuinely clip. `ui/dom.ts`'s
 * `scroller()` is the only way one gets built here and it always attaches
 * `role="group"`, `tabindex="0"` and an `aria-label` — so this assertion is
 * what proves nothing bypassed that helper. It fails on the Linux CI runner
 * even where it passes on a local browser, which is the reason it is not
 * optional.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. The
 * `hidden` tabpanels here take the `display: none` route, which is why five
 * panels' worth of buttons are legitimately absent from the tab order.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` with
 * full opacity and slides in on focus. The drive scans it focused.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`, and this repo's baseline was
 * captured by that live path.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here because the surfaces carrying
 *    this lab's meaning are `color-mix()` fills axe cannot resolve: every
 *    verdict tone, all four pill states, the model banner, the true-key row
 *    highlight, the hero aside and the shared bar's ink. Everything
 *    else in that bucket is a real result axe simply could not finish —
 *    including `aria-prohibited-attr`, which is where an `aria-label` on a
 *    role-less element hides. This page leans on getting that right: the act
 *    presets, the mask-source segment, every `.table-wrap` scroller and every
 *    `<canvas>` carry an `aria-label`, and each is paired with a real role
 *    (`group`, `img`). Drop any of those roles and the label is silently
 *    discarded — which for the canvases would mean the charts' only text
 *    equivalent disappearing without a single axe violation.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted —
 *    SC 1.4.3 is about what a reader SEES; see `contrast.ts` for what this
 *    lab hides and why it is measured anyway.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` holding an `<aside class="cl-hero-why">`, two `<nav>`s
  // (the shared actions and the tablist wrapper), one `<main>` and a footer.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // The aria-hidden walk, exemption lifted — axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the
  // ONLY thing that ever measures it. See `contrast.ts` for the inventory.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}


// ── The drive ───────────────────────────────────────────────────────────────

/** Switch to a tab by clicking it, and prove the switch happened. */
async function openTab(page: Page, name: RegExp, panelId: string): Promise<void> {
  await page.getByRole('tab', { name }).click();
  await expect(page.getByRole('tab', { name })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator(panelId)).toBeVisible();
  await expect(page.locator(panelId)).not.toBeEmpty();
}

/**
 * Wait for a panel's run to finish by its `data-run` counter, never by a fixed
 * timeout.
 *
 * The counter is incremented once per completed run — including a REFUSED one,
 * which matters: a fixed wait on "Done" would hang forever on a refusal, and a
 * wait on the status text alone can match a "Done" left over from the previous
 * run and scan a state that has already been replaced.
 */
async function runAndWait(page: Page, statusId: string, button: RegExp): Promise<void> {
  const before = Number((await page.locator(statusId).getAttribute('data-run')) ?? '0');
  await page.getByRole('button', { name: button }).click();
  await page.waitForFunction(
    ([sel, n]: [string, number]) =>
      Number(document.querySelector(sel)?.getAttribute('data-run') ?? '0') > n,
    [statusId, before] as [string, number],
    { timeout: 300_000 }
  );
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Five things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as a reader gets it: The
 *    split active with both charts drawn, five panels hidden and UNRENDERED,
 *    every disclosure shut.
 *
 *  - EVERY PANEL IS RENDERED LAZILY, so a tab that is never clicked is a panel
 *    that is never even IN the DOM. Each of the six is activated through its
 *    real tab button and scanned in its own driven states.
 *
 *  - EVERY VERDICT TONE IS REACHED. This lab paints four — `pass` when a
 *    countermeasure holds, `alarm` when a key falls out, `fail` when an input
 *    is refused, and `info` for a not-yet-run or retired result. Three of the
 *    four are only reachable by running a real attack or by typing something
 *    wrong on purpose, and none of them had ever been scanned before this
 *    drive existed.
 *
 *  - CONTROLS THAT DO NOT APPLY ARE `[hidden]`, AND THAT IS A CLAIM. A class
 *    rule setting `display` outranks the UA `[hidden]` rule, so an element can
 *    paint while the code believes it is hidden — this page really shipped that
 *    defect on `.field { display: flex }` during development. The drive asserts
 *    the hidden controls are genuinely not painted, in both the shown and
 *    hidden states, rather than force-revealing anything.
 *
 *  - HOVER AND FOCUS ARE STATES. `:hover` persists on the element under the
 *    pointer after `click()` resolves, so it is the state a reader occupies the
 *    instant after pressing Run; the tab buttons, the primary button and the
 *    shared bar's controls all repaint their fill on hover, and every one is
 *    scanned explicitly.
 *
 * The trace counts are lowered from the page's defaults wherever the SCANNED
 * RENDERING does not depend on them: a refusal verdict and a recovered-key
 * verdict paint identically at 3,000 traces and at 30,000, and a gate that
 * takes twenty minutes is a gate nobody runs. Where the rendering DOES depend
 * on the count — Act 2's "not recovered" and Act 3's recovered-key alarm are
 * different paints — the real count is used.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival: The split rendered, five panels unrendered, disclosures shut');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from top:-3rem');

  // ── The split ───────────────────────────────────────────────────────────
  // The balanced secret is the one state where the joint line is flat and the
  // mean product is zero — a different paint, a different note, and the state
  // the whole frozen-mask trap depends on.
  await page.locator('#split-secret').fill('15');
  await page.locator('#split-secret').dispatchEvent('input');
  await expect(page.locator('#split-joint-note')).toContainText('exactly flat');
  await scanAt('Split: a balanced secret — flat joint line, zero mean product');

  await page.locator('#split-secret').fill('255');
  await page.locator('#split-secret').dispatchEvent('input');
  await expect(page.locator('#split-joint-legend')).toContainText('slope -1.000');
  await scanAt('Split: an all-ones secret — the joint line inverted');

  await page.getByRole('button', { name: 'Draw a new mask' }).click();
  await scanAt('Split: a fresh mask drawn, the button still hovered');

  await page.locator('#panel-split details > summary').click();
  await expect(page.locator('#panel-split details[open]')).toHaveCount(1);
  await scanAt('Split: the derivation disclosure open');

  // ── Masked AES ──────────────────────────────────────────────────────────
  await openTab(page, /Masked AES/, '#panel-construction');
  await expect(page.locator('#con-table .verdict-pass')).toBeVisible();
  await expect(page.locator('#con-kat tbody tr')).toHaveCount(6);
  await scanAt('Construction: the fresh-mask default, table property holding, all KATs green');

  await page.getByRole('button', { name: /Frozen mask 0x01/ }).click();
  await expect(page.locator('#con-run .verdict-alarm')).toContainText('no longer protecting anything');
  await scanAt('Construction: frozen mask — a pass verdict and an alarm verdict side by side');

  await page.getByRole('button', { name: /Fresh mask each round/ }).click();
  await page.selectOption('#con-vector', '3');
  await expect(page.locator('#con-run')).toContainText('ae2d8a571e03ac9c9eb76fac45af8e51');
  await page.getByRole('button', { name: 'Draw new masks' }).click();
  await scanAt('Construction: a different vector, re-masked');

  for (const summary of await page.locator('#panel-construction details > summary').all()) {
    await summary.click();
  }
  await expect(page.locator('#panel-construction details[open]')).toHaveCount(2);
  await scanAt('Construction: both derivation disclosures open');

  // ── The bench ───────────────────────────────────────────────────────────
  await openTab(page, /The bench/, '#panel-bench');
  await expect(page.locator('#bench-result .verdict-info')).toContainText('Not run yet');
  // The second-order and bit-level controls must be absent for a first-order
  // attack — and ABSENT means not painted, not merely marked hidden.
  await expect(page.locator('#bench-partner')).toBeHidden();
  await expect(page.locator('#bench-bit')).toBeHidden();
  await scanAt('Bench: arrival — Act 1 preset loaded, nothing run, inapplicable controls hidden');

  await page.fill('#bench-traces', '3000');
  await runAndWait(page, '#bench-status', /Run the attack/);
  await expect(page.locator('#bench-result .verdict-alarm')).toContainText('Key byte recovered');
  await expect(page.locator('#bench-sample-card')).toBeVisible();
  await expect(page.locator('#bench-converge-card')).toBeVisible();
  await scanAt('Bench: Act 1 — the recovered-key alarm, ranking table, and both charts');

  await page.getByRole('button', { name: /Act 2/ }).click();
  await page.fill('#bench-traces', '20000');
  await runAndWait(page, '#bench-status', /Run the attack/);
  await expect(page.locator('#bench-result .verdict-pass')).toContainText('Not recovered');
  await scanAt('Bench: Act 2 — masking holds, the pass verdict and a flat sample scan');

  await page.getByRole('button', { name: /Act 3/ }).click();
  await expect(page.locator('#bench-partner')).toBeVisible();
  await page.fill('#bench-traces', '30000');
  await runAndWait(page, '#bench-status', /Run the attack/);
  await expect(page.locator('#bench-result .verdict-alarm')).toContainText('Key byte recovered');
  await scanAt('Bench: Act 3 — the second-order alarm and the negative correlation');

  await page.selectOption('#bench-attack', 'dpa');
  await expect(page.locator('#bench-bit')).toBeVisible();
  await expect(page.locator('#bench-partner')).toBeHidden();
  await page.selectOption('#bench-bit', '3');
  await page.fill('#bench-traces', '6000');
  await runAndWait(page, '#bench-status', /Run the attack/);
  await scanAt('Bench: the single-bit distinguisher, with its own control shown');

  // Every refusal path, each with a different named cause.
  await page.fill('#bench-key', 'not-a-key');
  await runAndWait(page, '#bench-status', /Run the attack/);
  await expect(page.locator('#bench-result .verdict-fail')).toContainText('Key rejected');
  await expect(page.locator('#bench-key')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#bench-sample-card')).toBeHidden();
  await scanAt('Bench: a malformed key — the refusal verdict and the aria-invalid boundary');

  await page.fill('#bench-key', '2b7e151628aed2a6abf7158809cf4f3c');
  await page.fill('#bench-traces', '1');
  await runAndWait(page, '#bench-status', /Run the attack/);
  await expect(page.locator('#bench-result .verdict-fail')).toContainText('Trace count rejected');
  await scanAt('Bench: a trace count below the floor — a different refusal');

  await page.fill('#bench-traces', '3000');
  await page.fill('#bench-noise', '99');
  await runAndWait(page, '#bench-status', /Run the attack/);
  await expect(page.locator('#bench-result .verdict-fail')).toContainText('Noise level rejected');
  await expect(page.locator('#bench-noise')).toHaveAttribute('aria-invalid', 'true');
  await scanAt('Bench: noise outside the modelled range — two invalid boundaries at once');

  await page.fill('#bench-noise', '6');
  await page.getByRole('button', { name: /Act 3/ }).click();
  await page.selectOption('#bench-partner', '24');
  await runAndWait(page, '#bench-status', /Run the attack/);
  await expect(page.locator('#bench-result .verdict-fail')).toContainText('Second-order pair rejected');
  await scanAt('Bench: a sample paired with itself — the pair refusal');

  await page.locator('#panel-bench details > summary').click();
  await expect(page.locator('#panel-bench details[open]')).toHaveCount(1);
  await scanAt('Bench: the sample-map disclosure open');

  // ── Frozen mask ─────────────────────────────────────────────────────────
  await openTab(page, /Frozen mask/, '#panel-frozen');
  await expect(page.locator('#frozen-result .verdict-info')).toContainText('Not measured yet');
  await scanAt('Frozen: arrival — the pinned constant, nothing measured');

  await runAndWait(page, '#frozen-status', /Measure this constant/);
  await expect(page.locator('#frozen-result .verdict-pass')).toContainText('Prediction matched');
  await scanAt('Frozen: the pinned 0x01 — prediction matched, protection gone, table of five benches');

  await page.selectOption('#frozen-constant', '15');
  await expect(page.locator('#frozen-result')).toContainText('Retired');
  await scanAt('Frozen: the constant changed — the stale verdict retired');

  await runAndWait(page, '#frozen-status', /Measure this constant/);
  await expect(page.locator('#frozen-result')).toContainText('The trap');
  await scanAt('Frozen: the balanced constant — the trap, with a silent CPA and a working bit attack');

  await page.selectOption('#frozen-constant', '0');
  await runAndWait(page, '#frozen-status', /Measure this constant/);
  await scanAt('Frozen: a zero constant — masking that masks nothing at all');

  for (const summary of await page.locator('#panel-frozen details > summary').all()) {
    await summary.click();
  }
  await expect(page.locator('#panel-frozen details[open]')).toHaveCount(2);
  await scanAt('Frozen: both disclosures open, including the not-claimed note');

  // ── Cost ────────────────────────────────────────────────────────────────
  await openTab(page, /Cost/, '#panel-cost');
  await expect(page.locator('#panel-cost tbody tr')).toHaveCount(7);
  await scanAt('Cost: the recorded table, the log-scale chart and the headline multiplier');

  await page.selectOption('#cost-claim', 'act1-unprotected-cpa');
  await runAndWait(page, '#cost-status', /Reproduce this claim/);
  await expect(page.locator('#cost-result .verdict-alarm')).toContainText('Inside the band');
  await scanAt('Cost: a disclosure claim reproduced — inside the band');

  await page.selectOption('#cost-claim', 'act2-masked-bit-dpa');
  await expect(page.locator('#cost-result')).toContainText('Retired');
  await runAndWait(page, '#cost-status', /Reproduce this claim/);
  await expect(page.locator('#cost-result .verdict-pass')).toContainText('Held');
  await scanAt('Cost: a negative claim reproduced — held');

  await page.locator('#panel-cost details > summary').click();
  await scanAt('Cost: the band-rationale disclosure open');

  // ── Scope ───────────────────────────────────────────────────────────────
  await openTab(page, /Scope/, '#panel-scope');
  await scanAt('Scope: the real/simulated split, the glitch note and the does-not-prove list');

  await page.locator('#panel-scope details > summary').click();
  await expect(page.locator('#panel-scope details[open]')).toHaveCount(1);
  await scanAt('Scope: the how-claims-are-checked disclosure open');

  // ── Hover, which persists after a click ─────────────────────────────────
  await page.getByRole('tab', { name: /The bench/ }).hover();
  await scanAt('an inactive tab hovered — its surface repainted');

  await page.getByRole('tab', { name: /Scope/ }).hover();
  await scanAt('the active tab hovered');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered');

  await openTab(page, /The bench/, '#panel-bench');
  await page.getByRole('button', { name: 'Run the attack' }).hover();
  await scanAt('the primary button hovered');

  // ── Focus rings on the controls that take them ──────────────────────────
  await page.locator('#bench-key').focus();
  await expect(page.locator('#bench-key')).toBeFocused();
  await scanAt('a text input focused, showing its focus-visible outline');

  await page.locator('#bench-protection').focus();
  await scanAt('a styled select focused, with its custom chevron');

  await page.getByRole('tab', { name: /The bench/ }).focus();
  await scanAt('the active tab focused');
}
