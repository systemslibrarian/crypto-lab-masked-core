import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where The
 * split has drawn both its charts and the other five tabpanels are hidden and
 * UNRENDERED; the shared skip link focused; the split's balanced and all-ones
 * secrets, which are the two renderings the frozen-mask trap depends on; the
 * masked construction on a fresh mask, on a frozen one, and on a second
 * vector; the bench across Acts 1, 2 and 3 and the single-bit distinguisher,
 * then through four different refusals — a malformed key, a trace count below
 * the floor, noise outside the model, and a sample paired with itself — each
 * of which paints a different named cause behind an `aria-invalid` boundary
 * and hides the charts; the frozen-mask panel on its pinned constant, on the
 * balanced constant that silences the Hamming-weight attack, on a zero
 * constant, and on the retired state between two measurements; the Cost tab
 * reproducing both a disclosure claim and a negative one; the Scope tab; every
 * disclosure opened through its own `<summary>`; three hover states and three
 * focus rings. Every one of those states is scanned, at desktop and phone
 * width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no panel is
 * revealed from script, why the lab's defaults are asserted rather than
 * assumed, and why `violations` is not the whole oracle.
 *
 * Dark is the only theme in this lab, so there is one theme loop rather than
 * two — and `boot` seeds `light` into localStorage first, to prove the head
 * script overwrites a stale value rather than reading it.
 */
for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
