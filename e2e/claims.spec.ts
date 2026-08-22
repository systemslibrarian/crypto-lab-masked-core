import { expect, test, type Page } from '@playwright/test';
import { SBOX } from '../src/aes/aes';
import { BLOCK_VECTORS } from '../src/aes/vectors';
import { COST_RATIO_FLOOR, DISCLOSURE_CLAIMS, FIXTURE, FROZEN_FIXTURE, NON_DISCLOSURE_CLAIMS } from '../src/claims/bands';
import { FAILURES } from '../src/claims/failures';
import { HW } from '../src/leakage/model';

/**
 * The claims suite: does the page tell the truth?
 *
 * The rule that makes these worth anything is that a test which re-derives the
 * same expression the source uses will happily agree with a bug. So the checks
 * here are of three kinds, and the important ones are the second and third:
 *
 *  - CROSS-CHECKS between two surfaces that must agree (the verdict sentence
 *    against the readout table; a claim's recorded band against the number the
 *    page measures; the ranking table's top row against the verdict's wording);
 *  - INDEPENDENT RE-DERIVATIONS, which recompute a claim from the page's own
 *    printed inputs by a DIFFERENT route than the renderer took — the frozen
 *    correlation from the constant's popcount, the second-order sign from the
 *    combining identity, the S-box output from the printed key and plaintext;
 *  - PARTS-SUM-TO-WHOLE where the maths offers one (the two shares XOR back to
 *    the secret; the ratio of two measured trace counts against the recorded
 *    cost floor).
 *
 * Plus every failure path, that the page NAMES the actual cause, that a stale
 * verdict is retired when an input changes, that re-selecting the same value
 * does NOT retire a fresh verdict, and the `[hidden]` probe.
 */

const BENCH = '#panel-bench';

async function open(page: Page, tab: RegExp): Promise<void> {
  await page.getByRole('tab', { name: tab }).click();
  await expect(page.getByRole('tab', { name: tab })).toHaveAttribute('aria-selected', 'true');
}

async function runCount(page: Page, id: string): Promise<number> {
  return Number((await page.locator(id).getAttribute('data-run')) ?? '0');
}

async function runBench(page: Page): Promise<string> {
  const before = await runCount(page, '#bench-status');
  await page.getByRole('button', { name: 'Run the attack' }).click();
  await page.waitForFunction(
    (n) => Number(document.querySelector('#bench-status')?.getAttribute('data-run') ?? '0') > n,
    before,
    { timeout: 240_000 }
  );
  return ((await page.locator('#bench-result').textContent()) ?? '').replace(/\s+/g, ' ');
}

/** Pull a labelled row out of a `dl.kv` readout by its term text.
 *  The term is escaped: several of these labels contain regex metacharacters
 *  ("Closed form 1 - HW(c)/4"), and an unescaped `(c)` is a capture group that
 *  matches a DIFFERENT string than the one on the page. */
async function readout(page: Page, scope: string, term: string): Promise<string> {
  const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const value = page
    .locator(`${scope} dl.kv dt`)
    .filter({ hasText: new RegExp(`^${escaped}$`, 'i') })
    .locator('xpath=following-sibling::dd[1]');
  return ((await value.first().textContent()) ?? '').trim();
}

/** The leading number of a readout that also carries explanatory text, e.g.
 *  "1.0000  (averaged over all 256 masks)". `Number()` on the whole cell is NaN. */
function leadingNumber(text: string): number {
  const m = text.match(/-?\d+(?:\.\d+)?/);
  expect(m, `no number found in readout: ${text}`).not.toBeNull();
  return Number(m![0]);
}

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('.cl-hero-title')).toHaveText('Masked Core');
});

test.describe('the page renders what it claims to render', () => {
  test('one h1, one main, one banner, the skip target and the scripture line', async ({ page }) => {
    await expect(page.locator('h1')).toHaveCount(1);
    await expect(page.locator('main')).toHaveCount(1);
    await expect(page.locator('#app')).toHaveCount(1);
    await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.locator('.scripture-footer p')).toHaveText(
      'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31'
    );
    await expect(page.getByRole('tab')).toHaveCount(6);
  });

  test('the leakage model is stated persistently, not only in the Scope tab', async ({ page }) => {
    // The brief requires the model to be on the page at all times. Assert it is
    // OUTSIDE the tab panels, so it cannot be satisfied by a tab nobody opens.
    const banner = page.locator('.model-banner');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText('Hamming weight');
    await expect(banner).toContainText('not modelled here');
    await expect(banner).toContainText('Not production crypto');
    expect(await banner.evaluate((el) => el.closest('[role="tabpanel"]') === null)).toBe(true);
  });

  test('THE HIDDEN PROBE: an inactive tabpanel is hidden AND not painted', async ({ page }) => {
    // A class rule that sets `display` outranks the UA `[hidden]` rule, so an
    // element can paint while the code believes it is hidden. This caught a real
    // defect here during development, on `.field { display: flex }`.
    const painted = await page.evaluate(() =>
      Array.from(document.querySelectorAll('[hidden]'))
        .filter((el) => (el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true }))
        .map((el) => `${el.tagName.toLowerCase()}#${el.id}`)
    );
    expect(painted, 'elements marked [hidden] that still paint').toEqual([]);
  });
});

test.describe('The split — the mechanism, cross-checked', () => {
  test('the two printed shares XOR back to the printed secret', async ({ page }) => {
    // Parts sum to whole, recomputed from what the page printed rather than
    // from anything the renderer returned.
    await open(page, /The split/);
    const parse = (s: string): number => parseInt(s.match(/0x([0-9a-f]{2})/)![1], 16);
    const secret = parse(await readout(page, '#split-shares', 'Secret byte v'));
    const mask = parse(await readout(page, '#split-shares', 'Mask m'));
    const masked = parse(await readout(page, '#split-shares', 'Masked share v XOR m'));
    expect(masked).toBe(secret ^ mask);
    expect(parse(await readout(page, '#split-shares', 'Recombined'))).toBe(secret);
  });

  test('the printed Hamming weights match a popcount of the printed bytes', async ({ page }) => {
    await open(page, /The split/);
    const row = await readout(page, '#split-shares', 'Secret byte v');
    const byte = parseInt(row.match(/0x([0-9a-f]{2})/)![1], 16);
    const bits = row.match(/\b([01]{8})\b/)![1];
    const weight = Number(row.match(/weight (\d)/)![1]);
    // Three independent routes to the same number: the hex, the printed binary
    // string, and the printed weight.
    expect(bits).toBe(byte.toString(2).padStart(8, '0'));
    expect(weight).toBe(bits.split('').filter((c) => c === '1').length);
    expect(weight).toBe(HW[byte]);
  });

  test('the measured mean product equals -(1/2)(HW(v) - 4), re-derived here', async ({ page }) => {
    await open(page, /The split/);
    const secret = parseInt(
      (await readout(page, '#split-shares', 'Secret byte v')).match(/0x([0-9a-f]{2})/)![1],
      16
    );
    const measured = leadingNumber(await readout(page, '#split-product', 'Measured mean product'));
    // Recomputed from the SECRET the page printed, by the closed form, not by
    // reading the page's own prediction row.
    expect(measured).toBeCloseTo(-0.5 * (HW[secret] - 4), 4);
    await expect(page.locator('#split-product .verdict-pass')).toContainText('Identical');
  });

  test('the marginals do not move when the secret does, and the joint does', async ({ page }) => {
    await open(page, /The split/);
    const marginals = async (): Promise<string> =>
      ((await page.locator('#split-marginals-legend').textContent()) ?? '').replace(/\s+/g, ' ');
    const joint = async (): Promise<string> =>
      ((await page.locator('#split-joint-legend').textContent()) ?? '').replace(/\s+/g, ' ');

    const m0 = await marginals();
    const j0 = await joint();
    await page.locator('#split-secret').fill('255');
    await page.locator('#split-secret').dispatchEvent('input');
    await expect(page.locator('#split-shares')).toContainText('0xff');

    // This is the first-order claim, asserted as a behaviour of the page: the
    // share distributions are byte-identical across two very different secrets.
    expect(await marginals()).toBe(m0);
    expect(await joint()).not.toBe(j0);
    await expect(page.locator('#split-joint-legend')).toContainText('slope -1.000');
  });

  test('a balanced secret makes the joint line flat, and the page says why', async ({ page }) => {
    await open(page, /The split/);
    await page.locator('#split-secret').fill('15'); // 0x0f, Hamming weight 4
    await page.locator('#split-secret').dispatchEvent('input');
    await expect(page.locator('#split-joint-legend')).toContainText('slope 0.000');
    await expect(page.locator('#split-joint-note')).toContainText('exactly flat');
    await expect(page.locator('#split-joint-note')).toContainText('blind spot');
    expect(leadingNumber(await readout(page, '#split-product', 'Measured mean product'))).toBe(0);
  });
});

test.describe('Masked AES — the construction tells the truth', () => {
  test('the unmasked output is the published ciphertext, and the masked state is not', async ({ page }) => {
    await open(page, /Masked AES/);
    const pt = await readout(page, '#con-run', 'Plaintext');
    const key = await readout(page, '#con-run', 'Key');
    const out = await readout(page, '#con-run', 'Unmasked output');
    const maskedState = await readout(page, '#con-run', 'Masked state before unmasking');
    const finalMask = await readout(page, '#con-run', 'Accumulated mask');

    // Independent: look the pair up in the published vector list rather than
    // trusting the page's own "Published ciphertext" row.
    const vector = BLOCK_VECTORS.find((v) => v.plaintext === pt && v.key === key);
    expect(vector, `page printed a plaintext/key pair that is not a published vector`).toBeTruthy();
    expect(out).toBe(vector!.ciphertext);

    // Parts sum to whole: masked state XOR accumulated mask is the ciphertext.
    const xor = (a: string, b: string): string =>
      a
        .match(/../g)!
        .map((h, i) => (parseInt(h, 16) ^ parseInt(b.slice(i * 2, i * 2 + 2), 16)).toString(16).padStart(2, '0'))
        .join('');
    expect(xor(maskedState, finalMask)).toBe(out);
    expect(maskedState).not.toBe(out);
  });

  test("the recomputed table row satisfies S'[x^mIn] = SBOX[x]^mOut, checked against SBOX here", async ({ page }) => {
    await open(page, /Masked AES/);
    const mIn = parseInt((await readout(page, '#con-table', 'Round 1 input mask mIn')).slice(2), 16);
    const mOut = parseInt((await readout(page, '#con-table', 'Round 1 output mask mOut')).slice(2), 16);
    const cells = await page.locator('#con-table tbody tr').first().locator('td').allTextContents();
    const [x, sbox, xMasked, tableOut, expected] = cells.map((c) => parseInt(c.trim().slice(2), 16));
    // Every column re-derived from the FIPS-197 S-box, not from the page.
    expect(sbox).toBe(SBOX[x]);
    expect(xMasked).toBe(x ^ mIn);
    expect(expected).toBe(SBOX[x] ^ mOut);
    expect(tableOut).toBe(expected);
    await expect(page.locator('#con-table .verdict-pass')).toContainText('Table property holds');
  });

  test('every published vector passes, and the count in the verdict matches the rows', async ({ page }) => {
    await open(page, /Masked AES/);
    const rows = await page.locator('#con-kat tbody tr').count();
    const passes = await page.locator('#con-kat tbody .pill-ok').count();
    const verdictText = (await page.locator('#con-kat .verdict').textContent()) ?? '';
    const [, got, total] = verdictText.match(/(\d+) \/ (\d+) vectors/)!;
    // The counter against the rows it counts.
    expect(Number(total)).toBe(rows);
    expect(Number(total)).toBe(BLOCK_VECTORS.length);
    expect(Number(got)).toBe(rows);
    expect(passes).toBe(rows * 2); // plain and masked columns
  });

  test('a frozen mask still produces the right ciphertext, and the page says that is not the tell', async ({ page }) => {
    await open(page, /Masked AES/);
    await page.getByRole('button', { name: /Frozen mask 0x01/ }).click();
    const pt = await readout(page, '#con-run', 'Plaintext');
    const out = await readout(page, '#con-run', 'Unmasked output');
    expect(out).toBe(BLOCK_VECTORS.find((v) => v.plaintext === pt)!.ciphertext);
    await expect(page.locator('#con-run .verdict-alarm')).toContainText('no longer protecting anything');
    await expect(page.locator('#con-run .verdict-alarm')).toContainText('Correctness is not the tell');
  });
});

test.describe('The bench — the acts, and what each verdict claims', () => {
  test('Act 1 recovers the key, and the verdict agrees with the readout and the table', async ({ page }) => {
    await open(page, /The bench/);
    await page.getByRole('button', { name: /Act 1/ }).click();
    const text = await runBench(page);

    await expect(page.locator(`${BENCH} #bench-result .verdict-alarm`)).toBeVisible();
    const recovered = text.match(/Key byte recovered: (0x[0-9a-f]{2})/)![1];
    const real = (await readout(page, '#bench-result', 'Real key byte')).match(/0x[0-9a-f]{2}/)![0];
    const rank = await readout(page, '#bench-result', 'Rank of the real key byte');

    // Three surfaces that must agree: the verdict sentence, the readout, and
    // the top row of the ranking table.
    expect(recovered).toBe(real);
    expect(rank).toBe('1 of 256');
    const topRow = await page.locator(`${BENCH} tbody tr`).first().locator('td').allTextContents();
    expect(topRow[0].trim()).toBe('1');
    expect(topRow[1].trim()).toBe(real);

    // Independent: the real key byte must be byte 0 of the key in the input.
    const keyHex = await page.locator('#bench-key').inputValue();
    expect(parseInt(real.slice(2), 16)).toBe(parseInt(keyHex.slice(0, 2), 16));

    // And it must land inside the band the page prints for this claim.
    const band = await readout(page, '#bench-result', 'Recorded band');
    const [lo, hi] = band.match(/([\d,]+) to ([\d,]+)/)!.slice(1).map((n) => Number(n.replace(/,/g, '')));
    const ttd = Number((await readout(page, '#bench-result', 'Traces to disclosure')).match(/^[\d,]+/)![0].replace(/,/g, ''));
    expect(ttd).toBeGreaterThanOrEqual(lo);
    expect(ttd).toBeLessThanOrEqual(hi);
    const claim = DISCLOSURE_CLAIMS.find((c) => c.id === 'act1-unprotected-cpa')!;
    expect([lo, hi]).toEqual([claim.band[0], claim.band[1]]);
  });

  test('Act 2 does NOT recover it, and the page says blind rather than slow', async ({ page }) => {
    await open(page, /The bench/);
    await page.getByRole('button', { name: /Act 2/ }).click();
    await page.fill('#bench-traces', '20000');
    const text = await runBench(page);
    await expect(page.locator(`${BENCH} #bench-result .verdict-pass`)).toBeVisible();
    expect(text).toContain('Not recovered');
    expect(text).toContain('it is blind');
    expect(Number((await readout(page, '#bench-result', 'Rank of the real key byte')).split(' ')[0])).toBeGreaterThan(1);
    expect(await readout(page, '#bench-result', 'Traces to disclosure')).toContain('no disclosure');

    // The negative claim the page prints must be the recorded one.
    const claim = NON_DISCLOSURE_CLAIMS.find((c) => c.id === 'act2-masked-first-order-cpa')!;
    expect(await readout(page, '#bench-result', 'Recorded claim')).toContain(
      claim.noDisclosureUpTo.toLocaleString('en-US')
    );
  });

  test('Act 3 recovers it, with the NEGATIVE sign the combining identity predicts', async ({ page }) => {
    await open(page, /The bench/);
    await page.getByRole('button', { name: /Act 3/ }).click();
    const text = await runBench(page);
    await expect(page.locator(`${BENCH} #bench-result .verdict-alarm`)).toBeVisible();

    const signed = Number(text.match(/signed value is (-?[\d.]+)/)![1]);
    // Independent re-derivation of the SIGN: E[(HW(m)-4)(HW(v^m)-4)] is
    // -(1/2)(HW(v)-4), a decreasing function of the predicted Hamming weight,
    // so a correct second-order guess must correlate negatively. A positive
    // peak would mean the attack is succeeding by some other route.
    expect(signed).toBeLessThan(0);
    expect(text).toContain('negative');

    // The pair really is (a mask, a value masked by that mask).
    const pair = await readout(page, '#bench-result', 'Sample under attack');
    expect(pair).toContain('output mask register mOut');
    expect(pair).toContain('S-box output, byte 0');
  });

  test('the same attack on the WRONG mask sample fails — so the pair is doing the work', async ({ page }) => {
    await open(page, /The bench/);
    await page.getByRole('button', { name: /Act 3/ }).click();
    await page.selectOption('#bench-partner', '3'); // mIn, not mOut
    await page.fill('#bench-traces', '30000');
    const text = await runBench(page);
    expect(text).toContain('Not recovered');
    expect(await readout(page, '#bench-result', 'Sample under attack')).toContain('input mask register mIn');
  });

  test('the cost ratio between Act 1 and Act 3, measured from the page, clears the floor', async ({ page }) => {
    // Parts-relate-to-whole, entirely from numbers the page printed.
    await open(page, /The bench/);
    const ttdFor = async (act: RegExp): Promise<number> => {
      await page.getByRole('button', { name: act }).click();
      await runBench(page);
      const raw = await readout(page, '#bench-result', 'Traces to disclosure');
      return Number(raw.match(/^[\d,]+/)![0].replace(/,/g, ''));
    };
    const first = await ttdFor(/Act 1/);
    const second = await ttdFor(/Act 3/);
    expect(second / first).toBeGreaterThanOrEqual(COST_RATIO_FLOOR);
  });
});

test.describe('the bench fails closed, and names the cause', () => {
  test.beforeEach(async ({ page }) => {
    await open(page, /The bench/);
    await page.getByRole('button', { name: /Act 1/ }).click();
    await runBench(page);
    await expect(page.locator('#bench-result .verdict-alarm')).toBeVisible();
  });

  test('a malformed key: named cause, aria-invalid, and NO stale result left standing', async ({ page }) => {
    await page.fill('#bench-key', 'not-a-key');
    await runBench(page);
    await expect(page.locator('#bench-result .verdict-fail')).toContainText(FAILURES.keyNotHex);
    await expect(page.locator('#bench-key')).toHaveAttribute('aria-invalid', 'true');
    // Fail-closed: the previous run's verdict and charts are gone, not left
    // sitting beside an input the page has just rejected.
    await expect(page.locator('#bench-result .verdict-alarm')).toHaveCount(0);
    await expect(page.locator('#bench-sample-card')).toBeHidden();
    await expect(page.locator('#bench-converge-card')).toBeHidden();
  });

  test('a key of the wrong length names a DIFFERENT cause than non-hex', async ({ page }) => {
    await page.fill('#bench-key', '2b7e15');
    await runBench(page);
    await expect(page.locator('#bench-result .verdict-fail')).toContainText(FAILURES.keyWrongLength);
    expect(FAILURES.keyWrongLength).not.toBe(FAILURES.keyNotHex);
  });

  test('a trace count below the floor and above the ceiling name different causes', async ({ page }) => {
    await page.fill('#bench-traces', '1');
    await runBench(page);
    await expect(page.locator('#bench-result .verdict-fail')).toContainText(FAILURES.traceCountTooLow);
    await page.fill('#bench-traces', '999999');
    await runBench(page);
    await expect(page.locator('#bench-result .verdict-fail')).toContainText(FAILURES.traceCountTooHigh);
  });

  test('noise outside the modelled range is refused', async ({ page }) => {
    await page.fill('#bench-noise', '99');
    await runBench(page);
    await expect(page.locator('#bench-result .verdict-fail')).toContainText(FAILURES.noiseOutOfRange);
  });

  test('combining a sample with itself is refused, and says why that cannot work', async ({ page }) => {
    await page.getByRole('button', { name: /Act 3/ }).click();
    await page.selectOption('#bench-partner', '24');
    await runBench(page);
    await expect(page.locator('#bench-result .verdict-fail')).toContainText(FAILURES.samePairSamples);
  });

  test('controls that do not apply to the chosen attack are not on the page', async ({ page }) => {
    await expect(page.locator('#bench-partner')).toBeHidden();
    await expect(page.locator('#bench-bit')).toBeHidden();
    await page.getByRole('button', { name: /Act 3/ }).click();
    await expect(page.locator('#bench-partner')).toBeVisible();
    await expect(page.locator('#bench-bit')).toBeHidden();
  });
});

test.describe('Frozen mask — the pinned fixture and the trap', () => {
  async function measure(page: Page, value?: string): Promise<string> {
    const before = await runCount(page, '#frozen-status');
    if (value !== undefined) await page.selectOption('#frozen-constant', value);
    await page.getByRole('button', { name: 'Measure this constant' }).click();
    await page.waitForFunction(
      (n) => Number(document.querySelector('#frozen-status')?.getAttribute('data-run') ?? '0') > n,
      before,
      { timeout: 180_000 }
    );
    return ((await page.locator('#frozen-result').textContent()) ?? '').replace(/\s+/g, ' ');
  }

  test('the default constant is the pinned one, and its prediction is re-derived here', async ({ page }) => {
    await open(page, /Frozen mask/);
    await measure(page);
    const printed = await readout(page, '#frozen-result', 'Frozen constant');
    const c = parseInt(printed.match(/0x([0-9a-f]{2})/)![1], 16);
    expect(c).toBe(FROZEN_FIXTURE.pinned);

    // Independent: recompute 1 - HW(c)/4 from a popcount of the constant the
    // page printed, rather than reading the page's own closed-form row.
    const popcount = c.toString(2).split('').filter((b) => b === '1').length;
    const predicted = 1 - popcount / 4;
    expect(leadingNumber(await readout(page, '#frozen-result', 'Closed form 1 - HW(c)/4'))).toBeCloseTo(predicted, 6);

    // And the measured ratio must land on it, within the stated sampling
    // tolerance — a genuine measurement compared against genuine algebra.
    const ratio = leadingNumber(await readout(page, '#frozen-result', 'Measured / unprotected'));
    expect(Math.abs(ratio - predicted)).toBeLessThanOrEqual(FROZEN_FIXTURE.toleranceOfPredicted);
    await expect(page.locator('#frozen-result .verdict-pass')).toContainText('Prediction matched');
  });

  test('the predicted bench correlation is the product of the two other printed rows', async ({ page }) => {
    await open(page, /Frozen mask/);
    await measure(page);
    const closed = Number(await readout(page, '#frozen-result', 'Closed form 1 - HW(c)/4'));
    const predicted = Number(
      (await readout(page, '#frozen-result', 'Predicted bench correlation')).split(' ')[0]
    );
    const measured = Number(await readout(page, '#frozen-result', 'Measured bench correlation'));
    const ratio = leadingNumber(await readout(page, '#frozen-result', 'Measured / unprotected'));
    // Two consistency relations across four printed numbers.
    expect(predicted / closed).toBeCloseTo(measured / ratio, 3);
    expect(Math.abs(measured - predicted)).toBeLessThan(0.05);
  });

  test('THE TRAP: a balanced constant silences the CPA while the bit attack still works', async ({ page }) => {
    await open(page, /Frozen mask/);
    const text = await measure(page, String(FROZEN_FIXTURE.balanced));
    expect(text).toContain('The trap');
    // The Hamming-weight attack sees nothing...
    const closed = leadingNumber(await readout(page, '#frozen-result', 'Closed form 1 - HW(c)/4'));
    expect(closed).toBe(0);
    const rows = await page.locator('#frozen-result tbody tr').allTextContents();
    const cpaRow = rows.find((r) => r.includes('Frozen mask') && r.includes('Hamming-weight'))!;
    // And it is NOT painted as a countermeasure holding. Colour tracks system
    // integrity, not the attack's return value: silent is not safe.
    expect(cpaRow).toContain('SILENT — NOT PROTECTED');
    expect(cpaRow).not.toContain('no recovery');
    // ...and the single-bit attack on the SAME traces does.
    const dpaRow = rows.find((r) => r.includes('Frozen mask') && r.includes('Single-bit'))!;
    expect(dpaRow).toContain('KEY RECOVERED');
    expect(text).toContain('A silent attack is not evidence of a working defence');
  });

  test('the control rows fail on BOTH attacks, so a failure means broken randomness', async ({ page }) => {
    await open(page, /Frozen mask/);
    await measure(page, String(FROZEN_FIXTURE.balanced));
    const rows = await page.locator('#frozen-result tbody tr').allTextContents();
    const controls = rows.filter((r) => r.includes('Fresh mask (control)'));
    expect(controls).toHaveLength(2);
    for (const r of controls) expect(r).toContain('no recovery');
  });

  test('RETIREMENT: changing the constant clears the stale verdict and says it was retired', async ({ page }) => {
    await open(page, /Frozen mask/);
    await measure(page);
    await expect(page.locator('#frozen-result .verdict-pass')).toBeVisible();
    await page.selectOption('#frozen-constant', '255');
    await expect(page.locator('#frozen-result')).toContainText('Retired');
    await expect(page.locator('#frozen-result .verdict-pass')).toHaveCount(0);
    await expect(page.locator('#frozen-result table')).toHaveCount(0);
  });

  test('NO-OP GUARD: re-selecting the SAME constant does not retire a fresh verdict', async ({ page }) => {
    await open(page, /Frozen mask/);
    await measure(page);
    await expect(page.locator('#frozen-result .verdict-pass')).toBeVisible();
    await page.selectOption('#frozen-constant', String(FROZEN_FIXTURE.pinned));
    await expect(page.locator('#frozen-result .verdict-pass')).toBeVisible();
    await expect(page.locator('#frozen-result')).not.toContainText('Retired');
  });
});

test.describe('Cost — the recorded claims, and reproducing one', () => {
  test('the printed table matches the recorded claim set exactly', async ({ page }) => {
    await open(page, /Cost/);
    const rows = await page.locator('#panel-cost tbody tr').allTextContents();
    expect(rows).toHaveLength(DISCLOSURE_CLAIMS.length + NON_DISCLOSURE_CLAIMS.length);
    for (const c of DISCLOSURE_CLAIMS) {
      const row = rows.find((r) => r.includes(c.id))!;
      expect(row, c.id).toBeTruthy();
      expect(row).toContain(c.measured.toLocaleString('en-US'));
      expect(row).toContain('KEY RECOVERED');
    }
    for (const c of NON_DISCLOSURE_CLAIMS) {
      const row = rows.find((r) => r.includes(c.id))!;
      expect(row, c.id).toBeTruthy();
      // Act 2's negative claims are a countermeasure holding; the frozen
      // balanced one is the trap, and the table must say so.
      expect(row).toContain(
        c.id.startsWith('act4-frozen') ? 'SILENT — NOT PROTECTED' : 'no recovery'
      );
    }
  });

  test('the headline multiplier is the ratio of two numbers in its own table', async ({ page }) => {
    await open(page, /Cost/);
    const headline = (await page.locator('#panel-cost .verdict-alarm').first().textContent()) ?? '';
    const stated = Number(headline.match(/about (\d+) times/)![1]);
    const first = Number(headline.match(/([\d,]+) traces against plain/)![1].replace(/,/g, ''));
    const second = Number(headline.match(/([\d,]+) traces against the masked/)![1].replace(/,/g, ''));
    expect(stated).toBe(Math.round(second / first));
    expect(stated).toBeGreaterThanOrEqual(COST_RATIO_FLOOR);
    // And those two numbers are the ones in the table.
    const rows = await page.locator('#panel-cost tbody tr').allTextContents();
    expect(rows.find((r) => r.includes('act1-unprotected-cpa'))).toContain(first.toLocaleString('en-US'));
    expect(rows.find((r) => r.includes('act3-masked-second-order-cpa'))).toContain(
      second.toLocaleString('en-US')
    );
  });

  test('reproducing a negative claim in the browser reaches the same answer', async ({ page }) => {
    await open(page, /Cost/);
    const before = await runCount(page, '#cost-status');
    await page.selectOption('#cost-claim', 'act2-masked-bit-dpa');
    await page.getByRole('button', { name: 'Reproduce this claim' }).click();
    await page.waitForFunction(
      (n) => Number(document.querySelector('#cost-status')?.getAttribute('data-run') ?? '0') > n,
      before,
      { timeout: 300_000 }
    );
    await expect(page.locator('#cost-result .verdict-pass')).toContainText('Held');
    await expect(page.locator('#cost-result')).toContainText('no disclosure');
  });

  test('RETIREMENT: changing the claim clears the previous reproduction', async ({ page }) => {
    await open(page, /Cost/);
    const before = await runCount(page, '#cost-status');
    await page.getByRole('button', { name: 'Reproduce this claim' }).click();
    await page.waitForFunction(
      (n) => Number(document.querySelector('#cost-status')?.getAttribute('data-run') ?? '0') > n,
      before,
      { timeout: 300_000 }
    );
    await page.selectOption('#cost-claim', 'act4-frozen-low-weight-cpa');
    await expect(page.locator('#cost-result')).toContainText('Retired');
  });
});

test.describe('Scope — the honesty the rest of the page depends on', () => {
  test('names what is real, what is simulated, and what it does not prove', async ({ page }) => {
    await open(page, /Scope/);
    const panel = page.locator('#panel-scope');
    await expect(panel).toContainText('Not production crypto');
    await expect(panel).toContainText('Real');
    await expect(panel).toContainText('Simulated');
    await expect(panel).toContainText('What this page does NOT prove');
    await expect(panel).toContainText('The power traces');
  });

  test('the glitch note is present and explicitly NOT simulated', async ({ page }) => {
    await open(page, /Scope/);
    const panel = page.locator('#panel-scope');
    await expect(panel).toContainText('glitch');
    await expect(panel).toContainText('threshold implementations');
    await expect(panel.locator('.verdict-info').filter({ hasText: 'Not simulated here' })).toBeVisible();
    await expect(panel).toContainText('none is faked');
  });

  test('the two failures are kept apart as separate claims', async ({ page }) => {
    // The brief is explicit that the frozen-mask result is a lesson about
    // randomness, not about masking, and that the two must not be conflated.
    await open(page, /Scope/);
    await expect(page.locator('#panel-scope')).toContainText('failure of RANDOMNESS');
    await expect(page.locator('#panel-scope')).toContainText('separate claim');
    await open(page, /Frozen mask/);
    await expect(page.locator('#panel-frozen')).toContainText('about randomness, not about masking');
  });

  test('the within-encryption overclaim is explicitly disclaimed', async ({ page }) => {
    await open(page, /Frozen mask/);
    // A <summary> is not exposed with role="button" in Chromium, so it is
    // opened the way a reader opens it: by clicking the summary itself.
    const details = page.locator('#panel-frozen details', {
      hasText: 'What this act does NOT claim',
    });
    await details.locator('summary').click();
    await expect(details).toHaveAttribute('open', '');
    await expect(details).toContainText(/WITHIN a single encryption/i);
    await expect(details).toContainText('horizontal');
    await expect(details).toContainText('overclaim');
  });

  test('the fixture printed on the Cost tab is the fixture the claims were recorded against', async ({ page }) => {
    await open(page, /Cost/);
    const note = (await page.locator('#panel-cost .note').first().textContent()) ?? '';
    expect(note).toContain(String(FIXTURE.seed));
    expect(note).toContain(`noise sigma ${FIXTURE.noise}`);
  });
});
