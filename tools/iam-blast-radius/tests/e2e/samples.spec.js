// Playwright browser acceptance for IAM-505 (built-in abuse-case samples).
// CI-only (needs a real browser + Worker); NOT run by the node --test loop.
//
// Covers the IAM-505 acceptance that requires a real DOM/Worker:
//   - samples load via mouse AND keyboard, filling the input and running the
//     normal flow (findings + coverage panel)
//   - the obvious-escalation sample renders its critical PassRole path
//   - a scary-but-neutralized sample demonstrates fail-closed coverage /
//     Deny suppression (no overstated finding)
//   - each sample loader is keyboard-focusable and has an associated description
//   - Clear wipes the loaded sample's output

import { test, expect } from '@playwright/test';

const PAGE = '/tools/iam-blast-radius/index.html';

test.beforeEach(async ({ page }) => {
  // Fail loudly if a loaded sample ever triggers a dialog - that would mean an
  // injection executed. (Samples are our own static data, but the flow is the
  // same one hostile paste input travels.)
  page.on('dialog', async (d) => {
    throw new Error(`Unexpected dialog (possible XSS): ${d.message()}`);
  });
  await page.goto(PAGE);
});

test('the sample loaders render with visible, associated descriptions', async ({ page }) => {
  const buttons = page.locator('#samples .sample-btn');
  await expect(buttons.first()).toBeVisible();
  const count = await buttons.count();
  expect(count).toBeGreaterThanOrEqual(2);

  // Every loader is a real button with an aria-describedby pointing at a
  // description element that exists and has text (keyboard/AT meaningful).
  for (let i = 0; i < count; i++) {
    const btn = buttons.nth(i);
    const descId = await btn.getAttribute('aria-describedby');
    expect(descId).toBeTruthy();
    await expect(page.locator(`#${descId}`)).not.toBeEmpty();
  }
});

test('clicking the escalation sample fills the input and renders the critical PassRole path', async ({ page }) => {
  await page.locator('#samples .sample-escalation').first().click();

  // Input is filled by the sample.
  await expect(page.locator('#policy-input')).not.toHaveValue('');

  // Normal flow ran: findings table + coverage panel.
  await expect(page.locator('#findings table')).toBeVisible();
  await expect(page.locator('#findings')).toContainText('PassRole');
  await expect(page.locator('#findings .sev-critical')).not.toHaveCount(0);
  await expect(page.locator('#coverage')).toContainText('Coverage summary');
});

test('a neutralized sample loads via keyboard and shows fail-closed coverage (unsupported != safe)', async ({ page }) => {
  // Find the NotPrincipal (unsupported) neutralized loader by its label text.
  const loader = page.locator('#samples .sample-btn', { hasText: 'NotPrincipal' });
  await loader.focus();
  await expect(loader).toBeFocused();
  await page.keyboard.press('Enter');

  await expect(page.locator('#policy-input')).not.toHaveValue('');

  // Fail-closed: a blocking coverage notice, no findings table, and the
  // "unsupported does not mean safe" framing.
  await expect(page.locator('#findings .coverage-blocked')).toBeVisible();
  await expect(page.locator('#findings table')).toHaveCount(0);
  await expect(page.locator('#findings')).toContainText('UNSUPPORTED_NOTPRINCIPAL');
  await expect(page.locator('#coverage')).toContainText('Coverage summary');
});

test('Clear wipes a loaded sample', async ({ page }) => {
  await page.locator('#samples .sample-escalation').first().click();
  await expect(page.locator('#findings table')).toBeVisible();

  await page.click('#clear-btn');
  await expect(page.locator('#policy-input')).toHaveValue('');
  await expect(page.locator('#findings table')).toHaveCount(0);
  await expect(page.locator('#coverage')).toBeEmpty();
});
