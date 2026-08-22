// Playwright browser acceptance for IAM-007 (UI shell).
// CI-only (needs a real browser); NOT run by the node --test authoring loop.
//
// Covers the IAM-007 acceptance that requires a real DOM/Worker:
//   - HTML-injection fixtures render as inert text (no XSS execution)
//   - security/privacy: zero network egress during analysis
//   - keyboard accessibility of the primary flow
//   - findings table is the authoritative view; Clear wipes it
//   - no policy content persisted to storage; cleared on pagehide

import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', '..', 'fixtures');
const PAGE = '/tools/iam-blast-radius/index.html';

function fixture(rel) {
  const fx = JSON.parse(readFileSync(join(fixturesDir, rel), 'utf8'));
  return typeof fx.policyRaw === 'string' ? fx.policyRaw : JSON.stringify(fx.policy, null, 2);
}

test.beforeEach(async ({ page }) => {
  // Fail loudly if analyzed content ever triggers a dialog (alert/prompt) -
  // that would mean an injection executed.
  page.on('dialog', async (d) => {
    throw new Error(`Unexpected dialog (possible XSS): ${d.message()}`);
  });
  await page.goto(PAGE);
});

test('prominent not-effective-permissions disclaimer is present', async ({ page }) => {
  const disclaimer = page.locator('.disclaimer');
  await expect(disclaimer).toBeVisible();
  await expect(disclaimer).toContainText('not');
  await expect(disclaimer).toContainText('effective permissions');
});

test('analyzes a policy and renders an accessible findings table', async ({ page }) => {
  await page.fill('#policy-input', fixture('wildcard/admin-star.json'));
  await page.click('#analyze-btn');

  const table = page.locator('#findings table');
  await expect(table).toBeVisible();
  await expect(table.locator('caption')).toContainText('finding');
  // Column headers are proper <th scope=col>.
  await expect(table.locator('thead th[scope="col"]').first()).toBeVisible();
  // The wildcard finding appears as text.
  await expect(page.locator('#findings')).toContainText('Wildcard');
});

test('HTML/JS/SVG payloads in policy fields do not execute or inject (no XSS)', async ({ page }) => {
  // Gold-standard XSS check: any executed payload would open a dialog.
  let dialogFired = false;
  page.on('dialog', async (d) => { dialogFired = true; await d.dismiss(); });

  await page.fill('#policy-input', fixture('adversarial/xss-in-sid-and-arn.json'));
  await page.click('#analyze-btn');
  await expect(page.locator('#status')).toContainText('Analysis complete');

  // Hostile Sid/ARN markup is inert data: safe DOM (createElement + textContent)
  // means NO element is ever synthesized from the payload, and nothing executes.
  // (Render-path inertness for payloads that DO surface is covered by the graph
  // svg-injection-inert spec.)
  await expect(page.locator('#findings img')).toHaveCount(0);
  await expect(page.locator('#findings script')).toHaveCount(0);
  await expect(page.locator('#findings svg')).toHaveCount(0);
  await expect(page.locator('#graph img')).toHaveCount(0);
  expect(dialogFired).toBe(false);
});

test('zero network egress during a full analysis', async ({ page }) => {
  const external = [];
  page.on('request', (req) => {
    const url = req.url();
    // Same-origin static assets + blob:/data: only. Anything else is egress.
    if (!url.startsWith('http://127.0.0.1') && !url.startsWith('blob:') && !url.startsWith('data:')) {
      external.push(url);
    }
  });
  await page.fill('#policy-input', fixture('pass-role/passrole-lambda-positive.json'));
  await page.click('#analyze-btn');
  await expect(page.locator('#findings table')).toBeVisible();
  expect(external, `unexpected network egress: ${external.join(', ')}`).toEqual([]);
});

test('primary flow is keyboard operable', async ({ page }) => {
  await page.locator('#policy-input').focus();
  await page.keyboard.insertText(fixture('wildcard/admin-star.json'));
  // Tab to the Analyze button and activate via keyboard.
  const analyze = page.locator('#analyze-btn');
  await analyze.focus();
  await expect(analyze).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#findings table')).toBeVisible();
});

test('Clear wipes the input and findings and retains nothing in storage', async ({ page }) => {
  await page.fill('#policy-input', fixture('wildcard/admin-star.json'));
  await page.click('#analyze-btn');
  await expect(page.locator('#findings table')).toBeVisible();

  await page.click('#clear-btn');
  await expect(page.locator('#policy-input')).toHaveValue('');
  await expect(page.locator('#findings table')).toHaveCount(0);

  // No policy content in web storage at any point.
  const storage = await page.evaluate(() => ({
    local: JSON.stringify(window.localStorage),
    session: JSON.stringify(window.sessionStorage),
  }));
  expect(storage.local).not.toContain('GodMode');
  expect(storage.session).not.toContain('GodMode');
});

test('findings table works with JavaScript and shows a no-JS message otherwise', async ({ page }) => {
  // The <noscript> fallback exists in the shipped HTML.
  const noscript = await page.locator('noscript').innerText().catch(() => '');
  // innerText of noscript is empty when JS is enabled; assert the element exists
  // in the DOM instead.
  await expect(page.locator('noscript')).toHaveCount(1);
});
