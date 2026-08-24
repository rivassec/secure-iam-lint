// Playwright browser acceptance for IAM-1007 (Phase 10, P2/P3): parser
// hardening + rendering/export safety, on the REAL DOM/Worker.
// CI-only (needs a real browser); NOT run by the node --test authoring loop.
//
// Covers the suite-3 acceptance that requires a real ingestion surface:
//   62  a .json file saved with a UTF-8 BOM imports and analyzes (the browser's
//       FileReader path plus validate()'s single-BOM strip)
//   63  paste and .json import of identical bytes render the same findings; the
//       imported filename never changes the result
//   98  a dangerous->safe re-analysis leaves no stale critical state in the UI
//   99  attacker-controlled Sid/ARN strings render as inert text (no dialog, no
//       DOM injection) and the JSON export still downloads

import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', '..', 'fixtures');
const PAGE = '/tools/iam-blast-radius/index.html';

const IDENTITY_READ = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Sid: 'Read', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::reports/*' }],
});

// A compound PassRole->Lambda escalation: critical (severity remodel reserves
// critical for a boundary-crossing compound path, IAM-102).
const DANGEROUS = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: ['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'], Resource: '*' }],
});

const SAFE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:ListRoles', Resource: '*' }],
});

test.beforeEach(async ({ page }) => {
  // Any alert/prompt/confirm from analyzed content means an injection executed.
  page.on('dialog', async (d) => {
    throw new Error(`Unexpected dialog (possible XSS): ${d.message()}`);
  });
  await page.goto(PAGE);
  await page.selectOption('#policy-family', 'auto');
});

test('62: a .json file saved with a UTF-8 BOM imports and analyzes', async ({ page }) => {
  const withBom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(IDENTITY_READ, 'utf8')]);
  await page.setInputFiles('#policy-file', { name: 'policy.json', mimeType: 'application/json', buffer: withBom });
  // The import auto-analyzes; a BOM must not surface a parse error.
  await expect(page.locator('#findings')).not.toContainText('could not be analyzed');
  await expect(page.locator('#coverage')).toContainText('Coverage summary');
});

test('63: paste and file import of identical bytes render the same findings; filename is inert', async ({ page }) => {
  // Paste path.
  await page.fill('#policy-input', DANGEROUS);
  await page.click('#analyze-btn');
  await expect(page.locator('#findings table')).toBeVisible();
  const pasted = (await page.locator('#findings table').innerText()).trim();

  // Import the same bytes under a deliberately misleading filename.
  await page.click('#clear-btn');
  await page.selectOption('#policy-family', 'auto');
  await page.setInputFiles('#policy-file', {
    name: 'trust-policy-DO-NOT-TRUST.json',
    mimeType: 'application/json',
    buffer: Buffer.from(DANGEROUS, 'utf8'),
  });
  await expect(page.locator('#findings table')).toBeVisible();
  const imported = (await page.locator('#findings table').innerText()).trim();

  expect(imported).toBe(pasted);
});

test('98: a dangerous->safe re-analysis leaves no stale critical state', async ({ page }) => {
  await page.fill('#policy-input', DANGEROUS);
  await page.click('#analyze-btn');
  await expect(page.locator('#findings table')).toBeVisible();
  await expect(page.locator('#findings .sev-critical').first()).toBeVisible();

  // Replace with the safe policy and re-analyze; the prior critical result must
  // not survive under the new conclusion.
  await page.fill('#policy-input', SAFE);
  await page.click('#analyze-btn');
  await expect(page.locator('#findings .sev-critical')).toHaveCount(0);
  await expect(page.locator('#findings')).not.toContainText('lambda:CreateFunction');
});

test('99: attacker-controlled strings render inert and the JSON export still downloads', async ({ page }) => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'acceptance-3', 'test-99-rendering-export-injection.json'), 'utf8'));
  await page.fill('#policy-input', JSON.stringify(fx.policy, null, 2));
  await page.click('#analyze-btn');
  await expect(page.locator('#findings table')).toBeVisible();

  // The hostile ARN is present as inert text (no <img>/<script> element created).
  await expect(page.locator('#findings')).toContainText('onerror=alert(1)');
  expect(await page.locator('#findings img').count()).toBe(0);
  expect(await page.locator('#findings script').count()).toBe(0);

  // Export still works (and the dialog guard in beforeEach proves nothing fired).
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 8000 }).catch(() => null),
    page.click('#export-json'),
  ]);
  expect(download, 'JSON export did not produce a download').not.toBeNull();
});
