// Playwright security battle-test - runs in CI (IAM Blast Radius CI) across
// Chromium/Firefox/WebKit. Promotes the security-probes/browser-probes.mjs
// harness into gating e2e: adversarial XSS payload battery, prototype
// pollution via the real UI, DoS input cap, export safety, and zero egress
// while analyzing hostile input. The engine-level probes
// (security-probes/engine-probes.mjs) cover pollution/ReDoS/exhaustion at the
// module layer; this file covers the browser DOM/Worker layer.
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', '..', 'fixtures');
const PAGE = '/tools/iam-blast-radius/index.html';

test.beforeEach(async ({ page }) => {
  // Any dialog during analysis means an injected payload executed -> fail hard.
  page.on('dialog', async (d) => { throw new Error(`Unexpected dialog (XSS executed): ${d.message()}`); });
  await page.goto(PAGE);
  // IAM-1001: policy-family selection is mandatory; opt into explicit Auto-detect.
  await page.selectOption('#policy-family', 'auto');
});

// A policy that triggers findings (Action "*") so the payload fields render.
function poly(fields) {
  return JSON.stringify({ Version: '2012-10-17', Statement: [{ Sid: 'S', Effect: 'Allow', Action: '*', Resource: '*', ...fields }] });
}
const XSS_PAYLOADS = [
  poly({ Sid: '<script>window.__xss=1</script>' }),
  poly({ Sid: '<img src=x onerror="window.__xss=1">' }),
  poly({ Resource: 'arn:aws:s3:::"><svg onload="window.__xss=1">/*' }),
  poly({ Resource: 'javascript:window.__xss=1' }),
  poly({ Condition: { StringEquals: { 'aws:username': '<iframe src=javascript:window.__xss=1></iframe>' } } }),
  poly({ Principal: { AWS: '<script>window.__xss=1</script>' } }),
  poly({ Sid: '"><input autofocus onfocus="window.__xss=1">' }),
  poly({ Sid: '</textarea><img src=x onerror="window.__xss=1">' }),
];

async function analyze(page, policy) {
  await page.fill('#policy-input', policy);
  await page.click('#analyze-btn');
  await page.waitForFunction(
    () => /complete|could not|failed|too|limit/i.test(document.querySelector('#status')?.textContent || ''),
    null, { timeout: 10000 },
  ).catch(() => {});
}

test('hostile payloads across all policy fields stay inert (no execution, no injected nodes)', async ({ page }) => {
  for (const p of XSS_PAYLOADS) {
    await analyze(page, p);
    // Nothing executed (the beforeEach dialog guard + this flag both check it).
    expect(await page.evaluate(() => window.__xss)).toBeFalsy();
    // No live dangerous element was synthesized from the payload markup.
    const injected = await page.evaluate(() => {
      const r = document.querySelector('main');
      return r.querySelectorAll('img[onerror], img[src="x"], script, iframe, [onload], [onfocus], [href^="javascript:"], [src^="javascript:"]').length;
    });
    expect(injected).toBe(0);
  }
});

test('prototype-pollution keys do not pollute Object.prototype', async ({ page }) => {
  const raw = readFileSync(join(fixturesDir, 'malformed', 'proto-pollution.json'), 'utf8');
  const policyRaw = JSON.parse(raw).policyRaw;
  await analyze(page, policyRaw);
  const polluted = await page.evaluate(() => ({}).polluted !== undefined || ({}).isAdmin !== undefined || ({}).x !== undefined);
  expect(polluted).toBe(false);
});

test('oversized policy is rejected by the input cap without hanging the tab', async ({ page }) => {
  const many = JSON.stringify({ Version: '2012-10-17', Statement: Array.from({ length: 20000 }, (_, i) => ({ Sid: 'S' + i, Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b' + i })) });
  await page.fill('#policy-input', many);
  const t = Date.now();
  await page.click('#analyze-btn');
  const resolved = await page.waitForFunction(
    () => /complete|could not|failed|too|limit|large|maximum/i.test(document.querySelector('#status')?.textContent || ''),
    null, { timeout: 10000 },
  ).then(() => true).catch(() => false);
  expect(resolved, 'oversized policy did not resolve within 10s (hang)').toBe(true);
  expect(Date.now() - t, 'oversized policy took too long').toBeLessThan(10000);
  expect(await page.evaluate(() => document.readyState)).toBe('complete');
});

test('export produces a download and does not execute payloads', async ({ page }) => {
  await analyze(page, poly({ Sid: '<img src=x onerror="window.__xss=1">' }));
  const [download] = await Promise.all([
    page.waitForEvent('download', { timeout: 8000 }).catch(() => null),
    page.click('#export-json'),
  ]);
  expect(download, 'JSON export did not produce a download').not.toBeNull();
  expect(await page.evaluate(() => window.__xss)).toBeFalsy();
});

test('analyzing hostile input causes zero external network egress', async ({ page }) => {
  const external = [];
  page.on('request', (req) => {
    const u = req.url();
    if (u.startsWith('data:') || u.startsWith('blob:')) return;
    if (!/^https?:\/\/(127\.0\.0\.1|localhost)/.test(u)) external.push(`${req.method()} ${u}`);
  });
  for (const p of XSS_PAYLOADS.slice(0, 4)) await analyze(page, p);
  expect(external, `external requests: ${external.join(' ; ')}`).toEqual([]);
});
