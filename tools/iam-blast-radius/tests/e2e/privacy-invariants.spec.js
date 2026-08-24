// IAM-504: privacy invariants as release gates (browser layer).
// Playwright e2e - runs in CI across Chromium/Firefox/WebKit (see
// playwright.config.js + the CI workflow); NOT part of the deterministic node
// authoring loop. Complements tests/privacy-invariants.test.js (source/engine
// layer) with the runtime DOM/Worker guarantees node cannot observe:
//   - no app-initiated network after initial asset load
//   - no localStorage / sessionStorage / IndexedDB writes by default
//   - policy text never lands in the URL (location/hash/search) or window.name
//   - Clear AND pagehide wipe in-memory analysis state
//   - a fixture produces the SAME findings through the real browser worker as
//     through the Node engine module (worker/node parity)
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', '..', 'fixtures');
const PAGE = '/tools/iam-blast-radius/index.html';

function fixtureText(rel) {
  const fx = JSON.parse(readFileSync(join(fixturesDir, rel), 'utf8'));
  return typeof fx.policyRaw === 'string' ? fx.policyRaw : JSON.stringify(fx.policy);
}

async function runAnalysis(page, text) {
  await page.fill('#policy-input', text);
  await page.click('#analyze-btn');
  await page.waitForFunction(
    () => /complete|could not|failed|too|limit|unsupported/i.test(
      document.querySelector('#status')?.textContent || '',
    ),
    null, { timeout: 10000 },
  ).catch(() => {});
}

test.beforeEach(async ({ page }) => {
  await page.goto(PAGE);
  // IAM-1001: policy-family selection is mandatory; opt into explicit Auto-detect.
  await page.selectOption('#policy-family', 'auto');
});

test('no app-initiated network requests after the initial asset load', async ({ page }) => {
  // Record every request that happens AFTER the page + its assets have loaded.
  await page.waitForLoadState('networkidle');
  // The Web Worker and its ES-module import graph (worker.js -> engine/*.js) are
  // constructed lazily on the FIRST analysis - i.e. after networkidle. Those are
  // the tool's OWN static assets, fetched same-origin over GET, carrying no
  // policy content; they are deferred asset loads, not egress. The zero-egress
  // invariant (architecture.md #1: "Policy content NEVER leaves the browser") is
  // about CROSS-ORIGIN / beacon traffic - so, exactly as security.spec.js does,
  // treat same-origin (127.0.0.1/localhost) requests as legitimate and flag only
  // egress-shaped requests. A belt-and-suspenders check below also asserts policy
  // text never appears in ANY late request URL.
  const egress = [];
  const captured = [];
  page.on('request', (req) => {
    const u = req.url();
    if (u.startsWith('data:') || u.startsWith('blob:')) return;
    captured.push(`${req.method()} ${u}`);
    if (!/^https?:\/\/(127\.0\.0\.1|localhost)/.test(u)) egress.push(`${req.method()} ${u}`);
  });
  await runAnalysis(page, fixtureText('wildcard/admin-star.json'));
  await page.click('#export-json').catch(() => {});
  // No cross-origin / off-host request at all...
  expect(egress, `unexpected egress requests: ${egress.join(' ; ')}`).toEqual([]);
  // ...and policy content never rides along in ANY late request URL.
  for (const r of captured) expect(r, `policy text leaked into a request URL: ${r}`).not.toContain('GodMode');
});

test('analysis writes nothing to localStorage / sessionStorage / IndexedDB', async ({ page }) => {
  await runAnalysis(page, fixtureText('wildcard/admin-star.json'));
  const storage = await page.evaluate(async () => {
    const dbs = (indexedDB.databases ? await indexedDB.databases() : []);
    return {
      localLen: window.localStorage.length,
      sessionLen: window.sessionStorage.length,
      localDump: JSON.stringify(window.localStorage),
      sessionDump: JSON.stringify(window.sessionStorage),
      idbCount: dbs.length,
    };
  });
  expect(storage.localLen).toBe(0);
  expect(storage.sessionLen).toBe(0);
  expect(storage.idbCount).toBe(0);
  expect(storage.localDump).not.toContain('GodMode');
  expect(storage.sessionDump).not.toContain('GodMode');
});

test('policy text never appears in the URL or window.name', async ({ page }) => {
  await runAnalysis(page, fixtureText('wildcard/admin-star.json'));
  const loc = await page.evaluate(() => ({
    href: location.href,
    hash: location.hash,
    search: location.search,
    name: window.name,
  }));
  for (const v of Object.values(loc)) {
    expect(v || '').not.toContain('GodMode');
  }
  expect(loc.hash).toBe('');
  expect(loc.search).toBe('');
});

test('Clear wipes in-memory analysis state (input, findings, coverage)', async ({ page }) => {
  await runAnalysis(page, fixtureText('wildcard/admin-star.json'));
  await expect(page.locator('#findings table')).toBeVisible();
  await page.click('#clear-btn');
  await expect(page.locator('#policy-input')).toHaveValue('');
  await expect(page.locator('#findings table')).toHaveCount(0);
  await expect(page.locator('#coverage .coverage-summary')).toHaveCount(0);
});

test('pagehide wipes in-memory analysis state', async ({ page }) => {
  await runAnalysis(page, fixtureText('wildcard/admin-star.json'));
  await expect(page.locator('#findings table')).toBeVisible();
  // Dispatch a real pagehide event (as a bfcache/navigation would) and assert
  // the handler cleared the rendered analysis + input.
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
  await expect(page.locator('#findings table')).toHaveCount(0);
  await expect(page.locator('#policy-input')).toHaveValue('');
});

test('worker/node parity: browser findings match the Node engine module', async ({ page }) => {
  const rel = 'pass-role/passrole-lambda-positive.json';
  const text = fixtureText(rel);
  // Expected from the Node engine module (same analyze() the worker imports).
  const expected = analyze(text).findings.map((f) => `${f.severity}|${f.title}`);
  await runAnalysis(page, text);
  await expect(page.locator('#findings table')).toBeVisible();
  // Ordered (severity, title) pairs rendered by the real browser worker path.
  const rendered = await page.$$eval('#findings tbody tr.finding-row', (rows) =>
    rows.map((r) => {
      const sev = r.querySelector('td:first-child')?.textContent?.trim() || '';
      const title = r.querySelector('.row-toggle')?.textContent?.replace('[+]', '').replace('[-]', '').trim() || '';
      return `${sev}|${title}`;
    }),
  );
  expect(rendered).toEqual(expected);
});
