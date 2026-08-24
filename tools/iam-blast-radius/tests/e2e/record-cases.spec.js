// IAM-1103 (Phase 11C): named Playwright assertions for the UI-only record-test
// bundle cases (docs/record-tests/, 2026-08-24).
//
// The engine-drivable BND-*/DEF-* cases are gated under `node --test` in
// tests/record-cases.test.js. The cases below need a real DOM + Worker (family
// switching + state isolation, three-browser parity, export-after-switch,
// stale-state on selector change, unsupported->supported switch, and the
// blocked-export contract), so they live here. Each test title carries a
// `[CASE-ID]` marker; the node suite asserts every UI-only case has its marker
// present in THIS file, so a UI-only case can never be silently skipped even
// though the browser run is CI's job.
//
// Assertions target STABLE rule identity via the finding's title/rule-name form
// (e.g. /wildcard[-\s]resource/i), never the bare word "wildcard" - the boundary
// envelope's own prose legitimately says "A wildcard boundary provides no
// meaningful upper bound", which must NOT trip a forbidden-rule assertion
// (BND-01/BND-02).

import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';

const PAGE = '/tools/iam-blast-radius/index.html';

// The shared MaximumPermissions wildcard policy (identity-shaped: no Principal),
// analyzable as identity, permissions-boundary, or session.
const WILDCARD_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Sid: 'MaximumPermissions',
    Effect: 'Allow',
    Action: ['s3:*', 'dynamodb:*'],
    Resource: '*',
  }],
}, null, 2);

// Rule-name form of the forbidden identity rule (NOT the bare word "wildcard").
const WILDCARD_RULE_NAME = /wildcard[-\s](resource|action)/i;

test.beforeEach(async ({ page }) => {
  page.on('dialog', async (d) => {
    throw new Error(`Unexpected dialog (possible XSS): ${d.message()}`);
  });
  await page.goto(PAGE);
});

async function analyzeAs(page, family, text) {
  await page.selectOption('#policy-family', family);
  await page.fill('#policy-input', text);
  await page.click('#analyze-btn');
}

async function readDownload(promise) {
  const download = await promise;
  const path = await download.path();
  return readFileSync(path, 'utf8');
}

// [BND-02] The narrow forbidden-rule assertion is NOT a no-op: the same
// rule-name matcher used to prove WILDCARD-RESOURCE is ABSENT in boundary mode
// fires POSITIVELY under identity, so the BND-01 fix (assert on rule identity,
// not prose) still catches a genuine wildcard rule.
test('[BND-02] the wildcard rule-name matcher fires under identity (forbidden-rule assertion is not weakened)', async ({ page }) => {
  await analyzeAs(page, 'identity', WILDCARD_POLICY);
  await expect(page.locator('#findings table')).toBeVisible();
  await expect(page.locator('#findings table')).toContainText(WILDCARD_RULE_NAME);
});

// [BND-03] Identity -> permissions-boundary switch clears identity rule state
// and recomputes; no capability edge is manufactured, no stale WILDCARD row.
test('[BND-03] identity-to-boundary family switch clears rule state, no capability edges', async ({ page }) => {
  await analyzeAs(page, 'identity', WILDCARD_POLICY);
  await expect(page.locator('#findings table')).toContainText(WILDCARD_RULE_NAME);

  await page.selectOption('#policy-family', 'permissions-boundary');
  await expect(page.locator('#findings table')).toContainText(/envelope/i);
  await expect(page.locator('#findings table')).not.toContainText(WILDCARD_RULE_NAME);
  await expect(page.locator('#graph .graph-edge')).toHaveCount(0);
  await expect(page.locator('#status')).toHaveAttribute('data-status', 'ok');
});

// [BND-04] The inverse switch: boundary -> identity recomputes rather than
// relabeling; the envelope prose/finding does not remain in the identity result.
test('[BND-04] boundary-to-identity inverse switch recomputes, envelope finding does not persist', async ({ page }) => {
  await analyzeAs(page, 'permissions-boundary', WILDCARD_POLICY);
  await expect(page.locator('#findings table')).toContainText(/envelope/i);

  await page.selectOption('#policy-family', 'identity');
  await expect(page.locator('#findings table')).toContainText(WILDCARD_RULE_NAME);
  await expect(page.locator('#findings table')).not.toContainText(/maximum-permissions envelope/i);
  await expect(page.locator('#status')).toHaveAttribute('data-status', /^(ok|warned)$/);
});

// [BND-05] The session ceiling uses the same semantic isolation: zero positive
// capability edges and no boundary/identity rule identifiers leaking in.
test('[BND-05] session ceiling creates zero capability edges and no boundary rule leaks', async ({ page }) => {
  await analyzeAs(page, 'session', WILDCARD_POLICY);
  await expect(page.locator('#findings table')).toContainText(/ceiling/i);
  await expect(page.locator('#findings table')).not.toContainText(WILDCARD_RULE_NAME);
  await expect(page.locator('#graph .graph-edge')).toHaveCount(0);
  await expect(page.locator('#status')).toHaveAttribute('data-status', 'ok');
});

// [BND-06] Three-browser acceptance: this spec runs under the chromium /
// firefox / webkit projects declared in playwright.config.js, so this test IS
// the browser-matrix execution of the boundary-envelope semantic. Identical
// assertions must hold in every project.
test('[BND-06] boundary-envelope semantics hold across the chromium/firefox/webkit project matrix', async ({ page }) => {
  await analyzeAs(page, 'permissions-boundary', WILDCARD_POLICY);
  await expect(page.locator('#findings table')).toContainText(/wildcard boundary provides no meaningful upper bound/i);
  await expect(page.locator('#findings table')).toContainText(/envelope/i);
  await expect(page.locator('#findings table')).not.toContainText(WILDCARD_RULE_NAME);
  await expect(page.locator('#graph .graph-edge')).toHaveCount(0);
});

// [BND-07] Export state after a family switch describes ONLY the latest
// analysis: the JSON export names permissions-boundary and carries no stale
// identity WILDCARD-RESOURCE rule identifier, while legitimate prose remains.
test('[BND-07] export after a family switch reflects only the latest family', async ({ page }) => {
  await analyzeAs(page, 'identity', WILDCARD_POLICY);
  await expect(page.locator('#findings table')).toContainText(WILDCARD_RULE_NAME);

  await page.selectOption('#policy-family', 'permissions-boundary');
  await expect(page.locator('#findings table')).toContainText(/envelope/i);
  await expect(page.locator('#export-json')).toBeEnabled();

  const json = await readDownload(
    Promise.all([
      page.waitForEvent('download'),
      page.click('#export-json'),
    ]).then(([d]) => d),
  );
  const parsed = JSON.parse(json);
  expect(parsed.family).toBe('permissions-boundary');
  // No stale identity capability findings in the exported latest-family result.
  const ids = (parsed.findings || []).map((f) => f.id);
  expect(ids).not.toContain('WILDCARD-RESOURCE');
  expect(ids).toContain('PERMISSIONS-BOUNDARY-ENVELOPE');
});

// [BND-08] Changing the selector to NO selection after a completed analysis
// removes the prior results and disables the export controls until a family +
// input pair is analyzed again - the page never shows identity findings under a
// stale/absent family label.
test('[BND-08] clearing the family selection after analysis removes results and disables export', async ({ page }) => {
  await analyzeAs(page, 'identity', WILDCARD_POLICY);
  await expect(page.locator('#findings table')).toBeVisible();
  await expect(page.locator('#export-json')).toBeEnabled();

  await page.selectOption('#policy-family', '');
  await expect(page.locator('#findings table')).toHaveCount(0);
  await expect(page.locator('#export-json')).toBeDisabled();
  await expect(page.locator('#export-md')).toBeDisabled();
  await expect(page.locator('#analyze-btn')).toBeDisabled();
});

// [DEF-09] Unsupported -> supported family switch: the fail-closed coverage
// warning clears before the supported identity result renders, and no blocked
// graph/export state leaks into the identity analysis.
test('[DEF-09] unsupported-to-supported family switch clears the blocked warning, no leaked state', async ({ page }) => {
  // 'resource' selected on an identity-shaped document fails closed.
  await analyzeAs(page, 'resource', WILDCARD_POLICY);
  await expect(page.locator('#findings .coverage-blocked')).toBeVisible();
  await expect(page.locator('#findings .coverage-blocked')).toContainText('UNSUPPORTED_POLICY_FAMILY');
  await expect(page.locator('#findings table')).toHaveCount(0);

  // Switch to identity: the blocked notice clears and the identity result renders.
  await page.selectOption('#policy-family', 'identity');
  await expect(page.locator('#findings .coverage-blocked')).toHaveCount(0);
  await expect(page.locator('#findings table')).toBeVisible();
  await expect(page.locator('#findings table')).toContainText(WILDCARD_RULE_NAME);
  await expect(page.locator('#status')).toHaveAttribute('data-status', /^(ok|warned)$/);
});

// [DEF-10] Blocked export contract: JSON and Markdown exports of a fail-closed
// result both say BLOCKED and name the unsupported family, and carry NO
// authoritative risk score / findings summary / attack-path graph.
test('[DEF-10] blocked JSON and Markdown exports say BLOCKED and carry no risk score or graph', async ({ page }) => {
  await analyzeAs(page, 'resource', WILDCARD_POLICY);
  await expect(page.locator('#findings .coverage-blocked')).toBeVisible();
  await expect(page.locator('#status')).toHaveAttribute('data-status', 'blocked');

  const json = await readDownload(
    Promise.all([
      page.waitForEvent('download'),
      page.click('#export-json'),
    ]).then(([d]) => d),
  );
  const parsed = JSON.parse(json);
  expect(parsed.status).toBe('blocked');
  expect(parsed.family).toBe('resource');
  expect(parsed.coverage && parsed.coverage.blocked).toBe(true);
  expect(parsed.findings || []).toHaveLength(0);
  expect(parsed.graph && (parsed.graph.edges || []).length).toBeFalsy();

  const md = await readDownload(
    Promise.all([
      page.waitForEvent('download'),
      page.click('#export-md'),
    ]).then(([d]) => d),
  );
  expect(md).toMatch(/Analysis status: blocked/i);
  expect(md).toMatch(/Coverage: BLOCKED/);
  expect(md).not.toMatch(/wildcard[-\s]resource/i);
});
