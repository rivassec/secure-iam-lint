// Playwright browser acceptance for IAM-503 (single-flight worker + fail-closed
// execution boundary). CI-only (needs a real browser + real module Worker); NOT
// run by the node --test authoring loop.
//
// Covers the IAM-503 acceptance that only a real DOM/Worker can exercise:
//   - rapid double-submit: the newer result wins and a stale (older) worker
//     result can never overwrite it
//   - a worker crash / runtime error AFTER dispatch NEVER re-runs the engine on
//     the main thread (bounded error instead)
//   - a post-dispatch watchdog timeout fails closed (bounded error, no reprocess)
//   - a malformed worker message fails closed (no reprocess)
//   - aria-busy + status announcements across busy / completion / failure
//
// Technique: for the crash/timeout/malformed/slow cases we intercept the
// module-worker request (**/worker.js) with page.route and fulfill it with a
// stand-in worker that crashes / hangs / returns garbage / stalls. The real
// engine is never loaded in those cases, so if a findings table still appeared
// it could ONLY be because app.js reprocessed on the main thread - which is
// exactly what this story forbids.

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

// A hostile-shaped but valid policy that, if the engine ran, yields many
// findings (Action "*"). Used as the input for the crash/timeout/malformed
// cases: because those cases load a stand-in worker (no real engine), a findings
// table can ONLY appear if app.js illegally reprocessed on the main thread.
const ADMIN = fixture('wildcard/admin-star.json');

test.beforeEach(async ({ page }) => {
  // Any dialog during analysis means injected content executed -> fail hard.
  page.on('dialog', async (d) => {
    throw new Error(`Unexpected dialog (possible XSS): ${d.message()}`);
  });
  await page.goto(PAGE);
});

// --- Single-flight: newer result wins -------------------------------------

test('rapid double-submit: the newer analysis wins and the older is discarded', async ({ page }) => {
  // First submission (a PassRole escalation path)...
  await page.fill('#policy-input', fixture('pass-role/passrole-lambda-positive.json'));
  await page.click('#analyze-btn');
  // ...immediately superseded by a second, different submission (a standalone
  // broad-resource grant with NO escalation path). We do not await the first.
  await page.fill('#policy-input', fixture('wildcard/wildcard-resource-with-write.json'));
  await page.click('#analyze-btn');

  await expect(page.locator('#findings table')).toBeVisible();
  await expect(page.locator('#status')).toContainText('Analysis complete');

  // The final rendered result is the SECOND policy's, and no trace of the first
  // (older) result survives - the stale worker was terminated/ignored. The
  // second fixture yields a STANDALONE WILDCARD-RESOURCE finding, whose rule ID
  // is never emitted as DOM text (only subsumed findings render their id); the UI
  // renders the human title + Sid + action instead, so assert on those - they are
  // unique to the second policy and absent from the first (a PassRole path).
  const findings = page.locator('#findings');
  await expect(findings).toContainText('Wildcard / overly broad resource scope');
  await expect(findings).toContainText('WriteAnywhere');
  await expect(findings).toContainText('s3:PutObject');
  await expect(findings.locator('.risk-summary-top')).toContainText('none');
  await expect(findings).not.toContainText('PASSROLE-LAMBDA');
  await expect(findings).not.toContainText('passed role (unknown privileges)');

  // Exactly one findings table is present (no double render from two jobs).
  await expect(page.locator('#findings table')).toHaveCount(1);
  // Settled -> not busy.
  await expect(page.locator('#findings')).toHaveAttribute('aria-busy', 'false');
});

// --- Fail-closed: worker crash after dispatch -----------------------------

test('a worker crash after dispatch fails closed and never re-runs the engine on the main thread', async ({ page }) => {
  // Stand-in worker that throws when it receives the analysis message. The real
  // engine module is never loaded on this route.
  await page.route('**/worker.js', (route) => route.fulfill({
    status: 200,
    contentType: 'text/javascript',
    body: 'self.onmessage = () => { throw new Error("injected worker crash"); };',
  }));

  await page.fill('#policy-input', ADMIN);
  await page.click('#analyze-btn');

  // Bounded error is shown; status announces the failure.
  await expect(page.locator('#findings .errors')).toContainText('worker stopped unexpectedly');
  await expect(page.locator('#findings .errors')).toContainText('not re-analyzed on the main thread');
  await expect(page.locator('#status')).toContainText('the worker stopped unexpectedly');

  // Proof the engine did NOT reprocess on the main thread: admin-star WOULD
  // produce a findings table + risk summary if analyze() had run here, but the
  // stand-in worker carries no engine, so neither may appear.
  await expect(page.locator('#findings table')).toHaveCount(0);
  await expect(page.locator('#findings .risk-summary')).toHaveCount(0);

  // Export stays disabled (no valid analysis) and busy is cleared.
  await expect(page.locator('#export-json')).toBeDisabled();
  await expect(page.locator('#findings')).toHaveAttribute('aria-busy', 'false');
});

// --- Fail-closed: post-dispatch watchdog timeout --------------------------

test('a post-dispatch watchdog timeout fails closed without main-thread reprocessing', async ({ page }) => {
  // Stand-in worker that receives the message but never responds -> the
  // app-side watchdog must terminate it and fail closed.
  await page.route('**/worker.js', (route) => route.fulfill({
    status: 200,
    contentType: 'text/javascript',
    body: 'self.onmessage = () => {};',
  }));

  const started = Date.now();
  await page.fill('#policy-input', ADMIN);
  await page.click('#analyze-btn');

  // Busy is announced while the (hung) job is in flight.
  await expect(page.locator('#findings')).toHaveAttribute('aria-busy', 'true');

  // The watchdog (WATCHDOG_MS = 8000) eventually fails closed. Allow margin.
  await expect(page.locator('#status')).toContainText('time budget', { timeout: 15000 });
  expect(Date.now() - started, 'watchdog did not fire in a bounded time').toBeLessThan(15000);

  await expect(page.locator('#findings .errors')).toContainText('not re-run on the main thread');
  await expect(page.locator('#findings table')).toHaveCount(0);
  await expect(page.locator('#findings .risk-summary')).toHaveCount(0);
  await expect(page.locator('#findings')).toHaveAttribute('aria-busy', 'false');
  await expect(page.locator('#export-json')).toBeDisabled();
});

// --- Fail-closed: malformed worker message --------------------------------

test('a malformed worker message fails closed and does not reprocess', async ({ page }) => {
  // Stand-in worker that echoes the job id but returns a result object with no
  // boolean `ok` - a malformed message the main thread must reject.
  await page.route('**/worker.js', (route) => route.fulfill({
    status: 200,
    contentType: 'text/javascript',
    body: 'self.onmessage = (e) => { self.postMessage({ id: e.data && e.data.id, result: { garbage: true } }); };',
  }));

  await page.fill('#policy-input', ADMIN);
  await page.click('#analyze-btn');

  await expect(page.locator('#findings .errors')).toContainText('unexpected message');
  await expect(page.locator('#status')).toContainText('unexpected result');
  await expect(page.locator('#findings table')).toHaveCount(0);
  await expect(page.locator('#findings .risk-summary')).toHaveCount(0);
  await expect(page.locator('#findings')).toHaveAttribute('aria-busy', 'false');
});

// --- aria-busy + status announcements -------------------------------------

test('aria-busy toggles true while a job is in flight and false once it settles', async ({ page }) => {
  // Stand-in worker that delays before responding, so the busy state is
  // observable. It returns a well-formed ok:false result (a bounded failure) to
  // exercise the failure announcement path too.
  await page.route('**/worker.js', (route) => route.fulfill({
    status: 200,
    contentType: 'text/javascript',
    body: 'self.onmessage = (e) => { setTimeout(function(){ self.postMessage({ id: e.data && e.data.id, result: { ok: false, errors: [{ code: "X", message: "delayed failure" }], findings: [] } }); }, 700); };',
  }));

  await page.fill('#policy-input', ADMIN);
  await page.click('#analyze-btn');

  // Busy is announced immediately at dispatch, and the running status is set.
  await expect(page.locator('#findings')).toHaveAttribute('aria-busy', 'true');
  await expect(page.locator('#status')).toContainText('Analyzing locally');

  // On completion the busy state clears and the outcome is announced.
  await expect(page.locator('#status')).toContainText('Analysis failed');
  await expect(page.locator('#findings')).toHaveAttribute('aria-busy', 'false');
  await expect(page.locator('#analyze-btn')).toHaveAttribute('aria-busy', 'false');
});

test('a successful analysis announces completion and clears the busy state (real worker)', async ({ page }) => {
  // No route: the real module worker + engine run end-to-end.
  await page.fill('#policy-input', fixture('wildcard/admin-star.json'));
  await page.click('#analyze-btn');

  await expect(page.locator('#findings table')).toBeVisible();
  await expect(page.locator('#status')).toContainText('Analysis complete');
  await expect(page.locator('#status')).toContainText('not effective permissions');
  await expect(page.locator('#findings')).toHaveAttribute('aria-busy', 'false');
});
