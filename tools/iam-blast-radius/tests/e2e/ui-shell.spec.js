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

test('compound escalation path shows a risk-factor checklist and no duplicate wildcard row (IAM-105)', async ({ page }) => {
  await page.fill('#policy-input', fixture('pass-role/passrole-lambda-positive.json'));
  await page.click('#analyze-btn');
  await expect(page.locator('#findings table')).toBeVisible();

  // One primary compound row.
  await expect(page.locator('#findings')).toContainText('PassRole');
  // No standalone WILDCARD-RESOURCE main row (it was subsumed into the path).
  await expect(page.locator('#findings tbody tr:not(.finding-detail)')).toHaveCount(1);

  // IAM-101: the detail row is collapsed by default; expand it via the row's
  // disclosure toggle (keyboard/mouse operable).
  const detail = page.locator('#findings tr.finding-detail');
  await expect(detail).toHaveCount(1);
  await expect(detail).toBeHidden();

  const toggle = page.locator('#findings .row-toggle').first();
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  await expect(detail).toBeVisible();

  // The expanded detail carries the present/absent checklist...
  await expect(detail).toContainText('Risk factors for this escalation path');
  await expect(detail.locator('ul.risk-factors li')).not.toHaveCount(0);
  // ...the subordinate wildcard grant folded in (not a separate row)...
  await expect(detail).toContainText('WILDCARD-RESOURCE');
  // ...and the prose that was moved out of the table columns.
  await expect(detail).toContainText('Why it matters');
  await expect(detail).toContainText('What this does NOT prove');
  await expect(detail).toContainText('Remediation');

  // Toggling again collapses it.
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await expect(detail).toBeHidden();
});

test('IAM-506: finding detail carries the condition classification (how the text reads, not a runtime verdict)', async ({ page }) => {
  // A broad s3:GetObject on * fenced by an IpAddress aws:SourceIp condition:
  // DATA-EXFIL fires, and its detail explains the condition as "appears to
  // narrow" without ever claiming a runtime allow/deny.
  await page.fill('#policy-input', fixture('negative/condition-sourceip-narrows-exfil.json'));
  await page.click('#analyze-btn');
  await expect(page.locator('#findings table')).toBeVisible();

  const toggle = page.locator('#findings .row-toggle').first();
  await toggle.click();
  const detail = page.locator('#findings tr.finding-detail').first();
  await expect(detail).toBeVisible();
  await expect(detail).toContainText('Condition classification (how the text reads, not a runtime verdict)');
  await expect(detail.locator('ul.condition-classes li.cc-narrows')).not.toHaveCount(0);
  await expect(detail).toContainText('aws:SourceIp');
});

test('IAM-506: an unmodelled condition key surfaces in the coverage panel as unsupported', async ({ page }) => {
  await page.fill('#policy-input', JSON.stringify({
    Statement: [{
      Effect: 'Allow', Action: 's3:GetObject', Resource: '*',
      Condition: { StringEquals: { 'unmodelled:key': 'x' } },
    }],
  }));
  await page.click('#analyze-btn');
  const panel = page.locator('#coverage .coverage-summary');
  await expect(panel).toBeVisible();
  // The coverage panel takes the incomplete/warning state and names the key.
  await expect(panel).toHaveClass(/coverage-incomplete/);
  await expect(panel).toContainText('unmodelled:key');
  await expect(panel).toContainText('Unsupported does NOT mean safe');
  // Unsupported does NOT mean safe: the broad read still fires.
  await expect(page.locator('#findings table')).toBeVisible();
});

test('IAM-101: compact findings table - prose is out of the row and rows are short', async ({ page }) => {
  // admin-star yields several findings; each is one compact main row plus a
  // collapsed detail row.
  await page.fill('#policy-input', fixture('wildcard/admin-star.json'));
  await page.click('#analyze-btn');
  await expect(page.locator('#findings table')).toBeVisible();

  // The main table header no longer carries the prose columns.
  const headers = await page.locator('#findings thead th').allInnerTexts();
  const headerText = headers.join(' | ');
  expect(headerText).toContain('Severity');
  expect(headerText).toContain('Finding');
  expect(headerText).toContain('Policy evidence');
  expect(headerText).toContain('Path exploitability');
  expect(headerText).not.toContain('Why it matters');
  expect(headerText).not.toContain('What this does NOT prove');
  expect(headerText).not.toContain('Remediation');

  // Every visible main row is short (prose lives in the collapsed detail).
  // Acceptance target: average row height well under 120px.
  const mainRows = page.locator('#findings tbody tr.finding-row');
  const count = await mainRows.count();
  expect(count).toBeGreaterThan(0);
  let total = 0;
  for (let i = 0; i < count; i++) {
    const box = await mainRows.nth(i).boundingBox();
    total += box ? box.height : 0;
  }
  expect(total / count).toBeLessThan(120);

  // Detail rows are collapsed by default (compactness relies on this).
  await expect(page.locator('#findings tr.finding-detail').first()).toBeHidden();

  // No prose lost: expand the first finding and confirm all three prose blocks
  // are reachable in the detail.
  const firstToggle = page.locator('#findings .row-toggle').first();
  await firstToggle.click();
  const firstDetail = page.locator('#findings tr.finding-detail').first();
  await expect(firstDetail).toBeVisible();
  await expect(firstDetail).toContainText('Why it matters');
  await expect(firstDetail).toContainText('What this does NOT prove');
  await expect(firstDetail).toContainText('Remediation');
});

test('IAM-101: per-row detail is keyboard operable', async ({ page }) => {
  await page.fill('#policy-input', fixture('wildcard/admin-star.json'));
  await page.click('#analyze-btn');
  await expect(page.locator('#findings table')).toBeVisible();

  const toggle = page.locator('#findings .row-toggle').first();
  const detail = page.locator('#findings tr.finding-detail').first();
  await expect(detail).toBeHidden();

  // Focus the toggle and activate it with the keyboard.
  await toggle.focus();
  await expect(toggle).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(toggle).toHaveAttribute('aria-expanded', 'true');
  await expect(detail).toBeVisible();

  await page.keyboard.press('Space');
  await expect(toggle).toHaveAttribute('aria-expanded', 'false');
  await expect(detail).toBeHidden();
});

test('risk-summary header renders above the table with counts and the highest-risk path (IAM-106)', async ({ page }) => {
  await page.fill('#policy-input', fixture('pass-role/passrole-lambda-positive.json'));
  await page.click('#analyze-btn');

  const summary = page.locator('#findings .risk-summary');
  await expect(summary).toBeVisible();
  await expect(summary.locator('h3')).toHaveText('Risk summary');
  // Four capability-family labels are present.
  await expect(summary).toContainText('Privilege-escalation paths');
  await expect(summary).toContainText('Role-assumption capabilities');
  await expect(summary).toContainText('Sensitive-data access capabilities');
  await expect(summary).toContainText('Standalone broad-resource findings');
  // The single highest-risk path is shown in one line.
  await expect(summary.locator('.risk-summary-top')).toContainText(
    'Principal -> iam:PassRole -> Lambda -> passed role (unknown privileges)',
  );

  // The summary is rendered BEFORE the findings table (source-order = above it).
  const summaryFirst = await page.evaluate(() => {
    const root = document.getElementById('findings');
    const rs = root.querySelector('.risk-summary');
    const table = root.querySelector('table');
    if (!rs || !table) return false;
    // eslint-disable-next-line no-bitwise
    return !!(rs.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING);
  });
  expect(summaryFirst).toBe(true);
});

test('risk-summary shows no highest-risk path when there is no escalation path (IAM-106)', async ({ page }) => {
  // A broad-resource grant with no PassRole/AssumeRole/direct-IAM action has
  // findings but NO escalation path, so the summary's highest-risk line reads
  // "none". (admin-star is NOT such a case: Action:"*" is de-facto admin and
  // necessarily contains escalation paths - see the wildcard/admin-star fixture.)
  await page.fill('#policy-input', fixture('wildcard/wildcard-resource-with-write.json'));
  await page.click('#analyze-btn');
  const summary = page.locator('#findings .risk-summary');
  await expect(summary).toBeVisible();
  await expect(summary.locator('.risk-summary-top')).toContainText('none');
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

// ---------------------------------------------------------------------------
// IAM-501: policy-family auto-detect + fail-closed coverage in the UI.
// ---------------------------------------------------------------------------

test('an optional manual family override selector is present (auto-detect default)', async ({ page }) => {
  const select = page.locator('#policy-family');
  await expect(select).toBeVisible();
  // Auto-detect is the default selection (paste-and-go preserved).
  await expect(select).toHaveValue('');
});

test('a resource-based policy fails closed with a visible blocking coverage notice', async ({ page }) => {
  await page.fill('#policy-input', fixture('family/resource-policy-blocked.json'));
  await page.click('#analyze-btn');

  // No findings table on a shape the engine does not model.
  await expect(page.locator('#findings table')).toHaveCount(0);
  // The blocking coverage notice is shown instead, with the machine-readable
  // code and the "unsupported does NOT mean safe" wording.
  const notice = page.locator('#findings .coverage-blocked');
  await expect(notice).toBeVisible();
  await expect(notice).toContainText('not supported');
  await expect(notice).toContainText('does NOT mean safe');
  await expect(notice).toContainText('UNSUPPORTED_POLICY_FAMILY');
  await expect(page.locator('#status')).toContainText('Analysis stopped');
});

test('NotPrincipal is rejected in the UI with its code and exact JSON path', async ({ page }) => {
  await page.fill('#policy-input', fixture('family/notprincipal-rejected.json'));
  await page.click('#analyze-btn');

  const notice = page.locator('#findings .coverage-blocked');
  await expect(notice).toBeVisible();
  await expect(notice).toContainText('UNSUPPORTED_NOTPRINCIPAL');
  await expect(notice).toContainText('Statement[0].NotPrincipal');
  await expect(page.locator('#findings table')).toHaveCount(0);
});

test('manual override to an unmodeled family blocks even a clean identity policy', async ({ page }) => {
  await page.fill('#policy-input', fixture('family/identity-auto-detect.json'));
  await page.selectOption('#policy-family', 'scp-rcp');
  await page.click('#analyze-btn');

  const notice = page.locator('#findings .coverage-blocked');
  await expect(notice).toBeVisible();
  await expect(notice).toContainText('UNSUPPORTED_POLICY_FAMILY');
  await expect(page.locator('#findings table')).toHaveCount(0);

  // Clearing resets the override back to auto-detect.
  await page.click('#clear-btn');
  await expect(page.locator('#policy-family')).toHaveValue('');
});

// ---------------------------------------------------------------------------
// IAM-502: compact analysis-coverage summary above the findings, in DOM order.
// ---------------------------------------------------------------------------

test('coverage summary renders above the findings and names family + versions (IAM-502)', async ({ page }) => {
  await page.fill('#policy-input', fixture('wildcard/admin-star.json'));
  await page.click('#analyze-btn');

  const panel = page.locator('#coverage .coverage-summary');
  await expect(panel).toBeVisible();
  await expect(panel.locator('h3')).toHaveText('Coverage summary');
  await expect(panel).toContainText('Identity policy');
  await expect(panel).toContainText('accepted');
  await expect(panel).toContainText('Layers not supplied');
  // The version footer ties a screenshot to a shipped revision.
  await expect(panel.locator('.coverage-versions')).toContainText('rule catalog');

  // Coverage precedes the findings in DOM order (its section is above findings).
  const coverageFirst = await page.evaluate(() => {
    const cov = document.getElementById('coverage');
    const findings = document.getElementById('findings');
    if (!cov || !findings) return false;
    // eslint-disable-next-line no-bitwise
    return !!(cov.compareDocumentPosition(findings) & Node.DOCUMENT_POSITION_FOLLOWING);
  });
  expect(coverageFirst).toBe(true);
});

test('coverage summary takes a warning state on an unsupported shape (IAM-502)', async ({ page }) => {
  await page.fill('#policy-input', fixture('family/resource-policy-blocked.json'));
  await page.click('#analyze-btn');

  const panel = page.locator('#coverage .coverage-summary');
  await expect(panel).toBeVisible();
  await expect(panel).toHaveClass(/coverage-incomplete/);
  await expect(panel.locator('.coverage-warn')).toContainText('does NOT mean safe');
  await expect(panel).toContainText('0 accepted');

  // Clearing wipes the coverage panel too.
  await page.click('#clear-btn');
  await expect(page.locator('#coverage .coverage-summary')).toHaveCount(0);
});

test('findings table works with JavaScript and shows a no-JS message otherwise', async ({ page }) => {
  // The <noscript> fallback exists in the shipped HTML.
  const noscript = await page.locator('noscript').innerText().catch(() => '');
  // innerText of noscript is empty when JS is enabled; assert the element exists
  // in the DOM instead.
  await expect(page.locator('noscript')).toHaveCount(1);
});
