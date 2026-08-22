// Playwright browser acceptance for IAM-008 (SVG graph + evidence panel).
// CI-only (needs a real browser); NOT run by the node --test authoring loop.
//
// Covers the IAM-008 acceptance that only a real DOM/SVG engine can prove:
//   - the graph renders as an inline SVG (progressive enhancement)
//   - distinct edge styles per certainty class are present
//   - SVG/HTML injection fixtures render inert (no dialog, no <script>/<img>,
//     no nested <svg> synthesized from input)
//   - click AND keyboard open the evidence panel
//   - reduced-motion is honored (no entrance animation applied)
//   - the findings table remains the authoritative view

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
  // Any dialog (alert/prompt/confirm) means an injected payload executed.
  page.on('dialog', async (d) => {
    throw new Error(`Unexpected dialog (possible XSS): ${d.message()}`);
  });
  await page.goto(PAGE);
});

test('renders the attack path as an inline SVG with styled edges', async ({ page }) => {
  await page.fill('#policy-input', fixture('pass-role/passrole-lambda-positive.json'));
  await page.click('#analyze-btn');

  const svg = page.locator('#graph svg');
  await expect(svg).toBeVisible();
  // At least one focusable edge with a certainty class.
  const edge = page.locator('#graph .graph-edge').first();
  await expect(edge).toHaveAttribute('role', 'button');
  await expect(edge).toHaveAttribute('tabindex', '0');
  const cls = await edge.getAttribute('class');
  expect(cls).toMatch(/cert-(confirmed|conditional|potential|blocked|unknown)/);

  // The visible edge-path must actually be painted by styles.css - the earlier
  // defect was that NO graph rules existed, so SVG defaulted to fill:black /
  // no stroke and the edges rendered as black blobs / invisible lines on the
  // dark theme. Assert a real, non-default stroke and fill:none.
  const painted = await edge.locator('.edge-path').evaluate((el) => {
    const s = getComputedStyle(el);
    return { stroke: s.stroke, fill: s.fill, width: parseFloat(s.strokeWidth) };
  });
  expect(painted.fill).toBe('none'); // a filled bezier would be a black blob
  expect(painted.stroke).not.toBe('none');
  expect(painted.stroke).not.toBe('rgb(0, 0, 0)'); // not the invisible default
  expect(painted.width).toBeGreaterThan(0);

  // Node boxes must be painted too (were previously black-on-near-black).
  const nodeFill = await page
    .locator('#graph .node-box')
    .first()
    .evaluate((el) => getComputedStyle(el).fill);
  expect(nodeFill).not.toBe('rgb(0, 0, 0)');

  // IAM-107: the PassRole path renders the privilege transition through an
  // unknown-privileges pivot, not a direct principal->service spoke. The pivot
  // node is present, visually distinguished (dashed border), and names its
  // unknown privileges as text (not color-only).
  const pivot = page.locator('#graph .node-unknown-priv').first();
  await expect(pivot).toBeVisible();
  await expect(pivot).toContainText(/unknown/i);
  const pivotDash = await pivot
    .locator('.node-box')
    .evaluate((el) => getComputedStyle(el).strokeDasharray);
  expect(pivotDash).not.toBe('none'); // dashed = the UNKNOWN pivot, distinct from solid known nodes
  // The service-execution node is flagged as the potential boundary crossing.
  await expect(page.locator('#graph .node-boundary').first()).toBeVisible();
});

test('each edge-certainty class resolves to a visually distinct stroke', async ({ page }) => {
  // admin-star yields edges of several certainties. Distinct certainty classes
  // must map to distinct stroke colors so blocked-by-deny never looks like
  // confirmed-by-context (threat-model T8: certainty must be truthful).
  await page.fill('#policy-input', fixture('wildcard/admin-star.json'));
  await page.click('#analyze-btn');
  await expect(page.locator('#graph svg')).toBeVisible();

  const strokeFor = async (cls) => {
    const loc = page.locator(`#graph .graph-edge.${cls} .edge-path`).first();
    if ((await loc.count()) === 0) return null;
    return loc.evaluate((el) => getComputedStyle(el).stroke);
  };
  const confirmed = await strokeFor('cert-confirmed');
  const potential = await strokeFor('cert-potential');
  // admin-star produces both confirmed and potentially-reachable edges.
  expect(confirmed).toBeTruthy();
  expect(potential).toBeTruthy();
  expect(confirmed).not.toBe(potential);
});

test('clicking an edge opens the evidence panel with statement + certainty', async ({ page }) => {
  await page.fill('#policy-input', fixture('pass-role/passrole-lambda-positive.json'));
  await page.click('#analyze-btn');
  // The edge is a <g role="button"> whose child <text> label overlays the
  // center, tripping Playwright's "subtree intercepts pointer events" guard.
  // The <g> is the real focusable button (a click bubbles to it in a real
  // browser), so force past the actionability intercept check.
  await page.locator('#graph .graph-edge').first().click({ force: true });

  const panel = page.locator('#evidence');
  await expect(panel).toContainText('Certainty');
  await expect(panel).toContainText('Statement');
  await expect(panel).toContainText('not effective permissions');
});

test('evidence panel opens from the keyboard (Enter)', async ({ page }) => {
  await page.fill('#policy-input', fixture('pass-role/passrole-lambda-positive.json'));
  await page.click('#analyze-btn');
  const edge = page.locator('#graph .graph-edge').first();
  await edge.focus();
  await expect(edge).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#evidence')).toContainText('Actions');
});

test('SVG/HTML payloads in policy fields render inert in the graph', async ({ page }) => {
  await page.fill('#policy-input', fixture('graph/svg-injection-inert.json'));
  await page.click('#analyze-btn');
  await expect(page.locator('#graph svg')).toBeVisible();

  // The payload appears as literal text in the SVG (a <text> node)...
  await expect(page.locator('#graph')).toContainText('alert(document.domain)');
  // ...but NO element was synthesized from the payload markup.
  await expect(page.locator('#graph script')).toHaveCount(0);
  await expect(page.locator('#graph img')).toHaveCount(0);
  // Exactly one <svg> (the root); no nested <svg> injected from the ARN payload.
  await expect(page.locator('#graph svg')).toHaveCount(1);

  // Inspecting the edge keeps the payload inert in the evidence panel too.
  // The edge is a <g role="button"> whose child <text> label overlays the
  // center, tripping Playwright's "subtree intercepts pointer events" guard.
  // The <g> is the real focusable button (a click bubbles to it in a real
  // browser), so force past the actionability intercept check.
  await page.locator('#graph .graph-edge').first().click({ force: true });
  await expect(page.locator('#evidence script')).toHaveCount(0);
  await expect(page.locator('#evidence img')).toHaveCount(0);
});

test('reduced-motion is honored: no entrance-animation class on the SVG', async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: 'reduce' });
  const page = await context.newPage();
  page.on('dialog', async (d) => { throw new Error(`Unexpected dialog: ${d.message()}`); });
  await page.goto(PAGE);
  await page.fill('#policy-input', fixture('wildcard/admin-star.json'));
  await page.click('#analyze-btn');
  const svg = page.locator('#graph svg');
  await expect(svg).toBeVisible();
  const cls = await svg.getAttribute('class');
  expect(cls).not.toContain('iam-graph-animate');
  await context.close();
});

test('findings table remains authoritative alongside the graph', async ({ page }) => {
  await page.fill('#policy-input', fixture('wildcard/admin-star.json'));
  await page.click('#analyze-btn');
  // Both the table and the graph are present; the table is the source of truth.
  await expect(page.locator('#findings table')).toBeVisible();
  await expect(page.locator('#graph svg')).toBeVisible();
});

test('zero network egress during graph render + edge inspection', async ({ page }) => {
  const external = [];
  page.on('request', (req) => {
    const url = req.url();
    if (!url.startsWith('http://127.0.0.1') && !url.startsWith('blob:') && !url.startsWith('data:')) {
      external.push(url);
    }
  });
  await page.fill('#policy-input', fixture('graph/svg-injection-inert.json'));
  await page.click('#analyze-btn');
  // The edge is a <g role="button"> whose child <text> label overlays the
  // center, tripping Playwright's "subtree intercepts pointer events" guard.
  // The <g> is the real focusable button (a click bubbles to it in a real
  // browser), so force past the actionability intercept check.
  await page.locator('#graph .graph-edge').first().click({ force: true });
  await expect(page.locator('#evidence')).toContainText('Certainty');
  expect(external, `unexpected network egress: ${external.join(', ')}`).toEqual([]);
});
