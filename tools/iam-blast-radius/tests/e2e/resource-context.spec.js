// IAM-1201 (Phase 12): Playwright browser acceptance for the attached-resource
// context control. CI-only (needs a real browser); NOT run by the node --test
// authoring loop.
//
// Covers the IAM-1201 acceptance that requires a real DOM/Worker:
//   - the resource-context control is CSP-clean, labeled, and keyboard-accessible
//   - it is revealed only for the Resource-based family (hidden for every other)
//   - family=resource + a valid attached-resource context is ACCEPTED and routed
//     to the resource evaluator (not identity rules): no blocked notice, status
//     'warned' (accepted but INCOMPLETE), no identity findings
//   - a missing context fails closed (RESOURCE_CONTEXT_REQUIRED)
//   - a valid ARN for an unmodeled service fails closed (UNSUPPORTED_RESOURCE_SHAPE)
//   - switching the family away from resource hides + clears the context

import { test, expect } from '@playwright/test';

const PAGE = '/tools/iam-blast-radius/index.html';

const RESOURCE_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Sid: 'PublicRead',
    Effect: 'Allow',
    Principal: '*',
    Action: 's3:GetObject',
    Resource: 'arn:aws:s3:::public-downloads/*',
  }],
}, null, 2);

test.beforeEach(async ({ page }) => {
  // Any injected dialog would mean an XSS executed.
  page.on('dialog', async (d) => {
    throw new Error(`Unexpected dialog (possible XSS): ${d.message()}`);
  });
  await page.goto(PAGE);
});

test('the resource-context control is hidden by default and for non-resource families', async ({ page }) => {
  await expect(page.locator('#resource-context')).toBeHidden();
  await page.selectOption('#policy-family', 'identity');
  await expect(page.locator('#resource-context')).toBeHidden();
  await page.selectOption('#policy-family', 'role-trust');
  await expect(page.locator('#resource-context')).toBeHidden();
});

test('selecting the resource family reveals a labeled, keyboard-accessible context control', async ({ page }) => {
  await page.selectOption('#policy-family', 'resource');
  await expect(page.locator('#resource-context')).toBeVisible();

  // Both fields carry a programmatic label (accessibility).
  await expect(page.locator('label[for="resource-type"]')).toHaveText(/Attached resource type/);
  await expect(page.locator('label[for="resource-arn"]')).toHaveText(/Attached resource ARN/);

  // Keyboard-operable: the ARN field can be focused and typed into.
  await page.locator('#resource-arn').focus();
  await expect(page.locator('#resource-arn')).toBeFocused();
  await page.keyboard.type('arn:aws:s3:::public-downloads/*');
  await expect(page.locator('#resource-arn')).toHaveValue('arn:aws:s3:::public-downloads/*');
});

test('resource family + valid context is accepted and routed to the resource evaluator (not identity)', async ({ page }) => {
  await page.fill('#policy-input', RESOURCE_POLICY);
  await page.selectOption('#policy-family', 'resource');
  await page.fill('#resource-arn', 'arn:aws:s3:::public-downloads/*');
  await page.click('#analyze-btn');

  // Accepted: no blocking notice. Status is 'warned' (accepted but INCOMPLETE -
  // the service-specific resource finding rules are a later tranche).
  await expect(page.locator('#findings .coverage-blocked')).toHaveCount(0);
  await expect(page.locator('#status')).toHaveAttribute('data-status', 'warned');
  // Never an identity finding on a resource policy.
  await expect(page.locator('#findings')).not.toContainText('Wildcard');
  // The coverage panel names the resource family.
  await expect(page.locator('#coverage')).toContainText('resource');
});

// IAM-1202 (Phase 12): principal-centric public-access + transport-vs-identity.
const TRANSPORT_DENY_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'PublicRead',
      Effect: 'Allow',
      Principal: '*',
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::public-downloads/*',
    },
    {
      Sid: 'DenyInsecureTransport',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: ['arn:aws:s3:::public-downloads', 'arn:aws:s3:::public-downloads/*'],
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    },
  ],
}, null, 2);

test('IAM-1202: Principal "*" resource policy renders PUBLIC-ACCESS; a TLS-only Deny does not neutralize it', async ({ page }) => {
  await page.fill('#policy-input', TRANSPORT_DENY_POLICY);
  await page.selectOption('#policy-family', 'resource');
  await page.fill('#resource-arn', 'arn:aws:s3:::public-downloads/*');
  await page.click('#analyze-btn');

  // Accepted (not blocked), still INCOMPLETE coverage.
  await expect(page.locator('#findings .coverage-blocked')).toHaveCount(0);
  await expect(page.locator('#status')).toHaveAttribute('data-status', 'warned');

  // The public-access finding is rendered from the RESOURCE's perspective.
  await expect(page.locator('#findings')).toContainText('Public resource access');
  // Never mis-analyzed as an identity policy.
  await expect(page.locator('#findings')).not.toContainText('Wildcard');

  // Expanding the finding detail shows the transport-vs-identity reasoning: the
  // aws:SecureTransport Deny is transport-only and does not make the public grant
  // private, and (for S3) exposure also depends on Block Public Access.
  await page.locator('#findings .row-toggle').first().click();
  await expect(page.locator('#findings')).toContainText('TRANSPORT constraint');
  await expect(page.locator('#findings')).toContainText('Block Public Access');

  // The graph roots at the anonymous external principal (not the policy subject)
  // and draws the typed resource-access edge.
  await expect(page.locator('.iam-graph .graph-edge.edge-type-can-access-resource')).toHaveCount(1);
});

// IAM-1204 (Phase 12): same-account grant + the optional owning-account field.
// An S3 bucket policy grants a same-account IAM user; S3 ARNs carry no account, so
// the owning account is supplied via the #resource-account field, letting the
// analyzer report a DIRECT same-account grant (not cross-account, not public).
const SAME_ACCOUNT_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Sid: 'DirectUserGrant',
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::123456789012:user/Alice' },
    Action: 's3:GetObject',
    Resource: 'arn:aws:s3:::finance-reports/*',
  }],
}, null, 2);

test('IAM-1204: owning-account field yields a same-account grant finding, not cross-account', async ({ page }) => {
  await page.selectOption('#policy-family', 'resource');
  // The owning-account field is labeled and keyboard-accessible.
  await expect(page.locator('label[for="resource-account"]')).toHaveText(/Owning account ID/);
  await page.locator('#resource-account').focus();
  await expect(page.locator('#resource-account')).toBeFocused();

  await page.fill('#policy-input', SAME_ACCOUNT_POLICY);
  await page.fill('#resource-arn', 'arn:aws:s3:::finance-reports');
  await page.fill('#resource-account', '123456789012');
  await page.click('#analyze-btn');

  await expect(page.locator('#findings .coverage-blocked')).toHaveCount(0);
  await expect(page.locator('#status')).toHaveAttribute('data-status', 'warned');
  await expect(page.locator('#findings')).toContainText('same-account');
  // Not misreported as cross-account or public.
  await expect(page.locator('#findings')).not.toContainText('Cross-account resource grant');
  await expect(page.locator('#findings')).not.toContainText('Public resource access');
  // The resource-vs-identity caveat is present in the expandable detail.
  await page.locator('#findings .row-toggle').first().click();
  await expect(page.locator('#findings')).toContainText('IMPLICIT deny');

  // Clearing wipes the owning-account field too (no stale context rides in).
  await page.click('#clear-btn');
  await expect(page.locator('#resource-account')).toHaveValue('');
});

test('resource family without a context fails closed RESOURCE_CONTEXT_REQUIRED', async ({ page }) => {
  await page.fill('#policy-input', RESOURCE_POLICY);
  await page.selectOption('#policy-family', 'resource');
  await page.click('#analyze-btn');

  const notice = page.locator('#findings .coverage-blocked');
  await expect(notice).toBeVisible();
  await expect(notice).toContainText('RESOURCE_CONTEXT_REQUIRED');
  await expect(notice).not.toContainText('UNSUPPORTED_POLICY_FAMILY');
  await expect(page.locator('#findings table')).toHaveCount(0);
  await expect(page.locator('#status')).toHaveAttribute('data-status', 'blocked');
});

test('resource family with an unmodeled service ARN fails closed UNSUPPORTED_RESOURCE_SHAPE', async ({ page }) => {
  await page.fill('#policy-input', RESOURCE_POLICY);
  await page.selectOption('#policy-family', 'resource');
  await page.fill('#resource-arn', 'arn:aws:lambda:us-east-1:123456789012:function:f');
  await page.click('#analyze-btn');

  const notice = page.locator('#findings .coverage-blocked');
  await expect(notice).toBeVisible();
  await expect(notice).toContainText('UNSUPPORTED_RESOURCE_SHAPE');
  await expect(page.locator('#findings table')).toHaveCount(0);
});

test('switching the family away from resource hides and clears the context', async ({ page }) => {
  await page.selectOption('#policy-family', 'resource');
  await page.fill('#resource-arn', 'arn:aws:s3:::public-downloads/*');
  await expect(page.locator('#resource-arn')).toHaveValue('arn:aws:s3:::public-downloads/*');

  await page.selectOption('#policy-family', 'identity');
  await expect(page.locator('#resource-context')).toBeHidden();

  // Back to resource: the previous ARN was cleared (no stale context rides in).
  await page.selectOption('#policy-family', 'resource');
  await expect(page.locator('#resource-arn')).toHaveValue('');
});
