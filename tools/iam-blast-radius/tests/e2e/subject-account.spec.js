// S2-crossaccount-scoped-surface (iteration-2, finding #1): Playwright browser
// acceptance for the analyzed-principal account control. CI-only (needs a real
// browser + Worker); NOT run by the node --test authoring loop.
//
// The story surfaces scoped-but-real CROSS-ACCOUNT capabilities at low/info, but ONLY
// when the subject account is KNOWN. Before this fix the browser exposed no way to
// supply it, so the flagship tool could NEVER surface those findings and read
// affirmatively CLEAN on a cross-account scoped sts:AssumeRole - a browser fail-open.
// This spec proves the wired-through field closes it in a real browser:
//   - the control is CSP-clean, labeled, keyboard-accessible
//   - it is revealed for the identity / auto families and hidden for the others
//   - with a subject account supplied, a cross-account scoped assume SURFACES
//   - with it blank, the same policy stays quiet (conservative: can't tell same/cross)
//   - a SAME-account subject keeps a same-account scoped assume quiet (no over-fire)
//   - Clear + switching family away wipes the field (no stale account rides in)

import { test, expect } from '@playwright/test';

const PAGE = '/tools/iam-blast-radius/index.html';

const SUBJECT = '123456789012';
const OTHER = '999999999999';

const CROSS_ASSUME_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Sid: 'AssumeOther',
    Effect: 'Allow',
    Action: 'sts:AssumeRole',
    Resource: `arn:aws:iam::${OTHER}:role/X`,
  }],
}, null, 2);

test.beforeEach(async ({ page }) => {
  page.on('dialog', async (d) => {
    throw new Error(`Unexpected dialog (possible XSS): ${d.message()}`);
  });
  await page.goto(PAGE);
});

test('the identity-context control is hidden by default and shown for identity / auto only', async ({ page }) => {
  await expect(page.locator('#identity-context')).toBeHidden();
  await page.selectOption('#policy-family', 'identity');
  await expect(page.locator('#identity-context')).toBeVisible();
  await page.selectOption('#policy-family', 'auto');
  await expect(page.locator('#identity-context')).toBeVisible();
  await page.selectOption('#policy-family', 'resource');
  await expect(page.locator('#identity-context')).toBeHidden();
  await page.selectOption('#policy-family', 'role-trust');
  await expect(page.locator('#identity-context')).toBeHidden();
});

test('the subject-account field is labeled and keyboard-accessible', async ({ page }) => {
  await page.selectOption('#policy-family', 'identity');
  await expect(page.locator('label[for="subject-account"]')).toHaveText(/Analyzed principal's account ID/);
  await page.locator('#subject-account').focus();
  await expect(page.locator('#subject-account')).toBeFocused();
  await page.keyboard.type(SUBJECT);
  await expect(page.locator('#subject-account')).toHaveValue(SUBJECT);
});

test('a supplied subject account surfaces a cross-account scoped assume (no browser fail-open)', async ({ page }) => {
  await page.fill('#policy-input', CROSS_ASSUME_POLICY);
  await page.selectOption('#policy-family', 'identity');
  await page.fill('#subject-account', SUBJECT);
  await page.click('#analyze-btn');

  await expect(page.locator('#findings .coverage-blocked')).toHaveCount(0);
  await expect(page.locator('#findings')).toContainText('Cross-account role assumption');
});

test('with the subject account blank, the same policy stays quiet (conservative)', async ({ page }) => {
  await page.fill('#policy-input', CROSS_ASSUME_POLICY);
  await page.selectOption('#policy-family', 'identity');
  await page.click('#analyze-btn');

  // No subject account -> the analyzer cannot tell same- from cross-account and stays
  // quiet; the cross-account finding must not appear.
  await expect(page.locator('#findings')).not.toContainText('Cross-account role assumption');
});

test('a SAME-account subject keeps a same-account scoped assume quiet (no over-fire)', async ({ page }) => {
  const sameAccount = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'AssumeOwn',
      Effect: 'Allow',
      Action: 'sts:AssumeRole',
      Resource: `arn:aws:iam::${SUBJECT}:role/X`,
    }],
  }, null, 2);
  await page.fill('#policy-input', sameAccount);
  await page.selectOption('#policy-family', 'identity');
  await page.fill('#subject-account', SUBJECT);
  await page.click('#analyze-btn');

  await expect(page.locator('#findings')).not.toContainText('Cross-account role assumption');
});

test('Clear and switching family away wipe the subject-account field (no stale context)', async ({ page }) => {
  await page.selectOption('#policy-family', 'identity');
  await page.fill('#subject-account', SUBJECT);
  await expect(page.locator('#subject-account')).toHaveValue(SUBJECT);

  // Switching to a non-identity/auto family hides and clears it.
  await page.selectOption('#policy-family', 'resource');
  await expect(page.locator('#identity-context')).toBeHidden();
  await page.selectOption('#policy-family', 'identity');
  await expect(page.locator('#subject-account')).toHaveValue('');

  // Clear wipes it too.
  await page.fill('#subject-account', SUBJECT);
  await page.click('#clear-btn');
  await expect(page.locator('#subject-account')).toHaveValue('');
});
