import { test, expect } from '@playwright/test';

// Adapt these selectors to the repository. Prefer stable semantic IDs.
const ui = {
  family: '[data-testid="policy-family"]',
  input: '[data-testid="policy-input"]',
  analyze: '[data-testid="analyze"]',
  findings: '[data-testid="findings"]',
  rule: id => `[data-rule-id="${id}"]`,
  capabilityEdge: '[data-edge-kind="capability"]'
};

const policy = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Sid: 'MaximumPermissions',
    Effect: 'Allow',
    Action: ['s3:*', 'dynamodb:*'],
    Resource: '*'
  }]
}, null, 2);

test('boundary envelope prose does not collide with forbidden rule assertion', async ({ page }) => {
  await page.goto('/tools/iam-blast-radius/');
  await page.locator(ui.family).selectOption('permissions-boundary');
  await page.locator(ui.input).fill(policy);
  await page.locator(ui.analyze).click();

  await expect(page.locator(ui.findings)).toContainText(/wildcard boundary provides no meaningful upper bound/i);
  await expect(page.locator(ui.rule('BOUNDARY-ENVELOPE'))).toHaveCount(1);
  await expect(page.locator(ui.rule('WILDCARD-RESOURCE'))).toHaveCount(0);
  await expect(page.locator(ui.capabilityEdge)).toHaveCount(0);
});

test('family change invalidates prior results before reanalysis', async ({ page }) => {
  await page.goto('/tools/iam-blast-radius/');
  await page.locator(ui.family).selectOption('identity');
  await page.locator(ui.input).fill(policy);
  await page.locator(ui.analyze).click();

  await page.locator(ui.family).selectOption('permissions-boundary');
  await expect(page.locator(ui.rule('WILDCARD-RESOURCE'))).toHaveCount(0);
  await expect(page.locator(ui.analyze)).toBeEnabled();
});
