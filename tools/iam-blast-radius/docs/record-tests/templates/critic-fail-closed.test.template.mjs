import test from 'node:test';
import assert from 'node:assert/strict';

// Replace with the repository's injected workflow adapter.
async function runReviewWithMocks(_scenario) {
  throw new Error('ADAPT_ME');
}

test('all critic 529 responses block acceptance and write a ledger row', async () => {
  const result = await runReviewWithMocks({
    requiredCritics: ['security', 'correctness', 'evidence'],
    responses: [529, 529, 529]
  });

  assert.equal(result.accepted, false);
  assert.equal(result.decision, 'review_error');
  assert.equal(result.ledgerRows.length, 1);
  assert.equal(result.ledgerRows[0].criticAttempts.length >= 3, true);
});

test('null findings without explicit PASS is invalid, not approval', async () => {
  const result = await runReviewWithMocks({responses: [{findings: null}]});
  assert.equal(result.accepted, false);
  assert.equal(result.criticResults[0].status, 'INVALID_RESPONSE');
});

test('empty required critic set cannot pass vacuously', async () => {
  const result = await runReviewWithMocks({requiredCritics: [], responses: []});
  assert.equal(result.accepted, false);
  assert.equal(result.configurationError, true);
});

test('ledger failure occurs before acceptance', async () => {
  const result = await runReviewWithMocks({
    responses: [{status: 'PASS', findings: []}],
    ledgerWrite: 'FAIL'
  });
  assert.equal(result.accepted, false);
  assert.equal(result.decision, 'review_error');
});
