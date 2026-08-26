// S3-dos-budget-all (round-2, info / defense-in-depth): the linear-today condition
// helpers now ACCRUE budget charge so a FUTURE superlinear regression fails CLOSED.
//
// conditions.js classifyConditions / unsupportedConditionKeys and resource.js
// principalScopingAnalysis / conditionKeyInventory / describeConditionComposition /
// commonSourceAccount are all O(condition size) scans reached from analyze()'s coverage
// enrichment and the resource evaluator. They never touch the shared matcher, so they
// charged the cooperative work budget ZERO - the exact uncharged-loop shape of every DoS
// residual in this story. They are linear today (not a live DoS), but leaving them
// uncharged lets the class stay open: a later change that made one superlinear could ride
// it to a multi-second COMPLETE verdict undetected. Each now charges chargeWork per
// operator/key/value inspected.
//
// chargeWork is a no-op while no budget is armed, so this changes NO verdict (the full
// suite proves that). This test witnesses the two properties that matter: (a) a legit
// heavy-condition policy still COMPLETES under the default budget (no false fail-closed
// from the new charge), and (b) the charge PARTICIPATES - a tight ceiling trips it, so a
// superlinear regression would fail closed instead of grinding uncharged.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';

// An identity policy whose single statement carries a Condition with K distinct
// (unmodelled) keys. classifyConditions is reached from unsupportedConditionKeys during
// analyze()'s coverage enrichment and now charges K. K=20000 is ~564KB (within MAX_BYTES).
function buildManyConditionKeys(K) {
  const inner = {};
  for (let i = 0; i < K; i++) inner[`aws:CustomKey${i}`] = `v${i}`;
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: ['s3:GetObject'], Resource: ['*'], Condition: { StringEquals: inner } }],
  });
}

const HEAVY_K = 20000;

test('condition helpers: a heavy-condition policy still COMPLETES under the default budget (the new charge does not false-close)', () => {
  const text = buildManyConditionKeys(HEAVY_K);
  assert.equal(validate(text).ok, true, 'the heavy-condition policy is within every limit');
  const a = analyze(text);
  assert.equal(a.ok, true, 'well-formed in-band result');
  assert.equal(a.coverage.summary.analysisAborted, false, 'the linear condition scan is NOT aborted by the default budget (no false fail-closed)');
  // The many unmodelled keys legitimately mark coverage incomplete (unsupported does NOT
  // mean safe) - that is the honest signal, NOT a DoS abort: no RESOURCE_BUDGET_EXCEEDED.
  assert.ok(!a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'), 'incomplete here is the unmodelled-keys signal, not a budget abort');
});

test('condition helpers: the condition-classification scan PARTICIPATES in the work budget -> fails CLOSED at a tight ceiling', () => {
  const text = buildManyConditionKeys(HEAVY_K);
  const a = analyze(text, { workLimit: 5000 });
  assert.equal(a.ok, true, 'well-formed in-band result');
  assert.equal(a.coverage.summary.analysisAborted, true, 'the now-charged condition scan trips a tight budget (proof it participates)');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'), 'the aborted coverage carries the RESOURCE_BUDGET_EXCEEDED code');
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('condition helpers: NO over-correction - a small-condition policy stays COMPLETE at the same tight ceiling', () => {
  const text = buildManyConditionKeys(3);
  assert.equal(validate(text).ok, true);
  const a = analyze(text, { workLimit: 5000 });
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small-condition policy does NOT trip even the tight budget (proportional charge, no blanket abort)');
});
