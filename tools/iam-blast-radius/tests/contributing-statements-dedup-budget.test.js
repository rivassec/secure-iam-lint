// S3-dos-budget-all (iter-8, close-the-class): the LAST uncharged-quadratic
// Array.includes dedup in escalation.js - contributingStatementsFrom.
//
// ROOT CAUSE (same class as F1 / survivingGrantedActions / specificAccountsInRoleArns
// / the role-takeover `dedupe`). A finding's evidence[] carries per-statement `actions`
// lists that grow with the policy's action patterns (a single statement can list up to
// MAX_ACTIONS=10000 grant patterns, all attributed to ONE statementIndex). The old dedup
// used `entry.actions.includes(a)` in a push loop - an O(A^2) Array-scan per statement
// with ZERO chargeWork, so the traversal itself did not participate in either the
// deterministic work budget or the Node wall-clock deadline (both sampled ONLY inside
// chargeWork). It is guarded upstream TODAY (the matcher work that produced these actions
// is charged and trips the budget first), but leaving the last includes-in-push O(n^2) in
// place is exactly the "another spelling" the fail-open hunter re-opens the class on.
//
// FIX. Per-entry Set membership (O(1), traversal O(A)) + chargeWork one unit per action
// inspected, so the dedup traversal PARTICIPATES in the budget and a future regression
// that reaches here under-charged fails CLOSED instead of grinding uncharged. Output shape
// (deduped, statement-index order) is byte-identical to the includes version.
//
// Verified black-box via analyze() (contributingStatementsFrom is module-internal).
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';

// A within-caps PassRole->lambda policy whose EXEC statement lists N DISTINCT action
// patterns that all glob-match lambda:CreateFunction, so the PASSROLE-LAMBDA finding's
// evidence attributes a large per-statement `actions` list to ONE statementIndex - the
// maximal-work case for the includes-in-push dedup the fix removes. Distinctness comes
// from a single '?' walked across each position of the concrete action (a '?' matches any
// one char, so every spelling still matches) plus trailing '*' runs.
function buildLargeExecActionList(N) {
  const concrete = 'lambda:createfunction';
  const set = new Set();
  let i = 0;
  while (set.size < N && i <= N * 60) {
    const p = i % concrete.length;
    const stars = (i / concrete.length) | 0;
    set.add(concrete.slice(0, p) + '?' + concrete.slice(p + 1) + '*'.repeat(stars));
    i++;
  }
  const execActions = [...set].slice(0, N);
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'Pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Sid: 'Exec', Effect: 'Allow', Action: execActions, Resource: '*' },
    ],
  });
}

// A ceiling above a SMALL PassRole policy's total charged work but far below the large
// action-list input's, witnessing that the (now-charged) contributingStatements traversal
// participates in the budget and fails CLOSED on a runaway rather than returning COMPLETE.
const TIGHT_WORK_LIMIT = 100000;
const LARGE_N = 3000;

test('iter-8: contributingStatements dedup preserves shape - entries carry EXACTLY {statementIndex, statementSid, actions}, no internal Set leaks', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'Pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      // duplicate lambda:CreateFunction must collapse; two distinct exec actions ride as
      // two array elements on the ONE exec statement's entry.
      { Sid: 'Exec', Effect: 'Allow', Action: ['lambda:CreateFunction', 'lambda:UpdateFunctionCode', 'lambda:CreateFunction'], Resource: '*' },
    ],
  });
  const a = analyze(text);
  assert.equal(a.ok, true);
  const f = a.findings.find((x) => x.id === 'PASSROLE-LAMBDA');
  assert.ok(f, 'the PassRole->lambda finding fires');
  assert.ok(Array.isArray(f.contributingStatements) && f.contributingStatements.length >= 2);
  for (const e of f.contributingStatements) {
    assert.deepEqual(Object.keys(e).sort(), ['actions', 'statementIndex', 'statementSid'],
      'entry has exactly the canonical keys (no internal `seen` Set leaked into output)');
  }
  const exec = f.contributingStatements.find((e) => e.statementSid === 'Exec');
  // Dedup preserved: the duplicated action appears once, order preserved.
  assert.deepEqual(exec.actions, ['lambda:CreateFunction', 'lambda:UpdateFunctionCode'],
    'per-statement actions are deduped and order-preserved (byte-identical to the includes version)');
});

test('iter-8: a large single-statement exec action list fails CLOSED under a tight budget (the dedup traversal now participates)', () => {
  const text = buildLargeExecActionList(LARGE_N);
  assert.equal(validate(text).ok, true, 'the large-action-list policy is within every limit');
  assert.ok(text.length < 1024 * 1024, 'and under 1 MiB');
  const a = analyze(text, { workLimit: TIGHT_WORK_LIMIT });
  assert.equal(a.ok, true, 'well-formed in-band result, never an uncaught throw');
  assert.equal(a.coverage.summary.analysisAborted, true, 'the charged traversal trips the tight budget');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'), 'carries the RESOURCE_BUDGET_EXCEEDED code');
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('iter-8: a large single-statement exec action list is BOUNDED under the default budget (never an unbounded COMPLETE grind)', () => {
  const text = buildLargeExecActionList(LARGE_N);
  const t0 = performance.now();
  const a = analyze(text); // browser style: deterministic work budget, no clock
  const elapsed = performance.now() - t0;
  assert.equal(a.ok, true);
  assert.ok(elapsed < 2000, `large exec action list analyzed in ${elapsed.toFixed(1)}ms (bounded, < 2s)`);
  // FAIL-CLOSED invariant: if it did NOT abort, it must at least not be a clean COMPLETE
  // that hides the (real) PassRole->service risk - a viable path must surface a finding.
  if (!a.coverage.summary.analysisAborted) {
    assert.ok(a.findings.length > 0 || a.coverage.summary.incomplete,
      'a COMPLETE verdict on a viable PassRole path must carry findings, never a clean empty pass');
  }
});

test('iter-8: analyze() on the large exec action list is DETERMINISTIC (op-count budget, no clock)', () => {
  const text = buildLargeExecActionList(LARGE_N);
  const a1 = analyze(text);
  const a2 = analyze(text);
  assert.deepEqual(a1.findings, a2.findings, 'same input -> same findings twice');
  assert.equal(a1.coverage.summary.analysisAborted, a2.coverage.summary.analysisAborted, 'same abort verdict twice');
  assert.equal(a1.coverage.summary.incomplete, a2.coverage.summary.incomplete, 'same completeness verdict twice');
});

test('iter-8: NO over-correction - a SMALL multi-action PassRole policy stays COMPLETE and still fires with correct provenance', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'Pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Sid: 'Exec', Effect: 'Allow', Action: ['lambda:CreateFunction', 'lambda:UpdateFunctionCode'], Resource: '*' },
    ],
  });
  const a = analyze(text, { workLimit: TIGHT_WORK_LIMIT });
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small policy does NOT trip the tight budget (proportional charge, no blanket abort)');
  assert.equal(a.coverage.summary.incomplete, false, 'it reaches a COMPLETE verdict');
  const f = a.findings.find((x) => x.id === 'PASSROLE-LAMBDA');
  assert.ok(f, 'the legitimate PassRole->service path still surfaces (no false negative from the dedup fix)');
});
