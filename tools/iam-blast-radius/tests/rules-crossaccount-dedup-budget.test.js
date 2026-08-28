// S4-rules-dos: the cross-account whole-container scan in rules.js
// `ruleDataReadScoped` (the `if (subjectAccount)` block) charged the deterministic
// work budget ZERO units.
//
// ROOT CAUSE (MEDIUM, budget-bypass). With a KNOWN subject account, the rule runs a
// hot loop `for (const r of stmt.resources)` that (a) `matched.filter(isWholeContainerRead)`
// - O(resources x matched) parses - and (b) deduped the cross-account resources/accounts
// with `crossResources.includes(r)` / `crossAccounts.includes(acct)` - an O(resources^2)
// Array scan. Neither reaches globMatch, and rules.js imported globMatch + isGlobBudgetError
// but NOT chargeWork, so the whole scan accrued ZERO work. The 60M browser work ceiling and
// the CLI/Action `--budget-ms` wall-clock deadline are BOTH sampled only inside chargeWork,
// so neither could abort it: a within-caps (10000 actions x 10000 resources) policy ground
// ~21.8s at `--budget-ms 3000` (a 7x overrun) yet the browser path returned a COMPLETE
// verdict - a direct violation of glob.js's invariant that analyze() can NEVER return
// COMPLETE after an unbounded run. Same class as the sibling PassRole / trust-deny dedup
// DoS bugs, one rule over.
//
// FIX. Import chargeWork from ./glob.js and charge the real inner-loop work
// (chargeWork(matched.length) per resource - exactly the isWholeContainerRead parse count
// the filter performs) so BOTH budgets participate and a runaway fails CLOSED mid-loop; and
// replace the O(resources^2) includes() membership with parallel Sets so the dedup is LINEAR
// (the arrays are retained only to preserve deterministic finding order). A pathological
// input now (a) resolves in LINEAR time (no ~21.8s hang) and (b) aborts under the default
// browser work budget AND under a wall-clock deadline; a normal-size policy charges a
// negligible amount and never newly trips the budget (no over-correction).
//
// TESTS-FIRST: these exercise the REAL shipped boundaries - analyze() (browser work budget),
// scan() (CLI wall-clock deadline), and a browser-vs-CLI parity assertion - not an in-process
// shortcut that would miss the bug.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';

// A within-caps identity policy whose single Allow statement grants A data-read actions
// over R whole-container resources, each in a DISTINCT foreign account (!= the subject),
// so EVERY resource routes through the cross-account dedup - the maximal-work case for the
// O(resources^2) includes() the fix removed AND for the per-resource filter the fix charges.
// dynamodb:Scan is a whole-container read for any account-bearing table ARN, so this is a
// genuine CROSS-ACCOUNT-DATA-READ (a REAL risk that must never read CLEAN), not synthetic
// noise. Duplicate actions are kept verbatim by the model, so A copies -> matched.length === A.
function buildCrossAccountReads(A, R) {
  const actions = [];
  for (let i = 0; i < A; i++) actions.push('dynamodb:Scan');
  const resources = [];
  for (let i = 0; i < R; i++) {
    // 12-digit, distinct per resource, and != the subject account below.
    const acct = String(100000000000 + i);
    resources.push(`arn:aws:dynamodb:us-east-1:${acct}:table/t${i}`);
  }
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'Read', Effect: 'Allow', Action: actions, Resource: resources }],
  });
}

// The subject account every foreign resource crosses. Supplied on BOTH surfaces (browser
// "Analyzed principal's account ID" -> worker -> analyze({subjectAccount}); CLI
// --subject-account -> scan({subjectAccount})), so the cross-account path fires identically.
const SUBJECT = '123456789012';

// 10000 actions x 10000 resources: within every count cap (MAX_ACTIONS/MAX_RESOURCES = 10000)
// and under 1 MiB, yet pre-fix the uncharged scan ground ~21.8s while returning COMPLETE.
const DOS_A = 10000;
const DOS_R = 10000;

// A generous absolute ceiling: pre-fix analyze()/scan() ran ~21.8s on this input; post-fix
// the linear+charged scan aborts (or completes) in ~1-2s. 6000ms cleanly separates the two
// (well under the pre-fix runtime, well above the post-fix ~1.2s) so it is a RELIABLE
// regression tripwire without being flaky on a loaded CI box.
const NO_HANG_MS = 6000;

// An ordinary (small) cross-account read: 2 actions x 3 foreign resources. Same finding
// class as the DoS input, but tiny - the control that must COMPLETE with the finding on
// BOTH surfaces (browser==CLI) and must NEVER newly trip the budget.
const ORD_A = 2;
const ORD_R = 3;

test('S4-rules-dos: the within-caps 10000x10000 cross-account read aborts under the DEFAULT browser work budget - never a COMPLETE runaway', () => {
  const text = buildCrossAccountReads(DOS_A, DOS_R);
  assert.equal(validate(text).ok, true, 'the pathological policy is within every validate limit');
  assert.ok(text.length < 1024 * 1024, 'and under 1 MiB');

  const t0 = performance.now();
  const a = analyze(text, { subjectAccount: SUBJECT }); // browser style: default 60M work budget, no clock
  const elapsed = performance.now() - t0;

  assert.equal(a.ok, true, 'well-formed in-band result, never an uncaught throw');
  assert.ok(
    elapsed < NO_HANG_MS,
    `analyzed in ${elapsed.toFixed(1)}ms; pre-fix was ~21800ms (uncharged O(R^2) grind); tripwire ${NO_HANG_MS}ms`,
  );
  // The now-charged scan trips the deterministic work budget mid-loop -> fail CLOSED.
  assert.equal(a.coverage.summary.analysisAborted, true, 'the now-charged cross-account scan trips the 60M work budget (proof it participates)');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'), 'the aborted coverage carries RESOURCE_BUDGET_EXCEEDED');
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('S4-rules-dos: the 10000x10000 input aborts WELL UNDER a --budget-ms wall-clock deadline (no 7x overrun), never clean', () => {
  const text = buildCrossAccountReads(DOS_A, DOS_R);
  const budgetMs = 3000; // the finding's own repro budget - pre-fix ran ~21.8s (7x over)
  const t0 = performance.now();
  const r = scan({ text, family: 'identity', subjectAccount: SUBJECT, budgetMs });
  const elapsed = performance.now() - t0;

  assert.ok(
    elapsed < budgetMs,
    `scan() returned in ${elapsed.toFixed(1)}ms under a ${budgetMs}ms budget (bounded; pre-fix was ~21800ms / 7x)`,
  );
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a cross-account-read runaway must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the budget fires on the cross-account scan -> exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.equal(r.findings.length, 0);
});

test('S4-rules-dos: the 10000x10000 input fails CLOSED under a ZERO wall-clock budget -> exit 3, deterministically, never clean', () => {
  const text = buildCrossAccountReads(DOS_A, DOS_R);
  // budgetMs:0 -> deadline at "now" -> chargeWork's `>=` check aborts DETERMINISTICALLY on
  // the first checkpoint the now-charged scan crosses. Pre-fix the scan barely charged, so a
  // runaway could slip past a zero budget and return COMPLETE.
  const r = scan({ text, family: 'identity', subjectAccount: SUBJECT, budgetMs: 0 });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'never a clean exit 0 on a runaway');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'zero budget -> deterministic exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.equal(r.findings.length, 0);
});

test('S4-rules-dos: scan() with NO wall-clock budget still fails CLOSED on the runaway via the work ceiling alone (browser-equivalent), never clean', () => {
  const text = buildCrossAccountReads(DOS_A, DOS_R);
  const r = scan({ text, family: 'identity', subjectAccount: SUBJECT }); // clock-free; only the 60M work budget
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'the work budget alone must still abort - never a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'exit 3 (work-budget fail-closed)');
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.equal(r.findings.length, 0);
});

test('S4-rules-dos: the abort verdict is DETERMINISTIC (op-count budget, no clock) - same input aborts identically twice', () => {
  const text = buildCrossAccountReads(DOS_A, DOS_R);
  const a1 = analyze(text, { subjectAccount: SUBJECT });
  const a2 = analyze(text, { subjectAccount: SUBJECT });
  assert.equal(a1.coverage.summary.analysisAborted, a2.coverage.summary.analysisAborted, 'same abort verdict twice');
  assert.equal(a1.coverage.summary.incomplete, a2.coverage.summary.incomplete, 'same completeness verdict twice');
  assert.deepEqual(a1.findings, a2.findings, 'same (empty) findings twice');
});

test('S4-rules-dos: NO over-correction - an ordinary cross-account read COMPLETES with its finding and never trips the budget', () => {
  const text = buildCrossAccountReads(ORD_A, ORD_R);
  assert.equal(validate(text).ok, true);
  const a = analyze(text, { subjectAccount: SUBJECT });
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small policy does NOT trip the budget (proportional charge, no blanket abort)');
  assert.equal(a.coverage.summary.incomplete, false, 'it reaches a COMPLETE verdict');
  assert.equal(a.findings.length, 1, 'the real cross-account read still surfaces (no false negative from the DoS fix)');
  assert.equal(a.findings[0].id, 'CROSS-ACCOUNT-DATA-READ', 'and it is the expected finding');
});

test('S4-rules-dos: NO over-correction - a mid-size (500x500) within-caps cross-account read still COMPLETES at the default budget', () => {
  // 500 actions x 500 resources charges ~250k work units from the fixed rule - three orders
  // of magnitude under the 60M ceiling - so a realistically large legitimate policy is
  // unaffected. Only a near-caps runaway approaches the budget.
  const text = buildCrossAccountReads(500, 500);
  assert.equal(validate(text).ok, true);
  const a = analyze(text, { subjectAccount: SUBJECT });
  assert.equal(a.coverage.summary.analysisAborted, false, 'a mid-size policy does not newly trip the budget');
  assert.equal(a.coverage.summary.incomplete, false, 'it completes');
  assert.equal(a.findings.length, 1);
  assert.equal(a.findings[0].id, 'CROSS-ACCOUNT-DATA-READ');
});

test('S4-rules-dos: browser==CLI parity on the ordinary cross-account read - same subject account, same verdict', () => {
  const text = buildCrossAccountReads(ORD_A, ORD_R);
  const a = analyze(text, { subjectAccount: SUBJECT });
  // CROSS-ACCOUNT-DATA-READ is an INFO/LOW-band capability (surfaced, never confirmed), so
  // like the golden crossaccount-bucket-read case the CLI is pinned to threshold 'info' -
  // where it gates - to compare surfacing rather than the default 'high' exit floor.
  const r = scan({ text, family: 'identity', subjectAccount: SUBJECT, threshold: 'info', budgetMs: 3000 });

  // Browser: COMPLETE with exactly the cross-account finding.
  assert.equal(a.coverage.summary.incomplete, false);
  assert.deepEqual(a.findings.map((f) => f.id), ['CROSS-ACCOUNT-DATA-READ']);
  // CLI: same finding, COMPLETE, exit 1 (findings at/above threshold) - NOT clean, NOT aborted.
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'CLI completes on the ordinary policy');
  assert.equal(r.exitCode, EXIT.FINDINGS, 'exit 1 (findings at threshold info), agreeing with the browser surfacing');
  assert.deepEqual(r.findings.map((f) => f.id), ['CROSS-ACCOUNT-DATA-READ'], 'CLI surfaces the same finding the browser does');
});
