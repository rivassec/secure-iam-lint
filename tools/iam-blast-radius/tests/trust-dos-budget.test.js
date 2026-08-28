// S3-dos-budget-all (iteration 2): close the DoS CLASS on the role-TRUST family.
//
// Round-2 blocker. After escalation.js's identity/role-takeover loops were charged,
// the SIBLING family analyzer trust.js was still entirely unbudgeted (ZERO chargeWork
// calls). Its policy-derived combinatorial driver - trustFindingDenyState's
//   O(principals x assume-actions x trust-Deny-statements)
// TRIPLE loop - short-circuits in principalEntryDeniedBy() (uncharged) BEFORE the sole
// charged call (denyActionApplies) for every NON-overlapping principal, so the whole
// walk was invisible to BOTH ceilings the tool arms: the deterministic WORK budget
// (browser + Node) and the CLI/Action WALL-CLOCK deadline are read only inside
// chargeWork(). A within-caps, validate-passing trust policy - N distinct trusted
// principals in one Allow x M non-overlapping trust-Deny statements - therefore drove
// the DEFAULT analyze(text) (auto-detected role-trust) and scan({family:'role-trust'})
// to multiple seconds and returned a COMPLETE verdict; neither budget ever fired
// (threat-model T5/T8 - the Phase-17 "patched the instance, left the class open" trap).
//
// The fix charges the deterministic work budget inside trust.js's policy-derived loops
// (classifyPrincipals' per-member pass, analyzeTrust's statement walk, and above all
// trustFindingDenyState's triple loop - the full product up front PLUS one unit per
// (principal, action, deny) inspected BEFORE the principalEntryDeniedBy short-circuit),
// and makes analyzeTrust's catch RE-THROW a budget abort instead of masking it as an
// INTERNAL error. Both surfaces now sample the path: a runaway fails CLOSED (aborted +
// incomplete on the browser; RESOURCE_BUDGET_EXCEEDED -> exit 3 on the CLI) rather than
// a slow COMPLETE pass. The negative / no-over-correction cases MUST stay green.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';

// A generous, strictly-POSITIVE wall-clock budget handed to scan() for the small-policy
// no-over-correction case (a tiny policy finishes well within it, so it is exit 1, not a
// false fail-closed). It is NOT used as an upper-bound assertion on legitimate heavy
// inputs: "completes bounded" there is asserted via the DETERMINISTIC op-count work budget
// (coverage.summary.analysisAborted === false), which is load-independent - an absolute ms
// ceiling flaked under the parallel full-suite run's CPU contention.
const BOUNDED_MS = 2000;

// The trust-family DoS shape (the finding's reproducer, downscaled to keep the DEFAULT-
// budget run fast while still exceeding a forced tight ceiling): ONE Allow trust
// statement naming N distinct cross-account role-ARN principals that may sts:AssumeRole,
// plus M trust-Deny statements whose principals (distinct account roots) OVERLAP NONE of
// the Allow principals. Because no Deny covers any Allow principal, principalEntryDeniedBy
// short-circuits every (principal, deny) pair - the exact path that used to accrue zero
// work. Auto-detects as role-trust; runs on the DEFAULT analyze(text) with NO options.
function buildTrustDosPolicy(nPrincipals, nDeny) {
  const principals = [];
  for (let i = 0; i < nPrincipals; i++) {
    principals.push(`arn:aws:iam::${String(100000000000 + i)}:role/r${i}`);
  }
  const statements = [
    { Effect: 'Allow', Principal: { AWS: principals }, Action: 'sts:AssumeRole' },
  ];
  for (let j = 0; j < nDeny; j++) {
    statements.push({
      Effect: 'Deny',
      Principal: { AWS: `arn:aws:iam::${String(900000000000 + j)}:root` },
      Action: 'sts:AssumeRole',
    });
  }
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}

// N x M product ~1.2e6: below the generous DEFAULT_WORK_LIMIT (completes bounded) but
// far above the tight forced ceiling used to witness participation, and well above one
// work-check interval so a past wall-clock deadline is sampled deterministically.
const DOS_N = 2000;
const DOS_M = 600;
const TIGHT_WORK_LIMIT = 1e6;

test('trust-family worst case is WITHIN caps yet the triple loop PARTICIPATES in the work budget -> fails CLOSED at a tight ceiling (never a COMPLETE pass from an unbudgeted loop)', () => {
  const text = buildTrustDosPolicy(DOS_N, DOS_M);
  assert.equal(validate(text).ok, true, 'the trust-DoS policy is within every limit (< 1MB, < 1000 statements)');

  const a = analyze(text, { workLimit: TIGHT_WORK_LIMIT });
  assert.equal(a.ok, true, 'well-formed in-band result (never an uncaught throw)');
  assert.equal(a.coverage.summary.analysisAborted, true, 'the now-charged trust triple loop ABORTS under a forced small work budget (it participates)');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(
    a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'),
    'the aborted coverage carries the RESOURCE_BUDGET_EXCEEDED code',
  );
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('trust-family worst case analyzes BOUNDED under the DEFAULT budget and is NEVER a clean/no-risk verdict (the cross-account trust still surfaces)', () => {
  const text = buildTrustDosPolicy(DOS_N, DOS_M);
  const a = analyze(text); // browser style: DEFAULT budget, no wall-clock armed

  assert.equal(a.ok, true, 'well-formed result');
  // Boundedness asserted via the DETERMINISTIC op-count work budget, NOT a wall-clock
  // ceiling. The trust triple loop IS charged (the forced-tight-budget test above trips
  // it), so a run that does NOT hit the work-budget abort proves the charged traversal
  // stayed under the fixed DEFAULT_WORK_LIMIT - the unbudgeted loop this guards against
  // ran free past it. This bound is load-independent; an absolute ms ceiling flaked here
  // (~2.96s) purely from CPU contention under the runner's default file parallelism, not
  // any logic regression.
  assert.equal(a.coverage.summary.analysisAborted, false, 'the charged trust triple loop completes within the fixed DEFAULT work budget (bounded op-count, no clock)');
  // The verdict is NEVER a clean/no-risk pass on this genuinely risky cross-account
  // trust: either a bounded COMPLETE-with-finding or a fail-closed incomplete.
  if (!a.coverage.summary.incomplete) {
    assert.ok(a.findings.length >= 1, 'a COMPLETE verdict MUST still carry the cross-account trust finding (no fail-open clean pass)');
    assert.ok(a.findings.some((f) => typeof f.id === 'string' && f.id.startsWith('TRUST-')), 'the surfaced risk is a trust finding');
  } else if (a.coverage.summary.analysisAborted) {
    // A budget-abort incomplete never ran to a conclusion, so it asserts no findings.
    assert.equal(a.findings.length, 0, 'a budget-aborted incomplete verdict asserts no findings (fail closed)');
  } else {
    // S2-airtight-incomplete (b): this within-caps worst case names 2000 principals,
    // so its attack-path graph exceeds the node bound and TRUNCATES -> incomplete via
    // GRAPH_TRUNCATED. That is a fail-closed (never-clean) verdict, and unlike a
    // budget abort the findings TABLE is authoritative and still carries the
    // cross-account trust (the graph, not the analysis, was bounded).
    assert.ok(a.coverage.summary.codes.includes('GRAPH_TRUNCATED'), 'the incomplete is the bounded-graph truncation signal');
    assert.ok(a.findings.some((f) => typeof f.id === 'string' && f.id.startsWith('TRUST-')), 'a truncated-graph incomplete still surfaces the cross-account trust finding');
  }
});

test('CLI scan() on the trust worst case fails CLOSED under a wall-clock budget -> exit 3, never a clean exit 0', () => {
  const text = buildTrustDosPolicy(DOS_N, DOS_M);
  // budgetMs:0 arms a deadline at "now"; chargeWork's `>=` check makes the now-charged
  // trust loop abort DETERMINISTICALLY on the first work checkpoint (the pre-fix path
  // never sampled the clock at all, so budgetMs was a total no-op and the run returned
  // complete).
  const r = scan({ text, family: 'role-trust', budgetMs: 0 });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a trust runaway must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the wall-clock deadline now fires on the trust path -> exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.equal(r.findings.length, 0);
});

test('CLI scan() on the trust worst case under the DEFAULT budget is BOUNDED and never clean (exit 3 via graph truncation)', () => {
  const text = buildTrustDosPolicy(DOS_N, DOS_M);
  const r = scan({ text, family: 'role-trust' }); // no budgetMs: only the deterministic work budget
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'the cross-account trust risk must never report clean');
  // S2-airtight-incomplete (b): the 2000-principal graph TRUNCATES, so the bounded
  // analysis fails closed to exit 3 (INCOMPLETE / GRAPH_TRUNCATED) rather than exit 1.
  // The budget is NOT tripped (this proves boundedness): reason is COVERAGE_INCOMPLETE,
  // never RESOURCE_BUDGET_EXCEEDED.
  assert.notEqual(r.reason, 'RESOURCE_BUDGET_EXCEEDED', 'a within-caps trust policy must not trip the work budget (bounded, not aborted)');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the truncated-graph within-caps trust policy fails closed to exit 3 (never clean)');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL);
  assert.ok(r.analysisStates.some((s) => s.code === 'GRAPH_TRUNCATED'), 'the fail-closed reason is the bounded-graph truncation');
});

test('BROWSER analyze() and CLI scan() agree on the trust worst case (parity: analyze() is never MORE permissive than scan())', () => {
  const text = buildTrustDosPolicy(DOS_N, DOS_M);
  const a = analyze(text);
  const r = scan({ text, family: 'role-trust' });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'scan() must never be clean on the risky trust path');
  if (!a.coverage.summary.incomplete) {
    assert.ok(a.findings.length >= 1, 'analyze() COMPLETE keeps the trust finding');
    assert.equal(r.exitCode, EXIT.FINDINGS, 'scan() COMPLETE is exit 1 (findings)');
  } else {
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'analyze() incomplete <-> scan() exit 3 (fail closed)');
  }
});

test('trust worst-case analysis is DETERMINISTIC (op-count budget, no clock in the verdict)', () => {
  const text = buildTrustDosPolicy(DOS_N, DOS_M);
  const a1 = analyze(text, { workLimit: TIGHT_WORK_LIMIT });
  const a2 = analyze(text, { workLimit: TIGHT_WORK_LIMIT });
  assert.deepEqual(a1.findings, a2.findings, 'same input -> same (empty) findings twice');
  assert.equal(
    a1.coverage.summary.analysisAborted && a2.coverage.summary.analysisAborted,
    true,
    'both runs abort at the same deterministic trip point',
  );
});

test('NO over-correction: a SMALL trust policy still analyzes to a COMPLETE verdict AND fires the trust finding, even at the tight ceiling', () => {
  // A handful of trusted principals + a couple of denies: real cross-account trust, tiny
  // work. The proportional charge must NOT trip on this legitimate policy (no false
  // fail-closed), and the cross-account trust finding must still fire (no false negative).
  const text = buildTrustDosPolicy(3, 2);
  assert.equal(validate(text).ok, true);
  const a = analyze(text, { workLimit: TIGHT_WORK_LIMIT });
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small trust policy does NOT trip even the tight budget');
  assert.equal(a.coverage.summary.incomplete, false, 'it reaches a COMPLETE verdict');
  assert.ok(a.findings.some((f) => typeof f.id === 'string' && f.id.startsWith('TRUST-')), 'the legitimate cross-account trust still fires (no false negative from the DoS fix)');

  // And a GENEROUS (real, positive) wall-clock budget does NOT fail-close a small policy:
  // it finishes in well under the budget, so the clock, though sampled, is never past the
  // deadline (proof the charge is proportional, not a blanket abort). NB: budgetMs<=0 is
  // deliberately NOT used here - a zero/negative budget is a deadline at/before "now" and
  // now (chargeWork's `>=` check) fails closed DETERMINISTICALLY on the first checkpoint
  // for ANY policy, so it cannot witness "no over-correction"; a strictly-positive budget
  // is the correct vehicle and removes the wall-clock race that made this assertion flaky
  // under the parallel full-suite run.
  const r = scan({ text, family: 'role-trust', budgetMs: BOUNDED_MS });
  assert.equal(r.exitCode, EXIT.FINDINGS, 'a small legitimate trust policy under a real budget is exit 1 (findings), not a false fail-closed');
});
