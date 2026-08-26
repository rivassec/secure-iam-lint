// S3-dos-budget-all (round-2 residual DOS-1): the role-takeover satisfiability
// TRIPLE loop charged too little to bound its OWN grind.
//
// ROOT CAUSE (DOS-1, blocking, measured on node v22 at the DEFAULT budget).
// detectRoleTakeover -> principalConditionsSatisfiable runs a grant x trust x assume
// TRIPLE loop over policy-derived legs. It charged the deterministic work budget ONE
// unit per triple (chargeWork(gLen*tLen*aLen)) and REBUILT principalPinsOf(stmt) - a
// parseOperator + Map/Set allocation - for the SAME statement O(N^2) times inside the
// loop with no memoization. A product of 160 legs per group (160^3 = 4,096,000 triples)
// is FAR below DEFAULT_WORK_LIMIT (60,000,000), so the 1-unit-per-triple charge never
// tripped, yet the O(N^3) pin-rebuild ground for ~2.9s and returned a COMPLETE verdict
// (ok:true, analysisAborted=false, incomplete=false, findings=320) - a direct violation
// of glob.js's invariant that analyze() can NEVER return COMPLETE after an unbounded run
// (threat-model T5/T8). The prior big-product role-takeover test (product ~1.25e8) always
// tripped even at 1 unit/triple, so it never covered this WITHIN-budget residual.
//
// The measured trigger: 480 statements (<= MAX_STATEMENTS=1000), ~80KB (<= MAX_BYTES),
// 160x each of iam:PutRolePolicy / iam:UpdateAssumeRolePolicy / sts:AssumeRole all on the
// SAME concrete role, with the grant+trust legs pinning aws:PrincipalAccount=111111111111
// and the assume legs pinning =999999999999 (disjoint -> EVERY triple contradicts -> the
// satisfiability search walks the full N^3 product, never short-circuiting). scan() with
// budgetMs:2000 OVERRAN to ~5481ms because the pin-rebuild burned CPU the wall-clock
// deadline (sampled only inside chargeWork) never got to see.
//
// FIX. (1) MEMOIZE principalPinsOf per statement (keyed by statement index, shared across
// the whole triple loop AND across anchor roles) so a Condition is parsed ONCE, not
// O(N^2) times - the real-CPU cut. (2) Charge the combinatorial product WEIGHTED by the
// real per-triple cost (SATISFIABILITY_TRIPLE_WORK) up front, so a product that would
// approach the ~2s grind trips the deterministic budget BEFORE the search runs. Result:
// the N=100..200-legs-per-group attack family fails CLOSED (aborted+incomplete on the
// browser, exit 3 on scan) well under 2s, the scan wall-clock budget actually bounds
// runtime, and small legitimate role-takeover chains still analyze COMPLETE and fire.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import { DEFAULT_WORK_LIMIT } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const ANCHOR_ROLE = 'arn:aws:iam::123456789012:role/target';

// The DOS-1 trigger, parametrised by legs-per-group N. N statements each of the three
// role-takeover primitives on the SAME concrete role; the grant + trust legs pin one
// principal account and the assume legs pin a DISJOINT one, so no (grant, trust, assume)
// triple is jointly satisfiable and the search walks the full N^3 product.
function buildDisjointPinTakeover(N) {
  const statements = [];
  const pin = (acct) => ({ StringEquals: { 'aws:PrincipalAccount': acct } });
  for (let i = 0; i < N; i++) {
    statements.push({ Effect: 'Allow', Action: 'iam:PutRolePolicy', Resource: ANCHOR_ROLE, Condition: pin('111111111111') });
    statements.push({ Effect: 'Allow', Action: 'iam:UpdateAssumeRolePolicy', Resource: ANCHOR_ROLE, Condition: pin('111111111111') });
    statements.push({ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: ANCHOR_ROLE, Condition: pin('999999999999') });
  }
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}

// 160 legs per group = 480 statements, ~80KB. product = 160^3 = 4,096,000 triples: BELOW
// DEFAULT_WORK_LIMIT (60M) at the old 1-unit-per-triple charge - the exact within-budget
// residual that returned COMPLETE after a ~2.9s grind. This is the measured DOS-1 input.
const RESIDUAL_N = 160;

test('DOS-1: the measured 480-statement disjoint-pin role-takeover is WITHIN caps yet fails CLOSED (never the pre-fix COMPLETE grind)', () => {
  const text = buildDisjointPinTakeover(RESIDUAL_N);
  assert.equal(validate(text).ok, true, 'the disjoint-pin role-takeover policy is within every limit');
  assert.ok(text.length < 1024 * 1024, 'and under 1 MiB');
  // The product sits below the raw work ceiling: proof the residual could NOT be caught
  // by a 1-unit-per-triple charge (that is why round-1 missed it).
  assert.ok(RESIDUAL_N ** 3 < DEFAULT_WORK_LIMIT, 'product 160^3 is below DEFAULT_WORK_LIMIT - the within-budget residual');

  const a = analyze(text); // browser style: only the deterministic work budget, no clock

  assert.equal(a.ok, true, 'well-formed in-band result, never an uncaught throw');
  // Boundedness is asserted via the DETERMINISTIC op-count budget (load-independent),
  // not a wall-clock ceiling: the weighted product charge trips DEFAULT_WORK_LIMIT up
  // front, so the O(N^3) grind never runs.
  assert.equal(a.coverage.summary.analysisAborted, true, 'the O(N^3) satisfiability grind is aborted by the weighted product charge');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never the pre-fix COMPLETE verdict');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'), 'the aborted coverage carries the RESOURCE_BUDGET_EXCEEDED code');
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis (pre-fix wrongly returned 320)');
});

test('DOS-1: the whole N=100..200 legs-per-group attack family fails CLOSED (browser), never a COMPLETE verdict', () => {
  for (const N of [100, 160, 200]) {
    const text = buildDisjointPinTakeover(N);
    assert.equal(validate(text).ok, true, `N=${N} is within caps`);
    const a = analyze(text);
    assert.equal(a.coverage.summary.analysisAborted, true, `N=${N}: aborted`);
    assert.equal(a.coverage.summary.incomplete, true, `N=${N}: incomplete`);
    assert.equal(a.findings.length, 0, `N=${N}: no findings from an aborted run`);
  }
});

test('DOS-1: the satisfiability product PARTICIPATES in the work budget -> fails CLOSED at a tight ceiling too', () => {
  const text = buildDisjointPinTakeover(RESIDUAL_N);
  const a = analyze(text, { workLimit: 100000 });
  assert.equal(a.ok, true, 'well-formed in-band result');
  assert.equal(a.coverage.summary.analysisAborted, true, 'aborted under a tight ceiling');
  assert.equal(a.coverage.summary.incomplete, true, 'incomplete, never a clean COMPLETE');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'));
  assert.equal(a.findings.length, 0);
});

test('DOS-1: analyze() on the residual input is DETERMINISTIC (same trip point twice, op-count budget)', () => {
  const text = buildDisjointPinTakeover(RESIDUAL_N);
  const a1 = analyze(text);
  const a2 = analyze(text);
  assert.deepEqual(a1.findings, a2.findings, 'same input -> same (empty) findings twice');
  assert.equal(a1.coverage.summary.analysisAborted, a2.coverage.summary.analysisAborted, 'same abort verdict twice');
  assert.equal(a1.coverage.summary.incomplete, a2.coverage.summary.incomplete, 'same completeness verdict twice');
});

test('DOS-1: scan() bounds the residual under the DEFAULT budget -> exit 3, never clean', () => {
  const text = buildDisjointPinTakeover(RESIDUAL_N);
  const r = scan({ text, family: 'identity' }); // no budgetMs: only the deterministic work budget
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a disjoint-pin runaway must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the runaway fails closed to exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.equal(r.findings.length, 0);
});

test('DOS-1: scan() wall-clock budget actually BOUNDS the residual (no 2.7x overrun), never clean', () => {
  const text = buildDisjointPinTakeover(RESIDUAL_N);
  const budgetMs = 2000;
  const t0 = performance.now();
  const r = scan({ text, family: 'identity', budgetMs });
  const elapsed = performance.now() - t0;
  // Pre-fix scan() ran ~5481ms under a 2000ms budget because the pin-rebuild burned CPU
  // the deadline never sampled. Post-fix the weighted product charge trips up front, so
  // the run returns in single-digit ms - here we only need it well under the budget.
  assert.ok(elapsed < budgetMs, `scan() returned in ${elapsed.toFixed(1)}ms under a ${budgetMs}ms budget (pre-fix was ~5481ms)`);
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'never a clean exit 0 on a runaway');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'fails closed to exit 3');
});

test('DOS-1: NO over-correction - a SMALL disjoint-pin role-takeover stays COMPLETE and still surfaces its standalone risks', () => {
  // 3 legs per group (product 27): far below the cap. The pins are disjoint so the
  // compound ROLE-TAKEOVER is correctly suppressed (no single principal executes the
  // whole chain), but the standalone modify primitives are genuine risks and MUST
  // surface - never a false fail-closed, never a clean/empty pass.
  const text = buildDisjointPinTakeover(3);
  assert.equal(validate(text).ok, true);
  const a = analyze(text);
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small policy does NOT trip the budget (no blanket abort from the DoS fix)');
  assert.equal(a.coverage.summary.incomplete, false, 'it reaches a COMPLETE verdict');
  assert.ok(a.findings.some((f) => f.id === 'PUT-INLINE-POLICY'), 'the iam:PutRolePolicy risk still surfaces');
  assert.ok(a.findings.some((f) => f.id === 'TRUST-POLICY-MODIFY'), 'the iam:UpdateAssumeRolePolicy risk still surfaces');
});

test('DOS-1: NO over-correction - a SMALL SATISFIABLE role-takeover still fires the compound ROLE-TAKEOVER finding', () => {
  // Same-account pins on all three legs (jointly satisfiable) and a handful of legs:
  // the compound path is real and must fire - the weighted charge must not false-close
  // it and the memoization must not change the verdict.
  const statements = [];
  const pin = { StringEquals: { 'aws:PrincipalAccount': '123456789012' } };
  for (let i = 0; i < 5; i++) {
    statements.push({ Effect: 'Allow', Action: 'iam:PutRolePolicy', Resource: ANCHOR_ROLE, Condition: pin });
    statements.push({ Effect: 'Allow', Action: 'iam:UpdateAssumeRolePolicy', Resource: ANCHOR_ROLE, Condition: pin });
    statements.push({ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: ANCHOR_ROLE, Condition: pin });
  }
  const text = JSON.stringify({ Version: '2012-10-17', Statement: statements });
  assert.equal(validate(text).ok, true);
  const a = analyze(text);
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small satisfiable chain does NOT trip the budget');
  assert.equal(a.coverage.summary.incomplete, false, 'COMPLETE verdict');
  assert.ok(a.findings.some((f) => f.id === 'ROLE-TAKEOVER'), 'the satisfiable role-takeover chain still fires (no false negative)');
});
