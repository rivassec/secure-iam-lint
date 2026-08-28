// S3-dos-budget-all (iteration 7): close the LAST sibling of the uncharged-quadratic
// dedup class the story targets - escalation.js `specificAccountsInRoleArns`.
//
// ROOT CAUSE (F1, blocking). `specificAccountsInRoleArns(resources)` deduped the
// PassRole target role-ARN accounts with `accts.includes(m[1])` in a push loop - an
// O(R^2) Array-scan over the PassRole statement's Resource list (capped at
// MAX_RESOURCES=10000 but still attacker-sized) - and reached NO matcher, so it charged
// the deterministic work budget ZERO times. It is called once per service inside the
// `for (const svc of PASS_ROLE_SERVICES)` loop (8 services), so an unpinned PassRole
// grant feeding all 8 service-execution paths amplified it to 8 x O(R^2). Because the
// work budget is sampled ONLY inside chargeWork (and the Node wall-clock deadline with
// it), BOTH ceilings were blind: a within-caps, validate-passing identity policy of
// ~469KB drove analyze() to an ~8.7s grind yet returned a COMPLETE verdict (ok:true,
// findings=8, coverage.summary.incomplete=false, analysisAborted=false) - a direct
// violation of glob.js's invariant that analyze() can NEVER return COMPLETE after an
// unbounded run. Same pattern as the story's own fixes, one sibling function over.
//
// FIX. Replace the O(R^2) `accts.includes()` with Set membership (traversal O(R)) AND
// charge one work unit per resource inspected, so the traversal PARTICIPATES in both the
// deterministic work budget and the CLI/Action wall-clock deadline. A pathological
// PassRole target list now (a) resolves in LINEAR time (the quadratic grind is gone) and
// (b) fails CLOSED under a tight budget instead of returning a COMPLETE verdict on a
// runaway. The same iter-7 change hardens the three other members of this dedup class in
// escalation.js (anchorRoles harvest, the role-takeover `dedupe` helper, and
// survivingGrantedActions) - all covered by the existing escalation suite staying green.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';

// The 8 services an unpinned iam:PassRole can feed, each completing a critical
// PassRole->service execution path. Listing all 8 is what amplified the O(R^2) dedup
// 8x in the finding's repro.
const EXEC_ACTIONS = [
  'lambda:CreateFunction', 'ec2:RunInstances', 'ecs:RunTask', 'glue:CreateJob',
  'cloudformation:CreateStack', 'sagemaker:CreateTrainingJob',
  'codebuild:CreateProject', 'datapipeline:CreatePipeline',
];

// A within-caps identity policy: statement 1 grants iam:PassRole over R role ARNs each
// pinning a DISTINCT account (so the account-dedup Set/array reaches size R - the
// maximal-work case for the includes() the fix removed); statement 2 grants all 8
// service-execution actions on "*", completing every PassRole->service path. With
// `sharedAccount` every role ARN pins the SAME account (dedup set stays size 1) - the
// finding's attribution control that isolated the includes-dedup as the sole pre-fix
// cost; post-fix BOTH shapes are linear and charge R-proportional work.
function buildPassRoleTargets(R, sharedAccount = false) {
  const roles = [];
  for (let i = 0; i < R; i++) {
    const account = sharedAccount
      ? '123456789012'
      : String(10000000000000000000n + BigInt(i)).slice(0, 20);
    roles.push(`arn:aws:iam::${account}:role/r${i}`);
  }
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'Pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: roles },
      { Sid: 'Exec', Effect: 'Allow', Action: EXEC_ACTIONS, Resource: '*' },
    ],
  });
}

// R=9999 distinct-account role ARNs is ~469KB (< 1 MiB) and within every count cap,
// yet pre-fix drove analyze() to ~8.7s (quadratic) while returning COMPLETE. Post-fix
// it is linear (~0.1s). The wall-clock margin between good (~0.1s) and a quadratic
// regression (~8.7s) is enormous, so - exactly like this suite's glob-ReDoS "resolves
// in LINEAR time" proofs - an absolute ms ceiling is a RELIABLE separator here (unlike
// the narrow-margin analyze-heavy cases that assert via the op-count budget instead).
const DOS_R = 9999;
const LINEAR_BUDGET_MS = 2000; // ~18x over the good case, ~4x under a quadratic regression

// A per-run work ceiling above a SMALL PassRole policy's total charged work but far
// below the pathological input's, witnessing that the (now-charged) PassRole target
// traversal fails CLOSED on a runaway instead of returning COMPLETE.
const TIGHT_WORK_LIMIT = 100000;

test('F1: within-caps distinct-account PassRole target list resolves in LINEAR time (the O(R^2) account-dedup grind is gone), never a COMPLETE hang', () => {
  const text = buildPassRoleTargets(DOS_R);
  assert.equal(validate(text).ok, true, 'the pathological PassRole policy is within every limit');
  assert.ok(text.length < 1024 * 1024, 'and under 1 MiB');

  const t0 = performance.now();
  const a = analyze(text); // browser style: only the deterministic work budget, no clock
  const elapsed = performance.now() - t0;

  assert.equal(a.ok, true, 'well-formed in-band result, never an uncaught throw');
  assert.ok(
    elapsed < LINEAR_BUDGET_MS,
    `pathological PassRole target list analyzed in ${elapsed.toFixed(1)}ms (linear); a quadratic regression is ~8700ms; budget ${LINEAR_BUDGET_MS}ms`,
  );
  // The DoS is gone AND the real risk is not hidden: this IS a viable set of
  // PassRole->service paths, so a bounded COMPLETE verdict must still carry the findings
  // (no fail-open clean pass, no false negative).
  assert.equal(a.coverage.summary.analysisAborted, false, 'the linear traversal completes within the DEFAULT work budget');
  assert.equal(a.coverage.summary.incomplete, false, 'it reaches a COMPLETE verdict');
  assert.equal(a.findings.length, 8, 'all 8 PassRole->service paths surface (no risk hidden by the DoS fix)');
});

test('F1: the account-dedup is INDEPENDENT of the distinct-account count (Set membership, not O(R^2) includes)', () => {
  // Same size and same 8 findings whether the R role ARNs pin R DISTINCT accounts or
  // ONE shared account - the pre-fix 8767ms-vs-68.8ms gap (the finding's attribution
  // control) is closed: both are now linear.
  const distinct = buildPassRoleTargets(DOS_R);
  const shared = buildPassRoleTargets(DOS_R, true);

  const t0 = performance.now();
  const aDistinct = analyze(distinct);
  const tDistinct = performance.now() - t0;
  const t1 = performance.now();
  const aShared = analyze(shared);
  const tShared = performance.now() - t1;

  assert.ok(tDistinct < LINEAR_BUDGET_MS, `distinct-account: ${tDistinct.toFixed(1)}ms (linear)`);
  assert.ok(tShared < LINEAR_BUDGET_MS, `shared-account: ${tShared.toFixed(1)}ms (linear)`);
  assert.equal(aDistinct.coverage.summary.incomplete, false);
  assert.equal(aShared.coverage.summary.incomplete, false);
  assert.equal(aDistinct.findings.length, 8);
  assert.equal(aShared.findings.length, 8);
});

test('F1: the PassRole target traversal PARTICIPATES in the work budget -> fails CLOSED at a tight ceiling, never a COMPLETE runaway', () => {
  const text = buildPassRoleTargets(DOS_R);
  const a = analyze(text, { workLimit: TIGHT_WORK_LIMIT });
  assert.equal(a.ok, true, 'well-formed in-band result');
  assert.equal(a.coverage.summary.analysisAborted, true, 'the now-charged PassRole target traversal trips the tight budget (proof it participates)');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'), 'the aborted coverage carries the RESOURCE_BUDGET_EXCEEDED code');
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('F1: NO over-correction: a SMALL distinct-account PassRole policy stays COMPLETE at the same tight ceiling AND fires all 8 paths', () => {
  const text = buildPassRoleTargets(3);
  assert.equal(validate(text).ok, true);
  const a = analyze(text, { workLimit: TIGHT_WORK_LIMIT });
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small PassRole policy does NOT trip the tight budget (proportional charge, no blanket abort)');
  assert.equal(a.coverage.summary.incomplete, false, 'it reaches a COMPLETE verdict');
  assert.equal(a.findings.length, 8, 'the legitimate PassRole->service paths still surface (no false negative from the DoS fix)');
});

test('F1: analyze() on the pathological PassRole input is DETERMINISTIC (op-count budget, no clock)', () => {
  const text = buildPassRoleTargets(DOS_R);
  const a1 = analyze(text);
  const a2 = analyze(text);
  assert.deepEqual(a1.findings, a2.findings, 'same input -> same findings twice');
  assert.equal(a1.coverage.summary.incomplete, a2.coverage.summary.incomplete, 'same completeness verdict twice');
});

test('F1: scan() wall-clock budget actually BOUNDS runtime on the PassRole target list (no multi-x overrun), never clean', () => {
  const text = buildPassRoleTargets(DOS_R);
  const budgetMs = LINEAR_BUDGET_MS;
  const t0 = performance.now();
  const r = scan({ text, family: 'identity', budgetMs });
  const elapsed = performance.now() - t0;
  // Pre-fix scan() ran 5481ms under a 2000ms budget (2.7x overrun) because the O(R^2)
  // account-dedup burned CPU that the wall-clock deadline (sampled only inside
  // chargeWork) never got to see. Post-fix the traversal is linear and charged, so the
  // run finishes well within budget.
  assert.ok(elapsed < budgetMs * 2, `scan() returned in ${elapsed.toFixed(1)}ms under a ${budgetMs}ms budget (bounded; pre-fix was 2.7x)`);
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a viable multi-service PassRole path must NEVER report a clean exit 0');
  // Within budget the analysis completes to a FINDINGS verdict; CLI and browser AGREE.
  assert.equal(r.exitCode, EXIT.FINDINGS, 'the within-caps policy analyzes COMPLETE to exit 1 (findings)');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.findings.length, 8);
});

test('F1: scan() fails CLOSED on the PassRole target list under a zero wall-clock budget -> exit 3, never clean', () => {
  const text = buildPassRoleTargets(DOS_R);
  // budgetMs:0 -> deadline at "now" -> chargeWork's `>=` check aborts DETERMINISTICALLY
  // on the first checkpoint the now-charged traversal crosses. Pre-fix the traversal
  // barely charged, so a runaway could slip past a zero budget and return COMPLETE.
  const r = scan({ text, family: 'identity', budgetMs: 0 });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a PassRole runaway must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the wall-clock deadline fires on the PassRole path -> exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.equal(r.findings.length, 0);
});
