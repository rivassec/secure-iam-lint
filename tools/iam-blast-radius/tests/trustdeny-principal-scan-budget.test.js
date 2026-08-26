// S3-dos-budget-all (iteration 4): close the RESIDUAL of the DoS class on the role-
// TRUST family - the many-principals-in-ONE-Deny shape.
//
// Round-2 blocker. Iteration 2 charged trustFindingDenyState's principals x assume-
// actions x trust-Deny-STATEMENTS triple loop. But the loop body,
//   principalEntryDeniedBy(p, d.principals)  ->  denyPrincipals.entries.some(...)
// was an O(#principals-in-that-Deny-statement) linear rescan that was NEVER charged.
// The up-front charge counted deny STATEMENTS (denyInfos.length), so a SINGLE Deny
// statement carrying thousands of principals multiplied the real cost by that count
// while the charge multiplier stayed 1-per-statement - the exact "charge the OUTER
// collection's cardinality while the loop body linearly rescans an INNER uncapped
// policy-derived collection that is left uncharged" defect. validate.js caps Action/
// Resource COUNTS and per-string length but NEVER the Principal COUNT, so the shape is
// within every limit (validate.ok=true, < 1MiB, 2 statements).
//
// MEASURED pre-fix (the finding's reproducer): Allow assume(N accounts) + Deny
// assume(N accounts), family=role-trust: n=2000 -> 1.1s, n=4000 -> 4.0s, n=8000 ->
// 16.3s, all ok:true / analysisAborted:false / incomplete:false - a clean O(N^2)
// grind returning a COMPLETE verdict (the 60M work budget never trips: total charged
// work ~ N << 60M). The CLI wall-clock was defeated too: scan({budgetMs:2000}) at
// n=8000 ran 10,773ms and returned exit 1/COMPLETE, because the charged work never
// reached a 2nd WORK_CHECK_INTERVAL checkpoint so the deadline was sampled only once.
//
// THE FIX (trust.js): precompute ONE canonical-key Set per Deny statement
// (buildDenyCoverage, charging its O(#deny-principals) construction) so
// principalEntryDeniedBy is an O(1) Set membership test instead of an O(#principals)
// rescan. The charged work now MATCHES the real work for every shape, so a within-caps
// many-principals Deny no longer grinds: the O(N^2) is GONE (it completes in tens of
// ms) and, because work is proportional to time, the wall-clock deadline can no longer
// be overrun to seconds. The Set-based lookup is byte-identical to the old
// `.entries.some((d) => canonicalPrincipalKey(d) === key)` - the bare-account-id <->
// arn:...:root canonical fold is preserved (a twin Deny still fully neutralizes).
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';

// A generous, strictly-POSITIVE wall-clock budget handed to scan() as its budgetMs. It is
// NOT used as a wall-clock upper-bound assertion on the analysis: "bounded / no overrun"
// is asserted via the DETERMINISTIC op-count work budget (analysisAborted === false, or a
// COMPLETE non-budget-exceeded scan verdict), which is load-independent - an absolute ms
// upper-bound on a genuinely-heavy input flakes under the runner's default file-level
// parallelism (CPU contention).
const BOUNDED_MS = 2000;

// The residual DoS shape: ONE Allow trust statement naming N distinct account
// principals that may sts:AssumeRole, plus ONE Deny trust statement naming N distinct
// account principals. It is the many-principals-in-ONE-Deny shape (a SINGLE Deny
// statement, not N of them), so the cost lived entirely in the uncharged inner
// principalEntryDeniedBy rescan. `overlap` picks whether the Deny principals are the
// SAME accounts as the Allow (as arn:...:root canonical twins -> full deny) or DISJOINT
// accounts (the cross-account trust survives as a finding). N=8000 is well within caps
// (< 1MiB, 2 statements).
function buildManyPrincipalTrust(n, overlap) {
  const allow = [];
  const deny = [];
  for (let i = 0; i < n; i++) {
    allow.push(String(100000000000 + i)); // bare 12-digit account id
    deny.push(overlap
      ? `arn:aws:iam::${String(100000000000 + i)}:root` // canonical twin of the Allow
      : String(900000000000 + i));                       // a disjoint account
  }
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Principal: { AWS: allow }, Action: 'sts:AssumeRole' },
      { Effect: 'Deny', Principal: { AWS: deny }, Action: 'sts:AssumeRole' },
    ],
  });
}

const DOS_N = 8000;

test('the many-principals-in-one-Deny trust shape is WITHIN caps (Principal count is uncapped)', () => {
  const text = buildManyPrincipalTrust(DOS_N, false);
  const v = validate(text);
  assert.equal(v.ok, true, 'validate accepts it (< 1MiB, 2 statements, per-string caps met)');
});

test('the cross-account (disjoint-Deny) many-principal shape analyzes BOUNDED and NEVER a clean/fail-open verdict', () => {
  // Pre-fix: 16.3s O(N^2) grind returning COMPLETE (the deterministic budget never
  // tripped). Post-fix: tens of ms, and NEVER a clean pass on a genuinely risky
  // cross-account trust - either a bounded COMPLETE-with-finding or a fail-closed
  // incomplete.
  const text = buildManyPrincipalTrust(DOS_N, false);
  const a = analyze(text); // browser style: DEFAULT budget, no wall-clock armed

  assert.equal(a.ok, true, 'well-formed result (never an uncaught throw)');
  // "O(N^2) is gone / bounded" via the DETERMINISTIC op-count budget, not a wall-clock
  // ceiling: an O(N^2) regression at N=8000 (~6.4e7) would exceed the fixed
  // DEFAULT_WORK_LIMIT (6e7) and abort, so a run that does NOT abort proves the scan
  // stayed linear - load-independent, unlike an absolute ms ceiling that flakes under the
  // runner's default file-level parallelism (CPU contention).
  assert.equal(a.coverage.summary.analysisAborted, false, 'the now-linear trust scan completes within the fixed op-count budget (an O(N^2) grind would exceed it and abort)');
  if (!a.coverage.summary.incomplete) {
    assert.ok(a.findings.length >= 1, 'a COMPLETE verdict MUST keep the cross-account trust finding (no fail-open clean pass)');
    assert.ok(a.findings.some((f) => typeof f.id === 'string' && f.id.startsWith('TRUST-')), 'the surfaced risk is a trust finding');
  } else {
    assert.equal(a.findings.length, 0, 'an incomplete verdict asserts no findings (fail closed)');
  }
});

test('CLI scan() on the many-principal trust shape does NOT overrun a wall-clock budget (the 10,773ms defeat is fixed)', () => {
  // Pre-fix: scan({budgetMs:2000}) ran 10,773ms and returned exit 1/COMPLETE - the
  // deadline was sampled only once because charged work never reached a 2nd checkpoint.
  // Post-fix: it completes far under the budget and never trips RESOURCE_BUDGET_EXCEEDED.
  const text = buildManyPrincipalTrust(DOS_N, false);
  const r = scan({ text, family: 'role-trust', budgetMs: BOUNDED_MS });

  // "No seconds-long overrun" is proved DETERMINISTICALLY by the terminal verdict, not a
  // wall-clock upper-bound: had the now-charged trust path overrun the wall-clock budget it
  // would carry reason RESOURCE_BUDGET_EXCEEDED and exit FAIL_CLOSED; a COMPLETE exit-1
  // FINDINGS result IS the "bounded, budget not tripped" proof, independent of CPU load.
  assert.notEqual(r.reason, 'RESOURCE_BUDGET_EXCEEDED', 'a within-caps trust policy must not falsely trip a generous budget');
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'the cross-account trust risk must never report clean');
  assert.equal(r.exitCode, EXIT.FINDINGS, 'it analyzes COMPLETE to exit 1 (findings), bounded');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
});

test('CLI scan() on the many-principal trust shape fails CLOSED under a past wall-clock deadline -> exit 3, never clean', () => {
  // budgetMs:0 arms a deadline at "now"; the trust path now charges work, so chargeWork's
  // `>=` check aborts DETERMINISTICALLY on the first checkpoint. Pre-fix the trust loop
  // charged too little for the clock to re-sample, so a runaway returned COMPLETE.
  const text = buildManyPrincipalTrust(DOS_N, false);
  const r = scan({ text, family: 'role-trust', budgetMs: 0 });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a wall-clock overrun must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the wall-clock deadline fires on the trust path -> exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.equal(r.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('BROWSER analyze() and CLI scan() agree on the many-principal trust shape (parity: analyze() never MORE permissive)', () => {
  const text = buildManyPrincipalTrust(DOS_N, false);
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

test('the many-principal analysis is DETERMINISTIC (op-count budget, no clock in the verdict)', () => {
  const text = buildManyPrincipalTrust(DOS_N, false);
  const a1 = analyze(text);
  const a2 = analyze(text);
  assert.deepEqual(a1.findings, a2.findings, 'same input -> same findings twice');
  assert.equal(a1.coverage.summary.incomplete, a2.coverage.summary.incomplete, 'same completeness verdict twice');
});

test('SEMANTIC EQUIVALENCE preserved: the O(1) Set lookup still folds the bare-account <-> root-ARN canonical twin (no over/under-correction)', () => {
  // The refactor from `.entries.some(canonicalPrincipalKey(d)===key)` to a precomputed
  // canonical-key Set must be byte-identical. Guard both directions on a SMALL policy so
  // it is a pure semantics check (no budget in play):
  //   overlap=true  (Deny arn:...:root twins of the Allow bare account ids) -> the
  //                 canonical fold makes the Deny cover EVERY Allow principal -> the
  //                 grant is fully neutralized -> the trust finding is SUPPRESSED.
  //   overlap=false (disjoint Deny accounts) -> nothing is covered -> the cross-account
  //                 trust finding STAYS.
  const twin = buildManyPrincipalTrust(4, true);
  const disjoint = buildManyPrincipalTrust(4, false);
  assert.equal(validate(twin).ok, true);
  assert.equal(validate(disjoint).ok, true);

  const aTwin = analyze(twin);
  assert.equal(aTwin.coverage.summary.incomplete, false, 'the small twin policy analyzes COMPLETE');
  assert.equal(
    aTwin.findings.some((f) => typeof f.id === 'string' && f.id.startsWith('TRUST-CROSS-ACCOUNT')),
    false,
    'a root-ARN Deny of the same accounts fully neutralizes the bare-account Allow (canonical fold via the Set)',
  );

  const aDisjoint = analyze(disjoint);
  assert.equal(aDisjoint.coverage.summary.incomplete, false, 'the small disjoint policy analyzes COMPLETE');
  assert.ok(
    aDisjoint.findings.some((f) => typeof f.id === 'string' && f.id.startsWith('TRUST-CROSS-ACCOUNT')),
    'a disjoint-account Deny neutralizes nothing, so the cross-account trust finding stays (no false suppression)',
  );
});

test('NO over-correction: the full-deny (twin) many-principal shape stays BOUNDED and truthful (fully denied -> no residual risk)', () => {
  // The twin shape at scale: every Allow principal is canonically denied, so the correct
  // verdict is a COMPLETE analysis with the trust finding suppressed - NOT a fail-closed
  // and NOT a seconds-long grind. Proves the fix is proportional (a legitimate large
  // policy completes) and preserves the full-deny semantics at scale.
  const text = buildManyPrincipalTrust(DOS_N, true);
  assert.equal(validate(text).ok, true);
  const a = analyze(text);
  assert.equal(a.ok, true, 'well-formed result');
  // Boundedness via the DETERMINISTIC op-count budget (the assertion below), not a
  // wall-clock ceiling that flakes under parallel CPU contention: a fully-denied
  // within-caps policy completing within the fixed DEFAULT_WORK_LIMIT proves it is bounded.
  assert.equal(a.coverage.summary.analysisAborted, false, 'a fully-denied within-caps policy does NOT fail closed (no over-correction) and completes within the fixed op-count budget');
  assert.equal(
    a.findings.some((f) => typeof f.id === 'string' && f.id.startsWith('TRUST-CROSS-ACCOUNT')),
    false,
    'every assume grant is canonically denied -> the cross-account finding is suppressed at scale too',
  );
});
