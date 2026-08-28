// S2-passrole-allstmts axis 3 (iteration 5): the PassRole viability-demotion path
// scanned every Deny RESOURCE per PassRole-Allow-statement WITHOUT charging the
// deterministic work budget, so a within-caps policy ran an unbudgeted O(nPassStmt x
// nDenyResource x nService) loop yet returned a COMPLETE verdict - a fail-OPEN DoS
// (threat-model T5/T8). On the browser analyze() path (no wall-clock watchdog) the
// work counter is the ONLY ceiling, and this loop never advanced it.
//
// Two distinct uncharged/redundant scans caused it, both closed here:
//   (1) denyRemovesAllSubjectRoles(): recomputed 8 x nPassStmt times (once per service x
//       PassRole statement inside the ranking loop), each a full scan of every Deny
//       resource, while its verdict is INVARIANT across those iterations. Now computed
//       ONCE per detectPassRolePaths call, charged, and threaded in.
//   (2) denyResourceCoverage(): its `resources.some(isStarResource)` scan inspects every
//       Deny resource BEFORE the allowRes.length===0 -> 'partial' early return that a
//       NotResource-shaped Allow hits (bypassing the already-charged denyResourcesCover
//       scan). That per-resource inspection is now charged.
//
// The fix must (a) make the loops PARTICIPATE in the work budget (a forced small budget
// aborts mid-analysis -> fail closed, never a COMPLETE verdict from an unbudgeted loop),
// (b) keep the max-size within-caps repro BOUNDED and SEMANTICALLY CORRECT (the direct
// same-account PassRole->EC2 path is VIABLE, so it stays CRITICAL / scan exit 1 - the
// memoize+charge changes only the COST, never the verdict), and (c) NOT over-correct a
// small legitimate NotResource-Deny policy into a false fail-closed.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

// "Completes bounded" is asserted via the DETERMINISTIC op-count work budget
// (coverage.summary.analysisAborted === false: the charged analysis stayed under the fixed
// DEFAULT_WORK_LIMIT), NOT an absolute wall-clock ceiling. A genuinely-heavy within-caps
// policy of this shape runs ~1-2s single-threaded, so a fixed ms ceiling flakes under the
// runner's default file-level parallelism (CPU contention) and red-flags good code; the
// op-count budget is load-independent and already proven reliable by the forced-tight-
// budget fail-closed test below.

const CTX = { subjectAccount: '123456789012', partition: 'aws' };

// The axis-3 DoS shape: `nPass` PassRole Allow statements shaped by NotResource
// (allowRes.length===0 -> denyResourceCoverage returns 'partial' before the charged
// denyResourcesCover scan), a viable same-account exec (ec2:RunInstances Resource:*),
// and `nDeny` concrete same-account DECOY Denies whose role path is NOT wildcard-
// equivalent (decoy-<d>-<k>). Those decoy Denies do NOT remove all subject roles, so the
// direct PassRole->EC2 path is VIABLE and must stay CRITICAL. Reordering / scaling the
// Deny resource list only changes COST, never the verdict.
function buildAxis3Policy(nPass, nDeny, resPerDeny) {
  const st = [];
  for (let i = 0; i < nPass; i++) {
    st.push({ Sid: `Pass${i}`, Effect: 'Allow', Action: 'iam:PassRole', NotResource: `arn:aws:iam::999888777666:role/nobody-${i}` });
  }
  st.push({ Sid: 'Exec', Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' });
  for (let d = 0; d < nDeny; d++) {
    const res = [];
    for (let k = 0; k < resPerDeny; k++) res.push(`arn:aws:iam::123456789012:role/decoy-${d}-${k}`);
    st.push({ Sid: `Deny${d}`, Effect: 'Deny', Action: 'iam:PassRole', Resource: res });
  }
  return JSON.stringify({ Version: '2012-10-17', Statement: st });
}

function hasViableCriticalPassRole(findings) {
  return findings.some(
    (f) => f.severity === 'critical'
      && f.escalation && f.escalation.service
      && Array.isArray(f.actions) && f.actions.some((a) => /iam:PassRole/i.test(a)),
  );
}

// --- committed canonical fixture: bounded + SEMANTICALLY correct (stays critical) ---

test('axis-3 canonical fixture is within caps yet analyzes BOUNDED to a CRITICAL verdict (never an unbudgeted COMPLETE clean pass)', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'passrole-notresource-deny-scan-dos.json'), 'utf8'));
  const text = JSON.stringify(fx.policy);
  assert.equal(validate(text).ok, true, 'the fixture is within every cap (a per-string/statement cap is no defense against the per-passStmt scan)');

  const a = analyze(text, CTX); // browser style: no wall-clock armed anywhere

  assert.equal(a.ok, true, 'well-formed result');
  // Boundedness is the DETERMINISTIC op-count budget outcome below (analysisAborted ===
  // false: the charged analysis stayed under the fixed DEFAULT_WORK_LIMIT), not a
  // wall-clock ceiling that flakes under the parallel full-suite run's CPU contention.
  assert.equal(a.coverage.summary.analysisAborted, false, 'a within-caps policy analyzes to completion within the fixed DEFAULT work budget (not aborted)');
  assert.equal(a.coverage.summary.incomplete, false, 'and reaches a COMPLETE verdict');
  assert.ok(hasViableCriticalPassRole(a.findings), 'the direct same-account PassRole->EC2 path is VIABLE and stays CRITICAL (memoize+charge changes cost, not verdict)');
});

test('axis-3 canonical fixture through scan() is exit 1 / FINDINGS (viable critical path), never a clean exit 0', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'passrole-notresource-deny-scan-dos.json'), 'utf8'));
  const text = JSON.stringify(fx.policy);
  const r = scan({ text, family: 'identity', subjectAccount: CTX.subjectAccount, partition: CTX.partition });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a viable critical PassRole path must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FINDINGS, 'the viable critical path is exit 1 (findings)');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'the within-caps policy analyzes COMPLETE');
});

// --- the loops now PARTICIPATE in the deterministic work budget (the DoS fix) -------

test('the per-passStmt Deny-resource scans are CHARGED: a forced small work budget aborts -> fail CLOSED (never a COMPLETE verdict from an unbudgeted loop)', () => {
  // The max-size within-caps repro from the finding: 990 NotResource PassRole Allows +
  // viable ec2:RunInstances + 3 Deny iam:PassRole x 3000 same-account non-wildcard-
  // equivalent role ARNs. Before the fix this ran ~1.37s of UNBUDGETED work and returned
  // a COMPLETE verdict; no work limit could stop the uncharged loop. Now the loop advances
  // the work counter, so a small forced budget aborts mid-scan.
  const text = buildAxis3Policy(990, 3, 3000);
  assert.equal(validate(text).ok, true, 'the max-size repro is within every cap');

  const a = analyze(text, { ...CTX, workLimit: 1e6 });
  assert.equal(a.ok, true, 'well-formed in-band result (never an uncaught throw)');
  assert.equal(a.coverage.summary.analysisAborted, true, 'a small forced work budget ABORTS the now-charged loop (it participates in the budget)');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(
    a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'),
    'the aborted coverage carries the RESOURCE_BUDGET_EXCEEDED code',
  );
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('the max-size within-caps repro analyzes BOUNDED and stays CRITICAL under the DEFAULT budget (charged, not unbudgeted; correct verdict preserved)', () => {
  // Under the default work budget the max within-caps shape completes (the resource caps
  // bound its charged work below the ceiling) with the CORRECT critical verdict - and the
  // work is now CHARGED, so it is no longer an unbudgeted loop (proven fail-closed-capable
  // by the forced-budget test above). Bounded wall time either way.
  const text = buildAxis3Policy(990, 3, 3000);
  const a = analyze(text, CTX);
  assert.equal(a.ok, true, 'well-formed result');
  // Boundedness asserted via the DETERMINISTIC op-count work budget, NOT a wall-clock
  // ceiling. The per-passStmt Deny-resource scans ARE charged (the forced-tight-budget
  // test above trips them), so a run that does NOT hit the work-budget abort proves the
  // charged scan work stayed under the fixed DEFAULT_WORK_LIMIT - the unbudgeted loop this
  // guards against would run free past it. This bound is load-independent; an absolute ms
  // ceiling flaked here (up to ~4.96s) purely from CPU contention under the runner's
  // default file parallelism, not any logic regression.
  assert.equal(a.coverage.summary.analysisAborted, false, 'the charged max-size repro completes within the fixed DEFAULT work budget (bounded op-count, no clock)');
  // Whichever way the default budget lands, the verdict is NEVER a clean COMPLETE pass on
  // this genuinely viable path: it is either a bounded COMPLETE-with-critical or a
  // fail-closed incomplete - never ok+critical-absent+complete.
  if (!a.coverage.summary.incomplete) {
    assert.ok(hasViableCriticalPassRole(a.findings), 'a COMPLETE verdict on this shape MUST carry the viable critical path (no fail-open demotion)');
  } else {
    assert.equal(a.findings.length, 0, 'an incomplete verdict asserts no findings (fail closed)');
  }
});

test('BROWSER analyze() and CLI scan() agree on the max-size repro (parity: analyze() is never MORE permissive than scan())', () => {
  const text = buildAxis3Policy(990, 3, 3000);
  const a = analyze(text, CTX);
  const r = scan({ text, family: 'identity', subjectAccount: CTX.subjectAccount, partition: CTX.partition });
  // analyze() COMPLETE-with-critical <-> scan() exit 1; analyze() incomplete <-> scan() exit 3.
  // Neither surface may report a clean/no-risk verdict on this viable path.
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'scan() must never be clean on the viable path');
  if (!a.coverage.summary.incomplete) {
    assert.ok(hasViableCriticalPassRole(a.findings), 'analyze() COMPLETE keeps the critical path');
    assert.equal(r.exitCode, EXIT.FINDINGS, 'scan() COMPLETE is exit 1 (findings)');
  } else {
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'analyze() incomplete <-> scan() exit 3 (fail closed)');
  }
});

// --- determinism (architecture invariant 8: op-count budget, no clock in the verdict) ---

test('axis-3 analysis is deterministic: same input -> deep-equal findings twice (no clock in the decision)', () => {
  const text = buildAxis3Policy(200, 3, 800);
  const a1 = analyze(text, CTX);
  const a2 = analyze(text, CTX);
  assert.deepEqual(a1.findings, a2.findings, 'the charged/memoized path stays deterministic');
  assert.equal(a1.coverage.summary.incomplete, a2.coverage.summary.incomplete, 'the trip/complete decision is a pure function of the input');
});

// --- NO over-correction: a small legitimate NotResource-Deny policy still COMPLETES ---

test('NO over-correction: a SMALL NotResource-Deny policy still analyzes to a COMPLETE critical verdict (the charge is proportional, not a blanket abort)', () => {
  // The charge is proportional to real per-resource work, not "any NotResource-Deny
  // aborts". A tiny policy does little work and MUST complete normally with the viable
  // critical path, or the fix would over-correct legitimate policies into fail-closed.
  const text = buildAxis3Policy(4, 2, 5);
  assert.equal(validate(text).ok, true, 'the small policy is within caps');
  const a = analyze(text, CTX);
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small NotResource-Deny policy does NOT trip the budget');
  assert.equal(a.coverage.summary.incomplete, false, 'it reaches a COMPLETE verdict');
  assert.ok(hasViableCriticalPassRole(a.findings), 'and correctly reports the viable critical PassRole path');
  const r = scan({ text, family: 'identity', subjectAccount: CTX.subjectAccount, partition: CTX.partition });
  assert.equal(r.exitCode, EXIT.FINDINGS, 'scan() reports exit 1 (findings), not fail-closed, on a small legitimate policy');
});

// --- the memoize+charge did not alter the axis-3 SEMANTIC verdict (decoy Deny) --------

test('a WILDCARD-EQUIVALENT Deny still correctly removes all subject roles (semantic verdict unchanged by the DoS fix)', () => {
  // Positive control for the charge/memoize refactor: a Deny whose role path IS
  // wildcard-equivalent (role/*) genuinely removes every subject role, so the direct
  // same-account path is NOT viable via that grant. The refactor must not have broken
  // this true-negative (deny-all) reasoning. Here the ONLY passable grant is same-account
  // and fully deny-all'd, so no viable same-account critical PassRole path survives.
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'Pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::123456789012:role/app-*' },
      { Sid: 'Exec', Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
      { Sid: 'DenyAll', Effect: 'Deny', Action: 'iam:PassRole', Resource: 'arn:aws:iam::123456789012:role/*' },
    ],
  });
  const a = analyze(text, CTX);
  assert.equal(a.ok, true);
  assert.equal(a.coverage.summary.incomplete, false, 'a small policy completes');
  assert.equal(
    hasViableCriticalPassRole(a.findings), false,
    'a wildcard-equivalent same-account Deny removes all subject roles -> no viable same-account critical PassRole path',
  );
});
