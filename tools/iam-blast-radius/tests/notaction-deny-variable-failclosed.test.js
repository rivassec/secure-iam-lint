// A NotAction-Deny whose exclusion list contains an IAM policy variable (${...})
// cannot be proven from the policy text to block the granted action -- the variable
// resolves only at request time. denyActionApplies() therefore returns
// { applies: true, certain: false } for that branch (escalation-deny.js), and the
// deny must NOT be treated as a definitive block: the underlying capability finding
// stays surfaced and coverage is marked incomplete.
//
// Provenance: found by the security-mutation harness
// (audit/mutation/security-mutations.mjs, id `deny-unbounded-false-certainty`).
// Flipping `certain: !hasVar` -> `certain: true` made a variable-bearing
// NotAction-Deny read as a certain block: the DATA-EXFIL finding was silently
// DROPPED. The T8 boundary itself held -- scan() still exited FAIL_CLOSED via the
// independent incomplete-coverage backstop -- so this is a precision / defense-in
// -depth regression rather than a CLEAN fail-open, but the finding-level behavior
// was previously unpinned. This test pins it so weakening `certain` goes red.
//
// It also pins the no-over-correction control: a NotAction-Deny that CONCRETELY
// excludes some OTHER action genuinely denies the granted action (certain: true),
// so that case legitimately removes the finding and reads CLEAN. Asserting both
// sides proves the test tracks certainty, not merely "any deny keeps the finding".
//
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '123456789012';
const CTX = { subjectAccount: ACCT, partition: 'aws' };

// A broad secret/object read that fires a capability finding regardless of a
// resource fence, so the ONLY variable across cases is the Deny's certainty.
const GRANT = { Sid: 'g', Effect: 'Allow', Action: 'secretsmanager:GetSecretValue', Resource: '*' };

function policy(...denies) {
  return JSON.stringify({ Version: '2012-10-17', Statement: [GRANT, ...denies] });
}
function capabilityFinding(res) {
  return (res.findings || []).find((f) => /DATA-EXFIL|EXFIL|SECRET/i.test(f.id) || f.escalation);
}
function scanExit(text) {
  return scan({ text, family: 'identity', subjectAccount: ACCT, partition: 'aws' }).exitCode;
}

test('control (grant only): the broad secret read fires and coverage is complete', () => {
  const text = policy();
  const res = analyze(text, CTX);
  assert.equal(res.ok, true);
  assert.ok(capabilityFinding(res), 'capability finding must be present');
  assert.equal(res.coverage?.summary?.incomplete, false, 'no deny -> coverage complete');
  assert.equal(scanExit(text), EXIT.FINDINGS);
});

test('NotAction-Deny with a policy VARIABLE does not block: finding stays, coverage incomplete, never CLEAN', () => {
  const text = policy({ Sid: 'd', Effect: 'Deny', NotAction: ['${aws:username}'], Resource: '*' });
  const res = analyze(text, CTX);
  assert.equal(res.ok, true);

  // Finding-level: the capability is NOT silently dropped (this is what the mutation broke).
  assert.ok(
    capabilityFinding(res),
    'a variable-bearing NotAction-Deny is not a certain block; the capability finding must remain',
  );
  // Coverage-level: the unresolved variable is surfaced as incomplete coverage.
  assert.equal(res.coverage?.summary?.incomplete, true, 'unresolved deny variable -> incomplete coverage');
  // Boundary: the CLI must never read CLEAN for this policy.
  assert.notEqual(scanExit(text), EXIT.CLEAN, 'must never report CLEAN on a real capability');
});

test('no over-correction: NotAction-Deny concretely excluding ANOTHER action genuinely blocks -> CLEAN', () => {
  // "Deny NotAction s3:GetObject on *" denies everything except s3:GetObject, so it
  // certainly (concretely) denies secretsmanager:GetSecretValue. This is a real block,
  // certain: true, and correctly removes the finding -- the test must accept that.
  const text = policy({ Sid: 'd', Effect: 'Deny', NotAction: ['s3:GetObject'], Resource: '*' });
  const res = analyze(text, CTX);
  assert.equal(res.ok, true);
  assert.equal(capabilityFinding(res), undefined, 'a concrete NotAction-Deny genuinely blocks the read');
  assert.equal(res.coverage?.summary?.incomplete, false, 'concrete block -> coverage complete');
  assert.equal(scanExit(text), EXIT.CLEAN);
});
