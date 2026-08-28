// S2-passrole-allstmts axis 3 — a narrow decoy Deny must NOT be read as "removes
// ALL subject roles".
//
// Regression for a DEFAULT-threshold clean fail-open (threat-model T8).
// denyRemovesAllSubjectRoles() used a two-fixed-probe heuristic: it concluded a Deny
// removed every subject-account role when the Deny's resource glob matched two
// internal probe strings ('...:role/__probe_alpha__', '...:role/__probe_beta_9x__').
// A NARROW decoy Deny whose role-path merely collides with those probes -
// arn:aws:iam::<acct>:role/_*  (denies only underscore-prefixed roles),
// role/__*, role/*probe* - satisfied both probes, so the function falsely returned
// true. That set subjectDenied=true, flipped a genuinely viable same-account
// iam:PassRole(role/deploy-*) + lambda:CreateFunction path to not-viable, and
// CONFIDENTLY demoted it critical->medium (PASSROLE_CROSS_ACCOUNT_INCOMPATIBLE),
// slipping under the exit gate to exit 0 CLEAN on a real critical escalation.
//
// The fix: a Deny removes all subject roles ONLY when its role-path component is
// WILDCARD-EQUIVALENT to "*" (composed solely of "*", imposing no literal or
// positional constraint), with a partition+account that reach the subject; or a bare
// "*". Any leading-literal / anchored role-path glob is strictly narrower and must
// NOT demote, so the viable same-account path stays critical / scan exit 1.
//
// This test drives the real engine (analyze()) AND the CLI fail-closed adapter
// (scan()) for each decoy spelling and asserts critical + exit 1, and asserts a
// genuine deny-all (role/*) still demotes (no false positive / no over-correction).
//
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '123456789012';
const CTX = { subjectAccount: ACCT, partition: 'aws' };

// Viable same-account PassRole -> Lambda code-execution path. Resources are SCOPED so
// no co-gating WILDCARD-RESOURCE finding masks the demotion - the demoted medium would
// otherwise slip under the default 'high' gate unaided, which is exactly the fail-open.
function policyWithDeny(denyResource) {
  const stmts = [
    { Sid: 'pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/deploy-*` },
    { Sid: 'exec', Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: `arn:aws:lambda:us-east-1:${ACCT}:function:app-*` },
  ];
  if (denyResource !== null) {
    stmts.push({ Sid: 'decoy', Effect: 'Deny', Action: 'iam:PassRole', Resource: denyResource });
  }
  return JSON.stringify({ Version: '2012-10-17', Statement: stmts });
}

function passFinding(res) {
  return (res.findings || []).find((f) => f.escalation || /PASSROLE/.test(f.id));
}

// Each narrow decoy Deny only denies a SUBSET of subject roles and does NOT deny
// role/deploy-*, so the same-account path remains genuinely viable and CRITICAL.
const NARROW_DECOYS = [
  { label: 'role/_* (underscore-prefixed only)', resource: `arn:aws:iam::${ACCT}:role/_*` },
  { label: 'role/__* (double-underscore-prefixed only)', resource: `arn:aws:iam::${ACCT}:role/__*` },
  { label: 'role/*probe* (contains "probe" only)', resource: `arn:aws:iam::${ACCT}:role/*probe*` },
  { label: 'role/deploy-x* (a sibling prefix, not deploy-*)', resource: `arn:aws:iam::${ACCT}:role/deploy-x*` },
  { label: 'role/service-role/* (a path-prefixed subset)', resource: `arn:aws:iam::${ACCT}:role/service-role/*` },
];

// Control: NO decoy Deny -> the path is unambiguously critical / exit 1. This anchors
// that the decoys below are the ONLY variable, so a demotion is provably wrong.
test('control (no decoy Deny): viable same-account PassRole is critical + exit 1', () => {
  const text = policyWithDeny(null);
  const res = analyze(text, CTX);
  assert.equal(res.ok, true);
  const f = passFinding(res);
  assert.ok(f, 'PASSROLE finding must be present');
  assert.equal(f.severity, 'critical');
  const r = scan({ text, family: 'identity', subjectAccount: ACCT, partition: 'aws' });
  assert.equal(r.exitCode, EXIT.FINDINGS);
});

for (const decoy of NARROW_DECOYS) {
  test(`narrow decoy Deny [${decoy.label}] does NOT demote: stays critical + exit 1`, () => {
    const text = policyWithDeny(decoy.resource);
    const res = analyze(text, CTX);
    assert.equal(res.ok, true, 'analyze() ok');
    const f = passFinding(res);
    assert.ok(f, `PASSROLE finding must be present for decoy [${decoy.label}]`);
    assert.equal(f.severity, 'critical',
      `a narrow decoy Deny must NOT demote the viable same-account path [${decoy.label}]`);
    assert.ok(
      !((f.escalation || {}).warningCodes || []).includes('PASSROLE_CROSS_ACCOUNT_INCOMPATIBLE'),
      `must NOT carry the cross-account demotion warning [${decoy.label}]`,
    );

    const r = scan({ text, family: 'identity', subjectAccount: ACCT, partition: 'aws' });
    assert.equal(r.exitCode, EXIT.FINDINGS,
      `a viable same-account PassRole must never report CLEAN [${decoy.label}]`);
    assert.notEqual(r.exitCode, EXIT.CLEAN);
  });
}

// No over-correction: a GENUINE deny-all (role-path wildcard-equivalent to "*") on the
// subject account+partition still removes every subject role and legitimately demotes
// the path. These MUST NOT become false positives.
const GENUINE_DENY_ALL = [
  { label: 'role/* (all roles in the subject account)', resource: `arn:aws:iam::${ACCT}:role/*` },
  { label: 'role/** (redundant wildcards, still all roles)', resource: `arn:aws:iam::${ACCT}:role/**` },
  { label: 'account-wildcard role/* (reaches subject account)', resource: 'arn:aws:iam::*:role/*' },
  { label: 'bare "*" (denies every PassRole)', resource: '*' },
];

for (const dz of GENUINE_DENY_ALL) {
  test(`genuine deny-all [${dz.label}] still demotes below the critical gate (no false positive)`, () => {
    const text = policyWithDeny(dz.resource);
    const res = analyze(text, CTX);
    assert.equal(res.ok, true);
    const f = passFinding(res);
    // The path is genuinely not viable: either no critical finding survives, or it is
    // demoted below critical. Assert it is NOT reported as a critical viable path.
    if (f) {
      assert.notEqual(f.severity, 'critical',
        `a genuine deny-all must remove viability, not report critical [${dz.label}]`);
    }
  });
}

// A DIFFERENT concrete account's role/* does not reach the subject and so must NOT
// demote the subject path (fail-closed on account reach, not spuriously deny-all).
test('deny-all on a FOREIGN account does not remove subject roles: stays critical + exit 1', () => {
  const text = policyWithDeny('arn:aws:iam::999999999999:role/*');
  const res = analyze(text, CTX);
  const f = passFinding(res);
  assert.ok(f);
  assert.equal(f.severity, 'critical');
  const r = scan({ text, family: 'identity', subjectAccount: ACCT, partition: 'aws' });
  assert.equal(r.exitCode, EXIT.FINDINGS);
});
