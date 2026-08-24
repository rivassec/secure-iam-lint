// IAM-1005 (Phase 10 P2): IAM + ECS semantic precision.
//
// Drives the acceptance fixtures for suite-2 tests 36/38 and suite-3 tests
// 86-91 through the REAL engine (analyze()) and asserts the finer semantics the
// generic fixture harnesses do not encode: the dedicated group-membership
// finding (not generic admin), ECS task-vs-execution-role separation across
// findings AND graph, staging-vs-launch severity, and the cross-account PassRole
// account-mismatch downgrade.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

function load(rel) {
  return JSON.parse(readFileSync(join(fixturesDir, rel), 'utf8'));
}
function run(rel) {
  const fx = load(rel);
  const text = typeof fx.policyRaw === 'string' ? fx.policyRaw : JSON.stringify(fx.policy);
  return analyze(text, fx.options || {});
}
function byId(res, id) {
  return res.findings.find((f) => f.id === id);
}
function edgeKeys(res) {
  return res.graph.edges.map((e) => `${e.from}|${e.type}|${e.to}`);
}
function hasNode(res, id) {
  return res.graph.nodes.some((n) => n.id === id);
}

// ---------------------------------------------------------------------------
// Group membership (tests 36 / 86)
// ---------------------------------------------------------------------------

test('86: AddUserToGroup -> dedicated GROUP-MEMBERSHIP, not generic direct-IAM admin', () => {
  const res = run('acceptance-3/test-86-add-user-to-group-membership.json');
  const gm = byId(res, 'GROUP-MEMBERSHIP');
  assert.ok(gm, 'GROUP-MEMBERSHIP must fire');
  // Never mislabeled as a direct policy edit.
  assert.ok(!byId(res, 'DIRECT-IAM-ADMIN'), 'must NOT be DIRECT-IAM-ADMIN');
  assert.ok(!byId(res, 'ATTACH-POLICY'), 'must NOT be ATTACH-POLICY');
  assert.ok(!byId(res, 'PUT-INLINE-POLICY'), 'must NOT be PUT-INLINE-POLICY');
  // High severity; group privilege inferred at MEDIUM confidence (pathExploitability).
  assert.equal(gm.severity, 'high');
  assert.equal(gm.pathExploitability, 'medium', 'inferred group privilege is medium confidence');
  // Explains: user selected by the API request; Resource scopes the group; the
  // group's real permissions are unknown / inferred from the name.
  assert.match(gm.why, /supplied in the API request/i);
  assert.match(gm.why, /Resource scopes only WHICH group/i);
  assert.match(gm.why, /inferred/i);
  assert.match(gm.why, /medium confidence/i);
});

// ---------------------------------------------------------------------------
// ECS task vs execution role (tests 38 / 87 / 88 / 89)
// ---------------------------------------------------------------------------

test('87: both roles passable -> critical; task and execution rendered as SEPARATE graph nodes', () => {
  const res = run('acceptance-3/test-87-ecs-task-and-execution-separate.json');
  const f = byId(res, 'PASSROLE-SERVICE');
  assert.ok(f, 'PASSROLE-SERVICE must fire');
  assert.equal(f.severity, 'critical');
  // RegisterTaskDefinition + RunTask stay jointly relevant.
  assert.ok(f.actions.includes('ecs:RegisterTaskDefinition'));
  assert.ok(f.actions.includes('ecs:RunTask'));
  // Task vs execution classified and kept distinct on the finding.
  assert.deepEqual(f.escalation.ecs.taskRoles, ['arn:aws:iam::123456789012:role/ecs/AppTaskRole']);
  assert.deepEqual(f.escalation.ecs.executionRoles, ['arn:aws:iam::123456789012:role/ecs/AppExecutionRole']);
  // Separate graph nodes - never merged.
  assert.ok(hasNode(res, 'role:passable:ecs:task'), 'task-role node present');
  assert.ok(hasNode(res, 'role:passable:ecs:execution'), 'execution-role node present');
  assert.ok(!hasNode(res, 'role:passable:ecs'), 'merged ecs node must NOT exist');
  // Application-credential path (can-execute-as) runs from the TASK role only.
  const keys = edgeKeys(res);
  assert.ok(keys.includes('role:passable:ecs:task|can-execute-as|service:ecs'),
    'app-credential can-execute-as edge from the task role');
  assert.ok(!keys.includes('role:passable:ecs:execution|can-execute-as|service:ecs'),
    'execution role must NOT get an application can-execute-as edge');
  // Wording keeps the roles distinct.
  assert.match(f.why, /application-credential path targets the ECS TASK role/i);
  assert.match(f.why, /EXECUTION role.*startup|image pulls|secret injection/i);
});

test('88: only execution role passable -> high, no invented task node, no app-cred claim', () => {
  const res = run('acceptance-3/test-88-only-execution-role-passable.json');
  const f = byId(res, 'PASSROLE-SERVICE');
  assert.ok(f, 'PASSROLE-SERVICE must fire');
  assert.equal(f.severity, 'high', 'execution-role-only is high, not critical');
  assert.deepEqual(f.escalation.ecs.taskRoles, [], 'no task role passed');
  assert.deepEqual(f.escalation.ecs.executionRoles, ['arn:aws:iam::123456789012:role/ecs/AppExecutionRole']);
  // Only the execution-role node; no invented task node/edge.
  assert.ok(hasNode(res, 'role:passable:ecs:execution'));
  assert.ok(!hasNode(res, 'role:passable:ecs:task'), 'must NOT invent a task-role node');
  const keys = edgeKeys(res);
  assert.ok(!keys.some((k) => k.startsWith('role:passable:ecs:task')), 'no task-role edge');
  assert.ok(!keys.includes('role:passable:ecs:execution|can-execute-as|service:ecs'),
    'no application can-execute-as edge for an execution-only path');
  // Does not claim application code receives execution-role credentials.
  assert.match(f.why, /application code does NOT receive the execution/i);
});

test('89: only task role passable -> critical task-role execution, target perms unknown', () => {
  const res = run('acceptance-3/test-89-only-task-role-passable.json');
  const f = byId(res, 'PASSROLE-SERVICE');
  assert.ok(f, 'PASSROLE-SERVICE must fire');
  assert.ok(['critical', 'high'].includes(f.severity), 'task-role execution is critical/high');
  assert.equal(f.severity, 'critical');
  assert.deepEqual(f.escalation.ecs.taskRoles, ['arn:aws:iam::123456789012:role/ecs/AppTaskRole']);
  assert.deepEqual(f.escalation.ecs.executionRoles, [], 'no execution role invented');
  assert.ok(hasNode(res, 'role:passable:ecs:task'));
  assert.ok(!hasNode(res, 'role:passable:ecs:execution'), 'must NOT invent an execution-role node');
  // Target role permissions remain unknown.
  assert.equal(f.escalation.targetPermissions, 'unknown');
  assert.match(f.limit, /unknown/i);
});

test('38 (suite-2): two passable roles kept distinct, RegisterTaskDefinition+RunTask joint', () => {
  const res = run('acceptance-2/test-38-ecs-task-execution-two-roles.json');
  const f = byId(res, 'PASSROLE-SERVICE');
  assert.ok(f);
  assert.equal(f.severity, 'critical');
  assert.ok(f.actions.includes('ecs:RegisterTaskDefinition') && f.actions.includes('ecs:RunTask'));
  assert.equal(f.escalation.ecs.taskRoles.length, 1);
  assert.equal(f.escalation.ecs.executionRoles.length, 1);
  assert.ok(hasNode(res, 'role:passable:ecs:task') && hasNode(res, 'role:passable:ecs:execution'));
});

// ---------------------------------------------------------------------------
// Staging vs launch (test 90)
// ---------------------------------------------------------------------------

test('90: RegisterTaskDefinition WITHOUT RunTask -> high staging, not critical execution', () => {
  const res = run('acceptance-3/test-90-register-without-runtask.json');
  const f = byId(res, 'PASSROLE-SERVICE');
  assert.ok(f, 'PASSROLE-SERVICE must fire');
  assert.equal(f.severity, 'high', 'staging-only is high, not critical');
  assert.notEqual(f.severity, 'critical');
  assert.equal(f.escalation.ecs.hasLaunch, false);
  assert.match(f.why, /STAGES a task definition/i);
  assert.match(f.why, /another actor or scheduler/i);
  // No launch action, so no boundary-crossing can-execute-as edge is drawn.
  const keys = edgeKeys(res);
  assert.ok(!keys.some((k) => k.includes('can-execute-as')), 'staging draws no execution edge');
});

// ---------------------------------------------------------------------------
// Cross-account PassRole target (test 91)
// ---------------------------------------------------------------------------

test('91: cross-account PassRole+EC2 with subject account -> not viable, account mismatch warned', () => {
  const res = run('acceptance-3/test-91-cross-account-passrole-target.json');
  const f = byId(res, 'PASSROLE-EC2');
  assert.ok(f, 'PASSROLE-EC2 finding present (reported, but not asserted viable)');
  assert.notEqual(f.severity, 'critical', 'a cross-account mismatch is not asserted as a viable critical path');
  assert.equal(f.pathExploitability, 'low', 'confidence lowered for the account mismatch');
  assert.ok(f.escalation.accountMismatch, 'account-mismatch metadata present');
  assert.equal(f.escalation.accountMismatch.viable, false);
  assert.deepEqual(f.escalation.accountMismatch.passedRoleAccounts, ['999900001111']);
  assert.equal(f.escalation.accountMismatch.subjectAccount, '123456789012');
  assert.match(f.why, /same account as the role/i);
  assert.match(f.why, /NOT a viable direct PassRole-to-ec2 path/i);
});

test('91: WITHOUT subject-account context the finding is not silently downgraded (unchanged behavior)', () => {
  const fx = load('acceptance-3/test-91-cross-account-passrole-target.json');
  const res = analyze(JSON.stringify(fx.policy)); // no options -> subject account unknown
  const f = byId(res, 'PASSROLE-EC2');
  assert.ok(f);
  assert.ok(!f.escalation.accountMismatch, 'no hard mismatch without subject-account context');
  // The honest same-account contextualizing note is still present.
  assert.match(f.why, /same account as the role/i);
});

// F1 regression guard: a foreign-account PassRole ARN coexisting with a bare "*"
// resource. The "*" reaches a role in the SUBJECT's own account, so a same-
// account pass to EC2 is viable and critical - the cross-account downgrade must
// NOT fire (firing it understates the blast radius / false negative).
test('91b: foreign PassRole ARN + bare "*" resource -> stays critical, no account-mismatch downgrade', () => {
  const res = run('acceptance-3/test-91b-cross-account-passrole-plus-wildcard.json');
  const f = byId(res, 'PASSROLE-EC2');
  assert.ok(f, 'PASSROLE-EC2 finding present');
  assert.equal(f.severity, 'critical', 'a same-account pass is possible via "*", so critical is retained');
  assert.ok(!f.escalation.accountMismatch, 'the bare "*" reaches the subject account -> no hard mismatch');
  // The definitive cross-account "not viable" assertion must NOT be emitted.
  assert.ok(
    !/NOT a viable direct PassRole-to-ec2 path across accounts/i.test(f.why),
    'must not assert the path is non-viable across accounts when "*" reaches the subject account',
  );
});

// F1 regression guard, case B2: a foreign-account ARN coexisting with an
// account-WILDCARD role ARN (arn:aws:iam::*:role/...). The wildcard account
// segment spans the subject's own account, so the downgrade must NOT fire.
test('91c: foreign PassRole ARN + account-wildcard ARN -> stays critical, no account-mismatch downgrade', () => {
  const res = run('acceptance-3/test-91c-cross-account-passrole-plus-account-wildcard.json');
  const f = byId(res, 'PASSROLE-EC2');
  assert.ok(f, 'PASSROLE-EC2 finding present');
  assert.equal(f.severity, 'critical', 'account-wildcard ARN spans the subject account -> critical retained');
  assert.ok(!f.escalation.accountMismatch, 'account-wildcard reaches the subject account -> no hard mismatch');
  assert.ok(
    !/NOT a viable direct PassRole-to-ec2 path across accounts/i.test(f.why),
    'must not assert non-viability when an account-wildcard reaches the subject account',
  );
});

// 11B (IAM-1102) regression guard: the cross-account demotion compares the
// subject account against the passed-role accounts by RAW string inequality, so
// it must fire ONLY for a well-formed concrete AWS account id (12 digits). An
// ambiguous / garbage subjectAccount ("unknown", "*", whitespace, textual, wrong
// length) means cross-account viability is UNKNOWN - the principal COULD be in
// the foreign account, making the path fully viable/critical - so the finding
// must stay critical and emit no account-mismatch (silently suppressing it is the
// exact false negative threat-model T8 forbids).
test('11B: an ambiguous/garbage subjectAccount does NOT demote a critical cross-account PassRole path', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::999988887777:role/foreignRole' },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  };
  const text = JSON.stringify(policy);
  // Sanity: with NO subject the path is critical.
  assert.equal(byId(analyze(text), 'PASSROLE-EC2').severity, 'critical');
  for (const bad of ['unknown', 'N/A', 'ambiguous', '*', '   ', 'acct-1', 'tbd', '123', '99998888777A', '0x1', '1234567890123']) {
    const f = byId(analyze(text, { subjectAccount: bad }), 'PASSROLE-EC2');
    assert.ok(f, `PASSROLE-EC2 present for subjectAccount ${JSON.stringify(bad)}`);
    assert.equal(f.severity, 'critical', `garbage subjectAccount ${JSON.stringify(bad)} must not demote the path`);
    assert.ok(!f.escalation.accountMismatch, `no account-mismatch asserted for ambiguous subject ${JSON.stringify(bad)}`);
    assert.ok(
      !/NOT a viable direct PassRole-to-ec2 path across accounts/i.test(f.why),
      `must not claim non-viability for ambiguous subject ${JSON.stringify(bad)}`,
    );
  }
  // A well-formed concrete account id that genuinely differs STILL demotes.
  const demoted = byId(analyze(text, { subjectAccount: '111122223333' }), 'PASSROLE-EC2');
  assert.notEqual(demoted.severity, 'critical', 'a real 12-digit foreign account id still demotes');
  assert.ok(demoted.escalation.accountMismatch, 'account-mismatch asserted for a concrete differing account');
});
