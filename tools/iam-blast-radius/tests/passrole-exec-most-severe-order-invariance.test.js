// S2-passrole-allstmts axis 2 — exec-statement selection is MOST-SEVERE across all
// statements, order-invariantly (mirrors the pass-side viability-tier rule).
//
// Regression for a threshold-critical clean fail-open + a default under-claim
// (threat-model T8). The exec-statement selector ranked candidate exec statements by
// RESOURCE BREADTH (execResourceBroadness), not by exec-action TECHNIQUE severity. So
// a co-located broad ecs:RegisterTaskDefinition (staging = high, Resource '*') was
// selected over a narrower ecs:RunTask (launch = critical, ECS_LAUNCH_ACTIONS), and
// the compound path lost its launch action: hasLaunch=false -> PASSROLE-SERVICE
// reported HIGH staging instead of CRITICAL launch. Under `--threshold critical`
// scan() returned exit 0 CLEAN on a genuine critical PassRole+RunTask launch path;
// reordering the byte-identical statements flipped exit 0<->1.
//
// The fix ranks exec candidates by technique severity FIRST (launch outranks
// staging), using resource breadth and lowest index only as within-tier settles, so
// ecs:RunTask in ANY statement keeps the path critical regardless of order.
//
// This test drives analyze() and scan() across BOTH statement orderings and asserts
// critical + exit 1, including under `threshold: 'critical'`.
//
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '123456789012';
const CTX = { subjectAccount: ACCT, partition: 'aws' };

const PASS = { Sid: 'pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/ecsTaskRole` };
// Staging = high, broad Resource '*'. Launch = critical, NARROWER concrete Resource so
// resource-breadth ranking alone would (wrongly) prefer the staging statement.
const STAGING = { Sid: 'reg', Effect: 'Allow', Action: 'ecs:RegisterTaskDefinition', Resource: '*' };
const LAUNCH = { Sid: 'run', Effect: 'Allow', Action: 'ecs:RunTask', Resource: `arn:aws:ecs:us-east-1:${ACCT}:task-definition/t:1` };

const ORDERINGS = [
  { label: 'staging-before-launch', stmts: [PASS, STAGING, LAUNCH] },
  { label: 'launch-before-staging', stmts: [PASS, LAUNCH, STAGING] },
];

function policyText(stmts) {
  return JSON.stringify({ Version: '2012-10-17', Statement: stmts });
}

function ecsFinding(res) {
  return (res.findings || []).find((f) => (f.escalation && f.escalation.ecs) || /PASSROLE/.test(f.id));
}

for (const ord of ORDERINGS) {
  test(`analyze(): launch action keeps path CRITICAL regardless of order [${ord.label}]`, () => {
    const res = analyze(policyText(ord.stmts), CTX);
    assert.equal(res.ok, true);
    const f = ecsFinding(res);
    assert.ok(f, `PASSROLE-SERVICE finding must be present [${ord.label}]`);
    assert.equal(f.severity, 'critical',
      `a granted ecs:RunTask launch action must keep the path critical [${ord.label}]`);
    const ecs = (f.escalation || {}).ecs || {};
    assert.equal(ecs.hasLaunch, true,
      `hasLaunch must be true when ecs:RunTask is granted in any statement [${ord.label}]`);
  });

  test(`scan(): exit 1 under DEFAULT threshold regardless of order [${ord.label}]`, () => {
    const r = scan({ text: policyText(ord.stmts), family: 'identity', subjectAccount: ACCT, partition: 'aws' });
    assert.equal(r.exitCode, EXIT.FINDINGS, `default-threshold exit for [${ord.label}]`);
  });

  test(`scan(): exit 1 under --threshold critical regardless of order [${ord.label}]`, () => {
    const r = scan({ text: policyText(ord.stmts), family: 'identity', subjectAccount: ACCT, partition: 'aws', threshold: 'critical' });
    assert.equal(r.exitCode, EXIT.FINDINGS,
      `critical-threshold exit for [${ord.label}] - a launch path must never be CLEAN`);
    assert.notEqual(r.exitCode, EXIT.CLEAN);
  });
}

// No over-correction: a STAGING-ONLY policy (no launch action anywhere) must stay HIGH
// and go CLEAN under --threshold critical - the launch preference must not manufacture
// a critical when no launch action is granted (test 90 semantics preserved).
test('staging-only (no launch action) stays HIGH and is CLEAN under --threshold critical', () => {
  const text = policyText([PASS, STAGING]);
  const res = analyze(text, CTX);
  const f = ecsFinding(res);
  assert.ok(f);
  assert.equal(f.severity, 'high', 'staging-only must remain high, not be promoted to critical');
  assert.equal((f.escalation || {}).ecs.hasLaunch, false);
  const r = scan({ text, family: 'identity', subjectAccount: ACCT, partition: 'aws', threshold: 'critical' });
  assert.equal(r.exitCode, EXIT.CLEAN, 'a staging-only high path is below the critical gate');
});
