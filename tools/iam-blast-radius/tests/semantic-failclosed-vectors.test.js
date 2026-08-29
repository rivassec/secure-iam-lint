// Phase 2 of the multi-team-review remediation: the semantic fail-open vectors that
// were flagged as UNDER-SWEPT (unicode homograph / case-fold / ARN normalization,
// NotAction/NotResource/Deny inversion, condition over-confinement). An adversarial
// sweep found NO new fail-open - every tricky input either fires correctly or fails
// CLOSED (incomplete). These tests LOCK IN that fail-closed behaviour so a future change
// cannot silently open one of these vectors.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const A = (policy, family, opts = {}) =>
  analyze(JSON.stringify(policy), { family, requireExplicitFamily: true, ...opts });
const clean = (r) => r.ok === true
  && !(r.coverage && r.coverage.summary && r.coverage.summary.incomplete)
  && (r.findings || []).length === 0;
const has = (r, re) => (r.findings || []).some((f) => re.test(f.id));
const incomplete = (r) => !!(r.coverage && r.coverage.summary && r.coverage.summary.incomplete);

// --- Vector 1: unicode / case-fold action matching ---------------------------

test('mixed-case actions match the same as lowercase (case-insensitive, not a bypass)', () => {
  const lower = A({ Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }] }, 'identity');
  const upper = A({ Statement: [{ Effect: 'Allow', Action: 'S3:GETOBJECT', Resource: '*' }] }, 'identity');
  assert.equal(has(upper, /DATA-EXFIL/), has(lower, /DATA-EXFIL/), 'mixed-case must surface the same finding');
  assert.ok(has(upper, /DATA-EXFIL/), 'the exfil finding must fire');
});

test('a HOMOGRAPH action (Cyrillic lookalike) fails CLOSED, never silently clean', () => {
  // U+0455 (Cyrillic dze) looks like ASCII "s" -> "ѕ3:*" is NOT s3:*.
  const r = A({ Statement: [{ Effect: 'Allow', Action: 'ѕ3:*', Resource: '*' }] }, 'identity');
  assert.equal(clean(r), false, 'a homograph action must never read clean-complete');
  assert.ok(incomplete(r), 'an unrecognized (homograph) action must mark coverage incomplete');
});

// --- Vector 2: NotAction / NotResource / Deny inversion ----------------------

test('Allow + empty NotAction (allow EVERYTHING) fails CLOSED, never clean-complete', () => {
  const r = A({ Statement: [{ Effect: 'Allow', NotAction: [], Resource: '*' }] }, 'identity');
  assert.equal(clean(r), false, 'allow-all via empty NotAction must not read clean-complete');
});

test('Allow + NotAction:iam:* is surfaced as broad (NOTACTION-ALLOW + criticals)', () => {
  const r = A({ Statement: [{ Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }] }, 'identity');
  assert.ok(has(r, /NOTACTION-ALLOW/) || has(r, /ASSUME-ROLE-EXPANSION|WILDCARD/), 'allow-all-but-iam must surface as broad');
});

test('a conditional Deny does not silently neutralize a broad Allow', () => {
  const r = A({ Statement: [
    { Effect: 'Allow', Action: '*', Resource: '*' },
    { Effect: 'Deny', Action: '*', Resource: '*', Condition: { StringEquals: { 'aws:PrincipalTag/x': 'y' } } },
  ] }, 'identity');
  assert.equal(clean(r), false, 'a conditional Deny must not clear the Allow criticals to clean');
});

// --- Vector 3: condition over-confinement (the downgrade direction) ----------

test('a bogus/wildcard/IfExists condition does NOT downgrade a cross-account trust', () => {
  const base = { Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole' }] };
  const withCond = (cond) => ({ Statement: [{ ...base.Statement[0], Condition: cond }] });
  const opts = { subjectAccount: '111111111111' };
  for (const cond of [
    { ArnLike: { 'aws:SourceArn': '*' } },
    { StringEqualsIfExists: { 'aws:PrincipalOrgID': 'o-x' } },
    { Null: { 'aws:MultiFactorAuthPresent': 'false' } },
  ]) {
    const r = A(withCond(cond), 'role-trust', opts);
    assert.ok(has(r, /TRUST-CROSS-ACCOUNT/), `cross-account trust must survive condition ${JSON.stringify(cond)}`);
  }
});

test('a wildcard/IfExists s3:ResourceAccount condition does NOT clear a broad exfil read', () => {
  const withCond = (cond) => ({ Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::*/*', Condition: cond }] });
  for (const cond of [{ StringEquals: { 's3:ResourceAccount': '*' } }, { StringEqualsIfExists: { 's3:ResourceAccount': '111111111111' } }]) {
    const r = A(withCond(cond), 'identity', { subjectAccount: '111111111111' });
    assert.equal(clean(r), false, `broad s3 read must not read clean under ${JSON.stringify(cond)}`);
  }
});

test('a wrong-service condition key does NOT confine a PassRole escalation away', () => {
  const r = A({ Statement: [{ Effect: 'Allow', Action: ['iam:PassRole', 'lambda:CreateFunction'], Resource: '*', Condition: { StringEquals: { 'ec2:InstanceType': 't2.micro' } } }] }, 'identity');
  assert.ok(has(r, /PASSROLE/), 'the passrole escalation must still fire despite a wrong-service condition');
});
