// v1.2.0 group A: no-op and inverted SCP/RCP guardrails must block (F1, F2, F4, F12).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const run = (stmt) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: [stmt] }),
  family: 'scp-rcp', partition: 'aws', threshold: 'high',
});
const sev = (r) => r.findings.map((f) => `${f.id}:${f.severity}`).join(',');
const scpDeny = (c, extra = {}) => ({ Effect: 'Deny', Action: '*', Resource: '*', Condition: c, ...extra });
const rcpDeny = (c) => ({ Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*', Condition: c });
const ORG = 'o-abc123def4';
const blocks = (r, label) => {
  assert.equal(r.exitCode, EXIT.FINDINGS, `${label}: ${sev(r)}`);
  assert.ok(r.findings.some((f) => f.severity === 'high' && f.hazard), `${label}: ${sev(r)}`);
};

test('F1: a Deny that can never fire is a blocking no-op', () => {
  const region = { StringNotEquals: { 'aws:RequestedRegion': 'us-east-2' } };
  blocks(run({ Effect: 'Deny', NotAction: ['iam:*', '*'], Resource: '*', Condition: region }), 'NotAction *');
  for (const v of ['*', '*-*-*']) {
    blocks(run({ Effect: 'Deny', NotAction: ['iam:*', 'sts:*'], Resource: '*',
      Condition: { StringNotLike: { 'aws:RequestedRegion': v } } }), `NotLike ${v}`);
  }
  // Controls: a real carve-out and a partial region glob stay info.
  const lock = run({ Effect: 'Deny', NotAction: ['iam:*'], Resource: '*', Condition: region });
  assert.equal(lock.exitCode, EXIT.CLEAN, sev(lock));
  assert.equal(run(scpDeny({ StringNotLike: { 'aws:RequestedRegion': 'us-*' } })).exitCode, EXIT.CLEAN);
});

test('F2: a negated *Like org perimeter that admits any org blocks', () => {
  blocks(run(rcpDeny({ StringNotLike: { 'aws:PrincipalOrgID': '*' } })), 'org *');
  blocks(run(rcpDeny({ StringNotLikeIfExists: { 'aws:PrincipalOrgID': 'o-*' } })), 'org o-*');
  const r = run(rcpDeny({ StringNotLike: { 'aws:SourceOrgPaths': '*' } }));
  assert.ok(r.findings.some((f) => f.wildcardOrgPerimeter), sev(r));
  // A pinned org path is not a wildcard perimeter.
  const pinned = run(rcpDeny({ StringNotLike: { 'aws:SourceOrgPaths': `${ORG}/r-ab12/*` } }));
  assert.ok(!pinned.findings.some((f) => f.wildcardOrgPerimeter), sev(pinned));
});

test('F4: inverted fences and inverted Bool gates block', () => {
  blocks(run(scpDeny({ StringEquals: { 'aws:RequestedRegion': 'us-east-2' } })), 'region StringEquals');
  blocks(run(rcpDeny({ StringEquals: { 'aws:PrincipalOrgID': ORG } })), 'org StringEquals');
  blocks(run({ Effect: 'Deny', Action: ['organizations:LeaveOrganization', 'cloudtrail:StopLogging'],
    Resource: '*', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } } }), 'MFA true');
  // The over-broad regional Deny stays a medium (availability, not a missing control).
  const ob = run(scpDeny({ StringNotEqualsIfExists: { 'aws:RequestedRegion': 'us-east-2' } }));
  assert.ok(ob.findings.every((f) => f.severity !== 'high'), sev(ob));
});

test('F12: the AWS RCP templates analyze; the service-polarity inversion blocks', () => {
  const perimeter = (v) => rcpDeny({ StringNotEqualsIfExists: { 'aws:PrincipalOrgID': ORG },
    BoolIfExists: { 'aws:PrincipalIsAWSService': v } });
  assert.equal(run(perimeter('false')).exitCode, EXIT.CLEAN);
  blocks(run(perimeter('true')), 'IsAWSService true');
  const deputy = run(rcpDeny({ StringNotEqualsIfExists: { 'aws:SourceOrgID': ORG },
    Bool: { 'aws:PrincipalIsAWSService': 'true' }, Null: { 'aws:SourceAccount': 'false' } }));
  assert.equal(deputy.exitCode, EXIT.CLEAN, sev(deputy));
  // Unmodeled shapes stay fail-closed.
  for (const c of [
    { StringNotEqualsIfExists: { 'aws:PrincipalOrgID': ORG }, StringEquals: { 'aws:PrincipalIsAWSService': 'false' } },
    { StringNotEqualsIfExists: { 'aws:PrincipalOrgID': ORG }, BoolIfExists: { 'aws:PrincipalIsAWSService': ['true', 'false'] } },
    { StringNotLikeIfExists: { 'aws:SourceOrgID': 'o-abc*' }, Bool: { 'aws:PrincipalIsAWSService': 'true' } },
  ]) {
    assert.notEqual(run(rcpDeny(c)).exitCode, EXIT.CLEAN, JSON.stringify(c));
  }
});
