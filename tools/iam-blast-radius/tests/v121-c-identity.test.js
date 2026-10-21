// v1.2.0 group C: T1-04, T1-05, T2-6, F6, N2. Each suppression has a near-miss that must still report.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const run = (statements, threshold = 'high') => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family: 'identity', partition: 'aws', threshold, subjectAccount: ACCT,
});
const ids = (r) => r.findings.map((f) => f.id);
const sev = (r, id) => (r.findings.find((f) => f.id === id) || {}).severity;
const allow = (Action, Resource = '*', extra = {}) => ({ Effect: 'Allow', Action, Resource, ...extra });
const deny = (Action, Resource = '*', extra = {}) => ({ Effect: 'Deny', Action, Resource, ...extra });
const IAM_STS = ['ATTACH-POLICY', 'POLICY-VERSION', 'PUT-INLINE-POLICY', 'TRUST-POLICY-MODIFY', 'CREDENTIAL-CREATION', 'ASSUME-ROLE-EXPANSION'];

test('T1-04: a service-wide Deny removes the escalations it denies from Allow *', () => {
  const r = run([allow('*'), deny(['iam:*', 'sts:*'])]);
  for (const id of IAM_STS) assert.ok(!ids(r).includes(id), `${id}: ${ids(r)}`);
  // Near-misses: a partial service Deny, and a conditional one, leave paths standing.
  const iamOnly = run([allow('*'), deny('iam:*')]);
  assert.ok(ids(iamOnly).includes('ASSUME-ROLE-EXPANSION'), ids(iamOnly).join(','));
  const cond = run([allow('*'), deny(['iam:*', 'sts:*'], '*', { Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } } })]);
  assert.ok(ids(cond).includes('ATTACH-POLICY'), ids(cond).join(','));
});

test('T1-05: a grant name matches at least one character', () => {
  assert.equal(run([allow('*'), deny('?*')]).exitCode, EXIT.CLEAN);
  for (const d of [deny('iam:*?'), deny(null, '*', { Action: undefined, NotAction: ['?'] })]) {
    const r = run([allow('iam:*'), d]);
    assert.ok(!ids(r).includes('DIRECT-IAM-ADMIN'), ids(r).join(','));
  }
  // A NotAction Deny sparing iam:Get* only narrows: the catalog can't prove the residual safe (V2-1)...
  const reads = run([allow('iam:*'), { Effect: 'Deny', NotAction: ['iam:Get*'], Resource: '*' }]);
  assert.ok(ids(reads).includes('DIRECT-IAM-ADMIN'), ids(reads).join(','));
  // ...near-misses: an exclusion sparing an admin action, and a pattern too short to cover.
  const na = run([allow('iam:*'), { Effect: 'Deny', NotAction: ['iam:Put*'], Resource: '*' }]);
  assert.ok(ids(na).includes('DIRECT-IAM-ADMIN'), ids(na).join(','));
  const short = run([allow('iam:*'), deny('iam:??')]);
  assert.ok(ids(short).includes('DIRECT-IAM-ADMIN'), ids(short).join(','));
});

test('N2: a same-scope unconditional Deny suppresses object-ACL and policy writes', () => {
  for (const a of ['s3:PutObjectAcl', 's3:PutBucketPolicy']) {
    assert.equal(run([allow(a, 'arn:aws:s3:::b/*'), deny(a, 'arn:aws:s3:::b/*')]).exitCode, EXIT.CLEAN, a);
    assert.equal(run([allow(a, 'arn:aws:s3:::b/*'), deny(a, 'arn:aws:s3:::*')]).exitCode, EXIT.CLEAN, a);
  }
  // Near-misses: partial scope, conditional Deny, different action.
  const keep = [
    [allow('s3:PutObjectAcl', 'arn:aws:s3:::b/*'), deny('s3:PutObjectAcl', 'arn:aws:s3:::b/private/*')],
    [allow('s3:PutObjectAcl', 'arn:aws:s3:::b/*'), deny('s3:PutObjectAcl', 'arn:aws:s3:::b/*', { Condition: { Bool: { 'aws:SecureTransport': 'false' } } })],
    [allow('s3:PutObjectAcl', 'arn:aws:s3:::b/*'), deny('s3:PutObjectTagging', 'arn:aws:s3:::b/*')],
  ];
  for (const st of keep) assert.ok(ids(run(st)).includes('OBJECT-ACL-WRITE'), JSON.stringify(st[1]));
});

test('T2-6: a PassedToService-only Deny that matches the service removes that path', () => {
  const pr = allow('iam:PassRole', `arn:aws:iam::${ACCT}:role/*`);
  const ec2 = allow('ec2:RunInstances');
  const ptsDeny = (op, v, extra = {}) => deny('iam:PassRole', '*', { Condition: { [op]: { 'iam:PassedToService': v }, ...extra } });
  for (const d of [ptsDeny('StringEquals', 'ec2.amazonaws.com'), ptsDeny('StringLike', '*')]) {
    assert.ok(!ids(run([pr, ec2, d])).includes('PASSROLE-EC2'), JSON.stringify(d.Condition));
  }
  // Near-misses: another service, an extra condition key, a variable value.
  for (const d of [ptsDeny('StringEquals', 'lambda.amazonaws.com'),
    ptsDeny('StringEquals', 'ec2.amazonaws.com', { Bool: { 'aws:MultiFactorAuthPresent': 'false' } }),
    ptsDeny('StringEquals', '${aws:PrincipalTag/svc}')]) {
    assert.ok(ids(run([pr, ec2, d])).includes('PASSROLE-EC2'), JSON.stringify(d.Condition));
  }
  // aws-cn may send the .cn spelling: a canonical-only Deny does not cover it.
  const cn = scan({ text: JSON.stringify({ Version: '2012-10-17', Statement: [
    allow('iam:PassRole', `arn:aws-cn:iam::${ACCT}:role/*`), ec2, ptsDeny('StringEquals', 'ec2.amazonaws.com')] }),
  family: 'identity', partition: 'aws-cn', threshold: 'high', subjectAccount: ACCT });
  assert.ok(ids(cn).includes('PASSROLE-EC2'), ids(cn).join(','));
});

test('T2-6: PassRole on non-role ARNs passes no role; wildcards and variables still do', () => {
  const ec2 = allow('ec2:RunInstances');
  for (const res of [`arn:aws:iam::${ACCT}:user/*`, `arn:aws:iam::${ACCT}:group/g`, 'arn:aws:s3:::b/*']) {
    assert.ok(!ids(run([allow('iam:PassRole', res), ec2])).includes('PASSROLE-EC2'), res);
  }
  for (const res of [`arn:aws:iam::${ACCT}:*`, `arn:aws:iam::${ACCT}:r*`, 'arn:aws:*:*:*:*', `arn:aws:iam::${ACCT}:user/\${aws:username}`, '*']) {
    assert.ok(ids(run([allow('iam:PassRole', res), ec2])).includes('PASSROLE-EC2'), res);
  }
});

test('T2-6: a fully denied PassRole statement is not an undecidable broad grant', () => {
  const r = run([allow('iam:PassRole', `arn:aws:iam::${ACCT}:role/*`), allow('ec2:RunInstances'),
    deny('iam:PassRole', `arn:aws:iam::${ACCT}:role/*`)]);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(!ids(r).includes('PASSROLE-EC2'), ids(r).join(','));
});

test('F6: self-applicable IAM admin on an all-or-self target is critical', () => {
  assert.equal(sev(run([allow('iam:*')]), 'DIRECT-IAM-ADMIN'), 'critical');
  const ic = run([allow(['iam:AttachUserPolicy', 'iam:CreatePolicyVersion', 'iam:PutUserPolicy'])], 'critical');
  assert.equal(ic.exitCode, EXIT.FINDINGS);
  for (const id of ['ATTACH-POLICY', 'POLICY-VERSION', 'PUT-INLINE-POLICY']) assert.equal(sev(ic, id), 'critical', id);
  assert.equal(sev(run([allow('iam:AttachUserPolicy', `arn:aws:iam::${ACCT}:user/\${aws:username}`)]), 'ATTACH-POLICY'), 'critical');
  // A named other principal stays high.
  assert.equal(sev(run([allow('iam:*', `arn:aws:iam::${ACCT}:role/app`)]), 'DIRECT-IAM-ADMIN'), 'high');
  assert.equal(sev(run([allow('iam:AttachRolePolicy', `arn:aws:iam::${ACCT}:role/app`)]), 'ATTACH-POLICY'), 'high');
});
