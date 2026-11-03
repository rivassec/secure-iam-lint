// v1.3.0 real-stack items in the engine: R5-3 (2008-10-17), R5-5 (exact PrincipalArn pin), C-3 (KMS keys).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const A = '111122223333';
const V = '444455556666';
const states = (r) => (r.analysisStates || []).map((s) => s.code);
const ids = (r) => r.findings.map((f) => `${f.id}:${f.severity}`);

// --- R5-3 -------------------------------------------------------------------
const legacy = (stmt) => JSON.stringify({ Version: '2008-10-17', Statement: [stmt] });
const ecr = (Resource) => ({ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${A}:root` }, Action: ['ecr:BatchGetImage'], ...(Resource ? { Resource } : {}) });

test('R5-3: a variable-free 2008-10-17 document is analyzed as 2012-10-17', () => {
  const id = scan({ text: legacy({ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/k' }), family: 'identity', partition: 'aws' });
  assert.ok(!states(id).includes('UNSUPPORTED_POLICY_VERSION'), states(id).join(','));
  const same = scan({ text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/k' }] }), family: 'identity', partition: 'aws' });
  assert.deepEqual(ids(id), ids(same));
  assert.equal(id.exitCode, same.exitCode);
});

test('R5-3: a 2008-10-17 document with a policy variable still fails closed', () => {
  for (const text of [
    legacy({ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/${aws:username}/*' }),
    // A JSON \u0024 escape decodes to "$", so this is a variable too.
    '{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/\\u0024{aws:username}"}]}',
    legacy({ Effect: 'Allow', Action: 's3:GetObject', Resource: '*', Condition: { StringEquals: { 's3:prefix': '${aws:userid}' } } }),
  ]) {
    const r = scan({ text, family: 'identity', partition: 'aws' });
    assert.ok(states(r).includes('UNSUPPORTED_POLICY_VERSION'), text);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  }
  const other = scan({ text: JSON.stringify({ Version: '2010-01-01', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }] }), family: 'identity', partition: 'aws' });
  assert.ok(states(other).includes('UNSUPPORTED_POLICY_VERSION'));
});

// --- R5-5 -------------------------------------------------------------------
const trust = (Principal, Condition, Action = 'sts:AssumeRole', o = {}) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal, Action, ...(Condition ? { Condition } : {}) }] }),
  family: 'role-trust', partition: 'aws', ...o,
});
const role = (a) => `arn:aws:iam::${a}:role/deploy`;

test('R5-5: Principal * pinned by an exact PrincipalArn is the named-principal trust', () => {
  for (const p of ['*', { AWS: '*' }]) {
    for (const op of ['ArnEquals', 'StringEquals']) {
      const r = trust(p, { [op]: { 'aws:PrincipalArn': [role(V)] } });
      assert.deepEqual(ids(r), ['TRUST-CROSS-ACCOUNT:high'], `${op} ${JSON.stringify(p)}`);
      assert.match(r.findings[0].why, /named directly/);
    }
  }
  const own = trust('*', { ArnEquals: { 'aws:PrincipalArn': role(A) } }, 'sts:AssumeRole', { resourceContext: { type: 'iam-role', arn: `arn:aws:iam::${A}:role/x` } });
  assert.deepEqual(ids(own), ['TRUST-SAME-ACCOUNT:low']);
  assert.deepEqual(ids(trust('*', { ArnEquals: { 'aws:PrincipalArn': role(A) } }, 'sts:AssumeRole', { subjectAccount: A })), ['TRUST-CROSS-ACCOUNT:high']);
});

test('R5-5 guards: wildcards, Like, IfExists, set operators and non-principal pins stay TRUST-PUBLIC', () => {
  for (const cond of [
    { ArnLike: { 'aws:PrincipalArn': `arn:aws:iam::${V}:role/*` } },
    { ArnLike: { 'aws:PrincipalArn': role(V) } },
    { ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy' } },
    { ArnEqualsIfExists: { 'aws:PrincipalArn': role(V) } },
    { 'ForAnyValue:StringEquals': { 'aws:PrincipalArn': role(V) } },
    { ArnEquals: { 'aws:PrincipalArn': `arn:aws:iam::${V}:root` } },
    { ArnEquals: { 'aws:PrincipalArn': [role(V), 'arn:aws:iam::${aws:PrincipalAccount}:role/x'] } },
    { ArnEquals: { 'aws:PrincipalArn': role(V) }, ArnNotEquals: { 'aws:PrincipalArn': role(A) } },
  ]) {
    const r = trust('*', cond);
    assert.ok(ids(r).some((x) => x.startsWith('TRUST-PUBLIC')), JSON.stringify(cond));
  }
});

// --- C-3 --------------------------------------------------------------------
const KEY = { type: 'kms-key', arn: `arn:aws:kms:us-east-1:${A}:key/1234abcd-12ab-34cd-56ef-1234567890ab` };
const keyPolicy = (...st) => scan({ text: JSON.stringify({ Version: '2012-10-17', Statement: st }), family: 'resource', partition: 'aws', subjectAccount: A, resourceContext: KEY });
const ROOT = { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${A}:root` }, Action: 'kms:*', Resource: '*' };

test('C-3: kms:GrantIsForAWSResource and kms:CallerAccount are modeled', () => {
  const grants = keyPolicy(ROOT, { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${A}:role/app` }, Action: 'kms:CreateGrant', Resource: '*', Condition: { Bool: { 'kms:GrantIsForAWSResource': 'true' } } });
  assert.ok(!states(grants).includes('UNSUPPORTED_CONDITION'), states(grants).join(','));
  const ebs = keyPolicy(ROOT, { Effect: 'Allow', Principal: { AWS: '*' }, Action: ['kms:Encrypt', 'kms:Decrypt', 'kms:CreateGrant', 'kms:DescribeKey'], Resource: '*',
    Condition: { StringEquals: { 'kms:CallerAccount': A, 'kms:ViaService': 'ec2.us-east-1.amazonaws.com' } } });
  assert.ok(!states(ebs).includes('UNSUPPORTED_CONDITION'), states(ebs).join(','));
  assert.notEqual(ebs.exitCode, EXIT.CLEAN);
  assert.ok(!ids(ebs).includes('PUBLIC-ACCESS:critical'), 'a concrete CallerAccount pins the caller');
});

test('C-3 guards: a wildcard or negated CallerAccount does not pin; GrantIsForAWSResource false does not narrow', () => {
  const wide = keyPolicy(ROOT, { Effect: 'Allow', Principal: { AWS: '*' }, Action: 'kms:Decrypt', Resource: '*', Condition: { StringLike: { 'kms:CallerAccount': '*' } } });
  assert.ok(ids(wide).includes('PUBLIC-ACCESS:critical'), ids(wide).join(','));
  const neg = keyPolicy(ROOT, { Effect: 'Allow', Principal: { AWS: '*' }, Action: 'kms:Decrypt', Resource: '*', Condition: { StringNotEquals: { 'kms:CallerAccount': V } } });
  assert.ok(ids(neg).includes('PUBLIC-ACCESS:critical'), ids(neg).join(','));
  const id = (v) => scan({ text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'kms:CreateGrant', Resource: KEY.arn, Condition: { Bool: { 'kms:GrantIsForAWSResource': v } } }] }), family: 'identity', partition: 'aws' });
  assert.ok(id('false').findings.length >= id('true').findings.length);
  assert.notEqual(id('false').exitCode, EXIT.CLEAN);
});
