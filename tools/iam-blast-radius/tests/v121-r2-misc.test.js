// v1.2.0 review round 2: V1-7 non-string scoping operators, V3-08 per-statement context, T2-7 reach note.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const doc = (stmts) => JSON.stringify({ Version: '2012-10-17', Statement: stmts });
const ctx = { type: 's3-bucket', arn: 'arn:aws:s3:::example-bucket', account: '111122223333' };
const res = (stmts) => scan({ text: doc(stmts), family: 'resource', partition: 'aws', threshold: 'high', resourceContext: ctx });
const pub = (cond, r = 'arn:aws:s3:::example-bucket/*') =>
  ({ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: r, ...(cond ? { Condition: cond } : {}) });
const sev = (r, id) => (r.findings.find((f) => f.id === id) || {}).severity;
const codes = (r) => JSON.stringify(r);

test('V1-7: a numeric/date/binary range on a scoping key is not a pin', () => {
  for (const cond of [
    { NumericGreaterThan: { 'aws:PrincipalAccount': '0' } },
    { NumericLessThanEquals: { 'aws:PrincipalAccount': '999999999999' } },
    { DateGreaterThan: { 'aws:PrincipalOrgID': '1970-01-01T00:00:00Z' } },
    { BinaryEquals: { 'aws:PrincipalAccount': 'NDQ0NDU1NTU2NjY2' } },
  ]) {
    const r = res([pub(cond)]);
    assert.equal(sev(r, 'PUBLIC-ACCESS'), 'critical', JSON.stringify(cond));
    assert.equal(r.exitCode, EXIT.FINDINGS);
  }
});

test('V1-7: String/Arn equality pins are still credited', () => {
  for (const cond of [
    { StringEquals: { 'aws:PrincipalAccount': '444455556666' } },
    { ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::444455556666:role/r' } },
  ]) assert.equal(sev(res([pub(cond)]), 'RESOURCE-CROSS-ACCOUNT'), 'high', JSON.stringify(cond));
});

test('V3-08: a statement naming another bucket keeps the public finding and stays exit 3', () => {
  const r = res([pub(null, ['arn:aws:s3:::other/*', 'arn:aws:s3:::example-bucket/*'])]);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(sev(r, 'PUBLIC-ACCESS'), 'critical');
  assert.ok(codes(r).includes('RESOURCE_CONTEXT_REQUIRED'));
  assert.ok(codes(r).includes('Statement[0].Resource'));
  assert.ok(!codes(r).includes('FAMILY_BLOCKED'));
});

test('V3-08: a Deny on another resource does not block analysis', () => {
  const r = res([{ Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: 'arn:aws:s3:::other/*' }, pub(null)]);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.equal(sev(r, 'PUBLIC-ACCESS'), 'critical');
  assert.ok(!codes(r).includes('RESOURCE_CONTEXT_REQUIRED'));
});

test('V3-08: a type hint that contradicts the ARN still blocks the family', () => {
  const r = scan({ text: doc([pub(null)]), family: 'resource', partition: 'aws', threshold: 'high',
    resourceContext: { type: 'kms', arn: 'arn:aws:s3:::example-bucket' } });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(r.findings.length, 0);
});

test('T2-7: pool-authenticated Cognito trust stays medium and points at attached policies', () => {
  const r = scan({ partition: 'aws', threshold: 'high', family: 'trust', text: doc([{
    Effect: 'Allow', Principal: { Federated: 'cognito-identity.amazonaws.com' },
    Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: {
      StringEquals: { 'cognito-identity.amazonaws.com:aud': 'us-east-1:12345678-1234-1234-1234-123456789012' },
      'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': 'authenticated' },
    },
  }]) });
  const f = r.findings.find((x) => x.id === 'TRUST-FEDERATED');
  assert.equal(f.severity, 'medium');
  assert.match(f.why, /Population-scale reach/);
  assert.match(f.why, /attached policies/);
});
