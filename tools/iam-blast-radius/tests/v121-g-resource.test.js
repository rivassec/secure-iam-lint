// v1.2.0 group G: the resource family can read complete (T2-4), with every newly
// complete shape pinned beside the unsafe siblings that must still report or stay
// exit 3. Plus T1-03/T2-5 (open principal conditions), F11 (NotPrincipal per
// statement) and F13 (unbound service grants are high).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const A = '111122223333';
const F = '444455556666';
const CTX = {
  s3: { type: 's3-bucket', arn: 'arn:aws:s3:::example-bucket', account: A },
  kms: { type: 'kms-key', arn: `arn:aws:kms:us-east-2:${A}:key/1234abcd-12ab-34cd-56ef-1234567890ab`, account: A },
  sqs: { type: 'sqs', arn: `arn:aws:sqs:us-east-2:${A}:q`, account: A },
  sns: { type: 'sns', arn: `arn:aws:sns:us-east-2:${A}:t`, account: A },
};
const OBJ = 'arn:aws:s3:::example-bucket/*';
const Q = CTX.sqs.arn;
const OWN_TOPIC = `arn:aws:sns:us-east-2:${A}:src`;
const SNS = { Service: 'sns.amazonaws.com' };
const allow = (Principal, Action, Resource, Condition) =>
  ({ Effect: 'Allow', Principal, Action, Resource, ...(Condition ? { Condition } : {}) });
const run = (ctx, ...Statement) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement }),
  family: 'resource', partition: 'aws', threshold: 'high', subjectAccount: A, resourceContext: CTX[ctx],
});
const ids = (r) => r.findings.map((f) => `${f.id}:${f.severity}`);
const codes = (r) => (r.analysisStates || []).map((s) => s.code);

test('T2-4: fully modeled same-account / delegation / bound / deny-only policies read complete', () => {
  const cases = [
    ['kms owner delegation', run('kms', allow({ AWS: `arn:aws:iam::${A}:root` }, 'kms:*', '*'))],
    ['s3 same-account role', run('s3', allow({ AWS: `arn:aws:iam::${A}:role/app` }, 's3:GetObject', OBJ))],
    ['sqs own-account sns', run('sqs', allow(SNS, 'sqs:SendMessage', Q, { ArnEquals: { 'aws:SourceArn': OWN_TOPIC } }))],
    ['s3 deny-only tls', run('s3', { Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: OBJ, Condition: { Bool: { 'aws:SecureTransport': 'false' } } })],
  ];
  for (const [name, r] of cases) {
    assert.equal(r.exitCode, EXIT.CLEAN, `${name}: ${ids(r)} ${codes(r)}`);
    assert.ok(!codes(r).includes('RESOURCE_ANALYSIS_INCOMPLETE'), name);
  }
});

test('T2-4: the unsafe siblings of every complete shape still report or stay exit 3', () => {
  const report = [
    ['anonymous', run('s3', allow('*', 's3:GetObject', OBJ))],
    ['anonymous AWS:*', run('s3', allow({ AWS: '*' }, 's3:GetObject', OBJ))],
    ['foreign account', run('s3', allow({ AWS: `arn:aws:iam::${F}:root` }, 's3:GetObject', OBJ))],
    ['kms foreign root', run('kms', allow({ AWS: `arn:aws:iam::${F}:root` }, 'kms:Decrypt', '*'))],
    ['kms default + foreign', run('kms', allow({ AWS: `arn:aws:iam::${A}:root` }, 'kms:*', '*'), allow({ AWS: `arn:aws:iam::${F}:root` }, 'kms:Decrypt', '*'))],
    ['service no source', run('sqs', allow(SNS, 'sqs:SendMessage', Q))],
    ['service foreign source', run('sqs', allow(SNS, 'sqs:SendMessage', Q, { ArnEquals: { 'aws:SourceArn': `arn:aws:sns:us-east-2:${F}:t` } }))],
    ['service own+foreign source', run('sqs', allow(SNS, 'sqs:SendMessage', Q, { ArnEquals: { 'aws:SourceArn': [OWN_TOPIC, `arn:aws:sns:us-east-2:${F}:t`] } }))],
    ['service source like *', run('sqs', allow(SNS, 'sqs:SendMessage', Q, { ArnLike: { 'aws:SourceArn': '*' } }))],
    ['service source acct glob', run('sqs', allow(SNS, 'sqs:SendMessage', Q, { ArnLike: { 'aws:SourceArn': 'arn:aws:sns:us-east-2:*:t' } }))],
    ['service source IfExists', run('sqs', allow(SNS, 'sqs:SendMessage', Q, { ArnEqualsIfExists: { 'aws:SourceArn': OWN_TOPIC } }))],
    ['service source ForAllValues', run('sqs', allow(SNS, 'sqs:SendMessage', Q, { 'ForAllValues:StringEquals': { 'aws:SourceAccount': A } }))],
    ['service source negated', run('sqs', allow(SNS, 'sqs:SendMessage', Q, { StringNotEquals: { 'aws:SourceAccount': F } }))],
    ['service source var account', run('sqs', allow(SNS, 'sqs:SendMessage', Q, { ArnLike: { 'aws:SourceArn': 'arn:aws:sns:us-east-2:${aws:PrincipalAccount}:t' } }))],
    ['own-bound + unbound statement', run('sqs', allow(SNS, 'sqs:SendMessage', Q, { ArnEquals: { 'aws:SourceArn': OWN_TOPIC } }), allow(SNS, 'sqs:SendMessage', Q))],
    ['deny beside public allow', run('s3', allow('*', 's3:GetObject', OBJ), { Effect: 'Deny', Principal: '*', Action: 's3:PutObject', Resource: OBJ })],
  ];
  for (const [name, r] of report) {
    assert.notEqual(r.exitCode, EXIT.CLEAN, `${name}: ${ids(r)} ${codes(r)}`);
  }
  // Unmodeled parts keep it exit 3 even when the only finding is non-blocking.
  const SAME = { AWS: `arn:aws:iam::${A}:role/app` };
  const stay3 = [
    ['unknown condition key', run('s3', allow(SAME, 's3:GetObject', OBJ, { StringEquals: { 'aws:ZzUnknown': 'x' } })), 'UNSUPPORTED_CONDITION'],
    ['unknown operator', run('s3', allow(SAME, 's3:GetObject', OBJ, { ZzWeirdOp: { 'aws:SourceIp': '203.0.113.0/24' } })), 'RESOURCE_STATEMENT_UNMODELED'],
    ['NotAction allow', run('s3', { Effect: 'Allow', Principal: SAME, NotAction: 's3:DeleteBucket', Resource: OBJ }), 'RESOURCE_STATEMENT_UNMODELED'],
    ['NotResource allow', run('s3', { Effect: 'Allow', Principal: SAME, Action: 's3:GetObject', NotResource: 'arn:aws:s3:::example-bucket/p/*' }), 'RESOURCE_STATEMENT_UNMODELED'],
    ['foreign-service action', run('s3', allow(SAME, 'sqs:SendMessage', OBJ)), 'RESOURCE_STATEMENT_UNMODELED'],
    ['unknown s3 action', run('s3', allow(SAME, 's3:ZzNotReal', OBJ)), 'UNKNOWN_ACTION'],
    ['canonical user', run('s3', allow({ CanonicalUser: '79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be' }, 's3:GetObject', OBJ)), 'RESOURCE_STATEMENT_UNMODELED'],
    ['federated', run('s3', allow({ Federated: 'cognito-identity.amazonaws.com' }, 's3:GetObject', OBJ)), 'RESOURCE_STATEMENT_UNMODELED'],
    ['kms silent key policy', run('kms', allow({ AWS: `arn:aws:iam::${A}:role/app` }, 'kms:Decrypt', '*')), 'KMS_SILENT_POLICY_UNKNOWN'],
  ];
  for (const [name, r, code] of stay3) {
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `${name}: ${ids(r)} ${codes(r)}`);
    assert.ok(codes(r).includes(code), `${name}: expected ${code}, got ${codes(r)}`);
  }
});

test('T2-4: an unmodeled part is located by path and never echoes policy text', () => {
  const r = run('s3', allow({ AWS: `arn:aws:iam::${A}:role/app` }, 's3:GetObject', OBJ, { 'ZzOp](x)': { 'aws:SourceIp': '1.2.3.4/32' } }));
  const st = r.analysisStates.find((s) => s.code === 'RESOURCE_STATEMENT_UNMODELED');
  assert.equal(st.path, 'Statement[0].Condition');
  assert.ok(!st.message.includes('ZzOp'), st.message);
});

test('T2-5/T1-03: a principal condition that narrows nothing scores like "*"; a real pin stays lower', () => {
  const open = [
    ['acct self', { StringEquals: { 'aws:PrincipalAccount': '${aws:PrincipalAccount}' } }],
    ['org self', { StringEquals: { 'aws:PrincipalOrgID': '${aws:PrincipalOrgID}' } }],
    ['arn self', { ArnEquals: { 'aws:PrincipalArn': '${aws:PrincipalArn}' } }],
    ['org like *', { StringLike: { 'aws:PrincipalOrgID': '*' } }],
    ['org Null false', { Null: { 'aws:PrincipalOrgID': 'false' } }],
    ['arn any account', { ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/a' } }],
    ['arn truncated', { ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam' } }],
    ['acct list with *', { StringLike: { 'aws:PrincipalAccount': [A, '*'] } }],
  ];
  for (const [name, cond] of open) {
    const r = run('s3', allow('*', 's3:GetObject', OBJ, cond));
    assert.ok(ids(r).includes('PUBLIC-ACCESS:critical'), `${name}: ${ids(r)}`);
    assert.equal(r.exitCode, EXIT.FINDINGS, name);
  }
  // v1.3.0: a scoped "*" is cross-account within the scope (J-5: own account = same-account).
  for (const [name, cond, want] of [
    ['org exact', { StringEquals: { 'aws:PrincipalOrgID': 'o-exampleorgid' } }, 'RESOURCE-CROSS-ACCOUNT:high'],
    ['own account', { StringEquals: { 'aws:PrincipalAccount': A } }, 'RESOURCE-SAME-ACCOUNT-GRANT:medium'],
    ['own role arn', { ArnEquals: { 'aws:PrincipalArn': `arn:aws:iam::${A}:role/a` } }, 'RESOURCE-CROSS-ACCOUNT:high'],
  ]) {
    const r = run('s3', allow('*', 's3:GetObject', OBJ, cond));
    assert.ok(ids(r).includes(want), `${name}: ${ids(r)}`);
    assert.ok(!ids(r).some((x) => x.startsWith('PUBLIC-ACCESS')), `${name}: not public`);
  }
  // key == ${key} is named as a tautology.
  const t = run('s3', allow('*', 's3:GetObject', OBJ, { StringEquals: { 'aws:PrincipalAccount': '${aws:PrincipalAccount}' } }));
  assert.ok(ids(t).includes('RESOURCE-CONDITION-TAUTOLOGY:info'), ids(t).join(','));
  const pub = t.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.equal(pub.resource.anonymous, false, 'anonymous callers lack the key');
});

test('T1-03: a self-referencing source binding binds nothing', () => {
  for (const cond of [
    { ArnEquals: { 'aws:SourceArn': '${aws:SourceArn}' } },
    { StringEquals: { 'aws:SourceAccount': '${aws:SourceAccount}' } },
  ]) {
    const r = run('sqs', allow(SNS, 'sqs:SendMessage', Q, cond));
    assert.ok(ids(r).includes('RESOURCE-CONFUSED-DEPUTY:high'), ids(r).join(','));
    assert.ok(ids(r).includes('RESOURCE-CONDITION-TAUTOLOGY:info'), ids(r).join(','));
    assert.equal(r.exitCode, EXIT.FINDINGS);
  }
});

test('F13: an unbound service grant is high; a binding counts only when it pins this account', () => {
  const unbound = run('sns', allow({ Service: 's3.amazonaws.com' }, 'sns:Publish', CTX.sns.arn));
  assert.deepEqual(ids(unbound), ['RESOURCE-CONFUSED-DEPUTY:high']);
  const own = run('sqs', allow(SNS, 'sqs:SendMessage', Q, { StringEquals: { 'aws:SourceAccount': A } }));
  assert.deepEqual(ids(own), ['RESOURCE-CONFUSED-DEPUTY:info']);
  // ANDed keys: an account-less S3 SourceArn plus an own-account SourceAccount is own-bound.
  const s3src = run('sqs', allow({ Service: 's3.amazonaws.com' }, 'sqs:SendMessage', Q,
    { ArnLike: { 'aws:SourceArn': 'arn:aws:s3:::notify-bucket' }, StringEquals: { 'aws:SourceAccount': A } }));
  assert.deepEqual(ids(s3src), ['RESOURCE-CONFUSED-DEPUTY:info']);
  // Without SourceAccount the bucket could be re-registered by another account.
  const s3only = run('sqs', allow({ Service: 's3.amazonaws.com' }, 'sqs:SendMessage', Q, { ArnLike: { 'aws:SourceArn': 'arn:aws:s3:::notify-bucket' } }));
  assert.deepEqual(ids(s3only), ['RESOURCE-CONFUSED-DEPUTY:high']);
  assert.equal(s3only.findings[0].resource.sourceBinding.state, 'source-unverified');
});

test('F11: a NotPrincipal statement fails closed alone; the other statements keep their findings', () => {
  const pub = allow('*', 's3:GetObject', OBJ);
  const npDeny = { Effect: 'Deny', NotPrincipal: { AWS: `arn:aws:iam::${A}:root` }, Action: 's3:PutObject', Resource: OBJ };
  const r = run('s3', pub, npDeny);
  assert.ok(ids(r).includes('PUBLIC-ACCESS:critical'), ids(r).join(','));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'incomplete dominates; never clean');
  const st = r.analysisStates.find((s) => s.code === 'UNSUPPORTED_NOTPRINCIPAL');
  assert.ok(st && st.path === 'Statement[1].NotPrincipal', JSON.stringify(r.analysisStates));
  // Deny-only with NotPrincipal: nothing granted, but never read as complete.
  assert.equal(run('s3', npDeny).exitCode, EXIT.FAIL_CLOSED);
  // Allow + NotPrincipal reaches everyone except the listed principals.
  const np = run('s3', { Effect: 'Allow', NotPrincipal: { AWS: `arn:aws:iam::${A}:root` }, Action: 's3:GetObject', Resource: OBJ });
  assert.ok(ids(np).includes('PUBLIC-ACCESS:critical'), ids(np).join(','));
  // Engine auto-detect (scan() refuses auto) keeps the whole-policy block.
  const auto = analyze(JSON.stringify({ Version: '2012-10-17', Statement: [pub, npDeny] }), {});
  assert.equal(auto.coverage.blocked, true);
  assert.ok(auto.coverage.blockingCodes.some((b) => b.code === 'UNSUPPORTED_NOTPRINCIPAL' && b.hazard === true));
});
