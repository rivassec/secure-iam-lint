// r8: CloudWatch Logs resource policies (log group, or the account-wide policy with the 'logs' hint).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const A = '111111111111';
const B = '222222222222';
const ACCOUNT_CTX = { type: 'logs', arn: `arn:aws:logs:us-east-1:${A}:*`, account: A };
const GROUP_CTX = { type: 'logs', arn: `arn:aws:logs:us-east-1:${A}:log-group:app` };
const P = (...s) => JSON.stringify({ Version: '2012-10-17', Statement: s });
const run = (text, resourceContext = ACCOUNT_CTX) => scan({ text, family: 'resource', threshold: 'high',
  subjectAccount: A, partition: 'aws', resourceContext });
const ids = (r) => (r.findings || []).map((f) => `${f.id}/${f.severity}`).sort();
const codes = (r) => (r.analysisStates || []).map((s) => s.code);
const GROUP = `arn:aws:logs:us-east-1:${A}:log-group:app:*`;
const DELIVER = ['logs:CreateLogStream', 'logs:PutLogEvents'];
const svc = (s) => ({ Service: s });

test('a source-bound service delivery grant is clean', () => {
  const r = run(P({ Effect: 'Allow', Principal: svc('delivery.logs.amazonaws.com'), Action: DELIVER,
    Resource: `arn:aws:logs:us-east-1:${A}:log-group:/aws/vendedlogs/*:log-stream:*`,
    Condition: { StringEquals: { 'aws:SourceAccount': A }, ArnLike: { 'aws:SourceArn': `arn:aws:logs:us-east-1:${A}:*` } } }));
  assert.equal(r.exitCode, EXIT.CLEAN, codes(r).join(','));
  assert.deepEqual(ids(r), []);
});

test('an unbound service grant is a confused deputy (high)', () => {
  const r = run(P({ Effect: 'Allow', Principal: svc('route53.amazonaws.com'), Action: DELIVER, Resource: GROUP }));
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.deepEqual(ids(r), ['RESOURCE-CONFUSED-DEPUTY/high']);
});

test('public and cross-account grants are reported, reads included', () => {
  const pub = run(P({ Effect: 'Allow', Principal: '*', Action: 'logs:GetLogEvents', Resource: GROUP }));
  assert.deepEqual(ids(pub), ['PUBLIC-ACCESS/critical', 'RESOURCE-DATA-EXPOSURE/high']);
  const x = run(P({ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${B}:root` }, Action: ['logs:FilterLogEvents', 'logs:StartQuery'], Resource: GROUP }));
  assert.equal(x.exitCode, EXIT.FINDINGS);
  assert.deepEqual(codes(x), [], 'logs reads are classified here, not UNKNOWN_ACTION');
  assert.deepEqual(ids(x), ['RESOURCE-CROSS-ACCOUNT/high']);
  const takeover = run(P({ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${B}:root` }, Action: 'logs:PutResourcePolicy', Resource: '*' }));
  assert.ok(ids(takeover).includes('RESOURCE-POLICY-TAKEOVER/high'));
});

test('unclassified actions, foreign resources and NotPrincipal fail closed', () => {
  const bound = { StringEquals: { 'aws:SourceAccount': A } };
  const deliv = run(P({ Effect: 'Allow', Principal: svc('delivery.logs.amazonaws.com'), Action: ['logs:PutLogEvents', 'logs:CreateDelivery'], Resource: GROUP, Condition: bound }));
  assert.equal(deliv.exitCode, EXIT.FAIL_CLOSED);
  assert.ok(codes(deliv).includes('RESOURCE_STATEMENT_UNMODELED'));
  for (const res of [`arn:aws:logs:us-east-1:${B}:log-group:x:*`, `arn:aws:logs:eu-west-1:${A}:log-group:x:*`, 'arn:aws:s3:::b/*']) {
    const r = run(P({ Effect: 'Allow', Principal: svc('route53.amazonaws.com'), Action: 'logs:PutLogEvents', Resource: res, Condition: bound }));
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, res);
  }
  const np = run(P({ Effect: 'Allow', NotPrincipal: { AWS: `arn:aws:iam::${A}:root` }, Action: 'logs:PutLogEvents', Resource: GROUP }));
  assert.equal(np.exitCode, EXIT.FAIL_CLOSED);
});

test('context: a log group is accepted without a hint; the account-wide ARN needs the logs hint', () => {
  const stmt = P({ Effect: 'Allow', Principal: svc('route53.amazonaws.com'), Action: DELIVER, Resource: GROUP, Condition: { StringEquals: { 'aws:SourceAccount': A } } });
  assert.equal(run(stmt, { arn: GROUP_CTX.arn }).exitCode, EXIT.CLEAN);
  assert.equal(run(stmt, { arn: `${GROUP_CTX.arn}:*` }).exitCode, EXIT.CLEAN);
  const noHint = run(stmt, { arn: ACCOUNT_CTX.arn });
  assert.equal(noHint.exitCode, EXIT.FAIL_CLOSED);
  assert.ok(codes(noHint).includes('UNSUPPORTED_RESOURCE_SHAPE'));
  // A log group covers its own streams, not another group.
  const other = run(P({ Effect: 'Allow', Principal: svc('route53.amazonaws.com'), Action: DELIVER,
    Resource: `arn:aws:logs:us-east-1:${A}:log-group:other:*`, Condition: { StringEquals: { 'aws:SourceAccount': A } } }), GROUP_CTX);
  assert.equal(other.exitCode, EXIT.FAIL_CLOSED);
  const stream = run(P({ Effect: 'Allow', Principal: svc('route53.amazonaws.com'), Action: DELIVER,
    Resource: `arn:aws:logs:us-east-1:${A}:log-group:app:log-stream:s1`, Condition: { StringEquals: { 'aws:SourceAccount': A } } }), GROUP_CTX);
  assert.equal(stream.exitCode, EXIT.CLEAN);
});

test('the identity family still fails logs closed (Deny-only there)', () => {
  const r = scan({ text: P({ Effect: 'Allow', Action: 'logs:GetLogEvents', Resource: GROUP }), family: 'identity', partition: 'aws', subjectAccount: A });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});
