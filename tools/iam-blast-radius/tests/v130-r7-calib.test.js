// v1.3.0 round 7: false-positive calibrations from the real estate, plus J-5 at high.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const id = (text, o = {}) => scan({ text, family: 'identity', partition: 'aws', ...o });
const sev = (r) => r.findings.map((f) => `${f.id}:${f.severity}`);
const maxSev = (r) => ['info', 'low', 'medium', 'high', 'critical'].findIndex((s) => s === r.findings.map((f) => f.severity)
  .sort((a, b) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(b) - ['info', 'low', 'medium', 'high', 'critical'].indexOf(a))[0]);
const HIGH = 3;
const QUEUE = 'arn:aws:sqs:us-east-2:111122223333:jobs';

test('Lambda basic logs on "*" are medium; other writes on "*" stay high', () => {
  const r = id(P({ Effect: 'Allow', Action: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'], Resource: '*' }));
  assert.ok(maxSev(r) < HIGH, sev(r).join());
  assert.ok(maxSev(id(P({ Effect: 'Allow', Action: ['logs:PutLogEvents', 's3:PutObject'], Resource: '*' }))) >= HIGH);
  assert.ok(maxSev(id(P({ Effect: 'Allow', Action: ['logs:Put*'], Resource: '*' }))) >= HIGH);
});

test('CodePipeline artifact store reads/writes are medium; deletes and other globs stay high', () => {
  const cp = 'arn:aws:s3:::codepipeline-us-east-2-*';
  const r = id(P({ Effect: 'Allow', Action: ['s3:PutObject', 's3:GetObject', 's3:GetObjectVersion', 's3:GetBucketAcl', 's3:GetBucketLocation'], Resource: [cp] }));
  assert.ok(maxSev(r) < HIGH, sev(r).join());
  assert.ok(maxSev(id(P({ Effect: 'Allow', Action: ['s3:DeleteObject'], Resource: cp }))) >= HIGH);
  for (const res of ['arn:aws:s3:::prod-*', 'arn:aws:s3:::codepipeline-*', '*']) {
    assert.ok(maxSev(id(P({ Effect: 'Allow', Action: ['s3:GetObject'], Resource: res }))) >= HIGH, res);
  }
});

test('SQS consumer ack is not destructive; queue deletion stays high; message reads stay unknown', () => {
  const r = id(P({ Effect: 'Allow', Action: ['sqs:ReceiveMessage', 'sqs:DeleteMessage', 'sqs:GetQueueAttributes'], Resource: QUEUE }));
  assert.ok(maxSev(r) < HIGH, sev(r).join());
  assert.equal(id(P({ Effect: 'Allow', Action: ['sqs:DeleteMessage', 'sqs:GetQueueAttributes'], Resource: QUEUE })).exitCode, EXIT.CLEAN);
  // A foreign-queue read must not lose its fail-closed backstop (Mac guard F4).
  assert.equal(id(P({ Effect: 'Allow', Action: 'sqs:ReceiveMessage', Resource: 'arn:aws:sqs:us-east-2:999988887777:q' })).exitCode, EXIT.FAIL_CLOSED);
  for (const a of ['sqs:DeleteQueue', 'sqs:PurgeQueue', 'sqs:Delete*']) {
    assert.ok(id(P({ Effect: 'Allow', Action: a, Resource: QUEUE })).findings.some((f) => f.id === 'DESTRUCTIVE-ACTION'), a);
  }
});

const ghTrust = (cond) => P({ Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com' },
  Action: 'sts:AssumeRoleWithWebIdentity', Condition: cond });
const trust = (text) => scan({ text, family: 'role-trust', partition: 'aws' });

test('GitHub repository_id pin is a modeled repo pin; Like, IfExists or a repo-segment-free glob stay broad', () => {
  const aud = { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' };
  const sub = { 'token.actions.githubusercontent.com:sub': 'repo:example-org/*:ref:refs/heads/main' };
  const pinned = trust(ghTrust({ StringEquals: { ...aud, 'token.actions.githubusercontent.com:repository_id': '123456789' }, StringLike: sub }));
  assert.notEqual(pinned.exitCode, EXIT.FAIL_CLOSED);
  assert.ok(maxSev(pinned) < HIGH, sev(pinned).join());
  const noPin = trust(ghTrust({ StringEquals: aud, StringLike: sub }));
  assert.ok(maxSev(noPin) >= HIGH);
  const anyRef = trust(ghTrust({ StringEquals: { ...aud, 'token.actions.githubusercontent.com:repository_id': '123456789' },
    StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:example-org/*:*' } }));
  assert.ok(maxSev(anyRef) >= HIGH, sev(anyRef).join());
  const likePin = trust(ghTrust({ StringEquals: aud, StringLike: { ...sub, 'token.actions.githubusercontent.com:repository_id': '12*' } }));
  assert.ok(maxSev(likePin) >= HIGH);
  // repository_id alone: analyzed (not exit 3), one repo any ref = high, not internet-open critical.
  const idOnly = trust(ghTrust({ StringEquals: { ...aud, 'token.actions.githubusercontent.com:repository_id': '123456789' } }));
  assert.equal(idOnly.exitCode, EXIT.FINDINGS);
  assert.deepEqual(sev(idOnly), ['TRUST-FEDERATED:high']);
});

test('J-5: "*" scoped to the owning account is SAME-ACCOUNT-GRANT high', () => {
  const r = scan({ text: P({ Effect: 'Allow', Principal: '*', Action: 'ecr:BatchGetImage', Condition: { StringEquals: { 'aws:PrincipalAccount': '111122223333' } } }),
    family: 'resource', partition: 'aws', resourceContext: { type: 'ecr-repository', arn: 'arn:aws:ecr:us-east-2:111122223333:repository/app' } });
  assert.deepEqual(sev(r), ['RESOURCE-SAME-ACCOUNT-GRANT:high']);
});
