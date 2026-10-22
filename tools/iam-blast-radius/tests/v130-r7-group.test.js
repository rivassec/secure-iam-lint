// v1.3.0 round 7: group context (Cognito population-scale reach) and the Pod Identity bypass.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { scanPulumi } from '../../../cli/pulumi.mjs';

const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const PRV = 'urn:pulumi:dev::p::pulumi:providers:aws::aws';
const role = (name, trust, inline) => ({
  urn: `urn:pulumi:dev::p::aws:iam/role:Role::${name}`, type: 'aws:iam/role:Role', custom: true,
  provider: `${PRV}::id1`, inputs: { name, assumeRolePolicy: trust, inlinePolicies: [{ name: 'p', policy: inline }] },
  outputs: { arn: `arn:aws:iam::111122223333:role/${name}` },
});
const run = (...res) => scanPulumi({ text: JSON.stringify({ deployment: { resources: [
  { urn: PRV, type: 'pulumi:providers:aws', custom: true, inputs: { region: 'us-east-1' } }, ...res] } }), partition: 'aws' });
const doc = (r, suffix) => r.documents.find((d) => d.artifact.endsWith(suffix));
const sev = (d, id) => d.result.findings.filter((f) => f.id === id).map((f) => f.severity);

const cognito = (amr) => P({ Effect: 'Allow', Principal: { Federated: 'cognito-identity.amazonaws.com' },
  Action: 'sts:AssumeRoleWithWebIdentity', Condition: {
    StringEquals: { 'cognito-identity.amazonaws.com:aud': 'us-east-1:11111111-2222-3333-4444-555555555555' },
    'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': amr } } });
const wholeBucket = P({ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::customer-docs/*' },
  { Effect: 'Allow', Action: 's3:List*', Resource: 'arn:aws:s3:::customer-docs' });
const perUser = P({ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::customer-docs/${cognito-identity.amazonaws.com:sub}/*' });

test('Cognito: an authenticated-pool role reading a whole bucket is raised to high', () => {
  const r = run(role('front', cognito('authenticated'), wholeBucket));
  const d = doc(r, 'front#inlinePolicies[p]');
  assert.ok(sev(d, 'DATA-READ').length > 0 && sev(d, 'DATA-READ').every((s) => s === 'high'), sev(d, 'DATA-READ').join(','));
  assert.match(d.result.findings.find((f) => f.id === 'DATA-READ').why, /population-scale/);
  assert.equal(d.result.exitCode, EXIT.FINDINGS);
});

test('Cognito: per-user-scoped resources and non-Cognito trusts are unchanged', () => {
  const scoped = doc(run(role('front', cognito('authenticated'), perUser)), 'front#inlinePolicies[p]');
  assert.ok(!sev(scoped, 'DATA-READ').includes('high'));
  const svc = P({ Effect: 'Allow', Principal: { Service: 'ecs-tasks.amazonaws.com' }, Action: 'sts:AssumeRole' });
  const plain = doc(run(role('task', svc, wholeBucket)), 'task#inlinePolicies[p]');
  assert.ok(!sev(plain, 'DATA-READ').includes('high'));
});

const irsa = { Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-2.amazonaws.com/id/ABC' },
  Action: 'sts:AssumeRoleWithWebIdentity', Condition: { StringEquals: {
    'oidc.eks.us-east-2.amazonaws.com/id/ABC:sub': 'system:serviceaccount:kube-system:controller',
    'oidc.eks.us-east-2.amazonaws.com/id/ABC:aud': 'sts.amazonaws.com' } } };
const pods = (cond) => ({ Effect: 'Allow', Principal: { Service: 'pods.eks.amazonaws.com' }, Action: ['sts:AssumeRole', 'sts:TagSession'], ...(cond ? { Condition: cond } : {}) });
const trustIds = (text) => scan({ text, family: 'role-trust', partition: 'aws' }).findings.map((f) => `${f.id}:${f.severity}`);

test('Pod Identity: an unbound pods.eks statement next to a pinned IRSA sub is low', () => {
  assert.ok(trustIds(P(irsa, pods())).includes('TRUST-POD-IDENTITY-UNBOUND:low'));
  assert.notEqual(scan({ text: P(irsa, pods()), family: 'role-trust', partition: 'aws' }).exitCode, EXIT.FAIL_CLOSED);
});

test('Pod Identity: no finding when bound, without IRSA, or with a wildcard sub', () => {
  assert.ok(!trustIds(P(irsa, pods({ StringEquals: { 'aws:SourceAccount': '111122223333' } }))).some((x) => x.startsWith('TRUST-POD-IDENTITY')));
  assert.ok(!trustIds(P(pods())).some((x) => x.startsWith('TRUST-POD-IDENTITY')));
  const wild = { ...irsa, Condition: { StringLike: { 'oidc.eks.us-east-2.amazonaws.com/id/ABC:sub': 'system:serviceaccount:*' } } };
  assert.ok(!trustIds(P(wild, pods())).some((x) => x.startsWith('TRUST-POD-IDENTITY')));
});

test('Pod Identity: raised to medium when the role can write IAM (Pulumi grouping)', () => {
  const admin = P({ Effect: 'Allow', Action: ['iam:AttachRolePolicy', 'iam:PutRolePolicy'], Resource: '*' });
  const r = run(role('ctrl', P(irsa, pods()), admin));
  assert.deepEqual(sev(doc(r, 'ctrl#assumeRolePolicy'), 'TRUST-POD-IDENTITY-UNBOUND'), ['medium']);
  const readOnly = P({ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/k' });
  assert.deepEqual(sev(doc(run(role('ctrl', P(irsa, pods()), readOnly)), 'ctrl#assumeRolePolicy'), 'TRUST-POD-IDENTITY-UNBOUND'), ['low']);
});
