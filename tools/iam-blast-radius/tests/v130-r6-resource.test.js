// v1.3.0 R6-1: ECR repository, Secrets Manager secret and DynamoDB table resource policies.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const A = '111122223333';
const V = '444455556666';
const ARN = {
  ecr: `arn:aws:ecr:us-east-1:${A}:repository/app`,
  sm: `arn:aws:secretsmanager:us-east-1:${A}:secret:db-AbCdEf`,
  ddb: `arn:aws:dynamodb:us-east-1:${A}:table/orders`,
};
const ACT = {
  ecr: { read: 'ecr:BatchGetImage', write: 'ecr:PutImage', policy: 'ecr:SetRepositoryPolicy', svc: 'lambda.amazonaws.com' },
  sm: { read: 'secretsmanager:GetSecretValue', write: 'secretsmanager:PutSecretValue', policy: 'secretsmanager:PutResourcePolicy', svc: 'events.amazonaws.com' },
  ddb: { read: 'dynamodb:Query', write: 'dynamodb:PutItem', policy: 'dynamodb:PutResourcePolicy', svc: 'events.amazonaws.com' },
};
const run = (svc, st, version = '2012-10-17') => scan({
  text: JSON.stringify({ Version: version, Statement: Array.isArray(st) ? st : [st] }),
  family: 'resource', partition: 'aws', resourceContext: { arn: ARN[svc] },
});
const ids = (r) => [...new Set(r.findings.map((f) => `${f.id}:${f.severity}`))];
const has = (r, id) => r.findings.some((f) => f.id === id);
const codes = (r) => (r.analysisStates || []).map((s) => s.code);

for (const svc of ['ecr', 'sm', 'ddb']) {
  const a = ACT[svc];
  test(`${svc}: public read and write are critical and name the data vector`, () => {
    for (const act of [a.read, a.write]) {
      const r = run(svc, { Effect: 'Allow', Principal: '*', Action: act, Resource: ARN[svc] });
      assert.equal(r.exitCode, EXIT.FINDINGS, act);
      assert.ok(ids(r).includes('PUBLIC-ACCESS:critical'), ids(r).join(','));
      assert.ok(has(r, 'RESOURCE-DATA-EXPOSURE'), act);
    }
  });
  test(`${svc}: cross-account is high; a policy write adds takeover`, () => {
    const x = run(svc, { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${V}:root` }, Action: a.read, Resource: ARN[svc] });
    assert.ok(ids(x).includes('RESOURCE-CROSS-ACCOUNT:high'));
    const p = run(svc, { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${V}:root` }, Action: a.policy, Resource: ARN[svc] });
    assert.ok(ids(p).includes('RESOURCE-POLICY-TAKEOVER:high'));
    const pub = run(svc, { Effect: 'Allow', Principal: '*', Action: `${a.policy.split(':')[0]}:*`, Resource: ARN[svc] });
    assert.ok(ids(pub).includes('RESOURCE-POLICY-TAKEOVER:critical'));
  });
  test(`${svc}: same-account grant is medium and complete`, () => {
    const r = run(svc, { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${A}:role/app` }, Action: a.read, Resource: ARN[svc] });
    assert.deepEqual(ids(r), ['RESOURCE-SAME-ACCOUNT-GRANT:medium']);
    assert.equal(r.exitCode, EXIT.CLEAN);
  });
  test(`${svc}: service principal with and without a source binding`, () => {
    const st = { Effect: 'Allow', Principal: { Service: a.svc }, Action: a.read, Resource: ARN[svc] };
    const unbound = run(svc, st);
    assert.ok(unbound.findings.some((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY' && f.severity !== 'info'), ids(unbound).join(','));
    const bound = run(svc, { ...st, Condition: { StringEquals: { 'aws:SourceAccount': A } } });
    assert.ok(!bound.findings.some((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY' && f.severity !== 'info'), ids(bound).join(','));
  });
  test(`${svc}: an org-scoped "*" is narrowed, not public`, () => {
    const r = run(svc, { Effect: 'Allow', Principal: '*', Action: a.read, Resource: ARN[svc], Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-abcdefghij' } } });
    assert.ok(!ids(r).includes('PUBLIC-ACCESS:critical'), ids(r).join(','));
    assert.ok(!has(r, 'RESOURCE-DATA-EXPOSURE'));
  });
  test(`${svc}: an unclassified action or a foreign Resource fails closed`, () => {
    const ns = a.read.split(':')[0];
    const u = run(svc, { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${A}:role/app` }, Action: `${ns}:NoSuchAction`, Resource: ARN[svc] });
    assert.equal(u.exitCode, EXIT.FAIL_CLOSED);
    const other = ARN[svc].replace(/app$|db-AbCdEf$|orders$/, 'other');
    const m = run(svc, { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${A}:role/app` }, Action: a.read, Resource: other });
    assert.equal(m.exitCode, EXIT.FAIL_CLOSED);
    assert.ok(codes(m).includes('RESOURCE_CONTEXT_REQUIRED'));
  });
}

test('real shape: ECR cross-account pull policy (2008 Version, no variables) is analyzed', () => {
  const r = run('ecr', { Sid: 'pull', Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${V}:root` },
    Action: ['ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer', 'ecr:BatchCheckLayerAvailability'] }, '2008-10-17');
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.deepEqual(ids(r), ['RESOURCE-CROSS-ACCOUNT:high']);
});

test('real shape: Secrets Manager same-account policy with Resource "*" is complete', () => {
  const r = run('sm', { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${A}:role/app` }, Action: 'secretsmanager:GetSecretValue', Resource: '*' });
  assert.equal(r.exitCode, EXIT.CLEAN);
});

test('DynamoDB: index and stream sub-resources of the attached table are accepted', () => {
  const r = run('ddb', { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${A}:role/app` }, Action: ['dynamodb:Query', 'dynamodb:GetRecords'],
    Resource: [ARN.ddb, `${ARN.ddb}/index/*`, `${ARN.ddb}/stream/*`] });
  assert.equal(r.exitCode, EXIT.CLEAN);
});

test('a stream or wildcard ARN as the attached resource stays unsupported', () => {
  for (const arn of [`${ARN.ddb}/stream/2026`, `arn:aws:ecr:us-east-1:${A}:repository/*`]) {
    const r = scan({ text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: '*', Action: '*' }] }),
      family: 'resource', partition: 'aws', resourceContext: { arn } });
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, arn);
  }
});

// --- pack s calibration (real-estate findings) ---
const ORG = 'o-exampleorg1';
test('R6 s: an org-scoped "*" on these services is cross-account within the org, not public', () => {
  for (const svc of ['ecr', 'sm', 'ddb']) {
    const r = run(svc, { Effect: 'Allow', Principal: { AWS: '*' }, Action: ACT[svc].read, Resource: ARN[svc], Condition: { StringEquals: { 'aws:PrincipalOrgID': ORG } } });
    assert.ok(!has(r, 'PUBLIC-ACCESS'), svc);
    assert.ok(ids(r).includes('RESOURCE-CROSS-ACCOUNT:high'), ids(r).join(','));
    assert.equal(r.exitCode, EXIT.FINDINGS);
  }
});

test('R6 s: a ForAllValues guard on a source-only key is vacuous for IAM callers', () => {
  const r = run('ecr', { Effect: 'Allow', Principal: { AWS: '*' }, Action: ['ecr:PutImage', 'ecr:UploadLayerPart'], Resource: ARN.ecr,
    Condition: { ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/github' }, StringEquals: { 'aws:PrincipalOrgID': ORG },
      'ForAllValues:StringNotLike': { 'aws:SourceOrgPaths': [`${ORG}/r-ab12/ou-ab12-sandbox/*`] } } });
  assert.equal(r.exitCode, EXIT.FINDINGS);
  const f = r.findings.find((x) => x.id === 'RESOURCE-CROSS-ACCOUNT');
  assert.ok(f && f.severity === 'high' && /constrains nothing/.test(f.why));
  // ForAnyValue on the same absent key is not vacuous-true: still unmodeled.
  const any = run('ecr', { Effect: 'Allow', Principal: { AWS: '*' }, Action: 'ecr:PutImage', Resource: ARN.ecr,
    Condition: { StringEquals: { 'aws:PrincipalOrgID': ORG }, 'ForAnyValue:StringNotLike': { 'aws:SourceOrgPaths': ['x/*'] } } });
  assert.equal(any.exitCode, EXIT.FAIL_CLOSED);
});

test('R6 s: a service grant bound by aws:SourceOrgID is source-bound', () => {
  const r = run('ecr', { Effect: 'Allow', Principal: { Service: ['lambda.amazonaws.com'] }, Action: 'ecr:BatchGetImage', Resource: ARN.ecr,
    Condition: { StringEquals: { 'aws:SourceOrgID': ORG } } });
  assert.ok(!has(r, 'RESOURCE-CONFUSED-DEPUTY'));
  assert.notEqual(r.exitCode, EXIT.FAIL_CLOSED);
});

test('R6 s: an exact aws:PrincipalArn pin lowers a cross-account grant to medium', () => {
  const st = { Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${V}:root` }, Action: 'secretsmanager:GetSecretValue', Resource: '*' };
  assert.ok(ids(run('sm', st)).includes('RESOURCE-CROSS-ACCOUNT:high'));
  const pinned = run('sm', { ...st, Condition: { ArnEquals: { 'aws:PrincipalArn': `arn:aws:iam::${V}:role/reader` } } });
  assert.deepEqual(ids(pinned), ['RESOURCE-CROSS-ACCOUNT:medium']);
  const glob = run('sm', { ...st, Condition: { ArnLike: { 'aws:PrincipalArn': `arn:aws:iam::${V}:role/*` } } });
  assert.ok(ids(glob).includes('RESOURCE-CROSS-ACCOUNT:high'), ids(glob).join(','));
});
