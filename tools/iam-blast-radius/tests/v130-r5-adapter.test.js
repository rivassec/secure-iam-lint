// v1.3.0 real-stack round: R5-1 (components), R5-2 (new mapped types), R5-4 (provider-account mapping).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scanPulumi } from '../../../cli/pulumi.mjs';
import { run } from '../../../cli/iam-br.mjs';
import { runAction } from '../../../action/index.mjs';
import { EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const V = '444455556666';
const STACK = 'urn:pulumi:dev::p::pulumi:pulumi:Stack::p-dev';
const PROV = 'urn:pulumi:dev::p::pulumi:providers:aws::aws';
const PROV_B = 'urn:pulumi:dev::p::pulumi:providers:aws::acct-b';
const U = (type, name) => `urn:pulumi:dev::p::${type}::${name}`;
const res = (type, name, inputs, extra = {}) => ({ urn: U(type, name), type, custom: true, inputs, outputs: {}, provider: `${PROV}::id1`, ...extra });
const prov = (urn, inputs = { region: 'us-east-1' }) => ({ urn, type: 'pulumi:providers:aws', custom: true, inputs, outputs: {} });
const exportOf = (...resources) => JSON.stringify({ version: 3, deployment: { resources: [
  { urn: STACK, type: 'pulumi:pulumi:Stack', custom: false, inputs: {}, outputs: {} }, prov(PROV), ...resources] } });
// An IAM role whose ARN proves the stack account.
const proof = res('aws:iam/role:Role', 'proof', { name: 'proof', assumeRolePolicy: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }] }) }, { outputs: { arn: `arn:aws:iam::${ACCT}:role/proof` } });
const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const ADMIN = P({ Effect: 'Allow', Action: '*', Resource: '*' });
const codes = (r) => [...r.analysisStates.map((s) => s.code), ...r.documents.flatMap((d) => d.result.analysisStates.map((s) => s.code))];

test('R5-1: a component repeating its child role policy is skipped; the child is analyzed', () => {
  const trust = P({ Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::111122223333:oidc-provider/oidc.eks' }, Action: 'sts:AssumeRoleWithWebIdentity' });
  const comp = { urn: U('components:index:Autoscaler', 'karp'), type: 'components:index:Autoscaler', custom: false, inputs: { assume_role_policy_document: trust } };
  const child = res('aws:iam/role:Role', 'karp-role', { name: 'karp-role', assumeRolePolicy: trust }, { parent: comp.urn });
  const r = scanPulumi({ text: exportOf(proof, comp, child), partition: 'aws' });
  assert.ok(!codes(r).includes('PULUMI_UNSUPPORTED_TYPE'), codes(r).join(','));
  assert.equal(r.documents.filter((d) => d.artifact.includes('karp')).length, 1);
  assert.ok(r.documents.some((d) => d.artifact.endsWith('karp-role#assumeRolePolicy')));
});

test('R5-1: a provider type marked as a component is malformed; a missing custom flag stays custom', () => {
  const fake = { ...res('aws:iam/policy:Policy', 'p', { policy: ADMIN }), custom: false };
  assert.ok(codes(scanPulumi({ text: exportOf(proof, fake), partition: 'aws' })).includes('PULUMI_MALFORMED'));
  const noFlag = res('aws:iam/policy:Policy', 'q', { policy: ADMIN });
  delete noFlag.custom;
  const r = scanPulumi({ text: exportOf(proof, noFlag), partition: 'aws' });
  assert.ok(r.documents.some((d) => d.artifact.endsWith('q#policy')));
  assert.equal(r.exitCode, EXIT.FINDINGS);
});

test('R5-2: the five real-state policy types are mapped, never UNSUPPORTED_TYPE, and never read clean when risky', () => {
  const pub = P({ Effect: 'Allow', Principal: '*', Action: '*', Resource: '*' });
  for (const [type, inputs, prop, family] of [
    ['aws:ssoadmin/permissionSetInlinePolicy:PermissionSetInlinePolicy', { instanceArn: 'arn:aws:sso:::instance/ssoins-1', permissionSetArn: 'arn:aws:sso:::permissionSet/ssoins-1/ps-1', inlinePolicy: ADMIN }, 'inlinePolicy', 'identity'],
    ['aws:ecr/registryPolicy:RegistryPolicy', { policy: pub }, 'policy', 'resource'],
    ['aws:ecr/repositoryCreationTemplate:RepositoryCreationTemplate', { prefix: 'app', appliedFors: ['PULL_THROUGH_CACHE'], repositoryPolicy: pub }, 'repositoryPolicy', 'resource'],
    ['aws:cloudwatch/logResourcePolicy:LogResourcePolicy', { policyName: 'p', policyDocument: pub }, 'policyDocument', 'resource'],
    ['aws:dynamodb/resourcePolicy:ResourcePolicy', { resourceArn: `arn:aws:dynamodb:us-east-1:${ACCT}:table/t`, policy: pub }, 'policy', 'resource'],
  ]) {
    const r = scanPulumi({ text: exportOf(proof, res(type, 'x', inputs)), partition: 'aws' });
    const d = r.documents.find((x) => x.artifact.endsWith(`x#${prop}`));
    assert.ok(d, type);
    assert.equal(d.family, family, type);
    assert.ok(!codes(r).includes('PULUMI_UNSUPPORTED_TYPE'), type);
    assert.notEqual(r.exitCode, EXIT.CLEAN, type);
  }
});

test('R5-4: a provider-account mapping resolves an unproven provider and shows in providers[]', () => {
  const text = exportOf(prov(PROV_B, { region: 'us-east-1', profile: 'acct-b-admin' }),
    res('aws:iam/policy:Policy', 'b', { policy: P({ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::bkt/key' }) }, { provider: `${PROV_B}::id2` }));
  assert.ok(codes(scanPulumi({ text, partition: 'aws' })).includes('PULUMI_ACCOUNT_UNRESOLVED'));
  for (const key of ['acct-b', PROV_B]) {
    const r = scanPulumi({ text, partition: 'aws', providerAccounts: [{ key, account: V }] });
    assert.ok(!codes(r).includes('PULUMI_ACCOUNT_UNRESOLVED'), key);
    const p = r.providers.find((x) => x.urn === PROV_B);
    assert.equal(p.account, V);
    assert.equal(p.accountProven, false); // an assertion, not proof
    assert.equal(p.evidence.mapped, V);
  }
});

test('R5-4: a mapping that contradicts the stack is a mismatch; bad entries are usage', () => {
  const r = scanPulumi({ text: exportOf(proof, res('aws:iam/policy:Policy', 'q', { policy: ADMIN })), partition: 'aws', providerAccounts: [{ key: 'aws', account: V }] });
  assert.ok(codes(r).includes('PULUMI_ACCOUNT_MISMATCH'));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  const text = exportOf(proof);
  for (const providerAccounts of [[{ key: 'nope', account: V }], [{ key: 'aws', account: '12' }], [{ key: 'aws', account: ACCT }, { key: PROV, account: V }]]) {
    assert.equal(scanPulumi({ text, partition: 'aws', providerAccounts }).exitCode, EXIT.USAGE, JSON.stringify(providerAccounts));
  }
});

test('R5-4: a mapping never proves a same-account trust', () => {
  const foreignTrust = P({ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${V}:root` }, Action: 'sts:AssumeRole' });
  const text = exportOf(prov(PROV_B, { region: 'us-east-1', profile: 'b' }),
    res('aws:iam/role:Role', 'r', { name: 'r', assumeRolePolicy: foreignTrust }, { provider: `${PROV_B}::id2` }));
  const r = scanPulumi({ text, partition: 'aws', providerAccounts: [{ key: 'acct-b', account: V }] });
  const d = r.documents.find((x) => x.artifact.endsWith('r#assumeRolePolicy'));
  assert.ok(!d.result.findings.some((f) => f.id === 'TRUST-SAME-ACCOUNT'));
});

test('R5-4: CLI --provider-account and the Action input; misuse is usage', async () => {
  const text = exportOf(proof);
  const io = { readFile: () => text, stdout: () => {}, stderr: () => {} };
  assert.equal(await run(['--input', 'pulumi', '--partition', 'aws', '--provider-account', `aws=${ACCT}`, 'x.json'], io), EXIT.CLEAN);
  assert.equal(await run(['--input', 'pulumi', '--provider-account', 'novalue', 'x.json'], io), EXIT.USAGE);
  assert.equal(await run(['--family', 'identity', '--provider-account', `aws=${ACCT}`, 'x.json'], io), EXIT.USAGE);
  const files = { 'export.json': text };
  const aio = { readFile: (rel) => { if (!(rel in files)) throw new Error('ENOENT'); return files[rel]; }, listFiles: () => Object.keys(files) };
  const env = { 'INPUT_PULUMI-JSON': 'export.json', INPUT_PARTITION: 'aws', 'INPUT_PROVIDER-ACCOUNTS': `aws=${ACCT}\n` };
  assert.equal(runAction({ env, io: aio }).exitCode, EXIT.CLEAN);
  assert.equal(runAction({ env: { ...env, 'INPUT_PROVIDER-ACCOUNTS': 'nope=111122223333' }, io: aio }).exitCode, EXIT.USAGE);
  assert.equal(runAction({ env: { INPUT_PATHS: 'export.json', INPUT_FAMILY: 'identity', 'INPUT_PROVIDER-ACCOUNTS': `aws=${ACCT}` }, io: aio }).exitCode, EXIT.USAGE);
});

// --- Round-5 review I-1: a component skip must be provably safe ---
test('I-1: component skip needs children that repeat its policies; URN type must match', async () => {
  const { scanPulumi: sp } = await import('../../../cli/pulumi.mjs');
  const PRV = 'urn:pulumi:dev::p::pulumi:providers:aws::aws';
  const pub = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole' }] };
  const svc = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' }, Action: 'sts:AssumeRole' }] };
  const comp = (type, policy) => ({ urn: `urn:pulumi:dev::p::${type}::c`, type, custom: false, inputs: { doc: policy } });
  const child = (policy) => ({ urn: 'urn:pulumi:dev::p::x:index:C$aws:iam/role:Role::r', type: 'aws:iam/role:Role', custom: true,
    parent: 'urn:pulumi:dev::p::x:index:C::c', provider: `${PRV}::id1`, inputs: { name: 'r', assumeRolePolicy: JSON.stringify(policy) }, outputs: {} });
  const run = (...res) => sp({ text: JSON.stringify({ deployment: { resources: [{ urn: PRV, type: 'pulumi:providers:aws', custom: true, inputs: { region: 'us-east-1' } }, ...res] } }), partition: 'aws' });
  const codes = (r) => r.analysisStates.map((s) => s.code);
  // A real component whose child repeats the policy: skipped cleanly.
  assert.ok(!codes(run(comp('x:index:C', svc), child(svc))).includes('PULUMI_UNSUPPORTED_TYPE'));
  // The child does not carry the component's policy: fail closed.
  assert.ok(codes(run(comp('x:index:C', pub), child(svc))).includes('PULUMI_UNSUPPORTED_TYPE'));
  // No children: the backstop runs.
  assert.ok(codes(run(comp('x:index:C', pub))).includes('PULUMI_UNSUPPORTED_TYPE'));
  // A type that disagrees with the URN: malformed.
  const bad = { ...comp('x:index:C', svc), type: 'pulumi-nodejs:dynamic:Resource' };
  assert.ok(codes(run(bad, child(svc))).includes('PULUMI_MALFORMED'));
});
