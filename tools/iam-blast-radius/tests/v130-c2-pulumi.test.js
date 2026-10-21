// v1.3.0 round-2 interim: R2-1 (backstop shape), R2-2 (report evidence), Lambda permissions (option d).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scanPulumi } from '../../../cli/pulumi.mjs';
import { toPulumiJsonReport } from '../../../cli/iam-br.mjs';
import { EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const V = '444455556666';
const PROV = 'urn:pulumi:dev::p::pulumi:providers:aws::aws';
const U = (type, name) => `urn:pulumi:dev::p::${type}::${name}`;
const prov = { op: 'update', urn: PROV, newState: { urn: PROV, type: 'pulumi:providers:aws', inputs: { region: 'us-east-1' } } };
const step = (type, name, inputs, outputs) => {
  const urn = U(type, name);
  return { op: 'update', urn, newState: { urn, type, inputs, provider: `${PROV}::id1` }, oldState: { outputs: outputs || {} } };
};
// A managed role whose ARN proves the stack account.
const proof = step('aws:iam/role:Role', 'proof', {}, { arn: `arn:aws:iam::${ACCT}:role/proof` });
const run = (...steps) => scanPulumi({ text: JSON.stringify({ steps: [prov, proof, ...steps] }), partition: 'aws' });
const codes = (r) => r.analysisStates.map((s) => `${s.code}@${s.path}`);

test('R2-1: a WAFv2 rule `statement` is not a policy document', () => {
  const waf = step('aws:wafv2/webAcl:WebAcl', 'acl', { rules: [{ name: 'r', statement: { byteMatchStatement: { searchString: 'x' } } }] });
  assert.ok(!codes(run(waf)).some((c) => c.startsWith('PULUMI_UNSUPPORTED_TYPE')), codes(run(waf)).join(' '));
});

test('R2-1: a real IAM document under an unmapped property still fails closed', () => {
  const doc = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] };
  for (const v of [doc, JSON.stringify(doc), { Statement: { Effect: 'Allow', Action: 's3:*' } }, '{"Statement": [{"Effect": "Allow"']) {
    const r = run(step('aws:foo/bar:Bar', 'b', { somethingElse: v }));
    assert.ok(codes(r).some((c) => c.startsWith('PULUMI_UNSUPPORTED_TYPE')), JSON.stringify(v).slice(0, 40));
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  }
});

test('R2-2: the Pulumi report shows the subject account and per-provider evidence', () => {
  const r = run();
  const rep = toPulumiJsonReport(r, { subjectAccount: ACCT, partition: 'aws' });
  assert.equal(rep.subjectAccountAsserted, ACCT);
  const p = rep.providers.find((x) => x.urn === PROV);
  assert.equal(p.account, ACCT);
  assert.equal(p.accountProven, true);
  assert.deepEqual(p.evidence.arnAccounts, [ACCT]);
});

const perm = (inputs) => step('aws:lambda/permission:Permission', 'perm', { action: 'lambda:InvokeFunction', function: 'f', ...inputs });
const unmodeled = (r) => codes(r).some((c) => c.startsWith('PULUMI_UNMODELED_PERMISSION'));

test('Lambda permission: risky shapes fail closed', () => {
  for (const inputs of [
    { principal: '*' },
    { principal: V },
    { principal: `arn:aws:iam::${V}:root` },
    { principal: 'apigateway.amazonaws.com' },
    { principal: '*', sourceAccount: V },
  ]) {
    const r = run(perm(inputs));
    assert.ok(unmodeled(r), JSON.stringify(inputs));
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  }
  assert.ok(codes(run(perm({ principal: '04da6b54-80e4-46f7-96ec-b56ff0331ba9' }))).some((c) => c.startsWith('PULUMI_UNKNOWN')));
});

test('Lambda permission: source-bound, org-scoped and own-account grants are listed, not failed', () => {
  for (const [inputs, reason] of [
    [{ principal: 'apigateway.amazonaws.com', sourceArn: `arn:aws:execute-api:us-east-1:${ACCT}:abc/*` }, 'service-principal-source-bound'],
    [{ principal: 's3.amazonaws.com', sourceAccount: ACCT }, 'service-principal-source-bound'],
    [{ principal: '*', principalOrgId: 'o-abcdefghij' }, 'org-scoped'],
    [{ principal: ACCT }, 'own-account-principal'],
    [{ principal: '*', sourceAccount: ACCT }, 'source-account-bound'],
  ]) {
    const r = run(perm(inputs));
    assert.ok(!unmodeled(r), JSON.stringify(inputs));
    assert.deepEqual(r.unanalyzed.map((u) => u.reason), [reason], JSON.stringify(inputs));
  }
});

test('Lambda permission: own-account needs a proven account, not just --subject-account', () => {
  const text = JSON.stringify({ steps: [prov, perm({ principal: ACCT })] });
  assert.ok(scanPulumi({ text, partition: 'aws', subjectAccount: ACCT }).analysisStates.some((s) => s.code === 'PULUMI_UNMODELED_PERMISSION'));
});
