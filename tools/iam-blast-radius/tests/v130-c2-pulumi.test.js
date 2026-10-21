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

// --- Round-2 review root cause A: only a resource's own computed ARN proves the account ---
const FOREIGN_ROOT = JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${V}:root` }, Action: 'sts:AssumeRole' }] });
const runBare = (...steps) => scanPulumi({ text: JSON.stringify({ steps: [prov, ...steps] }), partition: 'aws' });
const roleCreate = { op: 'create', urn: U('aws:iam/role:Role', 'r'), newState: { urn: U('aws:iam/role:Role', 'r'), type: 'aws:iam/role:Role', inputs: { name: 'r', assumeRolePolicy: FOREIGN_ROOT }, provider: `${PROV}::id1` } };
const trustIds = (r) => r.documents.find((d) => d.artifact.endsWith('r#assumeRolePolicy')).result.findings.map((f) => f.id);

test('A (F-4/G-02): EventTarget and SNS subscription ARNs never prove the account', () => {
  for (const s of [
    step('aws:cloudwatch/eventTarget:EventTarget', 't', { rule: 'x', arn: `arn:aws:events:us-east-1:${V}:event-bus/b` }, { arn: `arn:aws:events:us-east-1:${V}:event-bus/b` }),
    step('aws:sns/topicSubscription:TopicSubscription', 's', { topic: 'x' }, { arn: `arn:aws:sns:us-east-1:${V}:t:sub` }),
    step('aws:sqs/queue:Queue', 'echo', { arn: `arn:aws:sqs:us-east-1:${V}:q` }, { arn: `arn:aws:sqs:us-east-1:${V}:q` }),
  ]) {
    const r = runBare(s, roleCreate);
    assert.ok(!trustIds(r).includes('TRUST-SAME-ACCOUNT'), s.urn);
    assert.notEqual(r.exitCode, EXIT.CLEAN, s.urn);
  }
});

test('A (G-01): stale oldState outputs never carry across a replace or a provider move', () => {
  const P2 = 'urn:pulumi:dev::p::pulumi:providers:aws::other';
  const prov2 = { op: 'update', urn: P2, newState: { urn: P2, type: 'pulumi:providers:aws', inputs: { region: 'us-east-1' } } };
  const urn = U('aws:iam/role:Role', 'r');
  for (const [op, oldProv] of [['update', `${P2}::old`], ['replace', `${PROV}::id1`], ['create-replacement', `${PROV}::id1`]]) {
    const s = { op, urn, newState: { urn, type: 'aws:iam/role:Role', inputs: { name: 'r', assumeRolePolicy: FOREIGN_ROOT }, provider: `${PROV}::id1` },
      oldState: { provider: oldProv, outputs: { arn: `arn:aws:iam::${V}:role/r` } } };
    const r = scanPulumi({ text: JSON.stringify({ steps: [prov, prov2, s] }), partition: 'aws' });
    assert.ok(!trustIds(r).includes('TRUST-SAME-ACCOUNT'), op);
  }
});

// --- Root cause B: the backstop decodes, reports secrets/unknowns, and fails closed past its budget ---
const unmapped = (inputs) => runBare(step('aws:opensearch/domainPolicy:DomainPolicy', 'd', inputs));
const has = (r, code) => r.analysisStates.some((s) => s.code === code);

test('B (F-2): a secret or unknown policy on an unmapped type fails closed', () => {
  assert.ok(has(unmapped({ accessPolicies: '[secret]' }), 'PULUMI_SECRET'));
  assert.ok(has(unmapped({ accessPolicies: { '4dabf18193072939515e22adb298388d': '1b47061264138c4ac30d75fd1eb44270', ciphertext: 'x' } }), 'PULUMI_SECRET'));
  assert.ok(has(unmapped({ accessPolicies: '04da6b54-80e4-46f7-96ec-b56ff0331ba9' }), 'PULUMI_UNKNOWN'));
});

test('B (F-3): a bare statement object (aws-native EventBusPolicy) fails closed', () => {
  const r = runBare(step('aws-native:events:EventBusPolicy', 'eb', { statementId: 's', statement: { Effect: 'Allow', Principal: '*', Action: 'events:PutEvents', Resource: '*' } }));
  assert.ok(has(r, 'PULUMI_UNSUPPORTED_TYPE'));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('B (F-1): an escaped Statement key in a JSON string is still found', () => {
  const r = unmapped({ body: '{"\\u0053tatement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' });
  assert.ok(has(r, 'PULUMI_UNSUPPORTED_TYPE'));
});

test('B (F-5): nesting past the backstop depth fails closed', () => {
  let v = { Effect: 'Allow', Action: '*' };
  for (let i = 0; i < 40; i++) v = { n: v };
  assert.ok(has(unmapped({ cfg: v }), 'PULUMI_LIMIT'));
});

// --- Round-3 review: H-1 (adopted foreign resources), H-2 (YAML text), H-3 (provider id) ---
test('H-1: an imported or ARN-adoptable resource never proves the account', () => {
  const topic = (op) => ({ op, urn: U('aws:sns/topic:Topic', 'shared'),
    newState: { urn: U('aws:sns/topic:Topic', 'shared'), type: 'aws:sns/topic:Topic', inputs: { name: 'shared' }, outputs: { arn: `arn:aws:sns:us-east-2:${V}:shared` }, provider: `${PROV}::id1` } });
  for (const op of ['update', 'import']) {
    const r = runBare(topic(op), roleCreate, perm({ principal: V }));
    assert.ok(!trustIds(r).includes('TRUST-SAME-ACCOUNT'), op);
    assert.ok(!r.unanalyzed.some((u) => u.reason === 'own-account-principal'), op);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, op);
  }
  const imported = { ...proof, op: 'import' };
  assert.ok(runBare(imported, roleCreate).analysisStates.some((s) => s.code === 'PULUMI_ACCOUNT_UNRESOLVED'));
});

test('H-2: an IAM policy in YAML text fails closed; non-policy text does not', () => {
  const cfn = 'Resources:\n  P:\n    Type: AWS::IAM::ManagedPolicy\n    Properties:\n      PolicyDocument:\n        Statement:\n          - Effect: Allow\n            Action: "*"\n            Resource: "*"\n';
  assert.ok(has(runBare(step('aws:cloudformation/stack:Stack', 'cfn', { name: 'x', templateBody: cfn })), 'PULUMI_UNSUPPORTED_TYPE'));
  const quiet = runBare(step('aws:cloudwatch/dashboard:Dashboard', 'd', { dashboardBody: 'This statement has no effect on anything.' }));
  assert.ok(!has(quiet, 'PULUMI_UNSUPPORTED_TYPE'));
});

test('H-3: prior outputs are not reused across a provider id change', () => {
  const urn = U('aws:iam/role:Role', 'r');
  const s = { op: 'update', urn, newState: { urn, type: 'aws:iam/role:Role', inputs: { name: 'r', assumeRolePolicy: FOREIGN_ROOT }, provider: `${PROV}::id2` },
    oldState: { provider: `${PROV}::id1`, outputs: { arn: `arn:aws:iam::${V}:role/r` } } };
  assert.ok(!trustIds(runBare(s)).includes('TRUST-SAME-ACCOUNT'));
});
