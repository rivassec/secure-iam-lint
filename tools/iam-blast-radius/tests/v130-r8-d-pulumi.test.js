// v1.3.0 round 8, lane D: Pulumi resource context from the type (E-3), Lambda permissions as
// per-document verdicts (E-4), multi-account subject-account warning (E-5). Shapes mirror the
// trial bundle's pulumi/e3, e4, e5 and e7 exports (synthetic accounts).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scanPulumi, extractPulumiDocuments, pulumiUnits } from '../../../cli/pulumi.mjs';
import { run, toPulumiJsonReport } from '../../../cli/iam-br.mjs';
import { scan, EXIT } from '../../../cli/scan.mjs';
import { buildAggregateSarif } from '../../../action/action-aggregate.mjs';

const A = '111111111111';
const B = '222222222222';
const PA = 'urn:pulumi:syn::syn-fx::pulumi:providers:aws::a';
const PB = 'urn:pulumi:syn::syn-fx::pulumi:providers:aws::b';
const U = (type, name) => `urn:pulumi:syn::syn-fx::${type}::${name}`;
const provider = (urn, region = 'us-east-2') => ({ urn, custom: true, id: 'p', type: 'pulumi:providers:aws', inputs: { region }, outputs: { region } });
const res = (type, name, inputs, outputs = {}, prov = PA) => ({ urn: U(type, name), custom: true, id: name, type, inputs, outputs: { ...inputs, ...outputs }, provider: `${prov}::p` });
const exportOf = (...resources) => JSON.stringify({ version: 3, deployment: { resources: [provider(PA), ...resources] } });
const pol = (...Statement) => JSON.stringify({ Version: '2012-10-17', Statement });
const doc = (r, suffix) => r.documents.find((d) => d.artifact.endsWith(suffix));
const codes = (d) => d.result.analysisStates.map((s) => s.code);
const ids = (d) => d.result.findings.map((f) => `${f.id}/${f.severity}`);

// --- E-3 ---
const REG = res('aws:ecr/registryPolicy:RegistryPolicy', 'regpol', { policy: pol({ Sid: 'Repl', Effect: 'Allow',
  Principal: { AWS: `arn:aws:iam::${B}:root` }, Action: ['ecr:ReplicateImage', 'ecr:CreateRepository'], Resource: `arn:aws:ecr:us-east-2:${A}:repository/*` }) });
const LOGS = res('aws:cloudwatch/logResourcePolicy:LogResourcePolicy', 'logpol', { policyName: 'route53-logs', policyDocument: pol({ Effect: 'Allow',
  Principal: { Service: 'route53.amazonaws.com' }, Action: ['logs:CreateLogStream', 'logs:PutLogEvents'], Resource: `arn:aws:logs:us-east-1:${A}:log-group:/aws/route53/*` }) });
const tmpl = (prefix, policy) => res('aws:ecr/repositoryCreationTemplate:RepositoryCreationTemplate', 'tmpl', { ...(prefix === undefined ? {} : { prefix }),
  appliedFors: ['PULL_THROUGH_CACHE'], repositoryPolicy: policy || pol({ Sid: 'OrgPull', Effect: 'Allow', Principal: '*', Action: ['ecr:BatchGetImage', 'ecr:GetDownloadUrlForLayer'],
    Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-exampleorg' } } }) });
// A managed role whose ARN proves the provider account.
const PROOF = res('aws:iam/role:Role', 'proof', { name: 'proof', assumeRolePolicy: pol({ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }) },
  { arn: `arn:aws:iam::${A}:role/proof` });
const opts = { partition: 'aws', subjectAccount: A, providerAccounts: [{ key: PA, account: A }] };

test('E-3: without account proof each document fails closed on its own (bundle e3)', () => {
  const r = scanPulumi({ text: exportOf(REG, LOGS, tmpl('ROOT')), ...opts });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.deepEqual(r.analysisStates, [], 'no run-level state');
  for (const s of ['regpol#policy', 'logpol#policyDocument', 'tmpl#repositoryPolicy']) {
    assert.ok(codes(doc(r, s)).includes('PULUMI_CONTEXT_UNPROVEN'), s);
    assert.ok(codes(doc(r, s)).includes('RESOURCE_CONTEXT_REQUIRED'), s);
  }
  // subject-account / provider-account name an account but never prove it.
  assert.ok(extractPulumiDocuments(exportOf(REG), opts).documents.every((d) => !d.resourceContext.arn));
});

test('E-3: a proven account gives the registry, template and logs context', () => {
  const ext = extractPulumiDocuments(exportOf(PROOF, REG, LOGS, tmpl('ROOT')), opts);
  const ctx = (s) => ext.documents.find((d) => d.artifact.endsWith(s)).resourceContext;
  assert.deepEqual(ctx('regpol#policy'), { type: 'ecr-registry', arn: `arn:aws:ecr:us-east-2:${A}:repository/*`, account: A });
  assert.deepEqual(ctx('tmpl#repositoryPolicy'), { type: 'ecr-registry', arn: `arn:aws:ecr:us-east-2:${A}:repository/*`, account: A });
  assert.deepEqual(ctx('logpol#policyDocument'), { type: 'logs', arn: `arn:aws:logs:us-east-2:${A}:*`, account: A });
  const prefixed = extractPulumiDocuments(exportOf(PROOF, tmpl('prod/')), opts).documents.find((d) => d.artifact.endsWith('tmpl#repositoryPolicy'));
  assert.equal(prefixed.resourceContext.arn, `arn:aws:ecr:us-east-2:${A}:repository/prod/*`);
});

test('E-3: the cross-account replication grant is now analyzed and reported', () => {
  const r = scanPulumi({ text: exportOf(PROOF, REG, LOGS, tmpl('ROOT')), ...opts });
  assert.ok(ids(doc(r, 'regpol#policy')).includes('RESOURCE-CROSS-ACCOUNT/high'));
  assert.ok(ids(doc(r, 'tmpl#repositoryPolicy')).includes('RESOURCE-CROSS-ACCOUNT/high'));
  assert.equal(doc(r, 'tmpl#repositoryPolicy').result.exitCode, EXIT.FINDINGS);
  // Registry-level actions are not classified by the ECR evaluator: still exit 3 for that document.
  assert.equal(doc(r, 'regpol#policy').result.exitCode, EXIT.FAIL_CLOSED);
  // CloudWatch Logs resource policies are not modeled by the engine: unsupported, per document.
  assert.ok(codes(doc(r, 'logpol#policyDocument')).includes('UNSUPPORTED_RESOURCE_SHAPE'));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('E-3: a public template policy is a finding, not a blocked run', () => {
  const pub = pol({ Effect: 'Allow', Principal: '*', Action: ['ecr:BatchGetImage'] });
  const r = scanPulumi({ text: exportOf(PROOF, tmpl('ROOT', pub)), ...opts });
  assert.ok(ids(doc(r, 'tmpl#repositoryPolicy')).includes('PUBLIC-ACCESS/critical'));
  assert.equal(r.exitCode, EXIT.FINDINGS);
});

test('E-3: a bad, missing or unknown template prefix fails closed', () => {
  for (const [p, code] of [['Bad Prefix', 'PULUMI_PROPERTY_INVALID'], ['a*', 'PULUMI_PROPERTY_INVALID'], [undefined, 'PULUMI_PROPERTY_MISSING'],
    ['04da6b54-80e4-46f7-96ec-b56ff0331ba9', 'PULUMI_UNKNOWN']]) {
    const r = scanPulumi({ text: exportOf(PROOF, tmpl(p)), ...opts });
    const d = doc(r, 'tmpl#repositoryPolicy');
    assert.ok(codes(d).includes(code), `${p}: ${codes(d)}`);
    assert.equal(d.result.exitCode, EXIT.FAIL_CLOSED);
  }
});

test('E-3: a resource-level region wins over the provider region; a bad region is not used', () => {
  const regIn = (region) => res('aws:ecr/registryPolicy:RegistryPolicy', 'regpol', { region, policy: JSON.parse(REG.inputs.policy) });
  const ctx = (region) => extractPulumiDocuments(exportOf(PROOF, regIn(region)), opts).documents.find((d) => d.artifact.endsWith('regpol#policy')).resourceContext;
  assert.equal(ctx('eu-west-1').arn, `arn:aws:ecr:eu-west-1:${A}:repository/*`);
  assert.equal(ctx('cn-north-1').arn, undefined); // partition mismatch: never inferred
});

test('E-3 engine: a registry-wide repository ARN needs the explicit ecr-registry hint', () => {
  const text = pol({ Effect: 'Allow', Principal: '*', Action: 'ecr:BatchGetImage' });
  const go = (type, arn) => scan({ text, family: 'resource', partition: 'aws', resourceContext: { type, arn } });
  assert.equal(go('ecr-registry', `arn:aws:ecr:us-east-1:${A}:repository/*`).exitCode, EXIT.FINDINGS);
  assert.equal(go('ecr-registry', `arn:aws:ecr:us-east-1:${A}:repository/team/*`).exitCode, EXIT.FINDINGS);
  for (const [type, arn] of [[undefined, `arn:aws:ecr:us-east-1:${A}:repository/*`], ['ecr', `arn:aws:ecr:us-east-1:${A}:repository/*`],
    ['ecr-registry', `arn:aws:ecr:us-east-1:${A}:repository/p*`], ['ecr-registry', `arn:aws:ecr:us-east-1:${A}:*`],
    ['ecr-registry', `arn:aws:s3:::bucket/*`]]) {
    assert.equal(go(type, arn).exitCode, EXIT.FAIL_CLOSED, `${type} ${arn}`);
  }
});

// --- E-4 / e7 ---
const ROLE = res('aws:iam/role:Role', 'fnrole', { name: 'fnrole', assumeRolePolicy: pol({ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }) });
const FN = res('aws:lambda/function:Function', 'fn', { name: 'fn', role: `arn:aws:iam::${A}:role/fnrole` });
const perm = (inputs) => res('aws:lambda/permission:Permission', 'fn-perm', { action: 'lambda:InvokeFunction', function: 'fn', ...inputs });
const inline = (Action) => res('aws:iam/rolePolicy:RolePolicy', 'fnrole-inline', { role: 'fnrole',
  policy: pol({ Effect: 'Allow', Action, Resource: `arn:aws:dynamodb:us-east-2:${A}:table/t` }) });

test('E-4: an unbound service-principal permission is a confused-deputy finding (bundle e4)', () => {
  const r = scanPulumi({ text: exportOf(ROLE, FN, perm({ principal: 'secretsmanager.amazonaws.com' }), inline('dynamodb:GetItem')), ...opts });
  const d = doc(r, 'fn-perm#principal');
  assert.deepEqual(ids(d), ['RESOURCE-CONFUSED-DEPUTY/high']);
  assert.equal(d.family, 'resource');
  assert.deepEqual(r.analysisStates, []);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.equal(r.reason, 'FINDINGS_AT_OR_ABOVE_THRESHOLD');
  const sarif = JSON.stringify(buildAggregateSarif(pulumiUnits(r, 'Pulumi.yaml')));
  assert.ok(sarif.includes('RESOURCE-CONFUSED-DEPUTY'));
  assert.ok(!sarif.includes(']('));
});

test('E-4: a match-all sourceArn or a non-account sourceAccount binds nothing', () => {
  for (const extra of [{ sourceArn: '*' }, { sourceArn: 'arn:aws:*:*:*:*' }, { sourceAccount: '*' }]) {
    const r = scanPulumi({ text: exportOf(perm({ principal: 's3.amazonaws.com', ...extra })), ...opts });
    assert.deepEqual(ids(doc(r, 'fn-perm#principal')), ['RESOURCE-CONFUSED-DEPUTY/high'], JSON.stringify(extra));
  }
  const bound = scanPulumi({ text: exportOf(perm({ principal: 's3.amazonaws.com', sourceAccount: A })), ...opts });
  assert.equal(doc(bound, 'fn-perm#principal'), undefined);
  assert.deepEqual(bound.unanalyzed.map((u) => u.reason), ['service-principal-source-bound']);
});

test('E-4: a sourceArn binds only with a literal account (or no account and no glob)', () => {
  for (const sourceArn of ['arn:aws:secretsmanager:*:*:secret:*', `arn:aws:sns:us-east-1:*:t`,
    'arn:aws:s3:::bucket-*', 'not-an-arn']) {
    const r = scanPulumi({ text: exportOf(perm({ principal: 's3.amazonaws.com', sourceArn })), ...opts });
    assert.deepEqual(ids(doc(r, 'fn-perm#principal')), ['RESOURCE-CONFUSED-DEPUTY/high'], sourceArn);
  }
  for (const sourceArn of [`arn:aws:secretsmanager:us-east-1:${A}:secret:*`, 'arn:aws:s3:::bucket']) {
    const r = scanPulumi({ text: exportOf(perm({ principal: 's3.amazonaws.com', sourceArn })), ...opts });
    assert.deepEqual(r.unanalyzed.map((u) => u.reason), ['service-principal-source-bound'], sourceArn);
  }
});

// Was listed as unanalyzed (exit 0); now the R6 s org-scoped verdict.
test('E-4: an org-scoped grant is RESOURCE-CROSS-ACCOUNT high, never clean', () => {
  for (const extra of [{ principalOrgId: 'o-exampleorg' }, { organizationId: 'o-exampleorg' }]) {
    const r = scanPulumi({ text: exportOf(perm({ principal: '*', ...extra })), ...opts });
    assert.deepEqual(ids(doc(r, 'fn-perm#principal')), ['RESOURCE-CROSS-ACCOUNT/high'], JSON.stringify(extra));
    assert.equal(r.exitCode, EXIT.FINDINGS);
    assert.ok(!JSON.stringify(r).includes('o-exampleorg'), 'org id not echoed');
  }
  const bad = scanPulumi({ text: exportOf(perm({ principal: '*', principalOrgId: 'o-exampleorg', action: 'not an action' })), ...opts });
  assert.equal(bad.exitCode, EXIT.FAIL_CLOSED);
});

test('E-4: an unknown action on an unbound service grant still fails closed', () => {
  const r = scanPulumi({ text: exportOf(perm({ principal: 's3.amazonaws.com', action: '04da6b54-80e4-46f7-96ec-b56ff0331ba9' })), ...opts });
  assert.ok(codes(doc(r, 'fn-perm#principal')).includes('PULUMI_UNKNOWN'));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('E-4/e7: an unmodeled permission never names the run when another document can', () => {
  const e7 = scanPulumi({ text: exportOf(ROLE, FN, perm({ principal: 'secretsmanager.amazonaws.com' }), inline('ec2:CreateRoute')), ...opts });
  assert.equal(e7.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(e7.reason, doc(e7, 'fnrole-inline#policy').result.reason);
  // The public permission sorts first among the exit-3 documents but is demoted.
  const pub = scanPulumi({ text: exportOf(ROLE, FN, perm({ principal: '*' }), inline('ec2:CreateRoute')), ...opts });
  assert.equal(doc(pub, 'fn-perm#principal').result.reason, 'PULUMI_UNMODELED_PERMISSION');
  assert.notEqual(pub.reason, 'PULUMI_UNMODELED_PERMISSION');
  assert.equal(pub.exitCode, EXIT.FAIL_CLOSED);
  // Alone it still names the run and exits 3.
  const alone = scanPulumi({ text: exportOf(perm({ principal: '*' })), ...opts });
  assert.equal(alone.reason, 'PULUMI_UNMODELED_PERMISSION');
  assert.equal(alone.exitCode, EXIT.FAIL_CLOSED);
});

// --- E-5 ---
const twoAccounts = JSON.stringify({ version: 3, deployment: { resources: [provider(PA), provider(PB),
  res('aws:iam/role:Role', 'ra', { name: 'ra', assumeRolePolicy: ROLE.inputs.assumeRolePolicy }),
  res('aws:iam/role:Role', 'rb', { name: 'rb', assumeRolePolicy: ROLE.inputs.assumeRolePolicy }, {}, PB)] } });
const mapping = [{ key: PA, account: A }, { key: PB, account: B }];

test('E-5: subject-account on a multi-account stack warns once; never otherwise', () => {
  const w = scanPulumi({ text: twoAccounts, partition: 'aws', subjectAccount: A, providerAccounts: mapping });
  assert.deepEqual(w.warnings.map((x) => [x.code, x.accounts]), [['PULUMI_PROVIDERS_MULTI_ACCOUNT', 2]]);
  assert.equal(w.exitCode, EXIT.FAIL_CLOSED, 'the warning never changes the verdict');
  assert.deepEqual(scanPulumi({ text: twoAccounts, partition: 'aws', providerAccounts: mapping }).warnings, []);
  assert.deepEqual(scanPulumi({ text: exportOf(ROLE), ...opts }).warnings, []);
  assert.equal(toPulumiJsonReport(w, {}).warnings[0].code, 'PULUMI_PROVIDERS_MULTI_ACCOUNT');
  const runs = buildAggregateSarif(pulumiUnits(w, 'Pulumi.yaml')).runs;
  assert.ok(runs.length > 0 && runs.every((x) => x.properties.warnings === 'PULUMI_PROVIDERS_MULTI_ACCOUNT'));
});

test('E-5: the CLI prints the warning by code, with no input value', async () => {
  let err = '';
  const io = { readFile: () => twoAccounts, stdout: () => {}, stderr: (s) => { err += s; } };
  const argv = ['--input', 'pulumi', '--partition', 'aws', '--format', 'json', '--provider-account', `${PA}=${A}`, '--provider-account', `${PB}=${B}`];
  assert.equal(await run([...argv, '--subject-account', A, 'x.json'], io), EXIT.FAIL_CLOSED);
  const line = err.split('\n').find((l) => l.includes('PULUMI_PROVIDERS_MULTI_ACCOUNT'));
  assert.match(line, /^iam-br: warning PULUMI_PROVIDERS_MULTI_ACCOUNT: Providers resolve to 2 AWS accounts/);
  assert.ok(!line.includes(A) && !line.includes(B) && !line.includes('urn:'));
  err = '';
  assert.equal(await run([...argv, 'x.json'], io), EXIT.CLEAN);
  assert.ok(!err.includes('warning'));
});
