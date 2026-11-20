// v1.3.0 round 2: Pulumi preview / stack export input (P1-P5, P7). Fixtures are the Mac's
// synthetic program (pulumi-spec bundle, 2026-10-21); everything else is built inline.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  scanPulumi, extractPulumiDocuments, safeSourcePosition, parseJsonStrict, partitionForRegion,
  PULUMI_UNKNOWN, PULUMI_ENVELOPE_ID,
} from '../../../cli/pulumi.mjs';
import { run } from '../../../cli/iam-br.mjs';
import { runAction } from '../../../action/index.mjs';
import { EXIT } from '../../../cli/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => readFileSync(join(here, 'pulumi-fixtures', n), 'utf8');
const ACCT = '111122223333';
const OPTS = { subjectAccount: ACCT, partition: 'aws' };
const scanText = (text, o = OPTS) => scanPulumi({ text, ...o });
const docOf = (r, suffix) => r.documents.find((d) => d.artifact.endsWith(suffix));
const ids = (d) => d.result.findings.map((f) => f.id);
const codes = (d) => d.result.analysisStates.map((s) => s.code);
const allCodes = (r) => [...r.analysisStates.map((s) => s.code), ...r.documents.flatMap(codes)];

// --- synthetic preview builder -----------------------------------------------------------
const PROV = 'urn:pulumi:dev::p::pulumi:providers:aws::aws';
const U = (type, name) => `urn:pulumi:dev::p::${type}::${name}`;
const provStep = (inputs = { region: 'us-east-1' }, urn = PROV, op = 'update') => ({ op, urn, newState: { urn, type: 'pulumi:providers:aws', inputs } });
const step = (op, type, name, inputs, extra = {}) => {
  const urn = U(type, name);
  return { op, urn, newState: { urn, type, inputs, provider: `${extra.prov || PROV}::id1`, ...(extra.ns || {}) }, ...(extra.step || {}) };
};
const preview = (...steps) => JSON.stringify({ config: {}, steps: [provStep(), ...steps], changeSummary: {} });
const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const ADMIN = P({ Effect: 'Allow', Action: '*', Resource: '*' });
const TRUST_SAME = P({ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${ACCT}:role/helper` }, Action: 'sts:AssumeRole' });
const roleOut = (name) => ({ arn: `arn:aws:iam::${ACCT}:role/${name}` });

// --- Mac tests 1-4 -----------------------------------------------------------------------

test('1: preview-create fails closed on exactly the two unknown policies', () => {
  const r = scanText(fx('preview-create.json'));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(r.scanScope, 'delta');
  const unknown = r.documents.filter((d) => codes(d).includes('PULUMI_UNKNOWN')).map((d) => d.artifact.split('::').pop());
  assert.deepEqual(unknown.sort(), ['bucketPolicy#policy', 'prodRole#assumeRolePolicy']);
  assert.ok(ids(docOf(r, 'managed#policy')).includes('PASSROLE-UNSCOPED'));
  assert.ok(ids(docOf(r, 'prodRead#policy')).includes('DATA-EXFIL'));
  assert.ok(ids(docOf(r, 'devTaskRole#inlinePolicies[assume-helpers]')).includes('ASSUME-ROLE-EXPANSION'));
  assert.ok(ids(docOf(r, 'devTaskRole#assumeRolePolicy')).includes('TRUST-SERVICE'));
  assert.ok(!r.documents.some((d) => d.urn.endsWith('::secretHolder')), 'secretHolder is never read');
});

test('2: preview-update evaluates every policy; same-account trust and joined bucket ARN', () => {
  const r = scanText(fx('preview-update.json'));
  assert.ok(!allCodes(r).includes('PULUMI_UNKNOWN'));
  const trust = docOf(r, 'prodRole#assumeRolePolicy');
  assert.ok(!ids(trust).includes('TRUST-CROSS-ACCOUNT'));
  const bp = docOf(r, 'bucketPolicy#policy');
  assert.ok(bp.result.findings.some((f) => f.id === 'PUBLIC-ACCESS' && f.severity === 'critical'));
  const ext = extractPulumiDocuments(fx('preview-update.json'), OPTS);
  const d = ext.documents.find((x) => x.artifact.endsWith('bucketPolicy#policy'));
  assert.equal(d.resourceContext.arn, 'arn:aws:s3:::fx-data-dev');
  // E-1: the role ARN is built only from stack-proven account evidence (devTaskRole's ARN).
  const t = ext.documents.find((x) => x.artifact.endsWith('prodRole#assumeRolePolicy'));
  assert.deepEqual(t.resourceContext, { type: 'iam-role', arn: `arn:aws:iam::${ACCT}:role/helperbot-prod` });
});

test('3: secrets are never read; a [secret] or enveloped policy is PULUMI_SECRET', async () => {
  const r = scanText(preview(step('create', 'aws:iam/policy:Policy', 'p', { policy: '[secret]' })));
  assert.deepEqual(codes(docOf(r, 'p#policy')), ['PULUMI_SECRET']);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  const env = { [PULUMI_ENVELOPE_ID]: '1b47061264138c4ac30d75fd1eb44270', ciphertext: 'v1:ZZZCIPHERZZZ' };
  const exp = JSON.stringify({ version: 3, deployment: { resources: [
    { urn: PROV, type: 'pulumi:providers:aws', inputs: { region: 'us-east-1' } },
    { urn: U('aws-native:iam:ManagedPolicy', 'n'), type: 'aws-native:iam:ManagedPolicy', provider: `${PROV}::id1`, inputs: { policyDocument: env } },
    { urn: U('aws-native:iam:ManagedPolicy', 'm'), type: 'aws-native:iam:ManagedPolicy', provider: `${PROV}::id1`, inputs: { policyDocument: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*', Condition: { StringEquals: { 'aws:x': env } } }] } } },
  ] } });
  const e = scanText(exp);
  assert.deepEqual(codes(docOf(e, '::n#policyDocument')), ['PULUMI_SECRET']);
  assert.deepEqual(codes(docOf(e, '::m#policyDocument')), ['PULUMI_SECRET']);
  // No ciphertext anywhere in the CLI's JSON, SARIF or stderr.
  for (const format of ['json', 'sarif']) {
    let stdout = '';
    let stderr = '';
    await run(['--input', 'pulumi', '--format', format, '--subject-account', ACCT, 'x.json'], {
      readFile: () => exp, stdout: (s) => { stdout += s; }, stderr: (s) => { stderr += s; },
    });
    assert.ok(stdout.length > 0, format);
    assert.ok(!stdout.includes('ZZZCIPHERZZZ') && !stderr.includes('ZZZCIPHERZZZ'), format);
    assert.ok(!stdout.includes('1b47061264138c4ac30d75fd1eb44270'), format);
  }
});

test('4: a stack export gives the same verdicts as the update preview for shared resources', () => {
  const ex = scanText(fx('seed-state.json'));
  const up = scanText(fx('preview-update.json'));
  assert.equal(ex.scanScope, 'full');
  for (const d of ex.documents) {
    const u = up.documents.find((x) => x.artifact === d.artifact);
    assert.ok(u, d.artifact);
    assert.deepEqual(ids(d).sort(), ids(u).sort(), d.artifact);
    assert.equal(d.result.exitCode, u.result.exitCode, d.artifact);
  }
});

// --- determinism (Mac test 6, amended) --------------------------------------------------

const shuffleKeys = (v) => {
  if (Array.isArray(v)) return v.map(shuffleKeys);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).reverse().map((k) => [k, shuffleKeys(v[k])]));
  return v;
};
const cliJson = async (text, extra = []) => {
  let out = '';
  const code = await run(['--input', 'pulumi', '--subject-account', ACCT, '--partition', 'aws', ...extra, 'x.json'],
    { readFile: () => text, stdout: (s) => { out += s; }, stderr: () => {} });
  return { code, out };
};

test('6: output is byte-identical across runs and under shuffled steps and keys', async () => {
  const text = fx('preview-update.json');
  const doc = JSON.parse(text);
  const shuffled = JSON.stringify(shuffleKeys({ ...doc, steps: doc.steps.slice().reverse() }));
  for (const fmt of [[], ['--format', 'sarif']]) {
    const a = await cliJson(text, fmt);
    const b = await cliJson(text, fmt);
    const c = await cliJson(shuffled, fmt);
    assert.equal(a.out, b.out);
    assert.equal(a.out, c.out);
    assert.equal(a.code, EXIT.FINDINGS);
  }
});

// --- input shape -------------------------------------------------------------------------

test('shape: not Pulumi is usage (2); ambiguous or malformed Pulumi is fail-closed (3)', () => {
  assert.equal(scanText(ADMIN).exitCode, EXIT.USAGE);
  assert.equal(scanText('[]').exitCode, EXIT.USAGE);
  assert.equal(scanText('').exitCode, EXIT.USAGE);
  assert.equal(scanText('{"steps":[],"deployment":{}}').exitCode, EXIT.FAIL_CLOSED);
  assert.ok(allCodes(scanText('{"changeSummary":{}}')).includes('PULUMI_AMBIGUOUS_SHAPE'));
  assert.ok(allCodes(scanText('{"steps": [')).includes('PULUMI_MALFORMED'));
  assert.ok(allCodes(scanText('{"steps":{}}')).includes('PULUMI_MALFORMED'));
  assert.ok(allCodes(scanText('{"steps":[{"op":"create"}]}')).includes('PULUMI_MALFORMED'));
  assert.equal(scanText('{"steps":[]}').exitCode, EXIT.CLEAN);
});

test('shape: duplicate keys fail closed, in the document and inside a policy string', () => {
  assert.ok(allCodes(scanText('{"steps":[],"steps":[]}')).includes('PULUMI_DUPLICATE_KEY'));
  const dupPolicy = '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Effect":"Allow","Action":"*","Resource":"*"}]}';
  const r = scanText(preview(step('create', 'aws:iam/policy:Policy', 'p', { policy: dupPolicy })));
  assert.deepEqual(codes(docOf(r, 'p#policy')), ['PULUMI_DUPLICATE_KEY']);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.deepEqual(parseJsonStrict('{"a":{"b":1,"b":2}}', 10), { ok: false, code: 'DUPLICATE_KEY', path: '/a/b' });
  assert.equal(parseJsonStrict('{"__proto__":{"x":1}}', 10).value.__proto__.x, 1);
});

test('shape: nesting and size limits fail closed', () => {
  const deep = `${'['.repeat(200)}${']'.repeat(200)}`;
  assert.ok(allCodes(scanText(`{"steps":${deep}}`)).includes('PULUMI_TOO_DEEP'));
  assert.ok(allCodes(scanPulumi({ text: '', oversize: true })).includes('PULUMI_LIMIT'));
  const big = `{"Version":"2012-10-17","Statement":[],"x":"${'a'.repeat(1024 * 1024 + 10)}"}`;
  const r = scanText(preview(step('create', 'aws:iam/policy:Policy', 'p', { policy: big })));
  assert.deepEqual(codes(docOf(r, 'p#policy')), ['PULUMI_LIMIT']);
});

test('ops: allowlisted ops analyze, delete-like ops skip, others fail closed', () => {
  const pol = { policy: ADMIN };
  const r = scanText(preview(
    step('delete', 'aws:iam/policy:Policy', 'gone', pol),
    step('read', 'aws:iam/policy:Policy', 'ext', pol),
    step('remove-pending-replace', 'aws:iam/policy:Policy', 'odd', pol),
    { op: 'update', urn: U('aws:iam/policy:Policy', 'nostate') },
  ));
  assert.ok(!r.documents.some((d) => d.urn.endsWith('::gone')));
  assert.equal(docOf(r, '::ext#policy').managed, 'external');
  assert.ok(r.analysisStates.some((s) => s.code === 'PULUMI_UNKNOWN_OP'));
  assert.ok(r.analysisStates.some((s) => s.code === 'PULUMI_MISSING_STATE'));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.ok(r.findingsCount > 0, 'findings survive alongside exit 3');
});

test('ops: duplicate URNs collapse when identical and fail closed when they differ', () => {
  const s1 = step('create', 'aws:iam/policy:Policy', 'p', { policy: ADMIN });
  const same = scanText(preview(s1, s1));
  assert.equal(same.documents.length, 1);
  const s2 = step('create', 'aws:iam/policy:Policy', 'p', { policy: P({ Effect: 'Deny', Action: '*', Resource: '*' }) });
  const diff = scanText(preview(s1, s2));
  assert.ok(diff.analysisStates.some((s) => s.code === 'PULUMI_DUPLICATE_URN'));
  assert.equal(diff.documents.length, 0);
  assert.equal(diff.exitCode, EXIT.FAIL_CLOSED);
});

test('scope: delta by default, full with --show-sames, protect-only sames do not count', () => {
  const pol = { policy: ADMIN };
  assert.equal(scanText(preview(step('create', 'aws:iam/policy:Policy', 'p', pol))).scanScope, 'delta');
  assert.equal(scanText(preview(step('same', 'aws:iam/policy:Policy', 'p', pol))).scanScope, 'full');
  const protectOnly = step('same', 'aws:iam/policy:Policy', 'p', pol, { ns: { protect: true }, step: { oldState: { protect: false } } });
  assert.equal(scanText(preview(protectOnly)).scanScope, 'delta');
});

// --- properties -----------------------------------------------------------------------------

test('props: null/array/number policies and missing required ones fail closed', () => {
  for (const v of [null, [], 3, true]) {
    const r = scanText(preview(step('create', 'aws:iam/policy:Policy', 'p', { policy: v })));
    assert.deepEqual(codes(docOf(r, 'p#policy')), ['PULUMI_PROPERTY_INVALID'], String(v));
  }
  const m = scanText(preview(step('create', 'aws:iam/policy:Policy', 'p', {})));
  assert.deepEqual(codes(docOf(m, 'p#policy')), ['PULUMI_PROPERTY_MISSING']);
  // Optional and absent: no document.
  assert.equal(scanText(preview(step('create', 'aws:kms/key:Key', 'k', {}))).documents.length, 0);
});

test('props: the unknown sentinel is found at any depth of an object policy', () => {
  const doc = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: [`arn:aws:s3:::b/${PULUMI_UNKNOWN}`] }] };
  const r = scanText(preview(step('create', 'aws-native:iam:ManagedPolicy', 'n', { policyDocument: doc })));
  assert.deepEqual(codes(docOf(r, 'n#policyDocument')), ['PULUMI_UNKNOWN']);
});

test('props: aws-native object policies are analyzed; inline policies are keyed by name', () => {
  const r = scanText(preview(
    step('create', 'aws-native:iam:ManagedPolicy', 'n', { policyDocument: JSON.parse(ADMIN) }),
    step('create', 'aws:iam/role:Role', 'r', { assumeRolePolicy: TRUST_SAME, inlinePolicies: [{ name: 'a', policy: ADMIN }, { name: 'a', policy: ADMIN }, { name: 'we ird]', policy: ADMIN }] }),
  ));
  assert.ok(ids(docOf(r, 'n#policyDocument')).length > 0);
  assert.equal(docOf(r, 'n#policyDocument').result.exitCode, EXIT.FINDINGS);
  assert.ok(docOf(r, 'r#inlinePolicies[a]'));
  assert.ok(r.documents.some((d) => codes(d).includes('PULUMI_DUPLICATE_ID')));
  assert.ok(docOf(r, 'r#inlinePolicies["we ird]"]'));
});

test('props: organizations SCPs/RCPs are scanned; tag and backup policies are not IAM', () => {
  const scp = P({ Effect: 'Deny', Action: 'organizations:LeaveOrganization', Resource: '*' });
  const r = scanText(preview(
    step('create', 'aws:organizations/policy:Policy', 's', { content: scp, type: 'SERVICE_CONTROL_POLICY' }),
    step('create', 'aws:organizations/policy:Policy', 't', { content: '{"tags":{}}', type: 'TAG_POLICY' }),
  ));
  assert.equal(docOf(r, '::s#content').family, 'scp-rcp');
  assert.ok(!r.documents.some((d) => d.urn.endsWith('::t')));
});

test('backstop: unmapped IAM types and unanalyzed policy documents fail closed', () => {
  const r = scanText(preview(
    step('create', 'aws:iam/newThing:NewThing', 'x', { foo: 'bar' }),
    step('create', 'aws:opensearch/domainPolicy:DomainPolicy', 'o', { accessPolicies: ADMIN }),
    step('create', 'aws:iam/rolePolicyAttachment:RolePolicyAttachment', 'att', { role: 'r', policyArn: 'arn:aws:iam::aws:policy/ReadOnlyAccess' }),
    step('create', 'aws:autoscaling/policy:Policy', 'asg', { policyType: 'SimpleScaling' }),
  ));
  const unsupported = r.analysisStates.filter((s) => s.code === 'PULUMI_UNSUPPORTED_TYPE').map((s) => s.path.split('::').pop());
  assert.deepEqual(unsupported.sort(), ['o#accessPolicies', 'x']);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

// --- account / partition (P5) -----------------------------------------------------------------

test('account: unresolved without input or evidence; explicit input is cross-checked', () => {
  const pol = step('create', 'aws:iam/policy:Policy', 'p', { policy: ADMIN });
  const none = scanText(preview(pol), { partition: 'aws' });
  assert.ok(none.analysisStates.some((s) => s.code === 'PULUMI_ACCOUNT_UNRESOLVED'));
  assert.equal(none.exitCode, EXIT.FAIL_CLOSED);
  const proven = step('update', 'aws:iam/role:Role', 'r', { assumeRolePolicy: TRUST_SAME }, { step: { oldState: { outputs: roleOut('r') } } });
  assert.ok(!allCodes(scanText(preview(pol, proven), { partition: 'aws' })).includes('PULUMI_ACCOUNT_UNRESOLVED'));
  const mismatch = scanText(preview(pol, proven), { subjectAccount: '444455556666', partition: 'aws' });
  assert.ok(docOf(mismatch, 'p#policy').result.analysisStates.some((s) => s.code === 'PULUMI_ACCOUNT_MISMATCH'));
});

test('account: one provider proving two accounts is ambiguous; providers are separate', () => {
  const P2 = 'urn:pulumi:dev::p::pulumi:providers:aws::prod';
  const text = JSON.stringify({ steps: [
    provStep(), provStep({ region: 'us-east-1' }, P2),
    step('update', 'aws:iam/role:Role', 'a', { assumeRolePolicy: TRUST_SAME }, { step: { oldState: { outputs: roleOut('a') } } }),
    step('update', 'aws:iam/role:Role', 'b', { assumeRolePolicy: TRUST_SAME }, { step: { oldState: { outputs: { arn: 'arn:aws:iam::444455556666:role/b' } } } }),
    step('update', 'aws:iam/role:Role', 'c', { assumeRolePolicy: TRUST_SAME }, { prov: P2, step: { oldState: { outputs: { arn: 'arn:aws:iam::777788889999:role/c' } } } }),
  ] });
  const r = scanText(text, { partition: 'aws' });
  assert.ok(r.analysisStates.some((s) => s.code === 'PULUMI_ACCOUNT_AMBIGUOUS' && s.path === PROV));
  const c = extractPulumiDocuments(text, { partition: 'aws' }).documents.find((d) => d.urn.endsWith('::c'));
  assert.equal(c.subjectAccount, '777788889999');
});

test('partition: from the provider region, never defaulted; mismatches fail closed', () => {
  assert.equal(partitionForRegion('cn-north-1'), 'aws-cn');
  assert.equal(partitionForRegion('us-gov-west-1'), 'aws-us-gov');
  assert.equal(partitionForRegion('us-isob-east-1'), 'aws-iso-b');
  assert.equal(partitionForRegion('eu-west-2'), 'aws');
  assert.equal(partitionForRegion('xx-moon-1'), null);
  const pol = step('create', 'aws:iam/policy:Policy', 'p', { policy: ADMIN });
  const cn = JSON.stringify({ steps: [provStep({ region: 'cn-north-1' }), pol] });
  assert.equal(extractPulumiDocuments(cn, { subjectAccount: ACCT }).documents[0].partition, 'aws-cn');
  assert.ok(docOf(scanText(cn), 'p#policy').result.analysisStates.some((s) => s.code === 'PULUMI_PARTITION_MISMATCH'));
  const moon = JSON.stringify({ steps: [provStep({ region: 'xx-moon-1' }), pol] });
  const m = scanText(moon, { subjectAccount: ACCT });
  assert.ok(m.analysisStates.some((s) => s.code === 'PULUMI_PARTITION_UNRESOLVED'));
  assert.equal(extractPulumiDocuments(moon, { subjectAccount: ACCT }).documents[0].partition, null);
});

// --- resource context (P4) -----------------------------------------------------------------

test('context: joins to the referenced resource; ambiguous joins fail closed', () => {
  const bp = P({ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b1/*' });
  const bucket = (n, b) => step('update', 'aws:s3/bucketV2:BucketV2', n, { bucket: b }, { step: { oldState: { outputs: { arn: `arn:aws:s3:::${b}`, id: b } } } });
  const one = scanText(preview(bucket('bk', 'b1'), step('create', 'aws:s3/bucketPolicy:BucketPolicy', 'bp', { bucket: 'b1', policy: bp })));
  assert.ok(docOf(one, 'bp#policy').result.findings.some((f) => f.id === 'PUBLIC-ACCESS'));
  const two = scanText(preview(bucket('bk', 'b1'), bucket('bk2', 'b1'), step('create', 'aws:s3/bucketPolicy:BucketPolicy', 'bp', { bucket: 'b1', policy: bp })));
  assert.ok(codes(docOf(two, 'bp#policy')).includes('PULUMI_CONTEXT_AMBIGUOUS'));
  assert.equal(two.exitCode, EXIT.FAIL_CLOSED);
  const q = scanText(preview(step('create', 'aws:sqs/queuePolicy:QueuePolicy', 'qp', {
    queueUrl: `https://sqs.us-east-1.amazonaws.com/${ACCT}/q1`,
    policy: P({ Effect: 'Allow', Principal: '*', Action: 'sqs:SendMessage', Resource: `arn:aws:sqs:us-east-1:${ACCT}:q1` }),
  })));
  const qd = extractPulumiDocuments(preview(step('create', 'aws:sqs/queuePolicy:QueuePolicy', 'qp', { queueUrl: `https://sqs.us-east-1.amazonaws.com/${ACCT}/q1`, policy: ADMIN })), OPTS).documents[0];
  assert.equal(qd.resourceContext.arn, `arn:aws:sqs:us-east-1:${ACCT}:q1`);
  assert.notEqual(docOf(q, 'qp#policy').result.exitCode, EXIT.CLEAN);
  // A new KMS key has no ARN yet: the resource family fails closed, never guesses one.
  const k = scanText(preview(step('create', 'aws:kms/key:Key', 'k', { policy: ADMIN })));
  assert.equal(docOf(k, 'k#policy').result.exitCode, EXIT.FAIL_CLOSED);
});

test('context (E-1): a role ARN is never built from an unproven account', () => {
  const r = step('create', 'aws:iam/role:Role', 'r', { name: 'r', assumeRolePolicy: TRUST_SAME });
  const ext = extractPulumiDocuments(preview(r), OPTS);
  assert.equal(ext.documents[0].resourceContext, undefined);
});

// --- locations (P7) ------------------------------------------------------------------------

test('sourcePosition: only project-relative, traversal-free positions are used', () => {
  assert.deepEqual(safeSourcePosition('project:///index.ts#12,5'), { uri: 'index.ts', startLine: 12, startColumn: 5 });
  assert.deepEqual(safeSourcePosition('project:///src/main.py#3'), { uri: 'src/main.py', startLine: 3, startColumn: undefined });
  for (const bad of ['project:///../x.ts#1', 'project:////etc/passwd#1', 'project:///a/../../b#1', 'file:///x#1',
    'project:///%2e%2e/x#1', 'project:///a\nb#1', 'project:///a#0', 'project:///a\u202eb#1', 'project:///C:/x#1', 42]) {
    assert.equal(safeSourcePosition(bad), null, String(bad));
  }
});

test('sarif: URN logical location, line region, sanitized strings, scope property', async () => {
  const nasty = 'p\u001b[31m\nx';
  const text = preview(step('create', 'aws:iam/policy:Policy', nasty, { policy: ADMIN }, { ns: { sourcePosition: 'project:///infra/index.ts#7,3' } }));
  const { out } = await cliJson(text, ['--format', 'sarif']);
  const sarif = JSON.parse(out);
  const run0 = sarif.runs.find((r) => r.results.length > 0 && r.properties.artifact);
  const loc = run0.results[0].locations[0];
  assert.equal(loc.physicalLocation.artifactLocation.uri, 'infra/index.ts');
  assert.deepEqual(loc.physicalLocation.region, { startLine: 7, startColumn: 3 });
  assert.ok(loc.logicalLocations[0].fullyQualifiedName.endsWith('#policy'));
  assert.equal(run0.properties.scanScope, 'delta');
  assert.ok(!/[\u0000-\u0008\u000b-\u001f]/.test(out), 'no raw control characters');
  assert.ok(!out.includes('\u001b'));
});

// --- CLI + Action plumbing -----------------------------------------------------------------

test('cli: --input pulumi refuses single-policy flags (usage, exit 2)', async () => {
  const io = { readFile: () => fx('seed-state.json'), stdout: () => {}, stderr: () => {} };
  for (const argv of [['--family', 'identity'], ['--resource-arn', 'arn:aws:s3:::b']]) {
    assert.equal(await run(['--input', 'pulumi', ...argv, 'x.json'], io), EXIT.USAGE, argv.join(' '));
  }
  assert.equal(await run(['--input', 'pulumi'], { ...io, stdinIsTTY: true }), EXIT.USAGE);
  assert.equal(await run(['--input', 'terraform', '--family', 'identity', 'x.json'], io), EXIT.USAGE);
  const { code } = await cliJson(fx('seed-state.json'));
  assert.equal(code, EXIT.FINDINGS);
});

const actionIo = (files) => ({
  readFile: (rel) => { if (!(rel in files)) throw new Error('ENOENT'); return files[rel]; },
  listFiles: () => Object.keys(files),
});

test('action: pulumi-json scans the file and exposes scan-scope; misuse is usage', () => {
  const io = actionIo({ 'preview.json': fx('preview-update.json') });
  const env = { 'INPUT_PULUMI-JSON': 'preview.json', 'INPUT_SUBJECT-ACCOUNT': ACCT, INPUT_PARTITION: 'aws' };
  const ok = runAction({ env, io });
  assert.equal(ok.exitCode, EXIT.FINDINGS);
  assert.equal(ok.outputs['scan-scope'], 'delta');
  assert.ok(ok.sarifLog.runs.some((r) => r.results.some((x) => (x.locations[0].logicalLocations || [])[0])));
  for (const extra of [{ INPUT_PATHS: 'a.json' }, { INPUT_FAMILY: 'identity' }, { INPUT_BASELINE: 'b.json' }, { 'INPUT_RESOURCE-ARN': 'arn:aws:s3:::b' }]) {
    assert.equal(runAction({ env: { ...env, ...extra }, io }).exitCode, EXIT.USAGE, JSON.stringify(extra));
  }
  assert.equal(runAction({ env: { ...env, 'INPUT_PULUMI-JSON': '../preview.json' }, io }).exitCode, EXIT.USAGE);
  assert.equal(runAction({ env: { ...env, 'INPUT_PULUMI-JSON': 'missing.json' }, io }).exitCode, EXIT.USAGE);
  const create = runAction({ env, io: actionIo({ 'preview.json': fx('preview-create.json') }) });
  assert.equal(create.exitCode, EXIT.FAIL_CLOSED);
});

test('account: a read (external) resource never proves the stack account', () => {
  const V = '444455556666';
  const foreignTrust = P({ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${V}:role/vendor` }, Action: 'sts:AssumeRole' });
  const text = preview(
    step('read', 'aws:kms/key:Key', 'shared', { keyId: 'k' }, { ns: { outputs: { arn: `arn:aws:kms:us-east-1:${V}:key/k` } } }),
    step('create', 'aws:iam/role:Role', 'r', { name: 'r', assumeRolePolicy: foreignTrust }),
  );
  const d = docOf(scanText(text, { partition: 'aws' }), 'r#assumeRolePolicy');
  assert.ok(!ids(d).includes('TRUST-SAME-ACCOUNT'), ids(d).join(','));
  assert.ok(ids(d).includes('TRUST-CROSS-ACCOUNT'));
});
