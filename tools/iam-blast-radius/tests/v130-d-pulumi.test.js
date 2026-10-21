// v1.3.0 round 3: P8 URN-keyed baselines for --input pulumi, P9 role grouping.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanPulumi, applyPulumiBaseline, pulumiBaselineUri, pulumiUnits } from '../../../cli/pulumi.mjs';
import { buildBaseline, parseBaseline, formatBaseline } from '../../../cli/baseline.mjs';
import { run } from '../../../cli/iam-br.mjs';
import { runAction } from '../../../action/index.mjs';
import { EXIT } from '../../../cli/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fx = (n) => readFileSync(join(here, 'pulumi-fixtures', n), 'utf8');
const ACCT = '111122223333';
const OPTS = { subjectAccount: ACCT, partition: 'aws', threshold: 'high' };
const PROV = 'urn:pulumi:dev::p::pulumi:providers:aws::aws';
const prov = { op: 'update', urn: PROV, newState: { urn: PROV, type: 'pulumi:providers:aws', inputs: { region: 'us-east-1' } } };
const U = (type, name, stack = 'dev', project = 'p') => `urn:pulumi:${stack}::${project}::${type}::${name}`;
const step = (type, name, inputs, extra = {}) => {
  const urn = extra.urn || U(type, name);
  return { op: 'update', urn, newState: { urn, type, inputs, provider: `${PROV}::id1` }, oldState: { outputs: extra.outputs || {} } };
};
const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const ADMIN = P({ Effect: 'Allow', Action: '*', Resource: '*' });
const text = (...steps) => JSON.stringify({ steps: [prov, ...steps] });
// Baseline built from one run, parsed as a committed file would be.
const baselineOf = (t) => {
  const r = applyPulumiBaseline(scanPulumi({ text: t, ...OPTS }), null, 'high');
  const parsed = parseBaseline(formatBaseline(buildBaseline(pulumiUnits(r))));
  assert.ok(parsed.ok);
  return parsed.keys;
};
const applyTo = (t, keys) => applyPulumiBaseline(scanPulumi({ text: t, ...OPTS }), keys, 'high');
const keysOf = (r) => r.documents.flatMap((d) => [...d.result.baseline.keyOf.values()]);

test('P8: a baseline round-trips on the update preview (findings accepted, exit 0)', () => {
  const t = fx('preview-update.json');
  const before = scanPulumi({ text: t, ...OPTS });
  assert.equal(before.exitCode, EXIT.FINDINGS);
  const after = applyTo(t, baselineOf(t));
  assert.equal(after.exitCode, EXIT.CLEAN);
  assert.equal(after.reason, 'CLEAN_WITH_BASELINE');
  assert.deepEqual(after.baseline.stale, []);
  assert.ok(after.baseline.used.length > 0);
});

test('P8: a baseline never accepts adapter states (create preview stays exit 3)', () => {
  const t = fx('preview-create.json');
  const r = applyTo(t, baselineOf(t));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  const doc = r.documents.find((d) => d.artifact.endsWith('prodRole#assumeRolePolicy'));
  assert.equal(doc.result.exitCode, EXIT.FAIL_CLOSED);
});

test('P8: two findings under one rule in one policy get distinct ids', () => {
  const pol = P({ Effect: 'Allow', Action: 's3:PutObject', Resource: '*' }, { Effect: 'Allow', Action: 'sqs:SendMessage', Resource: '*' });
  const r = applyPulumiBaseline(scanPulumi({ text: text(step('aws:iam/policy:Policy', 'p', { policy: pol })), ...OPTS }), null, 'high');
  const d = r.documents[0];
  const ids = d.result.findings.map((f) => f.id);
  const dup = ids.find((id, i) => ids.indexOf(id) !== i);
  assert.ok(dup, `need a repeated rule id: ${ids}`);
  const keys = d.result.findings.map((f) => d.result.baseline.keyOf.get(f));
  assert.equal(new Set(keys).size, keys.length);
});

test('P8: the URI keeps (urn, property) unambiguous', () => {
  assert.notEqual(pulumiBaselineUri({ urn: 'a#b', property: 'policy' }), pulumiBaselineUri({ urn: 'a', property: 'b#policy' }));
});

test('P8 churn: renames are one removed + one new; inline reorder is no change', () => {
  const SVC = P({ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' });
  const role = (name, inl, extra) => step('aws:iam/role:Role', 'r', { name: 'r', assumeRolePolicy: SVC, inlinePolicies: inl }, extra);
  const A = { name: 'a', policy: ADMIN };
  const B = { name: 'b', policy: P({ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' }) };
  const base = text(role('r', [A, B]));
  const keys = baselineOf(base);
  const cases = [
    ['inline reorder', text(role('r', [B, A])), 0],
    ['resource rename', text(role('r', [A, B], { urn: U('aws:iam/role:Role', 'r2') })), 1],
    ['stack rename', text(role('r', [A, B], { urn: U('aws:iam/role:Role', 'r', 'prod') })), 1],
    ['project rename', text(role('r', [A, B], { urn: U('aws:iam/role:Role', 'r', 'dev', 'q') })), 1],
    ['inline rename', text(role('r', [{ ...A, name: 'a2' }, B])), 1],
    ['inline -> managed', text(role('r', [B]), step('aws:iam/policy:Policy', 'pa', { policy: ADMIN })), 1],
  ];
  for (const [name, t, changed] of cases) {
    const r = applyTo(t, keys);
    if (changed === 0) {
      assert.equal(r.exitCode, EXIT.CLEAN, name);
      assert.deepEqual(r.baseline.stale, [], name);
    } else {
      assert.ok(r.baseline.stale.length > 0, `${name}: old entries reported stale`);
      assert.equal(r.exitCode, EXIT.FINDINGS, `${name}: new entries not accepted`);
    }
  }
});

test('P8: CLI --format baseline then --baseline round-trips; a metadata mismatch is usage', async () => {
  const t = fx('preview-update.json');
  let out = '';
  const io = { readFile: () => t, stdout: (s) => { out += s; }, stderr: () => {} };
  assert.equal(await run(['--input', 'pulumi', '--subject-account', ACCT, '--partition', 'aws', '--format', 'baseline', 'x.json'], io), EXIT.FINDINGS);
  const doc = out;
  const files = { 'x.json': t, 'b.json': doc };
  const io2 = { readFile: (f) => files[f], stdout: () => {}, stderr: () => {} };
  assert.equal(await run(['--input', 'pulumi', '--subject-account', ACCT, '--partition', 'aws', '--baseline', 'b.json', 'x.json'], io2), EXIT.CLEAN);
  const bad = JSON.parse(doc);
  bad.entries[0].severity = bad.entries[0].severity === 'high' ? 'low' : 'high';
  files['b.json'] = JSON.stringify(bad);
  assert.equal(await run(['--input', 'pulumi', '--subject-account', ACCT, '--partition', 'aws', '--baseline', 'b.json', 'x.json'], io2), EXIT.USAGE);
});

const actionIo = (files) => ({
  readFile: (rel) => { if (!(rel in files)) throw new Error('ENOENT'); return files[rel]; },
  listFiles: () => Object.keys(files),
});

test('P8: the Action writes and applies a baseline with pulumi-json', () => {
  const files = { 'preview.json': fx('preview-update.json') };
  const env = { 'INPUT_PULUMI-JSON': 'preview.json', 'INPUT_SUBJECT-ACCOUNT': ACCT, INPUT_PARTITION: 'aws' };
  const first = runAction({ env: { ...env, 'INPUT_BASELINE-OUTPUT': 'baseline.json' }, io: actionIo(files) });
  assert.equal(first.exitCode, EXIT.FINDINGS);
  assert.ok(typeof first.baselineText === 'string' && JSON.parse(first.baselineText).entries.length > 0);
  files['baseline.json'] = first.baselineText;
  const second = runAction({ env: { ...env, INPUT_BASELINE: 'baseline.json' }, io: actionIo(files) });
  assert.equal(second.exitCode, EXIT.CLEAN);
  const create = runAction({ env: { ...env, INPUT_BASELINE: 'baseline.json' }, io: actionIo({ ...files, 'preview.json': fx('preview-create.json') }) });
  assert.equal(create.exitCode, EXIT.FAIL_CLOSED);
});

test('P9: grouping of the update preview (devTaskRole can assume prodRole; unknown refs are explicit)', () => {
  const r = scanPulumi({ text: fx('preview-update.json'), ...OPTS });
  const u = (n) => r.groups.map((g) => g.role).find((x) => x.endsWith(`::${n}`)) || r.documents.find((d) => d.urn.endsWith(`::${n}`))?.urn;
  const dev = r.groups.find((g) => g.role.endsWith('::devTaskRole'));
  const prod = r.groups.find((g) => g.role.endsWith('::prodRole'));
  assert.deepEqual(dev.documents.map((a) => a.split('::').pop()), ['devTaskRole#assumeRolePolicy', 'devTaskRole#inlinePolicies[assume-helpers]']);
  assert.ok(prod.edges.some((e) => e.kind === 'can-assume' && e.from === dev.role && e.to === prod.role));
  assert.ok(prod.edges.some((e) => e.kind === 'attachment-role' && e.from.endsWith('::attach') && e.to === prod.role));
  assert.ok(r.unresolvedEdges.some((e) => e.kind === 'attachment-policy' && e.from.endsWith('::attach') && e.reason === 'unknown' && e.to === null));
  assert.ok(r.unresolvedEdges.some((e) => e.kind === 'role-policy' && e.from.endsWith('::prodRead') && e.reason === 'unknown'));
  assert.ok(u('devTaskRole'));
});

test('P9: joins are same-provider and unique; AWS-managed policies are explicit', () => {
  const P2 = 'urn:pulumi:dev::p::pulumi:providers:aws::other';
  const role = (name, provider = PROV) => ({ op: 'update', urn: U('aws:iam/role:Role', name), newState: { urn: U('aws:iam/role:Role', name), type: 'aws:iam/role:Role', inputs: { name: 'shared' }, provider: `${provider}::x` } });
  const att = (arn) => step('aws:iam/rolePolicyAttachment:RolePolicyAttachment', 'att', { role: 'shared', policyArn: arn });
  // Same name under another provider: never joined.
  const r1 = scanPulumi({ text: JSON.stringify({ steps: [prov, role('a'), role('b', P2), att('arn:aws:iam::aws:policy/ReadOnlyAccess')] }), ...OPTS });
  const g = r1.groups.find((x) => x.role.endsWith('::a'));
  assert.ok(g.edges.some((e) => e.kind === 'attachment-policy' && e.external === 'aws-managed'));
  assert.ok(!r1.groups.find((x) => x.role.endsWith('::b')).edges.length);
  // Two same-provider roles with the name: ambiguous, never guessed.
  const r2 = scanPulumi({ text: JSON.stringify({ steps: [prov, role('a'), role('c'), att('arn:aws:iam::aws:policy/ReadOnlyAccess')] }), ...OPTS });
  assert.ok(r2.unresolvedEdges.some((e) => e.kind === 'attachment-role' && e.reason === 'ambiguous'));
});

test('P9: groups never change a verdict', () => {
  for (const f of ['preview-create.json', 'preview-update.json', 'seed-state.json']) {
    const r = scanPulumi({ text: fx(f), ...OPTS });
    const strip = (x) => JSON.stringify({ e: x.exitCode, d: x.documents.map((d) => [d.artifact, d.result.exitCode, d.result.findings.map((y) => y.id)]) });
    const { groups: _g, unresolvedEdges: _u, ...rest } = r;
    assert.equal(strip(rest), strip(r), f);
  }
});
