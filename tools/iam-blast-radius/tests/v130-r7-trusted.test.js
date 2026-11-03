// v1.3.0 round 7: the explicit trusted-account list (--trusted-account-id / trusted-account-ids).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { scanPulumi } from '../../../cli/pulumi.mjs';
import { toJsonReport } from '../../../cli/iam-br.mjs';
import { runAction } from '../../../action/index.mjs';
import { parseTrustedAccountIds } from '../../../cli/trusted-accounts.mjs';

const T = '444455556666';
const U = '777788889999';
const trust = (p, cond) => JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: p }, Action: 'sts:AssumeRole', ...(cond ? { Condition: cond } : {}) }] });
const run = (p, o = {}) => scan({ text: trust(p), family: 'role-trust', partition: 'aws', ...o });
const ids = (r) => r.findings.map((f) => `${f.id}:${f.severity}`);
const L = { trustedAccountIds: [T] };

test('a listed account\'s exact role is medium; the why names the list', () => {
  const r = run(`arn:aws:iam::${T}:role/deployer`, L);
  assert.deepEqual(ids(r), ['TRUST-CROSS-ACCOUNT:medium']);
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.match(r.findings[0].why, /listed as trusted \(trusted-account-ids\)/);
  assert.deepEqual(ids(run(`arn:aws:sts::${T}:assumed-role/x/s`, L)), ['TRUST-CROSS-ACCOUNT:medium']);
});

test('guards: unlisted, root, bare id, mixed, wildcard and no list stay high', () => {
  assert.deepEqual(ids(run(`arn:aws:iam::${U}:role/deployer`, L)), ['TRUST-CROSS-ACCOUNT:high']);
  assert.deepEqual(ids(run(`arn:aws:iam::${T}:root`, L)), ['TRUST-CROSS-ACCOUNT:high']);
  assert.deepEqual(ids(run(T, L)), ['TRUST-CROSS-ACCOUNT:high']);
  assert.deepEqual(ids(run([`arn:aws:iam::${T}:role/a`, `arn:aws:iam::${U}:role/b`], L)), ['TRUST-CROSS-ACCOUNT:high']);
  assert.ok(!ids(run(`arn:aws:iam::${T}:role/*`, L)).some((x) => x.endsWith(':medium') || x.endsWith(':low')));
  assert.deepEqual(ids(run(`arn:aws:iam::${T}:role/deployer`)), ['TRUST-CROSS-ACCOUNT:high']);
});

test('a confused-deputy constraint still lowers further; the list never raises', () => {
  const r = scan({ text: trust(`arn:aws:iam::${T}:role/deployer`, { StringEquals: { 'sts:ExternalId': 'x-1' } }), family: 'role-trust', partition: 'aws', ...L });
  assert.deepEqual(ids(r), ['TRUST-CROSS-ACCOUNT:low']);
});

test('parsing: comma and newline lists, dedup and sort; an invalid id is a usage error', () => {
  assert.deepEqual(parseTrustedAccountIds(`${U}, ${T}\n${T}`).ids, [T, U]);
  assert.equal(parseTrustedAccountIds(null).ids, null);
  assert.equal(run(`arn:aws:iam::${T}:role/deployer`, { trustedAccountIds: ['12'] }).exitCode, EXIT.USAGE);
  assert.deepEqual(toJsonReport(run(`arn:aws:iam::${T}:role/deployer`, L), { trustedAccountIds: [`${U},${T}`] }).trustedAccountIdsAsserted, [T, U]);
  assert.equal(toJsonReport(run(`arn:aws:iam::${T}:role/deployer`), {}).trustedAccountIdsAsserted, null);
});

test('the Action honors trusted-account-ids and refuses a bad list', () => {
  const io = { readFile: (rel) => { if (rel !== 't.json') throw new Error('ENOENT'); return trust(`arn:aws:iam::${T}:role/deployer`); }, listFiles: () => ['t.json'] };
  const env = { INPUT_PATHS: 't.json', INPUT_FAMILY: 'role-trust', INPUT_PARTITION: 'aws' };
  assert.equal(runAction({ env, io }).exitCode, EXIT.FINDINGS);
  assert.equal(runAction({ env: { ...env, 'INPUT_TRUSTED-ACCOUNT-IDS': T }, io }).exitCode, EXIT.CLEAN);
  assert.equal(runAction({ env: { ...env, 'INPUT_TRUSTED-ACCOUNT-IDS': '::bad' }, io }).exitCode, EXIT.USAGE);
});

test('the Pulumi path honors the list', () => {
  const PRV = 'urn:pulumi:dev::p::pulumi:providers:aws::aws';
  const role = 'urn:pulumi:dev::p::aws:iam/role:Role::r';
  const text = JSON.stringify({ deployment: { resources: [
    { urn: PRV, type: 'pulumi:providers:aws', custom: true, inputs: { region: 'us-east-1' } },
    { urn: role, type: 'aws:iam/role:Role', custom: true, provider: `${PRV}::id1`, inputs: { name: 'r', assumeRolePolicy: trust(`arn:aws:iam::${T}:role/deployer`) } },
  ] } });
  const doc = (r) => r.documents.find((d) => d.urn === role).result;
  assert.deepEqual(ids(doc(scanPulumi({ text, partition: 'aws', subjectAccount: '111122223333' }))), ['TRUST-CROSS-ACCOUNT:high']);
  assert.deepEqual(ids(doc(scanPulumi({ text, partition: 'aws', subjectAccount: '111122223333', trustedAccountIds: [T] }))), ['TRUST-CROSS-ACCOUNT:medium']);
  assert.equal(scanPulumi({ text, trustedAccountIds: ['x'] }).exitCode, EXIT.USAGE);
});
