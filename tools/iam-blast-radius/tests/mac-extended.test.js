// Follow-ups from the Mac's extended test of #36-#39.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { run } from '../../../cli/iam-br.mjs';
import { substitutePolicyVars, selfReferenceKeys } from '../../../content/tools/iam-blast-radius/engine/trust-conditions.js';

const trust = (principal, action, condition) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: principal, Action: action, Condition: condition }] }),
  family: 'role-trust', threshold: 'high', subjectAccount: '111122223333', partition: 'aws',
});
const ids = (r) => r.findings.map((f) => `${f.id}:${f.severity}`);
const GH = 'token.actions.githubusercontent.com';
const gh = { Federated: `arn:aws:iam::111122223333:oidc-provider/${GH}` };

test('${...} reads as *; literal parts kept; never tight', () => {
  assert.equal(substitutePolicyVars('repo:acme/${aws:username}:*'), 'repo:acme/*:*');
  assert.equal(substitutePolicyVars(`\${${GH}:sub}`), '*');
  const r = trust(gh, 'sts:AssumeRoleWithWebIdentity', { StringEquals: { [`${GH}:aud`]: 'sts.amazonaws.com', [`${GH}:sub`]: 'repo:acme/${aws:username}' } });
  assert.ok(ids(r).includes('TRUST-FEDERATED:high'), ids(r).join(','));
});

test('a self-reference scores as absent and is named', () => {
  const r = trust(gh, 'sts:AssumeRoleWithWebIdentity', { StringEquals: { [`${GH}:aud`]: 'sts.amazonaws.com', [`${GH}:sub`]: `\${${GH}:sub}` } });
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(ids(r).includes('TRUST-FEDERATED:high'));
  const t = r.findings.find((f) => f.id === 'TRUST-CONDITION-TAUTOLOGY');
  assert.ok(t && t.why.includes(`${GH}:sub`));
});

test('ExternalId / PrincipalOrgID self-references give no confused-deputy credit', () => {
  const xa = { AWS: 'arn:aws:iam::444455556666:root' };
  for (const [key, v] of [['sts:ExternalId', '${sts:ExternalId}'], ['aws:PrincipalOrgID', '${aws:PrincipalOrgID}']]) {
    const r = trust(xa, 'sts:AssumeRole', { StringEquals: { [key]: v } });
    assert.ok(ids(r).includes('TRUST-CROSS-ACCOUNT:high'), `${key}: ${ids(r).join(',')}`);
  }
});

test('selfReferenceKeys is case-insensitive on the key and ignores other variables', () => {
  assert.deepEqual(selfReferenceKeys({ StringEquals: { 'sts:ExternalId': '${STS:EXTERNALID}', 'aws:SourceAccount': '${aws:PrincipalAccount}' } }), ['sts:ExternalId']);
});

test('an exact literal ExternalId keeps its credit', () => {
  const r = trust({ AWS: 'arn:aws:iam::444455556666:root' }, 'sts:AssumeRole', { StringEquals: { 'sts:ExternalId': 'exact-123' } });
  assert.equal(r.exitCode, EXIT.CLEAN);
});

test('CLI accepts --resource-type/--resource-arn/--resource-account', async () => {
  const files = { 'b.json': JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }] }) };
  let out = '';
  const code = await run(['--family', 'resource', '--partition', 'aws', '--resource-type', 's3-bucket', '--resource-arn', 'arn:aws:s3:::b', '--resource-account', '111111111111', 'b.json'], {
    readFile: (p) => files[p], readStdin: async () => '', writeFile: () => {}, stdout: (s) => { out += s; }, stderr: () => {}, stdinIsTTY: true,
  });
  assert.notEqual(code, EXIT.USAGE);
  assert.ok(JSON.parse(out).findings.length > 0);
});

test('L1-02: Principal "*" + exact foreign PrincipalArn scores like the named form', () => {
  const pub = trust('*', 'sts:AssumeRole', { StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::444455556666:role/deploy' } });
  assert.equal(pub.exitCode, EXIT.FINDINGS);
  assert.ok(ids(pub).includes('TRUST-PUBLIC:high'), ids(pub).join(','));
  const named = trust({ AWS: 'arn:aws:iam::444455556666:role/deploy' }, 'sts:AssumeRole', undefined);
  assert.equal(named.exitCode, pub.exitCode);
  // An exact ExternalId correlation lowers it to medium, mirroring the named form.
  const corr = trust('*', 'sts:AssumeRole', {
    StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::444455556666:role/deploy', 'sts:ExternalId': 'exact-123' },
  });
  assert.ok(ids(corr).includes('TRUST-PUBLIC:medium'), ids(corr).join(','));
  assert.equal(corr.exitCode, EXIT.CLEAN);
});
