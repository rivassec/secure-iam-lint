// v1.2.0 severity calibration: G6/G7/G11 (DATA-EXFIL breadth) and T1-01/T1-02
// (trust scoring of account-open PrincipalArn and resource-side variables).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const run = (statements, { family = 'identity', partition = 'aws' } = {}) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family, partition, threshold: 'high', subjectAccount: ACCT,
});
const find = (r, id) => r.findings.find((f) => f.id === id);

const SECRET = `arn:aws:secretsmanager:us-east-2:${ACCT}:secret:/app/prod/api-key-AbCdEf`;

test('G11: a secret read on named resources is medium, not high', () => {
  // Exact ARN and the AWS -?????? random-suffix form are both "one named secret".
  for (const res of [SECRET, `${SECRET.slice(0, -6)}??????`]) {
    const r = run([{ Effect: 'Allow', Action: 'secretsmanager:GetSecretValue', Resource: res }]);
    const f = find(r, 'DATA-EXFIL');
    assert.ok(f, res);
    assert.equal(f.severity, 'medium', res);
    assert.equal(r.exitCode, EXIT.CLEAN, res); // medium does not block at high
  }
});

test('G11: ambiguous breadth stays high (fail closed)', () => {
  const g = (resource) => [{ Effect: 'Allow', Action: 'secretsmanager:GetSecretValue', Resource: resource }];
  for (const res of [
    [SECRET, '*'], // one broad element widens the statement
    `arn:aws:secretsmanager:us-east-2:${ACCT}:secret:/app/*`, // '*' in the id
    `arn:aws:secretsmanager:us-east-2:*:secret:/app/x`, // wildcard account
    'arn:aws:secretsmanager:us-east-2:${aws:PrincipalTag/acct}:secret:/app/x', // variable
  ]) {
    const r = run(g(res));
    const f = find(r, 'DATA-EXFIL');
    assert.ok(f, JSON.stringify(res));
    assert.equal(f.severity, 'high', JSON.stringify(res));
  }
  // NotResource is never named.
  const nr = run([{ Effect: 'Allow', Action: 'secretsmanager:GetSecretValue', NotResource: SECRET }]);
  assert.equal(find(nr, 'DATA-EXFIL').severity, 'high');
});

test('G6/G7: account-wide secret/parameter reads stay high', () => {
  const g6 = run([{ Effect: 'Allow', Action: ['ssm:GetParameter', 'ssm:GetParametersByPath'], Resource: '*' }]);
  assert.equal(find(g6, 'DATA-EXFIL').severity, 'high');
  assert.equal(g6.exitCode, EXIT.FINDINGS);
  const g7 = run([{ Effect: 'Allow', Action: ['secretsmanager:Get*', 'secretsmanager:Describe*', 'secretsmanager:List*'], Resource: '*' }]);
  assert.equal(find(g7, 'DATA-EXFIL').severity, 'high');
  assert.equal(g7.exitCode, EXIT.FINDINGS);
});

const pub = (condition) => [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole', Condition: condition }];
const trust = (statements) => run(statements, { family: 'role-trust' });

test('T1-01: an account-open aws:PrincipalArn is public-equivalent (critical)', () => {
  for (const cond of [
    { ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy' } },
    { StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::${aws:PrincipalAccount}:role/deploy' } },
    { ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::????????????:role/deploy' } },
  ]) {
    const r = trust(pub(cond));
    const f = find(r, 'TRUST-PUBLIC');
    assert.ok(f, JSON.stringify(cond));
    assert.equal(f.severity, 'critical', JSON.stringify(cond));
  }
});

test('T1-01: controls keep their scoring', () => {
  // A truncated/junk value matches no one: stays the fail-closed broad high (S7-4).
  const junk = trust(pub({ StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam' } }));
  assert.equal(find(junk, 'TRUST-PUBLIC').severity, 'high');
  // An exact concrete-account ARN is a genuine single-principal scope (not critical).
  const exact = trust(pub({ ArnEquals: { 'aws:PrincipalArn': `arn:aws:iam::444455556666:role/deploy` } }));
  assert.notEqual(find(exact, 'TRUST-CROSS-ACCOUNT').severity, 'critical'); // R5-5: named form
});

test('T1-02: resource-side variables read as pinned, not caller-controlled', () => {
  // The AWS data-perimeter idioms confine trust to the role's own account/org: high.
  const acct = trust(pub({ StringEquals: { 'aws:PrincipalAccount': '${aws:ResourceAccount}' } }));
  assert.equal(find(acct, 'TRUST-PUBLIC').severity, 'high');
  const org = trust(pub({ StringEquals: { 'aws:PrincipalOrgID': '${aws:ResourceOrgID}' } }));
  assert.equal(find(org, 'TRUST-PUBLIC').severity, 'high');
  // In an ARN account segment it resolves from the resource: not account-open.
  const arn = trust(pub({ ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::${aws:ResourceAccount}:role/ci' } }));
  assert.notEqual(find(arn, 'TRUST-PUBLIC').severity, 'critical');
});
