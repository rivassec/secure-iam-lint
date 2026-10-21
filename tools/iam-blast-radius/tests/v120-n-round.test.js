// 6f64883 confirmation round: N1 (variable account silenced PASSROLE-UNSCOPED), N3.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const run = (action, Resource) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: action, Resource }] }),
  family: 'identity', partition: 'aws', threshold: 'high', subjectAccount: ACCT,
});
const ids = (r) => r.findings.map((f) => f.id);

test('N1: a ${...} account never silences PASSROLE-UNSCOPED', () => {
  for (const v of ['${aws:PrincipalAccount}', '${aws:ResourceAccount}', '${aws:PrincipalTag/acct}']) {
    const r = run('iam:PassRole', `arn:aws:iam::${v}:role/*`);
    assert.equal(r.exitCode, EXIT.FINDINGS, v);
    assert.ok(ids(r).includes('PASSROLE-UNSCOPED'), `${v}: ${ids(r)}`);
  }
  // A literal name prefix stays a real scope, with or without a variable account.
  for (const res of [`arn:aws:iam::${ACCT}:role/app-*`, 'arn:aws:iam::${aws:PrincipalAccount}:role/app-*',
    `arn:aws:iam::${ACCT}:role/\${aws:username}`]) {
    assert.ok(!ids(run('iam:PassRole', res)).includes('PASSROLE-UNSCOPED'), res);
  }
});

test('N1: sts:AssumeRole on a variable-account role/* still reports', () => {
  const r = run('sts:AssumeRole', 'arn:aws:iam::${aws:PrincipalAccount}:role/*');
  assert.ok(ids(r).includes('ASSUME-ROLE-EXPANSION'), ids(r).join(','));
});

test('N3: a wildcard-only role name bounds length, not which roles', () => {
  for (const name of ['??????????', `*${'?'.repeat(20)}`, '?*']) {
    const r = run('iam:PassRole', `arn:aws:iam::${ACCT}:role/${name}`);
    assert.ok(ids(r).includes('PASSROLE-UNSCOPED'), `${name}: ${ids(r)}`);
  }
});
