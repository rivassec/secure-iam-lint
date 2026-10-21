// The 8854f5c review's rules-lane items: F1-01/F1-02 (OBJECT-ACL-WRITE),
// F1-03/F1-04 (allResourcesNamed breadth), F2-05/F2-06 (DB-AUTH matching + pin).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const run = (statements) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family: 'identity', partition: 'aws', threshold: 'high', subjectAccount: ACCT,
});
const allow = (action, resource) => ({ Effect: 'Allow', Action: action, Resource: resource });
const find = (r, id) => r.findings.filter((f) => f.id === id);

test('F1-01/F1-02: object-ACL writes are reported, scaled by scope', () => {
  // bucket/* and the PutObject* family: high, blocking.
  for (const action of ['s3:PutObjectAcl', 's3:PutObject*', 's3:PutObjectVersionAcl']) {
    const r = run([allow(action, 'arn:aws:s3:::example-bucket/*')]);
    assert.equal(r.exitCode, EXIT.FINDINGS, action);
    const f = find(r, 'OBJECT-ACL-WRITE');
    assert.equal(f.length, 1, action);
    assert.equal(f[0].severity, 'high', action);
  }
  // A single named object: medium, below the default threshold.
  const one = run([allow('s3:PutObjectAcl', `arn:aws:s3:::example-bucket/reports/annual.pdf`)]);
  assert.equal(one.exitCode, EXIT.CLEAN);
  assert.equal(find(one, 'OBJECT-ACL-WRITE')[0].severity, 'medium');
  // Resource '*' stays high.
  const star = run([allow('s3:PutObjectAcl', '*')]);
  assert.equal(find(star, 'OBJECT-ACL-WRITE')[0].severity, 'high');
  // G10 holds: PutObject* is still NOT a resource-policy write.
  const po = run([allow('s3:PutObject*', 'arn:aws:s3:::example-bucket/*')]);
  assert.equal(find(po, 'RESOURCE-POLICY-WRITE').length, 0);
  // G8 control: s3:Put* on a bucket keeps RESOURCE-POLICY-WRITE high.
  const g8 = run([allow(['s3:Put*', 's3:Delete*'], 'arn:aws:s3:::example-bucket')]);
  assert.equal(find(g8, 'RESOURCE-POLICY-WRITE')[0].severity, 'high');
});

test('F1-03: GetParametersByPath is never a named read', () => {
  const ssmArn = (id) => `arn:aws:ssm:us-east-1:${ACCT}:parameter${id}`;
  // Root and subtree paths: DATA-EXFIL high, exit 1 (was medium/exit 0).
  for (const [action, id] of [
    ['ssm:GetParametersByPath', '/'],
    ['ssm:GetParametersByPath', '/app'],
    ['ssm:GetParameter*', '/'],
    ['ssm:Get*', '/app'],
  ]) {
    const r = run([allow(action, ssmArn(id))]);
    assert.equal(r.exitCode, EXIT.FINDINGS, `${action} ${id}`);
    assert.equal(find(r, 'DATA-EXFIL')[0].severity, 'high', `${action} ${id}`);
  }
  // A plain GetParameter on one concrete parameter stays named: medium, exit 0.
  const one = run([allow('ssm:GetParameter', ssmArn('/app/db-host'))]);
  assert.equal(one.exitCode, EXIT.CLEAN);
  assert.equal(find(one, 'DATA-EXFIL')[0].severity, 'medium');
  // The degenerate ids never name a parameter even under plain GetParameter.
  for (const id of ['', '/']) {
    const r = run([allow('ssm:GetParameter', ssmArn(id))]);
    assert.equal(find(r, 'DATA-EXFIL')[0].severity, 'high', `id="parameter${id}"`);
  }
});

test('F1-04: "?" counts as named only as the trailing -?????? suffix', () => {
  const sec = (id) => `arn:aws:secretsmanager:us-east-1:${ACCT}:secret:${id}`;
  // The AWS random suffix still names one secret: medium.
  const sfx = run([allow('secretsmanager:GetSecretValue', sec('app/db-??????'))]);
  assert.equal(find(sfx, 'DATA-EXFIL')[0].severity, 'medium');
  // Any other ?-run names a length class: high.
  for (const id of [`prod/${'?'.repeat(30)}`, 'app/db-?????', 'ap?/db-AbCdEf']) {
    const r = run([allow('secretsmanager:GetSecretValue', sec(id))]);
    assert.equal(find(r, 'DATA-EXFIL')[0].severity, 'high', id);
  }
});

test('F2-05/F2-06: DB-AUTH matches rds-db:* and pins only concrete dbuser ARNs', () => {
  const dbuser = (id) => `arn:aws:rds-db:us-east-1:${ACCT}:dbuser:${id}`;
  // rds-db:* is exactly rds-db:connect: DB-AUTH fires (F2-05).
  const star = run([allow('rds-db:*', '*')]);
  assert.equal(find(star, 'DB-AUTH')[0].severity, 'high');
  assert.equal(find(run([allow('rds-db:*', dbuser('cluster-ABC/app'))]), 'DB-AUTH')[0].severity, 'medium');
  // F2-06: variables/non-ARNs are not pins.
  assert.equal(find(run([allow('rds-db:connect', dbuser('${aws:PrincipalTag/c}/app'))]), 'DB-AUTH')[0].severity, 'high');
  assert.equal(find(run([allow('rds-db:connect', 'cluster-ABC/app')]), 'DB-AUTH')[0].severity, 'high');
  // The documented per-user idiom stays pinned.
  assert.equal(find(run([allow('rds-db:connect', dbuser('cluster-ABC/${aws:username}'))]), 'DB-AUTH')[0].severity, 'medium');
  // Other variables in the user segment are not pins.
  assert.equal(find(run([allow('rds-db:connect', dbuser('cluster-ABC/${aws:PrincipalTag/u}'))]), 'DB-AUTH')[0].severity, 'high');
});
