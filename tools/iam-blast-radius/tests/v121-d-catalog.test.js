// v1.2.0 group D: F15 (risky actions only surfaced as UNKNOWN_ACTION) and T2-3.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const run = (statements) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family: 'identity', partition: 'aws', threshold: 'high', subjectAccount: ACCT,
});
const allow = (Action, Resource) => ({ Effect: 'Allow', Action, Resource });
const ids = (r) => r.findings.map((f) => f.id);

test('F15: every newly catalogued action names its risk at high (never 3 -> 0)', () => {
  const cases = [
    ['ec2:ModifySnapshotAttribute', `arn:aws:ec2:us-east-2:${ACCT}:snapshot/snap-0abc`, 'RESOURCE-POLICY-WRITE'],
    ['ec2:ModifyImageAttribute', `arn:aws:ec2:us-east-2::image/ami-0abc`, 'RESOURCE-POLICY-WRITE'],
    ['rds:ModifyDBSnapshotAttribute', `arn:aws:rds:us-east-2:${ACCT}:snapshot:s`, 'RESOURCE-POLICY-WRITE'],
    ['rds:ModifyDBClusterSnapshotAttribute', `arn:aws:rds:us-east-2:${ACCT}:cluster-snapshot:s`, 'RESOURCE-POLICY-WRITE'],
    ['iam:CreateOpenIDConnectProvider', '*', 'DIRECT-IAM-ADMIN'],
    ['iam:UpdateOpenIDConnectProviderThumbprint', `arn:aws:iam::${ACCT}:oidc-provider/x`, 'DIRECT-IAM-ADMIN'],
    ['iam:AddClientIDToOpenIDConnectProvider', `arn:aws:iam::${ACCT}:oidc-provider/x`, 'DIRECT-IAM-ADMIN'],
    ['iam:CreateSAMLProvider', '*', 'DIRECT-IAM-ADMIN'],
    ['iam:UpdateSAMLProvider', `arn:aws:iam::${ACCT}:saml-provider/x`, 'DIRECT-IAM-ADMIN'],
    ['iam:TagRole', `arn:aws:iam::${ACCT}:role/x`, 'DIRECT-IAM-ADMIN'],
    ['iam:TagUser', `arn:aws:iam::${ACCT}:user/x`, 'DIRECT-IAM-ADMIN'],
    ['kms:ScheduleKeyDeletion', `arn:aws:kms:us-east-2:${ACCT}:key/1234abcd-12ab-34cd-56ef-1234567890ab`, 'DESTRUCTIVE-ACTION'],
    ['ec2:ModifyInstanceAttribute', `arn:aws:ec2:us-east-2:${ACCT}:instance/i-0123456789abcdef0`, 'COMPUTE-CODE-OVERWRITE'],
  ];
  for (const [action, res, want] of cases) {
    const r = run([allow(action, res)]);
    assert.equal(r.exitCode, EXIT.FINDINGS, action);
    const f = r.findings.find((x) => x.id === want);
    assert.ok(f, `${action}: ${ids(r)}`);
    assert.ok(['high', 'critical'].includes(f.severity), `${action}: ${f.severity}`);
  }
});

test('F15: new why-text is specific; existing wording is unchanged', () => {
  const why = (stmts, id) => run(stmts).findings.find((f) => f.id === id).why;
  assert.match(why([allow('iam:UpdateSAMLProvider', '*')], 'DIRECT-IAM-ADMIN'), /federation backdoor/);
  assert.match(why([allow('iam:TagRole', '*')], 'DIRECT-IAM-ADMIN'), /ABAC/);
  assert.match(why([allow('ec2:ModifySnapshotAttribute', '*')], 'RESOURCE-POLICY-WRITE'), /share a copy/);
  // iam:* and the original actions keep the generic text (no golden churn).
  assert.match(why([allow('iam:*', '*')], 'DIRECT-IAM-ADMIN'), /^Grants direct IAM administration/);
  assert.match(why([allow('iam:CreateUser', '*')], 'DIRECT-IAM-ADMIN'), /^Grants direct IAM administration/);
  // Mixed old + new actions keep the generic text too.
  assert.match(why([allow(['iam:CreateUser', 'iam:TagRole'], '*')], 'DIRECT-IAM-ADMIN'), /^Grants direct IAM administration/);
  assert.match(why([allow('s3:PutBucketPolicy', 'arn:aws:s3:::b')], 'RESOURCE-POLICY-WRITE'), /^Grants a resource-policy write/);
});

test('F15: a same-policy Deny still removes the new findings', () => {
  for (const a of ['kms:ScheduleKeyDeletion', 'iam:TagRole', 'ec2:ModifySnapshotAttribute']) {
    const r = run([allow(a, '*'), { Effect: 'Deny', Action: a, Resource: '*' }]);
    assert.equal(r.exitCode, EXIT.CLEAN, `${a}: ${ids(r)}`);
  }
});

test('T2-3: PassRole + iam:AddRoleToInstanceProfile is PASSROLE-EC2', () => {
  const pr = allow('iam:PassRole', `arn:aws:iam::${ACCT}:role/admin`);
  for (const ip of [`arn:aws:iam::${ACCT}:instance-profile/web`, `arn:aws:iam::${ACCT}:instance-profile/*`]) {
    const r = run([pr, allow('iam:AddRoleToInstanceProfile', ip)]);
    assert.equal(r.exitCode, EXIT.FINDINGS, ip);
    assert.ok(ids(r).includes('PASSROLE-EC2'), `${ip}: ${ids(r)}`);
  }
  // A PassRole pinned away from EC2 does not complete the path.
  const pinned = run([{ ...pr, Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } },
    allow('iam:AddRoleToInstanceProfile', `arn:aws:iam::${ACCT}:instance-profile/web`)]);
  assert.ok(!ids(pinned).includes('PASSROLE-EC2'), ids(pinned).join(','));
});

test('T2-3: bare iam:* keeps its v1.2.0 shape (whether it is critical is F6)', () => {
  const r = run([allow('iam:*', '*')]);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(ids(r).includes('DIRECT-IAM-ADMIN'), ids(r).join(','));
  assert.ok(!ids(r).includes('PASSROLE-EC2'), ids(r).join(','));
  // An explicit grant beside iam:* still completes the path.
  const ex = run([allow('iam:*', '*'), allow('iam:AddRoleToInstanceProfile', `arn:aws:iam::${ACCT}:instance-profile/web`)]);
  assert.ok(ids(ex).includes('PASSROLE-EC2'), ids(ex).join(','));
});

test('T2-3: AddRoleToInstanceProfile alone matches the AssociateIamInstanceProfile precedent', () => {
  // AWS requires iam:PassRole for both; alone neither moves a role.
  const ip = run([allow('iam:AddRoleToInstanceProfile', `arn:aws:iam::${ACCT}:instance-profile/web`)]);
  const assoc = run([allow('ec2:AssociateIamInstanceProfile', `arn:aws:ec2:us-east-2:${ACCT}:instance/i-0abc`)]);
  assert.equal(ip.exitCode, assoc.exitCode);
});
