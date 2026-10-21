// v1.2.0 review round 2, root cause A: the catalog is not a wildcard's full reach.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const run = (statements) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family: 'identity', partition: 'aws', threshold: 'high', subjectAccount: ACCT,
});
const ids = (r) => r.findings.map((f) => f.id);
const sev = (r, id) => (r.findings.find((f) => f.id === id) || {}).severity;
const allow = (Action, Resource = '*') => ({ Effect: 'Allow', Action, Resource });
const deny = (Action, Resource = '*', extra = {}) => ({ Effect: 'Deny', Action, Resource, ...extra });

test('V2-1: a Deny of the catalogued reads does not cover ssm:GetParameter*', () => {
  const r = run([allow('ssm:GetParameter*'), deny(['ssm:GetParameter', 'ssm:GetParameters', 'ssm:GetParametersByPath'])]);
  assert.equal(r.exitCode, EXIT.FINDINGS, ids(r).join(','));
  assert.ok(ids(r).includes('DATA-EXFIL'), ids(r).join(','));
  const sm = run([allow('secretsmanager:*'), deny('secretsmanager:GetSecretValue')]);
  assert.notEqual(sm.exitCode, EXIT.CLEAN, ids(sm).join(','));
});

test('V2-2: a Deny of StopLogging does not cover cloudtrail:Stop*', () => {
  const trail = `arn:aws:cloudtrail:us-east-2:${ACCT}:trail/example`;
  const r = run([allow('cloudtrail:Stop*', trail), deny('cloudtrail:StopLogging', trail)]);
  assert.equal(r.exitCode, EXIT.FINDINGS, ids(r).join(','));
  assert.ok(ids(r).includes('DETECTION-IMPAIRMENT'), ids(r).join(','));
});

test('V2-3: ec2:* + PassRole stays critical under a catalogued-exec Deny', () => {
  const r = run([allow(['ec2:*', 'iam:PassRole']),
    deny(['ec2:RunInstances', 'ec2:AssociateIamInstanceProfile', 'ec2:ReplaceIamInstanceProfileAssociation'])]);
  assert.equal(sev(r, 'PASSROLE-EC2'), 'critical', ids(r).join(','));
});

test('V2-4: ArnLike on iam:PassedToService is not a certain Deny', () => {
  const r = run([allow(['iam:PassRole', 'lambda:CreateFunction']),
    deny('iam:PassRole', '*', { Condition: { ArnLike: { 'iam:PassedToService': 'lambda.amazonaws.com' } } })]);
  assert.equal(sev(r, 'PASSROLE-LAMBDA'), 'critical', ids(r).join(','));
  const se = run([allow(['iam:PassRole', 'lambda:CreateFunction']),
    deny('iam:PassRole', '*', { Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } })]);
  assert.ok(!ids(se).includes('PASSROLE-LAMBDA'), ids(se).join(','));
});

test('V2-5: iam:Create* keeps CREDENTIAL-CREATION under a Deny of the catalogued creates', () => {
  const r = run([allow('iam:Create*'), deny(['iam:CreatePolicy', 'iam:CreatePolicyVersion', 'iam:CreateUser',
    'iam:CreateRole', 'iam:CreateAccessKey', 'iam:CreateLoginProfile', 'iam:CreateOpenIDConnectProvider', 'iam:CreateSAMLProvider'])]);
  assert.ok(ids(r).includes('CREDENTIAL-CREATION'), ids(r).join(','));
});

test('controls: a Deny covering the grant token still suppresses', () => {
  assert.equal(run([allow('ssm:GetParameter*'), deny('ssm:GetParameter*')]).exitCode, EXIT.CLEAN);
  assert.equal(run([allow('ssm:GetParameter*'), deny('ssm:*')]).exitCode, EXIT.CLEAN);
  assert.equal(run([allow('*'), deny('*')]).exitCode, EXIT.CLEAN);
  // T1-04: a service-wide Deny still removes that service's paths from Allow *.
  const r = run([allow('*'), deny(['iam:*', 'sts:*'])]);
  assert.ok(!ids(r).includes('CREDENTIAL-CREATION'), ids(r).join(','));
  // A partial service Deny under Allow * only narrows.
  const p = run([allow('*'), deny(['iam:CreateAccessKey', 'iam:CreateLoginProfile', 'iam:UpdateLoginProfile', 'sts:GetFederationToken'])]);
  assert.ok(ids(p).includes('CREDENTIAL-CREATION'), ids(p).join(','));
});
