// F2 escalation items from the Mac's 8854f5c review: F2-01/02/03/04/07.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const run = (statements, { partition = 'aws', subjectAccount = ACCT } = {}) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family: 'identity', partition, threshold: 'high', subjectAccount,
});
const ids = (r) => r.findings.map((f) => f.id);
const by = (r, id) => r.findings.filter((f) => f.id === id);

const assoc = (part) => ({ Effect: 'Allow', Action: 'ec2:AssociateIamInstanceProfile', Resource: `arn:${part}:ec2:us-east-1:${ACCT}:instance/i-0abc` });

test('F2-01: every surviving companion feeds partition evidence; order never flips the verdict', () => {
  const pr = (v) => ({ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { StringNotEquals: { 'iam:PassedToService': v } } });
  // Two companions in different worlds: mixed evidence fails closed, the live
  // aws-world path (deny names only the .cn spelling) is reported.
  const a = run([pr('ec2.amazonaws.com.cn'), assoc('aws-cn'), assoc('aws')], { partition: null });
  assert.ok(ids(a).includes('PASSROLE-EC2'), ids(a).join(','));
  // Same statements, both orders, same answer.
  const b = run([assoc('aws'), pr('ec2.amazonaws.com'), assoc('aws-cn')], { partition: null });
  const c = run([assoc('aws-cn'), pr('ec2.amazonaws.com'), assoc('aws')], { partition: null });
  assert.deepEqual(ids(b).sort(), ids(c).sort());
  assert.ok(ids(b).includes('PASSROLE-EC2'), ids(b).join(','));
});

test('F2-02: NotResource and negated-condition ARNs poison the world, never vanish', () => {
  // cn ARN only in NotResource: the deny of the canonical spelling cannot be
  // credited as covering the cn world the text implies.
  const nr = run([
    { Effect: 'Allow', Action: 'iam:PassRole', NotResource: `arn:aws-cn:iam::${ACCT}:role/other`, Condition: { StringNotEquals: { 'iam:PassedToService': 'ec2.amazonaws.com' } } },
    { Effect: 'Allow', Action: 'ec2:AssociateIamInstanceProfile', Resource: '*' },
  ], { partition: null });
  assert.ok(ids(nr).includes('PASSROLE-EC2'), ids(nr).join(','));
  // cn ARN under a negated condition operator: same.
  const neg = run([
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { StringNotEquals: { 'iam:PassedToService': 'ec2.amazonaws.com' }, ArnNotLike: { 'iam:AssociatedResourceArn': `arn:aws-cn:ec2:cn-north-1:${ACCT}:instance/i-0abc` } } },
    { Effect: 'Allow', Action: 'ec2:AssociateIamInstanceProfile', Resource: '*' },
  ], { partition: null });
  assert.ok(ids(neg).includes('PASSROLE-EC2'), ids(neg).join(','));
});

test('F2-03: any pattern that reaches an arbitrary role name is unscoped', () => {
  const shapes = [
    `arn:aws:iam::${ACCT}:*`, 'arn:aws:iam::*:*', `arn:aws:iam::${ACCT}:role*`,
    `arn:aws:iam::${ACCT}:r*`, `arn:aws:iam::${ACCT}:role/*/*`, `arn:aws:iam::${ACCT}:role/**`,
    `arn:aws:iam::${ACCT}:role/?*`, 'arn:aws:*:*:*:*',
  ];
  for (const r of shapes) {
    const out = run([{ Effect: 'Allow', Action: 'iam:PassRole', Resource: r }]);
    assert.ok(ids(out).includes('PASSROLE-UNSCOPED'), `${r}: ${ids(out)}`);
  }
  // Deliberate scopes stay quiet.
  for (const r of [`arn:aws:iam::${ACCT}:role/service-role/*`, `arn:aws:iam::${ACCT}:role/a*`, `arn:aws:iam::${ACCT}:role/zz-*`, `arn:aws:iam::${ACCT}:role/app`]) {
    const out = run([{ Effect: 'Allow', Action: 'iam:PassRole', Resource: r }]);
    assert.ok(!ids(out).includes('PASSROLE-UNSCOPED'), `${r}: ${ids(out)}`);
  }
});

test('F2-04: UNSCOPED is withheld per consumed statement, not per document', () => {
  const narrowLambda = { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/lam`, Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } };
  const lambdaExec = { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' };
  const broadEc2 = { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { StringEquals: { 'iam:PassedToService': 'ec2.amazonaws.com' } } };
  const r = run([narrowLambda, lambdaExec, broadEc2]);
  assert.ok(ids(r).includes('PASSROLE-LAMBDA'), ids(r).join(','));
  assert.ok(ids(r).includes('PASSROLE-UNSCOPED'), ids(r).join(','));
  // The statement a compound path consumed does not double-report.
  const same = run([{ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' }, lambdaExec]);
  assert.ok(ids(same).includes('PASSROLE-LAMBDA'), ids(same).join(','));
  assert.ok(!ids(same).includes('PASSROLE-UNSCOPED'), ids(same).join(','));
});

test('F2-07: deny suppression, one finding per document, pin-aware remediation', () => {
  const broad = { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' };
  // A Deny over every subject role leaves nothing to pass.
  const denied = run([broad, { Effect: 'Deny', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/*` }]);
  assert.ok(!ids(denied).includes('PASSROLE-UNSCOPED'), ids(denied).join(','));
  // Without the subject account the deny's account may not be the caller's: fail closed, keep firing.
  const unknown = run([broad, { Effect: 'Deny', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/*` }], { subjectAccount: null });
  assert.ok(ids(unknown).includes('PASSROLE-UNSCOPED'), ids(unknown).join(','));
  // A narrowing deny degrades to medium.
  const narrowed = run([broad, { Effect: 'Deny', Action: 'iam:PassRole', NotResource: `arn:aws:iam::${ACCT}:role/app` }]);
  assert.equal(by(narrowed, 'PASSROLE-UNSCOPED')[0]?.severity, 'medium');
  // Two broad statements: one finding, evidence from both.
  const two = run([broad, { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/*` }]);
  assert.equal(by(two, 'PASSROLE-UNSCOPED').length, 1);
  assert.equal(by(two, 'PASSROLE-UNSCOPED')[0].evidence.length, 2);
  // Remediation does not advise a pin that is already there.
  const pinned = run([{ ...broad, Resource: `arn:aws:iam::${ACCT}:role/*`, Condition: { StringEquals: { 'iam:PassedToService': 'ec2.amazonaws.com' } } }]);
  const f = by(pinned, 'PASSROLE-UNSCOPED')[0];
  assert.ok(f, ids(pinned).join(','));
  assert.ok(!/and pin iam:PassedToService/.test(f.remediation), f.remediation);
  const unpinned = by(run([broad]), 'PASSROLE-UNSCOPED')[0];
  assert.ok(/pin iam:PassedToService/.test(unpinned.remediation), unpinned.remediation);
});
