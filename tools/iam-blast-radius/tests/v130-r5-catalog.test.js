// v1.3.0 r5: ecr/codeartifact/scheduler/eks snapshotted Deny-only; CI/ECS role actions known in an Allow.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const run = (text, family) => scan({ text, family, partition: 'aws', subjectAccount: ACCT });
const unknown = (r) => JSON.stringify(r).includes('UNKNOWN_ACTION');
const allow = (action, resource = '*') => run(P({ Effect: 'Allow', Action: action, Resource: resource }), 'identity');
const LOG = `arn:aws:logs:us-east-1:${ACCT}:log-group:x:*`;
const REPO = `arn:aws:ecr:us-east-1:${ACCT}:repository/r`;

const PICKS = {
  ecr: 'ecr:PutImage',
  codeartifact: 'codeartifact:DeleteRepository',
  scheduler: 'scheduler:CreateSchedule',
  eks: 'eks:CreateCluster',
};
for (const [svc, action] of Object.entries(PICKS)) {
  test(`${svc}: ${action} in a Deny is known; in an Allow it fails closed`, () => {
    const d = run(P({ Effect: 'Deny', Action: action, Resource: '*' }), 'scp-rcp');
    assert.ok(!unknown(d), `Deny reported UNKNOWN_ACTION (rc ${d.exitCode})`);
    assert.equal(allow(action).exitCode, EXIT.FAIL_CLOSED);
  });
}

test('control: a made-up ecr action is still UNKNOWN_ACTION in a Deny', () => {
  assert.ok(unknown(run(P({ Effect: 'Deny', Action: 'ecr:NoSuchAction', Resource: '*' }), 'scp-rcp')));
});

const C2 = [
  ['logs:CreateLogStream', LOG], ['logs:PutLogEvents', LOG], ['logs:CreateLogGroup', LOG],
  ['logs:DescribeLogGroups', '*'], ['logs:DescribeLogStreams', LOG],
  ['logs:DescribeMetricFilters', '*'], ['logs:DescribeSubscriptionFilters', '*'],
  ['ecr:GetAuthorizationToken', '*'], ['ecr:BatchCheckLayerAvailability', REPO],
  ['ecr:GetDownloadUrlForLayer', REPO], ['ecr:BatchGetImage', REPO],
];
for (const [action, res] of C2) {
  test(`${action} on ${res === '*' ? '*' : 'a narrow ARN'} is known in an Allow (not exit 3)`, () => {
    const r = allow(action, res);
    assert.notEqual(r.exitCode, EXIT.FAIL_CLOSED, JSON.stringify(r.findings));
    assert.ok(!unknown(r));
  });
}

test('log write actions on * still report WILDCARD-RESOURCE (existing detector)', () => {
  const r = allow(['logs:CreateLogStream', 'logs:PutLogEvents'], '*');
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(r.findings.some((f) => f.id === 'WILDCARD-RESOURCE'));
});

for (const [action, res] of [['logs:GetLogEvents', LOG], ['logs:FilterLogEvents', LOG], ['logs:GetQueryResults', '*'],
  ['logs:StartQuery', LOG], ['logs:GetLogRecord', '*'], ['ecr:PutImage', REPO],
  ['codeartifact:GetAuthorizationToken', '*'], ['eks:AccessKubernetesApi', '*']]) {
  test(`${action} in an Allow still fails closed`, () => {
    assert.equal(allow(action, res).exitCode, EXIT.FAIL_CLOSED);
    assert.equal(allow(action).exitCode, EXIT.FAIL_CLOSED);
  });
}

test('typical CI/ECS role shape is analyzable (not exit 3)', () => {
  const r = run(P(
    { Effect: 'Allow', Action: 'ecr:GetAuthorizationToken', Resource: '*' },
    { Effect: 'Allow', Action: ['ecr:BatchCheckLayerAvailability', 'ecr:GetDownloadUrlForLayer', 'ecr:BatchGetImage'], Resource: REPO },
    { Effect: 'Allow', Action: ['logs:CreateLogStream', 'logs:PutLogEvents'], Resource: LOG },
  ), 'identity');
  assert.equal(r.exitCode, EXIT.CLEAN, JSON.stringify(r.findings));
});
