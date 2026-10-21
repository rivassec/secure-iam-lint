// v1.3.0 branch A: catalog widened for Control Tower guardrail services.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const run = (text, family) => scan({ text, family, partition: 'aws', subjectAccount: ACCT });
const unknown = (r) => JSON.stringify(r).includes('UNKNOWN_ACTION');
const deny = (actions) => P({ Effect: 'Deny', Action: actions, Resource: '*' });
const allow = (action) => P({ Effect: 'Allow', Action: action, Resource: '*' });

// One withheld (unmodeled write/permissions) action per added service.
const PICKS = {
  sns: 'sns:CreateTopic',
  events: 'events:PutRule',
  logs: 'logs:PutRetentionPolicy',
  config: 'config:PutConfigRule',
  lambda: 'lambda:PutFunctionConcurrency',
  cloudformation: 'cloudformation:RegisterType',
  iam: 'iam:PutRolePermissionsBoundary',
};

for (const [svc, action] of Object.entries(PICKS)) {
  test(`${svc}: ${action} in a Deny is known; in an Allow it fails closed`, () => {
    const d = run(deny(action), 'scp-rcp');
    assert.ok(!unknown(d), `Deny reported UNKNOWN_ACTION (rc ${d.exitCode})`);
    const a = run(allow(action), 'identity');
    assert.equal(a.exitCode, EXIT.FAIL_CLOSED, `Allow rc ${a.exitCode}`);
  });
}

const CONTROL_TOWER = `cloudformation:DeregisterType cloudformation:PublishType cloudformation:RegisterType
cloudformation:SetTypeConfiguration cloudformation:SetTypeDefaultVersion config:DeleteAggregationAuthorization
config:DeleteConfigRule config:DeleteConfigurationAggregator config:DeleteEvaluationResults
config:DeleteRetentionConfiguration config:PutConfigRule config:PutConfigurationAggregator
config:PutDeliveryChannel config:PutRetentionConfiguration config:TagResource config:UntagResource
events:DeleteRule events:DisableRule events:PutRule events:PutTargets events:RemoveTargets
iam:DeleteRolePermissionsBoundary iam:PutRolePermissionsBoundary iam:UpdateRole iam:UpdateRoleDescription
lambda:CreateEventSourceMapping lambda:DeleteEventSourceMapping lambda:DeleteFunctionConcurrency
lambda:PutFunctionConcurrency lambda:RemovePermission lambda:UpdateEventSourceMapping
logs:DeleteLogGroup logs:PutRetentionPolicy sns:AddPermission sns:CreateTopic sns:DeleteTopic
sns:RemovePermission sns:SetTopicAttributes sns:Subscribe sns:Unsubscribe`.split(/\s+/);

test('Control Tower guardrail actions in one SCP Deny: none UNKNOWN_ACTION', () => {
  assert.equal(CONTROL_TOWER.length, 40);
  const r = run(deny(CONTROL_TOWER), 'scp-rcp');
  assert.ok(!unknown(r), `UNKNOWN_ACTION present (rc ${r.exitCode})`);
});

test('control: a made-up action in a known service is still UNKNOWN_ACTION', () => {
  assert.ok(unknown(run(deny('sns:NoSuchAction'), 'scp-rcp')));
});

// Deny-only services: reads, lists and tag changes stay fail-closed in an Allow (pre-1.3.0 behavior).
const NOT_IN_ALLOW = ['logs:GetLogEvents', 'logs:GetQueryResults', 'lambda:GetFunctionConfiguration',
  'cloudformation:GetTemplate', 'events:PutTargets', 'sns:ListTopics'];
for (const action of NOT_IN_ALLOW) {
  test(`${action} in an Allow still fails closed`, () => {
    const narrow = P({ Effect: 'Allow', Action: action, Resource: `arn:aws:${action.split(':')[0]}:us-east-1:${ACCT}:x` });
    assert.equal(run(narrow, 'identity').exitCode, EXIT.FAIL_CLOSED);
    assert.equal(run(allow(action), 'identity').exitCode, EXIT.FAIL_CLOSED);
  });
}

// Mac round-1 decision: ABAC tag writes and account-wide IAM dumps fail closed in an Allow.
for (const action of ['iam:UntagRole', 'iam:UntagUser', 'iam:TagPolicy', 'iam:GetAccountAuthorizationDetails',
  'iam:GetCredentialReport', 'iam:GenerateCredentialReport']) {
  test(`${action} in an Allow fails closed; known in a Deny`, () => {
    assert.equal(run(allow(action), 'identity').exitCode, EXIT.FAIL_CLOSED);
    assert.ok(!unknown(run(deny(action), 'scp-rcp')));
  });
}
test('curated iam:TagRole / iam:TagUser keep DIRECT-IAM-ADMIN', () => {
  for (const a of ['iam:TagRole', 'iam:TagUser']) {
    assert.ok(run(allow(a), 'identity').findings.some((f) => f.id === 'DIRECT-IAM-ADMIN'), a);
  }
});
