// v1.3.0 round 8, lane A: action-catalog snapshot gaps, E-1 curation, F-2 NOT_IN_REFERENCE.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { defaultCatalog, ACCESS_LEVELS } from '../../../content/tools/iam-blast-radius/engine/catalog.js';
import { AWS_REF_ACTIONS } from '../../../content/tools/iam-blast-radius/engine/catalog-aws-ref.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111111111111';
const run = (...Statement) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement }),
  family: 'identity', threshold: 'high', subjectAccount: ACCT, partition: 'aws',
});
const allow = (Action, Resource = '*') => ({ Effect: 'Allow', Action, Resource });
const codes = (r) => (r.analysisStates || []).map((s) => s.code);
const ids = (r) => (r.findings || []).map((f) => f.id);

test('snapshot gap: ecr-public is snapshotted', () => {
  assert.ok(AWS_REF_ACTIONS['ecr-public'], 'ecr-public in the reference snapshot');
  const tok = defaultCatalog.lookup('ecr-public:GetAuthorizationToken');
  assert.equal(tok.known, true);
  assert.equal(tok.accessLevel, ACCESS_LEVELS.READ);
  assert.equal(tok.requiresWildcardResource, true);
  // Image push / repo writes are withheld until a detector models them.
  for (const a of ['ecr-public:PutImage', 'ecr-public:CreateRepository']) {
    assert.equal(defaultCatalog.lookup(a).withheld, true, a);
  }
  // A real ECR Public login reads clean (the token carries only the caller's permissions).
  const r = run(allow(['ecr-public:GetAuthorizationToken', 'sts:GetServiceBearerToken']));
  assert.equal(r.exitCode, EXIT.CLEAN, codes(r).join(','));
});

test('snapshot gap: sts:GetServiceBearerToken is known (AWS: Read, no resource types)', () => {
  const r = defaultCatalog.lookup('sts:GetServiceBearerToken');
  assert.equal(r.known, true);
  assert.equal(r.accessLevel, ACCESS_LEVELS.READ);
  assert.equal(r.requiresWildcardResource, true);
  const s = run(allow('sts:GetServiceBearerToken'));
  assert.equal(s.exitCode, EXIT.CLEAN, codes(s).join(','));
});

test('a service-wildcard read on "*" is checked like its concrete reads (was CLEAN)', () => {
  for (const a of ['dynamodb:Get*', 'ec2:Get*', 'kms:Describe*', 'sqs:Get*']) {
    const r = run(allow(a));
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, a);
    assert.ok(codes(r).includes('BROAD_RESOURCE_UNDECIDABLE'), a);
  }
  // Listing-only and Resource-"*"-only reads stay clean.
  assert.equal(run(allow('ec2:Describe*')).exitCode, EXIT.CLEAN);
  // A narrow resource is unaffected.
  assert.equal(run(allow('ec2:Get*', `arn:aws:ec2:us-east-2:${ACCT}:instance/i-1`)).exitCode, EXIT.CLEAN);
  // A same-policy Deny of the reads removes them.
  assert.equal(run(allow('dynamodb:Get*'), { Effect: 'Deny', Action: 'dynamodb:*', Resource: '*' }).exitCode, EXIT.CLEAN);
});

// --- E-1 curation: every action moved out of withholding, with the result that justifies it.
const R = 'us-east-2';
const arn = (svc, res) => `arn:aws:${svc}:${R}:${ACCT}:${res}`;
const ROLE = `arn:aws:iam::${ACCT}:role/deployer-target`;
const passRole = { Effect: 'Allow', Action: 'iam:PassRole', Resource: ROLE };

test('E-1 (a): released reads and listings are clean on a narrow ARN or where AWS needs "*"', () => {
  const cases = [
    [['eks:DescribeCluster', 'eks:ListNodegroups', 'eks:DescribeNodegroup'], arn('eks', 'cluster/c')],
    [['eks:ListClusters', 'eks:DescribeAddonVersions'], '*'],
    [['elasticloadbalancing:Describe*'], '*'],
    [['cloudformation:Describe*', 'cloudformation:Get*', 'cloudformation:List*'], arn('cloudformation', 'stack/s/*')],
    [['ecr:Describe*', 'ecr:List*', 'ecr:Get*', 'ecr:BatchGet*'], arn('ecr', 'repository/r')],
    [['lambda:ListVersionsByFunction', 'lambda:GetFunctionConfiguration', 'lambda:GetAlias', 'lambda:GetPolicy'],
      arn('lambda', 'function:fn')],
    [['lambda:ListFunctions', 'lambda:ListLayers', 'lambda:GetAccountSettings'], '*'],
    [['events:Describe*', 'events:ListTargetsByRule'], arn('events', 'rule/r')],
    [['scheduler:GetSchedule', 'scheduler:ListSchedules'], arn('scheduler', 'schedule/default/s')],
    [['codeartifact:GetAuthorizationToken', 'codeartifact:GetRepositoryEndpoint'], arn('codeartifact', 'domain/d')],
  ];
  for (const [actions, res] of cases) {
    const r = run(allow(actions, res));
    assert.equal(r.exitCode, EXIT.CLEAN, `${actions.join(',')}: ${codes(r).join(',')} ${ids(r).join(',')}`);
  }
});

test('E-1 (a): a released resource-scopable read on "*" still fails closed (BROAD_RESOURCE_UNDECIDABLE)', () => {
  for (const a of ['cloudformation:Describe*', 'cloudformation:Get*', 'ecr:Describe*', 'eks:Describe*',
    'lambda:GetFunctionConfiguration', 'codeartifact:GetAuthorizationToken']) {
    const r = run(allow(a));
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, a);
    assert.deepEqual(codes(r), ['BROAD_RESOURCE_UNDECIDABLE'], a);
  }
});

test('E-1 (b): detector-backed writes report their finding (narrow ARN)', () => {
  const cases = [
    ['cloudformation:ExecuteChangeSet', arn('cloudformation', 'stack/s/*'), 'COMPUTE-CODE-OVERWRITE'],
    ['lambda:UpdateAlias', arn('lambda', 'function:fn'), 'COMPUTE-CODE-OVERWRITE'],
    ['ecr:PutImage', arn('ecr', 'repository/r'), 'COMPUTE-CODE-OVERWRITE'],
    ['cloudformation:DeleteChangeSet', arn('cloudformation', 'stack/s/*'), 'DESTRUCTIVE-ACTION'],
    ['lambda:RemovePermission', arn('lambda', 'function:fn'), 'DESTRUCTIVE-ACTION'],
    ['events:DeleteRule', arn('events', 'rule/r'), 'DESTRUCTIVE-ACTION'],
    ['ecr:SetRepositoryPolicy', arn('ecr', 'repository/r'), 'RESOURCE-POLICY-WRITE'],
    ['ec2:CreateNetworkInterfacePermission', arn('ec2', 'network-interface/eni-1'), 'RESOURCE-POLICY-WRITE'],
  ];
  for (const [a, res, id] of cases) {
    const r = run(allow(a, res));
    assert.equal(r.exitCode, EXIT.FINDINGS, a);
    assert.ok(ids(r).includes(id), `${a}: ${ids(r).join(',')}`);
    assert.deepEqual(codes(r), [], a);
  }
});

test('E-1 (b): role-taking writes complete a PassRole path; alone they cannot run as a role', () => {
  for (const [a, res] of [['cloudformation:CreateChangeSet', arn('cloudformation', 'stack/s/*')],
    ['scheduler:CreateSchedule', arn('scheduler', 'schedule/default/s')],
    ['scheduler:UpdateSchedule', arn('scheduler', 'schedule/default/s')],
    ['events:PutTargets', arn('events', 'rule/r')]]) {
    const paired = run(allow(a, res), passRole);
    assert.ok(ids(paired).includes('PASSROLE-SERVICE'), `${a}: ${ids(paired).join(',')}`);
    assert.equal(paired.exitCode, EXIT.FINDINGS, a);
    // Alone: AWS requires iam:PassRole for the role these name, so there is no role to run as.
    assert.equal(run(allow(a, res)).exitCode, EXIT.CLEAN, a);
  }
});

test('E-1 (b): ECR push staging is clean alone and flagged once PutImage moves a tag', () => {
  const repo = arn('ecr', 'repository/r');
  const staging = ['ecr:InitiateLayerUpload', 'ecr:UploadLayerPart', 'ecr:CompleteLayerUpload',
    'ecr:BatchCheckLayerAvailability', 'ecr:CreateRepository'];
  assert.equal(run(allow(staging, repo)).exitCode, EXIT.CLEAN);
  const push = run(allow([...staging, 'ecr:PutImage'], repo));
  assert.equal(push.exitCode, EXIT.FINDINGS);
  assert.ok(ids(push).includes('COMPUTE-CODE-OVERWRITE'));
  // On "*" the writes keep WILDCARD-RESOURCE.
  assert.ok(ids(run(allow('ecr:CreateRepository'))).includes('WILDCARD-RESOURCE'));
});

test('E-1: actions left withheld still fail closed (UNKNOWN_ACTION)', () => {
  const STILL = [
    'ec2:CreateNetworkInterface', 'ec2:AssignPrivateIpAddresses', 'ec2:UnassignPrivateIpAddresses',
    'ec2:AttachNetworkInterface', 'ec2:ModifyNetworkInterfaceAttribute',
    'elasticloadbalancing:CreateLoadBalancer', 'elasticloadbalancing:CreateTargetGroup',
    'elasticloadbalancing:ModifyListener', 'elasticloadbalancing:AddTags',
    'ecr:BatchImportUpstreamImage', 'ecr:PutLifecyclePolicy', 'ecr:PutRegistryPolicy',
    'events:PutRule', 'lambda:PublishVersion', 'lambda:PutFunctionEventInvokeConfig',
    'lambda:CreateFunctionUrlConfig', 'lambda:TagResource', 'lambda:GetDurableExecutionState',
    'cloudformation:SetStackPolicy', 'eks:CreateAccessEntry', 'eks:AssociateAccessPolicy',
    'eks:AccessKubernetesApi', 'codeartifact:PublishPackageVersion', 'ecr-public:PutImage',
    'logs:DeleteLogGroup', 'logs:PutRetentionPolicy',
  ];
  for (const a of STILL) {
    const r = run(allow(a, arn(a.split(':')[0], 'x/y')));
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, a);
    assert.ok(codes(r).includes('UNKNOWN_ACTION'), `${a}: ${codes(r).join(',')}`);
  }
  // A whole-family wildcard that reaches a withheld member stays unknown too.
  assert.ok(codes(run(allow('lambda:Get*'))).includes('UNKNOWN_ACTION'));
});
