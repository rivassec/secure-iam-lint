// v1.3.0 round 8, lane A: action-catalog snapshot gaps, E-1 curation, F-2 NOT_IN_REFERENCE.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { defaultCatalog, ACCESS_LEVELS } from '../../../content/tools/iam-blast-radius/engine/catalog.js';
import { AWS_REF_ACTIONS } from '../../../content/tools/iam-blast-radius/engine/catalog-aws-ref.js';
import { scan, EXIT } from '../../../cli/scan.mjs';
import { buildSarifLog } from '../../../cli/sarif.mjs';
import { applyBaseline, parseBaseline, buildBaseline } from '../../../cli/baseline.mjs';

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
    ['scheduler:UpdateSchedule', arn('scheduler', 'schedule/default/s')]]) {
    const paired = run(allow(a, res), passRole);
    assert.ok(ids(paired).includes('PASSROLE-SERVICE'), `${a}: ${ids(paired).join(',')}`);
    assert.equal(paired.exitCode, EXIT.FINDINGS, a);
    // Alone: AWS requires iam:PassRole for the role these name, so there is no role to run as.
    assert.equal(run(allow(a, res)).exitCode, EXIT.CLEAN, a);
  }
});

// A target needs no role for SNS/SQS/Lambda/event-bus delivery, so alone it can redirect events.
test('E-1: events:PutTargets alone is a high TRAFFIC-ROUTING finding and still completes the PassRole path', () => {
  const res = arn('events', 'rule/r');
  const alone = run(allow('events:PutTargets', res));
  assert.equal(alone.exitCode, EXIT.FINDINGS);
  assert.ok(alone.findings.some((f) => f.id === 'TRAFFIC-ROUTING' && f.severity === 'high'));
  assert.ok(ids(run(allow('events:PutTargets', res), passRole)).includes('PASSROLE-SERVICE'));
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
    'ec2:CreateRoute', 'ec2:ReplaceRoute', 'elasticloadbalancing:CreateTrustStore',
    'elasticloadbalancing:ModifyTrustStore', 'elasticloadbalancing:AddTags',
    'ecr:BatchImportUpstreamImage', 'ecr:PutLifecyclePolicy', 'ecr:PutRegistryPolicy',
    'events:CreateConnection', 'events:RetrieveConnectionCredentials', 'lambda:PublishVersion', 'lambda:PutFunctionEventInvokeConfig',
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

// --- F-2: NOT_IN_REFERENCE (bundle probes f2a-f2d, inline).
const state = (r, code) => (r.analysisStates || []).find((x) => x.code === code);
const FN = arn('lambda', 'function:fn');

test('F-2 f2a: a misspelled action of a snapshotted service is NOT_IN_REFERENCE with a hint', () => {
  const r = run(allow(['lambda:UpdateFunctionCode', 'lambda:UpdateFunction'], FN));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.deepEqual(codes(r), ['NOT_IN_REFERENCE']);
  const st = state(r, 'NOT_IN_REFERENCE');
  assert.deepEqual(st.details.actions, ['lambda:UpdateFunction']);
  assert.deepEqual(st.details.hints, [{ action: 'lambda:UpdateFunction', suggestion: 'lambda:UpdateFunctionCode' }]);
  assert.match(st.message, /not in the \d{4}-\d{2}-\d{2} AWS reference snapshot/);
  assert.ok(ids(r).includes('COMPUTE-CODE-OVERWRITE'));
});

test('F-2 f2b: a wildcard matching no reference action is NOT_IN_REFERENCE; the real action is known', () => {
  const r = run(allow(['ecr-public:GetAuthorizationToken', 'ecr-public:BatchGet*']));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.deepEqual(codes(r), ['NOT_IN_REFERENCE']);
  assert.deepEqual(state(r, 'NOT_IN_REFERENCE').details.actions, ['ecr-public:BatchGet*']);
});

test('F-2 f2c: s3:HeadObject is not an IAM action; hint s3:GetObject (and HeadBucket -> ListBucket)', () => {
  const r = run(allow(['s3:GetObject', 's3:HeadObject', 's3:HeadBucket'], 'arn:aws:s3:::example-bucket/*'));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  const st = state(r, 'NOT_IN_REFERENCE');
  assert.deepEqual(st.details.hints, [
    { action: 's3:HeadBucket', suggestion: 's3:ListBucket' },
    { action: 's3:HeadObject', suggestion: 's3:GetObject' },
  ]);
  assert.equal(state(r, 'UNKNOWN_ACTION'), undefined);
});

test('F-2 f2d control: the real action alone is a finding, not a state', () => {
  const r = run(allow('lambda:UpdateFunctionCode', FN));
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.deepEqual(codes(r), []);
});

test('F-2: withheld actions, unsnapshotted services and curated-only services stay UNKNOWN_ACTION', () => {
  const r = run(allow(['events:CreateConnection', 'lambda:Get*', 'madeupsvc:Thing', 'chime:GetMeeting', 'sqs:SendMessage',
    's3:GetObjcet'], 'arn:aws:s3:::b/k'));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.deepEqual(state(r, 'UNKNOWN_ACTION').details.actions,
    ['chime:GetMeeting', 'events:CreateConnection', 'lambda:Get*', 'madeupsvc:Thing', 'sqs:SendMessage']);
  assert.deepEqual(state(r, 'NOT_IN_REFERENCE').details.actions, ['s3:GetObjcet']);
  assert.deepEqual(state(r, 'NOT_IN_REFERENCE').details.hints, [{ action: 's3:GetObjcet', suggestion: 's3:GetObject' }]);
});

test('F-2: a far-off name gets no hint; the hint is deterministic', () => {
  const r = run(allow('ec2:Zzzzzzzzzzzzzzzz', arn('ec2', 'instance/i-1')));
  assert.equal(state(r, 'NOT_IN_REFERENCE').details.hints, undefined);
  const a = JSON.stringify(run(allow('ec2:DescribeInstance')).analysisStates);
  assert.equal(a, JSON.stringify(run(allow('ec2:DescribeInstance')).analysisStates));
  assert.match(a, /ec2:DescribeInstances/);
});

test('F-2: SARIF names the tokens and hints markdown-inert; no link survives', () => {
  const r = run(allow(['s3:GetObjec`](https://evil.example)', 's3:GetObjec`'], 'arn:aws:s3:::b/k'));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  const log = buildSarifLog(r, { file: 'p.json' }, { ruleVersion: '1' });
  const row = log.runs[0].results.find((x) => x.ruleId === 'analysis.NOT_IN_REFERENCE');
  assert.ok(row, 'NOT_IN_REFERENCE row');
  assert.match(row.message.text, /Did you mean: /);
  assert.ok(Array.isArray(row.properties.notInReferenceActions));
  assert.ok(Array.isArray(row.properties.nameHints));
  assert.ok(!JSON.stringify(log).includes(']('), 'no markdown link in SARIF');
});

test('F-2: a NOT_IN_REFERENCE state is baselinable like UNKNOWN_ACTION, keyed by its token list', () => {
  const text = (acts) => JSON.stringify({ Version: '2012-10-17', Statement: [allow(acts, 'arn:aws:s3:::b/*')] });
  const sc = (t) => scan({ text: t, family: 'identity', threshold: 'high', subjectAccount: ACCT, partition: 'aws' });
  const t1 = text(['s3:HeadObject']);
  const keyed = applyBaseline(sc(t1), 'p.json', null, 'high');
  const keys = parseBaseline(JSON.stringify(buildBaseline([{ file: 'p.json', result: keyed }]))).keys;
  assert.notEqual(applyBaseline(sc(t1), 'p.json', keys, 'high').exitCode, EXIT.FAIL_CLOSED);
  // A new missing name is not covered by the old acceptance.
  assert.equal(applyBaseline(sc(text(['s3:HeadObject', 's3:HeadBucket'])), 'p.json', keys, 'high').exitCode, EXIT.FAIL_CLOSED);
});
