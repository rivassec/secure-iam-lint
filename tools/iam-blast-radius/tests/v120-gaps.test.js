// G4 / G5 / datapipeline China pin from the v1.2.0 gap round.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { CHINA_SERVICE_PRINCIPALS } from '../../../content/tools/iam-blast-radius/engine/escalation-catalogs.js';

const ACCT = '111122223333';
const run = (statements, { family = 'identity', partition = 'aws' } = {}) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family, partition, threshold: 'high', subjectAccount: ACCT,
});
const ids = (r) => r.findings.map((f) => f.id);
const sev = (r, id) => r.findings.find((f) => f.id === id)?.severity;

test('G4: rds-db:connect is cataloged and fires DB-AUTH scaled by scope', () => {
  // The gap fixture shape: connect on * plus a scoped DescribeDBClusters.
  const r = run([
    { Effect: 'Allow', Action: 'rds-db:connect', Resource: '*' },
    { Effect: 'Allow', Action: 'rds:DescribeDBClusters', Resource: `arn:aws:rds:us-east-2:${ACCT}:cluster:example-db` },
  ]);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.equal(sev(r, 'DB-AUTH'), 'high', ids(r).join(','));
  // A wildcarded dbuser segment is still any-user access.
  const anyUser = run([{ Effect: 'Allow', Action: 'rds-db:connect', Resource: `arn:aws:rds-db:us-east-2:${ACCT}:dbuser:*/*` }]);
  assert.equal(sev(anyUser, 'DB-AUTH'), 'high');
  // A pinned cluster + db user is reported, below the high threshold.
  const pinned = run([{ Effect: 'Allow', Action: 'rds-db:connect', Resource: `arn:aws:rds-db:us-east-2:${ACCT}:dbuser:cluster-ABCDE12345/app_reader` }]);
  assert.equal(sev(pinned, 'DB-AUTH'), 'medium');
  assert.equal(pinned.exitCode, EXIT.CLEAN);
});

test('G5: PassRole on * with no launch action fires PASSROLE-UNSCOPED high', () => {
  // The gap fixture shape: eks-auth is cataloged, so the scan completes.
  const r = run([
    { Effect: 'Allow', Action: ['iam:PassRole', 'eks-auth:AssumeRoleForPodIdentity'], Resource: '*' },
  ]);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.equal(sev(r, 'PASSROLE-UNSCOPED'), 'high', ids(r).join(','));
  // Withheld when a compound PASSROLE-* path covers the document.
  const compound = run([
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
    { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
  ]);
  assert.ok(ids(compound).includes('PASSROLE-EC2'));
  assert.ok(!ids(compound).includes('PASSROLE-UNSCOPED'), ids(compound).join(','));
  // A literal role-path prefix is a deliberate scope (MUST-STAY-NARROW parity).
  const scoped = run([{ Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/deployment/*` }]);
  assert.ok(!ids(scoped).includes('PASSROLE-UNSCOPED'), ids(scoped).join(','));
});

test('datapipeline China pin: canonical-only denylist is not credited under aws-cn', () => {
  assert.equal(CHINA_SERVICE_PRINCIPALS['datapipeline.amazonaws.com'], 'datapipeline.amazonaws.com.cn');
  const pol = [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws-cn:iam::${ACCT}:role/admin`, Condition: { StringNotEquals: { 'iam:PassedToService': 'datapipeline.amazonaws.com' } } },
    { Effect: 'Allow', Action: 'datapipeline:CreatePipeline', Resource: '*' },
  ];
  const cn = run(pol, { partition: 'aws-cn' });
  assert.equal(cn.exitCode, EXIT.FINDINGS);
  assert.ok(ids(cn).includes('PASSROLE-SERVICE'), ids(cn).join(','));
  // Under canonical aws the deny is real: no PassRole-to-datapipeline path.
  const aws = run([
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/admin`, Condition: { StringNotEquals: { 'iam:PassedToService': 'datapipeline.amazonaws.com' } } },
    { Effect: 'Allow', Action: 'datapipeline:CreatePipeline', Resource: '*' },
  ]);
  assert.ok(!ids(aws).includes('PASSROLE-SERVICE'), ids(aws).join(','));
});
