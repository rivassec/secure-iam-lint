// G9/G10 from the v1.2.0 gap round: RESOURCE-POLICY-WRITE must track real
// policy-write actions, not object-scoped ACL writes.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const run = (statements) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family: 'identity', partition: 'aws', threshold: 'high', subjectAccount: ACCT,
});
const ids = (r) => r.findings.map((f) => f.id);

test('G10: object-scoped wildcards are not a resource-policy write', () => {
  const r = run([
    { Effect: 'Allow', Action: ['s3:GetObject*', 's3:PutObject*', 's3:DeleteObject*'], Resource: 'arn:aws:s3:::example-docs/*' },
    { Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::example-docs' },
  ]);
  assert.ok(!ids(r).includes('RESOURCE-POLICY-WRITE'), ids(r).join(','));
  // DeleteObject* keeps its destructive finding.
  assert.ok(ids(r).includes('DESTRUCTIVE-ACTION'), ids(r).join(','));
  // Deliberate G10 consequence: a bare object-ACL write alone is clean now.
  const exact = run([{ Effect: 'Allow', Action: 's3:PutObjectAcl', Resource: 'arn:aws:s3:::example-docs/key.txt' }]);
  assert.equal(exact.exitCode, EXIT.CLEAN);
});

test('G8 control: bucket-level s3:Put*/Delete* keep firing', () => {
  const r = run([{ Effect: 'Allow', Action: ['s3:List*', 's3:Get*', 's3:Put*', 's3:Delete*'], Resource: ['arn:aws:s3:::example-cold-store', 'arn:aws:s3:::example-cold-store/*'] }]);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  const f = r.findings.find((x) => x.id === 'RESOURCE-POLICY-WRITE');
  assert.ok(f && f.severity === 'high', ids(r).join(','));
  assert.ok(ids(r).includes('DESTRUCTIVE-ACTION'), ids(r).join(','));
});

test('G9: kinesis:Put* includes PutResourcePolicy', () => {
  const r = run([{ Effect: 'Allow', Action: 'kinesis:Put*', Resource: '*' }]);
  assert.equal(r.exitCode, EXIT.FINDINGS, r.reason);
  assert.equal(r.analysisStatus, 'complete');
  const f = r.findings.find((x) => x.id === 'RESOURCE-POLICY-WRITE');
  assert.ok(f && f.severity === 'high', ids(r).join(','));
  // A plain data-plane put is not a policy write.
  const rec = run([{ Effect: 'Allow', Action: 'kinesis:PutRecord', Resource: `arn:aws:kinesis:us-east-2:${ACCT}:stream/example` }]);
  assert.ok(!ids(rec).includes('RESOURCE-POLICY-WRITE'), ids(rec).join(','));
  // Uncatalogued kinesis actions stay unknown (fail closed).
  const desc = run([{ Effect: 'Allow', Action: 'kinesis:DescribeStream', Resource: `arn:aws:kinesis:us-east-2:${ACCT}:stream/example` }]);
  assert.equal(desc.exitCode, EXIT.FAIL_CLOSED);
});
