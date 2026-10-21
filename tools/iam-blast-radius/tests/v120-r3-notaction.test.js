// v1.2.0 confirmation round, A-1: a NotAction Deny spares part of a broad grant, so it is no fence.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const run = (statements) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family: 'identity', partition: 'aws', threshold: 'high', subjectAccount: '111122223333',
});
const ids = (r) => r.findings.map((f) => f.id);
const BUCKET = 'arn:aws:s3:::public-assets-111122223333/*';
const fence = (NotAction) => ({ Effect: 'Deny', NotAction, NotResource: [BUCKET] });

test('A-1: NotAction GetObjectVersion + NotResource does not fence s3:GetObject*', () => {
  const r = run([{ Effect: 'Allow', Action: 's3:GetObject*', Resource: '*' }, fence(['s3:GetObjectVersion'])]);
  assert.equal(r.exitCode, EXIT.FINDINGS, ids(r).join(','));
  assert.ok(ids(r).includes('DATA-EXFIL'), ids(r).join(','));
});

test('A-1b: the same Deny does not fence s3:Get*', () => {
  const r = run([{ Effect: 'Allow', Action: 's3:Get*', Resource: '*' }, fence(['s3:GetObjectVersion'])]);
  assert.equal(r.exitCode, EXIT.FINDINGS, ids(r).join(','));
  assert.ok(ids(r).includes('DATA-EXFIL'), ids(r).join(','));
});

test('control: a NotAction that misses the grant still fences it', () => {
  const r = run([{ Effect: 'Allow', Action: 's3:GetObject*', Resource: '*' }, fence(['ec2:*'])]);
  assert.ok(!ids(r).includes('DATA-EXFIL'), ids(r).join(','));
});

test('control: a plain NotResource Deny still fences a concrete read', () => {
  const r = run([{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: [BUCKET] }]);
  assert.ok(!ids(r).includes('DATA-EXFIL'), ids(r).join(','));
});
