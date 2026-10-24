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
