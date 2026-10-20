// The generated AWS-reference snapshot (engine/catalog-aws-ref.js, produced by
// scripts/gen-aws-action-catalog.mjs) merged under the curated catalog.
//
// Regression source: running v1.1.0 against real-world policies, a plain S3 sync
// policy and a region-deny SCP both failed closed (exit 3, UNKNOWN_ACTION) on
// ordinary actions the curated slice did not carry. These tests pin that those
// policies are now analyzable, that the merge never overrides a curated entry, and
// that the services the suite uses as "unknown" examples stay unknown.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { defaultCatalog, ACCESS_LEVELS } from '../../../content/tools/iam-blast-radius/engine/catalog.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const refPath = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius', 'engine', 'catalog-aws-ref.js');

function scanPolicy(policy, family = 'identity') {
  return scan({
    text: JSON.stringify(policy),
    family,
    threshold: 'high',
    subjectAccount: '123456789012',
    partition: 'aws',
  });
}

function stateCodes(result) {
  return (result.analysisStates || []).map((s) => s.code);
}

test('S3 sync actions that failed closed in v1.1.0 are known, with AWS access levels', () => {
  const expected = {
    's3:GetBucketLocation': ACCESS_LEVELS.READ,
    's3:PutObjectAcl': ACCESS_LEVELS.PERMISSIONS,
    's3:AbortMultipartUpload': ACCESS_LEVELS.WRITE,
    's3:ListMultipartUploadParts': ACCESS_LEVELS.LIST,
    's3:PutBucketVersioning': ACCESS_LEVELS.WRITE,
    's3:PutLifecycleConfiguration': ACCESS_LEVELS.WRITE,
  };
  for (const [action, level] of Object.entries(expected)) {
    const r = defaultCatalog.lookup(action);
    assert.equal(r.known, true, `${action} is known`);
    assert.equal(r.accessLevel, level, `${action} access level`);
  }
});

test('a plain S3 sync policy no longer fails closed on UNKNOWN_ACTION', () => {
  const result = scanPolicy({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['s3:ListBucket', 's3:GetBucketLocation', 's3:ListMultipartUploadParts'], Resource: 'arn:aws:s3:::my-bucket' },
      { Effect: 'Allow', Action: ['s3:GetObject', 's3:PutObject', 's3:AbortMultipartUpload'], Resource: 'arn:aws:s3:::my-bucket/*' },
      { Effect: 'Allow', Action: ['s3:PutBucketVersioning', 's3:PutLifecycleConfiguration'], Resource: 'arn:aws:s3:::my-bucket' },
    ],
  });
  assert.ok(!stateCodes(result).includes('UNKNOWN_ACTION'), JSON.stringify(result.analysisStates));
  assert.notEqual(result.exitCode, EXIT.FAIL_CLOSED);
});

test('region-deny SCP NotAction service wildcards are analyzable', () => {
  const result = scanPolicy({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'DenyOutsideRegions',
      Effect: 'Deny',
      NotAction: [
        'iam:*', 'organizations:*', 'route53:*', 'cloudfront:*', 'wafv2:*', 'sso:*',
        'sts:*', 'support:*', 'budgets:*', 'globalaccelerator:*', 'health:*', 'waf:*',
        'shield:*', 's3:GetBucketLocation', 's3:ListAllMyBuckets',
      ],
      Resource: '*',
      Condition: { StringNotEquals: { 'aws:RequestedRegion': ['us-east-1', 'us-west-2'] } },
    }],
  }, 'scp-rcp');
  assert.ok(!stateCodes(result).includes('UNKNOWN_ACTION'), JSON.stringify(result.analysisStates));
});

test('curated entries win over the reference on overlap', () => {
  // Curated s3 entries keep their curated level (and canonical name) after the merge.
  assert.equal(defaultCatalog.lookup('s3:GetObject').accessLevel, ACCESS_LEVELS.READ);
  assert.equal(defaultCatalog.lookup('s3:PutBucketAcl').accessLevel, ACCESS_LEVELS.PERMISSIONS);
  assert.equal(defaultCatalog.lookup('s3:ListBucket').accessLevel, ACCESS_LEVELS.LIST);
  // A curated required-wildcard read is unaffected; a curated scopable read stays scopable.
  assert.equal(defaultCatalog.requiresWildcardResource('sts:GetCallerIdentity'), true);
  assert.equal(defaultCatalog.requiresWildcardResource('s3:GetObject'), false);
});

test('reference wildcard-only reads are honored; reference scopable reads are not', () => {
  // organizations:DescribeOrganization has no resource types: Resource "*" is mandatory.
  const org = defaultCatalog.lookup('organizations:DescribeOrganization');
  assert.equal(org.known, true);
  assert.equal(org.accessLevel, ACCESS_LEVELS.READ);
  assert.equal(org.requiresWildcardResource, true);
  // s3:GetBucketLocation is bucket-scopable, so its "*" is an avoidable over-scope.
  assert.equal(defaultCatalog.requiresWildcardResource('s3:GetBucketLocation'), false);
});

test('a scopable reference READ on Resource "*" still fails closed (broad read stays incomplete)', () => {
  const result = scanPolicy({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetBucketTagging', Resource: '*' }],
  });
  assert.equal(result.exitCode, EXIT.FAIL_CLOSED, JSON.stringify(result.analysisStates));
  assert.ok(!stateCodes(result).includes('UNKNOWN_ACTION'));
});

test('services the suite treats as unknown stay out of the snapshot', () => {
  for (const svc of ['sqs', 'bedrock', 'fakesvc', 'madeupsvc', 'ghostsvc']) {
    assert.equal(defaultCatalog.hasService(svc), false, `${svc} must stay unknown`);
  }
});

test('the generated snapshot is pure data (no imports, no network)', () => {
  const src = readFileSync(refPath, 'utf8');
  assert.match(src, /^\/\/ GENERATED by scripts\/gen-aws-action-catalog\.mjs/);
  assert.doesNotMatch(src, /^\s*import\s/m);
  assert.doesNotMatch(src, /\bfetch\s*\(|require\s*\(/);
});
