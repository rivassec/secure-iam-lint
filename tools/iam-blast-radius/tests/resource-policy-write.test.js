// Stage-13 EFO-2: resource-policy-write / cross-account-grant actions
// (s3:PutBucketPolicy, s3:PutBucketAcl, kms:PutKeyPolicy, kms:CreateGrant,
// lambda:AddPermission, sns:AddPermission, ...) let a principal REWRITE a
// data-store / key / function / topic resource policy to grant an EXTERNAL or
// arbitrary principal - a cross-account exfil / key-control / backdoor
// capability. Before the fix these read fully CLEAN in the identity family: the
// catalogued ones (s3/kms/lambda in catalog.js as L.PERMISSIONS) were "recognized"
// so the incomplete safety net stayed false, yet no identity detector consumed
// them -> a T8 fail-open (known-but-unhandled fails open while genuinely-unknown
// actions fail closed). This suite pins the RESOURCE-POLICY-WRITE finding (high).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const A = (policy) => analyze(JSON.stringify(policy), { family: 'identity', requireExplicitFamily: true });
const ids = (r) => (r.findings || []).map((f) => f.id);

test('EFO-2: catalogued resource-policy-write actions are NOT clean (the core fail-open)', () => {
  const p = {
    Version: '2012-10-17',
    Statement: [{
      Sid: 'Ops', Effect: 'Allow',
      Action: ['s3:PutBucketPolicy', 'kms:PutKeyPolicy', 'kms:CreateGrant'],
      Resource: ['arn:aws:s3:::prod-data-lake', 'arn:aws:kms:us-east-1:123456789012:key/prod-cmk'],
    }],
  };
  const s = scan({ text: JSON.stringify(p), family: 'identity' });
  assert.notEqual(s.exitCode, 0, 'a resource-policy-write capability is never a clean pass');
  const r = A(p);
  assert.ok(ids(r).includes('RESOURCE-POLICY-WRITE'), 'the finding surfaces');
  const f = r.findings.find((x) => x.id === 'RESOURCE-POLICY-WRITE');
  assert.equal(f.severity, 'high');
});

test('EFO-2: lambda:AddPermission and s3:PutBucketAcl each fire on a concrete resource', () => {
  for (const action of ['lambda:AddPermission', 's3:PutBucketAcl']) {
    const r = A({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: action, Resource: 'arn:aws:s3:::b' }] });
    assert.ok(ids(r).includes('RESOURCE-POLICY-WRITE'), `${action} must fire RESOURCE-POLICY-WRITE`);
  }
});

test('EFO-2: previously-uncatalogued siblings now surface a finding (not just incomplete)', () => {
  // sns:AddPermission / secretsmanager:PutResourcePolicy used to fail closed
  // (incomplete). They are genuine resource-policy grants; naming the risk is
  // strictly better. (Their unrecognized-action status may still flip incomplete,
  // which is fine - the point is they are never a bare CLEAN.)
  for (const action of ['sns:AddPermission', 'secretsmanager:PutResourcePolicy']) {
    const r = A({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: action, Resource: 'arn:aws:sns:us-east-1:1:t' }] });
    assert.ok(ids(r).includes('RESOURCE-POLICY-WRITE'), `${action} must fire RESOURCE-POLICY-WRITE`);
  }
});

test('EFO-2: a same-policy Deny covering the resource-policy-write action removes it (clean)', () => {
  const p = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 's3:PutBucketPolicy', Resource: 'arn:aws:s3:::b' },
      { Effect: 'Deny', Action: 's3:PutBucketPolicy', Resource: '*' },
    ],
  };
  const s = scan({ text: JSON.stringify(p), family: 'identity' });
  assert.equal(s.exitCode, 0, 'an explicit same-policy Deny that AWS honors removes the finding');
});

test('EFO-2: a plain read/write action does not fire RESOURCE-POLICY-WRITE (no over-fire)', () => {
  const r = A({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 's3:PutObject'], Resource: 'arn:aws:s3:::b/*' }] });
  assert.ok(!ids(r).includes('RESOURCE-POLICY-WRITE'), 'only resource-policy-write actions fire the finding');
});

test('EFO-2: a service wildcard is owned by WILDCARD-ACTION, not double-flagged here', () => {
  // s3:* already fires WILDCARD-ACTION (never clean); RESOURCE-POLICY-WRITE targets
  // the SPECIFIC-action fail-open, so it does not also fire on service wildcards.
  const r = A({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: 'arn:aws:s3:::b/*' }] });
  assert.ok(ids(r).includes('WILDCARD-ACTION'), 'the wildcard is caught');
  assert.ok(!ids(r).includes('RESOURCE-POLICY-WRITE'), 'service wildcard is not double-flagged');
});
