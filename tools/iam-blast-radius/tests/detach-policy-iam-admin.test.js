// Stage-14 (FAILOPEN-IAM-DETACH-POLICY): iam:DetachRolePolicy / DetachUserPolicy were
// cataloged L.PERMISSIONS (so coverage=KNOWN, incomplete:false) yet emitted NO finding,
// while the sibling iam:DeleteRolePolicy fires DIRECT-IAM-ADMIN + DESTRUCTIVE-ACTION and
// the ATTACH side (iam:AttachRolePolicy) is in IAM_ADMIN_ACTIONS. Detaching a managed
// policy is the inverse IAM-attachment write (a de-restriction / guardrail-removal /
// persistence primitive), so a cataloged-but-silent CLEAN read was a fail-open. Add the
// Detach* variants to IAM_ADMIN_ACTIONS, mirroring Attach*/Delete*.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const A = (policy) => analyze(JSON.stringify(policy), { family: 'identity', requireExplicitFamily: true });
const ids = (r) => (r.findings || []).map((f) => f.id);

for (const action of ['iam:DetachRolePolicy', 'iam:DetachUserPolicy', 'iam:DetachGroupPolicy']) {
  test(`${action} is NOT clean (fires DIRECT-IAM-ADMIN, matching Attach*)`, () => {
    const p = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: action, Resource: 'arn:aws:iam::123456789012:role/target' }] };
    const s = scan({ text: JSON.stringify(p), family: 'identity' });
    assert.notEqual(s.exitCode, 0, `${action} must not read CLEAN`);
    assert.ok(ids(A(p)).includes('DIRECT-IAM-ADMIN'), `${action} must fire DIRECT-IAM-ADMIN`);
  });
}

// Stage-15: iam:UpdateAccessKey - cataloged Write credential-manipulation, was silent.
test('iam:UpdateAccessKey is NOT clean (fires DIRECT-IAM-ADMIN, sibling of CreateAccessKey)', () => {
  const p = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'iam:UpdateAccessKey', Resource: 'arn:aws:iam::123456789012:user/alice' }] };
  const s = scan({ text: JSON.stringify(p), family: 'identity' });
  assert.notEqual(s.exitCode, 0, 'iam:UpdateAccessKey must not read CLEAN');
  assert.ok(ids(A(p)).includes('DIRECT-IAM-ADMIN'), 'iam:UpdateAccessKey must fire DIRECT-IAM-ADMIN');
});
