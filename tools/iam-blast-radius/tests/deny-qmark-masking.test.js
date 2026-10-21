// A '?' in a Deny must not erase a wildcard Allow it cannot cover (Mac extended test L2-1/L2-2).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { denyPatternCovers } from '../../../content/tools/iam-blast-radius/engine/escalation-deny.js';

const run = (allow, deny) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Action: allow, Resource: '*' },
    { Effect: 'Deny', Action: deny, Resource: '*' },
  ] }),
  family: 'identity', threshold: 'high', subjectAccount: '123456789012', partition: 'aws',
});
const ids = (r) => r.findings.map((f) => f.id);

test('Allow * + Deny ? is not clean', () => {
  const r = run('*', '?');
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.ok(r.findings.length > 0);
});

test('Deny iam:CreatePolic? leaves CreatePolicyVersion flagged', () => {
  const r = run('iam:CreatePolic*', 'iam:CreatePolic?');
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(ids(r).includes('POLICY-VERSION'), ids(r).join(','));
});

test('Deny sts:AssumeRol? leaves AssumeRoleWith* allowed', () => {
  assert.notEqual(run('sts:AssumeRol*', 'sts:AssumeRol?').exitCode, EXIT.CLEAN);
});

test('under exit 3 the masked escalation is still named', () => {
  for (const [allow, deny, id] of [
    ['iam:*', 'iam:?', 'DIRECT-IAM-ADMIN'],
    ['iam:Attach*Policy', 'iam:Attach?Policy', 'ATTACH-POLICY'],
    ['iam:*Version', 'iam:?Version', 'POLICY-VERSION'],
  ]) {
    assert.ok(ids(run(allow, deny)).includes(id), `${allow} - ${deny}`);
  }
});

test('a Deny that really covers the grant still applies', () => {
  assert.equal(run('iam:CreatePolicyVersion', 'iam:CreatePolicyVersion').exitCode, EXIT.CLEAN);
  assert.equal(run('iam:CreatePolic*', 'iam:CreatePolic*').exitCode, EXIT.CLEAN);
  assert.equal(run('iam:CreatePolic*', 'iam:*').exitCode, EXIT.CLEAN);
});

test('denyPatternCovers semantics', () => {
  assert.equal(denyPatternCovers('?', '*'), false);
  assert.equal(denyPatternCovers('iam:createpolic?', 'iam:createpolic*'), false);
  assert.equal(denyPatternCovers('iam:*', 'iam:createpolic*'), true);
  assert.equal(denyPatternCovers('*', '*'), true);
  assert.equal(denyPatternCovers('iam:?ttach*', 'iam:attach?olicy'), true);
  assert.equal(denyPatternCovers('iam:createpolicy?ersion', 'iam:createpolicyversion'), true);
  assert.equal(denyPatternCovers('iam:get?', 'iam:get?'), true);
  assert.equal(denyPatternCovers('iam:geta', 'iam:get?'), false);
});
