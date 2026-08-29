// Regression for review finding D1: the resource family is advertised in the CLI +
// Action but resourceContext was never forwarded, so a resource policy always failed
// closed with RESOURCE_CONTEXT_REQUIRED - an advertised family that was unusable.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import { readInputs } from '../../../action/action-inputs.mjs';

const PUBLIC_BUCKET_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }],
});

test('D1: scan() forwards resourceContext so the resource family actually analyzes', () => {
  const without = scan({ text: PUBLIC_BUCKET_POLICY, family: 'resource' });
  assert.equal(without.reason, 'FAMILY_BLOCKED', 'without context the resource family stays blocked');
  assert.notEqual(without.exitCode, 0, 'blocked = non-zero exit (fail closed)');

  const withCtx = scan({
    text: PUBLIC_BUCKET_POLICY,
    family: 'resource',
    resourceContext: { type: 's3-bucket', arn: 'arn:aws:s3:::b' },
  });
  assert.notEqual(withCtx.reason, 'FAMILY_BLOCKED', 'with context the family is no longer blocked');
  assert.ok((withCtx.findings || []).some((f) => /PUBLIC-ACCESS/.test(f.id)),
    'a public bucket policy now surfaces PUBLIC-ACCESS instead of being unusable');
  assert.notEqual(withCtx.exitCode, 0, 'a public grant still blocks (never a clean pass)');
});

test('D1: a non-object resourceContext is dropped (fails closed, never throws)', () => {
  for (const bad of ['nope', 42, ['x'], null]) {
    const r = scan({ text: PUBLIC_BUCKET_POLICY, family: 'resource', resourceContext: bad });
    assert.equal(r.reason, 'FAMILY_BLOCKED', `resourceContext=${JSON.stringify(bad)} must be ignored -> blocked`);
  }
});

test('D1: the Action readInputs builds resourceContext from resource-* inputs', () => {
  const ctx = readInputs({
    'INPUT_PATHS': 'p.json', 'INPUT_FAMILY': 'resource',
    'INPUT_RESOURCE-ARN': 'arn:aws:s3:::b', 'INPUT_RESOURCE-TYPE': 's3-bucket', 'INPUT_RESOURCE-ACCOUNT': '111122223333',
  }).resourceContext;
  assert.deepEqual(ctx, { type: 's3-bucket', arn: 'arn:aws:s3:::b', account: '111122223333' });

  const none = readInputs({ 'INPUT_PATHS': 'p.json', 'INPUT_FAMILY': 'resource' }).resourceContext;
  assert.equal(none, undefined, 'no resource-* inputs -> undefined (family stays fail-closed)');
});
