// v1.3.0 trial finding T-1: the Cognito identity credential-exchange flow is catalogued.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const allow = (a) => scan({ text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: a, Resource: '*' }] }), family: 'identity', partition: 'aws' });

test('T-1: GetId / GetCredentialsForIdentity / GetOpenIdToken are known', () => {
  for (const a of ['cognito-identity:GetId', 'cognito-identity:GetCredentialsForIdentity', 'cognito-identity:GetOpenIdToken']) {
    assert.notEqual(allow(a).exitCode, EXIT.FAIL_CLOSED, a);
  }
});

test('T-1 guards: token minting and pool-role rebinding stay fail-closed; deletes stay high', () => {
  assert.equal(allow('cognito-identity:GetOpenIdTokenForDeveloperIdentity').exitCode, EXIT.FAIL_CLOSED);
  assert.equal(allow('cognito-identity:SetIdentityPoolRoles').exitCode, EXIT.FAIL_CLOSED);
  assert.ok(allow('cognito-identity:DeleteIdentityPool').findings.some((f) => f.id === 'DESTRUCTIVE-ACTION' && f.severity === 'high'));
});
