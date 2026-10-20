// Condition keys a real-world trial found unmodeled in v1.1.0 (each forced exit 3):
//   - s3:prefix (and s3:delimiter / s3:max-keys), the standard ListBucket scoping keys;
//   - aud/sub claims of an OIDC provider outside the built-in host allowlist (Okta,
//     Entra ID, GitLab, ...).
// The federation fix keeps the S2-airtight property (an attacker-named claim key
// never counts as modeled): a host is recognized only when it is the OIDC provider
// the SAME statement's Principal.Federated names.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyConditionEntry, classifyConditions, oidcProviderHosts,
} from '../../../content/tools/iam-blast-radius/engine/conditions.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

function scanPolicy(policy, family) {
  return scan({
    text: JSON.stringify(policy),
    family,
    threshold: 'high',
    subjectAccount: '123456789012',
    partition: 'aws',
  });
}

function unsupported(result) {
  const st = (result.analysisStates || []).find((s) => s.code === 'UNSUPPORTED_CONDITION');
  return st ? st.details.conditions : [];
}

const listBucket = (condition) => ({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::example-bucket', Condition: condition }],
});

test('s3:prefix / s3:delimiter / s3:max-keys are modeled (no longer fail closed)', () => {
  for (const key of ['s3:prefix', 's3:delimiter', 's3:max-keys']) {
    const r = scanPolicy(listBucket({ StringEquals: { [key]: 'home/alice/' } }), 'identity');
    assert.deepEqual(unsupported(r), [], key);
    assert.notEqual(r.exitCode, EXIT.FAIL_CLOSED, key);
  }
});

test('s3:prefix credits only a specific positive value', () => {
  assert.equal(classifyConditionEntry('StringLike', 's3:prefix', 'home/${aws:username}/*').credited, true);
  assert.equal(classifyConditionEntry('StringLike', 's3:prefix', '*').credited, false);
  assert.equal(classifyConditionEntry('StringNotLike', 's3:prefix', 'private/*').credited, false);
});

test('s3:delimiter and s3:max-keys are never credited as a guardrail', () => {
  for (const key of ['s3:delimiter', 's3:max-keys']) {
    const e = classifyConditionEntry('StringEquals', key, '1');
    assert.equal(e.known, true, key);
    assert.equal(e.credited, false, key);
  }
});

test('oidcProviderHosts extracts concrete OIDC provider hosts only', () => {
  const hosts = oidcProviderHosts([
    'arn:aws:iam::123456789012:oidc-provider/example.okta.com/oauth2/default',
    'arn:aws-us-gov:iam::123456789012:oidc-provider/gitlab.example.com',
    'arn:aws:iam::123456789012:saml-provider/corp',
    'arn:aws:iam::123456789012:oidc-provider/*',
    'arn:aws:iam::*:oidc-provider/wild.example.com',
    'arn:aws:iam::123456789012:oidc-provider/has:colon',
    'not-an-arn',
  ]);
  assert.deepEqual([...hosts].sort(), ['example.okta.com/oauth2/default', 'gitlab.example.com']);
});

const trust = (host, condition) => ({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow',
    Principal: { Federated: `arn:aws:iam::123456789012:oidc-provider/${host}` },
    Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: condition,
  }],
});

test('an enterprise IdP trust whose claim keys match its own provider is understood', () => {
  const host = 'example.okta.com/oauth2/default';
  const r = scanPolicy(trust(host, {
    StringEquals: { [`${host}:aud`]: 'api://default', [`${host}:sub`]: 'svc-deployer' },
  }), 'role-trust');
  assert.deepEqual(unsupported(r), []);
  assert.equal(r.exitCode, EXIT.CLEAN);
});

test('a claim key that does not match the statement provider still fails closed', () => {
  const host = 'example.okta.com/oauth2/default';
  const r = scanPolicy(trust(host, {
    StringEquals: { [`${host}:aud`]: 'api://default', 'acme:customkey:sub': 'x', 'other.idp.example:sub': 'y' },
  }), 'role-trust');
  assert.deepEqual(unsupported(r), ['acme:customkey:sub', 'other.idp.example:sub']);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('a provider named in one statement does not widen another statement', () => {
  const r = scanPolicy({
    Version: '2012-10-17',
    Statement: [
      trust('example.okta.com', { StringEquals: { 'example.okta.com:aud': 'a' } }).Statement[0],
      trust('gitlab.example.com', { StringEquals: { 'example.okta.com:sub': 'x' } }).Statement[0],
    ],
  }, 'role-trust');
  assert.deepEqual(unsupported(r), ['example.okta.com:sub'], JSON.stringify(r.analysisStates));
});

test('finding evidence agrees with coverage on a provider-matched claim', () => {
  const host = 'example.okta.com';
  const cc = classifyConditions({ StringEquals: { [`${host}:aud`]: 'a' } }, oidcProviderHosts([`arn:aws:iam::123456789012:oidc-provider/${host}`]));
  assert.deepEqual(cc.contextRequiredKeys, []);
  const r = scanPolicy(trust(host, { StringEquals: { [`${host}:aud`]: 'a', [`${host}:sub`]: 'svc' } }), 'role-trust');
  const fed = r.findings.find((f) => f.id === 'TRUST-FEDERATED');
  assert.ok(fed, 'TRUST-FEDERATED present');
  assert.deepEqual(fed.conditionClassification.contextRequiredKeys, []);
});
