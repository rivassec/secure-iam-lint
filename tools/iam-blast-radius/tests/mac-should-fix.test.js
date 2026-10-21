// Follow-ups from the Mac's #36-#39 verification.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { buildSarifLog } from '../../../cli/sarif.mjs';
import { classifyResource } from '../../../content/tools/iam-blast-radius/engine/resource-arn.js';

const ACCT = '123456789012';
const run = (statements, family = 'identity', partition = 'aws') => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family, threshold: 'high', subjectAccount: ACCT, partition,
});
const unknown = (r) => ((r.analysisStates || []).find((s) => s.code === 'UNKNOWN_ACTION') || { details: { actions: [] } }).details.actions;
const region = { StringNotEquals: { 'aws:RequestedRegion': ['us-east-1'] } };

test('region-deny SCP: the last three unknowns are resolved', () => {
  const r = run([{ Effect: 'Deny', NotAction: ['datapipeline:GetAccountLimits', 'license-manager:List*', 'discovery-marketplace:*', 'iam:*'], Resource: '*', Condition: region }], 'scp-rcp');
  assert.deepEqual(unknown(r), []);
});

test('discovery-marketplace is accepted only as a Deny NotAction svc:*', () => {
  const deny = (na) => ({ Effect: 'Deny', NotAction: na, Resource: '*', Condition: region });
  assert.deepEqual(unknown(run([deny(['discovery-marketplace:Foo'])], 'scp-rcp')), ['discovery-marketplace:Foo']);
  assert.deepEqual(unknown(run([deny(['discovery-marketplace:Get*'])], 'scp-rcp')), ['discovery-marketplace:Get*']);
  assert.deepEqual(unknown(run([{ Effect: 'Allow', Action: 'discovery-marketplace:*', Resource: '*' }])), ['discovery-marketplace:*']);
});

test('new license-manager write actions are withheld in an Allow', () => {
  const r = run([{ Effect: 'Allow', Action: 'license-manager:CreateGrant', Resource: `arn:aws:license-manager::${ACCT}:license/l-1` }]);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

const trust = (arn, host) => [{
  Effect: 'Allow', Principal: { Federated: arn }, Action: 'sts:AssumeRoleWithWebIdentity',
  Condition: { StringEquals: { [`${host}:aud`]: 'sts.amazonaws.com', [`${host}:sub`]: 'repo:o/r:ref:refs/heads/main' } },
}];

test('SARIF names the issuer of a federated trust (lookalike host visible)', () => {
  const host = 'token.actions.githubusercontent.com.evil.com';
  const r = run(trust(`arn:aws:iam::${ACCT}:oidc-provider/${host}`, host), 'role-trust');
  const row = buildSarifLog(r, { file: 't.json' }, { ruleVersion: '1' }).runs[0].results.find((x) => x.ruleId === 'TRUST-FEDERATED');
  assert.match(row.message.text, /; issuer: `token\.actions\.githubusercontent\.com\.evil\.com`/);
  assert.equal(row.properties.issuers.length, 1);
});

test('a provider ARN in another partition than the asserted one fails closed', () => {
  const host = 'token.actions.githubusercontent.com';
  const cn = run(trust(`arn:aws-cn:iam::${ACCT}:oidc-provider/${host}`, host), 'role-trust', 'aws');
  assert.equal(cn.exitCode, EXIT.FAIL_CLOSED);
  assert.ok(cn.analysisStates.some((s) => (s.details && s.details.requiredUnknowns || []).includes('providerPartition')));
  assert.equal(run(trust(`arn:aws-cn:iam::${ACCT}:oidc-provider/${host}`, host), 'role-trust', 'aws-cn').exitCode, EXIT.CLEAN);
  assert.equal(run(trust(`arn:aws:iam::${ACCT}:oidc-provider/${host}`, host), 'role-trust', 'aws').exitCode, EXIT.CLEAN);
});

test('AWS-published ARN shapes are classified, not MALFORMED', () => {
  assert.equal(classifyResource('arn:aws:bedrock:*::foundation-model/anthropic.claude-*'), 'NARROW');
  assert.equal(classifyResource('arn:aws:aws-marketplace:::catalog/Foo/product/*'), 'NARROW');
  assert.equal(classifyResource('arn:aws:partnercentral:*::catalog/AWS/engagement/*'), 'NARROW');
  assert.equal(classifyResource('arn:aws:organizations::*:'), 'BROAD');
});

test('still MALFORMED: unmodeled-service wildcards and empty ARNs', () => {
  for (const v of ['arn:aws:madeup:*::thing/x*', 'arn:aws:s3:::', 'arn:aws::::', '*.pem']) {
    assert.equal(classifyResource(v), 'MALFORMED', v);
  }
});
