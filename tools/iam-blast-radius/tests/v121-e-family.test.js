// v1.2.0 group E: family shape heuristics (F9, T2-8, F10, F8).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { expandTrustActions } from '../../../content/tools/iam-blast-radius/engine/trust-catalogs.js';

const ACCT = '111122223333';
const run = (family, Statement) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement }),
  family, partition: 'aws', threshold: 'high', subjectAccount: ACCT,
});
const ids = (r) => r.findings.map((f) => `${f.id}:${f.severity}`);
const pub = { AWS: '*' };
const gitlab = { Federated: `arn:aws:iam::${ACCT}:oidc-provider/gitlab.com` };

test('F9: public trust with wildcard sts / * / NotAction reports TRUST-PUBLIC critical', () => {
  for (const a of [{ Action: 'sts:*' }, { Action: '*' }, { Action: 'sts:AssumeRole*' }, { NotAction: 's3:*' }]) {
    const r = run('role-trust', [{ Effect: 'Allow', Principal: pub, ...a }]);
    assert.equal(r.exitCode, EXIT.FINDINGS, JSON.stringify(a));
    assert.ok(ids(r).includes('TRUST-PUBLIC:critical'), `${JSON.stringify(a)}: ${ids(r)}`);
  }
});

test('T2-8: federated trust with sts:* / sts:AssumeRoleWith* reports TRUST-FEDERATED', () => {
  const cond = { StringLike: { 'gitlab.com:sub': '*' } };
  for (const Action of ['sts:*', 'sts:AssumeRoleWith*']) {
    const r = run('role-trust', [{ Effect: 'Allow', Principal: gitlab, Action, Condition: cond }]);
    assert.equal(r.exitCode, EXIT.FINDINGS, Action);
    assert.ok(ids(r).some((i) => i.startsWith('TRUST-FEDERATED:')), `${Action}: ${ids(r)}`);
  }
});

test('F9 siblings: a pattern covering no trust action still fails closed', () => {
  for (const a of [{ Action: 's3:*' }, { Action: 'sts:Get*' }, { Action: ['sts:AssumeRole', 's3:GetObject'] },
    { NotAction: 'sts:*' }, { NotAction: [] }]) {
    assert.equal(run('role-trust', [{ Effect: 'Allow', Principal: pub, ...a }]).exitCode, EXIT.FAIL_CLOSED, JSON.stringify(a));
  }
});

test('F9: a wildcard trust Deny is applied exactly', () => {
  const allow = { Effect: 'Allow', Principal: pub, Action: 'sts:AssumeRole' };
  // Deny sts:* covers AssumeRole: same verdict as the literal Deny.
  assert.equal(run('role-trust', [allow, { Effect: 'Deny', Principal: pub, Action: 'sts:*' }]).exitCode, EXIT.CLEAN);
  // Deny NotAction sts:AssumeRole leaves AssumeRole open.
  const r = run('role-trust', [allow, { Effect: 'Deny', Principal: pub, NotAction: 'sts:AssumeRole' }]);
  assert.ok(ids(r).includes('TRUST-PUBLIC:critical'), ids(r).join(','));
});

test('modeled trust actions are not UNKNOWN_ACTION in the trust family', () => {
  const r = run('role-trust', [{ Effect: 'Allow', Principal: pub, Action: ['sts:AssumeRole', 'sts:TagSession'] }]);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  // Aux-only keeps its v1.2.0 info verdict, now without the catalog-gap exit 3.
  const aux = run('role-trust', [{ Effect: 'Allow', Principal: pub, Action: 'sts:TagSession' }]);
  assert.deepEqual(ids(aux), ['TRUST-SESSION-CONTROL:info']);
});

test('expandTrustActions: exact coverage', () => {
  assert.deepEqual(expandTrustActions({ actions: ['sts:AssumeRole'], notActions: [] }), ['sts:AssumeRole']);
  assert.deepEqual(expandTrustActions({ actions: ['sts:Tag*'], notActions: [] }), ['sts:TagSession']);
  assert.equal(expandTrustActions({ actions: ['sts:*', 's3:*'], notActions: [] }), null);
  assert.equal(expandTrustActions({ actions: [], notActions: ['*'] }), null);
});

test('F10: explicit identity on Allow * + conditional region Deny is analyzed as identity', () => {
  const st = [{ Effect: 'Allow', Action: '*', Resource: '*' },
    { Effect: 'Deny', Action: '*', Resource: '*', Condition: { StringNotEquals: { 'aws:RequestedRegion': 'us-east-2' } } }];
  const r = run('identity', st);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(ids(r).includes('WILDCARD-ACTION:high'), ids(r).join(','));
  // Same shape as a boundary routes to the envelope evaluator.
  assert.equal(run('permissions-boundary', st).exitCode, EXIT.FINDINGS);
  // All-Deny SCP shape under identity stays ambiguous.
  assert.equal(run('identity', [{ Effect: 'Deny', Action: 'organizations:LeaveOrganization', Resource: '*' }]).exitCode, EXIT.FAIL_CLOSED);
});

test('F8: explicit SCP accepts FullAWSAccess and named-action guardrails', () => {
  const full = { Effect: 'Allow', Action: '*', Resource: '*' };
  assert.ok(ids(run('scp-rcp', [full])).includes('SCP-CEILING:high'));
  const r = run('scp-rcp', [full, { Effect: 'Deny', Action: 'cloudtrail:StopLogging', Resource: '*' }]);
  assert.ok(ids(r).includes('SCP-GUARDRAIL:info'), ids(r).join(','));
  const sl = run('scp-rcp', [{ Effect: 'Deny', Action: 'cloudtrail:StopLogging', Resource: '*', Condition: { Null: { 'aws:SourceIp': 'false' } } }]);
  assert.deepEqual(ids(sl), ['SCP-GUARDRAIL:info']);
});

test('F8 siblings: no-op or identity-ambiguous SCP shapes keep failing closed', () => {
  for (const st of [
    [{ Effect: 'Deny', NotAction: '*', Resource: '*' }], // no-op guardrail (F1 class)
    [{ Effect: 'Deny', Action: [], Resource: '*' }],
    [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }, { Effect: 'Deny', Action: 'cloudtrail:StopLogging', Resource: '*' }],
    [{ Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*' }],
  ]) {
    assert.equal(run('scp-rcp', st).exitCode, EXIT.FAIL_CLOSED, JSON.stringify(st));
  }
});
