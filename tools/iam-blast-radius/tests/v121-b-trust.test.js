// v1.2.0 group B: trust calibration (F5, T1-06, T1-07, T1-08, T1-09, T2-7).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const run = (stmt, threshold = 'high') => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', ...stmt }] }),
  family: 'role-trust', partition: 'aws', threshold, subjectAccount: '111122223333',
});
const sev = (r, id) => (r.findings.find((f) => f.id === id) || {}).severity;

const GH = { Federated: 'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com' };
const GH_AUD = { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' };
const gh = (cond) => run({ Principal: GH, Action: 'sts:AssumeRoleWithWebIdentity', Condition: cond });
const COG = { Federated: 'cognito-identity.amazonaws.com' };
const POOL = 'us-east-2:12345678-abcd-abcd-abcd-123456789012';
const cog = (cond) => run({ Principal: COG, Action: 'sts:AssumeRoleWithWebIdentity', Condition: cond });
const XA = { AWS: 'arn:aws:iam::444455556666:root' };

test('F5: an internet-open GitHub or Cognito trust is critical', () => {
  for (const sub of ['*', 'repo:*', 'repo:*/x:*']) {
    const r = gh({ StringEquals: GH_AUD, StringLike: { 'token.actions.githubusercontent.com:sub': sub } });
    assert.equal(sev(r, 'TRUST-FEDERATED'), 'critical', sub);
    assert.equal(run({ Principal: GH, Action: 'sts:AssumeRoleWithWebIdentity', Condition: { StringEquals: GH_AUD, StringLike: { 'token.actions.githubusercontent.com:sub': sub } } }, 'critical').exitCode, EXIT.FINDINGS, sub);
  }
  assert.equal(sev(gh({ StringEquals: GH_AUD }), 'TRUST-FEDERATED'), 'critical', 'no sub');
  assert.equal(sev(gh({ StringEquals: GH_AUD, StringNotLike: { 'token.actions.githubusercontent.com:sub': 'repo:evil/*' } }), 'TRUST-FEDERATED'), 'critical', 'negated sub');
  assert.equal(sev(cog({}), 'TRUST-FEDERATED'), 'critical', 'cognito no aud');
  // Owner-scoped stays high; a tight sub stays low.
  assert.equal(sev(gh({ StringEquals: GH_AUD, StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:org/*' } }), 'TRUST-FEDERATED'), 'high');
  assert.equal(sev(gh({ StringEquals: { ...GH_AUD, 'token.actions.githubusercontent.com:sub': 'repo:org/app:ref:refs/heads/main' } }), 'TRUST-FEDERATED'), 'low');
  // A private IdP with no sub keeps the existing high.
  const okta = run({ Principal: { Federated: 'arn:aws:iam::111122223333:oidc-provider/example.okta.com' }, Action: 'sts:AssumeRoleWithWebIdentity' });
  assert.equal(sev(okta, 'TRUST-FEDERATED'), 'high');
});

test('T1-06: ${*} ${?} ${$} are literal characters, never globs', () => {
  for (const v of ['Secret${$}9f2', 'Secret${*}9f2', 'Secret${?}9f2']) {
    assert.equal(sev(run({ Principal: XA, Action: 'sts:AssumeRole', Condition: { StringEquals: { 'sts:ExternalId': v } } }), 'TRUST-CROSS-ACCOUNT'), 'low', v);
  }
  // Under StringLike the escaped '*' is literal too: still narrowing.
  assert.equal(sev(run({ Principal: XA, Action: 'sts:AssumeRole', Condition: { StringLike: { 'sts:ExternalId': '${*}' } } }), 'TRUST-CROSS-ACCOUNT'), 'low');
  // A real variable stays caller-controlled.
  assert.equal(sev(run({ Principal: XA, Action: 'sts:AssumeRole', Condition: { StringEquals: { 'sts:ExternalId': '${aws:username}' } } }), 'TRUST-CROSS-ACCOUNT'), 'high');
  // Bare unescaped '*' under StringLike still matches everything.
  assert.equal(sev(run({ Principal: XA, Action: 'sts:AssumeRole', Condition: { StringLike: { 'sts:ExternalId': '*' } } }), 'TRUST-CROSS-ACCOUNT'), 'high');
});

test('T1-07: IfExists / ForAllValues on aws:PrincipalArn is not bypassable on plain AssumeRole', () => {
  const pin = 'arn:aws:iam::444455556666:role/deploy';
  for (const op of ['StringEquals', 'StringEqualsIfExists', 'ForAllValues:StringEquals', 'ForAnyValue:StringEquals']) {
    const r = run({ Principal: { AWS: '*' }, Action: 'sts:AssumeRole', Condition: { [op]: { 'aws:PrincipalArn': pin } } });
    assert.equal(sev(r, 'TRUST-PUBLIC'), 'high', op);
  }
  // A web-identity action may lack the key: IfExists stays bypassable.
  const fed = run({ Principal: '*', Action: ['sts:AssumeRole', 'sts:AssumeRoleWithWebIdentity'], Condition: { StringEqualsIfExists: { 'aws:PrincipalArn': pin } } });
  assert.equal(sev(fed, 'TRUST-PUBLIC'), 'critical');
  // OrgID is not always present (non-org principals lack it): IfExists stays bypassable.
  const org = run({ Principal: { AWS: '*' }, Action: 'sts:AssumeRole', Condition: { StringEqualsIfExists: { 'aws:PrincipalOrgID': 'o-exampleorg1' } } });
  assert.equal(sev(org, 'TRUST-PUBLIC'), 'critical');
});

test('T1-08: a tight pin plus PrincipalOrgID is never scored broader than the pin', () => {
  const both = run({ Principal: { AWS: '*' }, Action: 'sts:AssumeRole', Condition: { StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::444455556666:role/deploy', 'aws:PrincipalOrgID': 'o-exampleorg1' } } });
  assert.equal(sev(both, 'TRUST-PUBLIC'), 'medium');
  // Org alone, or a broad pin plus org, stays high.
  const orgOnly = run({ Principal: { AWS: '*' }, Action: 'sts:AssumeRole', Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-exampleorg1' } } });
  assert.equal(sev(orgOnly, 'TRUST-PUBLIC'), 'high');
  const broad = run({ Principal: { AWS: '*' }, Action: 'sts:AssumeRole', Condition: { ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::444455556666:role/*' }, StringEquals: { 'aws:PrincipalOrgID': 'o-exampleorg1' } } });
  assert.equal(sev(broad, 'TRUST-PUBLIC'), 'high');
});

test('T1-09: a whitespace-padded self reference is not labelled a tautology', () => {
  const ids = (r) => r.findings.map((f) => f.id);
  const padded = run({ Principal: XA, Action: 'sts:AssumeRole', Condition: { StringEquals: { 'sts:ExternalId': ' ${sts:ExternalId} ' } } });
  assert.ok(!ids(padded).includes('TRUST-CONDITION-TAUTOLOGY'), ids(padded).join(','));
  assert.equal(sev(padded, 'TRUST-CROSS-ACCOUNT'), 'high');
  const exact = run({ Principal: XA, Action: 'sts:AssumeRole', Condition: { StringEquals: { 'sts:ExternalId': '${sts:ExternalId}' } } });
  assert.ok(ids(exact).includes('TRUST-CONDITION-TAUTOLOGY'), ids(exact).join(','));
});

test('T2-7: Cognito aud+amr shapes are distinguishable', () => {
  const amr = (v, op = 'ForAnyValue:StringLike') => ({ [op]: { 'cognito-identity.amazonaws.com:amr': v } });
  const aud = (v, op = 'StringEquals') => ({ [op]: { 'cognito-identity.amazonaws.com:aud': v } });
  const documented = cog({ ...aud(POOL), ...amr('authenticated') });
  assert.equal(sev(documented, 'TRUST-FEDERATED'), 'medium');
  assert.equal(documented.exitCode, EXIT.CLEAN);
  assert.equal(sev(cog(amr('authenticated')), 'TRUST-FEDERATED'), 'critical', 'amr only');
  assert.equal(sev(cog({ ...aud('*', 'StringLike'), ...amr('authenticated') }), 'TRUST-FEDERATED'), 'critical', 'aud *');
  assert.equal(sev(cog(aud(POOL)), 'TRUST-FEDERATED'), 'high', 'aud only');
  const guest = cog({ ...aud(POOL), ...amr('unauthenticated') });
  assert.equal(sev(guest, 'TRUST-FEDERATED'), 'high', 'guest');
  assert.match(guest.findings.find((f) => f.id === 'TRUST-FEDERATED').why, /UNAUTHENTICATED \(guest\)/);
  // Bypassable qualifiers are not credited.
  assert.equal(sev(cog({ ...aud(POOL, 'StringEqualsIfExists'), ...amr('authenticated') }), 'TRUST-FEDERATED'), 'high', 'aud IfExists');
  assert.equal(sev(cog({ ...aud(POOL), ...amr('authenticated', 'ForAllValues:StringLike') }), 'TRUST-FEDERATED'), 'high', 'amr ForAllValues');
});
