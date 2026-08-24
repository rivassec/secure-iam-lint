// Unit tests for IAM-801: role-trust family acceptance + the family-aware trust
// evaluator (engine/trust.js). Runs on node's built-in runner: `node --test`.
//
// Acceptance (prd.json IAM-801):
//   - role-trust is a SUPPORTED family (not blocked); Principal + trust-action
//     model parsed; trust statements routed to the trust analyzer.
//   - NotPrincipal, unknown Principal type, and mixed identity+trust still fail
//     closed.
//   - no identity-style broad-Resource finding on a trust policy; every trust
//     finding states the target role's permissions are out of scope / unknown.
//
// These assert the trust evaluator's classification against the AWS-verified
// severity model in docs/trust-policy-semantics.md and acceptance-suite tests
// 10/15/16/17/18. The 24-case acceptance harness (acceptance-suite.test.js)
// drives the fixturized versions; this suite pins the module contract directly.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';
import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import {
  analyzeTrust,
  classifyPrincipals,
  trustFindingDenyState,
  summarizeTrustDeny,
  TRUST_IDS,
  TRUST_ACTIONS,
} from '../../../content/tools/iam-blast-radius/engine/trust.js';

function pol(statement) {
  return JSON.stringify({ Version: '2012-10-17', Statement: statement });
}

function trust(statement) {
  return analyze(pol(statement));
}

function findingIds(r) {
  return r.findings.map((f) => f.id);
}

const TRUST_ID_SET = new Set(TRUST_IDS);

// ---------------------------------------------------------------------------
// Principal typing (docs/trust-policy-semantics.md section 2).
// ---------------------------------------------------------------------------

test('classifyPrincipals types every modeled Principal form', () => {
  assert.equal(classifyPrincipals({ anyPrincipal: true, byType: {} }).anonymous, true);
  const aws = classifyPrincipals({ anyPrincipal: false, byType: { AWS: [
    'arn:aws:iam::123456789012:root', '123456789012', 'arn:aws:iam::1:user/bob', '*',
  ] } });
  assert.ok(aws.categories.has('aws-root'));
  assert.ok(aws.categories.has('aws-account'));
  assert.ok(aws.categories.has('aws-principal-arn'));
  assert.ok(aws.anonymous, 'a bare "*" under AWS is anonymous/public');

  const svc = classifyPrincipals({ anyPrincipal: false, byType: { Service: ['lambda.amazonaws.com'] } });
  assert.ok(svc.categories.has('service'));

  const oidc = classifyPrincipals({ anyPrincipal: false, byType: { Federated: ['arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com'] } });
  assert.ok(oidc.categories.has('federated-oidc'));
  const saml = classifyPrincipals({ anyPrincipal: false, byType: { Federated: ['arn:aws:iam::1:saml-provider/Okta'] } });
  assert.ok(saml.categories.has('federated-saml'));

  const canon = classifyPrincipals({ anyPrincipal: false, byType: { CanonicalUser: ['79a59df9'] } });
  assert.ok(canon.categories.has('canonical-user'));

  const unknown = classifyPrincipals({ anyPrincipal: false, byType: { Potato: ['spud'] } });
  assert.deepEqual(unknown.unknownTypes, ['Potato']);
});

test('TRUST_ACTIONS covers the modeled sts trust action set', () => {
  for (const a of ['sts:assumerole', 'sts:assumerolewithsaml', 'sts:assumerolewithwebidentity', 'sts:tagsession', 'sts:setsourceidentity']) {
    assert.ok(TRUST_ACTIONS.has(a), `${a} is a trust action`);
  }
  assert.ok(!TRUST_ACTIONS.has('s3:getobject'));
});

// ---------------------------------------------------------------------------
// Severity model (docs/trust-policy-semantics.md section 5).
// ---------------------------------------------------------------------------

test('Principal "*" -> critical TRUST-PUBLIC; no identity broad-Resource finding', () => {
  const r = trust([{ Sid: 'P', Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }]);
  assert.equal(r.coverage.family, 'role-trust');
  assert.equal(r.coverage.blocked, false);
  const f = r.findings.find((x) => x.id === 'TRUST-PUBLIC');
  assert.ok(f, 'expected TRUST-PUBLIC');
  assert.equal(f.severity, 'critical');
  // A trust policy commonly omits Resource; its absence is never a finding.
  assert.ok(!findingIds(r).includes('WILDCARD-RESOURCE'), 'no identity broad-Resource finding on a trust policy');
});

test('StringNotEquals aws:PrincipalOrgID -> critical TRUST-ORG-EXPANSION, expansion polarity, no "missing" remediation', () => {
  const r = trust([{
    Sid: 'T', Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole',
    Condition: { StringNotEquals: { 'aws:PrincipalOrgID': 'o-x' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-ORG-EXPANSION');
  assert.ok(f, 'expected TRUST-ORG-EXPANSION');
  assert.equal(f.severity, 'critical');
  // The remediation must NOT tell the user to ADD the key as if it were absent;
  // it must frame the key as present with dangerous (expansion) polarity.
  assert.doesNotMatch(f.remediation, /\badd (a |an )?aws:principalorgid/i, 'must not recommend adding a "missing" key');
  assert.match(f.remediation, /present with dangerous polarity/i, 'frames the key as present with expansion polarity');
  assert.match(f.why, /outside/i, 'explains it trusts principals OUTSIDE the org');
});

test('external account + sts:ExternalId -> low/medium TRUST-CROSS-ACCOUNT; ExternalId not auth/secrecy, not "missing"', () => {
  const r = trust([{
    Sid: 'V', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111122223333:root' }, Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'sts:ExternalId': 'customer-7f6af74e' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f, 'expected TRUST-CROSS-ACCOUNT');
  assert.ok(['low', 'medium'].includes(f.severity), `ExternalId lowers severity, got ${f.severity}`);
  const text = `${f.why} ${f.remediation}`;
  assert.doesNotMatch(text, /missing (an? )?external ?id/i, 'never report "missing ExternalId"');
  // The finding must classify ExternalId as a confused-deputy mitigation, and
  // explicitly NOT as authentication or a secret (the affirmative negation is
  // correct - it should say "NOT authentication ... NOT a secret").
  assert.match(text, /confused[- ]deputy/i, 'framed as a confused-deputy mitigation');
  assert.match(text, /not authentication/i, 'explicitly states ExternalId is not authentication');
  assert.match(text, /not a secret/i, 'explicitly states ExternalId is not a secret');
});

// IAM-903 (Phase 9) INTENTIONAL behavior change: a partial-wildcard AWS
// Principal-element ARN is an INVALID pattern (the IAM Principal element cannot
// wildcard-match a principal name/ARN - AWS rejects it at save time; only the
// standalone Principal "*" is a valid wildcard). It must fail closed to a
// caveated TRUST-INVALID-PRINCIPAL finding, never a plain TRUST-CROSS-ACCOUNT /
// TRUST-ORG-EXPANSION expansion, and must not be silently over-trusted as "every
// role the pattern matches". This supersedes the earlier IAM-805/IAM-803 tests
// that modeled wildcard Principal ARNs (arn:aws:iam::*:role/*, .../role/app-*) as
// ORDINARY broad/bounded principals - that premise was the very bug IAM-903 fixes.
//
// The underlying IAM-805 breadth invariant (a confused-deputy correlation value
// does NOT neutralize an UNBOUNDED principal) still holds for the only VALID
// unbounded AWS principal, Principal "*", and is re-asserted below so nothing is
// lost.
test('IAM-903: a wildcard-ARN Principal (arn:aws:iam::*:role/*) is INVALID -> TRUST-INVALID-PRINCIPAL, never a plain TRUST-CROSS-ACCOUNT expansion', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::*:role/*' }, Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'sts:ExternalId': 'shared-correlation-value' } },
  }]);
  const inv = r.findings.find((x) => x.id === 'TRUST-INVALID-PRINCIPAL');
  assert.ok(inv, 'expected TRUST-INVALID-PRINCIPAL');
  assert.match(inv.why, /invalid|cannot use a partial/i, 'explains the principal ARN wildcard is invalid');
  assert.match(inv.remediation, /aws:PrincipalArn/, 'suggests Principal "*" + aws:PrincipalArn condition');
  assert.ok(!findingIds(r).includes('TRUST-CROSS-ACCOUNT'), 'an invalid wildcard principal is NOT expanded into an ordinary cross-account high');
  // Coverage fails closed: the invalid element makes the trusted set undetermined.
  assert.equal(r.coverage.summary.incomplete, true, 'invalid principal -> coverage incomplete');
  assert.ok(r.coverage.summary.codes.includes('INVALID_PRINCIPAL_WILDCARD_ARN'), 'coverage carries the machine-readable warning code');
});

test('IAM-903: an account-pinned wildcard-ARN Principal (arn:aws:iam::123456789012:role/app-*) is ALSO invalid (fail closed, no cross-account high)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::123456789012:role/app-*' }, Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'sts:ExternalId': 'vendor-correlation-id' } },
  }]);
  assert.ok(findingIds(r).includes('TRUST-INVALID-PRINCIPAL'), 'account-pinned partial wildcard in a Principal ARN is still invalid');
  assert.ok(!findingIds(r).includes('TRUST-CROSS-ACCOUNT'), 'not silently accepted as an ordinary (lowered) cross-account finding');
});

// IAM-903 (iteration 2, trust.js:433 defect): a partial wildcard that lands in
// the ACCOUNT field of an otherwise-:root ARN (arn:aws:iam::*:root) must still be
// typed as the INVALID wildcard form and fail closed. The glob test has to run
// BEFORE the :root$/^\d{12}$ shape tests, otherwise the wildcard-account ARN
// matches :root$ first and is silently accepted as a VALID whole-account
// 'aws-root' delegation - over-trusting every account instead of failing closed.
test('IAM-903: a wildcard in the account field of a :root ARN (arn:aws:iam::*:root) is INVALID, never a valid whole-account aws-root delegation', () => {
  const cls = classifyPrincipals({ anyPrincipal: false, byType: { AWS: ['arn:aws:iam::*:root'] } });
  assert.ok(cls.categories.has('aws-principal-arn-wildcard'),
    'a wildcarded account field types as the invalid wildcard form, not aws-root');
  assert.ok(!cls.categories.has('aws-root'),
    'must NOT be classified as a valid whole-account root delegation');

  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::*:root' }, Action: 'sts:AssumeRole',
  }]);
  assert.ok(findingIds(r).includes('TRUST-INVALID-PRINCIPAL'),
    'a wildcard-account :root ARN fails closed to TRUST-INVALID-PRINCIPAL');
  assert.ok(!findingIds(r).includes('TRUST-CROSS-ACCOUNT'),
    'not silently expanded into an ordinary cross-account trust finding');
  assert.equal(r.coverage.summary.incomplete, true, 'invalid principal -> coverage incomplete');
  assert.ok(r.coverage.summary.codes.includes('INVALID_PRINCIPAL_WILDCARD_ARN'),
    'coverage carries the machine-readable warning code');
});

// Boundary: a CONCRETE :root ARN and a bare 12-digit account (no glob) are still
// the valid whole-account forms - the reorder must not disturb them.
test('IAM-903 boundary: concrete :root ARN and bare account id stay valid whole-account principals (aws-root / aws-account)', () => {
  const cls = classifyPrincipals({ anyPrincipal: false, byType: { AWS: [
    'arn:aws:iam::123456789012:root', '123456789012',
  ] } });
  assert.ok(cls.categories.has('aws-root'), 'concrete :root ARN stays aws-root');
  assert.ok(cls.categories.has('aws-account'), 'bare 12-digit account stays aws-account');
  assert.ok(!cls.categories.has('aws-principal-arn-wildcard'),
    'no glob present -> not the invalid wildcard form');
});

// IAM-1006 (Phase 10, iteration 4): the partial-wildcard fail-closed handling was
// scoped to the AWS Principal key ONLY. A never-matching wildcard in a Service or
// Federated principal member was presented as a normal, COMPLETE trust
// (coverage.incomplete=false). AWS Service principals are exact identifiers and
// Federated principals are specific provider ARNs - neither element wildcard-
// matches - so a globbed member matches NOTHING and must fail closed to
// TRUST-INVALID-PRINCIPAL with coverage incomplete, exactly like a wildcard AWS
// Principal ARN. A never-matching wildcard principal must not read as a valid trust.
test('IAM-1006: a partial wildcard in a Service principal is INVALID -> TRUST-INVALID-PRINCIPAL, coverage incomplete; the valid member stays an info service trust', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { Service: ['lambda.amazonaws.com', 'ec2-*.amazonaws.com'] },
    Action: 'sts:AssumeRole',
  }]);
  const inv = r.findings.find((x) => x.id === 'TRUST-INVALID-PRINCIPAL');
  assert.ok(inv, 'the wildcard Service member fails closed to TRUST-INVALID-PRINCIPAL');
  assert.match(inv.why, /Service principal|invalid|exact service/i, 'explains the Service wildcard is invalid');
  assert.match(inv.why, /ec2-\*\.amazonaws\.com/, 'names the offending member');
  assert.doesNotMatch(inv.why, /normal service-role relationship/i, 'never calls a never-matching wildcard a normal service trust');
  const paths = (inv.invalidPrincipalPaths || []).map((p) => p.path);
  assert.ok(paths.includes('Statement[0].Principal.Service[1]'), 'locates the invalid member at its array index');
  // The valid lambda member is still a normal informational service trust.
  const svc = r.findings.find((x) => x.id === 'TRUST-SERVICE');
  assert.ok(svc, 'the valid lambda member remains an informational TRUST-SERVICE');
  assert.equal(svc.severity, 'info');
  assert.deepEqual(svc.evidence[0].principals.map((p) => p.value), ['lambda.amazonaws.com'], 'TRUST-SERVICE covers only the valid member');
  // Coverage fails closed: a never-matching member makes the trust incomplete.
  assert.equal(r.coverage.summary.incomplete, true, 'wildcard Service member -> coverage incomplete');
  assert.ok(r.coverage.summary.codes.includes('INVALID_PRINCIPAL_WILDCARD_ARN'), 'coverage carries the machine-readable warning code');
});

test('IAM-1006: a partial wildcard in a Federated principal is INVALID -> TRUST-INVALID-PRINCIPAL, coverage incomplete, never a complete TRUST-FEDERATED', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { Federated: 'arn:aws:iam::123456789012:oidc-provider/*' },
    Action: 'sts:AssumeRoleWithWebIdentity',
  }]);
  const inv = r.findings.find((x) => x.id === 'TRUST-INVALID-PRINCIPAL');
  assert.ok(inv, 'the wildcard Federated member fails closed to TRUST-INVALID-PRINCIPAL');
  assert.match(inv.why, /Federated principal|identity-provider|invalid/i, 'explains the Federated wildcard is invalid');
  assert.ok(!findingIds(r).includes('TRUST-FEDERATED'), 'a never-matching wildcard provider is NOT a complete federated trust');
  const paths = (inv.invalidPrincipalPaths || []).map((p) => p.path);
  assert.ok(paths.includes('Statement[0].Principal.Federated[0]'), 'locates the invalid member at its array index');
  assert.equal(r.coverage.summary.incomplete, true, 'wildcard Federated member -> coverage incomplete');
  assert.ok(r.coverage.summary.codes.includes('INVALID_PRINCIPAL_WILDCARD_ARN'), 'coverage carries the machine-readable warning code');
});

test('IAM-1006 boundary: a concrete (no-glob) Service / Federated principal stays a normal, COMPLETE trust', () => {
  const svc = trust([{ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }]);
  assert.ok(!findingIds(svc).includes('TRUST-INVALID-PRINCIPAL'), 'a concrete service identifier is valid');
  assert.ok(findingIds(svc).includes('TRUST-SERVICE'), 'a concrete service is a normal service trust');
  assert.equal(svc.coverage.summary.incomplete, false, 'a concrete service trust is complete');

  const fed = trust([{
    Effect: 'Allow',
    Principal: { Federated: 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com' },
    Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: {
      StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' },
      StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:example-org/repo:ref:refs/heads/main' },
    },
  }]);
  assert.ok(!findingIds(fed).includes('TRUST-INVALID-PRINCIPAL'), 'a concrete provider ARN is valid (the glob is in the sub condition, not the principal)');
  assert.ok(findingIds(fed).includes('TRUST-FEDERATED'), 'a concrete provider ARN is a normal federated trust');
});

test('IAM-805 breadth invariant preserved on the VALID unbounded principal: Principal "*" + sts:ExternalId stays CRITICAL public (a correlation value does not bound a public principal)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'sts:ExternalId': 'shared-correlation-value' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-PUBLIC');
  assert.ok(f, 'Principal "*" is TRUST-PUBLIC');
  assert.equal(f.severity, 'critical', 'a confused-deputy correlation value does not bound which principals a public trust admits');
});

test('unconditioned external account -> high TRUST-CROSS-ACCOUNT', () => {
  const r = trust([{ Sid: 'X', Effect: 'Allow', Principal: { AWS: '444455556666' }, Action: 'sts:AssumeRole' }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high');
});

test('OIDC broad sub (repo:org/*) -> high TRUST-FEDERATED; tight sub -> low', () => {
  const broad = trust([{
    Sid: 'G', Effect: 'Allow',
    Principal: { Federated: 'arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com' },
    Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: {
      StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' },
      StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:example-org/*' },
    },
  }]);
  const bf = broad.findings.find((x) => x.id === 'TRUST-FEDERATED');
  assert.ok(bf);
  assert.equal(bf.severity, 'high');
  assert.match(bf.remediation, /sub/i, 'recommends constraining the subject');
  assert.doesNotMatch(bf.why, /every repository can assume/i, 'never claims every repo can assume');

  const tight = trust([{
    Sid: 'G', Effect: 'Allow',
    Principal: { Federated: 'arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com' },
    Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: {
      StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' },
      StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:example-org/repo:ref:refs/heads/main' },
    },
  }]);
  const tf = tight.findings.find((x) => x.id === 'TRUST-FEDERATED');
  assert.ok(tf);
  assert.ok(['low', 'medium'].includes(tf.severity), `tight sub is not high, got ${tf.severity}`);
});

test('service principal -> informational TRUST-SERVICE, never an external/escalation finding', () => {
  const r = trust([{ Sid: 'L', Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }]);
  const f = r.findings.find((x) => x.id === 'TRUST-SERVICE');
  assert.ok(f, 'expected TRUST-SERVICE');
  assert.equal(f.severity, 'info');
  for (const bad of ['TRUST-PUBLIC', 'TRUST-CROSS-ACCOUNT', 'ASSUME-ROLE-EXPANSION', 'PASSROLE-LAMBDA']) {
    assert.ok(!findingIds(r).includes(bad), `service trust must not fire ${bad}`);
  }
});

// ---------------------------------------------------------------------------
// Auxiliary-session-only statements (IAM-805 iteration 3 blocking defect):
// sts:TagSession / sts:SetSourceIdentity grant no assumption. A statement whose
// ONLY action is auxiliary must NOT be scored as a public / cross-account /
// federated assume relationship, and its prose must never assert assumption
// (trust-policy-semantics.md section 3; threat-model T8).
// ---------------------------------------------------------------------------

test('sts:TagSession only + Principal "*" -> informational TRUST-SESSION-CONTROL, NOT critical TRUST-PUBLIC', () => {
  const r = trust([{ Sid: 'P', Effect: 'Allow', Principal: '*', Action: 'sts:TagSession' }]);
  assert.equal(r.coverage.family, 'role-trust');
  const f = r.findings.find((x) => x.id === 'TRUST-SESSION-CONTROL');
  assert.ok(f, 'expected TRUST-SESSION-CONTROL');
  assert.equal(f.severity, 'info');
  assert.equal(f.pathExploitability, 'low');
  for (const bad of ['TRUST-PUBLIC', 'TRUST-CROSS-ACCOUNT', 'TRUST-ORG-EXPANSION', 'TRUST-FEDERATED']) {
    assert.ok(!findingIds(r).includes(bad), `aux-only statement must not fire ${bad}`);
  }
  // The prose must NOT assert that the principal may assume the role.
  assert.doesNotMatch(f.why, /may assume|is trusted to assume|delegates assume-role|can assume this role/i,
    'aux-only prose must never claim assumption');
  assert.match(f.why, /does\s+NOT let the named principal assume|inert without a separate assume/i,
    'aux-only prose states it grants no assumption');
  // T8 invariant still stamped.
  assert.equal(f.trust.targetPermissions, 'unknown');
});

test('sts:SetSourceIdentity only + external account -> informational TRUST-SESSION-CONTROL, NOT high TRUST-CROSS-ACCOUNT', () => {
  const r = trust([{ Sid: 'S', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:SetSourceIdentity' }]);
  const f = r.findings.find((x) => x.id === 'TRUST-SESSION-CONTROL');
  assert.ok(f, 'expected TRUST-SESSION-CONTROL');
  assert.equal(f.severity, 'info');
  assert.ok(!findingIds(r).includes('TRUST-CROSS-ACCOUNT'), 'aux-only statement must not fire TRUST-CROSS-ACCOUNT');
  assert.doesNotMatch(f.why, /delegates assume-role|any identity the trusted account authorizes can assume/i,
    'aux-only prose must never claim the account may assume');
});

test('assume action alongside an auxiliary session action is still scored as the real assume relationship', () => {
  // sts:TagSession riding ALONGSIDE sts:AssumeRole is normal and expected; the
  // assume action drives the headline (here a whole-account cross-account HIGH).
  const r = trust([{
    Sid: 'M', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' },
    Action: ['sts:AssumeRole', 'sts:TagSession'],
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f, 'expected TRUST-CROSS-ACCOUNT');
  assert.equal(f.severity, 'high');
  assert.ok(!findingIds(r).includes('TRUST-SESSION-CONTROL'),
    'a statement with a real assume action is not a session-control-only finding');
});

// ---------------------------------------------------------------------------
// Adversarial-critic regressions (IAM-801 iteration 2): a confused-deputy /
// scoping constraint is only real when it matches a VALUE with a positive
// string/ARN operator. Non-matching operators and all-matching values must NOT
// neutralize a trust finding, and a wildcard Principal narrowed by a condition
// must not be reported as anonymous/public.
// ---------------------------------------------------------------------------

test('Null-operator sts:ExternalId does NOT neutralize a whole-account trust (stays high)', () => {
  // Null:{sts:ExternalId:true} matches only when NO ExternalId is supplied - the
  // OPPOSITE of a confused-deputy mitigation. It must not downgrade to low.
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { Null: { 'sts:ExternalId': 'true' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'Null-operator ExternalId is not a confused-deputy constraint');
  assert.match(f.why, /no confused[- ]deputy constraint/i, 'reports no constraint (must not fabricate a mitigation the Null-true condition forbids)');
  assert.doesNotMatch(f.why, /gated by a confused[- ]deputy constraint/i, 'must not claim the trust is gated by a mitigation');
});

test('non-string operator (DateGreaterThan) on sts:ExternalId does NOT neutralize (stays high)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { DateGreaterThan: { 'sts:ExternalId': '2020-01-01T00:00:00Z' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high');
});

test('wildcard aws:SourceArn ("*") is not a constraint (stays high)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { StringLike: { 'aws:SourceArn': '*' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'a "*" SourceArn constrains nothing');
});

test('all-addresses aws:SourceIp (0.0.0.0/0) is not a constraint (stays high)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { IpAddress: { 'aws:SourceIp': '0.0.0.0/0' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'an all-IPv4 CIDR constrains nothing');
});

test('aws:SourceIp is defense-in-depth: a whole-account trust STAYS high, path-exploitability lowered (IAM-802-B)', () => {
  // aws:SourceIp hardens HOW the request is made but does not narrow WHICH
  // principal in account 999988887777 is trusted - the whole account still is -
  // so it must NOT drop the trust below high (it is not a sanctioned neutralizer;
  // those are ExternalId / SourceArn / SourceAccount / positive org-id only). It
  // may lower path-exploitability one band and be noted as defense in depth.
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { IpAddress: { 'aws:SourceIp': '203.0.113.0/24' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'SourceIp does not bound the trusted principal set; stays high');
  assert.equal(f.pathExploitability, 'low', 'a request-context control lowers path-exploitability one band');
  assert.match(f.why, /defense in depth/i, 'framed as defense in depth, not a principal-narrowing constraint');
});

test('aws:MultiFactorAuthPresent is defense-in-depth: a whole-account trust STAYS high (IAM-802-B)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'MFA does not bound the trusted principal set; stays high');
  assert.equal(f.pathExploitability, 'low');
  assert.match(f.why, /defense in depth/i);
});

test('Principal "*" gated by a positive scoping condition is NOT critical public and the WHY does not claim anonymous/other-account trust', () => {
  const org = trust([{
    Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-abc123' } },
  }]);
  const of = org.findings.find((x) => x.id === 'TRUST-PUBLIC');
  assert.ok(of, 'still a TRUST-PUBLIC row (Principal is "*")');
  assert.notEqual(of.severity, 'critical', 'a present StringEquals org condition excludes outside/anonymous principals');
  assert.doesNotMatch(of.why, /ANY AWS principal/i, 'must not claim any/anonymous principal is trusted when a condition scopes it');
  assert.match(of.why, /scoping condition/i, 'names the scoping condition');

  const arn = trust([{
    Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::111122223333:role/App' } },
  }]);
  const af = arn.findings.find((x) => x.id === 'TRUST-PUBLIC');
  assert.ok(af);
  assert.notEqual(af.severity, 'critical');
});

// ---------------------------------------------------------------------------
// Adversarial-critic regressions (IAM-802 iteration 3): three over/under-claim
// defects verified against analyze.js.
// ---------------------------------------------------------------------------

test('co-present Federated + external AWS account: BOTH findings emitted; graph edges match the table (IAM-802-A)', () => {
  // One statement names a GitHub OIDC provider AND an external account. The
  // federated branch must NOT swallow the account: the whole-account external
  // trust scores at its OWN severity (high, unconditioned) and appears in the
  // table, matching the can-assume edge the graph draws for that account.
  const r = trust([{
    Sid: 'MixedFedAndAccount', Effect: 'Allow',
    Principal: {
      Federated: 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com',
      AWS: '999999999999',
    },
    Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: {
      StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' },
      StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:myorg/myrepo:ref:refs/heads/main' },
    },
  }]);

  const fed = r.findings.find((x) => x.id === 'TRUST-FEDERATED');
  const cross = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(fed, 'federated finding present');
  assert.ok(cross, 'co-present external-account finding is NOT dropped');
  assert.ok(['low', 'medium'].includes(fed.severity), `tight-sub federated is low/medium, got ${fed.severity}`);
  assert.equal(cross.severity, 'high', 'the external account scores high on its own (unconditioned by ExternalId/SourceArn/org)');

  // Attribution is clean: the federated finding names only the provider; the
  // cross-account finding names only the account.
  assert.match(fed.why, /githubusercontent\.com/);
  assert.doesNotMatch(fed.why, /999999999999/, 'federated finding must not claim the external account');
  assert.match(cross.why, /999999999999/);
  assert.doesNotMatch(cross.why, /githubusercontent\.com/, 'cross-account finding must not claim the federated provider');

  // The graph draws a can-assume edge for BOTH origins; the table now matches.
  const assumeEdges = r.graph.edges.filter((e) => e.type === 'can-assume');
  const targets = new Set(r.graph.nodes.filter((n) => n.type === 'ExternalPrincipal').map((n) => n.id));
  assert.ok(targets.has('ext:999999999999'), 'external-account origin node present');
  assert.ok(targets.has('ext:arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com'), 'federated origin node present');
  assert.equal(assumeEdges.length, 2, 'one can-assume edge per external origin; no orphan edge without a table finding');
});

test('StringNotEquals org on a BROAD principal ("*") stays critical org-expansion (IAM-802-C control)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole',
    Condition: { StringNotEquals: { 'aws:PrincipalOrgID': 'o-abc1234567' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-ORG-EXPANSION');
  assert.ok(f, 'broad principal + org-exclusion is the critical org-wide expansion');
  assert.equal(f.severity, 'critical');
});

test('StringNotEquals org on ONE specific role ARN is NOT org-wide critical; scoped to the cross-account case (IAM-802-C)', () => {
  // AWS evaluates Principal AND Condition: the trusted set is at most that one
  // role. Asserting org-wide expansion at critical would contradict the single-
  // ARN evidence. Expect a cross-account finding (high at most), the org
  // exclusion noted as expansion polarity, and NO critical org-expansion row.
  const r = trust([{
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::111111111111:role/very-specific-role' },
    Action: 'sts:AssumeRole',
    Condition: { StringNotEquals: { 'aws:PrincipalOrgID': 'o-abc1234567' } },
  }]);
  assert.ok(!findingIds(r).includes('TRUST-ORG-EXPANSION'), 'no org-wide critical headline on a single specific ARN');
  const cross = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(cross, 'scoped to the cross-account case');
  assert.equal(cross.severity, 'high', 'a negated org condition is an expansion, not a constraint - stays high, not lowered');
  assert.match(cross.why, /very-specific-role/, 'names the single trusted ARN');
  assert.doesNotMatch(cross.why, /organization-wide set of outside principals/i, 'does not overclaim org-wide expansion on one ARN');
  assert.match(cross.why, /expansion/i, 'still notes the negated org condition is expansion polarity');
});

test('IAM-903 supersedes IAM-803 it.3: a wildcard-ARN Principal ("arn:aws:iam::*:role/*") + negated org is INVALID (fail closed), not a critical TRUST-ORG-EXPANSION', () => {
  // The org-expansion critical branch (findingsForStatement:
  // `sig.orgExclusion && principalIsBroad(principals)`) is reached only by a VALID
  // broad principal - Principal "*". A NAMED principal ARN carrying a partial "*"
  // wildcard is NOT a valid principal element at all (IAM-903): it fails closed to
  // TRUST-INVALID-PRINCIPAL before any severity branch, so it can be neither the
  // critical org-expansion nor a bounded cross-account fall-through. (The
  // Principal "*" + negated-org critical case remains covered by the
  // TRUST-ORG-EXPANSION test earlier in this file.)
  const r = trust([{
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::*:role/*' },
    Action: 'sts:AssumeRole',
    Condition: { StringNotEquals: { 'aws:PrincipalOrgID': 'o-abc1234567' } },
  }]);
  assert.ok(findingIds(r).includes('TRUST-INVALID-PRINCIPAL'), 'a wildcard-ARN principal element is invalid');
  assert.ok(!findingIds(r).includes('TRUST-ORG-EXPANSION'), 'an invalid principal is not expanded into a critical org-expansion');
  assert.ok(!findingIds(r).includes('TRUST-CROSS-ACCOUNT'), 'nor into an ordinary cross-account high');
});

test('IAM-903 supersedes IAM-803 it.4: an account-pinned wildcard ARN ("arn:aws:iam::123456789012:role/app-*") + negated org is INVALID, not cross-account high', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::123456789012:role/app-*' },
    Action: 'sts:AssumeRole',
    Condition: { StringNotEquals: { 'aws:PrincipalOrgID': 'o-abc1234567' } },
  }]);
  assert.ok(findingIds(r).includes('TRUST-INVALID-PRINCIPAL'), 'account-pinned partial wildcard in a Principal ARN is still invalid');
  assert.ok(!findingIds(r).includes('TRUST-ORG-EXPANSION'), 'invalid principal is not org-wide critical');
  assert.ok(!findingIds(r).includes('TRUST-CROSS-ACCOUNT'), 'invalid principal is not a cross-account fall-through');
});

test('IAM-803 it.4 inversion guard preserved for VALID principals: whole-account id and :root ARN both stay cross-account high (never over-ranked)', () => {
  // The inversion guard applies to VALID principals. A wildcard-ARN principal is
  // now invalid (IAM-903, asserted above), so the guard is re-anchored on the two
  // valid whole-account spellings, which must both be cross-account high.
  const cond = { StringNotEquals: { 'aws:PrincipalOrgID': 'o-abc1234567' } };
  const wholeAccount = trust([{ Effect: 'Allow', Principal: { AWS: '999988887777' }, Action: 'sts:AssumeRole', Condition: cond }]);
  const rootArn = trust([{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole', Condition: cond }]);
  const sev = (r) => r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.equal(sev(wholeAccount).severity, 'high', 'bare account id + negated org -> cross-account high');
  assert.equal(sev(rootArn).severity, 'high', ':root ARN + negated org -> cross-account high');
  assert.ok(!findingIds(wholeAccount).includes('TRUST-ORG-EXPANSION'), 'a bounded whole-account principal is not org-wide critical');
});

// ---------------------------------------------------------------------------
// Adversarial-critic regressions (IAM-802 iteration 4): two verified defects.
//   (1) UNDER-CLAIM: a StringLike/ArnLike value that contains a literal char but
//       still matches the whole value space (arn:aws:*:*:*:*, 1*, o-*,
//       arn:aws:iam::*:*) slipped past the pure-wildcard guard and downgraded a
//       dangerous trust a full band. Such a value is NOT a real narrowing
//       constraint.
//   (2) WRONG-PROVENANCE: a same-statement positive aws:PrincipalArn scoping
//       condition on a named cross-account principal was ignored, so the finding
//       falsely asserted whole-account access the policy contradicts.
// ---------------------------------------------------------------------------

test('ArnLike aws:SourceArn "arn:aws:*:*:*:*" matches every ARN -> not a constraint (stays high)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:*:*:*:*' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'a value matching every ARN does not narrow');
  assert.match(f.why, /no confused[- ]deputy constraint/i);
});

test('StringLike aws:SourceAccount "1*" does not pin an account -> not a constraint (stays high)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole',
    Condition: { StringLike: { 'aws:SourceAccount': '1*' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'a wildcarded account id is never pinned');
});

test('StringLike aws:PrincipalOrgID "o-*" matches every org -> not a constraint (stays high)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole',
    Condition: { StringLike: { 'aws:PrincipalOrgID': 'o-*' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'o-* matches every organization id');
});

test('Principal "*" + StringLike aws:PrincipalArn "arn:aws:iam::*:*" does not narrow -> stays critical public', () => {
  const r = trust([{
    Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole',
    Condition: { StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:*' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-PUBLIC');
  assert.ok(f);
  assert.equal(f.severity, 'critical', 'a PrincipalArn matching every IAM principal does not narrow "*"');
});

test('a genuinely narrowing globbed SourceArn (account pinned) IS still a constraint (low)', () => {
  // Control: the account segment carries a concrete id, so it really narrows -
  // the iteration-4 fix must not over-correct and reject real constraints.
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:cloudtrail:*:123456789012:trail/*' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.ok(['low', 'medium'].includes(f.severity), `a real SourceArn constraint lowers severity, got ${f.severity}`);
});

// ---------------------------------------------------------------------------
// Adversarial-critic regression (IAM-804 iteration 2): a wildcard-ACCOUNT
// aws:SourceArn / aws:SourceAccount ARN whose only surviving literal is a bare
// resource-TYPE keyword (role, secret, function, ...) matches every resource of
// that type in EVERY account. It bounds neither WHICH account nor WHICH
// resource, so it is NOT a confused-deputy scope and must NOT neutralize a
// whole-account external trust (it previously slammed high->low and stamped the
// vacuous condition into the evidence as a real mitigation - a wrong-provenance
// under-claim, the same class already fixed for pure wildcards). This is the
// boundary against 'arn:aws:iam::*:*' (already high): the only difference is the
// no-op resource-type keyword, so both must stay high.
// ---------------------------------------------------------------------------

test('ArnLike aws:SourceArn "arn:aws:iam::*:role/*" is a bare type keyword across all accounts -> not a constraint (stays high)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:iam::*:role/*' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'every role in every account bounds nothing -> stays high');
  assert.match(f.why, /no confused[- ]deputy constraint/i,
    'must not credit the vacuous SourceArn as a confused-deputy mitigation');
  assert.doesNotMatch(f.why, /gated by a confused-deputy constraint/i);
});

test('ArnLike aws:SourceArn "arn:aws:secretsmanager:*:*:secret:*" matches every secret in every account -> not a constraint (stays high)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:secretsmanager:*:*:secret:*' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'a bare secret-type keyword pins no account and no secret');
  assert.match(f.why, /no confused[- ]deputy constraint/i);
});

test('boundary: "arn:aws:iam::*:*" and "arn:aws:iam::*:role/*" are BOTH high (the type keyword is a no-op)', () => {
  const noKeyword = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:iam::*:*' } },
  }]).findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  const withKeyword = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:iam::*:role/*' } },
  }]).findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.equal(noKeyword.severity, 'high');
  assert.equal(withKeyword.severity, 'high', 'adding a no-op resource-type keyword must not change the verdict');
  assert.equal(noKeyword.severity, withKeyword.severity, 'the type keyword must not flip the severity');
});

test('preservation: a CONCRETE resource id in a wildcard-account SourceArn still narrows (low/medium)', () => {
  // The fix must reject only BARE type keywords, not concrete identifiers. A
  // specific role name / bucket bounds WHICH resource, so it remains a (weaker)
  // scoping constraint and must not over-correct back to high.
  const role = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:iam::*:role/SpecificServiceRole' } },
  }]).findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(role);
  assert.ok(['low', 'medium'].includes(role.severity),
    `a concrete role identifier still narrows, got ${role.severity}`);
});

test('preservation: an S3 SourceArn pinning a concrete bucket (account-less) still narrows', () => {
  const s3 = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:s3:::specific-bucket/*' } },
  }]).findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(s3);
  assert.ok(['low', 'medium'].includes(s3.severity),
    `a concrete bucket name still narrows, got ${s3.severity}`);
});

test('named cross-account root + StringEquals aws:PrincipalArn (one role) is NOT a whole-account claim (provenance)', () => {
  // The same-statement aws:PrincipalArn pins exactly one role, so the finding must
  // not assert the whole account can assume. Treated symmetrically with the
  // Principal "*" path: an exact PrincipalArn scope -> medium, not high.
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/OnlyThisRole' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'medium', 'an exact PrincipalArn scope drops below whole-account high');
  assert.doesNotMatch(f.why, /any\s+identity the trusted account authorizes can assume this role/i,
    'must not assert whole-account access the condition contradicts');
  assert.doesNotMatch(f.why, /trusts the WHOLE account/i, 'must not claim whole-account trust');
  assert.match(f.why, /pins WHICH principal/i, 'accounts for the principal-scoping condition');
  assert.match(f.why, /aws:PrincipalArn/i, 'names the scoping condition');
});

test('named cross-account root + broad aws:PrincipalArn (role/*) stays high but is scoped, not whole-account', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole',
    Condition: { StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/*' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'a wildcarded (but account-pinned) PrincipalArn set stays broad -> high');
  assert.match(f.why, /pins WHICH principal/i, 'still accounts for the scoping condition, not a whole-account claim');
});

// ---------------------------------------------------------------------------
// Adversarial-critic regressions (IAM-802 iteration 5): MULTI-VALUE OR polarity.
// IAM combines the multiple values of one operator+key with OR, so a scoping /
// confused-deputy condition constrains ONLY when EVERY value narrows. A single
// co-listed match-all element (o-*, arn:aws:*:*:*:*, "*") makes the whole
// condition vacuous. The evaluator previously used `.some` (one narrow element
// flipped the constraint ON), under-claiming severity and stamping a vacuous
// condition into the evidence as an effective mitigation. Fixed to `.every`
// (+ non-empty guard), matching the aws:SourceIp all-addresses .every guard.
// ---------------------------------------------------------------------------

test('BUG-1: cross-account root + StringLike aws:PrincipalOrgID [pinned, "o-*"] is vacuous -> stays high', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { StringLike: { 'aws:PrincipalOrgID': ['o-victim12345', 'o-*'] } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'the co-listed o-* matches every org under OR, so the org constraint is vacuous');
  assert.match(f.why, /no confused[- ]deputy constraint/i, 'must not credit the vacuous org condition as a mitigation');
});

test('BUG-2: cross-account account + ArnLike aws:SourceArn [pinned, "arn:aws:*:*:*:*"] is vacuous -> stays high', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: '999988887777' }, Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': ['arn:aws:sns:us-east-1:999988887777:topic', 'arn:aws:*:*:*:*'] } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'the co-listed match-all ARN defeats the pinned one under OR');
  assert.match(f.why, /no confused[- ]deputy constraint/i);
});

test('BUG-3: cross-account root + StringLike sts:ExternalId [real, "*"] is vacuous -> stays high; no "gated by" wording', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { StringLike: { 'sts:ExternalId': ['real-correlation-id', '*'] } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'the co-listed "*" ExternalId matches everything, so the mitigation is vacuous');
  assert.doesNotMatch(f.why, /gated by a confused[- ]deputy constraint/i,
    'must not present a vacuous ExternalId as an effective mitigation (wrong provenance)');
  assert.match(f.why, /no confused[- ]deputy constraint/i);
});

test('BUG-4: Principal "*" + StringLike aws:PrincipalOrgID [pinned, "o-*"] is vacuous -> stays critical public', () => {
  const r = trust([{
    Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole',
    Condition: { StringLike: { 'aws:PrincipalOrgID': ['o-xreal12345', 'o-*'] } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-PUBLIC');
  assert.ok(f);
  assert.equal(f.severity, 'critical', 'a vacuous org scope does NOT narrow the wildcard principal');
  assert.match(f.why, /ANY AWS principal/i, 'the wildcard is not narrowed, so it is the full public-trust finding');
});

test('multi-value control: a positive condition whose values ALL narrow IS still a constraint (low)', () => {
  // Both org ids are concrete literals, so under OR the condition confines trust
  // to two named orgs - a real constraint. The .every fix must not over-correct
  // and reject a genuine multi-value constraint.
  const org = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'aws:PrincipalOrgID': ['o-realorg99', 'o-otherorg88'] } },
  }]);
  const of = org.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(of);
  assert.ok(['low', 'medium'].includes(of.severity), `all-narrow org list is a real constraint, got ${of.severity}`);

  const ext = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'sts:ExternalId': ['corr-a', 'corr-b'] } },
  }]);
  const ef = ext.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(ef);
  assert.ok(['low', 'medium'].includes(ef.severity), `all-narrow ExternalId list is a real constraint, got ${ef.severity}`);
});

test('single-value neutralized controls remain low (unchanged by the .every fix)', () => {
  const extId = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999988887777:root' }, Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'sts:ExternalId': 'unique-corr-id' } },
  }]);
  assert.ok(['low', 'medium'].includes(extId.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT').severity));

  const srcArn = trust([{
    Effect: 'Allow', Principal: { AWS: '999988887777' }, Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:cloudtrail:*:999988887777:trail/audit' } },
  }]);
  assert.ok(['low', 'medium'].includes(srcArn.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT').severity));

  const orgEq = trust([{
    Effect: 'Allow', Principal: { AWS: '999988887777' }, Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-realorg99' } },
  }]);
  assert.ok(['low', 'medium'].includes(orgEq.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT').severity));
});

// ---------------------------------------------------------------------------
// Adversarial-critic regressions (IAM-803 iteration 2): OPERATOR QUALIFIERS.
// A ...IfExists suffix or a ForAllValues: set prefix PASSES when the key is
// ABSENT from the request, so the constraint is trivially bypassed by omitting
// the key. trust.js used to discard the qualifier (parseBaseOperator) and credit
// such a condition as a full confused-deputy / scoping / tight-subject
// constraint, dropping a whole-account external (or tight federated) trust to
// low - while the finding's OWN conditionClassification.credited was false. The
// fix keeps the finding HIGH, names the qualifier in the why text, and severity
// now AGREES with conditionClassification.hasCreditableConstraint. ForAnyValue:
// is NOT a bypass (it needs a supplied value to match), so it stays creditable.
// ---------------------------------------------------------------------------

for (const [label, condition] of [
  ['StringEqualsIfExists sts:ExternalId', { StringEqualsIfExists: { 'sts:ExternalId': 'unique-id' } }],
  ['ForAllValues:StringEquals sts:ExternalId', { 'ForAllValues:StringEquals': { 'sts:ExternalId': 'unique-id' } }],
  ['ArnLikeIfExists aws:SourceArn (account-pinned)', { ArnLikeIfExists: { 'aws:SourceArn': 'arn:aws:cloudtrail:*:999888777666:trail/x' } }],
]) {
  test(`bypassable qualifier is NOT an effective constraint (${label}) -> stays high, credited=false`, () => {
    const r = trust([{
      Effect: 'Allow', Principal: { AWS: '999888777666' }, Action: 'sts:AssumeRole', Condition: condition,
    }]);
    const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
    assert.ok(f, 'cross-account trust surfaced');
    assert.equal(f.severity, 'high', 'a bypassable qualifier does not lower the finding');
    assert.equal(f.conditionClassification.hasCreditableConstraint, false,
      'severity must agree with conditionClassification: the qualifier is not credited');
    assert.match(f.why, /IfExists|ForAllValues/, 'the bypassable qualifier is named in the why text');
    assert.match(f.why, /no confused[- ]deputy constraint/i, 'not presented as a gated/mitigated trust');
  });
}

test('StringEqualsIfExists aws:PrincipalOrgID does not credit an org constraint -> stays high', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999888777666:root' }, Action: 'sts:AssumeRole',
    Condition: { StringEqualsIfExists: { 'aws:PrincipalOrgID': 'o-abc1234567' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high');
  assert.equal(f.conditionClassification.hasCreditableConstraint, false);
  assert.match(f.why, /IfExists/);
});

test('OIDC :sub that is tight but ...IfExists is bypassable -> broad, high, credited=false', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { Federated: 'arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com' },
    Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: { StringEqualsIfExists: { 'token.actions.githubusercontent.com:sub': 'repo:org/repo:ref:refs/heads/main' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-FEDERATED');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'a bypassable tight sub is treated as broad');
  assert.equal(f.conditionClassification.hasCreditableConstraint, false);
  assert.match(f.why, /IfExists/);
});

test('ForAnyValue is NOT a bypass: a real ExternalId constraint stays low + credited (control)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: '999888777666' }, Action: 'sts:AssumeRole',
    Condition: { 'ForAnyValue:StringEquals': { 'sts:ExternalId': 'unique-id' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.ok(['low', 'medium'].includes(f.severity), `ForAnyValue is creditable, got ${f.severity}`);
  assert.equal(f.conditionClassification.hasCreditableConstraint, true);
});

test('provenance coherence: match-everything glob on a key-aware key is high AND not credited', () => {
  // trust.js already kept these high (valueNarrowsKey rejects the glob); this pins
  // that conditions.js no longer credits the vacuous glob in the evidence panel.
  for (const condition of [
    { StringLike: { 'aws:PrincipalOrgID': 'o-*' } },
    { ArnLike: { 'aws:SourceArn': 'arn:aws:*:*:*:*' } },
  ]) {
    const r = trust([{
      Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999888777666:root' }, Action: 'sts:AssumeRole', Condition: condition,
    }]);
    const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
    assert.ok(f);
    assert.equal(f.severity, 'high');
    assert.equal(f.conditionClassification.hasCreditableConstraint, false,
      'a match-everything glob must not be credited as a guardrail');
  }
});

// ---------------------------------------------------------------------------
// Adversarial-critic regressions (IAM-804 iteration 4): the StringLike single-char
// wildcard '?' was treated as a LITERAL character in two places, both under-claims.
//   Finding 1: the federated-subject breadth test inspected only '*', so a
//     '?'-globbed OIDC sub scored low/TIGHT while conditions.js flagged it
//     broad/uncredited - severity disagreeing with the finding's own provenance.
//   Finding 2: the default-path narrowing test rejected only '' and pure-'*', so a
//     match-everything glob like sts:ExternalId "?*" was credited as a
//     confused-deputy constraint and dropped a whole-account trust high->low.
// Both must fail closed: a '?' in a sub is BROAD (high), an all-glob default-path
// value narrows NOTHING (stays high, uncredited), and trust severity must AGREE
// with conditions.js provenance.
// ---------------------------------------------------------------------------

test("Finding 1: OIDC sub with a '?' glob is BROAD -> TRUST-FEDERATED high, agreeing with provenance", () => {
  const r = trust([{
    Effect: 'Allow', Action: 'sts:AssumeRoleWithWebIdentity',
    Principal: { Federated: 'arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com' },
    Condition: { StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:myorg/myrep?:ref:refs/heads/main' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-FEDERATED');
  assert.ok(f);
  assert.equal(f.severity, 'high', "a '?' widens the trusted-workload set (myrepo, myrepa, ...), so the subject is BROAD");
  assert.doesNotMatch(f.why, /TIGHTLY-scoped subject/i, 'must not call a globbed subject tight');
  assert.match(f.why, /BROAD or absent subject scope/i);
  // Severity must AGREE with the finding's own embedded condition provenance.
  const sub = f.conditionClassification.entries.find((e) => e.key.endsWith(':sub'));
  assert.ok(sub);
  assert.equal(sub.credited, false, 'a globbed subject is not credited as a dependable guardrail');
});

test("Finding 1 (starker): a '?'-repeated org-wide sub 'repo:evilorg/??????????' is BROAD -> high", () => {
  const f = trust([{
    Effect: 'Allow', Action: 'sts:AssumeRoleWithWebIdentity',
    Principal: { Federated: 'arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com' },
    Condition: { StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:evilorg/??????????' } },
  }]).findings.find((x) => x.id === 'TRUST-FEDERATED');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'a subject matching any 10-char workload id across an org is broad, not tight');
});

test('Finding 1 preservation: a fully-literal (no glob) sub stays TIGHT -> low', () => {
  const f = trust([{
    Effect: 'Allow', Action: 'sts:AssumeRoleWithWebIdentity',
    Principal: { Federated: 'arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com' },
    Condition: { StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:myorg/myrepo:ref:refs/heads/main' } },
  }]).findings.find((x) => x.id === 'TRUST-FEDERATED');
  assert.ok(f);
  assert.equal(f.severity, 'low', 'no glob metacharacter -> a specific workload -> tight');
});

test('Finding 2: StringLike sts:ExternalId "?*" matches every non-empty string -> vacuous (stays high, uncredited)', () => {
  const r = trust([{
    Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999888777666:root' }, Action: 'sts:AssumeRole',
    Condition: { StringLike: { 'sts:ExternalId': '?*' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', '"?*" is functionally identical to "*" - a vacuous ExternalId any caller satisfies');
  assert.match(f.why, /no confused[- ]deputy constraint/i, 'must not credit the vacuous ExternalId as a mitigation');
  assert.doesNotMatch(f.why, /gated by a confused[- ]deputy constraint/i);
  // conditions.js provenance must AGREE (mirror): not credited in the evidence panel.
  assert.equal(f.conditionClassification.hasCreditableConstraint, false,
    'a match-everything glob ExternalId must not be credited (provenance agrees with trust.js)');
});

test('Finding 2: other all-glob default-path ExternalId values ("*?", "?", "**?") all stay high', () => {
  for (const v of ['*?', '?', '**?', '*?*']) {
    const f = trust([{
      Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999888777666:root' }, Action: 'sts:AssumeRole',
      Condition: { StringLike: { 'sts:ExternalId': v } },
    }]).findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
    assert.ok(f, `ExternalId ${v}`);
    assert.equal(f.severity, 'high', `an all-glob ExternalId "${v}" pins no literal correlation value -> stays high`);
    assert.equal(f.conditionClassification.hasCreditableConstraint, false, `"${v}" must not be credited`);
  }
});

test('Finding 2 preservation: a partial ExternalId carrying a LITERAL is still a (weaker) constraint (low/medium)', () => {
  for (const v of ['corr-?', 'my-ext-id-*', 'prefix?suffix']) {
    const f = trust([{
      Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999888777666:root' }, Action: 'sts:AssumeRole',
      Condition: { StringLike: { 'sts:ExternalId': v } },
    }]).findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
    assert.ok(f, `ExternalId ${v}`);
    assert.ok(['low', 'medium'].includes(f.severity),
      `a literal-carrying ExternalId "${v}" still forces a correlation substring, got ${f.severity}`);
    assert.equal(f.conditionClassification.hasCreditableConstraint, true, `"${v}" is credited (has a literal)`);
  }
});

// ---------------------------------------------------------------------------
// The load-bearing invariant: every trust finding states target-role perms are
// out of scope / unknown, and never claims effective/ inherited access.
// ---------------------------------------------------------------------------

test('every trust finding carries the target-unknown / not-effective-access limitation', () => {
  const policies = [
    [{ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }],
    [{ Effect: 'Allow', Principal: { AWS: '444455556666' }, Action: 'sts:AssumeRole' }],
    [{ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }],
    [{ Effect: 'Allow', Principal: { Federated: 'arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com' }, Action: 'sts:AssumeRoleWithWebIdentity' }],
  ];
  let seen = 0;
  for (const p of policies) {
    const r = trust(p);
    for (const f of r.findings) {
      seen += 1;
      assert.ok(TRUST_ID_SET.has(f.id), `finding ${f.id} is a trust id`);
      assert.match(f.limit, /not effective access/i, `${f.id}: capability-not-effective caveat`);
      assert.match(f.limit, /unknown/i, `${f.id}: target-role permissions stated unknown`);
      assert.equal(f.trust.targetPermissions, 'unknown', `${f.id}: targetPermissions never inferred`);
      assert.deepEqual(f.resources, [], `${f.id}: a trust finding has no Resource scope`);
      assert.equal(f.policyEvidence, 'high');
      assert.ok(['low', 'medium', 'high'].includes(f.pathExploitability));
    }
  }
  assert.ok(seen >= 4, 'exercised several trust findings');
});

// ---------------------------------------------------------------------------
// Fail-closed traps retained (IAM-801 requirement).
// ---------------------------------------------------------------------------

test('NotPrincipal on a trust shape stays fail-closed (UNSUPPORTED_NOTPRINCIPAL)', () => {
  const r = trust([{ Effect: 'Allow', NotPrincipal: { AWS: 'arn:aws:iam::1:root' }, Action: 'sts:AssumeRole' }]);
  assert.equal(r.coverage.blocked, true);
  assert.ok(r.coverage.blockingCodes.some((b) => b.code === 'UNSUPPORTED_NOTPRINCIPAL'));
  assert.equal(r.findings.length, 0);
});

test('unknown Principal type on a trust shape stays fail-closed (UNSUPPORTED_PRINCIPAL_TYPE)', () => {
  const r = trust([{ Effect: 'Allow', Principal: { Potato: 'spud' }, Action: 'sts:AssumeRole' }]);
  assert.equal(r.coverage.detected, 'role-trust');
  assert.equal(r.coverage.blocked, true);
  assert.ok(r.coverage.blockingCodes.some((b) => b.code === 'UNSUPPORTED_PRINCIPAL_TYPE'));
  assert.equal(r.findings.length, 0);
});

test('mixed identity + trust document stays fail-closed (AMBIGUOUS_POLICY_SHAPE)', () => {
  const r = trust([
    { Sid: 'id', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::x/*' },
    { Sid: 'tr', Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' },
  ]);
  assert.equal(r.coverage.blocked, true);
  assert.ok(r.coverage.blockingCodes.some((b) => b.code === 'AMBIGUOUS_POLICY_SHAPE'));
  assert.equal(r.findings.length, 0);
});

// ---------------------------------------------------------------------------
// IAM-802: external-origin trust graph. The graph origin is the EXTERNAL
// principal(s) that may assume the role - NOT the identity "Principal subject of
// this policy" root - and a can-assume edge points to the role node whose target
// privileges are marked unknown. No identity-style capability edge is emitted on
// a trust policy. (docs/trust-policy-semantics.md section 6, acceptance 15/16.)
// ---------------------------------------------------------------------------

const IDENTITY_CAPABILITY_EDGES = new Set([
  'can-pass', 'can-modify', 'can-execute-as', 'can-read', 'can-decrypt',
  'can-write', 'can-destroy',
]);

test('public trust graph: external-anonymous origin -> can-assume -> role (privileges unknown); no principal-subject root, no identity edges', () => {
  const r = trust([{ Sid: 'P', Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }]);
  const { nodes, edges } = r.graph;

  // Origin represents external principals, never the identity principal-subject.
  assert.ok(!nodes.some((n) => n.id === 'principal'),
    'a trust graph has no "Principal (subject of this policy)" root');
  const origin = nodes.find((n) => n.type === 'ExternalPrincipal');
  assert.ok(origin, 'an ExternalPrincipal origin node is present');
  assert.equal(origin.id, 'ext:anonymous');

  // The target role node marks its privileges unknown / out of scope.
  const role = nodes.find((n) => n.type === 'Role');
  assert.ok(role, 'a target Role node is present');
  assert.equal(role.unknownPrivileges, true, 'target-role privileges marked unknown');

  // Exactly one can-assume edge: origin -> role. No identity capability edges.
  const assumeEdges = edges.filter((e) => e.type === 'can-assume');
  assert.equal(assumeEdges.length, 1);
  assert.equal(assumeEdges[0].from, origin.id);
  assert.equal(assumeEdges[0].to, role.id);
  assert.deepEqual(assumeEdges[0].evidence.map((v) => v.actions), [['sts:AssumeRole']],
    'edge evidence attributes the sts action to its granting statement');
  for (const e of edges) {
    assert.ok(!IDENTITY_CAPABILITY_EDGES.has(e.type),
      `a trust graph must not emit identity capability edge ${e.type}`);
  }
  assert.equal(r.counts.nodes, nodes.length);
  assert.equal(r.counts.edges, edges.length);
});

test('cross-account (ExternalId) trust graph: external-account origin -> can-assume -> role; conditioned edge is context-required', () => {
  const r = trust([{
    Sid: 'V', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111122223333:root' }, Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'sts:ExternalId': 'customer-7f6af74e' } },
  }]);
  const origin = r.graph.nodes.find((n) => n.type === 'ExternalPrincipal');
  assert.ok(origin, 'external-account origin present');
  assert.match(origin.label, /111122223333/, 'origin labels the trusted account (inert)');
  const edge = r.graph.edges.find((e) => e.type === 'can-assume');
  assert.ok(edge);
  assert.equal(edge.to, r.graph.nodes.find((n) => n.type === 'Role').id);
  assert.equal(edge.certainty, 'context-required',
    'a conditioned trust reads as context-required (a runtime request must satisfy the Condition)');
});

test('service trust graph: origin is a Service node -> can-assume -> role; still no identity capability edges', () => {
  const r = trust([{ Sid: 'L', Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }]);
  const svc = r.graph.nodes.find((n) => n.type === 'Service');
  assert.ok(svc, 'service principal is a Service origin node');
  assert.equal(svc.id, 'svc:lambda.amazonaws.com');
  const edge = r.graph.edges.find((e) => e.type === 'can-assume' && e.from === svc.id);
  assert.ok(edge, 'service -> can-assume -> role');
  for (const e of r.graph.edges) {
    assert.ok(!IDENTITY_CAPABILITY_EDGES.has(e.type));
  }
});

test('a blocked trust shape (NotPrincipal) produces an empty graph (fail closed)', () => {
  const r = trust([{ Effect: 'Allow', NotPrincipal: { AWS: 'arn:aws:iam::1:root' }, Action: 'sts:AssumeRole' }]);
  assert.equal(r.graph.nodes.length, 0);
  assert.equal(r.graph.edges.length, 0);
});

// ---------------------------------------------------------------------------
// analyzeTrust module contract + determinism + exports.
// ---------------------------------------------------------------------------

test('analyzeTrust never runs on a Deny trust statement (Deny is not a grant)', () => {
  const m = modelFromText(pol([{ Effect: 'Deny', Principal: '*', Action: 'sts:AssumeRole' }]));
  const r = analyzeTrust(m.model);
  assert.equal(r.ok, true);
  assert.equal(r.findings.length, 0, 'a Deny trust statement yields no positive trust finding');
});

test('analyzeTrust is deterministic and returns a structured result on a bad model', () => {
  const bad = analyzeTrust(null);
  assert.equal(bad.ok, false);
  assert.equal(bad.findings.length, 0);
  const p = pol([{ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }]);
  assert.deepEqual(analyze(p), analyze(p), 'analyze() is deterministic over a trust policy');
});

test('trust findings serialize into JSON + Markdown exports', () => {
  const r = trust([{ Sid: 'P', Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }]);
  const json = JSON.parse(toJSON(r));
  assert.equal(json.family, 'role-trust');
  assert.ok(json.findings.some((f) => f.id === 'TRUST-PUBLIC'));
  const md = toMarkdown(r);
  assert.match(md, /Policy family: role-trust/);
  assert.match(md, /\[CRITICAL\]/);
  assert.match(md, /Rule: TRUST-PUBLIC/);
});

// ---------------------------------------------------------------------------
// IAM-803: trust condition keys are modeled by the Phase-5 classifier, so a
// trust policy's understood conditions are NOT reported as unsupported and the
// per-finding conditionClassification is coherent with the trust severity. A
// genuinely unknown trust condition key still reduces confidence (surfaced in
// coverage) - unsupported does NOT mean safe.
// ---------------------------------------------------------------------------

test('a modeled sts:ExternalId constraint keeps trust coverage complete + coherent evidence', () => {
  const r = trust([{
    Sid: 'Vendor', Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::111122223333:root' },
    Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'sts:ExternalId': 'customer-7f6af74e' } },
  }]);
  assert.equal(r.coverage.summary.incomplete, false, 'ExternalId is modeled -> coverage complete');
  assert.deepEqual(r.coverage.summary.unsupportedConditions, [], 'ExternalId is not surfaced as unsupported');
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f, 'cross-account trust finding present');
  const ext = f.conditionClassification.entries.find((e) => e.key === 'sts:ExternalId');
  assert.ok(ext, 'ExternalId classified on the finding');
  assert.equal(ext.class, 'constraint');
  assert.equal(ext.credited, true, 'the classifier agrees ExternalId is a confused-deputy constraint');
});

test('modeled OIDC aud/sub keep coverage complete; broad sub not credited as a guardrail', () => {
  const r = trust([{
    Sid: 'GitHubOIDC', Effect: 'Allow',
    Principal: { Federated: 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com' },
    Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: {
      StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' },
      StringLike: { 'token.actions.githubusercontent.com:sub': 'repo:example-org/*' },
    },
  }]);
  assert.equal(r.coverage.summary.incomplete, false, 'aud/sub are modeled -> coverage complete');
  assert.deepEqual(r.coverage.summary.unsupportedConditions, []);
  const f = r.findings.find((x) => x.id === 'TRUST-FEDERATED');
  assert.ok(f, 'federated trust finding present');
  const aud = f.conditionClassification.entries.find((e) => e.key.endsWith(':aud'));
  const sub = f.conditionClassification.entries.find((e) => e.key.endsWith(':sub'));
  assert.equal(aud.credited, true, 'aud is a recognized constraint');
  assert.equal(sub.credited, false, 'an org-wide wildcarded sub is broad, not a dependable guardrail');
});

test('an unknown trust condition key reduces confidence (surfaced) but never clears the finding', () => {
  const r = trust([{
    Sid: 'Vendor', Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::111122223333:root' },
    Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'sts:RoleSessionName': 'ci-runner' } },
  }]);
  assert.equal(r.coverage.summary.incomplete, true, 'an unmodeled trust key marks coverage incomplete');
  assert.ok(r.coverage.summary.unsupportedConditions.includes('sts:RoleSessionName'),
    'the unknown key is surfaced in coverage, not silently ignored');
  assert.ok(r.findings.some((f) => f.id === 'TRUST-CROSS-ACCOUNT'),
    'the cross-account trust still fires - unsupported does NOT mean safe');
});

// ---------------------------------------------------------------------------
// Adversarial-critic regressions (IAM-805 iteration 2): the principal-scoping-
// condition branch scored a scoping condition's breadth IN ISOLATION instead of
// INTERSECTING it with the named Principal (AWS evaluates Principal AND
// Condition), and it mis-modeled aws:PrincipalAccount as a sub-account narrowing
// (medium) when account granularity is exactly what a root/account Principal
// already carries (high). Four distinct policies with distinct wrong outputs.
// ---------------------------------------------------------------------------

test('IAM-805-it2 F1: root Principal + REDUNDANT aws:PrincipalAccount(==same account) stays HIGH (account granularity narrows nothing)', () => {
  // Baseline (root Principal, no condition) is HIGH; a PrincipalAccount condition
  // equal to the account the root Principal already names adds zero restriction -
  // the whole account is still trusted. It must NOT drop to medium, and the why
  // must NOT assert "does NOT trust the whole account".
  const r = trust([{
    Effect: 'Allow', Action: 'sts:AssumeRole',
    Principal: { AWS: 'arn:aws:iam::123456789012:root' },
    Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f, 'expected TRUST-CROSS-ACCOUNT');
  assert.equal(f.severity, 'high', 'a redundant account-granularity condition must not lower the no-condition HIGH baseline');
  assert.doesNotMatch(f.why, /does NOT trust the whole account/i,
    'the whole account is still trusted; the evidence text must not deny it');
  assert.match(f.why, /account-granularity/i, 'explains PrincipalAccount is account-granularity, not a sub-account scope');
});

test('IAM-805-it2 F2: Principal "*" + aws:PrincipalAccount==X is whole-account trust -> HIGH, matching the root-ARN form', () => {
  // "*" + PrincipalAccount==X is semantically identical to Principal root:X (both
  // trust every principal in account X), which scores HIGH. It must not be the
  // narrower medium tier, and the wording must not call a whole external account
  // "a specific principal".
  const r = trust([{
    Effect: 'Allow', Action: 'sts:AssumeRole', Principal: '*',
    Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-PUBLIC');
  assert.ok(f, 'expected TRUST-PUBLIC (Principal is "*")');
  assert.equal(f.severity, 'high', 'whole-account scope is HIGH, not medium');
  // Equivalence to the direct root-ARN form.
  const direct = trust([{
    Effect: 'Allow', Action: 'sts:AssumeRole', Principal: { AWS: 'arn:aws:iam::123456789012:root' },
  }]).findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.equal(f.severity, direct.severity, 'matches the equivalent whole-account root-ARN severity');
  assert.match(f.why, /entire AWS account|whole account/i, 'describes whole-account breadth accurately');
  assert.doesNotMatch(f.why, /a specific principal\b/i, 'must not call a whole external account a specific principal');
});

test('IAM-805-it2 F3: root:999 + StringLike aws:PrincipalArn "arn:aws:iam::*:role/deploy" intersects to ONE role -> MEDIUM (not broad)', () => {
  // The Principal pins account 999; the condition wildcards ONLY the account
  // segment (which the Principal already pins) and names a concrete role -> the
  // Principal AND Condition intersection is exactly arn:aws:iam::999999999999:
  // role/deploy, a single role. It must NOT be scored broad/high, and the why
  // must not claim the account is pinned by the CONDITION.
  const r = trust([{
    Effect: 'Allow', Action: 'sts:AssumeRole',
    Principal: { AWS: 'arn:aws:iam::999999999999:root' },
    Condition: { StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'medium', 'an effectively single-role intersection is not broad');
  assert.match(f.why, /a specific principal/i, 'describes the single-principal scope');
  assert.doesNotMatch(f.why, /wildcarded set/i, 'must not claim a wildcarded set / account pinned by the condition');
});

test('IAM-805-it2 F4: root:999 + StringLike aws:PrincipalArn "...:role/admin?" ("?"-glob) matches a SET -> HIGH', () => {
  // role/admin? matches admin1, adminA, adminX ... a SET of roles, exactly like
  // the "*"-globbed role/admin*. A "?"-only glob must be treated as broad (high),
  // consistent with the OIDC-subject hasGlob fix and conditions.js.
  const r = trust([{
    Effect: 'Allow', Action: 'sts:AssumeRole',
    Principal: { AWS: 'arn:aws:iam::999999999999:root' },
    Condition: { StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/admin?' } },
  }]);
  const f = r.findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high', 'a "?"-globbed principal ARN matches a set of roles -> broad/high');
  // Parity with the "*"-glob form.
  const star = trust([{
    Effect: 'Allow', Action: 'sts:AssumeRole',
    Principal: { AWS: 'arn:aws:iam::999999999999:root' },
    Condition: { StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/admin*' } },
  }]).findings.find((x) => x.id === 'TRUST-CROSS-ACCOUNT');
  assert.equal(f.severity, star.severity, '"?"-glob and "*"-glob principal-ARN sets score the same');
});

// ---------------------------------------------------------------------------
// IAM-806 (iteration-3 blocking finding): same-policy explicit-Deny precedence
// on a trust policy. analyzeTrust is Deny-unaware (a Deny is never a positive
// grant), but a same-policy Deny that fully neutralizes an Allow trust grant
// must NOT leave a false "any principal may assume" finding, an unqualified
// can-assume edge, or a coverage summary claiming a complete analysis while the
// Deny is ignored. Mirrors the identity engine's IAM-302 behavior.
// ---------------------------------------------------------------------------

function graphEdges(r) {
  return r.graph.edges.map((e) => `${e.from}|${e.type}|${e.certainty}|${e.to}`);
}

test('IAM-806: public Allow fully neutralized by an unconditional public Deny -> no TRUST-PUBLIC, blocked-by-deny edge, no bare can-assume', () => {
  const r = trust([
    { Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: '*', Action: 'sts:AssumeRole' },
  ]);
  assert.deepEqual(findingIds(r), [], 'the fully-denied public trust yields NO finding (no "any principal may assume")');
  const denies = r.graph.edges.filter((e) => e.type === 'denies');
  assert.equal(denies.length, 1, 'the Deny is shown as its own denies edge');
  assert.equal(denies[0].from, 'ext:anonymous');
  assert.equal(denies[0].to, 'role:trust-target');
  assert.equal(denies[0].certainty, 'blocked-by-deny', 'an unconditional Deny is blocked-by-deny');
  assert.equal(
    r.graph.edges.filter((e) => e.type === 'can-assume').length,
    0,
    'a fully-denied grant draws NO can-assume edge (denies are not grants)',
  );
});

test('IAM-806: cross-account Allow fully neutralized by same-principal unconditional Deny -> no TRUST-CROSS-ACCOUNT', () => {
  const r = trust([
    { Effect: 'Allow', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole' },
  ]);
  assert.deepEqual(findingIds(r), [], 'the fully-denied cross-account trust yields NO finding');
  assert.ok(
    r.graph.edges.some((e) => e.type === 'denies' && e.from === 'ext:123456789012' && e.certainty === 'blocked-by-deny'),
    'the denied account is shown as a blocked-by-deny denies edge',
  );
  assert.equal(r.graph.edges.filter((e) => e.type === 'can-assume').length, 0);
});

test('IAM-806: a fully-modeled Deny keeps coverage complete but surfaces the Deny as a caveat (never silently discarded)', () => {
  const r = trust([
    { Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: '*', Action: 'sts:AssumeRole' },
  ]);
  const s = r.coverage.summary;
  assert.equal(s.incomplete, false, 'a fully-modeled Deny is complete (mirrors identity IAM-302)');
  assert.equal(s.trustDeny.present, true, 'the trust Deny is surfaced in coverage');
  assert.equal(s.trustDeny.unmodeled, false);
  assert.match(String(s.trustDeny.note), /blocked-by-deny/i);
  const md = toMarkdown(r);
  assert.match(md, /Same-policy trust Deny:/, 'the Deny caveat appears in the Markdown export');
});

test('IAM-806: a CONDITIONAL same-policy Deny does NOT fully block -> finding stays + coverage incomplete + can-assume kept', () => {
  const r = trust([
    { Effect: 'Allow', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole' },
    {
      Effect: 'Deny', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole',
      Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } },
    },
  ]);
  assert.ok(findingIds(r).includes('TRUST-CROSS-ACCOUNT'), 'a conditional Deny may not fire -> the grant finding stays');
  assert.equal(r.coverage.summary.incomplete, true, 'an unmodeled (conditional) Deny marks coverage incomplete');
  assert.equal(r.coverage.summary.trustDeny.unmodeled, true);
  assert.ok(r.coverage.summary.codes.includes('TRUST_DENY_UNMODELED'), 'a machine-readable caveat code is emitted');
  assert.ok(r.graph.edges.some((e) => e.type === 'can-assume'), 'the still-reachable grant keeps its can-assume edge');
  assert.ok(
    r.graph.edges.some((e) => e.type === 'denies' && e.certainty === 'context-required'),
    'a conditional Deny is context-required, not blocked-by-deny',
  );
});

test('IAM-806: a Deny of a DIFFERENT principal does not suppress an unrelated grant, but is still shown', () => {
  const r = trust([
    { Effect: 'Allow', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: { AWS: '999988887777' }, Action: 'sts:AssumeRole' },
  ]);
  assert.ok(findingIds(r).includes('TRUST-CROSS-ACCOUNT'), 'the granted account 123... is still reported');
  assert.equal(r.coverage.summary.incomplete, false, 'a non-overlapping unconditional Deny is fully modeled');
  assert.ok(
    r.graph.edges.some((e) => e.type === 'denies' && e.from === 'ext:999988887777'),
    'the unrelated Deny is still surfaced as a denies edge',
  );
  assert.ok(r.graph.edges.some((e) => e.type === 'can-assume' && e.from === 'ext:123456789012'));
});

test('trustFindingDenyState classifies full / partial / none', () => {
  const full = analyzeTrust(modelFromText(pol([
    { Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: '*', Action: 'sts:AssumeRole' },
  ])).model);
  const model = modelFromText(pol([
    { Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: '*', Action: 'sts:AssumeRole' },
  ])).model;
  assert.equal(trustFindingDenyState(full.findings[0], model), 'full');

  const noDenyModel = modelFromText(pol([{ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }])).model;
  const noDeny = analyzeTrust(noDenyModel);
  assert.equal(trustFindingDenyState(noDeny.findings[0], noDenyModel), 'none');

  // A conditional Deny overlaps the grant but is not proven to fully block it.
  const partialModel = modelFromText(pol([
    { Effect: 'Allow', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole' },
    {
      Effect: 'Deny', Principal: { AWS: '123456789012' }, Action: 'sts:AssumeRole',
      Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } },
    },
  ])).model;
  const partial = analyzeTrust(partialModel);
  assert.equal(trustFindingDenyState(partial.findings[0], partialModel), 'partial', 'a conditional Deny overlaps but does not fully block');
});

test('summarizeTrustDeny reports presence + unmodeled correctly', () => {
  const none = summarizeTrustDeny(
    modelFromText(pol([{ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }])).model,
    [],
  );
  assert.equal(none.present, false);

  const model = modelFromText(pol([
    { Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: '*', Action: 'sts:AssumeRole' },
  ])).model;
  const sum = summarizeTrustDeny(model, analyzeTrust(model).findings);
  assert.equal(sum.present, true);
  assert.equal(sum.count, 1);
  assert.equal(sum.unmodeled, false);
});

test('IAM-806: deny-suppressed trust analysis stays deterministic', () => {
  const p = pol([
    { Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: '*', Action: 'sts:AssumeRole' },
  ]);
  assert.deepEqual(analyze(p), analyze(p));
});

// ---------------------------------------------------------------------------
// IAM-806 iteration 4: adversarial-critic defects on the same-policy Deny path.
//   defect 1 - root-ARN <-> bare-account-id canonical equivalence: a Deny in one
//     form must neutralize an Allow in the other (AWS: both delegate the whole
//     account). The table, graph, and coverage note must AGREE.
//   defect 2 - the "fully neutralizes the overlapping assume grant" note must only
//     appear when a Deny actually resolved a finding to 'full'; a Deny that
//     overlaps NO grant must not claim neutralization.
// ---------------------------------------------------------------------------

test('IAM-806: root-ARN Allow fully neutralized by bare-account-id Deny (canonical equivalence)', () => {
  const r = trust([
    { Sid: 'A', Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole' },
    { Sid: 'D', Effect: 'Deny', Principal: { AWS: '999999999999' }, Action: 'sts:AssumeRole' },
  ]);
  // Table: the cross-account grant is fully denied -> no over-claim.
  assert.deepEqual(findingIds(r), [], 'root-ARN Allow denied by same-account bare-id Deny yields NO finding');
  // Graph: exactly one external node (the account), one denies edge, no can-assume.
  const externals = r.graph.nodes.filter((n) => n.type === 'ExternalPrincipal');
  assert.equal(externals.length, 1, 'a single account is drawn as ONE external principal, not two');
  assert.equal(r.graph.edges.filter((e) => e.type === 'can-assume').length, 0, 'a fully-denied grant draws no can-assume edge');
  assert.ok(r.graph.edges.some((e) => e.type === 'denies' && e.certainty === 'blocked-by-deny'), 'the Deny is shown as a blocked-by-deny edge');
  // Coverage note agrees: neutralization claimed, and it is true.
  assert.equal(r.coverage.summary.trustDeny.unmodeled, false);
  assert.match(String(r.coverage.summary.trustDeny.note), /fully neutralizes/i);
});

test('IAM-806: bare-account-id Allow fully neutralized by root-ARN Deny (reverse spelling)', () => {
  const r = trust([
    { Sid: 'A', Effect: 'Allow', Principal: { AWS: '999999999999' }, Action: 'sts:AssumeRole' },
    { Sid: 'D', Effect: 'Deny', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole' },
  ]);
  assert.deepEqual(findingIds(r), [], 'reverse spelling is equally suppressed');
  assert.equal(r.graph.nodes.filter((n) => n.type === 'ExternalPrincipal').length, 1, 'still one account node');
  assert.equal(r.graph.edges.filter((e) => e.type === 'can-assume').length, 0);
});

test('IAM-806: trustFindingDenyState resolves root-ARN vs bare-account-id as full', () => {
  const model = modelFromText(pol([
    { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: { AWS: '999999999999' }, Action: 'sts:AssumeRole' },
  ])).model;
  const at = analyzeTrust(model);
  assert.equal(at.findings.length, 1, 'analyzeTrust is Deny-unaware: it still emits the Allow finding');
  assert.equal(trustFindingDenyState(at.findings[0], model), 'full', 'canonical account equivalence -> full');
});

test('IAM-806: an unconditional Deny that overlaps NO grant does not claim neutralization', () => {
  const model = modelFromText(pol([
    { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111111111111:root' }, Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: { AWS: 'arn:aws:iam::222222222222:root' }, Action: 'sts:AssumeRole' },
  ])).model;
  const sum = summarizeTrustDeny(model, analyzeTrust(model).findings);
  assert.equal(sum.present, true);
  assert.equal(sum.unmodeled, false, 'a non-overlapping unconditional Deny is fully modeled (not incomplete)');
  assert.doesNotMatch(String(sum.note), /neutralizes the overlapping/i, 'a Deny overlapping no grant must NOT claim to neutralize one');
  assert.match(String(sum.note), /overlaps an analyzed assume grant|additional principals/i, 'the note states the Deny restricts additional principals');

  // And the whole-pipeline finding for account 111 stands (the Deny of 222 is unrelated).
  const r = trust([
    { Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111111111111:root' }, Action: 'sts:AssumeRole' },
    { Effect: 'Deny', Principal: { AWS: 'arn:aws:iam::222222222222:root' }, Action: 'sts:AssumeRole' },
  ]);
  assert.ok(findingIds(r).includes('TRUST-CROSS-ACCOUNT'), 'the granted account 111 is still reported');
});
