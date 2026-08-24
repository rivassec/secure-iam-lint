// Acceptance Suite III regression gates (docs/acceptance-suite-3.md), the
// specific hostile cases hardened in the IAM-1001 iteration-2 review. Each test
// drives the REAL pipeline (validate() / analyze() / toMarkdown()) so the guard
// is enforced on every `node --test` run, not just by manual inspection.
//
//   Test 59 - case-insensitive duplicate condition keys are blocked
//   Test 74 - a wildcard modify grant overlapping a concrete assumable role
//             correlates into a role-takeover anchored on the concrete role
//   Test 75 - mutually exclusive principal-invariant conditions prevent the
//             takeover correlation (no false-critical)
//   Test 91 - a cross-account PassRole target carries the same-account-service
//             constraint caveat (never asserted as a fully-viable foreign path)
//   Test 96 - a sibling Null:{key:"false"} presence check suppresses the
//             ForAllValues "vacuously true when absent" caveat (vs case 41)
//   Test 97 - an empty ForAnyValue set is a structural never-match: no phantom
//             capability / wildcard-resource finding
//   Test 99 - attacker-controlled policy strings render INERT in the Markdown
//             export (no active link, no raw HTML), exact in the JSON export

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';

const ids = (r) => r.findings.map((f) => f.id);
const takeovers = (r) => r.findings.filter((f) => f.id === 'ROLE-TAKEOVER');

// --- Test 59 -----------------------------------------------------------------
test('Test 59: condition keys differing only in case are one duplicate key -> BLOCKED', () => {
  // Raw text (an object literal would collapse the duplicate before we see it).
  const text =
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",' +
    '"Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*","Condition":' +
    '{"StringEquals":{"aws:PrincipalOrgID":"o-one","AWS:PrincipalOrgId":"o-two"}}}]}';
  const r = validate(text);
  assert.equal(r.ok, false, 'must fail closed on a case-variant duplicate condition key');
  const dup = r.errors.find((e) => e.code === 'DUPLICATE_JSON_KEY');
  assert.ok(dup, 'DUPLICATE_JSON_KEY expected');
  assert.match(dup.path, /Statement\[0\]\.Condition\.StringEquals\./, 'names the condition-block path');
  // Both original spellings are preserved in the message.
  assert.match(dup.message, /aws:PrincipalOrgID/);
  assert.match(dup.message, /AWS:PrincipalOrgId/);
});

test('Test 59 control: two genuinely distinct condition keys are NOT flagged', () => {
  const text =
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",' +
    '"Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*","Condition":' +
    '{"StringEquals":{"aws:PrincipalOrgID":"o-one","aws:SourceVpc":"vpc-1"}}}]}';
  assert.equal(validate(text).ok, true, 'distinct keys must parse');
});

// --- Test 74 -----------------------------------------------------------------
test('Test 74: wildcard modify grant overlapping a concrete assumable role -> takeover on that role', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/deployment/*' },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/deployment/Prod' },
    ],
  };
  const t = takeovers(analyze(JSON.stringify(policy)));
  assert.equal(t.length, 1, 'exactly one takeover');
  assert.ok(['critical', 'high'].includes(t[0].severity), 'critical or high');
  // Anchored on the concrete intersecting role, NOT generalized to deployment/*.
  assert.deepEqual(t[0].resources, ['arn:aws:iam::123456789012:role/deployment/Prod']);
});

test('Test 74 control: a wildcard ASSUME scope is NOT expanded into a same-role takeover', () => {
  // The protected boundary (role-takeover.test.js test 142): modify concrete,
  // assume over *:role/* -> ASSUME-ROLE-EXPANSION, never a same-role takeover.
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/automation/DeploymentRole' },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::*:role/*' },
    ],
  };
  const r = analyze(JSON.stringify(policy));
  assert.equal(takeovers(r).length, 0, 'no same-role takeover from a wildcard assume scope');
  assert.ok(ids(r).includes('ASSUME-ROLE-EXPANSION'), 'the broad assume is still its own expansion finding');
});

// --- Test 75 -----------------------------------------------------------------
test('Test 75: mutually exclusive principal-account conditions across legs -> NO takeover', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '999900001111' } } },
    ],
  };
  const r = analyze(JSON.stringify(policy));
  assert.equal(takeovers(r).length, 0, 'unsatisfiable chain must not correlate into a critical takeover');
  // The standalone modification capabilities remain (reported, not hidden).
  assert.ok(ids(r).includes('PUT-INLINE-POLICY'), 'PutRolePolicy capability stands alone');
  assert.ok(ids(r).includes('TRUST-POLICY-MODIFY'), 'trust-modify capability stands alone');
});

test('Test 75 control: compatible (identical) conditions on all legs still correlate', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } } },
    ],
  };
  assert.equal(takeovers(analyze(JSON.stringify(policy))).length, 1, 'a satisfiable conditioned chain still fires');
});

// IAM-1003 iteration-2: aws:PrincipalArn's idiomatic exact-match operator is
// ArnEquals, NOT StringEquals. A contradiction written with ArnEquals must be
// caught exactly like the StringEquals form, else swapping the operator trivially
// evades the satisfiability guard and fabricates a false CRITICAL role-takeover
// (release-gate #3 / suite-3 test 75). Modify leg pins the caller to role/Alice,
// assume leg pins role/Bob; one principal has one ARN, so the chain is
// unsatisfiable and only the standalone capabilities survive.
test('Test 75 ArnEquals twin: mutually exclusive aws:PrincipalArn (ArnEquals) across legs -> NO takeover', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/Alice' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/Bob' } } },
    ],
  };
  const r = analyze(JSON.stringify(policy));
  assert.equal(takeovers(r).length, 0, 'ArnEquals-pinned contradiction must suppress the takeover just like StringEquals');
  assert.ok(ids(r).includes('PUT-INLINE-POLICY'), 'PutRolePolicy capability stands alone');
  assert.ok(ids(r).includes('TRUST-POLICY-MODIFY'), 'trust-modify capability stands alone');
});

test('Test 75 ArnEquals twin control: identical aws:PrincipalArn (ArnEquals) on all legs still correlates', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/Alice' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/Alice' } } },
    ],
  };
  assert.equal(takeovers(analyze(JSON.stringify(policy))).length, 1, 'a satisfiable ArnEquals-conditioned chain still fires');
});

// Lower-realism operator twin: StringEqualsIgnoreCase on aws:PrincipalAccount
// evades identically if only literal StringEquals is harvested.
test('Test 75 StringEqualsIgnoreCase twin: contradictory aws:PrincipalAccount across legs -> NO takeover', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEqualsIgnoreCase: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEqualsIgnoreCase: { 'aws:PrincipalAccount': '999900001111' } } },
    ],
  };
  assert.equal(takeovers(analyze(JSON.stringify(policy))).length, 0, 'StringEqualsIgnoreCase contradiction must also suppress the takeover');
});

// Conservatism guard: StringEqualsIgnoreCase is case-INSENSITIVE, so a case-only
// variance across legs is the SAME principal and must NOT be read as a
// contradiction (would suppress a real takeover - a P1 miss).
test('Test 75 case-insensitive control: StringEqualsIgnoreCase case-only variance still correlates', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEqualsIgnoreCase: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/Alice' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEqualsIgnoreCase: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/ALICE' } } },
    ],
  };
  assert.equal(takeovers(analyze(JSON.stringify(policy))).length, 1, 'case-insensitive same-principal must still fire the takeover');
});

// ArnLike (wildcard-admitting) is documented as NOT a hard pin: it must not
// fabricate a contradiction. Two ArnLike patterns leave the chain satisfiable.
test('Test 75 ArnLike stays excluded: wildcard-match operator creates no contradiction', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/team-a/*' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/team-b/*' } } },
    ],
  };
  assert.equal(takeovers(analyze(JSON.stringify(policy))).length, 1, 'ArnLike wildcard patterns are not hard pins; the takeover must still fire');
});

// IAM-1006 iteration-3 (F1): the exact-equality NEGATIONS must be modeled too.
// A modify leg pinning aws:PrincipalAccount == A and an assume leg requiring
// aws:PrincipalAccount != A can never be satisfied by one principal; ignoring the
// != constraint (harvesting only == pins) fabricates a false CRITICAL role-takeover
// no single principal can execute - the most idiomatic remaining evasion of the
// test-75 guard. Both leg positions and ArnNotEquals reproduce it.
test('Test 75 StringNotEquals twin: == A on modify / != A on assume -> NO takeover', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringNotEquals: { 'aws:PrincipalAccount': '123456789012' } } },
    ],
  };
  const r = analyze(JSON.stringify(policy));
  assert.equal(takeovers(r).length, 0, '== A / != A on the same key is unsatisfiable -> takeover suppressed');
  assert.ok(ids(r).includes('PUT-INLINE-POLICY'), 'standalone modify capability remains');
  assert.ok(ids(r).includes('TRUST-POLICY-MODIFY'), 'standalone modify capability remains');
});

test('Test 75 StringNotEquals twin (legs reversed): != A on modify / == A on assume -> NO takeover', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringNotEquals: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } } },
    ],
  };
  assert.equal(takeovers(analyze(JSON.stringify(policy))).length, 0, 'the contradiction is symmetric across leg positions');
});

test('Test 75 ArnNotEquals twin: ArnEquals Alice / ArnNotEquals Alice across legs -> NO takeover', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/Alice' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { ArnNotEquals: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/Alice' } } },
    ],
  };
  assert.equal(takeovers(analyze(JSON.stringify(policy))).length, 0, 'ArnNotEquals contradiction must suppress the takeover like the ArnEquals twin');
});

// Conservatism control: a NEGATED pin against a DIFFERENT value leaves the chain
// satisfiable (a principal that is == A also satisfies != B), so the takeover must
// still fire. Modeling negation must not over-suppress real takeovers.
test('Test 75 NotEquals control: == A modify / != B assume (different value) still correlates', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringNotEquals: { 'aws:PrincipalAccount': '999900001111' } } },
    ],
  };
  assert.equal(takeovers(analyze(JSON.stringify(policy))).length, 1, 'a principal in A satisfies == A and != B: takeover must still fire');
});

// Satisfiable control the critic named: BOTH legs use != A on the same key. A
// third principal (any account other than A) satisfies both, so the chain is
// satisfiable and the takeover must STILL fire (an all-negated key is not a
// contradiction). This guards against over-modeling negation into false negatives.
test('Test 75 NotEquals satisfiable control: != A on BOTH legs still correlates', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringNotEquals: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringNotEquals: { 'aws:PrincipalAccount': '123456789012' } } },
    ],
  };
  assert.equal(takeovers(analyze(JSON.stringify(policy))).length, 1, 'both legs != A share a satisfying principal: takeover must fire');
});

// IAM-1002 iteration-2: satisfiability is EXISTENTIAL across one statement per
// leg-group. Alternative statements within a group (here: two AssumeRole legs on
// the same role, one pinning account A, one pinning account B) must NOT be AND-ed
// together. A principal in account A satisfies grant-A + trust-A + assume-A - a
// real critical takeover - even though a *different* assume statement pins B.
// The earlier whole-set intersection let the B leg poison the chain and understated
// the blast radius (capped at the standalone HIGH modify capabilities), violating T8.
test('Test 75 alt-statements: one satisfiable assume leg fires the takeover despite an incompatible sibling assume leg', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'iam:PutRolePolicy', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'iam:UpdateAssumeRolePolicy', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '999900001111' } } },
    ],
  };
  assert.equal(takeovers(analyze(JSON.stringify(policy))).length, 1, 'a principal in account A executes grant-A + trust-A + assume-A: critical takeover must fire');
});

test('Test 75 alt-statements control: when EVERY assume alternative contradicts the modify legs, still no takeover', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '123456789012' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '999900001111' } } },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/DeploymentRole', Condition: { StringEquals: { 'aws:PrincipalAccount': '777700002222' } } },
    ],
  };
  const r = analyze(JSON.stringify(policy));
  assert.equal(takeovers(r).length, 0, 'no assume alternative is compatible with the modify legs -> no satisfiable chain');
  assert.ok(ids(r).includes('PUT-INLINE-POLICY'), 'standalone capabilities remain');
  assert.ok(ids(r).includes('TRUST-POLICY-MODIFY'), 'standalone capabilities remain');
});

// --- Test 91 -----------------------------------------------------------------
test('Test 91: cross-account PassRole target carries the same-account-service caveat', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::999900001111:role/ForeignRole' },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  };
  const f = analyze(JSON.stringify(policy)).findings.find((x) => x.id === 'PASSROLE-EC2');
  assert.ok(f, 'PASSROLE-EC2 present');
  assert.match(f.why, /SAME account/, 'warns the path is same-account-only');
  assert.match(f.why, /999900001111/, 'names the passed-role account');
});

test('Test 91 control: a bare "*" PassRole (no specific account) carries no account caveat', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  };
  const f = analyze(JSON.stringify(policy)).findings.find((x) => x.id === 'PASSROLE-EC2');
  assert.ok(f && !/SAME account/.test(f.why), 'no account-specific caveat when no account is pinned');
});

// --- Campaign D: principal validation (IAM-1004) -----------------------------

// Test 83: a Principal AWS ARRAY where one member carries a partial wildcard must
// identify the invalid member by its ARRAY INDEX and NOT silently drop it so only
// the valid member reads as a complete result. The invalid element is located at
// Principal.AWS[1]; coverage is flagged incomplete (never a clean conclusion).
test('Test 83: one invalid array member is located at index 1, not silently dropped', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Principal: { AWS: [
        'arn:aws:iam::123456789012:role/ValidRole',
        'arn:aws:iam::123456789012:role/invalid-*',
      ] },
      Action: 'sts:AssumeRole',
    }],
  };
  const r = analyze(JSON.stringify(policy));
  const inv = r.findings.find((f) => f.id === 'TRUST-INVALID-PRINCIPAL');
  assert.ok(inv, 'the poisoned array member fails closed to TRUST-INVALID-PRINCIPAL');
  const paths = (inv.invalidPrincipalPaths || []).map((p) => p.path);
  assert.deepEqual(paths, ['Statement[0].Principal.AWS[1]'], 'array index 1 is identified precisely');
  assert.match(inv.why, /Principal\.AWS\[1\]/, 'the finding prose names the array index');
  // The valid member is still analyzed, but the result is explicitly incomplete -
  // it is NOT presented as a complete clean conclusion for only ValidRole.
  assert.equal(r.coverage.summary.incomplete, true, 'coverage flagged incomplete');
  assert.ok(r.coverage.summary.codes.includes('INVALID_PRINCIPAL_WILDCARD_ARN'), 'coverage code present');
  const elem = r.coverage.summary.unsupportedElements.find((e) => e.code === 'INVALID_PRINCIPAL_WILDCARD_ARN');
  assert.equal(elem.path, 'Statement[0].Principal.AWS[1]', 'coverage element carries the exact path');
});

// Test 84: a bare 12-digit account principal is a VALID whole-account cross-account
// delegation - never misclassified as an invalid ARN.
test('Test 84: short-form 12-digit account principal stays valid cross-account delegation', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Principal: { AWS: '111122223333' }, Action: 'sts:AssumeRole' }],
  };
  const r = analyze(JSON.stringify(policy));
  const ids = r.findings.map((f) => f.id);
  assert.ok(ids.includes('TRUST-CROSS-ACCOUNT'), 'valid cross-account delegation');
  assert.ok(!ids.includes('TRUST-INVALID-PRINCIPAL'), 'a 12-digit account id is not an invalid ARN');
  assert.ok(!r.coverage.summary.codes.includes('INVALID_PRINCIPAL_WILDCARD_ARN'), 'no wildcard-ARN coverage warning');
});

// Test 85: a wildcard in an aws:PrincipalArn CONDITION value is a valid construct
// and must never be mis-flagged as a partial Principal-element wildcard. The
// document is resource-based (deferred family), so it fails closed - but not via
// the invalid-principal path.
test('Test 85: aws:PrincipalArn condition wildcard is not mis-flagged as an invalid Principal', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Principal: '*',
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::deployments/*',
      Condition: { ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/deployment/*' } },
    }],
  };
  const r = analyze(JSON.stringify(policy));
  assert.ok(!r.findings.some((f) => f.id === 'TRUST-INVALID-PRINCIPAL'), 'condition wildcard is not an invalid principal');
  assert.ok(!r.coverage.summary.codes.includes('INVALID_PRINCIPAL_WILDCARD_ARN'), 'no invalid-principal code');
  assert.equal(r.coverage.blocked, true, 'resource family is deferred -> fail closed');
  assert.ok((r.coverage.blockingCodes || []).some((b) => b.code === 'UNSUPPORTED_POLICY_FAMILY'), 'blocked as unsupported family');
});

// --- Test 97 -----------------------------------------------------------------
test('Test 97: empty ForAnyValue set -> ineffective statement, no capability/wildcard finding', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 'ec2:CreateTags', Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'aws:TagKeys': [] } } }],
  };
  const r = analyze(JSON.stringify(policy));
  assert.ok(!ids(r).includes('WILDCARD-RESOURCE'), 'no wildcard-resource finding for a never-match statement');
  assert.equal(r.findings.length, 0, 'a never-match statement grants nothing');
});

test('Test 97 control: a non-empty ForAnyValue set is evaluated normally', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 'ec2:CreateTags', Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'aws:TagKeys': ['environment'] } } }],
  };
  assert.ok(ids(analyze(JSON.stringify(policy))).includes('WILDCARD-RESOURCE'), 'a real value set still evaluates');
});

test('Test 97 control: an empty ForAllValues set is NOT suppressed (vacuously satisfiable)', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 'ec2:CreateTags', Resource: '*', Condition: { 'ForAllValues:StringEquals': { 'aws:TagKeys': [] } } }],
  };
  assert.ok(analyze(JSON.stringify(policy)).findings.length > 0, 'ForAllValues-empty is satisfiable, must not be dropped');
});

// --- Test 96 -----------------------------------------------------------------
// A sibling Null:{aws:TagKeys:"false"} presence check REQUIRES the key to be
// present, so a ForAllValues set-operator on the same key no longer has its
// "vacuously true when the key is absent" footgun. The absent-key caveat that
// case 41 (no Null) emits must be SUPPRESSED here (suite-3 test 96), while the
// guardrail is still NOT credited (fail-safe). The key is not modelled by v1, so
// the ForAllValues entry stays context-required either way.
const favEntry = (r) => {
  for (const f of r.findings) {
    const cc = f.conditionClassification;
    if (!cc || !Array.isArray(cc.entries)) continue;
    const e = cc.entries.find((x) => x.setOperator === 'ForAllValues' && x.key === 'aws:TagKeys');
    if (e) return e;
  }
  return null;
};

test('Test 96: a sibling Null presence check suppresses the ForAllValues absent-key caveat', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow', Action: 'ec2:CreateTags', Resource: '*',
      Condition: {
        'ForAllValues:StringEquals': { 'aws:TagKeys': ['environment', 'cost-center'] },
        Null: { 'aws:TagKeys': 'false' },
      },
    }],
  };
  const r = analyze(JSON.stringify(policy));
  const e = favEntry(r);
  assert.ok(e, 'the ForAllValues aws:TagKeys entry is classified');
  assert.equal(e.credited, false, 'the guardrail is still not credited (fail-safe)');
  assert.doesNotMatch(e.note, /may not constrain a request that omits the key/,
    'the false absent-key caveat must be suppressed when a sibling presence check requires the key');
  assert.match(e.note, /presence check/i, 'the presence check that forecloses the omitted-key path is annotated');
  // The suppression must reach the Markdown export (report.js renders e.note).
  const md = toMarkdown(r);
  assert.ok(!md.includes('may not constrain a request that omits the key'),
    'the suppressed caveat must not appear in the export for test 96');
});

test('Test 41 control: ForAllValues WITHOUT a sibling presence check still warns about the absent key', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow', Action: 'ec2:CreateTags', Resource: '*',
      Condition: { 'ForAllValues:StringEquals': { 'aws:TagKeys': ['environment', 'cost-center'] } },
    }],
  };
  const r = analyze(JSON.stringify(policy));
  const e = favEntry(r);
  assert.ok(e, 'the ForAllValues aws:TagKeys entry is classified');
  assert.equal(e.credited, false, 'still not credited');
  assert.match(e.note, /may not constrain a request that omits the key/,
    'without a presence check the absent-key caveat is retained (case 41)');
});

// --- Test 99 -----------------------------------------------------------------
test('Test 99: hostile policy strings render INERT in the Markdown export', () => {
  // The witnesses must reach the findings section, so use a firing policy.
  const policy = {
    Version: '2012-10-17',
    Statement: [{
      Sid: '[click](javascript:alert(1))',
      Effect: 'Allow',
      Action: '*',
      Resource: [
        '*',
        'arn:aws:s3:::example/<img src=x onerror=alert(1)>',
        'arn:aws:s3:::example/[click](javascript:alert(1))',
        'arn:aws:s3:::example/```html<script>alert(1)</script>```',
        // Bare-URL / "www." autolink witnesses: GFM (GitHub), CommonMark-with-
        // autolink, and pandoc --autolink_bare_uris turn a bare scheme token into
        // an ACTIVE clickable link even though there is no []() / <> link syntax.
        // mdEscape does not escape ':' or '/', so these must be neutralized by
        // breaking the scheme token (IAM-1002 report.js breakAutolinks).
        'https://evil.example.com/leak',
        'http://evil.example.com/x',
        'ftp://evil.example.com/y',
        'www.evil.com/track',
      ],
    }],
  };
  const r = analyze(JSON.stringify(policy));
  assert.ok(r.findings.length > 0, 'the payload reaches the findings section');
  const md = toMarkdown(r);

  // No ACTIVE link: no unescaped "](" bridging text and destination, and no
  // "](javascript:" anywhere.
  assert.ok(!/[^\\]\]\(/.test(md), 'no unescaped ]( link syntax survives');
  assert.ok(!md.includes(']('.concat('javascript:')), 'no javascript: link');
  // No RAW HTML: every "<" is backslash-escaped, so no unescaped tag can form.
  assert.ok(!/(^|[^\\])</.test(md), 'no unescaped "<" survives (no raw HTML tag)');
  assert.ok(md.includes('\\<img'), 'the payload is present, but escaped');

  // No BARE-URL autolink: the attacker-controlled scheme tokens must not survive
  // as a contiguous "https://evil..." / "www.evil..." that a Markdown renderer
  // would autolink. The catalog docRef (a tool-authored AWS-docs URL) is emitted
  // unescaped and stays clickable, so we assert on the attacker host specifically.
  assert.ok(!md.includes('https://evil'), 'no contiguous https:// attacker autolink');
  assert.ok(!md.includes('http://evil'), 'no contiguous http:// attacker autolink');
  assert.ok(!md.includes('ftp://evil'), 'no contiguous ftp:// attacker autolink');
  assert.ok(!md.includes('www.evil'), 'no contiguous www. attacker autolink');
  // The value is still PRESENT as readable inert text (broken, not dropped).
  assert.ok(md.includes('evil.example.com/leak'), 'the URL value is preserved as inert text');
  // The legitimate, tool-authored docRef URL remains an active link.
  assert.ok(/- Reference: https:\/\/docs\.aws\.amazon\.com/.test(md), 'catalog docRef stays clickable');

  // JSON export preserves the exact hostile strings verbatim.
  const parsed = JSON.parse(toJSON(r));
  const res = parsed.findings.flatMap((f) => (Array.isArray(f.resources) ? f.resources : []));
  assert.ok(res.includes('arn:aws:s3:::example/<img src=x onerror=alert(1)>'), 'JSON keeps the exact string');
  assert.ok(res.includes('https://evil.example.com/leak'), 'JSON keeps the exact bare URL');
});

// --- Test 95 (F2): per-action resource evaluation --------------------------
// IAM-1006 iteration-3: a statement mixing a required-wildcard enumeration action
// (iam:ListRoles, which has no resource-level scoping) with a dangerous one
// (iam:PassRole) on Resource "*" must NOT present iam:ListRoles as a remediable
// wildcard. Only iam:PassRole belongs in the WILDCARD-RESOURCE finding's actions;
// recommending "scope the ARN" for iam:ListRoles is impossible remediation.
test('Test 95: mixed ListRoles+PassRole -> WILDCARD-RESOURCE lists only iam:PassRole', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: ['iam:ListRoles', 'iam:PassRole'], Resource: '*' }],
  };
  const r = analyze(JSON.stringify(policy));
  const wild = r.findings.find((f) => f.id === 'WILDCARD-RESOURCE');
  assert.ok(wild, 'the dangerous sibling still produces a WILDCARD-RESOURCE finding');
  assert.ok(wild.actions.includes('iam:PassRole'), 'iam:PassRole is remediable and present');
  assert.ok(!wild.actions.includes('iam:ListRoles'), 'iam:ListRoles (required wildcard) must be absent from the remediable finding');
});

// Regression controls 92/93/94: a required-wildcard enumeration action ALONE on
// Resource "*" must produce NO remediable WILDCARD-RESOURCE finding (no impossible
// ARN remediation).
for (const [action, label] of [
  ['iam:ListRoles', '92'],
  ['ec2:DescribeInstances', '93'],
  ['s3:ListAllMyBuckets', '94'],
]) {
  test(`Test ${label}: ${action} on * -> no remediable WILDCARD-RESOURCE finding`, () => {
    const policy = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: action, Resource: '*' }] };
    const r = analyze(JSON.stringify(policy));
    assert.ok(!ids(r).includes('WILDCARD-RESOURCE'), `${action} must not raise a remediable wildcard finding`);
  });
}

// --- Test 50 (F3): action/resource-type mismatch coverage warning ----------
// IAM-1006 iteration-3: s3:GetObject (an object action) scoped to a bucket-only
// ARN matches no object request. The engine must not report a confirmed
// object-read, and must not report a silent complete/empty analysis: it surfaces
// a non-blocking coverage warning (incomplete + ACTION_RESOURCE_TYPE_MISMATCH)
// carrying bucket-vs-object remediation.
test('Test 50: object action on a bucket-only ARN -> mismatch coverage warning, no object-read', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{ Sid: 'IncorrectObjectReadScope', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::documents' }],
  };
  const r = analyze(JSON.stringify(policy));
  // No confirmed object-read capability.
  assert.ok(!ids(r).includes('DATA-EXFIL'), 'no confirmed bulk object-read');
  assert.ok(!ids(r).includes('DATA-READ'), 'no confirmed object-read capability');
  // Coverage is incomplete with the stable mismatch code (not a silent complete/empty).
  const s = r.coverage.summary;
  assert.equal(s.incomplete, true, 'the mismatch must flip coverage to incomplete');
  assert.ok(s.codes.includes('ACTION_RESOURCE_TYPE_MISMATCH'), 'stable mismatch code present');
  const m = s.actionResourceMismatches[0];
  assert.ok(m, 'a mismatch entry is present');
  assert.deepEqual(m.actions, ['s3:GetObject'], 'the object action is named');
  assert.deepEqual(m.resources, ['arn:aws:s3:::documents'], 'the bucket-only ARN is named');
  // Remediation distinguishes bucket actions from object actions.
  assert.match(m.remediation, /object actions/);
  assert.match(m.remediation, /bucket actions/);
  assert.match(m.remediation, /arn:aws:s3:::documents\/\*/);
});

// Control: an object action correctly scoped to an object ARN raises no mismatch.
test('Test 50 control: object action on an object ARN -> no mismatch warning', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 's3:ListBucket'], Resource: ['arn:aws:s3:::documents', 'arn:aws:s3:::documents/*'] }],
  };
  const s = analyze(JSON.stringify(policy)).coverage.summary;
  assert.equal(s.incomplete, false, 'a correctly-scoped object read is a complete analysis');
  assert.ok(!s.codes.includes('ACTION_RESOURCE_TYPE_MISMATCH'), 'no mismatch code');
});
