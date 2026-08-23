// IAM-506: condition classification v1.
// Runs on node's built-in runner: `node --test`.
//
// The classifier describes how a Condition entry READS - it "appears to narrow"
// (constraint), "appears to select" (selector), "appears to broaden" (expansion),
// or is "context-required" (unmodelled / unresolvable) - and it must NEVER claim
// a runtime AWS allow/deny, NEVER credit an unknown key or a footgun operator as
// protective, and NEVER lower a finding's risk to "safe" on an unknown condition.
//
// These are unit tests over the pure classifier plus integration tests through
// analyze() (coverage wiring + per-finding evidence + export carriage).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  classifyConditionEntry,
  classifyConditions,
  parseOperator,
  unsupportedConditionKeys,
  CONDITION_CLASS,
} from '../../../content/tools/iam-blast-radius/engine/conditions.js';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';

const here = dirname(fileURLToPath(import.meta.url));
const ccDir = join(here, '..', 'fixtures', 'condition-class');

// ---------------------------------------------------------------------------
// parseOperator: set qualifier + IfExists stripping.
// ---------------------------------------------------------------------------

test('parseOperator splits set qualifier, IfExists, and the base operator', () => {
  assert.deepEqual(parseOperator('StringEquals'), { base: 'stringequals', setOperator: null, ifExists: false });
  assert.deepEqual(parseOperator('StringEqualsIfExists'), { base: 'stringequals', setOperator: null, ifExists: true });
  assert.deepEqual(parseOperator('ForAllValues:StringEquals'), { base: 'stringequals', setOperator: 'ForAllValues', ifExists: false });
  assert.deepEqual(parseOperator('ForAnyValue:StringLikeIfExists'), { base: 'stringlike', setOperator: 'ForAnyValue', ifExists: true });
  assert.deepEqual(parseOperator('Null'), { base: 'null', setOperator: null, ifExists: false });
});

// ---------------------------------------------------------------------------
// Per-key classification: each covered key with a plain narrowing operator.
// ---------------------------------------------------------------------------

test('constraint keys with a plain operator appear to narrow and ARE credited', () => {
  for (const [op, key, val] of [
    ['Bool', 'aws:MultiFactorAuthPresent', 'true'],
    ['IpAddress', 'aws:SourceIp', '203.0.113.0/24'],
    ['StringEquals', 'aws:SourceVpc', 'vpc-123'],
    ['StringEquals', 'aws:SourceVpce', 'vpce-123'],
    ['StringEquals', 'aws:PrincipalOrgID', 'o-abcd'],
    ['StringEquals', 'aws:RequestedRegion', 'us-east-1'],
  ]) {
    const e = classifyConditionEntry(op, key, val);
    assert.equal(e.class, CONDITION_CLASS.CONSTRAINT, `${key} should be a constraint`);
    assert.equal(e.appears, 'narrows', `${key} should appear to narrow`);
    assert.equal(e.credited, true, `${key} should be credited as a guardrail-shaped constraint`);
    assert.equal(e.known, true);
    // Capability-safe wording: never a runtime verdict.
    assert.doesNotMatch(e.note, /\b(will|is denied|is allowed|denied|allowed)\b/i, `${key} note must not claim a runtime verdict`);
  }
});

test('selector keys appear to select and are NOT credited (scope, not a guardrail)', () => {
  for (const [op, key, val] of [
    ['StringEquals', 'iam:PassedToService', 'ec2.amazonaws.com'],
    ['StringEquals', 'kms:ViaService', 's3.us-east-1.amazonaws.com'],
    ['ArnEquals', 'iam:AssociatedResourceArn', 'arn:aws:ec2:us-east-1:111122223333:instance/*'],
  ]) {
    const e = classifyConditionEntry(op, key, val);
    assert.equal(e.class, CONDITION_CLASS.SELECTOR, `${key} should be a selector`);
    assert.equal(e.appears, 'selects');
    assert.equal(e.credited, false, `${key} must not be credited as protective`);
  }
});

// ---------------------------------------------------------------------------
// Negated / wildcard / missing-key: broadening, never credited.
// ---------------------------------------------------------------------------

test('a negated operator on a constraint key broadens (expansion), never credited', () => {
  const e = classifyConditionEntry('StringNotEquals', 'aws:SourceIp', '203.0.113.0/24');
  assert.equal(e.class, CONDITION_CLASS.EXPANSION);
  assert.equal(e.appears, 'broadens');
  assert.equal(e.negated, true);
  assert.equal(e.credited, false);
});

test('an all-addresses aws:SourceIp range is NOT a credited constraint (IAM-806 iter2: matches trust.js isAllAddressIp)', () => {
  // trust.js refuses these values via isAllAddressIp and keeps a cross-account
  // trust HIGH with "no confused-deputy constraint"; conditions.js must agree in
  // its evidence panel (expansion/uncredited) so the two never contradict - a
  // vacuous 0.0.0.0/0 shown as a credited guardrail would falsely reassure a
  // reviewer of a wide-open trust (threat-model T8).
  for (const val of ['0.0.0.0/0', '0/0', '::/0', '::0/0', '::0', '::']) {
    const e = classifyConditionEntry('IpAddress', 'aws:SourceIp', val);
    assert.equal(e.class, CONDITION_CLASS.EXPANSION, `${val} must classify as expansion`);
    assert.equal(e.appears, 'broadens', `${val} must appear to broaden`);
    assert.equal(e.credited, false, `${val} must never be credited as a Source-IP guardrail`);
    assert.doesNotMatch(e.note, /\b(will|is denied|is allowed|denied|allowed)\b/i, `${val} note must not claim a runtime verdict`);
  }
  // A genuine bounded range still narrows and IS credited (non-regression).
  const bounded = classifyConditionEntry('IpAddress', 'aws:SourceIp', '203.0.113.0/24');
  assert.equal(bounded.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(bounded.credited, true);
  // The all-addresses guard applies to the whole value set: a co-listed all-
  // addresses element defeats a pinned one (IAM ORs an operator+key's values).
  const mixed = classifyConditionEntry('IpAddress', 'aws:SourceIp', ['203.0.113.0/24', '0.0.0.0/0']);
  assert.equal(mixed.class, CONDITION_CLASS.EXPANSION);
  assert.equal(mixed.credited, false);
});

test('a negated operator on a selector selects by exclusion (denylist), never credited', () => {
  const e = classifyConditionEntry('StringNotEquals', 'iam:PassedToService', 'lambda.amazonaws.com');
  assert.equal(e.class, CONDITION_CLASS.SELECTOR);
  assert.equal(e.negated, true);
  assert.equal(e.credited, false);
  assert.match(e.note, /exclusion|denylist/i);
});

test('a wildcard value does not constrain (expansion), never credited', () => {
  const e = classifyConditionEntry('StringLike', 'aws:SourceVpce', '*');
  assert.equal(e.class, CONDITION_CLASS.EXPANSION);
  assert.equal(e.wildcardValue, true);
  assert.equal(e.credited, false);
});

test('Null true = missing-key broadening; Null false = presence-only constraint (uncredited)', () => {
  const absent = classifyConditionEntry('Null', 'aws:SourceVpc', 'true');
  assert.equal(absent.class, CONDITION_CLASS.EXPANSION);
  assert.equal(absent.nullTest, 'absent');
  assert.equal(absent.credited, false);

  const present = classifyConditionEntry('Null', 'aws:SourceVpc', 'false');
  assert.equal(present.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(present.nullTest, 'present');
  assert.equal(present.credited, false, 'presence-only does not constrain the value');
});

test('Bool false on MFA broadens (MFA not required); Bool true narrows', () => {
  const off = classifyConditionEntry('Bool', 'aws:MultiFactorAuthPresent', 'false');
  assert.equal(off.class, CONDITION_CLASS.EXPANSION);
  assert.equal(off.credited, false);
  const on = classifyConditionEntry('Bool', 'aws:MultiFactorAuthPresent', 'true');
  assert.equal(on.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(on.credited, true);
});

test('...IfExists and ForAllValues weaken a would-be constraint (uncredited, noted)', () => {
  const ifx = classifyConditionEntry('BoolIfExists', 'aws:MultiFactorAuthPresent', 'true');
  assert.equal(ifx.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(ifx.ifExists, true);
  assert.equal(ifx.credited, false);
  assert.match(ifx.note, /IfExists/);

  const fav = classifyConditionEntry('ForAllValues:StringEquals', 'aws:RequestedRegion', 'us-east-1');
  assert.equal(fav.setOperator, 'ForAllValues');
  assert.equal(fav.credited, false);
  assert.match(fav.note, /ForAllValues matches when the key is absent/);
});

// ---------------------------------------------------------------------------
// Unknown keys: context-required, NEVER credited.
// ---------------------------------------------------------------------------

test('an unknown condition key is context-required and never credited', () => {
  const e = classifyConditionEntry('StringEquals', 's3:x-amz-acl', 'private');
  assert.equal(e.class, CONDITION_CLASS.CONTEXT_REQUIRED);
  assert.equal(e.appears, 'context-required');
  assert.equal(e.known, false);
  assert.equal(e.credited, false);
});

// ---------------------------------------------------------------------------
// Trust condition keys + polarity (IAM-803, docs/trust-policy-semantics.md 4).
// The classifier now MODELS the trust keys so a role-trust policy's conditions
// are understood (not reported unsupported), with correct polarity: a positive
// value-match reads as a constraint; a NEGATED operator flips to an expansion;
// federation aud is a constraint; a wildcarded federation subject is broad and
// is NOT credited as a dependable guardrail. Classification is text-only.
// ---------------------------------------------------------------------------

test('sts:ExternalId (positive match) is a modeled confused-deputy constraint, credited', () => {
  const e = classifyConditionEntry('StringEquals', 'sts:ExternalId', 'customer-7f6af74e');
  assert.equal(e.known, true, 'ExternalId is modeled, not context-required');
  assert.equal(e.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(e.role, 'confused-deputy');
  assert.equal(e.credited, true);
  // Never described as authentication or a secret; only its presence/polarity.
  assert.doesNotMatch(e.note, /secret|authentication|credential/i);
});

test('aws:SourceArn / aws:SourceAccount are modeled confused-deputy constraints', () => {
  const arn = classifyConditionEntry('ArnLike', 'aws:SourceArn', 'arn:aws:cloudtrail:us-east-1:111122223333:trail/org');
  assert.equal(arn.known, true);
  assert.equal(arn.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(arn.credited, true);
  const acct = classifyConditionEntry('StringEquals', 'aws:SourceAccount', '111122223333');
  assert.equal(acct.known, true);
  assert.equal(acct.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(acct.credited, true);
});

test('a NEGATED trust constraint flips to an expansion (broadens, never credited)', () => {
  // The crux polarity case: StringNotEquals aws:PrincipalOrgID reads as an
  // EXPANSION (principals OUTSIDE the org), not a protective org restriction.
  const org = classifyConditionEntry('StringNotEquals', 'aws:PrincipalOrgID', 'o-exampleorgid');
  assert.equal(org.class, CONDITION_CLASS.EXPANSION);
  assert.equal(org.appears, 'broadens');
  assert.equal(org.credited, false);
  assert.equal(org.negated, true);
  // A positive aws:PrincipalOrgID is the constraint polarity.
  const orgPos = classifyConditionEntry('StringEquals', 'aws:PrincipalOrgID', 'o-exampleorgid');
  assert.equal(orgPos.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(orgPos.credited, true);
  // A negated confused-deputy key broadens too.
  const arnNeg = classifyConditionEntry('ArnNotEquals', 'aws:SourceArn', 'arn:aws:s3:::x');
  assert.equal(arnNeg.class, CONDITION_CLASS.EXPANSION);
  assert.equal(arnNeg.credited, false);
});

test('aws:PrincipalArn / aws:PrincipalAccount are modeled principal-scoping constraints', () => {
  const parn = classifyConditionEntry('StringEquals', 'aws:PrincipalArn', 'arn:aws:iam::111122223333:role/App');
  assert.equal(parn.known, true);
  assert.equal(parn.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(parn.credited, true);
  const pacct = classifyConditionEntry('StringEquals', 'aws:PrincipalAccount', '111122223333');
  assert.equal(pacct.known, true);
  assert.equal(pacct.class, CONDITION_CLASS.CONSTRAINT);
});

test('federated aud is a modeled constraint; a wildcarded sub is broad and NOT credited', () => {
  const aud = classifyConditionEntry('StringEquals', 'token.actions.githubusercontent.com:aud', 'sts.amazonaws.com');
  assert.equal(aud.known, true, 'OIDC aud is understood, not context-required');
  assert.equal(aud.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(aud.credited, true);
  const samlAud = classifyConditionEntry('StringEquals', 'saml:aud', 'https://signin.aws.amazon.com/saml');
  assert.equal(samlAud.known, true);
  assert.equal(samlAud.class, CONDITION_CLASS.CONSTRAINT);

  const subBroad = classifyConditionEntry('StringLike', 'token.actions.githubusercontent.com:sub', 'repo:example-org/*');
  assert.equal(subBroad.known, true, 'OIDC sub is understood, not context-required');
  assert.equal(subBroad.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(subBroad.credited, false, 'an org-wide wildcarded subject is not a dependable guardrail');
  assert.match(subBroad.note, /broad/i);

  const subTight = classifyConditionEntry('StringEquals', 'token.actions.githubusercontent.com:sub', 'repo:example-org/repo:ref:refs/heads/main');
  assert.equal(subTight.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(subTight.credited, true, 'a repo + ref bound subject is a dependable scope');
});

test('IAM-803 iter2: a match-everything glob on a key-aware constraint key is NOT credited', () => {
  // hasWildcardValue only rejected the exact "*", so key-aware match-everything
  // globs (o-*, arn:aws:*:*:*:*) were credited=true in the evidence panel even
  // though trust.js correctly keeps such a trust HIGH (valueNarrowsKey rejects the
  // glob). conditions.js now applies the SAME key-aware narrowing test, so
  // conditionClassification.credited agrees with the trust severity.
  const orgGlob = classifyConditionEntry('StringLike', 'aws:PrincipalOrgID', 'o-*');
  assert.equal(orgGlob.known, true);
  assert.equal(orgGlob.class, CONDITION_CLASS.EXPANSION, 'o-* matches every org -> does not narrow');
  assert.equal(orgGlob.credited, false, 'a match-every-org glob is not a credited guardrail');

  const arnGlob = classifyConditionEntry('ArnLike', 'aws:SourceArn', 'arn:aws:*:*:*:*');
  assert.equal(arnGlob.class, CONDITION_CLASS.EXPANSION, 'arn:aws:*:*:*:* pins nothing -> does not narrow');
  assert.equal(arnGlob.credited, false);

  const acctGlob = classifyConditionEntry('StringLike', 'aws:SourceAccount', '1*');
  assert.equal(acctGlob.credited, false, 'a wildcarded account id is never pinned');
});

test('IAM-803 iter2 control: a genuinely-narrowing globbed ARN (account pinned) IS still credited', () => {
  // The fix must not over-correct: an ARN whose account segment carries a concrete
  // id really narrows and stays a credited constraint.
  const pinned = classifyConditionEntry('ArnLike', 'aws:SourceArn', 'arn:aws:cloudtrail:*:111122223333:trail/*');
  assert.equal(pinned.class, CONDITION_CLASS.CONSTRAINT);
  assert.equal(pinned.credited, true, 'an account-pinned ARN glob is a real narrowing constraint');
});

test('IAM-804 iter3: a bare resource-TYPE-keyword ARN (role/*, secret:*) is NOT credited', () => {
  // conditions.js arnValueNarrows diverged from trust.js: it stripped [*?/] and
  // credited any surviving literal, so a match-everything ARN whose only literal is
  // a leading resource-TYPE keyword (arn:aws:iam::*:role/* = every role in every
  // account) classified as a credited confused-deputy constraint, contradicting the
  // HIGH severity trust.js correctly assigns (wrong-provenance over-credit). The
  // two arnValueNarrows must agree: such an ARN does NOT narrow.
  const roleGlob = classifyConditionEntry('ArnLike', 'aws:SourceArn', 'arn:aws:iam::*:role/*');
  assert.equal(roleGlob.known, true);
  assert.equal(roleGlob.class, CONDITION_CLASS.EXPANSION, 'role/* matches every role in every account -> does not narrow');
  assert.equal(roleGlob.credited, false, 'a match-everything resource-type-keyword ARN is not a guardrail');
  assert.equal(roleGlob.appears, 'broadens');

  // The same class of value on aws:PrincipalArn (D-ARN-3) and other resource-type
  // keywords must also be uncredited, matching trust.js on every such value.
  for (const [key, val] of [
    ['aws:PrincipalArn', 'arn:aws:iam::*:user/*'],
    ['aws:SourceArn', 'arn:aws:secretsmanager:*:*:secret:*'],
    ['aws:SourceArn', 'arn:aws:sns:*:*:topic:*'],
    ['aws:SourceArn', 'arn:aws:dynamodb:*:*:table/*'],
    ['aws:SourceArn', 'arn:aws:logs:*:*:log-group:*'],
  ]) {
    const e = classifyConditionEntry('ArnLike', key, val);
    assert.equal(e.credited, false, `${key} ${val} bounds nothing -> not credited`);
    assert.equal(e.class, CONDITION_CLASS.EXPANSION, `${key} ${val} -> expansion`);
  }

  // Control: a concrete resource IDENTIFIER after the wildcard account still
  // narrows (the fix must not over-correct).
  const concrete = classifyConditionEntry('ArnLike', 'aws:SourceArn', 'arn:aws:s3:::specific-bucket/*');
  assert.equal(concrete.class, CONDITION_CLASS.CONSTRAINT, 'a concrete resource id narrows');
  assert.equal(concrete.credited, true);
});

test('IAM-804 iter4: an all-glob default-path value (sts:ExternalId "?*", "*?", "?") is NOT credited', () => {
  // The default-arm narrowing test rejected only '' and pure-'*', so a
  // match-everything glob that is not the bare "*" - sts:ExternalId "?*" matches
  // every non-empty string, functionally identical to "*" - was credited=true here
  // while trust.js (whose default arm now also rejects it) keeps the trust HIGH.
  // The two default arms must agree: an all-glob value narrows NOTHING.
  for (const v of ['?*', '*?', '?', '**?', '*?*']) {
    const e = classifyConditionEntry('StringLike', 'sts:ExternalId', v);
    assert.equal(e.known, true);
    assert.equal(e.class, CONDITION_CLASS.EXPANSION, `"${v}" matches the whole value space -> does not narrow`);
    assert.equal(e.credited, false, `an all-glob ExternalId "${v}" is not a credited guardrail`);
  }
});

test('IAM-804 iter4 control: a literal-carrying ExternalId glob still narrows and IS credited', () => {
  // The fix must reject only ALL-glob values; a partial ExternalId carrying a
  // literal still forces the caller to present that correlation substring.
  for (const v of ['corr-?', 'my-ext-id-*', 'prefix?suffix']) {
    const e = classifyConditionEntry('StringLike', 'sts:ExternalId', v);
    assert.equal(e.class, CONDITION_CLASS.CONSTRAINT, `"${v}" carries a literal -> narrows`);
    assert.equal(e.credited, true, `a literal-carrying ExternalId "${v}" is a credited constraint`);
  }
});

test('IAM-804 iter5: a non-string operator (Date/Numeric) on a value-scoping trust key is NOT credited', () => {
  // conditions.js credited any non-negated/non-wildcard operator on a known
  // constraint key, so DateGreaterThan sts:ExternalId (a date comparison that does
  // NOT pin an external-id correlation value) classified as a credited confused-
  // deputy guardrail, contradicting the HIGH severity trust.js correctly keeps
  // (trust.js requires a positive string/ARN operator to scope these keys). The two
  // must agree: only a positive string/ARN match credits a value-scoping trust key.
  const dateExt = classifyConditionEntry('DateGreaterThan', 'sts:ExternalId', '2020-01-01T00:00:00Z');
  assert.equal(dateExt.known, true);
  assert.equal(dateExt.class, CONDITION_CLASS.CONSTRAINT, 'the key is a known scoping key');
  assert.equal(dateExt.credited, false, 'a Date operator does not scope ExternalId by value -> not credited');
  assert.match(dateExt.note, /not a positive string\/ARN match/i);

  for (const [op, key, val] of [
    ['NumericEquals', 'aws:SourceAccount', '111122223333'],
    ['DateGreaterThan', 'aws:PrincipalOrgID', 'o-exampleorgid'],
    ['DateLessThan', 'aws:SourceArn', 'arn:aws:cloudtrail:us-east-1:111122223333:trail/org'],
    ['NumericLessThan', 'aws:PrincipalArn', 'arn:aws:iam::111122223333:role/App'],
    ['NumericEquals', 'aws:PrincipalAccount', '111122223333'],
  ]) {
    const e = classifyConditionEntry(op, key, val);
    assert.equal(e.credited, false, `${op} on ${key} must not be credited as a value scope`);
  }

  // Control: the SAME keys/values under a positive string/ARN operator ARE credited
  // (the gate rejects only the wrong-operator case, never over-corrects a real one).
  for (const [op, key, val] of [
    ['StringEquals', 'sts:ExternalId', 'customer-7f6af74e'],
    ['StringEquals', 'aws:SourceAccount', '111122223333'],
    ['StringEquals', 'aws:PrincipalOrgID', 'o-exampleorgid'],
    ['ArnLike', 'aws:SourceArn', 'arn:aws:cloudtrail:us-east-1:111122223333:trail/org'],
    ['StringEquals', 'aws:PrincipalArn', 'arn:aws:iam::111122223333:role/App'],
  ]) {
    const e = classifyConditionEntry(op, key, val);
    assert.equal(e.credited, true, `${op} on ${key} is a positive value scope -> credited`);
  }
});

test('an unknown TRUST-shaped condition key is still context-required and surfaced', () => {
  // Only aud/sub federation claims and the enumerated keys are modeled; any other
  // sts:/trust-adjacent key stays unknown -> reduces confidence, surfaced in
  // coverage. Unsupported does NOT mean safe.
  const e = classifyConditionEntry('StringEquals', 'sts:RoleSessionName', 'ci-runner');
  assert.equal(e.known, false);
  assert.equal(e.class, CONDITION_CLASS.CONTEXT_REQUIRED);
  assert.equal(e.credited, false);
});

// ---------------------------------------------------------------------------
// Aggregation.
// ---------------------------------------------------------------------------

test('classifyConditions summarizes classes, context-required keys, and creditability', () => {
  const cc = classifyConditions({
    Bool: { 'aws:MultiFactorAuthPresent': 'true' },
    StringEquals: { 'kms:ViaService': 's3.amazonaws.com', 'made:up': 'x' },
  });
  assert.equal(cc.present, true);
  assert.equal(cc.classes[CONDITION_CLASS.CONSTRAINT], 1);
  assert.equal(cc.classes[CONDITION_CLASS.SELECTOR], 1);
  assert.equal(cc.classes[CONDITION_CLASS.CONTEXT_REQUIRED], 1);
  assert.deepEqual(cc.contextRequiredKeys, ['made:up']);
  assert.equal(cc.hasCreditableConstraint, true);
  // Deterministic entry ordering (operator then key).
  const cc2 = classifyConditions({
    Bool: { 'aws:MultiFactorAuthPresent': 'true' },
    StringEquals: { 'kms:ViaService': 's3.amazonaws.com', 'made:up': 'x' },
  });
  assert.deepEqual(cc, cc2);
});

test('classifyConditions on null/absent returns a stable not-present shape', () => {
  const none = classifyConditions(null);
  assert.equal(none.present, false);
  assert.deepEqual(none.entries, []);
  assert.deepEqual(none.contextRequiredKeys, []);
  assert.equal(none.hasCreditableConstraint, false);
});

// ---------------------------------------------------------------------------
// Fixture-driven per-entry expectations (protective / selector / negated /
// footgun / unknown all distinguished).
// ---------------------------------------------------------------------------

function loadCC(name) {
  return JSON.parse(readFileSync(join(ccDir, name), 'utf8'));
}

for (const file of readdirSync(ccDir).filter((f) => f.endsWith('.json'))) {
  test(`condition-class fixture: ${file}`, () => {
    const fx = loadCC(file);
    const m = modelFromText(JSON.stringify(fx.policy));
    assert.equal(m.ok, true, `${file}: model built`);

    // Flatten every statement's classified entries in statement order.
    const got = [];
    for (const stmt of m.model.statements) {
      for (const e of classifyConditions(stmt.condition).entries) got.push(e);
    }
    const expect = fx.conditionClass;
    assert.equal(got.length, expect.entries.length, `${file}: entry count`);
    for (let i = 0; i < expect.entries.length; i++) {
      const want = expect.entries[i];
      const e = got.find((x) => x.key === want.key);
      assert.ok(e, `${file}: expected an entry for ${want.key}`);
      for (const k of ['class', 'appears', 'credited', 'known', 'negated', 'ifExists', 'setOperator', 'wildcardValue', 'nullTest']) {
        if (k in want) assert.equal(e[k], want[k], `${file}: ${want.key} field ${k}`);
      }
      // Wording invariant: no runtime allow/deny claim anywhere.
      assert.doesNotMatch(e.note, /request (?:is|will be) (?:allowed|denied)/i, `${file}: ${want.key} note claims a runtime verdict`);
    }
    if (expect.noneCredited) {
      assert.ok(got.every((e) => e.credited === false), `${file}: no entry may be credited`);
    }

    // Coverage wiring: unmodelled keys surface as unsupported conditions.
    const keys = unsupportedConditionKeys(m.model);
    if (Array.isArray(expect.unsupportedConditions)) {
      assert.deepEqual(keys, expect.unsupportedConditions, `${file}: unsupportedConditionKeys`);
    }
    const res = analyze(JSON.stringify(fx.policy));
    assert.equal(res.ok, true);
    assert.equal(res.coverage.summary.incomplete, expect.coverageIncomplete,
      `${file}: coverage incompleteness`);
    if (Array.isArray(expect.expectFindingIds)) {
      const ids = res.findings.map((f) => f.id);
      for (const id of expect.expectFindingIds) {
        assert.ok(ids.includes(id), `${file}: expected finding ${id} to still fire (unknown condition must not clear risk)`);
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Integration: analyze() coverage + per-finding evidence + export carriage.
// ---------------------------------------------------------------------------

const UNKNOWN_COND = JSON.stringify({
  Statement: [{
    Effect: 'Allow', Action: 's3:GetObject', Resource: '*',
    Condition: { StringEquals: { 'unmodelled:key': 'x' } },
  }],
});
const KNOWN_COND = JSON.stringify({
  Statement: [{
    Effect: 'Allow', Action: 's3:GetObject', Resource: '*',
    Condition: { IpAddress: { 'aws:SourceIp': '203.0.113.0/24' } },
  }],
});

test('an unknown condition marks coverage incomplete but never clears the finding', () => {
  const res = analyze(UNKNOWN_COND);
  assert.equal(res.ok, true);
  assert.equal(res.coverage.summary.incomplete, true, 'unknown condition => incomplete coverage');
  assert.deepEqual(res.coverage.summary.unsupportedConditions, ['unmodelled:key']);
  assert.ok(res.findings.some((f) => f.id === 'DATA-EXFIL'), 'broad read still fires - unsupported != safe');
});

test('a fully-modelled condition keeps coverage complete', () => {
  const res = analyze(KNOWN_COND);
  assert.equal(res.ok, true);
  assert.equal(res.coverage.summary.incomplete, false, 'all keys modelled => complete');
  assert.deepEqual(res.coverage.summary.unsupportedConditions, []);
});

test('every finding carries a conditionClassification evidence field', () => {
  const res = analyze(KNOWN_COND);
  for (const f of res.findings) {
    assert.ok(f.conditionClassification && typeof f.conditionClassification === 'object',
      `${f.id} missing conditionClassification`);
    assert.equal(typeof f.conditionClassification.present, 'boolean');
  }
  const exfil = res.findings.find((f) => f.id === 'DATA-EXFIL');
  assert.ok(exfil, 'DATA-EXFIL present');
  const entry = exfil.conditionClassification.entries.find((e) => e.key === 'aws:SourceIp');
  assert.ok(entry, 'SourceIp classified on the finding');
  assert.equal(entry.appears, 'narrows');
  // The narrowing condition is reflected in a reduced path-exploitability
  // (the classifier feeds the exploitability story; it never raises it to safe).
  assert.notEqual(exfil.pathExploitability, 'high', 'a network-fenced broad read is not maximally exploitable');
});

test('exports carry the condition classification (JSON verbatim + Markdown, inert)', () => {
  const res = analyze(KNOWN_COND);
  const parsed = JSON.parse(toJSON(res));
  const exfil = parsed.findings.find((f) => f.id === 'DATA-EXFIL');
  assert.ok(exfil.conditionClassification, 'JSON carries conditionClassification');
  assert.ok(exfil.conditionClassification.entries.some((e) => e.key === 'aws:SourceIp'));

  const md = toMarkdown(res);
  assert.match(md, /Condition classification \(how the text reads, not a runtime verdict\)/);
  assert.match(md, /aws:SourceIp/);
});

test('classification and coverage are deterministic (same input -> same output)', () => {
  const a = analyze(UNKNOWN_COND);
  const b = analyze(UNKNOWN_COND);
  assert.deepEqual(a.coverage.summary.unsupportedConditions, b.coverage.summary.unsupportedConditions);
  assert.deepEqual(
    a.findings.map((f) => f.conditionClassification),
    b.findings.map((f) => f.conditionClassification),
  );
});
