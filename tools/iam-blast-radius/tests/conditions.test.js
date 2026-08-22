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
