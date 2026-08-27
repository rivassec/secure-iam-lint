// Regression tests for story S3-class-sweep (the unswept sibling of NEW-02 / R2).
//
// THREAT: SARIF PRINCIPAL-OBJECT fingerprint forgery via the inner "=" separator.
//
// findingIdentity (cli/sarif.mjs) folds a finding's normalized principals into the canonical
// identity string. NEW-02 routed the POSITIVE lists (actions/resources/principals) through the
// injective joinInjective() for the OUTER '|' element boundary, and its suite proved the ARRAY
// principal form is injective. But findingPrincipals ALSO has an OBJECT branch: a Principal
// object ({ AWS: [...], Service: [...] }) is FLATTENED to "type=value" tokens with a PLAIN
// `${k}=${v}`. BOTH the key (a Principal-object key) and the value (an ARN token) are
// attacker-controlled (a fork PR owns the whole policy JSON; the engine applies no charset
// restriction). The NEW-02 suite explicitly waved this off ("the Principal-OBJECT form
// prefixes each element and would not collide") - TRUE for the OUTER '|', but FALSE for the
// INNER '=': the '=' join is itself non-injective.
//
// REPRODUCED: {'AWS=arn:aws:iam::111122223333:root': ['x']} and
// {'AWS': ['arn:aws:iam::111122223333:root=x']} BOTH flatten to the single token
// 'AWS=arn:aws:iam::111122223333:root=x', so two SEMANTICALLY DISTINCT principal sets hash to
// ONE partialFingerprint - a GitHub code-scanning dismissal of one AUTO-SUPPRESSES the other
// (fail-OPEN on re-detection), the exact class NEW-02/R2 closed for the '|' delimiter.
//
// FIX (class-level): escape the KEY before the "type=value" join ('\' first so the escapes are
// unambiguous, then '='), making the first UNESCAPED '=' the sole type/value boundary; the whole
// token still flows through joinInjective for the outer '|'/'\'/newline boundary, so the
// composition is injective. A benign single-key principal ('AWS'/'Service'/... - no '\'/'=' in
// the key) emits byte-for-byte as the plain flatten did, so no existing fingerprint churns.
//
// Assertions are measured on the exported findingIdentity AND on the ACTUAL emitted SARIF bytes
// (buildSarifLog / formatSarif), mirroring the NEW-02 real-boundary suite. No shipped rule emits
// a top-level principal OBJECT, so - like the NEW-02 synthetic-principal case - these drive a
// synthetic finding through the real exporter, the genuine boundary for the fingerprint identity.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  buildSarifLog, formatSarif, findingIdentity, FINGERPRINT_KEY,
} from '../../../cli/sarif.mjs';

const MANIFEST = { ruleVersion: '1' };

const CONTROL = /[\u0000-\u001F\u007F-\u009F]/;
const BIDI_ZW = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/;

function principalsLine(id) {
  return id.split('\n').find((l) => l.startsWith('principals='));
}

const BASE = Object.freeze({
  id: 'TRUST-CROSS-ACCOUNT', severity: 'high', title: 't', statementIndex: 0,
  statementSid: 'S', actions: ['sts:AssumeRole'], resources: [], conditions: null,
});

// ============================================================================
// The inner "=" separator of the Principal-OBJECT flatten must be injective.
// ============================================================================

test('S3-sweep: a "="-bearing Principal-object KEY cannot forge a colliding identity', () => {
  const a = { ...BASE, principal: { 'AWS=arn:aws:iam::111122223333:root': ['x'] } };
  const b = { ...BASE, principal: { AWS: ['arn:aws:iam::111122223333:root=x'] } };
  assert.notEqual(
    findingIdentity(a, 'role-trust'), findingIdentity(b, 'role-trust'),
    'a key that swallows the "=" boundary must not collapse to the value-side spelling',
  );
});

test('S3-sweep: a backslash in a Principal-object key stays injective ("\\" escaped first)', () => {
  // Escaping '=' WITHOUT escaping '\' first would let a key ending in '\' merge with the
  // following escape and re-open the collision. Prove '\' is escaped first.
  const a = { ...BASE, principal: { 'AWS\\': ['=x'] } };
  const b = { ...BASE, principal: { AWS: ['\\=x'] } };
  assert.notEqual(
    findingIdentity(a, 'role-trust'), findingIdentity(b, 'role-trust'),
    'a backslash-bearing key must not collide with a backslash-bearing value',
  );
});

test('S3-sweep: two distinct multi-key Principal objects get distinct identities', () => {
  const a = { ...BASE, principal: { AWS: ['arn:aws:iam::111122223333:root'], Service: ['ec2.amazonaws.com'] } };
  const b = { ...BASE, principal: { 'AWS=arn:aws:iam::111122223333:root=Service=ec2.amazonaws.com': ['z'] } };
  assert.notEqual(
    findingIdentity(a, 'role-trust'), findingIdentity(b, 'role-trust'),
    'a single crafted key must not reproduce a two-key principal object identity',
  );
});

// ============================================================================
// Same collision closed on the ACTUAL emitted SARIF fingerprint.
// ============================================================================

test('S3-sweep: the "="-forgery pair gets DISTINCT SARIF partialFingerprints', () => {
  const mk = (principal) => {
    const finding = { ...BASE, principal };
    const result = { family: 'role-trust', findings: [finding], analysisStates: [] };
    const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
    const row = log.runs[0].results.find((r) => r.ruleId === 'TRUST-CROSS-ACCOUNT');
    assert.ok(row, 'TRUST-CROSS-ACCOUNT row present');
    return row.partialFingerprints[FINGERPRINT_KEY];
  };
  const a = mk({ 'AWS=arn:aws:iam::111122223333:root': ['x'] });
  const b = mk({ AWS: ['arn:aws:iam::111122223333:root=x'] });
  assert.notEqual(a, b, 'dismissing one principal-object alert must not auto-suppress the distinct other');
});

// ============================================================================
// The forged token rides the hash INERT and never injects a live identity line.
// ============================================================================

test('S3-sweep: a newline/pipe in a Principal-object key stays inert + non-forging', () => {
  const finding = {
    ...BASE,
    principal: { 'AWS\nescTechnique=forged|escService=forged': ['arn:aws:iam::111122223333:root'] },
  };
  const bytes = formatSarif(
    { family: 'role-trust', findings: [finding], analysisStates: [] }, { file: 'p.json' }, MANIFEST,
  );
  const log = JSON.parse(bytes); // must remain valid JSON
  const row = log.runs[0].results.find((r) => r.ruleId === 'TRUST-CROSS-ACCOUNT');
  const fp = row.partialFingerprints[FINGERPRINT_KEY];
  assert.equal(typeof fp, 'string', 'a fingerprint is emitted');
  assert.ok(!CONTROL.test(fp) && !BIDI_ZW.test(fp), 'the fingerprint hash is control-free');
  const id = findingIdentity(finding, 'role-trust');
  assert.ok(!/\nescTechnique=forged/.test(id) && !/\nescService=forged/.test(id),
    'a forged escTechnique/escService identity line must not appear via a principal-object key');
});

// ============================================================================
// NO CHURN: a benign single-key / multi-key principal object flattens byte-for-byte as the
// plain "type=value" join produced (real keys carry no '\' or '=' to escape).
// ============================================================================

test('S3-sweep: a benign Principal object flattens byte-for-byte as the plain join (no churn)', () => {
  const finding = {
    ...BASE,
    principal: { AWS: ['arn:aws:iam::111122223333:root', 'arn:aws:iam::444455556666:root'], Service: ['ec2.amazonaws.com'] },
  };
  const line = principalsLine(findingIdentity(finding, 'role-trust'));
  // Sorted keys (AWS, Service); within each key sorted+deduped values; joined by the outer '|'.
  assert.equal(
    line,
    'principals=AWS=arn:aws:iam::111122223333:root|AWS=arn:aws:iam::444455556666:root|Service=ec2.amazonaws.com',
    'benign principal-object flatten is byte-identical to the plain "type=value" join',
  );
  // Key order in the source object must not churn the identity (Object.keys is sorted).
  const reordered = {
    ...BASE,
    principal: { Service: ['ec2.amazonaws.com'], AWS: ['arn:aws:iam::444455556666:root', 'arn:aws:iam::111122223333:root'] },
  };
  assert.equal(findingIdentity(reordered, 'role-trust'), findingIdentity(finding, 'role-trust'),
    'principal key/value order does not churn identity');
});

// ============================================================================
// viability channel: structurally routed through the SAME injective joiner (defense in depth).
// requiredUnknowns is tool-enum today (byte-identical), so this cannot churn a real finding,
// but the join must not be re-openable by a future attacker-derived unknown.
// ============================================================================

test('S3-sweep: the viability list is joined injectively (no forged identity line)', () => {
  const mk = (requiredUnknowns) => ({
    ...BASE, escalation: { requiredUnknowns },
  });
  // A hostile pipe/newline in a viability token must not collapse two distinct lists nor
  // inject a fresh identity line - even though real requiredUnknowns are tool-enum literals.
  const two = mk(['subjectAccount', 'subjectPartition']);
  const onePipe = mk(['subjectAccount|subjectPartition']);
  assert.notEqual(findingIdentity(onePipe, 'role-trust'), findingIdentity(two, 'role-trust'),
    'a "|"-bearing single viability token must not collapse to the two-element list');
  const oneNl = mk(['subjectAccount\nescService=forged']);
  const id = findingIdentity(oneNl, 'role-trust');
  assert.ok(!/\nescService=forged/.test(id),
    'a newline in a viability token must be encoded, not injected as a new identity line');
});

test('S3-sweep: an ordinary tool-enum viability list is byte-identical (no churn)', () => {
  const finding = { ...BASE, escalation: { requiredUnknowns: ['subjectPartition', 'subjectAccount'] } };
  const line = findingIdentity(finding, 'role-trust').split('\n').find((l) => l.startsWith('viability='));
  // sorted tool-enum literals joined by '|', exactly as the pre-sweep plain join produced.
  assert.equal(line, 'viability=subjectAccount|subjectPartition',
    'tool-enum viability tokens join byte-for-byte as the plain "|"-join did');
});
