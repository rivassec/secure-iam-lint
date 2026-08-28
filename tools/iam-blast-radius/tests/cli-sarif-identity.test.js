// Regression tests for story S2-R2-sarif-identity.
//
// THREAT (R2 [MED]): SARIF partialFingerprint collision + excluded scope never in SARIF.
//
// findingIdentity (cli/sarif.mjs) hashed a finding's POSITIVE actions/resources but NOT
// its excludedActions / excludedResources. makeFinding (engine/rules.js) EMPTIES the
// positive scope for a NotAction / NotResource grant - a NotResource DATA-EXFIL reports
// actions:[...], resources:[] and a NotAction NOTACTION-ALLOW / WILDCARD-RESOURCE reports
// actions:["*"], resources:["*"] - and stows the REAL discriminating scope in
// excludedActions / excludedResources, which sarif.mjs grepped NOWHERE. So two carve-outs
// differing ONLY in their NotResource / NotAction target hashed to ONE partialFingerprint
// (reproduced: 1c2a72... shared by two distinct NotResource DATA-EXFIL grants). Impact:
// GitHub code-scanning dismissal of carve-out A AUTO-SUPPRESSES the still-live distinct
// finding B (a fail-OPEN on re-detection), and the distinguishing evidence never reached
// the SARIF at all.
//
// FIX: (identity) fold excludedActions + excludedResources into findingIdentity, mirroring
// the escService/escTechnique precedent, canonicalized through the SAME normList as
// actions/resources (sort + de-dup; actions case-folded; scalar-vs-list collapsed) and
// appended CONDITIONALLY so non-complement fingerprints never churn. BOTH complement sides.
// (surfacing) emit excludedActions/excludedResources in the SARIF result properties, routed
// through the EXISTING inertTokenList (markdown-inert + count/char-capped), never raw.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import {
  buildSarifLog, formatSarif, findingIdentity, FINGERPRINT_KEY,
} from '../../../cli/sarif.mjs';

const MANIFEST = { ruleVersion: '1' };

// C0/C1 control chars (backtick is NOT a control char; markdown-inert KEEPS it, escaped).
const CONTROL = /[\u0000-\u001F\u007F-\u009F]/;
// The bidi/zero-width class a hostile value must be stripped of before a SARIF sink.
const BIDI_ZW = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/;

// Assert a rendered BARE properties string is markdown-inert + control-free: no control
// char, no unescaped link/image boundary "](", and no backtick that could open a code span.
function assertInert(s, label) {
  assert.equal(typeof s, 'string', `${label}: is a string`);
  assert.ok(!CONTROL.test(s), `${label}: no control chars`);
  assert.ok(!BIDI_ZW.test(s), `${label}: no bidi/zero-width chars`);
  assert.ok(!s.includes(']('), `${label}: no unescaped markdown link/image boundary`);
  assert.ok(!/(^|[^\\])`/.test(s), `${label}: no unescaped backtick (no code span can open)`);
  assert.ok(!/<https?:/i.test(s), `${label}: no unescaped autolink`);
}

function dataExfilRow(text) {
  const result = scan({ text, family: 'identity' });
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  return log.runs[0].results.find((r) => r.ruleId === 'DATA-EXFIL');
}

function notActionRows(text) {
  const result = scan({ text, family: 'identity' });
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  // NOTACTION-ALLOW + WILDCARD-RESOURCE are the two complement rows carrying excludedActions.
  return log.runs[0].results.filter((r) => r.ruleId === 'NOTACTION-ALLOW');
}

const NOTRESOURCE = (bucket) => JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 's3:GetObject', NotResource: [`arn:aws:s3:::${bucket}/*`] }],
});
// A NotResource carve-out taking the raw ARN array verbatim (used to feed a single
// element that literally contains the '|' identity delimiter).
const NOTRESOURCE_ARR = (arr) => JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 's3:GetObject', NotResource: arr }],
});
const NOTACTION = (excluded) => JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', NotAction: [excluded], Resource: '*' }],
});
// A NotAction carve-out taking the raw action array verbatim.
const NOTACTION_ARR = (arr) => JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', NotAction: arr, Resource: '*' }],
});

// ============================================================================
// DISTINCTNESS: two complement grants differing ONLY in the excluded target get
// DISTINCT partialFingerprints - measured on the ACTUAL SARIF result, not the helper.
// ============================================================================

test('R2: two NotResource DATA-EXFIL carve-outs differing only in target -> DISTINCT SARIF fingerprints', () => {
  const a = dataExfilRow(NOTRESOURCE('safe-bucket-a'));
  const b = dataExfilRow(NOTRESOURCE('safe-bucket-b'));
  assert.ok(a && b, 'both DATA-EXFIL rows present');
  // Both empty positive resources - the ONLY difference is the excluded carve-out.
  assert.deepEqual(a.properties.evidence, undefined); // (no evidence on this rule; sanity)
  const fpA = a.partialFingerprints[FINGERPRINT_KEY];
  const fpB = b.partialFingerprints[FINGERPRINT_KEY];
  assert.notEqual(fpA, fpB,
    'distinct NotResource carve-outs must NOT collide (dismissing A cannot suppress B)');
});

test('R2: two NotAction grants differing only in the excluded action -> DISTINCT SARIF fingerprints', () => {
  const [a] = notActionRows(NOTACTION('s3:GetObject'));
  const [b] = notActionRows(NOTACTION('ec2:DescribeInstances'));
  assert.ok(a && b, 'both NOTACTION-ALLOW rows present');
  assert.notEqual(
    a.partialFingerprints[FINGERPRINT_KEY],
    b.partialFingerprints[FINGERPRINT_KEY],
    'distinct NotAction carve-outs must NOT collide',
  );
});

// ============================================================================
// ITERATION 2 [test/high]: DELIMITER (pipe) injection must not forge a collision.
// findingIdentity joined the excluded set with '|' into the canonical identity string,
// so a SINGLE carve-out ARN/action literally containing '|' produced the byte-identical
// identity as a TWO-element carve-out split on that '|'. Reproduced: two semantically
// DISTINCT DATA-EXFIL carve-outs hashed to ONE partialFingerprint (fp 01c5a3df...),
// so dismissing one code-scanning alert AUTO-SUPPRESSES the other (fail-OPEN). The
// element boundary must be UNFORGEABLE - measured on the ACTUAL SARIF result identity.
// ============================================================================

test('R2 iter2: a pipe inside a NotResource ARN cannot forge a colliding SARIF fingerprint', () => {
  // A excludes TWO buckets; B excludes ONE ARN that literally contains the '|' delimiter.
  // Distinct carve-outs (A spares two buckets; B spares one oddly-named resource) that a
  // raw "|"-join collapsed to one identity.
  const a = dataExfilRow(NOTRESOURCE_ARR(['arn:aws:s3:::pipe-a/*', 'arn:aws:s3:::pipe-b/*']));
  const b = dataExfilRow(NOTRESOURCE_ARR(['arn:aws:s3:::pipe-a/*|arn:aws:s3:::pipe-b/*']));
  assert.ok(a && b, 'both DATA-EXFIL rows present');
  assert.notEqual(
    a.partialFingerprints[FINGERPRINT_KEY],
    b.partialFingerprints[FINGERPRINT_KEY],
    'a "|"-bearing single carve-out must NOT collide with a two-element carve-out (delimiter injection)',
  );
});

test('R2 iter2: a pipe inside a NotAction cannot forge a colliding SARIF fingerprint', () => {
  // Tokens chosen already-lowercased and in sorted order, so the two-element canonical
  // join ("alpha:read|bravo:read") is byte-identical to the single "|"-bearing token -
  // the exact shape a raw "|"-join collided (normList sort/case cannot save it here).
  const a = notActionRows(NOTACTION_ARR(['alpha:read', 'bravo:read']))[0];
  const b = notActionRows(NOTACTION_ARR(['alpha:read|bravo:read']))[0];
  assert.ok(a && b, 'both NOTACTION-ALLOW rows present');
  assert.notEqual(
    a.partialFingerprints[FINGERPRINT_KEY],
    b.partialFingerprints[FINGERPRINT_KEY],
    'a "|"-bearing single NotAction must NOT collide with a two-element NotAction carve-out',
  );
});

test('R2 iter2: findingIdentity encodes the excluded set injectively (delimiter + newline)', () => {
  const base = { id: 'DATA-EXFIL', severity: 'high', title: 't', statementIndex: 0,
    statementSid: 'S', actions: ['s3:GetObject'], resources: [], conditions: null };
  // Two-element list vs single element carrying the '|' delimiter.
  const two = { ...base, excludedResources: ['arn:aws:s3:::a/*', 'arn:aws:s3:::b/*'] };
  const onePipe = { ...base, excludedResources: ['arn:aws:s3:::a/*|arn:aws:s3:::b/*'] };
  assert.notEqual(findingIdentity(onePipe, 'identity'), findingIdentity(two, 'identity'),
    'a "|"-bearing single element must not collapse to the two-element identity');
  // A newline in a token must not be able to inject a fresh "key=value" identity line
  // (which could forge, e.g., an escService part).
  const oneNl = { ...base, excludedResources: ['arn:aws:s3:::a/*\nescService=forged'] };
  const plain = { ...base, excludedResources: ['arn:aws:s3:::a/*'] };
  assert.notEqual(findingIdentity(oneNl, 'identity'), findingIdentity(plain, 'identity'),
    'a newline-bearing token must be encoded, not injected as a new identity line');
  assert.ok(!/\nescService=forged/.test(findingIdentity(oneNl, 'identity')),
    'a forged escService line must not appear as a live identity part');
});

test('R2: findingIdentity separates carve-outs on BOTH complement sides', () => {
  const baseR = { id: 'DATA-EXFIL', severity: 'high', title: 't', statementIndex: 0,
    statementSid: 'S', actions: ['s3:GetObject'], resources: [], conditions: null,
    excludedResources: ['arn:aws:s3:::bucket-a/*'] };
  const diffR = { ...baseR, excludedResources: ['arn:aws:s3:::bucket-b/*'] };
  assert.notEqual(findingIdentity(diffR, 'identity'), findingIdentity(baseR, 'identity'),
    'a different NotResource target changes the identity');

  const baseA = { id: 'NOTACTION-ALLOW', severity: 'high', title: 't', statementIndex: 0,
    statementSid: 'S', actions: ['*'], resources: ['*'], conditions: null,
    excludedActions: ['s3:GetObject'] };
  const diffA = { ...baseA, excludedActions: ['ec2:DescribeInstances'] };
  assert.notEqual(findingIdentity(diffA, 'identity'), findingIdentity(baseA, 'identity'),
    'a different NotAction target changes the identity');
});

// ============================================================================
// NO OVER-CORRECTION: an equivalent carve-out (order / case / scalar-vs-list) must
// NOT churn the fingerprint - only a genuinely different target splits.
// ============================================================================

test('R2: equivalent excluded set (order / case / scalar-vs-list) -> SAME identity', () => {
  const base = { id: 'DATA-EXFIL', severity: 'high', title: 't', statementIndex: 0,
    statementSid: 'S', actions: ['s3:GetObject'], resources: [], conditions: null,
    excludedResources: ['arn:aws:s3:::a/*', 'arn:aws:s3:::b/*'] };
  const reordered = { ...base, excludedResources: ['arn:aws:s3:::b/*', 'arn:aws:s3:::a/*'] };
  const duped = { ...base, excludedResources: ['arn:aws:s3:::a/*', 'arn:aws:s3:::b/*', 'arn:aws:s3:::a/*'] };
  assert.equal(findingIdentity(reordered, 'identity'), findingIdentity(base, 'identity'),
    'NotResource order does not churn the fingerprint');
  assert.equal(findingIdentity(duped, 'identity'), findingIdentity(base, 'identity'),
    'a duplicate NotResource entry does not churn the fingerprint');

  // Actions are case-insensitive in AWS; scalar and single-element list are equivalent.
  const aList = { id: 'NOTACTION-ALLOW', severity: 'high', title: 't', statementIndex: 0,
    statementSid: 'S', actions: ['*'], resources: ['*'], conditions: null,
    excludedActions: ['S3:GetObject'] };
  const aScalar = { ...aList, excludedActions: 's3:getobject' };
  assert.equal(findingIdentity(aScalar, 'identity'), findingIdentity(aList, 'identity'),
    'NotAction case + scalar-vs-list do not churn the fingerprint');
});

// ============================================================================
// NO CHURN for non-complement findings: their identity string is byte-identical to
// before (the excluded parts are ABSENT, not empty-valued), and their SARIF rows carry
// no excluded* properties.
// ============================================================================

test('R2: a non-complement finding identity carries NO excluded parts (no churn)', () => {
  const plain = { id: 'WILDCARD-RESOURCE', severity: 'high', title: 't', statementIndex: 0,
    statementSid: 'S', actions: ['*'], resources: ['*'], conditions: null };
  const id = findingIdentity(plain, 'identity');
  assert.ok(!id.includes('excludedActions='), 'no excludedActions line for a non-complement finding');
  assert.ok(!id.includes('excludedResources='), 'no excludedResources line for a non-complement finding');
  // Two identical non-complement findings still hash identically.
  assert.equal(findingIdentity(plain, 'identity'), findingIdentity({ ...plain }, 'identity'));
});

test('R2: a non-complement SARIF row carries no excluded* properties', () => {
  // A plain wildcard grant (positive Resource "*"): no NotAction/NotResource.
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }],
  });
  const result = scan({ text, family: 'identity' });
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  for (const r of log.runs[0].results) {
    assert.ok(!('excludedActions' in r.properties),
      `${r.ruleId}: no excludedActions on a non-complement row`);
    assert.ok(!('excludedResources' in r.properties),
      `${r.ruleId}: no excludedResources on a non-complement row`);
  }
});

// ============================================================================
// SURFACING: the discriminating carve-out reaches the SARIF properties, so a reviewer
// can tell two otherwise-identical rows apart.
// ============================================================================

test('R2: excludedResources is surfaced (inert) in the DATA-EXFIL SARIF properties', () => {
  const row = dataExfilRow(NOTRESOURCE('safe-bucket-a'));
  assert.ok(Array.isArray(row.properties.excludedResources),
    'excludedResources present in properties');
  // The (benign) bucket name is readable; punctuation is backslash-escaped but the token
  // survives so the carve-out is distinguishable.
  // Punctuation is backslash-escaped (markdown-inert); strip the escapes to read the token.
  const joined = row.properties.excludedResources.join(' ').replace(/\\(.)/g, '$1');
  assert.match(joined, /safe-bucket-a/, 'the distinguishing bucket name reaches the SARIF');
  for (const t of row.properties.excludedResources) assertInert(t, 'excludedResources token');
});

// ============================================================================
// HOSTILE excluded values stay INERT + BOUNDED (matching the evidence-field tests).
// ============================================================================

test('R2: a hostile NotResource (embedded markdown link) is rendered markdown-inert in SARIF', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject',
      NotResource: ['arn:aws:s3:::evil[CLICK](https://evil.example)/*'] }],
  });
  const row = dataExfilRow(text);
  assert.ok(row && Array.isArray(row.properties.excludedResources), 'excludedResources surfaced');
  for (const t of row.properties.excludedResources) assertInert(t, 'hostile excludedResources token');
});

test('R2: a hostile bidi/zero-width NotResource is neutralized at the SARIF sink', () => {
  // Feed a SYNTHETIC finding straight into the pure builder so the bidi payload reaches the
  // SARIF surface even though the engine model would strip it upstream (defense in depth for
  // a synthetic caller). It must come out with the bidi override stripped + markdown-inert.
  const finding = { id: 'DATA-EXFIL', severity: 'high', title: 't', statementIndex: 0,
    statementSid: 'S', actions: ['s3:GetObject'], resources: [], conditions: null,
    excludedResources: ['arn:aws:s3:::evil\u202E/tender/*', 'arn:aws:s3:::b\u200B/*'] };
  const result = { family: 'identity', findings: [finding], analysisStates: [] };
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const row = log.runs[0].results.find((r) => r.ruleId === 'DATA-EXFIL');
  assert.ok(Array.isArray(row.properties.excludedResources));
  for (const t of row.properties.excludedResources) assertInert(t, 'bidi excludedResources token');
});

test('R2: an oversized excluded array is bounded (count-capped with a truthful marker)', () => {
  const big = Array.from({ length: 50 }, (_, i) => `arn:aws:s3:::b${i}/*`);
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', NotAction: big, Resource: '*' }],
  });
  const [row] = notActionRows(text);
  assert.ok(row && Array.isArray(row.properties.excludedActions), 'excludedActions surfaced');
  // MAX_EVIDENCE_TOKENS is 32; the list is capped and a truthful truncation marker appended.
  assert.ok(row.properties.excludedActions.length <= 33,
    `bounded token count (${row.properties.excludedActions.length})`);
  assert.ok(row.properties.excludedActions.includes('(list truncated)'),
    'a truthful truncation marker is present (no silent drop)');
  // The FULL canonical set still discriminates the fingerprint (surfacing cap != identity).
  const other = Array.from({ length: 50 }, (_, i) => `arn:aws:s3:::c${i}/*`);
  const textOther = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', NotAction: other, Resource: '*' }],
  });
  const [rowOther] = notActionRows(textOther);
  assert.notEqual(
    row.partialFingerprints[FINGERPRINT_KEY],
    rowOther.partialFingerprints[FINGERPRINT_KEY],
    'a fully-distinct oversized carve-out still gets a distinct fingerprint despite the display cap',
  );
});

// ============================================================================
// DETERMINISM: the excluded-scope surfacing + fingerprint is byte-stable.
// ============================================================================

test('R2: SARIF with excluded scope is byte-identical across builds', () => {
  const text = NOTRESOURCE('safe-bucket-a');
  const result = scan({ text, family: 'identity' });
  assert.equal(
    formatSarif(result, { file: 'p.json' }, MANIFEST),
    formatSarif(result, { file: 'p.json' }, MANIFEST),
    'deterministic SARIF for a complement grant',
  );
});
