// Regression tests for story S3-class-sweep, blocking finding S3-SWEEP-01.
//
// THREAT (S3-SWEEP-01 [HIGH]): analyze.js findingIdentityKey non-injective join (the
// unswept SIBLING of the cli/sarif.mjs findingIdentity join that S1-NEW02 already fixed).
//
// analyze.js builds a suppression key for the surviving-spared derived findings
// (survivingSparedContainerReads). The pre-fix key folded a finding's attacker-controlled
// POSITIVE lists - actions, resources - into the key with a PLAIN, non-injective join:
//     [ id,
//       statementIndex,
//       actions.map(lower).sort().join(','),   // inner comma-join
//       resources.map(String).sort().join(','), // inner comma-join
//     ].join('|')                               // outer pipe-join
// This key SEEDS derivedSeen (from the authoritative table) and DROPS any derived finding
// whose key already appears. A single resource / action token that literally contains the
// ',' (inner) or '|' (outer) delimiter, or a newline, forges the sorted-join key of a
// DISTINCT multi-element list - so a semantically distinct SURVIVING cross-account/whole-
// container read collides with an existing key and is silently dropped from the table
// (analyze.js:1096), i.e. a live exfil primitive reads CLEAN (threat-model R1 / T8 fail-open).
//
// FIX (class-level, mirrors S1-NEW02): route the sorted actions/resources through an
// INJECTIVE encoder (JSON.stringify of the [id, statementIndex, sortedActions, sortedResources]
// tuple). JSON string quoting/escaping makes the ',' and '|' inside any token INERT - a
// delimiter can never span a field or an element boundary - so two distinct lists always
// produce distinct keys, while benign findings (real ARNs / actions carry no delimiter) keep
// exactly their pre-fix equivalence classes (no dedup behavior change, no over-suppression).
//
// The identity function IS the real boundary of this fix (it is what performs the
// suppression), so it is asserted directly - mirroring how cli-sarif-positive-identity.test.js
// asserts findingIdentity directly - and the delimiter-laden policies are additionally driven
// through the shipped analyze() to prove no over-suppression / no regression at the pipeline.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze, findingIdentityKey } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const SUBJECT = '123456789012';
function policy(statements) {
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}
function ids(r) { return r.ok ? r.findings.map((f) => f.id) : []; }

// ============================================================================
// INJECTIVITY: the exact ambiguous pairs a plain comma / pipe / newline join collapsed.
// These are the keys survivingSparedContainerReads' dedup compares; a collision here is a
// dropped SURVIVING finding.
// ============================================================================

test('S3-SWEEP-01: a comma inside a single resource cannot forge a two-element resource key', () => {
  // The exact collision: derived finding sparing TWO buckets [a/*, b/*] vs a finding whose
  // single resource literally contains the inner "," delimiter ("a/*,b/*"). A plain
  // resources.sort().join(",") produced the SAME string for both.
  const base = { id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', statementIndex: 0, actions: ['s3:GetObject'] };
  const two = { ...base, resources: ['arn:aws:s3:::a/*', 'arn:aws:s3:::b/*'] };
  const oneComma = { ...base, resources: ['arn:aws:s3:::a/*,arn:aws:s3:::b/*'] };
  assert.notEqual(findingIdentityKey(oneComma), findingIdentityKey(two),
    'a ","-bearing single resource must NOT collide with a two-element resource list');
});

test('S3-SWEEP-01: a comma inside a single action cannot forge a two-element action key', () => {
  // Tokens chosen already-lowercased + sorted so the two-element join is byte-identical to
  // the single ","-bearing token under the old inner comma-join.
  const base = { id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', statementIndex: 0, resources: ['arn:aws:s3:::x/*'] };
  const two = { ...base, actions: ['alpha:read', 'bravo:read'] };
  const oneComma = { ...base, actions: ['alpha:read,bravo:read'] };
  assert.notEqual(findingIdentityKey(oneComma), findingIdentityKey(two),
    'a ","-bearing single action must NOT collide with a two-element action list');
});

test('S3-SWEEP-01: a pipe inside a resource cannot forge a collision across the outer field boundary', () => {
  // The outer ".join('|')" delimiter: a "|"-bearing token must not bridge the id / index /
  // actions / resources field boundaries into another finding's key.
  const a = { id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', statementIndex: 0, actions: ['s3:GetObject'], resources: ['arn:aws:s3:::a/*'] };
  const b = { id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', statementIndex: 0, actions: ['s3:GetObject'], resources: ['arn:aws:s3:::a/*|extra'] };
  assert.notEqual(findingIdentityKey(a), findingIdentityKey(b),
    'a "|"-bearing resource must not collapse into another key');
});

test('S3-SWEEP-01: a newline inside a token cannot inject / forge a distinct key', () => {
  const base = { id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', statementIndex: 0, actions: ['s3:GetObject'] };
  const plain = { ...base, resources: ['arn:aws:s3:::a/*'] };
  const oneNl = { ...base, resources: ['arn:aws:s3:::a/*\narn:aws:s3:::b/*'] };
  assert.notEqual(findingIdentityKey(oneNl), findingIdentityKey(plain),
    'a newline-bearing resource must be encoded, not treated as a fresh element/line');
});

// ============================================================================
// STABILITY / DETERMINISM: benign findings keep stable keys; order / case does not churn;
// distinct-id and distinct-statement findings never share a key.
// ============================================================================

test('S3-SWEEP-01: resource + action ORDER does not churn the identity key', () => {
  const a = { id: 'CROSS-ACCOUNT-DATA-READ', statementIndex: 2, actions: ['s3:ListBucket', 's3:GetObject'], resources: ['arn:aws:s3:::b/*', 'arn:aws:s3:::a/*'] };
  const b = { id: 'CROSS-ACCOUNT-DATA-READ', statementIndex: 2, actions: ['s3:GetObject', 's3:ListBucket'], resources: ['arn:aws:s3:::a/*', 'arn:aws:s3:::b/*'] };
  assert.equal(findingIdentityKey(a), findingIdentityKey(b),
    'sorted-set identity is order-independent (same capability -> same key)');
});

test('S3-SWEEP-01: action CASE does not churn the identity key (lowercased)', () => {
  const a = { id: 'X', statementIndex: 0, actions: ['S3:GetObject'], resources: ['r'] };
  const b = { id: 'X', statementIndex: 0, actions: ['s3:getobject'], resources: ['r'] };
  assert.equal(findingIdentityKey(a), findingIdentityKey(b), 'actions are lowercased for identity');
});

test('S3-SWEEP-01: distinct id or distinct statementIndex yield distinct keys', () => {
  const base = { statementIndex: 0, actions: ['s3:GetObject'], resources: ['arn:aws:s3:::a/*'] };
  const k = findingIdentityKey({ id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', ...base });
  assert.notEqual(k, findingIdentityKey({ id: 'CROSS-ACCOUNT-DATA-READ', ...base }), 'id participates in identity');
  assert.notEqual(k, findingIdentityKey({ id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', ...base, statementIndex: 1 }),
    'statementIndex participates in identity');
});

test('S3-SWEEP-01: findingIdentityKey is a pure, deterministic string', () => {
  const f = { id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', statementIndex: 0, actions: ['s3:GetObject'], resources: ['arn:aws:s3:::a/*'] };
  assert.equal(typeof findingIdentityKey(f), 'string');
  assert.equal(findingIdentityKey(f), findingIdentityKey(f));
});

test('S3-SWEEP-01: findingIdentityKey tolerates malformed/absent fields without throwing', () => {
  assert.equal(typeof findingIdentityKey(null), 'string');
  assert.equal(typeof findingIdentityKey({}), 'string');
  assert.equal(typeof findingIdentityKey({ id: 'X', actions: 'notarray', resources: null, statementIndex: 'nope' }), 'string');
});

// ============================================================================
// REAL BOUNDARY (no over-suppression / no regression): the delimiter-laden fenced policies
// still surface the surviving read through the shipped analyze(), and coexisting distinct
// surviving reads are NOT dropped.
// ============================================================================

test('S3-SWEEP-01: a fence sparing TWO buckets surfaces ONE derived finding covering BOTH (not dropped)', () => {
  // A single fence spares [bucketa/*, bucketb/*]; the surviving read must be surfaced with
  // both buckets - the injective key must not collapse the two-element list against any
  // comma-bearing key already in the table.
  const text = policy([
    { Sid: 'AllowBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Sid: 'Fence', Effect: 'Deny', Action: 's3:GetObject', NotResource: ['arn:aws:s3:::bucketa/*', 'arn:aws:s3:::bucketb/*'] },
  ]);
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(text, opt);
    assert.equal(r.ok, true);
    const undet = r.findings.filter((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
    assert.equal(undet.length, 1, `exactly one surviving read finding; got [${ids(r)}]`);
    assert.deepEqual(undet[0].resources.slice().sort(), ['arn:aws:s3:::bucketa/*', 'arn:aws:s3:::bucketb/*'],
      'the surviving read covers BOTH spared buckets (the injective key did not drop the two-element list)');
  }
});

test('S3-SWEEP-01: a comma-bearing spared bucket ARN still surfaces (delimiter rides inert through analyze)', () => {
  // The spared bucket name literally contains the old inner "," delimiter. It must still
  // surface as a surviving whole-container read, never collapse/drop.
  const arn = 'arn:aws:s3:::acme,competitor/*';
  const text = policy([
    { Sid: 'AllowBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Sid: 'Fence', Effect: 'Deny', Action: 's3:GetObject', NotResource: arn },
  ]);
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(text, opt);
    const f = r.findings.find((x) => x.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
    assert.ok(f, `a comma-bearing spared bucket must still surface; got [${ids(r)}]`);
    assert.deepEqual(f.resources, [arn], 'the comma-bearing ARN is preserved verbatim, not split');
  }
});

test('S3-SWEEP-01: determinism - analyze() over a delimiter-laden fenced policy is deep-equal twice', () => {
  const text = policy([
    { Sid: 'AllowBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Sid: 'Fence', Effect: 'Deny', Action: 's3:GetObject', NotResource: ['arn:aws:s3:::b|ad/*', 'arn:aws:s3:::worse,name/*'] },
  ]);
  assert.deepEqual(analyze(text, { subjectAccount: SUBJECT }), analyze(text, { subjectAccount: SUBJECT }));
});
