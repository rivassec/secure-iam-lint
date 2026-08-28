// Regression tests for story S1-NEW02-sarif-identity-injective.
//
// THREAT (NEW-02 [HIGH]): SARIF POSITIVE-list fingerprint forgery (sibling of R2).
//
// findingIdentity (cli/sarif.mjs) folds a finding's normalized POSITIVE lists - actions,
// resources, principals - into the canonical identity string. R2 already closed this class
// for the EXCLUDED (NotAction / NotResource) lists via the INJECTIVE joinExcluded() (escape
// '\', '|', newline). But the POSITIVE lists were still joined with a PLAIN, non-injective
// '|':
//     actions=${normList(f.actions).join('|')}
//     resources=${normList(f.resources).join('|')}
//     principals=${findingPrincipals(f).join('|')}
// A resource / principal token (S3 keys permit ~any byte; the engine applies NO charset
// restriction) that literally contains a '|' or a newline forges the sorted-join identity of
// a DISTINCT multi-element list. REPRODUCED end-to-end: policy A with resources
// [arn:aws:s3:::a/*, arn:aws:s3:::b/*] vs policy B with the single resource
// "arn:aws:s3:::a/*|arn:aws:s3:::b/*" produced a BYTE-IDENTICAL partialFingerprint
// (0d30051c... on the CROSS-ACCOUNT-DATA-READ-UNDETERMINED result), so a GitHub code-scanning
// dismissal of A AUTO-SUPPRESSES the still-live, semantically distinct B - a fail-OPEN on
// re-detection. A newline token could additionally inject a fresh "key=value" identity line
// (forging, e.g., escService).
//
// FIX (class-level): route EVERY attacker-controlled identity list through the injective
// escaping helper - actions, resources, AND principals - i.e. fix the WHOLE findingIdentity
// join, not one field. The other identity channels are already safe and unchanged (condition
// via stableStringify; escService/escTechnique/viability are tool enums, never attacker text).
//
// These assertions are measured on the ACTUAL emitted SARIF bytes (through scan() +
// buildSarifLog / formatSarif), not merely the helper, mirroring the R2 real-boundary suite.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import {
  buildSarifLog, formatSarif, findingIdentity, FINGERPRINT_KEY,
} from '../../../cli/sarif.mjs';

const MANIFEST = { ruleVersion: '1' };

// C0/C1 control chars + the bidi/zero-width class a hostile value must be stripped of.
const CONTROL = /[\u0000-\u001F\u007F-\u009F]/;
const BIDI_ZW = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/;

// A whole-bucket read of a foreign-named bucket with a KNOWN subject account surfaces
// CROSS-ACCOUNT-DATA-READ-UNDETERMINED, whose finding carries the POSITIVE resource list
// verbatim - the channel the forgery rides. subjectAccount is set so the finding fires.
const SUBJECT = '111122223333';
function readRow(resource) {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: resource }],
  });
  const result = scan({ text, family: 'identity', subjectAccount: SUBJECT, threshold: 'info' });
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  return log.runs[0].results.find((r) => r.ruleId === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
}
function fpOf(row) {
  assert.ok(row, 'the CROSS-ACCOUNT-DATA-READ-UNDETERMINED row is present');
  return row.partialFingerprints[FINGERPRINT_KEY];
}

// ============================================================================
// DELIMITER (pipe) injection on the POSITIVE resource list must not forge a collision,
// measured on the ACTUAL emitted SARIF result identity.
// ============================================================================

test('NEW-02: a pipe inside a positive Resource ARN cannot forge a colliding SARIF fingerprint', () => {
  // A grants a read of TWO buckets; B grants a read of ONE oddly-named resource that
  // literally contains the '|' identity delimiter. Distinct grants a raw "|"-join collapsed.
  const a = readRow(['arn:aws:s3:::pipe-a/*', 'arn:aws:s3:::pipe-b/*']);
  const b = readRow(['arn:aws:s3:::pipe-a/*|arn:aws:s3:::pipe-b/*']);
  assert.notEqual(fpOf(a), fpOf(b),
    'a "|"-bearing single positive resource must NOT collide with a two-element resource list');
});

test('NEW-02: the reproduced A-vs-B positive-resource forgery pair gets DISTINCT SARIF fingerprints', () => {
  // The exact pair from the story reproduction (a/*,b/* vs a/*|b/*).
  const a = readRow(['arn:aws:s3:::a/*', 'arn:aws:s3:::b/*']);
  const b = readRow(['arn:aws:s3:::a/*|arn:aws:s3:::b/*']);
  assert.notEqual(fpOf(a), fpOf(b),
    'dismissing A must not auto-suppress the distinct live B (positive-list forgery closed)');
});

// ============================================================================
// findingIdentity encodes the POSITIVE lists injectively (delimiter + newline), on all
// three positive channels - actions, resources, principals.
// ============================================================================

test('NEW-02: findingIdentity encodes positive resources injectively (delimiter + newline)', () => {
  const base = {
    id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', severity: 'info', title: 't',
    statementIndex: 0, statementSid: 'S', actions: ['s3:GetObject'], conditions: null,
  };
  const two = { ...base, resources: ['arn:aws:s3:::a/*', 'arn:aws:s3:::b/*'] };
  const onePipe = { ...base, resources: ['arn:aws:s3:::a/*|arn:aws:s3:::b/*'] };
  assert.notEqual(findingIdentity(onePipe, 'identity'), findingIdentity(two, 'identity'),
    'a "|"-bearing single resource must not collapse to the two-element identity');

  // A newline in a token must not inject a fresh "key=value" identity line (forging escService).
  const oneNl = { ...base, resources: ['arn:aws:s3:::a/*\nescService=forged'] };
  const plain = { ...base, resources: ['arn:aws:s3:::a/*'] };
  assert.notEqual(findingIdentity(oneNl, 'identity'), findingIdentity(plain, 'identity'),
    'a newline-bearing resource must be encoded, not injected as a new identity line');
  assert.ok(!/\nescService=forged/.test(findingIdentity(oneNl, 'identity')),
    'a forged escService line must not appear as a live identity part via a resource token');
});

test('NEW-02: findingIdentity encodes positive actions injectively (delimiter + newline)', () => {
  const base = {
    id: 'WILDCARD-RESOURCE', severity: 'high', title: 't',
    statementIndex: 0, statementSid: 'S', resources: ['*'], conditions: null,
  };
  // Tokens chosen already-lowercased + sorted so the two-element join is byte-identical to
  // the single "|"-bearing token - the exact shape a raw "|"-join collided (case/sort cannot
  // save it). Actions are lowercased by normList.
  const two = { ...base, actions: ['alpha:read', 'bravo:read'] };
  const onePipe = { ...base, actions: ['alpha:read|bravo:read'] };
  assert.notEqual(findingIdentity(onePipe, 'identity'), findingIdentity(two, 'identity'),
    'a "|"-bearing single action must not collapse to the two-element action identity');
});

test('NEW-02: findingIdentity encodes positive principals injectively (delimiter + newline)', () => {
  const base = {
    id: 'TRUST-CROSS-ACCOUNT', severity: 'high', title: 't',
    statementIndex: 0, statementSid: 'S', actions: ['sts:AssumeRole'], resources: [], conditions: null,
  };
  // findingPrincipals maps an array of principal tokens verbatim (normList). Two distinct
  // principals vs one that carries the '|' delimiter inside a single value - the shape a plain
  // '|' join collapsed (the Principal-OBJECT form prefixes each element and would not collide).
  const two = { ...base, principals: ['arn:aws:iam::111122223333:root', 'arn:aws:iam::444455556666:root'] };
  const onePipe = { ...base, principals: ['arn:aws:iam::111122223333:root|arn:aws:iam::444455556666:root'] };
  assert.notEqual(findingIdentity(onePipe, 'identity'), findingIdentity(two, 'identity'),
    'a "|"-bearing single principal must not collapse to the two-element principal identity');

  const oneNl = { ...base, principals: ['arn:aws:iam::111122223333:root\nescTechnique=forged'] };
  const plain = { ...base, principals: ['arn:aws:iam::111122223333:root'] };
  assert.notEqual(findingIdentity(oneNl, 'identity'), findingIdentity(plain, 'identity'),
    'a newline-bearing principal must be encoded, not injected as a new identity line');
  assert.ok(!/\nescTechnique=forged/.test(findingIdentity(oneNl, 'identity')),
    'a forged escTechnique line must not appear as a live identity part via a principal token');
});

// A synthetic finding carrying a hostile multi-principal list, driven through the REAL
// emitted SARIF (buildSarifLog), proves the principal channel is injective + inert on the
// actual artifact (no real rule reliably emits a top-level multi-principal positive list).
test('NEW-02: a pipe-bearing principal cannot forge a colliding fingerprint in the emitted SARIF', () => {
  const mk = (principals) => {
    const finding = {
      id: 'TRUST-CROSS-ACCOUNT', severity: 'high', title: 't', statementIndex: 0,
      statementSid: 'S', actions: ['sts:AssumeRole'], resources: [], conditions: null, principals,
    };
    const result = { family: 'role-trust', findings: [finding], analysisStates: [] };
    const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
    return log.runs[0].results.find((r) => r.ruleId === 'TRUST-CROSS-ACCOUNT');
  };
  const a = mk(['arn:aws:iam::111122223333:root', 'arn:aws:iam::444455556666:root']);
  const b = mk(['arn:aws:iam::111122223333:root|arn:aws:iam::444455556666:root']);
  assert.notEqual(fpOf(a), fpOf(b),
    'a "|"-bearing single principal must NOT collide with a two-element principal list in the SARIF');
});

// ============================================================================
// INERT + non-forging: a '|' and a newline token ride the identity hash but never
// break the rendered SARIF (control-free) or forge a live identity line.
// ============================================================================

test('NEW-02: a pipe/newline-bearing resource stays inert in the emitted SARIF and non-forging', () => {
  const finding = {
    id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', severity: 'info', title: 't', statementIndex: 0,
    statementSid: 'S', actions: ['s3:GetObject'],
    resources: ['arn:aws:s3:::a/*|escService=forged\nescTechnique=forged'], conditions: null,
  };
  const result = { family: 'identity', findings: [finding], analysisStates: [] };
  const bytes = formatSarif(result, { file: 'p.json' }, MANIFEST);
  // The emitted document must remain valid JSON and free of raw control chars in its strings.
  const log = JSON.parse(bytes);
  const row = log.runs[0].results.find((r) => r.ruleId === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.ok(row, 'row present');
  const fp = row.partialFingerprints[FINGERPRINT_KEY];
  assert.equal(typeof fp, 'string', 'a fingerprint is emitted');
  assert.ok(!CONTROL.test(fp) && !BIDI_ZW.test(fp), 'the fingerprint hash is control-free');
  // The identity string never grows a LIVE escService/escTechnique line from the token.
  const id = findingIdentity(finding, 'identity');
  assert.ok(!/\nescService=forged/.test(id) && !/\nescTechnique=forged/.test(id),
    'a forged escService/escTechnique identity line must not appear');
});

// ============================================================================
// NO CHURN: an ORDINARY finding (benign tokens: no '\', '|', or newline) keeps its exact
// pre-fix identity string and fingerprint - the injective helper is byte-identical to a
// plain "|"-join for every real ARN / action / principal.
// ============================================================================

test('NEW-02: an ordinary multi-resource finding identity is byte-for-byte the plain-join form (no churn)', () => {
  const finding = {
    id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED', severity: 'info', title: 't', statementIndex: 0,
    statementSid: 'S', actions: ['s3:getobject', 's3:listbucket'],
    resources: ['arn:aws:s3:::a/*', 'arn:aws:s3:::b/*'], conditions: null,
  };
  const id = findingIdentity(finding, 'identity');
  // The pre-fix plain-join form of each positive line, reconstructed independently.
  assert.ok(id.includes('actions=s3:getobject|s3:listbucket'),
    'benign sorted action list is joined exactly as the plain "|"-join produced');
  assert.ok(id.includes('resources=arn:aws:s3:::a/*|arn:aws:s3:::b/*'),
    'benign sorted resource list is joined exactly as the plain "|"-join produced');
  // Equivalent order / case / scalar-vs-list must not churn the identity.
  const reordered = { ...finding, resources: ['arn:aws:s3:::b/*', 'arn:aws:s3:::a/*'] };
  assert.equal(findingIdentity(reordered, 'identity'), id, 'resource order does not churn identity');
});

test('NEW-02: an ordinary finding SARIF fingerprint is stable + byte-identical across builds', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
  });
  const result = scan({ text, family: 'identity' });
  assert.equal(
    formatSarif(result, { file: 'p.json' }, MANIFEST),
    formatSarif(result, { file: 'p.json' }, MANIFEST),
    'deterministic SARIF for an ordinary finding',
  );
});
