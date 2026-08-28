// S1-dataexfil-arn (iteration 5): the broadness test is now SEMANTIC. A Resource
// value is judged broad by interpreting it as an AWS resource GLOB (case-sensitive,
// '*' = any run incl. empty, '?' = exactly one char) and testing what it MATCHES
// against a fixed battery of diverse canonical probe ARNs spanning multiple accounts
// and services: a value reaching across >= 2 distinct accounts is broad. This
// replaces the leaky arn:-prefix / startsWith('*') shape enumeration that let the
// adversarial hunter re-spell the SAME boundary-crossing class around the checks.
//
// This suite locks, at the shipped-engine analyze() AND CLI scan() level:
//   1. the NON-arn glob fail-opens the hunter reproduced ('*/*','?*','**','*:*',
//      'arn*') now fire DATA-EXFIL:high and drive a non-zero CLI exit;
//   2. spelling-agnostic robustness: further NEW spellings of the same class are
//      also caught (no new shape branch was added for any of them);
//   3. no over-firing: genuinely scoped, single-resource ARNs (and concrete
//      non-ARN resource strings) stay clean - the negative corpus must not move.
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';

const BROAD_IDS = new Set(['DATA-EXFIL', 'WILDCARD-RESOURCE']);

function policyText(action, resource) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'S', Effect: 'Allow', Action: action, Resource: resource }],
  });
}

function findingIds(result) {
  return result.ok ? result.findings.map((f) => f.id) : [];
}

// --- The non-ARN glob fail-opens the hunter reproduced ------------------------
// Each is a bulk object read whose Resource carries NO 'arn:' prefix yet spans
// essentially every resource. All previously returned findings=[] exit 0 CLEAN.
const NON_ARN_GLOBS = ['*/*', '?*', '**', '*:*', 'arn*'];

test('non-ARN glob resources fire DATA-EXFIL:high on analyze() (fail-CLOSED)', () => {
  for (const resource of NON_ARN_GLOBS) {
    const result = analyze(policyText('s3:GetObject', resource));
    assert.equal(result.ok, true, `${resource}: expected a clean analysis`);
    const ids = findingIds(result);
    assert.ok(ids.includes('DATA-EXFIL'), `${resource}: MUST fire DATA-EXFIL; got [${ids.join(', ')}]`);
    const exfil = result.findings.filter((f) => f.id === 'DATA-EXFIL');
    for (const f of exfil) {
      assert.equal(f.severity, 'high', `${resource}: DATA-EXFIL must be high, got ${f.severity}`);
    }
    // GetObject is a read verb: the resource-scope WILDCARD-RESOURCE rule (non-read
    // only) must NOT fire, so the broadness fix does not manufacture a false extra.
    assert.ok(!ids.includes('WILDCARD-RESOURCE'), `${resource}: read verb must not fire WILDCARD-RESOURCE`);
  }
});

test('non-ARN glob resources drive a non-zero CLI exit via scan() (blocking)', () => {
  for (const resource of NON_ARN_GLOBS) {
    const r = scan({ text: policyText('s3:GetObject', resource), family: 'identity' });
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE,
      `${resource}: expected a complete analysis; got ${r.analysisStatus}`);
    assert.equal(r.exitCode, EXIT.FINDINGS, `${resource}: expected exit ${EXIT.FINDINGS}; got ${r.exitCode}`);
    assert.notEqual(r.exitCode, EXIT.CLEAN, `${resource}: must not exit 0/clean on a risky policy`);
    assert.ok(r.blockingCount >= 1, `${resource}: expected blockingCount>=1; got ${r.blockingCount}`);
  }
});

// A non-read (mutating) action on the same non-ARN globs is a broad resource scope:
// WILDCARD-RESOURCE:high must fire (the same predicate feeds it).
test('non-ARN glob resources fire WILDCARD-RESOURCE:high for a non-read action', () => {
  for (const resource of NON_ARN_GLOBS) {
    const result = analyze(policyText('s3:PutObject', resource));
    assert.equal(result.ok, true, `${resource}: expected a clean analysis`);
    const wr = result.findings.filter((f) => f.id === 'WILDCARD-RESOURCE');
    assert.ok(wr.length > 0, `${resource}: MUST fire WILDCARD-RESOURCE for a non-read action`);
    for (const f of wr) assert.equal(f.severity, 'high', `${resource}: WILDCARD-RESOURCE must be high`);
  }
});

// --- Spelling-agnostic robustness --------------------------------------------
// NEW spellings of the SAME boundary-crossing class must ALSO be caught, proving
// the predicate is semantic (matches diverse probes) and not shape-enumerated.
// None of these has a dedicated branch anywhere in the engine.
const NEW_SPELLINGS = [
  '*/**',            // path glob, extra star
  '*?*',             // any run around a mandatory char (every non-empty resource)
  'arn:*',           // arn then any run (single colon)
  '*:*:*',           // multi-colon glob
  'arn?*',           // arn, one char, any run (every ARN)
];

test('new spellings of the boundary-crossing class are also flagged (semantic, not enumerated)', () => {
  for (const resource of NEW_SPELLINGS) {
    const result = analyze(policyText('s3:GetObject', resource));
    assert.equal(result.ok, true, `${resource}: expected a clean analysis`);
    const ids = findingIds(result);
    assert.ok(ids.includes('DATA-EXFIL'), `${resource}: MUST fire DATA-EXFIL (fail-open); got [${ids.join(', ')}]`);
  }
});

// --- No over-firing: scoped resources stay quiet ------------------------------
// A resource pinned to ONE concrete resource (arn or non-arn) matches < 2 probe
// accounts and must NOT be treated as broad - the negative corpus must hold.
const SCOPED_QUIET = [
  'arn:aws:s3:::my-bucket/*',
  'arn:aws:s3:::my-bucket/prefix/*',
  'arn:aws:s3:::example-bucket',
  'arn:aws:iam::123456789012:role/app-team/*',
  'arn:aws:iam::123456789012:role/deployment/*',
  'arn:aws:iam::111122223333:role/app-worker-readonly',
  'arn:aws:kms:us-east-1:123456789012:key/abcd',
  'arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap/object/*',
  'arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-abc/bucket/my-bucket/object/*',
  'arn:aws:sqs:us-east-1:123456789012:app-events',
  // concrete NON-arn resource strings must not read as broad either
  'my-plain-resource',
  'https://evil.example.com/leak',
];

test('scoped single-resource values stay quiet on analyze() (no over-firing)', () => {
  for (const resource of SCOPED_QUIET) {
    const result = analyze(policyText('s3:GetObject', resource));
    assert.equal(result.ok, true, `${resource}: expected a clean analysis`);
    const ids = findingIds(result);
    for (const id of ids) {
      assert.ok(!BROAD_IDS.has(id), `${resource}: must NOT fire broad-scope ${id}; got [${ids.join(', ')}]`);
    }
  }
});

test('scoped single-resource read exits CLEAN via scan()', () => {
  for (const resource of SCOPED_QUIET) {
    const r = scan({ text: policyText('s3:GetObject', resource), family: 'identity' });
    // Some scoped names infer sensitivity (DATA-READ, medium) but that never blocks
    // at the default high threshold; the point is no broad-scope block appears.
    assert.notEqual(r.exitCode, EXIT.ERROR, `${resource}: unexpected adapter error`);
    assert.ok(r.blockingCount === 0 || r.exitCode === EXIT.CLEAN,
      `${resource}: a scoped read must not BLOCK on a broad-scope finding; got exit ${r.exitCode} blocking ${r.blockingCount}`);
  }
});

// --- Determinism --------------------------------------------------------------
test('broadness classification is deterministic', () => {
  for (const resource of [...NON_ARN_GLOBS, ...NEW_SPELLINGS, ...SCOPED_QUIET]) {
    const t = policyText('s3:GetObject', resource);
    assert.deepEqual(analyze(t), analyze(t), `${resource}: analyze() must be deterministic`);
  }
});
