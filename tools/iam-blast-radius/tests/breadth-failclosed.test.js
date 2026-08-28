// S1-breadth-failclosed: close the RESOURCE-BREADTH fail-open CLASS.
//
// ROOT UNSOUNDNESS this locks: the semantic probe battery (BROADNESS_PROBES) can
// only ever PROVE a Resource value BROAD (matches >= 2 probe accounts); it can
// NEVER prove a value NARROW. isBroadArnResource() nonetheless treated "matched
// < 2 probes" as a DEFINITIVE narrow verdict, so two whole classes of risky value
// slipped through and returned a bare CLEAN (ok:true, findings=[], incomplete=false)
// on a bulk s3:GetObject / s3:PutObject:
//
//   (1) NON-ARN, non-star globs whose suffix/infix defeats every fixed-key probe:
//       */*.pem, *.pem, *.key, *.env, *.txt, *log, *-prod. These are MALFORMED per
//       the AWS IAM grammar (a Resource must be "*" or an ARN); the engine cannot
//       decide their scope, so they are routed to coverage.summary.incomplete
//       (MALFORMED_RESOURCE_ARN) - fail CLOSED, never a fabricated confident finding.
//
//   (2) arn:-shaped values whose wildcard spans the account-less S3 bucket namespace
//       from a CONCRETE prefix: arn:aws:s3:::my-bucket-*/*.pem, arn:aws:s3:::probe-*/*.pem.
//       A bucket-name-segment wildcard spans MANY buckets (across accounts), so it is
//       BROAD and must FIRE (DATA-EXFIL / WILDCARD-RESOURCE).
//
// The class guarantee: a Resource value is fail-CLOSED either way - provably broad
// (fires) or undecidable (incomplete) - and NEVER a bare CLEAN. This is decided by
// the arn:-shape GRAMMAR + a structural bucket-name-wildcard check, not by which
// probes happen to match, so no NEW spelling can re-open it.
//
// ANTI-OVER-CORRECTION: a wildcard that scopes WITHIN one concrete named
// resource+account stays NARROW (arn:aws:s3:::my-bucket/prefix/*,
// arn:aws:iam::123456789012:role/app-*), and the must-keep-firing broad controls
// keep firing.
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';
import { isBroadArnResource } from '../../../content/tools/iam-blast-radius/engine/rules.js';
import { detectMaskedGrants, MASKED_GRANT_CODES } from '../../../content/tools/iam-blast-radius/engine/masked-grant.js';
import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';

const BROAD_IDS = new Set(['DATA-EXFIL', 'WILDCARD-RESOURCE']);

function policyText(action, resource) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'S', Effect: 'Allow', Action: action, Resource: resource }],
  });
}

function isClean(result) {
  // The browser-cli-parity "clean" invariant.
  return !!(result && result.ok === true
    && Array.isArray(result.findings) && result.findings.length === 0
    && !(result.coverage && result.coverage.summary && result.coverage.summary.incomplete));
}
function findingIds(result) {
  return result.ok ? result.findings.map((f) => f.id) : [];
}
function incomplete(result) {
  return !!(result.coverage && result.coverage.summary && result.coverage.summary.incomplete);
}

// --- The reproduced fail-opens ------------------------------------------------
// (1) non-ARN suffix/infix globs: undecidable -> INCOMPLETE (never bare CLEAN).
const NON_ARN_UNDECIDABLE = ['*/*.pem', '*.pem', '*.key', '*.env', '*.txt', '*log', '*-prod'];
// (2) arn:-shaped bucket-name-prefix wildcards: BROAD -> must FIRE.
const ARN_COMPONENT_BROAD = ['arn:aws:s3:::my-bucket-*/*.pem', 'arn:aws:s3:::probe-*/*.pem'];

for (const action of ['s3:GetObject', 's3:PutObject']) {
  test(`(1) non-ARN undecidable globs are never bare CLEAN on analyze() [${action}]`, () => {
    for (const resource of NON_ARN_UNDECIDABLE) {
      const r = analyze(policyText(action, resource));
      assert.equal(r.ok, true, `${resource}: expected a well-formed analysis`);
      assert.equal(isClean(r), false, `${resource}: MUST NOT be a bare CLEAN (fail-open, T8)`);
      // The class treatment is INCOMPLETE (undecidable), not a fabricated finding.
      assert.equal(incomplete(r), true, `${resource}: undecidable value must mark coverage incomplete`);
      const codes = r.coverage.summary.codes;
      assert.ok(codes.includes('MALFORMED_RESOURCE_ARN'), `${resource}: carries MALFORMED_RESOURCE_ARN; got [${codes.join(', ')}]`);
    }
  });

  test(`(1) non-ARN undecidable globs drive a non-zero, fail-closed CLI exit [${action}]`, () => {
    for (const resource of NON_ARN_UNDECIDABLE) {
      const r = scan({ text: policyText(action, resource), family: 'identity' });
      assert.notEqual(r.exitCode, EXIT.CLEAN, `${resource}: must NOT exit 0/clean on a risky policy`);
      assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `${resource}: expected fail-closed exit 3; got ${r.exitCode}`);
      assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED, `${resource}: expected FAILED status`);
      assert.equal(r.reason, 'MALFORMED_RESOURCE_ARN', `${resource}: expected MALFORMED_RESOURCE_ARN reason; got ${r.reason}`);
    }
  });

  test(`(2) arn: bucket-name-prefix wildcards FIRE a broad finding on analyze() [${action}]`, () => {
    for (const resource of ARN_COMPONENT_BROAD) {
      const r = analyze(policyText(action, resource));
      assert.equal(r.ok, true, `${resource}: expected a well-formed analysis`);
      assert.equal(isClean(r), false, `${resource}: MUST NOT be a bare CLEAN (fail-open, T8)`);
      const ids = findingIds(r);
      assert.ok(ids.some((id) => BROAD_IDS.has(id)), `${resource}: MUST fire a broad-scope finding; got [${ids.join(', ')}]`);
      // GetObject (read) -> DATA-EXFIL; PutObject (write) -> WILDCARD-RESOURCE.
      const expected = action === 's3:GetObject' ? 'DATA-EXFIL' : 'WILDCARD-RESOURCE';
      assert.ok(ids.includes(expected), `${resource}: MUST fire ${expected} for ${action}; got [${ids.join(', ')}]`);
    }
  });

  test(`(2) arn: bucket-name-prefix wildcards drive a non-zero CLI exit [${action}]`, () => {
    for (const resource of ARN_COMPONENT_BROAD) {
      const r = scan({ text: policyText(action, resource), family: 'identity' });
      assert.notEqual(r.exitCode, EXIT.CLEAN, `${resource}: must NOT exit 0/clean on a risky policy`);
      assert.ok(r.exitCode !== EXIT.CLEAN && r.blockingCount >= 1, `${resource}: expected a blocking finding; got exit ${r.exitCode} blocking ${r.blockingCount}`);
    }
  });
}

// isBroadArnResource, at the predicate level, proves the fix(2) structural rule.
test('fix(2): a plain-S3 bucket-name-segment wildcard is BROAD regardless of position', () => {
  for (const r of ARN_COMPONENT_BROAD) {
    assert.equal(isBroadArnResource(r), true, `${r}: bucket-name wildcard must be broad`);
  }
  assert.equal(isBroadArnResource('arn:aws:s3:::my-bucket-*'), true, 'trailing bucket wildcard is broad');
  assert.equal(isBroadArnResource('arn:aws:s3:::pre*fix/key'), true, 'interior bucket wildcard is broad');
});

// --- ITERATION-2 BLOCKER: S3 bucket-name wildcard dressed with spurious region/
// account segments must NOT read narrow. A canonical S3 bucket ARN has empty
// region+account; a populated region and/or account on a bucket-name ARN is itself
// MALFORMED and must NEVER be a narrowing signal. Because the value starts with
// "arn:", masked-grant's (non-ARN-only) MALFORMED_RESOURCE_ARN path does not catch
// it, so the ONLY defense is the rules breadth check - it must fire regardless of
// the region/account segments. A concrete trailing key (…/key.pem) makes the value
// match ZERO fixed-key probes, so the finite probe battery reads it narrow: this is
// exactly the fail-open the structural s3-head check closes.
const ARN_DECORATED_BUCKET_WILDCARD_BROAD = [
  'arn:aws:s3:us-east-1::my-bucket-*/key.pem',
  'arn:aws:s3::123456789012:my-bucket-*/config.json',
  'arn:aws:s3:us-east-1:123456789012:corp-*/db.sql',
  'arn:aws:s3:us-east-1::prod-*',
  'arn:aws:s3:x::my-bucket-*/a',
  'arn:aws:s3:0:0:my-bucket-*/a',
];

test('iter2 fix: a spurious region/account is never a narrowing signal on an S3 bucket-name wildcard', () => {
  for (const r of ARN_DECORATED_BUCKET_WILDCARD_BROAD) {
    assert.equal(isBroadArnResource(r), true, `${r}: decorated bucket-name wildcard must be broad`);
  }
  // The canonical twin (empty region+account) already fires and must keep firing.
  assert.equal(isBroadArnResource('arn:aws:s3:::my-bucket-*/key.pem'), true);
});

for (const action of ['s3:GetObject', 's3:PutObject']) {
  test(`iter2 fix: decorated S3 bucket-name wildcards are never bare CLEAN on analyze() [${action}]`, () => {
    for (const resource of ARN_DECORATED_BUCKET_WILDCARD_BROAD) {
      const r = analyze(policyText(action, resource));
      assert.equal(r.ok, true, `${resource}: expected a well-formed analysis`);
      assert.equal(isClean(r), false, `${resource}: MUST NOT be a bare CLEAN (fail-open, T8)`);
      const ids = findingIds(r);
      assert.ok(ids.some((id) => BROAD_IDS.has(id)), `${resource}: MUST fire a broad-scope finding; got [${ids.join(', ')}]`);
      const expected = action === 's3:GetObject' ? 'DATA-EXFIL' : 'WILDCARD-RESOURCE';
      assert.ok(ids.includes(expected), `${resource}: MUST fire ${expected} for ${action}; got [${ids.join(', ')}]`);
    }
  });

  test(`iter2 fix: decorated S3 bucket-name wildcards drive a non-zero CLI exit [${action}]`, () => {
    for (const resource of ARN_DECORATED_BUCKET_WILDCARD_BROAD) {
      const r = scan({ text: policyText(action, resource), family: 'identity' });
      assert.notEqual(r.exitCode, EXIT.CLEAN, `${resource}: must NOT exit 0/clean on a risky policy`);
      assert.ok(r.blockingCount >= 1, `${resource}: expected a blocking finding; got exit ${r.exitCode} blocking ${r.blockingCount}`);
    }
  });
}

// The class boundary the fix must NOT overshoot: an s3-outposts bucket ARN pins a
// MEANINGFUL, concrete account+outpost, so a concrete-prefix bucket wildcard scopes
// WITHIN one account (narrow, like role/app-*); only its whole-collection leading
// wildcard is broad (locked by the must-warn corpus). Valid non-bucket S3 ARNs carry
// a concrete type-keyword head and stay narrow. Firing on these would be an
// over-correction / false positive.
const ITER2_MUST_STAY_NARROW = [
  'arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-abc/bucket/my-bucket-*/object/key',
  'arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-abc/bucket/prod-*',
  'arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap/object/*',
  'arn:aws:s3:us-east-1:123456789012:job/my-job-id',
  'arn:aws:s3:us-east-1:123456789012:storage-lens/my-config',
];

test('iter2 anti-over-correction: concrete-account S3/S3-outposts ARNs stay narrow', () => {
  for (const r of ITER2_MUST_STAY_NARROW) {
    assert.equal(isBroadArnResource(r), false, `${r}: concrete-account-scoped ARN must stay narrow`);
    const res = analyze(policyText('s3:GetObject', r));
    assert.equal(res.ok, true, `${r}: well-formed`);
    assert.equal(incomplete(res), false, `${r}: a decided narrow ARN must NOT mark incomplete`);
    for (const id of findingIds(res)) {
      assert.ok(!BROAD_IDS.has(id), `${r}: must NOT fire broad-scope ${id}`);
    }
  }
});

// --- ANTI-OVER-CORRECTION: these MUST stay NARROW (no broad finding, no incomplete)
const MUST_STAY_NARROW = [
  { resource: 'arn:aws:s3:::my-bucket/prefix/*', action: 's3:GetObject' },
  { resource: 'arn:aws:iam::123456789012:role/app-*', action: 'iam:GetRole' },
];

test('anti-over-correction: a wildcard scoped WITHIN one concrete resource+account stays narrow', () => {
  for (const { resource, action } of MUST_STAY_NARROW) {
    assert.equal(isBroadArnResource(resource), false, `${resource}: must NOT be classified broad`);
    const r = analyze(policyText(action, resource));
    assert.equal(r.ok, true, `${resource}: well-formed`);
    assert.equal(incomplete(r), false, `${resource}: a decided narrow ARN must NOT mark incomplete`);
    for (const id of findingIds(r)) {
      assert.ok(!BROAD_IDS.has(id), `${resource}: must NOT fire broad-scope ${id}`);
    }
    // A decided, scoped ARN is a fully CLEAN analysis here (no finding + not incomplete).
    assert.equal(isClean(r), true, `${resource}: a scoped, decided ARN must analyze CLEAN`);
  }
});

test('anti-over-correction: no MALFORMED_RESOURCE_ARN masked grant on a scoped ARN', () => {
  for (const { resource } of MUST_STAY_NARROW) {
    const m = modelFromText(policyText('s3:GetObject', resource));
    assert.equal(m.ok, true);
    const grants = detectMaskedGrants(m.model);
    assert.ok(!grants.some((g) => g.code === MASKED_GRANT_CODES.MALFORMED_RESOURCE_ARN),
      `${resource}: a decided ARN must not be flagged MALFORMED_RESOURCE_ARN`);
  }
});

// --- MUST-KEEP-FIRING: the broad controls the corpus already locks ------------
const MUST_KEEP_BROAD = [
  '*',
  'arn:aws:s3:::*/*',
  'arn:aws:s3:::*-prod/*.pem',
  'arn:aws:s3:::*/private/*',
  'arn:aws:iam::*:role/*-prod',
  'arn:*:s3:::my-bucket/*',
];

test('must-keep-firing: every locked broad control stays broad', () => {
  for (const r of MUST_KEEP_BROAD) {
    assert.equal(isBroadArnResource(r), true, `${r}: must remain broad`);
  }
});

test('must-keep-firing: broad controls are never a bare CLEAN through analyze()', () => {
  for (const r of MUST_KEEP_BROAD) {
    // A mutating action so WILDCARD-RESOURCE is in play for the ARN forms; "*" and
    // s3 forms fire DATA-EXFIL / WILDCARD-RESOURCE either way.
    const res = analyze(policyText('s3:PutObject', r));
    assert.equal(isClean(res), false, `${r}: a broad control must never read CLEAN`);
  }
});

// --- Non-ARN detection is Allow-only (a malformed Deny resource does not mask) --
test('a non-ARN Resource on a DENY statement is not flagged (Allow-only, no false incomplete)', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'Allow', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::my-bucket/*' },
      { Sid: 'Deny', Effect: 'Deny', Action: 's3:GetObject', Resource: '*.pem' },
    ],
  });
  const m = modelFromText(text);
  assert.equal(m.ok, true);
  const grants = detectMaskedGrants(m.model);
  assert.ok(!grants.some((g) => g.code === MASKED_GRANT_CODES.MALFORMED_RESOURCE_ARN),
    'a malformed Deny resource must not be flagged (Allow-only)');
});

// --- Determinism --------------------------------------------------------------
test('breadth classification is deterministic', () => {
  for (const resource of [...NON_ARN_UNDECIDABLE, ...ARN_COMPONENT_BROAD, ...MUST_KEEP_BROAD]) {
    const t = policyText('s3:GetObject', resource);
    assert.deepEqual(analyze(t), analyze(t), `${resource}: analyze() must be deterministic`);
  }
});
