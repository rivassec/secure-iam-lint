// RELEASE GATE (opt-in): at release time, GREEN must NOT mean "known holes still allowed".
//
// The plain harness run keeps the confirmed fail-opens as node:test `todo`s so the suite
// stays green during the remediation window (see golden-oracle.test.js and
// packaging.test.js). That is deliberate - but it means a passing run can still hide
// unfixed fail-opens, and the manifest PINs even encode the vulnerable baseline as the
// "expected" value. This file closes that gap: when GOLDEN_RELEASE_GATE=1 it HARD-FAILS
// if ANY known-open case still reproduces its fail-open. Ship only when this is green.
//
//   plain run  :  node --test audit/golden-corpus/                  (todos stay green)
//   release run:  GOLDEN_RELEASE_GATE=1 node --test audit/golden-corpus/release-gate.test.js
//
// The gate is INACTIVE (every check skips) unless GOLDEN_RELEASE_GATE=1, so it never
// disturbs the normal green run.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, symlinkSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { scan, EXIT, ANALYSIS_STATUS } from '../../../../cli/scan.mjs';
import { buildSarifLog, findingIdentity, FINGERPRINT_KEY } from '../../../../cli/sarif.mjs';
import { analyze } from '../../../../content/tools/iam-blast-radius/engine/analyze.js';
import { CASES, scanInputFor, analyzeOptionsFor, corpusText } from './manifest.mjs';

const GATE = process.env.GOLDEN_RELEASE_GATE === '1';
const skip = GATE ? false : 'release gate inactive (set GOLDEN_RELEASE_GATE=1 to enforce)';

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(here, '..', '..', '..', '..');
const CLI = join(REPO_ROOT, 'cli', 'iam-br.mjs');
const ADMIN_FIXTURE = join(here, 'corpus', '01-admin-full.json');

// The known-open BEHAVIOURAL cases (manifest `knownOpen`): the fail-open reproduces while
// the current exit still equals the pinned buggy exit. At release time it must be fixed.
for (const c of CASES.filter((x) => x.knownOpen)) {
  test(`RELEASE-GATE: known-open '${c.id}' (${c.knownOpen.bug}) must be FIXED`, { skip }, () => {
    const sr = scan(scanInputFor(c));
    assert.notEqual(
      sr.exitCode,
      c.knownOpen.currentExit,
      `${c.id}: fail-open STILL reproduces - exit ${sr.exitCode} equals the known-open pin `
        + `${c.knownOpen.currentExit}; bug '${c.knownOpen.bug}' (${c.knownOpen.ref}) is not fixed`,
    );
    assert.notEqual(sr.exitCode, EXIT.CLEAN, `${c.id}: a risky policy must never be a clean pass at release`);
  });
}

// The two S3-rules-breadth effective-breadth-miss fixes (story S3-rules-breadth): each
// was a known fail-open where a risky policy read CLEAN. They are no longer manifest
// `knownOpen` (fixed), so the loop above no longer covers them; the release gate
// re-verifies at ship time that neither regresses to a clean exit-0 on a risky policy.
const S3_BREADTH_FIXED = Object.freeze([
  { id: 'notresource-write-severity', bug: 'syntax-keyed-severity',
    why: 'a NotResource-only broad non-read WILDCARD-RESOURCE must gate at high (exit != 0)' },
  { id: 'vacuous-notresource-deny-exfil', bug: 'vacuous-Deny-suppression',
    why: 'a vacuous NotResource Deny must NOT suppress DATA-EXFIL (exit != 0)' },
  { id: 'undecidable-notresource-deny-exfil', bug: 'vacuous-Deny-suppression',
    why: 'an UNDECIDABLE (MALFORMED spared-set) NotResource Deny must NOT suppress DATA-EXFIL (exit != 0)' },
  { id: 'notresource-deny-fences-surviving-whole-bucket', bug: 'deny-fence-surviving-spared-resource',
    why: 'a NARROW NotResource Deny that fences a broad exfil read to one WHOLE BUCKET must surface '
      + 'the surviving account-blind read (CROSS-ACCOUNT-DATA-READ-UNDETERMINED at info), never a clean exit-0' },
  { id: 'notresource-deny-fences-surviving-sensitive-bucket', bug: 'deny-fence-surviving-spared-resource',
    why: 'a fence sparing a SENSITIVELY-NAMED whole bucket (production-secrets/*) - the highest-value '
      + 'exfil target - must surface the surviving account-blind read, never a clean exit-0 (R1 iter-2)' },
  { id: 'notresource-complement-allow-deny-fences-surviving-whole-bucket', bug: 'surviving-spared-blind-to-complement-allow',
    why: 'a broad NotResource-COMPLEMENT Allow fenced down to one spared whole bucket must surface the '
      + 'surviving account-blind read (CROSS-ACCOUNT-DATA-READ-UNDETERMINED at info) exactly as the '
      + 'Resource:"*" form does, never a clean exit-0 (R1 iter-6 complement fail-open)' },
]);
for (const fixed of S3_BREADTH_FIXED) {
  test(`RELEASE-GATE: S3-rules-breadth '${fixed.id}' (${fixed.bug}) stays FIXED`, { skip }, () => {
    const c = CASES.find((x) => x.id === fixed.id);
    assert.ok(c, `manifest case '${fixed.id}' must exist`);
    const sr = scan(scanInputFor(c));
    assert.notEqual(sr.exitCode, EXIT.CLEAN,
      `${fixed.id}: risky policy must never be a clean exit-0 at release - ${fixed.why} (bug '${fixed.bug}')`);
    assert.equal(sr.exitCode, 1,
      `${fixed.id}: risky policy must exit 1 (findings) - ${fixed.why}`);
  });
}

// The S1-R1 iteration-3 OVER-CORRECTION fix (bug: surviving-spared-not-intersected-with-
// allow). survivingSparedContainerReads classified the RAW NotResource union without
// intersecting the broad Allow's own resource scope, so an ARN-WILDCARD broad Allow whose
// spared bucket falls OUTSIDE the grant fabricated a CROSS-ACCOUNT-DATA-READ-UNDETERMINED
// finding on a bucket the policy grants no access to (threat-model T8) - a false positive on
// a valid, effectively-SAFE policy. Fix: intersect the proven-surviving spared set with the
// Allow's own resource patterns. The release gate re-verifies at ship time that this
// effectively-safe input stays a genuine CLEAN pass with ZERO fabricated findings - so the
// fail-CLOSED R1 fix did not silently become a fail-into-noise regression.
test('RELEASE-GATE: S1-R1 over-correction (surviving-spared-not-intersected-with-allow) stays FIXED', { skip }, () => {
  const c = CASES.find((x) => x.id === 'notresource-deny-fences-uncovered-bucket-clean');
  assert.ok(c, "manifest case 'notresource-deny-fences-uncovered-bucket-clean' must exist");

  // The false positive gated at INFO; prove it is GONE at that threshold, both surfaces.
  for (const opts of [{}, { subjectAccount: '111111111111' }]) {
    const sr = scan({ ...scanInputFor(c), ...opts });
    assert.equal(sr.exitCode, EXIT.CLEAN,
      'effectively-safe ARN-wildcard-Allow + uncovered-spare must be a clean exit-0 (no fabricated finding)');
    assert.equal(sr.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'clean requires a complete analysis');
    assert.equal(sr.findingsCount, 0,
      'the spared bucket the Allow never grants must NOT fabricate a surviving-spared finding');

    const ar = analyze(corpusText(c.file), { ...analyzeOptionsFor(c), ...opts });
    const fabricated = (ar.findings || []).filter(
      (f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED' || f.id === 'CROSS-ACCOUNT-DATA-READ',
    );
    assert.equal(fabricated.length, 0,
      'browser must not fabricate a surviving-spared finding on a bucket outside the Allow grant either');
  }
});

// The S1-R1 iteration-4 OVER-CORRECTION fix (bug: surviving-spared-is-union-not-net-of-
// whole-deny-set). survivingSparedContainerReads unioned each NotResource fence's spared
// set and never subtracted what the REST of the Deny set removed, so a net-UNREADABLE
// policy (two mutually-exclusive fences, or a fence plus an explicit-Resource / blanket
// Deny) fabricated a surviving-spared CROSS-ACCOUNT-DATA-READ[-UNDETERMINED] finding
// (threat-model T8 noise). Fix: the surviving set is spared-by-fence MINUS denied-elsewhere
// (for the mutual-fence case, the INTERSECTION of the fences' spared sets = empty). The
// release gate re-verifies at ship time that each net-unreadable shape stays a genuine CLEAN
// pass with ZERO fabricated findings on BOTH surfaces - so the fail-CLOSED R1 fix did not
// silently regress into fail-into-noise.
test('RELEASE-GATE: S1-R1 over-correction (surviving-spared-is-union-not-net-of-whole-deny-set) stays FIXED', { skip }, () => {
  const c = CASES.find((x) => x.id === 'notresource-deny-fences-double-fenced-clean');
  assert.ok(c, "manifest case 'notresource-deny-fences-double-fenced-clean' must exist");

  // The corpus fixture (two mutually-exclusive NotResource fences) plus the explicit-Deny
  // and blanket-Deny variants - all net-ZERO readable. The false positive gated at INFO;
  // prove it is GONE at that threshold, both surfaces, with and without a subject account.
  const P = (st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
  const variants = [
    { label: 'two mutually-exclusive NotResource fences (corpus)', text: corpusText(c.file) },
    { label: 'fence + explicit Resource-Deny on the spared bucket', text: P([
      { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
      { Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
      { Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::acme-competitor-bucket/*' },
    ]) },
    { label: 'fence + blanket Deny s3:* Resource:*', text: P([
      { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
      { Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
      { Effect: 'Deny', Action: 's3:*', Resource: '*' },
    ]) },
  ];

  for (const v of variants) {
    for (const opts of [{}, { subjectAccount: '111111111111' }]) {
      const sr = scan({ text: v.text, family: 'identity', threshold: 'info', ...opts });
      assert.equal(sr.exitCode, EXIT.CLEAN,
        `${v.label}: net-unreadable policy must be a clean exit-0 (no fabricated finding)`);
      assert.equal(sr.analysisStatus, ANALYSIS_STATUS.COMPLETE, `${v.label}: clean requires a complete analysis`);
      assert.equal(sr.findingsCount, 0, `${v.label}: a net-unreadable spare must not fabricate any finding`);

      const ar = analyze(v.text, { family: 'identity', requireExplicitFamily: true, ...opts });
      const fabricated = (ar.findings || []).filter(
        (f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED' || f.id === 'CROSS-ACCOUNT-DATA-READ',
      );
      assert.equal(fabricated.length, 0,
        `${v.label}: browser must not fabricate a surviving-spared finding on a net-unreadable policy either`);
    }
  }
});

// The S1-R1 iteration-5 OVER-CORRECTION fix (bug: surviving-spared-subset-action-duplicate-
// report). When the spared bucket is ALSO an explicit Allow resource AND the fence covers
// only a STRICT ACTION-SUBSET of the Allow's reads, ruleDataReadScoped surfaced the Allow's
// own leg on that bucket with the FULL read set while the surviving-spared post-pass derived
// the SAME bucket on the FENCED subset - and the analyze.js dedup, keyed on exact action-set
// equality, let the subset row slip: TWO CROSS-ACCOUNT-DATA-READ-UNDETERMINED alerts (distinct
// fingerprints) for ONE surviving bucket, so dismissing one code-scanning alert left the other
// (threat-model T8 noise). Fix: SUBSET-aware dedup - a derived finding covered (same id +
// statement, resources subset, actions subset) by a broader table finding is dropped. The
// release gate re-verifies at ship time that the read still SURFACES (fail-closed) but as
// EXACTLY ONE row / ONE SARIF result per surviving bucket on BOTH surfaces - the noise fix did
// not silently drop the surviving capability, and the duplicate did not return.
test('RELEASE-GATE: S1-R1 over-correction (surviving-spared-subset-action-duplicate-report) stays FIXED', { skip }, () => {
  const c = CASES.find((x) => x.id === 'notresource-deny-fences-subset-action-explicit-allow');
  assert.ok(c, "manifest case 'notresource-deny-fences-subset-action-explicit-allow' must exist");

  const sr = scan(scanInputFor(c));
  // Still surfaces (fail-closed): never a clean exit-0 on a live surviving read.
  assert.notEqual(sr.exitCode, EXIT.CLEAN,
    'the surviving read must never be a clean exit-0 at release');
  assert.equal(sr.exitCode, 1, 'the surviving read gates at info -> exit 1');
  // But EXACTLY ONE derived row (no subset-action duplicate).
  const scanUndet = sr.findings.filter((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.equal(scanUndet.length, 1,
    `one surviving bucket must yield exactly one row (CLI), not a subset-action duplicate; got ${scanUndet.length}`);

  const ar = analyze(corpusText(c.file), analyzeOptionsFor(c));
  const browserUndet = (ar.findings || []).filter((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.equal(browserUndet.length, 1,
    `one surviving bucket must yield exactly one row (browser); got ${browserUndet.length}`);
  // The kept row carries the FULL surviving capability, not just the fenced subset.
  assert.deepEqual(browserUndet[0].actions.slice().sort(), ['s3:GetObject', 's3:ListBucket'],
    'the kept row reports the FULL surviving read set (the strict-subset derived row was dropped)');
});

// The S1-R1 iteration-6 OVER-CORRECTION guard (bug: surviving-spared-blind-to-complement-
// allow, no-false-positive half). The complement-aware grant test (allowGrantsSparedResource)
// must drop a spared bucket the complement Allow's OWN carve-out entirely excludes: {Allow
// s3:GetObject NotResource:acme/*} grants everything EXCEPT acme, and {Deny s3:GetObject
// NotResource:acme/*} spares ONLY acme - so the only Deny-readable bucket is the one the Allow
// refuses to grant -> net ZERO readable. The release gate re-verifies at ship time that this
// effectively-safe complement policy stays a genuine CLEAN pass with ZERO fabricated findings
// on BOTH surfaces - so the fail-CLOSED R1 iter-6 fix did not silently regress into fail-into-
// noise for the complement shape.
test('RELEASE-GATE: S1-R1 iter-6 over-correction (complement Allow excludes the spared bucket) stays CLEAN', { skip }, () => {
  const c = CASES.find((x) => x.id === 'notresource-complement-allow-excludes-spared-clean');
  assert.ok(c, "manifest case 'notresource-complement-allow-excludes-spared-clean' must exist");

  // The surviving-spared finding gates at INFO; prove there is none at that threshold, both
  // surfaces, with and without a subject account.
  for (const opts of [{}, { subjectAccount: '111111111111' }]) {
    const sr = scan({ ...scanInputFor(c), ...opts });
    assert.equal(sr.exitCode, EXIT.CLEAN,
      'a complement Allow that excludes its own spared bucket is net-ZERO readable -> clean exit-0');
    assert.equal(sr.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'clean requires a complete analysis');
    assert.equal(sr.findingsCount, 0,
      'the spared bucket the complement Allow excludes must NOT fabricate a surviving-spared finding');

    const ar = analyze(corpusText(c.file), { ...analyzeOptionsFor(c), ...opts });
    const fabricated = (ar.findings || []).filter(
      (f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED' || f.id === 'CROSS-ACCOUNT-DATA-READ',
    );
    assert.equal(fabricated.length, 0,
      'browser must not fabricate a surviving-spared finding on a net-unreadable complement policy either');
  }
});

// The S5-partition-parity fix (bug: defaulted-subject-partition-confident-demote): a
// DEFAULTED (absent) subject partition made analyze() (the browser) CONFIDENTLY demote a
// same-account cross-partition PassRole to medium and read CLEAN at the high threshold,
// while scan() (the CLI) failed closed - browser MORE permissive than CLI. It is no
// longer a manifest `knownOpen` (fixed); the release gate re-verifies at ship time that
// scan() still fails closed AND analyze() is not more permissive (surfaces the CRITICAL
// PassRole finding as unknown-viability, never a confident PARTITION_MISMATCH medium).
test('RELEASE-GATE: S5-partition-parity defaulted-partition PassRole stays FIXED (browser not more permissive)', { skip }, () => {
  const c = CASES.find((x) => x.id === 'passrole-defaulted-partition-unknown');
  assert.ok(c, "manifest case 'passrole-defaulted-partition-unknown' must exist");

  const sr = scan(scanInputFor(c));
  assert.notEqual(sr.exitCode, EXIT.CLEAN,
    'defaulted-partition PassRole must never be a clean exit-0 at release (CLI)');
  assert.equal(sr.exitCode, EXIT.FAIL_CLOSED, 'CLI must fail closed at exit 3 (unknown viability)');
  assert.equal(sr.analysisStatus, ANALYSIS_STATUS.PARTIAL, 'CLI analysisStatus must be partial');

  const ar = analyze(corpusText(c.file), analyzeOptionsFor(c));
  const browserClean = !!(ar && ar.ok === true
    && Array.isArray(ar.findings) && ar.findings.length === 0
    && !(ar.coverage && ar.coverage.summary && ar.coverage.summary.incomplete));
  assert.equal(browserClean, false, 'browser must not read clean while the CLI fails closed (parity)');
  const pr = (ar.findings || []).find((f) => f.id === 'PASSROLE-EC2');
  assert.ok(pr, 'browser must surface the PassRole path, never silently drop it');
  assert.equal(pr.severity, 'critical',
    'browser must NOT confidently demote to medium (the reproduced fail-open) while the CLI fails closed');
  assert.ok(
    Array.isArray(pr.escalation && pr.escalation.requiredUnknowns)
      && pr.escalation.requiredUnknowns.includes('subjectPartition'),
    "browser must record the SAME unknown viability the CLI does (requiredUnknowns:['subjectPartition'])",
  );
  assert.ok(
    !(((pr.escalation && pr.escalation.warningCodes) || []).includes('PARTITION_MISMATCH')),
    'a DEFAULTED partition must never drive a confident PARTITION_MISMATCH demotion at release',
  );
});

// The S1-NEW02 SARIF POSITIVE-LIST identity forgery (sibling of R2): findingIdentity joined
// a finding's attacker-controlled POSITIVE lists (actions / resources / principals) with a
// PLAIN, non-injective '|', so a single token carrying the '|' delimiter forged the sorted-
// join identity of a DISTINCT multi-element list -> identical partialFingerprint -> a GitHub
// code-scanning dismissal of A auto-suppresses the still-live distinct B (a fail-OPEN on
// re-detection). Fixed by routing every identity list through the injective joinInjective().
// The release gate re-verifies at ship time - on the REAL emitted SARIF the code-scanning gate
// consumes - that the forgery pair no longer collides, on ALL THREE positive channels.
test('RELEASE-GATE: S1-NEW02 SARIF positive-list identity forgery stays FIXED (distinct fingerprints)', { skip }, () => {
  const M = { ruleVersion: '1' };
  // (1) POSITIVE RESOURCE, end-to-end through scan() + the emitted SARIF: a whole-bucket read
  // with a KNOWN subject surfaces CROSS-ACCOUNT-DATA-READ-UNDETERMINED carrying the resource list.
  const readFp = (resource) => {
    const text = JSON.stringify({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: resource }],
    });
    const sr = scan({ text, family: 'identity', subjectAccount: '111122223333', threshold: 'info' });
    const log = buildSarifLog(sr, { file: 'p.json' }, M);
    const row = log.runs[0].results.find((r) => r.ruleId === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
    assert.ok(row, 'the surviving cross-account read must surface a SARIF result at release');
    return row.partialFingerprints[FINGERPRINT_KEY];
  };
  assert.notEqual(
    readFp(['arn:aws:s3:::a/*', 'arn:aws:s3:::b/*']),
    readFp(['arn:aws:s3:::a/*|arn:aws:s3:::b/*']),
    'positive-resource "|"-forgery still collides in the emitted SARIF - NEW-02 is not fixed',
  );

  // (2) POSITIVE ACTIONS + (3) PRINCIPALS via findingIdentity (the canonical hashed string),
  // proving the whole join is injective, not just the resource field.
  const idBase = {
    id: 'WILDCARD-RESOURCE', severity: 'high', title: 't', statementIndex: 0,
    statementSid: 'S', resources: ['*'], conditions: null,
  };
  assert.notEqual(
    findingIdentity({ ...idBase, actions: ['alpha:read', 'bravo:read'] }, 'identity'),
    findingIdentity({ ...idBase, actions: ['alpha:read|bravo:read'] }, 'identity'),
    'positive-action "|"-forgery still collides in findingIdentity - NEW-02 is not fixed',
  );
  const trustBase = {
    id: 'TRUST-CROSS-ACCOUNT', severity: 'high', title: 't', statementIndex: 0,
    statementSid: 'S', actions: ['sts:AssumeRole'], resources: [], conditions: null,
  };
  // Array-form principals (findingPrincipals -> normList verbatim) so the single "|"-bearing
  // token genuinely forges the two-element sorted-join under a plain '|' join (the object form
  // would prefix each element and never collide).
  assert.notEqual(
    findingIdentity({ ...trustBase, principals: ['arn:aws:iam::111122223333:root', 'arn:aws:iam::444455556666:root'] }, 'role-trust'),
    findingIdentity({ ...trustBase, principals: ['arn:aws:iam::111122223333:root|arn:aws:iam::444455556666:root'] }, 'role-trust'),
    'positive-principal "|"-forgery still collides in findingIdentity - NEW-02 is not fixed',
  );
});

// The ENTRYPOINT fail-open (raw-realpath-mismatch): a SYMLINKED launch of the CLI routes
// argv[1] through a symlink and today fails OPEN (exit 0, zero analysis). This reproduces
// it cheaply (no npm pack): the release gate requires the symlinked launch to analyze and
// fail closed. packaging.test.js documents the same class via npx / bin-shim as todos.
test('RELEASE-GATE: symlinked CLI launch fails closed (raw-realpath-mismatch must be FIXED)', { skip }, () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), 'iam-br-gate-')));
  const link = join(dir, 'iam-br-link.mjs');
  try {
    symlinkSync(CLI, link);
    const res = spawnSync('node', [link, '--family', 'identity', ADMIN_FIXTURE], { encoding: 'utf8' });
    assert.notEqual(res.status, null, 'symlinked launch must run to completion');
    assert.notEqual(
      res.status,
      0,
      'symlinked launch STILL fails OPEN to exit 0 (raw-realpath-mismatch); the entrypoint guard is not fixed',
    );
    assert.match(res.stdout || '', /WILDCARD-ACTION/,
      'symlinked launch must PERFORM ANALYSIS (finding marker), not exit non-zero with zero output');
  } finally {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});
