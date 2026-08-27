// GOLDEN-CORPUS ORACLE (the load-bearing half of the harness).
//
// These are METAMORPHIC / ORACLE assertions: fail-closed PROPERTIES that must hold
// regardless of today's baseline. A pure snapshot only proves STABILITY, and since
// the current engine carries KNOWN fail-open bugs a snapshot would just freeze wrong
// behaviour - so the primary mechanism is properties derived from BEHAVIOUR, not from
// a captured artifact.
//
// The five properties (per the build spec), asserted per applicable corpus case:
//   (1) zero analyzed candidates  => CLI exit != 0 AND not CLEAN.
//   (2) a 'risky' case            => a finding at/above threshold AND CLI exit != 0.
//   (3) a 'malformed' case        => coverage incomplete/error, never CLEAN.
//   (4) browser analyze() is NEVER more permissive than the CLI on the same input.
//   (5) a 'clean'/'quiet' case    => exit 0 only when genuinely nothing risky.
//
// scan() is the CLI's in-process core and the SOURCE OF TRUTH for the exit code, so
// the exit-code properties are asserted against scan() directly (fast, deterministic).
// The ENTRYPOINT fail-open class (bug: raw-realpath-mismatch) is invisible in-process
// and is covered by real process spawns in packaging.test.js - by design.
//
// KNOWN-OPEN: a case whose manifest carries `knownOpen` hits one of the six confirmed
// bugs. Its property is registered as a node:test `todo` so the suite stays GREEN
// today while DOCUMENTING the fail-open; fixing the bug flips the todo to a real pass.
// A companion non-todo test PINS the current buggy behaviour so a silent change is
// still caught.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT, ANALYSIS_STATUS } from '../../../../cli/scan.mjs';
import { buildSarifLog, FINGERPRINT_KEY } from '../../../../cli/sarif.mjs';
import { analyze } from '../../../../content/tools/iam-blast-radius/engine/analyze.js';
import {
  CASES, CLASS, SEVERITIES, scanInputFor, analyzeOptionsFor, corpusText,
} from './manifest.mjs';

// --- shared predicates --------------------------------------------------------

// The CLI "clean" predicate: exit 0 AND a COMPLETE analysis. Anything else is a
// fail-closed / findings verdict and is NOT clean.
function scanClean(sr) {
  return sr.exitCode === EXIT.CLEAN && sr.analysisStatus === ANALYSIS_STATUS.COMPLETE;
}

// The browser "clean" predicate (identical to browser-cli-parity.test.js): ok, zero
// findings, and coverage not incomplete.
function analyzeClean(ar) {
  return !!(ar && ar.ok === true
    && Array.isArray(ar.findings) && ar.findings.length === 0
    && !(ar.coverage && ar.coverage.summary && ar.coverage.summary.incomplete));
}

const SEV_RANK = new Map(SEVERITIES.map((s, i) => [s, i]));
function atOrAbove(sev, threshold) {
  const a = SEV_RANK.has(sev) ? SEV_RANK.get(sev) : Infinity;
  const t = SEV_RANK.has(threshold) ? SEV_RANK.get(threshold) : Infinity;
  return a <= t; // lower index = more severe
}

function runScan(c) {
  return scan(scanInputFor(c));
}
function runAnalyze(c) {
  return analyze(corpusText(c.file), analyzeOptionsFor(c));
}

// ============================================================================
// Property (1): a run that analyzed ZERO candidates must fail closed - never a
// clean exit 0. (An empty/missing input is a usage error, exit 2; it is emphatically
// NOT a clean pass having done zero analysis.)
// ============================================================================

test('P1: empty input analyzes nothing -> exit != 0 AND not clean', () => {
  const sr = scan({ text: '', family: 'identity' });
  assert.notEqual(sr.exitCode, EXIT.CLEAN, 'zero-analysis must not exit 0');
  assert.equal(scanClean(sr), false, 'zero-analysis must not be clean');
  assert.equal(sr.exitCode, EXIT.USAGE, 'empty input is a usage error (exit 2)');
});

test('P1: whitespace-only input analyzes nothing -> exit != 0 AND not clean', () => {
  const sr = scan({ text: '   \n\t ', family: 'identity' });
  assert.notEqual(sr.exitCode, EXIT.CLEAN);
  assert.equal(scanClean(sr), false);
});

// ============================================================================
// Property (2): a 'risky' case surfaces a finding at/above its threshold AND the
// CLI exits non-zero. Known-open risky cases (a confirmed bug hides the finding)
// are asserted as `todo`, with a pinning companion test for the current behaviour.
// ============================================================================

for (const c of CASES.filter((x) => x.klass === CLASS.RISKY)) {
  const threshold = c.threshold || 'high';

  const body = () => {
    const sr = runScan(c);
    // Core fail-closed invariant: a risky policy is NEVER a clean pass.
    assert.equal(scanClean(sr), false, `${c.id}: risky policy must not be clean`);
    assert.notEqual(sr.exitCode, EXIT.CLEAN, `${c.id}: risky policy must exit != 0`);

    // If the analysis COMPLETED, a blocking finding at/above threshold must exist.
    // (A fail-closed exit 3 - e.g. the DoS-budget abort on the huge case - satisfies
    // the invariant without a completed finding set; exitAny marks those.)
    if (sr.analysisStatus === ANALYSIS_STATUS.COMPLETE) {
      assert.ok(sr.blockingCount >= 1, `${c.id}: completed risky analysis must have >=1 blocking finding`);
      const hasAtThreshold = sr.findings.some((f) => atOrAbove(f.severity, threshold));
      assert.ok(hasAtThreshold, `${c.id}: a finding at/above '${threshold}' must be present`);
    } else if (!c.exitAny) {
      assert.fail(`${c.id}: expected a completed analysis with findings (status=${sr.analysisStatus})`);
    }

    // A case that must SURFACE a finding even below the gate (never silently cleared).
    if (c.surfacesFinding) {
      const ar = runAnalyze(c);
      assert.ok(ar.findings && ar.findings.length >= 1,
        `${c.id}: capability must be SURFACED (analyze() has >=1 finding), never silently cleared`);
    }
  };

  if (c.knownOpen) {
    // The safety property FAILS today because of the named bug; register it as a
    // todo so the suite stays green and a FIX flips it to a real pass.
    test(`P2 risky: ${c.id} surfaces at/above '${threshold}' and exits != 0`,
      { todo: `known-open (${c.knownOpen.bug}, ${c.knownOpen.ref}) - fix flips this green` }, body);

    // Companion PIN (non-todo): document the exact current fail-open so a silent
    // change to the buggy behaviour is still caught by the suite.
    test(`P2 risky: ${c.id} PINS current fail-open (bug: ${c.knownOpen.bug})`, () => {
      const sr = runScan(c);
      assert.equal(sr.exitCode, c.knownOpen.currentExit,
        `${c.id}: current (buggy) exit is ${c.knownOpen.currentExit}; if this changed, re-check the todo above`);
    });
  } else {
    test(`P2 risky: ${c.id} surfaces at/above '${threshold}' and exits != 0`, body);
  }
}

// ============================================================================
// Property (3): a 'malformed' case reports incomplete/error coverage and NEVER
// reads clean - on BOTH surfaces.
// ============================================================================

for (const c of CASES.filter((x) => x.klass === CLASS.MALFORMED)) {
  test(`P3 malformed: ${c.id} fails closed on both surfaces, never clean`, () => {
    const sr = runScan(c);
    assert.equal(scanClean(sr), false, `${c.id}: malformed must not be clean (CLI)`);
    assert.notEqual(sr.analysisStatus, ANALYSIS_STATUS.COMPLETE, `${c.id}: analysisStatus must not be complete`);
    assert.equal(sr.exitCode, EXIT.FAIL_CLOSED, `${c.id}: malformed fails closed (exit 3)`);

    const ar = runAnalyze(c);
    // Browser path is never clean either: either ok:false OR coverage incomplete.
    const browserIncomplete = ar.ok === false
      || !!(ar.coverage && ar.coverage.summary && ar.coverage.summary.incomplete);
    assert.equal(analyzeClean(ar), false, `${c.id}: malformed must not be clean (browser)`);
    assert.ok(browserIncomplete, `${c.id}: browser must mark ok:false or coverage incomplete`);
  });
}

test('P3: prototype-pollution corpus case does NOT pollute Object.prototype', () => {
  const c = CASES.find((x) => x.id === 'proto-pollution');
  runScan(c);
  runAnalyze(c);
  assert.equal({}.polluted, undefined, 'Object.prototype must not carry an injected key');
  assert.equal(Object.prototype.polluted, undefined);
});

// ============================================================================
// Property (4): the browser engine analyze() is NEVER more permissive than the CLI
// scan() on the same input - over EVERY corpus case. Forbids the exact fail-open:
// scan fails-closed/non-clean while analyze reports a clean pass.
// ============================================================================

for (const c of CASES) {
  test(`P4 parity: analyze() not more permissive than scan() - ${c.id}`, () => {
    const sr = runScan(c);
    const ar = runAnalyze(c);
    assert.ok(
      scanClean(sr) || !analyzeClean(ar),
      `PARITY VIOLATION (browser more permissive than CLI) on ${c.id}: `
        + `scan{exit:${sr.exitCode},status:${sr.analysisStatus}} `
        + `analyze{ok:${ar.ok},findings:${ar.findings && ar.findings.length},`
        + `incomplete:${!!(ar.coverage && ar.coverage.summary && ar.coverage.summary.incomplete)}}`,
    );
  });
}

// ============================================================================
// Property (4b) - S5-partition-parity, the headline case: a DEFAULTED (absent) subject
// partition must fail CLOSED as unknown-viability on BOTH surfaces, so the browser is
// never more permissive than the CLI. This pins the SPECIFIC verdict shape the generic
// P4 parity check cannot see: scan() partial/exit 3 (UNKNOWN_VIABILITY), and analyze()
// surfacing a CRITICAL PassRole finding carrying requiredUnknowns:['subjectPartition'] -
// NEVER a confident PARTITION_MISMATCH medium demotion.
// ============================================================================

test('P4b S5-parity: defaulted subject partition -> scan fails closed AND browser surfaces the same unknown', () => {
  const c = CASES.find((x) => x.id === 'passrole-defaulted-partition-unknown');
  assert.ok(c, 'the S5 defaulted-partition corpus case must exist');

  // CLI: fails closed as UNKNOWN_VIABILITY (partial, exit 3), never a clean pass.
  const sr = runScan(c);
  assert.equal(scanClean(sr), false, 'defaulted-partition PassRole must not read clean (CLI)');
  assert.equal(sr.exitCode, EXIT.FAIL_CLOSED, 'CLI fails closed at exit 3');
  assert.equal(sr.analysisStatus, ANALYSIS_STATUS.PARTIAL, 'CLI analysisStatus is partial (unknown viability)');

  // Browser: surfaces the SAME unknown viability - a CRITICAL PassRole finding marked
  // requiredUnknowns:['subjectPartition'], never a confident PARTITION_MISMATCH medium.
  const ar = runAnalyze(c);
  assert.equal(analyzeClean(ar), false, 'browser must not read clean either (a finding fires)');
  const pr = ar.findings.find((f) => f.id === 'PASSROLE-EC2');
  assert.ok(pr, 'the PassRole path is surfaced, never silently dropped');
  assert.equal(pr.severity, 'critical', 'browser must NOT confidently demote to medium while the CLI fails closed');
  const esc = pr.escalation || {};
  assert.ok(
    Array.isArray(esc.requiredUnknowns) && esc.requiredUnknowns.includes('subjectPartition'),
    "browser surfaces the SAME unknown viability the CLI does (requiredUnknowns:['subjectPartition'])",
  );
  assert.ok(
    !((esc.warningCodes || []).includes('PARTITION_MISMATCH')),
    'a DEFAULTED partition must never drive a confident PARTITION_MISMATCH demotion',
  );
});

// ============================================================================
// Property (4c) - S1-R1 iteration-5, the NO-DUPLICATE-REPORT oracle: when the spared
// bucket is ALSO an explicit Allow resource and the fence covers only a strict ACTION-
// SUBSET of the Allow's reads, the surviving read is ONE capability and must surface as
// EXACTLY ONE row per bucket, not one-per-action-subset. The generic P2 (surfaces + exit
// != 0) cannot see a duplicate; this pins the count on BOTH surfaces so a subset-action
// duplicate-report (two code-scanning alerts for one bucket) cannot regress.
// ============================================================================

test('P4c S1-R1 iter-5: subset-action fence on an explicit-Allow spared bucket surfaces EXACTLY ONE row', () => {
  const c = CASES.find((x) => x.id === 'notresource-deny-fences-subset-action-explicit-allow');
  assert.ok(c, 'the S1-R1 iteration-5 subset-action corpus case must exist');

  // CLI: still risky (surfaces + exit != 0), and exactly one derived undetermined finding.
  const sr = runScan(c);
  assert.equal(scanClean(sr), false, 'the surviving read must still fail the gate (never clean)');
  const scanUndet = sr.findings.filter((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.equal(scanUndet.length, 1,
    `one surviving bucket -> exactly one row (CLI), not one-per-action-subset; got ${scanUndet.length}`);

  // Browser: identical - exactly one row, and the kept row carries the FULL surviving
  // capability (the strict-subset derived row was dropped as already-covered).
  const ar = runAnalyze(c);
  assert.equal(analyzeClean(ar), false, 'browser must not read clean either');
  const browserUndet = ar.findings.filter((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.equal(browserUndet.length, 1,
    `one surviving bucket -> exactly one row (browser); got ${browserUndet.length}`);
  assert.deepEqual(browserUndet[0].resources, ['arn:aws:s3:::acme-competitor-bucket/*']);
  assert.deepEqual(browserUndet[0].actions.slice().sort(), ['s3:GetObject', 's3:ListBucket'],
    'the kept row reports the FULL surviving read set, not just the fenced action subset');

  // No two findings share (id, statementIndex, actions, resources) - no duplicate-report.
  const keys = ar.findings.map((f) => [f.id, f.statementIndex,
    (f.actions || []).slice().sort().join(','), (f.resources || []).slice().sort().join(',')].join('|'));
  assert.equal(new Set(keys).size, keys.length, 'no duplicate-report row on the browser surface');
});

// ============================================================================
// Property (6) - S1-NEW02, the SARIF IDENTITY-INJECTIVITY oracle: a partialFingerprint
// must be INJECTIVE over a finding's attacker-controlled POSITIVE identity lists (actions /
// resources / principals), so two SEMANTICALLY DISTINCT policies can NEVER forge one
// fingerprint. The forgery primitive: a token with NO charset restriction (an S3 key permits
// ~any byte) that literally contains the '|' identity delimiter, collapsing a single-element
// list into the sorted-join of a multi-element list. This is a fail-OPEN - a GitHub
// code-scanning dismissal of A would auto-suppress the still-live distinct B. Asserted on the
// REAL emitted SARIF (buildSarifLog), the artifact the code-scanning gate consumes.
// ============================================================================

const NEW02_FP_MANIFEST = { ruleVersion: '1' };
// A whole-bucket read of a foreign-named bucket with a KNOWN subject account surfaces
// CROSS-ACCOUNT-DATA-READ-UNDETERMINED, whose finding carries the POSITIVE resource list
// verbatim - the channel the forgery rides.
function new02ReadFingerprint(resource) {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: resource }],
  });
  const sr = scan({ text, family: 'identity', subjectAccount: '111122223333', threshold: 'info' });
  const log = buildSarifLog(sr, { file: 'p.json' }, NEW02_FP_MANIFEST);
  const row = log.runs[0].results.find((r) => r.ruleId === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.ok(row, 'the surviving cross-account read must surface a SARIF result');
  return row.partialFingerprints[FINGERPRINT_KEY];
}

test('P6 S1-NEW02: a "|"-bearing positive Resource cannot forge a colliding SARIF fingerprint', () => {
  // A reads TWO buckets; B reads ONE oddly-named resource containing the '|' delimiter.
  const twoElements = new02ReadFingerprint(['arn:aws:s3:::a/*', 'arn:aws:s3:::b/*']);
  const singlePipe = new02ReadFingerprint(['arn:aws:s3:::a/*|arn:aws:s3:::b/*']);
  assert.notEqual(twoElements, singlePipe,
    'a single "|"-bearing resource must not collide with a two-element resource list (positive-list forgery)');
});

// ============================================================================
// Property (5): a 'clean'/'quiet' case exits 0 (genuinely nothing at/above the
// threshold). A 'quiet' case additionally carries ZERO findings - its silence is a
// design choice (scoped same-account capability), and the oracle proves no NEW noise
// crept in, NOT that the policy is "safe".
// ============================================================================

for (const c of CASES.filter((x) => x.klass === CLASS.CLEAN || x.klass === CLASS.QUIET)) {
  test(`P5 ${c.klass}: ${c.id} exits 0 (nothing at/above threshold)`, () => {
    const sr = runScan(c);
    assert.equal(sr.exitCode, EXIT.CLEAN, `${c.id}: expected clean exit 0`);
    assert.equal(sr.analysisStatus, ANALYSIS_STATUS.COMPLETE, `${c.id}: clean requires a complete analysis`);
    assert.equal(scanClean(sr), true, `${c.id}: must be a genuine clean pass`);
    assert.equal(sr.blockingCount, 0, `${c.id}: a clean pass has zero blocking findings`);

    if (c.klass === CLASS.QUIET) {
      assert.equal(sr.findingsCount, 0, `${c.id}: a QUIET scoped capability surfaces zero findings by design`);
      const ar = runAnalyze(c);
      assert.equal(ar.findings.length, 0, `${c.id}: browser path is quiet too`);
    }
  });
}

// ============================================================================
// Manifest self-consistency: the recorded expectedExit matches reality, so the
// corpus cannot silently rot. (exitAny cases only require non-zero fail-closed.)
// ============================================================================

for (const c of CASES) {
  const label = c.knownOpen ? `${c.id} (KNOWN-OPEN)` : c.id;
  test(`manifest: expectedExit is accurate - ${label}`, () => {
    const sr = runScan(c);
    if (c.knownOpen) {
      assert.equal(sr.exitCode, c.knownOpen.currentExit,
        `${c.id}: known-open current exit drifted from ${c.knownOpen.currentExit}`);
    } else if (c.exitAny) {
      assert.notEqual(sr.exitCode, EXIT.CLEAN, `${c.id}: exitAny case must stay non-zero`);
    } else {
      assert.equal(sr.exitCode, c.expectedExit, `${c.id}: expectedExit drifted`);
    }
  });
}
