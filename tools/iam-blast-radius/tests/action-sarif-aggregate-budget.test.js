// Tests for the aggregate SARIF DOCUMENT-level output budget (story S2-NEW-SARIF-AGGREGATE).
//
// cli/sarif.mjs bounds ONE run (MAX_SARIF_BYTES=8 MiB + a SARIF_OUTPUT_TRUNCATED guard), but
// action/index.mjs buildAggregateSarif CONCATENATED one run per scanned file with NO document
// budget. GitHub code-scanning caps the whole upload (~5000 RESULTS, over which it SILENTLY
// drops the excess; ~10 MB gzip). A within-caps fan-out (e.g. 100 files x 50 findings = 5000
// results at only ~3.25 MB) therefore hit the RESULT cap far below the byte cap and lost
// Security-tab findings with ZERO truncation marker - the exact harm the per-run budget exists
// to prevent.
//
// The fix gives the aggregate a DOCUMENT-LEVEL budget mirroring the per-run one: cap the
// aggregate RESULT count (below 5000) AND aggregate BYTE size (below the 10 MB gzip cap, via a
// safe uncompressed proxy); on breach TRUNCATE deterministically (highest-severity/blocking +
// every fail-closed analyzer-state kept first) and append a VISIBLE SARIF_OUTPUT_TRUNCATED
// analyzer-state. The caps are configurable (max-sarif-results / max-sarif-bytes). The exit
// code is driven ONLY by finding severity and is NEVER downgraded by truncation.
//
// These tests pin the load-bearing invariants at the REAL boundary (runAction -> the emitted
// aggregate SARIF), plus the MUST-NOT-BREAK properties (under-cap identical; exit-code contract).

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  runAction,
  buildAggregateSarif,
  readInputs,
  DEFAULT_MAX_SARIF_RESULTS,
  DEFAULT_MAX_SARIF_BYTES,
  SARIF_OUTPUT_TRUNCATED_REASON,
  EXIT,
} from '../../../action/index.mjs';

// --- Policy fixtures (inline; deterministic). --------------------------------

const P = (st) => JSON.stringify({ Version: '2012-10-17', Statement: st });

// `*`/`*`: a big fan-out of findings - 4 CRITICAL (AssumeRole/PassRole) + several HIGH.
const STAR_ADMIN = P([{ Effect: 'Allow', Action: '*', Resource: '*' }]);
// A single INFO finding (CROSS-ACCOUNT-DATA-READ-UNDETERMINED) when a subject account is set.
const INFO_XACCT_READ = P([{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::other-corp-bucket/*' }]);
// Genuinely narrow, zero findings.
const CLEAN = P([{ Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc' }]);

// --- Injected IO + env helpers ------------------------------------------------

function makeIo(files) {
  return {
    listFiles: () => Object.keys(files),
    readFile: (rel) => {
      if (Object.prototype.hasOwnProperty.call(files, rel)) return files[rel];
      const e = new Error(`ENOENT: ${rel}`);
      e.code = 'ENOENT';
      throw e;
    },
  };
}

function makeEnv({ paths, family = 'identity', subjectAccount, maxSarifResults, maxSarifBytes } = {}) {
  const env = {};
  if (paths !== undefined) env['INPUT_PATHS'] = paths;
  if (family !== undefined) env['INPUT_FAMILY'] = family;
  if (subjectAccount !== undefined) env['INPUT_SUBJECT-ACCOUNT'] = subjectAccount;
  if (maxSarifResults !== undefined) env['INPUT_MAX-SARIF-RESULTS'] = String(maxSarifResults);
  if (maxSarifBytes !== undefined) env['INPUT_MAX-SARIF-BYTES'] = String(maxSarifBytes);
  return env;
}

function manyFiles(n, contents, prefix = 'policies/p') {
  const files = {};
  for (let i = 0; i < n; i++) files[`${prefix}${String(i).padStart(4, '0')}.json`] = contents;
  return files;
}

// Every result across every run in a SARIF log.
function allResults(sarifLog) {
  return sarifLog.runs.flatMap((run) => run.results || []);
}
function analyzerStates(sarifLog) {
  return allResults(sarifLog).filter(
    (r) => r.kind === 'fail' && r.properties && r.properties.category === 'analysis-state',
  );
}
function truncationStates(sarifLog) {
  return analyzerStates(sarifLog).filter((r) => r.ruleId === `analysis.${SARIF_OUTPUT_TRUNCATED_REASON}`);
}
function securityFindings(sarifLog) {
  return allResults(sarifLog).filter((r) => r.properties && r.properties.category === 'security');
}
function sarifBytes(sarifLog) {
  // Exactly what emitArtifacts writes: pretty-printed + a trailing newline.
  return Buffer.byteLength(`${JSON.stringify(sarifLog, null, 2)}\n`, 'utf8');
}

// ============================================================================
// Input parsing
// ============================================================================

test('readInputs: max-sarif-results / max-sarif-bytes parse; absent -> generous defaults', () => {
  const inputs = readInputs(makeEnv({ paths: 'a.json' }));
  assert.equal(inputs.maxSarifResults, DEFAULT_MAX_SARIF_RESULTS);
  assert.equal(inputs.maxSarifBytes, DEFAULT_MAX_SARIF_BYTES);
});

test('readInputs: explicit positive integers honored; non-positive/non-numeric -> default', () => {
  const good = readInputs(makeEnv({ paths: 'a.json', maxSarifResults: 20, maxSarifBytes: 4096 }));
  assert.equal(good.maxSarifResults, 20);
  assert.equal(good.maxSarifBytes, 4096);
  for (const bad of ['0', '-3', 'banana', '2.5', '', '   ']) {
    const inputs = readInputs(makeEnv({ paths: 'a.json', maxSarifResults: bad, maxSarifBytes: bad }));
    assert.equal(inputs.maxSarifResults, DEFAULT_MAX_SARIF_RESULTS, `results default for ${JSON.stringify(bad)}`);
    assert.equal(inputs.maxSarifBytes, DEFAULT_MAX_SARIF_BYTES, `bytes default for ${JSON.stringify(bad)}`);
  }
});

test('the default caps stay comfortably below GitHub code-scanning upload limits', () => {
  assert.ok(DEFAULT_MAX_SARIF_RESULTS < 5000, 'result cap must be below GitHub 5000-per-upload');
  assert.ok(DEFAULT_MAX_SARIF_BYTES < 10 * 1000 * 1000, 'byte proxy must be below the 10 MB gzip cap');
});

// ============================================================================
// RESULT-COUNT cap
// ============================================================================

test('RESULT-count breach -> truncation marker + count bounded + blocking kept + exit unchanged', () => {
  // 10 files x ~15 findings each = ~150 aggregate results; cap of 20 forces truncation.
  const io = makeIo(manyFiles(10, STAR_ADMIN));
  const truncated = runAction({ env: makeEnv({ paths: 'policies/**/*.json', maxSarifResults: 20 }), io });
  // The SAME run with a generous cap: the exit code (and blocking count) must be identical -
  // truncation shapes only the SARIF document, never the verdict.
  const untruncated = runAction({ env: makeEnv({ paths: 'policies/**/*.json', maxSarifResults: 100000 }), io });

  // Exit code driven only by severity, unchanged by truncation.
  assert.equal(truncated.exitCode, EXIT.FINDINGS, 'blocking findings -> exit 1');
  assert.equal(truncated.exitCode, untruncated.exitCode, 'truncation must not change the exit code');
  assert.equal(truncated.blockingCount, untruncated.blockingCount, 'blocking count unchanged by truncation');

  // A visible truncation marker is present (never a silent drop).
  assert.equal(truncationStates(truncated.sarifLog).length, 1, 'exactly one aggregate truncation marker');
  const marker = truncationStates(truncated.sarifLog)[0];
  assert.equal(marker.properties['security-severity'], undefined, 'the marker is NOT a vulnerability score');
  assert.equal(marker.properties.failClosed, true);

  // Result count is BOUNDED below the configured cap (marker included).
  assert.ok(allResults(truncated.sarifLog).length <= 20, 'total results must be bounded by the cap');
  assert.ok(untruncated.sarifLog.runs.flatMap((r) => r.results || []).length > 20, 'untruncated genuinely exceeds it');

  // A BLOCKING (highest-severity) finding still rides in the SARIF.
  const kept = securityFindings(truncated.sarifLog);
  assert.ok(kept.some((r) => r.properties.severity === 'critical'),
    'a critical finding (highest severity) must survive truncation');
  assert.ok(kept.every((r) => r.level === 'error' || r.level === 'warning' || r.level === 'note'));
});

test('RESULT truncation keeps HIGHEST-severity first: criticals survive, info findings elided', () => {
  // One STAR file (criticals + highs) plus 8 INFO-only files. A small cap keeps the top few by
  // severity - the criticals - and sheds the low-value INFO cross-account reads.
  const files = { 'policies/aaa-star.json': STAR_ADMIN, ...manyFiles(8, INFO_XACCT_READ, 'policies/zzz-info-') };
  const io = makeIo(files);
  const r = runAction({ env: makeEnv({ paths: 'policies/**/*.json', subjectAccount: '123456789012', maxSarifResults: 5 }), io });

  assert.equal(truncationStates(r.sarifLog).length, 1, 'truncation marker present');
  const kept = securityFindings(r.sarifLog);
  assert.ok(kept.some((f) => f.properties.severity === 'critical'), 'a critical finding is kept');
  assert.ok(!kept.some((f) => f.ruleId === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
    'the low-priority INFO cross-account reads are the ones elided, not the criticals');
  assert.ok(allResults(r.sarifLog).length <= 5);
});

// ============================================================================
// BYTE cap
// ============================================================================

test('BYTE breach -> truncation marker + real bytes bounded + blocking kept + exit unchanged', () => {
  const io = makeIo(manyFiles(10, STAR_ADMIN));
  // Generous result cap so the BYTE axis is the one that trips; a small byte ceiling.
  const byteCap = 20 * 1024;
  const truncated = runAction({ env: makeEnv({ paths: 'policies/**/*.json', maxSarifResults: 100000, maxSarifBytes: byteCap }), io });
  const untruncated = runAction({ env: makeEnv({ paths: 'policies/**/*.json', maxSarifResults: 100000, maxSarifBytes: 100 * 1024 * 1024 }), io });

  assert.ok(sarifBytes(untruncated.sarifLog) > byteCap, 'the untruncated document genuinely exceeds the byte cap');

  assert.equal(truncated.exitCode, EXIT.FINDINGS);
  assert.equal(truncated.exitCode, untruncated.exitCode, 'truncation must not change the exit code');
  assert.equal(truncationStates(truncated.sarifLog).length, 1, 'a visible byte-truncation marker is present');
  // The REAL emitted document stays under the configured byte cap (conservative estimate holds).
  assert.ok(sarifBytes(truncated.sarifLog) <= byteCap,
    `truncated SARIF (${sarifBytes(truncated.sarifLog)} B) must be <= the byte cap (${byteCap} B)`);
  assert.ok(securityFindings(truncated.sarifLog).some((f) => f.properties.severity === 'critical'),
    'a blocking finding still survives the byte truncation');
});

// ============================================================================
// UNDER-cap: unchanged, no marker (MUST-NOT-BREAK)
// ============================================================================

test('UNDER-cap aggregate is UNCHANGED: no marker, one run per file, identical to un-budgeted', () => {
  const io = makeIo(manyFiles(2, STAR_ADMIN));
  const env = makeEnv({ paths: 'policies/**/*.json' }); // default (generous) caps
  const r = runAction({ env, io });

  assert.equal(truncationStates(r.sarifLog).length, 0, 'no truncation marker on an under-cap run');
  assert.equal(analyzerStates(r.sarifLog).length, 0, 'no aggregate analyzer-state at all');
  assert.equal(r.sarifLog.runs.length, 2, 'one run per scanned file, unchanged');
  // Byte-for-byte identical to the un-budgeted concatenation: buildAggregateSarif over the
  // same units with astronomically large caps takes the early "under-cap -> return unchanged"
  // path, so its output is the plain one-run-per-file document the pre-budget code produced.
  const unbudgeted = buildAggregateSarif(r.units, undefined, {
    maxResults: Number.MAX_SAFE_INTEGER, maxBytes: Number.MAX_SAFE_INTEGER, family: 'identity',
  });
  assert.equal(JSON.stringify(r.sarifLog), JSON.stringify(unbudgeted), 'under-cap document is unchanged');
  assert.equal(r.exitCode, EXIT.FINDINGS);
});

test('a clean multi-file run stays clean and unchanged (no false truncation)', () => {
  const io = makeIo(manyFiles(5, CLEAN));
  const r = runAction({ env: makeEnv({ paths: 'policies/**/*.json' }), io });
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.equal(r.analysisStatus, 'complete');
  assert.equal(analyzerStates(r.sarifLog).length, 0);
  assert.equal(r.sarifLog.runs.length, 5);
});

// ============================================================================
// Exit-code contract: exit 3 (fail-closed) is NEVER downgraded by truncation
// ============================================================================

test('exit 3 (fail-closed) survives even when the aggregate is truncated', () => {
  // A malformed file forces exit 3; many STAR files force truncation. The worst exit code
  // (3, fail-closed) must reach the caller unchanged - truncation never greens it.
  const files = { 'policies/aaa-bad.json': '{ not valid json', ...manyFiles(10, STAR_ADMIN, 'policies/zzz-') };
  const io = makeIo(files);
  const r = runAction({ env: makeEnv({ paths: 'policies/**/*.json', maxSarifResults: 10 }), io });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'fail-closed (3) dominates and is never downgraded');
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.equal(truncationStates(r.sarifLog).length, 1, 'the truncation is still announced');
});

// ============================================================================
// Determinism
// ============================================================================

test('aggregate truncation is deterministic: identical inputs -> identical SARIF', () => {
  const io = makeIo(manyFiles(10, STAR_ADMIN));
  const env = makeEnv({ paths: 'policies/**/*.json', maxSarifResults: 20 });
  const a = runAction({ env, io });
  const b = runAction({ env, io });
  assert.equal(JSON.stringify(a.sarifLog), JSON.stringify(b.sarifLog));
});

// ============================================================================
// buildAggregateSarif direct: legacy 2-arg call still works (back-compat)
// ============================================================================

test('buildAggregateSarif with no caps uses the generous defaults (legacy 2-arg call unchanged)', () => {
  const units = [{ file: 'a.json', result: { analysisStatus: 'complete', analysisStates: [], findings: [], findingsCount: 0, blockingCount: 0, exitCode: 0, reason: 'clean', family: 'identity' } }];
  const log = buildAggregateSarif(units);
  assert.equal(log.version, '2.1.0');
  assert.equal(log.runs.length, 1);
  assert.equal(analyzerStates(log).length, 0);
});
