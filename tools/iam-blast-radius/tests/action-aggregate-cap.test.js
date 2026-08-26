// Tests for the GitHub Action AGGREGATE resource ceiling (story S6-action-aggregate-cap).
//
// resolveFiles + the per-file scan loop budget EACH file independently (the engine's
// per-file 1 MiB byte cap; a per-file work/wall-clock budgetMs), but nothing bounded the
// CUMULATIVE cost across MANY files beyond the static walkFiles MAX_FILES=200000. A fork
// PR matching thousands of near-cap policy files scales CI runtime linearly - an
// availability/cost DoS on the fork-PR surface (each file still fails closed, so this is
// NOT a fail-OPEN; it is unbounded work).
//
// The fix adds a DETERMINISTIC aggregate ceiling on BOTH a matched-file COUNT (max-files)
// and an aggregate UTF-8 BYTE total (max-total-bytes), configurable with generous defaults.
// These tests pin the load-bearing invariants:
//   - tripping EITHER ceiling FAILS CLOSED (exit 3), emits the findings gathered so far,
//     marks the run INCOMPLETE (analysis-status partial + an 'incomplete' analyzer-state),
//     and carries a SARIF analyzer-state (kind:fail, NO security-severity) notification -
//     it is NEVER reported as a clean pass;
//   - a LARGE-BUT-LEGITIMATE run (many small benign files, each under the per-file budget,
//     total under the configured ceiling) still COMPLETES and PASSES (exit 0) - proving the
//     cap does not clip real monorepo usage (no adoption-killing false positive);
//   - the cap is CONFIGURABLE and DETERMINISTIC (stable sorted traversal -> reproducible).

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  runAction,
  readInputs,
  DEFAULT_MAX_FILES,
  DEFAULT_MAX_TOTAL_BYTES,
  AGGREGATE_CAP_REASON,
  EXIT,
} from '../../../action/index.mjs';

// --- Policy fixtures (inline; deterministic). --------------------------------

const CLEAN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow',
    Action: 'ec2:DescribeInstances',
    Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc',
  }],
});

const ADMIN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
});

// --- Injected IO + env helpers (mirror action-index.test.js) ------------------

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

function makeEnv({ paths, family = 'identity', maxFiles, maxTotalBytes } = {}) {
  const env = {};
  if (paths !== undefined) env['INPUT_PATHS'] = paths;
  if (family !== undefined) env['INPUT_FAMILY'] = family;
  if (maxFiles !== undefined) env['INPUT_MAX-FILES'] = String(maxFiles);
  if (maxTotalBytes !== undefined) env['INPUT_MAX-TOTAL-BYTES'] = String(maxTotalBytes);
  return env;
}

// Build a { name: contents } map of N distinct clean policy files (zero-padded names so
// the resolveFiles sort order is stable and obvious).
function manyCleanFiles(n, contents = CLEAN_IDENTITY) {
  const files = {};
  for (let i = 0; i < n; i++) {
    files[`policies/p${String(i).padStart(4, '0')}.json`] = contents;
  }
  return files;
}

// The analyzer-state (kind:fail) results across every SARIF run.
function analyzerStates(sarifLog) {
  return sarifLog.runs
    .flatMap((run) => run.results || [])
    .filter((res) => res.kind === 'fail' && res.properties && res.properties.category === 'analysis-state');
}

// ============================================================================
// Input parsing
// ============================================================================

test('readInputs: max-files / max-total-bytes parse; absent -> generous defaults', () => {
  const inputs = readInputs(makeEnv({ paths: 'a.json' }));
  assert.equal(inputs.maxFiles, DEFAULT_MAX_FILES);
  assert.equal(inputs.maxTotalBytes, DEFAULT_MAX_TOTAL_BYTES);
});

test('readInputs: explicit positive integers are honored', () => {
  const inputs = readInputs(makeEnv({ paths: 'a.json', maxFiles: 5, maxTotalBytes: 4096 }));
  assert.equal(inputs.maxFiles, 5);
  assert.equal(inputs.maxTotalBytes, 4096);
});

test('readInputs: a non-positive / non-numeric ceiling falls back to the default (never bricks)', () => {
  for (const bad of ['0', '-3', 'banana', '2.5', '', '   ']) {
    const inputs = readInputs(makeEnv({ paths: 'a.json', maxFiles: bad, maxTotalBytes: bad }));
    assert.equal(inputs.maxFiles, DEFAULT_MAX_FILES, `max-files should default for ${JSON.stringify(bad)}`);
    assert.equal(inputs.maxTotalBytes, DEFAULT_MAX_TOTAL_BYTES, `max-total-bytes should default for ${JSON.stringify(bad)}`);
  }
});

// ============================================================================
// FILE-COUNT ceiling
// ============================================================================

test('the FILE-COUNT ceiling trips -> exit 3, INCOMPLETE, SARIF analyzer-state; NEVER clean', () => {
  // 5 clean files, ceiling of 2: the first 2 are analyzed, then the run fails closed.
  const env = makeEnv({ paths: 'policies/**/*.json', family: 'identity', maxFiles: 2 });
  const io = makeIo(manyCleanFiles(5));
  const r = runAction({ env, io });

  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'aggregate count-cap breach must fail closed (exit 3)');
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.equal(r.reason, AGGREGATE_CAP_REASON);
  assert.equal(r.analysisStatus, 'partial', 'some files analyzed, the rest not -> incomplete/partial');

  // A SARIF analyzer-state notification announces the truncation, and it carries NO
  // security-severity (it is not a vulnerability score) - the load-bearing separation.
  const states = analyzerStates(r.sarifLog);
  const capState = states.find((s) => s.ruleId === `analysis.${AGGREGATE_CAP_REASON}`);
  assert.ok(capState, 'a SARIF analyzer-state for the aggregate cap must be present');
  assert.equal(capState.properties['security-severity'], undefined);
  assert.equal(capState.properties.failClosed, true);
});

test('exactly max-files matched -> no breach, clean pass (boundary is not off-by-one)', () => {
  const env = makeEnv({ paths: 'policies/**/*.json', family: 'identity', maxFiles: 4 });
  const io = makeIo(manyCleanFiles(4));
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.equal(r.analysisStatus, 'complete');
  assert.equal(r.reason, 'clean');
  // No aggregate-cap analyzer-state.
  assert.equal(analyzerStates(r.sarifLog).length, 0);
});

test('findings gathered BEFORE the cap are preserved (blocking finding + fail-closed both survive)', () => {
  // admin.json sorts first (a* < p*): it produces a blocking finding, then the count cap
  // trips on the clean files. The aggregate exit is worst(1, 3) = 3, and the finding is
  // NOT lost - it still rides in the SARIF and the findings count.
  const files = { 'admin.json': ADMIN_IDENTITY, ...manyCleanFiles(5) };
  const env = makeEnv({ paths: '**/*.json', family: 'identity', maxFiles: 1 });
  const io = makeIo(files);
  const r = runAction({ env, io });

  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'fail-closed (3) dominates the sibling finding (1)');
  assert.ok(r.findingsCount >= 1, 'the finding gathered before the cap must be preserved');
  assert.ok(r.blockingCount >= 1, 'the blocking finding must be preserved');
  // Both a real security finding AND the aggregate-cap analyzer-state appear in SARIF.
  const allResults = r.sarifLog.runs.flatMap((run) => run.results || []);
  assert.ok(allResults.some((res) => res.kind !== 'fail'), 'a security finding survives');
  assert.ok(analyzerStates(r.sarifLog).some((s) => s.ruleId === `analysis.${AGGREGATE_CAP_REASON}`),
    'the aggregate-cap analyzer-state survives');
});

// ============================================================================
// BYTE ceiling
// ============================================================================

test('the aggregate BYTE ceiling trips -> exit 3, INCOMPLETE, SARIF analyzer-state; NEVER clean', () => {
  // Each clean file is > 100 bytes; a byte ceiling of 200 admits ~1 file, then fails closed
  // (count is generous so the BYTE axis is the one that trips).
  const perFileBytes = Buffer.byteLength(CLEAN_IDENTITY, 'utf8');
  assert.ok(perFileBytes > 100, 'fixture must exceed the tiny byte ceiling used here');
  const env = makeEnv({
    paths: 'policies/**/*.json', family: 'identity', maxFiles: 1000, maxTotalBytes: perFileBytes + 10,
  });
  const io = makeIo(manyCleanFiles(5));
  const r = runAction({ env, io });

  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'aggregate byte-cap breach must fail closed (exit 3)');
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.equal(r.reason, AGGREGATE_CAP_REASON);
  assert.equal(r.analysisStatus, 'partial');
  assert.ok(analyzerStates(r.sarifLog).some((s) => s.ruleId === `analysis.${AGGREGATE_CAP_REASON}`));
});

test('a single file larger than the byte ceiling fails closed (never a clean pass)', () => {
  const env = makeEnv({ paths: 'big.json', family: 'identity', maxTotalBytes: 8 });
  const io = makeIo({ 'big.json': CLEAN_IDENTITY });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.equal(r.reason, AGGREGATE_CAP_REASON);
});

// ============================================================================
// LARGE-BUT-LEGITIMATE: the cap must NOT clip real usage (no false positive)
// ============================================================================

test('a large-but-legitimate run (many small benign files under the defaults) COMPLETES and PASSES', () => {
  // 200 small clean policy files - well under the default 1000-file / 64 MiB ceilings and
  // each far under the per-file 1 MiB budget. This is the adoption case a too-tight cap
  // would wrongly fail; it MUST stay exit 0, complete, with no aggregate-cap state.
  const n = 200;
  const io = makeIo(manyCleanFiles(n));
  const env = makeEnv({ paths: 'policies/**/*.json', family: 'identity' }); // default ceilings
  const r = runAction({ env, io });

  assert.equal(r.exitCode, EXIT.CLEAN, 'a legitimate large monorepo must not be capped');
  assert.equal(r.analysisStatus, 'complete');
  assert.equal(r.blockingCount, 0);
  assert.equal(analyzerStates(r.sarifLog).length, 0, 'no aggregate-cap notification on a legitimate run');
  // One SARIF run per analyzed file - every file was actually scanned.
  assert.equal(r.sarifLog.runs.length, n);
});

test('a large-but-legitimate run under EXPLICIT (generous) ceilings also passes', () => {
  const n = 50;
  const io = makeIo(manyCleanFiles(n));
  const env = makeEnv({
    paths: 'policies/**/*.json', family: 'identity', maxFiles: 100, maxTotalBytes: 10 * 1024 * 1024,
  });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.equal(r.analysisStatus, 'complete');
  assert.equal(r.sarifLog.runs.length, n);
});

// ============================================================================
// Determinism
// ============================================================================

test('the aggregate cap is deterministic: identical inputs -> identical outputs + SARIF', () => {
  const env = makeEnv({ paths: 'policies/**/*.json', family: 'identity', maxFiles: 3 });
  const io = makeIo(manyCleanFiles(10));
  const r1 = runAction({ env, io });
  const r2 = runAction({ env, io });
  assert.equal(r1.exitCode, EXIT.FAIL_CLOSED);
  assert.deepEqual(r1.outputs, r2.outputs);
  assert.equal(JSON.stringify(r1.sarifLog), JSON.stringify(r2.sarifLog));
});
