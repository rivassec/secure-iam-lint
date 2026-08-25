// Tests for the GitHub Action wrapper (Phase 16, story P16-action).
//
// The action wrapper is a THIN adapter over the headless scan() module. These
// tests pin the load-bearing invariants of a fail-closed CI gate carried into a
// stranger's pipeline:
//   - CLI exit 3 (fail-closed could-not-analyze) MUST fail the action - it NEVER
//     collapses to exit 0 / a clean pass.
//   - Multi-file aggregation uses STRICT worst-exit-code semantics: ONE fail-closed
//     file makes the whole run fail.
//   - An empty/missing glob (and missing paths / missing family) is a usage error
//     (exit 2), NOT a clean scan.
//   - A caught error NEVER becomes exit 0 (fails closed to internal exit 4).
//   - All outputs are written, and SARIF is written BEFORE the action fails.
//
// The core (runAction) is pure over an injected IO surface + an injectable scan, so
// it is unit-tested with no process/filesystem/env of its own.

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  runAction,
  emitArtifacts,
  readInputs,
  getInput,
  splitPaths,
  hasMagic,
  globToRegExp,
  resolveFiles,
  worstExitCode,
  aggregateStatus,
  buildAggregateSarif,
  formatOutputs,
  formatSummary,
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

// Malformed JSON -> engine ok:false -> scan fails closed (exit 3).
const MALFORMED = '{ this is not json';

// --- Injected IO helpers ------------------------------------------------------

// An in-memory IO surface: `files` maps cwd-relative POSIX path -> contents.
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

// A minimal INPUT_* env for the action.
function makeEnv({ paths, family = 'identity', failOn, partition, subjectAccount, sarifOutput } = {}) {
  const env = {};
  if (paths !== undefined) env['INPUT_PATHS'] = paths;
  if (family !== undefined) env['INPUT_FAMILY'] = family;
  if (failOn !== undefined) env['INPUT_FAIL-ON'] = failOn;
  if (partition !== undefined) env['INPUT_PARTITION'] = partition;
  if (subjectAccount !== undefined) env['INPUT_SUBJECT-ACCOUNT'] = subjectAccount;
  if (sarifOutput !== undefined) env['INPUT_SARIF-OUTPUT'] = sarifOutput;
  return env;
}

// ============================================================================
// Input reading
// ============================================================================

test('getInput maps hyphenated input names to INPUT_* env vars (GitHub transform)', () => {
  const env = { 'INPUT_FAIL-ON': ' critical ', 'INPUT_SUBJECT-ACCOUNT': '111122223333' };
  assert.equal(getInput(env, 'fail-on'), 'critical'); // trimmed like @actions/core
  assert.equal(getInput(env, 'subject-account'), '111122223333');
  assert.equal(getInput(env, 'missing'), '');
});

test('getInput also accepts an underscore variant defensively', () => {
  const env = { 'INPUT_FAIL_ON': 'medium' };
  assert.equal(getInput(env, 'fail-on'), 'medium');
});

test('readInputs applies action.yml defaults (fail-on high, sarif-output)', () => {
  const inputs = readInputs(makeEnv({ paths: 'a.json', family: 'identity' }));
  assert.equal(inputs.failOn, 'high');
  assert.equal(inputs.sarifOutput, 'iam-blast-radius.sarif');
});

test('readInputs: an OMITTED partition stays UNASSERTED (empty string), NOT defaulted to aws', () => {
  // Load-bearing fail-closed invariant: account ids do not encode partition, so a
  // defaulted 'aws' would let scan() trust a cross-partition demotion the consumer
  // never vouched for. Omitted must stay "" (-> undefined at the scan boundary),
  // mirroring the CLI's `partition: undefined`.
  const inputs = readInputs(makeEnv({ paths: 'a.json', family: 'identity' }));
  assert.equal(inputs.partition, '');
});

test('readInputs: an EXPLICIT partition is preserved verbatim (caller asserted it)', () => {
  const inputs = readInputs(makeEnv({ paths: 'a.json', family: 'identity', partition: 'aws-us-gov' }));
  assert.equal(inputs.partition, 'aws-us-gov');
});

// ============================================================================
// paths / glob resolution
// ============================================================================

test('splitPaths splits newlines, trims, and drops blanks', () => {
  assert.deepEqual(splitPaths('a.json\n  b/c.json \n\n\n  \n d.json'), ['a.json', 'b/c.json', 'd.json']);
  assert.deepEqual(splitPaths(''), []);
  assert.deepEqual(splitPaths(null), []);
});

test('hasMagic detects glob metacharacters', () => {
  assert.equal(hasMagic('policies/**/*.json'), true);
  assert.equal(hasMagic('a?.json'), true);
  assert.equal(hasMagic('a[0-9].json'), true);
  assert.equal(hasMagic('policies/prod.json'), false);
});

test('globToRegExp: ** matches any depth incl. zero; * stays within a segment', () => {
  const re = globToRegExp('policies/**/*.json');
  assert.equal(re.test('policies/a.json'), true);        // zero intermediate segments
  assert.equal(re.test('policies/prod/a.json'), true);   // one segment
  assert.equal(re.test('policies/a/b/c.json'), true);    // deep
  assert.equal(re.test('policies/a.txt'), false);        // wrong extension
  assert.equal(re.test('other/a.json'), false);          // wrong root

  const star = globToRegExp('src/*.json');
  assert.equal(star.test('src/a.json'), true);
  assert.equal(star.test('src/a/b.json'), false);        // * does not cross '/'
});

test('resolveFiles: literal + glob resolve to a sorted, de-duplicated set', () => {
  const list = ['policies/a.json', 'policies/sub/b.json', 'policies/a.txt', 'readme.md'];
  const { files, error } = resolveFiles(['policies/**/*.json', 'readme.md'], list);
  assert.equal(error, null);
  assert.deepEqual(files, ['policies/a.json', 'policies/sub/b.json', 'readme.md']);
});

test('resolveFiles: no patterns -> MISSING_PATHS usage error', () => {
  const { files, error } = resolveFiles([], ['a.json']);
  assert.deepEqual(files, []);
  assert.equal(error.reason, 'MISSING_PATHS');
});

test('resolveFiles: a named literal file that is absent -> MISSING_FILE (fail closed)', () => {
  const { error } = resolveFiles(['policies/missing.json'], ['policies/a.json']);
  assert.equal(error.reason, 'MISSING_FILE');
});

test('resolveFiles: an all-empty glob -> NO_FILES_MATCHED usage error, never clean', () => {
  const { files, error } = resolveFiles(['policies/**/*.json'], ['readme.md']);
  assert.deepEqual(files, []);
  assert.equal(error.reason, 'NO_FILES_MATCHED');
});

// ============================================================================
// Aggregation primitives (STRICT worst-exit-code)
// ============================================================================

test('worstExitCode: any 1 dominates 0; any 3 dominates 1; 4 dominates all', () => {
  assert.equal(worstExitCode([0, 0, 0]), 0);
  assert.equal(worstExitCode([0, 1]), 1);
  assert.equal(worstExitCode([0, 3]), 3);          // ONE fail-closed dominates clean
  assert.equal(worstExitCode([1, 3]), 3);          // fail-closed dominates findings
  assert.equal(worstExitCode([1, 2]), 2);
  assert.equal(worstExitCode([3, 4]), 4);          // internal dominates fail-closed
  assert.equal(worstExitCode([0, 1, 2, 3]), 3);
});

test('worstExitCode: a garbage/out-of-range code fails closed to INTERNAL, never 0', () => {
  assert.equal(worstExitCode([0, 99]), EXIT.INTERNAL);
  assert.equal(worstExitCode([0, -1]), EXIT.INTERNAL);
  assert.equal(worstExitCode([0, null]), EXIT.INTERNAL);
  assert.equal(worstExitCode([]), EXIT.USAGE); // nothing scanned is a config problem
});

test('aggregateStatus: failed dominates partial dominates complete', () => {
  assert.equal(aggregateStatus(['complete', 'complete']), 'complete');
  assert.equal(aggregateStatus(['complete', 'partial']), 'partial');
  assert.equal(aggregateStatus(['partial', 'failed']), 'failed');
  assert.equal(aggregateStatus([]), 'failed');
  assert.equal(aggregateStatus(['complete', 'weird']), 'failed'); // unrecognized fails closed
});

// ============================================================================
// runAction - the load-bearing exit-code behavior
// ============================================================================

test('runAction: a single clean policy -> exit 0, status complete', () => {
  const env = makeEnv({ paths: 'clean.json', family: 'identity' });
  const io = makeIo({ 'clean.json': CLEAN_IDENTITY });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.equal(r.analysisStatus, 'complete');
  assert.equal(r.blockingCount, 0);
  assert.equal(r.outputs['exit-code'], '0');
});

test('runAction: a policy with blocking findings -> exit 1', () => {
  const env = makeEnv({ paths: 'admin.json', family: 'identity' });
  const io = makeIo({ 'admin.json': ADMIN_IDENTITY });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(r.blockingCount >= 1);
  assert.equal(r.outputs['blocking-findings-count'], String(r.blockingCount));
});

test('runAction: a malformed policy FAILS CLOSED (exit 3), NEVER collapses to 0', () => {
  const env = makeEnv({ paths: 'bad.json', family: 'identity' });
  const io = makeIo({ 'bad.json': MALFORMED });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.equal(r.analysisStatus, 'failed');
});

test('runAction: multi-file where ONE file is fail-closed -> aggregate exit 3 (worst)', () => {
  const env = makeEnv({ paths: 'a.json\nb.json\nc.json', family: 'identity' });
  const io = makeIo({ 'a.json': CLEAN_IDENTITY, 'b.json': MALFORMED, 'c.json': CLEAN_IDENTITY });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED); // the single fail-closed file wins
  assert.notEqual(r.exitCode, EXIT.CLEAN);
});

test('runAction: multi-file clean + findings -> exit 1; counts are summed', () => {
  const env = makeEnv({ paths: '*.json', family: 'identity' });
  const io = makeIo({ 'clean.json': CLEAN_IDENTITY, 'admin.json': ADMIN_IDENTITY });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(r.findingsCount >= 1);
});

test('runAction: fail-closed does NOT lose to a sibling findings file (3 beats 1)', () => {
  const env = makeEnv({ paths: 'admin.json\nbad.json', family: 'identity' });
  const io = makeIo({ 'admin.json': ADMIN_IDENTITY, 'bad.json': MALFORMED });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

// A cross-partition PassRole policy: same account, DIFFERENT partition in the role
// ARN. The engine tags PARTITION_MISMATCH and demotes the PASSROLE-EC2 finding
// critical->medium. That demotion is only trustworthy if the CALLER vouched for the
// subject's partition; account ids do not encode partition. With NO partition
// asserted, the "not viable" verdict is genuinely UNKNOWN and scan() must fail
// closed (exit 3) rather than let the demoted medium slip under fail-on high.
const CROSS_PARTITION_PASSROLE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws-us-gov:iam::111122223333:role/deployer' },
    { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
  ],
});

test('runAction: cross-partition PassRole with partition OMITTED FAILS CLOSED (exit 3), NEVER green', () => {
  // Adversarial: exact fail-open the action must NOT have. A defaulted 'aws' would
  // make scan() trust the critical->medium demotion, drop below fail-on high, and
  // report exit 0 / a green check. Omitted partition must stay "not asserted" so the
  // cross-partition viability question is UNKNOWN and the action fails closed -
  // identical to the CLI (which passes partition: undefined when --partition omitted).
  const env = makeEnv({ paths: 'p.json', family: 'identity', subjectAccount: '111122223333' });
  const io = makeIo({ 'p.json': CROSS_PARTITION_PASSROLE });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.equal(r.analysisStatus, 'partial');
  assert.equal(r.reason, 'UNKNOWN_VIABILITY');
  // The fail-closed signal survives into SARIF: at least one analyzer-state result.
  const results = r.sarifLog.runs.flatMap((run) => run.results || []);
  assert.ok(results.some((res) => res.kind === 'fail'));
});

test('runAction: an EXPLICITLY asserted partition re-enables the confident verdict', () => {
  // The consumer takes responsibility by asserting the subject's partition. With the
  // role in aws-us-gov and partition=aws-us-gov, the PassRole path IS viable -> a
  // blocking finding (exit 1). This is a CONFIDENT analysis, not a fail-closed one.
  const env = makeEnv({
    paths: 'p.json', family: 'identity', subjectAccount: '111122223333', partition: 'aws-us-gov',
  });
  const io = makeIo({ 'p.json': CROSS_PARTITION_PASSROLE });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.equal(r.analysisStatus, 'complete');
  assert.ok(r.blockingCount >= 1);
});

test('runAction: a BOGUS partition token is NOT trusted as an assertion (still fails closed)', () => {
  // scan() only trusts a RECOGNIZED partition. A garbage token ("banana") is treated
  // as NOT provided, so the cross-partition verdict stays UNKNOWN and fails closed.
  // The action must not let a bogus token masquerade as a confident assertion.
  const env = makeEnv({
    paths: 'p.json', family: 'identity', subjectAccount: '111122223333', partition: 'banana',
  });
  const io = makeIo({ 'p.json': CROSS_PARTITION_PASSROLE });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.notEqual(r.exitCode, EXIT.CLEAN);
});

test('runAction: an empty/missing glob is a usage error (exit 2), not clean', () => {
  const env = makeEnv({ paths: 'policies/**/*.json', family: 'identity' });
  const io = makeIo({ 'readme.md': 'x' });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.USAGE);
  assert.equal(r.reason, 'NO_FILES_MATCHED');
});

test('runAction: missing paths input -> exit 2', () => {
  const env = makeEnv({ paths: '   \n  ', family: 'identity' });
  const io = makeIo({ 'a.json': CLEAN_IDENTITY });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.USAGE);
  assert.equal(r.reason, 'MISSING_PATHS');
});

test('runAction: missing family input -> exit 2 (never auto-detected)', () => {
  const env = makeEnv({ paths: 'a.json', family: '' });
  const io = makeIo({ 'a.json': CLEAN_IDENTITY });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.USAGE);
  assert.equal(r.reason, 'MISSING_FAMILY');
});

test('runAction: a named literal missing file -> exit 2 (fail closed)', () => {
  const env = makeEnv({ paths: 'policies/prod.json', family: 'identity' });
  const io = makeIo({ 'policies/other.json': CLEAN_IDENTITY });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.USAGE);
  assert.equal(r.reason, 'MISSING_FILE');
});

test('runAction: an empty policy file is a per-unit usage error (exit 2), not clean', () => {
  const env = makeEnv({ paths: 'empty.json', family: 'identity' });
  const io = makeIo({ 'empty.json': '   ' });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.USAGE);
  assert.notEqual(r.exitCode, EXIT.CLEAN);
});

test('runAction: a scan that THROWS never becomes exit 0 (per-file internal, exit 4)', () => {
  const env = makeEnv({ paths: 'a.json', family: 'identity' });
  const io = makeIo({ 'a.json': CLEAN_IDENTITY });
  const scanFn = () => { throw new Error('boom'); };
  const r = runAction({ env, io, scanFn });
  assert.equal(r.exitCode, EXIT.INTERNAL);
  assert.notEqual(r.exitCode, EXIT.CLEAN);
});

test('runAction: a scan returning a garbage exit code fails closed to INTERNAL', () => {
  const env = makeEnv({ paths: 'a.json', family: 'identity' });
  const io = makeIo({ 'a.json': CLEAN_IDENTITY });
  const scanFn = () => ({ exitCode: 42, analysisStatus: 'complete', findings: [], findingsCount: 0, blockingCount: 0, reason: 'X' });
  const r = runAction({ env, io, scanFn });
  assert.equal(r.exitCode, EXIT.INTERNAL);
});

test('runAction: an internal error inside the wrapper never yields exit 0', () => {
  // A pathological io.listFiles that throws should fail closed to INTERNAL, not 0.
  const env = makeEnv({ paths: 'a.json', family: 'identity' });
  const io = { listFiles: () => { throw new Error('fs exploded'); }, readFile: () => '' };
  const r = runAction({ env, io });
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.equal(r.exitCode, EXIT.INTERNAL);
});

// ============================================================================
// Outputs + SARIF assembly
// ============================================================================

test('runAction: outputs carry the full contract set', () => {
  const env = makeEnv({ paths: 'admin.json', family: 'identity', sarifOutput: 'out/br.sarif' });
  const io = makeIo({ 'admin.json': ADMIN_IDENTITY });
  const r = runAction({ env, io });
  assert.deepEqual(Object.keys(r.outputs).sort(), [
    'analysis-status', 'blocking-findings-count', 'exit-code', 'findings-count', 'sarif-path',
  ]);
  assert.equal(r.outputs['sarif-path'], 'out/br.sarif');
  assert.equal(r.outputs['exit-code'], String(r.exitCode));
  assert.equal(r.outputs['analysis-status'], r.analysisStatus);
});

test('buildAggregateSarif: one run per file; fail-closed file carries an analyzer-state result', () => {
  const env = makeEnv({ paths: 'a.json\nb.json', family: 'identity' });
  const io = makeIo({ 'a.json': CLEAN_IDENTITY, 'b.json': MALFORMED });
  const r = runAction({ env, io });
  const sarif = r.sarifLog;
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 2); // one run per scanned file
  // The fail-closed file's run must carry an analyzer-state (kind:fail) result -
  // never a security finding, and never zero results masquerading as clean.
  const analyzerStates = sarif.runs
    .flatMap((run) => run.results)
    .filter((res) => res.kind === 'fail' && res.properties && res.properties.category === 'analysis-state');
  assert.ok(analyzerStates.length >= 1);
  // And none of the analyzer-state results carry a security-severity (the load-
  // bearing separation an adversary must not be able to collapse).
  for (const res of analyzerStates) {
    assert.equal(res.properties['security-severity'], undefined);
  }
});

test('buildAggregateSarif: a config error produces a single descriptive run, not empty/clean', () => {
  const env = makeEnv({ paths: '', family: 'identity' });
  const io = makeIo({ 'a.json': CLEAN_IDENTITY });
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.USAGE);
  assert.equal(r.sarifLog.runs.length, 1);
  const results = r.sarifLog.runs[0].results;
  assert.ok(results.some((res) => res.kind === 'fail'));
});

// ============================================================================
// formatOutputs / formatSummary
// ============================================================================

test('formatOutputs: single-line scalars render as name=value lines', () => {
  const body = formatOutputs({ 'exit-code': '3', 'analysis-status': 'failed' });
  assert.equal(body, 'exit-code=3\nanalysis-status=failed\n');
});

test('formatOutputs: a value containing a newline uses the heredoc delimiter form', () => {
  const body = formatOutputs({ note: 'line1\nline2' });
  assert.match(body, /^note<<ghadelim_note_EOF\nline1\nline2\nghadelim_note_EOF\n$/);
});

test('formatSummary: PASS only when exit 0; carries no policy content', () => {
  const outputs = { 'analysis-status': 'complete', 'findings-count': '0', 'blocking-findings-count': '0', 'sarif-path': 'x.sarif' };
  assert.match(formatSummary(outputs, 0), /PASS/);
  assert.match(formatSummary(outputs, 3), /FAIL \(exit 3\)/);
});

// ============================================================================
// emitArtifacts - output-writing order + contract
// ============================================================================

test('emitArtifacts: writes SARIF FIRST, then outputs, then summary', () => {
  const env = makeEnv({ paths: 'admin.json', family: 'identity' });
  const io = makeIo({ 'admin.json': ADMIN_IDENTITY });
  const r = runAction({ env, io });

  const calls = [];
  let sarifText = null;
  let outputText = null;
  const sinks = {
    writeSarif: (p, t) => { calls.push('sarif'); sarifText = t; },
    appendOutput: (t) => { calls.push('output'); outputText = t; },
    appendSummary: () => { calls.push('summary'); },
  };
  const fakeEnv = { GITHUB_OUTPUT: '/tmp/out', GITHUB_STEP_SUMMARY: '/tmp/sum' };
  const { ops, writeError } = emitArtifacts(r, fakeEnv, sinks);

  assert.equal(writeError, null);
  assert.deepEqual(calls, ['sarif', 'output', 'summary']); // SARIF before outputs
  assert.deepEqual(ops.map((o) => o.op), ['sarif', 'output', 'summary']);
  // The output body carries every contract output.
  assert.match(outputText, /exit-code=1/);
  assert.match(outputText, /sarif-path=/);
  assert.match(outputText, /analysis-status=/);
  // The SARIF written is the aggregate log.
  assert.match(sarifText, /"version": "2\.1\.0"/);
});

test('emitArtifacts: skips GITHUB_OUTPUT append when the env var is absent', () => {
  const env = makeEnv({ paths: 'clean.json', family: 'identity' });
  const io = makeIo({ 'clean.json': CLEAN_IDENTITY });
  const r = runAction({ env, io });
  const calls = [];
  const sinks = {
    writeSarif: () => calls.push('sarif'),
    appendOutput: () => calls.push('output'),
    appendSummary: () => calls.push('summary'),
  };
  const { ops } = emitArtifacts(r, {}, sinks); // no GITHUB_OUTPUT / GITHUB_STEP_SUMMARY
  assert.deepEqual(calls, ['sarif']); // only SARIF is unconditional
  assert.deepEqual(ops.map((o) => o.op), ['sarif']);
});

test('emitArtifacts: a sink failure is captured, not thrown (caller decides exit)', () => {
  const env = makeEnv({ paths: 'clean.json', family: 'identity' });
  const io = makeIo({ 'clean.json': CLEAN_IDENTITY });
  const r = runAction({ env, io });
  const sinks = { writeSarif: () => { throw new Error('disk full'); } };
  const { writeError } = emitArtifacts(r, {}, sinks);
  assert.match(writeError, /disk full/);
});

// ============================================================================
// Determinism
// ============================================================================

test('runAction is deterministic: same inputs -> identical outputs + SARIF', () => {
  const env = makeEnv({ paths: 'a.json\nb.json', family: 'identity' });
  const io = makeIo({ 'a.json': ADMIN_IDENTITY, 'b.json': CLEAN_IDENTITY });
  const r1 = runAction({ env, io });
  const r2 = runAction({ env, io });
  assert.deepEqual(r1.outputs, r2.outputs);
  assert.equal(JSON.stringify(r1.sarifLog), JSON.stringify(r2.sarifLog));
});
