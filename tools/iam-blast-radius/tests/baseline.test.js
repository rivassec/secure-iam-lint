// Accepted-results baseline (cli/baseline.mjs) through the CLI, the Action and the SARIF.
//
// The load-bearing properties: opt-in only; each result accepted INDIVIDUALLY (a new
// unknown action / finding still fails); keys bound to the file; usage / internal /
// FAILED analyses never accepted; a bad baseline is exit 2, never "no baseline";
// analysisStatus stays truthful.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import {
  applyBaseline, parseBaseline, buildBaseline, findingBaselineKey, stateBaselineKey,
  BASELINE_VERSION, MAX_BASELINE_ENTRIES,
} from '../../../cli/baseline.mjs';
import { buildSarifLog } from '../../../cli/sarif.mjs';
import { run } from '../../../cli/iam-br.mjs';
import { runAction } from '../../../action/index.mjs';

const POLICY = (actions) => JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: actions, Resource: 'arn:aws:s3:::b/*' }],
});

function scanText(text, family = 'identity') {
  return scan({ text, family, threshold: 'high', subjectAccount: '123456789012', partition: 'aws' });
}

function acceptAll(text, uri = 'p.json') {
  const keyed = applyBaseline(scanText(text), uri, null, 'high');
  return parseBaseline(JSON.stringify(buildBaseline([{ file: uri, result: keyed }]))).keys;
}

test('no baseline: the verdict is unchanged, keys are still attached', () => {
  const raw = scanText(POLICY(['s3:DeleteObject', 'sqs:SendMessage']));
  const r = applyBaseline(raw, 'p.json', null, 'high');
  assert.equal(r.exitCode, raw.exitCode);
  assert.equal(r.reason, raw.reason);
  assert.equal(r.blockingCount, raw.blockingCount);
  assert.equal(r.baseline.applied, false);
  assert.ok(r.baseline.keyOf.size >= 2);
});

test('accepting every result turns a partial exit 3 into exit 0, status stays partial', () => {
  const text = POLICY(['s3:DeleteObject', 'sqs:SendMessage']);
  const raw = scanText(text);
  assert.equal(raw.exitCode, EXIT.FAIL_CLOSED);
  const r = applyBaseline(raw, 'p.json', acceptAll(text), 'high');
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.equal(r.reason, 'CLEAN_WITH_BASELINE');
  assert.equal(r.analysisStatus, 'partial');
  assert.equal(r.blockingCount, 0);
});

test('a NEW unknown action is not covered by an accepted unknown-action state', () => {
  const keys = acceptAll(POLICY(['s3:GetObject', 'sqs:SendMessage']));
  const r = applyBaseline(scanText(POLICY(['s3:GetObject', 'sqs:SendMessage', 'sqs:DeleteQueue'])), 'p.json', keys, 'high');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('a NEW blocking finding still fails while the accepted one does not', () => {
  const keys = acceptAll(POLICY(['s3:DeleteObject']));
  const same = applyBaseline(scanText(POLICY(['s3:DeleteObject'])), 'p.json', keys, 'high');
  assert.equal(same.exitCode, EXIT.CLEAN);
  const broader = applyBaseline(scanText(POLICY(['s3:DeleteObject', 's3:PutBucketPolicy'])), 'p.json', keys, 'high');
  assert.equal(broader.exitCode, EXIT.FINDINGS);
  assert.equal(broader.blockingCount, 1);
});

test('keys are bound to the file URI', () => {
  const text = POLICY(['s3:DeleteObject', 'sqs:SendMessage']);
  const r = applyBaseline(scanText(text), 'other.json', acceptAll(text, 'p.json'), 'high');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('non-baselinable fail-closed states are never accepted', () => {
  // A FAILED analysis (malformed JSON) and a partial with a non-baselinable state.
  const malformed = scanText('{ not json');
  const r1 = applyBaseline(malformed, 'p.json', new Set(), 'high');
  assert.equal(r1.exitCode, malformed.exitCode);
  const blocked = scan({ text: POLICY(['s3:GetObject']), family: 'identity', threshold: 'high', budgetMs: 0 });
  const r2 = applyBaseline(blocked, 'p.json', new Set(), 'high');
  assert.equal(r2.exitCode, EXIT.FAIL_CLOSED);
  // A state that is not UNKNOWN_ACTION / UNSUPPORTED_CONDITION has no key at all.
  assert.equal(stateBaselineKey({ code: 'BROAD_RESOURCE_UNDECIDABLE', analysisState: 'incomplete' }, 'p.json'), null);
  assert.equal(stateBaselineKey({ code: 'UNKNOWN_ACTION', details: { actions: [] } }, 'p.json'), null);
});

test('usage (2) and internal (4) results are never changed', () => {
  for (const exitCode of [EXIT.USAGE, EXIT.INTERNAL]) {
    const r = applyBaseline({ exitCode, analysisStatus: 'failed', reason: 'X', findings: [], analysisStates: [] }, 'p.json', new Set(), 'high');
    assert.equal(r.exitCode, exitCode);
  }
});

test('keys are SHA-256 hex and deterministic; distinct identities differ', () => {
  const f = { id: 'DESTRUCTIVE-ACTION', severity: 'high', statementIndex: 0, actions: ['s3:DeleteObject'], resources: ['*'] };
  const k1 = findingBaselineKey(f, 'identity', 'p.json');
  assert.match(k1, /^[0-9a-f]{64}$/);
  assert.equal(k1, findingBaselineKey(f, 'identity', 'p.json'));
  assert.notEqual(k1, findingBaselineKey({ ...f, actions: ['s3:DeleteObject', 's3:DeleteBucket'] }, 'identity', 'p.json'));
  assert.notEqual(k1, findingBaselineKey(f, 'resource', 'p.json'));
});

test('parseBaseline validates shape, version, key format and size', () => {
  assert.equal(parseBaseline('nope').ok, false);
  assert.equal(parseBaseline('[]').ok, false);
  assert.equal(parseBaseline(JSON.stringify({ version: 2, entries: [] })).ok, false);
  assert.equal(parseBaseline(JSON.stringify({ version: BASELINE_VERSION })).ok, false);
  assert.equal(parseBaseline(JSON.stringify({ version: BASELINE_VERSION, entries: [{ id: 'ABC' }] })).ok, false);
  const many = Array.from({ length: MAX_BASELINE_ENTRIES + 1 }, () => ({ id: 'a'.repeat(64) }));
  assert.equal(parseBaseline(JSON.stringify({ version: BASELINE_VERSION, entries: many })).ok, false);
  const entry = { id: 'a'.repeat(64), file: 'p.json', ruleId: 'DESTRUCTIVE-ACTION', severity: 'high' };
  const ok = parseBaseline(JSON.stringify({ version: BASELINE_VERSION, entries: [entry] }));
  assert.equal(ok.ok, true);
  assert.equal(ok.keys.size, 1);
  // Review metadata is required, and an id may appear once.
  assert.equal(parseBaseline(JSON.stringify({ version: BASELINE_VERSION, entries: [{ id: entry.id }] })).ok, false);
  assert.equal(parseBaseline(JSON.stringify({ version: BASELINE_VERSION, entries: [{ ...entry, severity: undefined }] })).ok, false);
  assert.equal(parseBaseline(JSON.stringify({ version: BASELINE_VERSION, entries: [entry, entry] })).ok, false);
  assert.equal(parseBaseline(JSON.stringify({ version: BASELINE_VERSION, entries: [{ id: entry.id, file: 'p.json', ruleId: 'analysis.UNKNOWN_ACTION' }] })).ok, true);
});

test('SARIF publishes baselineKey; an applied baseline marks baselineState + suppressions', () => {
  const text = POLICY(['s3:DeleteObject', 'sqs:SendMessage']);
  const unapplied = buildSarifLog(applyBaseline(scanText(text), 'p.json', null, 'high'), { file: 'p.json' }, { ruleVersion: '1' });
  for (const r of unapplied.runs[0].results) {
    assert.match(r.properties.baselineId, /^[0-9a-f]{64}$/, r.ruleId);
    assert.equal(r.baselineState, undefined);
    assert.equal(r.suppressions, undefined);
  }
  const keys = acceptAll(POLICY(['s3:DeleteObject']));
  const applied = buildSarifLog(applyBaseline(scanText(text), 'p.json', keys, 'high'), { file: 'p.json' }, { ruleVersion: '1' });
  const byRule = Object.fromEntries(applied.runs[0].results.map((r) => [r.ruleId, r]));
  assert.equal(byRule['DESTRUCTIVE-ACTION'].baselineState, 'unchanged');
  assert.equal(byRule['DESTRUCTIVE-ACTION'].suppressions[0].status, 'accepted');
  assert.equal(byRule['analysis.UNKNOWN_ACTION'].baselineState, 'new');
  assert.equal(byRule['analysis.UNKNOWN_ACTION'].suppressions, undefined);
});

function cliIo(files) {
  let stdout = '';
  let stderr = '';
  return {
    io: {
      readFile: (p) => { if (!Object.hasOwn(files, p)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }); return files[p]; },
      readStdin: async () => '',
      writeFile: () => {},
      stdout: (s) => { stdout += s; },
      stderr: (s) => { stderr += s; },
      stdinIsTTY: true,
    },
    get stdout() { return stdout; },
    get stderr() { return stderr; },
  };
}

test('CLI: --format baseline then --baseline round-trips; a bad baseline is exit 2', async () => {
  const files = { 'p.json': POLICY(['s3:DeleteObject', 'sqs:SendMessage']) };
  const gen = cliIo(files);
  const base = ['--family', 'identity', '--partition', 'aws', 'p.json'];
  assert.equal(await run(['--format', 'baseline', ...base], gen.io), EXIT.FAIL_CLOSED);
  files['b.json'] = gen.stdout;
  assert.equal(await run(['--baseline', 'b.json', ...base], cliIo(files).io), EXIT.CLEAN);
  files['bad.json'] = '{"version":1,"entries":[{"id":"x"}]}';
  assert.equal(await run(['--baseline', 'bad.json', ...base], cliIo(files).io), EXIT.USAGE);
  assert.equal(await run(['--baseline', 'missing.json', ...base], cliIo(files).io), EXIT.USAGE);
});

function actionIo(files) {
  return {
    readFile: (rel) => { if (!Object.hasOwn(files, rel)) throw new Error('ENOENT'); return files[rel]; },
    listFiles: () => Object.keys(files).filter((f) => f.startsWith('p/')).sort(),
  };
}

test('Action: baseline-output then baseline turns exit 3 into 0 with truthful outputs', () => {
  const files = { 'p/a.json': POLICY(['s3:DeleteObject', 'sqs:SendMessage']) };
  const env = { INPUT_PATHS: 'p/*.json', INPUT_FAMILY: 'identity', INPUT_PARTITION: 'aws', 'INPUT_BASELINE-OUTPUT': 'iam.baseline.json' };
  const first = runAction({ env, io: actionIo(files) });
  assert.equal(first.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(first.baselinePath, 'iam.baseline.json');
  files['iam.baseline.json'] = first.baselineText;
  const second = runAction({ env: { INPUT_PATHS: 'p/*.json', INPUT_FAMILY: 'identity', INPUT_PARTITION: 'aws', INPUT_BASELINE: 'iam.baseline.json' }, io: actionIo(files) });
  assert.equal(second.exitCode, EXIT.CLEAN);
  assert.equal(second.outputs['analysis-status'], 'partial');
  assert.equal(second.outputs['baselined-count'], '2');
  assert.equal(second.outputs['baseline-stale-count'], '0');
});

test('Action: without a baseline the output set is unchanged', () => {
  const r = runAction({ env: { INPUT_PATHS: 'p/*.json', INPUT_FAMILY: 'identity', INPUT_PARTITION: 'aws' }, io: actionIo({ 'p/a.json': POLICY(['s3:GetObject']) }) });
  assert.deepEqual(Object.keys(r.outputs).sort(), ['analysis-status', 'blocking-findings-count', 'exit-code', 'findings-count', 'sarif-path']);
  assert.equal(r.baselinePath, null);
});

test('Action: an unsafe, unreadable or malformed baseline is a usage error', () => {
  const files = { 'p/a.json': POLICY(['s3:GetObject']), 'bad.json': 'not json' };
  for (const [input, value, reason] of [
    ['INPUT_BASELINE', '/etc/passwd', 'UNSAFE_BASELINE_PATH'],
    ['INPUT_BASELINE', '../x.json', 'UNSAFE_BASELINE_PATH'],
    ['INPUT_BASELINE', 'missing.json', 'BASELINE_UNREADABLE'],
    ['INPUT_BASELINE', 'bad.json', 'INVALID_BASELINE'],
    ['INPUT_BASELINE-OUTPUT', '/tmp/b.json', 'UNSAFE_BASELINE_OUTPUT'],
  ]) {
    const r = runAction({ env: { INPUT_PATHS: 'p/*.json', INPUT_FAMILY: 'identity', [input]: value }, io: actionIo(files) });
    assert.equal(r.exitCode, EXIT.USAGE, `${input}=${value}`);
    assert.equal(r.reason, reason, `${input}=${value}`);
    assert.equal(r.baselinePath, null, 'nothing is written on a usage error');
  }
});

test('a matched id with a false file / ruleId / severity label is not accepted and fails the run', async () => {
  const text = POLICY(['s3:DeleteObject']);
  const real = JSON.parse(JSON.stringify(buildBaseline([{ file: 'p.json', result: applyBaseline(scanText(text), 'p.json', null, 'high') }])));
  for (const tamper of [{ ruleId: 'WILDCARD-RESOURCE' }, { severity: 'low' }, { file: 'other.json' }]) {
    const doc = { ...real, entries: real.entries.map((e) => ({ ...e, ...tamper })) };
    const keys = parseBaseline(JSON.stringify(doc)).keys;
    const r = applyBaseline(scanText(text), 'p.json', keys, 'high');
    assert.equal(r.exitCode, EXIT.FINDINGS, JSON.stringify(tamper));
    assert.equal(r.baseline.mismatched.length, 1, JSON.stringify(tamper));
    const files = { 'p.json': text, 'b.json': JSON.stringify(doc) };
    assert.equal(await run(['--family', 'identity', '--partition', 'aws', '--baseline', 'b.json', 'p.json'], cliIo(files).io), EXIT.USAGE);
    const act = runAction({ env: { INPUT_PATHS: 'p/*.json', INPUT_FAMILY: 'identity', INPUT_PARTITION: 'aws', INPUT_BASELINE: 'b.json' },
      io: actionIo({ 'p/x.json': text, 'b.json': JSON.stringify({ ...doc, entries: doc.entries.map((e) => ({ ...e, file: e.file === 'p.json' ? 'p/x.json' : e.file })) }) }) });
    assert.notEqual(act.exitCode, EXIT.CLEAN, JSON.stringify(tamper));
  }
});

test('a severity change invalidates an accepted finding', () => {
  const f = { id: 'DESTRUCTIVE-ACTION', severity: 'medium', ruleVersion: '1', statementIndex: 0, actions: ['s3:DeleteObject'], resources: ['*'] };
  assert.notEqual(findingBaselineKey(f, 'identity', 'p.json'), findingBaselineKey({ ...f, severity: 'high' }, 'identity', 'p.json'));
  assert.notEqual(findingBaselineKey(f, 'identity', 'p.json'), findingBaselineKey({ ...f, ruleVersion: '2' }, 'identity', 'p.json'));
});

test('SARIF never suppresses a listed id on an ineligible (failed) result', () => {
  const text = POLICY(['s3:DeleteObject']);
  const keys = acceptAll(text);
  const failed = { ...scanText(text), exitCode: EXIT.FAIL_CLOSED, analysisStatus: 'failed', reason: 'RESOURCE_BUDGET_EXCEEDED' };
  const r = applyBaseline(failed, 'p.json', keys, 'high');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  const row = buildSarifLog(r, { file: 'p.json' }, { ruleVersion: '1' }).runs[0].results.find((x) => x.ruleId === 'DESTRUCTIVE-ACTION');
  assert.equal(row.baselineState, 'new');
  assert.equal(row.suppressions, undefined);
});
