// S6-sarif-testrealism: REAL-SUBPROCESS regression for SARIF as a GATE-CONSUMED
// artifact, on BOTH process faces (cli/iam-br.mjs --format sarif + action/index.mjs).
//
// THE GAP. Before this file, SARIF was only ever exercised IN-PROCESS: the suite
// called buildSarifLog()/formatSarif() directly on synthetic (and real scan())
// results and validated the returned object/string. NOTHING spawned the actual CLI
// with `--format sarif` (a real FORMATS value) and parsed the BYTES it wrote to the
// consumer, nor parsed the SARIF FILE the Action writes for the GitHub code-scanning
// gate. So a regression in the real argv/format/IO plumbing that only manifests when
// Node is the process entry point - a broken --format dispatch, a stdout the SARIF is
// never flushed to, an exit code that disagrees with the emitted SARIF - could ship
// while every in-process SARIF test stayed green.
//
// WHY A REAL SUBPROCESS. The gate consumes BYTES on stdout / a file on disk, produced
// by the real entrypoint (argv parse -> --format sarif dispatch -> formatSarif ->
// stdout/file sink -> process exit code). An in-process buildSarifLog() call skips all
// of that plumbing. Each case here therefore SPAWNS `node <entrypoint>`, JSON.parses
// the bytes the consumer would actually read, and asserts BOTH a valid SARIF 2.1.0
// shape AND that a blocking finding survives into the artifact as a result at/above
// threshold - i.e. SARIF as a gate artifact, not merely a structurally valid document.
//
// FAIL-CLOSED tie-in: the exit code the gate keys on MUST agree with the SARIF the gate
// reads. A risky policy is exit 1 with a security result present; the format never
// changes the code (a byte-faithful contract the CLI header pins).

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(here, '..', '..', '..');
const CLI_PATH = path.join(REPO, 'cli', 'iam-br.mjs');
const ACTION_PATH = path.join(REPO, 'action', 'index.mjs');

// A full-admin identity policy: `iam:*` on `*` fires DIRECT-IAM-ADMIN (severity high,
// blocking at the default 'high' threshold). A genuine analysis is exit 1 (findings)
// and the SARIF result names a rule id we can key on to prove analysis RAN.
const ADMIN_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
});

// The blocking finding types a full-admin identity policy must surface.
const BLOCKING_RULE_RE = /^(WILDCARD-ACTION|DIRECT-IAM-ADMIN)$/;

const VALID_LEVELS = new Set(['error', 'warning', 'note', 'none']);

function withTmp(prefix, fn) {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Strip inherited INPUT_*/GITHUB_* so the parent CI env cannot contaminate an Action run.
function cleanActionEnv(patch) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) {
    if (k.startsWith('INPUT_') || k.startsWith('GITHUB_')) delete env[k];
  }
  return { ...env, ...patch };
}

// A minimal SARIF 2.1.0 required-field validator (no external schema dependency).
// Returns the list of structural problems; an empty list means the log is well-formed.
function sarifStructuralProblems(log) {
  const problems = [];
  const req = (cond, msg) => { if (!cond) problems.push(msg); };
  req(log && typeof log === 'object', 'log is an object');
  req(log && log.version === '2.1.0', 'version === 2.1.0');
  req(log && Array.isArray(log.runs), 'runs is an array');
  for (const run of (log.runs || [])) {
    req(run && run.tool && run.tool.driver, 'run.tool.driver present');
    const driver = run.tool && run.tool.driver;
    req(driver && typeof driver.name === 'string' && driver.name.length > 0, 'driver.name non-empty');
    req(driver && Array.isArray(driver.rules), 'driver.rules is an array');
    req(Array.isArray(run.results), 'run.results is an array');
    for (const r of (run.results || [])) {
      req(r && typeof r.ruleId === 'string' && r.ruleId.length > 0, 'result.ruleId non-empty');
      req(r && r.message && typeof r.message.text === 'string' && r.message.text.length > 0,
        'result.message.text non-empty');
      req(r && VALID_LEVELS.has(r.level), `result.level valid (${r && r.level})`);
      req(r && Array.isArray(r.locations) && r.locations.length >= 1, 'result.locations >= 1');
      const uri = r && r.locations && r.locations[0]
        && r.locations[0].physicalLocation
        && r.locations[0].physicalLocation.artifactLocation
        && r.locations[0].physicalLocation.artifactLocation.uri;
      req(typeof uri === 'string' && uri.length > 0, 'artifactLocation.uri non-empty');
    }
  }
  return problems;
}

// Assert `log` carries a BLOCKING security finding present as a result at/above the
// 'high' threshold: level error, category security, a security-severity, keyed on a
// rule id a full-admin policy must surface. Proves analysis RAN into the artifact.
function assertBlockingSecurityResult(log) {
  const results = log.runs.flatMap((run) => run.results || []);
  const blocking = results.find((r) => r
    && r.properties && r.properties.category === 'security'
    && r.level === 'error'
    && BLOCKING_RULE_RE.test(r.ruleId));
  assert.ok(blocking, 'a blocking security result (error-level) is present in the SARIF');
  assert.ok('security-severity' in blocking.properties,
    'the blocking result carries a security-severity (a real vulnerability, not an analyzer state)');
  assert.equal(blocking.properties.severity, 'high', 'the blocking finding is at the high threshold');
  // The rule descriptor for that result exists in the driver (ruleId -> reportingDescriptor).
  const driverRules = log.runs
    .find((run) => (run.results || []).includes(blocking))
    .tool.driver.rules;
  assert.ok(driverRules.some((rule) => rule.id === blocking.ruleId),
    'the blocking result ruleId resolves to a reportingDescriptor');
}

// =============================================================================
// CLI (cli/iam-br.mjs) --format sarif  -- SARIF bytes on stdout, and to --output.
// =============================================================================

test('CLI --format sarif on a risky fixture: real subprocess emits gate-consumable SARIF 2.1.0 with a blocking result (exit 1)', () => {
  withTmp('ibr-sarif-cli-', (dir) => {
    // A risky policy FIXTURE on disk (exercises the real file-read path too).
    const fixture = path.join(dir, 'admin.json');
    writeFileSync(fixture, ADMIN_POLICY);

    const p = spawnSync('node', [CLI_PATH, '--family', 'identity', '--format', 'sarif', fixture], {
      encoding: 'utf8',
    });

    // The gate keys on the exit code; a risky policy is exit 1 regardless of format.
    assert.equal(p.status, 1, 'a risky policy scanned as SARIF is exit 1 (findings), never a false clean');

    // Parse the exact BYTES the consumer would read off stdout.
    let log;
    assert.doesNotThrow(() => { log = JSON.parse(p.stdout); },
      'the emitted stdout bytes are valid JSON');
    assert.deepEqual(sarifStructuralProblems(log), [], 'stdout is a structurally valid SARIF 2.1.0 log');
    // The run-level verdict mirror agrees with the process exit code.
    assert.equal(log.runs[0].properties.exitCode, 1, 'run-level exitCode mirror agrees with the gate exit code');
    assert.equal(log.runs[0].properties.analysisStatus, 'complete');
    assertBlockingSecurityResult(log);
    // The file uri (not the stdin default) is recorded for a file-arg invocation.
    const uri = log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    assert.notEqual(uri, 'stdin', 'a file-arg invocation records the file path, not the stdin default');
    assert.match(uri, /admin\.json$/, 'the artifact uri is the scanned file path');
  });
});

test('CLI --format sarif --output: real subprocess writes gate-consumable SARIF bytes to a file (exit 1)', () => {
  withTmp('ibr-sarif-cli-out-', (dir) => {
    const fixture = path.join(dir, 'admin.json');
    writeFileSync(fixture, ADMIN_POLICY);

    // --output must be a CONFINED relative path; run with cwd=dir so it lands inside.
    const p = spawnSync('node', [
      CLI_PATH, '--family', 'identity', '--format', 'sarif', '--output', 'report.sarif', 'admin.json',
    ], { cwd: dir, encoding: 'utf8' });

    assert.equal(p.status, 1, 'writing SARIF to a file does not change the gate exit code');
    const bytes = readFileSync(path.join(dir, 'report.sarif'), 'utf8');
    const log = JSON.parse(bytes);
    assert.deepEqual(sarifStructuralProblems(log), [], 'the written file is a valid SARIF 2.1.0 log');
    assertBlockingSecurityResult(log);
  });
});

test('CLI --format sarif on a CLEAN fixture: real subprocess emits an empty-results SARIF and exits 0', () => {
  withTmp('ibr-sarif-cli-clean-', (dir) => {
    const clean = JSON.stringify({
      Version: '2012-10-17',
      Statement: [{
        Effect: 'Allow', Action: 'ec2:DescribeInstances',
        Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc',
      }],
    });
    const fixture = path.join(dir, 'clean.json');
    writeFileSync(fixture, clean);

    const p = spawnSync('node', [CLI_PATH, '--family', 'identity', '--format', 'sarif', fixture], {
      encoding: 'utf8',
    });
    assert.equal(p.status, 0, 'a genuinely clean policy is exit 0');
    const log = JSON.parse(p.stdout);
    assert.deepEqual(sarifStructuralProblems(log), [], 'a clean SARIF is still structurally valid');
    assert.deepEqual(log.runs[0].results, [], 'a clean scan yields zero SARIF results');
    assert.equal(log.runs[0].properties.exitCode, 0);
  });
});

// =============================================================================
// Action (action/index.mjs) -- the SARIF FILE it writes IS the gate-consumed artifact.
// =============================================================================

function makeActionWorkspace() {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-sarif-act-ws-'));
  mkdirSync(path.join(ws, 'policies'));
  writeFileSync(path.join(ws, 'policies', 'admin.json'), ADMIN_POLICY);
  const outFile = path.join(ws, '.gh_output');
  writeFileSync(outFile, '');
  const summaryFile = path.join(ws, '.gh_summary');
  writeFileSync(summaryFile, '');
  return { ws, outFile, summaryFile };
}

// A faithful GITHUB_OUTPUT parser (GitHub's env-file semantics for our single-line
// scalar outputs): `name=value` per top-level line.
function parseGithubOutput(body) {
  const out = {};
  for (const line of String(body).split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0 && !line.includes('<<')) out[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return out;
}

test('Action real subprocess on a risky tree: writes a gate-consumable SARIF 2.1.0 file with a blocking result AND a matching GITHUB_OUTPUT (fails the check)', () => {
  const { ws, outFile, summaryFile } = makeActionWorkspace();
  try {
    const p = spawnSync('node', [ACTION_PATH], {
      cwd: ws,
      env: cleanActionEnv({
        GITHUB_WORKSPACE: ws,
        GITHUB_OUTPUT: outFile,
        GITHUB_STEP_SUMMARY: summaryFile,
        INPUT_PATHS: 'policies/**/*.json',
        INPUT_FAMILY: 'identity',
        INPUT_FAIL_ON: 'high',
      }),
      encoding: 'utf8',
    });

    // The gate keys on a non-zero exit; a risky tree fails the check.
    assert.equal(p.status, 1, 'a risky tree fails the Action check (exit 1), never a green pass');

    // The SARIF FILE the Action wrote is what GitHub code-scanning ingests: parse it.
    const sarifBytes = readFileSync(path.join(ws, 'iam-blast-radius.sarif'), 'utf8');
    let log;
    assert.doesNotThrow(() => { log = JSON.parse(sarifBytes); }, 'the SARIF file bytes are valid JSON');
    assert.deepEqual(sarifStructuralProblems(log), [],
      'the Action SARIF file is a structurally valid SARIF 2.1.0 log');
    assertBlockingSecurityResult(log);

    // GITHUB_OUTPUT (the step-output contract) agrees with the SARIF gate artifact.
    const outputs = parseGithubOutput(readFileSync(outFile, 'utf8'));
    assert.equal(outputs['exit-code'], '1', 'GITHUB_OUTPUT exit-code reflects real findings');
    assert.equal(outputs['analysis-status'], 'complete');
    assert.equal(outputs['sarif-path'], 'iam-blast-radius.sarif', 'GITHUB_OUTPUT names the SARIF gate artifact');
    assert.ok(Number(outputs['blocking-findings-count']) >= 1, 'GITHUB_OUTPUT reports >= 1 blocking finding');
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});
