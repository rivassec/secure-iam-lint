// Tests for the headless CLI (Phase 15, story P15-cli).
//
// The CLI (cli/iam-br.mjs) is the process-face ADAPTER over the pure scan module.
// These tests pin the LOAD-BEARING invariant it exists to enforce: the exit-code
// contract survives argv parsing, file/STDIN input, and JSON *or* SARIF formatting,
// and a fail-closed "could not analyze" NEVER collapses to 0/clean.
//
// The core is exercised through `run(argv, io)` with an INJECTED I/O surface (no
// process spawn, deterministic, fast), plus one real end-to-end spawn of the actual
// file to prove the shebang/runnable path and that process exit codes propagate.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  run, parseArgs, EXIT, formatSarif, formatJson, toJsonReport, versionString, HELP_TEXT,
} from '../../../cli/iam-br.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = join(here, '..', '..', '..', 'cli', 'iam-br.mjs');

// --- Fixtures (inline, deterministic) ----------------------------------------

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

// A PassRole path pinned to a CONCRETE account, NO subject account -> unknown
// viability -> partial -> exit 3.
const PASSROLE_UNKNOWN = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::999988887777:role/app' },
    { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
  ],
});

// Cross-partition PassRole role: viability depends on the subject's partition, which
// account ids do not encode. With a subject account but NO partition it must fail
// closed (exit 3), NOT be silently evaluated as a confident 'aws' assertion.
const PASSROLE_GOVCLOUD = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws-us-gov:iam::111122223333:role/app' },
    { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
  ],
});

const RESOURCE_SHAPE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::bucket/*',
  }],
});

const MALFORMED = '{ not valid json';

// A full-admin Allow whose grant is silently suppressed by the engine's condition-
// VALUE handling on a MODELED key: a non-string ForAnyValue member ([{}]) is dropped
// by toValueArray and the emptied set makes the whole Allow a never-match. AWS also
// rejects the element as MalformedPolicyDocument. It must fail closed (exit 3), never
// pass a CI gate as CLEAN (P15-cli iteration 2 BLOCKER).
const MASKED_COND_ADMIN = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow', Action: '*', Resource: '*',
    Condition: { 'ForAnyValue:StringEquals': { 'aws:SourceVpc': [{}] } },
  }],
});

// A broad-resource single-action grant expressed as an empty-array NotResource
// complement. Under AWS semantics an empty NotResource excludes nothing, so this
// Allow applies to EVERY resource - byte-for-byte the same broad scope as
// Resource:"*". The engine models it as "no resource scope" and never fires
// WILDCARD-RESOURCE, so it would otherwise pass a CI gate CLEAN (exit 0) while the
// byte-equivalent Resource:"*" blocks at exit 1. It must fail closed (exit 3),
// never pass CLEAN (P15-purity iteration 3 BLOCKER).
const EMPTY_NOTRESOURCE_ADMIN = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:PassRole', NotResource: [] }],
});
// The byte-equivalent broad-resource control expressed as Resource:"*" (exit 1).
const RESOURCE_STAR_ADMIN = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' }],
});

// --- Injected-I/O harness -----------------------------------------------------

// Build a fake io. `stdin` is the piped policy text (null => a TTY with no input).
// `files` maps a path -> its contents (a missing key throws ENOENT like fs would).
function makeIo({ stdin = null, files = {}, scan, manifest } = {}) {
  const out = [];
  const err = [];
  const written = {};
  const io = {
    readFile(p) {
      if (Object.prototype.hasOwnProperty.call(files, p)) return files[p];
      const e = new Error(`ENOENT: no such file '${p}'`);
      e.code = 'ENOENT';
      throw e;
    },
    async readStdin() { return stdin == null ? '' : stdin; },
    writeFile(p, data) { written[p] = data; },
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    stdinIsTTY: stdin == null,
  };
  if (scan) io.scan = scan;
  if (manifest) io.manifest = manifest;
  return {
    io,
    stdout: () => out.join(''),
    stderr: () => err.join(''),
    written,
  };
}

async function runWith(argv, ioOpts) {
  const h = makeIo(ioOpts);
  const code = await run(argv, h.io);
  return { code, stdout: h.stdout(), stderr: h.stderr(), written: h.written };
}

// =============================================================================
// THE EXIT-CODE MATRIX: one crafted input per contract code, asserting the code.
// =============================================================================

test('EXIT-CODE MATRIX: 0 = analyzed, no findings at/above threshold', async () => {
  const r = await runWith(['--family', 'identity'], { stdin: CLEAN_IDENTITY });
  assert.equal(r.code, 0);
  assert.equal(r.code, EXIT.CLEAN);
});

test('EXIT-CODE MATRIX: 1 = analyzed, findings at/above threshold', async () => {
  const r = await runWith(['--family', 'identity'], { stdin: ADMIN_IDENTITY });
  assert.equal(r.code, 1);
  assert.equal(r.code, EXIT.FINDINGS);
});

test('EXIT-CODE MATRIX: 2 = usage/config error (missing --family)', async () => {
  const r = await runWith([], { stdin: CLEAN_IDENTITY });
  assert.equal(r.code, 2);
  assert.equal(r.code, EXIT.USAGE);
});

test('EXIT-CODE MATRIX: 3 = fail-closed could-not-analyze (malformed input)', async () => {
  const r = await runWith(['--family', 'identity'], { stdin: MALFORMED });
  assert.equal(r.code, 3);
  assert.equal(r.code, EXIT.FAIL_CLOSED);
});

test('EXIT-CODE MATRIX: 4 = internal invariant error (scan reports INTERNAL)', async () => {
  // An internal invariant error is, by design, unreachable via normal input (the
  // engine never throws). Craft it by injecting a scan that returns exit 4 - the
  // CLI MUST propagate it faithfully and never downgrade it to 0.
  const internalScan = () => Object.freeze({
    analysisStatus: 'failed',
    analysisStates: [{ analysisState: 'internal', code: 'INTERNAL', message: 'boom' }],
    findings: [],
    blockingCount: 0,
    findingsCount: 0,
    exitCode: 4,
    reason: 'INTERNAL',
    family: 'identity',
  });
  const r = await runWith(['--family', 'identity'], { stdin: CLEAN_IDENTITY, scan: internalScan });
  assert.equal(r.code, 4);
  assert.equal(r.code, EXIT.INTERNAL);
});

test('EXIT-CODE MATRIX is exhaustive: every code 0..4 is producible', async () => {
  const codes = new Set();
  codes.add((await runWith(['--family', 'identity'], { stdin: CLEAN_IDENTITY })).code); // 0
  codes.add((await runWith(['--family', 'identity'], { stdin: ADMIN_IDENTITY })).code); // 1
  codes.add((await runWith([], { stdin: CLEAN_IDENTITY })).code); // 2
  codes.add((await runWith(['--family', 'identity'], { stdin: MALFORMED })).code); // 3
  codes.add((await runWith(['--family', 'identity'], {
    stdin: CLEAN_IDENTITY,
    scan: () => ({ analysisStatus: 'failed', analysisStates: [], findings: [], blockingCount: 0, findingsCount: 0, exitCode: 4, reason: 'INTERNAL' }),
  })).code); // 4
  assert.deepEqual([...codes].sort(), [0, 1, 2, 3, 4]);
});

// =============================================================================
// Adversarial: fail-closed must NEVER collapse to 0/clean.
// =============================================================================

test('missing --family is exit 2 and is NEVER auto-detected as identity', async () => {
  // The same bytes would be a clean identity analysis WITH --family; without it the
  // CLI must refuse (exit 2), not guess the family and pass.
  const r = await runWith([], { stdin: CLEAN_IDENTITY });
  assert.equal(r.code, EXIT.USAGE);
  assert.match(r.stderr, /--family/);
  assert.equal(r.stdout, '', 'no analysis output is produced for a usage error');
});

test('--family auto is refused (exit 2), not treated as auto-detection', async () => {
  const r = await runWith(['--family', 'auto'], { stdin: CLEAN_IDENTITY });
  assert.equal(r.code, EXIT.USAGE);
});

test('an unknown --family value is a usage error (exit 2), never analyzed', async () => {
  // A family that does not exist is a caller mistake (exit 2), distinct from a
  // valid family whose document cannot be analyzed (exit 3). Never analyzed.
  const r = await runWith(['--family', 'bogus'], { stdin: CLEAN_IDENTITY });
  assert.equal(r.code, EXIT.USAGE);
  assert.equal(r.stdout, '', 'no analysis output is produced for a usage error');
});

test('a fail-closed malformed input is exit 3, never 0', async () => {
  const r = await runWith(['--family', 'identity'], { stdin: MALFORMED });
  assert.equal(r.code, EXIT.FAIL_CLOSED);
  assert.notEqual(r.code, EXIT.CLEAN);
});

test('an unsupported family/shape is exit 3, never 0', async () => {
  const r = await runWith(['--family', 'resource'], { stdin: RESOURCE_SHAPE });
  assert.equal(r.code, EXIT.FAIL_CLOSED);
  assert.notEqual(r.code, EXIT.CLEAN);
});

test('an unknown-viability finding is exit 3, never 0', async () => {
  const r = await runWith(['--family', 'identity'], { stdin: PASSROLE_UNKNOWN });
  assert.equal(r.code, EXIT.FAIL_CLOSED);
});

test('--threshold none does NOT turn a malformed fail-closed 3 into 0', async () => {
  const r = await runWith(['--family', 'identity', '--threshold', 'none'], { stdin: MALFORMED });
  assert.equal(r.code, EXIT.FAIL_CLOSED);
  assert.notEqual(r.code, EXIT.CLEAN);
});

test('--threshold none does NOT turn an unknown-viability partial into 0', async () => {
  const r = await runWith(['--family', 'identity', '--threshold', 'none'], { stdin: PASSROLE_UNKNOWN });
  assert.equal(r.code, EXIT.FAIL_CLOSED);
});

test('--threshold none DOES yield exit 0 for a genuinely complete analysis with findings', async () => {
  const r = await runWith(['--family', 'identity', '--threshold', 'none'], { stdin: ADMIN_IDENTITY });
  assert.equal(r.code, EXIT.CLEAN);
});

// =============================================================================
// Partition fail-closed: the CLI must NOT inject a confident 'aws' default.
// =============================================================================

test('cross-partition PassRole with subject account but NO --partition -> exit 3 (no injected aws)', async () => {
  const r = await runWith(
    ['--family', 'identity', '--subject-account', '111122223333'],
    { stdin: PASSROLE_GOVCLOUD },
  );
  assert.equal(r.code, EXIT.FAIL_CLOSED, 'omitting --partition must stay UNKNOWN, not default-aws confident');
  assert.notEqual(r.code, EXIT.CLEAN);
});

test('an unrecognized --partition token is treated as omitted -> still exit 3', async () => {
  const r = await runWith(
    ['--family', 'identity', '--subject-account', '111122223333', '--partition', 'banana'],
    { stdin: PASSROLE_GOVCLOUD },
  );
  assert.equal(r.code, EXIT.FAIL_CLOSED);
});

test('explicit --partition aws-us-gov resolves the path as viable -> exit 1', async () => {
  const r = await runWith(
    ['--family', 'identity', '--subject-account', '111122223333', '--partition', 'aws-us-gov'],
    { stdin: PASSROLE_GOVCLOUD },
  );
  assert.equal(r.code, EXIT.FINDINGS);
});

test('explicit --partition aws is a CONFIDENT mismatch -> complete, exit 0', async () => {
  const r = await runWith(
    ['--family', 'identity', '--subject-account', '111122223333', '--partition', 'aws'],
    { stdin: PASSROLE_GOVCLOUD },
  );
  assert.equal(r.code, EXIT.CLEAN);
});

// =============================================================================
// Format never changes the exit code (JSON vs SARIF).
// =============================================================================

test('--format sarif preserves the exit code across the whole matrix', async () => {
  const cases = [
    [CLEAN_IDENTITY, ['--family', 'identity'], EXIT.CLEAN],
    [ADMIN_IDENTITY, ['--family', 'identity'], EXIT.FINDINGS],
    [MALFORMED, ['--family', 'identity'], EXIT.FAIL_CLOSED],
    [RESOURCE_SHAPE, ['--family', 'resource'], EXIT.FAIL_CLOSED],
  ];
  for (const [stdin, baseArgs, expected] of cases) {
    const j = await runWith(baseArgs, { stdin });
    const s = await runWith([...baseArgs, '--format', 'sarif'], { stdin });
    assert.equal(j.code, expected, `json code for ${baseArgs.join(' ')}`);
    assert.equal(s.code, expected, `sarif code must match json for ${baseArgs.join(' ')}`);
  }
});

test('SARIF of a fail-closed run carries an analyzer-state result with NO security-severity', async () => {
  const r = await runWith(['--family', 'identity', '--format', 'sarif'], { stdin: MALFORMED });
  assert.equal(r.code, EXIT.FAIL_CLOSED);
  const sarif = JSON.parse(r.stdout);
  const results = sarif.runs[0].results;
  assert.ok(results.length >= 1);
  for (const res of results) {
    assert.equal(res.properties.category, 'analysis-state');
    assert.equal(res.properties.failClosed, true);
    assert.equal(res.kind, 'fail');
    assert.equal(res.level, 'error');
    assert.ok(!('security-severity' in res.properties), 'analyzer-state must NOT carry security-severity');
  }
});

test('masked-condition full-admin fail-open exits 3 through the CLI (JSON and SARIF), never 0', async () => {
  const j = await runWith(['--family', 'identity'], { stdin: MASKED_COND_ADMIN });
  assert.equal(j.code, EXIT.FAIL_CLOSED);
  assert.notEqual(j.code, EXIT.CLEAN);
  const report = JSON.parse(j.stdout);
  assert.notEqual(report.analysisStatus, 'complete');
  assert.equal(report.exitCode, 3);
  // --threshold none must NOT collapse the fail-closed to 0/clean.
  const none = await runWith(['--family', 'identity', '--threshold', 'none'], { stdin: MASKED_COND_ADMIN });
  assert.equal(none.code, EXIT.FAIL_CLOSED);
  // SARIF: same exit code, and the analyzer-state result is SEPARATED (no security-severity).
  const s = await runWith(['--family', 'identity', '--format', 'sarif'], { stdin: MASKED_COND_ADMIN });
  assert.equal(s.code, EXIT.FAIL_CLOSED);
  const sarif = JSON.parse(s.stdout);
  const states = sarif.runs[0].results.filter((x) => x.properties.category === 'analysis-state');
  assert.ok(states.length >= 1, 'a fail-closed analyzer-state result is present');
  for (const res of states) {
    assert.equal(res.properties.failClosed, true);
    assert.ok(!('security-severity' in res.properties), 'analyzer-state must NOT carry security-severity');
  }
});

test('E2E: masked-condition full-admin fail-open exits 3 through a real process spawn', () => {
  assert.equal(spawnCli(['--family', 'identity'], MASKED_COND_ADMIN).status, 3);
  assert.equal(spawnCli(['--family', 'identity', '--threshold', 'none'], MASKED_COND_ADMIN).status, 3);
});

test('empty-NotResource broad-resource fail-open exits 3 through the CLI (JSON and SARIF), never 0', async () => {
  const j = await runWith(['--family', 'identity'], { stdin: EMPTY_NOTRESOURCE_ADMIN });
  assert.equal(j.code, EXIT.FAIL_CLOSED);
  assert.notEqual(j.code, EXIT.CLEAN);
  const report = JSON.parse(j.stdout);
  assert.notEqual(report.analysisStatus, 'complete');
  assert.equal(report.exitCode, 3);
  assert.equal(report.reason, 'EMPTY_NOTRESOURCE_COMPLEMENT');
  // --threshold none must NOT collapse the fail-closed to 0/clean.
  const none = await runWith(['--family', 'identity', '--threshold', 'none'], { stdin: EMPTY_NOTRESOURCE_ADMIN });
  assert.equal(none.code, EXIT.FAIL_CLOSED);
  // SARIF: same exit code, and the analyzer-state result is SEPARATED (no security-severity).
  const s = await runWith(['--family', 'identity', '--format', 'sarif'], { stdin: EMPTY_NOTRESOURCE_ADMIN });
  assert.equal(s.code, EXIT.FAIL_CLOSED);
  const sarif = JSON.parse(s.stdout);
  const states = sarif.runs[0].results.filter((x) => x.properties.category === 'analysis-state');
  assert.ok(states.length >= 1, 'a fail-closed analyzer-state result is present');
  for (const res of states) {
    assert.equal(res.properties.failClosed, true);
    assert.equal(res.kind, 'fail');
    assert.equal(res.level, 'error');
    assert.ok(!('security-severity' in res.properties), 'analyzer-state must NOT carry security-severity');
  }
});

test('NotResource:[] and its Resource:"*" twin both FAIL the gate through the CLI (never one exit 0)', async () => {
  // The byte-equivalent broad-resource grants must never split into one clean, one
  // blocked: Resource:"*" blocks at exit 1; NotResource:[] must also fail (exit 3).
  const control = await runWith(['--family', 'identity', '--threshold', 'high'], { stdin: RESOURCE_STAR_ADMIN });
  const twin = await runWith(['--family', 'identity', '--threshold', 'high'], { stdin: EMPTY_NOTRESOURCE_ADMIN });
  assert.equal(control.code, EXIT.FINDINGS, 'Resource:"*" control blocks at exit 1');
  assert.notEqual(twin.code, EXIT.CLEAN, 'NotResource:[] twin must NEVER be clean exit 0');
  // A CI gate treats both 1 and 3 as FAILED - the twins are equivalent at the gate.
  for (const code of [control.code, twin.code]) {
    assert.ok([EXIT.FINDINGS, EXIT.FAIL_CLOSED].includes(code), `code ${code} must be a gate FAIL`);
  }
});

test('E2E: empty-NotResource broad-resource fail-open exits 3 through a real process spawn', () => {
  assert.equal(spawnCli(['--family', 'identity'], EMPTY_NOTRESOURCE_ADMIN).status, 3);
  assert.equal(spawnCli(['--family', 'identity', '--threshold', 'none'], EMPTY_NOTRESOURCE_ADMIN).status, 3);
  // The byte-equivalent Resource:"*" control blocks (exit 1) - never one clean twin.
  assert.equal(spawnCli(['--family', 'identity'], RESOURCE_STAR_ADMIN).status, 1);
});

test('SARIF of a findings run maps severity to level + security-severity (security, not analysis-state)', async () => {
  const r = await runWith(['--family', 'identity', '--format', 'sarif'], { stdin: ADMIN_IDENTITY });
  assert.equal(r.code, EXIT.FINDINGS);
  const sarif = JSON.parse(r.stdout);
  const results = sarif.runs[0].results;
  const security = results.filter((x) => x.properties.category === 'security');
  assert.ok(security.length >= 1, 'a security finding is present');
  for (const res of security) {
    assert.ok(['error', 'warning', 'note'].includes(res.level));
    assert.notEqual(res.kind, 'fail');
  }
});

test('SARIF envelope is structurally a SARIF 2.1.0 log', async () => {
  const r = await runWith(['--family', 'identity', '--format', 'sarif'], { stdin: CLEAN_IDENTITY });
  const sarif = JSON.parse(r.stdout);
  assert.equal(sarif.version, '2.1.0');
  assert.ok(Array.isArray(sarif.runs) && sarif.runs.length === 1);
  assert.equal(sarif.runs[0].tool.driver.name, 'IAM Blast Radius');
  assert.ok(Array.isArray(sarif.runs[0].results));
});

test('--artifact-uri overrides the SARIF location uri; default for stdin is "stdin"', async () => {
  const dflt = await runWith(['--family', 'identity', '--format', 'sarif'], { stdin: MALFORMED });
  const loc = JSON.parse(dflt.stdout).runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  assert.equal(loc, 'stdin');

  const custom = await runWith(
    ['--family', 'identity', '--format', 'sarif', '--artifact-uri', 'policies/app.json'],
    { stdin: MALFORMED },
  );
  const loc2 = JSON.parse(custom.stdout).runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  assert.equal(loc2, 'policies/app.json');
});

// =============================================================================
// I/O plumbing: file input, STDIN, stdout/stderr split, --output.
// =============================================================================

test('reads the policy from a file argument', async () => {
  const r = await runWith(['--family', 'identity', 'policy.json'], {
    files: { 'policy.json': ADMIN_IDENTITY },
  });
  assert.equal(r.code, EXIT.FINDINGS);
});

test('a missing/unreadable file is a usage error (exit 2), NOT a clean scan', async () => {
  const r = await runWith(['--family', 'identity', 'nope.json'], { files: {} });
  assert.equal(r.code, EXIT.USAGE);
  assert.notEqual(r.code, EXIT.CLEAN);
  assert.match(r.stderr, /cannot read policy file/);
});

test('empty STDIN with no file is a usage error (exit 2)', async () => {
  const r = await runWith(['--family', 'identity'], { stdin: '' });
  assert.equal(r.code, EXIT.USAGE);
});

test('no file and an interactive TTY (no piped input) is a usage error (exit 2)', async () => {
  const r = await runWith(['--family', 'identity'], { stdin: null });
  assert.equal(r.code, EXIT.USAGE);
  assert.match(r.stderr, /no data on stdin|no policy file/);
});

test('analysis output goes to STDOUT; diagnostics go to STDERR', async () => {
  const r = await runWith(['--family', 'identity'], { stdin: CLEAN_IDENTITY });
  const parsed = JSON.parse(r.stdout); // stdout is pure JSON
  assert.equal(parsed.analysisStatus, 'complete');
  assert.match(r.stderr, /iam-br: status=complete exit=0/);
  // The diagnostic must NOT leak policy content (no ARNs/account ids on stderr).
  assert.doesNotMatch(r.stderr, /arn:aws|111122223333/);
});

test('--output writes formatted output to a file and leaves STDOUT empty', async () => {
  const r = await runWith(['--family', 'identity', '--output', 'out.json'], { stdin: ADMIN_IDENTITY });
  assert.equal(r.code, EXIT.FINDINGS);
  assert.equal(r.stdout, '', 'stdout is empty when writing to a file');
  assert.ok(r.written['out.json'], 'the output file was written');
  const parsed = JSON.parse(r.written['out.json']);
  assert.equal(parsed.exitCode, 1);
});

// =============================================================================
// --version / --help / bad flags.
// =============================================================================

test('--version prints the version and exits 0 without analyzing', async () => {
  const r = await runWith(['--version'], { stdin: MALFORMED });
  assert.equal(r.code, EXIT.CLEAN);
  assert.match(r.stdout, /IAM Blast Radius/);
});

test('--version short-circuits even when --family is absent', async () => {
  const r = await runWith(['--version'], { stdin: null });
  assert.equal(r.code, EXIT.CLEAN);
});

test('--help prints usage and exits 0', async () => {
  const r = await runWith(['--help'], { stdin: null });
  assert.equal(r.code, EXIT.CLEAN);
  assert.match(r.stdout, /USAGE/);
  assert.equal(r.stdout, HELP_TEXT);
});

test('-h is an alias for --help', async () => {
  const r = await runWith(['-h'], { stdin: null });
  assert.equal(r.code, EXIT.CLEAN);
  assert.match(r.stdout, /USAGE/);
});

test('an unknown flag is a usage error (exit 2)', async () => {
  const r = await runWith(['--family', 'identity', '--bogus'], { stdin: CLEAN_IDENTITY });
  assert.equal(r.code, EXIT.USAGE);
});

test('an invalid --format is a usage error (exit 2)', async () => {
  const r = await runWith(['--family', 'identity', '--format', 'xml'], { stdin: CLEAN_IDENTITY });
  assert.equal(r.code, EXIT.USAGE);
});

test('an invalid --threshold is a usage error (exit 2)', async () => {
  const r = await runWith(['--family', 'identity', '--threshold', 'nope'], { stdin: CLEAN_IDENTITY });
  assert.equal(r.code, EXIT.USAGE);
});

test('more than one policy file is a usage error (exit 2)', async () => {
  const r = await runWith(['--family', 'identity', 'a.json', 'b.json'], {
    files: { 'a.json': CLEAN_IDENTITY, 'b.json': CLEAN_IDENTITY },
  });
  assert.equal(r.code, EXIT.USAGE);
});

test('a value flag missing its value is a usage error (exit 2)', async () => {
  const r = await runWith(['--family'], { stdin: CLEAN_IDENTITY });
  assert.equal(r.code, EXIT.USAGE);
});

// =============================================================================
// parseArgs unit coverage (--flag=value, defaults, partition-not-asserted).
// =============================================================================

test('parseArgs supports --flag=value and --flag value forms', () => {
  const a = parseArgs(['--family=identity', '--threshold=low']);
  assert.equal(a.ok, true);
  assert.equal(a.opts.family, 'identity');
  assert.equal(a.opts.threshold, 'low');
  const b = parseArgs(['--family', 'identity', '--threshold', 'low']);
  assert.equal(b.opts.threshold, 'low');
});

test('parseArgs defaults: threshold=high, format=json, partition undefined (NOT aws)', () => {
  const a = parseArgs(['--family', 'identity']);
  assert.equal(a.opts.threshold, 'high');
  assert.equal(a.opts.format, 'json');
  assert.equal(a.opts.partition, undefined, 'partition must default to undefined so omission stays fail-closed');
});

test('parseArgs treats "-" positional as STDIN (no file)', () => {
  const a = parseArgs(['--family', 'identity', '-']);
  assert.equal(a.ok, true);
  assert.equal(a.opts.file, undefined);
});

// =============================================================================
// Determinism + robustness.
// =============================================================================

test('CLI JSON output is deterministic (same argv + input -> byte-identical stdout)', async () => {
  const a = await runWith(['--family', 'identity'], { stdin: PASSROLE_UNKNOWN });
  const b = await runWith(['--family', 'identity'], { stdin: PASSROLE_UNKNOWN });
  assert.equal(a.stdout, b.stdout);
  assert.equal(a.code, b.code);
});

test('an unexpected throw in scan fails CLOSED to exit 4, never 0', async () => {
  const throwingScan = () => { throw new Error('unexpected'); };
  const r = await runWith(['--family', 'identity'], { stdin: CLEAN_IDENTITY, scan: throwingScan });
  assert.equal(r.code, EXIT.INTERNAL);
  assert.notEqual(r.code, EXIT.CLEAN);
});

test('an out-of-range exit code from scan fails CLOSED to exit 4, never 0', async () => {
  const weirdScan = () => ({ analysisStatus: 'complete', analysisStates: [], findings: [], blockingCount: 0, findingsCount: 0, exitCode: 99, reason: 'X' });
  const r = await runWith(['--family', 'identity'], { stdin: CLEAN_IDENTITY, scan: weirdScan });
  assert.equal(r.code, EXIT.INTERNAL);
  assert.notEqual(r.code, EXIT.CLEAN);
});

test('a formatting failure fails CLOSED (never downgrades a findings/fail-closed code to 0)', async () => {
  // Inject a scan whose findings contain a value that JSON.stringify cannot encode
  // (a BigInt) so formatting throws; the CLI must return 4, never 0.
  const badFindingScan = () => ({
    analysisStatus: 'complete', analysisStates: [], findings: [{ id: 'X', big: 1n }],
    blockingCount: 1, findingsCount: 1, exitCode: 1, reason: 'FINDINGS_AT_OR_ABOVE_THRESHOLD', family: 'identity',
  });
  const r = await runWith(['--family', 'identity'], { stdin: CLEAN_IDENTITY, scan: badFindingScan });
  assert.equal(r.code, EXIT.INTERNAL);
  assert.notEqual(r.code, EXIT.CLEAN);
});

test('run never throws on hostile argv', async () => {
  for (const argv of [null, undefined, [42], ['--family', 'identity', '--family']]) {
    await assert.doesNotReject(async () => {
      await run(argv, makeIo({ stdin: CLEAN_IDENTITY }).io);
    });
  }
});

test('exit-code constants are stable', () => {
  assert.deepEqual({ ...EXIT }, { CLEAN: 0, FINDINGS: 1, USAGE: 2, FAIL_CLOSED: 3, INTERNAL: 4 });
});

test('toJsonReport surfaces the load-bearing verdict fields', () => {
  const r = toJsonReport(
    { analysisStatus: 'failed', analysisStates: [{ code: 'X' }], findings: [], findingsCount: 0, blockingCount: 0, exitCode: 3, reason: 'MALFORMED_INPUT', family: 'identity' },
    { family: 'identity', threshold: 'high' },
  );
  assert.equal(r.analysisStatus, 'failed');
  assert.equal(r.exitCode, 3);
  assert.equal(r.reason, 'MALFORMED_INPUT');
  assert.equal(r.partitionAsserted, null);
});

test('versionString is derived from the canonical manifest', () => {
  const s = versionString({ ruleVersion: '9', actionCatalogVersion: '2099.01.01', buildSha: 'abc' });
  assert.match(s, /rule-catalog 9/);
  assert.match(s, /action-catalog 2099\.01\.01/);
  assert.match(s, /build abc/);
});

// =============================================================================
// End-to-end: the actual file is runnable and propagates process exit codes.
// =============================================================================

function spawnCli(args, input) {
  return spawnSync('node', [CLI_PATH, ...args], { input, encoding: 'utf8' });
}

test('E2E: the file is runnable and returns exit 0 for a clean policy (stdin)', () => {
  const p = spawnCli(['--family', 'identity'], CLEAN_IDENTITY);
  assert.equal(p.status, 0);
  const parsed = JSON.parse(p.stdout);
  assert.equal(parsed.analysisStatus, 'complete');
});

test('E2E: exit 1 for findings, exit 3 for a fail-closed input', () => {
  assert.equal(spawnCli(['--family', 'identity'], ADMIN_IDENTITY).status, 1);
  assert.equal(spawnCli(['--family', 'identity'], MALFORMED).status, 3);
});

test('E2E: missing --family exits 2 (never auto-detected)', () => {
  assert.equal(spawnCli([], CLEAN_IDENTITY).status, 2);
});

test('E2E: cross-partition PassRole without --partition exits 3 (no injected aws default)', () => {
  const p = spawnCli(['--family', 'identity', '--subject-account', '111122223333'], PASSROLE_GOVCLOUD);
  assert.equal(p.status, 3);
});

test('E2E: --version exits 0', () => {
  const p = spawnCli(['--version'], '');
  assert.equal(p.status, 0);
  assert.match(p.stdout, /IAM Blast Radius/);
});
