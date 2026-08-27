// REAL-INVOCATION PACKAGING fixtures (the class an in-process test CANNOT catch).
//
// The fail-closed exit-code contract is only worth anything if it survives the ways a
// consumer actually runs the tool: a `node` invocation, `npx`, an npm bin shim, and a
// symlink to the bin. The ENTRYPOINT guard (`import.meta.url === pathToFileURL(argv[1])`)
// compares a REALPATH-resolved URL to a RAW argv path, so any invocation whose argv[1]
// is a symlink (npm's `.bin/` shim IS a symlink; `npx` resolves through it) fails the
// guard, main() never runs, and the process exits 0 having analyzed NOTHING - a silent
// fail-OPEN in the shipped entrypoint. No in-process `run(argv, io)` test can see this;
// only a real `npm pack` -> install -> spawn does. That is the whole reason this file
// exists.
//
// This packs the PUBLISHABLE package (the repo ROOT package.json - the one that
// declares `bin: iam-br`; the dev-harness package.json under tools/ is `private` and
// has no bin), installs the tarball into a throwaway project, and drives the installed
// bin FOUR ways on an admin fixture. Each must PERFORM ANALYSIS and exit NON-ZERO.
//
// FIXED (story S1-entrypoint-guard, bug: raw-realpath-mismatch): both guards now run
// main() when import.meta.url matches EITHER realpathSync(argv[1]) OR the raw argv[1],
// so `node <realpath>`, npx, the npm `.bin` shim, and a bin symlink ALL run main() and
// exit non-zero on the admin fixture. The four invocations below assert that fixed
// behaviour directly (no `todo`); a REGRESSION to the raw-only compare would flip npx /
// bin-shim / symlink back to a silent exit-0 fail-open and fail these tests.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, symlinkSync, rmSync, mkdirSync, readFileSync, existsSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(here, '..', '..', '..', '..');
const ACTION_ENTRY = join(REPO_ROOT, 'action', 'index.mjs');
const ADMIN_FIXTURE = join(here, 'corpus', '01-admin-full.json');
const NARROW_FIXTURE = join(here, 'corpus', '04-narrow-clean.json');

// A single npm pack + install, shared by every invocation test.
let workDir = null;      // throwaway root
let projDir = null;      // consumer project with the tarball installed
let installOk = false;
let installDiag = '';

function npm(args, opts) {
  return spawnSync('npm', args, { encoding: 'utf8', ...opts });
}

test.before(() => {
  // CRITICAL: canonicalize the temp dir. On macOS mkdtemp returns a path under a
  // SYMLINKED ancestor (/var -> /private/var), which would make even a `node <realpath>`
  // invocation's raw argv[1] differ from the realpath-resolved import.meta.url and trip
  // the SAME entrypoint bug - masking which invocations are genuinely broken. Resolving
  // the base to its realpath isolates (a) as the guard's happy path, so the remaining
  // fail-opens are attributable purely to the .bin/npx/symlink indirection under test.
  workDir = realpathSync(mkdtempSync(join(tmpdir(), 'iam-br-pack-')));
  // 1. Pack the publishable ROOT package -> tarball in workDir.
  const packed = npm(['pack', '--pack-destination', workDir], { cwd: REPO_ROOT });
  if (packed.status !== 0) {
    installDiag = `npm pack failed: ${packed.stderr || packed.stdout}`;
    return;
  }
  const tarball = String(packed.stdout).trim().split('\n').pop().trim();
  const tarballPath = join(workDir, tarball);
  if (!existsSync(tarballPath)) {
    installDiag = `tarball not found at ${tarballPath}`;
    return;
  }
  // 2. Fresh consumer project; install the tarball (zero runtime deps -> offline-safe).
  projDir = join(workDir, 'proj');
  mkdirSync(projDir, { recursive: true });
  writeFileSync(join(projDir, 'package.json'),
    JSON.stringify({ name: 'consumer', version: '1.0.0', private: true }, null, 2));
  const inst = npm(['install', tarballPath, '--no-audit', '--no-fund', '--no-package-lock'], { cwd: projDir });
  if (inst.status !== 0) {
    installDiag = `npm install failed: ${inst.stderr || inst.stdout}`;
    return;
  }
  installOk = true;
});

test.after(() => {
  if (workDir) { try { rmSync(workDir, { recursive: true, force: true }); } catch { /* best effort */ } }
});

// A GATE prerequisite failure (npm pack / tarball resolution / npm install) must FAIL
// the test, never skip it: a skipped gate reads as a pass and lets a broken package ship.
function assertInstalled() {
  assert.ok(installOk, `packaging prerequisite FAILED (a gate must fail, not skip): ${installDiag}`);
}

// Paths inside the installed consumer project.
function installedRealBin() { return join(projDir, 'node_modules', 'secure-iam-lint', 'cli', 'iam-br.mjs'); }
function installedBinShim() { return join(projDir, 'node_modules', '.bin', 'iam-br'); }

// Assert a spawn PERFORMED ANALYSIS: it must run to completion, exit NON-ZERO, AND emit
// a real finding marker on stdout - the SAME positive proof the direct-`node` happy path
// (test (a)) uses (/WILDCARD-ACTION/). A bare `status != 0` is not enough: a syntax /
// module-load / usage error also exits non-zero while analyzing NOTHING, which would let
// a zero-analysis failure masquerade as "fail-closed". The finding marker distinguishes
// genuine analysis from an incidental non-zero exit.
function assertAnalyzedNonZero(res, label) {
  assert.notEqual(res.status, null, `${label}: process must run to completion`);
  assert.notEqual(res.status, 0, `${label}: must exit NON-ZERO (fail-closed), got 0 (silent fail-open?)`);
  assert.match(res.stdout || '', /WILDCARD-ACTION/,
    `${label}: output must PROVE analysis ran (an admin-policy finding marker), not just a non-zero exit`);
}

// ============================================================================
// (a) direct `node <installed real path>` - the guard's happy path (works today).
// ============================================================================

test('(a) direct `node <bin>` on admin fixture analyzes and exits non-zero', (t) => {
  assertInstalled();
  const res = spawnSync('node', [installedRealBin(), '--family', 'identity', ADMIN_FIXTURE], { encoding: 'utf8' });
  assertAnalyzedNonZero(res, 'direct node');
  assert.equal(res.status, 1, 'admin fixture gates at exit 1');
  assert.match(res.stdout, /WILDCARD-ACTION/, 'real analysis output present on stdout');
});

test('(a) direct `node <bin>` on a NARROW fixture is a genuine clean exit 0 (control)', (t) => {
  assertInstalled();
  const res = spawnSync('node', [installedRealBin(), '--family', 'identity', NARROW_FIXTURE], { encoding: 'utf8' });
  assert.equal(res.status, 0, 'a genuinely narrow grant is exit 0');
  assert.match(res.stdout, /"analysisStatus":\s*"complete"/, 'exit 0 is backed by a COMPLETE analysis, not zero-analysis');
});

// ============================================================================
// (b) npx, (c) bin symlink, (d) bin shim - all route argv[1] through a symlink. Before
// S1-entrypoint-guard these hit the raw-realpath-mismatch fail-open (silent exit 0);
// the fix makes each run main() and exit non-zero WITH real analysis output. These are
// now the primary regression guards for the fix on the REAL packaged entrypoint.
// ============================================================================

test('(b) `npx iam-br` on admin fixture analyzes and exits non-zero (S1 fix)', (t) => {
  assertInstalled();
  const res = spawnSync('npx', ['--no-install', 'iam-br', '--family', 'identity', ADMIN_FIXTURE],
    { cwd: projDir, encoding: 'utf8' });
  assertAnalyzedNonZero(res, 'npx');
});

test('(c) bin symlink invocation on admin fixture analyzes and exits non-zero (S1 fix)', (t) => {
  assertInstalled();
  const link = join(workDir, 'iam-br-symlink.mjs');
  try { rmSync(link, { force: true }); } catch { /* ignore */ }
  symlinkSync(installedRealBin(), link);
  const res = spawnSync('node', [link, '--family', 'identity', ADMIN_FIXTURE], { encoding: 'utf8' });
  assertAnalyzedNonZero(res, 'symlink');
});

test('(d) npm bin-shim invocation on admin fixture analyzes and exits non-zero (S1 fix)', (t) => {
  assertInstalled();
  const res = spawnSync(installedBinShim(), ['--family', 'identity', ADMIN_FIXTURE], { encoding: 'utf8' });
  assertAnalyzedNonZero(res, 'bin shim');
});

// ============================================================================
// Action-style capture: spawn action/index.mjs (real path, as GitHub invokes it)
// with GITHUB_WORKSPACE / GITHUB_OUTPUT / INPUT_* set on a RISKY tree. Assert
// non-zero AND real outputs written.
// ============================================================================

test('Action-style: risky tree -> non-zero exit AND real GITHUB_OUTPUT written', () => {
  const ws = mkdtempSync(join(tmpdir(), 'iam-br-action-'));
  try {
    // A risky policy file inside the workspace, matched by the paths glob.
    writeFileSync(join(ws, 'policy.json'), readFileSync(ADMIN_FIXTURE, 'utf8'));
    const outFile = join(ws, 'gh_output');
    const summaryFile = join(ws, 'gh_summary');
    writeFileSync(outFile, '');
    writeFileSync(summaryFile, '');
    const env = {
      ...process.env,
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      GITHUB_STEP_SUMMARY: summaryFile,
      INPUT_PATHS: 'policy.json',
      INPUT_FAMILY: 'identity',
    };
    const res = spawnSync('node', [ACTION_ENTRY], { cwd: ws, env, encoding: 'utf8' });
    assert.notEqual(res.status, 0, 'a risky tree must FAIL the action (non-zero), never a clean pass');
    const out = readFileSync(outFile, 'utf8');
    assert.match(out, /exit-code=/, 'GITHUB_OUTPUT carries the exit-code output');
    assert.match(out, /analysis-status=complete/, 'analysis actually ran (status complete)');
    assert.match(out, /findings-count=[1-9]/, 'real findings were counted, not zero-analysis');
    // SARIF is written into the workspace by default.
    assert.ok(existsSync(join(ws, 'iam-blast-radius.sarif')), 'default SARIF report written to the workspace');
  } finally {
    try { rmSync(ws, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

test('Action-style: a CLEAN tree exits 0 with a COMPLETE analysis (control, not zero-analysis)', () => {
  const ws = mkdtempSync(join(tmpdir(), 'iam-br-action-clean-'));
  try {
    writeFileSync(join(ws, 'policy.json'), readFileSync(NARROW_FIXTURE, 'utf8'));
    const outFile = join(ws, 'gh_output');
    writeFileSync(outFile, '');
    writeFileSync(join(ws, 'gh_summary'), '');
    const env = {
      ...process.env,
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      GITHUB_STEP_SUMMARY: join(ws, 'gh_summary'),
      INPUT_PATHS: 'policy.json',
      INPUT_FAMILY: 'identity',
    };
    const res = spawnSync('node', [ACTION_ENTRY], { cwd: ws, env, encoding: 'utf8' });
    assert.equal(res.status, 0, 'a genuinely narrow tree is a clean pass');
    const out = readFileSync(outFile, 'utf8');
    assert.match(out, /analysis-status=complete/, 'exit 0 is backed by a COMPLETE analysis, never zero-analysis');
  } finally {
    try { rmSync(ws, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});
