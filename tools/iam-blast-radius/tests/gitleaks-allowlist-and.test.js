// S5-R3-gitleaks: .gitleaks.toml [allowlist] must be NARROW (path-scoped), never
// blind the scanner with repo-wide marker regexes.
//
// R3 as filed: the [allowlist] combined `paths` + `regexes` (EXAMPLE/FAKE/DUMMY).
// The proposed fix was matchCondition = "AND" so a marker only excuses a hit
// INSIDE an allowlisted path. EMPIRICAL FINDING (gitleaks 8.30.1): the top-level
// [allowlist] does NOT honor matchCondition - it always ORs the condition types.
// So keeping the marker regexes there allowlists that text REPO-WIDE regardless
// of matchCondition: a real accidental secret whose value contains EXAMPLE/FAKE/
// DUMMY anywhere in the tree is silently suppressed. That is exactly the "broad
// key regex that would blind the scanner" the config header forbids.
//
// The real fix: allowlist ONLY by path (fixtures/tests/docs/samples), drop the
// repo-wide marker regexes, and keep matchCondition = "AND" to state intent /
// stay forward-compatible. This suite pins that shape and exercises the REAL
// boundary (the shipped gitleaks binary + the shipped .gitleaks.toml).
//
// If gitleaks is not installed the live cases skip, but the static shape guard
// always runs so the blinding regexes cannot silently return. CI installs
// gitleaks (security.yml), so the live boundary is enforced there.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, rmSync, mkdirSync, mkdtempSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');
const configPath = join(repoRoot, '.gitleaks.toml');
const configText = readFileSync(configPath, 'utf8');

// Slice out the [allowlist] table body (up to the next top-level [table] header).
function allowlistBody() {
  const start = configText.indexOf('[allowlist]');
  assert.ok(start !== -1, '.gitleaks.toml must define an [allowlist] table');
  const rest = configText.slice(start + '[allowlist]'.length);
  const next = rest.search(/^\s*\[[^\]]+\]\s*$/m);
  return next === -1 ? rest : rest.slice(0, next);
}

// --- Static shape guard: path-scoped, no repo-wide marker regexes. -------------
test('[allowlist] is path-scoped with matchCondition = "AND"', () => {
  const body = allowlistBody();
  assert.match(body, /^\s*matchCondition\s*=\s*"AND"\s*$/m,
    'matchCondition = "AND" must be inside the [allowlist] table');
  assert.match(body, /paths\s*=/, '[allowlist] must scope by paths');
});

test('[allowlist] does NOT carry repo-wide marker regexes (would blind the scanner)', () => {
  const body = allowlistBody();
  // A top-level `regexes = [...]` on the global allowlist is OR-combined by
  // gitleaks regardless of matchCondition, so it allowlists marker text repo-wide.
  // Marker exceptions, if ever needed, belong in a RULE-level [[rules.allowlists]].
  assert.doesNotMatch(body, /^\s*regexes\s*=/m,
    '[allowlist] must not list repo-wide regexes (EXAMPLE/FAKE/DUMMY) - it ORs them tree-wide');
});

// --- Live boundary: real gitleaks against the shipped config. ------------------
function gitleaksAvailable() {
  return spawnSync('gitleaks', ['version'], { stdio: 'ignore' }).status === 0;
}

// Scan `dir` with the shipped config in no-git mode; return the set of files with
// a reported leak. Fails CLOSED: any exit other than 0 (clean) or 1 (leaks)
// throws, so a broken scan can never pass as clean.
function leakFiles(dir) {
  const report = join(dir, '_gl-report.json');
  const r = spawnSync(
    'gitleaks',
    ['detect', '--no-banner', '--redact', '--no-git', '-c', configPath,
     '--source', dir, '--report-format', 'json', '--report-path', report],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );
  assert.ok(r.status === 0 || r.status === 1,
    `gitleaks exited ${r.status}: ${r.stderr || r.stdout}`);
  return new Set(JSON.parse(readFileSync(report, 'utf8')).map((f) => f.File));
}

// A secret that (a) trips gitleaks' default generic-api-key rule and (b) has the
// dummy marker "DUMMY" INSIDE the captured secret value - so the allowlist regex
// (matched against the secret) WOULD have suppressed it under the old repo-wide
// regexes. This is the true OR-blinding discriminator: with marker regexes gone,
// it must surface everywhere except allowlisted paths.
const DUMMY_SECRET = 'api_key = "DUMMYx8Kp3Qw9Zt2Lr7Vn4Bs6Hd1Fj5Mc0Ae"';

test('a DUMMY-bearing secret OUTSIDE allowlisted paths is reported (no repo-wide blinding)', (t) => {
  if (!gitleaksAvailable()) return t.skip('gitleaks binary not installed');
  // Root in the OS temp dir: gitleaks reports absolute paths and matches the
  // (unanchored) allowlist path regexes against them, so a sandbox under the repo
  // tree would spuriously inherit an allowlisted prefix.
  const sandbox = mkdtempSync(join(tmpdir(), 'gl-r3-out-'));
  mkdirSync(join(sandbox, 'src'), { recursive: true });
  writeFileSync(join(sandbox, 'src', 'leak.txt'), `${DUMMY_SECRET}\n`);
  try {
    const leaked = leakFiles(sandbox);
    assert.ok([...leaked].some((f) => f.endsWith('leak.txt')),
      'a DUMMY-marked secret outside fixtures/ must be reported - marker regexes must not allowlist it repo-wide');
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
});

test('the same DUMMY-bearing secret INSIDE an allowlisted fixture path stays quiet', (t) => {
  if (!gitleaksAvailable()) return t.skip('gitleaks binary not installed');
  const sandbox = mkdtempSync(join(tmpdir(), 'gl-r3-in-'));
  const fx = join(sandbox, 'tools', 'iam-blast-radius', 'fixtures');
  mkdirSync(fx, { recursive: true });
  writeFileSync(join(fx, 'sample.txt'), `${DUMMY_SECRET}\n`);
  try {
    assert.equal(leakFiles(sandbox).size, 0,
      'a secret under an allowlisted fixture path must stay allowlisted (by path)');
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
});

// --- Fail-closed on the REAL tree: the committed working tree must scan clean. --
// Guards against a fixture carrying a rule-tripping secret that relied on the
// (now removed) marker regexes. If this fires, add the marker to a value the
// default rules ignore, or scope the file under an allowlisted path - never
// re-add repo-wide regexes.
test('the real repo working tree scans clean under the shipped config', (t) => {
  if (!gitleaksAvailable()) return t.skip('gitleaks binary not installed');
  const report = join(here, '_gl-realtree-report.json');
  try {
    const r = spawnSync(
      'gitleaks',
      ['detect', '--no-banner', '--redact', '--no-git', '-c', configPath,
       '--source', repoRoot, '--report-format', 'json', '--report-path', report],
      { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
    );
    assert.ok(r.status === 0 || r.status === 1,
      `gitleaks exited ${r.status}: ${r.stderr || r.stdout}`);
    const findings = JSON.parse(readFileSync(report, 'utf8'));
    assert.equal(findings.length, 0,
      `real tree must scan clean; unexpected leaks: ${JSON.stringify(findings.map((f) => `${f.File}:${f.StartLine}`))}`);
  } finally {
    rmSync(report, { force: true });
  }
});
