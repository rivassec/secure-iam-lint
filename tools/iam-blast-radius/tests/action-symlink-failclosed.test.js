// S1-symlink-failclosed: REAL-FILESYSTEM symlink-EXCLUSION fail-open regression.
//
// walkFiles NEVER follows symlinks (traversal safety - avoids cycles + escaping the
// workspace). Before this fix it did `if (ent.isSymbolicLink()) continue;` with ZERO
// bookkeeping, so a symlinked policy file that MATCHES the scan glob was SILENTLY dropped
// from enumeration. If the remaining real files analyzed clean, the aggregate reported
// analysis-status "complete" / exit 0 - the exact "one file quietly falls out of the
// aggregate" the threat model forbids (a maintainer sees a green check while an unanalyzed
// permissive policy rode in behind a symlink).
//
// The fix: walkFiles RECORDS excluded symlink entries; runAction checks whether any
// excluded symlink's path MATCHES a scan pattern and, if so, FAILS CLOSED - marks the run
// INCOMPLETE (analysis-status partial + a SYMLINK_EXCLUDED 'incomplete' analyzer-state) and
// returns exit 3, never a silent complete/exit 0. A symlink NOT matching any scan pattern
// (an unrelated file) must NOT trip it (no false-fail on a monorepo full of symlinks).
//
// These tests drive the REAL main() code path (real fs, real walkFiles, real io) against
// REAL on-disk symlinks created with fs.symlinkSync - NOT a mocked listFiles - so they pin
// the actual enumeration behavior the audit reproduced on Gentoo.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync, mkdirSync, writeFileSync, symlinkSync, readFileSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  main, EXIT, matchedExcludedSymlinks, SYMLINK_EXCLUDED_REASON, globCanMatchUnderDir,
} from '../../../action/index.mjs';

const CLEAN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow',
    Action: 'ec2:DescribeInstances',
    Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc',
  }],
});

// A permissive policy the fork PR wants smuggled in behind a symlink (iam:* on *). It must
// NEVER be analyzed here (it is the symlink target); the point is that it is EXCLUDED yet
// the run still fails closed instead of reporting a green pass.
const ADMIN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
});

// Save/restore the exact process globals main() reads and mutates, so tests do not leak.
function withProcess(envPatch, fn) {
  const savedEnv = { ...process.env };
  const savedExit = process.exitCode;
  for (const k of Object.keys(process.env)) {
    if (k.startsWith('INPUT_') || k.startsWith('GITHUB_')) delete process.env[k];
  }
  Object.assign(process.env, envPatch);
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      for (const k of Object.keys(process.env)) delete process.env[k];
      Object.assign(process.env, savedEnv);
      process.exitCode = savedExit;
    });
}

// A workspace with an INPUT_* env pre-wired to write SARIF + outputs to temp files so the
// artifacts can be inspected after main() returns.
function makeWorkspace() {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-slink-ws-'));
  const outFile = path.join(ws, '.gh_output');
  writeFileSync(outFile, '');
  return { ws, outFile };
}

function readSarif(ws) {
  return JSON.parse(readFileSync(path.join(ws, 'iam-blast-radius.sarif'), 'utf8'));
}

// Does the aggregate SARIF carry a SYMLINK_EXCLUDED analyzer-state result?
function sarifHasSymlinkExcluded(sarif) {
  for (const run of sarif.runs || []) {
    for (const res of run.results || []) {
      const props = res.properties || {};
      if (props.category === 'analysis-state' && props.analysisState === 'incomplete') {
        const text = (res.message && res.message.text) || '';
        if (text.includes('SYMLINK') || text.includes('symlink')) return true;
      }
      // The rule id / code also carries the stable SYMLINK_EXCLUDED token.
      if (JSON.stringify(res).includes(SYMLINK_EXCLUDED_REASON)) return true;
    }
  }
  return false;
}

test('REPRODUCTION: a glob-matching symlinked policy file is excluded -> run FAILS CLOSED (exit 3, incomplete), NOT a green pass', async () => {
  const { ws, outFile } = makeWorkspace();
  try {
    mkdirSync(path.join(ws, 'policies'));
    // A benign real policy that analyzes clean on its own.
    writeFileSync(path.join(ws, 'policies', 'ok.json'), CLEAN_IDENTITY);
    // The permissive policy checked into the repo, at a path the scan glob does NOT match.
    writeFileSync(path.join(ws, 'permissive.json'), ADMIN_IDENTITY);
    // policies/admin.json is a SYMLINK to the permissive policy; its path DOES match the
    // consumer glob `policies/**/*.json`, so walkFiles excludes it (never followed).
    symlinkSync(path.join(ws, 'permissive.json'), path.join(ws, 'policies', 'admin.json'), 'file');

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: 'policies/**/*.json',
      INPUT_FAMILY: 'identity',
    }, () => main());

    // FAIL CLOSED: a matching-but-excluded symlinked policy can never be a clean pass.
    assert.equal(code, EXIT.FAIL_CLOSED, 'must fail closed to exit 3, not report exit 0');

    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /exit-code=3/, 'exit-code output must be 3');
    assert.match(outputs, /analysis-status=partial/, 'analysis-status must be partial (INCOMPLETE), never complete');

    const sarif = readSarif(ws);
    assert.equal(sarifHasSymlinkExcluded(sarif), true, 'SARIF must carry a SYMLINK_EXCLUDED analyzer-state');
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});

test('an UNRELATED symlink (matches no scan pattern) does NOT trip the guard -> clean pass (exit 0)', async () => {
  const { ws, outFile } = makeWorkspace();
  try {
    mkdirSync(path.join(ws, 'policies'));
    writeFileSync(path.join(ws, 'policies', 'ok.json'), CLEAN_IDENTITY);
    // Real target files the symlinks point at, at non-matching paths.
    writeFileSync(path.join(ws, 'permissive.json'), ADMIN_IDENTITY);
    mkdirSync(path.join(ws, 'vendor'));
    writeFileSync(path.join(ws, 'vendor', 'target.json'), ADMIN_IDENTITY);
    // (a) a non-.json symlink at the root; (b) a .json symlink OUTSIDE the matched path.
    // Neither matches the glob `policies/**/*.json`, so neither may false-fail the run.
    symlinkSync(path.join(ws, 'permissive.json'), path.join(ws, 'notes.txt'), 'file');
    symlinkSync(path.join(ws, 'vendor', 'target.json'), path.join(ws, 'vendor', 'link.json'), 'file');

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: 'policies/**/*.json',
      INPUT_FAMILY: 'identity',
    }, () => main());

    assert.equal(code, EXIT.CLEAN, 'an unrelated symlink must not fail the clean run');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /analysis-status=complete/, 'a run with only unrelated symlinks stays complete');
    assert.equal(sarifHasSymlinkExcluded(readSarif(ws)), false, 'no SYMLINK_EXCLUDED state for unrelated symlinks');
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});

test('when the ONLY pattern-matching entry is a symlink (no real match), the run still FAILS CLOSED (exit 3), never a usage exit 2 that could be mistaken for a config typo', async () => {
  const { ws, outFile } = makeWorkspace();
  try {
    mkdirSync(path.join(ws, 'policies'));
    writeFileSync(path.join(ws, 'permissive.json'), ADMIN_IDENTITY);
    // The only thing under policies/ matching the glob is a symlink.
    symlinkSync(path.join(ws, 'permissive.json'), path.join(ws, 'policies', 'admin.json'), 'file');

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: 'policies/**/*.json',
      INPUT_FAMILY: 'identity',
    }, () => main());

    // resolveFiles would report NO_FILES_MATCHED (exit 2), but the excluded matching symlink
    // dominates with exit 3 (worst-code wins): fail closed, never a clean pass.
    assert.equal(code, EXIT.FAIL_CLOSED, 'a matching symlink with no real match still fails closed to exit 3');
    assert.equal(sarifHasSymlinkExcluded(readSarif(ws)), true);
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});

test('a LITERAL (non-glob) path naming a symlinked policy file FAILS CLOSED (exit 3), not a MISSING_FILE usage error alone', async () => {
  const { ws, outFile } = makeWorkspace();
  try {
    mkdirSync(path.join(ws, 'policies'));
    writeFileSync(path.join(ws, 'permissive.json'), ADMIN_IDENTITY);
    symlinkSync(path.join(ws, 'permissive.json'), path.join(ws, 'policies', 'admin.json'), 'file');

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: 'policies/admin.json', // exact literal naming the symlink
      INPUT_FAMILY: 'identity',
    }, () => main());

    assert.equal(code, EXIT.FAIL_CLOSED, 'a literal path naming a symlink must fail closed to exit 3');
    assert.equal(sarifHasSymlinkExcluded(readSarif(ws)), true);
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});

// --- Pure matcher precision (mirrors resolveFiles semantics) ------------------

test('matchedExcludedSymlinks: precise pattern matching, dedup, stable sort', () => {
  const links = ['policies/admin.json', 'vendor/link.json', 'notes.txt', 'policies/sub/deep.json'];
  // Glob only matches under policies/, at any depth.
  assert.deepEqual(
    matchedExcludedSymlinks(['policies/**/*.json'], links),
    ['policies/admin.json', 'policies/sub/deep.json'],
  );
  // A literal exactly names a symlink.
  assert.deepEqual(matchedExcludedSymlinks(['vendor/link.json'], links), ['vendor/link.json']);
  // No pattern matches -> empty (no false-fail).
  assert.deepEqual(matchedExcludedSymlinks(['configs/**/*.yaml'], links), []);
  // Overlapping patterns dedup to one entry each, sorted.
  assert.deepEqual(
    matchedExcludedSymlinks(['policies/**/*.json', 'policies/admin.json'], links),
    ['policies/admin.json', 'policies/sub/deep.json'],
  );
  // No symlinks at all -> empty.
  assert.deepEqual(matchedExcludedSymlinks(['**/*.json'], []), []);
});

// --- S1-DIRSYMLINK: a DIRECTORY symlink smuggling a whole subtree past the aggregate -------
//
// The residual fail-open the re-audit reproduced end-to-end: a DIRECTORY symlink whose OWN
// name does not match the file glob (e.g. `configs` vs `**/*.json` or `configs/*.json`) hides
// an entire subtree of policy files from enumeration. The old guard only matched each excluded
// symlink's literal path against the file glob, so a FILE symlink (linked.json) was caught but
// a DIRECTORY symlink evaded entirely, and the run reported exit 0 clean with the admin policy
// behind the symlink never analyzed. The fix: an excluded symlink whose subtree COULD contain a
// pattern match (globCanMatchUnderDir) also fails closed.

test('globCanMatchUnderDir: a directory could contain a pattern match iff the pattern can descend into it', () => {
  // Recursive-from-root and dir-rooted patterns can descend into `configs`.
  assert.equal(globCanMatchUnderDir('**/*.json', 'configs'), true);
  assert.equal(globCanMatchUnderDir('configs/*.json', 'configs'), true);
  assert.equal(globCanMatchUnderDir('configs/**/*.json', 'configs'), true);
  assert.equal(globCanMatchUnderDir('configs/**', 'configs'), true);
  // A literal path naming a file INSIDE the directory symlink also fails closed.
  assert.equal(globCanMatchUnderDir('configs/admin.json', 'configs'), true);
  // Nested directory symlink under the pattern root.
  assert.equal(globCanMatchUnderDir('policies/**/*.json', 'policies/sub'), true);
  // An UNRELATED directory cannot be descended into by these patterns -> false (no false-fail).
  assert.equal(globCanMatchUnderDir('policies/**/*.json', 'vendor'), false);
  assert.equal(globCanMatchUnderDir('other/*.json', 'configs'), false);
  assert.equal(globCanMatchUnderDir('configs/*.yaml', 'unrelated'), false);
  // Empty dir -> false (defensive).
  assert.equal(globCanMatchUnderDir('**/*.json', ''), false);
});

test('matchedExcludedSymlinks: a DIRECTORY symlink whose subtree could match fails closed (S1-DIRSYMLINK)', () => {
  // The exact bug case from the finding: a directory symlink `configs` under `**/*.json`.
  assert.deepEqual(matchedExcludedSymlinks(['**/*.json'], ['configs']), ['configs']);
  assert.deepEqual(matchedExcludedSymlinks(['configs/*.json'], ['configs']), ['configs']);
  // A TYPED entry: a KNOWN directory symlink is flagged; a KNOWN non-directory (file/dangling)
  // symlink whose OWN path does not match is NOT over-flagged (no noise on file symlinks).
  assert.deepEqual(matchedExcludedSymlinks(['**/*.json'], [{ path: 'configs', isDir: true }]), ['configs']);
  assert.deepEqual(matchedExcludedSymlinks(['**/*.json'], [{ path: 'configs', isDir: false }]), []);
  // A KNOWN file symlink whose OWN path DOES match still fails closed (unchanged behavior).
  assert.deepEqual(matchedExcludedSymlinks(['**/*.json'], [{ path: 'admin.json', isDir: false }]), ['admin.json']);
  // An unrelated directory symlink (pattern cannot descend into it) does not false-fail.
  assert.deepEqual(matchedExcludedSymlinks(['policies/**/*.json'], [{ path: 'vendor', isDir: true }]), []);
});

test('REPRODUCTION (S1-DIRSYMLINK): a DIRECTORY symlink hiding an admin policy subtree -> run FAILS CLOSED (exit 3), NOT exit 0 clean', async () => {
  const { ws, outFile } = makeWorkspace();
  // The subtree the directory symlink points at, OUTSIDE the workspace.
  const ext = mkdtempSync(path.join(tmpdir(), 'ibr-slink-ext-'));
  try {
    // A benign real policy that analyzes clean on its own.
    writeFileSync(path.join(ws, 'clean.json'), CLEAN_IDENTITY);
    // The admin policy lives behind a DIRECTORY symlink: `configs` -> ext/ containing danger.json.
    writeFileSync(path.join(ext, 'danger.json'), ADMIN_IDENTITY);
    symlinkSync(ext, path.join(ws, 'configs'), 'dir');

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: '**/*.json',
      INPUT_FAMILY: 'identity',
      INPUT_FAIL_ON: 'high',
    }, () => main());

    // FAIL CLOSED: the directory symlink's hidden subtree could contain a matching policy, so the
    // run is INCOMPLETE and can never be a clean exit 0.
    assert.equal(code, EXIT.FAIL_CLOSED, 'a directory symlink hiding a policy subtree must fail closed to exit 3, not exit 0');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /exit-code=3/, 'exit-code output must be 3');
    assert.match(outputs, /analysis-status=partial/, 'analysis-status must be partial (INCOMPLETE), never complete');
    assert.equal(sarifHasSymlinkExcluded(readSarif(ws)), true, 'SARIF must carry a SYMLINK_EXCLUDED analyzer-state for the directory symlink');
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(ext, { recursive: true, force: true });
  }
});

test('a directory symlink UNRELATED to the scan glob does NOT false-fail (exit 0 clean)', async () => {
  const { ws, outFile } = makeWorkspace();
  const ext = mkdtempSync(path.join(tmpdir(), 'ibr-slink-ext2-'));
  try {
    mkdirSync(path.join(ws, 'policies'));
    writeFileSync(path.join(ws, 'policies', 'ok.json'), CLEAN_IDENTITY);
    // A directory symlink `vendor` whose subtree the rooted glob `policies/**/*.json` can never
    // descend into -> must not fail the clean run.
    writeFileSync(path.join(ext, 'whatever.json'), ADMIN_IDENTITY);
    symlinkSync(ext, path.join(ws, 'vendor'), 'dir');

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: 'policies/**/*.json',
      INPUT_FAMILY: 'identity',
    }, () => main());

    assert.equal(code, EXIT.CLEAN, 'an unrelated directory symlink must not fail the clean run');
    assert.equal(sarifHasSymlinkExcluded(readSarif(ws)), false, 'no SYMLINK_EXCLUDED state for an unrelated directory symlink');
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(ext, { recursive: true, force: true });
  }
});
