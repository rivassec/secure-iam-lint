// S1-entrypoint-guard: REAL-SUBPROCESS regression for the raw-realpath-mismatch
// false-CLEAN in BOTH entrypoints (cli/iam-br.mjs + action/index.mjs).
//
// THE BUG. Both files decided "am I the direct entry?" with
//     import.meta.url === pathToFileURL(process.argv[1]).href
// import.meta.url is REALPATH-resolved by Node's ESM loader, while process.argv[1]
// is the RAW path Node was handed. Any symlink in the invocation path - an npm
// `.bin` shim, `npx`, a self-hosted-runner checkout, a macOS `/tmp` -> `/private/tmp`
// link - makes the raw form differ from the realpath form, so the compare MISSED,
// main() NEVER ran, and the process exited 0 (Node's default) having performed ZERO
// analysis: a false CLEAN / green check on a full-admin policy. This is the exact
// fail-open the threat model forbids (never report clean / exit 0 with zero analysis).
//
// THE FIX. Run when EITHER the raw entry OR its realpathSync-resolved form matches
// import.meta.url, with realpathSync in its own try so a resolve failure can never
// silence a genuine direct invocation - and an in-process import (argv[1] is the
// importer, not the module) still matches NEITHER, so it does not auto-run main().
//
// WHY A REAL SUBPROCESS. The bug lives in the argv[1] vs import.meta.url comparison
// that only exists when Node is the process entry point. An in-process import cannot
// reproduce it (importing never sets argv[1] to the module). So each case SPAWNS
// `node <path>` with a real fs.symlinkSync symlink as argv[1] and asserts a NON-ZERO
// exit AND a REAL finding in the artifact - proving analysis actually RAN, not merely
// that the process failed for some unrelated reason.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync, mkdirSync, writeFileSync, symlinkSync, readFileSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(here, '..', '..', '..');
const CLI_PATH = path.join(REPO, 'cli', 'iam-br.mjs');
const ACTION_PATH = path.join(REPO, 'action', 'index.mjs');

// A full-admin identity policy: `iam:*` fires BOTH WILDCARD-ACTION and
// DIRECT-IAM-ADMIN at/above the default fail threshold, so a genuine analysis is
// exit 1 (findings) and its output names a rule id we can key on.
const ADMIN_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
});

const FINDING_RE = /WILDCARD-ACTION|DIRECT-IAM-ADMIN/;

function withTmp(prefix, fn) {
  const dir = mkdtempSync(path.join(tmpdir(), prefix));
  try {
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// A clean env for the Action subprocess: strip any inherited INPUT_*/GITHUB_* so the
// parent CI environment cannot contaminate the run, keep everything else (PATH, etc.).
function cleanActionEnv(patch) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) {
    if (k.startsWith('INPUT_') || k.startsWith('GITHUB_')) delete env[k];
  }
  return { ...env, ...patch };
}

// =============================================================================
// CLI (cli/iam-br.mjs)
// =============================================================================

test('CLI: invoked through a SYMLINK argv[1] still ANALYZES and exits non-zero (not a false CLEAN)', () => {
  withTmp('ibr-entry-cli-', (dir) => {
    // argv[1] = a symlink to the real CLI; its realpath differs from the raw path.
    const link = path.join(dir, 'iam-br-shim.mjs');
    symlinkSync(CLI_PATH, link);

    const p = spawnSync('node', [link, '--family', 'identity'], {
      input: ADMIN_POLICY,
      encoding: 'utf8',
    });

    assert.notEqual(p.status, 0, 'a symlinked invocation must NOT exit 0 (zero-analysis false clean)');
    assert.equal(p.status, 1, 'a full-admin policy analyzed through a symlink is exit 1 (findings)');
    assert.match(p.stdout, FINDING_RE, 'proof analysis RAN: a real finding is in the JSON output');
  });
});

test('CLI: invoked through a NESTED-symlinked directory argv[1] still analyzes (npx/.bin-shim shape)', () => {
  withTmp('ibr-entry-cli-nest-', (dir) => {
    // A symlinked DIRECTORY that contains the shim - models `.bin`/npx layouts where a
    // path component (not just the leaf) is a symlink.
    const realBin = path.join(dir, 'real-bin');
    mkdirSync(realBin);
    const shim = path.join(realBin, 'iam-br');
    symlinkSync(CLI_PATH, shim);
    const linkBin = path.join(dir, 'bin');
    symlinkSync(realBin, linkBin, 'dir');

    const p = spawnSync('node', [path.join(linkBin, 'iam-br'), '--family', 'identity'], {
      input: ADMIN_POLICY,
      encoding: 'utf8',
    });

    assert.equal(p.status, 1, 'a symlinked-dir invocation still analyzes -> exit 1');
    assert.match(p.stdout, FINDING_RE, 'analysis ran through the symlinked directory');
  });
});

test('CLI CONTROL: normal direct real-path invocation still analyzes and exits 1', () => {
  const p = spawnSync('node', [CLI_PATH, '--family', 'identity'], {
    input: ADMIN_POLICY,
    encoding: 'utf8',
  });
  assert.equal(p.status, 1, 'direct invocation must still run analysis');
  assert.match(p.stdout, FINDING_RE);
});

test('CLI CONTROL: an in-process IMPORT does NOT auto-run main() (no findings emitted)', () => {
  withTmp('ibr-entry-cli-imp-', (dir) => {
    const importer = path.join(dir, 'importer.mjs');
    // argv[1] is the importer, NOT the CLI module, so the guard must stay false.
    writeFileSync(importer,
      `import mod from ${JSON.stringify(pathToFileURL(CLI_PATH).href)};\n`
      + "process.stdout.write('IMPORTER_OK default=' + typeof mod + '\\n');\n");

    // Feed a full-admin policy on stdin: if main() wrongly auto-ran it would consume it
    // and print findings. It must NOT.
    const p = spawnSync('node', [importer], { input: ADMIN_POLICY, encoding: 'utf8' });
    assert.equal(p.status, 0, 'importing must not fail');
    assert.match(p.stdout, /IMPORTER_OK default=function/, 'the module imported (default export present)');
    assert.doesNotMatch(p.stdout, FINDING_RE, 'importing must NOT auto-run analysis');
  });
});

// =============================================================================
// Action (action/index.mjs)
// =============================================================================

// Build a workspace holding a full-admin policy the Action will glob-match + scan.
function makeActionWorkspace() {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-entry-act-ws-'));
  mkdirSync(path.join(ws, 'policies'));
  writeFileSync(path.join(ws, 'policies', 'admin.json'), ADMIN_POLICY);
  const outFile = path.join(ws, '.gh_output');
  writeFileSync(outFile, '');
  return { ws, outFile };
}

function actionEnv(ws, outFile) {
  return cleanActionEnv({
    GITHUB_WORKSPACE: ws,
    GITHUB_OUTPUT: outFile,
    INPUT_PATHS: 'policies/**/*.json',
    INPUT_FAMILY: 'identity',
    INPUT_FAIL_ON: 'high',
  });
}

test('Action: invoked through a SYMLINK argv[1] still ANALYZES and fails the check (not a green pass)', () => {
  withTmp('ibr-entry-act-link-', (linkDir) => {
    const { ws, outFile } = makeActionWorkspace();
    try {
      const link = path.join(linkDir, 'index-shim.mjs');
      symlinkSync(ACTION_PATH, link);

      const p = spawnSync('node', [link], {
        cwd: ws,
        env: actionEnv(ws, outFile),
        encoding: 'utf8',
      });

      assert.notEqual(p.status, 0, 'a symlinked Action invocation must NOT exit 0 / green (zero-analysis false clean)');
      assert.equal(p.status, 1, 'a full-admin policy analyzed through a symlink fails the check (exit 1)');

      const sarif = readFileSync(path.join(ws, 'iam-blast-radius.sarif'), 'utf8');
      assert.match(sarif, FINDING_RE, 'proof analysis RAN: a real finding is in the SARIF artifact');
      const outputs = readFileSync(outFile, 'utf8');
      assert.match(outputs, /exit-code=1/, 'the exit-code output reflects real findings, not a silent 0');
    } finally {
      rmSync(ws, { recursive: true, force: true });
    }
  });
});

test('Action: invoked through a NESTED-symlinked directory argv[1] still analyzes (self-hosted-runner shape)', () => {
  withTmp('ibr-entry-act-nest-', (linkDir) => {
    const { ws, outFile } = makeActionWorkspace();
    try {
      const realDir = path.join(linkDir, 'real');
      mkdirSync(realDir);
      const shim = path.join(realDir, 'index.mjs');
      symlinkSync(ACTION_PATH, shim);
      const linkedDir = path.join(linkDir, 'checkout');
      symlinkSync(realDir, linkedDir, 'dir');

      const p = spawnSync('node', [path.join(linkedDir, 'index.mjs')], {
        cwd: ws,
        env: actionEnv(ws, outFile),
        encoding: 'utf8',
      });

      assert.equal(p.status, 1, 'a symlinked-dir Action invocation still analyzes -> exit 1');
      const sarif = readFileSync(path.join(ws, 'iam-blast-radius.sarif'), 'utf8');
      assert.match(sarif, FINDING_RE, 'analysis ran through the symlinked directory');
    } finally {
      rmSync(ws, { recursive: true, force: true });
    }
  });
});

test('Action CONTROL: normal direct real-path invocation still analyzes and fails the check (exit 1)', () => {
  const { ws, outFile } = makeActionWorkspace();
  try {
    const p = spawnSync('node', [ACTION_PATH], {
      cwd: ws,
      env: actionEnv(ws, outFile),
      encoding: 'utf8',
    });
    assert.equal(p.status, 1, 'direct Action invocation must still run analysis');
    const sarif = readFileSync(path.join(ws, 'iam-blast-radius.sarif'), 'utf8');
    assert.match(sarif, FINDING_RE);
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});

test('Action CONTROL: an in-process IMPORT does NOT auto-run main() (no SARIF, no analysis)', () => {
  withTmp('ibr-entry-act-imp-', (dir) => {
    const { ws, outFile } = makeActionWorkspace();
    try {
      const importer = path.join(dir, 'importer.mjs');
      writeFileSync(importer,
        `import mod from ${JSON.stringify(pathToFileURL(ACTION_PATH).href)};\n`
        + "process.stdout.write('IMPORTER_OK default=' + typeof mod + '\\n');\n");

      // A fully-wired Action env is present; if main() auto-ran on import it would write
      // the SARIF file and outputs. It must NOT.
      const p = spawnSync('node', [importer], {
        cwd: ws,
        env: actionEnv(ws, outFile),
        encoding: 'utf8',
      });
      assert.equal(p.status, 0, 'importing the Action must not fail or run the check');
      assert.match(p.stdout, /IMPORTER_OK default=function/, 'the module imported (default export present)');
      // No analysis => no SARIF written, no exit-code output.
      let sarifExists = true;
      try { readFileSync(path.join(ws, 'iam-blast-radius.sarif'), 'utf8'); } catch { sarifExists = false; }
      assert.equal(sarifExists, false, 'importing must NOT auto-run main() (no SARIF produced)');
      assert.equal(readFileSync(outFile, 'utf8'), '', 'importing must not write action outputs');
    } finally {
      rmSync(ws, { recursive: true, force: true });
    }
  });
});
