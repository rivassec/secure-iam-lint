// S4-action-hardening (ROUND 2): REAL-FILESYSTEM symlink write-escape regression.
//
// The story class is "arbitrary file WRITE outside the workspace via sarif-output".
// The first round closed the LEXICAL spellings (absolute paths, ".." escapes, control
// chars) but both guards were purely lexical - neither resolved symlinks. A sarif-output
// that is a valid RELATIVE, ".."-free path whose leading directory component (or the
// target file itself) is a symlink checked into the tree writes the SARIF THROUGH the
// symlink, landing OUTSIDE GITHUB_WORKSPACE - silently, exit 0, no writeError.
//
// These tests drive the REAL main() code path (real fs, real path, real writeSarif
// sink, real io.sarifTargetContained) against REAL on-disk symlinks - the exact PoC
// from the audit - and prove:
//   Variant A: a symlinked DIRECTORY component (`reports` -> external dir).
//   Variant B: a direct symlink FILE target (`results.sarif` -> external file).
// In both, the run must FAIL CLOSED (non-zero exit) and write NOTHING outside the
// workspace. A positive control proves a genuinely-contained relative path still writes.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { main, EXIT } from '../../../action/index.mjs';

const CLEAN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow',
    Action: 'ec2:DescribeInstances',
    Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc',
  }],
});

// Save/restore the exact process globals main() reads and mutates, so tests do not leak.
function withProcess(envPatch, fn) {
  const savedEnv = { ...process.env };
  const savedExit = process.exitCode;
  // Wipe the INPUT_*/GITHUB_* surface so a stray outer value cannot bleed in.
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

function makeWorkspace() {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-ws-'));
  const external = mkdtempSync(path.join(tmpdir(), 'ibr-ext-'));
  writeFileSync(path.join(ws, 'policy.json'), CLEAN_IDENTITY);
  return { ws, external };
}

test('Variant A: sarif-output through a symlinked DIRECTORY component fails CLOSED and writes nothing outside the workspace', async () => {
  const { ws, external } = makeWorkspace();
  try {
    // `reports` inside the workspace is a symlink to an external directory.
    symlinkSync(external, path.join(ws, 'reports'), 'dir');
    const externalTarget = path.join(external, 'pwned.sarif');

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      INPUT_PATHS: 'policy.json',
      INPUT_FAMILY: 'identity',
      'INPUT_SARIF-OUTPUT': 'reports/pwned.sarif',
    }, () => main());

    // FAIL CLOSED: never a clean exit 0.
    assert.notEqual(code, EXIT.CLEAN, 'symlink write-escape must not report a clean pass');
    assert.equal(code, EXIT.USAGE, 'must be a UNSAFE_SARIF_OUTPUT usage error (exit 2)');
    // NOTHING written through the symlink, outside the workspace.
    assert.equal(existsSync(externalTarget), false, 'SARIF must NOT be written outside the workspace');
    assert.deepEqual(readdirSync(external), [], 'external target dir must stay empty');
    // The safe default SARIF is written INSIDE the workspace instead.
    assert.equal(existsSync(path.join(ws, 'iam-blast-radius.sarif')), true, 'safe-default SARIF written in-workspace');
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(external, { recursive: true, force: true });
  }
});

test('Variant B: sarif-output that IS a symlink FILE fails CLOSED and writes nothing through it', async () => {
  const { ws, external } = makeWorkspace();
  try {
    const externalTarget = path.join(external, 'direct-pwn.sarif');
    // `results.sarif` inside the workspace is itself a symlink to an external file path.
    symlinkSync(externalTarget, path.join(ws, 'results.sarif'), 'file');

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      INPUT_PATHS: 'policy.json',
      INPUT_FAMILY: 'identity',
      'INPUT_SARIF-OUTPUT': 'results.sarif',
    }, () => main());

    assert.notEqual(code, EXIT.CLEAN, 'symlink-file write-escape must not report a clean pass');
    assert.equal(code, EXIT.USAGE);
    assert.equal(existsSync(externalTarget), false, 'nothing written through the symlink file');
    assert.deepEqual(readdirSync(external), [], 'external target dir must stay empty');
    assert.equal(existsSync(path.join(ws, 'iam-blast-radius.sarif')), true);
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(external, { recursive: true, force: true });
  }
});

test('Variant A (nested): a symlink deeper in the sarif-output path also fails CLOSED', async () => {
  const { ws, external } = makeWorkspace();
  try {
    // real dir `out`, then `out/link` -> external dir; sarif-output=out/link/x.sarif.
    mkdirSync(path.join(ws, 'out'));
    symlinkSync(external, path.join(ws, 'out', 'link'), 'dir');
    const externalTarget = path.join(external, 'x.sarif');

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      INPUT_PATHS: 'policy.json',
      INPUT_FAMILY: 'identity',
      'INPUT_SARIF-OUTPUT': 'out/link/x.sarif',
    }, () => main());

    assert.notEqual(code, EXIT.CLEAN);
    assert.equal(code, EXIT.USAGE);
    assert.equal(existsSync(externalTarget), false);
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(external, { recursive: true, force: true });
  }
});

test('positive control: a genuinely-contained relative sarif-output (real dirs, no symlink) writes INSIDE the workspace, exit 0', async () => {
  const { ws, external } = makeWorkspace();
  try {
    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      INPUT_PATHS: 'policy.json',
      INPUT_FAMILY: 'identity',
      'INPUT_SARIF-OUTPUT': 'out/reports/br.sarif', // nested REAL dirs, created by the sink
    }, () => main());

    assert.equal(code, EXIT.CLEAN, 'a clean policy with a safe path must pass');
    assert.equal(existsSync(path.join(ws, 'out', 'reports', 'br.sarif')), true, 'SARIF written at the requested in-workspace path');
    // No leakage outside the workspace.
    assert.deepEqual(readdirSync(external), []);
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(external, { recursive: true, force: true });
  }
});
