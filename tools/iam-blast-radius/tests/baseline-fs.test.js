// Real-filesystem confinement of the Action's baseline / baseline-output paths (main()):
// io.readFile's O_NOFOLLOW guards only the LAST path component, so a symlinked PARENT
// directory must be rejected explicitly - for the read as well as the write.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, existsSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { main, EXIT } from '../../../action/index.mjs';

const POLICY = JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }] });
const EMPTY_BASELINE = JSON.stringify({ version: 2, entries: [] });

async function runMain(ws, extra) {
  const savedEnv = { ...process.env };
  const savedExit = process.exitCode;
  const savedWrite = process.stderr.write;
  for (const k of Object.keys(process.env)) if (k.startsWith('INPUT_') || k.startsWith('GITHUB_')) delete process.env[k];
  Object.assign(process.env, { GITHUB_WORKSPACE: ws, INPUT_PATHS: 'policy.json', INPUT_FAMILY: 'identity', INPUT_PARTITION: 'aws' }, extra);
  process.stderr.write = () => true;
  try {
    return await main();
  } finally {
    process.stderr.write = savedWrite;
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, savedEnv);
    process.exitCode = savedExit;
  }
}

function fixture() {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-blws-'));
  const outside = mkdtempSync(path.join(tmpdir(), 'ibr-blout-'));
  writeFileSync(path.join(ws, 'policy.json'), POLICY);
  writeFileSync(path.join(outside, 'b.json'), EMPTY_BASELINE);
  return { ws, outside, cleanup: () => { rmSync(ws, { recursive: true, force: true }); rmSync(outside, { recursive: true, force: true }); } };
}

test('a baseline read through a symlinked parent directory is rejected (exit 2)', async () => {
  const { ws, outside, cleanup } = fixture();
  try {
    symlinkSync(outside, path.join(ws, 'linkdir'), 'dir');
    assert.equal(await runMain(ws, { INPUT_BASELINE: 'linkdir/b.json' }), EXIT.USAGE);
  } finally { cleanup(); }
});

test('a baseline that is itself a symlink is rejected (exit 2)', async () => {
  const { ws, outside, cleanup } = fixture();
  try {
    symlinkSync(path.join(outside, 'b.json'), path.join(ws, 'b.json'));
    assert.equal(await runMain(ws, { INPUT_BASELINE: 'b.json' }), EXIT.USAGE);
  } finally { cleanup(); }
});

test('a regular in-workspace baseline is read (exit 0)', async () => {
  const { ws, cleanup } = fixture();
  try {
    writeFileSync(path.join(ws, 'b.json'), EMPTY_BASELINE);
    assert.equal(await runMain(ws, { INPUT_BASELINE: 'b.json' }), EXIT.CLEAN);
  } finally { cleanup(); }
});

test('baseline-output through a symlinked parent or onto a symlink writes nothing outside', async () => {
  const { ws, outside, cleanup } = fixture();
  try {
    symlinkSync(outside, path.join(ws, 'linkdir'), 'dir');
    symlinkSync(path.join(outside, 'target.json'), path.join(ws, 'final.json'));
    for (const out of ['linkdir/new.json', 'final.json']) {
      assert.equal(await runMain(ws, { 'INPUT_BASELINE-OUTPUT': out }), EXIT.USAGE, out);
    }
    assert.deepEqual(readdirSync(outside).sort(), ['b.json']);
    assert.equal(existsSync(path.join(outside, 'target.json')), false);
  } finally { cleanup(); }
});
