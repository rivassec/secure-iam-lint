// The Action's one-line failure message carries a fixed fix-it hint for usage errors
// whose reason code alone does not say what to change. Real-world trial: the first
// thing an adopter tries is `sarif-output: /tmp/x.sarif`, which used to print only
// "failed (exit 2): UNSAFE_SARIF_OUTPUT". The hint is keyed by reason code and never
// interpolates the input, so a hostile value cannot reach the runner log.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { main, EXIT } from '../../../action/index.mjs';

const CLEAN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::example-bucket/*' }],
});

async function runCapturingStderr(envPatch) {
  const savedEnv = { ...process.env };
  const savedExit = process.exitCode;
  const savedWrite = process.stderr.write;
  let stderr = '';
  for (const k of Object.keys(process.env)) {
    if (k.startsWith('INPUT_') || k.startsWith('GITHUB_')) delete process.env[k];
  }
  Object.assign(process.env, envPatch);
  process.stderr.write = (chunk) => { stderr += String(chunk); return true; };
  try {
    const code = await main();
    return { code, stderr };
  } finally {
    process.stderr.write = savedWrite;
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, savedEnv);
    process.exitCode = savedExit;
  }
}

test('an absolute sarif-output fails with a workspace-relative hint', async () => {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-hint-'));
  try {
    writeFileSync(path.join(ws, 'policy.json'), CLEAN_IDENTITY);
    const { code, stderr } = await runCapturingStderr({
      GITHUB_WORKSPACE: ws,
      INPUT_PATHS: 'policy.json',
      INPUT_FAMILY: 'identity',
      INPUT_PARTITION: 'aws',
      'INPUT_SARIF-OUTPUT': '/tmp/x.sarif',
    });
    assert.equal(code, EXIT.USAGE);
    assert.match(stderr, /failed \(exit 2\): UNSAFE_SARIF_OUTPUT - use a workspace-relative path/);
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});

test('the hint never echoes the rejected input value', async () => {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-hint-'));
  try {
    writeFileSync(path.join(ws, 'policy.json'), CLEAN_IDENTITY);
    const { stderr } = await runCapturingStderr({
      GITHUB_WORKSPACE: ws,
      INPUT_PATHS: 'policy.json',
      INPUT_FAMILY: 'identity',
      'INPUT_SARIF-OUTPUT': '/tmp/evil\n::warning::forged.sarif',
    });
    assert.doesNotMatch(stderr, /forged/);
    assert.doesNotMatch(stderr, /^::/m);
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});
