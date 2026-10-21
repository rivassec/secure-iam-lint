// Unrecognized INPUT_* variables are named on stderr instead of being dropped silently
// (a real trial set INPUT_FEDERATION-HOSTS from a proposal that never shipped and got no
// signal). DECLARED_INPUTS must match action.yml exactly.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { DECLARED_INPUTS, unrecognizedInputs } from '../../../action/action-inputs.mjs';
import { main } from '../../../action/index.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const ACTION_YML = readFileSync(path.join(here, '..', '..', '..', 'action.yml'), 'utf8');

test('DECLARED_INPUTS matches the inputs action.yml declares', () => {
  const sec = ACTION_YML.slice(ACTION_YML.indexOf('\ninputs:\n'), ACTION_YML.indexOf('\noutputs:\n'));
  const declared = [...sec.matchAll(/^ {2}([a-z0-9-]+):$/gm)].map((m) => m[1]);
  assert.deepEqual([...DECLARED_INPUTS].sort(), declared.sort());
});

test('unrecognizedInputs names strays, accepts both spellings of declared inputs', () => {
  const r = unrecognizedInputs({
    'INPUT_FAIL-ON': 'high', INPUT_FAIL_ON: 'high', INPUT_PATHS: 'x', 'INPUT_FEDERATION-HOSTS': 'a',
    INPUT_REPORT_ONLY: 'true', 'INPUT_EVIL::WARNING::X': '1', PATH: '/bin',
  });
  assert.deepEqual(r.names, ['federation-hosts', 'report_only']);
  assert.equal(r.odd, 1);
});

test('main() warns on stderr about a stray input, naming it but no value', async () => {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-inputs-'));
  const savedEnv = { ...process.env };
  const savedExit = process.exitCode;
  const savedWrite = process.stderr.write;
  let stderr = '';
  try {
    writeFileSync(path.join(ws, 'p.json'), JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }] }));
    for (const k of Object.keys(process.env)) if (k.startsWith('INPUT_') || k.startsWith('GITHUB_')) delete process.env[k];
    Object.assign(process.env, { GITHUB_WORKSPACE: ws, INPUT_PATHS: 'p.json', INPUT_FAMILY: 'identity', INPUT_PARTITION: 'aws', 'INPUT_FEDERATION-HOSTS': 'secret-looking-value' });
    process.stderr.write = (c) => { stderr += String(c); return true; };
    await main();
  } finally {
    process.stderr.write = savedWrite;
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, savedEnv);
    process.exitCode = savedExit;
    rmSync(ws, { recursive: true, force: true });
  }
  assert.match(stderr, /ignoring unrecognized input\(s\): federation-hosts \(not declared in action\.yml\)/);
  assert.doesNotMatch(stderr, /secret-looking-value/);
});
