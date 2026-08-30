// Keeps the AWS differential oracle harness working without needing AWS creds:
// runs it in --dry-run (canned AWS response) and asserts the diff logic is sound
// (every benchmark policy grants a dangerous action, and the engine reads none of
// them CLEAN, so there must be zero fail-closed violations). The real AWS run is
// manual (`--profile <name>`); this only guards the harness itself.
//
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SCRIPT = resolve(HERE, 'aws-differential.mjs');

test('AWS differential oracle: --dry-run passes with zero fail-closed violations', () => {
  const out = execFileSync('node', [SCRIPT, '--dry-run'], { encoding: 'utf8', maxBuffer: 8 << 20 });
  assert.match(out, /Fail-closed violations \(AWS says allowed, engine CLEAN\): 0/,
    'dry-run must report zero fail-closed violations');
});

test('AWS differential oracle: refuses to run against AWS without an explicit profile', () => {
  // No --profile and no --dry-run -> must refuse (exit non-zero), never guess an account.
  let threw = false;
  try {
    execFileSync('node', [SCRIPT], { encoding: 'utf8', env: { ...process.env, AWS_PROFILE: '' } });
  } catch (e) {
    threw = true;
    assert.match(String(e.stderr || e.stdout || ''), /Refusing to guess an AWS account/);
  }
  assert.ok(threw, 'must refuse (non-zero exit) when no profile and no --dry-run');
});
