// Round 8 lane E: run-level headline (E-7), reason output (E-8), credentials warning (F-4).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runAction, credentialsInEnv, formatOutputs } from '../../../action/index.mjs';
import { main } from '../../../action/index.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const fx = (n) => readFileSync(path.join(here, 'pulumi-fixtures', n), 'utf8');
const pulumi = (name, extra = {}) => runAction({
  env: { ...extra, 'INPUT_PULUMI-JSON': name, INPUT_PARTITION: 'aws', 'INPUT_FAIL-ON': 'high', 'INPUT_SARIF-OUTPUT': 'x.sarif' },
  io: { readFile: () => fx(name) },
});

test('E-7: a run-level state beats a document-level COVERAGE_INCOMPLETE at the same exit code', () => {
  const r = pulumi('e7-headline.json');
  assert.equal(r.exitCode, 3);
  const reasons = r.units.map((u) => u.result.reason);
  assert.ok(reasons.includes('COVERAGE_INCOMPLETE'));
  assert.ok(reasons.includes('PULUMI_ACCOUNT_UNRESOLVED'));
  assert.equal(r.reason, 'PULUMI_ACCOUNT_UNRESOLVED');
  assert.equal(r.outputs.reason, 'PULUMI_ACCOUNT_UNRESOLVED');
});

test('E-7 with the account resolved: the unmodeled-permission state is the headline', () => {
  const r = pulumi('e7-headline.json', { 'INPUT_PROVIDER-ACCOUNTS': 'a=111111111111' });
  assert.equal(r.reason, 'PULUMI_UNMODELED_PERMISSION');
  assert.ok(r.units.some((u) => u.result.reason === 'COVERAGE_INCOMPLETE'));
});

test('E-7 control: without the permission resource the headline stays COVERAGE_INCOMPLETE', () => {
  const r = pulumi('e7-headline-control.json', { 'INPUT_PROVIDER-ACCOUNTS': 'a=111111111111' });
  assert.equal(r.exitCode, 3);
  assert.equal(r.reason, 'COVERAGE_INCOMPLETE');
  assert.equal(r.outputs.reason, 'COVERAGE_INCOMPLETE');
});

test('E-8: reason output is clean on a clean run and enum-shaped always', () => {
  const clean = runAction({
    env: { INPUT_PATHS: 'p.json', INPUT_FAMILY: 'identity', INPUT_PARTITION: 'aws' },
    io: { listFiles: () => ['p.json'], readFile: () => JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }] }) },
  });
  assert.equal(clean.exitCode, 0);
  assert.equal(clean.outputs.reason, 'clean');
  assert.match(formatOutputs(clean.outputs), /^reason=clean$/m);
});

test('F-4: credentialsInEnv reports names only, ignores empty values', () => {
  assert.deepEqual(credentialsInEnv({ AWS_ACCESS_KEY_ID: 'AKIAXXXX', AWS_SESSION_TOKEN: '', PATH: '/bin' }), ['AWS_ACCESS_KEY_ID']);
  assert.deepEqual(credentialsInEnv({}), []);
});

test('F-4: main() warns by code when credentials are in env, never printing a value', async () => {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-creds-'));
  const savedEnv = { ...process.env };
  const savedExit = process.exitCode;
  const savedWrite = process.stderr.write;
  let stderr = '';
  try {
    writeFileSync(path.join(ws, 'p.json'), JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }] }));
    for (const k of Object.keys(process.env)) if (k.startsWith('INPUT_') || k.startsWith('GITHUB_') || k.startsWith('AWS_')) delete process.env[k];
    Object.assign(process.env, {
      GITHUB_WORKSPACE: ws, INPUT_PATHS: 'p.json', INPUT_FAMILY: 'identity', INPUT_PARTITION: 'aws',
      AWS_ACCESS_KEY_ID: 'AKIA-sentinel-value', AWS_SECRET_ACCESS_KEY: '::error::sentinel-secret',
    });
    process.stderr.write = (c) => { stderr += String(c); return true; };
    await main();
  } finally {
    process.stderr.write = savedWrite;
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, savedEnv);
    process.exitCode = savedExit;
    rmSync(ws, { recursive: true, force: true });
  }
  assert.match(stderr, /AWS_CREDENTIALS_IN_ENV: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY set/);
  assert.doesNotMatch(stderr, /sentinel/);
});
