// v1.2.0 small fixes: F7 session ceiling severity, F14 resource context checks, F16 family tokens.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

import { scan, EXIT, SELECTABLE_FAMILIES } from '../../../cli/scan.mjs';

const ROOT = new URL('../../../', import.meta.url);
const doc = (stmts) => JSON.stringify({ Version: '2012-10-17', Statement: stmts });
const run = (stmts, family, extra = {}) => scan({ text: doc(stmts), family, partition: 'aws', threshold: 'high', ...extra });
const ids = (r) => r.findings.map((f) => `${f.id}:${f.severity}`);

test('F7: session Allow * and broad NotAction rate high, like the boundary', () => {
  for (const stmt of [
    { Effect: 'Allow', Action: '*', Resource: '*' },
    { Effect: 'Allow', NotAction: 'iam:*', Resource: '*' },
  ]) {
    const s = run([stmt], 'session');
    const b = run([stmt], 'permissions-boundary');
    assert.deepEqual(ids(s), ['SESSION-CEILING:high']);
    assert.equal(s.exitCode, EXIT.FINDINGS);
    assert.equal(s.exitCode, b.exitCode);
  }
});

test('F7: a scoped session policy stays info and clean', () => {
  const r = run([{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/k' }], 'session');
  assert.deepEqual(ids(r), ['SESSION-CEILING:info']);
  assert.equal(r.exitCode, EXIT.CLEAN);
});

const pub = (res) => [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: res }];
const rctx = (resourceContext, res = 'arn:aws:s3:::example-bucket/*') => run(pub(res), 'resource', { resourceContext });
const blocked = (r) => JSON.stringify(r).includes('RESOURCE_CONTEXT_REQUIRED');

test('F14: a type hint that contradicts the ARN service fails closed (exit 3)', () => {
  const r = rctx({ type: 'kms', arn: 'arn:aws:s3:::example-bucket' });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.ok(blocked(r));
  assert.equal(r.findings.length, 0);
  assert.ok(blocked(rctx({ type: 'sqs', arn: 'arn:aws:s3:::example-bucket' })));
});

test('F14: a policy Resource for another bucket fails closed (exit 3)', () => {
  const r = rctx({ type: 's3-bucket', arn: 'arn:aws:s3:::example-bucket' }, 'arn:aws:s3:::other/*');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.ok(blocked(r));
  assert.ok(blocked(rctx({ type: 'sns', arn: 'arn:aws:sns:us-east-1:111122223333:t' }, 'arn:aws:sns:us-east-1:111122223333:other')));
});

test('F14: matching type and Resource are still analyzed as before', () => {
  for (const ctx of [
    { type: 's3-bucket', arn: 'arn:aws:s3:::example-bucket' },
    { type: 's3', arn: 'arn:aws:s3:::example-bucket' },
    { type: 'other', arn: 'arn:aws:s3:::example-bucket' },
    { arn: 'arn:aws:s3:::example-bucket' },
  ]) {
    const r = rctx(ctx);
    assert.ok(!blocked(r), JSON.stringify(ctx));
    assert.ok(r.findings.some((f) => f.id === 'PUBLIC-ACCESS'), JSON.stringify(ctx));
  }
  assert.ok(!blocked(rctx({ type: 's3-bucket', arn: 'arn:aws:s3:::example-bucket' }, '*')));
});

test('F16: help, usage errors, README and ACTION.md state the accepted family tokens', () => {
  const tokens = [...SELECTABLE_FAMILIES];
  const cli = (...a) => spawnSync(process.execPath, ['cli/iam-br.mjs', ...a], { cwd: ROOT, encoding: 'utf8' });
  const help = cli('--help').stdout;
  const usage = cli('--family', 'bogus', 'x.json');
  assert.equal(usage.status, EXIT.USAGE);
  for (const t of tokens) {
    for (const [where, text] of [['help', help], ['usage', usage.stderr]]) {
      assert.match(text, new RegExp(`(^|[\\s|(])${t}([\\s|)]|$)`), `${where} lacks ${t}`);
    }
    for (const f of ['README.md', 'ACTION.md']) {
      assert.ok(readFileSync(new URL(f, ROOT), 'utf8').includes(`\`${t}\``), `${f} lacks ${t}`);
    }
  }
});

test('F16: the scan() usage error names every accepted token', () => {
  const r = scan({ text: '{}', family: 'bogus' });
  assert.equal(r.exitCode, EXIT.USAGE);
  for (const t of SELECTABLE_FAMILIES) assert.ok(JSON.stringify(r).includes(t), t);
});
