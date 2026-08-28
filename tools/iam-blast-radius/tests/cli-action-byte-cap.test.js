// Regression tests for STORY D-byte-cap (threat-model T5, availability).
//
// The MAX_BYTES input cap must be enforced BEFORE the whole input is materialized -
// so an unbounded / multi-GB STDIN stream or an oversized FILE is rejected without
// buffering it into memory - and it must ALWAYS fail CLOSED (never a clean pass /
// exit 0). The pre-guard (CLI readStdin / readFileCapped, Action per-file statSync)
// and the engine's own validate() guard share ONE limit (LIMITS.MAX_BYTES exported
// from engine/validate.js) so they cannot drift.
//
// These tests pin:
//   1. STDIN over-cap ABORTS mid-stream (does not buffer the whole stream).
//   2. A just-under-cap VALID MULTIBYTE policy still decodes correctly and passes
//      (a multibyte char split across a chunk boundary is neither miscounted nor
//      mis-decoded) - i.e. we do not over-correct into a false positive.
//   3. readFileCapped rejects an over-cap file via statSync BEFORE readFileSync,
//      and reads an at/under-cap file normally.
//   4. run() routes a pre-guard TOO_LARGE down the fail-closed exit-3 path.
//   5. The Action fails a single over-cap file closed to exit 3 (not exit 4, not 0).

import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { run, EXIT, readStdin, readFileCapped } from '../../../cli/iam-br.mjs';
import { runAction, exceedsInputByteCap, EXIT as ACTION_EXIT } from '../../../action/index.mjs';
import { LIMITS } from '../../../content/tools/iam-blast-radius/engine/validate.js';

const MAX = LIMITS.MAX_BYTES;

// =============================================================================
// 1. STDIN pre-guard: over-cap aborts WITHOUT fully buffering the stream.
// =============================================================================

test('readStdin ABORTS once encoded bytes exceed MAX_BYTES, before buffering the whole stream', async () => {
  const stream = new EventEmitter();
  const p = readStdin(stream); // attaches listeners synchronously

  // Emit far MORE data than the cap, in chunks, synchronously. The guard must reject
  // on the chunk that crosses the cap and stop consuming - the later chunks land with
  // no 'data' listener attached (removed on abort) and are never buffered.
  const CHUNK = 300 * 1000; // 300 kB; 4 chunks (1.2 MB) crosses the 1 MiB cap
  const TOTAL_CHUNKS = 200; // 60 MB attempted - must NOT all be buffered
  const chunk = Buffer.alloc(CHUNK, 0x78 /* 'x' */);
  for (let i = 0; i < TOTAL_CHUNKS; i++) stream.emit('data', chunk);
  stream.emit('end'); // no-op: promise already settled by the abort

  const err = await p.then(
    () => { throw new Error('readStdin must REJECT an over-cap stream, not resolve'); },
    (e) => e,
  );
  assert.equal(err.code, 'INPUT_TOO_LARGE');
  // It aborted at the FIRST chunk that crossed the cap, not after draining all 200:
  // exactly 4 chunks (>1 MiB) were counted, nowhere near the 60 MB attempted.
  assert.equal(err.bytes, 4 * CHUNK);
  assert.ok(err.bytes <= MAX + CHUNK, 'aborted within one chunk of the cap');
  assert.ok(err.bytes < TOTAL_CHUNKS * CHUNK, 'did NOT buffer the whole stream');
});

test('readStdin: a chunk landing exactly AT the cap is accepted; the next byte trips it', async () => {
  // 1 MiB exactly -> ok; 1 byte more -> over.
  const atCap = new EventEmitter();
  const pOk = readStdin(atCap);
  atCap.emit('data', Buffer.alloc(MAX, 0x78));
  atCap.emit('end');
  const okText = await pOk;
  assert.equal(Buffer.byteLength(okText, 'utf8'), MAX);

  const overCap = new EventEmitter();
  const pOver = readStdin(overCap);
  overCap.emit('data', Buffer.alloc(MAX, 0x78));
  overCap.emit('data', Buffer.from('!')); // one byte over
  overCap.emit('end');
  const e = await pOver.then(() => null, (x) => x);
  assert.ok(e && e.code === 'INPUT_TOO_LARGE', 'MAX_BYTES + 1 must fail closed');
});

// =============================================================================
// 2. Just-under-cap VALID MULTIBYTE policy: correct decode, no false positive.
// =============================================================================

test('readStdin decodes a multibyte char SPLIT across a chunk boundary without corruption', async () => {
  // A policy Sid padded with a multibyte character (U+00E9 "é", 2 UTF-8 bytes) so the
  // document stays JUST UNDER the cap. We split the UTF-8 buffer at an ODD byte offset
  // that lands in the MIDDLE of an "é" - the naive "setEncoding utf8 + count string
  // length per chunk" approach would both mis-decode (U+FFFD) and mis-count here.
  const pad = 'é'.repeat(1000); // 2000 UTF-8 bytes of multibyte content
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: `S${pad}`, Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' }],
  });
  const buf = Buffer.from(policy, 'utf8');
  assert.ok(buf.length < MAX, 'fixture must be under the cap');

  // Find a split index that bisects a multibyte sequence (a continuation byte 0x80-0xBF
  // on the high side means the previous byte started a multibyte char).
  let split = -1;
  for (let i = 1; i < buf.length; i++) {
    if ((buf[i] & 0xc0) === 0x80) { split = i; break; }
  }
  assert.ok(split > 0, 'fixture must contain a splittable multibyte char');

  const stream = new EventEmitter();
  const p = readStdin(stream);
  stream.emit('data', buf.subarray(0, split));
  stream.emit('data', buf.subarray(split));
  stream.emit('end');
  const text = await p;
  assert.equal(text, policy, 'the split multibyte policy must decode back byte-for-byte');
});

test('a just-under-cap valid multibyte policy piped to run() is NOT flagged TOO_LARGE', async () => {
  // Whole-pipe check: an injected readStdin returns an under-cap multibyte policy; the
  // scan must NOT fail closed on the byte cap (it is clean -> exit 0). Guards against
  // over-correcting the availability fix into a false positive.
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: `Se${'é'.repeat(50)}`,
      Effect: 'Allow',
      Action: 'ec2:DescribeInstances',
      Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc',
    }],
  });
  assert.ok(Buffer.byteLength(policy, 'utf8') < MAX);
  const out = [];
  const io = {
    readStdin: async () => policy,
    stdout: (s) => out.push(s),
    stderr: () => {},
    stdinIsTTY: false,
  };
  const code = await run(['--family', 'identity'], io);
  assert.equal(code, EXIT.CLEAN, 'an under-cap valid policy must not fail closed on the byte cap');
});

// =============================================================================
// 3. readFileCapped: statSync gate BEFORE readFileSync.
// =============================================================================

test('readFileCapped rejects an over-cap file via statSync (before reading it into memory)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'iam-br-bytecap-'));
  try {
    const big = join(dir, 'big.json');
    writeFileSync(big, Buffer.alloc(MAX + 1, 0x78)); // one byte over the cap
    assert.throws(() => readFileCapped(big), (e) => e && e.code === 'INPUT_TOO_LARGE');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('readFileCapped reads an at/under-cap file normally', () => {
  const dir = mkdtempSync(join(tmpdir(), 'iam-br-bytecap-'));
  try {
    const ok = join(dir, 'ok.json');
    const policy = JSON.stringify({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' }],
    });
    writeFileSync(ok, policy);
    assert.equal(readFileCapped(ok), policy);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// =============================================================================
// 4. run() routes a pre-guard TOO_LARGE down the fail-closed exit-3 path.
// =============================================================================

function tooLargeError() {
  const e = new Error('input exceeds the byte limit');
  e.code = 'INPUT_TOO_LARGE';
  return e;
}

test('run(): a STDIN pre-guard TOO_LARGE fails CLOSED to exit 3 (never clean/exit 0)', async () => {
  const out = [];
  const io = {
    readStdin: async () => { throw tooLargeError(); },
    stdout: (s) => out.push(s),
    stderr: () => {},
    stdinIsTTY: false,
  };
  const code = await run(['--family', 'identity'], io);
  assert.equal(code, EXIT.FAIL_CLOSED);
  const report = JSON.parse(out.join(''));
  assert.equal(report.analysisStatus, 'failed');
  assert.ok(
    report.analysisStates.some((s) => s.code === 'TOO_LARGE'),
    'the fail-closed verdict must carry the engine TOO_LARGE state',
  );
});

test('run(): a FILE pre-guard TOO_LARGE fails CLOSED to exit 3 (not the usage exit 2)', async () => {
  const out = [];
  const io = {
    readFile: () => { throw tooLargeError(); },
    readStdin: async () => '',
    stdout: (s) => out.push(s),
    stderr: () => {},
    stdinIsTTY: true,
  };
  const code = await run(['--family', 'identity', 'big.json'], io);
  assert.equal(code, EXIT.FAIL_CLOSED);
});

test('run(): a NON-TOO_LARGE file read error is still a usage error (exit 2), unchanged', async () => {
  const io = {
    readFile: () => { const e = new Error('nope'); e.code = 'ENOENT'; throw e; },
    readStdin: async () => '',
    stdout: () => {},
    stderr: () => {},
    stdinIsTTY: true,
  };
  const code = await run(['--family', 'identity', 'missing.json'], io);
  assert.equal(code, EXIT.USAGE);
});

// =============================================================================
// 5. Action: an over-cap file fails THAT file closed to exit 3 (not 4, not 0).
// =============================================================================

test('exceedsInputByteCap boundary: MAX passes, MAX+1 trips, garbage passes (no cap)', () => {
  assert.equal(exceedsInputByteCap(MAX), false);
  assert.equal(exceedsInputByteCap(MAX + 1), true);
  assert.equal(exceedsInputByteCap(0), false);
  assert.equal(exceedsInputByteCap(NaN), false); // non-finite -> not "over cap"
});

test('runAction: a per-file statSync TOO_LARGE fails CLOSED to exit 3 (not INTERNAL exit 4)', () => {
  const env = { 'INPUT_PATHS': 'big.json', 'INPUT_FAMILY': 'identity' };
  const io = {
    listFiles: () => ['big.json'],
    readFile: () => { throw tooLargeError(); },
  };
  const r = runAction({ env, io });
  assert.equal(r.exitCode, ACTION_EXIT.FAIL_CLOSED, 'over-cap file must be exit 3, never exit 4 or 0');
  assert.equal(r.analysisStatus, 'failed');
  assert.equal(r.reason, 'TOO_LARGE');
});

test('runAction: worst-code aggregation - an over-cap file makes a mixed run fail closed (>=3)', () => {
  const cleanPolicy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0' }],
  });
  const env = { 'INPUT_PATHS': 'a.json\nbig.json', 'INPUT_FAMILY': 'identity' };
  const io = {
    listFiles: () => ['a.json', 'big.json'],
    readFile: (rel) => {
      if (rel === 'big.json') throw tooLargeError();
      return cleanPolicy;
    },
  };
  const r = runAction({ env, io });
  assert.equal(r.exitCode, ACTION_EXIT.FAIL_CLOSED, 'one over-cap file must fail the whole run closed');
});
