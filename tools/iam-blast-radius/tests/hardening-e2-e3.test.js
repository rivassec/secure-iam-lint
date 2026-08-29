// Regression for review findings E2 (sanitizeTree prototype-pollution guard) and
// E3 (readStdin idle timeout - a never-EOF producer must not hang the CLI).

import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';

import { sanitizeTree } from '../../../content/tools/iam-blast-radius/engine/format-control.js';
import { readStdin } from '../../../cli/iam-br.mjs';

// --- E2 -------------------------------------------------------------------

test('E2: sanitizeTree drops __proto__/constructor/prototype keys (no reparenting)', () => {
  // JSON.parse creates a real own "__proto__" data property (object-literal syntax cannot).
  const hostile = JSON.parse('{"__proto__":{"polluted":"yes"},"constructor":{"x":1},"Sid":"ok"}');
  const out = sanitizeTree(hostile);
  assert.equal(Object.getPrototypeOf(out), Object.prototype, 'output prototype must be untouched');
  assert.equal({}.polluted, undefined, 'Object.prototype must not be polluted');
  assert.equal(Object.prototype.hasOwnProperty.call(out, '__proto__'), false, '__proto__ key dropped');
  assert.equal(Object.prototype.hasOwnProperty.call(out, 'constructor'), false, 'constructor key dropped');
  assert.equal(out.Sid, 'ok', 'benign keys survive');
});

// --- E3 -------------------------------------------------------------------

test('E3: readStdin fails closed on a never-EOF producer (idle timeout)', async () => {
  process.env.IAM_BR_STDIN_IDLE_MS = '80'; // tiny idle window for the test
  // The idle timer is unref()'d (so the real CLI exits naturally); keep the test's event
  // loop alive with a ref'd interval so the runner does not resolve before it fires.
  const keepAlive = setInterval(() => {}, 20);
  try {
    const fake = new EventEmitter();
    fake.pause = () => {};
    fake.destroy = () => {};
    // Emit a few under-cap bytes, then NEVER 'end' (a stalled producer).
    setTimeout(() => fake.emit('data', Buffer.from('{"Ver')), 5);
    await assert.rejects(
      readStdin(fake),
      (e) => e && e.code === 'STDIN_IDLE_TIMEOUT',
      'a stalled stdin must reject with STDIN_IDLE_TIMEOUT, never hang',
    );
  } finally {
    clearInterval(keepAlive);
    delete process.env.IAM_BR_STDIN_IDLE_MS;
  }
});

test('E3: readStdin still resolves normally when the stream ends', async () => {
  const keepAlive = setInterval(() => {}, 20);
  try {
    const fake = new EventEmitter();
    fake.pause = () => {};
    setTimeout(() => { fake.emit('data', Buffer.from('{"ok":1}')); fake.emit('end'); }, 5);
    const out = await readStdin(fake);
    assert.equal(out, '{"ok":1}', 'a normal stdin must resolve with its content');
  } finally {
    clearInterval(keepAlive);
  }
});
