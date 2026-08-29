// Stage-11 re-review, RC-A finding #8.
//
// sanitizeTree() checked its dangerous-key blocklist against the RAW key and only
// THEN ran neutralizeForDisplay() to produce the output key. A format-control-
// spoofed key such as `__pro<U+200B>to__` slips past the raw blocklist (it is not
// literally "__proto__") and neutralizeForDisplay() then collapses it back to
// "__proto__", so `out[neutralizeForDisplay(key)] = ...` reparents the output
// object's prototype (or silently drops the key content). Fix: neutralize the key
// FIRST, then test the blocklist against the cleaned key - the same strip-before-
// check ordering the model boundary already uses.

import test from 'node:test';
import assert from 'node:assert/strict';

import { sanitizeTree } from '../../../content/tools/iam-blast-radius/engine/format-control.js';

const ZWSP = '​';

test('#8: a format-control-spoofed __proto__ key never reparents the output prototype', () => {
  const out = sanitizeTree({ [`__pro${ZWSP}to__`]: { polluted: true }, keep: 'v' });
  assert.equal(Object.getPrototypeOf(out), Object.prototype,
    'the spoofed proto key must not reparent the sanitized output');
  assert.equal(({}).polluted, undefined, 'no global prototype pollution');
  assert.equal(Object.prototype.hasOwnProperty.call(out, '__proto__'), false,
    'the collapsed __proto__ key is dropped, not written as data');
  assert.equal(out.keep, 'v', 'legitimate sibling keys survive');
});

for (const danger of ['constructor', 'prototype']) {
  test(`#8: a spoofed ${danger} key is dropped after neutralization`, () => {
    const spoofed = `${danger.slice(0, 2)}${ZWSP}${danger.slice(2)}`;
    const out = sanitizeTree({ [spoofed]: { x: 1 } });
    assert.equal(Object.prototype.hasOwnProperty.call(out, danger), false,
      `${danger} must not appear as an own key after neutralization`);
  });
}

test('#8: a legitimate key that merely resembles nothing dangerous is preserved', () => {
  const out = sanitizeTree({ 'aws:username': 'alice', nested: { ok: [1, 'two'] } });
  assert.deepEqual(out, { 'aws:username': 'alice', nested: { ok: [1, 'two'] } });
});
