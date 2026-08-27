// Runs the SECONDARY snapshot channel under `node --test`: every corpus snapshot must
// match its committed baseline, and the diff engine itself must actually detect drift.
// This is a change-detector, NOT a safety proof (the oracle is the safety proof).

import test from 'node:test';
import assert from 'node:assert/strict';

import { runDiff, firstDiff } from './diff.mjs';

test('snapshot: every corpus case matches its committed baseline', () => {
  const { ok, drifts, missing, extra } = runDiff();
  assert.deepEqual(missing, [], `missing baselines: ${missing.join(', ')} (run capture.mjs --update)`);
  assert.deepEqual(extra, [], `stale baselines: ${extra.join(', ')} (run capture.mjs --update)`);
  assert.deepEqual(drifts, [], `snapshot drift: ${drifts.map((d) => `${d.id} (${d.reason})`).join('; ')}`);
  assert.equal(ok, true);
});

test('firstDiff detects a value change, a type change, a length change, and a key change', () => {
  assert.equal(firstDiff({ a: 1 }, { a: 1 }), null);
  assert.match(firstDiff({ a: 1 }, { a: 2 }), /a: 1 != 2/);
  assert.match(firstDiff({ a: 1 }, { a: '1' }), /type number != string/);
  assert.match(firstDiff({ a: [1, 2] }, { a: [1] }), /length 2 != 1/);
  assert.match(firstDiff({ a: 1 }, { a: 1, b: 2 }), /keys/);
});
