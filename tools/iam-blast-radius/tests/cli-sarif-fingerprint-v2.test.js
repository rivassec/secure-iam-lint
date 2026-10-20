// partialFingerprints v2: content identity (no statement position), an occurrence ordinal
// for true duplicates, the offending set in analyzer-state identity, and SHA-256/128.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { scan } from '../../../cli/scan.mjs';
import { buildSarifLog, FINGERPRINT_KEY, sha256Hex } from '../../../cli/sarif.mjs';

const stmt = (a, extra = {}) => ({ Effect: 'Allow', Action: a, Resource: '*', ...extra });
const doc = (list) => JSON.stringify({ Version: '2012-10-17', Statement: list });

function rows(text) {
  const result = scan({ text, family: 'identity', threshold: 'high', subjectAccount: '123456789012', partition: 'aws' });
  return buildSarifLog(result, { file: 'p.json' }, { ruleVersion: '1' }).runs[0].results;
}
const fps = (text) => rows(text).map((r) => `${r.ruleId}:${r.partialFingerprints[FINGERPRINT_KEY]}`);

test('the fingerprint key is versioned v2 and the value is 128 bits of hex', () => {
  assert.equal(FINGERPRINT_KEY, 'iamBlastRadius/semanticIdentity/v2');
  for (const r of rows(doc([stmt('s3:DeleteObject')]))) {
    assert.deepEqual(Object.keys(r.partialFingerprints), [FINGERPRINT_KEY]);
    assert.match(r.partialFingerprints[FINGERPRINT_KEY], /^[0-9a-f]{32}$/);
  }
});

test('sha256Hex matches node:crypto over UTF-16 code units, incl. padding boundaries and lone surrogates', () => {
  const ref = (s) => {
    const b = Buffer.alloc(s.length * 2);
    for (let i = 0; i < s.length; i += 1) b.writeUInt16BE(s.charCodeAt(i), i * 2);
    return createHash('sha256').update(b).digest('hex');
  };
  for (const n of [0, 1, 27, 28, 29, 31, 32, 33, 59, 60, 64, 100, 5000]) {
    const s = 'a'.repeat(n);
    assert.equal(sha256Hex(s), ref(s), `len ${n}`);
  }
  for (const s of ['\ud800', '\udc00', 'é\u0000✓😀', '\ud800x']) assert.equal(sha256Hex(s), ref(s));
  assert.notEqual(sha256Hex('\ud800'), sha256Hex('\udc00'));
});

test('a harmless statement inserted above does not change an existing finding fingerprint', () => {
  const before = fps(doc([stmt('s3:DeleteObject')]));
  const after = fps(doc([stmt('sqs:SendMessage', { Resource: 'arn:aws:sqs:us-east-1:111122223333:q' }), stmt('s3:DeleteObject')]));
  assert.ok(before.length > 0);
  for (const f of before) assert.ok(after.includes(f), f);
});

test('Sid rename, key order and whitespace do not change the fingerprint', () => {
  const a = doc([stmt('s3:DeleteObject', { Sid: 'One' })]);
  const b = '{\r\n "Statement":[{"Resource":"*","Action":["s3:DeleteObject"],"Effect":"Allow","Sid":"Two"}],\r\n"Version":"2012-10-17"}';
  assert.deepEqual(fps(a), fps(b));
});

test('genuine duplicates stay distinct (occurrence ordinal) and stable', () => {
  const two = fps(doc([stmt('s3:DeleteObject'), stmt('s3:DeleteObject')]));
  assert.equal(new Set(two).size, two.length);
  const shifted = fps(doc([stmt('sqs:SendMessage'), stmt('s3:DeleteObject'), stmt('s3:DeleteObject')]));
  for (const f of two) assert.ok(shifted.includes(f), f);
  // The first occurrence keeps the fingerprint it had when it was alone.
  const one = fps(doc([stmt('s3:DeleteObject')]));
  for (const f of one) assert.ok(two.includes(f), f);
});

test('different unknown actions / unsupported conditions get different state fingerprints', () => {
  const pick = (text, code) => rows(text).filter((r) => r.ruleId === code).map((r) => r.partialFingerprints[FINGERPRINT_KEY]);
  const u1 = pick(doc([stmt('fakesvc:One')]), 'analysis.UNKNOWN_ACTION');
  const u2 = pick(doc([stmt('sqs:SendMessage'), stmt('fakesvc:Two')]), 'analysis.UNKNOWN_ACTION');
  assert.equal(u1.length, 1);
  assert.equal(u2.length, 1);
  assert.notEqual(u1[0], u2[0]);
  const c = (k) => pick(doc([stmt('s3:ListBucket', { Resource: 'arn:aws:s3:::b', Condition: { StringEquals: { [k]: 'x' } } })]), 'analysis.UNSUPPORTED_CONDITION');
  assert.notEqual(c('zzz:one')[0], c('zzz:two')[0]);
});
