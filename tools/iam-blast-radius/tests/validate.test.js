// Unit tests for IAM-001: input validation + hostile-input guards.
// Runs on node's built-in runner: `node --test tests/`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { validate, LIMITS } from '../../../content/tools/iam-blast-radius/engine/validate.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

// A fixture supplies either raw text (policyRaw) or a policy object (policy)
// that we stringify to feed the string-based validate(text) API.
function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

function loadFixtures(category) {
  const dir = join(fixturesDir, category);
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => ({ file: `${category}/${f}`, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
}

// ---------------------------------------------------------------------------
// Fixture-driven: every malformed/ and adversarial/ fixture must be handled
// with zero uncaught exceptions and the expected valid/invalid verdict.
// ---------------------------------------------------------------------------

for (const category of ['malformed', 'adversarial', 'safe']) {
  for (const { file, data } of loadFixtures(category)) {
    test(`fixture ${file}: no uncaught + expected verdict`, () => {
      const text = fixtureText(data);
      let result;
      assert.doesNotThrow(() => {
        result = validate(text);
      }, `validate() threw on ${file}`);

      assert.equal(typeof result.ok, 'boolean');
      assert.ok(Array.isArray(result.errors));

      if (data.expect && typeof data.expect.valid === 'boolean') {
        assert.equal(result.ok, data.expect.valid, `ok mismatch for ${file}`);
      }

      if (data.expect && Array.isArray(data.expect.errorCodes)) {
        const codes = result.errors.map((e) => e.code);
        for (const expected of data.expect.errorCodes) {
          assert.ok(codes.includes(expected), `expected error code ${expected} for ${file}, got ${codes.join(',')}`);
        }
        if (data.expect.errorCodes.length === 0) {
          assert.equal(result.errors.length, 0, `expected no errors for ${file}`);
        }
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Prototype pollution must never touch Object.prototype.
// ---------------------------------------------------------------------------

test('proto-pollution fixture rejected and prototype untouched', () => {
  const raw = readFileSync(join(fixturesDir, 'malformed', 'proto-pollution.json'), 'utf8');
  const fx = JSON.parse(raw);
  const result = validate(fx.policyRaw);
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.code === 'DANGEROUS_KEY'));
  assert.equal({}.polluted, undefined, 'Object.prototype was polluted');
});

test('nested __proto__ rejected without polluting prototype', () => {
  const before = Object.prototype.polluted;
  const result = validate(
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","x":{"__proto__":{"polluted":true}}}]}',
  );
  assert.equal(result.ok, false);
  assert.ok(result.errors.some((e) => e.code === 'DANGEROUS_KEY'));
  assert.equal(Object.prototype.polluted, before);
  assert.equal({}.polluted, undefined);
});

test('constructor and prototype keys rejected', () => {
  for (const key of ['constructor', 'prototype', '__proto__']) {
    const result = validate(`{"Statement":[{"Effect":"Allow","${key}":{"a":1}}]}`);
    assert.equal(result.ok, false, `${key} should be rejected`);
    assert.ok(result.errors.some((e) => e.code === 'DANGEROUS_KEY'), `${key} -> DANGEROUS_KEY`);
  }
});

// ---------------------------------------------------------------------------
// Structured return shape and null-prototype raw.
// ---------------------------------------------------------------------------

test('valid input returns ok with null-prototype raw', () => {
  const result = validate('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');
  assert.equal(result.ok, true);
  assert.deepEqual(result.errors, []);
  assert.ok(result.raw);
  assert.equal(Object.getPrototypeOf(result.raw), null, 'top-level raw must be null-prototype');
  const stmt = result.raw.Statement[0];
  assert.equal(Object.getPrototypeOf(stmt), null, 'nested objects must be null-prototype');
});

test('errors carry structured {code,message,path}', () => {
  const result = validate('not json');
  assert.equal(result.ok, false);
  for (const e of result.errors) {
    assert.equal(typeof e.code, 'string');
    assert.equal(typeof e.message, 'string');
    assert.ok('path' in e);
  }
});

// ---------------------------------------------------------------------------
// Guard limits.
// ---------------------------------------------------------------------------

test('non-string input rejected, no throw', () => {
  for (const bad of [null, undefined, 42, {}, [], true]) {
    let r;
    assert.doesNotThrow(() => {
      r = validate(bad);
    });
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.code === 'NOT_A_STRING'));
  }
});

test('empty / whitespace input rejected', () => {
  for (const s of ['', '   ', '\n\t ']) {
    const r = validate(s);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.code === 'EMPTY_INPUT'));
  }
});

test('oversize input rejected with TOO_LARGE', () => {
  // Build a syntactically-plausible but huge string just over the byte cap.
  const filler = 'x'.repeat(LIMITS.MAX_BYTES + 10);
  const big = `{"Version":"${filler}"}`;
  const r = validate(big);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.code === 'TOO_LARGE'));
});

test('over-deep nesting rejected before parse (no stack overflow)', () => {
  const deep = '['.repeat(LIMITS.MAX_DEPTH + 5) + ']'.repeat(LIMITS.MAX_DEPTH + 5);
  let r;
  assert.doesNotThrow(() => {
    r = validate(deep);
  });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.code === 'TOO_DEEP'));
});

test('depth guard ignores braces inside string literals', () => {
  // Many { and [ characters, but all inside a string value -> depth 1.
  const bracesInString = '{"Sid":"' + '{['.repeat(200) + '"}';
  const r = validate(bracesInString);
  // Valid JSON object, not over-deep; should not be TOO_DEEP.
  assert.ok(!r.errors.some((e) => e.code === 'TOO_DEEP'));
});

test('too many statements rejected', () => {
  const stmts = [];
  for (let i = 0; i < LIMITS.MAX_STATEMENTS + 1; i++) {
    stmts.push({ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' });
  }
  const r = validate(JSON.stringify({ Version: '2012-10-17', Statement: stmts }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.code === 'TOO_MANY_STATEMENTS'));
});

test('too many actions rejected', () => {
  const actions = [];
  for (let i = 0; i < LIMITS.MAX_ACTIONS + 1; i++) actions.push(`svc:Action${i}`);
  const r = validate(JSON.stringify({ Statement: [{ Effect: 'Allow', Action: actions, Resource: '*' }] }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.code === 'TOO_MANY_ACTIONS'));
});

test('too many resources rejected', () => {
  const resources = [];
  for (let i = 0; i < LIMITS.MAX_RESOURCES + 1; i++) resources.push(`arn:aws:s3:::b${i}`);
  const r = validate(JSON.stringify({ Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: resources }] }));
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.code === 'TOO_MANY_RESOURCES'));
});

test('statement counting tolerates single-object Statement', () => {
  const r = validate('{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}');
  assert.equal(r.ok, true);
});

test('top-level non-object rejected', () => {
  for (const s of ['42', '"a string"', 'true', 'null', '[1,2,3]']) {
    const r = validate(s);
    assert.equal(r.ok, false, `${s} should be rejected`);
    assert.ok(r.errors.some((e) => e.code === 'NOT_AN_OBJECT'));
  }
});

// ---------------------------------------------------------------------------
// IAM-901: duplicate object-key detection (fail closed). JSON.parse silently
// keeps last-key-wins, so the raw text is scanned for a repeated key WITHIN the
// same object.
// ---------------------------------------------------------------------------

test('duplicate key within a statement object rejected with DUPLICATE_JSON_KEY', () => {
  const text = '{"Version":"2012-10-17","Statement":[{"Sid":"Dup","Effect":"Allow","Action":"s3:GetObject","Action":"iam:*","Resource":"*"}]}';
  const r = validate(text);
  assert.equal(r.ok, false);
  const dup = r.errors.find((e) => e.code === 'DUPLICATE_JSON_KEY');
  assert.ok(dup, 'expected DUPLICATE_JSON_KEY');
  assert.ok(dup.message.includes('"Action"'), 'names the duplicated key');
  assert.ok(dup.message.includes('Statement[0]') || String(dup.path).includes('Statement[0]'),
    'locates the statement object');
  assert.equal(r.raw, null, 'no raw returned on a blocked policy');
});

test('same key in DIFFERENT objects is legal (no false positive)', () => {
  const text = '{"Version":"2012-10-17","Statement":[' +
    '{"Sid":"A","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},' +
    '{"Sid":"B","Effect":"Allow","Action":"iam:*","Resource":"*"}]}';
  const r = validate(text);
  assert.equal(r.ok, true);
  assert.ok(!r.errors.some((e) => e.code === 'DUPLICATE_JSON_KEY'));
});

test('duplicate top-level key rejected and located', () => {
  const text = '{"Version":"2012-10-17","Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}';
  const r = validate(text);
  assert.equal(r.ok, false);
  const dup = r.errors.find((e) => e.code === 'DUPLICATE_JSON_KEY');
  assert.ok(dup);
  assert.ok(dup.message.includes('"Version"'));
});

test('escaped-form duplicate key still collides (matches JSON.parse semantics)', () => {
  // "Action" decodes to "Action"; JSON.parse would collapse the two.
  const text = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","\\u0041ction":"iam:*","Resource":"*"}]}';
  const r = validate(text);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.code === 'DUPLICATE_JSON_KEY'));
});

test('a key value containing braces/quotes does not confuse the scanner', () => {
  // The string value has {, }, and an escaped quote; the scanner must treat it
  // as one string and not mis-open an object scope.
  const text = '{"Version":"2012-10-17","Statement":[{"Sid":"weird {}\\" value","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}';
  const r = validate(text);
  assert.equal(r.ok, true);
  assert.ok(!r.errors.some((e) => e.code === 'DUPLICATE_JSON_KEY'));
});

// ---------------------------------------------------------------------------
// Determinism: same input -> identical result.
// ---------------------------------------------------------------------------

test('validate is deterministic', () => {
  const text = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*","iam:*"],"Resource":"*"}]}';
  const a = validate(text);
  const b = validate(text);
  assert.deepEqual(a.errors, b.errors);
  assert.equal(a.ok, b.ok);
  assert.deepEqual(JSON.parse(JSON.stringify(a.raw)), JSON.parse(JSON.stringify(b.raw)));
});
