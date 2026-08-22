// Unit tests for IAM-002: IAM JSON parser + normalized model.
// Runs on node's built-in runner: `node --test "tests/**/*.test.js"`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import { parse } from '../../../content/tools/iam-blast-radius/engine/parse.js';
import {
  buildModel,
  modelFromText,
} from '../../../content/tools/iam-blast-radius/engine/model.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

function loadFixtures(category) {
  const dir = join(fixturesDir, category);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => ({
      file: `${category}/${f}`,
      data: JSON.parse(readFileSync(join(dir, f), 'utf8')),
    }));
}

// Strip a frozen model into a plain JSON-comparable object (drops null-proto /
// frozen distinctions so deepEqual against a fixture literal is apples-to-apples).
function plain(v) {
  return JSON.parse(JSON.stringify(v));
}

// ---------------------------------------------------------------------------
// Fixture-driven: safe/ + not-action/ + not-resource/ parse to expected model.
// ---------------------------------------------------------------------------

for (const category of ['safe', 'not-action', 'not-resource']) {
  for (const { file, data } of loadFixtures(category)) {
    test(`fixture ${file}: parses to a normalized model`, () => {
      const text = fixtureText(data);
      let result;
      assert.doesNotThrow(() => {
        result = modelFromText(text);
      }, `modelFromText threw on ${file}`);

      assert.equal(result.ok, true, `expected ok model for ${file}: ${JSON.stringify(result.errors)}`);
      assert.ok(result.model, `model missing for ${file}`);

      // Structural invariants that hold for every normalized model.
      assert.ok(Array.isArray(result.model.statements));
      result.model.statements.forEach((s, i) => {
        assert.equal(s.index, i, `index must equal position for ${file}`);
        assert.ok(Array.isArray(s.actions));
        assert.ok(Array.isArray(s.notActions));
        assert.ok(Array.isArray(s.resources));
        assert.ok(Array.isArray(s.notResources));
        assert.ok(s.effect === 'Allow' || s.effect === 'Deny');
      });

      // Exact expected model when the fixture supplies one.
      if (data.expect && data.expect.model) {
        assert.deepEqual(plain(result.model), data.expect.model, `model mismatch for ${file}`);
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Statement container tolerance: object OR array.
// ---------------------------------------------------------------------------

test('single Statement object is normalized to a one-element list', () => {
  const r = modelFromText(
    '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}',
  );
  assert.equal(r.ok, true);
  assert.equal(r.model.statements.length, 1);
  assert.equal(r.model.statements[0].index, 0);
  assert.deepEqual(r.model.statements[0].actions, ['s3:GetObject']);
});

test('Statement array preserves order and assigns 0-based index', () => {
  const r = modelFromText(
    JSON.stringify({
      Statement: [
        { Sid: 'a', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
        { Sid: 'b', Effect: 'Deny', Action: 's3:DeleteObject', Resource: '*' },
        { Sid: 'c', Effect: 'Allow', Action: 'ec2:*', Resource: '*' },
      ],
    }),
  );
  assert.equal(r.ok, true);
  assert.deepEqual(
    r.model.statements.map((s) => [s.index, s.sid, s.effect]),
    [
      [0, 'a', 'Allow'],
      [1, 'b', 'Deny'],
      [2, 'c', 'Allow'],
    ],
  );
});

// ---------------------------------------------------------------------------
// Scalar/array normalization.
// ---------------------------------------------------------------------------

test('scalar Action/Resource promoted to arrays', () => {
  const r = modelFromText('{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}');
  assert.equal(r.ok, true);
  assert.deepEqual(r.model.statements[0].actions, ['s3:GetObject']);
  assert.deepEqual(r.model.statements[0].resources, ['arn:aws:s3:::b/*']);
});

test('array Action/Resource preserved as arrays', () => {
  const r = modelFromText('{"Statement":[{"Effect":"Allow","Action":["a:1","a:2"],"Resource":["r1","r2"]}]}');
  assert.equal(r.ok, true);
  assert.deepEqual(r.model.statements[0].actions, ['a:1', 'a:2']);
  assert.deepEqual(r.model.statements[0].resources, ['r1', 'r2']);
});

test('missing Resource defaults to empty array (tolerant)', () => {
  const r = modelFromText('{"Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}');
  assert.equal(r.ok, true);
  assert.deepEqual(r.model.statements[0].resources, []);
  assert.deepEqual(r.model.statements[0].notResources, []);
});

// ---------------------------------------------------------------------------
// NotAction / NotResource semantics land in the right fields.
// ---------------------------------------------------------------------------

test('NotAction populates notActions and leaves actions empty', () => {
  const r = modelFromText('{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}');
  assert.equal(r.ok, true);
  assert.deepEqual(r.model.statements[0].actions, []);
  assert.deepEqual(r.model.statements[0].notActions, ['iam:*']);
});

test('NotResource populates notResources and leaves resources empty', () => {
  const r = modelFromText('{"Statement":[{"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::keep"]}]}');
  assert.equal(r.ok, true);
  assert.deepEqual(r.model.statements[0].resources, []);
  assert.deepEqual(r.model.statements[0].notResources, ['arn:aws:s3:::keep']);
});

// ---------------------------------------------------------------------------
// Optional fields: Sid, Version, Id, Condition, Principal.
// ---------------------------------------------------------------------------

test('absent Sid/Version/Id normalize to null', () => {
  const r = modelFromText('{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');
  assert.equal(r.ok, true);
  assert.equal(r.model.version, null);
  assert.equal(r.model.id, null);
  assert.equal(r.model.statements[0].sid, null);
  assert.equal(r.model.statements[0].condition, null);
  assert.equal(r.model.statements[0].principal, null);
});

test('Version and Id captured when present', () => {
  const r = modelFromText('{"Version":"2012-10-17","Id":"policy-42","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');
  assert.equal(r.ok, true);
  assert.equal(r.model.version, '2012-10-17');
  assert.equal(r.model.id, 'policy-42');
});

test('Condition object preserved intact', () => {
  const cond = { StringEquals: { 'aws:PrincipalOrgID': 'o-123' }, Bool: { 'aws:MultiFactorAuthPresent': 'true' } };
  const r = modelFromText(JSON.stringify({ Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*', Condition: cond }] }));
  assert.equal(r.ok, true);
  assert.deepEqual(r.model.statements[0].condition, cond);
});

test('Principal "*" normalizes to anyPrincipal', () => {
  const r = modelFromText('{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Resource":"*"}]}');
  assert.equal(r.ok, true);
  assert.deepEqual(r.model.statements[0].principal, { anyPrincipal: true, byType: {} });
});

test('Principal object normalizes each type to string arrays', () => {
  const r = modelFromText(
    JSON.stringify({
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::111122223333:root', Service: ['lambda.amazonaws.com', 'ec2.amazonaws.com'] },
          Action: 'sts:AssumeRole',
          Resource: '*',
        },
      ],
    }),
  );
  assert.equal(r.ok, true);
  assert.deepEqual(r.model.statements[0].principal, {
    anyPrincipal: false,
    byType: {
      AWS: ['arn:aws:iam::111122223333:root'],
      Service: ['lambda.amazonaws.com', 'ec2.amazonaws.com'],
    },
  });
});

// ---------------------------------------------------------------------------
// Schema errors (strict), never thrown.
// ---------------------------------------------------------------------------

function expectError(text, code) {
  let r;
  assert.doesNotThrow(() => {
    r = modelFromText(text);
  });
  assert.equal(r.ok, false, `expected failure for code ${code}`);
  assert.equal(r.model, null);
  assert.ok(r.errors.some((e) => e.code === code), `expected code ${code}, got ${r.errors.map((e) => e.code).join(',')}`);
}

test('missing Statement -> NO_STATEMENT', () => {
  expectError('{"Version":"2012-10-17"}', 'NO_STATEMENT');
});

test('invalid Effect -> INVALID_EFFECT', () => {
  expectError('{"Statement":[{"Effect":"allow","Action":"s3:*","Resource":"*"}]}', 'INVALID_EFFECT');
  expectError('{"Statement":[{"Action":"s3:*","Resource":"*"}]}', 'INVALID_EFFECT');
});

test('both Action and NotAction -> ACTION_AND_NOTACTION', () => {
  expectError('{"Statement":[{"Effect":"Allow","Action":"s3:*","NotAction":"iam:*","Resource":"*"}]}', 'ACTION_AND_NOTACTION');
});

test('neither Action nor NotAction -> MISSING_ACTION', () => {
  expectError('{"Statement":[{"Effect":"Allow","Resource":"*"}]}', 'MISSING_ACTION');
});

test('both Resource and NotResource -> RESOURCE_AND_NOTRESOURCE', () => {
  expectError('{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","NotResource":"arn:x"}]}', 'RESOURCE_AND_NOTRESOURCE');
});

test('non-string Action element -> INVALID_ELEMENT_TYPE', () => {
  expectError('{"Statement":[{"Effect":"Allow","Action":["s3:*",42],"Resource":"*"}]}', 'INVALID_ELEMENT_TYPE');
});

test('object Action -> INVALID_FIELD_TYPE', () => {
  expectError('{"Statement":[{"Effect":"Allow","Action":{"nope":1},"Resource":"*"}]}', 'INVALID_FIELD_TYPE');
});

test('non-object statement -> INVALID_STATEMENT', () => {
  expectError('{"Statement":["not-a-statement"]}', 'INVALID_STATEMENT');
});

test('non-object Condition -> INVALID_CONDITION', () => {
  expectError('{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":"nope"}]}', 'INVALID_CONDITION');
});

test('invalid Principal scalar -> INVALID_PRINCIPAL', () => {
  expectError('{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Principal":42}]}', 'INVALID_PRINCIPAL');
});

// ---------------------------------------------------------------------------
// Hostile input never throws and never pollutes the prototype.
// ---------------------------------------------------------------------------

test('XSS payloads in Sid/Resource survive as inert strings', () => {
  const r = modelFromText(
    JSON.stringify({
      Statement: [
        {
          Sid: '<img src=x onerror=alert(1)>',
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: ['arn:aws:s3:::<script>alert(1)</script>/*'],
        },
      ],
    }),
  );
  assert.equal(r.ok, true);
  assert.equal(r.model.statements[0].sid, '<img src=x onerror=alert(1)>');
  assert.equal(r.model.statements[0].resources[0], 'arn:aws:s3:::<script>alert(1)</script>/*');
});

test('__proto__ in Condition is rejected without polluting Object.prototype', () => {
  // Fed straight to buildModel to bypass validate() and prove model.js guards
  // dangerous keys on its own (defense in depth).
  const raw = Object.create(null);
  raw.Statement = [Object.create(null)];
  raw.Statement[0].Effect = 'Allow';
  raw.Statement[0].Action = 's3:*';
  raw.Statement[0].Resource = '*';
  const cond = Object.create(null);
  const inner = Object.create(null);
  inner.polluted = true;
  cond.__proto__ = inner; // own null-proto key named "__proto__"
  raw.Statement[0].Condition = cond;

  const before = Object.prototype.polluted;
  let r;
  assert.doesNotThrow(() => {
    r = buildModel(raw);
  });
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.code === 'DANGEROUS_KEY'));
  assert.equal(Object.prototype.polluted, before);
  assert.equal({}.polluted, undefined);
});

// ---------------------------------------------------------------------------
// Frozen + deterministic.
// ---------------------------------------------------------------------------

test('model is deeply frozen', () => {
  const r = modelFromText('{"Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}');
  assert.equal(r.ok, true);
  assert.ok(Object.isFrozen(r.model));
  assert.ok(Object.isFrozen(r.model.statements));
  assert.ok(Object.isFrozen(r.model.statements[0]));
  assert.ok(Object.isFrozen(r.model.statements[0].actions));
  assert.ok(Object.isFrozen(r.model.statements[0].condition));
  assert.ok(Object.isFrozen(r.model.statements[0].condition.Bool));
  assert.throws(() => {
    'use strict';
    r.model.statements[0].actions.push('x');
  });
});

test('buildModel is deterministic (same input -> same model)', () => {
  const text = '{"Version":"2012-10-17","Statement":[{"Sid":"s","Effect":"Allow","Action":["s3:*","iam:*"],"Resource":["*"],"Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}]}';
  const a = modelFromText(text);
  const b = modelFromText(text);
  assert.deepEqual(plain(a.model), plain(b.model));
  assert.deepEqual(a.errors, b.errors);
});

// ---------------------------------------------------------------------------
// parse() unit behavior (container-level).
// ---------------------------------------------------------------------------

test('parse extracts version/id and array statements', () => {
  const raw = { Version: '2012-10-17', Id: 'x', Statement: [{ Effect: 'Allow' }] };
  const r = parse(raw);
  assert.equal(r.ok, true);
  assert.equal(r.version, '2012-10-17');
  assert.equal(r.id, 'x');
  assert.equal(r.statements.length, 1);
});

test('parse rejects non-object top level', () => {
  const r = parse([1, 2, 3]);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.code === 'NOT_AN_OBJECT'));
});

test('validate -> buildModel pipeline agrees with modelFromText', () => {
  const text = '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}';
  const v = validate(text);
  assert.equal(v.ok, true);
  const viaRaw = buildModel(v.raw);
  const viaText = modelFromText(text);
  assert.deepEqual(plain(viaRaw.model), plain(viaText.model));
});
