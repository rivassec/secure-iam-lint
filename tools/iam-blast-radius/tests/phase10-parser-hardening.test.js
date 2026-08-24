// IAM-1007 (Phase 10, P2/P3): parser hardening + rendering/export safety +
// limits. Drives the REAL pipeline (validate() / analyze() / report.js) so the
// suite-3 Campaign-A + Campaign-F contract is a gate on every `node --test` run.
//
//   Campaign A - strict parser and import equivalence
//     55/56 duplicate Action key (dangerous value first / last) -> BLOCKED
//     57    escaped key (Action) decodes to Action -> BLOCKED
//     58    duplicate nested condition key -> BLOCKED at the exact path
//     60    duplicate Sids -> flagged (DUPLICATE_SID), IDs stay distinct
//     61    JSONC comments / trailing commas -> INVALID_JSON (never silently fixed)
//     62    UTF-8 BOM -> stripped (exactly one leading U+FEFF), embedded U+FEFF kept
//     63    paste / import / harness parity -> identical status/code/findings;
//           filename never affects the result
//   Campaign F - state isolation, rendering safety, boundary performance
//     98    dangerous-to-safe re-analysis leaves no stale state (determinism)
//     99    rendering + export injection witnesses render inert / safe / exact
//     100   exact limits, early-abort ordering, determinism, no partial success

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate, LIMITS } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import { toJSON, toMarkdown, analysisStatus } from '../../../content/tools/iam-blast-radius/engine/report.js';

const here = dirname(fileURLToPath(import.meta.url));
const codes = (r) => (r.errors || []).map((e) => e.code);
const ids = (r) => r.findings.map((f) => f.id);

// --- Campaign A: duplicate-key regression (tests 55-58, 61) ------------------

test('Test 55: duplicate Action (dangerous value first) -> BLOCKED DUPLICATE_JSON_KEY, no findings', () => {
  const text =
    '{"Version":"2012-10-17","Statement":[{"Sid":"DangerousFirst","Effect":"Allow",' +
    '"Action":"iam:*","Action":"s3:GetObject","Resource":"*"}]}';
  const v = validate(text);
  assert.equal(v.ok, false);
  const dup = v.errors.find((e) => e.code === 'DUPLICATE_JSON_KEY');
  assert.ok(dup, 'DUPLICATE_JSON_KEY expected');
  assert.match(dup.path, /Statement\[0\]\.Action/, 'names the duplicated Action path');
  const r = analyze(text);
  assert.equal(r.ok, false, 'analyze fails closed');
  assert.equal(r.findings.length, 0, 'no IAM/S3 finding from a last-key-wins parse');
});

test('Test 56: duplicate Action (dangerous value last) -> same BLOCKED result, order-independent', () => {
  const text =
    '{"Version":"2012-10-17","Statement":[{"Sid":"DangerousLast","Effect":"Allow",' +
    '"Action":"s3:GetObject","Action":"iam:*","Resource":"*"}]}';
  const v = validate(text);
  assert.equal(v.ok, false, 'duplicate rejection is a syntax invariant, not risk-dependent');
  assert.ok(codes(v).includes('DUPLICATE_JSON_KEY'));
  assert.equal(analyze(text).findings.length, 0);
});

test('Test 57: escaped key \\u0041ction decodes to Action -> BLOCKED (post-escape comparison)', () => {
  const text =
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",' +
    '"Action":"s3:GetObject","\\u0041ction":"iam:*","Resource":"*"}]}';
  const v = validate(text);
  assert.equal(v.ok, false, 'a JSON-escape-decoded key collision must be caught');
  assert.ok(codes(v).includes('DUPLICATE_JSON_KEY'));
});

test('Test 58: duplicate nested condition key -> BLOCKED at the exact condition path', () => {
  const text =
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",' +
    '"Resource":"arn:aws:s3:::reports/*","Condition":{"StringEquals":' +
    '{"aws:PrincipalOrgID":"o-approved","aws:PrincipalOrgID":"o-attacker"}}}]}';
  const v = validate(text);
  assert.equal(v.ok, false);
  const dup = v.errors.find((e) => e.code === 'DUPLICATE_JSON_KEY');
  assert.ok(dup, 'recursive duplicate detection reaches condition depth');
  assert.match(dup.path, /Statement\[0\]\.Condition\.StringEquals\.aws:PrincipalOrgID/);
});

test('Test 61: JSONC comments / trailing commas remain invalid JSON (never silently fixed)', () => {
  const text =
    '{\n  // JSONC, not JSON.\n  "Version":"2012-10-17",\n  "Statement":[{"Effect":"Allow",' +
    '"Action":"s3:GetObject","Resource":"*",}]\n}';
  const v = validate(text);
  assert.equal(v.ok, false);
  assert.ok(codes(v).includes('INVALID_JSON'), 'comments/trailing commas are rejected, not stripped');
  assert.equal(analyze(text).findings.length, 0);
});

// --- Test 60: duplicate Sids -------------------------------------------------

test('Test 60: non-unique Sids are flagged (DUPLICATE_SID); statement/finding IDs stay distinct', () => {
  // Both statements carry the SAME Sid AND each fires a distinct finding, so the
  // test can prove one statement's evidence never overwrites the other's.
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'RepeatedSid', Effect: 'Allow', Action: 'iam:PutUserPolicy', Resource: 'arn:aws:iam::123456789012:user/self' },
      { Sid: 'RepeatedSid', Effect: 'Allow', Action: 'iam:CreateAccessKey', Resource: '*' },
    ],
  };
  const r = analyze(JSON.stringify(policy), { family: 'identity' });
  assert.equal(r.ok, true, 'colliding Sids are legal JSON (distinct array members), so analysis proceeds');

  // Flagged as a stable, machine-readable coverage code + structured entry.
  const s = r.coverage.summary;
  assert.ok(s.codes.includes('DUPLICATE_SID'), 'DUPLICATE_SID coverage code present');
  assert.equal(s.duplicateSids.length, 1, 'one duplicated Sid group');
  assert.equal(s.duplicateSids[0].sid, 'RepeatedSid');
  assert.deepEqual([...s.duplicateSids[0].statementIndexes], [0, 1], 'both colliding indexes recorded');

  // Statement indexes remain distinct even though the Sids collide, so no
  // finding/DOM/export record overwrites another (evidence-identity invariant):
  // both statements' findings are present, each anchored on its own index.
  const stmtIndexes = new Set(r.findings.map((f) => f.statementIndex));
  assert.ok(stmtIndexes.has(0) && stmtIndexes.has(1), 'findings keyed on distinct indexes despite Sid collision');

  // Graph edges never collapse two statements' evidence onto one id.
  const edgeIds = r.graph.edges.map((e) => e.id);
  assert.equal(new Set(edgeIds).size, edgeIds.length, 'graph edge ids are unique across colliding Sids');

  // The flag survives into the JSON export (test 71: family + status + coverage travel).
  const parsed = JSON.parse(toJSON(r));
  assert.ok(parsed.warnings.includes('DUPLICATE_SID'), 'export warnings carry the flag');
  assert.equal(parsed.coverage.summary.duplicateSids[0].sid, 'RepeatedSid');
});

test('Test 60 control: unique (and absent) Sids raise no DUPLICATE_SID flag', () => {
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'One', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::one/*' },
      { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::two/*' },
      { Sid: 'Two', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::three/*' },
    ],
  };
  const r = analyze(JSON.stringify(policy), { family: 'identity' });
  assert.ok(!r.coverage.summary.codes.includes('DUPLICATE_SID'), 'distinct/absent Sids are not a collision');
  assert.equal(r.coverage.summary.duplicateSids.length, 0);
});

// --- Test 62: UTF-8 BOM ------------------------------------------------------

const BOM = '﻿';

test('Test 62: a single leading UTF-8 BOM is stripped and the policy validates', () => {
  const body = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}]}';
  const withBom = BOM + body;
  // Without the strip, JSON.parse would reject the leading BOM as INVALID_JSON.
  assert.equal(validate(withBom).ok, true, 'documented behavior: strip exactly one leading BOM, then accept');
});

test('Test 62: only ONE leading BOM is stripped; a second leading BOM still fails as invalid JSON', () => {
  const body = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}';
  const v = validate(BOM + BOM + body);
  assert.equal(v.ok, false, 'a second leading BOM is not stripped');
  assert.ok(codes(v).includes('INVALID_JSON'));
});

test('Test 62: an embedded U+FEFF inside a string is PRESERVED, never stripped', () => {
  const sid = `Report${BOM}Access`; // BOM in the middle of a Sid value
  const policy = { Version: '2012-10-17', Statement: [{ Sid: sid, Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::reports/*' }] };
  const v = validate(JSON.stringify(policy));
  assert.equal(v.ok, true);
  assert.equal(v.raw.Statement[0].Sid, sid, 'embedded U+FEFF rides through as inert data');
  const r = analyze(JSON.stringify(policy), { family: 'identity' });
  assert.equal(r.model.statements[0].sid, sid, 'the model keeps the embedded BOM verbatim');
});

// --- Test 63: paste / import / harness parity --------------------------------

test('Test 63: repeated ingestion of identical bytes yields identical validate() + analyze()', () => {
  const text = JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' }, { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' }] });
  assert.deepEqual(validate(text), validate(text), 'validate() is deterministic');
  const a = analyze(text, { family: 'identity' });
  const b = analyze(text, { family: 'identity' });
  assert.equal(JSON.stringify(a), JSON.stringify(b), 'analyze() is deterministic across ingestion paths');
});

test('Test 63: a BOM-prefixed input (import path) converges on the same result as the pasted bytes', () => {
  const body = JSON.stringify({ Version: '2012-10-17', Statement: [{ Sid: 'Read', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::reports/*' }] });
  // The import path (FileReader.readAsText) strips a leading BOM during UTF-8
  // decoding; validate() strips it for the paste path. Both must agree.
  const pasted = analyze(body, { family: 'identity' });
  const imported = analyze(BOM + body, { family: 'identity' });
  assert.equal(JSON.stringify(pasted), JSON.stringify(imported), 'BOM and non-BOM ingestion produce identical analysis');
});

test('Test 63: the (imported) filename never influences the analysis', () => {
  const text = JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::reports/*' }] });
  // A filename-shaped option is not part of the engine contract; passing one must
  // change nothing (family is the only shape-selecting input).
  const plain = analyze(text, { family: 'identity' });
  const named = analyze(text, { family: 'identity', fileName: 'trust-policy.json' });
  assert.equal(JSON.stringify(plain), JSON.stringify(named), 'no filename-derived family or finding drift');
});

// --- Test 98: dangerous-to-safe state isolation ------------------------------

test('Test 98: re-analysis fully replaces prior state (no stale critical result resurrected)', () => {
  const dangerous = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}';
  const safe = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*"}]}';

  const first = analyze(dangerous, { family: 'identity' });
  assert.ok(first.findings.some((f) => f.severity === 'critical' || f.severity === 'high'), 'the dangerous policy fires high-severity findings');

  const second = analyze(safe, { family: 'identity' });
  assert.ok(!second.findings.some((f) => f.severity === 'critical'), 'the safe re-analysis carries no critical finding');
  assert.ok(!ids(second).includes('DIRECT-IAM-ADMIN'), 'no stale direct-IAM-admin finding survives');
  assert.ok(!ids(second).includes('WILDCARD-RESOURCE'), 'iam:ListRoles requires Resource:* -> no remediable wildcard');

  // The engine holds no shared mutable state: re-running the first input after the
  // second reproduces the first result byte-for-byte.
  const firstAgain = analyze(dangerous, { family: 'identity' });
  assert.equal(JSON.stringify(first), JSON.stringify(firstAgain), 'the first result is reproducible after an intervening analysis');
});

// --- Test 99: rendering + export injection (fixture-backed witness) ----------

test('Test 99: the injection-witness fixture renders inert in Markdown and exact in JSON', () => {
  const fx = JSON.parse(readFileSync(join(here, '..', 'fixtures', 'acceptance-3', 'test-99-rendering-export-injection.json'), 'utf8'));
  const r = analyze(JSON.stringify(fx.policy), fx.options || {});
  assert.ok(r.findings.length > 0, 'the witnesses reach the findings section');

  const md = toMarkdown(r);
  // No ACTIVE markdown link and no raw HTML tag can form from the payload.
  assert.ok(!/[^\\]\]\(/.test(md), 'no unescaped ]( link syntax survives');
  assert.ok(!md.includes(']('.concat('javascript:')), 'no javascript: link');
  assert.ok(!/(^|[^\\])</.test(md), 'no unescaped "<" survives (no raw HTML tag)');
  // No bare-URL / www. autolink for the attacker host.
  assert.ok(!md.includes('https://evil'), 'no contiguous https:// attacker autolink');
  assert.ok(!md.includes('www.evil'), 'no contiguous www. attacker autolink');
  // Present as inert readable text (broken, not dropped).
  assert.ok(md.includes('evil.example.com/leak'), 'the URL value is preserved as inert text');

  // JSON export preserves the exact hostile strings verbatim.
  const blob = toJSON(r);
  for (const s of fx.expect.preservesStrings) {
    assert.ok(blob.includes(s), `JSON keeps the exact string ${JSON.stringify(s)}`);
  }
});

// --- Test 100: exact limits, early-abort ordering, determinism ---------------

function padded(nBytes) {
  // A non-JSON blob larger than nBytes (byte cap must fire BEFORE JSON.parse).
  return 'x'.repeat(nBytes + 16);
}

test('Test 100: byte-size rejection precedes JSON parsing (TOO_LARGE, not INVALID_JSON)', () => {
  const v = validate(padded(LIMITS.MAX_BYTES));
  assert.equal(v.ok, false);
  assert.ok(codes(v).includes('TOO_LARGE'), 'the byte cap is the first gate');
  assert.ok(!codes(v).includes('INVALID_JSON'), 'JSON.parse never runs on an over-cap input');
});

test('Test 100: statement-count boundary - at limit accepted, limit+1 rejected before findings', () => {
  const mk = (n) => JSON.stringify({
    Version: '2012-10-17',
    Statement: Array.from({ length: n }, (_, i) => ({ Sid: `S${i}`, Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' })),
  });
  // limit - 1 and limit: accepted by the count gate.
  assert.equal(validate(mk(LIMITS.MAX_STATEMENTS - 1)).ok, true, 'limit-1 accepted');
  assert.equal(validate(mk(LIMITS.MAX_STATEMENTS)).ok, true, 'exactly-at-limit accepted (documented boundary)');
  // limit + 1: rejected with the count code, before any rule matching.
  const over = analyze(mk(LIMITS.MAX_STATEMENTS + 1), { family: 'identity' });
  assert.equal(over.ok, false, 'over-limit fails closed');
  assert.equal(over.findings.length, 0, 'no findings computed on an over-limit policy');
  assert.equal(over.graph.edges.length, 0, 'no graph layout on an over-limit policy');
  assert.ok((over.errors || []).some((e) => e.code === 'TOO_MANY_STATEMENTS'), 'specific complexity code');
});

test('Test 100: actions-per-policy boundary - at limit accepted, limit+1 rejected', () => {
  const mk = (n) => JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: Array.from({ length: n }, (_, i) => `svc:Action${i}`), Resource: '*' }],
  });
  assert.equal(validate(mk(LIMITS.MAX_ACTIONS)).ok, true, 'exactly-at-limit accepted');
  assert.ok(codes(validate(mk(LIMITS.MAX_ACTIONS + 1))).includes('TOO_MANY_ACTIONS'), 'limit+1 rejected');
});

test('Test 100: resources-per-policy boundary - at limit accepted, limit+1 rejected', () => {
  const mk = (n) => JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: Array.from({ length: n }, (_, i) => `arn:aws:s3:::b${i}/*`) }],
  });
  assert.equal(validate(mk(LIMITS.MAX_RESOURCES)).ok, true, 'exactly-at-limit accepted');
  assert.ok(codes(validate(mk(LIMITS.MAX_RESOURCES + 1))).includes('TOO_MANY_RESOURCES'), 'limit+1 rejected');
});

test('Test 100: nesting-depth boundary - the depth gate fires only at limit+1', () => {
  // Isolate the depth gate: build a nested-array chain of a chosen structural
  // depth. At MAX_DEPTH the depth gate does not fire (other schema errors may);
  // at MAX_DEPTH+1 TOO_DEEP fires before parse.
  const nest = (d) => '['.repeat(d) + ']'.repeat(d);
  assert.ok(!codes(validate(nest(LIMITS.MAX_DEPTH))).includes('TOO_DEEP'), 'exactly-at-limit passes the depth gate');
  assert.ok(codes(validate(nest(LIMITS.MAX_DEPTH + 1))).includes('TOO_DEEP'), 'limit+1 fails the depth gate before parse');
});

test('Test 100: an early parser error precedes any semantic finding, and status is never "complete"', () => {
  const r = analyze('{ this is not json ', { family: 'identity' });
  assert.equal(r.ok, false);
  assert.equal(r.findings.length, 0, 'no semantic findings after an early parse error');
  assert.equal(analysisStatus(r), 'error', 'a failed parse never reports a completed analysis');
});

test('Test 100: over-limit and under-limit results are both deterministic (no partial success)', () => {
  const under = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"},{"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"*"}]}';
  assert.equal(JSON.stringify(analyze(under, { family: 'identity' })), JSON.stringify(analyze(under, { family: 'identity' })), 'under-limit deterministic');
  const over = 'x'.repeat(LIMITS.MAX_BYTES + 1);
  assert.equal(JSON.stringify(analyze(over)), JSON.stringify(analyze(over)), 'over-limit deterministic');
});

test('Test 100: graph node cap bounds a high-fan-out policy (truncated, never a hang)', () => {
  // A tiny-input / large-fan-out policy: many distinct role resources on a
  // PassRole+exec compound. The graph must stay bounded (truncated flag), and the
  // findings table stays authoritative. Resolves well under the wall-clock budget.
  const roles = Array.from({ length: 400 }, (_, i) => `arn:aws:iam::123456789012:role/r${i}`);
  const policy = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: roles },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
    ],
  };
  const r = analyze(JSON.stringify(policy), { family: 'identity' });
  assert.equal(r.ok, true);
  assert.ok(r.graph.nodes.length <= r.graph.limits.maxNodes, 'graph stays within the node cap');
  assert.ok(r.findings.length > 0, 'the findings table remains authoritative under graph truncation');
});
