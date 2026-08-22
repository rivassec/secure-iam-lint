// Unit tests for IAM-007: analysis orchestration used by the UI shell.
// Runs on node's built-in runner: `node --test`.
//
// The UI's worker + synchronous fallback both delegate to analyze(); these
// tests exercise that pure pipeline with NO DOM/Worker present, covering the
// IAM-007 acceptance that is testable off-browser:
//   - every fixture (positive/negative/boundary/malformed/adversarial) is
//     handled with zero uncaught exceptions
//   - positive findingIds are produced; notFindingIds are absent
//   - deterministic (same input -> deep-equal output, twice)
//   - hostile SIDs/ARNs ride through the pipeline as inert DATA (verbatim
//     strings), so the createElement+textContent renderer receives inert text
//   - the presentation helpers (sortFindings / findingToRow) expose a stable,
//     string-only row contract for the accessible table
//
// Browser-level acceptance (csp_audit, grep gate, real DOM inertness, a11y)
// is covered by the Playwright spec + CI workflow, not this suite.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  analyze,
  sortFindings,
  findingToRow,
  FINDING_COLUMNS,
  SEVERITY_ORDER,
  CATALOG_VERSION,
} from '../../../content/tools/iam-blast-radius/engine/analyze.js';

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
    .sort()
    .map((f) => ({
      file: `${category}/${f}`,
      data: JSON.parse(readFileSync(join(dir, f), 'utf8')),
    }));
}

const ALL_CATEGORIES = readdirSync(fixturesDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const RESULT_KEYS = ['ok', 'errors', 'findings', 'model', 'graph', 'catalogVersion', 'counts'];

test('analyze() returns a frozen, well-shaped result for every fixture and never throws', () => {
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const text = fixtureText(data);
      let result;
      assert.doesNotThrow(() => { result = analyze(text); }, `${file} must not throw`);
      for (const k of RESULT_KEYS) {
        assert.ok(k in result, `${file}: result missing key ${k}`);
      }
      assert.equal(typeof result.ok, 'boolean', `${file}: ok is boolean`);
      assert.ok(Array.isArray(result.findings), `${file}: findings is array`);
      assert.ok(Array.isArray(result.errors), `${file}: errors is array`);
      assert.ok(Object.isFrozen(result), `${file}: result frozen`);
      assert.ok(Object.isFrozen(result.findings), `${file}: findings frozen`);
      assert.equal(result.catalogVersion, CATALOG_VERSION, `${file}: catalog version`);
      // Counts agree with the payload.
      assert.equal(result.counts.findings, result.findings.length, `${file}: findings count`);
      assert.equal(result.counts.edges, result.graph.edges.length, `${file}: edges count`);
      assert.equal(result.counts.nodes, result.graph.nodes.length, `${file}: nodes count`);
      // Well-formed inputs must not report a failure and vice-versa.
      const expectValid = data.expect && data.expect.valid;
      if (expectValid === true) assert.equal(result.ok, true, `${file}: expected valid`);
      if (expectValid === false) assert.equal(result.ok, false, `${file}: expected invalid`);
    }
  }
});

test('analyze() produces expected findingIds and omits notFindingIds', () => {
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const expect = data.expect || {};
      if (!Array.isArray(expect.findingIds) && !Array.isArray(expect.notFindingIds)) continue;
      const result = analyze(fixtureText(data));
      const ids = new Set(result.findings.map((f) => f.id));
      for (const want of expect.findingIds || []) {
        assert.ok(ids.has(want), `${file}: expected finding ${want}; got [${[...ids].join(', ')}]`);
      }
      for (const notWant of expect.notFindingIds || []) {
        assert.ok(!ids.has(notWant), `${file}: finding ${notWant} must NOT be present`);
      }
    }
  }
});

test('analyze() is deterministic (same input -> deep-equal output, twice)', () => {
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const text = fixtureText(data);
      const a = analyze(text);
      const b = analyze(text);
      assert.deepEqual(a, b, `${file}: analyze() must be deterministic`);
    }
  }
});

test('every finding carries the canonical fields the table + export rely on', () => {
  const required = ['id', 'severity', 'title', 'statementSid', 'confidence', 'why', 'limit', 'remediation', 'ruleVersion'];
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const result = analyze(fixtureText(data));
      for (const f of result.findings) {
        for (const key of required) {
          assert.ok(key in f, `${file}: finding ${f.id} missing ${key}`);
        }
        assert.ok(Object.prototype.hasOwnProperty.call(SEVERITY_ORDER, f.severity),
          `${file}: finding ${f.id} has known severity`);
      }
    }
  }
});

test('hostile SIDs/ARNs pass through as inert verbatim data', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'xss-in-sid-and-arn.json'), 'utf8'));
  const result = analyze(fixtureText(fx));
  assert.equal(result.ok, true, 'adversarial fixture is valid input');

  // The hostile Sid/ARNs must survive verbatim somewhere in the model (as data,
  // never parsed/transformed). We assert the exact payload strings are present
  // as string values, which is what the renderer will place via textContent.
  const stmt = result.model.statements[0];
  assert.equal(stmt.sid, '<img src=x onerror=alert(1)>', 'Sid preserved verbatim as data');
  assert.ok(
    stmt.resources.includes('arn:aws:s3:::<script>alert(document.domain)</script>/*'),
    'script-bearing ARN preserved verbatim as data',
  );

  // No finding turned the payload into anything other than a plain string.
  for (const f of result.findings) {
    for (const cell of findingToRow(f)) {
      assert.equal(typeof cell.text, 'string', 'every rendered cell is a plain string');
    }
  }
});

test('malformed input fails gracefully with structured errors and empty output', () => {
  for (const { file, data } of loadFixtures('malformed')) {
    const result = analyze(fixtureText(data));
    assert.equal(result.ok, false, `${file}: malformed input must not be ok`);
    assert.ok(result.errors.length > 0, `${file}: malformed input reports errors`);
    assert.equal(result.findings.length, 0, `${file}: no findings on failure`);
    assert.equal(result.graph.edges.length, 0, `${file}: no graph edges on failure`);
    assert.equal(result.model, null, `${file}: no model on failure`);
  }
});

test('analyze() never throws on non-string / empty / junk input', () => {
  const junk = [undefined, null, 42, {}, [], '', '   ', 'not json', '{"Statement":', '[]'];
  for (const input of junk) {
    let result;
    assert.doesNotThrow(() => { result = analyze(input); }, `input ${String(input)} must not throw`);
    assert.equal(result.ok, false, `input ${String(input)} should be rejected`);
    assert.ok(result.errors.length > 0, `input ${String(input)} reports errors`);
  }
});

// --- presentation helpers ----------------------------------------------------

test('findingToRow returns one string cell per column, in column order', () => {
  const finding = {
    id: 'WILDCARD-ACTION',
    severity: 'critical',
    title: 'Wildcard action',
    statementSid: '(index 0)',
    actions: ['*'],
    resources: ['*'],
    confidence: 'high',
    why: 'why text',
    limit: 'limit text',
    remediation: 'fix it',
  };
  const row = findingToRow(finding);
  assert.equal(row.length, FINDING_COLUMNS.length, 'one cell per column');
  for (let i = 0; i < row.length; i++) {
    assert.equal(row[i].key, FINDING_COLUMNS[i].key, `cell ${i} key matches column`);
    assert.equal(typeof row[i].text, 'string', `cell ${i} text is a string`);
  }
  assert.equal(row[0].text, 'critical');
  assert.equal(row[3].text, '*'); // actions joined
});

test('sortFindings orders by severity, then statement index, deterministically', () => {
  const input = [
    { id: 'B', severity: 'low', statementIndex: 0 },
    { id: 'A', severity: 'critical', statementIndex: 5 },
    { id: 'C', severity: 'critical', statementIndex: 1 },
    { id: 'D', severity: 'high', statementIndex: 0 },
  ];
  const out = sortFindings(input);
  assert.deepEqual(out.map((f) => f.id), ['C', 'A', 'D', 'B']);
  // Pure: input not mutated.
  assert.equal(input[0].id, 'B');
  // Deterministic.
  assert.deepEqual(sortFindings(input), out);
});
