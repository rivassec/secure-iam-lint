// IAM-302: wire the negative regression corpus into the blocking suite.
//
// fixtures/negative/ holds the FROZEN "does-not-fire truth" authored + validated
// in IAM-301: each fixture is a policy plus a `negativeExpect` contract asserting
// what the engine MUST and MUST NOT conclude, with a `rationale` citing the real
// AWS behavior that makes the expectation correct. These assert the engine knows
// when NOT to fire (or to lower severity/exploitability), which is where an
// analyzer most easily overstates risk (threat-model T8).
//
// This suite runs every negative fixture through the FULL analyze() pipeline and
// checks the authoritative findings table (analyze().findings) against its
// contract. The fixture expectations are FROZEN TRUTH - this test never bends
// them to match the engine; IAM-302 fixes the engine (rules.js / escalation.js /
// correlate.js) to match the corpus.
//
//   negativeExpect.mustFind[]              ids that MUST be present
//   negativeExpect.mustNotFind[]           ids that MUST be absent
//   negativeExpect.maxSeverity{id:sev}     a present finding's severity must be
//                                          no MORE severe than the cap
//   negativeExpect.maxPathExploitability{id:level}
//                                          a present finding's pathExploitability
//                                          must be no HIGHER than the cap
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze, SEVERITY_ORDER } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const negativeDir = join(here, '..', 'fixtures', 'negative');

// pathExploitability ordering, most-exploitable first (mirrors SEVERITY_ORDER).
const EXPLOITABILITY_ORDER = Object.freeze({ high: 0, medium: 1, low: 2 });

function loadNegativeFixtures() {
  if (!existsSync(negativeDir)) return [];
  return readdirSync(negativeDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `negative/${f}`, data: JSON.parse(readFileSync(join(negativeDir, f), 'utf8')) }));
}

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

const FIXTURES = loadNegativeFixtures();

test('negative corpus is present and well-formed (>=15 fixtures, each with policy + negativeExpect + rationale)', () => {
  assert.ok(FIXTURES.length >= 15, `expected >=15 negative fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy object`);
    assert.ok(data.negativeExpect && typeof data.negativeExpect === 'object', `${file}: has a negativeExpect`);
    assert.equal(typeof data.rationale, 'string', `${file}: has a rationale string`);
    assert.ok(data.rationale.length > 0, `${file}: rationale is non-empty`);
  }
});

test('analyze() satisfies every frozen negative-fixture contract (present/absent/severity/exploitability)', () => {
  for (const { file, data } of FIXTURES) {
    const expect = data.negativeExpect || {};
    const result = analyze(fixtureText(data));

    // Valid policies must analyze cleanly (never a false failure that would hide
    // a would-be finding and vacuously satisfy a mustNotFind).
    assert.equal(result.ok, true, `${file}: expected a clean analysis; got errors ${JSON.stringify(result.errors)}`);

    const findings = result.findings;
    const ids = findings.map((f) => f.id);
    const idSet = new Set(ids);

    for (const want of expect.mustFind || []) {
      assert.ok(idSet.has(want), `${file}: MUST find ${want}; got [${ids.join(', ')}]`);
    }
    for (const notWant of expect.mustNotFind || []) {
      assert.ok(!idSet.has(notWant), `${file}: MUST NOT find ${notWant}; got [${ids.join(', ')}]`);
    }

    // Severity must not be overstated: a present finding's severity is no MORE
    // severe (lower order index) than the fixture's cap.
    for (const [id, maxSev] of Object.entries(expect.maxSeverity || {})) {
      const cap = SEVERITY_ORDER[maxSev];
      assert.ok(cap !== undefined, `${file}: unknown maxSeverity level "${maxSev}"`);
      for (const f of findings.filter((x) => x.id === id)) {
        assert.ok(
          SEVERITY_ORDER[f.severity] >= cap,
          `${file}: ${id} severity "${f.severity}" overstates the cap "${maxSev}"`,
        );
      }
    }

    // Path-exploitability must not be overstated either.
    for (const [id, maxExp] of Object.entries(expect.maxPathExploitability || {})) {
      const cap = EXPLOITABILITY_ORDER[maxExp];
      assert.ok(cap !== undefined, `${file}: unknown maxPathExploitability level "${maxExp}"`);
      for (const f of findings.filter((x) => x.id === id)) {
        assert.ok(
          EXPLOITABILITY_ORDER[f.pathExploitability] >= cap,
          `${file}: ${id} pathExploitability "${f.pathExploitability}" overstates the cap "${maxExp}"`,
        );
      }
    }
  }
});

test('analyze() is deterministic over the negative corpus (same input -> deep-equal twice)', () => {
  for (const { file, data } of FIXTURES) {
    const text = fixtureText(data);
    assert.deepEqual(analyze(text), analyze(text), `${file}: analyze() must be deterministic`);
  }
});
