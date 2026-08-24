// IAM-901 (Phase 9): suite-2 acceptance harness for the in-scope bug fixes.
//
// docs/acceptance-suite-2.md tests 25-54 are the advanced suite. This harness
// wires the suite-2 fixtures that Phase-9 stories land under
// fixtures/acceptance-2/ and drives each through the REAL engine (analyze() +
// validate()), never from the fixture's declared numbers alone.
//
// IAM-901 scope: test 44 (duplicate JSON key -> fail closed) plus its
// no-false-positive boundary control. Later Phase-9 stories (902/903) add their
// own suite-2 fixtures here; this file grows with them.
//
// It also asserts the cross-cutting guarantee for IAM-901: the new duplicate-key
// block must NEVER false-positive on the existing suite-1 acceptance fixtures or
// the identity/trust negative corpora (none may newly fail).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');
const suite2Dir = join(fixturesDir, 'acceptance-2');

function fixtureText(data) {
  return typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
}

function loadDir(dir) {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
}

// ---------------------------------------------------------------------------
// Per-fixture semantics.
// ---------------------------------------------------------------------------

for (const { file, data } of loadDir(suite2Dir)) {
  test(`suite-2 ${file}: engine matches expectation`, () => {
    const text = fixtureText(data);

    let vres;
    assert.doesNotThrow(() => { vres = validate(text); }, `validate() threw on ${file}`);
    let res;
    assert.doesNotThrow(() => { res = analyze(text, data.options || {}); }, `analyze() threw on ${file}`);

    const exp = data.expect || {};
    const errExp = data.errorExpect || {};

    if (typeof exp.valid === 'boolean') {
      assert.equal(vres.ok, exp.valid, `${file}: validate ok mismatch`);
      // analyze() blocks whenever validation fails.
      if (exp.valid === false) {
        assert.equal(res.ok, false, `${file}: analyze must fail closed`);
      } else {
        assert.equal(res.ok, true, `${file}: analyze must succeed`);
      }
    }

    if (exp.status === 'blocked') {
      assert.equal(res.ok, false, `${file}: blocked status requires ok:false`);
      // No findings, no risk score, no graph on a blocked policy.
      assert.equal(res.findings.length, 0, `${file}: blocked result must have zero findings`);
      assert.equal(res.graph.nodes.length, 0, `${file}: blocked result must have zero graph nodes`);
      assert.equal(res.graph.edges.length, 0, `${file}: blocked result must have zero graph edges`);
      assert.equal(res.counts.findings, 0, `${file}: blocked result finding count must be 0`);
    }

    const vcodes = vres.errors.map((e) => e.code);
    const acodes = res.errors.map((e) => e.code);

    for (const code of (errExp.errorCodes || [])) {
      assert.ok(vcodes.includes(code), `${file}: validate missing error code ${code} (got ${vcodes.join(',')})`);
      assert.ok(acodes.includes(code), `${file}: analyze missing error code ${code} (got ${acodes.join(',')})`);
    }

    for (const code of (exp.notErrorCodes || [])) {
      assert.ok(!vcodes.includes(code), `${file}: validate unexpectedly produced ${code}`);
      assert.ok(!acodes.includes(code), `${file}: analyze unexpectedly produced ${code}`);
    }

    // Duplicate-key specifics: the error must name the key and its location.
    if (errExp.duplicateKey || errExp.locationIncludes) {
      const dup = vres.errors.find((e) => e.code === 'DUPLICATE_JSON_KEY');
      assert.ok(dup, `${file}: expected a DUPLICATE_JSON_KEY error`);
      if (errExp.duplicateKey) {
        assert.ok(
          dup.message.includes(`"${errExp.duplicateKey}"`),
          `${file}: DUPLICATE_JSON_KEY message must name the key "${errExp.duplicateKey}" (got: ${dup.message})`,
        );
      }
      if (errExp.locationIncludes) {
        const located = String(dup.message).includes(errExp.locationIncludes) ||
          String(dup.path || '').includes(errExp.locationIncludes);
        assert.ok(located, `${file}: DUPLICATE_JSON_KEY must locate ${errExp.locationIncludes} (message: ${dup.message}, path: ${dup.path})`);
      }
    }

    for (const id of (exp.findingIds || [])) {
      assert.ok(res.findings.some((f) => f.id === id), `${file}: expected finding ${id}`);
    }
    for (const id of (exp.notFindingIds || [])) {
      const present = res.findings.some((f) => f.id === id ||
        (Array.isArray(f.subsumed) && f.subsumed.some((s) => s.id === id)));
      assert.ok(!present, `${file}: finding ${id} must NOT be present`);
    }

    // IAM-1006 (test 50): analysis-coverage contract. A fixture may assert the
    // coverage summary's incomplete flag and machine-readable codes so a
    // non-blocking coverage WARNING (e.g. an action/resource-type mismatch) is
    // verified, not just the finding set.
    if (exp.coverage) {
      const s = res.coverage && res.coverage.summary;
      assert.ok(s, `${file}: expected an enriched coverage summary`);
      if (typeof exp.coverage.incomplete === 'boolean') {
        assert.equal(s.incomplete, exp.coverage.incomplete, `${file}: coverage incomplete mismatch`);
      }
      for (const code of (exp.coverage.codesInclude || [])) {
        assert.ok(s.codes.includes(code), `${file}: coverage codes must include ${code} (got ${s.codes.join(',')})`);
      }
      for (const code of (exp.coverage.codesExclude || [])) {
        assert.ok(!s.codes.includes(code), `${file}: coverage codes must NOT include ${code}`);
      }
    }
  });
}

// ---------------------------------------------------------------------------
// No-false-positive guard: the duplicate-key block must not newly reject any
// existing suite-1 acceptance fixture or negative-corpus fixture (same key in
// different objects/statements is legal). If any of these produced
// DUPLICATE_JSON_KEY, an ordinary same-key-in-different-statements policy would
// break.
// ---------------------------------------------------------------------------

test('duplicate-key block never false-positives on the protected corpora', () => {
  const dirs = ['acceptance', 'negative', 'negative-trust'];
  const offenders = [];
  for (const d of dirs) {
    for (const { file, data } of loadDir(join(fixturesDir, d))) {
      // Only object-based fixtures (a stringified clean object can never carry a
      // duplicate key); skip anything with raw text designed to be malformed
      // unless it declares itself duplicate-key-relevant.
      const text = fixtureText(data);
      const vres = validate(text);
      if (vres.errors.some((e) => e.code === 'DUPLICATE_JSON_KEY')) {
        offenders.push(`${d}/${file}`);
      }
    }
  }
  assert.deepEqual(offenders, [], `duplicate-key false positives: ${offenders.join(', ')}`);
});
