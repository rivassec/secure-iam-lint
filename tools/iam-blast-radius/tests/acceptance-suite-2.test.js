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
import { toMarkdown, toJSON } from '../../../content/tools/iam-blast-radius/engine/report.js';

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

// ---------------------------------------------------------------------------
// IAM-1206 (suite-2 test 29): the Deny + NotPrincipal hazard. A resource (or
// trust) policy that uses NotPrincipal with a Deny effect is a documented AWS
// trap - a NotPrincipal + Deny ALWAYS denies any principal that has a
// permissions boundary attached, regardless of the NotPrincipal list - so it
// cannot be modeled as an ordinary exclusion. The engine keeps FAILING CLOSED
// (UNSUPPORTED_NOTPRINCIPAL, empty graph, zero findings) but must SURFACE the
// specific hazard (the permissions-boundary caveat + the ArnNotEquals /
// aws:PrincipalArn recommendation) as a high-confidence warning, in the DOM
// coverage notice AND in every export. This drives that fixture explicitly.
// ---------------------------------------------------------------------------

function hazardFixture() {
  const all = loadDir(suite2Dir);
  const hit = all.find(({ data }) => data.expect && data.expect.notPrincipalHazard);
  assert.ok(hit, 'a suite-2 fixture must carry a notPrincipalHazard expectation (test 29)');
  return hit;
}

test('suite-2 test 29: Deny + NotPrincipal fails closed AND surfaces the specific hazard', () => {
  const { data } = hazardFixture();
  const exp = data.expect;
  const hz = exp.notPrincipalHazard;
  const text = fixtureText(data);

  const res = analyze(text, data.options || {});
  // Fail-closed coverage state: a well-formed conclusion, not a crash.
  assert.equal(res.ok, true, 'ok:true (blocking coverage, not an error)');
  assert.equal(res.coverage.blocked, true, 'blocked (fail closed)');
  assert.equal(res.family, exp.detectedFamily, 'detected family');
  // Never an ordinary deny graph, never a finding row.
  assert.equal(res.findings.length, 0, 'zero findings');
  assert.equal(res.graph.nodes.length, 0, 'empty graph nodes');
  assert.equal(res.graph.edges.length, 0, 'empty graph edges');

  // The blocking code is the NotPrincipal code at the exact JSON path, now
  // carrying the high-confidence hazard marker + the specific hazard message.
  const np = res.coverage.blockingCodes.find((b) => b.code === 'UNSUPPORTED_NOTPRINCIPAL');
  assert.ok(np, 'UNSUPPORTED_NOTPRINCIPAL present');
  assert.equal(np.path, hz.path, 'exact JSON path');
  assert.equal(np.hazard, true, 'flagged as a high-confidence hazard');
  for (const needle of hz.messageIncludes) {
    assert.ok(String(np.message).includes(needle), `blocking message must mention "${needle}"`);
  }

  // The enriched coverage summary carries the hazard on the unsupported element.
  const el = res.coverage.summary.unsupportedElements.find((e) => e.element === 'NotPrincipal');
  assert.ok(el, 'NotPrincipal unsupported element present');
  assert.equal(el.hazard, true, 'unsupported element flagged hazard');
  assert.ok(el.hazardMessage && el.hazardMessage.includes('ArnNotEquals'), 'element carries the hazard message');
  assert.equal(res.coverage.summary.incomplete, true, 'coverage incomplete');
  assert.ok(res.coverage.summary.codes.includes('UNSUPPORTED_NOTPRINCIPAL'), 'code in summary');

  // Every export surfaces the hazard (Markdown + JSON), not just the DOM.
  const md = toMarkdown(res);
  for (const needle of hz.messageIncludes) {
    assert.ok(md.includes(needle), `Markdown export must surface "${needle}"`);
  }
  const json = JSON.parse(toJSON(res));
  const jnp = json.coverage.blockingCodes.find((b) => b.code === 'UNSUPPORTED_NOTPRINCIPAL');
  assert.ok(jnp && jnp.hazard === true, 'JSON export carries the hazard code');
  assert.ok(String(jnp.message).includes('aws:PrincipalArn'), 'JSON export carries the recommendation');
});

test('suite-2 test 29: hazard surfaces under an explicit resource family selection too', () => {
  const { data } = hazardFixture();
  const text = fixtureText(data);
  // Explicit resource selection must NOT downgrade the hazard to a plain
  // unsupported-shape block: the NotPrincipal block stays authoritative and keeps
  // the hazard marker + message (family.js leaves the recognized-but-unmodeled
  // element block in place even when resource is explicitly selected).
  const res = analyze(text, {
    family: 'resource',
    resourceContext: { type: 's3-bucket', arn: 'arn:aws:s3:::audit-archive' },
  });
  assert.equal(res.coverage.blocked, true, 'still fails closed under explicit resource');
  assert.equal(res.findings.length, 0, 'still zero findings');
  const np = res.coverage.blockingCodes.find((b) => b.code === 'UNSUPPORTED_NOTPRINCIPAL');
  assert.ok(np && np.hazard === true, 'hazard marker preserved under explicit resource selection');
  assert.ok(String(np.message).includes('permissions boundary'), 'hazard message preserved');
});

test('suite-2 test 29: an Allow + NotPrincipal (invalid) stays the generic unmodeled block, no hazard', () => {
  // AWS only supports NotPrincipal with Deny. An Allow + NotPrincipal is not the
  // documented permissions-boundary trap, so it must NOT be flagged as the
  // hazard - it stays the generic recognized-but-unmodeled NotPrincipal block.
  const res = analyze(JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', NotPrincipal: { AWS: 'arn:aws:iam::123456789012:root' }, Action: 'sts:AssumeRole' },
    ],
  }));
  assert.equal(res.coverage.blocked, true, 'still fails closed');
  const np = res.coverage.blockingCodes.find((b) => b.code === 'UNSUPPORTED_NOTPRINCIPAL');
  assert.ok(np, 'UNSUPPORTED_NOTPRINCIPAL present');
  assert.ok(np.hazard !== true, 'Allow + NotPrincipal is NOT flagged as the Deny hazard');
});
