// IAM-1207 (Phase 12): wire the RESOURCE NEGATIVE CORPUS into the blocking suite.
//
// fixtures/negative-resource/ holds the FROZEN "does-not-fire / low" contracts for
// resource-based policies, analogous to the identity negative corpus
// (fixtures/negative/, tests/negative.test.js) and the trust negative corpus
// (fixtures/negative-trust/, tests/negative-trust.test.js). Each fixture is a
// resource policy plus the explicit attached-resource context (the "resource-policy
// context is explicit" invariant) and a `negativeExpect` contract asserting what
// the resource evaluator MUST and MUST NOT conclude, with a `rationale` citing the
// real AWS behavior (grounded in docs/resource-policy-semantics.md) that makes the
// expectation correct. This is the credibility artifact proving the resource
// analyzer knows when NOT to fire - the highest-value place to prevent an overclaim
// (threat-model T8, resource-policy-semantics.md sec 0/10.2: a resource policy is
// POTENTIAL blast radius from the RESOURCE's perspective, never effective access).
//
// The fixtures are FROZEN TRUTH: this test never bends an expectation to match the
// engine. If the engine fails a semantically-correct contract, that is a real
// defect to fix in engine/resource.js, not here.
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
import { RESOURCE_IDS } from '../../../content/tools/iam-blast-radius/engine/resource.js';

const here = dirname(fileURLToPath(import.meta.url));
const negResourceDir = join(here, '..', 'fixtures', 'negative-resource');

// pathExploitability ordering, most-exploitable first (mirrors SEVERITY_ORDER).
const EXPLOITABILITY_ORDER = Object.freeze({ high: 0, medium: 1, low: 2 });

// Identity-family finding ids that must NEVER appear on a resource policy (a
// resource policy is routed to the resource evaluator, never the identity rules;
// its Resource is contextual to the attached resource, not an identity blast surface).
const IDENTITY_STYLE_IDS = Object.freeze([
  'WILDCARD-RESOURCE',
  'WILDCARD-ACTION',
  'ASSUME-ROLE-EXPANSION',
  'PASSROLE-EC2',
  'PASSROLE-LAMBDA',
  'DATA-EXFIL',
  'DATA-READ',
  'DIRECT-IAM-ADMIN',
  'KMS-DECRYPT',
]);

function loadFixtures() {
  if (!existsSync(negResourceDir)) return [];
  return readdirSync(negResourceDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `negative-resource/${f}`, data: JSON.parse(readFileSync(join(negResourceDir, f), 'utf8')) }));
}

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

const FIXTURES = loadFixtures();

test('resource negative corpus is present and well-formed (each fixture has policy + explicit context + negativeExpect + rationale)', () => {
  assert.ok(FIXTURES.length >= 5, `expected >=5 resource negative fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy object`);
    assert.equal(data.family, 'resource', `${file}: is a resource fixture`);
    // The resource-policy context is EXPLICIT and required (invariant sec 10.1).
    assert.ok(data.options && typeof data.options === 'object', `${file}: has analyze options`);
    assert.equal(data.options.family, 'resource', `${file}: explicitly selects the resource family`);
    assert.ok(
      data.options.resourceContext && typeof data.options.resourceContext.arn === 'string',
      `${file}: carries the explicit attached-resource context (type + ARN)`,
    );
    assert.ok(data.negativeExpect && typeof data.negativeExpect === 'object', `${file}: has a negativeExpect`);
    assert.equal(typeof data.rationale, 'string', `${file}: has a rationale string`);
    assert.ok(data.rationale.length > 0, `${file}: rationale is non-empty`);
  }
});

test('analyze() satisfies every frozen resource-negative contract (present/absent/severity/exploitability)', () => {
  for (const { file, data } of FIXTURES) {
    const expect = data.negativeExpect || {};
    const result = analyze(fixtureText(data), data.options);

    // Valid resource policies with an explicit context must analyze cleanly (not
    // fail closed) - a false block would hide a would-be finding and vacuously
    // satisfy a mustNotFind.
    assert.equal(result.ok, true, `${file}: expected a clean analysis; got errors ${JSON.stringify(result.errors)}`);
    assert.equal(result.family, 'resource', `${file}: expected the resource family`);
    assert.ok(result.coverage && result.coverage.blocked === false, `${file}: resource analysis must not be blocked`);

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

test('no resource-negative fixture emits an identity-style finding (resource policies are never run through identity rules)', () => {
  for (const { file, data } of FIXTURES) {
    const result = analyze(fixtureText(data), data.options);
    const idSet = new Set(result.findings.map((f) => f.id));
    for (const forbidden of IDENTITY_STYLE_IDS) {
      assert.ok(!idSet.has(forbidden), `${file}: identity-style finding ${forbidden} must never fire on a resource policy`);
    }
    // Every finding a resource policy emits is a resource-family id.
    for (const f of result.findings) {
      assert.ok(RESOURCE_IDS.includes(f.id), `${file}: ${f.id} is not a resource-family finding id`);
    }
  }
});

test('every resource finding carries the potential-blast-radius-not-effective caveat (T8 invariant)', () => {
  for (const { file, data } of FIXTURES) {
    const result = analyze(fixtureText(data), data.options);
    for (const f of result.findings) {
      assert.equal(typeof f.limit, 'string', `${file}: ${f.id} has a limit string`);
      assert.match(
        f.limit,
        /not effective access/i,
        `${file}: ${f.id} limit must state this is potential blast radius, not effective access`,
      );
    }
  }
});

test('source-bound negative control: a correctly source-bound service principal never reports a MISSING source binding', () => {
  // Guards the confused-deputy rule that a present aws:SourceArn + aws:SourceAccount
  // binding is a NEGATIVE control, not an exposure - the mirror of the trust family's
  // "ExternalId present is not missing" guard.
  for (const { file, data } of FIXTURES) {
    const result = analyze(fixtureText(data), data.options);
    for (const f of result.findings) {
      if (f.id !== 'RESOURCE-CONFUSED-DEPUTY') continue;
      if (f.resource && f.resource.sourceBinding && f.resource.sourceBinding.state === 'source-bound') {
        const text = `${f.why || ''} ${f.remediation || ''}`;
        assert.ok(!/NO source binding/i.test(text), `${file}: a source-bound control must not warn about a missing source binding`);
      }
    }
  }
});

test('analyze() is deterministic over the resource negative corpus (same input -> deep-equal twice)', () => {
  for (const { file, data } of FIXTURES) {
    const text = fixtureText(data);
    assert.deepEqual(analyze(text, data.options), analyze(text, data.options), `${file}: analyze() must be deterministic`);
  }
});
