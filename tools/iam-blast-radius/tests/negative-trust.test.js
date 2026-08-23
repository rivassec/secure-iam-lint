// IAM-805: wire the trust NEGATIVE CORPUS into the blocking suite.
//
// fixtures/negative-trust/ holds the FROZEN "does-not-fire / low" contracts for
// role-trust policies, analogous to the Phase-3 identity negative corpus
// (fixtures/negative/, tests/negative.test.js). Each fixture is a role-trust
// policy plus a `negativeExpect` contract asserting what the trust analyzer MUST
// and MUST NOT conclude, with a `rationale` citing the real AWS behavior
// (grounded in docs/trust-policy-semantics.md) that makes the expectation
// correct. This is the credibility artifact proving the trust analyzer knows
// when NOT to fire - the highest-value place to prevent an overclaim
// (threat-model T8: a trust policy conveys WHO MAY ASSUME a role, never the
// assumed role's permissions).
//
// The fixtures are FROZEN TRUTH: this test never bends an expectation to match
// the engine. If the engine fails a semantically-correct contract, that is a
// real defect to fix in engine/trust.js, not here.
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
const negTrustDir = join(here, '..', 'fixtures', 'negative-trust');

// pathExploitability ordering, most-exploitable first (mirrors SEVERITY_ORDER).
const EXPLOITABILITY_ORDER = Object.freeze({ high: 0, medium: 1, low: 2 });

// Identity-family finding ids that must NEVER appear on a role-trust policy
// (trust policies commonly omit Resource; its absence is normal, not a finding).
const IDENTITY_STYLE_IDS = Object.freeze([
  'WILDCARD-RESOURCE',
  'WILDCARD-ACTION',
  'ASSUME-ROLE-EXPANSION',
  'PASSROLE-EC2',
  'PASSROLE-LAMBDA',
  'DATA-EXFIL',
  'DIRECT-IAM-ADMIN',
]);

function loadFixtures() {
  if (!existsSync(negTrustDir)) return [];
  return readdirSync(negTrustDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `negative-trust/${f}`, data: JSON.parse(readFileSync(join(negTrustDir, f), 'utf8')) }));
}

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

const FIXTURES = loadFixtures();

test('trust negative corpus is present and well-formed (each fixture has policy + negativeExpect + rationale)', () => {
  assert.ok(FIXTURES.length >= 5, `expected >=5 trust negative fixtures, found ${FIXTURES.length}`);
  // The five cases IAM-805 mandates, by intent, are all represented.
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy object`);
    assert.equal(data.family, 'role-trust', `${file}: is a role-trust fixture`);
    assert.ok(data.negativeExpect && typeof data.negativeExpect === 'object', `${file}: has a negativeExpect`);
    assert.equal(typeof data.rationale, 'string', `${file}: has a rationale string`);
    assert.ok(data.rationale.length > 0, `${file}: rationale is non-empty`);
  }
});

test('analyze() satisfies every frozen trust-negative contract (present/absent/severity/exploitability)', () => {
  for (const { file, data } of FIXTURES) {
    const expect = data.negativeExpect || {};
    const result = analyze(fixtureText(data));

    // Valid trust policies must analyze cleanly - a false failure would hide a
    // would-be finding and vacuously satisfy a mustNotFind.
    assert.equal(result.ok, true, `${file}: expected a clean analysis; got errors ${JSON.stringify(result.errors)}`);
    assert.equal(
      result.coverage && result.coverage.family,
      'role-trust',
      `${file}: expected the role-trust family to be detected`,
    );

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

test('no trust-negative fixture emits an identity-style finding (trust policies are never run through identity rules)', () => {
  for (const { file, data } of FIXTURES) {
    const result = analyze(fixtureText(data));
    const idSet = new Set(result.findings.map((f) => f.id));
    for (const forbidden of IDENTITY_STYLE_IDS) {
      assert.ok(!idSet.has(forbidden), `${file}: identity-style finding ${forbidden} must never fire on a trust policy`);
    }
  }
});

test('every trust finding marks the assumed role\'s permissions out of scope / unknown (T8 invariant)', () => {
  for (const { file, data } of FIXTURES) {
    const result = analyze(fixtureText(data));
    for (const f of result.findings) {
      // Structured invariant: the trust block records target privileges unknown.
      assert.equal(
        f.trust && f.trust.targetPermissions,
        'unknown',
        `${file}: ${f.id} must record trust.targetPermissions === 'unknown'`,
      );
      // Human-readable invariant: the limitation text states it plainly.
      assert.equal(typeof f.limit, 'string', `${file}: ${f.id} has a limit string`);
      assert.match(
        f.limit,
        /out of scope|unknown|not convey|never conveys/i,
        `${file}: ${f.id} limit must state the target role's permissions are out of scope / unknown`,
      );
    }
  }
});

test('service-trust negative control: a service principal never yields ExternalId "missing" remediation', () => {
  // Guards the trust-policy-semantics rule that ExternalId absence is context,
  // not a finding, and that a service principal is not treated as external.
  for (const { file, data } of FIXTURES) {
    const result = analyze(fixtureText(data));
    for (const f of result.findings) {
      const text = `${f.why || ''} ${f.remediation || ''}`;
      assert.ok(
        !/missing\s+(sts:)?externalid/i.test(text),
        `${file}: ${f.id} must not report "missing ExternalId"`,
      );
      assert.ok(
        !/missing\s+aws:principalorgid/i.test(text),
        `${file}: ${f.id} must not report "missing aws:PrincipalOrgID"`,
      );
    }
  }
});

test('analyze() is deterministic over the trust negative corpus (same input -> deep-equal twice)', () => {
  for (const { file, data } of FIXTURES) {
    const text = fixtureText(data);
    assert.deepEqual(analyze(text), analyze(text), `${file}: analyze() must be deterministic`);
  }
});
