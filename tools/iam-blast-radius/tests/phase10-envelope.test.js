// IAM-1002 (Phase 10): permissions-boundary + session family semantics
// (envelope / restriction, NO positive capability edges).
//
// docs/acceptance-suite-2.md tests 30/31 + docs/acceptance-suite-3.md tests
// 65/66. Runs on node's built-in runner: `node --test`.
//
// Under an EXPLICIT permissions-boundary / session selection the engine routes
// to the family-aware envelope evaluator (engine/envelope.js) instead of the
// identity rules/escalation engine:
//   - Permissions boundary  -> a MAXIMUM-PERMISSIONS ENVELOPE (a ceiling). Report
//     the breadth, emit ZERO positive capability edges, NO escalation findings,
//     and state the INTERSECTION semantics. The identity family on the same bytes
//     must differ materially (test 30/65).
//   - Session               -> a session RESTRICTION/ceiling. No positive
//     capability edge without parent context; state intersection (test 31/66).
// The exported family reflects the explicit selection, and auto-detect NEVER
// resolves to these families (they are indistinguishable from identity by shape).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { ENVELOPE_IDS } from '../../../content/tools/iam-blast-radius/engine/envelope.js';
import { ESCALATION_IDS } from '../../../content/tools/iam-blast-radius/engine/escalation.js';
import { COVERAGE_CODES } from '../../../content/tools/iam-blast-radius/engine/family.js';
import { toJSON, toMarkdown, analysisStatus } from '../../../content/tools/iam-blast-radius/engine/report.js';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', 'fixtures', 'family-envelope');

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

const FIXTURES = readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));

const ESC = new Set(ESCALATION_IDS);
const ENV = new Set(ENVELOPE_IDS);

// ---------------------------------------------------------------------------
// Fixture-driven contract (suite-2 30/31, suite-3 65/66).
// ---------------------------------------------------------------------------

test('family-envelope/ corpus is present and well-formed', () => {
  assert.ok(FIXTURES.length >= 4, `expected >=4 fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy`);
    assert.ok(data.options && typeof data.options === 'object', `${file}: has analyze options`);
    assert.ok(data.envelopeExpect && typeof data.envelopeExpect === 'object', `${file}: has envelopeExpect`);
  }
});

test('analyze() matches every family-envelope fixture contract', () => {
  for (const { file, data } of FIXTURES) {
    const e = data.envelopeExpect;
    const result = analyze(fixtureText(data), data.options);

    assert.equal(result.ok, e.ok, `${file}: ok`);
    const cov = result.coverage;
    assert.ok(cov && typeof cov === 'object', `${file}: coverage present`);
    assert.equal(cov.blocked, e.blocked, `${file}: blocked`);
    assert.equal(result.family, e.family, `${file}: result.family reflects the explicit selection`);
    assert.equal(cov.override, e.override, `${file}: override recorded`);
    assert.equal(cov.supported, true, `${file}: family is supported (envelope evaluator)`);
    assert.equal(analysisStatus(result), e.status, `${file}: analysis status`);

    // Finding ids match, and each envelope finding is an envelope id (never an
    // identity/escalation id).
    assert.deepEqual(
      result.findings.map((f) => f.id).sort(),
      e.findingIds.slice().sort(),
      `${file}: finding ids`,
    );
    for (const f of result.findings) {
      assert.ok(ENV.has(f.id), `${file}: ${f.id} must be an envelope/ceiling id`);
      assert.ok(!ESC.has(f.id), `${file}: ${f.id} must NOT be an escalation id`);
      assert.equal(f.escalation, undefined, `${file}: ${f.id} must carry no escalation enrichment`);
      // Severities as declared.
      if (e.severities && e.severities[f.id]) {
        assert.equal(f.severity, e.severities[f.id], `${file}: ${f.id} severity`);
      }
      // Intersection semantics stated + capability-not-effective caveat present.
      if (e.statesIntersection) {
        assert.match(f.limit, /INTERSECTION/, `${file}: ${f.id} must state the intersection semantics`);
        assert.match(f.limit, /not effective access/i, `${file}: ${f.id} must carry the capability-not-effective caveat`);
      }
      // Never critical/high-as-escalation: a ceiling grants nothing.
      assert.notEqual(f.severity, 'critical', `${file}: ${f.id} must never be critical (no compound path)`);
    }

    // ZERO positive capability edges: the graph is empty by construction.
    if (e.zeroCapabilityEdges) {
      assert.equal(result.graph.edges.length, 0, `${file}: envelope/ceiling must emit ZERO capability edges`);
      assert.equal(result.graph.nodes.length, 0, `${file}: envelope/ceiling must emit ZERO graph nodes`);
      assert.equal(result.counts.edges, 0, `${file}: counts.edges is 0`);
    }
    if (e.noEscalation) {
      assert.ok(
        !result.findings.some((f) => ESC.has(f.id) || f.escalation),
        `${file}: no escalation findings under an envelope/ceiling family`,
      );
    }

    // The same bytes under an explicit Identity selection must differ materially.
    if (e.differsFromIdentity) {
      const asIdentity = analyze(fixtureText(data), { family: 'identity', requireExplicitFamily: true });
      assert.notDeepEqual(
        result.findings.map((f) => f.id).sort(),
        asIdentity.findings.map((f) => f.id).sort(),
        `${file}: the ${e.family} result must differ from the identity result for identical bytes`,
      );
    }
  }
});

test('analyze() is deterministic over the family-envelope corpus', () => {
  for (const { file, data } of FIXTURES) {
    const text = fixtureText(data);
    assert.deepEqual(
      analyze(text, data.options),
      analyze(text, data.options),
      `${file}: analyze() must be deterministic`,
    );
  }
});

// ---------------------------------------------------------------------------
// Test 30 / 65 - permissions-boundary envelope, no capability edges.
// ---------------------------------------------------------------------------

const BOUNDARY_BYTES = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Sid: 'MaximumPermissions', Effect: 'Allow', Action: ['s3:*', 'dynamodb:*'], Resource: '*' }],
});

test('test 30/65: a permissions boundary reports a broad envelope with no positive capability edges', () => {
  const r = analyze(BOUNDARY_BYTES, { family: 'permissions-boundary', requireExplicitFamily: true });
  assert.equal(r.ok, true);
  assert.equal(r.coverage.blocked, false);
  assert.equal(r.family, 'permissions-boundary', 'exported family is permissions-boundary');
  assert.deepEqual(r.findings.map((f) => f.id), ['PERMISSIONS-BOUNDARY-ENVELOPE']);
  assert.equal(r.findings[0].severity, 'high', 'a wildcard boundary is broad envelope breadth');
  // No positive capability edge of any kind.
  assert.equal(r.graph.edges.length, 0);
  assert.equal(r.graph.nodes.length, 0);
  // Intersection semantics + identity-must-independently-allow are stated.
  assert.match(r.findings[0].limit, /INTERSECTION/);
  assert.match(r.findings[0].why, /ceiling/i);
});

test('test 65: switching the same bytes to Identity produces a materially different result', () => {
  const asBoundary = analyze(BOUNDARY_BYTES, { family: 'permissions-boundary', requireExplicitFamily: true });
  const asIdentity = analyze(BOUNDARY_BYTES, { family: 'identity', requireExplicitFamily: true });

  assert.ok(asIdentity.findings.length > 0, 'identity produces capability findings');
  // Identity emits positive capability edges; the boundary emits none.
  assert.ok(asIdentity.graph.edges.length > 0, 'identity produces graph edges');
  assert.equal(asBoundary.graph.edges.length, 0, 'boundary produces no capability edges');
  assert.notDeepEqual(
    asBoundary.findings.map((f) => f.id).sort(),
    asIdentity.findings.map((f) => f.id).sort(),
    'boundary vs identity finding ids differ',
  );
});

// ---------------------------------------------------------------------------
// Test 31 / 66 - session ceiling, no standalone capability edge.
// ---------------------------------------------------------------------------

const SESSION_BYTES = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Sid: 'SessionScope', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::incident-evidence/*' }],
});

test('test 31/66: a session policy reports a ceiling with no capability edge and no identity relabel', () => {
  const r = analyze(SESSION_BYTES, { family: 'session', requireExplicitFamily: true });
  assert.equal(r.ok, true);
  assert.equal(r.coverage.blocked, false);
  assert.equal(r.family, 'session', 'exported family is session, never relabeled identity');
  assert.deepEqual(r.findings.map((f) => f.id), ['SESSION-CEILING']);
  assert.equal(r.graph.edges.length, 0, 'no capability/exfil edge without parent context');
  assert.equal(r.graph.nodes.length, 0);
  assert.match(r.findings[0].limit, /INTERSECTION/);
  assert.match(r.findings[0].limit, /parent/i, 'ceiling needs the parent policy for effective access');
});

// ---------------------------------------------------------------------------
// Fail-closed: an envelope selection is valid ONLY on an identity-shaped
// (no-Principal) document. A Principal-bearing / trust-shaped document under a
// boundary/session selection fails closed rather than manufacture a ceiling.
// ---------------------------------------------------------------------------

test('permissions-boundary selected on a Principal-bearing (resource) shape fails closed', () => {
  const bytes = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::public/*' }],
  });
  const r = analyze(bytes, { family: 'permissions-boundary', requireExplicitFamily: true });
  assert.equal(r.coverage.blocked, true, 'a Principal-bearing shape cannot be a boundary');
  assert.equal(r.findings.length, 0);
  assert.equal(r.graph.edges.length, 0);
});

test('session selected on a role-trust shape fails closed with a shape mismatch', () => {
  const bytes = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Principal: { AWS: '111122223333' }, Action: 'sts:AssumeRole' }],
  });
  const r = analyze(bytes, { family: 'session', requireExplicitFamily: true });
  assert.equal(r.coverage.blocked, true, 'a trust shape cannot be a session policy');
  assert.ok(
    r.coverage.blockingCodes.some((b) => b.code === COVERAGE_CODES.OVERRIDE_SHAPE_MISMATCH),
    'shape-mismatch block present',
  );
  assert.equal(r.findings.length, 0);
});

// ---------------------------------------------------------------------------
// Exports carry the selected family + status across surfaces.
// ---------------------------------------------------------------------------

test('exports record the selected boundary/session family and agree on status', () => {
  for (const [bytes, fam] of [[BOUNDARY_BYTES, 'permissions-boundary'], [SESSION_BYTES, 'session']]) {
    const r = analyze(bytes, { family: fam, requireExplicitFamily: true });
    const json = JSON.parse(toJSON(r));
    const md = toMarkdown(r);
    assert.equal(json.family, fam, `${fam}: JSON family`);
    assert.equal(json.selectedFamily, fam, `${fam}: JSON selectedFamily`);
    assert.equal(json.status, analysisStatus(r), `${fam}: JSON status agrees`);
    assert.match(md, new RegExp(`- Policy family: ${fam}`), `${fam}: Markdown policy family`);
    assert.match(md, new RegExp(`- Selected family: ${fam}`), `${fam}: Markdown selected family`);
    // A blocked/authoritative confusion is impossible: status is ok and the graph
    // carries nothing to describe as authoritative.
    assert.equal(json.graph.edges.length, 0);
  }
});

// ---------------------------------------------------------------------------
// Auto-detect never resolves to a boundary/session family (indistinguishable
// from identity by shape) - the identity behavior is unchanged for these bytes.
// ---------------------------------------------------------------------------

test('auto-detect never resolves boundary/session; identity behavior unchanged', () => {
  const auto = analyze(BOUNDARY_BYTES, { family: 'auto', requireExplicitFamily: true });
  assert.equal(auto.coverage.detected, 'identity', 'auto-detect sees an identity shape');
  assert.equal(auto.family, 'identity', 'auto-detect never yields a boundary/session family');
  assert.ok(auto.findings.some((f) => f.id === 'WILDCARD-RESOURCE'), 'identity rules still fire under auto-detect');
});
