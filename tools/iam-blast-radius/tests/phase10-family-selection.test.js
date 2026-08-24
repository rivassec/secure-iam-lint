// IAM-1001 (Phase 10): mandatory policy-family selection contract.
//
// docs/acceptance-suite-3.md Campaign B (tests 64/67/68/69/70/71) + release gate 2.
// Runs on node's built-in runner: `node --test`.
//
// The MANDATORY behavior is the UI contract, but its engine substrate is the
// analyze() options { family, requireExplicitFamily }:
//   - requireExplicitFamily + no selection -> BLOCKED POLICY_FAMILY_REQUIRED,
//     never a shape-based identity default (test 64).
//   - an explicit family drives semantics and family-shape guards: Identity +
//     Principal -> UNSUPPORTED_PRINCIPAL (test 67); Role-trust + Resource ->
//     UNSUPPORTED_TRUST_RESOURCE (test 68); Resource / SCP-RCP -> fail closed
//     UNSUPPORTED_POLICY_FAMILY naming the family (test 69).
//   - switching the family materially changes the result (test 70).
//   - every JSON + Markdown export records the selected family, analysis status,
//     catalog version, and warnings; statuses agree across surfaces (test 71).
//
// Engine back-compat: analyze() WITHOUT requireExplicitFamily still auto-detects,
// so the existing 956 unit tests + suite-1/suite-2 fixtures are unaffected -
// asserted here too.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { COVERAGE_CODES } from '../../../content/tools/iam-blast-radius/engine/family.js';
import { toJSON, toMarkdown, analysisStatus } from '../../../content/tools/iam-blast-radius/engine/report.js';
import { LIMITS } from '../../../content/tools/iam-blast-radius/engine/validate.js';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', 'fixtures', 'family-selection');

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

const FIXTURES = readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));

// ---------------------------------------------------------------------------
// Fixture-driven Campaign B (tests 64/67/68/69 + positives).
// ---------------------------------------------------------------------------

test('family-selection/ corpus is present and well-formed', () => {
  assert.ok(FIXTURES.length >= 6, `expected >=6 fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy`);
    assert.ok(data.options && typeof data.options === 'object', `${file}: has analyze options`);
    assert.ok(data.phase10Expect && typeof data.phase10Expect === 'object', `${file}: has phase10Expect`);
  }
});

test('analyze() matches every family-selection fixture contract', () => {
  for (const { file, data } of FIXTURES) {
    const e = data.phase10Expect;
    const result = analyze(fixtureText(data), data.options);

    assert.equal(result.ok, e.ok, `${file}: ok`);
    const cov = result.coverage;
    assert.ok(cov && typeof cov === 'object', `${file}: coverage present`);
    assert.equal(cov.blocked, e.blocked, `${file}: blocked`);
    assert.equal(cov.detected, e.detected, `${file}: detected family`);
    assert.equal(result.family, e.family, `${file}: result.family`);
    if (Object.prototype.hasOwnProperty.call(e, 'override')) {
      assert.equal(cov.override, e.override, `${file}: override`);
    }

    // Machine-readable status agrees with the fixture.
    assert.equal(analysisStatus(result), e.status, `${file}: analysis status`);

    for (const want of e.blockingCodes || []) {
      const hit = cov.blockingCodes.find((b) => b.code === want.code);
      assert.ok(hit, `${file}: expected blocking code ${want.code}; got ${cov.blockingCodes.map((b) => b.code).join(',')}`);
      if (Object.prototype.hasOwnProperty.call(want, 'path')) {
        assert.equal(hit.path, want.path, `${file}: ${want.code} JSON path`);
      }
    }
    for (const code of e.notBlockingCodes || []) {
      assert.ok(
        !cov.blockingCodes.some((b) => b.code === code),
        `${file}: must NOT emit ${code}`,
      );
    }

    if (e.noFindings) {
      assert.equal(result.findings.length, 0, `${file}: blocked -> no findings`);
      assert.equal(result.graph.edges.length, 0, `${file}: blocked -> no graph edges`);
      assert.equal(result.graph.nodes.length, 0, `${file}: blocked -> no graph nodes`);
    }
    if (e.hasFindings) {
      assert.ok(result.findings.length > 0, `${file}: expected findings`);
    }
  }
});

test('analyze() is deterministic over the family-selection corpus', () => {
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
// Test 64 - no family selected: fail closed, never default to identity by shape.
// ---------------------------------------------------------------------------

const S3_GET = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }],
});

test('test 64: requireExplicitFamily with no selection -> POLICY_FAMILY_REQUIRED, no identity default', () => {
  const r = analyze(S3_GET, { requireExplicitFamily: true });
  assert.equal(r.ok, true, 'a blocking coverage state is a conclusion, not a crash');
  assert.equal(r.coverage.blocked, true);
  assert.equal(r.family, null, 'no family is defaulted from shape');
  assert.equal(r.coverage.detected, 'unknown', 'detected is unknown, never identity');
  assert.ok(
    r.coverage.blockingCodes.some((b) => b.code === COVERAGE_CODES.POLICY_FAMILY_REQUIRED),
    'POLICY_FAMILY_REQUIRED present',
  );
  assert.equal(r.findings.length, 0, 'no risk result appears');
});

test('test 64: an empty-string family is treated as no selection under the required contract', () => {
  const r = analyze(S3_GET, { family: '', requireExplicitFamily: true });
  assert.equal(r.coverage.blocked, true);
  assert.ok(r.coverage.blockingCodes.some((b) => b.code === COVERAGE_CODES.POLICY_FAMILY_REQUIRED));
});

test('engine back-compat: WITHOUT requireExplicitFamily, no selection still auto-detects (identity)', () => {
  const r = analyze(S3_GET);
  assert.equal(r.ok, true);
  assert.equal(r.coverage.blocked, false, 'back-compat auto-detect is preserved for existing callers');
  assert.equal(r.coverage.detected, 'identity');
});

test('explicit Auto-detect satisfies the mandatory contract and detects the shape', () => {
  const r = analyze(S3_GET, { family: 'auto', requireExplicitFamily: true });
  assert.equal(r.coverage.blocked, false);
  assert.equal(r.coverage.detected, 'identity');
  assert.equal(r.coverage.override, null, 'auto carries no override');
});

// ---------------------------------------------------------------------------
// Test 70 - switching the family materially changes the result (invalidation
// substrate: the same bytes yield a different conclusion under a different
// family, so a stale identity result can never be correct under a new label).
// ---------------------------------------------------------------------------

test('test 70: the same bytes analyzed under two families produce materially different results', () => {
  const bytes = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'MaximumPermissions', Effect: 'Allow', Action: ['s3:*', 'dynamodb:*'], Resource: '*' }],
  });
  const asIdentity = analyze(bytes, { family: 'identity', requireExplicitFamily: true });
  const asBoundary = analyze(bytes, { family: 'permissions-boundary', requireExplicitFamily: true });

  assert.equal(asIdentity.coverage.blocked, false, 'identity analyzes');
  assert.ok(asIdentity.findings.length > 0, 'identity produces capability findings');

  // IAM-1002 ships the permissions-boundary envelope evaluator, so the same bytes
  // under a boundary selection now produce an ENVELOPE finding (not the identity
  // capability set); either way the result must NOT be the identity result under a
  // boundary label. (Detailed envelope semantics live in phase10-envelope.test.js.)
  assert.notDeepEqual(
    asBoundary.findings.map((f) => f.id),
    asIdentity.findings.map((f) => f.id),
    'the boundary result must differ from the identity result for identical bytes',
  );
  assert.equal(asBoundary.family, 'permissions-boundary', 'the export family reflects the explicit selection');
});

// ---------------------------------------------------------------------------
// Test 71 - family + status + catalog version + warnings survive every export,
// and the three surfaces (browser helper / JSON / Markdown) agree on status.
// ---------------------------------------------------------------------------

function surfacesAgree(result, expectedStatus, label) {
  const browser = analysisStatus(result);
  const json = JSON.parse(toJSON(result));
  const md = toMarkdown(result);

  assert.equal(browser, expectedStatus, `${label}: browser status`);
  assert.equal(json.status, expectedStatus, `${label}: JSON status agrees`);
  assert.match(md, new RegExp(`- Analysis status: ${expectedStatus}\\b`), `${label}: Markdown status agrees`);

  // Family, catalog version, and warnings are present on every export.
  assert.ok(Object.prototype.hasOwnProperty.call(json, 'family'), `${label}: JSON has family`);
  assert.ok(Object.prototype.hasOwnProperty.call(json, 'selectedFamily'), `${label}: JSON has selectedFamily`);
  assert.ok(Array.isArray(json.warnings), `${label}: JSON has warnings[]`);
  assert.ok(json.catalogVersion, `${label}: JSON has catalogVersion`);
  assert.match(md, /- Rule catalog version: /, `${label}: Markdown has catalog version`);
  assert.match(md, /- Selected family: /, `${label}: Markdown has selected family`);
  assert.match(md, /- Warnings: /, `${label}: Markdown has warnings`);
  return { json, md };
}

test('test 71: status agrees across browser/JSON/Markdown for ok/warned/blocked/error', () => {
  // ok: a clean identity analysis with no unsupported input.
  const okRes = analyze(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::111122223333:role/app' }],
  }), { family: 'identity', requireExplicitFamily: true });
  surfacesAgree(okRes, 'ok', 'ok-case');

  // warned: an unrecognized/unknown action makes coverage incomplete.
  const warnedRes = analyze(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 'madeupservice:DoTheThing', Resource: '*' }],
  }), { family: 'identity', requireExplicitFamily: true });
  assert.equal(warnedRes.coverage.summary.incomplete, true, 'unknown action -> incomplete coverage');
  surfacesAgree(warnedRes, 'warned', 'warned-case');

  // blocked (POLICY_FAMILY_REQUIRED): no family selected.
  const blockedReq = analyze(S3_GET, { requireExplicitFamily: true });
  const { json: bj } = surfacesAgree(blockedReq, 'blocked', 'blocked-required');
  assert.ok(bj.warnings.includes('POLICY_FAMILY_REQUIRED'), 'blocked warning code carried in JSON');

  // blocked (unsupported family): resource selected.
  const blockedFam = analyze(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::public/*' }],
  }), { family: 'resource', requireExplicitFamily: true });
  surfacesAgree(blockedFam, 'blocked', 'blocked-family');

  // error: over the byte limit fails before a conclusion (ok:false).
  const huge = 'x'.repeat(LIMITS.MAX_BYTES + 1);
  const errRes = analyze(huge, { family: 'identity', requireExplicitFamily: true });
  assert.equal(errRes.ok, false, 'oversized input fails');
  surfacesAgree(errRes, 'error', 'error-case');
});

test('test 71: a blocked export is never labeled authoritative (status blocked, not ok)', () => {
  const blocked = analyze(S3_GET, { requireExplicitFamily: true });
  const json = JSON.parse(toJSON(blocked));
  assert.equal(json.status, 'blocked');
  assert.notEqual(json.status, 'ok');
  // The graph carries nothing to describe as authoritative.
  assert.equal(json.graph.edges.length, 0);
});

test('test 71: the explicitly selected family is recorded in both exports', () => {
  const r = analyze(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }],
  }), { family: 'identity', requireExplicitFamily: true });
  const json = JSON.parse(toJSON(r));
  assert.equal(json.selectedFamily, 'identity', 'JSON records the selected family');
  assert.match(toMarkdown(r), /- Selected family: identity/, 'Markdown records the selected family');
});
