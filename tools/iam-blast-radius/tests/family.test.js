// Unit tests for IAM-501: policy-family model with auto-detect + fail-closed.
// Runs on node's built-in runner: `node --test`.
//
// Acceptance (prd.json IAM-501):
//   - ambiguous/mixed/unknown shapes fail before rule evaluation with a
//     machine-readable code + JSON path
//   - NotPrincipal is rejected UNSUPPORTED_NOTPRINCIPAL, never silently ignored
//   - existing single identity-policy fixtures still analyze (auto-detect =
//     identity)
//   - family classification correct per AWS grammar
//   - every export records the selected/detected family + blocking coverage
//
// The family gate lives in analyze() (the orchestrator): it classifies the
// document shape and, on a shape the engine does not model, returns a BLOCKING
// COVERAGE STATE (ok:true, zero findings, empty graph, coverage.blocked) rather
// than presenting confident identity findings on a shape it does not understand.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { modelFromText, buildModel } from '../../../content/tools/iam-blast-radius/engine/model.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import {
  detectFamily,
  FAMILIES,
  SUPPORTED_FAMILIES,
  OVERRIDE_FAMILIES,
  COVERAGE_CODES,
} from '../../../content/tools/iam-blast-radius/engine/family.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');
const familyDir = join(fixturesDir, 'family');

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

function loadFamilyFixtures() {
  if (!existsSync(familyDir)) return [];
  return readdirSync(familyDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `family/${f}`, data: JSON.parse(readFileSync(join(familyDir, f), 'utf8')) }));
}

const FIXTURES = loadFamilyFixtures();

// ---------------------------------------------------------------------------
// Fixture-driven: each family/ fixture carries a `familyExpect` contract.
// ---------------------------------------------------------------------------

test('family/ corpus is present and well-formed', () => {
  assert.ok(FIXTURES.length >= 6, `expected >=6 family fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy object`);
    assert.ok(data.familyExpect && typeof data.familyExpect === 'object', `${file}: has a familyExpect`);
  }
});

test('analyze() matches every family fixture coverage contract', () => {
  for (const { file, data } of FIXTURES) {
    const fe = data.familyExpect;

    // A hard model-level schema error (Principal + NotPrincipal) fails the whole
    // pipeline before family classification.
    if (fe.modelError) {
      const result = analyze(fixtureText(data));
      assert.equal(result.ok, false, `${file}: expected a hard failure`);
      assert.ok(
        result.errors.some((e) => e.code === fe.modelError),
        `${file}: expected error ${fe.modelError}; got ${result.errors.map((e) => e.code).join(',')}`,
      );
      if (fe.modelErrorPath) {
        assert.ok(
          result.errors.some((e) => e.code === fe.modelError && e.path === fe.modelErrorPath),
          `${file}: expected ${fe.modelError} at path ${fe.modelErrorPath}`,
        );
      }
      // A hard failure records no family/coverage (never reached classification).
      assert.equal(result.family, null, `${file}: no family on hard failure`);
      assert.equal(result.coverage, null, `${file}: no coverage on hard failure`);
      continue;
    }

    const result = analyze(fixtureText(data));
    // The pipeline always runs to a well-formed result (ok:true) - a blocking
    // coverage state is a CONCLUSION, not a crash.
    assert.equal(result.ok, true, `${file}: expected ok:true; errors ${JSON.stringify(result.errors)}`);
    const cov = result.coverage;
    assert.ok(cov && typeof cov === 'object', `${file}: coverage present`);
    assert.equal(cov.detected, fe.detected, `${file}: detected family`);
    assert.equal(cov.family, fe.family, `${file}: effective family`);
    assert.equal(result.family, fe.family, `${file}: result.family mirrors coverage.family`);
    assert.equal(cov.blocked, fe.blocked, `${file}: blocked state`);
    assert.equal(cov.supported, fe.supported, `${file}: supported state`);

    // A blocked shape yields ZERO findings and an empty graph (fail closed).
    if (fe.blocked) {
      assert.equal(result.findings.length, 0, `${file}: blocked -> no findings`);
      assert.equal(result.graph.edges.length, 0, `${file}: blocked -> no graph edges`);
      assert.equal(result.graph.nodes.length, 0, `${file}: blocked -> no graph nodes`);
    }

    // Every expected blocking code is present WITH its exact JSON path.
    for (const want of fe.blockingCodes || []) {
      const hit = cov.blockingCodes.find((b) => b.code === want.code);
      assert.ok(hit, `${file}: expected blocking code ${want.code}; got ${cov.blockingCodes.map((b) => b.code).join(',')}`);
      if (Object.prototype.hasOwnProperty.call(want, 'path')) {
        assert.equal(hit.path, want.path, `${file}: ${want.code} JSON path`);
      }
    }
    if ((fe.blockingCodes || []).length === 0) {
      assert.equal(cov.blockingCodes.length, 0, `${file}: expected no blocking codes`);
    }
  }
});

test('analyze() is deterministic over the family corpus', () => {
  for (const { file, data } of FIXTURES) {
    const text = fixtureText(data);
    assert.deepEqual(analyze(text), analyze(text), `${file}: analyze() must be deterministic`);
  }
});

// ---------------------------------------------------------------------------
// NotPrincipal: distinct element, rejected, exact path (threat-model T8).
// ---------------------------------------------------------------------------

test('NotPrincipal is modeled as a DISTINCT element (not merged with Principal)', () => {
  const m = modelFromText(JSON.stringify({
    Statement: [{ Effect: 'Deny', NotPrincipal: { AWS: 'arn:aws:iam::1:root' }, Action: 's3:*', Resource: '*' }],
  }));
  assert.equal(m.ok, true, 'a NotPrincipal statement is a valid MODEL (rejection is a coverage decision, not a schema error)');
  const s = m.model.statements[0];
  assert.equal(s.principal, null, 'Principal is absent');
  assert.ok(s.notPrincipal && s.notPrincipal.byType, 'NotPrincipal is captured on its own field');
  assert.deepEqual(s.notPrincipal.byType.AWS, ['arn:aws:iam::1:root'], 'NotPrincipal value preserved');
});

test('NotPrincipal is rejected UNSUPPORTED_NOTPRINCIPAL with the exact path, never ignored', () => {
  const result = analyze(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
      { Effect: 'Deny', NotPrincipal: { AWS: 'x' }, Action: 's3:*', Resource: '*' },
    ],
  }));
  assert.equal(result.ok, true, 'blocking coverage, not a crash');
  assert.equal(result.coverage.blocked, true, 'blocked');
  const np = result.coverage.blockingCodes.find((b) => b.code === COVERAGE_CODES.UNSUPPORTED_NOTPRINCIPAL);
  assert.ok(np, 'UNSUPPORTED_NOTPRINCIPAL present');
  assert.equal(np.path, 'Statement[1].NotPrincipal', 'exact JSON path of the offending element');
  assert.equal(result.findings.length, 0, 'no findings on a NotPrincipal shape');
});

test('Principal + NotPrincipal in one statement is a hard schema error', () => {
  const m = modelFromText(JSON.stringify({
    Statement: [{ Effect: 'Deny', Principal: { AWS: '*' }, NotPrincipal: { AWS: 'x' }, Action: 's3:*', Resource: '*' }],
  }));
  assert.equal(m.ok, false, 'mutually-exclusive elements are rejected');
  assert.ok(m.errors.some((e) => e.code === 'PRINCIPAL_AND_NOTPRINCIPAL' && e.path === 'Statement[0]'));
});

// ---------------------------------------------------------------------------
// detectFamily() classification per AWS grammar.
// ---------------------------------------------------------------------------

function familyOf(policy, options) {
  const m = buildModel(validate(JSON.stringify(policy)).raw);
  assert.equal(m.ok, true, 'model built');
  return detectFamily(m.model, options);
}

test('detectFamily classifies each family from shape', () => {
  assert.equal(familyOf({ Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }).detected, FAMILIES.IDENTITY);
  assert.equal(familyOf({ Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:*', Resource: 'arn:aws:s3:::b/*' }] }).detected, FAMILIES.RESOURCE);
  assert.equal(familyOf({ Statement: [{ Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' }, Action: 'sts:AssumeRole' }] }).detected, FAMILIES.ROLE_TRUST);
  // A Principal-bearing statement WITH a Resource is a general resource policy, not trust.
  assert.equal(familyOf({ Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::1:role/r' }] }).detected, FAMILIES.RESOURCE);
});

test('detectFamily: identity and role-trust are supported; a resource policy is not', () => {
  const id = familyOf({ Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] });
  assert.equal(id.blocked, false);
  assert.equal(id.supported, true);

  // IAM-801: a role-trust shape is now supported (routed to the trust evaluator).
  const trust = familyOf({ Statement: [{ Effect: 'Allow', Principal: { Service: 'ec2.amazonaws.com' }, Action: 'sts:AssumeRole' }] });
  assert.equal(trust.detected, FAMILIES.ROLE_TRUST);
  assert.equal(trust.blocked, false, 'role-trust is supported, not blocked');
  assert.equal(trust.supported, true);
  assert.ok(SUPPORTED_FAMILIES.has(FAMILIES.ROLE_TRUST));

  // A general resource-based policy stays unmodeled and fails closed.
  const res = familyOf({ Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:*', Resource: 'arn:aws:s3:::b/*' }] });
  assert.equal(res.blocked, true, 'resource blocked');
  assert.equal(res.supported, false, 'resource unsupported');
  assert.ok(!SUPPORTED_FAMILIES.has(res.family));
});

// ---------------------------------------------------------------------------
// Optional manual family override.
// ---------------------------------------------------------------------------

test('manual override: selecting an unmodeled family blocks even a clean identity shape', () => {
  const idPolicy = { Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] };
  // IAM-801: role-trust is now a SUPPORTED family, so it is no longer in this
  // "unmodeled" list; forcing it onto an identity shape is a shape mismatch,
  // asserted separately below.
  // IAM-1002: permissions-boundary and session are now SUPPORTED families (the
  // envelope/restriction evaluator) on an identity-shaped document, so they are
  // no longer in this "unmodeled" list either (asserted supported below). Only
  // resource + scp-rcp remain unmodeled and fail closed.
  for (const fam of ['resource', 'scp-rcp']) {
    assert.ok(OVERRIDE_FAMILIES.has(fam), `${fam} is a selectable override`);
    const c = familyOf(idPolicy, { family: fam });
    assert.equal(c.override, fam, `${fam} recorded as override`);
    assert.equal(c.family, fam, `${fam} is the effective family`);
    assert.equal(c.blocked, true, `${fam} override blocks (no evaluator)`);
    assert.ok(c.blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY));
  }
});

test('IAM-1002: permissions-boundary / session override on an identity shape is SUPPORTED (envelope evaluator)', () => {
  const idPolicy = { Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] };
  for (const fam of ['permissions-boundary', 'session']) {
    assert.ok(OVERRIDE_FAMILIES.has(fam), `${fam} is a selectable override`);
    assert.ok(SUPPORTED_FAMILIES.has(fam), `${fam} is now a supported family`);
    const c = familyOf(idPolicy, { family: fam });
    assert.equal(c.override, fam, `${fam} recorded as override`);
    assert.equal(c.family, fam, `${fam} is the effective family`);
    assert.equal(c.blocked, false, `${fam} on an identity-shaped document is NOT blocked`);
    assert.equal(c.supported, true, `${fam} is supported`);
    assert.equal(c.blockingCodes.length, 0, `${fam} emits no blocking codes on an identity shape`);
  }
});

test('IAM-1002: permissions-boundary / session override on a Principal-bearing shape fails closed', () => {
  const resPolicy = { Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:*', Resource: 'arn:aws:s3:::b/*' }] };
  for (const fam of ['permissions-boundary', 'session']) {
    const c = familyOf(resPolicy, { family: fam });
    assert.equal(c.blocked, true, `${fam} cannot apply to a Principal-bearing shape`);
    assert.equal(c.supported, false, `${fam} on a resource shape is unsupported`);
  }
});

test('manual override "role-trust" on an identity shape fails closed (shape wins)', () => {
  const c = familyOf({ Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }, { family: 'role-trust' });
  assert.equal(c.override, 'role-trust');
  assert.equal(c.blocked, true, 'cannot force the trust evaluator onto an identity shape');
  assert.ok(c.blockingCodes.some((b) => b.code === COVERAGE_CODES.OVERRIDE_SHAPE_MISMATCH));
});

test('manual override "identity" on a Principal-bearing shape fails closed UNSUPPORTED_PRINCIPAL (IAM-1001 test 67)', () => {
  const c = familyOf(
    { Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:*', Resource: 'arn:aws:s3:::b/*' }] },
    { family: 'identity' },
  );
  assert.equal(c.blocked, true, 'cannot force identity rules onto a Principal-bearing shape');
  // IAM-1001: the family-shape guard names the offending Principal (with its JSON
  // path) rather than a generic mismatch, and never drops it to analyze the rest.
  const hit = c.blockingCodes.find((b) => b.code === COVERAGE_CODES.UNSUPPORTED_PRINCIPAL);
  assert.ok(hit, 'UNSUPPORTED_PRINCIPAL emitted');
  assert.equal(hit.path, 'Statement[0].Principal', 'exact JSON path of the Principal');
  assert.ok(
    !c.blockingCodes.some((b) => b.code === COVERAGE_CODES.OVERRIDE_SHAPE_MISMATCH),
    'the specific Principal guard supersedes the generic shape mismatch',
  );
});

test('manual override "identity" on an identity shape analyzes normally', () => {
  const result = analyze(
    JSON.stringify({ Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }),
    { family: 'identity' },
  );
  assert.equal(result.ok, true);
  assert.equal(result.coverage.blocked, false);
  assert.equal(result.coverage.override, 'identity');
  assert.ok(result.findings.length > 0, 'identity rules ran');
});

// IAM-1103 (11C): a NON-EMPTY unrecognized/typo family token must FAIL CLOSED
// with INVALID_FAMILY - never fall through to auto-detect and get analyzed as an
// identity policy (the DEF-05-style fail-OPEN). Whitespace is trimmed and case is
// canonicalized BEFORE matching, so "banana", "scpp", "identityx", and "SCP "
// (trailing space that would otherwise miss the scp alias) are each rejected as
// invalid, EXCEPT "SCP " which trims to the recognized scp synonym.
test('an unrecognized/typo family token fails closed with INVALID_FAMILY (never auto-detect)', () => {
  for (const bad of ['nonsense', 'banana', 'scpp', 'identityx', 'roletrust', 'IDENTITYX']) {
    const c = familyOf({ Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }, { family: bad });
    assert.equal(c.override, null, `${bad}: garbage token not recorded as an override`);
    assert.equal(c.family, null, `${bad}: no family resolved`);
    assert.equal(c.detected, FAMILIES.UNKNOWN, `${bad}: detected UNKNOWN, never guessed identity`);
    assert.equal(c.blocked, true, `${bad}: fails closed`);
    assert.equal(c.supported, false, `${bad}: unsupported`);
    assert.ok(
      c.blockingCodes.some((b) => b.code === COVERAGE_CODES.INVALID_FAMILY),
      `${bad}: blocks with INVALID_FAMILY`,
    );
  }
});

// IAM-1103: whitespace is trimmed BEFORE alias matching, so a recognized synonym
// with stray surrounding whitespace still canonicalizes (it is NOT treated as an
// invalid token). "SCP " -> scp -> scp-rcp -> fails closed as an unmodeled family.
test('a recognized family with stray whitespace is trimmed, not rejected as invalid', () => {
  const idShape = { Statement: [{ Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }] };
  for (const token of ['SCP ', '  scp', ' rcp ', 'identity ']) {
    const c = familyOf(idShape, { family: token });
    assert.ok(
      !c.blockingCodes.some((b) => b.code === COVERAGE_CODES.INVALID_FAMILY),
      `${JSON.stringify(token)}: trimmed to a recognized family, not INVALID_FAMILY`,
    );
  }
});

// An empty / whitespace-only selection is "no selection" (paste-and-go
// auto-detect), NOT an invalid token - it must never block with INVALID_FAMILY.
test('an empty or whitespace-only family is no-selection (auto-detect), not INVALID_FAMILY', () => {
  for (const token of ['', '   ', undefined]) {
    const c = familyOf({ Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }, { family: token });
    assert.ok(
      !c.blockingCodes.some((b) => b.code === COVERAGE_CODES.INVALID_FAMILY),
      `${JSON.stringify(token)}: no-selection auto-detects, never INVALID_FAMILY`,
    );
    assert.equal(c.family, FAMILIES.IDENTITY, `${JSON.stringify(token)}: auto-detect prevails`);
    assert.equal(c.blocked, false);
  }
});

// IAM-1103 (11C) regression guard: a RECOGNIZED family synonym for an unmodeled
// control-policy family ("scp" / "rcp", the aliases of the canonical scp-rcp)
// must NOT slip through the "unrecognized token -> auto-detect" path and get
// analyzed as an identity policy (the DEF-05 fail-OPEN, where an SCP run through
// identity rules would emit confident capability findings on a grant-nothing
// document). It canonicalizes to scp-rcp and fails closed, never analyzing as
// identity. A genuinely unknown token ("nonsense") now ALSO fails closed - with
// INVALID_FAMILY (asserted above) - so neither a known control-family synonym nor
// an unknown token can fall through to the identity auto-detect fail-open.
test('IAM-1103: recognized control-family synonyms (scp/rcp/trust) canonicalize and fail closed - never analyze as identity', () => {
  const idShape = { Statement: [{ Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }] };
  for (const alias of ['scp', 'rcp', 'SCP', 'Rcp']) {
    const c = familyOf(idShape, { family: alias });
    assert.equal(c.family, FAMILIES.SCP_RCP, `${alias} canonicalizes to scp-rcp`);
    assert.equal(c.override, FAMILIES.SCP_RCP, `${alias} recorded as an scp-rcp override, not ignored`);
    assert.equal(c.blocked, true, `${alias} fails closed (unmodeled control family)`);
    assert.equal(c.supported, false, `${alias} is unsupported`);
    assert.ok(
      c.blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY),
      `${alias} blocks with UNSUPPORTED_POLICY_FAMILY`,
    );
  }
  // "trust" is the role-trust synonym; on an identity shape it fails closed on the
  // shape mismatch (the shape wins), never analyzing the identity grant.
  const t = familyOf(idShape, { family: 'trust' });
  assert.equal(t.family, FAMILIES.ROLE_TRUST, 'trust canonicalizes to role-trust');
  assert.equal(t.blocked, true, 'role-trust forced onto an identity shape fails closed');
});

// IAM-1103: end-to-end through analyze() - the DEF-05 case. A caller driving
// analyze() directly with family:'scp' must get a BLOCKED result with zero
// findings and zero capability edges, not identity findings.
test('IAM-1103: analyze() with family "scp" fails closed - no findings, no edges (DEF-05)', () => {
  const scpPolicy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }],
  });
  const res = analyze(scpPolicy, { family: 'scp' });
  assert.equal(res.coverage.blocked, true, 'scp fails closed');
  assert.equal(res.findings.length, 0, 'no capability findings on an unmodeled control policy');
  const edgeCount = res.graph ? (res.graph.edges || []).length : 0;
  assert.equal(edgeCount, 0, 'no capability edges leak from a blocked family');
});

// ---------------------------------------------------------------------------
// Existing identity policies still auto-detect as identity (paste-and-go).
// ---------------------------------------------------------------------------

test('existing identity fixtures still auto-detect as identity and analyze', () => {
  let checked = 0;
  for (const category of ['safe', 'wildcard', 'pass-role', 'direct-iam']) {
    const dir = join(fixturesDir, category);
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.json'))) {
      const data = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      // Skip the (rare) fixtures that legitimately carry a Principal.
      const text = fixtureText(data);
      if (/"Principal"|"NotPrincipal"/.test(text)) continue;
      const result = analyze(text);
      if (!result.ok) continue; // malformed-by-design fixtures are out of scope here
      assert.equal(result.coverage.detected, 'identity', `${category}/${f}: identity auto-detect`);
      assert.equal(result.coverage.blocked, false, `${category}/${f}: not blocked`);
      checked += 1;
    }
  }
  assert.ok(checked >= 4, `expected several identity fixtures checked, got ${checked}`);
});

// ---------------------------------------------------------------------------
// The two pre-existing Principal-bearing trust fixtures are now ANALYZED by the
// family-aware trust evaluator (intentional IAM-801 change): role-trust is a
// supported family, so they are no longer blocked. Crucially they still produce
// NO identity-escalation finding on a trust policy - only trust (TRUST-*)
// findings may appear.
// ---------------------------------------------------------------------------

test('pre-existing trust fixtures are analyzed by the role-trust evaluator (supported, no identity findings)', () => {
  for (const rel of [
    'assume-role/trust-policy-not-escalation.json',
    'negative/resource-based-trust-policy-no-escalation.json',
  ]) {
    const data = JSON.parse(readFileSync(join(fixturesDir, rel), 'utf8'));
    const result = analyze(fixtureText(data));
    assert.equal(result.ok, true, `${rel}: ok`);
    assert.equal(result.coverage.blocked, false, `${rel}: role-trust is supported (not blocked)`);
    assert.equal(result.coverage.family, 'role-trust', `${rel}: detected role-trust`);
    // A trust policy never yields an identity-style finding; only TRUST-* rows.
    for (const f of result.findings) {
      assert.ok(/^TRUST-/.test(f.id), `${rel}: only trust findings allowed on a trust policy, got ${f.id}`);
    }
    for (const bad of ['ASSUME-ROLE-EXPANSION', 'TRUST-POLICY-MODIFY', 'WILDCARD-RESOURCE', 'PASSROLE-LAMBDA', 'DIRECT-IAM-ADMIN']) {
      assert.ok(!result.findings.some((f) => f.id === bad), `${rel}: must not fire identity ${bad}`);
    }
  }
});

// ---------------------------------------------------------------------------
// Exports record the selected/detected family + blocking coverage state.
// ---------------------------------------------------------------------------

test('JSON + Markdown exports record family and blocking coverage', () => {
  // Blocked (resource) case.
  const blocked = analyze(JSON.stringify({
    Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:*', Resource: 'arn:aws:s3:::b/*' }],
  }));
  const bj = JSON.parse(toJSON(blocked));
  assert.equal(bj.family, 'resource', 'JSON records the family');
  assert.ok(bj.coverage && bj.coverage.blocked === true, 'JSON records the blocking coverage');
  assert.ok(
    bj.coverage.blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY && b.path),
    'JSON coverage carries code + path',
  );
  const bm = toMarkdown(blocked);
  assert.match(bm, /Policy family: resource/);
  assert.match(bm, /Coverage: BLOCKED/);
  assert.match(bm, /UNSUPPORTED_POLICY_FAMILY/);

  // Supported (identity) case still records family + a non-blocking coverage.
  const ok = analyze(JSON.stringify({ Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] }));
  const oj = JSON.parse(toJSON(ok));
  assert.equal(oj.family, 'identity');
  assert.ok(oj.coverage && oj.coverage.blocked === false);
  assert.match(toMarkdown(ok), /Policy family: identity/);
});

test('a failed analysis records null family/coverage and exports without throwing', () => {
  const result = analyze('not valid json');
  assert.equal(result.ok, false);
  assert.equal(result.family, null);
  assert.equal(result.coverage, null);
  assert.doesNotThrow(() => toJSON(result));
  assert.doesNotThrow(() => toMarkdown(result));
  const parsed = JSON.parse(toJSON(result));
  assert.equal(parsed.family, null);
  assert.equal(parsed.coverage, null);
});
