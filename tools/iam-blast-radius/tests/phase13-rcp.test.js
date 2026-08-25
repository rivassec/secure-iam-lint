// IAM-1302 (Phase 13): RCP resource-control guardrail family semantics.
//
// docs/acceptance-suite-2.md test 52 (RCP confused-deputy guardrail) + an
// organization-perimeter RCP case. Runs on node's built-in runner: `node --test`.
//
// PHASE-13 IMMUTABLE GUARDRAIL: an RCP is a DENY-ONLY org RESOURCE guardrail /
// permission CEILING, NEVER a grant. Under an EXPLICIT SCP/RCP selection the engine
// routes a Principal-bearing, deny-only org-resource guardrail (carrying an
// org-scope condition key) to the family-aware RCP evaluator (engine/rcp.js)
// instead of the identity/resource GRANT engine:
//   - Every Deny -> an RCP-GUARDRAIL finding describing what the ceiling FORBIDS
//     (org confused-deputy, organization-perimeter, or generic resource Deny).
//   - The confused-deputy conditions (StringNotEqualsIfExists aws:SourceOrgID +
//     Null aws:SourceAccount + Bool aws:PrincipalIsAWSService) are preserved as ONE
//     guardrail (logical AND), NOT three independent denies.
//   - NO S3 permissions / public-access finding is emitted (a Principal "*" is the
//     subject the deny reaches, not a grant to anyone); ZERO positive capability
//     edges; every finding states RCPs are deny-only and a corresponding Allow must
//     exist elsewhere (intersection with identity/resource policies, not supplied).
// The exported family is scp-rcp (the org-control family token); auto-detect still
// FAILS CLOSED on an RCP shape (detected=resource; the auto flip is IAM-1303).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { analyzeRcp, RCP_IDS } from '../../../content/tools/iam-blast-radius/engine/rcp.js';
import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import { ESCALATION_IDS } from '../../../content/tools/iam-blast-radius/engine/escalation.js';
import { RESOURCE_IDS } from '../../../content/tools/iam-blast-radius/engine/resource.js';
import { COVERAGE_CODES } from '../../../content/tools/iam-blast-radius/engine/family.js';
import { toJSON, toMarkdown, analysisStatus } from '../../../content/tools/iam-blast-radius/engine/report.js';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', 'fixtures', 'family-rcp');

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

const FIXTURES = readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));

const ESC = new Set(ESCALATION_IDS);
const RCP = new Set(RCP_IDS);
const RESOURCE = new Set(RESOURCE_IDS);

// ---------------------------------------------------------------------------
// Fixture-driven contract (suite-2 test 52 + organization-perimeter RCP).
// ---------------------------------------------------------------------------

test('family-rcp/ corpus is present and well-formed', () => {
  assert.ok(FIXTURES.length >= 1, `expected >=1 fixture, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy`);
    assert.ok(data.options && typeof data.options === 'object', `${file}: has analyze options`);
    assert.ok(data.rcpExpect && typeof data.rcpExpect === 'object', `${file}: has rcpExpect`);
  }
});

test('analyze() matches every family-rcp fixture contract', () => {
  for (const { file, data } of FIXTURES) {
    const e = data.rcpExpect;
    const result = analyze(fixtureText(data), data.options);

    assert.equal(result.ok, e.ok, `${file}: ok`);
    const cov = result.coverage;
    assert.ok(cov && typeof cov === 'object', `${file}: coverage present`);
    assert.equal(cov.blocked, e.blocked, `${file}: blocked`);
    assert.equal(result.family, e.family, `${file}: result.family reflects the RCP selection`);
    assert.equal(cov.override, e.override, `${file}: override recorded`);
    assert.equal(cov.supported, true, `${file}: RCP family is supported (ceiling evaluator)`);
    assert.equal(analysisStatus(result), e.status, `${file}: analysis status`);

    // Finding ids match, and every finding is an RCP guardrail id (never an
    // identity / escalation / resource-capability id).
    assert.deepEqual(
      result.findings.map((f) => f.id).sort(),
      e.findingIds.slice().sort(),
      `${file}: finding ids`,
    );
    for (const f of result.findings) {
      assert.ok(RCP.has(f.id), `${file}: ${f.id} must be an RCP guardrail id`);
      assert.ok(!ESC.has(f.id), `${file}: ${f.id} must NOT be an escalation id`);
      assert.ok(!RESOURCE.has(f.id), `${file}: ${f.id} must NOT be a resource-capability id`);
      assert.equal(f.escalation, undefined, `${file}: ${f.id} must carry no escalation enrichment`);
      // A deny-only guardrail is never a capability grant / compound path.
      assert.notEqual(f.severity, 'critical', `${file}: ${f.id} must never be critical (an RCP grants nothing)`);
      assert.notEqual(f.severity, 'high', `${file}: ${f.id} is a protective guardrail, not a high-risk grant`);
      assert.equal(f.denyOnly, true, `${file}: ${f.id} is deny-only`);
      if (e.severities && e.severities[f.id]) {
        assert.equal(f.severity, e.severities[f.id], `${file}: ${f.id} severity`);
      }
      // The ceiling-not-grant + intersection caveat (Phase-13 immutable guardrail).
      if (e.statesCeilingNotGrant) {
        assert.match(f.limit, /ceiling/i, `${file}: ${f.id} must frame the finding as a ceiling`);
        assert.match(f.limit, /INTERSECTION/, `${file}: ${f.id} must state the intersection semantics`);
        assert.match(f.limit, /not\s+grant/i, `${file}: ${f.id} must state RCPs do not grant`);
        assert.match(f.limit, /not effective access/i, `${file}: ${f.id} must carry the capability-not-effective caveat`);
        assert.match(f.limit, /corresponding Allow/i, `${file}: ${f.id} must reference a corresponding Allow`);
        assert.match(f.limit, /must exist elsewhere/i, `${file}: ${f.id} must state that Allow must exist elsewhere`);
        assert.match(f.limit, /deny-only/i, `${file}: ${f.id} must state RCPs are deny-only`);
      }
    }

    // ZERO positive capability edges: the graph is empty by construction.
    if (e.zeroCapabilityEdges) {
      assert.equal(result.graph.edges.length, 0, `${file}: RCP guardrail must emit ZERO capability edges`);
      assert.equal(result.graph.nodes.length, 0, `${file}: RCP guardrail must emit ZERO graph nodes`);
      assert.equal(result.counts.edges, 0, `${file}: counts.edges is 0`);
    }
    if (e.noEscalation) {
      assert.ok(
        !result.findings.some((f) => ESC.has(f.id) || f.escalation),
        `${file}: no escalation findings under an RCP family`,
      );
    }

    // NO S3 permissions / public-access finding: a deny-only ceiling never
    // manufactures a resource grant from Principal "*" + s3:*.
    if (e.noPublicAccess) {
      assert.ok(
        !result.findings.some((f) => f.id === 'PUBLIC-ACCESS' || RESOURCE.has(f.id)),
        `${file}: an RCP guardrail must never emit a public-access / resource-grant finding`,
      );
    }
    if (Array.isArray(e.forbidFindingIds)) {
      const present = new Set(result.findings.map((f) => f.id));
      for (const forbidden of e.forbidFindingIds) {
        assert.ok(!present.has(forbidden), `${file}: forbidden finding id ${forbidden} must be absent`);
      }
    }

    // Guardrail kinds (confused-deputy / organization / general) in statement order.
    if (Array.isArray(e.guardrailKinds)) {
      const kinds = result.findings
        .filter((f) => f.id === 'RCP-GUARDRAIL')
        .sort((a, b) => a.statementIndex - b.statementIndex)
        .map((f) => f.guardrailKind);
      assert.deepEqual(kinds, e.guardrailKinds, `${file}: guardrail kinds`);
    }

    const primary = result.findings.find((f) => f.id === 'RCP-GUARDRAIL');
    assert.ok(primary, `${file}: an RCP-GUARDRAIL finding is present`);

    if (typeof e.confusedDeputy === 'boolean') {
      assert.equal(primary.confusedDeputy === true, e.confusedDeputy, `${file}: confusedDeputy flag`);
    }
    if (Array.isArray(e.orgScopeKeys)) {
      assert.deepEqual(primary.orgScopeKeys.slice().sort(), e.orgScopeKeys.slice().sort(), `${file}: org-scope keys preserved`);
    }
    if (typeof e.orgScopeNegatedIfExists === 'boolean') {
      assert.equal(primary.orgScopeNegatedIfExists, e.orgScopeNegatedIfExists, `${file}: negated-IfExists (fail-closed) org check`);
    }
    if (typeof e.targetsAwsServicePrincipals === 'boolean') {
      assert.equal(primary.targetsAwsServicePrincipals, e.targetsAwsServicePrincipals, `${file}: AWS-service-principal targeting`);
    }
    if (typeof e.sourceAccountPresenceRequired === 'boolean') {
      assert.equal(primary.sourceAccountPresenceRequired, e.sourceAccountPresenceRequired, `${file}: aws:SourceAccount presence gate`);
    }
    if (e.wildcardPrincipalSubject) {
      assert.equal(primary.wildcardPrincipalSubject, true, `${file}: wildcard Principal recorded as a subject, not a grant`);
    }

    // The three confused-deputy conditions are preserved TOGETHER as one guardrail
    // (interaction intact), never re-read as independent denies.
    if (Array.isArray(e.conditionOperatorsPreserved)) {
      const ops = Object.getOwnPropertyNames(primary.conditions || {});
      for (const op of e.conditionOperatorsPreserved) {
        assert.ok(ops.includes(op), `${file}: condition operator ${op} preserved on the finding`);
      }
    }
    if (Array.isArray(e.conditionKeysPreserved)) {
      const keys = [];
      for (const op of Object.getOwnPropertyNames(primary.conditions || {})) {
        for (const k of Object.getOwnPropertyNames(primary.conditions[op] || {})) keys.push(k);
      }
      for (const k of e.conditionKeysPreserved) {
        assert.ok(keys.includes(k), `${file}: condition key ${k} preserved on the finding`);
      }
    }
  }
});

test('analyze() is deterministic over the family-rcp corpus', () => {
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
// Test 52 - RCP confused-deputy guardrail: deny-only ceiling, no manufactured grant.
// ---------------------------------------------------------------------------

const RCP_52_BYTES = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Sid: 'EnforceServiceSourceOrganization',
    Effect: 'Deny',
    Principal: '*',
    Action: 's3:*',
    Resource: '*',
    Condition: {
      StringNotEqualsIfExists: { 'aws:SourceOrgID': 'o-exampleorgid' },
      Null: { 'aws:SourceAccount': 'false' },
      Bool: { 'aws:PrincipalIsAWSService': 'true' },
    },
  }],
});

test('test 52: RCP confused-deputy guardrail analyzed as a resource-control ceiling (no grant, no public access)', () => {
  const r = analyze(RCP_52_BYTES, { family: 'rcp', requireExplicitFamily: true });
  assert.equal(r.ok, true);
  assert.equal(r.coverage.blocked, false, 'explicit RCP selection is analyzed, not fail-closed');
  assert.equal(r.family, 'scp-rcp');
  assert.equal(r.graph.edges.length, 0, 'no positive capability edges from an RCP');
  assert.equal(r.graph.nodes.length, 0);
  assert.equal(r.findings.length, 1, 'one guardrail finding for the Deny statement');
  const g = r.findings[0];
  assert.equal(g.id, 'RCP-GUARDRAIL');
  assert.equal(g.guardrailKind, 'confused-deputy');
  assert.equal(g.severity, 'info', 'a protective guardrail, never high/critical');
  assert.equal(g.denyOnly, true);
  // No S3 permissions / public access reported.
  assert.ok(!r.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'no public-access finding');
  assert.equal(g.wildcardPrincipalSubject, true, 'Principal "*" recorded as subject, not a grant');
  assert.match(g.why, /NOT public access/i, 'explains the wildcard Principal is not public access');
  // The three conditions are preserved TOGETHER (interaction intact), not independent denies.
  assert.deepEqual(
    Object.getOwnPropertyNames(g.conditions).sort(),
    ['Bool', 'Null', 'StringNotEqualsIfExists'],
    'all three confused-deputy operators preserved on one finding',
  );
  assert.equal(g.conditions.StringNotEqualsIfExists['aws:SourceOrgID'], 'o-exampleorgid');
  assert.equal(g.conditions.Null['aws:SourceAccount'], 'false');
  assert.equal(g.conditions.Bool['aws:PrincipalIsAWSService'], 'true');
  assert.match(g.why, /logical AND|TOGETHER/i, 'frames the conditions as one guardrail, not independent denies');
  assert.equal(g.targetsAwsServicePrincipals, true);
  assert.equal(g.sourceAccountPresenceRequired, true);
  assert.equal(g.orgScopeNegatedIfExists, true, 'negated ...IfExists org check is fail-closed');
  // A corresponding Allow must exist elsewhere; RCPs are deny-only and never grant.
  assert.match(g.limit, /corresponding Allow/i);
  assert.match(g.limit, /must exist elsewhere/i);
  assert.match(g.limit, /deny-only/i);
  assert.match(g.limit, /not\s+grant/i);
});

// ---------------------------------------------------------------------------
// Iteration 2 / review finding F1 - operator POLARITY of the org-scope Deny.
//
// A confused-deputy / org-perimeter RCP is meant to use a NEGATED comparator
// (StringNotEqualsIfExists) so it denies UNLESS the request is from your org. If
// it instead uses a POSITIVE comparator (StringEquals), the Deny fires WHEN the
// org matches - it denies your OWN org and permits outsiders, the inverse of the
// intended guardrail (the classic StringEquals/StringNotEquals footgun). The
// evaluator must model that polarity, narrate the inverted effect, stop asserting
// confused-deputy "protection", and flag it as a misconfiguration hazard (like
// scp.js's over-broad-region hazard). The guardrail-not-grant invariant must hold.
// ---------------------------------------------------------------------------

const RCP_INVERTED_CD_BYTES = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Sid: 'EnforceServiceSourceOrganizationInverted',
    Effect: 'Deny',
    Principal: '*',
    Action: 's3:*',
    Resource: '*',
    Condition: {
      StringEquals: { 'aws:PrincipalOrgID': 'o-exampleorgid' },
      Bool: { 'aws:PrincipalIsAWSService': 'true' },
    },
  }],
});

test('F1: positive-operator org-scope Deny is flagged as an inverted-polarity hazard, not confused-deputy protection', () => {
  const r = analyze(RCP_INVERTED_CD_BYTES, { family: 'rcp', requireExplicitFamily: true });
  assert.equal(r.ok, true);
  assert.equal(r.coverage.blocked, false);
  assert.equal(r.family, 'scp-rcp');
  // Guardrail-not-grant invariant is UNCHANGED: deny-only, empty graph, no grant.
  assert.equal(r.graph.edges.length, 0, 'still zero capability edges');
  assert.equal(r.graph.nodes.length, 0);
  assert.equal(r.findings.length, 1);
  const g = r.findings[0];
  assert.equal(g.id, 'RCP-GUARDRAIL');
  assert.equal(g.denyOnly, true);
  assert.ok(!r.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'no public-access finding');
  // Polarity is recorded and surfaced as a misconfiguration hazard.
  assert.equal(g.hazard, true, 'inverted org-scope Deny raised as a hazard');
  assert.equal(g.orgScopePositiveOperator, true, 'positive operator polarity recorded');
  assert.equal(g.severity, 'medium', 'a likely misconfiguration is raised to medium (never high/critical)');
  assert.notEqual(g.severity, 'high');
  assert.notEqual(g.severity, 'critical');
  assert.equal(g.orgScopeNegatedIfExists, false, 'the org check is NOT negated-IfExists here');
  // Narration describes the INVERTED effect and must NOT assert the "deny unless
  // the org matches" clause or claim it implements confused-deputy protection.
  assert.match(g.title, /inverted org-scope Deny/i, 'title flags the inverted polarity');
  assert.match(g.why, /WHEN the source organization matches/i, 'narrates deny-when-match');
  assert.match(g.why, /INVERSE/i);
  assert.match(g.why, /MISCONFIGURATION/i);
  assert.doesNotMatch(g.why, /UNLESS the source organization matches/i, 'must NOT emit the inverted "unless matches" clause');
  assert.doesNotMatch(g.why, /implementing confused-deputy protection/i, 'must NOT assert confused-deputy protection for a positive-operator Deny');
  assert.match(g.remediation, /NEGATED comparator|StringNotEqualsIfExists/i, 'remediation points at the operator fix');
});

test('F1: inverted polarity on an organization-perimeter RCP (no service key) is also flagged', () => {
  const bytes = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'EnforceOrgPerimeterInverted',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: '*',
      Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-exampleorgid' } },
    }],
  });
  const r = analyze(bytes, { family: 'rcp', requireExplicitFamily: true });
  assert.equal(r.ok, true);
  assert.equal(r.graph.edges.length, 0);
  const g = r.findings[0];
  assert.equal(g.guardrailKind, 'organization');
  assert.equal(g.hazard, true);
  assert.equal(g.orgScopePositiveOperator, true);
  assert.equal(g.severity, 'medium');
  assert.match(g.why, /WHEN the request's source \/ principal organization matches/i);
  assert.match(g.why, /INVERSE/i);
  assert.doesNotMatch(g.why, /unless the request's source \/ principal organization matches/i);
});

test('F1 regression: a NEGATED org-scope Deny (test 52) still narrates "deny unless the org matches", no hazard', () => {
  const r = analyze(RCP_52_BYTES, { family: 'rcp', requireExplicitFamily: true });
  const g = r.findings[0];
  assert.equal(g.hazard, undefined, 'a correctly-negated guardrail is not a hazard');
  assert.equal(g.orgScopePositiveOperator, undefined, 'no positive-operator polarity on a negated Deny');
  assert.equal(g.severity, 'info');
  assert.match(g.why, /UNLESS the source organization matches/i, 'negated path keeps the correct "unless matches" clause');
  assert.match(g.why, /implementing confused-deputy protection/i, 'negated path still asserts confused-deputy protection');
  assert.doesNotMatch(g.why, /INVERSE|MISCONFIGURATION/i, 'no inverted-effect narration on a correct guardrail');
});

// ---------------------------------------------------------------------------
// Auto-detect still FAILS CLOSED on an RCP shape (IAM-1303 flips the auto path).
// Under auto-detect the RCP shape reads as a resource-based document and blocks
// with UNSUPPORTED_POLICY_FAMILY (detected=resource) - unchanged by IAM-1302.
// ---------------------------------------------------------------------------

test('auto-detect still blocks an RCP shape as a resource-based document (UNSUPPORTED_POLICY_FAMILY)', () => {
  const r = analyze(RCP_52_BYTES);
  assert.equal(r.coverage.blocked, true, 'auto-detect fails closed on an RCP shape');
  assert.equal(r.coverage.detected, 'resource', 'auto-detect reads the RCP shape as resource-based (unchanged)');
  assert.ok(
    r.coverage.blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY),
    'UNSUPPORTED_POLICY_FAMILY under auto-detect',
  );
  assert.equal(r.findings.length, 0);
  assert.equal(r.graph.edges.length, 0);
});

// ---------------------------------------------------------------------------
// An ordinary resource GRANT (Principal-bearing, but no org-scope guardrail
// signal, and/or an Allow) selected as RCP fails closed - never relabeled as a
// deny-only ceiling (no manufactured guardrail from a real grant).
// ---------------------------------------------------------------------------

test('selecting RCP on an ordinary resource grant fails closed (no relabeling)', () => {
  const bytes = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'PublicRead',
      Effect: 'Allow',
      Principal: '*',
      Action: 's3:GetObject',
      Resource: 'arn:aws:s3:::public-downloads/*',
    }],
  });
  const r = analyze(bytes, { family: 'rcp', requireExplicitFamily: true });
  assert.equal(r.coverage.blocked, true, 'an Allow resource grant is not an RCP guardrail shape');
  assert.equal(r.findings.length, 0, 'no findings - never relabeled as a ceiling');
  assert.equal(r.graph.edges.length, 0);
  assert.ok(r.coverage.blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY));
});

test('selecting RCP on a Principal-bearing Deny with NO org-scope signal fails closed', () => {
  // A deny-only, Principal-bearing resource statement WITHOUT any org-scope
  // guardrail key is not distinguishable as an RCP guardrail - it fails closed
  // rather than being relabeled a ceiling.
  const bytes = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'DenyInsecureTransport',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: 'arn:aws:s3:::example/*',
      Condition: { Bool: { 'aws:SecureTransport': 'false' } },
    }],
  });
  const r = analyze(bytes, { family: 'rcp', requireExplicitFamily: true });
  assert.equal(r.coverage.blocked, true, 'no org-scope signal -> not an RCP guardrail shape');
  assert.equal(r.findings.length, 0);
  assert.equal(r.graph.edges.length, 0);
  assert.ok(r.coverage.blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY));
});

// ---------------------------------------------------------------------------
// The RCP evaluator on its own: a pass-through Allow (RCPFullAWSAccess default)
// contributes no finding; only Deny guardrails do.
// ---------------------------------------------------------------------------

test('analyzeRcp ignores an RCPFullAWSAccess pass-through Allow and emits only Deny guardrails', () => {
  const m = modelFromText(JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'RCPFullAWSAccess', Effect: 'Allow', Principal: '*', Action: '*', Resource: '*' },
      {
        Sid: 'EnforceServiceSourceOrganization',
        Effect: 'Deny',
        Principal: '*',
        Action: 's3:*',
        Resource: '*',
        Condition: {
          StringNotEqualsIfExists: { 'aws:SourceOrgID': 'o-exampleorgid' },
          Null: { 'aws:SourceAccount': 'false' },
          Bool: { 'aws:PrincipalIsAWSService': 'true' },
        },
      },
    ],
  }));
  assert.equal(m.ok, true);
  const res = analyzeRcp(m.model);
  assert.equal(res.ok, true);
  assert.equal(res.findings.length, 1, 'the pass-through Allow contributes no finding');
  assert.equal(res.findings[0].id, 'RCP-GUARDRAIL');
  assert.equal(res.findings[0].guardrailKind, 'confused-deputy');
});

// ---------------------------------------------------------------------------
// Exports record the SCP/RCP family + agree on status across surfaces.
// ---------------------------------------------------------------------------

test('exports record the scp-rcp family and agree on status', () => {
  const r = analyze(RCP_52_BYTES, { family: 'rcp', requireExplicitFamily: true });
  const json = JSON.parse(toJSON(r));
  const md = toMarkdown(r);
  assert.equal(json.family, 'scp-rcp', 'JSON family');
  assert.equal(json.selectedFamily, 'scp-rcp', 'JSON selectedFamily');
  assert.equal(json.status, analysisStatus(r), 'JSON status agrees');
  assert.equal(json.graph.edges.length, 0, 'no capability edges in the export');
  assert.match(md, /- Policy family: scp-rcp/, 'Markdown policy family');
  assert.match(md, /- Selected family: scp-rcp/, 'Markdown selected family');
});
