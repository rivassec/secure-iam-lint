// IAM-1301 (Phase 13): SCP ceiling / guardrail family semantics.
//
// docs/acceptance-suite.md test 19 (SCP deny guardrail) + docs/acceptance-suite-2.md
// test 43 (negated IfExists in a Deny) + an SCP allow-list ceiling case. Runs on
// node's built-in runner: `node --test`.
//
// PHASE-13 IMMUTABLE GUARDRAIL: an SCP is a permission CEILING / GUARDRAIL, NEVER
// a grant. Under an EXPLICIT SCP selection the engine routes to the family-aware
// SCP evaluator (engine/scp.js) instead of the identity rules/escalation engine:
//   - An SCP Allow  -> a MAXIMUM-PERMISSIONS ENVELOPE (a ceiling). Report the
//     breadth, emit ZERO positive capability edges, NO escalation findings, and
//     state the INTERSECTION / ceiling-not-grant semantics.
//   - An SCP Deny   -> a GUARDRAIL (region / organization / generic). A NotAction
//     list is a CARVE-OUT (excludedActions), NEVER reported as allowed. A negated
//     ...IfExists region Deny with no global-service carve-out is a potentially
//     over-broad regional-Deny HAZARD.
// The exported family is scp-rcp (the org-control family token); auto-detect still
// FAILS CLOSED on a deny-guardrail SCP shape (the auto-detect flip is IAM-1303).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { analyzeScp, SCP_IDS } from '../../../content/tools/iam-blast-radius/engine/scp.js';
import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import { ESCALATION_IDS } from '../../../content/tools/iam-blast-radius/engine/escalation.js';
import { COVERAGE_CODES } from '../../../content/tools/iam-blast-radius/engine/family.js';
import { toJSON, toMarkdown, analysisStatus } from '../../../content/tools/iam-blast-radius/engine/report.js';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', 'fixtures', 'family-scp');

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

const FIXTURES = readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));

const ESC = new Set(ESCALATION_IDS);
const SCP = new Set(SCP_IDS);

// ---------------------------------------------------------------------------
// Fixture-driven contract (suite-1 test 19, suite-2 test 43, allow-list ceiling).
// ---------------------------------------------------------------------------

test('family-scp/ corpus is present and well-formed', () => {
  assert.ok(FIXTURES.length >= 2, `expected >=2 fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy`);
    assert.ok(data.options && typeof data.options === 'object', `${file}: has analyze options`);
    assert.ok(data.scpExpect && typeof data.scpExpect === 'object', `${file}: has scpExpect`);
  }
});

test('analyze() matches every family-scp fixture contract', () => {
  for (const { file, data } of FIXTURES) {
    const e = data.scpExpect;
    const result = analyze(fixtureText(data), data.options);

    assert.equal(result.ok, e.ok, `${file}: ok`);
    const cov = result.coverage;
    assert.ok(cov && typeof cov === 'object', `${file}: coverage present`);
    assert.equal(cov.blocked, e.blocked, `${file}: blocked`);
    assert.equal(result.family, e.family, `${file}: result.family reflects the SCP selection`);
    assert.equal(cov.override, e.override, `${file}: override recorded`);
    assert.equal(cov.supported, true, `${file}: SCP family is supported (ceiling evaluator)`);
    assert.equal(analysisStatus(result), e.status, `${file}: analysis status`);

    // Finding ids match, and every finding is an SCP ceiling/guardrail id (never
    // an identity/escalation id).
    assert.deepEqual(
      result.findings.map((f) => f.id).sort(),
      e.findingIds.slice().sort(),
      `${file}: finding ids`,
    );
    for (const f of result.findings) {
      assert.ok(SCP.has(f.id), `${file}: ${f.id} must be an SCP ceiling/guardrail id`);
      assert.ok(!ESC.has(f.id), `${file}: ${f.id} must NOT be an escalation id`);
      assert.equal(f.escalation, undefined, `${file}: ${f.id} must carry no escalation enrichment`);
      // A ceiling/guardrail is never a compound escalation path.
      assert.notEqual(f.severity, 'critical', `${file}: ${f.id} must never be critical (a ceiling grants nothing)`);
      if (e.severities && e.severities[f.id]) {
        assert.equal(f.severity, e.severities[f.id], `${file}: ${f.id} severity`);
      }
      // The ceiling-not-grant + intersection caveat (Phase-13 immutable guardrail).
      if (e.statesCeilingNotGrant) {
        assert.match(f.limit, /ceiling/i, `${file}: ${f.id} must frame the finding as a ceiling`);
        assert.match(f.limit, /INTERSECTION/, `${file}: ${f.id} must state the intersection semantics`);
        assert.match(f.limit, /not\s+grant/i, `${file}: ${f.id} must state SCPs do not grant`);
        assert.match(f.limit, /not effective access/i, `${file}: ${f.id} must carry the capability-not-effective caveat`);
      }
    }

    // ZERO positive capability edges: the graph is empty by construction.
    if (e.zeroCapabilityEdges) {
      assert.equal(result.graph.edges.length, 0, `${file}: SCP ceiling/guardrail must emit ZERO capability edges`);
      assert.equal(result.graph.nodes.length, 0, `${file}: SCP ceiling/guardrail must emit ZERO graph nodes`);
      assert.equal(result.counts.edges, 0, `${file}: counts.edges is 0`);
    }
    if (e.noEscalation) {
      assert.ok(
        !result.findings.some((f) => ESC.has(f.id) || f.escalation),
        `${file}: no escalation findings under an SCP family`,
      );
    }

    // Guardrail kinds (region / organization / general) in statement order.
    if (Array.isArray(e.guardrailKinds)) {
      const kinds = result.findings
        .filter((f) => f.id === 'SCP-GUARDRAIL')
        .sort((a, b) => a.statementIndex - b.statementIndex)
        .map((f) => f.guardrailKind);
      assert.deepEqual(kinds, e.guardrailKinds, `${file}: guardrail kinds`);
    }

    // A NotAction carve-out is surfaced as excludedActions and NEVER as the
    // finding's covered/allowed actions (docs/scp-rcp-semantics.md section 4).
    if (e.excludedActionsPresent) {
      const withExcluded = result.findings.filter((f) => Array.isArray(f.excludedActions) && f.excludedActions.length > 0);
      assert.ok(withExcluded.length > 0, `${file}: a carve-out finding carries excludedActions`);
      if (Array.isArray(e.excludedActionsNeverAllowed)) {
        for (const f of withExcluded) {
          for (const ex of e.excludedActionsNeverAllowed) {
            if (f.excludedActions.includes(ex)) {
              // The excluded (carve-out) action must not also appear as an allowed/
              // covered action on the same finding - it is exempt, not granted.
              assert.ok(
                !f.actions.includes(ex),
                `${file}: carve-out ${ex} must never be reported as a covered/allowed action`,
              );
            }
          }
        }
      }
    }

    // Region guardrail evidence: the allowed-Region set is surfaced (not inverted
    // into a fabricated capability).
    if (Array.isArray(e.allowedRegions)) {
      const region = result.findings.find((f) => f.guardrailKind === 'region');
      assert.ok(region, `${file}: a region guardrail finding is present`);
      assert.deepEqual(region.allowedRegions.slice().sort(), e.allowedRegions.slice().sort(), `${file}: allowed regions`);
    }

    // The negated-IfExists over-broad regional-Deny hazard (test 43).
    if (e.hazard) {
      const hz = result.findings.find((f) => f.hazard === true);
      assert.ok(hz, `${file}: the over-broad regional-Deny hazard is flagged`);
      assert.equal(hz.guardrailKind, 'region', `${file}: hazard is a region guardrail`);
      assert.equal(hz.negatedIfExists, true, `${file}: hazard notes the negated ...IfExists`);
      if (e.hazardWhyMatches) {
        assert.match(hz.why, new RegExp(e.hazardWhyMatches, 'i'), `${file}: hazard why explains the over-broad Deny`);
      }
      // Framed as a denial/guardrail that grants nothing (never inverted into a
      // grant inside or outside the regions).
      assert.match(hz.why, /denies/i, `${file}: hazard is framed as a denial`);
      assert.match(hz.why, /never grants|removes actions from the ceiling/i, `${file}: hazard states it grants nothing`);
    }
    if (e.noHazard) {
      assert.ok(!result.findings.some((f) => f.hazard === true), `${file}: no over-broad hazard on a well-formed guardrail`);
    }
  }
});

test('analyze() is deterministic over the family-scp corpus', () => {
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
// Test 19 - SCP deny guardrail: NotAction is never reported as allowed.
// ---------------------------------------------------------------------------

const SCP_19_BYTES = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Sid: 'DenyLeavingOrganization', Effect: 'Deny', Action: 'organizations:LeaveOrganization', Resource: '*' },
    {
      Sid: 'DenyUnapprovedRegions',
      Effect: 'Deny',
      NotAction: ['iam:*', 'route53:*', 'support:*'],
      Resource: '*',
      Condition: { StringNotEquals: { 'aws:RequestedRegion': ['us-east-1', 'us-west-2'] } },
    },
  ],
});

test('test 19: SCP deny guardrails reported as ceilings, NotAction carve-out never allowed', () => {
  const r = analyze(SCP_19_BYTES, { family: 'scp', requireExplicitFamily: true });
  assert.equal(r.ok, true);
  assert.equal(r.coverage.blocked, false, 'explicit SCP selection is analyzed, not fail-closed');
  assert.equal(r.family, 'scp-rcp');
  assert.equal(r.graph.edges.length, 0, 'no positive capability edges from an SCP');
  assert.equal(r.findings.length, 2, 'one guardrail finding per Deny statement');
  assert.ok(r.findings.every((f) => f.id === 'SCP-GUARDRAIL'));
  // The region guardrail's global-service NotAction list is a carve-out, not a grant.
  const region = r.findings.find((f) => f.guardrailKind === 'region');
  assert.deepEqual(region.excludedActions, ['iam:*', 'route53:*', 'support:*']);
  for (const ex of region.excludedActions) {
    assert.ok(!region.actions.includes(ex), `carve-out ${ex} is not a covered/allowed action`);
  }
  // The org-departure deny is an organization guardrail.
  const org = r.findings.find((f) => f.guardrailKind === 'organization');
  assert.ok(org, 'organization-departure guardrail present');
  assert.match(org.why, /organization/i);
  // Every finding states SCPs set ceilings and do not grant.
  for (const f of r.findings) {
    assert.match(f.limit, /do NOT grant permissions|do not grant permissions/i);
  }
});

// ---------------------------------------------------------------------------
// Test 43 - negated IfExists in a Deny: potentially over-broad regional Deny.
// ---------------------------------------------------------------------------

const SCP_43_BYTES = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'DenyOutsideApprovedRegions',
      Effect: 'Deny',
      Action: '*',
      Resource: '*',
      Condition: { StringNotEqualsIfExists: { 'aws:RequestedRegion': ['us-east-1', 'us-west-2'] } },
    },
  ],
});

test('test 43: negated ...IfExists region Deny flagged as a potentially over-broad guardrail (not a grant)', () => {
  const r = analyze(SCP_43_BYTES, { family: 'scp', requireExplicitFamily: true });
  assert.equal(r.ok, true);
  assert.equal(r.coverage.blocked, false);
  assert.equal(r.family, 'scp-rcp');
  assert.equal(r.findings.length, 1);
  const g = r.findings[0];
  assert.equal(g.id, 'SCP-GUARDRAIL');
  assert.equal(g.guardrailKind, 'region');
  assert.equal(g.severity, 'medium', 'the over-broad regional Deny is a visible hazard');
  assert.equal(g.hazard, true);
  assert.equal(g.negatedIfExists, true);
  assert.match(g.why, /absent|omit|missing/i, 'explains that an absent key is still denied');
  assert.match(g.why, /global/i, 'notes global-service impact');
  // Framed as a denial/guardrail, and the ceiling-not-grant caveat is present.
  assert.match(g.why, /denies/i, 'framed as a denial, not a grant');
  assert.match(g.limit, /not\s+grant/i, 'states SCPs do not grant');
  assert.equal(r.graph.edges.length, 0);
});

// ---------------------------------------------------------------------------
// Auto-detect still FAILS CLOSED on a deny-guardrail SCP shape (IAM-1303 flips
// the auto path). The explicit SCP selection is what unlocks the evaluator.
// ---------------------------------------------------------------------------

test('auto-detect still blocks a deny-guardrail SCP shape (UNSUPPORTED_SCP_SHAPE)', () => {
  for (const bytes of [SCP_19_BYTES, SCP_43_BYTES]) {
    const r = analyze(bytes);
    assert.equal(r.coverage.blocked, true, 'auto-detect fails closed on an SCP shape');
    assert.ok(
      r.coverage.blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_SCP_SHAPE),
      'UNSUPPORTED_SCP_SHAPE under auto-detect',
    );
    assert.equal(r.findings.length, 0);
    assert.equal(r.graph.edges.length, 0);
  }
});

// ---------------------------------------------------------------------------
// IAM-1302 iteration-3 regression: the CANONICAL mixed SCP shape.
//
// The most common real-world SCP carries the AWS managed FullAWSAccess Allow
// (Action */Resource *) ALONGSIDE its Deny guardrails. That mixed Allow+Deny shape
// was previously NOT recognized as an SCP (the recognizer required every statement
// to be a Deny), so under AUTO-DETECT it fell through to the identity family and
// the escalation engine manufactured CRITICAL can-* capability grants a CEILING can
// never establish. The recognizer now detects the mixed FullAWSAccess + org/region
// Deny shape, so:
//   - AUTO-DETECT fails closed (UNSUPPORTED_SCP_SHAPE): zero findings, zero edges,
//     and NEVER an escalation / capability finding.
//   - An EXPLICIT SCP selection analyzes it as a ceiling/guardrail (SCP-CEILING for
//     the FullAWSAccess envelope + SCP-GUARDRAIL for the region Deny), still zero
//     capability edges.
// ---------------------------------------------------------------------------

const MIXED_FULLAWSACCESS_REGION_DENY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Sid: 'FullAWSAccess', Effect: 'Allow', Action: '*', Resource: '*' },
    {
      Sid: 'DenyRegion',
      Effect: 'Deny',
      Action: '*',
      Resource: '*',
      Condition: { StringNotEqualsIfExists: { 'aws:RequestedRegion': 'us-east-1' } },
    },
  ],
});

// Identity finding-id prefixes that must NEVER appear for an SCP-shaped document in
// ANY mode (the blocking-criterion families: escalation/wildcard/credential/etc.).
const IDENTITY_GRANT_ID = /^(ASSUME|PASSROLE|CREDENTIAL|POLICY-VERSION|PUT-INLINE|TRUST-POLICY|ATTACH-POLICY|WILDCARD)/;

test('IAM-1302: a mixed FullAWSAccess + region-Deny SCP FAILS CLOSED under auto-detect (never manufactures a grant)', () => {
  const r = analyze(MIXED_FULLAWSACCESS_REGION_DENY);
  assert.equal(r.coverage.blocked, true, 'auto-detect fails closed on the mixed SCP shape');
  assert.ok(
    r.coverage.blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_SCP_SHAPE),
    'UNSUPPORTED_SCP_SHAPE, not an identity default',
  );
  assert.equal(r.findings.length, 0, 'no findings - never analyzed as identity');
  assert.equal(r.graph.edges.length, 0, 'zero capability edges');
  assert.equal(r.graph.nodes.length, 0, 'zero graph nodes');
  assert.ok(!r.findings.some((f) => IDENTITY_GRANT_ID.test(f.id)), 'no escalation/capability grant finding');
  assert.ok(!r.findings.some((f) => ESC.has(f.id) || f.escalation), 'no escalation enrichment');
});

test('IAM-1302: the same mixed SCP under an explicit SCP selection is a ceiling + guardrail (no grant, no edges)', () => {
  const r = analyze(MIXED_FULLAWSACCESS_REGION_DENY, { family: 'scp', requireExplicitFamily: true });
  assert.equal(r.ok, true);
  assert.equal(r.coverage.blocked, false, 'explicit SCP selection analyzes the mixed shape');
  assert.equal(r.family, 'scp-rcp');
  assert.deepEqual(r.findings.map((f) => f.id).sort(), ['SCP-CEILING', 'SCP-GUARDRAIL']);
  assert.ok(r.findings.every((f) => SCP.has(f.id)), 'only SCP ceiling/guardrail ids');
  assert.ok(r.findings.every((f) => f.severity !== 'critical'), 'a ceiling is never critical');
  assert.ok(!r.findings.some((f) => IDENTITY_GRANT_ID.test(f.id)), 'no identity grant finding');
  // The FullAWSAccess Allow is a maximum-permissions ENVELOPE, not a grant.
  const ceiling = r.findings.find((f) => f.id === 'SCP-CEILING');
  assert.ok(ceiling, 'FullAWSAccess Allow reported as an SCP ceiling');
  assert.match(ceiling.limit, /ceiling/i);
  assert.match(ceiling.limit, /INTERSECTION/);
  assert.match(ceiling.limit, /not\s+grant/i);
  // Zero positive capability edges from the whole ceiling/guardrail.
  assert.equal(r.graph.edges.length, 0);
  assert.equal(r.graph.nodes.length, 0);
});

test('IAM-1302: broadening the SCP recognizer does NOT sweep up identity policies', () => {
  // A plain full-admin identity policy (Allow */* with NO Deny guardrail) stays
  // identity - it must still fire WILDCARD-ACTION and the usual escalation rules.
  const fullAdmin = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
  });
  const rAdmin = analyze(fullAdmin);
  assert.equal(rAdmin.family, 'identity', 'full-admin identity is not an SCP shape');
  assert.equal(rAdmin.coverage.blocked, false);
  assert.ok(rAdmin.findings.some((f) => f.id === 'WILDCARD-ACTION'), 'still analyzed as an identity grant');

  // Allow */* PLUS a signal-less Deny (a NotAction deny with no org/region signal)
  // is identity-ambiguous, NOT an SCP guardrail - it must stay identity (this is the
  // shape of the protected graph/rule-edge-notaction-deny-narrows-full-star fixture).
  const notActionDenyNarrows = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: '*', Resource: '*' },
      { Effect: 'Deny', NotAction: 'iam:CreateAccessKey', Resource: '*' },
    ],
  });
  const rNarrow = analyze(notActionDenyNarrows);
  assert.equal(rNarrow.family, 'identity', 'a signal-less Deny does not make it an SCP');
  assert.equal(rNarrow.coverage.blocked, false);
});

// ---------------------------------------------------------------------------
// IAM-1302: an RCP (Principal-bearing) shape is now analyzed by the family-aware
// RCP GUARDRAIL evaluator (engine/rcp.js), NOT the SCP ceiling evaluator. The
// scp/rcp synonyms both canonicalize to the scp-rcp family, so an RCP-shaped
// document under EITHER selection routes to the RCP evaluator (deny-only resource
// guardrail), never mis-analyzed as an SCP and never as an identity/resource grant.
// (Detailed RCP assertions live in tests/phase13-rcp.test.js.)
// ---------------------------------------------------------------------------

test('an RCP (Principal-bearing) shape under an scp-rcp selection routes to the RCP guardrail evaluator (not the SCP ceiling, not fail-closed)', () => {
  const rcpBytes = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'EnforceServiceSourceOrganization',
      Effect: 'Deny',
      Principal: '*',
      Action: 's3:*',
      Resource: '*',
      Condition: { StringNotEqualsIfExists: { 'aws:SourceOrgID': 'o-exampleorgid' } },
    }],
  });
  const r = analyze(rcpBytes, { family: 'scp', requireExplicitFamily: true });
  assert.equal(r.coverage.blocked, false, 'a Principal-bearing (RCP) shape is analyzed as an RCP guardrail');
  assert.equal(r.family, 'scp-rcp');
  assert.equal(r.findings.length, 1, 'one RCP guardrail finding for the Deny');
  assert.equal(r.findings[0].id, 'RCP-GUARDRAIL', 'analyzed by the RCP evaluator, never as an SCP ceiling/guardrail');
  assert.ok(!SCP.has(r.findings[0].id), 'not an SCP finding id');
  // Deny-only resource ceiling: no positive capability edges, no S3/public-access.
  assert.equal(r.graph.edges.length, 0);
  assert.ok(!r.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'no public-access finding manufactured from an RCP');
});

// ---------------------------------------------------------------------------
// An allow-list SCP is structurally identical to an identity policy, so it CANNOT
// be shape-detected and selecting SCP on such a document fails closed (preserving
// suite-3 test 69: an SCP ceiling is never conjured from an arbitrary identity
// grant). The SCP-CEILING (Allow-envelope) branch is still modeled - an SCP Allow
// is a maximum-permissions envelope, never a grant - and is exercised directly on
// the evaluator so the ceiling semantics are covered without relabeling identity.
// ---------------------------------------------------------------------------

test('selecting SCP on an identity-shaped allow-list document fails closed (no relabeling)', () => {
  const bytes = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'OrgCeilingExceptIam', Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }],
  });
  const r = analyze(bytes, { family: 'scp', requireExplicitFamily: true });
  assert.equal(r.coverage.blocked, true, 'an allow-list (identity-shaped) doc is not an SCP guardrail shape');
  assert.equal(r.findings.length, 0, 'no findings - never relabeled as a ceiling');
  assert.equal(r.graph.edges.length, 0);
  assert.ok(r.coverage.blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY));
});

test('analyzeScp models an SCP Allow statement as a maximum-permissions CEILING (never a grant)', () => {
  const m = modelFromText(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'OrgCeilingExceptIam', Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }],
  }));
  assert.equal(m.ok, true);
  const res = analyzeScp(m.model);
  assert.equal(res.ok, true);
  assert.equal(res.findings.length, 1);
  const f = res.findings[0];
  assert.equal(f.id, 'SCP-CEILING');
  assert.equal(f.severity, 'high', 'a wildcard/complement SCP Allow is a wide ceiling');
  assert.notEqual(f.severity, 'critical', 'a ceiling is never a compound escalation path');
  // NotAction is a carve-out (excluded), NEVER the allowed set.
  assert.deepEqual(f.excludedActions, ['iam:*']);
  assert.ok(!f.actions.includes('iam:*'), 'the carve-out is not reported as an allowed action');
  // Ceiling-not-grant + intersection semantics stated.
  assert.match(f.limit, /ceiling/i);
  assert.match(f.limit, /INTERSECTION/);
  assert.match(f.limit, /not\s+grant/i);
  assert.match(f.why, /does NOT grant|never grant/i);
  // No positive-capability leakage: an SCP finding carries no escalation/capability edge data.
  assert.equal(f.escalation, undefined);
});

// ---------------------------------------------------------------------------
// Exports record the SCP family + agree on status across surfaces.
// ---------------------------------------------------------------------------

test('exports record the SCP family and agree on status', () => {
  const r = analyze(SCP_43_BYTES, { family: 'scp', requireExplicitFamily: true });
  const json = JSON.parse(toJSON(r));
  const md = toMarkdown(r);
  assert.equal(json.family, 'scp-rcp', 'JSON family');
  assert.equal(json.selectedFamily, 'scp-rcp', 'JSON selectedFamily');
  assert.equal(json.status, analysisStatus(r), 'JSON status agrees');
  assert.equal(json.graph.edges.length, 0, 'no capability edges in the export');
  assert.match(md, /- Policy family: scp-rcp/, 'Markdown policy family');
  assert.match(md, /- Selected family: scp-rcp/, 'Markdown selected family');
});
