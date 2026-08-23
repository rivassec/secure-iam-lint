// IAM-705: dedup wildcard-action flood + collapse overlapping IAM-admin findings
// + severity reconciliation (acceptance suite tests 12, 4, 5). Runs on node's
// built-in runner: `node --test`.
//
// Three defects this story closes, asserted here against analyze() OUTPUT (not
// just the fixtures' declared expectations):
//
//  1. iam:* flood (test 12). iam:* expanded into 7 near-duplicate top-level rows
//     (WILDCARD-ACTION, WILDCARD-RESOURCE, DIRECT-IAM-ADMIN + every specific IAM
//     primitive). It must now collapse to ONE primary broad-IAM-administration
//     finding with the primitives + wildcard folded in as subsumed techniques /
//     risk factors (reusing the test-23 subsumption mechanism). Severity stays
//     consistent with the single documented IAM-102 scoring model, and the
//     rule-catalog version is surfaced on the result.
//
//  2. Generic/specific double-fire (tests 4, 5). A statement that grants a
//     concrete IAM primitive tripped BOTH the specific escalation (POLICY-VERSION
//     / CREDENTIAL-CREATION / ...) AND the generic DIRECT-IAM-ADMIN rule. The
//     generic must be folded into the specific as a risk factor, never reported as
//     its own duplicate row.
//
//  3. Spurious credential edge (test 5). iam:CreateAccessKey drew a
//     can-modify(policy:self) edge as if it modified a policy. CreateAccessKey is
//     credential creation / impersonation, not policy modification: its only edge
//     is the credential-target impersonation edge.
//
// Fixtures under fixtures/acceptance/ carry a `dedupExpect` block:
//   primaryId          the id that must survive as the single primary row
//   primaryCount       how many top-level rows carry primaryId (default 1)
//   subsumesIds[]      ids that must be attached to the primary's subsumed[]
//   notTopLevelIds[]   ids that must NOT appear as their own top-level row
//   riskFactors[]      {key,present} entries required on the primary's checklist
//   expectSeverity     the primary's severity (single documented scoring model)
//   requireCatalogVersion  the result must surface a non-empty rule-catalog version
//   forbidGraphEdges[] {from?,to,type} edges that must be ABSENT from the graph
//   requireGraphEdges[] {from?,to,type} edges that must be PRESENT in the graph

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const acceptanceDir = join(here, '..', 'fixtures', 'acceptance');

function fixtureText(fx) {
  return typeof fx.policyRaw === 'string' ? fx.policyRaw : JSON.stringify(fx.policy);
}

function loadFixtures() {
  return readdirSync(acceptanceDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `acceptance/${f}`, data: JSON.parse(readFileSync(join(acceptanceDir, f), 'utf8')) }));
}

function edgeMatches(edge, want) {
  if (want.type && edge.type !== want.type) return false;
  if (want.to && edge.to !== want.to) return false;
  if (want.from && edge.from !== want.from) return false;
  return true;
}

let checked = 0;
for (const { file, data } of loadFixtures()) {
  const d = data.dedupExpect;
  if (!d) continue;
  test(`fixture ${file}: IAM-705 dedup collapses the overlap`, () => {
    checked++;
    const result = analyze(fixtureText(data));
    assert.equal(result.ok, true, `${file}: expected a valid analysis`);

    // Rule-catalog version surfaced (test 12: do not expand against an unversioned
    // list without exposing the version).
    if (d.requireCatalogVersion) {
      assert.ok(
        typeof result.catalogVersion === 'string' && result.catalogVersion.length > 0,
        `${file}: result must surface a non-empty rule-catalog version`,
      );
    }

    // Exactly the expected number of primary rows.
    const primaries = result.findings.filter((f) => f.id === d.primaryId);
    assert.equal(
      primaries.length,
      typeof d.primaryCount === 'number' ? d.primaryCount : 1,
      `${file}: expected ${d.primaryCount || 1} top-level ${d.primaryId} row(s)`,
    );
    const primary = primaries[0];
    assert.ok(primary, `${file}: primary ${d.primaryId} must be present`);

    // Severity stays consistent with the single documented scoring model.
    if (d.expectSeverity) {
      assert.equal(primary.severity, d.expectSeverity, `${file}: primary severity`);
    }

    // Every folded id is attached to the primary's subsumed[] AND is not a
    // separate top-level row (nothing lost, no double-fire).
    const subsumedIds = new Set((primary.subsumed || []).map((s) => s.id));
    for (const id of d.subsumesIds || []) {
      assert.ok(subsumedIds.has(id), `${file}: ${id} must be folded into ${d.primaryId}.subsumed`);
    }
    for (const id of d.notTopLevelIds || []) {
      assert.ok(
        !result.findings.some((f) => f.id === id),
        `${file}: ${id} must NOT appear as its own top-level row (de-flooded)`,
      );
    }

    // The primary exposes the expected risk-factor checklist entries.
    for (const want of d.riskFactors || []) {
      const rf = (primary.riskFactors || []).find((x) => x.key === want.key);
      assert.ok(rf, `${file}: risk factor ${want.key} expected on ${d.primaryId}`);
      assert.equal(rf.present, want.present, `${file}: risk factor ${want.key} present=${want.present}`);
    }

    // Subsumed views preserve the prose (nothing lost when folded away).
    for (const s of (primary.subsumed || [])) {
      assert.equal(typeof s.why, 'string', `${file}: subsumed ${s.id} keeps why`);
      assert.equal(typeof s.limit, 'string', `${file}: subsumed ${s.id} keeps limit`);
      assert.equal(typeof s.remediation, 'string', `${file}: subsumed ${s.id} keeps remediation`);
    }

    // Graph-edge corrections (test 5: no spurious policy:self edge for a
    // credential-creation statement; the credential-target edge is present).
    const edges = (result.graph && result.graph.edges) || [];
    for (const want of d.forbidGraphEdges || []) {
      assert.ok(
        !edges.some((e) => edgeMatches(e, want)),
        `${file}: graph must NOT contain edge ${JSON.stringify(want)}`,
      );
    }
    for (const want of d.requireGraphEdges || []) {
      assert.ok(
        edges.some((e) => edgeMatches(e, want)),
        `${file}: graph must contain edge ${JSON.stringify(want)}`,
      );
    }
  });
}

// Coverage guard: the dedup harness must actually exercise the IAM-705 cases
// (tests 12, 4, 5). Fail (not skip) if the fixtures carrying dedupExpect vanish.
test('IAM-705 dedup fixtures are present and exercised (tests 12, 4, 5)', () => {
  const withDedup = loadFixtures().filter(({ data }) => data.dedupExpect);
  const acceptanceTests = new Set(withDedup.map(({ data }) => data.acceptanceTest));
  for (const n of [12, 4, 5]) {
    assert.ok(acceptanceTests.has(n), `expected a dedupExpect fixture for acceptance test ${n}`);
  }
  assert.ok(checked >= 3, `expected at least three dedup fixtures exercised, ran ${checked}`);
});
