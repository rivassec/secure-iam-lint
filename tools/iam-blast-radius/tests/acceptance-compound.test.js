// IAM-703: compound-path AND/OR semantics + standalone techniques
// (acceptance suite tests 2, 3, 5). Runs on node's built-in runner: `node --test`.
//
// The defect this story closes: escalation findings carried a FLAT requiredActions
// AND-list that (a) implied unrelated alternative techniques were all jointly
// required, and (b) listed catalog actions the analyzed policy did not actually
// grant (test 5: CREDENTIAL-CREATION listing CreateLoginProfile/UpdateLoginProfile
// when only CreateAccessKey was present).
//
// The fix: every escalation finding exposes explicit AND/OR prerequisites -
//   prerequisites.anyOf  = alternative TECHNIQUES (holding any one suffices)
//   technique.allOf      = grant groups jointly required by that technique
//   group.anyOf          = interchangeable actions satisfying that group
// and requiredActions is GROUNDED (only actions the policy grants). For Lambda,
// the standalone lambda:UpdateFunctionCode technique (Path B) is its own path and
// does NOT require iam:PassRole. Remediation must not recommend adding
// iam:PassedToService when it is already present.
//
// All assertions are VERIFIED AGAINST analyze() OUTPUT, not just the fixtures'
// declared expectations (the story's acceptance criterion: "no requiredActions
// entry references an action absent from the analyzed policy ... verified against
// analyze() output").

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { actionGrants, hasPolicyVariable } from '../../../content/tools/iam-blast-radius/engine/escalation.js';

const here = dirname(fileURLToPath(import.meta.url));
const acceptanceDir = join(here, '..', 'fixtures', 'acceptance');

function loadAcceptanceFixtures() {
  return readdirSync(acceptanceDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `acceptance/${f}`, data: JSON.parse(readFileSync(join(acceptanceDir, f), 'utf8')) }));
}

// Does statement `stmt` grant action token `action`? Mirrors the provenance
// test's helper: an action is granted when it matches a granted pattern (either
// direction under casefold) or is preserved by an Allow+NotAction complement.
function statementGrants(stmt, action) {
  if (!stmt) return false;
  const a = String(action);
  for (const p of stmt.actions) {
    if (hasPolicyVariable(p)) continue;
    if (actionGrants(p, a) || actionGrants(a, p)) return true;
  }
  if (stmt.notActions.length > 0) {
    const excluded = stmt.notActions.some((p) => !hasPolicyVariable(p) && actionGrants(p, a));
    if (!excluded) return true;
  }
  return false;
}

// Is `action` granted by ANY statement in the analyzed model?
function modelGrants(model, action) {
  return model.statements.some((s) => statementGrants(s, action));
}

function lowerSet(arr) {
  return new Set((Array.isArray(arr) ? arr : []).map((s) => String(s).toLowerCase()));
}

function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}

// Collect every action token that appears anywhere in a finding's prerequisites
// (requiredActions + every technique.allOf group.anyOf leaf).
function prerequisiteActions(f) {
  const out = [];
  const esc = f.escalation || {};
  for (const a of (esc.requiredActions || [])) out.push(a);
  const pr = esc.prerequisites;
  if (pr && Array.isArray(pr.anyOf)) {
    for (const tech of pr.anyOf) {
      for (const g of (tech.allOf || [])) {
        for (const a of (g.anyOf || [])) out.push(a);
      }
    }
  }
  return out;
}

// Assert prerequisites is well-formed AND/OR structure (never a flat list).
function assertPrereqShape(f, ctx) {
  const pr = f.escalation && f.escalation.prerequisites;
  assert.ok(pr && Array.isArray(pr.anyOf) && pr.anyOf.length > 0,
    `${ctx}: prerequisites.anyOf must be a non-empty array of techniques`);
  for (const tech of pr.anyOf) {
    assert.ok(typeof tech.technique === 'string' && tech.technique.length > 0, `${ctx}: technique id`);
    assert.equal(typeof tech.requiresPassRole, 'boolean', `${ctx}: technique.requiresPassRole boolean`);
    assert.ok(Array.isArray(tech.allOf) && tech.allOf.length > 0, `${ctx}: technique.allOf non-empty`);
    for (const g of tech.allOf) {
      assert.ok(Array.isArray(g.anyOf) && g.anyOf.length > 0, `${ctx}: group.anyOf non-empty`);
    }
    // If a technique claims requiresPassRole=true, iam:PassRole must be one of its
    // groups; if false, iam:PassRole must NOT appear (a PassRole-free path may not
    // secretly depend on PassRole, and vice versa).
    const legs = tech.allOf.map((g) => lowerSet(g.anyOf));
    const anyGroupHasPassRole = legs.some((s) => s.has('iam:passrole'));
    if (tech.requiresPassRole) {
      assert.ok(anyGroupHasPassRole, `${ctx}: technique ${tech.technique} claims requiresPassRole but has no iam:PassRole group`);
    } else {
      assert.ok(!anyGroupHasPassRole, `${ctx}: technique ${tech.technique} is PassRole-free but lists iam:PassRole`);
    }
  }
}

// ---------------------------------------------------------------------------
// Generic grounding invariant: for EVERY escalation finding of EVERY acceptance
// fixture, no prerequisite action (requiredActions or any anyOf leaf) references
// an action the analyzed policy does not grant. Verified against analyze() model.
// ---------------------------------------------------------------------------

for (const { file, data } of loadAcceptanceFixtures()) {
  test(`${file}: escalation prerequisites are grounded + well-formed (IAM-703)`, () => {
    const text = typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
    const result = analyze(text);
    if (!result.ok) return; // blocked/invalid fixtures carry no escalation findings

    for (const f of result.findings) {
      if (!f.escalation) continue; // rule-catalog findings have no escalation block
      const fctx = `${file}/${f.id}`;
      assert.ok(Array.isArray(f.escalation.requiredActions) && f.escalation.requiredActions.length > 0,
        `${fctx}: requiredActions must be a non-empty array`);
      assertPrereqShape(f, fctx);
      for (const a of prerequisiteActions(f)) {
        assert.ok(modelGrants(result.model, a),
          `${fctx}: prerequisite action "${a}" is NOT granted by the analyzed policy - requiredActions/prerequisites must be grounded`);
      }
    }
  });
}

// ---------------------------------------------------------------------------
// Per-fixture compoundExpect assertions (tests 2, 3, 5 specifics).
// ---------------------------------------------------------------------------

for (const { file, data } of loadAcceptanceFixtures()) {
  const ce = data.compoundExpect;
  if (!ce) continue;

  test(`${file}: compound AND/OR semantics match expectations (IAM-703)`, () => {
    const text = typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
    const result = analyze(text);
    assert.equal(result.ok, true, `${file}: analyze() must succeed`);

    const ids = new Set(result.findings.map((f) => f.id));
    for (const forbid of (ce.forbidFindings || [])) {
      assert.ok(!ids.has(forbid), `${file}: finding ${forbid} must NOT be produced`);
    }

    const focus = result.findings.find((f) => f.id === ce.focusFindingId);
    assert.ok(focus, `${file}: expected focus finding ${ce.focusFindingId}`);
    assert.ok(focus.escalation, `${file}: focus finding must carry escalation enrichment`);

    // requiredActions is EXACTLY the grounded set (no more, no less).
    if (Array.isArray(ce.requiredActions)) {
      assert.ok(setsEqual(lowerSet(focus.escalation.requiredActions), lowerSet(ce.requiredActions)),
        `${file}: requiredActions expected [${ce.requiredActions.join(', ')}]; got [${focus.escalation.requiredActions.join(', ')}]`);
    }

    // No forbidden action may appear anywhere in the prerequisites (test 5: the
    // absent CreateLoginProfile/UpdateLoginProfile must never surface).
    if (Array.isArray(ce.forbidPrerequisiteActions)) {
      const all = lowerSet(prerequisiteActions(focus));
      for (const bad of ce.forbidPrerequisiteActions) {
        assert.ok(!all.has(String(bad).toLowerCase()),
          `${file}: prerequisites must NOT list absent action "${bad}"`);
      }
    }

    // Exact set of techniques (anyOf), each with its allOf groups and PassRole flag.
    if (Array.isArray(ce.techniques)) {
      const got = focus.escalation.prerequisites.anyOf;
      assert.equal(got.length, ce.techniques.length,
        `${file}: expected ${ce.techniques.length} technique(s); got ${got.length}`);
      for (const wantT of ce.techniques) {
        const gotT = got.find((t) => t.technique === wantT.technique);
        assert.ok(gotT, `${file}: expected technique "${wantT.technique}"`);
        assert.equal(gotT.requiresPassRole, wantT.requiresPassRole,
          `${file}: technique ${wantT.technique} requiresPassRole`);
        if (Array.isArray(wantT.allOf)) {
          assert.equal(gotT.allOf.length, wantT.allOf.length,
            `${file}: technique ${wantT.technique} allOf group count`);
          for (let i = 0; i < wantT.allOf.length; i++) {
            const gotGroup = gotT.allOf.find((g) => setsEqual(lowerSet(g.anyOf), lowerSet(wantT.allOf[i])));
            assert.ok(gotGroup,
              `${file}: technique ${wantT.technique} missing allOf group [${wantT.allOf[i].join(', ')}]`);
          }
        }
        if (typeof wantT.noteIncludes === 'string') {
          assert.ok(typeof gotT.note === 'string' && gotT.note.includes(wantT.noteIncludes),
            `${file}: technique ${wantT.technique} note must include "${wantT.noteIncludes}"; got "${gotT.note}"`);
        }
      }
    }

    // Standalone PassRole-free technique (test 3, Path B) is present and truly
    // PassRole-free, with exactly its grounded action(s).
    if (ce.standalonePassRoleFreeTechnique) {
      const want = ce.standalonePassRoleFreeTechnique;
      const gotT = focus.escalation.prerequisites.anyOf.find((t) => t.technique === want.technique);
      assert.ok(gotT, `${file}: expected standalone technique "${want.technique}"`);
      assert.equal(gotT.requiresPassRole, false, `${file}: standalone technique must be PassRole-free`);
      const leaves = [];
      for (const g of gotT.allOf) for (const a of g.anyOf) leaves.push(a);
      assert.ok(setsEqual(lowerSet(leaves), lowerSet(want.actions)),
        `${file}: standalone technique actions expected [${want.actions.join(', ')}]; got [${leaves.join(', ')}]`);
      assert.ok(!lowerSet(leaves).has('iam:passrole'),
        `${file}: standalone technique must not depend on iam:PassRole`);
    }

    // Remediation wording (test 2): when PassedToService is already pinned, the
    // remediation must not recommend adding it, and should acknowledge it exists.
    if (typeof ce.remediationForbids === 'string') {
      assert.ok(!focus.remediation.includes(ce.remediationForbids),
        `${file}: remediation must NOT contain "${ce.remediationForbids}" (condition already present)`);
    }
    if (typeof ce.remediationIncludes === 'string') {
      assert.ok(focus.remediation.includes(ce.remediationIncludes),
        `${file}: remediation must acknowledge the present condition ("${ce.remediationIncludes}")`);
    }
    if (typeof ce.whyIncludes === 'string') {
      assert.ok(focus.why.includes(ce.whyIncludes),
        `${file}: why must include "${ce.whyIncludes}"`);
    }
  });
}
