// IAM-701: cross-statement evidence provenance (acceptance suite tests 1, 4, 11).
// Runs on node's built-in runner: `node --test`.
//
// The provenance defect this story closes: a compound finding's detailed
// evidence[] was already correct per-statement, but (a) the finding HEADER
// (statementSid + actions) attributed the whole combined action list to a single
// Sid, and (b) graph-edge evidence attributed a combined action list to one
// statementIndex. Contributed actions were also carried as a comma-joined STRING
// where a statement contributed several.
//
// The fix: every finding carries explicit per-statement provenance
// (contributingStatements[]) so no action is attributed to a statement that does
// not grant it, graph transition edges keep their own per-statement evidence, and
// contributed actions are ARRAYS everywhere (findings, escalation evidence,
// graph-edge evidence) - never a comma-joined string.
//
// These assertions are VERIFIED AGAINST analyze() OUTPUT (not just the fixtures'
// declared expectations), per the story's acceptance criterion.

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

// Does statement `stmt` (normalized model statement) grant concrete/pattern
// action token `action`? Mirrors how the engine builds evidence: an action rides
// in evidence because it is one of the statement's granted patterns (case-
// insensitive glob), OR because it is preserved by an Allow+NotAction complement.
function statementGrants(stmt, action) {
  if (!stmt) return false;
  const a = String(action);
  for (const p of stmt.actions) {
    if (hasPolicyVariable(p)) continue;
    // Either the granted pattern matches the token, or the token itself is a
    // (possibly wildcard) pattern equal to a granted pattern under casefold.
    if (actionGrants(p, a) || actionGrants(a, p)) return true;
  }
  if (stmt.notActions.length > 0) {
    const excluded = stmt.notActions.some((p) => !hasPolicyVariable(p) && actionGrants(p, a));
    if (!excluded) return true; // NotAction-Allow grants everything except the listed
  }
  return false;
}

function lowerSet(arr) {
  return new Set((Array.isArray(arr) ? arr : []).map((s) => String(s).toLowerCase()));
}

function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}

// No contributed-actions value may be a comma-joined string masquerading as one
// action (the pre-IAM-701 defect). Every element must be a single action token.
function assertNoCommaJoined(actions, ctx) {
  assert.ok(Array.isArray(actions), `${ctx}: actions must be an array, not a string`);
  for (const a of actions) {
    assert.equal(typeof a, 'string', `${ctx}: action element must be a string`);
    assert.ok(!a.includes(','), `${ctx}: action "${a}" is comma-joined; contributed actions must be an array of single tokens`);
  }
}

// The generic provenance invariant, applied to EVERY finding of EVERY acceptance
// fixture: no action is attributed to a statement that does not grant it, in the
// header, the escalation evidence[], or the graph-edge evidence.
function assertProvenance(result, ctx) {
  assert.equal(result.ok, true, `${ctx}: analyze() must succeed`);
  const stmtByIndex = new Map();
  for (const s of result.model.statements) stmtByIndex.set(s.index, s);

  for (const f of result.findings) {
    const fctx = `${ctx}/${f.id}`;
    assert.ok(typeof f.statementSid === 'string' && f.statementSid.length > 0, `${fctx}: statementSid`);
    assert.ok(Array.isArray(f.actions) && f.actions.length > 0, `${fctx}: header actions non-empty array`);
    assertNoCommaJoined(f.actions, `${fctx}: header actions`);

    // Header provenance. Prefer the explicit per-statement breakdown; fall back
    // to the scalar (statementIndex -> actions) pair for single-statement rule
    // findings that do not carry contributingStatements.
    const cs = Array.isArray(f.contributingStatements) ? f.contributingStatements : null;
    if (cs && cs.length > 0) {
      const union = new Set();
      for (const entry of cs) {
        const ectx = `${fctx}: contributingStatements[${entry.statementIndex}]`;
        const stmt = stmtByIndex.get(entry.statementIndex);
        assert.ok(stmt, `${ectx}: references a real statement`);
        assertNoCommaJoined(entry.actions, ectx);
        assert.ok(entry.actions.length > 0, `${ectx}: entry has at least one action`);
        for (const a of entry.actions) {
          assert.ok(statementGrants(stmt, a), `${ectx}: action "${a}" is NOT granted by statement ${entry.statementIndex} (${entry.statementSid}) - provenance defect`);
          union.add(String(a).toLowerCase());
        }
      }
      // Nothing lost / nothing invented: the per-statement union must equal the
      // header's combined action set.
      assert.ok(setsEqual(union, lowerSet(f.actions)),
        `${fctx}: contributingStatements actions must union to exactly the header actions`);
    } else if (typeof f.statementIndex === 'number') {
      const stmt = stmtByIndex.get(f.statementIndex);
      if (stmt) {
        for (const a of f.actions) {
          assert.ok(statementGrants(stmt, a), `${fctx}: header action "${a}" is NOT granted by its statement ${f.statementIndex}`);
        }
      }
    }

    // Escalation evidence[] records (present on escalation findings).
    for (const ev of (Array.isArray(f.evidence) ? f.evidence : [])) {
      const ectx = `${fctx}: evidence@${ev.statementIndex}(${ev.role})`;
      assertNoCommaJoined(ev.actions, ectx);
      assert.ok(!('action' in ev), `${ectx}: legacy singular "action" field must be gone (use actions[])`);
      const stmt = stmtByIndex.get(ev.statementIndex);
      assert.ok(stmt, `${ectx}: references a real statement`);
      for (const a of ev.actions) {
        assert.ok(statementGrants(stmt, a), `${ectx}: action "${a}" not granted by statement ${ev.statementIndex}`);
      }
    }
  }

  // Graph-edge evidence: every record's actions are an array and are all granted
  // by the statement the record names.
  for (const e of result.graph.edges) {
    for (const ev of e.evidence) {
      const ectx = `${ctx}: edge ${e.type} ${e.from}->${e.to} evidence@${ev.statementIndex}`;
      assertNoCommaJoined(ev.actions, ectx);
      if (typeof ev.statementIndex === 'number') {
        const stmt = stmtByIndex.get(ev.statementIndex);
        // Deny pseudo-edges reference model statements too; only assert for
        // statements that exist in the model (all of them here).
        if (stmt) {
          for (const a of ev.actions) {
            assert.ok(statementGrants(stmt, a), `${ectx}: action "${a}" not granted by statement ${ev.statementIndex} - graph-edge provenance defect`);
          }
        }
      }
    }
  }
}

// Match a graph edge by from/to/type and assert its statementIndex + the actions
// its evidence attributes to that statement.
function assertGraphEdge(result, want, ctx) {
  const e = result.graph.edges.find((x) => x.from === want.from && x.to === want.to && x.type === want.type);
  assert.ok(e, `${ctx}: expected a ${want.type} edge ${want.from} -> ${want.to}`);
  if (typeof want.statementIndex === 'number') {
    assert.equal(e.statementIndex, want.statementIndex, `${ctx}: ${want.type} edge anchored on statement ${want.statementIndex}`);
  }
  // The edge's evidence must attribute EXACTLY the expected actions to the
  // expected statement, and nothing else.
  const attributed = new Set();
  for (const ev of e.evidence) for (const a of ev.actions) attributed.add(String(a).toLowerCase());
  assert.ok(setsEqual(attributed, lowerSet(want.actions)),
    `${ctx}: ${want.type} edge evidence must attribute exactly [${want.actions.join(', ')}]; got [${[...attributed].join(', ')}]`);
}

// ---------------------------------------------------------------------------
// Per-fixture: analyze() output satisfies the generic provenance invariant AND
// the fixture's specific provenanceExpect block.
// ---------------------------------------------------------------------------

for (const { file, data } of loadAcceptanceFixtures()) {
  test(`${file}: cross-statement provenance is correct (IAM-701)`, () => {
    const text = typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
    const result = analyze(text);
    // IAM-707: fixtures for hard validation failures (acceptance tests 22A/22B)
    // return ok:false with no findings/graph - there is no provenance to check.
    // The provenance invariant is vacuous for a blocked/invalid analysis; the
    // fail-closed behavior itself is asserted by the acceptance-suite harness.
    if (!result.ok) return;
    assertProvenance(result, file);

    const pe = data.provenanceExpect;
    if (!pe) return;

    const focus = result.findings.find((f) => f.id === pe.focusFindingId);
    assert.ok(focus, `${file}: expected focus finding ${pe.focusFindingId}`);

    // Cross-statement vs single-statement classification is explicit and checked
    // against analyze() output (test 11 MUST stay single-statement; test 1 MUST
    // be cross-statement).
    const nStatements = Array.isArray(focus.contributingStatements) ? focus.contributingStatements.length : 1;
    if (pe.crossStatement === true) {
      assert.ok(nStatements > 1, `${file}: ${pe.focusFindingId} must span multiple statements`);
    } else if (pe.crossStatement === false) {
      assert.equal(nStatements, 1, `${file}: ${pe.focusFindingId} must be a single-statement finding (both actions legitimately share one Sid)`);
    }

    // Exact per-statement provenance the fixture declares.
    if (Array.isArray(pe.contributingStatements)) {
      assert.equal(focus.contributingStatements.length, pe.contributingStatements.length,
        `${file}: contributingStatements count`);
      for (const want of pe.contributingStatements) {
        const got = focus.contributingStatements.find((c) => c.statementIndex === want.statementIndex);
        assert.ok(got, `${file}: contributingStatements missing statement ${want.statementIndex}`);
        assert.equal(got.statementSid, want.statementSid, `${file}: statement ${want.statementIndex} Sid`);
        assert.ok(setsEqual(lowerSet(got.actions), lowerSet(want.actions)),
          `${file}: statement ${want.statementIndex} actions expected [${want.actions.join(', ')}]; got [${got.actions.join(', ')}]`);
      }
    }

    // Exact graph-edge provenance the fixture declares (test 1: the transition
    // edges retain original per-statement evidence objects).
    for (const want of (pe.graphEdges || [])) {
      assertGraphEdge(result, want, file);
    }
  });
}
