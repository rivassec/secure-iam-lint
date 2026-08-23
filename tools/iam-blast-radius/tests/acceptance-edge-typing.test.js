// IAM-702: graph edge semantic typing + deny must not emit capability edges
// (acceptance suite tests 8, 24; also guards the test-1 edge-provenance case).
// Runs on node's built-in runner: `node --test`.
//
// Two defects this story closes, asserted here against analyze() OUTPUT (not just
// the fixtures' declared expectations):
//
//  1. Generic can-write catch-all. A broad-resource grant that mixes unlike
//     actions (a read, a decrypt, a delegation, a destroy) was aggregated into a
//     single `can-write` edge, reusing one edge semantic for many capabilities
//     (cross-test invariant 7 violation). Now each capability draws its own typed
//     edge: ec2:Describe* -> can-read, kms:Decrypt -> can-decrypt, iam:PassRole ->
//     can-pass (delegation), s3:DeleteObject -> can-destroy; and iam:PassRole
//     alone never creates a can-execute-as execution path.
//
//  2. Deny leak. A fully explicitly-denied action still emitted positive
//     capability edges (can-write AND can-destroy). A suppressed grant must emit
//     NO positive capability edge and must not count in risk totals - only the
//     informational `denies` edge remains ("denies are not grants", invariant 5).
//
// Fixtures under fixtures/acceptance/ carry an `edgeTypingExpect` block:
//   expectEdges[]        {from,to,type,actions} present; edge evidence attributes
//                        EXACTLY `actions` (case-insensitive) and nothing else.
//   forbidEdges[]        {from,to,type} must be ABSENT.
//   onlyDeniesEdges      every edge in the graph must be type `denies` (no
//                        positive capability edge survives).
//   noExecutionPath      no can-execute-as edge exists (PassRole alone must not
//                        create an execution path).
//   noSemanticReuse      no single edge attributes actions of more than one
//                        capability class (catches re-aggregation).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const acceptanceDir = join(here, '..', 'fixtures', 'acceptance');

function loadFixtures() {
  return readdirSync(acceptanceDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `acceptance/${f}`, data: JSON.parse(readFileSync(join(acceptanceDir, f), 'utf8')) }));
}

function lowerSet(arr) {
  return new Set((Array.isArray(arr) ? arr : []).map((s) => String(s).toLowerCase()));
}

function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}

// The capability an action belongs to (mirrors engine/graph.js classifyCapability;
// kept local so the test independently pins the intended classification).
const READ_VERB = /^(get|list|describe|view|lookup|search|head|read|batchget)/i;
const DESTRUCTIVE_VERB = /^(delete|terminate|remove|destroy|purge|deregister)/i;
function capabilityClass(action) {
  const lower = String(action).toLowerCase();
  if (lower === 'iam:passrole') return 'delegation';
  if (lower === 'kms:decrypt') return 'decrypt';
  const idx = lower.indexOf(':');
  const verb = idx === -1 ? '' : lower.slice(idx + 1);
  if (DESTRUCTIVE_VERB.test(verb)) return 'destroy';
  if (READ_VERB.test(verb)) return 'read';
  return 'write';
}

// The set of actions an edge's evidence attributes to it (lowercased).
function edgeAttributedActions(edge) {
  const s = new Set();
  for (const ev of edge.evidence) for (const a of ev.actions) s.add(String(a).toLowerCase());
  return s;
}

function findEdge(graph, want) {
  return graph.edges.find((e) => e.from === want.from && e.to === want.to && e.type === want.type);
}

for (const { file, data } of loadFixtures()) {
  const ete = data.edgeTypingExpect;
  if (!ete) continue;
  test(`${file}: graph edge semantic typing + deny-no-leak (IAM-702)`, () => {
    const text = typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
    const result = analyze(text);
    assert.equal(result.ok, true, `${file}: analyze() must succeed`);
    const graph = result.graph;

    // Every positive capability edge is dropped for a fully-suppressed grant.
    if (ete.onlyDeniesEdges) {
      for (const e of graph.edges) {
        assert.equal(e.type, 'denies',
          `${file}: fully-denied policy must emit only denies edges; found a ${e.type} edge to ${e.to}`);
      }
    }

    // iam:PassRole alone must not manufacture an execution path.
    if (ete.noExecutionPath) {
      assert.ok(!graph.edges.some((e) => e.type === 'can-execute-as'),
        `${file}: iam:PassRole alone must not create a can-execute-as execution path`);
    }

    // No edge aggregates actions of more than one capability class.
    if (ete.noSemanticReuse) {
      for (const e of graph.edges) {
        if (e.type === 'denies') continue; // deny edges legitimately list what they block
        const classes = new Set([...edgeAttributedActions(e)].map(capabilityClass));
        assert.ok(classes.size <= 1,
          `${file}: edge ${e.type} ${e.from}->${e.to} aggregates unlike capabilities [${[...classes].join(', ')}] - no semantic edge reuse (invariant 7)`);
      }
    }

    for (const want of (ete.expectEdges || [])) {
      const e = findEdge(graph, want);
      assert.ok(e, `${file}: expected a ${want.type} edge ${want.from} -> ${want.to}`);
      if (Array.isArray(want.actions)) {
        assert.ok(setsEqual(edgeAttributedActions(e), lowerSet(want.actions)),
          `${file}: ${want.type} edge ${want.from}->${want.to} must attribute exactly [${want.actions.join(', ')}]; got [${[...edgeAttributedActions(e)].join(', ')}]`);
      }
    }

    for (const want of (ete.forbidEdges || [])) {
      assert.ok(!findEdge(graph, want),
        `${file}: forbidden edge ${want.type} ${want.from}->${want.to} must NOT exist (no generic aggregation / no suppressed-grant edge)`);
    }
  });
}
