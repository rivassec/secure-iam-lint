// S2-passrole-allstmts (iteration 5) — a DEMOTED PassRole path must never HIDE a
// co-located higher-severity broad-resource grant, in ANY statement order.
//
// Regression for a HIGH, order-dependent CLI fail-open (threat-model T8). correlate.js
// folds a same-service WILDCARD-RESOURCE (high) INTO the compound PassRole path as a
// `subsumed` sub-entry and, historically, never raised the primary's gating severity.
// That is safe only while the compound path is at least as severe as what it swallows.
// Once the T91/S2 cross-account/partition viability check DEMOTES the path
// critical->medium (or an ECS staging path high->low), the subsumed HIGH grant dropped
// beneath the 'high' exit gate and scan() reported exit 0 CLEAN on a policy carrying a
// genuine HIGH over-broad-resource grant. Because the exec statement was selected by
// lowest INDEX, reordering the byte-content-identical statements swapped which exec the
// path consumed and flipped exit 0<->1.
//
// The fix closes the CLASS on two axes:
//   1. correlate.js — a subsumption may never lower the effective gating severity below
//      the severity of what it folds away: a subordinate that OUTRANKS the (post-demotion)
//      primary stays an independent top-level row so its own severity keeps gating.
//   2. escalation.js — exec-statement selection prefers the BROADEST resource scope by
//      content (not lowest index), so which exec the path consumes is order-invariant.
//
// This test drives the SAME statements through the real engine (analyze()) AND the CLI
// fail-closed adapter (scan()) in every enumerated ordering and asserts, for each:
//   - exit 1 (never a clean 0),
//   - a top-level WILDCARD-RESOURCE/high row is PRESENT (never hidden in subsumed[]),
//   - the PassRole path is still correctly demoted (its documented post-demotion severity).
// A control asserts the broad grant ALONE is a genuine HIGH (exit 1), proving the row the
// demotion must not swallow is real - not a false positive minted by this test.
//
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(
  join(here, '..', 'fixtures', 'order-invariance',
    'passrole-demoted-must-not-hide-broad-resource.json'),
  'utf8',
));

const ctx = fixture.context;
const opts = { subjectAccount: ctx.subjectAccount, partition: ctx.partition };

function policyText(statements) {
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}

function topLevelWildcardResource(findings) {
  return (findings || []).find((f) => f.id === 'WILDCARD-RESOURCE');
}

function passFinding(findings, passId) {
  return (findings || []).find((f) => f.id === passId);
}

for (const c of fixture.cases) {
  const stmtFor = (token) => {
    const s = c.statements[token];
    assert.ok(s, `case "${c.label}" references unknown statement token "${token}"`);
    return s;
  };

  // Control: the broad grant ALONE is a genuine HIGH WILDCARD-RESOURCE at exit 1.
  // This is what the demoted PassRole path must never be allowed to hide.
  test(`[${c.label}] control: the broad grant ALONE is a genuine HIGH (exit 1)`, () => {
    const text = policyText([stmtFor(c.controlBroadOnly)]);
    const res = analyze(text, opts);
    assert.equal(res.ok, true);
    const wr = topLevelWildcardResource(res.findings);
    assert.ok(wr, 'the broad grant fires WILDCARD-RESOURCE on its own');
    assert.equal(wr.severity, 'high');
    const r = scan({ text, family: 'identity', ...opts });
    assert.equal(r.exitCode, EXIT.FINDINGS, 'the broad grant alone gates at exit 1');
  });

  // Sanity: the orderings actually exercise BOTH relative positions of the broad
  // exec vs. the PassRole statement (otherwise the regression proves nothing about
  // exec-selection order-invariance).
  test(`[${c.label}] orderings place the broad exec both before AND after the pass grant`, () => {
    const rel = c.orderings.map((o) => (o.indexOf('broad') < o.indexOf('pass') ? 'broad-first' : 'pass-first'));
    assert.ok(rel.includes('broad-first'), 'need a broad-first ordering');
    assert.ok(rel.includes('pass-first'), 'need a pass-first ordering');
  });

  for (const ordering of c.orderings) {
    const label = ordering.join(' -> ');
    const text = () => policyText(ordering.map(stmtFor));

    // Engine level: the HIGH broad-resource grant is a top-level row (NOT buried in a
    // demoted primary's subsumed[]), and the PassRole path is correctly demoted.
    test(`[${c.label}] analyze(): HIGH broad-resource stays top-level + PassRole demoted [${label}]`, () => {
      const res = analyze(text(), opts);
      assert.equal(res.ok, true, 'analyze() ok');
      const wr = topLevelWildcardResource(res.findings);
      assert.ok(wr, `WILDCARD-RESOURCE must be a top-level row, never hidden by the demoted path [${label}]`);
      assert.equal(wr.severity, 'high');
      const pass = passFinding(res.findings, c.passId);
      assert.ok(pass, `${c.passId} present [${label}]`);
      assert.equal(pass.severity, c.passSeverity, `PassRole path stays demoted to ${c.passSeverity} [${label}]`);
      // The HIGH broad-resource row must not be tucked inside the demoted path's subsumed[].
      const buried = (pass.subsumed || []).some((s) => s.id === 'WILDCARD-RESOURCE' && s.severity === 'high');
      assert.equal(buried, false, `the HIGH broad-resource grant must NOT be subsumed under the demoted path [${label}]`);
    });

    // Adapter level: the load-bearing exit-code contract - exit 1 in EVERY order.
    test(`[${c.label}] scan(): exit 1 (never a clean 0) regardless of order [${label}]`, () => {
      const r = scan({ text: text(), family: 'identity', ...opts });
      assert.equal(r.exitCode, EXIT.FINDINGS, `exit code for ordering [${label}]`);
      assert.notEqual(r.exitCode, EXIT.CLEAN, 'a genuine HIGH grant must never report CLEAN');
      assert.ok(r.blockingCount >= 1, 'at least one at/above-threshold finding gates the run');
    });
  }
}

// Determinism: a fixed ordering yields byte-identical findings JSON across runs.
test('analyze(): deterministic findings for a fixed ordering', () => {
  const c = fixture.cases[0];
  const text = policyText(c.orderings[0].map((t) => c.statements[t]));
  const a = JSON.stringify(analyze(text, opts).findings);
  const b = JSON.stringify(analyze(text, opts).findings);
  assert.equal(a, b);
});
