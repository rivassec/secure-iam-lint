// S2-passrole-allstmts — PassRole viability is a statement-ORDER-independent,
// ALL-STATEMENTS property.
//
// Regression for a HIGH fail-open (threat-model T8): detectPassRolePaths selected
// ONE iam:PassRole statement per service by lowest index and then ran the T91
// account-viability check on ONLY that statement. When a cross-account DECOY
// statement sorted BEFORE a viable same-account grant, the whole compound path was
// demoted critical->medium (PASSROLE_CROSS_ACCOUNT_INCOMPATIBLE) and slipped under
// the 'high' exit gate to exit 0 CLEAN, HIDING a viable same-account PassRole in a
// different statement. Reordering the byte-identical statements flipped exit 0<->1.
//
// The fix makes viability an ALL-STATEMENTS property (mirroring the existing
// all-statements DENY reasoning): a viable same-account grant in ANY candidate
// statement keeps the path critical, so the verdict is independent of statement
// order. This test drives the SAME statements through the real engine (analyze())
// AND the CLI fail-closed adapter (scan()) in every enumerated ordering and asserts
// critical + exit 1 for each - so a re-sort can never reopen the fail-open.
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
    'passrole-cross-account-decoy-vs-same-account-order-invariance.json'),
  'utf8',
));

// Resolve a fixture ordering token to its concrete statement object.
function statementFor(token) {
  if (token === 'run') return fixture.runStatement;
  const s = fixture.passStatements[token];
  assert.ok(s, `fixture ordering references unknown statement token "${token}"`);
  return s;
}

function policyText(ordering) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: ordering.map(statementFor),
  });
}

const want = fixture.expect.everyOrdering;
const ctx = fixture.context;

// Enumerated orderings must actually exercise BOTH relative positions of the decoy
// vs. the viable grant (otherwise the regression proves nothing).
test('fixture enumerates orderings with the decoy BOTH before and after the viable grant', () => {
  const rel = fixture.orderings.map((o) => {
    const oo = o.filter((t) => t !== 'run');
    return oo.indexOf('decoyCrossAccount') < oo.indexOf('viableSameAccount') ? 'decoy-first' : 'viable-first';
  });
  assert.ok(rel.includes('decoy-first'), 'need at least one decoy-first ordering');
  assert.ok(rel.includes('viable-first'), 'need at least one viable-first ordering');
});

for (const ordering of fixture.orderings) {
  const label = ordering.join(' -> ');

  // Engine level: the finding stays critical and points at the viable same-account
  // role, with NO cross-account demotion, regardless of statement order.
  test(`analyze(): PassRole stays critical + viable regardless of order [${label}]`, () => {
    const res = analyze(policyText(ordering), {
      subjectAccount: ctx.subjectAccount,
      partition: ctx.partition,
    });
    assert.equal(res.ok, true, 'analyze() ok');
    const f = (res.findings || []).find((x) => x.id === want.findingId);
    assert.ok(f, `${want.findingId} must be present (never demoted-then-dropped)`);
    assert.equal(f.severity, want.severity, `severity for ordering [${label}]`);
    const esc = f.escalation || {};
    assert.deepEqual(esc.targetResources || [], want.targetResources,
      `targetResources must point at the viable same-account role [${label}]`);
    assert.ok(
      !(esc.warningCodes || []).includes(want.mustNotHaveWarningCode),
      `must NOT carry ${want.mustNotHaveWarningCode} when a viable same-account grant exists [${label}]`,
    );
  });

  // Adapter level: the load-bearing exit-code contract. A viable same-account
  // PassRole must gate at exit 1 (FINDINGS) under the default 'high' threshold in
  // EVERY ordering - never exit 0 CLEAN.
  test(`scan(): exit 1 (never a clean 0) regardless of order [${label}]`, () => {
    const r = scan({ text: policyText(ordering), family: 'identity', subjectAccount: ctx.subjectAccount, partition: ctx.partition });
    assert.equal(r.exitCode, want.exitCode, `exit code for ordering [${label}]`);
    assert.equal(r.exitCode, EXIT.FINDINGS);
    assert.notEqual(r.exitCode, EXIT.CLEAN, 'a viable same-account PassRole must never report CLEAN');
  });
}

// Determinism: the SAME ordering yields byte-identical findings JSON across runs.
test('analyze(): deterministic findings for a fixed ordering', () => {
  const text = policyText(fixture.orderings[0]);
  const opts = { subjectAccount: ctx.subjectAccount, partition: ctx.partition };
  const a = JSON.stringify(analyze(text, opts).findings);
  const b = JSON.stringify(analyze(text, opts).findings);
  assert.equal(a, b);
});
