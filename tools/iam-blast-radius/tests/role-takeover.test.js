// IAM-902 (Phase 9): role-takeover chain correlation (modify-then-assume, no
// iam:PassRole). Runs on node's built-in runner: `node --test`.
//
// A permission-grant primitive (iam:PutRolePolicy / iam:AttachRolePolicy) AND
// iam:UpdateAssumeRolePolicy AND sts:AssumeRole, all on the SAME concrete role,
// correlate into ONE critical ROLE-TAKEOVER finding. These tests drive the REAL
// pipeline (analyze()) and assert:
//   - the compound fires with severity `critical` and needs no iam:PassRole;
//   - per-statement evidence is preserved (no action attributed to a statement
//     that does not grant it - acceptance-suite-2 test 34 spans statements 0/1);
//   - the contributing standalone primitives are folded in as subsumed risk
//     factors, not duplicate top-level rows (nothing lost);
//   - a partial set (2 of 3) or the primitives on DIFFERENT roles does NOT fire;
//   - the graph shows the same-role modify-then-assume linkage with typed edges
//     (can-modify + can-assume to the one role node), no generic can-write.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { EDGE_TYPES } from '../../../content/tools/iam-blast-radius/engine/graph.js';

const ROLE = 'arn:aws:iam::123456789012:role/automation/DeploymentRole';

// Acceptance-suite-2 test 34: the modify legs in statement 0, the assume leg in
// statement 1, all on the same role.
const test34 = {
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'ModifyTargetRole',
      Effect: 'Allow',
      Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'],
      Resource: ROLE,
    },
    {
      Sid: 'AssumeTargetRole',
      Effect: 'Allow',
      Action: 'sts:AssumeRole',
      Resource: ROLE,
    },
  ],
};

function run(policy) {
  return analyze(JSON.stringify(policy));
}

test('test 34: modify-then-assume on the same role -> one critical ROLE-TAKEOVER', () => {
  const res = run(test34);
  assert.equal(res.ok, true);

  const takeovers = res.findings.filter((f) => f.id === 'ROLE-TAKEOVER');
  assert.equal(takeovers.length, 1, 'exactly one top-level ROLE-TAKEOVER');
  const f = takeovers[0];
  assert.equal(f.severity, 'critical', 'takeover is critical');

  // No iam:PassRole anywhere in the finding (this technique does not need it):
  // not in the header actions, nor in any prerequisite group's action list.
  assert.ok(!f.actions.includes('iam:PassRole'), 'takeover requires no iam:PassRole');
  const prereqActions = f.escalation.prerequisites.anyOf
    .flatMap((t) => t.allOf)
    .flatMap((g) => g.anyOf);
  assert.ok(!prereqActions.includes('iam:PassRole'), 'no prerequisite group names iam:PassRole');

  // The contributing standalone primitives are folded in, NOT left as top-level
  // rows (the primary must be the critical chain).
  const topIds = new Set(res.findings.map((x) => x.id));
  assert.ok(!topIds.has('PUT-INLINE-POLICY'), 'PUT-INLINE-POLICY folded into the takeover, not top-level');
  assert.ok(!topIds.has('TRUST-POLICY-MODIFY'), 'TRUST-POLICY-MODIFY folded into the takeover, not top-level');
  const subIds = new Set((f.subsumed || []).map((s) => s.id));
  assert.ok(subIds.has('PUT-INLINE-POLICY'), 'PUT-INLINE-POLICY preserved as a subsumed risk factor');
  assert.ok(subIds.has('TRUST-POLICY-MODIFY'), 'TRUST-POLICY-MODIFY preserved as a subsumed risk factor');
});

test('test 34: per-statement evidence is preserved (no cross-statement misattribution)', () => {
  const f = run(test34).findings.find((x) => x.id === 'ROLE-TAKEOVER');

  // contributingStatements maps each action to ONLY the statement that grants it.
  const byIndex = new Map(f.contributingStatements.map((c) => [c.statementIndex, c.actions]));
  assert.deepEqual(
    byIndex.get(0).slice().sort(),
    ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'],
    'statement 0 grants exactly the two modify actions',
  );
  assert.deepEqual(byIndex.get(1), ['sts:AssumeRole'], 'statement 1 grants exactly sts:AssumeRole');

  // Invariant: every action attributed to a statement appears in that statement.
  const stmtActions = [
    ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'],
    ['sts:AssumeRole'],
  ];
  for (const c of f.contributingStatements) {
    for (const a of c.actions) {
      assert.ok(stmtActions[c.statementIndex].includes(a), `${a} must be granted by statement ${c.statementIndex}`);
    }
  }

  // The per-leg evidence records carry their own statement + actions.
  const legs = new Map(f.evidence.map((e) => [e.role, e]));
  assert.equal(legs.get('grant-permissions').statementIndex, 0);
  assert.deepEqual(legs.get('grant-permissions').actions, ['iam:PutRolePolicy']);
  assert.equal(legs.get('modify-trust').statementIndex, 0);
  assert.deepEqual(legs.get('modify-trust').actions, ['iam:UpdateAssumeRolePolicy']);
  assert.equal(legs.get('assume').statementIndex, 1);
  assert.deepEqual(legs.get('assume').actions, ['sts:AssumeRole']);
});

test('test 34: prerequisites are an AND of all three legs (allOf)', () => {
  const f = run(test34).findings.find((x) => x.id === 'ROLE-TAKEOVER');
  const anyOf = f.escalation.prerequisites.anyOf;
  assert.equal(anyOf.length, 1, 'a single technique');
  const allOf = anyOf[0].allOf;
  const roles = allOf.map((g) => g.role).sort();
  assert.deepEqual(roles, ['assume', 'grant-permissions', 'modify-trust'], 'three jointly-required groups');
  assert.equal(anyOf[0].requiresPassRole, false);
});

test('boundary: only 2 of the 3 primitives -> NO critical takeover', () => {
  const partial = {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'ModifyOnly', Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: ROLE },
    ],
  };
  const res = run(partial);
  assert.ok(!res.findings.some((f) => f.id === 'ROLE-TAKEOVER'), 'no takeover without the assume leg');
});

test('boundary: primitives on DIFFERENT roles -> NO critical takeover', () => {
  const split = {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'ModifyA', Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/RoleA' },
      { Sid: 'AssumeB', Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/RoleB' },
    ],
  };
  const res = run(split);
  assert.ok(!res.findings.some((f) => f.id === 'ROLE-TAKEOVER'), 'different roles must not correlate into a takeover');
});

test('boundary: a wildcard role scope is not expanded into "the same role"', () => {
  // grant/trust on a concrete role, assume over a broad wildcard scope: the
  // wildcard is the ASSUME-ROLE-EXPANSION shape, never folded into a same-role
  // takeover (exact-role match only).
  const wild = {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'ModifyOne', Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: ROLE },
      { Sid: 'AssumeAny', Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::*:role/*' },
    ],
  };
  const res = run(wild);
  assert.ok(!res.findings.some((f) => f.id === 'ROLE-TAKEOVER'), 'wildcard assume scope is not the same concrete role');
  assert.ok(res.findings.some((f) => f.id === 'ASSUME-ROLE-EXPANSION'), 'the broad assume is still its own expansion finding');
});

test('IAM-1006 mirror of test 74: a BOUNDED wildcard ASSUME scope covering a concrete modify/trust role -> one critical takeover anchored on the concrete role', () => {
  // The exact MIRROR of the test-74 shape (wildcard modify + concrete assume):
  // here the permission-grant/trust-modify legs name a CONCRETE role and the
  // assume leg is a bounded, account-pinned wildcard (role/deployment/*) that
  // provably covers it. All three legs reach the same concrete role, so the
  // compound must yield the SAME single critical ROLE-TAKEOVER as its forward
  // mirror. (Anchors are now harvested from ANY contributing leg, not only assume
  // legs - a role named solely by a modify/trust leg used to be missed.)
  const mirror = {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'ModifyProd', Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: 'arn:aws:iam::123456789012:role/deployment/Prod' },
      { Sid: 'AssumeDeployment', Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::123456789012:role/deployment/*' },
    ],
  };
  const res = run(mirror);
  const takeovers = res.findings.filter((f) => f.id === 'ROLE-TAKEOVER');
  assert.equal(takeovers.length, 1, 'exactly one takeover, anchored on the concrete role');
  assert.equal(takeovers[0].severity, 'critical');
  assert.deepEqual(
    takeovers[0].resources,
    ['arn:aws:iam::123456789012:role/deployment/Prod'],
    'anchored on the concrete role the modify/trust legs name, not generalized to the wildcard',
  );
  assert.ok(!takeovers[0].actions.includes('iam:PassRole'), 'no iam:PassRole needed');
  // The bounded wildcard assume ALSO stands as its own expansion finding.
  assert.ok(res.findings.some((f) => f.id === 'ASSUME-ROLE-EXPANSION'), 'the wildcard assume scope is still its own expansion');
});

test('IAM-1006 boundary preserved: a MAXIMALLY-BROAD assume (*:role/*) with a concrete modify/trust role stays expansion-only, never a same-role takeover', () => {
  // Regression guard for role-takeover test 142 after the anchor-derivation change:
  // even though the concrete modify/trust role is now a candidate anchor, a
  // maximally-broad *:role/* assume scope must NOT confirm it into a same-role
  // takeover - that scope stays the ASSUME-ROLE-EXPANSION shape.
  const wild = {
    Version: '2012-10-17',
    Statement: [
      { Sid: 'ModifyOne', Effect: 'Allow', Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'], Resource: ROLE },
      { Sid: 'AssumeAny', Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::*:role/*' },
    ],
  };
  const res = run(wild);
  assert.ok(!res.findings.some((f) => f.id === 'ROLE-TAKEOVER'), 'maximally-broad assume is not a same-role takeover');
  assert.ok(res.findings.some((f) => f.id === 'ASSUME-ROLE-EXPANSION'), 'it stays its own expansion finding');
});

test('graph shows the same-role modify-then-assume linkage with typed edges', () => {
  const res = run(test34);
  const roleId = `role:${ROLE}`;
  const toRole = res.graph.edges.filter((e) => e.to === roleId);
  const types = new Set(toRole.map((e) => e.type));
  assert.ok(types.has(EDGE_TYPES.CAN_MODIFY), 'a can-modify edge targets the role');
  assert.ok(types.has(EDGE_TYPES.CAN_ASSUME), 'a can-assume edge targets the same role');
  // No generic can-write aggregation anywhere in the graph (IAM-702 invariant).
  assert.ok(!res.graph.edges.some((e) => e.type === EDGE_TYPES.CAN_WRITE), 'no generic can-write aggregation');
});
