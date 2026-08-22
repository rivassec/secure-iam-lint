// Unit tests for IAM-006: graph model builder (data only).
// Runs on node's built-in runner: `node --test`.
//
// Acceptance (prd.json IAM-006):
//   - graph edges match expected fixtures for pass-role + wildcard cases
//   - certainty classes correct
//   - reliability critic >=95 - deterministic, deep-frozen, never throws,
//     bounded node count, hostile input inert, no prototype pollution
//
// The builder is PURE DATA: this suite asserts there is no DOM/SVG dependency
// (it imports and runs under plain node with no document/window) and that every
// edge carries evidence + a certainty class from the architecture vocabulary.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import { analyzeRules } from '../../../content/tools/iam-blast-radius/engine/rules.js';
import { analyzeEscalations } from '../../../content/tools/iam-blast-radius/engine/escalation.js';
import {
  buildGraph,
  buildGraphFromText,
  NODE_TYPES,
  EDGE_TYPES,
  CERTAINTY,
  GRAPH_LIMITS,
} from '../../../content/tools/iam-blast-radius/engine/graph.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

const NODE_TYPE_SET = new Set(Object.values(NODE_TYPES));
const EDGE_TYPE_SET = new Set(Object.values(EDGE_TYPES));
const CERTAINTY_SET = new Set(Object.values(CERTAINTY));

// Every fixture directory in the repo (graph invariants must hold on ALL of
// them, not only the graph-specific ones).
const ALL_CATEGORIES = readdirSync(fixturesDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

function loadFixtures(category) {
  const dir = join(fixturesDir, category);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `${category}/${f}`, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
}

// Project an edge down to the {from,to,type} identity used for set comparison.
function edgeKey(e) {
  return `${e.from}|${e.type}|${e.to}`;
}

function findEdge(graph, exp) {
  return graph.edges.find((e) => e.from === exp.from && e.to === exp.to && e.type === exp.type);
}

// ---------------------------------------------------------------------------
// Structural invariants on the produced graph. Reused everywhere.
// ---------------------------------------------------------------------------

function assertGraphInvariants(graph, ctx) {
  assert.ok(graph && typeof graph === 'object', `${ctx}: graph missing`);
  assert.ok(Array.isArray(graph.nodes), `${ctx}: nodes must be an array`);
  assert.ok(Array.isArray(graph.edges), `${ctx}: edges must be an array`);
  assert.ok(Object.isFrozen(graph), `${ctx}: graph must be frozen`);
  assert.ok(Object.isFrozen(graph.nodes), `${ctx}: nodes must be frozen`);
  assert.ok(Object.isFrozen(graph.edges), `${ctx}: edges must be frozen`);

  // Node count is bounded (threat-model T5).
  assert.ok(graph.nodes.length <= GRAPH_LIMITS.MAX_NODES, `${ctx}: node cap exceeded`);

  const nodeIds = new Set();
  for (const n of graph.nodes) {
    assert.ok(typeof n.id === 'string' && n.id.length > 0, `${ctx}: node missing id`);
    assert.ok(!nodeIds.has(n.id), `${ctx}: duplicate node id ${n.id}`);
    nodeIds.add(n.id);
    assert.ok(NODE_TYPE_SET.has(n.type), `${ctx}: bad node type ${n.type}`);
    assert.ok(typeof n.label === 'string' && n.label.length > 0, `${ctx}: node missing label`);
  }
  // Any non-empty graph is rooted at the Principal node. (A rejected/invalid
  // input yields a fully empty graph - no nodes, no edges.)
  if (graph.nodes.length > 0) {
    assert.ok(nodeIds.has('principal'), `${ctx}: missing principal root node`);
  }
  if (graph.edges.length > 0) {
    assert.ok(nodeIds.has('principal'), `${ctx}: edges present without principal root`);
  }

  const edgeIds = new Set();
  for (const e of graph.edges) {
    assert.ok(typeof e.id === 'string' && e.id.length > 0, `${ctx}: edge missing id`);
    assert.ok(!edgeIds.has(e.id), `${ctx}: duplicate edge id ${e.id}`);
    edgeIds.add(e.id);
    assert.equal(e.from, 'principal', `${ctx}: every edge originates at the principal`);
    assert.ok(EDGE_TYPE_SET.has(e.type), `${ctx}: bad edge type ${e.type}`);
    assert.ok(CERTAINTY_SET.has(e.certainty), `${ctx}: bad certainty ${e.certainty}`);
    // Endpoints must reference real nodes (no dangling edges after truncation).
    assert.ok(nodeIds.has(e.from), `${ctx}: edge from missing node ${e.from}`);
    assert.ok(nodeIds.has(e.to), `${ctx}: edge to missing node ${e.to}`);
    // Every edge carries the exact supporting evidence (architecture contract).
    assert.ok(Array.isArray(e.evidence) && e.evidence.length > 0, `${ctx}: edge missing evidence`);
    for (const ev of e.evidence) {
      assert.ok('statementIndex' in ev, `${ctx}: evidence missing statementIndex`);
      assert.ok(Array.isArray(ev.actions), `${ctx}: evidence missing actions`);
      assert.ok(Array.isArray(ev.resources), `${ctx}: evidence missing resources`);
      assert.ok('condition' in ev, `${ctx}: evidence missing condition`);
    }
  }
}

// ---------------------------------------------------------------------------
// Fixture-driven: every fixture builds a valid graph without throwing, and any
// fixture that declares graphEdges / exactGraphEdges matches.
// ---------------------------------------------------------------------------

for (const category of ALL_CATEGORIES) {
  for (const { file, data } of loadFixtures(category)) {
    const exp = data.expect || {};
    test(`fixture ${file}: graph builds, invariants hold, edges match`, () => {
      let r;
      assert.doesNotThrow(() => {
        r = buildGraphFromText(fixtureText(data));
      }, `${file}: buildGraphFromText threw`);
      assert.ok(typeof r.ok === 'boolean', `${file}: missing ok`);
      assertGraphInvariants(r.graph, file);

      if (exp.valid === false) {
        assert.equal(r.ok, false, `${file}: invalid input must yield ok=false`);
        assert.deepEqual(r.graph.edges, [], `${file}: invalid input must yield no edges`);
      }

      if (Array.isArray(exp.graphEdges)) {
        const produced = new Set(r.graph.edges.map(edgeKey));
        for (const want of exp.graphEdges) {
          assert.ok(
            produced.has(edgeKey(want)),
            `${file}: expected edge ${edgeKey(want)}; got ${JSON.stringify([...produced])}`,
          );
          if (want.certainty) {
            const e = findEdge(r.graph, want);
            assert.equal(e.certainty, want.certainty, `${file}: wrong certainty on ${edgeKey(want)}`);
          }
        }
      }

      if (Array.isArray(exp.exactGraphEdges)) {
        const produced = r.graph.edges.map(edgeKey).sort();
        const want = exp.exactGraphEdges.map(edgeKey).sort();
        assert.deepEqual(produced, want, `${file}: exact edge set mismatch`);
        for (const w of exp.exactGraphEdges) {
          if (!w.certainty) continue;
          const e = findEdge(r.graph, w);
          assert.equal(e.certainty, w.certainty, `${file}: wrong certainty on ${edgeKey(w)}`);
        }
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Acceptance: pass-role case edges + certainty.
// ---------------------------------------------------------------------------

test('acceptance: PassRole+Lambda -> can-pass and can-execute-as edges to Service:lambda (confirmed)', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::1:role/app-*', Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } },
      { Sid: 'run', Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: 'arn:aws:lambda:us-east-1:1:function:app-*' },
    ],
  }));
  assert.equal(r.ok, true);
  const pass = findEdge(r.graph, { from: 'principal', to: 'service:lambda', type: 'can-pass' });
  const exec = findEdge(r.graph, { from: 'principal', to: 'service:lambda', type: 'can-execute-as' });
  assert.ok(pass, 'expected a can-pass edge to service:lambda');
  assert.ok(exec, 'expected a can-execute-as edge to service:lambda');
  assert.equal(pass.certainty, CERTAINTY.CONFIRMED_BY_CONTEXT);
  assert.equal(exec.certainty, CERTAINTY.CONFIRMED_BY_CONTEXT);
  // The Service node exists and is typed correctly.
  const svc = r.graph.nodes.find((n) => n.id === 'service:lambda');
  assert.ok(svc && svc.type === NODE_TYPES.SERVICE);
  // Evidence names both the pass ARN and the execution action.
  assert.ok(pass.evidence.some((ev) => ev.resources.includes('arn:aws:iam::1:role/app-*')));
});

test('acceptance: a conditioned execution statement downgrades PassRole edges to conditionally-reachable', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*', Condition: { StringEquals: { 'aws:RequestedRegion': 'us-east-1' } } },
    ],
  }));
  const pass = findEdge(r.graph, { from: 'principal', to: 'service:ec2', type: 'can-pass' });
  assert.ok(pass);
  assert.equal(pass.certainty, CERTAINTY.CONDITIONALLY_REACHABLE);
});

// ---------------------------------------------------------------------------
// Acceptance: wildcard case edges + certainty.
// ---------------------------------------------------------------------------

test('acceptance: Action "*" on Resource "*" -> allows(actiongroup:*) + can-write(resource:*), both confirmed', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [{ Sid: 'god', Effect: 'Allow', Action: '*', Resource: '*' }],
  }));
  const keys = r.graph.edges.map(edgeKey).sort();
  assert.deepEqual(keys, [
    'principal|allows|actiongroup:*',
    'principal|can-write|resource:*',
  ]);
  for (const e of r.graph.edges) assert.equal(e.certainty, CERTAINTY.CONFIRMED_BY_CONTEXT);
  assert.equal(r.graph.nodes.find((n) => n.id === 'actiongroup:*').type, NODE_TYPES.ACTION_GROUP);
  assert.equal(r.graph.nodes.find((n) => n.id === 'resource:*').type, NODE_TYPES.RESOURCE);
});

test('acceptance: service wildcard s3:* (scoped resource) -> single allows edge to actiongroup:s3:*', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: ['arn:aws:s3:::b', 'arn:aws:s3:::b/*'] }],
  }));
  assert.deepEqual(r.graph.edges.map(edgeKey), ['principal|allows|actiongroup:s3:*']);
});

// ---------------------------------------------------------------------------
// Certainty classes: blocked-by-deny, conditionally-reachable, potentially,
// unknown. (Confirmed covered above.)
// ---------------------------------------------------------------------------

test('unconditional Deny -> denies edge with blocked-by-deny certainty', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [{ Sid: 'block', Effect: 'Deny', Action: 'iam:*', Resource: '*' }],
  }));
  const deny = r.graph.edges.find((e) => e.type === EDGE_TYPES.DENIES);
  assert.ok(deny, 'expected a denies edge');
  assert.equal(deny.certainty, CERTAINTY.BLOCKED_BY_DENY);
});

test('conditional Deny -> denies edge is conditionally-reachable, not blocked', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [{ Effect: 'Deny', Action: 's3:DeleteBucket', Resource: '*', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } } }],
  }));
  const deny = r.graph.edges.find((e) => e.type === EDGE_TYPES.DENIES);
  assert.ok(deny);
  assert.equal(deny.certainty, CERTAINTY.CONDITIONALLY_REACHABLE);
});

test('broad AssumeRole -> can-assume edge is potentially-reachable (unknown targets)', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: '*' }],
  }));
  const e = findEdge(r.graph, { from: 'principal', to: 'role:*', type: 'can-assume' });
  assert.ok(e, 'expected a can-assume edge to role:*');
  assert.equal(e.certainty, CERTAINTY.POTENTIALLY_REACHABLE);
});

// ---------------------------------------------------------------------------
// Deny-aware RULE edges: rules.js is deliberately not Deny-aware (a Deny is
// never itself a blast-radius grant), so graph.js must apply AWS explicit-Deny
// precedence to rule-derived edges. Escalation edges arrive pre-folded. Without
// this, a rule grant that a same-policy Deny overrides would still read as
// confirmed-by-context - an overstated-certainty (threat-model T8) harm.
// ---------------------------------------------------------------------------

test('rule edge fully overridden by an unconditional same-policy Deny -> blocked-by-deny', () => {
  const arn = 'arn:aws:ec2:us-east-1:1:instance/i-abc';
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'grant', Effect: 'Allow', Action: 'ec2:TerminateInstances', Resource: arn },
      { Sid: 'block', Effect: 'Deny', Action: 'ec2:TerminateInstances', Resource: arn },
    ],
  }));
  assert.equal(r.ok, true);
  const destroy = findEdge(r.graph, { from: 'principal', to: `resource:${arn}`, type: EDGE_TYPES.CAN_DESTROY });
  assert.ok(destroy, 'expected a can-destroy edge from the DESTRUCTIVE-ACTION rule');
  assert.equal(
    destroy.certainty,
    CERTAINTY.BLOCKED_BY_DENY,
    'a same-policy Deny of the granted action must block the rule edge, not leave it confirmed',
  );
});

test('rule edge partially narrowed by a same-policy Deny -> downgraded to conditionally-reachable', () => {
  const arn = 'arn:aws:ec2:us-east-1:1:instance/i-abc';
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'grant', Effect: 'Allow', Action: ['ec2:TerminateInstances', 'ec2:DeleteVolume'], Resource: arn },
      { Sid: 'block', Effect: 'Deny', Action: 'ec2:TerminateInstances', Resource: arn },
    ],
  }));
  const destroy = findEdge(r.graph, { from: 'principal', to: `resource:${arn}`, type: EDGE_TYPES.CAN_DESTROY });
  assert.ok(destroy);
  assert.equal(destroy.certainty, CERTAINTY.CONDITIONALLY_REACHABLE);
});

test('conditional same-policy Deny narrows a rule edge but never hard-blocks it', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'grant', Effect: 'Allow', Action: 'iam:PutUserPolicy', Resource: '*' },
      { Sid: 'block', Effect: 'Deny', Action: 'iam:PutUserPolicy', Resource: '*', Condition: { BoolIfExists: { 'aws:MultiFactorAuthPresent': 'false' } } },
    ],
  }));
  const self = findEdge(r.graph, { from: 'principal', to: 'policy:self', type: EDGE_TYPES.CAN_MODIFY });
  assert.ok(self);
  assert.equal(
    self.certainty,
    CERTAINTY.CONDITIONALLY_REACHABLE,
    'a conditional Deny may not fire, so it downgrades rather than hard-blocks',
  );
});

test('a narrow Deny does NOT downgrade a broad wildcard rule edge (no false downgrade)', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'all', Effect: 'Allow', Action: 's3:*', Resource: '*' },
      { Sid: 'one', Effect: 'Deny', Action: 's3:DeleteBucket', Resource: '*' },
    ],
  }));
  const allows = findEdge(r.graph, { from: 'principal', to: 'actiongroup:s3:*', type: EDGE_TYPES.ALLOWS });
  assert.ok(allows, 'expected the s3:* allows edge');
  assert.equal(
    allows.certainty,
    CERTAINTY.CONFIRMED_BY_CONTEXT,
    's3:* is still confirmed; a single denied action does not cover the wildcard grant',
  );
  // The Deny is still surfaced on its own separate denies edge.
  const deny = r.graph.edges.find((e) => e.type === EDGE_TYPES.DENIES);
  assert.ok(deny, 'the narrow Deny must still appear as its own denies edge');
});

test('a NotAction-Deny narrows a broad wildcard rule edge but NEVER hard-blocks it', () => {
  // Allow s3:* + Deny NotAction:s3:GetObject. The Deny denies everything EXCEPT
  // s3:GetObject, so s3:GetObject stays allowed - the wildcard grant is narrowed,
  // not fully blocked. Rendering it as blocked-by-deny would tell the user a
  // still-reachable capability is definitively blocked (a false deny, T8).
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'all', Effect: 'Allow', Action: 's3:*', Resource: '*' },
      { Sid: 'notget', Effect: 'Deny', NotAction: 's3:GetObject', Resource: '*' },
    ],
  }));
  const allows = findEdge(r.graph, { from: 'principal', to: 'actiongroup:s3:*', type: EDGE_TYPES.ALLOWS });
  assert.ok(allows, 'expected the s3:* allows edge to survive');
  assert.notEqual(
    allows.certainty,
    CERTAINTY.BLOCKED_BY_DENY,
    'a NotAction-Deny can never fully cover a broad grant, so the edge must not be blocked',
  );
  assert.equal(
    allows.certainty,
    CERTAINTY.CONDITIONALLY_REACHABLE,
    'the wildcard grant is narrowed (downgraded), not blocked',
  );
  // The Deny is still surfaced on its own separate denies edge (NotAction form).
  const deny = r.graph.edges.find((e) => e.type === EDGE_TYPES.DENIES);
  assert.ok(deny, 'the NotAction-Deny must still appear as its own denies edge');
});

test('a NotAction-Deny narrows a full "*" rule edge but NEVER hard-blocks it', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'god', Effect: 'Allow', Action: '*', Resource: '*' },
      { Sid: 'notkey', Effect: 'Deny', NotAction: 'iam:CreateAccessKey', Resource: '*' },
    ],
  }));
  const allows = findEdge(r.graph, { from: 'principal', to: 'actiongroup:*', type: EDGE_TYPES.ALLOWS });
  assert.ok(allows, 'expected the "*" allows edge to survive');
  assert.equal(
    allows.certainty,
    CERTAINTY.CONDITIONALLY_REACHABLE,
    'iam:CreateAccessKey remains allowed, so "*" is narrowed, not blocked',
  );
});

test('control: a POSITIVE-action Deny that covers the whole wildcard grant DOES block it', () => {
  // Contrast with the NotAction cases above: Allow s3:* + Deny s3:* (positive
  // Action) genuinely covers the entire grant, so blocked-by-deny is correct.
  // This must stay distinct from the NotAction narrowing case.
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'all', Effect: 'Allow', Action: 's3:*', Resource: '*' },
      { Sid: 'blockall', Effect: 'Deny', Action: 's3:*', Resource: '*' },
    ],
  }));
  const allows = findEdge(r.graph, { from: 'principal', to: 'actiongroup:s3:*', type: EDGE_TYPES.ALLOWS });
  assert.ok(allows);
  assert.equal(allows.certainty, CERTAINTY.BLOCKED_BY_DENY);
});

test('NotAction-Allow rule edge is narrowed (never fully blocked) by a same-policy Deny', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'allbut', Effect: 'Allow', NotAction: 'iam:*', Resource: '*' },
      { Sid: 'block', Effect: 'Deny', Action: 'ec2:TerminateInstances', Resource: '*' },
    ],
  }));
  const e = findEdge(r.graph, { from: 'principal', to: 'actiongroup:not-action', type: EDGE_TYPES.ALLOWS });
  assert.ok(e, 'expected the NotAction allows edge');
  // ec2:TerminateInstances is granted by "everything except iam:*" and denied,
  // so the all-but-listed grant is narrowed, but a Deny can never cover it all.
  assert.equal(e.certainty, CERTAINTY.CONDITIONALLY_REACHABLE);
});

test('escalation edges remain driven by escalation.js confidence, not re-folded here', () => {
  // escalation.js already suppresses a fully-blocked PUT-INLINE-POLICY path, so
  // graph.js must not also try to block it: with the Allow fully denied, the
  // only surviving edge is the DIRECT-IAM-ADMIN rule edge (blocked-by-deny), and
  // there is exactly one can-modify(policy:self) edge (no escalation duplicate).
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'grant', Effect: 'Allow', Action: 'iam:PutUserPolicy', Resource: '*' },
      { Sid: 'block', Effect: 'Deny', Action: 'iam:PutUserPolicy', Resource: '*' },
    ],
  }));
  const selfEdges = r.graph.edges.filter((e) => e.to === 'policy:self' && e.type === EDGE_TYPES.CAN_MODIFY);
  assert.equal(selfEdges.length, 1, 'the suppressed escalation must not add a second self edge');
  assert.equal(selfEdges[0].certainty, CERTAINTY.BLOCKED_BY_DENY);
});

// ---------------------------------------------------------------------------
// Edge merging: two statements supporting the same relationship -> ONE edge
// carrying multiple evidence records, with the strongest certainty.
// ---------------------------------------------------------------------------

test('two attach-policy statements collapse into one can-modify(policy:self) edge with merged evidence', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'a', Effect: 'Allow', Action: 'iam:AttachRolePolicy', Resource: '*' },
      { Sid: 'b', Effect: 'Allow', Action: 'iam:AttachUserPolicy', Resource: '*' },
    ],
  }));
  const selfEdges = r.graph.edges.filter((e) => e.to === 'policy:self' && e.type === EDGE_TYPES.CAN_MODIFY);
  assert.equal(selfEdges.length, 1, 'the two statements must merge into a single edge');
  assert.ok(selfEdges[0].evidence.length >= 2, 'merged edge must retain both supporting statements');
  // Merged edge anchors on the lowest statement index (deterministic).
  assert.equal(selfEdges[0].statementIndex, 0);
});

test('merged edge keeps the STRONGEST certainty across supporting findings', () => {
  // Two DIRECT-IAM-ADMIN grants: one unconditional (high->confirmed), one
  // conditioned (medium->conditional). The merged self edge must stay confirmed.
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Sid: 'cond', Effect: 'Allow', Action: 'iam:PutUserPolicy', Resource: '*', Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } } },
      { Sid: 'plain', Effect: 'Allow', Action: 'iam:AttachUserPolicy', Resource: '*' },
    ],
  }));
  const self = r.graph.edges.find((e) => e.to === 'policy:self' && e.type === EDGE_TYPES.CAN_MODIFY);
  assert.ok(self);
  assert.equal(self.certainty, CERTAINTY.CONFIRMED_BY_CONTEXT);
});

// ---------------------------------------------------------------------------
// Determinism + deep freeze.
// ---------------------------------------------------------------------------

test('buildGraph is deterministic (same input -> byte-identical graph) and deeply frozen', () => {
  const text = JSON.stringify({
    Statement: [
      { Sid: 'p', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Sid: 'x', Effect: 'Allow', Action: ['lambda:CreateFunction', 'ec2:RunInstances'], Resource: '*' },
      { Sid: 'd', Effect: 'Deny', Action: 's3:DeleteBucket', Resource: '*' },
    ],
  });
  const a = buildGraphFromText(text);
  const b = buildGraphFromText(text);
  assert.deepEqual(JSON.parse(JSON.stringify(a.graph)), JSON.parse(JSON.stringify(b.graph)));
  assert.ok(Object.isFrozen(a.graph));
  assert.ok(Object.isFrozen(a.graph.nodes));
  assert.ok(Object.isFrozen(a.graph.edges));
  if (a.graph.edges.length) {
    assert.ok(Object.isFrozen(a.graph.edges[0]));
    assert.ok(Object.isFrozen(a.graph.edges[0].evidence));
  }
});

test('nodes are ordered by node-type then id; edges by statementIndex then type then to', () => {
  const r = buildGraphFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:AttachRolePolicy', Resource: '*' },
      { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: '*' },
    ],
  }));
  const edgeSeq = r.graph.edges.map((e) => e.statementIndex);
  const sortedSeq = [...edgeSeq].sort((x, y) => x - y);
  assert.deepEqual(edgeSeq, sortedSeq, 'edges must be ordered by statement index');
  // Principal node always sorts first.
  assert.equal(r.graph.nodes[0].id, 'principal');
});

// ---------------------------------------------------------------------------
// Bounded node count (threat-model T5): a huge finding set truncates, no throw.
// ---------------------------------------------------------------------------

test('node count is capped at GRAPH_LIMITS.MAX_NODES; excess is truncated, not thrown', () => {
  const findings = [];
  const n = GRAPH_LIMITS.MAX_NODES + 100;
  for (let i = 0; i < n; i++) {
    findings.push({
      id: 'DESTRUCTIVE-ACTION',
      confidence: 'high',
      statementIndex: i,
      statementSid: `s${i}`,
      actions: ['ec2:TerminateInstances'],
      resources: [`arn:aws:ec2:us-east-1:1:instance/i-${i}`],
      conditions: null,
    });
  }
  let r;
  assert.doesNotThrow(() => {
    r = buildGraph({ statements: [] }, findings);
  });
  assert.equal(r.ok, true);
  assert.ok(r.graph.nodes.length <= GRAPH_LIMITS.MAX_NODES, 'node cap must hold');
  assert.equal(r.graph.truncated, true, 'graph must report truncation');
  assertGraphInvariants(r.graph, 'bounded');
});

// ---------------------------------------------------------------------------
// Purity: no DOM / SVG dependency (this test file runs under bare node).
// ---------------------------------------------------------------------------

test('graph builder is pure data: no document/window usage at import or call time', () => {
  assert.equal(typeof globalThis.document, 'undefined', 'test env must have no DOM');
  const r = buildGraphFromText(JSON.stringify({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }));
  assert.ok(r.ok);
  // Result is plain JSON-serializable data (no DOM nodes, functions, symbols).
  assert.doesNotThrow(() => JSON.stringify(r.graph));
});

// ---------------------------------------------------------------------------
// Hostile input: XSS payloads pass through as inert node ids/labels; prototype
// pollution is not possible; malformed input never throws.
// ---------------------------------------------------------------------------

test('XSS-laden ARN becomes an inert node id/label string, never markup', () => {
  // Trailing wildcard keeps the role scope "broad" (so ASSUME-ROLE-EXPANSION
  // fires) while carrying the hostile markup verbatim into the node id.
  const payload = 'arn:aws:iam::1:role/<img src=x onerror=alert(1)>-*';
  const r = buildGraphFromText(JSON.stringify({
    Statement: [{ Sid: '<svg/onload=alert(1)>', Effect: 'Allow', Action: 'sts:AssumeRole', Resource: payload }],
  }));
  const e = findEdge(r.graph, { from: 'principal', to: `role:${payload}`, type: 'can-assume' });
  assert.ok(e, 'the hostile ARN must appear only as an inert node id');
  const node = r.graph.nodes.find((x) => x.id === `role:${payload}`);
  assert.ok(node);
  assert.equal(typeof node.label, 'string');
  // The Sid rides through the evidence as an inert string.
  assert.ok(e.evidence.some((ev) => ev.statementSid === '<svg/onload=alert(1)>'));
});

test('building a graph does not pollute Object.prototype', () => {
  buildGraphFromText(
    '{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"__proto__":{"polluted":true}}}}]}',
  );
  assert.equal(({}).polluted, undefined);
});

test('buildGraph never throws on a bad model', () => {
  assert.doesNotThrow(() => {
    const r = buildGraph(null, []);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.code === 'NO_MODEL'));
    assert.deepEqual(r.graph.edges, []);
  });
  assert.doesNotThrow(() => {
    const r = buildGraph({ statements: 'nope' }, []);
    assert.equal(r.ok, false);
  });
  assert.doesNotThrow(() => {
    const r = buildGraph({ statements: [] }, 'not-an-array');
    assert.equal(r.ok, true);
    assert.deepEqual(r.graph.edges, []);
  });
});

test('buildGraphFromText surfaces validation failures and never throws on malformed/adversarial fixtures', () => {
  for (const { file, data } of [...loadFixtures('malformed'), ...loadFixtures('adversarial')]) {
    assert.doesNotThrow(() => {
      const r = buildGraphFromText(fixtureText(data));
      assert.ok(typeof r.ok === 'boolean', `${file}: missing ok`);
      assertGraphInvariants(r.graph, file);
      if (data.expect && data.expect.valid === false) {
        assert.equal(r.ok, false, `${file}: expected validation failure`);
        assert.deepEqual(r.graph.edges, [], `${file}: rejected input must yield no edges`);
      }
    }, `${file}: buildGraphFromText threw`);
  }
});

// ---------------------------------------------------------------------------
// buildGraph accepts findings assembled by the caller exactly as the worker
// would (rules + escalations concatenated), matching buildGraphFromText.
// ---------------------------------------------------------------------------

test('buildGraph(model, rules+escalations) equals buildGraphFromText', () => {
  const text = JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
    ],
  });
  const m = modelFromText(text);
  const findings = [
    ...analyzeRules(m.model).findings,
    ...analyzeEscalations(m.model).findings,
  ];
  const direct = buildGraph(m.model, findings);
  const viaText = buildGraphFromText(text);
  assert.deepEqual(
    JSON.parse(JSON.stringify(direct.graph)),
    JSON.parse(JSON.stringify(viaText.graph)),
  );
});

// ---------------------------------------------------------------------------
// safe/ fixtures produce no allow-side edges (only possible denies edges).
// ---------------------------------------------------------------------------

test('safe/ fixtures produce no risk edges', () => {
  const fixtures = loadFixtures('safe');
  assert.ok(fixtures.length > 0, 'safe/ has no fixtures');
  for (const { file, data } of fixtures) {
    const r = buildGraphFromText(fixtureText(data));
    assert.equal(r.ok, true, `${file}: build not ok`);
    const risky = r.graph.edges.filter((e) => e.type !== EDGE_TYPES.DENIES);
    assert.deepEqual(risky, [], `${file}: safe fixture produced risk edges`);
  }
});
