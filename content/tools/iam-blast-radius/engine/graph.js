// IAM Blast Radius - graph model builder (data only) (IAM-006).
//
// Sixth stage of the pipeline (see docs/architecture.md data-flow):
//   text -> validate() -> parse() -> buildModel() -> [ evaluator, rules,
//   escalation ] -> { findings[], graph{nodes,edges} }
//
// buildGraph() turns a normalized, frozen model (buildModel(), IAM-002) plus the
// findings emitted by rules.js (IAM-004) and escalation.js (IAM-005) into a pure
// DATA structure of nodes and edges. It performs NO rendering: there is no DOM,
// no SVG, no measurement here. render-graph.js (IAM-008) consumes this data
// behind a rendering interface, so the model stays replaceable and testable.
//
// Node types (docs/architecture.md "Graph model"):
//   Principal, Policy, Role, Service, ActionGroup, Resource, DataStore,
//   Account, ExternalPrincipal.
// Edge types:
//   allows, denies, can-assume, trusts, can-pass, can-modify, can-execute-as,
//   can-read, can-write, can-destroy.
// Edge certainty classes (kept distinct, NOT blended into one score):
//   confirmed-by-context, conditionally-reachable, potentially-reachable,
//   blocked-by-deny, unknown-incomplete-context.
//
// Every edge carries the EXACT supporting evidence (statement Sid + index,
// actions, resources, condition) so IAM-008's inspect panel and the findings
// table can show why the edge exists. Multiple statements/findings that justify
// the same relationship merge into ONE edge whose `evidence[]` lists each, and
// whose certainty is the strongest supporting class.
//
// TRUTHFULNESS INVARIANT (docs/architecture.md #6, threat-model T8): an edge's
// certainty describes reachability WITHIN THE SUPPLIED POLICY CONTEXT, never
// effective permissions. `confirmed-by-context` means "this policy text, on its
// own, grants this" - not that the principal effectively has it (boundaries,
// SCPs, resource policies, session policies are out of scope). The graph is
// never the only representation; the findings table remains authoritative.
//
// Analyzed policies are HOSTILE input (docs/threat-model.md). Node ids and
// labels embed policy strings (ARNs, Sids) verbatim as INERT DATA - they are
// only ever compared and stored here, never interpreted as code or markup, and
// never rendered in this module. Node count is bounded (T5: resource-exhaustion)
// and the builder never throws.
//
// Public API:
//   NODE_TYPES, EDGE_TYPES, CERTAINTY, GRAPH_LIMITS   -> frozen vocab/limits
//   buildGraph(model, findings)     -> { ok, errors[], graph }   (frozen)
//   buildGraphFromText(text)        -> { ok, errors[], graph }   (full pipeline)
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. Deterministic:
// same model + findings -> same nodes, edges, and order, every run (no
// Date/Math.random).

import { modelFromText } from './model.js';
import { analyzeRules } from './rules.js';
import {
  analyzeEscalations,
  applyDenyToActions,
  denyResourceCoverage,
  actionGrants,
  hasPolicyVariable,
} from './escalation.js';

// --- Vocabulary --------------------------------------------------------------

export const NODE_TYPES = Object.freeze({
  PRINCIPAL: 'Principal',
  EXTERNAL_PRINCIPAL: 'ExternalPrincipal',
  ACCOUNT: 'Account',
  POLICY: 'Policy',
  ROLE: 'Role',
  SERVICE: 'Service',
  ACTION_GROUP: 'ActionGroup',
  DATA_STORE: 'DataStore',
  RESOURCE: 'Resource',
});

export const EDGE_TYPES = Object.freeze({
  ALLOWS: 'allows',
  DENIES: 'denies',
  CAN_ASSUME: 'can-assume',
  TRUSTS: 'trusts',
  CAN_PASS: 'can-pass',
  CAN_MODIFY: 'can-modify',
  CAN_EXECUTE_AS: 'can-execute-as',
  CAN_READ: 'can-read',
  CAN_WRITE: 'can-write',
  CAN_DESTROY: 'can-destroy',
});

export const CERTAINTY = Object.freeze({
  CONFIRMED_BY_CONTEXT: 'confirmed-by-context',
  CONDITIONALLY_REACHABLE: 'conditionally-reachable',
  POTENTIALLY_REACHABLE: 'potentially-reachable',
  BLOCKED_BY_DENY: 'blocked-by-deny',
  UNKNOWN_INCOMPLETE_CONTEXT: 'unknown-incomplete-context',
});

export const GRAPH_LIMITS = Object.freeze({
  // Hard cap on graph nodes (threat-model T5: resource exhaustion). Real
  // policies produce a handful; 500 is far above any legitimate result yet
  // bounds a pathological many-statement policy. When adding a node would
  // exceed this, the node (and any edge that needs it) is dropped and the
  // graph is marked `truncated`.
  MAX_NODES: 500,
});

// Deterministic sort orders for node/edge types.
const NODE_TYPE_ORDER = new Map(
  [
    NODE_TYPES.PRINCIPAL,
    NODE_TYPES.EXTERNAL_PRINCIPAL,
    NODE_TYPES.ACCOUNT,
    NODE_TYPES.POLICY,
    NODE_TYPES.ROLE,
    NODE_TYPES.SERVICE,
    NODE_TYPES.ACTION_GROUP,
    NODE_TYPES.DATA_STORE,
    NODE_TYPES.RESOURCE,
  ].map((t, i) => [t, i]),
);

const EDGE_TYPE_ORDER = new Map(
  [
    EDGE_TYPES.ALLOWS,
    EDGE_TYPES.DENIES,
    EDGE_TYPES.CAN_ASSUME,
    EDGE_TYPES.TRUSTS,
    EDGE_TYPES.CAN_PASS,
    EDGE_TYPES.CAN_MODIFY,
    EDGE_TYPES.CAN_EXECUTE_AS,
    EDGE_TYPES.CAN_READ,
    EDGE_TYPES.CAN_WRITE,
    EDGE_TYPES.CAN_DESTROY,
  ].map((t, i) => [t, i]),
);

// Strength ordering so merged edges keep the strongest supporting certainty.
// blocked-by-deny is ranked most-decisive: a definitive Deny is the single most
// important thing to surface. It only ever applies to `denies` edges, which
// never merge with allow-side edges (distinct type), so it cannot mask a grant.
const CERTAINTY_RANK = new Map([
  [CERTAINTY.UNKNOWN_INCOMPLETE_CONTEXT, 0],
  [CERTAINTY.POTENTIALLY_REACHABLE, 1],
  [CERTAINTY.CONDITIONALLY_REACHABLE, 2],
  [CERTAINTY.CONFIRMED_BY_CONTEXT, 3],
  [CERTAINTY.BLOCKED_BY_DENY, 4],
]);

// --- The single Principal node -----------------------------------------------
// Every graph is rooted at the principal this policy is attached to. Its exact
// identity is unknown from a bare policy document, so it is a synthetic root.
const PRINCIPAL_ID = 'principal';

function principalNode() {
  return {
    id: PRINCIPAL_ID,
    type: NODE_TYPES.PRINCIPAL,
    label: 'Principal (subject of this policy)',
  };
}

// --- Helpers -----------------------------------------------------------------

function err(code, message) {
  return { code, message, path: null };
}

// First resource of a finding's scope, used as a representative target-node key.
// Findings always carry a non-empty resources array (rules.js/escalation.js fall
// back to an explicit "(no Resource...)" marker), but guard anyway.
function firstResource(finding) {
  if (Array.isArray(finding.resources) && finding.resources.length > 0) {
    return String(finding.resources[0]);
  }
  return '(unspecified)';
}

// Map a finding's confidence to a BASE edge certainty class:
//   high   -> confirmed-by-context   (granted by this policy text, unconditional)
//   medium -> conditionally-reachable (a Condition may gate it at runtime)
//   low    -> potentially-reachable   (multiple unknowns stack up)
//
// DENY-AWARENESS (see ruleCertainty / ESCALATION vs RULE findings below).
// escalation.js findings arrive with gating Conditions, unresolved PassedToService
// operators, AND possibly-blocking same-policy Denies ALREADY folded into
// `confidence` (fully-blocked paths are suppressed there entirely), so for those
// findings this base mapping is authoritative. rules.js findings, by contrast,
// fold ONLY Conditions into confidence - they are deliberately NOT Deny-aware (a
// Deny is never itself a blast-radius grant, so rules.js does not model it). That
// left rule edges overstating certainty: a wildcard/destructive/IAM-admin grant
// whose action a same-policy explicit Deny overrides would still read as
// `confirmed-by-context`, a truthfulness harm (docs/architecture.md #6,
// threat-model T8). graph.js therefore applies AWS explicit-Deny precedence to
// rule findings here, mirroring what escalation.js already does for its own
// findings: see ruleCertainty(). A confirming Condition (e.g. an
// iam:PassedToService that PROVES a path) is not a gate, so it never lowers
// confidence in those engines and is correctly read as confirmed.
function certaintyFromConfidence(confidence) {
  switch (confidence) {
    case 'high':
      return CERTAINTY.CONFIRMED_BY_CONTEXT;
    case 'medium':
      return CERTAINTY.CONDITIONALLY_REACHABLE;
    default:
      return CERTAINTY.POTENTIALLY_REACHABLE;
  }
}

// Weaken a base certainty by one notch when a same-policy Deny may (but is not
// proven to) block part of a rule finding's grant. confirmed -> conditional ->
// potential; potential and unknown are already the weakest and stay put. This
// never strengthens a class and never invents a hard block (that is the separate
// blocked-by-deny result), so it cannot overstate certainty.
function downgradeCertainty(certainty) {
  switch (certainty) {
    case CERTAINTY.CONFIRMED_BY_CONTEXT:
      return CERTAINTY.CONDITIONALLY_REACHABLE;
    case CERTAINTY.CONDITIONALLY_REACHABLE:
      return CERTAINTY.POTENTIALLY_REACHABLE;
    default:
      return certainty;
  }
}

// Locate the Allow statement a rule finding was raised on (by preserved index),
// needed to evaluate a Deny's resource coverage against the granted scope.
function findStatement(model, index) {
  if (typeof index !== 'number') return null;
  for (const s of model.statements) {
    if (s && s.index === index) return s;
  }
  return null;
}

// Does any same-policy Deny narrow an Allow+NotAction grant ("everything except a
// listed few")? Such a grant can be NARROWED by a Deny but never fully blocked (a
// Deny cannot cover every action), so this only ever downgrades. A Deny narrows
// it when, with resource scope overlapping the Allow (coverage !== 'none'), it
// denies at least one action the NotAction Allow still grants - i.e. an action
// NOT in the Allow's exclusion list (or a NotAction-Deny, which denies ~all, or a
// variable-bearing pattern whose runtime target is unknown).
function denyNarrowsNotAction(denies, allowStmt) {
  for (const deny of denies) {
    if (denyResourceCoverage(deny, allowStmt) === 'none') continue;
    if (deny.notActions.length > 0) return true; // NotAction-Deny denies ~everything
    for (const dp of deny.actions) {
      if (hasPolicyVariable(dp)) return true; // may hit a granted action at runtime
      const excluded = allowStmt.notActions.some(
        (ex) => !hasPolicyVariable(ex) && actionGrants(ex, dp),
      );
      if (!excluded) return true; // denies an action the grant still allows
    }
  }
  return false;
}

// Certainty for a RULE finding's edge, applying same-policy explicit-Deny
// precedence (rules.js is intentionally not Deny-aware; graph.js is, so rule
// edges match escalation edges). Returns:
//   blocked-by-deny  - an unconditional, in-scope, concrete Deny definitively
//                      overrides EVERY granted action (the grant is fully denied).
//   downgraded base  - a Deny may block / partially narrows the grant.
//   base             - no same-policy Deny touches the grant.
function ruleCertainty(finding, denies, model) {
  const base = certaintyFromConfidence(finding.confidence);
  if (!denies || denies.length === 0) return base;
  const allowStmt = findStatement(model, finding.statementIndex);
  if (!allowStmt) return base;
  // Allow + NotAction: grants all-but-listed. Never fully blocked; may narrow.
  if (allowStmt.notActions.length > 0) {
    return denyNarrowsNotAction(denies, allowStmt) ? downgradeCertainty(base) : base;
  }
  const actions = Array.isArray(finding.actions) ? finding.actions : [];
  if (actions.length === 0) return base;
  // Positive-grant rules: reuse escalation.js's exact Deny-precedence resolver so
  // the two engines cannot drift. A narrow Deny of a broad wildcard action does
  // NOT apply (pattern-vs-pattern), so a wildcard edge stays confirmed while the
  // Deny is shown on its own `denies` edge - only a Deny that actually covers the
  // granted action(s) blocks or narrows the edge.
  const eff = applyDenyToActions(denies, actions, allowStmt);
  if (eff.blocked) return CERTAINTY.BLOCKED_BY_DENY;
  if (eff.narrowed) return downgradeCertainty(base);
  return base;
}

// Build the evidence record attached to an edge for one supporting finding.
function evidenceFromFinding(finding) {
  return {
    findingId: finding.id,
    statementSid:
      typeof finding.statementSid === 'string' ? finding.statementSid : null,
    statementIndex:
      typeof finding.statementIndex === 'number' ? finding.statementIndex : null,
    actions: Array.isArray(finding.actions) ? finding.actions.slice() : [],
    resources: Array.isArray(finding.resources) ? finding.resources.slice() : [],
    condition:
      finding.conditions === undefined ? null : finding.conditions,
  };
}

// --- Builder state -----------------------------------------------------------
// A small accumulator so the per-finding mapping stays declarative. It owns node
// de-duplication, the node cap, and edge merging.

function createBuilder() {
  const nodes = new Map(); // id -> node
  const edges = new Map(); // edgeId -> edge
  let truncated = false;

  // The Principal root always exists and does not count against surprising the
  // user with truncation (but it does count toward MAX_NODES for a hard bound).
  const root = principalNode();
  nodes.set(root.id, root);

  function ensureNode(id, type, label) {
    if (nodes.has(id)) return true;
    if (nodes.size >= GRAPH_LIMITS.MAX_NODES) {
      truncated = true;
      return false;
    }
    nodes.set(id, { id, type, label });
    return true;
  }

  // Add (or merge into) an edge from PRINCIPAL_ID to `toId`.
  function addEdge({ toId, toType, toLabel, type, certainty, finding, statementIndex, label }) {
    // The target node must exist; if the cap blocked it, drop the edge too.
    if (!ensureNode(toId, toType, toLabel)) return;
    const edgeId = `${PRINCIPAL_ID}|${type}|${toId}`;
    const evidence = finding ? evidenceFromFinding(finding) : null;
    const existing = edges.get(edgeId);
    if (existing) {
      // Merge: keep the strongest certainty, append evidence, keep the lowest
      // statementIndex as the primary anchor (deterministic).
      if (CERTAINTY_RANK.get(certainty) > CERTAINTY_RANK.get(existing.certainty)) {
        existing.certainty = certainty;
      }
      if (evidence) existing.evidence.push(evidence);
      if (
        typeof statementIndex === 'number' &&
        (existing.statementIndex === null || statementIndex < existing.statementIndex)
      ) {
        existing.statementIndex = statementIndex;
      }
      return;
    }
    edges.set(edgeId, {
      id: edgeId,
      from: PRINCIPAL_ID,
      to: toId,
      type,
      certainty,
      label: label || type,
      statementIndex: typeof statementIndex === 'number' ? statementIndex : null,
      evidence: evidence ? [evidence] : [],
    });
  }

  function result() {
    return { nodes, edges, truncated };
  }

  return { ensureNode, addEdge, result };
}

// --- Finding -> edge mapping --------------------------------------------------
// Each risk rule (IAM-004) and escalation (IAM-005) id maps to a target node and
// an edge type. The mapping is a pure function of the finding, so the graph is
// deterministic and every edge is grounded in a real finding.

// Risk-rule (rules.js) mappings. Each receives the finding, the builder, and the
// deny-aware `certainty` computed by ruleCertainty() (rules.js is not Deny-aware,
// so the certainty is decided here rather than from f.confidence directly).
const RULE_MAP = {
  'WILDCARD-ACTION': (f, b, certainty) => {
    const key = f.actions.length ? String(f.actions[0]) : '*';
    b.addEdge({
      toId: `actiongroup:${key}`,
      toType: NODE_TYPES.ACTION_GROUP,
      toLabel: `Actions: ${key}`,
      type: EDGE_TYPES.ALLOWS,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: `allows ${key}`,
    });
  },
  'WILDCARD-RESOURCE': (f, b, certainty) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      // A broad non-read grant across resources = write reach over them.
      type: EDGE_TYPES.CAN_WRITE,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'broad write scope',
    });
  },
  'DIRECT-IAM-ADMIN': (f, b, certainty) =>
    selfIamModify(f, b, 'direct IAM administration', certainty),
  'NOTACTION-ALLOW': (f, b, certainty) => {
    b.addEdge({
      toId: 'actiongroup:not-action',
      toType: NODE_TYPES.ACTION_GROUP,
      toLabel: 'Actions: every action except a listed few (NotAction)',
      type: EDGE_TYPES.ALLOWS,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'allows all-but-listed',
    });
  },
  'DATA-EXFIL': (f, b, certainty) => {
    b.addEdge({
      toId: 'datastore:sensitive-data',
      toType: NODE_TYPES.DATA_STORE,
      toLabel: 'Sensitive data (secrets / KMS / objects)',
      type: EDGE_TYPES.CAN_READ,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'reads sensitive data',
    });
  },
  'DESTRUCTIVE-ACTION': (f, b, certainty) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      type: EDGE_TYPES.CAN_DESTROY,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can destroy',
    });
  },
  'DETECTION-IMPAIRMENT': (f, b, certainty) => {
    b.addEdge({
      toId: 'service:detection',
      toType: NODE_TYPES.SERVICE,
      toLabel: 'Security telemetry (CloudTrail / GuardDuty / Config)',
      type: EDGE_TYPES.CAN_MODIFY,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can stop/delete telemetry',
    });
  },
};

// Escalation (escalation.js) mappings.
const ESCALATION_MAP = {
  'PASSROLE-LAMBDA': (f, b) => passRoleEdges(f, b),
  'PASSROLE-EC2': (f, b) => passRoleEdges(f, b),
  'PASSROLE-SERVICE': (f, b) => passRoleEdges(f, b),
  // Escalation findings arrive with same-policy Deny already folded into
  // confidence by escalation.js (fully-blocked paths are suppressed there), so
  // their edge certainty comes straight from confidence.
  'POLICY-VERSION': (f, b) =>
    selfIamModify(f, b, 'managed-policy version manipulation', certaintyFromConfidence(f.confidence)),
  'ATTACH-POLICY': (f, b) =>
    selfIamModify(f, b, 'attach managed policy', certaintyFromConfidence(f.confidence)),
  'PUT-INLINE-POLICY': (f, b) =>
    selfIamModify(f, b, 'write inline policy', certaintyFromConfidence(f.confidence)),
  'TRUST-POLICY-MODIFY': (f, b) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `role:${key}`,
      toType: NODE_TYPES.ROLE,
      toLabel: `Role: ${key}`,
      type: EDGE_TYPES.CAN_MODIFY,
      certainty: certaintyFromConfidence(f.confidence),
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can rewrite trust policy',
    });
  },
  'CREDENTIAL-CREATION': (f, b) => {
    b.addEdge({
      toId: 'principal:credential-target',
      toType: NODE_TYPES.PRINCIPAL,
      toLabel: 'Target principal (credential recipient)',
      type: EDGE_TYPES.CAN_MODIFY,
      certainty: certaintyFromConfidence(f.confidence),
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can mint credentials for',
    });
  },
  'ASSUME-ROLE-EXPANSION': (f, b) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `role:${key}`,
      toType: NODE_TYPES.ROLE,
      toLabel: `Role: ${key}`,
      type: EDGE_TYPES.CAN_ASSUME,
      // The reachable roles (and their power) are genuinely not known from this
      // policy: a broad wildcard scope is a POTENTIAL expansion, not a confirmed
      // one, regardless of how unconditional the sts:AssumeRole grant is.
      certainty: CERTAINTY.POTENTIALLY_REACHABLE,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can assume (broad role scope)',
    });
  },
};

// IAM self-administration primitives (direct-admin rule + policy escalations) all
// point at a single Policy node: the principal can rewrite its own permissions.
function selfIamModify(f, b, label, certainty) {
  b.addEdge({
    toId: 'policy:self',
    toType: NODE_TYPES.POLICY,
    toLabel: 'IAM permissions (self-administration)',
    type: EDGE_TYPES.CAN_MODIFY,
    certainty,
    finding: f,
    statementIndex: f.statementIndex,
    label,
  });
}

// PassRole escalations produce two edges to the target Service node: the ability
// to PASS a role to the service, and the ability to make the service EXECUTE AS
// that role (the two halves of the primitive). The passed-role ARN(s) live in
// the edge evidence (`resources`).
function passRoleEdges(f, b) {
  const svc = f.escalation && f.escalation.service ? String(f.escalation.service) : 'service';
  const certainty = certaintyFromConfidence(f.confidence);
  const toId = `service:${svc}`;
  const toLabel = `Service: ${svc}`;
  b.addEdge({
    toId,
    toType: NODE_TYPES.SERVICE,
    toLabel,
    type: EDGE_TYPES.CAN_PASS,
    certainty,
    finding: f,
    statementIndex: f.statementIndex,
    label: `can pass a role to ${svc}`,
  });
  b.addEdge({
    toId,
    toType: NODE_TYPES.SERVICE,
    toLabel,
    type: EDGE_TYPES.CAN_EXECUTE_AS,
    certainty,
    finding: f,
    statementIndex: f.statementIndex,
    label: `can run code as the passed role via ${svc}`,
  });
}

// --- Model Deny statements -> `denies` edges (blocked-by-deny) ----------------
// Findings only cover the Allow side (a Deny never grants blast radius, so it is
// not a finding). But the graph should still SHOW same-policy Denies, since an
// explicit Deny is the single most decisive fact about reachability. Each Deny
// statement becomes one `denies` edge to an ActionGroup node describing what it
// blocks. An unconditional Deny is `blocked-by-deny`; a conditional one is only
// `conditionally-reachable` (it may not fire).
function addDenyEdges(model, b) {
  for (const stmt of model.statements) {
    if (stmt.effect !== 'Deny') continue;
    const usesNotAction = stmt.notActions.length > 0;
    const actions = usesNotAction ? stmt.notActions : stmt.actions;
    const key = usesNotAction ? `not-action#${stmt.index}` : `deny#${stmt.index}`;
    const conditioned = stmt.condition !== null && stmt.condition !== undefined;
    const label = usesNotAction
      ? 'denied: every action except a listed few (NotAction)'
      : `denied: ${actions.join(', ') || '(none)'}`;
    // Synthesize a finding-shaped evidence carrier so the edge carries the same
    // {statementSid, statementIndex, actions, resources, condition} shape.
    const pseudo = {
      id: 'DENY',
      statementSid:
        typeof stmt.sid === 'string' && stmt.sid.length > 0 ? stmt.sid : `(index ${stmt.index})`,
      statementIndex: stmt.index,
      actions: actions.slice(),
      resources:
        stmt.resources.length > 0
          ? stmt.resources.slice()
          : stmt.notResources.length > 0
            ? stmt.notResources.slice()
            : ['(no Resource/NotResource specified)'],
      conditions: stmt.condition,
    };
    b.addEdge({
      toId: `actiongroup:${key}`,
      toType: NODE_TYPES.ACTION_GROUP,
      toLabel: label,
      type: EDGE_TYPES.DENIES,
      certainty: conditioned
        ? CERTAINTY.CONDITIONALLY_REACHABLE
        : CERTAINTY.BLOCKED_BY_DENY,
      finding: pseudo,
      statementIndex: stmt.index,
      label: usesNotAction ? 'denies all-but-listed' : 'denies',
    });
  }
}

// --- Public entry points -----------------------------------------------------

/**
 * Build the graph data structure from a normalized model and its findings.
 * Never throws.
 *
 * @param {object} model normalized, frozen model from buildModel()
 * @param {Array<object>} findings rule + escalation findings (canonical shape)
 * @returns {{ok:boolean, errors:Array<{code:string,message:string,path:?string}>,
 *            graph:{nodes:Array, edges:Array, truncated:boolean,
 *                   limits:{maxNodes:number}}}}
 */
export function buildGraph(model, findings) {
  const errors = [];
  try {
    if (!model || typeof model !== 'object' || !Array.isArray(model.statements)) {
      errors.push(err('NO_MODEL', 'buildGraph() requires a normalized model.'));
      return frozenResult(false, errors, emptyGraph());
    }
    const findingList = Array.isArray(findings) ? findings : [];

    const b = createBuilder();

    // Same-policy Deny statements, used to make RULE edges Deny-aware (AWS
    // explicit-Deny precedence). Escalation findings already have Deny folded in.
    const denies = model.statements.filter((s) => s && s.effect === 'Deny');

    // Allow-side edges from findings (deterministic id-keyed mapping).
    for (const f of findingList) {
      if (!f || typeof f !== 'object' || typeof f.id !== 'string') continue;
      const ruleMap = RULE_MAP[f.id];
      if (ruleMap) {
        ruleMap(f, b, ruleCertainty(f, denies, model));
        continue;
      }
      const escMap = ESCALATION_MAP[f.id];
      if (escMap) escMap(f, b);
    }

    // Deny-side edges straight from the model.
    addDenyEdges(model, b);

    const { nodes, edges, truncated } = b.result();

    // Deterministic ordering.
    const nodeArr = [...nodes.values()].sort(compareNodes);
    const edgeArr = [...edges.values()].sort(compareEdges);
    // Freeze the per-edge evidence arrays' order too (by statementIndex then id).
    for (const e of edgeArr) {
      e.evidence.sort((a, c) => {
        const ai = a.statementIndex === null ? Infinity : a.statementIndex;
        const ci = c.statementIndex === null ? Infinity : c.statementIndex;
        if (ai !== ci) return ai - ci;
        const af = a.findingId || '';
        const cf = c.findingId || '';
        return af < cf ? -1 : af > cf ? 1 : 0;
      });
    }

    const graph = {
      nodes: nodeArr,
      edges: edgeArr,
      truncated,
      limits: { maxNodes: GRAPH_LIMITS.MAX_NODES },
    };
    return frozenResult(true, errors, graph);
  } catch (e) {
    errors.push(err('INTERNAL', 'Graph construction failed unexpectedly.'));
    return frozenResult(false, errors, emptyGraph());
  }
}

/**
 * Convenience: run the full text -> validate -> parse -> model -> (rules +
 * escalations) -> graph pipeline. Never throws.
 *
 * @param {string} text raw pasted/imported policy text
 * @returns {{ok:boolean, errors:Array, graph:object}}
 */
export function buildGraphFromText(text) {
  const m = modelFromText(text);
  if (!m.ok) {
    return frozenResult(false, m.errors, emptyGraph());
  }
  const rules = analyzeRules(m.model);
  const esc = analyzeEscalations(m.model);
  const findings = [
    ...(rules.ok ? rules.findings : []),
    ...(esc.ok ? esc.findings : []),
  ];
  return buildGraph(m.model, findings);
}

// --- Ordering + freezing -----------------------------------------------------

function compareNodes(a, c) {
  const ao = NODE_TYPE_ORDER.has(a.type) ? NODE_TYPE_ORDER.get(a.type) : 999;
  const co = NODE_TYPE_ORDER.has(c.type) ? NODE_TYPE_ORDER.get(c.type) : 999;
  if (ao !== co) return ao - co;
  return a.id < c.id ? -1 : a.id > c.id ? 1 : 0;
}

function compareEdges(a, c) {
  const ai = a.statementIndex === null ? Infinity : a.statementIndex;
  const ci = c.statementIndex === null ? Infinity : c.statementIndex;
  if (ai !== ci) return ai - ci;
  const at = EDGE_TYPE_ORDER.has(a.type) ? EDGE_TYPE_ORDER.get(a.type) : 999;
  const ct = EDGE_TYPE_ORDER.has(c.type) ? EDGE_TYPE_ORDER.get(c.type) : 999;
  if (at !== ct) return at - ct;
  if (a.to !== c.to) return a.to < c.to ? -1 : 1;
  return a.id < c.id ? -1 : a.id > c.id ? 1 : 0;
}

function emptyGraph() {
  return { nodes: [], edges: [], truncated: false, limits: { maxNodes: GRAPH_LIMITS.MAX_NODES } };
}

function frozenResult(ok, errors, graph) {
  deepFreeze(graph);
  return Object.freeze({ ok, errors: Object.freeze(errors), graph });
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Object.isFrozen(value)) return value;
  Object.freeze(value);
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

export default buildGraph;
