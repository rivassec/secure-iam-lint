// IAM Blast Radius - graph model builder (data only) (IAM-006).
//
// Sixth stage of the pipeline (see docs/architecture.md data-flow):
//   text -> validate() -> parse() -> buildModel() -> [ rules, escalation,
//   family-aware analyzers ] -> { findings[], graph{nodes,edges} }
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
//   can-read, can-decrypt, can-write, can-destroy.
//   (IAM-202 adds `can-decrypt` for kms:Decrypt, distinct from a plain
//   `can-read` data read: it turns ciphertext into plaintext, not secret
//   enumeration/retrieval.)
// Edge certainty classes (kept distinct, NOT blended into one score) - IAM-202
// vocabulary:
//   confirmed-by-policy   - a grant literally present in this policy text
//   policy-supported      - the grants are present, but the transition needs an
//                           out-of-scope precondition (e.g. a usable target
//                           role / trust config) that this policy cannot prove
//   context-required      - a Condition in the policy may gate it at runtime
//   potentially-reachable - multiple unknowns stack up
//   blocked-by-deny       - an explicit same-policy Deny overrides the grant
//   unknown-incomplete-context
//
// Every edge carries the EXACT supporting evidence (statement Sid + index,
// actions, resources, condition) so IAM-008's inspect panel and the findings
// table can show why the edge exists. Multiple statements/findings that justify
// the same relationship merge into ONE edge whose `evidence[]` lists each, and
// whose certainty is the strongest supporting class.
//
// TRUTHFULNESS INVARIANT (docs/architecture.md #6, threat-model T8): an edge's
// certainty describes reachability WITHIN THE SUPPLIED POLICY CONTEXT, never
// effective permissions. `confirmed-by-policy` means "this policy text, on its
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
// IAM-401: every edge also carries a semantic `lane` (see LANES) so the renderer
// can group paths into labeled sections (privilege escalation / identity
// expansion / data access / scope / explicit deny) instead of a flat radial
// layout. The lane is a pure function of the finding kind + relationship; it is
// a visual/organizational grouping only and never changes a finding's severity,
// certainty, or the AWS semantics it asserts.
//
// Public API:
//   NODE_TYPES, EDGE_TYPES, CERTAINTY, GRAPH_LIMITS   -> frozen vocab/limits
//   LANES, LANE_ORDER                                 -> frozen lane vocab/order
//   buildGraph(model, findings)     -> { ok, errors[], graph }   (frozen)
//   buildGraphFromText(text)        -> { ok, errors[], graph }   (full pipeline)
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. Deterministic:
// same model + findings -> same nodes, edges, and order, every run (no
// Date/Math.random).

import { modelFromText } from './model.js';
import {
  RULE_MAP, ESCALATION_MAP, roleTakeoverEdges, CREDENTIAL_ONLY_ADMIN_ACTIONS, isCredentialOnlyAdmin, selfIamModify, wildcardResourceEdges, passRoleEdges, ecsPassRoleEdges, edgeEvidenceCarrier, addDenyEdges, dropRedundantGenericDelegation,
} from './graph-edges.js';
export * from './graph-edges.js';
import {
  resourceTargetNode, resourceEdgeCertainty, buildResourceGraph,
} from './graph-resource.js';
export * from './graph-resource.js';
import {
  TRUST_ROLE_ID, TRUST_ROLE_LABEL, trustOriginNode, trustEdgeCertainty, buildTrustGraph,
} from './graph-trust.js';
export * from './graph-trust.js';
import {
  compareNodes, compareEdges, emptyGraph, frozenResult, deepFreeze,
} from './graph-result.js';
export * from './graph-result.js';
import {
  principalNode, err, firstResource, READ_VERB, DESTRUCTIVE_VERB, verbOf, classifyCapability, findingWithActions, certaintyFromEvidence, passRoleCertainty, downgradeCertainty, findStatement, denyNarrowsNotAction, ruleCertainty, evidenceFromFinding,
} from './graph-helpers.js';
export * from './graph-helpers.js';
import {
  NODE_TYPES, EDGE_TYPES, LANES, LANE_ORDER, CERTAINTY, GRAPH_LIMITS, NODE_TYPE_ORDER, EDGE_TYPE_ORDER, CERTAINTY_RANK, PRINCIPAL_ID,
} from './graph-catalogs.js';
export * from './graph-catalogs.js';
import { analyzeRules } from './rules.js';
import {
  analyzeEscalations,
  applyDenyToActions,
  denyResourceCoverage,
  actionGrants,
  hasPolicyVariable,
  hasNonEmptyCondition,
} from './escalation.js';
import {
  classifyPrincipals,
  isTrustStatement,
  trustDenyStatements,
  trustFindingDenyState,
} from './trust.js';

// --- Vocabulary --------------------------------------------------------------

function createBuilder() {
  const nodes = new Map(); // id -> node
  const edges = new Map(); // edgeId -> edge
  let truncated = false;

  // The Principal root always exists and does not count against surprising the
  // user with truncation (but it does count toward MAX_NODES for a hard bound).
  const root = principalNode();
  nodes.set(root.id, root);

  function ensureNode(id, type, label, extra) {
    if (nodes.has(id)) return true;
    if (nodes.size >= GRAPH_LIMITS.MAX_NODES) {
      truncated = true;
      return false;
    }
    const node = { id, type, label };
    // Optional flags that carry the analyzer's KNOWN/UNKNOWN distinction to the
    // renderer (IAM-107): e.g. `unknownPrivileges` on a passable-role pivot,
    // `boundaryCrossing` on the service-execution node. These are our own fixed
    // boolean markers, never values from analyzed input, and they do NOT change
    // the node's `type` (which stays within the architecture vocabulary).
    if (extra && typeof extra === 'object') {
      for (const k of Object.keys(extra)) node[k] = extra[k];
    }
    nodes.set(id, node);
    return true;
  }

  // Add (or merge into) an edge from `fromId` (default: the Principal root) to
  // `toId`. Most edges are principal-rooted spokes; escalation-path edges
  // (IAM-107) chain THROUGH an intermediate node (e.g. principal -> passable
  // role -> service execution), so a non-principal `fromId` is supported. A
  // transition edge's source node must ALREADY exist - it is created as the
  // `to` of the preceding principal-rooted edge - which keeps every edge rooted
  // at the principal and prevents a stranded source node at the size cap.
  function addEdge({
    fromId,
    toId,
    toType,
    toLabel,
    toExtra,
    type,
    certainty,
    finding,
    statementIndex,
    label,
    lane,
  }) {
    const sourceId = fromId || PRINCIPAL_ID;
    const edgeId = `${sourceId}|${type}|${toId}`;
    const existing = edges.get(edgeId);
    // Edge cap (IAM-108): a genuinely NEW edge that would push us past the cap
    // is dropped BEFORE its target node is created, so no dangling node is
    // left behind. Merging evidence into an already-present edge is always
    // allowed (it does not grow the edge count).
    if (!existing && edges.size >= GRAPH_LIMITS.MAX_EDGES) {
      truncated = true;
      return;
    }
    // A transition edge whose source node is not present (its rooting edge was
    // dropped, e.g. by the cap) is itself dropped: the graph must stay rooted at
    // the principal, never grow a floating subgraph.
    if (sourceId !== PRINCIPAL_ID && !nodes.has(sourceId)) return;
    // The target node must exist; if the node cap blocked it, drop the edge too.
    if (!ensureNode(toId, toType, toLabel, toExtra)) return;
    const evidence = finding ? evidenceFromFinding(finding) : null;
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
      from: sourceId,
      to: toId,
      type,
      certainty,
      // IAM-401: the semantic lane this edge belongs to. A pure function of the
      // finding kind + relationship, so merges (same from|type|to) always carry
      // the same lane. Falls back to SCOPE for any unmapped edge so the renderer
      // always has a valid lane to place it in.
      lane: typeof lane === 'string' ? lane : LANES.SCOPE,
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
// so the certainty is decided here rather than from f.policyEvidence directly).
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
        const certainty = ruleCertainty(f, denies, model);
        // DENY LEAK FIX (IAM-702): a rule grant whose actions a same-policy
        // explicit Deny FULLY overrides is a suppressed grant. It must NOT emit a
        // positive capability edge (can-write/can-destroy/can-read/... or an
        // `allows` edge) or count toward risk - "denies are not grants"
        // (acceptance suite test 8, cross-test invariant 5). The Deny is still
        // shown on its own `denies` edge (addDenyEdges below); the informational
        // block lives there, not on a phantom positive edge. Partially-narrowed
        // grants (certainty downgraded, not blocked) still draw their edge.
        if (certainty === CERTAINTY.BLOCKED_BY_DENY) continue;
        ruleMap(f, b, certainty, model);
        continue;
      }
      const escMap = ESCALATION_MAP[f.id];
      if (escMap) escMap(f, b);
    }

    // Deny-side edges straight from the model.
    addDenyEdges(model, b);

    const { nodes, edges, truncated } = b.result();

    // IAM-702: a standalone iam:PassRole (broad resource, no compatible service
    // execution primitive) draws a generic delegation edge to `role:passable`.
    // When a compound PassRole path ALSO exists it draws a specific per-service
    // pivot (role:passable:<svc>) for the same delegation, so the generic pivot
    // is redundant - drop it (and its now-orphan node) so delegation is shown
    // once, by the more precise edge. Never removes the LAST delegation edge.
    dropRedundantGenericDelegation(nodes, edges);

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
      limits: { maxNodes: GRAPH_LIMITS.MAX_NODES, maxEdges: GRAPH_LIMITS.MAX_EDGES },
    };
    return frozenResult(true, errors, graph);
  } catch (e) {
    errors.push(err('INTERNAL', 'Graph construction failed unexpectedly.'));
    return frozenResult(false, errors, emptyGraph());
  }
}

// --- Role-trust graph (IAM-802, Phase 8) -------------------------------------
//
// A ROLE TRUST policy is a fundamentally different graph shape from an identity
// policy (docs/trust-policy-semantics.md section 6, acceptance-suite tests
// 15/16). Its origin is the EXTERNAL principal(s) that may assume the role, NOT
// "the Principal subject of this policy" (the identity-graph root). The single
// relationship it models is:
//
//   [external principal(s)] --can-assume--> [this role: target privileges UNKNOWN]
//
// The target node is explicitly marked `unknownPrivileges` so the renderer keeps
// the KNOWN fact (this principal is trusted to assume) visually distinct from the
// UNKNOWN one (what the assumed role can actually do - out of scope; threat-model
// T8). We reuse the existing typed `can-assume` edge; we NEVER reintroduce a
// generic can-write aggregation (the Phase-7 defect stays fixed) and never run
// identity capability edges on a trust policy.
//
// This builder does NOT create the identity-graph Principal root: a trust graph
// that rooted itself at "Principal (subject of this policy)" would contradict the

// The single attached-resource node every resource graph terminates at. Its id
// embeds the attached ARN VERBATIM as inert data (compared/stored/rendered via
// textContent only, never interpreted - T1).
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


export default buildGraph;
