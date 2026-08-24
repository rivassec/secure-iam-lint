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
  // IAM-202: kms:Decrypt is its own edge type, distinct from a plain data read.
  CAN_DECRYPT: 'can-decrypt',
  CAN_WRITE: 'can-write',
  CAN_DESTROY: 'can-destroy',
  // IAM-1202: a resource-policy grant lets an external/anonymous principal act on
  // the ATTACHED resource. Its own typed edge (never aggregated into can-write) so
  // "who can access this resource" reads distinctly from an identity capability.
  CAN_ACCESS_RESOURCE: 'can-access-resource',
});

// Semantic attack-path lanes (IAM-401). Every edge is assigned to exactly one
// lane so the renderer can group paths into labeled sections instead of a flat
// radial layout where every node competes. The lane is a VISUAL/ORGANIZATIONAL
// grouping only - it never changes a finding's severity, certainty, or the AWS
// semantics a finding asserts. Lane ids/labels are our own fixed vocabulary,
// never derived from analyzed input.
//   PRIVILEGE ESCALATION - paths that let the principal gain privileges:
//     the PassRole -> passable role [unknown privileges] -> service-execution
//     transition, plus IAM self-administration (policy/credential/trust
//     manipulation).
//   IDENTITY EXPANSION   - sts:AssumeRole reaching other roles.
//   DATA ACCESS          - sensitive-data reads and KMS decryption.
//   SCOPE                - broad-resource / wildcard-scope grants and direct
//     resource/telemetry impact that is not itself an escalation path.
//   EXPLICIT DENY        - same-policy Deny edges (the most decisive fact),
//     kept in their own lane so a block never sits inside a grant lane.
export const LANES = Object.freeze({
  PRIVILEGE_ESCALATION: 'privilege-escalation',
  IDENTITY_EXPANSION: 'identity-expansion',
  DATA_ACCESS: 'data-access',
  SCOPE: 'scope',
  EXPLICIT_DENY: 'explicit-deny',
});

// Deterministic lane order (escalation first, denies last). The renderer walks
// non-empty lanes in this order; empty lanes are omitted (no empty headings).
export const LANE_ORDER = Object.freeze([
  LANES.PRIVILEGE_ESCALATION,
  LANES.IDENTITY_EXPANSION,
  LANES.DATA_ACCESS,
  LANES.SCOPE,
  LANES.EXPLICIT_DENY,
]);

export const CERTAINTY = Object.freeze({
  // IAM-202 vocabulary. `confirmed-by-policy` replaces the former
  // `confirmed-by-context`; `context-required` replaces `conditionally-reachable`;
  // `policy-supported` is new (grants present, transition needs an out-of-scope
  // precondition this policy cannot prove - e.g. a usable passable target role).
  CONFIRMED_BY_POLICY: 'confirmed-by-policy',
  POLICY_SUPPORTED: 'policy-supported',
  CONTEXT_REQUIRED: 'context-required',
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
  // Hard cap on graph edges (IAM-108, threat-model T5). A node can carry
  // several distinct edges (e.g. a PassRole path adds both can-pass and
  // can-execute-as to one Service node), so the edge count can outgrow the
  // node count; it needs its own bound. Real policies produce a handful of
  // edges; 900 is far above any legitimate result yet bounds a pathological
  // policy that would otherwise emit thousands of multi-edges. When adding a
  // NEW edge would exceed this, the edge (and any node it alone would have
  // created) is dropped and the graph is marked `truncated`. Merging evidence
  // into an existing edge never counts against this cap.
  MAX_EDGES: 900,
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
    EDGE_TYPES.CAN_DECRYPT,
    EDGE_TYPES.CAN_WRITE,
    EDGE_TYPES.CAN_DESTROY,
    EDGE_TYPES.CAN_ACCESS_RESOURCE,
  ].map((t, i) => [t, i]),
);

// Strength ordering so merged edges keep the strongest supporting certainty.
// blocked-by-deny is ranked most-decisive: a definitive Deny is the single most
// important thing to surface. It only ever applies to `denies` edges, which
// never merge with allow-side edges (distinct type), so it cannot mask a grant.
const CERTAINTY_RANK = new Map([
  [CERTAINTY.UNKNOWN_INCOMPLETE_CONTEXT, 0],
  [CERTAINTY.POTENTIALLY_REACHABLE, 1],
  [CERTAINTY.CONTEXT_REQUIRED, 2],
  [CERTAINTY.POLICY_SUPPORTED, 3],
  [CERTAINTY.CONFIRMED_BY_POLICY, 4],
  [CERTAINTY.BLOCKED_BY_DENY, 5],
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

// --- Per-action capability typing (IAM-702) ----------------------------------
// A broad-resource (WILDCARD-RESOURCE) grant is NOT a single "can-write" reach:
// its statement can mix reads, decrypts, delegation, destroys, and genuine
// mutation. Typing every such action under one `can-write` edge aggregates
// unlike capabilities (acceptance suite tests 8, 24, 1) and reuses one edge
// semantic for many - a violation of cross-test invariant 7 ("no semantic edge
// reuse"). classifyCapability() maps one action pattern to the ONE capability it
// represents so the graph can draw a distinctly-typed edge per capability.
//
// These verb tests mirror rules.js's classifiers (kept local so graph.js has no
// new import surface). The over-approximation direction matches rules.js: an
// action that is not a recognized read/destroy/decrypt/delegation is treated as
// a mutating write (the safe direction - never under-state).
const READ_VERB = /^(get|list|describe|view|lookup|search|head|read|batchget)/i;
const DESTRUCTIVE_VERB = /^(delete|terminate|remove|destroy|purge|deregister)/i;

// The verb portion of an action (what follows the first ':'); '' for a bare "*".
function verbOf(pattern) {
  const p = String(pattern);
  const idx = p.indexOf(':');
  return idx === -1 ? '' : p.slice(idx + 1);
}

// Classify ONE action pattern into its single capability kind. Case-insensitive
// (IAM action matching is), so "IAM:passrole" classifies as delegation just like
// "iam:PassRole".
//   'delegation' - iam:PassRole (pass a role to a service; a delegation, never a
//                  plain resource write). Alone this is NOT an execution path.
//   'decrypt'    - kms:Decrypt (turns ciphertext to plaintext; its own edge type,
//                  distinct from a data read - IAM-202).
//   'destroy'    - delete/terminate/remove/destroy/purge/deregister families.
//   'read'       - get/list/describe/... enumeration/read verbs.
//   'write'      - everything else (incl. "*", "service:*", create/update/put):
//                  a genuine broad mutation, the safe over-approximation.
function classifyCapability(pattern) {
  const lower = String(pattern).toLowerCase();
  if (lower === 'iam:passrole') return 'delegation';
  if (lower === 'kms:decrypt') return 'decrypt';
  const verb = verbOf(pattern);
  if (DESTRUCTIVE_VERB.test(verb)) return 'destroy';
  if (READ_VERB.test(verb)) return 'read';
  return 'write';
}

// A finding-shaped evidence carrier for ONE typed edge, carrying only the subset
// of actions that belong to that edge's capability (never the whole aggregate) so
// the edge's evidence attributes exactly its own actions to the statement
// (provenance invariant, IAM-701/702). Reuses the granting finding's statement
// Sid/index, resources, and condition verbatim.
function findingWithActions(f, actions) {
  return {
    id: f.id,
    statementSid: f.statementSid,
    statementIndex: f.statementIndex,
    actions: actions.slice(),
    resources: f.resources,
    conditions: f.conditions,
  };
}

// Map a finding's policyEvidence (IAM-104: the strength of the POLICY-TEXT
// evidence for the grant, formerly the single `confidence` field) to a BASE edge
// certainty class. Edge certainty is about whether THIS policy grants the edge,
// so it keys off policyEvidence, NOT pathExploitability (how likely the grant is
// actually exploitable is a separate signal that never strengthens/weakens what
// the policy text demonstrably says):
//   high   -> confirmed-by-policy    (granted by this policy text, unconditional)
//   medium -> context-required       (a Condition may gate it at runtime)
//   low    -> potentially-reachable  (multiple unknowns stack up)
//
// DENY-AWARENESS (see ruleCertainty / ESCALATION vs RULE findings below).
// escalation.js findings arrive with gating Conditions, unresolved PassedToService
// operators, AND possibly-blocking same-policy Denies ALREADY folded into
// `policyEvidence` (fully-blocked paths are suppressed there entirely), so for those
// findings this base mapping is authoritative. rules.js findings, by contrast,
// fold ONLY Conditions into policyEvidence - they are deliberately NOT Deny-aware (a
// Deny is never itself a blast-radius grant, so rules.js does not model it). That
// left rule edges overstating certainty: a wildcard/destructive/IAM-admin grant
// whose action a same-policy explicit Deny overrides would still read as
// `confirmed-by-policy`, a truthfulness harm (docs/architecture.md #6,
// threat-model T8). graph.js therefore applies AWS explicit-Deny precedence to
// rule findings here, mirroring what escalation.js already does for its own
// findings: see ruleCertainty(). A confirming Condition (e.g. an
// iam:PassedToService that PROVES a path) is not a gate, so it never lowers
// policyEvidence in those engines and is correctly read as confirmed.
function certaintyFromEvidence(policyEvidence) {
  switch (policyEvidence) {
    case 'high':
      return CERTAINTY.CONFIRMED_BY_POLICY;
    case 'medium':
      return CERTAINTY.CONTEXT_REQUIRED;
    default:
      return CERTAINTY.POTENTIALLY_REACHABLE;
  }
}

// PassRole->service transition certainty (IAM-202). A PassRole path always needs
// an OUT-OF-SCOPE precondition the policy cannot prove: a usable target role
// actually exists and its trust policy accepts this service. So even when both
// grants are unconditional (policyEvidence high), the transition is
// `policy-supported`, NOT `confirmed-by-policy` - the policy supports the grants
// but does not confirm the transition end-to-end (threat-model T8: never
// overclaim). A gating Condition on the execution/pass statement still weakens it
// further (medium -> context-required, low -> potentially-reachable).
function passRoleCertainty(policyEvidence) {
  switch (policyEvidence) {
    case 'high':
      return CERTAINTY.POLICY_SUPPORTED;
    case 'medium':
      return CERTAINTY.CONTEXT_REQUIRED;
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
    case CERTAINTY.CONFIRMED_BY_POLICY:
    case CERTAINTY.POLICY_SUPPORTED:
      return CERTAINTY.CONTEXT_REQUIRED;
    case CERTAINTY.CONTEXT_REQUIRED:
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
  const base = certaintyFromEvidence(finding.policyEvidence);
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
      lane: LANES.SCOPE,
    });
  },
  'WILDCARD-RESOURCE': (f, b, certainty, model) => wildcardResourceEdges(f, b, certainty, model),
  'DIRECT-IAM-ADMIN': (f, b, certainty) => {
    // IAM-705 (acceptance test 5): credential creation (iam:CreateAccessKey /
    // iam:Create*LoginProfile / iam:Update*LoginProfile) is an impersonation
    // primitive, NOT a self-policy modification - it mints credentials for a
    // principal, it does not rewrite a policy. A DIRECT-IAM-ADMIN finding whose
    // ONLY actions are credential creation therefore must not draw the
    // can-modify(policy:self) edge; the CREDENTIAL-CREATION escalation already
    // draws the credential-target impersonation edge. A wildcard (iam:* / *) or any
    // genuine policy-editing action keeps the self-modify edge.
    if (isCredentialOnlyAdmin(f)) return;
    selfIamModify(f, b, 'direct IAM administration', certainty);
  },
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
      lane: LANES.SCOPE,
    });
  },
  'DATA-EXFIL': (f, b, certainty) => {
    b.addEdge({
      toId: 'datastore:sensitive-data',
      toType: NODE_TYPES.DATA_STORE,
      toLabel: 'Sensitive data (secrets / objects)',
      type: EDGE_TYPES.CAN_READ,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'reads sensitive data',
      lane: LANES.DATA_ACCESS,
    });
  },
  'KMS-DECRYPT': (f, b, certainty) => {
    b.addEdge({
      toId: 'datastore:kms-decrypt',
      toType: NODE_TYPES.DATA_STORE,
      toLabel: 'KMS-decryptable ciphertext',
      // Decryption of caller-supplied ciphertext for usable keys (IAM-103). This
      // is its OWN edge type `can-decrypt` (IAM-202), distinct from a plain
      // `can-read` data read: it turns ciphertext into plaintext, it does NOT
      // enumerate or retrieve secret material.
      type: EDGE_TYPES.CAN_DECRYPT,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can decrypt ciphertext',
      lane: LANES.DATA_ACCESS,
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
      lane: LANES.SCOPE,
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
      lane: LANES.SCOPE,
    });
  },
  // IAM-1005: adding a user to a group assigns privilege INDIRECTLY through the
  // group. The edge targets the group Resource node (the group is what the ARN
  // scopes; the added user is a request parameter, not resource-scoped), and its
  // certainty stays potential - the group's real permissions are unknown.
  'GROUP-MEMBERSHIP': (f, b) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Group: ${key}`,
      type: EDGE_TYPES.CAN_MODIFY,
      // A group whose actual policies are unknown -> the assignment's reach is a
      // potential, name-inferred one, never confirmed from this policy.
      certainty: CERTAINTY.POTENTIALLY_REACHABLE,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can add a user to this group',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  },
};

// Escalation (escalation.js) mappings.
const ESCALATION_MAP = {
  'PASSROLE-LAMBDA': (f, b) => passRoleEdges(f, b),
  'PASSROLE-EC2': (f, b) => passRoleEdges(f, b),
  'PASSROLE-SERVICE': (f, b) => passRoleEdges(f, b),
  // Escalation findings arrive with same-policy Deny already folded into
  // policyEvidence by escalation.js (fully-blocked paths are suppressed there), so
  // their edge certainty comes straight from policyEvidence.
  'POLICY-VERSION': (f, b) =>
    selfIamModify(f, b, 'managed-policy version manipulation', certaintyFromEvidence(f.policyEvidence)),
  'ATTACH-POLICY': (f, b) =>
    selfIamModify(f, b, 'attach managed policy', certaintyFromEvidence(f.policyEvidence)),
  'PUT-INLINE-POLICY': (f, b) =>
    selfIamModify(f, b, 'write inline policy', certaintyFromEvidence(f.policyEvidence)),
  'TRUST-POLICY-MODIFY': (f, b) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `role:${key}`,
      toType: NODE_TYPES.ROLE,
      toLabel: `Role: ${key}`,
      type: EDGE_TYPES.CAN_MODIFY,
      certainty: certaintyFromEvidence(f.policyEvidence),
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can rewrite trust policy',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  },
  'CREDENTIAL-CREATION': (f, b) => {
    b.addEdge({
      toId: 'principal:credential-target',
      toType: NODE_TYPES.PRINCIPAL,
      toLabel: 'Target principal (credential recipient)',
      type: EDGE_TYPES.CAN_MODIFY,
      certainty: certaintyFromEvidence(f.policyEvidence),
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can mint credentials for',
      lane: LANES.PRIVILEGE_ESCALATION,
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
      lane: LANES.IDENTITY_EXPANSION,
    });
  },
  // IAM-902: the modify-then-assume role-takeover chain renders as same-role typed
  // edges - the principal can MODIFY the role (grant it permissions + rewrite its
  // trust) and can ASSUME it - both pointing at the one role node, so the takeover
  // linkage is explicit and no generic can-write aggregation is used.
  'ROLE-TAKEOVER': (f, b) => roleTakeoverEdges(f, b),
};

// IAM-902: draw the role-takeover linkage with per-statement evidence (IAM-701).
// A can-modify edge (the grant-permissions + modify-trust legs) and a can-assume
// edge (the assume leg) both target the SAME role node, so the same-role
// modify-then-assume chain is visible as two distinctly-typed edges. Each edge
// carries ONLY its own leg's statement + actions, never the finding's combined
// action list re-attributed to the anchor.
function roleTakeoverEdges(f, b) {
  const role = firstResource(f);
  const roleId = `role:${role}`;
  const ev = Array.isArray(f.evidence) ? f.evidence : [];
  const modifyEv = ev.filter((e) => e && (e.role === 'grant-permissions' || e.role === 'modify-trust'));
  const assumeEv = ev.filter((e) => e && e.role === 'assume');
  // Modify leg(s): the grant/trust grants are literally in the policy -> the edge
  // is confirmed-by-policy (a gating Condition already lowered policyEvidence).
  for (const leg of modifyEv) {
    b.addEdge({
      toId: roleId,
      toType: NODE_TYPES.ROLE,
      toLabel: `Role: ${role}`,
      type: EDGE_TYPES.CAN_MODIFY,
      certainty: certaintyFromEvidence(f.policyEvidence),
      finding: edgeEvidenceCarrier(f, leg),
      statementIndex: leg.statementIndex,
      label: 'can grant permissions to / rewrite the trust policy of this role',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  }
  // Assume leg(s): assuming the re-trusted role is a POLICY-SUPPORTED transition -
  // the grant is present, but the actual elevation depends on what the modify leg
  // writes onto the role and any permission boundary / SCP capping it (out of scope).
  for (const leg of assumeEv) {
    b.addEdge({
      toId: roleId,
      toType: NODE_TYPES.ROLE,
      toLabel: `Role: ${role}`,
      type: EDGE_TYPES.CAN_ASSUME,
      certainty: CERTAINTY.POLICY_SUPPORTED,
      finding: edgeEvidenceCarrier(f, leg),
      statementIndex: leg.statementIndex,
      label: 'can assume this role once its trust policy permits it',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  }
}

// IAM credential-creation actions (impersonation primitives). A DIRECT-IAM-ADMIN
// finding whose actions are EXACTLY (case-insensitively) these - and nothing that
// edits a policy - represents credential minting, not self-policy modification, so
// it must not draw the can-modify(policy:self) edge (IAM-705, acceptance test 5).
// Concrete tokens only: a wildcard like "iam:*" is not in this set (it also grants
// policy-editing actions), so a wildcard admin grant keeps the self-modify edge.
const CREDENTIAL_ONLY_ADMIN_ACTIONS = new Set([
  'iam:createaccesskey',
  'iam:createloginprofile',
  'iam:updateloginprofile',
]);
function isCredentialOnlyAdmin(f) {
  const actions = Array.isArray(f.actions) ? f.actions : [];
  return (
    actions.length > 0 &&
    actions.every((a) => CREDENTIAL_ONLY_ADMIN_ACTIONS.has(String(a).toLowerCase()))
  );
}

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
    // IAM self-administration is a privilege-escalation primitive.
    lane: LANES.PRIVILEGE_ESCALATION,
  });
}

// WILDCARD-RESOURCE broad-scope grant -> per-capability typed edges (IAM-702).
// The finding covers a statement whose actions have a broad resource scope
// (Resource "*" or a NotResource fence). Rather than aggregate every action into
// one generic `can-write` edge (which merges unlike capabilities - reads,
// decrypts, delegation, destroys - into one meaningless edge), split the actions
// by capability and draw ONE distinctly-typed edge per capability kind:
//   read       -> can-read     (to the broad resource node)
//   destroy    -> can-destroy  (to the broad resource node; merges with any
//                               DESTRUCTIVE-ACTION edge on the same resource so a
//                               destroy is can-destroy, NOT also can-write)
//   decrypt    -> can-decrypt  (to the shared kms-decrypt datastore; merges with
//                               any KMS-DECRYPT edge - decryption is not a write)
//   delegation -> can-pass     (iam:PassRole to a passable-role pivot; a
//                               delegation edge only. It does NOT create an
//                               execution path - no compatible service-execution
//                               primitive is asserted here, so no can-execute-as.
//                               A later dedup drops this generic pivot when a
//                               compound PassRole path already draws a specific
//                               per-service pivot for the same grant.)
//   write      -> can-write    (genuine broad mutation: create/update/put/"*"/etc)
// Each edge's evidence carries ONLY its own capability's actions, so no action is
// attributed to an edge it does not belong to (provenance, IAM-701/702).
//
// An Allow+NotAction statement is a complement grant ("everything except a listed
// few"); its finding `actions` are the EXCLUDED set, not a concrete granted list,
// so per-action capability typing would be meaningless. For that shape we keep
// the single broad-scope `can-write` edge (unchanged legacy behavior; complement
// semantics are handled elsewhere) rather than typing the exclusion list.
function wildcardResourceEdges(f, b, certainty, model) {
  const key = firstResource(f);
  const stmt = findStatement(model, f.statementIndex);
  const isNotAction = !!(stmt && Array.isArray(stmt.notActions) && stmt.notActions.length > 0);
  if (isNotAction) {
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      type: EDGE_TYPES.CAN_WRITE,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'broad write scope (all-but-listed)',
      lane: LANES.SCOPE,
    });
    return;
  }

  // Group the granted actions by capability, preserving order + determinism.
  // Type edges from the STATEMENT's full action set, not the finding's `actions`:
  // IAM-1006 narrows the WILDCARD-RESOURCE finding row to the remediable (non-read)
  // actions, but the graph is the full per-action capability view and must still
  // draw the can-read edge for an enumeration/read action in the same statement
  // (acceptance test 24). Falls back to the finding actions if the statement is
  // unavailable. The NotAction complement path returned above.
  const typedActions = stmt && Array.isArray(stmt.actions)
    ? stmt.actions
    : (Array.isArray(f.actions) ? f.actions : []);
  const groups = { read: [], destroy: [], decrypt: [], delegation: [], write: [] };
  for (const a of typedActions) {
    groups[classifyCapability(a)].push(a);
  }

  if (groups.read.length > 0) {
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      type: EDGE_TYPES.CAN_READ,
      certainty,
      finding: findingWithActions(f, groups.read),
      statementIndex: f.statementIndex,
      label: 'broad read scope',
      lane: LANES.SCOPE,
    });
  }
  if (groups.destroy.length > 0) {
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      type: EDGE_TYPES.CAN_DESTROY,
      certainty,
      finding: findingWithActions(f, groups.destroy),
      statementIndex: f.statementIndex,
      label: 'can destroy',
      lane: LANES.SCOPE,
    });
  }
  if (groups.decrypt.length > 0) {
    b.addEdge({
      toId: 'datastore:kms-decrypt',
      toType: NODE_TYPES.DATA_STORE,
      toLabel: 'KMS-decryptable ciphertext',
      type: EDGE_TYPES.CAN_DECRYPT,
      certainty,
      finding: findingWithActions(f, groups.decrypt),
      statementIndex: f.statementIndex,
      label: 'can decrypt ciphertext',
      lane: LANES.DATA_ACCESS,
    });
  }
  if (groups.delegation.length > 0) {
    b.addEdge({
      toId: 'role:passable',
      toType: NODE_TYPES.ROLE,
      toLabel: 'Passable role [unknown privileges]',
      toExtra: { unknownPrivileges: true },
      type: EDGE_TYPES.CAN_PASS,
      certainty,
      finding: findingWithActions(f, groups.delegation),
      statementIndex: f.statementIndex,
      label: 'can pass a role (delegation)',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  }
  if (groups.write.length > 0) {
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      type: EDGE_TYPES.CAN_WRITE,
      certainty,
      finding: findingWithActions(f, groups.write),
      statementIndex: f.statementIndex,
      label: 'broad write scope',
      lane: LANES.SCOPE,
    });
  }
}

// PassRole escalations encode the PRIVILEGE TRANSITION, not just the service
// sequence (IAM-107). The graph walks the actual pivot:
//
//   Principal --can-pass (iam:PassRole)--> Passable role [unknown privileges]
//            --can-execute-as (service action)--> Service execution
//                                                 (potential privilege-boundary crossing)
//
// The intermediate ROLE node is the crux: the analyzer KNOWS the principal can
// pass a role to the service and make the service run as it (both grants are in
// the policy text), but it does NOT know that role's actual permissions - so
// whether this crosses a privilege boundary is genuinely unknown from this
// policy alone (threat-model T8: never overclaim). `unknownPrivileges` marks
// that node so the renderer can visually separate what is known (the two edges)
// from what is not (the role's power); `boundaryCrossing` marks the service node
// as the potential crossing point. The passed-role ARN(s) ride in the edge
// evidence (`resources`). Both edges take the PassRole transition certainty
// (IAM-202): even with both grants unconditional the transition is
// `policy-supported`, never `confirmed-by-policy`, because a usable target role
// / accepting trust config is an out-of-scope precondition this policy cannot
// prove. A gating Condition (already folded into policyEvidence by
// escalation.js) weakens it further.
function passRoleEdges(f, b) {
  const svc = f.escalation && f.escalation.service ? String(f.escalation.service) : 'service';
  const certainty = passRoleCertainty(f.policyEvidence);
  const roleId = `role:passable:${svc}`;
  const svcId = `service:${svc}`;
  // IAM-701: attach PER-STATEMENT evidence to each transition edge. A compound
  // PassRole path is distributed across statements (the PassRole grant in one,
  // the service-execution action in another); the finding's evidence[] already
  // holds the correct per-statement records (role 'pass' / 'execute'). The
  // edges MUST carry those same records, not the finding's combined action list
  // re-attributed to the anchor statement - otherwise the can-execute-as edge
  // would claim the exec action came from the PassRole statement (the provenance
  // defect this story fixes). Each edge therefore takes only the actions +
  // statement of its own leg.
  const passEv = Array.isArray(f.evidence) ? f.evidence.find((e) => e && e.role === 'pass') : null;
  const execEv = Array.isArray(f.evidence) ? f.evidence.find((e) => e && e.role === 'execute') : null;
  const passFinding = edgeEvidenceCarrier(f, passEv);
  const execFinding = edgeEvidenceCarrier(f, execEv);
  // IAM-1005: ECS renders the task role and the execution role as SEPARATE nodes
  // (never merged). The task role is the application-credential path (can-pass ->
  // task role -> can-execute-as -> ECS execution); the execution role is startup/
  // pull/logs/secrets influence only (a can-pass edge, NO application can-execute-as
  // edge, no invented task-role node when only the execution role is passable).
  if (svc === 'ecs' && f.escalation && f.escalation.ecs
    && (f.escalation.ecs.taskRoles.length > 0 || f.escalation.ecs.executionRoles.length > 0
      || f.escalation.ecs.hasLaunch === false)) {
    ecsPassRoleEdges(f, b, svc, svcId, certainty, passEv, execEv, passFinding, execFinding);
    return;
  }
  // Hop 1 (KNOWN): the principal can pass a role to the service.
  b.addEdge({
    toId: roleId,
    toType: NODE_TYPES.ROLE,
    toLabel: 'Passable role [unknown privileges]',
    toExtra: { unknownPrivileges: true },
    type: EDGE_TYPES.CAN_PASS,
    certainty,
    finding: passFinding,
    statementIndex: passEv ? passEv.statementIndex : f.statementIndex,
    label: `can pass a role to ${svc}`,
    lane: LANES.PRIVILEGE_ESCALATION,
  });
  // Hop 2 (KNOWN grant, UNKNOWN reach): the service executes as that passed
  // role - a potential privilege-boundary crossing whose blast radius depends on
  // the role's (unknown) privileges. Source is the passable-role pivot from hop 1.
  b.addEdge({
    fromId: roleId,
    toId: svcId,
    toType: NODE_TYPES.SERVICE,
    toLabel: `Service: ${svc} execution`,
    toExtra: { boundaryCrossing: true },
    type: EDGE_TYPES.CAN_EXECUTE_AS,
    certainty,
    finding: execFinding,
    statementIndex: execEv ? execEv.statementIndex : f.statementIndex,
    label: `executes as the passed role (potential privilege-boundary crossing)`,
    lane: LANES.PRIVILEGE_ESCALATION,
  });
}

// IAM-1005: ECS-specific transition edges keeping the task role and execution role
// as distinct nodes (suite-2 test 38, suite-3 tests 87/88/89/90). The application
// task role is the credential-exposure path (can-pass -> task role -> can-execute-as
// -> ECS execution, only when a launch action is present); the execution role gets
// a can-pass edge only (startup/pull/logs/secrets influence), never an application
// can-execute-as edge, and no task-role node is invented when only the execution
// role is passable.
function ecsPassRoleEdges(f, b, svc, svcId, certainty, passEv, execEv, passFinding, execFinding) {
  const ecs = f.escalation.ecs;
  const hasLaunch = ecs.hasLaunch !== false;
  const passStmtIndex = passEv ? passEv.statementIndex : f.statementIndex;
  const execStmtIndex = execEv ? execEv.statementIndex : f.statementIndex;
  // The application-credential path uses the TASK role; an unclassified role is
  // treated conservatively as a possible task role (same as the finding severity).
  const taskCapable = ecs.taskRoles.length > 0 || ecs.unknownRoles.length > 0;
  const hasExec = ecs.executionRoles.length > 0;

  if (taskCapable) {
    const taskRoleId = 'role:passable:ecs:task';
    b.addEdge({
      toId: taskRoleId,
      toType: NODE_TYPES.ROLE,
      toLabel: 'Passable ECS task role [unknown privileges]',
      toExtra: { unknownPrivileges: true, ecsRole: 'task' },
      type: EDGE_TYPES.CAN_PASS,
      certainty,
      finding: passFinding,
      statementIndex: passStmtIndex,
      label: 'can pass the application task role to ECS',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
    // Only a launch action (RunTask/StartTask) actually runs the task and yields
    // the task role's credentials. Staging alone (RegisterTaskDefinition) draws no
    // execution edge - this principal cannot launch it (test 90).
    if (hasLaunch) {
      b.addEdge({
        fromId: taskRoleId,
        toId: svcId,
        toType: NODE_TYPES.SERVICE,
        toLabel: `Service: ${svc} execution`,
        toExtra: { boundaryCrossing: true },
        type: EDGE_TYPES.CAN_EXECUTE_AS,
        certainty,
        finding: execFinding,
        statementIndex: execStmtIndex,
        label: 'application code obtains the task role (potential privilege-boundary crossing)',
        lane: LANES.PRIVILEGE_ESCALATION,
      });
    }
  }

  if (hasExec) {
    // Execution-role influence only: image pulls, log delivery, secret injection at
    // startup. NO application can-execute-as edge (the app does not receive these
    // credentials), so the node is distinct from the task-role credential path.
    b.addEdge({
      toId: 'role:passable:ecs:execution',
      toType: NODE_TYPES.ROLE,
      toLabel: 'Passable ECS execution role [startup: image pull / logs / secrets]',
      toExtra: { unknownPrivileges: true, ecsRole: 'execution' },
      type: EDGE_TYPES.CAN_PASS,
      certainty,
      finding: passFinding,
      statementIndex: passStmtIndex,
      label: 'can pass the ECS execution role (startup influence, not application credentials)',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  }
}

// IAM-701: build a finding-shaped evidence carrier for ONE transition edge from a
// single per-statement escalation evidence record. evidenceFromFinding() reads
// {id, statementSid, statementIndex, actions, resources, conditions}; the
// escalation evidence record stores its condition under `condition` (singular),
// so it is remapped to `conditions` here. Falls back to the whole finding when a
// leg's evidence record is somehow absent (defensive; escalation.js always emits
// both a 'pass' and an 'execute' record for a compound path).
function edgeEvidenceCarrier(finding, ev) {
  if (!ev) return finding;
  return {
    id: finding.id,
    statementSid: typeof ev.statementSid === 'string' ? ev.statementSid : finding.statementSid,
    statementIndex: typeof ev.statementIndex === 'number' ? ev.statementIndex : finding.statementIndex,
    actions: Array.isArray(ev.actions) ? ev.actions.slice() : [],
    resources: Array.isArray(ev.resources) ? ev.resources.slice() : [],
    conditions: ev.condition === undefined ? null : ev.condition,
  };
}

// --- Model Deny statements -> `denies` edges (blocked-by-deny) ----------------
// Findings only cover the Allow side (a Deny never grants blast radius, so it is
// not a finding). But the graph should still SHOW same-policy Denies, since an
// explicit Deny is the single most decisive fact about reachability. Each Deny
// statement becomes one `denies` edge to an ActionGroup node describing what it
// blocks. An unconditional Deny is `blocked-by-deny`; a conditional one is only
// `context-required` (it may not fire).
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
        ? CERTAINTY.CONTEXT_REQUIRED
        : CERTAINTY.BLOCKED_BY_DENY,
      finding: pseudo,
      statementIndex: stmt.index,
      label: usesNotAction ? 'denies all-but-listed' : 'denies',
      lane: LANES.EXPLICIT_DENY,
    });
  }
}

// Drop the generic `role:passable` delegation edge (from a standalone broad
// iam:PassRole) when a specific per-service passable-role pivot
// (`role:passable:<svc>`, drawn by a compound PassRole escalation) already
// represents the same delegation. Operates on the builder's node/edge Maps
// BEFORE ordering/freezing. Removes the now-orphan generic node too. Pure,
// deterministic, never throws.
function dropRedundantGenericDelegation(nodes, edges) {
  const GENERIC = 'role:passable';
  const genericEdgeId = `${PRINCIPAL_ID}|${EDGE_TYPES.CAN_PASS}|${GENERIC}`;
  if (!edges.has(genericEdgeId)) return;
  let hasSpecific = false;
  for (const e of edges.values()) {
    if (e.type === EDGE_TYPES.CAN_PASS && e.to.startsWith(`${GENERIC}:`)) {
      hasSpecific = true;
      break;
    }
  }
  if (!hasSpecific) return;
  edges.delete(genericEdgeId);
  // Remove the orphan node only if no surviving edge still references it.
  let referenced = false;
  for (const e of edges.values()) {
    if (e.from === GENERIC || e.to === GENERIC) {
      referenced = true;
      break;
    }
  }
  if (!referenced) nodes.delete(GENERIC);
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
 *                   limits:{maxNodes:number, maxEdges:number}}}}
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
// trust semantics (acceptance test 15). It is a separate, small, dependency-free
// data builder with the same node/edge cap (threat-model T5) and the same
// deterministic ordering + freeze as buildGraph.

const TRUST_ROLE_ID = 'role:trust-target';
const TRUST_ROLE_LABEL = 'This role (target privileges UNKNOWN)';

// Map one typed Principal entry (trust.js classifyPrincipals categories) to its
// external-origin graph node. Node ids/labels embed the policy's Principal string
// (account id, ARN, provider) VERBATIM as inert data - only ever compared/stored
// here and rendered via textContent, never interpreted as code or markup (T1).
// A service principal is a Service node (a normal AWS service trust, not an
// external attacker origin); everything else is an ExternalPrincipal.
function trustOriginNode(entry) {
  const type = entry && typeof entry === 'object' ? String(entry.type) : '';
  const value = entry && entry.value != null ? String(entry.value) : '';
  switch (type) {
    case 'anonymous':
      return { id: 'ext:anonymous', type: NODE_TYPES.EXTERNAL_PRINCIPAL, label: 'Any principal (public / anonymous)' };
    case 'service':
      return { id: `svc:${value}`, type: NODE_TYPES.SERVICE, label: value };
    case 'aws-account':
      return { id: `ext:${value}`, type: NODE_TYPES.EXTERNAL_PRINCIPAL, label: `AWS account ${value}` };
    case 'aws-root':
      return { id: `ext:${value}`, type: NODE_TYPES.EXTERNAL_PRINCIPAL, label: `${value} (whole account)` };
    case 'aws-principal-arn':
      return { id: `ext:${value}`, type: NODE_TYPES.EXTERNAL_PRINCIPAL, label: value };
    case 'federated-oidc':
    case 'federated-saml':
      return { id: `ext:${value}`, type: NODE_TYPES.EXTERNAL_PRINCIPAL, label: `${value} (federated)` };
    case 'canonical-user':
      return { id: `ext:canonical:${value}`, type: NODE_TYPES.EXTERNAL_PRINCIPAL, label: `${value} (S3 canonical user)` };
    default:
      // Unknown types never reach here (family.js fails closed on them), but stay
      // safe: represent as an external principal keyed by type+value.
      return { id: `ext:${type}:${value}`, type: NODE_TYPES.EXTERNAL_PRINCIPAL, label: value || type };
  }
}

// Trust can-assume certainty: the trust policy TEXT literally grants who may
// assume, so an UNCONDITIONED trust is `confirmed-by-policy` for the assume
// relationship itself (the `unknownPrivileges` target node - not the edge - is
// what prevents any inherited-power overclaim, T8). A CONDITIONED trust is
// `context-required`: a runtime request must still satisfy the Condition
// (ExternalId, org id, source, sub/aud, ...), which this analyzer classifies but
// never evaluates. Text-only; never a runtime STS allow/deny.
function trustEdgeCertainty(finding) {
  const c = finding.conditions;
  const conditioned = c && typeof c === 'object' && !Array.isArray(c) && Object.keys(c).length > 0;
  return conditioned ? CERTAINTY.CONTEXT_REQUIRED : CERTAINTY.CONFIRMED_BY_POLICY;
}

/**
 * Build the external-origin graph for a role-trust policy from its trust findings
 * (engine/trust.js analyzeTrust output). Never throws. Deterministic.
 *
 * Emits ExternalPrincipal/Service origin node(s) -> a single `can-assume` edge ->
 * the target role node (marked unknownPrivileges). NEVER emits identity-style
 * capability edges and NEVER creates the identity Principal root.
 *
 * @param {object} model normalized, frozen model from buildModel()
 * @param {Array<object>} findings trust findings (TRUST-* ids) from analyzeTrust
 * @returns {{ok:boolean, errors:Array, graph:object}}
 */
export function buildTrustGraph(model, findings) {
  const errors = [];
  try {
    if (!model || typeof model !== 'object' || !Array.isArray(model.statements)) {
      errors.push(err('NO_MODEL', 'buildTrustGraph() requires a normalized model.'));
      return frozenResult(false, errors, emptyGraph());
    }
    const findingList = Array.isArray(findings) ? findings : [];
    const nodes = new Map(); // id -> node
    const edges = new Map(); // edgeId -> edge
    let truncated = false;

    function ensureNode(node) {
      if (nodes.has(node.id)) return true;
      if (nodes.size >= GRAPH_LIMITS.MAX_NODES) {
        truncated = true;
        return false;
      }
      nodes.set(node.id, node);
      return true;
    }

    for (const f of findingList) {
      if (!f || typeof f !== 'object' || typeof f.id !== 'string') continue;
      // Only genuine trust findings shape this graph. A defensive guard - the
      // caller (analyze.js trustResult) only passes analyzeTrust findings.
      if (!f.id.startsWith('TRUST-')) continue;
      // TRUST-SESSION-CONTROL is an auxiliary-session-only statement (sts:TagSession
      // / sts:SetSourceIdentity, no assume action): it grants NO assumption, so it
      // must NOT draw a can-assume edge. Emitting one would leak into the graph the
      // exact "may assume" overclaim the finding layer removed (trust.js
      // findingsForStatement; threat-model T8, IAM-805 iteration 3).
      if (f.id === 'TRUST-SESSION-CONTROL') continue;
      // IAM-903: an INVALID partial-wildcard Principal-element ARN is fail-closed
      // (marked invalid + a coverage warning); it must NOT draw a can-assume edge.
      // Drawing one would silently expand the invalid pattern into trust for every
      // role it appears to match - exactly the over-trust the finding layer refuses
      // (threat-model T8). The invalid principal is surfaced in the findings table
      // + coverage, not as a positive graph grant.
      if (f.id === 'TRUST-INVALID-PRINCIPAL') continue;
      // IAM-806: a grant a same-policy trust Deny FULLY neutralizes draws NO
      // can-assume edge - the principal cannot assume the role, so an unqualified
      // can-assume edge would be a false grant ("denies are not grants",
      // threat-model T8). The Deny is shown below on its own blocked-by-deny
      // `denies` edge (mirrors the identity graph: a fully-overridden rule grant
      // emits no positive edge, only the denies edge - graph.test.js IAM-702).
      if (trustFindingDenyState(f, model) === 'full') continue;
      const ev0 = Array.isArray(f.evidence) && f.evidence[0] ? f.evidence[0] : null;
      const principalEntries = ev0 && Array.isArray(ev0.principals) ? ev0.principals : [];
      const certainty = trustEdgeCertainty(f);
      for (const entry of principalEntries) {
        const origin = trustOriginNode(entry);
        const edgeId = `${origin.id}|${EDGE_TYPES.CAN_ASSUME}|${TRUST_ROLE_ID}`;
        const existing = edges.get(edgeId);
        // Edge cap (T5): a genuinely NEW edge past the cap is dropped BEFORE its
        // nodes are created, so no dangling node is left behind.
        if (!existing && edges.size >= GRAPH_LIMITS.MAX_EDGES) {
          truncated = true;
          continue;
        }
        if (!ensureNode(origin)) continue;
        if (!ensureNode({
          id: TRUST_ROLE_ID,
          type: NODE_TYPES.ROLE,
          label: TRUST_ROLE_LABEL,
          // The KNOWN/UNKNOWN marker (IAM-107 convention): the assumed role's
          // actual privileges are out of scope / unknown from a trust policy.
          unknownPrivileges: true,
        })) continue;
        const evidence = evidenceFromFinding(f);
        if (existing) {
          if (CERTAINTY_RANK.get(certainty) > CERTAINTY_RANK.get(existing.certainty)) {
            existing.certainty = certainty;
          }
          existing.evidence.push(evidence);
          if (
            typeof f.statementIndex === 'number' &&
            (existing.statementIndex === null || f.statementIndex < existing.statementIndex)
          ) {
            existing.statementIndex = f.statementIndex;
          }
          continue;
        }
        edges.set(edgeId, {
          id: edgeId,
          from: origin.id,
          to: TRUST_ROLE_ID,
          type: EDGE_TYPES.CAN_ASSUME,
          certainty,
          // The trust relationship groups under IDENTITY EXPANSION: an external
          // principal that may become a principal in your account.
          lane: LANES.IDENTITY_EXPANSION,
          label: 'can assume (target privileges unknown)',
          statementIndex: typeof f.statementIndex === 'number' ? f.statementIndex : null,
          evidence: [evidence],
        });
      }
    }

    // IAM-806: same-policy explicit trust Deny -> blocked-by-deny `denies` edge
    // from each denied external principal to the role (mirrors the identity graph
    // addDenyEdges). A Deny is the single most decisive fact about who may assume,
    // so it is drawn even when it does not overlap any Allow grant. An
    // unconditional Deny is blocked-by-deny; a conditional one is context-required
    // (it may not fire at runtime - text-only classification, never an STS verdict).
    for (const stmt of model.statements) {
      if (!stmt || stmt.effect !== 'Deny' || !isTrustStatement(stmt)) continue;
      const denyPrincipals = classifyPrincipals(stmt.principal);
      const conditioned = hasNonEmptyCondition(stmt);
      const certainty = conditioned ? CERTAINTY.CONTEXT_REQUIRED : CERTAINTY.BLOCKED_BY_DENY;
      const stmtIndex = typeof stmt.index === 'number' ? stmt.index : null;
      const denyActions = Array.isArray(stmt.actions) ? stmt.actions.slice() : [];
      const denyEvidence = Object.freeze({
        findingId: 'TRUST-DENY',
        statementSid:
          typeof stmt.sid === 'string' && stmt.sid.length > 0 ? stmt.sid : `(index ${stmt.index})`,
        statementIndex: stmtIndex,
        actions: denyActions,
        resources: [],
        condition: stmt.condition === undefined ? null : stmt.condition,
      });
      for (const entry of denyPrincipals.entries) {
        const origin = trustOriginNode(entry);
        const edgeId = `${origin.id}|${EDGE_TYPES.DENIES}|${TRUST_ROLE_ID}`;
        const existing = edges.get(edgeId);
        if (!existing && edges.size >= GRAPH_LIMITS.MAX_EDGES) {
          truncated = true;
          continue;
        }
        if (!ensureNode(origin)) continue;
        if (!ensureNode({
          id: TRUST_ROLE_ID,
          type: NODE_TYPES.ROLE,
          label: TRUST_ROLE_LABEL,
          unknownPrivileges: true,
        })) continue;
        if (existing) {
          if (CERTAINTY_RANK.get(certainty) > CERTAINTY_RANK.get(existing.certainty)) {
            existing.certainty = certainty;
          }
          existing.evidence.push(denyEvidence);
          if (
            stmtIndex !== null &&
            (existing.statementIndex === null || stmtIndex < existing.statementIndex)
          ) {
            existing.statementIndex = stmtIndex;
          }
          continue;
        }
        edges.set(edgeId, {
          id: edgeId,
          from: origin.id,
          to: TRUST_ROLE_ID,
          type: EDGE_TYPES.DENIES,
          certainty,
          lane: LANES.EXPLICIT_DENY,
          label: 'denied from assuming this role',
          statementIndex: stmtIndex,
          evidence: [denyEvidence],
        });
      }
    }

    const nodeArr = [...nodes.values()].sort(compareNodes);
    const edgeArr = [...edges.values()].sort(compareEdges);
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
    errors.push(err('INTERNAL', 'Trust graph construction failed unexpectedly.'));
    return frozenResult(false, errors, emptyGraph());
  }
}

// The single attached-resource node every resource graph terminates at. Its id
// embeds the attached ARN VERBATIM as inert data (compared/stored/rendered via
// textContent only, never interpreted - T1).
function resourceTargetNode(context) {
  const arn = context && context.arn != null ? String(context.arn) : '(attached resource)';
  const label = context && context.label ? `${context.label}: ${arn}` : arn;
  return { id: `resource:${arn}`, type: NODE_TYPES.RESOURCE, label, attachedResource: true };
}

// Resource can-access certainty: a resource-policy grant literally names WHO may
// act on the resource, so an UNCONDITIONED grant is `confirmed-by-policy` for the
// direct grant itself (the RESOURCE_LIMIT on the finding, not the edge, is what
// prevents any effective-access overclaim - T8). A CONDITIONED grant is
// `context-required`: a runtime request must still satisfy the Condition, which
// this analyzer classifies but never evaluates. Text-only; never a runtime verdict.
function resourceEdgeCertainty(finding) {
  const c = finding.conditions;
  const conditioned = c && typeof c === 'object' && !Array.isArray(c) && Object.keys(c).length > 0;
  return conditioned ? CERTAINTY.CONTEXT_REQUIRED : CERTAINTY.CONFIRMED_BY_POLICY;
}

/**
 * Build the who-can-access-this-resource graph for a resource-based policy from its
 * resource findings (engine/resource.js output). Never throws. Deterministic.
 *
 * Emits ExternalPrincipal/Service ORIGIN node(s) (the anonymous public principal,
 * an external account/root/principal-ARN, or a service) -> a single
 * `can-access-resource` edge -> the ATTACHED resource node. The origin is the
 * external/anonymous principal, NOT the policy subject: a resource policy is read
 * from the resource's perspective. NEVER emits identity-style capability edges and
 * NEVER creates the identity Principal root.
 *
 * @param {object} model normalized, frozen model
 * @param {Array<object>} findings resource findings (RESOURCE_IDS) from analyzeResource
 * @param {object} context validated attached-resource context (service, arn, label)
 * @returns {{ok:boolean, errors:Array, graph:object}}
 */
export function buildResourceGraph(model, findings, context) {
  const errors = [];
  try {
    if (!model || typeof model !== 'object' || !Array.isArray(model.statements)) {
      errors.push(err('NO_MODEL', 'buildResourceGraph() requires a normalized model.'));
      return frozenResult(false, errors, emptyGraph());
    }
    const findingList = Array.isArray(findings) ? findings : [];
    const target = resourceTargetNode(context || {});
    const nodes = new Map();
    const edges = new Map();
    let truncated = false;

    function ensureNode(node) {
      if (nodes.has(node.id)) return true;
      if (nodes.size >= GRAPH_LIMITS.MAX_NODES) {
        truncated = true;
        return false;
      }
      nodes.set(node.id, node);
      return true;
    }

    for (const f of findingList) {
      if (!f || typeof f !== 'object' || typeof f.id !== 'string') continue;
      // Only genuine resource GRANT findings shape this graph. RESOURCE-CONFUSED-
      // DEPUTY (IAM-1203) draws the SERVICE principal as the origin (test 26: the
      // graph origin is the calling service), never the policy subject.
      if (
        f.id !== 'PUBLIC-ACCESS' &&
        f.id !== 'RESOURCE-CROSS-ACCOUNT' &&
        f.id !== 'RESOURCE-CONFUSED-DEPUTY'
      ) continue;
      const ev0 = Array.isArray(f.evidence) && f.evidence[0] ? f.evidence[0] : null;
      const principalEntries = ev0 && Array.isArray(ev0.principals) ? ev0.principals : [];
      const certainty = resourceEdgeCertainty(f);
      // A "*" grant NARROWED by a principal-scoping condition (aws:PrincipalArn,
      // etc.; resource.js principalScopedBy) is NOT anonymous/public reach - the
      // condition restricts it to authenticated principals (test 85). Represent its
      // origin as a condition-scoped principal node, never the public/anonymous one,
      // so the graph does not assert anonymous reach either.
      const scopedBy = f.resource && Array.isArray(f.resource.principalScopedBy)
        ? f.resource.principalScopedBy
        : [];
      const principalScoped = scopedBy.length > 0;
      for (const entry of principalEntries) {
        // Reuse the trust origin mapping: anonymous "*" -> a public ExternalPrincipal,
        // an account/root/principal-ARN -> ExternalPrincipal, a service -> Service.
        const origin = (principalScoped && entry && entry.type === 'anonymous')
          ? {
              id: `ext:principal-scoped:${scopedBy.join(',')}`,
              type: NODE_TYPES.EXTERNAL_PRINCIPAL,
              label: `Principals matching ${scopedBy.join(', ')} (condition-scoped, not anonymous)`,
            }
          : trustOriginNode(entry);
        const edgeId = `${origin.id}|${EDGE_TYPES.CAN_ACCESS_RESOURCE}|${target.id}`;
        const existing = edges.get(edgeId);
        if (!existing && edges.size >= GRAPH_LIMITS.MAX_EDGES) {
          truncated = true;
          continue;
        }
        if (!ensureNode(origin)) continue;
        if (!ensureNode(target)) continue;
        const evidence = evidenceFromFinding(f);
        if (existing) {
          if (CERTAINTY_RANK.get(certainty) > CERTAINTY_RANK.get(existing.certainty)) {
            existing.certainty = certainty;
          }
          existing.evidence.push(evidence);
          if (
            typeof f.statementIndex === 'number' &&
            (existing.statementIndex === null || f.statementIndex < existing.statementIndex)
          ) {
            existing.statementIndex = f.statementIndex;
          }
          continue;
        }
        edges.set(edgeId, {
          id: edgeId,
          from: origin.id,
          to: target.id,
          type: EDGE_TYPES.CAN_ACCESS_RESOURCE,
          certainty,
          // Access to the resource groups under DATA ACCESS (who can reach the
          // attached resource), never a privilege-escalation or scope lane.
          lane: LANES.DATA_ACCESS,
          label: 'can access this resource (effective access depends on other layers)',
          statementIndex: typeof f.statementIndex === 'number' ? f.statementIndex : null,
          evidence: [evidence],
        });
      }
    }

    const nodeArr = [...nodes.values()].sort(compareNodes);
    const edgeArr = [...edges.values()].sort(compareEdges);
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
    errors.push(err('INTERNAL', 'Resource graph construction failed unexpectedly.'));
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
  return {
    nodes: [],
    edges: [],
    truncated: false,
    limits: { maxNodes: GRAPH_LIMITS.MAX_NODES, maxEdges: GRAPH_LIMITS.MAX_EDGES },
  };
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
