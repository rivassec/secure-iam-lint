// graph-catalogs.js - node/edge/lane/certainty type catalogs + graph limits + ordering maps. Extracted (behavior-preserving; frozen data).

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
export const NODE_TYPE_ORDER = new Map(
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

export const EDGE_TYPE_ORDER = new Map(
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
export const CERTAINTY_RANK = new Map([
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
export const PRINCIPAL_ID = 'principal';
