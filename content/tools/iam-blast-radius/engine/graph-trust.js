// graph-trust.js - trust-graph builder (who can assume THIS role, from trust-policy findings). Extracted (behavior-preserving).
import { emptyGraph, frozenResult, compareNodes, compareEdges, deepFreeze } from './graph-result.js';
import { err, evidenceFromFinding } from './graph-helpers.js';
import { classifyPrincipals, isTrustStatement } from './trust-classify.js';
import { trustFindingDenyState } from './trust-deny.js';
import { hasNonEmptyCondition } from './escalation-conditions.js';
import { NODE_TYPES, EDGE_TYPES, LANES, CERTAINTY, GRAPH_LIMITS, CERTAINTY_RANK } from './graph-catalogs.js';

// trust semantics (acceptance test 15). It is a separate, small, dependency-free
// data builder with the same node/edge cap (threat-model T5) and the same
// deterministic ordering + freeze as buildGraph.

export const TRUST_ROLE_ID = 'role:trust-target';
export const TRUST_ROLE_LABEL = 'This role (target privileges UNKNOWN)';

// Map one typed Principal entry (trust.js classifyPrincipals categories) to its
// external-origin graph node. Node ids/labels embed the policy's Principal string
// (account id, ARN, provider) VERBATIM as inert data - only ever compared/stored
// here and rendered via textContent, never interpreted as code or markup (T1).
// A service principal is a Service node (a normal AWS service trust, not an
// external attacker origin); everything else is an ExternalPrincipal.
export function trustOriginNode(entry) {
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
export function trustEdgeCertainty(finding) {
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
