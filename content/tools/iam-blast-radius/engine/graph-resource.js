// graph-resource.js - resource-graph builder (who can act on THIS resource, from resource-policy findings). Extracted (behavior-preserving).
import { compareEdges, compareNodes, emptyGraph, frozenResult } from './graph-result.js';
import { err, evidenceFromFinding } from './graph-helpers.js';
import { trustOriginNode } from './graph-trust.js';
import { NODE_TYPES, EDGE_TYPES, LANES, CERTAINTY, GRAPH_LIMITS, CERTAINTY_RANK } from './graph-catalogs.js';

export function resourceTargetNode(context) {
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
export function resourceEdgeCertainty(finding) {
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
