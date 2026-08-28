// graph-result.js - shared graph-result helpers: deterministic node/edge comparators, empty-graph builder, frozen-result wrapper, deepFreeze. Imported by all three graph builders. Extracted (behavior-preserving).
import { GRAPH_LIMITS, NODE_TYPE_ORDER, EDGE_TYPE_ORDER } from './graph-catalogs.js';

export function compareNodes(a, c) {
  const ao = NODE_TYPE_ORDER.has(a.type) ? NODE_TYPE_ORDER.get(a.type) : 999;
  const co = NODE_TYPE_ORDER.has(c.type) ? NODE_TYPE_ORDER.get(c.type) : 999;
  if (ao !== co) return ao - co;
  return a.id < c.id ? -1 : a.id > c.id ? 1 : 0;
}

export function compareEdges(a, c) {
  const ai = a.statementIndex === null ? Infinity : a.statementIndex;
  const ci = c.statementIndex === null ? Infinity : c.statementIndex;
  if (ai !== ci) return ai - ci;
  const at = EDGE_TYPE_ORDER.has(a.type) ? EDGE_TYPE_ORDER.get(a.type) : 999;
  const ct = EDGE_TYPE_ORDER.has(c.type) ? EDGE_TYPE_ORDER.get(c.type) : 999;
  if (at !== ct) return at - ct;
  if (a.to !== c.to) return a.to < c.to ? -1 : 1;
  return a.id < c.id ? -1 : a.id > c.id ? 1 : 0;
}

export function emptyGraph() {
  return {
    nodes: [],
    edges: [],
    truncated: false,
    limits: { maxNodes: GRAPH_LIMITS.MAX_NODES, maxEdges: GRAPH_LIMITS.MAX_EDGES },
  };
}

export function frozenResult(ok, errors, graph) {
  deepFreeze(graph);
  return Object.freeze({ ok, errors: Object.freeze(errors), graph });
}

export function deepFreeze(value) {
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
