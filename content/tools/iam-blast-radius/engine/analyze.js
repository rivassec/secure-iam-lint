// Analysis orchestration for the UI shell (IAM-007).
//
// Pure, deterministic, and dependency-free: runs the full engine pipeline
// text -> validate -> model -> (rules + escalations) -> graph and returns a
// single frozen result object. Both worker.js (Web Worker path) and app.js
// (synchronous no-Worker fallback) call analyze(); keeping the orchestration
// here guarantees the two paths produce byte-identical output and lets the
// pipeline be unit-tested under `node --test` with no DOM/Worker present.
//
// Determinism (architecture invariant 8): no Date.now()/Math.random() anywhere.
// Never throws: every failure mode from the underlying engine is surfaced as a
// structured { ok:false, errors[] } result.

import { modelFromText } from './model.js';
import { analyzeRules } from './rules.js';
import { analyzeEscalations } from './escalation.js';
import { buildGraph, GRAPH_LIMITS } from './graph.js';

// The catalog version reported in the UI footer + export. Rule + escalation
// findings all carry ruleVersion '1' in this phase.
export const CATALOG_VERSION = '1';

// Severity display order (highest blast radius first). Used to sort the
// findings table deterministically and by the Markdown/JSON export.
export const SEVERITY_ORDER = Object.freeze({
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
});

function severityRank(sev) {
  return Object.prototype.hasOwnProperty.call(SEVERITY_ORDER, sev)
    ? SEVERITY_ORDER[sev]
    : 99;
}

/**
 * Deterministically order findings for presentation: most severe first, then
 * by originating statement index, then by rule id, then by escalation service
 * (stable tiebreak for multiple services anchored on one statement).
 *
 * Returns a new array; does not mutate the input.
 *
 * @param {Array<object>} findings
 * @returns {Array<object>}
 */
export function sortFindings(findings) {
  const list = Array.isArray(findings) ? findings.slice() : [];
  list.sort((a, b) => {
    const ra = severityRank(a && a.severity);
    const rb = severityRank(b && b.severity);
    if (ra !== rb) return ra - rb;
    const ia = a && typeof a.statementIndex === 'number' ? a.statementIndex : Infinity;
    const ib = b && typeof b.statementIndex === 'number' ? b.statementIndex : Infinity;
    if (ia !== ib) return ia - ib;
    const idA = (a && a.id) || '';
    const idB = (b && b.id) || '';
    if (idA !== idB) return idA < idB ? -1 : 1;
    const sa = (a && a.escalation && a.escalation.service) || '';
    const sb = (b && b.escalation && b.escalation.service) || '';
    return sa < sb ? -1 : sa > sb ? 1 : 0;
  });
  return list;
}

// Fixed column contract for the accessible findings table. The renderer
// (app.js) walks these keys in order; keeping the contract here means the
// column set is unit-testable without a DOM.
export const FINDING_COLUMNS = Object.freeze([
  { key: 'severity', label: 'Severity' },
  { key: 'title', label: 'Finding' },
  { key: 'statement', label: 'Statement' },
  { key: 'actions', label: 'Actions' },
  { key: 'resources', label: 'Resources' },
  { key: 'confidence', label: 'Confidence' },
  { key: 'why', label: 'Why it matters' },
  { key: 'limit', label: 'What this does NOT prove' },
  { key: 'remediation', label: 'Remediation' },
]);

function textList(value) {
  if (Array.isArray(value)) return value.map((v) => String(v)).join(', ');
  if (value === null || value === undefined) return '';
  return String(value);
}

/**
 * Project a finding into the ordered list of table cells (plain strings only).
 * All values are stringified here; the renderer places each string via
 * textContent, so hostile SIDs/ARNs/conditions ride through as inert text.
 *
 * @param {object} finding
 * @returns {Array<{key:string,label:string,text:string}>}
 */
export function findingToRow(finding) {
  const f = finding || {};
  return FINDING_COLUMNS.map((col) => {
    let text;
    switch (col.key) {
      case 'severity':
        text = String(f.severity || 'info');
        break;
      case 'statement':
        text = String(f.statementSid || '');
        break;
      case 'actions':
        text = textList(f.actions);
        break;
      case 'resources':
        text = textList(f.resources);
        break;
      default:
        text = textList(f[col.key]);
    }
    return { key: col.key, label: col.label, text };
  });
}

function emptyGraph() {
  return {
    nodes: [],
    edges: [],
    truncated: false,
    limits: { maxNodes: GRAPH_LIMITS.MAX_NODES },
  };
}

function fail(errors) {
  return Object.freeze({
    ok: false,
    errors: Object.freeze(Array.isArray(errors) ? errors.slice() : []),
    findings: Object.freeze([]),
    model: null,
    graph: Object.freeze(emptyGraph()),
    catalogVersion: CATALOG_VERSION,
    counts: Object.freeze({ findings: 0, edges: 0, nodes: 0 }),
  });
}

/**
 * Run the full analysis pipeline on raw policy text.
 *
 * Never throws. On any validation/model failure returns { ok:false, errors[] }
 * with empty findings/graph. On success returns findings sorted for display,
 * the normalized model, and the graph data structure.
 *
 * @param {string} text raw pasted/imported policy text
 * @returns {{ok:boolean, errors:Array, findings:Array<object>, model:(object|null),
 *            graph:object, catalogVersion:string, counts:object}}
 */
export function analyze(text) {
  try {
    const m = modelFromText(text);
    if (!m.ok) return fail(m.errors);

    const rules = analyzeRules(m.model);
    const esc = analyzeEscalations(m.model);
    const errors = [
      ...(rules.ok ? [] : rules.errors),
      ...(esc.ok ? [] : esc.errors),
    ];
    if (errors.length) return fail(errors);

    const combined = [...rules.findings, ...esc.findings];
    const findings = Object.freeze(sortFindings(combined));

    const g = buildGraph(m.model, combined);
    const graph = g.ok ? g.graph : emptyGraph();

    return Object.freeze({
      ok: true,
      errors: Object.freeze([]),
      findings,
      model: m.model,
      graph,
      catalogVersion: CATALOG_VERSION,
      counts: Object.freeze({
        findings: findings.length,
        edges: graph.edges.length,
        nodes: graph.nodes.length,
      }),
    });
  } catch (e) {
    // Absolute backstop: the UI must never see an uncaught exception.
    return fail([{ code: 'INTERNAL', message: 'Analysis failed unexpectedly.', path: null }]);
  }
}

export default analyze;
