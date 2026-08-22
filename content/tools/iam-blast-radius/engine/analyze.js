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
import { correlateFindings } from './correlate.js';
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
//
// IAM-101: the main table is limited to scannable fields only. The three prose
// columns (why / limit / remediation) that used to sit in the row - and made
// rows ~650px tall by wrapping - are moved OUT into a per-row expandable detail
// (see renderDetailRow in app.js). They stay on the finding object (export +
// detail still carry them); they are simply no longer table COLUMNS.
export const FINDING_COLUMNS = Object.freeze([
  { key: 'severity', label: 'Severity' },
  { key: 'title', label: 'Finding' },
  { key: 'statement', label: 'Statement' },
  { key: 'actions', label: 'Actions' },
  { key: 'resources', label: 'Resources' },
  // IAM-104: the single 'Confidence' column is split into two orthogonal signals.
  { key: 'policyEvidence', label: 'Policy evidence' },
  { key: 'pathExploitability', label: 'Path exploitability' },
]);

// IAM-101: the prose fields that were table columns are now rendered in each
// finding's expandable detail. Kept as a documented, ordered contract so the
// detail renderer (app.js) and any future export stay in sync.
export const FINDING_DETAIL_FIELDS = Object.freeze([
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

// --- Risk summary (IAM-106) --------------------------------------------------
// A scannable header rendered above the authoritative findings table: counts of
// the four highlighted capability families plus the single highest-risk
// escalation path in one line. Pure and deterministic (like findingToRow); the
// app.js renderer walks this structure with createElement+textContent only.

// Ordered category contract for the summary header. The renderer walks these in
// order, so display order is fixed here (highest-leverage family first).
export const SUMMARY_CATEGORIES = Object.freeze([
  { key: 'privEscPaths', label: 'Privilege-escalation paths' },
  { key: 'roleAssumption', label: 'Role-assumption capabilities' },
  { key: 'sensitiveData', label: 'Sensitive-data access capabilities' },
  // IAM-201: renamed - the count reflects only standalone WILDCARD-RESOURCE rows
  // that survive correlation (same-statement capability subsumption folds the
  // rest into their capability finding), so it is a count of STANDALONE broad-
  // resource findings, not of every broad-resource grant in the policy.
  { key: 'broadResource', label: 'Standalone broad-resource findings' },
]);

// Documented, deterministic mapping from finding id -> summary category. Findings
// whose id is absent here (DIRECT-IAM-ADMIN, WILDCARD-ACTION, NOTACTION-ALLOW,
// DESTRUCTIVE-ACTION, DETECTION-IMPAIRMENT) remain in the authoritative table but
// are not part of these four highlighted families - the summary is a curated
// risk overview, not a total. WILDCARD-ACTION is action breadth, not resource
// breadth, so it is intentionally NOT counted under Standalone broad-resource findings.
const SUMMARY_CATEGORY_BY_ID = Object.freeze({
  'PASSROLE-LAMBDA': 'privEscPaths',
  'PASSROLE-EC2': 'privEscPaths',
  'PASSROLE-SERVICE': 'privEscPaths',
  'POLICY-VERSION': 'privEscPaths',
  'ATTACH-POLICY': 'privEscPaths',
  'PUT-INLINE-POLICY': 'privEscPaths',
  'TRUST-POLICY-MODIFY': 'privEscPaths',
  'CREDENTIAL-CREATION': 'privEscPaths',
  'ASSUME-ROLE-EXPANSION': 'roleAssumption',
  'DATA-EXFIL': 'sensitiveData',
  'KMS-DECRYPT': 'sensitiveData',
  'WILDCARD-RESOURCE': 'broadResource',
});

// Human labels for the services a PassRole path can execute code under. Falls
// back to the raw service token (inert data) so an unmapped service is still
// rendered truthfully.
const SERVICE_LABELS = Object.freeze({
  lambda: 'Lambda',
  ec2: 'EC2',
  ecs: 'ECS',
  glue: 'Glue',
  cloudformation: 'CloudFormation',
  sagemaker: 'SageMaker',
  codebuild: 'CodeBuild',
  datapipeline: 'Data Pipeline',
});

function serviceLabel(service) {
  if (!service) return 'the target service';
  return Object.prototype.hasOwnProperty.call(SERVICE_LABELS, service)
    ? SERVICE_LABELS[service]
    : String(service);
}

// A one-line "Principal -> ... -> ..." path for an escalation finding, or null
// when the finding is not an escalation path. Wording stays capability-accurate
// (target role privileges are "unknown"), consistent with IAM-103.
function pathLineFor(finding) {
  const esc = finding && finding.escalation;
  if (!esc || typeof esc.technique !== 'string') return null;
  switch (esc.technique) {
    case 'passrole-service-execution':
      return `Principal -> iam:PassRole -> ${serviceLabel(esc.service)} ` +
        '-> passed role (unknown privileges)';
    case 'assume-role-expansion':
      return 'Principal -> sts:AssumeRole -> assumed role (unknown privileges)';
    case 'policy-version-manipulation':
      return 'Principal -> iam:CreatePolicyVersion -> attacker-selected policy version';
    case 'attach-policy':
      return 'Principal -> iam:Attach*Policy -> attacker-chosen managed policy';
    case 'put-inline-policy':
      return 'Principal -> iam:Put*Policy -> attacker-authored inline policy';
    case 'trust-policy-modification':
      return 'Principal -> iam:UpdateAssumeRolePolicy -> re-trusted role (unknown privileges)';
    case 'credential-creation':
      return 'Principal -> iam:Create*/Update* credential -> new usable principal credentials';
    default:
      return null;
  }
}

/**
 * Build the deterministic risk summary for a (already display-sorted) finding
 * list. Counts are taken over the supplied findings as displayed - subsumed
 * subordinate findings (IAM-105) are already folded out, so they never inflate a
 * count. The highest-risk path is the first finding, in display order, that is an
 * escalation path (has an `escalation` enrichment); since findings are sorted
 * most-severe-first, that is the highest-severity path. null when none exists.
 *
 * @param {Array<object>} findings display-ordered findings
 * @returns {{categories:Array<{key:string,label:string,count:number}>,
 *            highestRisk:({id:string,severity:string,path:string}|null),
 *            total:number}}
 */
export function summarize(findings) {
  const list = Array.isArray(findings) ? findings : [];
  const counts = { privEscPaths: 0, roleAssumption: 0, sensitiveData: 0, broadResource: 0 };
  for (const f of list) {
    const cat = f && SUMMARY_CATEGORY_BY_ID[f.id];
    if (cat) counts[cat] += 1;
  }
  const categories = SUMMARY_CATEGORIES.map((c) => ({
    key: c.key,
    label: c.label,
    count: counts[c.key],
  }));

  let highestRisk = null;
  for (const f of list) {
    const path = pathLineFor(f);
    if (path) {
      highestRisk = { id: String(f.id || ''), severity: String(f.severity || 'info'), path };
      break;
    }
  }

  return { categories, highestRisk, total: list.length };
}

function emptyGraph() {
  return {
    nodes: [],
    edges: [],
    truncated: false,
    limits: { maxNodes: GRAPH_LIMITS.MAX_NODES, maxEdges: GRAPH_LIMITS.MAX_EDGES },
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
    // IAM-105: fold subordinate wildcard/broad-resource rows into the compound
    // escalation path that already accounts for them, so the table shows one
    // primary path finding with a risk-factor checklist instead of duplicate
    // subordinate rows. Independent wildcard findings are untouched.
    const correlated = correlateFindings(combined);
    const findings = Object.freeze(sortFindings(correlated));

    // The graph is built from the full (pre-correlation) finding set: a
    // subsumed wildcard grant is still a real edge in the attack-path model.
    // The findings table stays the authoritative, de-duplicated view.
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
