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
import { analyzeRules, ruleFindingDenySuppressed, actionResourceTypeMismatches } from './rules.js';
import { analyzeEscalations } from './escalation.js';
import { analyzeTrust, trustFindingDenyState, summarizeTrustDeny } from './trust.js';
import { analyzeEnvelope } from './envelope.js';
import { correlateFindings } from './correlate.js';
import { buildGraph, buildTrustGraph, GRAPH_LIMITS } from './graph.js';
import { detectFamily, FAMILIES } from './family.js';
import { enrichCoverage, duplicateSids } from './coverage.js';
import { classifyConditions, unsupportedConditionKeys } from './conditions.js';
import { defaultCatalog, unrecognizedActions } from './catalog.js';

// The RULE/finding catalog version reported at the top level of the result (UI
// footer + export "Rule catalog version"). Rule + escalation findings all carry
// ruleVersion '1' in this phase. This is DISTINCT from the ACTION-catalog version
// (catalog.js ACTION_CATALOG_VERSION), a dated snapshot surfaced separately in the
// coverage summary (versions.catalogVersion) - the two version on their own cadence.
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
        // IAM-701: a compound cross-statement finding is granted by MORE THAN
        // ONE statement; showing only the anchor Sid next to the combined action
        // list would imply that one statement granted everything. List every
        // contributing statement's Sid so the cell never mis-attributes an
        // action's origin (the per-action breakdown rides in contributingStatements
        // / the export). Single-statement findings render their one Sid as before.
        text = Array.isArray(f.contributingStatements) && f.contributingStatements.length > 1
          ? f.contributingStatements
            .map((s) => String(s.statementSid || `(index ${s.statementIndex})`))
            .join(', ')
          : String(f.statementSid || '');
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
  // IAM-706: a resource/variable-scoped data-read capability is a sensitive-data
  // access capability too (lower certainty than DATA-EXFIL, still counted here).
  'DATA-READ': 'sensitiveData',
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

// IAM-504: explainable evidence. Every finding must expose the policy FAMILY it
// was evaluated under alongside the statement/action/resource/condition/rule-id/
// certainty/limitation it already carries. The family is an analyze()-level fact
// (rules.js / escalation.js do not know it), so it is stamped here. Findings are
// deep-frozen at creation, so we return NEW objects with the field added rather
// than mutating. Subsumed sub-findings (IAM-105/201) are findings too and get the
// same stamp so a folded row is equally explainable in the export.
function stampFamily(finding, family) {
  if (!finding || typeof finding !== 'object') return finding;
  const subsumed = Array.isArray(finding.subsumed)
    ? finding.subsumed.map((s) => Object.freeze({ ...s, policyFamily: family }))
    : finding.subsumed;
  const stamped = { ...finding, policyFamily: family };
  if (subsumed !== finding.subsumed) stamped.subsumed = Object.freeze(subsumed);
  // IAM-506: attach the condition classification for the condition block this
  // finding carries. This makes the path-exploitability story explainable (why a
  // condition does or does not read like a guardrail) without ever claiming a
  // runtime allow/deny. `null` conditions classify to a stable "not present"
  // shape. This is additive evidence; it does not change severity/exploitability
  // (the escalation/rule engines already fold conditions into those numbers).
  stamped.conditionClassification = classifyConditions(finding.conditions);
  return Object.freeze(stamped);
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
    // IAM-501: input never reached family classification (validation/model
    // failed first), so there is no family/coverage to record.
    family: null,
    coverage: null,
  });
}

// IAM-501: the model parsed cleanly but its SHAPE is not one the engine can
// faithfully evaluate (NotPrincipal, resource/role-trust/other unmodeled family,
// ambiguous mixed shape, or an unmodeled manual override). We STOP before rule
// evaluation and return a BLOCKING COVERAGE STATE: ok:true (the pipeline ran to
// a well-formed conclusion the UI can render), zero findings, an empty graph
// (no confident graph on a shape we do not understand), and the coverage object
// carrying the machine-readable blocking codes + exact JSON paths. Exports read
// `family` + `coverage` from here (requirement: every export records them).
function blockedResult(model, coverage) {
  const graph = emptyGraph();
  // IAM-502: enrich the family-gate coverage into the full analysis-coverage
  // summary (statements accepted/rejected, unsupported elements, missing layers,
  // graph state, versions). A blocked shape has zero statements accepted and is
  // marked incomplete, which flips the zero-findings wording in every export.
  const enriched = enrichCoverage(coverage, {
    model,
    graph,
    // IAM-507: report the ACTION-catalog version (a dated snapshot) and any
    // concrete actions the snapshot does not recognize. A blocked shape is
    // already incomplete, but naming its unknown actions keeps the coverage
    // honest and the version traceable in the export.
    catalogVersion: defaultCatalog.version,
    unrecognizedActions: unrecognizedActions(model, defaultCatalog),
  });
  return Object.freeze({
    ok: true,
    errors: Object.freeze([]),
    findings: Object.freeze([]),
    model,
    graph: Object.freeze(graph),
    catalogVersion: CATALOG_VERSION,
    counts: Object.freeze({ findings: 0, edges: 0, nodes: 0 }),
    family: enriched.family,
    coverage: enriched,
  });
}

// IAM-801: the model parsed cleanly and the family gate classified it as a
// SUPPORTED role-trust policy. Route it to the family-aware trust evaluator
// (engine/trust.js) instead of the identity rules/escalation engine, then build
// the same success-shaped result the identity path returns.
//
// IAM-802: the trust GRAPH now models the external-origin relationship
// (external principal(s) -> can-assume -> this role, target privileges unknown)
// via buildTrustGraph. The origin is the EXTERNAL principals, never the identity
// "Principal subject of this policy" root (acceptance-suite test 15); it reuses
// the typed `can-assume` edge and never emits identity-style capability edges on
// a trust policy. The findings table remains the authoritative view.
function trustResult(model, coverage, effectiveFamily) {
  const trust = analyzeTrust(model);
  if (!trust.ok) return fail(trust.errors);

  // IAM-806: same-policy explicit-Deny precedence for the AUTHORITATIVE TABLE.
  // analyzeTrust is Deny-unaware (a Deny is never a positive trust grant), so a
  // trust grant a same-policy Deny FULLY neutralizes is dropped from the table
  // here - it would otherwise over-claim "any principal may assume" a role that is
  // actually unassumable (threat-model T8). This mirrors the identity path's
  // ruleFindingDenySuppressed filter (IAM-302). buildTrustGraph still receives the
  // FULL trust.findings + model, so it can draw the blocked-by-deny `denies` edge.
  const tableFindings = trust.findings.filter(
    (f) => trustFindingDenyState(f, model) !== 'full',
  );
  const stamped = tableFindings.map((f) => stampFamily(f, effectiveFamily));
  const findings = Object.freeze(sortFindings(stamped));

  // Build the trust graph from the raw trust findings (they carry the typed
  // per-statement Principal evidence buildTrustGraph reads) PLUS the model (for
  // the same-policy Deny edges). On any failure we fall back to an empty graph -
  // the findings table stays authoritative.
  const tg = buildTrustGraph(model, trust.findings);
  const graph = tg.ok ? tg.graph : emptyGraph();
  // IAM-806 (c): never report a "complete" analysis while a neutralizing Deny is
  // silently discarded. summarizeTrustDeny surfaces every same-policy trust Deny
  // as a coverage caveat; an UNMODELED one (conditional / partial overlap) marks
  // coverage incomplete. A fully-modeled Deny (finding suppressed + blocked-by-deny
  // edge) is not itself incomplete, matching the identity engine.
  // IAM-903: surface every INVALID partial-wildcard Principal-element ARN as a
  // coverage warning (from the TRUST-INVALID-PRINCIPAL findings the trust
  // evaluator fails closed to). A clean parse is not complete coverage: an invalid
  // principal element makes the trusted set undetermined, so coverage is flagged
  // incomplete rather than presented as a confident cross-account conclusion.
  // IAM-1004: carry the exact JSON path of each invalid Principal member into the
  // coverage element (Statement[N].Principal.<key>[<i>]) so a poisoned array member
  // (e.g. array index 1) is located, not just listed by value. Falls back to the
  // value-only shape when a finding predates the enriched location fields.
  const invalidPrincipals = trust.findings
    .filter((f) => f.id === 'TRUST-INVALID-PRINCIPAL')
    .flatMap((f) => {
      if (Array.isArray(f.invalidPrincipalPaths) && f.invalidPrincipalPaths.length > 0) {
        return f.invalidPrincipalPaths.map((p) => ({ value: p.value, path: p.path }));
      }
      return f.evidence && f.evidence[0] && Array.isArray(f.evidence[0].principals)
        ? f.evidence[0].principals.map((p) => p.value)
        : [];
    });

  const enriched = enrichCoverage(coverage, {
    model,
    graph,
    catalogVersion: defaultCatalog.version,
    unsupportedConditions: unsupportedConditionKeys(model),
    unrecognizedActions: unrecognizedActions(model, defaultCatalog),
    trustDeny: summarizeTrustDeny(model, trust.findings),
    invalidPrincipals,
    // IAM-1007 (test 60): non-unique Sids are an evidence-identity advisory on
    // any family; the trust path surfaces them too.
    duplicateSids: duplicateSids(model),
  });

  return Object.freeze({
    ok: true,
    errors: Object.freeze([]),
    findings,
    model,
    graph: Object.freeze(graph),
    catalogVersion: CATALOG_VERSION,
    counts: Object.freeze({
      findings: findings.length,
      edges: graph.edges.length,
      nodes: graph.nodes.length,
    }),
    family: enriched.family,
    coverage: enriched,
  });
}

// IAM-1002 (Phase 10): an EXPLICIT permissions-boundary / session selection is
// routed to the family-aware ENVELOPE/RESTRICTION evaluator (engine/envelope.js),
// NEVER to the identity rules/escalation engine. A boundary Allow is a
// maximum-permissions CEILING and a session Allow is a session RESTRICTION -
// neither grants anything - so the identity engine would emit spurious positive
// capability findings and edges (can-read/can-write/can-pass/data-exfil/
// escalation) that a ceiling can never establish (threat-model T8). The graph is
// EMPTY by construction: no positive capability edges for these families. Every
// finding states the intersection semantics (effective permissions are the
// intersection with the identity/parent policy, not supplied here).
function envelopeResult(model, coverage, effectiveFamily) {
  const env = analyzeEnvelope(model, effectiveFamily);
  if (!env.ok) return fail(env.errors);

  const stamped = env.findings.map((f) => stampFamily(f, effectiveFamily));
  const findings = Object.freeze(sortFindings(stamped));

  // No positive capability edges for an envelope/restriction family - the graph
  // is empty. The findings table (ceiling breadth + intersection caveat) is the
  // authoritative and only representation.
  const graph = emptyGraph();

  const enriched = enrichCoverage(coverage, {
    model,
    graph,
    catalogVersion: defaultCatalog.version,
    unsupportedConditions: unsupportedConditionKeys(model),
    unrecognizedActions: unrecognizedActions(model, defaultCatalog),
    // IAM-1007 (test 60): non-unique Sids advisory (envelope/session family).
    duplicateSids: duplicateSids(model),
  });

  return Object.freeze({
    ok: true,
    errors: Object.freeze([]),
    findings,
    model,
    graph: Object.freeze(graph),
    catalogVersion: CATALOG_VERSION,
    counts: Object.freeze({
      findings: findings.length,
      edges: graph.edges.length,
      nodes: graph.nodes.length,
    }),
    family: enriched.family,
    coverage: enriched,
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
export function analyze(text, options) {
  try {
    const m = modelFromText(text);
    if (!m.ok) return fail(m.errors);

    // IAM-501: classify the policy family from shape (auto-detect by default;
    // an optional manual override is honored). Fail closed BEFORE any rule
    // evaluation on a shape the engine does not model - never present confident
    // identity findings on a resource/trust/ambiguous/NotPrincipal document.
    const coverage = detectFamily(m.model, options || {});
    if (coverage.blocked) return blockedResult(m.model, coverage);

    const effectiveFamily = coverage.family || coverage.detected || 'unknown';

    // IAM-801 (Phase 8): a role-trust policy is routed to the family-aware TRUST
    // evaluator, NEVER to the identity rules/escalation engine. A trust policy
    // conveys WHO MAY ASSUME the role, not the role's permissions; running
    // identity rules on it would emit spurious identity-style findings (e.g. a
    // broad-Resource finding for the Resource a trust policy legitimately omits).
    // Every trust finding carries the limitation that the assumed role's
    // permissions are out of scope / unknown.
    if (effectiveFamily === FAMILIES.ROLE_TRUST) {
      return trustResult(m.model, coverage, effectiveFamily);
    }

    // IAM-1002 (Phase 10): an explicit permissions-boundary / session selection
    // is a CEILING/RESTRICTION, not a grant. Route it to the envelope evaluator
    // (no positive capability edges, no escalation) rather than the identity
    // engine. Auto-detect never reaches here (it cannot distinguish these from
    // identity); only an explicit override selects them.
    if (effectiveFamily === FAMILIES.PERMISSIONS_BOUNDARY
      || effectiveFamily === FAMILIES.SESSION) {
      return envelopeResult(m.model, coverage, effectiveFamily);
    }

    const rules = analyzeRules(m.model);
    const esc = analyzeEscalations(m.model, options || {});
    const errors = [
      ...(rules.ok ? [] : rules.errors),
      ...(esc.ok ? [] : esc.errors),
    ];
    if (errors.length) return fail(errors);

    const combined = [...rules.findings, ...esc.findings];

    // IAM-302: same-policy explicit-Deny precedence for the AUTHORITATIVE TABLE.
    // rules.js is deliberately Deny-UNAWARE when it emits findings so the graph
    // can still draw the `blocked-by-deny` edge for a granted-but-denied
    // capability (a Phase-2 invariant). Here we drop from the TABLE only those
    // rule findings whose capability a same-policy Deny fully removes (fully
    // blocked, or a broad bulk-read fenced to a narrow set). Escalation findings
    // already have Deny folded in by escalation.js. The graph below still
    // receives the FULL `combined` set, so blocked-by-deny edges are preserved.
    const tableFindings = combined.filter(
      (f) => !ruleFindingDenySuppressed(f, m.model),
    );

    // IAM-105: fold subordinate wildcard/broad-resource rows into the compound
    // escalation path that already accounts for them, so the table shows one
    // primary path finding with a risk-factor checklist instead of duplicate
    // subordinate rows. Independent wildcard findings are untouched.
    const correlated = correlateFindings(tableFindings);
    // IAM-504: stamp the effective policy family onto every finding so each row
    // carries the full explainable-evidence set (family + statement + action +
    // resource + condition + rule id + certainty + limitation). effectiveFamily
    // is computed once above (used by the trust-family branch too).
    const stamped = correlated.map((f) => stampFamily(f, effectiveFamily));
    const findings = Object.freeze(sortFindings(stamped));

    // The graph is built from the full (pre-correlation, pre-Deny-suppression)
    // finding set: a subsumed wildcard grant is still a real edge, and a
    // Deny-blocked capability is still shown as a blocked-by-deny edge. The
    // findings table stays the authoritative, de-duplicated, live-capability view.
    const g = buildGraph(m.model, combined);
    const graph = g.ok ? g.graph : emptyGraph();

    // IAM-502: enrich the family-gate coverage into the full analysis-coverage
    // summary now that the model + graph exist (statement counts, graph
    // complete/truncated, missing evaluation layers, versions). Exports and the
    // coverage panel read this single object.
    // IAM-506: report condition keys the classifier does not model as
    // unsupported conditions. A single such key marks coverage incomplete
    // (unsupported does NOT mean safe) - the honest signal that the analysis
    // could not reason about part of the request-context gating.
    // IAM-507: the ACTION-catalog reports concrete actions it does not recognize
    // as "unknown action" in coverage (not an error, not silently dropped), and
    // its dated version travels in the summary. Unknown actions mark coverage
    // incomplete - the snapshot could not vouch for that grant (unsupported does
    // NOT mean safe). The catalog sits behind an interface (defaultCatalog) so a
    // generated/sharded snapshot can replace it without touching this pipeline.
    const enriched = enrichCoverage(coverage, {
      model: m.model,
      graph,
      catalogVersion: defaultCatalog.version,
      unsupportedConditions: unsupportedConditionKeys(m.model),
      unrecognizedActions: unrecognizedActions(m.model, defaultCatalog),
      // IAM-1006 (test 50): object-action vs bucket-only-ARN mismatches - a
      // non-blocking coverage warning so an ineffective grant is never reported
      // as a complete, empty analysis.
      actionResourceMismatches: actionResourceTypeMismatches(m.model),
      // IAM-1007 (test 60): non-unique Sids across statements - a non-blocking
      // evidence-identity advisory (statements stay keyed on their distinct
      // index; the collision is named, never allowed to overwrite a record).
      duplicateSids: duplicateSids(m.model),
    });

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
      // IAM-501/502: the detected/selected family + enriched coverage summary
      // travel with every successful result so exports and the coverage panel
      // can name the family they analyzed and what they did / did not cover.
      family: enriched.family,
      coverage: enriched,
    });
  } catch (e) {
    // Absolute backstop: the UI must never see an uncaught exception.
    return fail([{ code: 'INTERNAL', message: 'Analysis failed unexpectedly.', path: null }]);
  }
}

export default analyze;
