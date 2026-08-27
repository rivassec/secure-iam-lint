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
import { analyzeRules, ruleFindingDenySuppressed, actionResourceTypeMismatches, survivingBroadReadActions } from './rules.js';
import { analyzeEscalations } from './escalation.js';
import { analyzeTrust, trustFindingDenyState, summarizeTrustDeny } from './trust.js';
import { analyzeEnvelope } from './envelope.js';
import { analyzeScp } from './scp.js';
import { analyzeRcp } from './rcp.js';
import { analyzeResource } from './resource.js';
import { correlateFindings } from './correlate.js';
import { buildGraph, buildTrustGraph, buildResourceGraph, GRAPH_LIMITS } from './graph.js';
import { detectFamily, FAMILIES, isRcpShape } from './family.js';
import { enrichCoverage, duplicateSids } from './coverage.js';
import { classifyConditions, unsupportedConditionKeys } from './conditions.js';
// S1-breadth-classify: the shared Resource-ARN classifier. Used here (post-rules) to
// close the last breadth fail-open the rule engine cannot: ANY value classifyResource()
// reports BROAD - a non-ARN glob ("?*", "*/*") OR a broad WELL-FORMED ARN
// ("arn:aws:dynamodb::*:table/foo", wildcard ACCOUNT) - riding on an Allow statement the
// rule engine covered with NO finding (a non-exfil read like dynamodb:GetItem, which
// fires neither DATA-EXFIL nor WILDCARD-RESOURCE). "broad implies a rule fired" is
// exactly the assumption that fails open (and it fails open identically for a glob and a
// well-formed ARN); this checks the fired findings instead, symmetric across spellings.
import { classifyResource, RESOURCE_CLASS } from './resource-arn.js';
import { defaultCatalog, unrecognizedActions, ACCESS_LEVELS } from './catalog.js';
// Cooperative resource budgets (S3-dos-budget). analyze() arms a DETERMINISTIC
// WORK budget (an op-count ceiling, not a clock - so architecture invariant 8 holds)
// on EVERY run, including the browser/worker path, so a pathological within-caps
// policy whose CPU cost explodes can never return a COMPLETE verdict: it fails CLOSED
// to a graceful in-band "analysis aborted (resource budget)" incomplete result. The
// separate WALL-CLOCK sentinel (armed only by the Node adapter, cli/scan.mjs) is
// RE-THROWN so scan() maps it to its timing-dependent RESOURCE_BUDGET_EXCEEDED verdict.
import { isGlobBudgetError, setWorkLimit, getWorkLimit } from './glob.js';

// Default deterministic WORK ceiling for one analyze() run. Units are ~char-compares
// / automaton word-steps charged inside the shared matcher. Sized FAR above any
// legitimate policy (a within-all-caps policy analyzes in a few million work units)
// yet far below an unbounded runaway, so it never trips a real analysis but bounds a
// pathological one (whose cost comes from the deny-coverage nested loops calling the
// matcher an enormous number of times, not from any single quadratic call). It is an
// op count, not milliseconds, so the trip point is DETERMINISTIC across machines;
// with the now-linear matcher this budget is a backstop, not the primary control.
// Callers may override via options.workLimit (a finite number; <=0 forces an
// immediate abort for tests; Infinity disables it).
export const DEFAULT_WORK_LIMIT = 60000000;

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

// S3-dos-budget: the DETERMINISTIC work budget tripped mid-analysis (a within-caps
// policy whose CPU cost - not its size - exploded). Build a fail-closed, well-formed
// result: ok:true (the UI can render it), ZERO findings, an EMPTY graph, and an
// enriched coverage marked ABORTED + incomplete so no surface reads it as a clean
// pass. Deterministic: the work budget is an op count, so the same input aborts at
// the same point every run. `model`/`coverage` may be null if the trip somehow
// preceded model/family classification (it cannot in practice - the matcher only
// runs after both - but this stays total either way).
function abortedResult(model, coverage) {
  const graph = emptyGraph();
  const baseCoverage = coverage || {
    family: null, detected: 'unknown', supported: false, blocked: false, blockingCodes: [],
  };
  const enriched = enrichCoverage(baseCoverage, {
    model: model || null,
    graph,
    catalogVersion: defaultCatalog.version,
    // The single flag that flips coverage to the aborted/incomplete fail-closed state.
    analysisAborted: true,
  });
  return Object.freeze({
    ok: true,
    errors: Object.freeze([]),
    findings: Object.freeze([]),
    model: model || null,
    graph: Object.freeze(graph),
    catalogVersion: CATALOG_VERSION,
    counts: Object.freeze({ findings: 0, edges: 0, nodes: 0 }),
    family: enriched.family,
    coverage: enriched,
    // A top-level convenience flag mirroring coverage.summary.analysisAborted.
    aborted: true,
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

// IAM-1301 (Phase 13): an EXPLICIT SCP/RCP selection resolved to an SCP-analyzable
// (no-Principal) document is routed to the family-aware SCP CEILING evaluator
// (engine/scp.js), NEVER to the identity rules/escalation engine. An SCP Allow is
// a maximum-permissions CEILING and a Deny is a GUARDRAIL - neither grants - so the
// identity engine would emit spurious positive capability findings and edges
// (can-read/can-write/can-pass/data-exfil/escalation) that a ceiling can never
// establish (threat-model T8; Phase-13 immutable guardrail: an SCP/RCP is a
// ceiling, never a grant). The graph is EMPTY by construction: no positive
// capability edges for this family. Every finding states the intersection
// semantics (effective access is the intersection with identity policies, not
// supplied here) and SCPs never grant.
function scpResult(model, coverage, effectiveFamily) {
  const scp = analyzeScp(model);
  if (!scp.ok) return fail(scp.errors);

  const stamped = scp.findings.map((f) => stampFamily(f, effectiveFamily));
  const findings = Object.freeze(sortFindings(stamped));

  // No positive capability edges for a ceiling/guardrail family - the graph is
  // empty. The findings table (ceiling breadth + guardrail shape + intersection
  // caveat) is the authoritative and only representation.
  const graph = emptyGraph();

  const enriched = enrichCoverage(coverage, {
    model,
    graph,
    catalogVersion: defaultCatalog.version,
    unsupportedConditions: unsupportedConditionKeys(model),
    unrecognizedActions: unrecognizedActions(model, defaultCatalog),
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

// IAM-1302 (Phase 13): an EXPLICIT SCP/RCP selection resolved to an RCP-shaped
// document (a Principal-bearing, DENY-ONLY org resource guardrail carrying an
// org-scope condition key) is routed to the family-aware RCP GUARDRAIL evaluator
// (engine/rcp.js), NEVER to the identity/resource engine. An RCP is deny-only and
// grants nothing; running the resource engine on it would emit a spurious
// public-access / S3 capability finding (from the Principal:"*" + s3:*) that a
// deny-only ceiling can never establish (threat-model T8; Phase-13 immutable
// guardrail: an SCP/RCP is a ceiling, never a grant). The graph is EMPTY by
// construction: no positive capability edges for this family. Every finding states
// the intersection semantics (a corresponding Allow must exist elsewhere; effective
// access is the intersection with identity/resource policies, not supplied here)
// and preserves the confused-deputy condition interaction as one guardrail.
function rcpResult(model, coverage, effectiveFamily) {
  const rcp = analyzeRcp(model);
  if (!rcp.ok) return fail(rcp.errors);

  const stamped = rcp.findings.map((f) => stampFamily(f, effectiveFamily));
  const findings = Object.freeze(sortFindings(stamped));

  // No positive capability edges for a deny-only guardrail family - the graph is
  // empty. The findings table (guardrail shape + intersection caveat) is the
  // authoritative and only representation.
  const graph = emptyGraph();

  const enriched = enrichCoverage(coverage, {
    model,
    graph,
    catalogVersion: defaultCatalog.version,
    unsupportedConditions: unsupportedConditionKeys(model),
    unrecognizedActions: unrecognizedActions(model, defaultCatalog),
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

// IAM-1201 (Phase 12): an EXPLICIT, context-validated resource family is routed
// to the family-aware RESOURCE evaluator (engine/resource.js), NEVER to the
// identity rules/escalation engine. A resource-based policy is analyzed from the
// RESOURCE's perspective (who may act on THIS attached resource); running identity
// rules on it would emit confident but wrong identity-style findings (threat-model
// T8). This foundational tranche accepts + routes the family, records the attached-
// resource context, and reports coverage as INCOMPLETE (the service-specific
// resource finding families are IAM-1202..1206). The graph is EMPTY by
// construction (the external-principal -> resource graph is IAM-1202). Every
// resource finding (none in this tranche) will carry the caveat that effective
// access depends on identity policies + other layers not supplied.
function resourceResult(model, coverage, effectiveFamily, options) {
  const resourceContext = (options && options.resourceContext) || null;
  const res = analyzeResource(model, resourceContext);
  if (!res.ok) return fail(res.errors);

  const stamped = res.findings.map((f) => stampFamily(f, effectiveFamily));
  const findings = Object.freeze(sortFindings(stamped));

  // IAM-1202: the resource GRAPH models the external-origin relationship - each
  // anonymous/external principal named by a resource grant -> a can-access-resource
  // edge -> the ATTACHED resource node (built from res.findings + the validated
  // attached-resource context). The origin is the external principal, NOT the
  // policy subject. On any failure fall back to an empty graph (the findings table
  // + coverage stay the authoritative representation).
  const rg = res.context ? buildResourceGraph(model, res.findings, res.context) : null;
  const graph = rg && rg.ok ? rg.graph : emptyGraph();

  const enriched = enrichCoverage(coverage, {
    model,
    graph,
    catalogVersion: defaultCatalog.version,
    unsupportedConditions: unsupportedConditionKeys(model),
    unrecognizedActions: unrecognizedActions(model, defaultCatalog),
    duplicateSids: duplicateSids(model),
    // IAM-1201: the resource evaluator's coverage (detected service + attached ARN
    // + enumerated principal types) flips coverage to INCOMPLETE so an accepted
    // resource policy with zero findings is never presented as proven-safe.
    resourceCoverage: res.coverage,
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

// A statement carries a RESOURCE-SCOPABLE READ on the bare "*" when at least one of
// its CONCRETE actions resolves (in the action catalog) to the "Read" access level -
// a read that CAN be scoped to a specific ARN (dynamodb:GetItem, iam:GetRole,
// kms:DescribeKey, s3:GetBucketPolicy, secretsmanager:DescribeSecret). Reading such
// an action on Resource "*" is an account-wide broad read the rule catalog leaves
// finding-free (WILDCARD-RESOURCE needs a non-read action; DATA-EXFIL needs the
// s3-bulk/secret catalog), so the bare "*" must NOT be waved through as a decided
// scope - it flips coverage.summary.incomplete exactly as the equally-broad "?*"
// does (broadUndecidableUncovered), symmetric across analyze() and scan().
//
// This is DELIBERATELY the catalog "Read" level, NOT the rules.js verb heuristic:
// an ENUMERATION/LIST action (ec2:DescribeInstances, s3:ListAllMyBuckets, iam:ListRoles)
// is "List" - it genuinely has NO resource-level scoping and AWS REQUIRES Resource "*"
// for it, so flagging its mandatory wildcard would be a false positive (the
// aws-required-wildcard-resource-not-penalized negative fixture). Only CONCRETE tokens
// are consulted: a wildcard action pattern (ec2:Describe*, iam:Get*) spans both Read
// and List members, so it is never treated as a decidably-scopable read here. A
// mutating action would already fire WILDCARD-RESOURCE and cover the statement, so it
// never reaches this net.
//
// Iteration 7: catalog "Read" is NECESSARY but NOT SUFFICIENT for resource-scopability.
// A subset of READ-level actions have NO resource-level permission support and AWS
// REQUIRES Resource "*" for them (ec2:DescribeTags, cloudtrail:LookupEvents /
// DescribeTrails, sts:GetCallerIdentity / GetSessionToken / GetFederationToken). Their
// "*" is service-mandated least privilege, not an avoidable account-wide over-scope, so
// treating it as a decidably-scopable read flipped a minimal, correct policy to
// incomplete - a false positive that re-broke the read-only-wildcard-resource negative
// fixture. The catalog now carries a `requiresWildcardResource` bit (consulted here, NOT
// the READ level alone): only a READ that GENUINELY supports a resource-level ARN
// (dynamodb:GetItem, iam:GetRole, kms:DescribeKey, s3:GetBucketPolicy,
// secretsmanager:DescribeSecret) counts as scopable-on-"*" and flips incomplete; a
// required-wildcard READ stays a decided scope (CLEAN, exit 0). Fail-closed by
// construction: an unlisted required-wildcard action defaults to scopable -> incomplete,
// never a bare CLEAN.
// Returns the statement's resource-scopable READ actions (the list backing
// statementHasScopableReadOnStar). analyze.js's broad-uncovered net then filters
// this list through survivingBroadReadActions() so a read a same-policy Deny fully
// removes or fences-to-narrow is not counted as a surviving broad read.
function statementScopableReadActions(stmt) {
  if (!stmt || !Array.isArray(stmt.actions)) return [];
  return stmt.actions.filter((a) => {
    const res = defaultCatalog.lookup(a);
    return res.known
      && res.accessLevel === ACCESS_LEVELS.READ
      && !res.requiresWildcardResource;
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
  const opts = options || {};
  // S3-dos-budget: arm the DETERMINISTIC work budget for this run (browser + Node).
  // A finite options.workLimit overrides the default (<=0 forces an immediate abort
  // for tests); options.workLimit === Infinity disables it. Save/restore the prior
  // limit so a caller that already armed one (or a wall-clock deadline set by scan())
  // is left exactly as it was. The wall-clock deadline is independent and untouched.
  const prevWorkLimit = getWorkLimit();
  let workLimit = DEFAULT_WORK_LIMIT;
  if (opts.workLimit === Infinity) workLimit = Infinity;
  else if (Number.isFinite(opts.workLimit)) workLimit = opts.workLimit;
  setWorkLimit(workLimit);
  // Refs hoisted so the budget-abort catch can build a coverage-bearing fail-closed
  // result from whatever context the pipeline reached before the trip.
  let model = null;
  let coverageRef = null;
  try {
    const m = modelFromText(text);
    if (!m.ok) return fail(m.errors);
    model = m.model;

    // IAM-501: classify the policy family from shape (auto-detect by default;
    // an optional manual override is honored). Fail closed BEFORE any rule
    // evaluation on a shape the engine does not model - never present confident
    // identity findings on a resource/trust/ambiguous/NotPrincipal document.
    const coverage = detectFamily(m.model, opts);
    coverageRef = coverage;
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

    // IAM-1301 / IAM-1302 (Phase 13): an accepted SCP/RCP family (explicit selection
    // on a guardrail-shaped document - the family gate has already failed closed on
    // any non-guardrail shape) is a CEILING/GUARDRAIL. Route it to the family-aware
    // ceiling evaluator (no positive capability edges, no escalation) rather than
    // the identity/resource engine. The two org-control shapes are disjoint: an SCP
    // is no-Principal (isScpShape rejects Principals) and an RCP is Principal-bearing
    // (isRcpShape requires a Principal on every statement), so a Principal-bearing
    // accepted document is the RCP guardrail and everything else is the SCP ceiling.
    if (effectiveFamily === FAMILIES.SCP_RCP) {
      if (isRcpShape(m.model.statements)) {
        return rcpResult(m.model, coverage, effectiveFamily);
      }
      return scpResult(m.model, coverage, effectiveFamily);
    }

    // IAM-1201 (Phase 12): an accepted resource family (explicit selection + a
    // valid attached-resource context - the family gate has already failed closed
    // otherwise) is routed to the resource evaluator, never the identity engine.
    // Only a NON-blocked accepted resource reaches here (blocked shapes returned
    // via blockedResult above), so this is the accept-and-route path.
    if (effectiveFamily === FAMILIES.RESOURCE) {
      return resourceResult(m.model, coverage, effectiveFamily, options || {});
    }

    const rules = analyzeRules(m.model, options || {});
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
    // Computed HERE (before the broad-uncovered net) because that net keys its
    // "covered" decision off the DENY-SURVIVING findings, not the pre-suppression
    // set - see the coveredStatementIndexes note below.
    const tableFindings = combined.filter(
      (f) => !ruleFindingDenySuppressed(f, m.model),
    );

    // S1-breadth-classify (iter 2): close the residual breadth fail-open the rule
    // catalog is structurally blind to. A resource value classifyResource() reports
    // BROAD - the bare "*", a wildcard high in the ARN (partition/service/ACCOUNT), a
    // whole-collection identifier wildcard (role/*), a bucket-name-segment wildcard, or
    // a boundary-crossing non-ARN glob ("?*"/"*/*") - matches essentially every resource
    // of a service or spans the account boundary. When a finding fired on its Allow
    // statement (s3:GetObject on "?*" -> DATA-EXFIL; iam:PassRole on "arn:aws:iam::*:role/*"
    // -> WILDCARD-RESOURCE) the risk is already surfaced. When NO finding fired the grant
    // would otherwise read as a bare CLEAN: a fail-OPEN (threat-model T8). This is the
    // exact shape of a broad-resource READ: the rule catalog DELIBERATELY treats a
    // read-only wildcard as routine (grantsNonReadAction gates WILDCARD-RESOURCE;
    // DATA-EXFIL needs the s3-bulk/secret catalog), so dynamodb:GetItem / iam:GetRole /
    // kms:DescribeKey / s3:GetBucketPolicy on a BROAD resource fires NEITHER rule.
    //
    // The control MUST hold SYMMETRICALLY across spellings of "read broadly": the glob
    // "?*" and the equally-broad WELL-FORMED ARN "arn:aws:dynamodb::*:table/foo" (wildcard
    // ACCOUNT - a cross-account read) are the SAME broadness from the one shared classifier
    // and must BOTH route to incomplete. So this nets on ONLY two facts: (a) the shared
    // classifier's BROAD verdict, and (b) whether a rule finding actually COVERED the
    // statement - NEVER on "a well-formed ARN implies a rule fired", which is precisely the
    // assumption that fails open (iter-1 excluded well-formed ARNs here via parseArn, which
    // re-instated that assumption and left every broad-well-formed-ARN read a bare CLEAN).
    // Allow-only; the bare "*" is excluded (its scope is fully decided and it is the single
    // most-recognized wildcard the rule catalog owns).
    //
    // Iteration 4: the covered set is built from the DENY-SURVIVING findings
    // (`tableFindings`), NOT the pre-suppression `combined` set. Keying it off
    // `combined` re-instated the forbidden assumption this design warns against:
    // a rule DID fire on a statement, so the statement was marked "covered" and
    // the net SKIPPED it - but the authoritative table later DROPS that finding
    // via ruleFindingDenySuppressed (same-policy Deny precedence / NotResource
    // fence). "A rule fired" then no longer implies "a risk was surfaced": a
    // DIFFERENT surviving broad read on that same statement (dynamodb:GetItem next
    // to a Deny-suppressed s3:GetObject on "arn:aws:...:table/*") was never
    // flagged and the tool returned a bare CLEAN. Keying "covered" off findings
    // that ACTUALLY SURVIVE into the table means a statement whose only finding is
    // Deny-suppressed re-enters this net and its surviving broad read flips
    // incomplete - never a bare CLEAN. Symmetric across both Deny mechanisms
    // (full action-Deny AND NotResource fence) and both covering rules
    // (DATA-EXFIL bulk-read AND secret-read), since both are folded out of
    // tableFindings by the same ruleFindingDenySuppressed filter.
    const coveredStatementIndexes = new Set(
      tableFindings
        .map((f) => (typeof f.statementIndex === 'number' ? f.statementIndex : null))
        .filter((i) => i !== null),
    );
    //
    // Iteration 3: this net must cover the NotResource axis too, symmetric with
    // masked-grant.js's both-axis MALFORMED handling (which already covers Resource
    // AND NotResource). rules.js resourceIsBroad() treats a NON-EMPTY NotResource as
    // broad (Allow-everything-EXCEPT-a-narrow-set spans essentially every ARN), so a
    // routine-read Allow scoped by NotResource (dynamodb:GetItem NotResource
    // arn:aws:s3:::my-bucket/*) fires NO rule yet is account-wide broad. Inspecting
    // only s.resources left that grant a bare CLEAN on the NotResource axis - an
    // internal asymmetry (a malformed NotResource was already caught, a broad-but-
    // well-formed one was not). Both axes now flip incomplete.
    const broadUndecidableUncovered = [];
    for (const s of m.model.statements) {
      if (!s || s.effect !== 'Allow') continue;
      if (coveredStatementIndexes.has(s.index)) continue;
      const sid = (typeof s.sid === 'string' && s.sid.length > 0) ? s.sid : `(index ${s.index})`;
      // Iteration 6: the bare "*" is NOT unconditionally a decided/covered scope. For a
      // RESOURCE-SCOPABLE READ (catalog "Read" level: dynamodb:GetItem, iam:GetRole,
      // kms:DescribeKey, s3:GetBucketPolicy, secretsmanager:DescribeSecret) that no rule
      // covered, Resource "*" is an account-wide broad read the rule catalog is blind to
      // ("*" >= "?*", yet only "?*" was flipping) - it must flip incomplete exactly as
      // "?*" does. An ENUMERATION/LIST read (ec2:DescribeInstances, s3:ListAllMyBuckets,
      // iam:ListRoles) genuinely REQUIRES "*" (no resource-level scoping), so its "*" is
      // still waved through - flagging it would be a false positive. A mutating "*"
      // already fired WILDCARD-RESOURCE, so it never reaches this uncovered net.
      // Iteration 8: EXCLUDE the scope a same-policy explicit Deny covers before
      // treating this statement's broad resource as a surviving broad read. A
      // Deny-suppressed rule finding drops out of tableFindings, so its statement
      // re-enters this net (see the coveredStatementIndexes note) - but if the SAME
      // same-policy Deny fully removes the scopable read (explicit-deny-suppresses-
      // exfil: Deny s3:GetObject "*") or fences its broad scope down to a narrow set
      // (notresource-deny-fences-exfil: Deny NotResource approved-data/*), there is
      // NO surviving broad read and the correct verdict is CLEAN. Keying off the
      // literal "*" resource instead of the fenced effective scope re-flagged those
      // as BROAD_RESOURCE_UNDECIDABLE - a false positive that contradicts Control B
      // (a Deny-suppressed statement with a NARROW surviving resource stays CLEAN).
      // survivingBroadReadActions() applies the identical Deny semantics
      // ruleFindingDenySuppressed() uses (no drift). When the statement HAD scopable
      // reads but a Deny covered them ALL, the broad resource is Deny-decided: skip
      // it (a statement with no scopable reads is unaffected; a partially-surviving
      // read still flips incomplete).
      const scopableReads = statementScopableReadActions(s);
      const survivingReads = survivingBroadReadActions(scopableReads, s, m.model);
      if (scopableReads.length > 0 && survivingReads.length === 0) continue;
      const starIsScopableRead = survivingReads.length > 0;
      // Resource axis: a broad Resource value the rule catalog left uncovered.
      let flagged = false;
      if (Array.isArray(s.resources)) {
        for (const v of s.resources) {
          // The bare "*" is a decided scope EXCEPT when a resource-scopable read rides
          // it uncovered (then it is the broadest possible undecidable-for-coverage read).
          if (String(v).trim() === '*' && !starIsScopableRead) continue;
          if (classifyResource(v) !== RESOURCE_CLASS.BROAD) continue; // narrow/malformed handled elsewhere
          broadUndecidableUncovered.push(Object.freeze({
            statementIndex: s.index,
            statementSid: sid,
            axis: 'Resource',
            value: String(v),
          }));
          flagged = true;
          break; // one entry per statement is enough to mark it incomplete
        }
      }
      if (flagged) continue; // a statement carries either Resource or NotResource, never both
      // NotResource axis: a NON-EMPTY NotResource complement is inherently broad
      // (resourceIsBroad() true). An empty complement is handled by masked-grant
      // (EMPTY_NOTRESOURCE_COMPLEMENT); a malformed member is handled by masked-grant
      // (MALFORMED_RESOURCE_ARN). A broad well-formed complement on an uncovered read
      // fell through both - close it here.
      if (Array.isArray(s.notResources) && s.notResources.length > 0) {
        broadUndecidableUncovered.push(Object.freeze({
          statementIndex: s.index,
          statementSid: sid,
          axis: 'NotResource',
          value: s.notResources.map((v) => String(v)).join(', '),
        }));
      }
    }

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
      // S1-breadth-classify: broad-but-undecidable resource globs on statements the
      // rule catalog left finding-free (dynamodb:GetItem on "?*"). Flips incomplete so
      // an under-covered broad grant is never a bare CLEAN.
      broadUndecidableUncovered,
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
    // S3-dos-budget: a tripped resource budget is not an internal fault.
    if (isGlobBudgetError(e)) {
      // WALL-CLOCK deadline ('clock', armed only by the Node adapter): re-throw so
      // scan() maps it to its timing-dependent RESOURCE_BUDGET_EXCEEDED verdict. This
      // path is never taken on the browser (it never arms a clock).
      if (e.kind === 'clock') throw e;
      // DETERMINISTIC work ceiling ('work', armed on every run incl. the browser):
      // convert to a graceful, well-formed fail-closed result - ok:true, zero
      // findings, coverage marked aborted/incomplete - so a runaway can NEVER return
      // a COMPLETE verdict and NEVER surfaces as an uncaught throw or a clean pass.
      return abortedResult(model, coverageRef);
    }
    // Absolute backstop: the UI must never see an uncaught exception.
    return fail([{ code: 'INTERNAL', message: 'Analysis failed unexpectedly.', path: null }]);
  } finally {
    // Restore the work limit the caller had (Infinity by default), leaving any
    // wall-clock deadline scan() armed untouched.
    setWorkLimit(prevWorkLimit);
  }
}

export default analyze;
