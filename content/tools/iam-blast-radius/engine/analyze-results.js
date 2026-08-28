// analyze-results.js - per-family result assemblers (fail/blocked/aborted/trust/envelope/scp/rcp/resource result objects) + emptyGraph. Extracted (behavior-preserving).
import { ruleFindingDenySuppressed, survivingBroadReadActions } from './rules.js';
import { analyzeTrust, trustFindingDenyState, summarizeTrustDeny } from './trust.js';
import { analyzeEnvelope } from './envelope.js';
import { analyzeScp } from './scp.js';
import { analyzeRcp } from './rcp.js';
import { analyzeResource } from './resource.js';
import { buildTrustGraph, buildResourceGraph, GRAPH_LIMITS } from './graph.js';
import { enrichCoverage, duplicateSids } from './coverage.js';
import { unsupportedConditionKeys } from './conditions.js';
import { defaultCatalog, unrecognizedActions } from './catalog.js';
import { sortFindings, stampFamily, CATALOG_VERSION } from './analyze-format.js';

export function emptyGraph() {
  return {
    nodes: [],
    edges: [],
    truncated: false,
    limits: { maxNodes: GRAPH_LIMITS.MAX_NODES, maxEdges: GRAPH_LIMITS.MAX_EDGES },
  };
}

export function fail(errors) {
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
export function blockedResult(model, coverage) {
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
export function abortedResult(model, coverage) {
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
export function trustResult(model, coverage, effectiveFamily) {
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
export function envelopeResult(model, coverage, effectiveFamily) {
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
export function scpResult(model, coverage, effectiveFamily) {
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
export function rcpResult(model, coverage, effectiveFamily) {
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
export function resourceResult(model, coverage, effectiveFamily, options) {
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
