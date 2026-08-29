// IAM Blast Radius - analysis coverage summary (IAM-502).
//
// IAM-501 produced a family-gate `coverage` object (detected/override/family/
// supported/blocked/blockingCodes/notes). This module ENRICHES that object into
// a single, compact "Analysis coverage" summary the UI panel and every export
// read from the same source:
//
//   detected family + effective family (+ override),
//   statements accepted / rejected,
//   unrecognized actions (reserved; IAM-507 populates),
//   unsupported conditions / elements,
//   the AWS evaluation layers this single document did NOT cover ("missing
//   layers" - which is what makes "not effective permissions" concrete),
//   graph complete / truncated,
//   build SHA + rule version + catalog version,
//   stable machine-readable codes.
//
// A clean parse is NOT the same as complete coverage (threat-model T8:
// overstated certainty is a security harm). When any unsupported semantic input
// exists, `summary.incomplete` is true and the zero-findings wording flips to
// "No findings in the supported subset - unsupported elements prevent a complete
// conclusion" everywhere reports travel. "Unsupported does NOT mean safe."
//
// Pure, deterministic, dependency-free. No network APIs. No eval/Function. No
// DOM. Same coverage (+ same context) -> same summary, every run.

import { FAMILY_LABELS, COVERAGE_CODES } from './family.js';
import { detectMaskedGrants } from './masked-grant.js';

// No build step ships this tool (architecture invariant 2): what is committed is
// what runs, so there is no build-time SHA injection. This is a committed marker,
// updated by hand at deploy time, that ties a downloaded report back to a shipped
// revision; asset coherence otherwise relies on the per-deploy Cloudflare cache
// purge (see DEPLOY.md). Keep it a short, stable, opaque token.
export const BUILD_SHA = 'dev';

// Rule-catalog version the shipped rules/escalation findings carry (every finding
// this phase has ruleVersion '1'). Distinct from the ACTION-catalog version
// (catalog.js ACTION_CATALOG_VERSION, a dated snapshot supplied by analyze() via
// context.catalogVersion since IAM-507); the two version independently.
export const RULE_VERSION = '1';

// The AWS policy-evaluation layers a single supplied document can only ever be
// ONE of. Naming the layers this analysis did NOT see makes the
// "not effective permissions" caveat concrete: a missing identity/boundary/SCP/
// session layer can only further RESTRICT access, and a missing resource/trust
// layer can also grant cross-account - either way, their absence means no
// effective-permissions conclusion is possible from this document alone.
export const EVALUATION_LAYERS = Object.freeze([
  { key: 'identity', label: 'Identity-based policies' },
  { key: 'resource', label: 'Resource-based policies' },
  { key: 'permissions-boundary', label: 'Permissions boundaries' },
  { key: 'scp', label: 'Service control policies (SCPs)' },
  { key: 'rcp', label: 'Resource control policies (RCPs)' },
  { key: 'session', label: 'Session policies' },
]);

// Which evaluation layer(s) a detected/effective family REPRESENTS, so the rest
// can be listed as missing. Ambiguous/unknown shapes represent nothing (every
// layer is listed as missing).
const FAMILY_LAYERS = Object.freeze({
  identity: ['identity'],
  resource: ['resource'],
  'role-trust': ['resource'],
  'permissions-boundary': ['permissions-boundary'],
  'scp-rcp': ['scp', 'rcp'],
  session: ['session'],
  ambiguous: [],
  unknown: [],
});

// The zero-findings wording, and the flip when coverage is incomplete. Kept as
// exported constants so app.js (UI) and report.js (export) render byte-identical
// text and the flip is unit-testable.
export const NO_FINDINGS_COMPLETE =
  'No blast-radius findings were produced from the supplied policy. This is not ' +
  'proof the policy is safe - it means none of the current rules matched the ' +
  'supplied context.';

export const NO_FINDINGS_INCOMPLETE =
  'No findings in the supported subset - unsupported elements prevent a complete ' +
  'conclusion. Unsupported does NOT mean safe.';

/**
 * Pick the zero-findings message for a coverage object: the incomplete variant
 * whenever any unsupported semantic input exists, otherwise the complete one.
 * Tolerates a null/absent coverage (a failed analysis) -> the complete message.
 *
 * @param {object|null} coverage enriched coverage (with .summary)
 * @returns {string}
 */
export function noFindingsMessage(coverage) {
  const s = coverage && coverage.summary;
  return s && s.incomplete ? NO_FINDINGS_INCOMPLETE : NO_FINDINGS_COMPLETE;
}

/**
 * IAM-1007 (suite-3 test 60): detect non-unique Sids across a policy's
 * statements. AWS does NOT require Sids to be unique within a policy, and
 * JSON.parse keeps colliding-Sid statements as DISTINCT array members (they are
 * different objects, not a duplicate object key - so validate()'s duplicate-key
 * gate does not and must not fire on them). A repeated Sid is nonetheless an
 * evidence-identity hazard: any consumer that keys a finding/graph/DOM/export
 * record on the Sid instead of the 0-based statement INDEX would overwrite one
 * statement's evidence with another's. This engine keys everything on the stable
 * statement index, so the records stay distinct; we still surface the collision
 * as a non-blocking coverage warning so the report names it and a downstream
 * consumer is never misled by a duplicated Sid.
 *
 * Returns a deterministic array of { sid, statementIndexes[] } for every Sid that
 * appears on more than one statement, in first-seen order. Statements with no Sid
 * (null/empty) are never grouped together (an absent Sid is not a collision).
 *
 * @param {object|null} model normalized model
 * @returns {Array<{sid:string, statementIndexes:number[]}>}
 */
export function duplicateSids(model) {
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  const byId = new Map(); // sid -> [statementIndex, ...] (insertion order = first-seen)
  for (const s of statements) {
    if (!s || s.sid == null || s.sid === '') continue;
    const key = String(s.sid);
    if (!byId.has(key)) byId.set(key, []);
    byId.get(key).push(typeof s.index === 'number' ? s.index : null);
  }
  const out = [];
  for (const [sid, indexes] of byId) {
    if (indexes.length > 1) out.push({ sid, statementIndexes: indexes.slice() });
  }
  return out;
}

/**
 * Enrich a family-gate coverage object into the full analysis-coverage summary.
 *
 * Returns a NEW frozen coverage object that is a SUPERSET of the input (every
 * IAM-501 field preserved: detected/override/family/supported/blocked/
 * blockingCodes/notes) plus a `summary` sub-object carrying the IAM-502 fields.
 * One object so the UI panel and the JSON/MD exports read the same source.
 *
 * Never throws. Deterministic (no Date.now()/Math.random()).
 *
 * @param {object} coverage family-gate coverage (from detectFamily)
 * @param {{model?:object, graph?:object, catalogVersion?:string,
 *          unrecognizedActions?:Array, unsupportedConditions?:Array}} [context]
 * @returns {object} enriched, frozen coverage
 */
export function enrichCoverage(coverage, context) {
  const cov = coverage || {};
  const ctx = context || {};
  const model = ctx.model || null;
  const graph = ctx.graph || null;
  const catalogVersion = ctx.catalogVersion || RULE_VERSION;

  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  const total = statements.length;
  // Fail closed: a blocked shape has NOTHING accepted for rule evaluation, so it
  // is truthfully "0 accepted / all rejected". A supported shape evaluates every
  // statement. (When a future phase evaluates a partial subset, this becomes a
  // real per-statement split without changing the contract.)
  const accepted = cov.blocked ? 0 : total;
  const rejected = total - accepted;

  const blockingCodes = Array.isArray(cov.blockingCodes) ? cov.blockingCodes : [];

  // Unsupported ELEMENTS: recognized-but-unmodeled elements, derived from the
  // blocking codes. Today only NotPrincipal; kept generic so a future element
  // slots in by adding its coverage code here.
  // IAM-1206: a Deny + NotPrincipal blocking code carries a high-confidence
  // hazard marker + the specific hazard message (permissions-boundary trap +
  // ArnNotEquals recommendation). Carry both onto the unsupported-element entry
  // so the summary, the JSON/Markdown exports, and the UI can render it as a
  // first-class security hazard, not a generic unmodeled element.
  const notPrincipalElements = blockingCodes
    .filter((b) => b && b.code === COVERAGE_CODES.UNSUPPORTED_NOTPRINCIPAL)
    .map((b) => Object.freeze({
      element: 'NotPrincipal',
      code: b.code,
      path: b.path || null,
      hazard: b.hazard === true,
      hazardMessage: b.hazard === true && typeof b.message === 'string' ? b.message : null,
    }));

  // IAM-903: invalid partial-wildcard Principal-element ARNs (from analyze()'s
  // trust path). Each is a recognized-but-unmodeled element that makes the trusted
  // set undetermined - a non-blocking coverage warning (analysis continues on any
  // valid principals) that still flips `incomplete` and the zero-findings wording.
  // IAM-1004: an invalid principal may arrive as a bare string (value only) or as
  // { value, path } carrying the exact array-member location (Principal.AWS[1]).
  // Normalize both so the coverage element records the location when known.
  const invalidPrincipals = Array.isArray(ctx.invalidPrincipals)
    ? ctx.invalidPrincipals.map((p) => (
      p && typeof p === 'object'
        ? { value: String(p.value), path: p.path != null ? String(p.path) : null }
        : { value: String(p), path: null }
    ))
    : [];
  const invalidPrincipalElements = invalidPrincipals.map((p) => Object.freeze({
    element: 'Principal',
    code: COVERAGE_CODES.INVALID_PRINCIPAL_WILDCARD_ARN,
    value: p.value,
    path: p.path,
  }));

  const unsupportedElements = notPrincipalElements.concat(invalidPrincipalElements);

  // Supplied by analyze(): the action catalog (IAM-507, catalog.js) reports
  // concrete actions its dated snapshot does not recognize; the condition
  // classifier (IAM-506) reports unsupported conditions. Both are stable arrays
  // so the panel + exports have a fixed shape; each is empty when nothing applies.
  const unrecognizedActions = Array.isArray(ctx.unrecognizedActions)
    ? ctx.unrecognizedActions.map((a) => String(a))
    : [];
  const unsupportedConditions = Array.isArray(ctx.unsupportedConditions)
    ? ctx.unsupportedConditions.map((c) => String(c))
    : [];

  // Stage-11 RC-A (fail-open fix): the model (model.js) records when
  // stripModelSpoof CANONICALIZED a security-relevant token - the source carried
  // an invisible/reordering code point, so the token only exists in its clean form
  // AFTER de-spoofing. Such a token is AWS-INERT (AWS matches the literal requested
  // action/key against the pattern that STILL carries the code point and does not
  // match), so it must never be TRUSTED as coverage: a spoofed Deny/NotAction that
  // the engine "cleans" into a matching pattern would otherwise SUPPRESS a real
  // finding and read CLEAN (the T8 worst-bug). Any canonicalized token flips
  // `incomplete` below - the verdict fails closed exactly like a non-canonical
  // (homograph) token already does, while the model still stores the cleaned value
  // for display. Zero on every legitimate pure-ASCII policy (no false fail-closed).
  const spoofedTokenCount = ctx.model && Number.isFinite(ctx.model.spoofedTokenCount)
    ? ctx.model.spoofedTokenCount
    : 0;

  // IAM-1006 (suite-2 test 50): action/resource-type mismatches - a supplied
  // grant whose action operates on a resource type the supplied ARN cannot
  // identify (an S3 object action scoped to a bucket-only ARN). Each is a
  // non-blocking coverage WARNING that flips `incomplete` (a "complete" analysis
  // must not silently absorb a grant that matches nothing) and carries
  // bucket-vs-object remediation. Never a confirmed-capability finding.
  const actionResourceMismatches = Array.isArray(ctx.actionResourceMismatches)
    ? ctx.actionResourceMismatches.map((m) => Object.freeze({
      statementIndex: Number.isFinite(m && m.statementIndex) ? m.statementIndex : null,
      statementSid: m && m.statementSid != null ? String(m.statementSid) : null,
      actions: Object.freeze(Array.isArray(m && m.actions) ? m.actions.map((a) => String(a)) : []),
      resources: Object.freeze(Array.isArray(m && m.resources) ? m.resources.map((r) => String(r)) : []),
      code: m && m.code ? String(m.code) : 'ACTION_RESOURCE_TYPE_MISMATCH',
      note: m && m.note != null ? String(m.note) : '',
      remediation: m && m.remediation != null ? String(m.remediation) : '',
    }))
    : [];

  // IAM-1007 (test 60): non-unique Sids across statements. A NON-BLOCKING
  // advisory - it does not reduce analytical completeness (every colliding
  // statement is still fully analyzed and keyed on its distinct statement index),
  // so it does NOT flip `incomplete`; it is surfaced as a stable code + a
  // structured summary entry so the report can name the collision.
  const duplicateSidsList = Array.isArray(ctx.duplicateSids)
    ? ctx.duplicateSids.map((d) => Object.freeze({
      sid: String(d && d.sid),
      statementIndexes: Object.freeze(
        Array.isArray(d && d.statementIndexes)
          ? d.statementIndexes.map((n) => (typeof n === 'number' ? n : null))
          : [],
      ),
    }))
    : [];

  // IAM-1201: the resource evaluator's coverage (detected service + attached ARN
  // + enumerated principal types). An ACCEPTED resource family is routed to the
  // resource evaluator, but the service-specific resource finding rules are not
  // yet implemented in this tranche, so the analysis is INCOMPLETE (a resource
  // policy accepted with zero findings must never read as proven-safe). Recorded
  // for the panel/export and contributes to `incomplete` + a stable code.
  const rcov = (ctx.resourceCoverage && typeof ctx.resourceCoverage === 'object')
    ? ctx.resourceCoverage
    : null;
  const resourceContextSummary = rcov
    ? Object.freeze({
      service: rcov.service != null ? String(rcov.service) : null,
      arn: rcov.arn != null ? String(rcov.arn) : null,
      type: rcov.type != null ? String(rcov.type) : null,
      principalTypes: Object.freeze(
        Array.isArray(rcov.principalTypes) ? rcov.principalTypes.map((p) => String(p)) : [],
      ),
      anonymousPresent: !!rcov.anonymousPresent,
      unknownPrincipalTypes: Object.freeze(
        Array.isArray(rcov.unknownPrincipalTypes)
          ? rcov.unknownPrincipalTypes.map((p) => String(p))
          : [],
      ),
      incomplete: !!rcov.incomplete,
      note: rcov.note != null ? String(rcov.note) : '',
    })
    : null;

  // IAM-1508 (S2-guard-parity): masked-grant shapes the model faithfully
  // represents but the rule/escalation/graph engines evaluate as granting nothing
  // (empty NotAction/NotResource complement, malformed condition value, suppressed
  // ForAnyValue never-match). Detected from the model so the SHARED engine - not
  // just the CLI adapter - fails closed on them. Each flips `incomplete` (a masked
  // full-admin/broad-resource grant must never read as a clean, complete analysis)
  // and carries a stable code + JSON path. Frozen structured entries so the CLI/
  // SARIF adapters translate them into fail-closed analyzer-states without
  // re-parsing the raw text (single detection source; the two surfaces cannot drift).
  const maskedGrants = detectMaskedGrants(model).map((g) => Object.freeze({
    element: String(g.element),
    code: String(g.code),
    path: g.path != null ? String(g.path) : null,
    kind: String(g.kind),
  }));

  // S3-dos-budget: the analysis was ABORTED mid-run by the cooperative resource
  // budget (a pathological within-caps policy whose CPU cost - not its size -
  // exploded). This is a hard fail-closed state: the analysis did NOT run to a
  // conclusion, so its (empty) findings prove nothing. It flips `incomplete` and
  // surfaces a stable code + a recognized-but-uncompleted element so the UI's
  // incomplete panel and every export name it, and NEVER read as a clean pass.
  // S1-breadth-classify: broad-but-undecidable resource globs ("?*", "*/*") on Allow
  // statements the rule catalog left finding-free (a non-exfil read like
  // dynamodb:GetItem). Supplied by analyze() (it needs the fired findings to know a
  // statement is uncovered). Each flips `incomplete` and carries a stable code + the
  // statement location, so a broad grant the rules could not cover is never a bare
  // CLEAN. Frozen structured entries for the CLI/SARIF adapters + the UI panel.
  const broadUndecidableUncovered = Array.isArray(ctx.broadUndecidableUncovered)
    ? ctx.broadUndecidableUncovered.map((u) => Object.freeze({
      statementIndex: Number.isFinite(u && u.statementIndex) ? u.statementIndex : null,
      statementSid: u && u.statementSid != null ? String(u.statementSid) : null,
      // Which policy axis the broad-but-uncovered scope rode on: 'Resource' (a broad
      // Resource glob/ARN) or 'NotResource' (a non-empty complement). Defaults to
      // 'Resource' for backward compatibility with entries that predate the axis field.
      axis: (u && u.axis === 'NotResource') ? 'NotResource' : 'Resource',
      value: u && u.value != null ? String(u.value) : '',
    }))
    : [];

  const analysisAborted = ctx.analysisAborted === true;
  const abortedElements = analysisAborted
    ? [Object.freeze({
      element: 'analysis',
      code: 'RESOURCE_BUDGET_EXCEEDED',
      path: null,
      hazard: true,
      hazardMessage:
        'analysis aborted (resource budget): the analysis exceeded its resource ' +
        'budget and was stopped before completing. Zero findings here does NOT mean ' +
        'the policy is safe - it means the policy could not be fully analyzed.',
    })]
    : [];

  const represented = FAMILY_LAYERS[cov.family] || FAMILY_LAYERS[cov.detected] || [];
  const missingLayers = EVALUATION_LAYERS
    .filter((l) => !represented.includes(l.key))
    .map((l) => Object.freeze({ key: l.key, label: l.label }));

  // S2-airtight-incomplete fix (b): a TRUNCATED graph dropped nodes/edges to stay
  // within its bound, so the attack-path model is INCOMPLETE - some capability the
  // policy grants could not be represented. It must flip coverage.summary.incomplete
  // (folded into `incomplete` below) and carry a stable GRAPH_TRUNCATED code, so no
  // surface (browser CLEAN or CLI exit 0) ever reads a truncated analysis as a
  // complete pass. A truncated graph does NOT mean the policy is safe.
  const truncated = !!(graph && graph.truncated);

  // IAM-806: same-policy trust Deny caveat (from summarizeTrustDeny). A trust
  // policy's explicit Deny restricts who may assume the role; it must never be
  // silently discarded from a "complete" analysis. `present` surfaces it; an
  // `unmodeled` one (conditional / partial overlap) contributes to incomplete.
  const trustDenyCtx = (ctx.trustDeny && typeof ctx.trustDeny === 'object') ? ctx.trustDeny : null;
  const trustDeny = trustDenyCtx
    ? Object.freeze({
      present: !!trustDenyCtx.present,
      count: Number.isFinite(trustDenyCtx.count) ? trustDenyCtx.count : 0,
      unmodeled: !!trustDenyCtx.unmodeled,
      note: trustDenyCtx.note ? String(trustDenyCtx.note) : null,
    })
    : Object.freeze({ present: false, count: 0, unmodeled: false, note: null });

  // Any unsupported semantic input makes the coverage incomplete: a blocked
  // shape, a recognized-but-unmodeled element, an unrecognized action, an
  // unsupported condition, or an unmodeled same-policy trust Deny. Drives the
  // zero-findings wording flip + warning state.
  const incomplete = !!cov.blocked
    || unsupportedElements.length > 0
    || unrecognizedActions.length > 0
    || unsupportedConditions.length > 0
    || actionResourceMismatches.length > 0
    || trustDeny.unmodeled
    // IAM-1201: an accepted resource policy whose service-specific rules are not
    // yet implemented is INCOMPLETE (zero findings != proven safe).
    || !!(resourceContextSummary && resourceContextSummary.incomplete)
    // IAM-1508: any masked-grant shape makes the analysis INCOMPLETE - a masked
    // full-admin/broad-resource grant must never read as a clean, complete pass.
    || maskedGrants.length > 0
    // S1-breadth-classify: a broad-but-undecidable resource glob the rules left
    // finding-free is INCOMPLETE (never a bare CLEAN).
    || broadUndecidableUncovered.length > 0
    // S3-dos-budget: an analysis stopped by the resource budget never ran to a
    // conclusion, so it is INCOMPLETE by construction (never a clean pass).
    || analysisAborted
    // S2-airtight-incomplete (b): a truncated attack-path graph dropped edges to
    // stay within its bound, so the analysis could not be fully represented and is
    // INCOMPLETE (a truncated graph is never a bare CLEAN pass).
    || truncated
    // Stage-11 RC-A: a canonicalized (spoofed) security-relevant token cannot be
    // trusted as coverage; the analysis fails closed (never a bare CLEAN).
    || spoofedTokenCount > 0;

  // Stable machine-readable codes carried into exports. Today this mirrors the
  // family gate's blocking codes; future non-blocking coverage codes append here
  // (a clean parse is still not proof of complete coverage).
  const codes = blockingCodes.map((b) => String(b && b.code));
  if (trustDeny.unmodeled) codes.push('TRUST_DENY_UNMODELED');
  // IAM-1006: one stable code when any action/resource-type mismatch is present.
  if (actionResourceMismatches.length > 0) codes.push('ACTION_RESOURCE_TYPE_MISMATCH');
  // IAM-903: a stable, machine-readable code for the invalid-principal coverage
  // warning, emitted once when any invalid wildcard Principal ARN is present.
  if (invalidPrincipalElements.length > 0) codes.push(COVERAGE_CODES.INVALID_PRINCIPAL_WILDCARD_ARN);
  // IAM-1007 (test 60): one stable code when any Sid is non-unique across
  // statements (non-blocking advisory; does not flip `incomplete`).
  if (duplicateSidsList.length > 0) codes.push('DUPLICATE_SID');
  // IAM-1201: a stable code for the accepted-but-foundational resource analysis
  // (service-specific resource rules not yet implemented in this tranche).
  if (resourceContextSummary && resourceContextSummary.incomplete) {
    codes.push(COVERAGE_CODES.RESOURCE_ANALYSIS_INCOMPLETE || 'RESOURCE_ANALYSIS_INCOMPLETE');
  }
  // IAM-1508: one stable code per DISTINCT masked-grant code present (dedup keeps
  // the codes list stable when a shape recurs across statements).
  for (const g of maskedGrants) {
    if (!codes.includes(g.code)) codes.push(g.code);
  }
  // S3-dos-budget: a stable code for a budget-aborted analysis.
  if (analysisAborted && !codes.includes('RESOURCE_BUDGET_EXCEEDED')) {
    codes.push('RESOURCE_BUDGET_EXCEEDED');
  }
  // S1-breadth-classify: one stable code when any broad-but-undecidable uncovered
  // resource glob is present.
  if (broadUndecidableUncovered.length > 0 && !codes.includes('BROAD_RESOURCE_UNDECIDABLE')) {
    codes.push('BROAD_RESOURCE_UNDECIDABLE');
  }
  // S2-airtight-incomplete (b): a stable code for a truncated attack-path graph.
  if (truncated && !codes.includes('GRAPH_TRUNCATED')) {
    codes.push('GRAPH_TRUNCATED');
  }
  // Stage-11 RC-A: a stable code when a security-relevant token was canonicalized
  // by stripModelSpoof (invisible/reordering code point in Action/Resource/
  // Condition/Principal). Names the reason the verdict fails closed.
  if (spoofedTokenCount > 0 && !codes.includes('SPOOFED_TOKEN_NORMALIZED')) {
    codes.push('SPOOFED_TOKEN_NORMALIZED');
  }

  const summary = Object.freeze({
    detectedFamily: cov.detected || 'unknown',
    detectedFamilyLabel: FAMILY_LABELS[cov.detected] || String(cov.detected || 'unknown'),
    effectiveFamily: cov.family || cov.detected || 'unknown',
    override: cov.override || null,
    supported: !!cov.supported,
    blocked: !!cov.blocked,
    incomplete,
    statements: Object.freeze({ total, accepted, rejected }),
    unrecognizedActions: Object.freeze(unrecognizedActions),
    unsupportedConditions: Object.freeze(unsupportedConditions),
    unsupportedElements: Object.freeze(unsupportedElements.concat(abortedElements)),
    // S3-dos-budget: true when the analysis was stopped by the resource budget
    // before completing. A hard fail-closed signal the CLI/SARIF adapters and the
    // browser UI read to report "analysis aborted (resource budget)".
    analysisAborted,
    actionResourceMismatches: Object.freeze(actionResourceMismatches),
    duplicateSids: Object.freeze(duplicateSidsList),
    // IAM-1508: masked-grant analyzer-states (empty NotAction/NotResource
    // complement, malformed condition value, suppressed ForAnyValue never-match).
    // Each { element, code, path, kind } - kind 'malformed' (hard fail-closed) or
    // 'incomplete' (suppressed would-be grant left a trace). Empty for a policy
    // that carries none.
    maskedGrants: Object.freeze(maskedGrants),
    // S1-breadth-classify: broad-but-undecidable resource globs on statements the
    // rule catalog left finding-free (dynamodb:GetItem on "?*"). Each { statementIndex,
    // statementSid, value }. Empty for a policy that carries none.
    broadUndecidableUncovered: Object.freeze(broadUndecidableUncovered),
    // IAM-1201: the attached-resource context recorded for a resource-family
    // analysis (null for every other family). Names the detected service, the
    // attached ARN, and the principal types the policy names, as inert evidence.
    resourceContext: resourceContextSummary,
    missingLayers: Object.freeze(missingLayers),
    trustDeny,
    graph: Object.freeze({ complete: !truncated, truncated }),
    versions: Object.freeze({
      buildSha: BUILD_SHA,
      ruleVersion: RULE_VERSION,
      catalogVersion,
    }),
    codes: Object.freeze(codes),
  });

  return Object.freeze({ ...cov, summary });
}

export default enrichCoverage;
