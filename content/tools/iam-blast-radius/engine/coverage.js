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
  const unsupportedElements = blockingCodes
    .filter((b) => b && b.code === COVERAGE_CODES.UNSUPPORTED_NOTPRINCIPAL)
    .map((b) => Object.freeze({ element: 'NotPrincipal', code: b.code, path: b.path || null }));

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

  const represented = FAMILY_LAYERS[cov.family] || FAMILY_LAYERS[cov.detected] || [];
  const missingLayers = EVALUATION_LAYERS
    .filter((l) => !represented.includes(l.key))
    .map((l) => Object.freeze({ key: l.key, label: l.label }));

  const truncated = !!(graph && graph.truncated);

  // Any unsupported semantic input makes the coverage incomplete: a blocked
  // shape, a recognized-but-unmodeled element, an unrecognized action, or an
  // unsupported condition. Drives the zero-findings wording flip + warning state.
  const incomplete = !!cov.blocked
    || unsupportedElements.length > 0
    || unrecognizedActions.length > 0
    || unsupportedConditions.length > 0;

  // Stable machine-readable codes carried into exports. Today this mirrors the
  // family gate's blocking codes; future non-blocking coverage codes append here
  // (a clean parse is still not proof of complete coverage).
  const codes = blockingCodes.map((b) => String(b && b.code));

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
    unsupportedElements: Object.freeze(unsupportedElements),
    missingLayers: Object.freeze(missingLayers),
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
