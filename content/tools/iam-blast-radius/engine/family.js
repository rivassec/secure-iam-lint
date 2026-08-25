// IAM Blast Radius - policy-family model + fail-closed coverage gate (IAM-501).
//
// A single IAM JSON document can be one of several policy FAMILIES, and the
// rules/escalation engine only models IDENTITY-policy semantics. Running those
// rules on a resource policy, a role trust policy, an SCP, or a NotPrincipal
// statement would produce confident-looking but WRONG conclusions (threat-model
// T8: overstated certainty is a security harm). This module classifies the
// family from the document SHAPE and, when the shape is not one the engine can
// faithfully evaluate, FAILS CLOSED: it returns a blocking coverage state and
// the orchestrator (analyze.js) skips rule evaluation entirely.
//
// Design refinements for this phase:
//   - AUTO-DETECT is the default (preserve paste-and-go). No manual selector is
//     required before Analyze; an OPTIONAL manual override is accepted.
//   - FAIL CLOSED on ambiguous / mixed / unknown shapes and on recognized-but-
//     unmodeled elements (NotPrincipal), each with a machine-readable code and
//     the exact JSON path.
//   - Principal and NotPrincipal are DISTINCT elements (see model.js). This gate
//     rejects NotPrincipal with UNSUPPORTED_NOTPRINCIPAL rather than silently
//     treating it as "no principal".
//
// Pure, deterministic, dependency-free. No network APIs. No eval/Function. No
// DOM. Same input (+ same options) -> same coverage, every run.

// IAM-1201: the resource family is context-gated. The gate validates the explicit
// attached-resource context (type + ARN) via the resource module, which owns the
// service detection and the resource coverage codes.
import { parseResourceContext, RESOURCE_CODES } from './resource.js';

// Recognized families. IDENTITY is the only family the current rule engine
// models; the rest are DETECTED (so exports and the coverage panel can name
// them truthfully) but fail closed until a family-aware evaluator exists.
export const FAMILIES = Object.freeze({
  IDENTITY: 'identity',
  RESOURCE: 'resource',
  ROLE_TRUST: 'role-trust',
  PERMISSIONS_BOUNDARY: 'permissions-boundary',
  SCP_RCP: 'scp-rcp',
  SESSION: 'session',
  // Non-family classifications used when the shape cannot be resolved.
  AMBIGUOUS: 'ambiguous',
  UNKNOWN: 'unknown',
});

// Families the engine can actually evaluate in this phase. Everything else
// fails closed. Kept as a Set so a future phase adds an evaluator by adding a
// family here (plus its rules), without touching this gate's control flow.
// IAM-801 (Phase 8): ROLE_TRUST joins IDENTITY as a supported family - it now
// has a dedicated, family-aware evaluator (engine/trust.js) that the
// orchestrator routes trust statements to instead of the identity rules.
// IAM-1002 (Phase 10): PERMISSIONS_BOUNDARY and SESSION join as supported
// families via the family-aware ENVELOPE/RESTRICTION evaluator (engine/
// envelope.js). They report ceiling breadth but emit NO positive capability
// edges and NO escalation findings (a boundary/session grants nothing). The
// remaining families (resource / scp-rcp) stay fail-closed until each grows its
// own evaluator.
export const SUPPORTED_FAMILIES = Object.freeze(new Set([
  FAMILIES.IDENTITY,
  FAMILIES.ROLE_TRUST,
  FAMILIES.PERMISSIONS_BOUNDARY,
  FAMILIES.SESSION,
]));

// IAM-1002: permissions-boundary and session policies are STRUCTURALLY identical
// to an identity policy (no Principal element) - they cannot be told apart from
// shape. So an EXPLICIT boundary/session selection is valid ONLY on an
// identity-shaped (no-Principal) document; on a Principal-bearing / SCP /
// ambiguous shape it fails closed. Auto-detect never resolves to these families
// (it cannot distinguish them from identity); they are reachable only via an
// explicit manual selection.
const ENVELOPE_FAMILIES = Object.freeze(new Set([
  FAMILIES.PERMISSIONS_BOUNDARY,
  FAMILIES.SESSION,
]));

// The Principal type keys the role-trust evaluator models (trust-policy-
// semantics.md section 2). A role-trust document that names any OTHER Principal
// type is an unmodeled shape: the gate fails closed on it rather than guess
// ("unsupported != safe"). Mirrors trust.js KNOWN_PRINCIPAL_TYPES.
const KNOWN_PRINCIPAL_TYPES = new Set(['AWS', 'Service', 'Federated', 'CanonicalUser']);

// The single IAM policy-language version whose grammar this analyzer models
// (IAM-704). An ABSENT Version is tolerated (the model records null and AWS
// applies default/legacy behavior); any OTHER explicit version - notably the
// legacy '2008-10-17' - is unsupported. The engine NEVER silently rewrites an
// unsupported version to this one; it fails closed instead.
export const SUPPORTED_POLICY_VERSION = '2012-10-17';

// Human labels for the UI / exports. Falls back to the raw token.
export const FAMILY_LABELS = Object.freeze({
  identity: 'Identity policy',
  resource: 'Resource-based policy',
  'role-trust': 'Role trust policy',
  'permissions-boundary': 'Permissions boundary',
  'scp-rcp': 'SCP / RCP (organizations)',
  session: 'Session policy',
  ambiguous: 'Ambiguous / mixed shape',
  unknown: 'Unknown shape',
});

// Stable, machine-readable coverage codes. These travel into every export.
export const COVERAGE_CODES = Object.freeze({
  UNSUPPORTED_NOTPRINCIPAL: 'UNSUPPORTED_NOTPRINCIPAL',
  UNSUPPORTED_POLICY_FAMILY: 'UNSUPPORTED_POLICY_FAMILY',
  AMBIGUOUS_POLICY_SHAPE: 'AMBIGUOUS_POLICY_SHAPE',
  OVERRIDE_SHAPE_MISMATCH: 'OVERRIDE_SHAPE_MISMATCH',
  // IAM-704: a control-policy (SCP/RCP) shape must fail closed rather than fall
  // back to identity rules - SCPs set permission CEILINGS, they do not grant.
  UNSUPPORTED_SCP_SHAPE: 'UNSUPPORTED_SCP_SHAPE',
  // IAM-704: an explicit policy Version this analyzer does not model.
  UNSUPPORTED_POLICY_VERSION: 'UNSUPPORTED_POLICY_VERSION',
  // IAM-801: a role-trust document naming a Principal type the trust evaluator
  // does not model (anything outside AWS/Service/Federated/CanonicalUser). The
  // shape is recognized as role-trust but stays fail-closed - never guessed.
  UNSUPPORTED_PRINCIPAL_TYPE: 'UNSUPPORTED_PRINCIPAL_TYPE',
  // IAM-903: a role-trust document whose AWS Principal-element ARN carries a
  // partial "*"/"?" wildcard - an invalid principal pattern AWS rejects. Surfaced
  // as a non-blocking coverage warning (the statement is fail-closed to a
  // TRUST-INVALID-PRINCIPAL finding, never a plain TRUST-CROSS-ACCOUNT high).
  INVALID_PRINCIPAL_WILDCARD_ARN: 'INVALID_PRINCIPAL_WILDCARD_ARN',
  // IAM-1001 (Phase 10): the UI contract now REQUIRES an explicit policy-family
  // selection before analysis. When a caller demands an explicit selection
  // (requireExplicitFamily) and none was made, analysis fails closed with this
  // code BEFORE any shape classification - the family is never guessed from shape.
  POLICY_FAMILY_REQUIRED: 'POLICY_FAMILY_REQUIRED',
  // IAM-1001: an EXPLICIT Identity selection on a document that carries a
  // Principal element. Identity policies never contain a Principal, so this is a
  // family-shape error; the Principal is never dropped so the rest can be analyzed
  // as an identity grant (test 67).
  UNSUPPORTED_PRINCIPAL: 'UNSUPPORTED_PRINCIPAL',
  // IAM-1001: an EXPLICIT Role-trust selection on a trust-shaped document that
  // carries a Resource. A trust policy applies to the role it is attached to and
  // has no Resource element, so a Resource here is a trust-policy syntax error
  // (test 68).
  UNSUPPORTED_TRUST_RESOURCE: 'UNSUPPORTED_TRUST_RESOURCE',
  // IAM-1103 (11C): a NON-EMPTY family selection that is neither a recognized
  // canonical family, a known synonym (scp/rcp/trust), nor auto-detect. A typo or
  // garbage token ("banana", "scpp", "identityx", "SCP " with stray whitespace)
  // must FAIL CLOSED here rather than fall through to the auto-detect fallback and
  // get silently analyzed as an identity policy (the DEF-05-style fail-OPEN). An
  // absent/empty selection is NOT invalid - it is "no selection" (paste-and-go
  // auto-detect, or POLICY_FAMILY_REQUIRED under the explicit-family contract).
  INVALID_FAMILY: 'INVALID_FAMILY',
  // IAM-1201 (Phase 12): the resource family is now ACCEPTED, but its context is
  // explicit and required. These codes (owned by engine/resource.js) surface here
  // for the gate + every export. RESOURCE_CONTEXT_REQUIRED: family=resource was
  // selected on a resource-policy shape but no valid attached-resource context
  // (type + ARN) was supplied. UNSUPPORTED_RESOURCE_SHAPE: the context parsed to a
  // valid ARN for a service this analyzer does not yet model. Both fail closed.
  RESOURCE_CONTEXT_REQUIRED: RESOURCE_CODES.RESOURCE_CONTEXT_REQUIRED,
  UNSUPPORTED_RESOURCE_SHAPE: RESOURCE_CODES.UNSUPPORTED_RESOURCE_SHAPE,
  // IAM-1201: non-blocking - an accepted resource family whose service-specific
  // finding rules are foundational (not yet implemented), so coverage is
  // incomplete ("zero findings does NOT mean safe").
  RESOURCE_ANALYSIS_INCOMPLETE: RESOURCE_CODES.RESOURCE_ANALYSIS_INCOMPLETE,
});

// IAM-1206: the high-confidence Deny + NotPrincipal hazard warning surfaced on
// the blocking code (and, via coverage.js, on the unsupported-element entry and
// in every export). It states the documented permissions-boundary trap and the
// recommended safe rewrite. Kept as a single constant so the engine, coverage
// summary, and UI all speak with one voice (docs/resource-policy-semantics.md
// section 8; acceptance-suite-2 test 29).
export const NOTPRINCIPAL_DENY_HAZARD_MESSAGE =
  'SECURITY HAZARD: Deny with NotPrincipal is not an ordinary "deny everyone ' +
  'except these" exclusion and cannot be modeled as one. AWS documents that a ' +
  'NotPrincipal element with a Deny effect ALWAYS denies any IAM principal that ' +
  'has a permissions boundary attached, regardless of the principals listed in ' +
  'NotPrincipal - so principals you intended to EXEMPT can still be denied. It is ' +
  'also easy to accidentally deny an entire account. This analyzer does not model ' +
  'NotPrincipal, so it fails closed here rather than render a misleading ordinary-' +
  'deny result. Recommended safe rewrite: Deny on Principal "*" with ' +
  'ArnNotEquals on aws:PrincipalArn naming the allowed principal ARN(s) instead ' +
  'of NotPrincipal.';

// IAM-1103: canonicalize the family-selection vocabulary. A caller (or a record-
// test bundle) may name a family by a common synonym - notably the org-control
// families "scp" / "rcp", and "trust" for role-trust. These are RECOGNIZED family
// names, not garbage, so they must NOT slip through to the "unrecognized token ->
// auto-detect" path and get silently analyzed as an identity policy (the DEF-05
// fail-OPEN: an SCP run through identity rules emits confident capability findings
// on a document that GRANTS nothing). We map each synonym to its canonical engine
// token BEFORE override resolution; the canonical token then fails closed on its
// own merits (scp-rcp / resource are unmodeled -> UNSUPPORTED_POLICY_FAMILY;
// role-trust is shape-checked). A token that is neither canonical nor a known
// synonym stays "unrecognized" and preserves the back-compatible auto-detect
// fallback (family.test.js: "nonsense" -> auto-detect).
const FAMILY_ALIASES = Object.freeze({
  scp: FAMILIES.SCP_RCP,
  rcp: FAMILIES.SCP_RCP,
  trust: FAMILIES.ROLE_TRUST,
});

// The set of families a caller may select via the optional manual override.
// (AMBIGUOUS / UNKNOWN are classifications, not selectable families.)
export const OVERRIDE_FAMILIES = Object.freeze(new Set([
  FAMILIES.IDENTITY,
  FAMILIES.RESOURCE,
  FAMILIES.ROLE_TRUST,
  FAMILIES.PERMISSIONS_BOUNDARY,
  FAMILIES.SCP_RCP,
  FAMILIES.SESSION,
]));

// sts actions that define a ROLE TRUST policy (the "who may assume me"
// direction). Compared case-insensitively. A Principal-bearing policy whose
// actions are all trust actions and that carries no Resource is a role trust
// policy; any other Principal-bearing policy is a general resource policy.
const TRUST_ACTIONS = new Set([
  'sts:assumerole',
  'sts:assumerolewithsaml',
  'sts:assumerolewithwebidentity',
  'sts:tagsession',
  'sts:setsourceidentity',
]);

function code(c, message, path) {
  return { code: c, message, path: path === undefined ? null : path };
}

// A statement carries a principal ELEMENT if it names either Principal or
// NotPrincipal. Both are resource-policy shape signals.
function hasPrincipalElement(s) {
  return (s && (s.principal != null || s.notPrincipal != null)) || false;
}

// --- SCP / RCP control-policy shape (IAM-704, test 19) -----------------------
// An SCP/RCP is an ORGANIZATIONS control policy: a set of Deny guardrails (or
// Allow ceilings) that CAP what member accounts may do - it never grants a
// permission. Run through identity rules it would look like a harmless zero-
// grant policy (all-Deny yields no findings), which silently hides that the
// document was never an identity policy at all. We detect the control-policy
// shape and fail closed. Full SCP CEILING analysis is a later feature; here we
// only refuse to mis-analyze it as identity.
//
// Shape signature (deliberately narrow so a legitimate identity policy is not
// swept up): EVERY statement is an unconditional-family Deny (no Principal),
// AND at least one statement carries a hallmark org/region guardrail signal -
// an `organizations:*` action/NotAction, or a region-scoping condition key
// (aws:RequestedRegion). A plain "Deny everything except iam:*" with no such
// guardrail stays an ordinary (identity) Deny and is NOT treated as an SCP.
const SCP_GUARDRAIL_CONDITION_KEYS = new Set(['aws:requestedregion']);

function isOrgControlAction(a) {
  return String(a).toLowerCase().startsWith('organizations:');
}

function hasScpGuardrailCondition(stmt) {
  const c = stmt.condition;
  if (!c || typeof c !== 'object') return false;
  for (const op of Object.getOwnPropertyNames(c)) {
    const inner = c[op];
    if (!inner || typeof inner !== 'object') continue;
    for (const key of Object.getOwnPropertyNames(inner)) {
      if (SCP_GUARDRAIL_CONDITION_KEYS.has(String(key).toLowerCase())) return true;
    }
  }
  return false;
}

// A FullAWSAccess-style ceiling Allow: Action "*" on Resource "*" with no
// NotAction / NotResource scoping. This is the AWS managed FullAWSAccess default
// that virtually every real SCP carries alongside its Deny guardrails ("when you
// enable SCPs, AWS Organizations attaches ... FullAWSAccess which allows all
// services and actions", docs/scp-rcp-semantics.md section 2). It is the ONLY
// Allow shape the SCP recognizer tolerates: a SCOPED Allow (specific
// actions/resources, or a NotAction/NotResource complement) is structurally
// indistinguishable from an identity grant, so a document carrying one is left to
// the identity path rather than swept into the SCP family.
function isFullAccessAllow(s) {
  const actions = Array.isArray(s.actions) ? s.actions : [];
  const resources = Array.isArray(s.resources) ? s.resources : [];
  const notActions = Array.isArray(s.notActions) ? s.notActions : [];
  const notResources = Array.isArray(s.notResources) ? s.notResources : [];
  return notActions.length === 0 && notResources.length === 0
    && actions.length === 1 && actions[0] === '*'
    && resources.length === 1 && resources[0] === '*';
}

function isScpShape(statements) {
  if (statements.length === 0) return false;
  if (statements.some(hasPrincipalElement)) return false; // SCPs attach to OUs, not principals
  // An SCP is a set of Deny guardrails, optionally alongside a FullAWSAccess-style
  // Allow ceiling (the AWS managed default nearly every real SCP carries). We
  // recognize BOTH the original all-Deny SCP AND the canonical mixed
  // FullAWSAccess + Deny SCP - the shape almost every real-world SCP takes, since
  // it carries the FullAWSAccess Allow. Recognition requires TWO things:
  //   1) at least one Deny carries a hallmark org/region guardrail signal (an
  //      organizations:* action/NotAction, or an aws:RequestedRegion condition).
  //      Requiring that guardrail signal keeps a plain full-admin identity policy
  //      ([Allow * *] plus an ordinary Deny with no org/region signal - e.g. the
  //      graph/rule-edge NotAction-deny fixture) OUT of the SCP family; it stays
  //      an identity policy.
  //   2) every NON-Deny statement is a FullAWSAccess-style Allow ceiling. A scoped
  //      Allow is identity-ambiguous, so a document carrying one is left to the
  //      identity path (this recognizer bails out, returning false).
  // Detecting the mixed shape here is what closes the auto-detect fail-OPEN: a
  // FullAWSAccess + region/org Deny SCP is no longer misclassified as identity and
  // run through the escalation engine (which would manufacture can-* capability
  // edges and critical escalation findings a CEILING can never establish).
  let sawGuardrail = false;
  for (const s of statements) {
    if (s.effect === 'Deny') {
      if (s.actions.some(isOrgControlAction)
        || s.notActions.some(isOrgControlAction)
        || hasScpGuardrailCondition(s)) {
        sawGuardrail = true;
      }
    } else if (s.effect === 'Allow') {
      if (!isFullAccessAllow(s)) return false; // a scoped Allow is identity-ambiguous
    } else {
      return false; // an unrecognized effect is not a clean SCP shape
    }
  }
  return sawGuardrail;
}

// --- RCP (Resource Control Policy) shape (IAM-1302, test 52) ------------------
// An RCP is the resource-side sibling of an SCP: an ORGANIZATIONS control policy
// that CAPS who may access org resources. Unlike an SCP it names a Principal (it
// is Principal-bearing, like a resource-based policy) and it is DENY-ONLY in
// practice (its Allow is only the RCPFullAWSAccess pass-through default). It is a
// CEILING, never a grant. Structurally it looks like a resource-based policy, so
// it can be told apart only by its org-scope guardrail condition keys
// (aws:SourceOrgID / aws:SourceOrgPaths / aws:PrincipalOrgID / the
// aws:PrincipalIsAWSService confused-deputy signal). We detect that shape so an
// EXPLICIT SCP/RCP selection routes it to the RCP guardrail evaluator instead of
// mis-analyzing it as an ordinary resource GRANT (which would emit a spurious
// public-access / S3 capability finding a deny-only ceiling can never establish).
const RCP_GUARDRAIL_CONDITION_KEYS = new Set([
  'aws:sourceorgid', 'aws:sourceorgpaths', 'aws:principalorgid', 'aws:principalisawsservice',
]);

function hasRcpGuardrailCondition(stmt) {
  const c = stmt.condition;
  if (!c || typeof c !== 'object') return false;
  for (const op of Object.getOwnPropertyNames(c)) {
    const inner = c[op];
    if (!inner || typeof inner !== 'object') continue;
    for (const key of Object.getOwnPropertyNames(inner)) {
      if (RCP_GUARDRAIL_CONDITION_KEYS.has(String(key).toLowerCase())) return true;
    }
  }
  return false;
}

// An RCP shape: EVERY statement is a Principal-bearing Deny (RCPs are deny-only
// and name a Principal, capping who may reach org resources), NONE names a
// NotPrincipal (a Deny + NotPrincipal is the documented hazard, kept fail-closed),
// AND at least one statement carries an org-scope guardrail condition key. The
// org-scope signal is what distinguishes an RCP guardrail from an ordinary
// resource-based grant, so a plain resource policy is never swept up.
export function isRcpShape(statements) {
  if (statements.length === 0) return false;
  if (!statements.every((s) => s.effect === 'Deny')) return false; // deny-only
  if (!statements.every((s) => s.principal != null)) return false; // Principal-bearing
  if (statements.some((s) => s.notPrincipal != null)) return false; // NotPrincipal is the hazard
  return statements.some(hasRcpGuardrailCondition);
}

// Role-trust statements whose Principal names a type the trust evaluator does
// not model (a key outside KNOWN_PRINCIPAL_TYPES). A wildcard Principal ("*")
// carries no byType keys, so it is never flagged here. Deterministic order.
function unmodeledPrincipalTypeStatements(statements) {
  const out = [];
  for (const s of statements) {
    const p = s && s.principal;
    if (!p || p.anyPrincipal || !p.byType) continue;
    for (const key of Object.keys(p.byType)) {
      if (!KNOWN_PRINCIPAL_TYPES.has(key)) { out.push(s); break; }
    }
  }
  return out;
}

function isTrustOnly(statements) {
  for (const s of statements) {
    // A trust policy has no Resource/NotResource and only trust actions.
    if (s.resources.length > 0 || s.notResources.length > 0) return false;
    if (s.notActions.length > 0) return false;
    if (s.actions.length === 0) return false;
    for (const a of s.actions) {
      if (!TRUST_ACTIONS.has(String(a).toLowerCase())) return false;
    }
  }
  return true;
}

// Classify the family from shape alone (no override applied). Returns the
// detected family plus any blocking codes the SHAPE mandates.
//
// IAM-1201: when the caller has EXPLICITLY selected the resource family
// (opts.suppressResourceBlock), a clean resource shape must NOT be auto-blocked
// here with UNSUPPORTED_POLICY_FAMILY - detectFamily's resource branch decides
// accepted (with context) vs RESOURCE_CONTEXT_REQUIRED (without). Auto-detect
// (no explicit resource selection) still fails closed on a resource shape.
function classifyShape(statements, opts) {
  const suppressResourceBlock = !!(opts && opts.suppressResourceBlock);
  // IAM-1301 (Phase 13): when the SCP family is EXPLICITLY selected, an SCP-shaped
  // (deny-guardrail) document is routed to the family-aware SCP evaluator instead
  // of failing closed here. Auto-detect (no explicit SCP selection) still fails
  // closed on an SCP shape (the auto-detect flip is IAM-1303's job).
  const suppressScpBlock = !!(opts && opts.suppressScpBlock);
  const blockingCodes = [];

  // 0) SCP / RCP control-policy shape (IAM-704, test 19): a deny-only org
  // guardrail must never be analyzed with identity rules. IAM-1301: under an
  // EXPLICIT SCP selection this shape is CEILING-analyzed (suppressScpBlock), so
  // the block is skipped and the family resolves to SCP_RCP for the SCP evaluator.
  // Without an explicit SCP selection we fail closed (deny-guardrail SCP under
  // auto-detect stays blocked until IAM-1303 flips the auto path).
  if (isScpShape(statements)) {
    if (!suppressScpBlock) {
      blockingCodes.push(code(
        COVERAGE_CODES.UNSUPPORTED_SCP_SHAPE,
        'Detected a Service Control Policy / Resource Control Policy shape ' +
          '(organization-wide Deny guardrails). SCPs set permission CEILINGS and ' +
          'do not GRANT permissions, so identity-policy rules do not apply and a ' +
          'NotAction here does not describe allowed capabilities. Select the ' +
          'SCP / RCP family to analyze it as a ceiling / guardrail; under ' +
          'auto-detect analysis stops rather than fall back to identity-policy rules.',
        `Statement[${statements[0].index}]`,
      ));
    }
    return { detected: FAMILIES.SCP_RCP, blockingCodes };
  }

  // 0b) RCP (Resource Control Policy) shape (IAM-1302, test 52): a DENY-ONLY,
  // Principal-bearing org RESOURCE guardrail (carrying an org-scope condition key
  // such as aws:SourceOrgID / aws:PrincipalIsAWSService). It is a CEILING, never a
  // grant. Under an EXPLICIT SCP/RCP selection (suppressScpBlock) it is routed to
  // the family-aware RCP guardrail evaluator (detected=SCP_RCP, no block here).
  // Under AUTO-DETECT (no explicit selection) it is deliberately LEFT to the
  // resource branch below, which fails closed (UNSUPPORTED_POLICY_FAMILY) exactly
  // as before - the auto-detect flip for org-control policies is IAM-1303's job,
  // so gating on suppressScpBlock keeps auto-detect behavior byte-for-byte
  // unchanged (the deferred RCP fixture still detects `resource` + fails closed).
  if (suppressScpBlock && isRcpShape(statements)) {
    return { detected: FAMILIES.SCP_RCP, blockingCodes };
  }

  // 1) NotPrincipal is a recognized-but-unmodeled element: reject each
  // occurrence with its exact JSON path. This is a resource-policy element, so
  // the detected family is resource, but it fails closed regardless.
  //
  // IAM-1206: a Deny + NotPrincipal statement is a DOCUMENTED semantic TRAP, not
  // an ordinary "deny everyone except these" exclusion. AWS states the
  // NotPrincipal + Deny element "will always deny any IAM principal that has a
  // permissions boundary policy attached, regardless of the values specified in
  // the NotPrincipal element" - so the principals the author intended to EXEMPT
  // can still be denied. We keep failing closed (UNSUPPORTED_NOTPRINCIPAL, empty
  // graph - never a rendered ordinary-deny graph) BUT surface the SPECIFIC hazard
  // (the permissions-boundary caveat + the ArnNotEquals / aws:PrincipalArn
  // recommendation) as a high-confidence warning on the blocking code, so a
  // reader is not left thinking the exclusion behaves as written
  // (docs/resource-policy-semantics.md section 8; acceptance-suite-2 test 29).
  // A NotPrincipal with any other effect (AWS only supports it with Deny; an
  // Allow + NotPrincipal is invalid) stays the generic unmodeled-element message.
  const notPrincipalStmts = statements.filter((s) => s.notPrincipal != null);
  for (const s of notPrincipalStmts) {
    if (s.effect === 'Deny') {
      blockingCodes.push({
        code: COVERAGE_CODES.UNSUPPORTED_NOTPRINCIPAL,
        message: NOTPRINCIPAL_DENY_HAZARD_MESSAGE,
        path: `Statement[${s.index}].NotPrincipal`,
        // High-confidence, first-class hazard marker (not an ordinary unsupported
        // element): lets coverage/exports/UI render it as a security hazard.
        hazard: true,
      });
    } else {
      blockingCodes.push(code(
        COVERAGE_CODES.UNSUPPORTED_NOTPRINCIPAL,
        'NotPrincipal is a recognized resource-policy element that this analyzer ' +
          'does not yet model. It is not the same as an absent Principal and is ' +
          'never silently ignored.',
        `Statement[${s.index}].NotPrincipal`,
      ));
    }
  }

  const withElement = statements.filter(hasPrincipalElement);
  const withoutElement = statements.filter((s) => !hasPrincipalElement(s));

  // 2) No principal element anywhere -> identity-shaped. (Permissions boundary /
  // SCP / session policies are structurally identical to an identity policy and
  // cannot be told apart from shape; auto-detect resolves to identity. A user
  // who knows otherwise uses the manual override.)
  if (withElement.length === 0) {
    return { detected: FAMILIES.IDENTITY, blockingCodes };
  }

  // 3) Every statement carries a principal element -> resource-based. Refine to
  // role-trust when the shape is the trust-policy shape.
  //   - role-trust (IAM-801): SUPPORTED via the family-aware trust evaluator, so
  //     it does NOT fail closed here - UNLESS it names an unmodeled Principal
  //     type, which keeps it fail-closed ("unsupported != safe").
  //   - a general resource-based policy stays unmodeled: fail closed.
  // NotPrincipal was already rejected above (UNSUPPORTED_NOTPRINCIPAL); when it
  // is present we add no further family/principal-type block (the NotPrincipal
  // block is authoritative).
  if (withoutElement.length === 0) {
    const detected = isTrustOnly(statements) ? FAMILIES.ROLE_TRUST : FAMILIES.RESOURCE;
    if (notPrincipalStmts.length === 0) {
      if (detected === FAMILIES.ROLE_TRUST) {
        for (const s of unmodeledPrincipalTypeStatements(statements)) {
          blockingCodes.push(code(
            COVERAGE_CODES.UNSUPPORTED_PRINCIPAL_TYPE,
            'This role trust policy names a Principal type the trust evaluator ' +
              'does not model (only AWS, Service, Federated, and CanonicalUser ' +
              'are modeled). Analysis stops rather than guess an unrecognized ' +
              'principal shape (unsupported does NOT mean safe).',
            `Statement[${s.index}].Principal`,
          ));
        }
      } else if (!suppressResourceBlock) {
        // Auto-detect (no explicit resource selection): a resource shape fails
        // closed. When resource is EXPLICITLY selected (suppressResourceBlock),
        // detectFamily's resource branch handles it (accept-with-context or
        // RESOURCE_CONTEXT_REQUIRED) instead of this generic block.
        blockingCodes.push(code(
          COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY,
          `Detected a ${FAMILY_LABELS[detected]} (every statement names a ` +
            'Principal). This analyzer models identity-policy and role-trust ' +
            'semantics only, so it stops before rule evaluation rather than ' +
            'present findings on a resource-based document it does not model.',
          `Statement[${statements[0].index}].Principal`,
        ));
      }
    }
    return { detected, blockingCodes };
  }

  // 4) Some statements name a principal element and some do not: this is not a
  // valid single identity OR resource policy. Ambiguous -> fail closed, citing
  // the first statement that breaks consistency with statement 0.
  const firstHas = hasPrincipalElement(statements[0]);
  let mismatch = statements.find((s) => hasPrincipalElement(s) !== firstHas);
  if (!mismatch) mismatch = statements[0];
  blockingCodes.push(code(
    COVERAGE_CODES.AMBIGUOUS_POLICY_SHAPE,
    'Some statements name a Principal / NotPrincipal and some do not. A single ' +
      'policy cannot be both an identity policy and a resource-based policy; the ' +
      'family is ambiguous, so analysis stops before rule evaluation.',
    `Statement[${mismatch.index}]`,
  ));
  return { detected: FAMILIES.AMBIGUOUS, blockingCodes };
}

/**
 * Detect the policy family and produce the coverage state for a normalized
 * model. AUTO-DETECT by default; an optional manual override is honored and
 * recorded. Never throws.
 *
 * @param {object} model normalized, frozen model (from buildModel/modelFromText)
 * @param {{family?: string, requireExplicitFamily?: boolean}} [options]
 *   family: an explicit family selection - an OVERRIDE_FAMILIES token, or
 *     'auto'/'auto-detect' for explicit shape auto-detect. Absent/empty means no
 *     selection.
 *   requireExplicitFamily: when true (the UI contract), an absent selection fails
 *     closed with POLICY_FAMILY_REQUIRED instead of auto-detecting. Omit it (the
 *     default) to preserve back-compatible auto-detect for existing callers.
 * @returns {Readonly<{
 *   detected: string, override: (string|null), family: string,
 *   supported: boolean, blocked: boolean,
 *   blockingCodes: ReadonlyArray<{code:string,message:string,path:?string}>,
 *   notes: ReadonlyArray<string>
 * }>}
 */
export function detectFamily(model, options) {
  const opts = options || {};
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  const notes = [];

  // IAM-1001: resolve the family SELECTION before touching the shape. "auto"
  // (and its alias "auto-detect") is now an EXPLICIT opt-in choice - distinct
  // from an ABSENT selection - so paste-and-go auto-detect remains available but
  // is no longer a silent default. An OVERRIDE_FAMILIES token is an explicit pick
  // of a concrete family; anything else (empty / garbage) is "no selection".
  // IAM-1103: canonicalize a recognized family synonym (scp/rcp/trust/...) to its
  // engine token BEFORE any selection logic, so a known control-policy family
  // never falls through to the auto-detect fallback and gets analyzed as identity
  // (the DEF-05 fail-open). Case-insensitive; a genuinely unknown token is left
  // untouched (it stays "unrecognized" and auto-detects, per family.test.js).
  // IAM-1103: TRIM whitespace and canonicalize BEFORE any matching so a stray
  // space ("SCP ") or case variance ("Rcp") still resolves to its canonical
  // family. Resolution order: known synonym (scp/rcp/trust) -> canonical override
  // family -> auto -> otherwise preserve the raw token for messaging. Case-
  // insensitive throughout.
  const rawInputRaw = typeof opts.family === 'string' ? opts.family : '';
  const trimmed = rawInputRaw.trim();
  const lower = trimmed.toLowerCase();
  let canonical;
  if (Object.prototype.hasOwnProperty.call(FAMILY_ALIASES, lower)) {
    canonical = FAMILY_ALIASES[lower];
  } else if (OVERRIDE_FAMILIES.has(lower)) {
    canonical = lower;
  } else if (lower === 'auto' || lower === 'auto-detect') {
    canonical = lower;
  } else {
    canonical = trimmed; // unrecognized token, preserved for the error message
  }
  const rawSelection = canonical;
  const isAuto = rawSelection === 'auto' || rawSelection === 'auto-detect';
  const hasExplicitSelection = isAuto || OVERRIDE_FAMILIES.has(rawSelection);

  // IAM-1103 (11C): a NON-EMPTY selection that resolved to none of the recognized
  // forms is an INVALID family. FAIL CLOSED here - BEFORE shape classification and
  // before the requireExplicitFamily gate - never auto-detect a typo/garbage token
  // into identity (the DEF-05 fail-OPEN: an unrecognized family on an SCP-shaped
  // grant-nothing document would emit confident identity capability findings). An
  // empty/absent selection is "no selection", handled below, and is NOT invalid.
  if (trimmed.length > 0 && !hasExplicitSelection) {
    return Object.freeze({
      detected: FAMILIES.UNKNOWN,
      override: null,
      family: null,
      supported: false,
      blocked: true,
      blockingCodes: Object.freeze([Object.freeze(code(
        COVERAGE_CODES.INVALID_FAMILY,
        `Unrecognized policy family "${trimmed}". Select a supported family ` +
          '(identity, resource, role-trust, permissions-boundary, scp-rcp, or ' +
          'session) or Auto-detect. Analysis stops rather than guess a family from ' +
          'an unrecognized selection and risk analyzing the document as the wrong ' +
          'family (unsupported does NOT mean safe).',
        null,
      ))]),
      notes: Object.freeze([]),
    });
  }

  // IAM-1001: MANDATORY family selection (the UI contract). When the caller
  // demands an explicit selection and none was made, fail closed with
  // POLICY_FAMILY_REQUIRED BEFORE classifying the shape - the family is NEVER
  // defaulted from shape (detected stays UNKNOWN so nothing implies an identity
  // default). Back-compat: callers that omit requireExplicitFamily (the existing
  // unit tests + suite-1/suite-2 fixtures) still auto-detect below.
  if (opts.requireExplicitFamily && !hasExplicitSelection) {
    return Object.freeze({
      detected: FAMILIES.UNKNOWN,
      override: null,
      family: null,
      supported: false,
      blocked: true,
      blockingCodes: Object.freeze([Object.freeze(code(
        COVERAGE_CODES.POLICY_FAMILY_REQUIRED,
        'Select a policy family before analyzing. This tool does not guess the ' +
          'policy family from the document shape: an identity policy and a ' +
          'resource-based policy can look structurally similar, and analyzing one ' +
          'as the other would produce confident but wrong findings. Choose a ' +
          'family (or Auto-detect) and analyze again.',
        null,
      ))]),
      notes: Object.freeze([]),
    });
  }

  // IAM-1201: is the resource family EXPLICITLY selected? If so, a clean resource
  // shape is not auto-blocked in classifyShape; the resource branch below decides
  // accepted (with context) vs RESOURCE_CONTEXT_REQUIRED (without).
  const resourceExplicit = rawSelection === FAMILIES.RESOURCE;
  // IAM-1301: is the SCP/RCP family EXPLICITLY selected? If so, a deny-guardrail
  // SCP shape is CEILING-analyzed (not auto-blocked) - classifyShape skips the
  // UNSUPPORTED_SCP_SHAPE block and the SCP override branch below routes it.
  const scpExplicit = rawSelection === FAMILIES.SCP_RCP;
  const { detected, blockingCodes } = classifyShape(statements, {
    suppressResourceBlock: resourceExplicit,
    suppressScpBlock: scpExplicit,
  });

  // IAM-704 (test 22C): version gate. An ABSENT Version is tolerated; any
  // EXPLICIT version other than the modeled grammar (e.g. legacy '2008-10-17')
  // is unsupported. Fail closed rather than analyze under - or silently rewrite
  // to - a version whose semantics were never validated. This is orthogonal to
  // the family shape, so it stacks with any shape block above.
  const version = model && typeof model.version === 'string' ? model.version : null;
  if (version !== null && version !== SUPPORTED_POLICY_VERSION) {
    blockingCodes.push(code(
      COVERAGE_CODES.UNSUPPORTED_POLICY_VERSION,
      `Policy Version "${version}" is not supported. This analyzer models the ` +
        `"${SUPPORTED_POLICY_VERSION}" policy grammar and never silently rewrites ` +
        'an unsupported version. Analysis stops rather than present findings under ' +
        'a version whose semantics it has not validated.',
      'Version',
    ));
  }

  // Resolve the explicit override. It NEVER relaxes a shape-mandated block (you
  // cannot force a NotPrincipal / resource document to evaluate as identity), and
  // selecting an unmodeled family blocks even a clean identity shape. "auto" is
  // an explicit selection but carries NO override (pure shape auto-detect).
  let override = null;
  if (isAuto) {
    notes.push('Policy family explicitly set to Auto-detect.');
  } else if (rawSelection.length > 0) {
    if (OVERRIDE_FAMILIES.has(rawSelection)) {
      override = rawSelection;
    } else {
      // An unrecognized override token is ignored (auto-detect wins) but noted.
      notes.push(`Ignored unrecognized family override "${rawSelection}"; used auto-detect.`);
    }
  }

  const family = override || detected;

  // IAM-1201: set true only when an explicit resource selection is ACCEPTED (a
  // resource shape + a valid, modeled attached-resource context). Drives
  // `supported` below so the orchestrator routes an accepted resource policy to
  // the resource evaluator, while resource stays OUT of SUPPORTED_FAMILIES (a
  // resource shape is not supported without its explicit context).
  let resourceAccepted = false;

  // IAM-1301 / IAM-1302: set true when an explicit SCP/RCP selection is ACCEPTED as
  // a ceiling family - either an SCP-analyzable no-Principal guardrail shape
  // (IAM-1301) OR an RCP-shaped Principal-bearing deny-only org resource guardrail
  // (IAM-1302). Drives `supported` so the orchestrator routes it to the SCP/RCP
  // ceiling evaluator, while SCP_RCP stays OUT of SUPPORTED_FAMILIES (auto-detect
  // never resolves to it - an org-control shape is only ceiling-analyzed under an
  // explicit selection).
  let scpAccepted = false;

  if (override) {
    // IAM-1001 family-shape guards for an EXPLICIT selection. These are more
    // specific than the generic OVERRIDE_SHAPE_MISMATCH: they name the exact
    // element that does not belong in the selected family, with its JSON path,
    // and they NEVER drop that element to analyze the remainder.
    let shapeGuardFired = false;
    if (override === FAMILIES.IDENTITY) {
      // An identity policy attaches to a principal and never CONTAINS a Principal
      // element; a Principal here means the document is a resource-based (or
      // trust) policy (test 67). (NotPrincipal is already rejected by
      // classifyShape with UNSUPPORTED_NOTPRINCIPAL.)
      for (const s of statements.filter((x) => x && x.principal != null)) {
        blockingCodes.push(code(
          COVERAGE_CODES.UNSUPPORTED_PRINCIPAL,
          'Identity policy selected, but this statement names a Principal. Identity ' +
            'policies attach to a principal and never contain a Principal element, ' +
            'so a Principal here means this is a resource-based or trust policy. ' +
            'Analysis stops rather than drop the Principal and analyze the remainder ' +
            'as an identity grant.',
          `Statement[${s.index}].Principal`,
        ));
        shapeGuardFired = true;
      }
    } else if (override === FAMILIES.ROLE_TRUST) {
      // A role-trust policy names WHO may assume the role and carries no Resource;
      // a Resource in a trust-shaped document is a syntax error (test 68). Only
      // guard a genuinely trust-shaped document (one that names a Principal): a
      // plain identity shape forced to role-trust is a generic shape mismatch, not
      // a trust-Resource syntax error.
      if (statements.some(hasPrincipalElement)) {
        for (const s of statements.filter((x) => x && (x.resources.length > 0 || x.notResources.length > 0))) {
          blockingCodes.push(code(
            COVERAGE_CODES.UNSUPPORTED_TRUST_RESOURCE,
            'Role trust policy selected, but this statement names a Resource. A trust ' +
              'policy applies to the role it is attached to and has no Resource ' +
              'element; the supplied Resource must not become a second role target. ' +
              'Analysis stops on the trust-policy syntax error.',
            `Statement[${s.index}].Resource`,
          ));
          shapeGuardFired = true;
        }
      }
    }

    if (override === FAMILIES.RESOURCE) {
      // IAM-1201: the resource family is ACCEPTED, gated on the explicit attached-
      // resource context. Three outcomes, all fail-closed on anything but a clean
      // resource shape with a modeled context:
      //   (a) not a resource shape -> UNSUPPORTED_POLICY_FAMILY (the document does
      //       not name a Principal on every statement, so it is not a resource
      //       policy). Preserved for the record/e2e contract (resource selected on
      //       an identity shape fails closed). A more specific shape block from
      //       classifyShape (NotPrincipal / ambiguous / version) stays authoritative.
      //   (b) a resource shape already failed closed on a recognized-but-unmodeled
      //       element (NotPrincipal) or an unsupported Version -> that block stands.
      //   (c) a clean resource shape -> require + validate the attached-resource
      //       context: missing/invalid -> RESOURCE_CONTEXT_REQUIRED; a recognized-
      //       but-unmodeled service -> UNSUPPORTED_RESOURCE_SHAPE; otherwise accept.
      if (detected !== FAMILIES.RESOURCE) {
        if (blockingCodes.length === 0) {
          blockingCodes.push(code(
            COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY,
            'Resource-based policy selected, but this document is not a resource-' +
              'policy shape: a resource-based policy names a Principal on every ' +
              'statement. Analysis stops rather than analyze it as a resource policy; ' +
              'your input is preserved so you can re-select a supported family.',
            null,
          ));
        }
        notes.push('Resource family selected; the document is not a resource-policy shape.');
      } else if (blockingCodes.length > 0) {
        // A resource shape that classifyShape / the version gate already failed
        // closed (e.g. NotPrincipal is UNSUPPORTED_NOTPRINCIPAL until IAM-1206).
        // Leave that block authoritative; do not accept.
        notes.push('Resource family selected; a recognized-but-unmodeled element blocks analysis.');
      } else {
        const rc = parseResourceContext(opts.resourceContext);
        if (!rc.ok) {
          blockingCodes.push(code(rc.code, rc.message, null));
          notes.push('Resource family selected without a modeled attached-resource context.');
        } else {
          resourceAccepted = true;
          notes.push(
            `Resource family accepted; attached ${rc.service} resource context supplied ` +
              '(routed to the resource evaluator, not identity rules).',
          );
        }
      }
    } else if (override === FAMILIES.SCP_RCP) {
      // IAM-1301 / IAM-1302 (Phase 13): an EXPLICIT SCP/RCP selection routes to the
      // ceiling family - an SCP Allow is a maximum-permissions envelope and an
      // SCP/RCP Deny is a guardrail; neither grants. This is gated on the GUARDRAIL
      // SHAPE (classifyShape, with suppressScpBlock, returns detected=SCP_RCP only
      // when isScpShape matched an all-Deny, no-Principal org/region guardrail, OR
      // isRcpShape matched a Principal-bearing deny-only org RESOURCE guardrail
      // carrying an org-scope condition key). We deliberately do NOT relabel an
      // arbitrary grant as a ceiling: an allow-list SCP is structurally identical
      // to an identity policy, and an ordinary resource GRANT (no org-scope signal)
      // is not an RCP guardrail, so selecting SCP/RCP on such a shape fails closed
      // (deferred), naming the family - preserving suite-3 test 69 and never mis-
      // analyzing an identity grant or a resource grant. Auto-detect on the same
      // guardrail shape still fails closed (IAM-1303 flips it).
      if (detected === FAMILIES.SCP_RCP) {
        scpAccepted = true;
        notes.push(
          'SCP / RCP family selected; analyzed as a permission ceiling / guardrail ' +
            '(SCPs and RCPs set the maximum permissions and never grant).',
        );
      } else {
        if (!blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY)) {
          blockingCodes.push(code(
            COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY,
            'SCP / RCP selected, but this document is not an SCP or RCP guardrail ' +
              'shape. An SCP is an all-Deny organization guardrail with an org- or ' +
              'region-control signal and never names a Principal; an RCP is a ' +
              'deny-only, Principal-bearing org RESOURCE guardrail carrying an ' +
              'org-scope condition key (for example aws:SourceOrgID or ' +
              'aws:PrincipalIsAWSService). An allow-list SCP is structurally ' +
              'identical to an identity policy, and an ordinary resource GRANT is ' +
              'not an RCP guardrail, so neither can be safely relabeled as a ' +
              'ceiling. Analysis stops rather than mis-analyze it; your input is ' +
              'preserved so you can re-select a supported family.',
            null,
          ));
        }
        notes.push('SCP / RCP selected; the document is not an SCP or RCP guardrail shape.');
      }
    } else if (!SUPPORTED_FAMILIES.has(override)) {
      // Selected a family we do not model -> fail closed NAMING the selected
      // family; the input is preserved so the user can re-select (test 69).
      // (SCP_RCP is handled above; RESOURCE above; this is the residual safety net.)
      if (!blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY)) {
        blockingCodes.push(code(
          COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY,
          `Policy family "${FAMILY_LABELS[override] || override}" was selected, a ` +
            'family this analyzer does not yet model. Analysis stops before rule ' +
            'evaluation; your input is preserved so you can re-select a supported ' +
            'family.',
          null,
        ));
      }
      notes.push(`Policy family selected: "${override}".`);
    } else if (ENVELOPE_FAMILIES.has(override)) {
      // IAM-1002: an EXPLICIT permissions-boundary / session selection. These
      // shapes are indistinguishable from an identity policy, so the selection is
      // valid ONLY on an identity-shaped (no-Principal) document. On any other
      // shape it fails closed - a Principal-bearing / SCP / ambiguous document
      // already carries a shape block from classifyShape (authoritative); a
      // role-trust shape carries none, so add the generic mismatch there.
      if (detected === FAMILIES.IDENTITY) {
        notes.push(
          `Policy family "${override}" selected; the document is structurally ` +
            'identity-shaped and analyzed as a ceiling/envelope, not as a grant.',
        );
      } else {
        if (blockingCodes.length === 0) {
          blockingCodes.push(code(
            COVERAGE_CODES.OVERRIDE_SHAPE_MISMATCH,
            `Selected family "${FAMILY_LABELS[override] || override}" requires an ` +
              `identity-shaped (no-Principal) document, but the detected shape is ` +
              `${FAMILY_LABELS[detected] || detected}. The shape wins; analysis ` +
              'stops rather than evaluate a ceiling on a document of another family.',
            null,
          ));
        }
        notes.push(`Selected family "${override}" did not match the detected shape.`);
      }
    } else if (shapeGuardFired) {
      // A specific family-shape guard already blocked (Principal / Resource); the
      // generic mismatch would be redundant and less precise.
      notes.push(`Policy family "${override}" selected; it conflicts with the document shape.`);
    } else if (override !== detected) {
      // A SUPPORTED family (identity or role-trust) forced onto a shape that is a
      // different family. The SHAPE always wins: fail closed rather than run one
      // family's evaluator on a document of another shape.
      blockingCodes.push(code(
        COVERAGE_CODES.OVERRIDE_SHAPE_MISMATCH,
        `Selected family "${FAMILY_LABELS[override] || override}" conflicts with ` +
          `the detected ${FAMILY_LABELS[detected] || detected}. The shape wins; ` +
          'analysis stops rather than force one family\'s rules onto a document ' +
          'whose shape is a different family.',
        null,
      ));
      notes.push(`Selected family "${override}" did not match the detected shape.`);
    } else {
      notes.push(`Policy family "${override}" selected (matches the detected shape).`);
    }
  }

  const blocked = blockingCodes.length > 0;
  // IAM-1201: an ACCEPTED resource family is supported (routed to the resource
  // evaluator) even though resource is deliberately kept OUT of SUPPORTED_FAMILIES
  // (a resource shape without its explicit context is not supported).
  const supported = !blocked && (SUPPORTED_FAMILIES.has(family) || resourceAccepted || scpAccepted);

  return Object.freeze({
    detected,
    override,
    family,
    supported,
    blocked,
    blockingCodes: Object.freeze(blockingCodes.map((b) => Object.freeze(b))),
    notes: Object.freeze(notes),
  });
}

export default detectFamily;
