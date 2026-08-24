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
// orchestrator routes trust statements to instead of the identity rules. The
// remaining families (resource / permissions-boundary / scp-rcp / session) stay
// fail-closed until each grows its own evaluator.
export const SUPPORTED_FAMILIES = Object.freeze(new Set([
  FAMILIES.IDENTITY,
  FAMILIES.ROLE_TRUST,
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

function isScpShape(statements) {
  if (statements.length === 0) return false;
  if (!statements.every((s) => s.effect === 'Deny')) return false;
  if (statements.some(hasPrincipalElement)) return false; // SCPs attach to OUs, not principals
  for (const s of statements) {
    if (s.actions.some(isOrgControlAction)) return true;
    if (s.notActions.some(isOrgControlAction)) return true;
    if (hasScpGuardrailCondition(s)) return true;
  }
  return false;
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
function classifyShape(statements) {
  const blockingCodes = [];

  // 0) SCP / RCP control-policy shape (IAM-704, test 19): fail closed BEFORE the
  // identity fallback so a deny-only org guardrail is never analyzed with
  // identity rules. This is fail-closed only; full SCP ceiling semantics come
  // later.
  if (isScpShape(statements)) {
    blockingCodes.push(code(
      COVERAGE_CODES.UNSUPPORTED_SCP_SHAPE,
      'Detected a Service Control Policy / Resource Control Policy shape ' +
        '(organization-wide Deny guardrails). SCPs set permission CEILINGS and ' +
        'do not GRANT permissions, so identity-policy rules do not apply and a ' +
        'NotAction here does not describe allowed capabilities. Full SCP ceiling ' +
        'analysis is not yet supported; analysis stops rather than fall back to ' +
        'identity-policy rules.',
      `Statement[${statements[0].index}]`,
    ));
    return { detected: FAMILIES.SCP_RCP, blockingCodes };
  }

  // 1) NotPrincipal is a recognized-but-unmodeled element: reject each
  // occurrence with its exact JSON path. This is a resource-policy element, so
  // the detected family is resource, but it fails closed regardless.
  const notPrincipalStmts = statements.filter((s) => s.notPrincipal != null);
  for (const s of notPrincipalStmts) {
    blockingCodes.push(code(
      COVERAGE_CODES.UNSUPPORTED_NOTPRINCIPAL,
      'NotPrincipal is a recognized resource-policy element that this analyzer ' +
        'does not yet model. It is not the same as an absent Principal and is ' +
        'never silently ignored.',
      `Statement[${s.index}].NotPrincipal`,
    ));
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
      } else {
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
 * @param {{family?: string}} [options] optional manual family override
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

  const { detected, blockingCodes } = classifyShape(statements);

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

  // Optional manual override. It NEVER relaxes a shape-mandated block (you
  // cannot force a NotPrincipal / resource document to evaluate as identity),
  // and selecting an unmodeled family blocks even a clean identity shape.
  let override = null;
  if (typeof opts.family === 'string' && opts.family.length > 0) {
    if (OVERRIDE_FAMILIES.has(opts.family)) {
      override = opts.family;
    } else {
      // An unrecognized override token is ignored (auto-detect wins) but noted.
      notes.push(`Ignored unrecognized family override "${opts.family}"; used auto-detect.`);
    }
  }

  const family = override || detected;

  if (override) {
    if (!SUPPORTED_FAMILIES.has(override)) {
      // User asked us to treat it as a family we do not model -> fail closed.
      if (!blockingCodes.some((b) => b.code === COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY)) {
        blockingCodes.push(code(
          COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY,
          `Manual override selected "${FAMILY_LABELS[override] || override}", a ` +
            'family this analyzer does not yet model. Analysis stops before rule ' +
            'evaluation.',
          null,
        ));
      }
      notes.push(`Family manually overridden to "${override}".`);
    } else if (override !== detected) {
      // User forced a SUPPORTED family (identity or role-trust) onto a shape that
      // is not that family. The SHAPE always wins: fail closed with a mismatch
      // rather than force one family's evaluator onto a document of another shape
      // (e.g. identity rules onto a trust policy, or the trust evaluator onto an
      // identity policy).
      blockingCodes.push(code(
        COVERAGE_CODES.OVERRIDE_SHAPE_MISMATCH,
        `Manual override "${FAMILY_LABELS[override] || override}" conflicts with ` +
          `the detected ${FAMILY_LABELS[detected] || detected}. The shape wins; ` +
          'analysis stops rather than force one family\'s rules onto a document ' +
          'whose shape is a different family.',
        null,
      ));
      notes.push(`Manual override "${override}" did not match the detected shape.`);
    } else {
      notes.push(`Family manually overridden to "${override}" (matches detected shape).`);
    }
  }

  const blocked = blockingCodes.length > 0;
  const supported = !blocked && SUPPORTED_FAMILIES.has(family);

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
