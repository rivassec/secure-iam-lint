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
export const SUPPORTED_FAMILIES = Object.freeze(new Set([FAMILIES.IDENTITY]));

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
  // role-trust when the shape is the trust-policy shape. Either way this is an
  // unmodeled family: fail closed.
  if (withoutElement.length === 0) {
    const detected = isTrustOnly(statements) ? FAMILIES.ROLE_TRUST : FAMILIES.RESOURCE;
    if (notPrincipalStmts.length === 0) {
      blockingCodes.push(code(
        COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY,
        `Detected a ${FAMILY_LABELS[detected]} (every statement names a ` +
          'Principal). This analyzer models identity-policy semantics only, so ' +
          'it stops before rule evaluation rather than present identity findings ' +
          'on a resource-based document.',
        `Statement[${statements[0].index}].Principal`,
      ));
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
    } else if (override === FAMILIES.IDENTITY && detected !== FAMILIES.IDENTITY) {
      // User forced "identity" on a shape that is not identity-shaped. We do not
      // trust the override to override the shape: fail closed with a mismatch.
      blockingCodes.push(code(
        COVERAGE_CODES.OVERRIDE_SHAPE_MISMATCH,
        `Manual override "identity" conflicts with the detected ` +
          `${FAMILY_LABELS[detected] || detected}. The shape wins; analysis stops ` +
          'rather than force identity rules onto a document that is not an ' +
          'identity policy.',
        null,
      ));
      notes.push('Manual override "identity" did not match the detected shape.');
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
