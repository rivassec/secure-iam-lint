// IAM Blast Radius - evaluator: Allow/Deny/NotAction/NotResource semantics (IAM-003).
//
// Fourth stage of the pipeline (see docs/architecture.md data-flow):
//   text -> validate() -> parse() -> buildModel() -> evaluate()/decide()
//
// This module answers two related questions about a SINGLE normalized policy:
//
//   evaluate(model)          -> a per-statement "capability view": what each
//                               statement grants or denies, in plain language,
//                               with correct NotAction / NotResource caveats.
//   decide(model, request)   -> for one concrete { action, resource } request,
//                               what THIS policy says, honoring explicit-Deny
//                               precedence and condition uncertainty.
//
// CRITICAL TRUTHFULNESS INVARIANT (docs/architecture.md #6, threat-model T8):
// A single policy CANNOT establish *effective* permissions. Effective access is
// the union of every attached identity policy, resource policy, permission
// boundary, SCP, and session policy - none of which is in scope here. So this
// module NEVER says "allowed" full stop. It reports CAPABILITY ("this policy,
// on its own, would grant this") and always attaches a caveat. Overstating
// certainty is itself a security harm, so:
//   - a conditional Deny is NEVER reported as a definitive deny;
//   - "no matching Allow" is reported as "not granted by THIS policy", never as
//     "effectively denied";
//   - an unconditional Allow is reported as capability, never effective access.
//
// Analyzed policies are HOSTILE input. Wildcard matching uses a linear
// two-pointer glob matcher (NOT a regex built from input) to avoid ReDoS.
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. Deterministic:
// same model + same request -> same output, every run (no Date/Math.random).

// --- Public enums ------------------------------------------------------------

// Outcome of decide() for a single (action, resource) request against THIS
// policy alone. Deliberately NOT the words "allowed"/"denied" unqualified.
export const DECISION = Object.freeze({
  // An unconditional Deny statement matches: within any context this policy is
  // in, the request is blocked. Explicit deny wins over every Allow.
  EXPLICIT_DENY: 'explicit-deny',
  // An unconditional Allow matches and no Deny (of any kind) matches: this
  // policy, on its own, would grant the request. Still a CAPABILITY, not proof
  // of effective access.
  ALLOWED_BY_POLICY: 'allowed-by-policy',
  // The outcome depends on runtime Condition keys and/or unspecified request
  // context (e.g. a conditional Allow, or an Allow shadowed by a conditional
  // Deny). Cannot be resolved from the policy text alone.
  CONDITIONAL: 'conditional',
  // No statement in this policy grants the request. NOT the same as "denied":
  // another attached policy could still allow it. Implicit-deny is per-policy.
  NOT_GRANTED_BY_POLICY: 'not-granted-by-policy',
});

// Certainty classes mirror the graph edge vocabulary in docs/architecture.md so
// IAM-006 can map a decision straight onto an edge style.
export const CERTAINTY = Object.freeze({
  BLOCKED_BY_DENY: 'blocked-by-deny',
  CONFIRMED_BY_CONTEXT: 'confirmed-by-context',
  CONDITIONALLY_REACHABLE: 'conditionally-reachable',
  POTENTIALLY_REACHABLE: 'potentially-reachable',
  UNKNOWN_INCOMPLETE_CONTEXT: 'unknown-incomplete-context',
});

// The single most important string this tool emits. Kept as one constant so the
// UI, the export, and every decision share identical wording.
export const CAPABILITY_CAVEAT =
  'Capability, not effective permissions. A single policy cannot establish ' +
  'effective access; the real outcome also depends on other identity policies, ' +
  'resource policies, permission boundaries, SCPs, and session policies not ' +
  'supplied here.';

// --- Linear glob matcher (ReDoS-safe) ----------------------------------------
// Matches an IAM wildcard pattern ('*' = any run incl. empty, '?' = one char)
// against a literal string using two-pointer scanning. O(n*m) worst case with
// NO catastrophic backtracking, unlike a regex compiled from hostile input.

function globMatch(pattern, text) {
  const p = String(pattern);
  const t = String(text);
  let pi = 0;
  let ti = 0;
  let starIdx = -1;
  let matchIdx = 0;
  while (ti < t.length) {
    if (pi < p.length && (p[pi] === '?' || p[pi] === t[ti])) {
      pi++;
      ti++;
    } else if (pi < p.length && p[pi] === '*') {
      starIdx = pi;
      matchIdx = ti;
      pi++;
    } else if (starIdx !== -1) {
      pi = starIdx + 1;
      matchIdx++;
      ti = matchIdx;
    } else {
      return false;
    }
  }
  while (pi < p.length && p[pi] === '*') pi++;
  return pi === p.length;
}

// IAM action matching is case-insensitive ("s3:getobject" == "s3:GetObject").
function actionMatches(pattern, action) {
  return globMatch(String(pattern).toLowerCase(), String(action).toLowerCase());
}

// ARN / resource matching is case-sensitive in AWS.
function resourceMatches(pattern, resource) {
  return globMatch(pattern, resource);
}

// --- IAM policy variables (${...}) -------------------------------------------
// AWS substitutes policy variables such as ${aws:username},
// ${aws:PrincipalTag/team}, ${saml:sub}, etc. into Action/Resource/NotResource
// patterns AT RUNTIME, before matching. Their value is NOT knowable from the
// policy text alone. Our glob matcher would compare '$','{','}' as ordinary
// characters, which is wrong in BOTH directions: a variable-scoped Deny that
// SHOULD match after substitution would be skipped (false allow), and a
// variable-scoped NotResource that SHOULD spare a resource after substitution
// would not (false deny). Both are blocking under the truthfulness invariant.
//
// So any pattern containing '${' is treated as UNCERTAIN: the statement is kept
// in play as *potentially* applying, but the match is never reported as certain,
// forcing the decision to degrade to CONDITIONAL instead of a definitive
// ALLOWED_BY_POLICY / EXPLICIT_DENY. (Escape forms like ${*} ${?} ${$} also
// trip this; over-conditionalizing is the safe direction - it can never
// manufacture a false allow or false deny.)
function hasPolicyVariable(pattern) {
  return String(pattern).includes('${');
}

// Evaluate whether `value` falls in the set described by `patterns`, honoring
// the fact that variable-bearing patterns can only be resolved at runtime.
// Returns { matched, certain, hasVariable }:
//   - a CONCRETE (variable-free) pattern that matches -> matched:true, certain:true
//   - no concrete match but a variable pattern present -> matched:true, certain:false
//     (it could match once the variable is substituted; we cannot rule it out)
//   - no concrete match and no variable pattern        -> matched:false, certain:true
function scopeMatch(patterns, value, matcher) {
  let concreteMatched = false;
  let hasVariable = false;
  for (const p of patterns) {
    if (hasPolicyVariable(p)) {
      hasVariable = true;
      continue;
    }
    if (matcher(p, value)) concreteMatched = true;
  }
  if (concreteMatched) return { matched: true, certain: true, hasVariable };
  if (hasVariable) return { matched: true, certain: false, hasVariable };
  return { matched: false, certain: true, hasVariable };
}

// --- Per-dimension matching against one statement ----------------------------

// Does `action` fall within the set of actions this statement governs?
//   Action    -> the listed actions (any pattern matches).
//   NotAction  -> EVERYTHING EXCEPT the listed actions.
// Policy variables in an Action/NotAction pattern (rare, but handled for
// completeness) degrade certainty exactly as they do for resources.
// Returns { applies, basis, certain, policyVariable }.
function actionApplies(stmt, action) {
  if (stmt.notActions.length > 0) {
    const s = scopeMatch(stmt.notActions, action, actionMatches);
    if (s.certain) {
      // Definite membership in the excluded set -> statement does NOT apply.
      return { applies: !s.matched, basis: 'NotAction', certain: true, policyVariable: s.hasVariable };
    }
    // A variable NotAction might exclude this action at runtime, might not:
    // keep the statement in play but uncertain.
    return { applies: true, basis: 'NotAction', certain: false, policyVariable: true };
  }
  const s = scopeMatch(stmt.actions, action, actionMatches);
  return { applies: s.matched, basis: 'Action', certain: s.certain, policyVariable: s.hasVariable };
}

// Does `resource` fall within the set this statement governs?
//   Resource     -> the listed resources.
//   NotResource   -> EVERYTHING EXCEPT the listed resources.
//   (neither)     -> resource scope is unspecified in the statement; we cannot
//                    confirm it, so we treat it as applying but NOT certain.
// If the caller omitted `resource`, we do not evaluate this dimension.
// A policy variable (${...}) anywhere in the relevant pattern list also forces
// certain=false so the decision degrades to CONDITIONAL (see hasPolicyVariable).
// Returns { applies, basis, certain, policyVariable }.
//   basis: 'Resource' | 'NotResource' | 'unspecified' | 'not-evaluated'
function resourceApplies(stmt, resource) {
  if (resource === undefined || resource === null) {
    return { applies: true, basis: 'not-evaluated', certain: false, policyVariable: false };
  }
  if (stmt.resources.length > 0) {
    const s = scopeMatch(stmt.resources, resource, resourceMatches);
    return { applies: s.matched, basis: 'Resource', certain: s.certain, policyVariable: s.hasVariable };
  }
  if (stmt.notResources.length > 0) {
    const s = scopeMatch(stmt.notResources, resource, resourceMatches);
    if (s.certain) {
      // Definite membership in the excluded set -> statement does NOT apply.
      return { applies: !s.matched, basis: 'NotResource', certain: true, policyVariable: s.hasVariable };
    }
    // A variable NotResource might spare this resource at runtime, might not.
    return { applies: true, basis: 'NotResource', certain: false, policyVariable: true };
  }
  // No Resource and no NotResource: scope is unknown for this request.
  return { applies: true, basis: 'unspecified', certain: false, policyVariable: false };
}

function hasCondition(stmt) {
  return stmt.condition !== null && stmt.condition !== undefined;
}

// --- decide(): resolve one (action, resource) request ------------------------

/**
 * Evaluate what THIS policy says about one concrete request. Never throws.
 * Honors explicit-Deny precedence; never overstates certainty.
 *
 * @param {object} model normalized, frozen model from buildModel()
 * @param {{action:string, resource?:string}} request concrete request context
 * @returns {{
 *   ok:boolean, errors:Array, action:(string|null), resource:(string|null),
 *   decision:string, certainty:string, caveat:string, explanation:string,
 *   explicitDeny:boolean, conditionalDeny:boolean,
 *   allow:boolean, conditionalAllow:boolean,
 *   matches:Array<object>
 * }}
 */
export function decide(model, request) {
  const errors = [];
  const empty = {
    ok: false,
    errors,
    action: null,
    resource: null,
    decision: DECISION.NOT_GRANTED_BY_POLICY,
    certainty: CERTAINTY.UNKNOWN_INCOMPLETE_CONTEXT,
    caveat: CAPABILITY_CAVEAT,
    explanation: '',
    explicitDeny: false,
    conditionalDeny: false,
    allow: false,
    conditionalAllow: false,
    policyVariable: false,
    matches: [],
  };

  try {
    if (!model || typeof model !== 'object' || !Array.isArray(model.statements)) {
      errors.push({ code: 'NO_MODEL', message: 'decide() requires a normalized model.', path: null });
      return empty;
    }
    if (!request || typeof request !== 'object' || typeof request.action !== 'string') {
      errors.push({
        code: 'BAD_REQUEST',
        message: 'request must be an object with a string "action".',
        path: null,
      });
      return empty;
    }
    const action = request.action;
    const resource =
      typeof request.resource === 'string' ? request.resource : undefined;

    const matches = [];
    let explicitDeny = false;
    let conditionalDeny = false;
    let allow = false;
    let conditionalAllow = false;
    let policyVariable = false;

    for (const stmt of model.statements) {
      const a = actionApplies(stmt, action);
      if (!a.applies) continue;
      const r = resourceApplies(stmt, resource);
      if (!r.applies) continue;

      const conditioned = hasCondition(stmt);
      const usesVariable = Boolean(a.policyVariable || r.policyVariable);
      if (usesVariable) policyVariable = true;
      // A match is "definite" only when nothing is left to runtime: no
      // Condition block, AND both the action and resource dimensions were
      // checked with certainty (no IAM policy variable left to substitute).
      const definite = !conditioned && r.certain && a.certain;

      matches.push({
        index: stmt.index,
        sid: stmt.sid,
        effect: stmt.effect,
        actionBasis: a.basis,
        resourceBasis: r.basis,
        conditional: !definite,
        policyVariable: usesVariable,
        conditions: stmt.condition,
      });

      if (stmt.effect === 'Deny') {
        if (definite) explicitDeny = true;
        else conditionalDeny = true;
      } else {
        if (definite) allow = true;
        else conditionalAllow = true;
      }
    }

    const resolved = resolveDecision({
      explicitDeny,
      conditionalDeny,
      allow,
      conditionalAllow,
    });

    return {
      ok: true,
      errors,
      action,
      resource: resource === undefined ? null : resource,
      decision: resolved.decision,
      certainty: resolved.certainty,
      caveat: CAPABILITY_CAVEAT,
      explanation: buildDecisionExplanation(action, resource, resolved, {
        explicitDeny,
        conditionalDeny,
        allow,
        conditionalAllow,
        policyVariable,
      }),
      explicitDeny,
      conditionalDeny,
      allow,
      conditionalAllow,
      policyVariable,
      matches,
    };
  } catch (e) {
    errors.push({ code: 'INTERNAL', message: 'Evaluation failed unexpectedly.', path: null });
    return empty;
  }
}

// Pure resolution of the four booleans into a decision + certainty. Explicit
// (unconditional) Deny always wins. A conditional Deny is never treated as a
// definitive block.
function resolveDecision({ explicitDeny, conditionalDeny, allow, conditionalAllow }) {
  if (explicitDeny) {
    return { decision: DECISION.EXPLICIT_DENY, certainty: CERTAINTY.BLOCKED_BY_DENY };
  }
  if (allow) {
    // An unconditional Allow matches. If a conditional Deny could still fire,
    // the true outcome depends on that Condition -> conditional, not allowed.
    if (conditionalDeny) {
      return { decision: DECISION.CONDITIONAL, certainty: CERTAINTY.CONDITIONALLY_REACHABLE };
    }
    return { decision: DECISION.ALLOWED_BY_POLICY, certainty: CERTAINTY.CONFIRMED_BY_CONTEXT };
  }
  if (conditionalAllow) {
    return { decision: DECISION.CONDITIONAL, certainty: CERTAINTY.CONDITIONALLY_REACHABLE };
  }
  // No Allow of any kind, but a conditional Deny might fire at runtime (a
  // Condition block and/or an IAM policy variable whose value is unknown here).
  // Reporting NOT_GRANTED would hide a deny that may actually apply, and
  // reporting EXPLICIT_DENY would overstate certainty (a false deny). The honest
  // answer is that the outcome depends on runtime context.
  if (conditionalDeny) {
    return {
      decision: DECISION.CONDITIONAL,
      certainty: CERTAINTY.UNKNOWN_INCOMPLETE_CONTEXT,
    };
  }
  // Nothing matches at all. This policy does not grant the request.
  return {
    decision: DECISION.NOT_GRANTED_BY_POLICY,
    certainty: CERTAINTY.UNKNOWN_INCOMPLETE_CONTEXT,
  };
}

// IAM policy variables (${...}) resolve only at runtime, so any decision that
// depended on a variable-bearing pattern must say so.
const POLICY_VARIABLE_CAVEAT =
  ' One or more matching statements use IAM policy variables (e.g. ' +
  '${aws:username}), whose values are substituted at runtime; the true match ' +
  'therefore depends on the request principal and cannot be resolved from the ' +
  'policy text alone.';

function buildDecisionExplanation(action, resource, resolved, flags) {
  const on = resource ? ` on "${resource}"` : '';
  const varNote = flags.policyVariable ? POLICY_VARIABLE_CAVEAT : '';
  switch (resolved.decision) {
    case DECISION.EXPLICIT_DENY:
      return `"${action}"${on} is explicitly denied by an unconditional Deny statement. Explicit Deny overrides every Allow, so this policy blocks the request within any context it applies to.`;
    case DECISION.ALLOWED_BY_POLICY:
      return `This policy, on its own, would grant "${action}"${on}. ${CAPABILITY_CAVEAT}`;
    case DECISION.CONDITIONAL: {
      if (flags.allow && flags.conditionalDeny) {
        return `This policy would grant "${action}"${on}, but a conditional Deny may block it depending on runtime Condition keys and/or IAM policy variables. Outcome cannot be resolved from the policy text alone.${varNote}`;
      }
      if (!flags.allow && !flags.conditionalAllow && flags.conditionalDeny) {
        return `This policy contains a Deny for "${action}"${on} whose applicability depends on runtime context (a Condition and/or an IAM policy variable), so it cannot be resolved from the policy text alone. It does not grant the request.${varNote}`;
      }
      return `Whether this policy grants "${action}"${on} depends on runtime Condition keys and/or request context not supplied here.${varNote}`;
    }
    default:
      return `No statement in this policy grants "${action}"${on}. This is a per-policy implicit deny - it does NOT prove the principal lacks the permission, because other attached policies are not in scope.`;
  }
}

// --- evaluate(): per-statement capability view -------------------------------

/**
 * Produce a plain-language capability view of every statement in the policy.
 * Never throws. This is the single-policy "what does each statement grant or
 * deny" answer - explicitly a capability view, never effective permissions.
 *
 * @param {object} model normalized, frozen model from buildModel()
 * @returns {{ok:boolean, errors:Array, caveat:string, hasExplicitDeny:boolean,
 *            allowCount:number, denyCount:number, statements:Array<object>}}
 */
export function evaluate(model) {
  const errors = [];
  try {
    if (!model || typeof model !== 'object' || !Array.isArray(model.statements)) {
      errors.push({ code: 'NO_MODEL', message: 'evaluate() requires a normalized model.', path: null });
      return Object.freeze({
        ok: false,
        errors,
        caveat: CAPABILITY_CAVEAT,
        hasExplicitDeny: false,
        allowCount: 0,
        denyCount: 0,
        statements: [],
      });
    }

    let allowCount = 0;
    let denyCount = 0;
    let hasExplicitDeny = false;
    const statements = model.statements.map((stmt) => {
      if (stmt.effect === 'Deny') {
        denyCount++;
        if (!hasCondition(stmt)) hasExplicitDeny = true;
      } else {
        allowCount++;
      }
      return explainStatement(stmt);
    });

    return Object.freeze({
      ok: true,
      errors,
      caveat: CAPABILITY_CAVEAT,
      hasExplicitDeny,
      allowCount,
      denyCount,
      statements: Object.freeze(statements),
    });
  } catch (e) {
    errors.push({ code: 'INTERNAL', message: 'Evaluation failed unexpectedly.', path: null });
    return Object.freeze({
      ok: false,
      errors,
      caveat: CAPABILITY_CAVEAT,
      hasExplicitDeny: false,
      allowCount: 0,
      denyCount: 0,
      statements: [],
    });
  }
}

/**
 * Explain a single normalized statement as a capability object. Exported for
 * direct unit testing. Never throws for a well-formed normalized statement.
 */
export function explainStatement(stmt) {
  const actionMode = stmt.notActions.length > 0 ? 'NotAction' : 'Action';
  let resourceMode = 'none';
  if (stmt.resources.length > 0) resourceMode = 'Resource';
  else if (stmt.notResources.length > 0) resourceMode = 'NotResource';

  const conditional = hasCondition(stmt);
  const caveats = [];

  // NotAction is an inversion: it governs EVERYTHING EXCEPT the listed actions.
  // This is a classic source of accidental over-grant - spell it out.
  if (actionMode === 'NotAction') {
    caveats.push(
      stmt.effect === 'Allow'
        ? 'NotAction on an Allow grants EVERY action EXCEPT the ones listed - a very broad grant that is easy to underestimate. It does not scope down to a service.'
        : 'NotAction on a Deny denies EVERY action EXCEPT the ones listed.',
    );
  }
  // NotResource likewise inverts the resource set.
  if (resourceMode === 'NotResource') {
    caveats.push(
      stmt.effect === 'Deny'
        ? 'NotResource on a Deny denies the action(s) on EVERY resource EXCEPT the ones listed - the listed resources are the only ones spared.'
        : 'NotResource on an Allow grants the action(s) on EVERY resource EXCEPT the ones listed - typically far broader than intended.',
    );
  }
  if (resourceMode === 'none') {
    caveats.push(
      'Statement specifies neither Resource nor NotResource, so its resource scope cannot be determined from the policy text.',
    );
  }
  // IAM policy variables (${...}) in any dimension are resolved only at runtime;
  // matches against concrete ARNs here are indicative, never definitive.
  const usesPolicyVariable = [
    stmt.actions,
    stmt.notActions,
    stmt.resources,
    stmt.notResources,
  ].some((list) => list.some((p) => hasPolicyVariable(p)));
  if (usesPolicyVariable) {
    caveats.push(
      'This statement uses IAM policy variables (e.g. ${aws:username}); its true scope is only known at runtime after variable substitution, so any match against a concrete ARN or action here is potential, not definitive.',
    );
  }
  if (conditional) {
    caveats.push(
      'This statement is gated by a Condition block; whether it takes effect depends on runtime request context not supplied here.',
    );
  }

  return {
    index: stmt.index,
    sid: stmt.sid,
    effect: stmt.effect,
    actionMode,
    resourceMode,
    actions: stmt.actions,
    notActions: stmt.notActions,
    resources: stmt.resources,
    notResources: stmt.notResources,
    conditional,
    conditions: stmt.condition,
    policyVariable: usesPolicyVariable,
    summary: buildStatementSummary(stmt, actionMode, resourceMode, conditional),
    caveats,
    label: 'capability',
    caveat: CAPABILITY_CAVEAT,
  };
}

function joinList(items) {
  return items.length ? items.join(', ') : '(none)';
}

function buildStatementSummary(stmt, actionMode, resourceMode, conditional) {
  const verb = stmt.effect === 'Allow' ? 'Allows' : 'Denies';
  let actionPart;
  if (actionMode === 'NotAction') {
    actionPart = `every action EXCEPT ${joinList(stmt.notActions)}`;
  } else {
    actionPart = joinList(stmt.actions);
  }
  let resourcePart;
  if (resourceMode === 'Resource') {
    resourcePart = ` on ${joinList(stmt.resources)}`;
  } else if (resourceMode === 'NotResource') {
    resourcePart = ` on every resource EXCEPT ${joinList(stmt.notResources)}`;
  } else {
    resourcePart = ' on an unspecified resource scope';
  }
  const cond = conditional ? ', subject to a Condition' : '';
  return `${verb} ${actionPart}${resourcePart}${cond}.`;
}

export default evaluate;
