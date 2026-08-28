// escalation-consts.js - shared evidence/limit message strings for escalation findings. Extracted (behavior-preserving; pure string constants).

export const CAPABILITY_LIMIT =
  'Capability from this policy alone, not effective access. A single policy ' +
  'cannot establish effective permissions: other identity policies, resource ' +
  'policies, permission boundaries, SCPs, session policies, explicit Denies, ' +
  'and Condition keys may narrow or block this path.';

// The permissions of the role that is passed, assumed, or re-trusted are not in
// scope here and are treated as UNKNOWN, never inferred.
export const TARGET_UNKNOWN_LIMIT =
  ' The permissions of the target role (passed / assumed / re-trusted) are not ' +
  'in scope and are treated as unknown; this finding does not claim what that ' +
  'role can do, only that this policy would let the principal reach it.';

export const CONDITION_LIMIT =
  ' One or more statements in this path carry a Condition block beyond what was ' +
  'used to confirm it, so the path may be gated at runtime; confidence is ' +
  'reduced accordingly.';

// Applied when a Deny in the SAME policy touches an action in this path but does
// not definitively remove it across the whole granted scope (a conditional Deny,
// a Deny whose resource scope only partially overlaps, or a Deny match that
// cannot be resolved from the policy text). An unconditional, in-scope, concrete
// Deny suppresses the path entirely (no finding); this note covers the residual
// "may be blocked" cases where suppression would overstate a false deny.
export const DENY_NARROW_LIMIT =
  ' Another statement in this policy Denies one or more actions in this path. ' +
  'Explicit Deny overrides Allow, so this Deny may block or narrow the path at ' +
  'runtime; confidence is reduced accordingly.';

// Applied when the PassRole grant carries an iam:PassedToService condition using
// an operator whose effect cannot be resolved from the policy text (e.g. Null or
// an unsupported operator). The path is kept but not asserted with certainty.
export const PASSED_TO_SERVICE_UNCERTAIN_LIMIT =
  ' The iam:PassedToService condition on the PassRole grant uses an operator ' +
  'that cannot be resolved from the policy text, so whether this service may ' +
  'receive the role is uncertain; confidence is reduced accordingly.';
