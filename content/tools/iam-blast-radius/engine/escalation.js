// IAM Blast Radius - privilege-escalation path engine (IAM-005).
//
// Fifth stage of the pipeline (see docs/architecture.md data-flow):
//   text -> validate() -> parse() -> buildModel() -> [ evaluator, rules,
//   escalation ] -> { findings[], graph }
//
// analyzeEscalations() scans a normalized, frozen model (from buildModel()) and
// emits deterministic escalation findings using the canonical finding shape
// from docs/architecture.md. Where a rule (rules.js, IAM-004) reports a single
// dangerous CAPABILITY, an ESCALATION here reports a named attack PATH: a
// combination of grants (and their resource / condition relationships) that
// lets a principal grant itself more than it was given.
//
// Escalation families implemented (>=5, <=10 per the story):
//   1. PASSROLE-LAMBDA   iam:PassRole (to lambda) + lambda create/update.
//   2. PASSROLE-EC2      iam:PassRole (to ec2)    + ec2:RunInstances.
//   3. PASSROLE-SERVICE  iam:PassRole (to a service) + that service's
//                        role-consuming action (ecs/glue/cloudformation/
//                        sagemaker/codebuild/datapipeline).
//   4. POLICY-VERSION    iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion.
//   5. ATTACH-POLICY     iam:Attach{User,Role,Group}Policy (attach admin to self).
//   6. PUT-INLINE-POLICY iam:Put{User,Role,Group}Policy (write inline admin).
//   7. TRUST-POLICY-MODIFY iam:UpdateAssumeRolePolicy (rewrite a role's trust).
//   8. CREDENTIAL-CREATION iam:CreateAccessKey / Create|UpdateLoginProfile.
//   9. ASSUME-ROLE-EXPANSION sts:AssumeRole over a wildcard / broad role scope.
//
// TRUTHFULNESS INVARIANTS (docs/architecture.md #6, threat-model T8):
//   - A single policy CANNOT establish effective permissions. Every finding's
//     `limit` says so, and every escalation carries `targetPermissions:
//     "unknown"` - the permissions of the role that is passed / assumed /
//     re-trusted are NOT in scope here and are NEVER inferred (story
//     requirement: "Represent missing target-role permissions as 'unknown',
//     never inferred").
//   - The PassRole family respects Resource / NotResource and the
//     iam:PassedToService condition: iam:PassRole ALONE is never flagged, and a
//     PassRole whose PassedToService pins a DIFFERENT service than the granted
//     service-execution action does not manufacture a path for that action.
//   - Escalation paths are built from Allow statements, but same-policy
//     explicit-Deny precedence is honored (AWS resolves access with explicit
//     Deny overriding Allow): an unconditional, in-scope, concrete Deny of a
//     required action SUPPRESSES the path (no finding), and a conditional /
//     partial-scope / unresolved Deny reduces its confidence. Permission
//     boundaries, SCPs, and session policies not supplied here may still block
//     a path - the `limit` states this.
//
// Analyzed policies are HOSTILE input. Wildcard matching uses a linear
// two-pointer glob matcher (NOT a regex compiled from input) to avoid ReDoS.
// Every string from the policy is inert data: only ever compared, never
// interpreted as code or markup.
//
// Public API:
//   ESCALATIONS                    -> frozen catalog metadata (id/title/...)
//   ESCALATION_IDS                 -> frozen array of every id this can emit
//   analyzeEscalations(model)      -> { ok, errors[], findings[] }   (frozen)
//   analyzeEscalationsFromText(t)  -> { ok, errors[], findings[] }   (pipeline)
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. Deterministic:
// same model -> same findings, same order, every run (no Date/Math.random).

import { modelFromText } from './model.js';

// --- Shared caveat language --------------------------------------------------
// One constant so every escalation's `limit` carries identical, non-overstated
// wording about what a single policy can and cannot prove. Contains the phrase
// "not effective access" that the truthfulness tests assert on.
const CAPABILITY_LIMIT =
  'Capability from this policy alone, not effective access. A single policy ' +
  'cannot establish effective permissions: other identity policies, resource ' +
  'policies, permission boundaries, SCPs, session policies, explicit Denies, ' +
  'and Condition keys may narrow or block this path.';

// The permissions of the role that is passed, assumed, or re-trusted are not in
// scope here and are treated as UNKNOWN, never inferred.
const TARGET_UNKNOWN_LIMIT =
  ' The permissions of the target role (passed / assumed / re-trusted) are not ' +
  'in scope and are treated as unknown; this finding does not claim what that ' +
  'role can do, only that this policy would let the principal reach it.';

const CONDITION_LIMIT =
  ' One or more statements in this path carry a Condition block beyond what was ' +
  'used to confirm it, so the path may be gated at runtime; confidence is ' +
  'reduced accordingly.';

// Applied when a Deny in the SAME policy touches an action in this path but does
// not definitively remove it across the whole granted scope (a conditional Deny,
// a Deny whose resource scope only partially overlaps, or a Deny match that
// cannot be resolved from the policy text). An unconditional, in-scope, concrete
// Deny suppresses the path entirely (no finding); this note covers the residual
// "may be blocked" cases where suppression would overstate a false deny.
const DENY_NARROW_LIMIT =
  ' Another statement in this policy Denies one or more actions in this path. ' +
  'Explicit Deny overrides Allow, so this Deny may block or narrow the path at ' +
  'runtime; confidence is reduced accordingly.';

// Applied when the PassRole grant carries an iam:PassedToService condition using
// an operator whose effect cannot be resolved from the policy text (e.g. Null or
// an unsupported operator). The path is kept but not asserted with certainty.
const PASSED_TO_SERVICE_UNCERTAIN_LIMIT =
  ' The iam:PassedToService condition on the PassRole grant uses an operator ' +
  'that cannot be resolved from the policy text, so whether this service may ' +
  'receive the role is uncertain; confidence is reduced accordingly.';

// --- Linear glob matcher (ReDoS-safe) ----------------------------------------
// Matches an IAM wildcard pattern ('*' = any run incl. empty, '?' = one char)
// against a literal string using two-pointer scanning. O(n*m) worst case, NO
// catastrophic backtracking (unlike a regex compiled from hostile input).
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
// Exported so graph.js (IAM-006) can apply the SAME same-policy Deny precedence
// to rule findings that this module already applies to escalation findings.
export function actionGrants(pattern, concreteAction) {
  return globMatch(String(pattern).toLowerCase(), String(concreteAction).toLowerCase());
}

// The full wildcard: owned by rules.js WILDCARD-ACTION. Escalation deliberately
// skips a bare "*" so an admin policy is not re-flagged as every named path
// (noise); "*" is already the widest possible critical finding on its own.
function isFullWildcard(pattern) {
  return pattern === '*';
}

// IAM policy variables (${...}) resolve only at runtime. A variable-bearing
// pattern cannot be matched from the policy text; treat it as uncertain so we
// never manufacture a false path (or hide one). Handled per-use below.
export function hasPolicyVariable(pattern) {
  return String(pattern).includes('${');
}

// Does statement `stmt` (an Allow) grant at least one action matching any of the
// concrete actions in `catalog`? Returns the matching statement patterns.
// Skips a bare "*" (owned by WILDCARD-ACTION) so escalation stays specific.
function grantedPatternsFor(stmt, catalog) {
  const matched = [];
  for (const p of stmt.actions) {
    if (isFullWildcard(p)) continue;
    if (hasPolicyVariable(p)) continue; // cannot resolve from text -> skip
    if (catalog.some((concrete) => actionGrants(p, concrete))) matched.push(p);
  }
  // An Allow with NotAction grants everything EXCEPT the listed actions, so it
  // grants these sensitive actions unless one is explicitly excluded. This is a
  // genuine (broad) grant of the escalation action.
  if (stmt.notActions.length > 0) {
    for (const concrete of catalog) {
      const excluded = stmt.notActions.some(
        (p) => !hasPolicyVariable(p) && actionGrants(p, concrete),
      );
      // Not excluded => this NotAction-Allow grants the sensitive action. Report
      // the concrete action it fails to exclude (guard against dupes).
      if (!excluded && !matched.includes(concrete)) matched.push(concrete);
    }
  }
  return matched;
}

// --- Service-execution catalog (PassRole targets) ----------------------------
// Each entry: the AWS service, its service principal (matched against
// iam:PassedToService), the finding id to emit, and the concrete role-consuming
// actions that, combined with iam:PassRole, complete the path. Passing a role
// to a service you can also make run code as = run code with that role.
const PASS_ROLE_SERVICES = Object.freeze([
  Object.freeze({
    service: 'lambda',
    principal: 'lambda.amazonaws.com',
    id: 'PASSROLE-LAMBDA',
    execActions: Object.freeze([
      'lambda:CreateFunction',
      'lambda:UpdateFunctionCode',
      'lambda:UpdateFunctionConfiguration',
    ]),
  }),
  Object.freeze({
    service: 'ec2',
    principal: 'ec2.amazonaws.com',
    id: 'PASSROLE-EC2',
    execActions: Object.freeze(['ec2:RunInstances']),
  }),
  Object.freeze({
    service: 'ecs',
    principal: 'ecs-tasks.amazonaws.com',
    id: 'PASSROLE-SERVICE',
    execActions: Object.freeze([
      'ecs:RunTask',
      'ecs:StartTask',
      'ecs:RegisterTaskDefinition',
    ]),
  }),
  Object.freeze({
    service: 'glue',
    principal: 'glue.amazonaws.com',
    id: 'PASSROLE-SERVICE',
    execActions: Object.freeze(['glue:CreateJob', 'glue:UpdateJob', 'glue:CreateDevEndpoint']),
  }),
  Object.freeze({
    service: 'cloudformation',
    principal: 'cloudformation.amazonaws.com',
    id: 'PASSROLE-SERVICE',
    execActions: Object.freeze(['cloudformation:CreateStack', 'cloudformation:UpdateStack']),
  }),
  Object.freeze({
    service: 'sagemaker',
    principal: 'sagemaker.amazonaws.com',
    id: 'PASSROLE-SERVICE',
    execActions: Object.freeze([
      'sagemaker:CreateTrainingJob',
      'sagemaker:CreateProcessingJob',
      'sagemaker:CreateNotebookInstance',
    ]),
  }),
  Object.freeze({
    service: 'codebuild',
    principal: 'codebuild.amazonaws.com',
    id: 'PASSROLE-SERVICE',
    execActions: Object.freeze(['codebuild:CreateProject', 'codebuild:UpdateProject']),
  }),
  Object.freeze({
    service: 'datapipeline',
    principal: 'datapipeline.amazonaws.com',
    id: 'PASSROLE-SERVICE',
    execActions: Object.freeze(['datapipeline:CreatePipeline', 'datapipeline:PutPipelineDefinition']),
  }),
]);

const PASS_ROLE_ACTION = 'iam:PassRole';

// --- Single-action / broad-scope escalation catalogs -------------------------

const POLICY_VERSION_ACTIONS = Object.freeze([
  'iam:CreatePolicyVersion',
  'iam:SetDefaultPolicyVersion',
]);

const ATTACH_POLICY_ACTIONS = Object.freeze([
  'iam:AttachUserPolicy',
  'iam:AttachRolePolicy',
  'iam:AttachGroupPolicy',
]);

const PUT_INLINE_POLICY_ACTIONS = Object.freeze([
  'iam:PutUserPolicy',
  'iam:PutRolePolicy',
  'iam:PutGroupPolicy',
]);

const TRUST_MODIFY_ACTIONS = Object.freeze(['iam:UpdateAssumeRolePolicy']);

const CREDENTIAL_ACTIONS = Object.freeze([
  'iam:CreateAccessKey',
  'iam:CreateLoginProfile',
  'iam:UpdateLoginProfile',
]);

const ASSUME_ROLE_ACTIONS = Object.freeze(['sts:AssumeRole', 'sts:AssumeRoleWithSAML', 'sts:AssumeRoleWithWebIdentity']);

// --- Catalog metadata --------------------------------------------------------
// Ordering here defines the deterministic within-statement finding order.

export const ESCALATIONS = Object.freeze({
  'PASSROLE-LAMBDA': Object.freeze({
    id: 'PASSROLE-LAMBDA',
    order: 0,
    title: 'PassRole to Lambda + function create/update',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html',
  }),
  'PASSROLE-EC2': Object.freeze({
    id: 'PASSROLE-EC2',
    order: 1,
    title: 'PassRole to EC2 + RunInstances',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html',
  }),
  'PASSROLE-SERVICE': Object.freeze({
    id: 'PASSROLE-SERVICE',
    order: 2,
    title: 'PassRole to a service + that service running code as the role',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html',
  }),
  'POLICY-VERSION': Object.freeze({
    id: 'POLICY-VERSION',
    order: 3,
    title: 'Managed-policy version manipulation',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagement.html',
  }),
  'ATTACH-POLICY': Object.freeze({
    id: 'ATTACH-POLICY',
    order: 4,
    title: 'Attach managed policy to self / a principal',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagement.html',
  }),
  'PUT-INLINE-POLICY': Object.freeze({
    id: 'PUT-INLINE-POLICY',
    order: 5,
    title: 'Write inline policy on self / a principal',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagement.html',
  }),
  'TRUST-POLICY-MODIFY': Object.freeze({
    id: 'TRUST-POLICY-MODIFY',
    order: 6,
    title: 'Role trust-policy modification (UpdateAssumeRolePolicy)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/roles-managingrole-editing-console.html',
  }),
  'CREDENTIAL-CREATION': Object.freeze({
    id: 'CREDENTIAL-CREATION',
    order: 7,
    title: 'Credential creation for a principal (access key / login profile)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagement.html',
  }),
  'ASSUME-ROLE-EXPANSION': Object.freeze({
    id: 'ASSUME-ROLE-EXPANSION',
    order: 8,
    title: 'Broad AssumeRole (role assumption over a wildcard scope)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html',
  }),
});

export const ESCALATION_IDS = Object.freeze(Object.keys(ESCALATIONS));

// --- Condition helpers -------------------------------------------------------

// Extract every Condition entry that binds iam:PassedToService (case-insensitive
// key), preserving the OPERATOR it appears under - the operator decides whether
// the values are an allowlist (StringEquals/StringLike) or a denylist
// (StringNotEquals/StringNotLike). Returns [{ op, values[] }]. Values are inert
// strings, only ever glob-compared to a service principal.
function passedToServiceEntries(condition) {
  const entries = [];
  if (!condition || typeof condition !== 'object') return entries;
  for (const op of Object.keys(condition)) {
    const block = condition[op];
    if (!block || typeof block !== 'object') continue;
    for (const key of Object.keys(block)) {
      if (key.toLowerCase() !== 'iam:passedtoservice') continue;
      const values = [];
      const v = block[key];
      if (typeof v === 'string') values.push(v);
      else if (Array.isArray(v)) {
        for (const item of v) if (typeof item === 'string') values.push(item);
      }
      entries.push({ op, values });
    }
  }
  return entries;
}

// Normalize a condition operator to its base form: drop the set qualifier
// (ForAnyValue:/ForAllValues:) and the ...IfExists suffix so StringEquals,
// ForAnyValue:StringEquals and StringEqualsIfExists all classify the same.
function normalizeOperator(op) {
  let o = String(op).toLowerCase();
  o = o.replace(/^forany(value)?:/, '').replace(/^forall(values)?:/, '');
  o = o.replace(/ifexists$/, '');
  return o;
}

// Given one PassedToService condition entry (operator + values), does it permit
// passing a role to `principal`? Returns 'permit' | 'deny' | 'uncertain'.
//   - Allowlist operators (StringEquals/StringLike, case-insensitive variants):
//     permit iff a value glob-matches the principal, else deny (only the listed
//     services may receive the role).
//   - Denylist operators (StringNotEquals/StringNotLike): permit iff NO value
//     matches (may pass to any service EXCEPT the listed ones).
//   - Null and any unrecognized operator: uncertain (cannot resolve from text;
//     do NOT assume allowlist semantics, which would invert the meaning).
function operatorPermitsService(op, values, principal) {
  const base = normalizeOperator(op);
  const p = String(principal).toLowerCase();
  const matchAny = values.some((v) => globMatch(String(v).toLowerCase(), p));
  switch (base) {
    case 'stringequals':
    case 'stringequalsignorecase':
    case 'stringlike':
    case 'arnequals':
    case 'arnlike':
      return matchAny ? 'permit' : 'deny';
    case 'stringnotequals':
    case 'stringnotequalsignorecase':
    case 'stringnotlike':
    case 'arnnotequals':
    case 'arnnotlike':
      return matchAny ? 'deny' : 'permit';
    default:
      // Null, Date*, Bool, and anything unrecognized: meaning cannot be
      // determined from the policy text -> uncertain.
      return 'uncertain';
  }
}

// Does a PassRole statement's PassedToService condition permit passing a role to
// service principal `principal`? AWS ANDs multiple condition operators together,
// so a single operator that forbids this service blocks it. Returns:
//   { permits: boolean, pinned: boolean, uncertain: boolean }
//   - pinned=false  : no PassedToService condition -> can pass to ANY service
//                     (subject to the role's own trust policy, unknown here).
//   - pinned=true   : condition present; permits reflects allow/deny-list logic.
//   - uncertain=true: an operator (e.g. Null / unsupported) could not be
//                     resolved from the policy text; the path is kept but its
//                     confidence is reduced rather than asserting a false result.
function passRolePermitsService(condition, principal) {
  const entries = passedToServiceEntries(condition);
  if (entries.length === 0) return { permits: true, pinned: false, uncertain: false };
  let uncertain = false;
  for (const e of entries) {
    const disp = operatorPermitsService(e.op, e.values, principal);
    // A definitive deny under any AND-ed operator blocks this service outright.
    if (disp === 'deny') return { permits: false, pinned: true, uncertain: false };
    if (disp === 'uncertain') uncertain = true;
  }
  return { permits: true, pinned: true, uncertain };
}

function hasNonEmptyCondition(stmt) {
  return (
    stmt.condition !== null &&
    stmt.condition !== undefined &&
    typeof stmt.condition === 'object' &&
    Object.keys(stmt.condition).length > 0
  );
}

// --- Resource-scope helpers --------------------------------------------------

function resourceScope(stmt) {
  if (stmt.resources.length > 0) return stmt.resources;
  if (stmt.notResources.length > 0) return stmt.notResources;
  return ['(no Resource/NotResource specified)'];
}

// Is a resource pattern "broad" for role assumption? True for a bare "*", a
// NotResource inverse, an unspecified scope, or an ARN that wildcards the role
// path (e.g. arn:aws:iam::*:role/*). A single concrete role ARN is NOT broad.
function resourceListIsBroadForAssume(stmt) {
  if (stmt.notResources.length > 0) return true;
  if (stmt.resources.length === 0) return true; // unspecified scope
  return stmt.resources.some((r) => {
    if (r === '*') return true;
    // A wildcard in the role-name portion of the ARN reaches many roles.
    return r.includes('*') || r.includes('?');
  });
}

// --- Explicit-Deny analysis (same-policy precedence) -------------------------
// AWS resolves access with explicit-Deny precedence: an in-scope, applicable
// Deny overrides every Allow. The escalation engine builds paths from Allow
// statements, but a same-policy Deny of a required action can remove or narrow
// the path. Mirrors evaluator.js resolveDecision(): an unconditional, concrete,
// in-scope Deny is definitive; a conditional / variable / partial-scope Deny is
// treated as "may block" (reduces confidence) rather than a false certainty.

// Does a Deny statement's Action/NotAction apply to concrete `action`?
// Returns { applies, certain }. NotAction on a Deny denies everything EXCEPT the
// listed actions. Variable-bearing patterns cannot be resolved from text -> the
// match is possible but not certain.
function denyActionApplies(stmt, action) {
  if (stmt.notActions.length > 0) {
    let concreteExcluded = false;
    let hasVar = false;
    for (const p of stmt.notActions) {
      if (hasPolicyVariable(p)) { hasVar = true; continue; }
      if (actionGrants(p, action)) concreteExcluded = true;
    }
    if (concreteExcluded) return { applies: false, certain: true };
    // Not concretely excluded: NotAction-Deny applies to (touches) this action. A
    // variable in the exclusion list might exclude it at runtime -> uncertain.
    // NOTE: `applies:true` here means the Deny narrows the grant, NOT that it
    // fully covers it. Whether it can HARD-BLOCK is decided in denyEffectOnAction,
    // which refuses full coverage for a NotAction-Deny against a broad/wildcard
    // grant token (the preserved actions stay allowed) - do not "optimize" this to
    // block a wildcard grant here, or false denies return (threat-model T8).
    return { applies: true, certain: !hasVar };
  }
  let concreteMatch = false;
  let hasVar = false;
  for (const p of stmt.actions) {
    if (hasPolicyVariable(p)) { hasVar = true; continue; }
    if (actionGrants(p, action)) concreteMatch = true;
  }
  if (concreteMatch) return { applies: true, certain: true };
  if (hasVar) return { applies: true, certain: false }; // might match at runtime
  return { applies: false, certain: true };
}

// True if a resource pattern is a bare "*" (or the account/path-spanning
// "arn:...:*" form is NOT treated as full here; only a literal "*" fully covers).
function isStarResource(r) {
  return r === '*';
}

// A grant token is "broad" when it is a wildcard pattern ('*', 'service:*', or
// any pattern containing '*' / '?') - i.e. it matches more than one concrete
// action. A NotAction-Deny ("deny everything EXCEPT the listed actions") can
// NEVER fully cover a broad grant token: at least one NotAction-preserved action
// falls within the broad grant and stays ALLOWED, so such a Deny can only NARROW
// the grant, never remove it. (Reporting it as fully blocked would be a false
// deny - it renders a still-reachable capability as definitively blocked, a
// truthfulness harm; docs/architecture.md #6, threat-model T8.) A CONCRETE grant
// token, by contrast, is either preserved by the NotAction list -> the Deny does
// not apply -> or fully denied -> genuine full coverage.
function grantTokenIsBroad(action) {
  const a = String(action);
  return a.includes('*') || a.includes('?');
}

// How completely does `denyStmt` cover the resource scope granted by `allowStmt`?
// Returns 'full' | 'partial' | 'none'. Only 'full' (paired with an unconditional,
// certain action match) suppresses a path; 'partial' reduces confidence.
export function denyResourceCoverage(denyStmt, allowStmt) {
  // A Deny scoped by NotResource, or with no Resource/NotResource, cannot be
  // proven to fully cover the Allow scope from the policy text -> partial.
  if (denyStmt.notResources.length > 0) return 'partial';
  if (denyStmt.resources.length === 0) return 'partial';
  // A Deny on "*" covers every resource the Allow could reach.
  if (denyStmt.resources.some(isStarResource)) return 'full';

  const allowRes = allowStmt.resources;
  // Allow scoped by NotResource or unspecified is broad; a concrete Deny list
  // cannot be shown to cover all of it -> partial overlap at most.
  if (allowStmt.notResources.length > 0 || allowRes.length === 0) return 'partial';

  // Both have concrete Resource lists. Full coverage requires every Allow
  // resource to be a concrete literal (no wildcard / no policy variable) that
  // some concrete Deny pattern matches. Otherwise the coverage is uncertain.
  let anyOverlap = false;
  const allCovered = allowRes.every((ar) => {
    if (hasPolicyVariable(ar) || ar.includes('*') || ar.includes('?')) {
      // Wildcarded / variable Allow scope: a concrete Deny may still overlap
      // part of it, but cannot be proven to cover all -> not full.
      if (denyStmt.resources.some((dr) => !hasPolicyVariable(dr) && globMatch(dr, ar))) {
        anyOverlap = true;
      }
      return false;
    }
    const covered = denyStmt.resources.some(
      (dr) => !hasPolicyVariable(dr) && globMatch(dr, ar),
    );
    if (covered) anyOverlap = true;
    return covered;
  });
  if (allCovered) return 'full';
  return anyOverlap ? 'partial' : 'none';
}

// Classify how the model's Deny statements affect one required `action` granted
// by `allowStmt`. Returns 'blocked' | 'may-block' | 'clear'.
function denyEffectOnAction(denies, action, allowStmt) {
  let result = 'clear';
  for (const deny of denies) {
    const a = denyActionApplies(deny, action);
    if (!a.applies) continue;
    const coverage = denyResourceCoverage(deny, allowStmt);
    if (coverage === 'none') continue;
    const conditioned = hasNonEmptyCondition(deny);
    // A NotAction-Deny cannot FULLY cover a broad/wildcard grant token (the
    // NotAction-preserved action(s) remain allowed), so against such a grant it
    // can only narrow, never block. Full action coverage - the precondition for
    // a hard block - therefore requires either a positive-Action Deny (whose
    // pattern demonstrably covers the grant token) or a concrete grant token.
    const notActionVsBroadGrant = deny.notActions.length > 0 && grantTokenIsBroad(action);
    if (!conditioned && a.certain && coverage === 'full' && !notActionVsBroadGrant) {
      return 'blocked'; // definitive, in-scope explicit Deny -> path removed
    }
    result = 'may-block'; // conditional / partial / uncertain / narrowing -> narrows path
  }
  return result;
}

// Apply same-policy Deny precedence to a finding's matched concrete actions.
// Returns { actions, blocked, narrowed }:
//   - actions : matched actions with definitively-blocked ones removed
//   - blocked : true if EVERY matched action was definitively blocked (suppress)
//   - narrowed: true if any action was removed or may be blocked (downgrade)
export function applyDenyToActions(denies, matchedActions, allowStmt) {
  if (denies.length === 0) {
    return { actions: matchedActions.slice(), blocked: false, narrowed: false };
  }
  const kept = [];
  let narrowed = false;
  for (const a of matchedActions) {
    const e = denyEffectOnAction(denies, a, allowStmt);
    if (e === 'blocked') { narrowed = true; continue; }
    if (e === 'may-block') narrowed = true;
    kept.push(a);
  }
  return { actions: kept, blocked: kept.length === 0, narrowed };
}

// --- Finding factory ---------------------------------------------------------

function statementSid(stmt) {
  return typeof stmt.sid === 'string' && stmt.sid.length > 0
    ? stmt.sid
    : `(index ${stmt.index})`;
}

// Build a canonical finding (docs/architecture.md shape) plus escalation-only
// enrichment: `escalation` (technique/service/target-unknown) and `evidence`
// (per-statement support for the graph builder in IAM-006). Extra fields are
// permitted alongside the canonical shape.
function makeEscalation(id, anchor, fields) {
  const meta = ESCALATIONS[id];
  // Confidence: caller supplies a base; a Condition beyond the confirming one
  // reduces it a notch (never below low). A same-policy Deny that may block the
  // path reduces it a further notch. Never auto-upgrade.
  let confidence = fields.confidence;
  let extraLimit = '';
  if (fields.conditioned) {
    confidence = downgrade(confidence);
    extraLimit += CONDITION_LIMIT;
  }
  if (fields.denyNarrowed) {
    confidence = downgrade(confidence);
    extraLimit += DENY_NARROW_LIMIT;
  }
  if (fields.passUncertain) {
    confidence = downgrade(confidence);
    extraLimit += PASSED_TO_SERVICE_UNCERTAIN_LIMIT;
  }
  return {
    id: meta.id,
    severity: fields.severity,
    title: meta.title,
    statementSid: statementSid(anchor),
    statementIndex: anchor.index,
    actions: fields.actions.slice(),
    resources: (fields.resources || []).slice(),
    conditions: anchor.condition, // null when absent; inert data otherwise
    confidence,
    why: fields.why,
    limit: CAPABILITY_LIMIT + TARGET_UNKNOWN_LIMIT + extraLimit,
    remediation: fields.remediation,
    ruleVersion: meta.ruleVersion,
    docRef: meta.docRef,
    // --- escalation enrichment (beyond the canonical shape) ---
    escalation: {
      technique: fields.technique,
      service: fields.service || null,
      requiredActions: (fields.requiredActions || []).slice(),
      targetPermissions: 'unknown',
    },
    evidence: fields.evidence.slice(),
  };
}

function downgrade(confidence) {
  if (confidence === 'high') return 'medium';
  if (confidence === 'medium') return 'low';
  return 'low';
}

function evidenceOf(stmt, role, action, note) {
  return {
    statementIndex: stmt.index,
    statementSid: statementSid(stmt),
    role, // 'pass' | 'execute' | 'primitive'
    action,
    resources: resourceScope(stmt),
    condition: stmt.condition,
    note: note || null,
  };
}

// --- PassRole + service-execution family -------------------------------------

function detectPassRolePaths(allows, out, denies) {
  // Gather the Allow statements that grant iam:PassRole (concrete or via iam:*).
  const passStmts = [];
  for (const stmt of allows) {
    const matched = grantedPatternsFor(stmt, [PASS_ROLE_ACTION]);
    if (matched.length > 0) passStmts.push(stmt);
  }
  if (passStmts.length === 0) return; // PassRole alone is never flagged, and
  // without any PassRole grant there is no pass path at all.

  for (const svc of PASS_ROLE_SERVICES) {
    // Gather EVERY Allow granting a role-consuming action for this service, then
    // apply same-policy explicit-Deny precedence PER statement. A Deny that fully
    // covers ONE exec statement must not hide a path that a DIFFERENT, un-denied
    // exec statement still grants (multi-statement policies) - suppressing on the
    // first-selected statement alone would be a false-safe / false negative
    // (docs/architecture.md #6, threat-model T8). We therefore keep a surviving
    // exec statement (not fully denied) and suppress only when EVERY exec
    // candidate is definitively, in-scope denied. Among survivors we prefer a
    // fully-clear one over a merely narrowed one, then the lowest statement index
    // (deterministic), so a live path is never reported as narrower than it is.
    let execStmt = null;
    let effectiveExecActions = null;
    let execNarrowed = false;
    let execAnyCandidate = false;
    for (const stmt of allows) {
      const m = grantedPatternsFor(stmt, svc.execActions);
      if (m.length === 0) continue;
      execAnyCandidate = true;
      const d = applyDenyToActions(denies, m, stmt);
      if (d.blocked) continue; // this exec statement is fully, in-scope denied
      const better =
        execStmt === null ||
        (execNarrowed && !d.narrowed) ||
        (execNarrowed === d.narrowed && stmt.index < execStmt.index);
      if (better) {
        execStmt = stmt;
        effectiveExecActions = d.actions;
        execNarrowed = d.narrowed;
      }
    }
    if (!execAnyCandidate) continue; // no service-execution action -> not this path
    if (!execStmt) continue; // every exec statement definitively denied -> path removed

    // Gather EVERY PassRole grant that can feed THIS service (respecting
    // PassedToService operator semantics: allowlist vs denylist vs uncertain),
    // then apply the SAME per-statement Deny precedence. As with the exec side, a
    // Deny that removes one PassRole grant must not suppress the path when another
    // permitting PassRole grant survives un-denied.
    let passStmt = null;
    let pinned = false;
    let passUncertain = false;
    let passNarrowed = false;
    let passAnyPermits = false;
    for (const stmt of passStmts) {
      const p = passRolePermitsService(stmt.condition, svc.principal);
      if (!p.permits) continue;
      passAnyPermits = true;
      const eff = denyEffectOnAction(denies, PASS_ROLE_ACTION, stmt);
      if (eff === 'blocked') continue; // this PassRole grant is fully, in-scope denied
      const narrowed = eff === 'may-block';
      const better =
        passStmt === null ||
        (passNarrowed && !narrowed) ||
        (passNarrowed === narrowed && stmt.index < passStmt.index);
      if (better) {
        passStmt = stmt;
        pinned = p.pinned;
        passUncertain = p.uncertain;
        passNarrowed = narrowed;
      }
    }
    if (!passAnyPermits) continue; // every PassRole forbids this service -> blocked
    if (!passStmt) continue; // every permitting PassRole grant definitively denied

    const denyNarrowed = passNarrowed || execNarrowed;

    // Confidence: an explicit PassedToService that matches this service confirms
    // the path (high). An unpinned PassRole can feed any service (also high, the
    // primitive exists). A Condition on the execution statement (not the
    // confirming PassedToService) gates the path and lowers confidence.
    const execConditioned = hasNonEmptyCondition(execStmt);
    const anchor = passStmt.index <= execStmt.index ? passStmt : execStmt;
    const combinedActions = [PASS_ROLE_ACTION].concat(effectiveExecActions);
    const evidence = [
      evidenceOf(
        passStmt,
        'pass',
        PASS_ROLE_ACTION,
        pinned
          ? `an iam:PassedToService condition permits passing a role to ${svc.principal}`
          : 'PassRole is not pinned to a service (can pass to any service)',
      ),
      evidenceOf(execStmt, 'execute', effectiveExecActions.join(', '), `runs code as the passed role via ${svc.service}`),
    ];
    out.push(
      makeEscalation(svc.id, anchor, {
        severity: 'high',
        confidence: 'high',
        conditioned: execConditioned,
        denyNarrowed,
        passUncertain,
        technique: 'passrole-service-execution',
        service: svc.service,
        requiredActions: [PASS_ROLE_ACTION].concat(svc.execActions),
        actions: combinedActions,
        resources: resourceScope(passStmt),
        evidence,
        why:
          `Grants iam:PassRole together with ${svc.service} action(s) ` +
          `(${effectiveExecActions.join(', ')}) that run code as the passed role. A ` +
          `principal can create/update a ${svc.service} workload with a role it ` +
          'is allowed to pass and execute as that role, gaining the role\'s ' +
          'permissions. ' +
          (pinned
            ? `The PassRole grant\'s iam:PassedToService condition permits passing ` +
              `a role to ${svc.principal}, so it can feed this service.`
            : 'The PassRole grant is not restricted with iam:PassedToService, so ' +
              'it can pass a role to this service.'),
        remediation:
          'Scope iam:PassRole to the specific role ARNs that must be passed and ' +
          `pin iam:PassedToService to ${svc.principal}; separate role-passing ` +
          `from ${svc.service} workload-creation duties, and constrain the ` +
          'passable roles with a permission boundary.',
      }),
    );
  }
}

// --- Single-action / broad-scope families ------------------------------------

function detectPolicyVersion(allows, out, denies) {
  for (const stmt of allows) {
    const matched = grantedPatternsFor(stmt, POLICY_VERSION_ACTIONS);
    if (matched.length === 0) continue;
    const deny = applyDenyToActions(denies, matched, stmt);
    if (deny.blocked) continue; // same-policy explicit Deny removes the path
    const actions = deny.actions;
    out.push(
      makeEscalation('POLICY-VERSION', stmt, {
        severity: 'high',
        confidence: 'high',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'policy-version-manipulation',
        requiredActions: POLICY_VERSION_ACTIONS.slice(),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions.join(', '))],
        why:
          'Grants managed-policy version control (iam:CreatePolicyVersion / ' +
          'iam:SetDefaultPolicyVersion). A principal attached to (or able to ' +
          'target) a customer-managed policy can publish a new, more permissive ' +
          'version and set it as the default, escalating its own access without ' +
          'attaching a new policy.',
        remediation:
          'Restrict policy-version actions to a dedicated policy-administration ' +
          'role, scope the Resource to specific policy ARNs, and require review ' +
          '(e.g. an MFA / approval Condition) for version changes.',
      }),
    );
  }
}

function detectAttachPolicy(allows, out, denies) {
  for (const stmt of allows) {
    const matched = grantedPatternsFor(stmt, ATTACH_POLICY_ACTIONS);
    if (matched.length === 0) continue;
    const deny = applyDenyToActions(denies, matched, stmt);
    if (deny.blocked) continue; // same-policy explicit Deny removes the path
    const actions = deny.actions;
    out.push(
      makeEscalation('ATTACH-POLICY', stmt, {
        severity: 'critical',
        confidence: 'high',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'attach-policy',
        requiredActions: ATTACH_POLICY_ACTIONS.slice(),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions.join(', '))],
        why:
          'Grants iam:Attach{User,Role,Group}Policy. A principal that can attach ' +
          'a managed policy to itself (or a principal it controls) can attach ' +
          'AdministratorAccess and obtain full administrative access - a direct ' +
          'privilege-escalation path.',
        remediation:
          'Remove self-service policy-attachment; if attachment is required, ' +
          'constrain the attachable policies with iam:PolicyARN Conditions and a ' +
          'permission boundary, and route changes through a reviewed pipeline.',
      }),
    );
  }
}

function detectPutInlinePolicy(allows, out, denies) {
  for (const stmt of allows) {
    const matched = grantedPatternsFor(stmt, PUT_INLINE_POLICY_ACTIONS);
    if (matched.length === 0) continue;
    const deny = applyDenyToActions(denies, matched, stmt);
    if (deny.blocked) continue; // same-policy explicit Deny removes the path
    const actions = deny.actions;
    out.push(
      makeEscalation('PUT-INLINE-POLICY', stmt, {
        severity: 'critical',
        confidence: 'high',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'put-inline-policy',
        requiredActions: PUT_INLINE_POLICY_ACTIONS.slice(),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions.join(', '))],
        why:
          'Grants iam:Put{User,Role,Group}Policy. A principal that can write an ' +
          'inline policy on itself (or a principal it controls) can grant itself ' +
          'any permission, including full admin - a direct privilege-escalation ' +
          'path.',
        remediation:
          'Remove self-service inline-policy writes; constrain with a permission ' +
          'boundary that caps the effective permissions, and route policy ' +
          'changes through a reviewed pipeline.',
      }),
    );
  }
}

function detectTrustModify(allows, out, denies) {
  for (const stmt of allows) {
    const matched = grantedPatternsFor(stmt, TRUST_MODIFY_ACTIONS);
    if (matched.length === 0) continue;
    const deny = applyDenyToActions(denies, matched, stmt);
    if (deny.blocked) continue; // same-policy explicit Deny removes the path
    const actions = deny.actions;
    out.push(
      makeEscalation('TRUST-POLICY-MODIFY', stmt, {
        severity: 'high',
        confidence: 'high',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'trust-policy-modification',
        requiredActions: TRUST_MODIFY_ACTIONS.slice(),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions.join(', '))],
        why:
          'Grants iam:UpdateAssumeRolePolicy. A principal can rewrite a role\'s ' +
          'trust policy to trust itself and then assume the role, taking on the ' +
          'role\'s permissions. Whether the target role is more privileged is not ' +
          'known from this policy, but the trust-then-assume primitive is present.',
        remediation:
          'Restrict iam:UpdateAssumeRolePolicy to a dedicated role-administration ' +
          'identity, scope the Resource to specific role ARNs, and protect ' +
          'high-value roles with a permission boundary and change review.',
      }),
    );
  }
}

function detectCredentialCreation(allows, out, denies) {
  for (const stmt of allows) {
    const matched = grantedPatternsFor(stmt, CREDENTIAL_ACTIONS);
    if (matched.length === 0) continue;
    const deny = applyDenyToActions(denies, matched, stmt);
    if (deny.blocked) continue; // same-policy explicit Deny removes the path
    const actions = deny.actions;
    out.push(
      makeEscalation('CREDENTIAL-CREATION', stmt, {
        severity: 'high',
        confidence: 'high',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'credential-creation',
        requiredActions: CREDENTIAL_ACTIONS.slice(),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions.join(', '))],
        why:
          'Grants credential creation (iam:CreateAccessKey / ' +
          'iam:CreateLoginProfile / iam:UpdateLoginProfile). A principal that can ' +
          'mint an access key or set a console password for another (more ' +
          'privileged) user can authenticate as that user - a lateral-movement / ' +
          'escalation primitive.',
        remediation:
          'Scope credential actions to the principal\'s own identity where ' +
          'possible (e.g. an ${aws:username} Resource Condition), and restrict ' +
          'creation of credentials for other users to a dedicated admin role.',
      }),
    );
  }
}

function detectAssumeRoleExpansion(allows, out, denies) {
  for (const stmt of allows) {
    const matched = grantedPatternsFor(stmt, ASSUME_ROLE_ACTIONS);
    if (matched.length === 0) continue;
    // Only a broad / wildcard role scope is an expansion path; assuming one
    // specific named role is the intended, routine use of AssumeRole.
    if (!resourceListIsBroadForAssume(stmt)) continue;
    const deny = applyDenyToActions(denies, matched, stmt);
    if (deny.blocked) continue; // same-policy explicit Deny removes the path
    const actions = deny.actions;
    out.push(
      makeEscalation('ASSUME-ROLE-EXPANSION', stmt, {
        severity: 'high',
        // Target roles are unknown, so this is a POTENTIAL expansion: medium.
        confidence: 'medium',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'assume-role-expansion',
        requiredActions: ['sts:AssumeRole'],
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions.join(', '), 'broad role scope')],
        why:
          'Grants sts:AssumeRole over a wildcard / broad role scope. A principal ' +
          'can assume many roles in the account and operate with their ' +
          'permissions. Which roles are reachable (and how privileged they are) ' +
          'depends on those roles\' trust policies, which are not in scope here.',
        remediation:
          'Scope sts:AssumeRole to the specific role ARNs the principal must ' +
          'assume; avoid wildcards in the role path, and ensure target roles\' ' +
          'trust policies only trust the intended principals.',
      }),
    );
  }
}

const DETECTORS = [
  detectPassRolePaths,
  detectPolicyVersion,
  detectAttachPolicy,
  detectPutInlinePolicy,
  detectTrustModify,
  detectCredentialCreation,
  detectAssumeRoleExpansion,
];

// --- Public entry points -----------------------------------------------------

/**
 * Analyze a normalized, frozen model for privilege-escalation paths. Never
 * throws.
 *
 * @param {object} model normalized, frozen model from buildModel()
 * @returns {{ok:boolean, errors:Array<{code:string,message:string,path:?string}>,
 *            findings:Array<object>}} frozen result; findings in deterministic
 *            order (anchor statement index, then escalation order, then id).
 */
export function analyzeEscalations(model) {
  const errors = [];
  try {
    if (!model || typeof model !== 'object' || !Array.isArray(model.statements)) {
      errors.push({ code: 'NO_MODEL', message: 'analyzeEscalations() requires a normalized model.', path: null });
      return Object.freeze({ ok: false, errors: Object.freeze(errors), findings: Object.freeze([]) });
    }

    // Escalation paths are built only from Allow statements; a Deny reduces
    // access and never grants a path. But a same-policy Deny of a required
    // action DOES constrain a path (AWS explicit-Deny precedence), so detectors
    // receive the Deny statements to suppress or narrow paths accordingly.
    // Escalation models what the ANALYZED IDENTITY can do. A statement that
    // names a Principal is a resource/trust-policy statement (it grants access
    // TO that principal - e.g. a role's trust policy allowing sts:AssumeRole),
    // not an identity-policy grant, so it must not drive identity-escalation
    // detection. Without this guard a trust policy's sts:AssumeRole is read as
    // ASSUME-ROLE-EXPANSION. normalizePrincipal() returns null iff no Principal.
    // (Found via real-policy corpus QA, 2026-08-21.)
    const isIdentityStmt = (s) => s.principal == null;
    const allows = model.statements.filter((s) => s.effect === 'Allow' && isIdentityStmt(s));
    const denies = model.statements.filter((s) => s.effect === 'Deny' && isIdentityStmt(s));

    const findings = [];
    for (const detect of DETECTORS) detect(allows, findings, denies);

    // Deterministic order: by anchor statement index, then escalation order,
    // then id (stable tiebreak for two findings sharing an anchor + order, e.g.
    // several PASSROLE-SERVICE services anchored on one PassRole statement).
    findings.sort((a, b) => {
      if (a.statementIndex !== b.statementIndex) return a.statementIndex - b.statementIndex;
      const oa = ESCALATIONS[a.id].order;
      const ob = ESCALATIONS[b.id].order;
      if (oa !== ob) return oa - ob;
      if (a.id !== b.id) return a.id < b.id ? -1 : 1;
      // Same id (e.g. two PASSROLE-SERVICE services): order by service name.
      const sa = (a.escalation && a.escalation.service) || '';
      const sb = (b.escalation && b.escalation.service) || '';
      return sa < sb ? -1 : sa > sb ? 1 : 0;
    });

    for (const f of findings) deepFreeze(f);
    return Object.freeze({ ok: true, errors: Object.freeze(errors), findings: Object.freeze(findings) });
  } catch (e) {
    errors.push({ code: 'INTERNAL', message: 'Escalation analysis failed unexpectedly.', path: null });
    return Object.freeze({ ok: false, errors: Object.freeze(errors), findings: Object.freeze([]) });
  }
}

/**
 * Convenience: run the full text -> validate -> parse -> model -> escalation
 * pipeline. Never throws.
 *
 * @param {string} text raw pasted/imported policy text
 * @returns {{ok:boolean, errors:Array, findings:Array<object>}}
 */
export function analyzeEscalationsFromText(text) {
  const m = modelFromText(text);
  if (!m.ok) {
    return Object.freeze({ ok: false, errors: m.errors, findings: Object.freeze([]) });
  }
  return analyzeEscalations(m.model);
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Object.isFrozen(value)) return value;
  Object.freeze(value);
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

export default analyzeEscalations;
