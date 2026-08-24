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
// SEVERITY MODEL (IAM-102). `critical` is RESERVED for compound escalation
// paths that plausibly cross a privilege boundary:
//   - PASSROLE-LAMBDA / PASSROLE-EC2 / PASSROLE-SERVICE: iam:PassRole combined
//     with a service action that runs code as the passed role - the principal
//     reaches execution under a DIFFERENT role's credentials (boundary crossing).
//   - ASSUME-ROLE-EXPANSION when, and ONLY when, the resource scope is
//     effectively ALL roles (a bare "*", or a role ARN whose role-name segment
//     is exactly "*" such as arn:aws:iam::*:role/* or arn:aws:iam::123:role/*,
//     or a NotResource inverse, or an unspecified scope). A PARTIAL role-name
//     wildcard (role/app-*) reaches many roles but not all -> stays `high`.
// Every other escalation here is a standalone single-action self-administration
// primitive (policy-version manipulation, attach/put policy, trust-policy
// modification, credential creation) or a scoped AssumeRole expansion. These are
// serious but standalone, so they cap at `high`. Asserting critical for a
// standalone primitive would claim more than the evidence supports
// (threat-model T8: overstated severity is itself a security harm). Severity
// (potential blast-radius magnitude) is orthogonal to confidence (evidence
// certainty): a broad AssumeRole is critical by scope yet only medium
// confidence because the target roles' permissions are unknown.
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

// A bare "*" action grant (Action:"*") grants EVERY action in every service,
// which necessarily includes iam:PassRole, sts:AssumeRole, and every direct-IAM
// self-administration action. It is therefore a superset of every escalation
// trigger this module recognizes, and MUST surface the paths it contains: an
// Action:"*" policy is de-facto AdministratorAccess. (Earlier this module
// skipped a bare "*" on the assumption that WILDCARD-ACTION "*" was already the
// single widest CRITICAL finding, so re-listing the named paths would be noise.
// IAM-102 removed that compensating critical - WILDCARD-ACTION is now `high` -
// so skipping "*" here left the risk summary affirmatively reporting
// "privilege-escalation paths: 0" for full admin, a strictly narrower iam:*
// policy yielding more paths than "*". That is an inaccurate security claim
// (threat-model T8: understating blast radius is as harmful as overstating it),
// so a bare "*" is now matched like any other pattern via actionGrants().)

// IAM policy variables (${...}) resolve only at runtime. A variable-bearing
// pattern cannot be matched from the policy text; treat it as uncertain so we
// never manufacture a false path (or hide one). Handled per-use below.
export function hasPolicyVariable(pattern) {
  return String(pattern).includes('${');
}

// Does statement `stmt` (an Allow) grant at least one action matching any of the
// concrete actions in `catalog`? Returns the matching statement patterns. A bare
// "*" glob-matches every catalog action (Action:"*" grants all of them), so it
// is reported like any other matching pattern - see the note above on why a
// full wildcard is no longer skipped here.
function grantedPatternsFor(stmt, catalog) {
  const matched = [];
  for (const p of stmt.actions) {
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

// IAM-902 role-takeover chain (modify-then-assume, no PassRole required). Three
// primitives that, when granted on the SAME role, let a principal take the role
// over: give it permissions, rewrite its trust to trust the attacker, then assume
// it. Each is scoped to a role, so all three are role-targeting actions.
//   grant  - iam:PutRolePolicy / iam:AttachRolePolicy write/attach a permission
//            policy onto the role (the user/group variants target a different
//            principal type and are NOT part of a role takeover).
//   trust  - iam:UpdateAssumeRolePolicy rewrites the role's trust policy.
//   assume - sts:AssumeRole assumes the re-trusted role. The federated
//            WithSAML / WithWebIdentity variants require an out-of-scope IdP
//            trust and are deliberately excluded from this exact-role chain.
const ROLE_TAKEOVER_GRANT_ACTIONS = Object.freeze(['iam:PutRolePolicy', 'iam:AttachRolePolicy']);
const ROLE_TAKEOVER_ASSUME_ACTIONS = Object.freeze(['sts:AssumeRole']);

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
  // IAM-902: compound role-takeover chain on a single role - grant permissions,
  // rewrite trust, then assume - which crosses a privilege boundary without
  // iam:PassRole. A critical compound path, distinct from the standalone
  // TRUST-POLICY-MODIFY / PUT-INLINE-POLICY / ATTACH-POLICY primitives it correlates.
  'ROLE-TAKEOVER': Object.freeze({
    id: 'ROLE-TAKEOVER',
    order: 9,
    title: 'Role takeover chain (grant permissions + rewrite trust + assume, same role)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_modify.html',
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

export function hasNonEmptyCondition(stmt) {
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

// IAM-102 severity discriminator: does an AssumeRole grant reach "effectively
// ALL roles" - i.e. all roles across ARBITRARY accounts? Critical is reserved
// for that boundary-crossing scope. Two axes must BOTH be unconstrained:
//   (1) account axis arbitrary   - the grant is not pinned to concrete
//       account id(s): a NotResource inverse, an unspecified scope, a bare "*",
//       a non-ARN pattern, or an ARN whose account field is wildcarded/empty
//       (this is exactly assumeAccountReach().arbitrary).
//   (2) role-name axis fully open - a NotResource inverse, an unspecified
//       scope, a bare "*", the bare shorthand "role/*", or a role ARN whose
//       role-name path segment is exactly "*".
// A grant pinned to a CONCRETE account - even arn:aws:iam::111122223333:role/*
// (all roles in ONE account) - is broad but BOUNDED to that account, so it is
// NOT effectively-all-roles and stays `high`, never critical: asserting critical
// would claim reach the account-pinned ARN does not support (threat-model T8,
// IAM-301 negative corpus). A PARTIAL role-name wildcard (role/app-*, role/app-?)
// reaches many roles but not all, so it too stays `high`.
function assumeScopeIsAllRoles(stmt) {
  // Account axis must be arbitrary first: a concrete-account grant is bounded.
  if (!assumeAccountReach(stmt).arbitrary) return false;
  if (stmt.notResources.length > 0) return true; // inverse: ~all roles
  if (stmt.resources.length === 0) return true; // unspecified: unconstrained
  return stmt.resources.some((r) => {
    if (r === '*') return true;
    if (r === 'role/*') return true; // bare shorthand
    const marker = ':role/';
    const idx = r.lastIndexOf(marker);
    if (idx === -1) return false;
    return r.slice(idx + marker.length) === '*'; // role-name segment is exactly "*"
  });
}

// A broad-for-assume grant is not necessarily cross-account. Determine whether
// the resource set can reach roles in accounts OTHER than ones it names.
// Returns { arbitrary, accounts }:
//   arbitrary=true  -> a NotResource inverse, an unspecified scope, a bare "*",
//                      a non-ARN pattern, or an ARN whose account field is
//                      wildcarded/empty is present -> reach is not confined to
//                      named accounts (may span arbitrary AWS accounts).
//   arbitrary=false -> every resource pins a concrete account; `accounts` lists
//                      the distinct account IDs the grant is confined to.
// Only the arbitrary case may carry the "arbitrary AWS accounts" claim; a grant
// like arn:aws:iam::111122223333:role/* is broad within ONE account, not across.
function assumeAccountReach(stmt) {
  if (stmt.notResources.length > 0) return { arbitrary: true, accounts: [] };
  if (stmt.resources.length === 0) return { arbitrary: true, accounts: [] };
  const accounts = new Set();
  for (const r of stmt.resources) {
    if (r === '*') return { arbitrary: true, accounts: [] };
    // ARN layout: arn:partition:service:region:account:resource
    const parts = r.split(':');
    if (parts.length < 6) return { arbitrary: true, accounts: [] }; // not a full ARN
    const account = parts[4];
    if (account === '' || account.includes('*') || account.includes('?')) {
      return { arbitrary: true, accounts: [] };
    }
    accounts.add(account);
  }
  return { arbitrary: false, accounts: [...accounts] };
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
export function denyActionApplies(stmt, action) {
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
  // Split certainty (IAM-104): every finding carries TWO orthogonal signals in
  // place of the old single `confidence`.
  //   policyEvidence     - how strongly THIS policy text establishes that the
  //                        required grants are present (both/all actions granted,
  //                        in scope, not overridden). Drives graph edge certainty.
  //   pathExploitability - how likely the path actually yields elevated privilege
  //                        given what is NOT in scope here: the target role's
  //                        (passed / assumed / re-trusted) unknown permissions,
  //                        service/instance-profile runtime behavior, and other
  //                        controls. A compound PassRole->service path has strong
  //                        policy evidence yet only MEDIUM exploitability because
  //                        the passable role's power is unknown.
  // Each caller supplies a base for both. A Condition beyond the confirming one,
  // a possibly-blocking same-policy Deny, and an unresolved iam:PassedToService
  // operator are runtime gates: each reduces BOTH signals a notch (never below
  // low, never auto-upgrade), since a gate weakens both the evidence that the
  // grant holds and the likelihood the path is reachable.
  let policyEvidence = fields.policyEvidence;
  let pathExploitability = fields.pathExploitability;
  let extraLimit = '';
  if (fields.conditioned) {
    policyEvidence = downgrade(policyEvidence);
    pathExploitability = downgrade(pathExploitability);
    extraLimit += CONDITION_LIMIT;
  }
  if (fields.denyNarrowed) {
    policyEvidence = downgrade(policyEvidence);
    pathExploitability = downgrade(pathExploitability);
    extraLimit += DENY_NARROW_LIMIT;
  }
  if (fields.passUncertain) {
    policyEvidence = downgrade(policyEvidence);
    pathExploitability = downgrade(pathExploitability);
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
    policyEvidence,
    pathExploitability,
    why: fields.why,
    limit: CAPABILITY_LIMIT + TARGET_UNKNOWN_LIMIT + extraLimit,
    remediation: fields.remediation,
    ruleVersion: meta.ruleVersion,
    docRef: meta.docRef,
    // --- escalation enrichment (beyond the canonical shape) ---
    escalation: {
      technique: fields.technique,
      service: fields.service || null,
      // IAM-703: `requiredActions` is a flat convenience list for the PRIMARY
      // technique, and it is GROUNDED - every entry is an action the analyzed
      // policy actually grants (never a catalog action the policy does not
      // contain). The authoritative AND/OR structure lives in `prerequisites`.
      requiredActions: (fields.requiredActions || []).slice(),
      // IAM-703: explicit AND/OR prerequisites. `prerequisites.anyOf` lists the
      // alternative TECHNIQUES that achieve this escalation (holding any ONE
      // suffices - they are NOT jointly required). Each technique's `allOf` lists
      // the grant groups it jointly needs; each group's `anyOf` lists the
      // interchangeable actions that satisfy that group. This replaces the old
      // flat requiredActions AND-list that wrongly implied unrelated alternative
      // techniques were all jointly required. Every action named here is granted
      // by the analyzed policy (grounded), never an absent catalog action.
      prerequisites: fields.prerequisites || null,
      targetPermissions: 'unknown',
    },
    evidence: fields.evidence.slice(),
    // IAM-701: explicit per-statement provenance for the header. Every action is
    // attributed ONLY to the statement that grants it, so a cross-statement
    // compound finding never implies the anchor Sid granted the whole set.
    contributingStatements: contributingStatementsFrom(fields.evidence),
    // IAM-105: compound escalation paths expose a present/absent risk-factor
    // checklist (the grants + scope conditions that constitute the path). null
    // for single-action primitives, which are not compound paths.
    riskFactors: Array.isArray(fields.riskFactors)
      ? fields.riskFactors.map((rf) => ({
          key: rf.key,
          label: rf.label,
          present: !!rf.present,
        }))
      : null,
  };
}

function downgrade(confidence) {
  if (confidence === 'high') return 'medium';
  if (confidence === 'medium') return 'low';
  return 'low';
}

// IAM-701: contributed actions are represented as an ARRAY, never a comma-joined
// string. Where a statement contributes several actions (e.g. an exec statement
// granting lambda:CreateFunction + lambda:UpdateFunctionCode) they ride as
// distinct array elements so every downstream consumer (graph-edge evidence,
// correlate, render, export) can reason per-action without re-splitting a
// display string. `actions` accepts a string or an array and is normalized to an
// array here.
function evidenceOf(stmt, role, actions, note) {
  const list = Array.isArray(actions) ? actions.slice() : [actions];
  return {
    statementIndex: stmt.index,
    statementSid: statementSid(stmt),
    role, // 'pass' | 'execute' | 'primitive'
    actions: list,
    resources: resourceScope(stmt),
    condition: stmt.condition,
    note: note || null,
  };
}

// IAM-701: per-statement provenance for a finding HEADER. A compound path is
// distributed across statements (PassRole in one, the service action in
// another); the scalar statementSid/statementIndex names only the anchor, so on
// its own it would attribute the whole combined action list to a single Sid.
// contributingStatements makes the mapping explicit and correct: one entry per
// contributing statement, each carrying ONLY the actions that statement grants
// (deduped, ordered by statement index). Derived from the same per-statement
// evidence[] records, so header and evidence[] can never drift.
function contributingStatementsFrom(evidence) {
  const byIndex = new Map();
  for (const ev of Array.isArray(evidence) ? evidence : []) {
    if (!ev || typeof ev.statementIndex !== 'number') continue;
    let entry = byIndex.get(ev.statementIndex);
    if (!entry) {
      entry = {
        statementIndex: ev.statementIndex,
        statementSid: ev.statementSid,
        actions: [],
      };
      byIndex.set(ev.statementIndex, entry);
    }
    for (const a of Array.isArray(ev.actions) ? ev.actions : []) {
      if (!entry.actions.includes(a)) entry.actions.push(a);
    }
  }
  return [...byIndex.keys()].sort((x, y) => x - y).map((i) => byIndex.get(i));
}

// --- Prerequisite (AND/OR) helpers (IAM-703) ---------------------------------
// A `group` is an OR of interchangeable actions that satisfy one requirement of
// a technique (e.g. "any lambda code-run action"). A `technique` ANDs its groups
// together (allOf) and is one alternative way to achieve the escalation; the
// finding's prerequisites OR the techniques together (anyOf). Every action here
// must be one the policy actually grants - callers pass grounded action lists.
function prereqGroup(anyOf, role) {
  return { role: role || null, anyOf: (Array.isArray(anyOf) ? anyOf : [anyOf]).slice() };
}

function prereqTechnique(id, allOf, opts) {
  return {
    technique: id,
    allOf: (Array.isArray(allOf) ? allOf : [allOf]).slice(),
    requiresPassRole: !!(opts && opts.requiresPassRole),
    note: (opts && opts.note) || null,
  };
}

function prerequisitesOf(techniques) {
  return { anyOf: (Array.isArray(techniques) ? techniques : [techniques]).slice() };
}

// Gather every concrete action in `catalog` that is granted by some Allow in
// `allows` and SURVIVES same-policy explicit-Deny precedence (deny-filtered).
// Deterministic order: statement order, then match order; deduped. Used to
// ground a standalone technique's prerequisites in the policy's real grants.
function survivingGrantedActions(allows, denies, catalog) {
  const found = [];
  for (const stmt of allows) {
    const m = grantedPatternsFor(stmt, catalog);
    if (m.length === 0) continue;
    const d = applyDenyToActions(denies, m, stmt);
    for (const a of d.actions) if (!found.includes(a)) found.push(a);
  }
  return found;
}

// Lambda: only role-SETTING actions (create a function with a role, or change an
// existing function's execution role) require iam:PassRole. Replacing an existing
// function's code (lambda:UpdateFunctionCode) runs under that function's EXISTING
// role and needs NO PassRole - it is a distinct standalone technique (acceptance
// suite test 3, Path B), NOT part of the compound PassRole path's requirement.
const LAMBDA_CODE_ONLY_ACTIONS = Object.freeze(['lambda:UpdateFunctionCode']);

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

    // IAM-105 risk-factor checklist: the present/absent grants + scope
    // conditions that make up THIS compound path. Deterministic order. A
    // subordinate wildcard/broad-resource rule finding on the pass or exec
    // statement is a risk FACTOR of this path (see correlate.js), so its
    // signal is captured here rather than as a duplicate top-level row.
    const riskFactors = [
      { key: 'pass-role', label: 'iam:PassRole granted', present: true },
    ];
    for (const execAction of effectiveExecActions) {
      riskFactors.push({
        key: execAction,
        label: `${svc.service} execution action granted (${execAction})`,
        present: true,
      });
    }
    riskFactors.push({
      key: 'pass-role-resource-wildcard',
      label: 'iam:PassRole resource is wildcard-scoped (reaches many roles)',
      present: resourceListIsBroadForAssume(passStmt),
    });
    riskFactors.push({
      key: 'exec-resource-wildcard',
      label: `${svc.service} action resource is "*" (unscoped)`,
      present: execStmt.resources.includes('*'),
    });
    riskFactors.push({
      key: 'passed-to-service-restriction',
      label: 'iam:PassedToService restriction present',
      present: pinned,
    });
    const evidence = [
      evidenceOf(
        passStmt,
        'pass',
        [PASS_ROLE_ACTION],
        pinned
          ? `an iam:PassedToService condition permits passing a role to ${svc.principal}`
          : 'PassRole is not pinned to a service (can pass to any service)',
      ),
      evidenceOf(execStmt, 'execute', effectiveExecActions, `runs code as the passed role via ${svc.service}`),
    ];

    // IAM-703: structured AND/OR prerequisites replace the old flat AND-list.
    // The PRIMARY technique ANDs the iam:PassRole grant with ANY ONE surviving
    // service-execution action - both are grounded in this policy's real grants.
    const techniques = [
      prereqTechnique('passrole-service-execution', [
        prereqGroup([PASS_ROLE_ACTION], 'pass'),
        prereqGroup(effectiveExecActions, 'execute'),
      ], { requiresPassRole: true }),
    ];
    // Lambda-only alternative technique (acceptance suite test 3, Path B):
    // lambda:UpdateFunctionCode replaces an EXISTING function's code, which runs
    // under that function's existing execution role, so it needs NO iam:PassRole.
    // It is a SEPARATE path, never folded into the compound AND-list. Surface it
    // when the policy grants it and it survives same-policy Deny.
    if (svc.service === 'lambda') {
      const codeOnly = survivingGrantedActions(allows, denies, LAMBDA_CODE_ONLY_ACTIONS);
      if (codeOnly.length > 0) {
        techniques.push(
          prereqTechnique('replace-existing-function-code', [
            prereqGroup(codeOnly, 'execute'),
          ], {
            requiresPassRole: false,
            note:
              'Replaces the code of an existing Lambda function, which runs ' +
              'under that function\'s existing execution role - this technique ' +
              'does not require iam:PassRole. The existing function\'s role and ' +
              'its invocation path are outside the supplied context.',
          }),
        );
      }
    }

    out.push(
      makeEscalation(svc.id, anchor, {
        // Critical (IAM-102): a compound PassRole + service-execution path lets
        // the principal reach execution under a DIFFERENT role's credentials -
        // a plausible privilege-boundary crossing, not a standalone capability.
        severity: 'critical',
        // Both iam:PassRole and the service-execution action are present in the
        // policy -> strong policy evidence. But whether launching under the
        // passed role actually elevates depends on that role's UNKNOWN
        // permissions (and instance-profile / service runtime behavior), so
        // exploitability is medium, not high. (IAM-104 canonical example.)
        policyEvidence: 'high',
        pathExploitability: 'medium',
        conditioned: execConditioned,
        denyNarrowed,
        passUncertain,
        technique: 'passrole-service-execution',
        service: svc.service,
        // Grounded (IAM-703): only iam:PassRole + the surviving service-execution
        // action(s) this policy actually grants - never the full service catalog.
        // Alternative techniques (e.g. Lambda Path B) live in prerequisites.
        requiredActions: combinedActions,
        prerequisites: prerequisitesOf(techniques),
        actions: combinedActions,
        resources: resourceScope(passStmt),
        evidence,
        riskFactors,
        why:
          `Grants iam:PassRole together with ${svc.service} action(s) ` +
          `(${effectiveExecActions.join(', ')}) that run code as the passed role. A ` +
          `principal can create/update a ${svc.service} workload with a role it ` +
          'is allowed to pass, potentially obtaining execution under the passed ' +
          'role\'s credentials (whether execution is actually obtained still ' +
          'depends on instance-profile / service behavior). ' +
          (pinned
            ? `The PassRole grant\'s iam:PassedToService condition selects ` +
              `${svc.principal} and thereby excludes other services (for example ` +
              `EC2), so this grant can feed ${svc.service} but not the services it ` +
              'excludes.'
            : 'The PassRole grant does not use iam:PassedToService to restrict ' +
              'which supported AWS services may receive the role (AWS still ' +
              'enforces which services a role can be passed to).'),
        remediation: pinned
          ? // Already pinned to this service - do NOT recommend adding the
            // iam:PassedToService restriction that is already present (IAM-703,
            // test 2: no "missing iam:PassedToService" remediation).
            `The PassRole grant already pins iam:PassedToService to ${svc.principal}, ` +
              `which correctly excludes other services. Further reduce risk by ` +
              'scoping iam:PassRole to the specific role ARNs that must be passed, ' +
              `separating role-passing from ${svc.service} workload-creation duties, ` +
              'and constraining the passable roles with a permission boundary.'
          : 'Scope iam:PassRole to the specific role ARNs that must be passed and ' +
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
        // Direct self-administration: the grant is present (evidence high) and
        // the principal can directly set a policy version it controls, so the
        // capability is exploitable without any unknown target role gating it.
        policyEvidence: 'high',
        pathExploitability: 'high',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'policy-version-manipulation',
        // Grounded (IAM-703): only the policy-version action(s) actually granted,
        // not the full catalog. These are interchangeable alternatives - holding
        // either one satisfies the technique - so prerequisites is a single
        // anyOf group, never an AND-list.
        requiredActions: actions.slice(),
        prerequisites: prerequisitesOf([
          prereqTechnique('policy-version-manipulation', [prereqGroup(actions, 'primitive')], {}),
        ]),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions)],
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
        // High, not critical (IAM-102): attaching a managed policy to self is a
        // standalone direct-IAM primitive, not a compound privilege-boundary
        // crossing. Critical is reserved for compound escalation paths.
        severity: 'high',
        // Direct self-administration: grant present (evidence high); attaching a
        // managed policy (e.g. AdministratorAccess) directly grants permissions,
        // no unknown target role gates it -> exploitability high.
        policyEvidence: 'high',
        pathExploitability: 'high',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'attach-policy',
        // Grounded (IAM-703): only the attach action(s) granted; interchangeable
        // alternatives -> a single anyOf group.
        requiredActions: actions.slice(),
        prerequisites: prerequisitesOf([
          prereqTechnique('attach-policy', [prereqGroup(actions, 'primitive')], {}),
        ]),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions)],
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
        // High, not critical (IAM-102): writing an inline policy on self is a
        // standalone direct-IAM primitive, not a compound privilege-boundary
        // crossing. Critical is reserved for compound escalation paths.
        severity: 'high',
        // Direct self-administration: grant present (evidence high); writing an
        // arbitrary inline Allow policy directly grants permissions with no
        // unknown target role in the way -> exploitability high.
        policyEvidence: 'high',
        pathExploitability: 'high',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'put-inline-policy',
        // Grounded (IAM-703): only the put-inline action(s) granted;
        // interchangeable alternatives -> a single anyOf group.
        requiredActions: actions.slice(),
        prerequisites: prerequisitesOf([
          prereqTechnique('put-inline-policy', [prereqGroup(actions, 'primitive')], {}),
        ]),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions)],
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
        // Grant present (evidence high). Rewriting a role's trust policy lets the
        // principal make itself assumable, but reaching elevated privilege then
        // depends on that role's UNKNOWN permissions -> exploitability medium.
        policyEvidence: 'high',
        pathExploitability: 'medium',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'trust-policy-modification',
        // Grounded (IAM-703): only the trust-modify action(s) granted.
        requiredActions: actions.slice(),
        prerequisites: prerequisitesOf([
          prereqTechnique('trust-policy-modification', [prereqGroup(actions, 'primitive')], {}),
        ]),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions)],
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
        // Grant present (evidence high). Minting an access key / login profile
        // yields working credentials, but ELEVATION requires that the target
        // principal be MORE privileged than the caller - a target whose power is
        // not in scope here (the ${aws:username} self-scoped case yields no
        // elevation at all). This is the same unknown that caps
        // TRUST-POLICY-MODIFY and ASSUME-ROLE-EXPANSION at medium, so the
        // credential-minting path is likewise -> exploitability medium.
        policyEvidence: 'high',
        pathExploitability: 'medium',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'credential-creation',
        // Grounded (IAM-703, acceptance suite test 5): only the credential-
        // creation action(s) this policy actually grants - NOT the full catalog.
        // A policy granting only iam:CreateAccessKey must not list
        // iam:CreateLoginProfile / iam:UpdateLoginProfile as prerequisites, since
        // those are absent. The granted primitives are interchangeable
        // alternatives -> a single anyOf group.
        requiredActions: actions.slice(),
        prerequisites: prerequisitesOf([
          prereqTechnique('credential-creation', [prereqGroup(actions, 'primitive')], {}),
        ]),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions)],
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
    const reach = assumeAccountReach(stmt);
    // Scope the cross-account claim to the evidence: only an account-wildcarded /
    // NotResource / unspecified / bare-"*" grant can reach arbitrary accounts. A
    // grant that pins a concrete account (e.g. arn:aws:iam::111122223333:role/*)
    // is broad WITHIN that account, so we must not assert cross-account reach.
    let why;
    if (reach.arbitrary) {
      why =
        'Grants sts:AssumeRole over a wildcard / broad role scope. A principal ' +
        'can assume roles across arbitrary AWS accounts whose trust policies ' +
        'permit this principal, and operate with their permissions - a role ARN ' +
        'such as arn:aws:iam::*:role/* spans every account, not just this one. ' +
        'Which roles are reachable (and how privileged they are) depends on ' +
        'those roles\' trust policies, which are not in scope here.';
    } else {
      const scope =
        reach.accounts.length === 1
          ? 'account ' + reach.accounts[0]
          : 'accounts ' + reach.accounts.join(', ');
      why =
        'Grants sts:AssumeRole over a wildcard / broad role scope within ' +
        scope + '. A principal can assume many roles within ' +
        (reach.accounts.length === 1 ? 'that account' : 'those accounts') +
        ' whose trust policies permit this principal, and operate with their ' +
        'permissions - the role path is wildcarded, so it reaches many roles, ' +
        'not one. Which roles are reachable (and how privileged they are) ' +
        'depends on those roles\' trust policies, which are not in scope here.';
    }
    out.push(
      makeEscalation('ASSUME-ROLE-EXPANSION', stmt, {
        // Critical (IAM-102) ONLY when the scope is effectively all roles (an
        // unconstrained role-name axis crosses into arbitrary target roles - a
        // privilege-boundary crossing); a partial role-name wildcard reaches
        // many-but-not-all roles and stays high. Severity (blast-radius scope)
        // is orthogonal to both certainty signals below.
        severity: assumeScopeIsAllRoles(stmt) ? 'critical' : 'high',
        // IAM-104 split: the sts:AssumeRole grant and its wildcard role scope are
        // plainly present in the policy text -> policy evidence HIGH. But which
        // roles are reachable and how privileged they are is unknown (their trust
        // policies are not in scope), so this is a POTENTIAL expansion, not a
        // confirmed elevation -> path exploitability MEDIUM. This is exactly the
        // "target roles' permissions are unknown" reasoning the old single
        // confidence folded in; the split now names it as exploitability.
        policyEvidence: 'high',
        pathExploitability: 'medium',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'assume-role-expansion',
        // Grounded (IAM-703): the sts:AssumeRole* action(s) actually granted -
        // never a hardcoded 'sts:AssumeRole' the policy may not contain (a policy
        // may grant only sts:AssumeRoleWithWebIdentity). Interchangeable
        // alternatives -> a single anyOf group.
        requiredActions: actions.slice(),
        prerequisites: prerequisitesOf([
          prereqTechnique('assume-role-expansion', [prereqGroup(actions, 'primitive')], {}),
        ]),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions, 'broad role scope')],
        why,
        remediation:
          'Scope sts:AssumeRole to the specific role ARNs the principal must ' +
          'assume; avoid wildcards in the role path, and ensure target roles\' ' +
          'trust policies only trust the intended principals.',
      }),
    );
  }
}

// IAM-902: is `r` a CONCRETE role ARN (names one specific role, no wildcard)?
// A takeover chain is only asserted when the three primitives target the exact
// same named role. A wildcard role scope (arn:aws:iam::*:role/*, role/*, a bare
// "*", or any partial wildcard) is a DIFFERENT, broader shape - it is the
// province of ASSUME-ROLE-EXPANSION / the wildcard rules, not this same-role
// correlation - so it is excluded here (never expand a wildcard into "the same
// role"). Determinism: pure string test, no regex compiled from input.
function isConcreteRoleArn(r) {
  const s = String(r == null ? '' : r);
  if (s.includes('*') || s.includes('?')) return false;
  return s.includes(':role/');
}

// IAM-902: correlate the modify-then-assume ROLE-TAKEOVER chain. A principal that,
// on the SAME concrete role, is granted (a) a permission-grant primitive
// (iam:PutRolePolicy / iam:AttachRolePolicy), (b) iam:UpdateAssumeRolePolicy, and
// (c) sts:AssumeRole can give the role permissions, rewrite its trust to trust
// itself, and then assume it - a critical privilege-boundary crossing that needs
// NO iam:PassRole. The three grants may live in one statement or (as in
// acceptance-suite-2 test 34) span several; per-statement evidence is preserved so
// no action is attributed to a statement that does not grant it. Same-policy
// explicit-Deny precedence applies to each leg (a fully-denied leg cannot
// contribute). A PARTIAL set (only 2 of 3) or the actions spread across DIFFERENT
// roles does NOT fire - that is the boundary the correlation must respect.
function detectRoleTakeover(allows, out, denies) {
  // Per concrete role ARN, the surviving contributing (stmt, actions) for each leg.
  const legs = {
    grant: new Map(), // role ARN -> [{ stmt, actions }]
    trust: new Map(),
    assume: new Map(),
  };
  const record = (legName, stmt, actions) => {
    for (const r of stmt.resources) {
      if (!isConcreteRoleArn(r)) continue;
      const m = legs[legName];
      if (!m.has(r)) m.set(r, []);
      m.get(r).push({ stmt, actions });
    }
  };
  for (const stmt of allows) {
    const g = grantedPatternsFor(stmt, ROLE_TAKEOVER_GRANT_ACTIONS);
    if (g.length > 0) {
      const d = applyDenyToActions(denies, g, stmt);
      if (!d.blocked) record('grant', stmt, d.actions);
    }
    const t = grantedPatternsFor(stmt, TRUST_MODIFY_ACTIONS);
    if (t.length > 0) {
      const d = applyDenyToActions(denies, t, stmt);
      if (!d.blocked) record('trust', stmt, d.actions);
    }
    const a = grantedPatternsFor(stmt, ROLE_TAKEOVER_ASSUME_ACTIONS);
    if (a.length > 0) {
      const d = applyDenyToActions(denies, a, stmt);
      if (!d.blocked) record('assume', stmt, d.actions);
    }
  }

  // A role qualifies only when ALL THREE legs name it. Deterministic order.
  const roles = [...legs.grant.keys()]
    .filter((r) => legs.trust.has(r) && legs.assume.has(r))
    .sort();

  for (const role of roles) {
    const grantLegs = legs.grant.get(role);
    const trustLegs = legs.trust.get(role);
    const assumeLegs = legs.assume.get(role);

    // Per-statement evidence: one record per contributing statement/leg, each
    // carrying ONLY the actions that statement grants toward this chain (IAM-701
    // provenance - never attribute all three actions to one statement).
    const evidence = [];
    for (const { stmt, actions } of grantLegs) {
      evidence.push(
        evidenceOf(stmt, 'grant-permissions', actions, `can attach/write a permission policy onto ${role}`),
      );
    }
    for (const { stmt, actions } of trustLegs) {
      evidence.push(
        evidenceOf(stmt, 'modify-trust', actions, `can rewrite the trust policy of ${role} to trust an attacker-controlled principal`),
      );
    }
    for (const { stmt, actions } of assumeLegs) {
      evidence.push(
        evidenceOf(stmt, 'assume', actions, `can assume ${role} once its trust policy permits it`),
      );
    }

    // Grounded action lists per leg (deduped, statement order preserved).
    const dedupe = (arr) => {
      const seen = [];
      for (const x of arr) if (!seen.includes(x)) seen.push(x);
      return seen;
    };
    const grantActions = dedupe(grantLegs.flatMap((l) => l.actions));
    const trustActions = dedupe(trustLegs.flatMap((l) => l.actions));
    const assumeActions = dedupe(assumeLegs.flatMap((l) => l.actions));
    const combinedActions = dedupe([...grantActions, ...trustActions, ...assumeActions]);

    // Anchor = lowest contributing statement index (deterministic header anchor).
    let anchor = null;
    for (const { stmt } of [...grantLegs, ...trustLegs, ...assumeLegs]) {
      if (anchor === null || stmt.index < anchor.index) anchor = stmt;
    }

    // Any contributing leg carrying a Condition gates the chain (lower confidence).
    const conditioned = [...grantLegs, ...trustLegs, ...assumeLegs].some(
      ({ stmt }) => hasNonEmptyCondition(stmt),
    );
    const denyNarrowed = [...grantLegs, ...trustLegs, ...assumeLegs].some(
      ({ stmt, actions }) => applyDenyToActions(denies, actions, stmt).narrowed,
    );

    // AND semantics (IAM-703): all three prerequisite groups are jointly required.
    const prerequisites = prerequisitesOf([
      prereqTechnique(
        'role-takeover-chain',
        [
          prereqGroup(grantActions, 'grant-permissions'),
          prereqGroup(trustActions, 'modify-trust'),
          prereqGroup(assumeActions, 'assume'),
        ],
        { requiresPassRole: false },
      ),
    ]);

    const riskFactors = [
      { key: 'grant-permissions', label: `Permission-grant primitive on ${role} (${grantActions.join(' / ')})`, present: true },
      { key: 'modify-trust', label: `Trust-policy rewrite on ${role} (${trustActions.join(' / ')})`, present: true },
      { key: 'assume', label: `Role assumption of ${role} (${assumeActions.join(' / ')})`, present: true },
      { key: 'same-role', label: 'All three primitives target the same role ARN', present: true },
    ];

    out.push(
      makeEscalation('ROLE-TAKEOVER', anchor, {
        // Critical (IAM-102/902): a compound chain that grants a role permissions,
        // re-trusts it, and assumes it plausibly crosses a privilege boundary - the
        // reserved-critical bar - and does so without iam:PassRole.
        severity: 'critical',
        // All three grants are literally present in the policy text -> policy
        // evidence HIGH. Whether the assumption actually elevates depends on what
        // the permission-grant leg then writes onto the role and any permission
        // boundary / SCP capping it (out of scope) -> exploitability MEDIUM.
        policyEvidence: 'high',
        pathExploitability: 'medium',
        conditioned,
        denyNarrowed,
        technique: 'role-takeover-chain',
        service: null,
        requiredActions: combinedActions,
        prerequisites,
        actions: combinedActions,
        resources: [role],
        evidence,
        riskFactors,
        why:
          `Grants a compound role-takeover chain on ${role}: a permission-grant ` +
          `primitive (${grantActions.join(' / ')}) to give the role permissions, ` +
          `iam:UpdateAssumeRolePolicy to rewrite its trust policy so the principal ` +
          `may assume it, and sts:AssumeRole to then assume it. Together these let ` +
          `the principal take the role over - grant it permissions, make it ` +
          `assumable, and assume it - WITHOUT needing iam:PassRole. The role's ` +
          `current permissions and any permission boundary on it are not in scope.`,
        remediation:
          'Separate role-permission management (iam:PutRolePolicy / ' +
          'iam:AttachRolePolicy), trust-policy management ' +
          '(iam:UpdateAssumeRolePolicy), and role assumption (sts:AssumeRole) ' +
          'across distinct administrative identities so no single principal can ' +
          'grant, re-trust, and assume the same role; scope each to specific role ' +
          'ARNs and protect high-value roles with a permission boundary and change ' +
          'review.',
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
  detectRoleTakeover,
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
