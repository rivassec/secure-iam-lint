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
import { statementNeverMatches, parseOperator } from './conditions.js';

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

// IAM-1005: ECS distinguishes two roles a task can carry, and they must never be
// merged (suite-2 test 38, suite-3 tests 87/88/89):
//   - the TASK role is the application's own credentials (what the container's
//     code obtains via the task metadata endpoint) - the credential-exposure path;
//   - the EXECUTION role is what the ECS agent uses to pull images, write logs,
//     and inject secrets at startup - infrastructure influence, NOT application
//     credentials. Passing only the execution role must NOT be presented as the
//     application obtaining that role's credentials.
// Classification is inferred from the role NAME (medium confidence): a name that
// says "task" is a task role, one that says "exec"/"execution" is an execution
// role, anything else is unclassified (kept conservative).
function classifyEcsRole(resource) {
  const s = String(resource == null ? '' : resource).toLowerCase();
  const name = /:role\/(.+)$/.exec(s);
  const n = name ? name[1] : s;
  const hasExec = n.includes('exec'); // covers "exec" and "execution"
  const hasTask = n.includes('task');
  if (hasTask && !hasExec) return 'task';
  if (hasExec && !hasTask) return 'execution';
  return 'unknown';
}

// IAM-1005: only ecs:RunTask / ecs:StartTask actually LAUNCH a task (run code);
// ecs:RegisterTaskDefinition only STAGES a definition. PassRole + a launch action
// is a confirmed code-execution path (critical); PassRole + staging ALONE is a
// high staging capability (another actor/scheduler must still run it) - suite-3
// test 90.
const ECS_LAUNCH_ACTIONS = Object.freeze(['ecs:RunTask', 'ecs:StartTask']);

// Bucket a set of passed role ARNs by ECS role class (task / execution / unknown),
// preserving order within each bucket.
function ecsRoleClasses(resources) {
  const out = { task: [], execution: [], unknown: [] };
  for (const r of Array.isArray(resources) ? resources : []) {
    const cls = classifyEcsRole(r);
    out[cls].push(String(r));
  }
  return out;
}

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

// An AWS account id is exactly 12 decimal digits. The cross-account PassRole
// downgrade (T91) compares the subject account against the accounts pinned in
// the passed-role ARNs via raw string inequality, so it MUST only run for a
// well-formed concrete account id. A missing, wildcard ("*"), whitespace, or
// textual/garbage subject ("unknown", "N/A", "tbd", "acct-1", ...) means the
// subject account is AMBIGUOUS, not "a known account that differs": the path's
// cross-account viability is UNKNOWN, so the critical->medium demotion must NOT
// fire (firing it would silently suppress a possibly-viable critical path - the
// exact false negative threat-model T8 forbids). Normalize/validate here so the
// passedRoleAccounts comparison downstream is only reached for a real account id.
const CONCRETE_ACCOUNT_ID_RE = /^[0-9]{12}$/;

function detectPassRolePaths(allows, out, denies, ctx) {
  const rawSubjectAccount = ctx && ctx.subjectAccount != null ? String(ctx.subjectAccount) : null;
  const subjectAccount = rawSubjectAccount && CONCRETE_ACCOUNT_ID_RE.test(rawSubjectAccount)
    ? rawSubjectAccount
    : null;
  // The subject's partition (aws / aws-us-gov / aws-cn / ...). Defaults to 'aws'.
  const subjectPartition = ctx && typeof ctx.partition === 'string' && ctx.partition.trim()
    ? ctx.partition.trim()
    : 'aws';
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

    // suite-3 test 91: when the PassRole grant pins a specific account, warn that
    // the direct path is same-account-only and that its viability depends on the
    // (unsupplied) workload/principal account - never assert a foreign-account
    // path as fully viable. Honest and always-correct; it does not change
    // severity/confidence (that would require subject-account context this
    // single-policy analyzer does not have).
    const passedRoleAccounts = specificAccountsInRoleArns(passStmt.resources);
    const crossAccountNote = passedRoleAccounts.length > 0
      ? ' Note: iam:PassRole can pass a role only to a service in the SAME account as ' +
        `the role (here account ${passedRoleAccounts.join(', ')}), so this direct ` +
        'path is viable only if the workload/principal runs in that same account - ' +
        'which this single policy does not establish; if the principal is in a ' +
        'different account, the direct PassRole path does not apply.'
      : '';

    // Confidence: an explicit PassedToService that matches this service confirms
    // the path (high). An unpinned PassRole can feed any service (also high, the
    // primitive exists). A Condition on the execution statement (not the
    // confirming PassedToService) gates the path and lowers confidence.
    const execConditioned = hasNonEmptyCondition(execStmt);
    const anchor = passStmt.index <= execStmt.index ? passStmt : execStmt;
    const combinedActions = [PASS_ROLE_ACTION].concat(effectiveExecActions);

    // IAM-1005: per-path severity + framing overrides. Default is the compound
    // critical PassRole->service path; ECS staging-only, ECS execution-role-only,
    // and a hard cross-account account mismatch adjust it deterministically.
    let severity = 'critical';
    let pathExploitability = 'medium';
    let ecsMeta = null;
    let extraWhy = '';

    // --- ECS: task vs execution role, launch vs staging (tests 38/87/88/89/90) -
    if (svc.service === 'ecs') {
      const classes = ecsRoleClasses(passStmt.resources);
      const hasTaskRole = classes.task.length > 0;
      const hasExecRole = classes.execution.length > 0;
      const hasUnknownRole = classes.unknown.length > 0;
      // effectiveExecActions holds the granted PATTERNS (which may be "*" / "ecs:*",
      // not the concrete action), so test grant-membership, not string equality: a
      // wildcard that covers ecs:RunTask DOES have launch capability.
      const hasLaunch = ECS_LAUNCH_ACTIONS.some(
        (la) => effectiveExecActions.some((p) => actionGrants(p, la)),
      );
      ecsMeta = {
        taskRoles: classes.task.slice(),
        executionRoles: classes.execution.slice(),
        unknownRoles: classes.unknown.slice(),
        hasLaunch,
      };
      if (!hasLaunch) {
        // Only ecs:RegisterTaskDefinition (staging) - no RunTask/StartTask to
        // launch it. A definition can be STAGED but not run by this principal;
        // another actor or a scheduler would still have to launch it (test 90).
        severity = 'high';
        pathExploitability = 'low';
        extraWhy =
          ' This grant STAGES a task definition (ecs:RegisterTaskDefinition) but ' +
          'does NOT include a launch action (ecs:RunTask / ecs:StartTask), so this ' +
          'principal cannot itself run the definition and obtain the passed role; ' +
          'another actor or scheduler that later runs the definition could - which ' +
          'this policy does not establish. Reported as a task-definition staging ' +
          'capability, not a confirmed code-execution path.';
      } else if (hasTaskRole || hasUnknownRole) {
        // A passable TASK role (or an unclassified role that could be one) is the
        // application-credential path: code in the task obtains the task role's
        // credentials -> critical (tests 87/89).
        severity = 'critical';
        extraWhy =
          ' The application-credential path targets the ECS TASK role' +
          (hasTaskRole ? ` (${classes.task.join(', ')})` : '') +
          ': container code obtains the task role\'s credentials via the task ' +
          'metadata endpoint; the role\'s actual permissions are unknown here.' +
          (hasExecRole
            ? ` The passable EXECUTION role (${classes.execution.join(', ')}) is ` +
              'separate: ECS uses it for image pulls, log delivery, and secret ' +
              'injection at startup - infrastructure influence, NOT application ' +
              'credentials, and it is not presented as such.'
            : '');
      } else if (hasExecRole) {
        // ONLY an execution role is passable (test 88): the attacker can run a
        // task using that execution role - influencing image pulls, logging, and
        // secret injection - but the application code does NOT receive the
        // execution role's credentials, and no task-role edge is invented.
        severity = 'high';
        pathExploitability = 'low';
        extraWhy =
          ` Only an ECS EXECUTION role is passable (${classes.execution.join(', ')}), ` +
          'not a task role. Running a task with it lets the actor influence image ' +
          'pulls, log delivery, and secret injection at startup (execution-role ' +
          'influence), but the application code does NOT receive the execution ' +
          'role\'s credentials. No application task-role credential path is claimed, ' +
          'and no task-role edge is invented from absent context.';
      }
    }

    // --- PassRole target viability: account + partition + deny-residual (T91) -
    // iam:PassRole passes a role only to a service in the SAME account AND SAME
    // partition as the role; the service launch (ec2:RunInstances and peers) runs
    // in the CALLER's account+partition. The direct compound path is viable only
    // if a role in the subject's own account+partition can actually be passed.
    //
    //   subject KNOWN, no reachable same-account+partition role -> NOT viable:
    //     demote (critical->medium) + a warning code. A pure PARTITION difference
    //     (account matches, partition differs) -> PARTITION_MISMATCH; otherwise a
    //     cross-ACCOUNT incompatibility -> PASSROLE_CROSS_ACCOUNT_INCOMPATIBLE.
    //     A Deny that removes every subject-account role (residual foreign-only,
    //     T91-09) is the same kind of non-viability even when an Allow "*" nominally
    //     reaches the subject account.
    //   subject UNKNOWN, viability hinges on a concrete-account match (every passable
    //     resource pins a CONCRETE 12-digit account, none is "*"/account-wildcard)
    //     -> viability UNKNOWN: cap pathExploitability at low + record subjectAccount
    //     as a required-unknown. Severity is NOT lowered (the subject COULD be that
    //     account - suppressing a possibly-viable critical path is the false negative
    //     threat-model T8 forbids); we merely refuse to over-claim exploitability.
    //   otherwise (a "*" / account-wildcard reaches any account) -> viable, unchanged.
    const parsedPassResources = passStmt.resources.map(parsePassResource);
    const concreteSpecific = parsedPassResources.filter(
      (r) => !r.star && !r.other
        && !String(r.account).includes('*')
        && !String(r.partition).includes('*'),
    );
    let accountMismatch = false;
    let targetResources = [];
    let excludedTargets = [];
    const warningCodes = [];
    const requiredUnknowns = [];

    if (subjectAccount) {
      for (const r of concreteSpecific) {
        if (resourceReachesSubject(r, subjectAccount, subjectPartition)) targetResources.push(r.raw);
        else excludedTargets.push(r.raw);
      }
      const anyReaches = parsedPassResources.some(
        (r) => resourceReachesSubject(r, subjectAccount, subjectPartition),
      );
      const subjectDenied = denyRemovesAllSubjectRoles(denies, subjectAccount, subjectPartition);
      const viable = anyReaches && !subjectDenied;
      if (!viable && (concreteSpecific.length > 0 || subjectDenied)) {
        accountMismatch = true;
        severity = severity === 'critical' ? 'medium' : 'low';
        pathExploitability = 'low';
        // A pure partition mismatch: every pinned resource matches the subject
        // ACCOUNT but sits in a different partition (and no deny-residual involved).
        const partitionOnly = !subjectDenied
          && concreteSpecific.length > 0
          && concreteSpecific.every(
            (r) => r.account === subjectAccount && !partitionReaches(r.partition, subjectPartition),
          );
        if (partitionOnly) {
          warningCodes.push('PARTITION_MISMATCH');
          extraWhy +=
            ` Partition mismatch: the passed role(s) are in partition ` +
            `${[...new Set(concreteSpecific.map((r) => r.partition))].join(', ')} but the ` +
            `analyzed principal is in partition ${subjectPartition}. iam:PassRole cannot ` +
            'pass a role across partitions, so this is NOT a viable direct ' +
            `PassRole-to-${svc.service} path.`;
        } else {
          warningCodes.push('PASSROLE_CROSS_ACCOUNT_INCOMPATIBLE');
          extraWhy += subjectDenied
            ? ` Deny residual: an explicit Deny removes every iam:PassRole target in the ` +
              `analyzed principal's account (${subjectAccount}), leaving only foreign-account ` +
              'roles in the allowed scope. A foreign-account role cannot be passed to a ' +
              `same-account ${svc.service}, so this is NOT a viable direct PassRole-to-` +
              `${svc.service} path across accounts.`
            : ` Account mismatch: the passed role(s) are in account ` +
              `${excludedTargets.length ? [...new Set(concreteSpecific.map((r) => r.account))].join(', ') : passedRoleAccounts.join(', ')} ` +
              `but the analyzed principal is in account ${subjectAccount}. iam:PassRole can ` +
              'pass a role only to a service in the SAME account as the role, so this is NOT ' +
              `a viable direct PassRole-to-${svc.service} path across accounts.`;
        }
      }
    } else {
      // Subject account unknown. Only cap exploitability when viability genuinely
      // depends on an account we cannot confirm: every passable resource pins a
      // CONCRETE 12-digit account (no "*"/account-wildcard that would reach any
      // account regardless). A placeholder/short account id (e.g. "1") is NOT
      // treated as a concrete account (preserves prior medium exploitability).
      const allPinConcreteAccount = parsedPassResources.length > 0
        && parsedPassResources.every(
          (r) => !r.star && !r.other && CONCRETE_ACCOUNT_ID_RE.test(String(r.account)),
        );
      if (allPinConcreteAccount) {
        pathExploitability = 'low'; // cap (never raises: 'low' is the floor)
        requiredUnknowns.push('subjectAccount');
        extraWhy +=
          ` The passed role(s) pin a specific account, but the analyzed principal's ` +
          'account is not supplied, so whether this is a same-account (viable) or ' +
          'cross-account (not viable) pass is UNKNOWN. Path exploitability is capped ' +
          'at low pending the subject account; supply it to resolve viability.';
      }
    }

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

    const escalationFinding = makeEscalation(svc.id, anchor, {
        // Severity (IAM-102 / IAM-1005): the compound PassRole + service-execution
        // path is normally critical (execution under a DIFFERENT role's
        // credentials, a plausible privilege-boundary crossing). ECS staging-only,
        // ECS execution-role-only, and a hard cross-account mismatch lower it.
        severity,
        // Both iam:PassRole and the service-execution action are present in the
        // policy -> strong policy evidence. But whether launching under the
        // passed role actually elevates depends on that role's UNKNOWN
        // permissions (and instance-profile / service runtime behavior), so
        // exploitability is medium by default (lower for staging/exec-only/
        // account-mismatch). (IAM-104 canonical example.)
        policyEvidence: 'high',
        pathExploitability,
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
              'enforces which services a role can be passed to).') +
          crossAccountNote + extraWhy,
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
      });
    // IAM-1005: carry ECS task/execution-role classification and the
    // cross-account mismatch flag on the escalation enrichment so the graph can
    // draw distinct task/execution role nodes and exports can record the mismatch.
    // Mutated before analyzeEscalations() deep-freezes the finding.
    if (ecsMeta) escalationFinding.escalation.ecs = ecsMeta;
    if (accountMismatch) {
      escalationFinding.escalation.accountMismatch = {
        subjectAccount,
        passedRoleAccounts: passedRoleAccounts.slice(),
        viable: false,
      };
    }
    // IAM-1102 (11B): partition/account/deny-residual viability metadata. Only
    // attached when non-empty so unaffected findings are byte-identical.
    if (warningCodes.length) escalationFinding.escalation.warningCodes = warningCodes.slice();
    if (requiredUnknowns.length) escalationFinding.escalation.requiredUnknowns = requiredUnknowns.slice();
    if (targetResources.length) escalationFinding.escalation.targetResources = targetResources.slice();
    if (excludedTargets.length) escalationFinding.escalation.excludedTargets = excludedTargets.slice();
    out.push(escalationFinding);
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

// suite-3 test 74: does a modify-leg resource COVER the concrete assumable role
// `role`? True for an exact match, or for a role-ARN wildcard pattern
// (arn:...:role/deployment/*) that subsumes the concrete role
// (arn:...:role/deployment/Prod). Only role-ARN patterns subsume roles - a bare
// "*" or a non-role ARN pattern is NOT treated as a same-role modify grant here
// (it stays the broader wildcard/expansion shape), so the takeover is never
// generalized to roles the modify leg does not actually name. ARN matching is
// case-sensitive (IAM resource ARNs are), so globMatch is used directly.
function resourceCoversRole(resource, role) {
  const s = String(resource == null ? '' : resource);
  if (s === role) return true;
  if (!s.includes(':role/')) return false;
  if (!s.includes('*') && !s.includes('?')) return false;
  return globMatch(s, role);
}

// role-takeover test 142: a MAXIMALLY-BROAD assume scope ("all roles across
// arbitrary accounts") is the ASSUME-ROLE-EXPANSION shape, NOT a same-role
// takeover confirmation - even though it glob-covers any concrete role. Both axes
// must be fully open: the account field is arbitrary (wildcarded/empty) AND the
// role-name segment is exactly "*" (or the bare "*" / "role/*" shorthands). A
// scope pinned to a concrete account (arn:aws:iam::123456789012:role/deployment/*)
// or a specific role-name path is BOUNDED and DOES confirm an anchor a
// permission-grant/trust-modify leg names concretely (the C2 wildcard-assume
// mirror of test 74). Mirrors assumeScopeIsAllRoles(), evaluated per-resource so a
// concrete member in the same statement still confirms.
function isAllRolesAssumeScope(resource) {
  const s = String(resource == null ? '' : resource);
  if (s === '*') return true;
  if (s === 'role/*') return true; // bare shorthand
  const marker = ':role/';
  const idx = s.lastIndexOf(marker);
  if (idx === -1) return false;
  if (s.slice(idx + marker.length) !== '*') return false; // role-name not fully open
  const parts = s.split(':');
  if (parts.length < 6) return false;
  const account = parts[4];
  return account === '' || account.includes('*') || account.includes('?'); // arbitrary account
}

// suite-3 test 91: the specific (non-wildcard) AWS account IDs a set of role
// ARNs pins in the account field of arn:aws:iam::<account>:role/... . Used to
// caveat a PassRole path: iam:PassRole passes a role only to a service in the
// SAME account as the role, so a path through an account-pinned role is viable
// only when the workload/principal runs in that same account - which a single
// identity policy does not establish. A wildcarded account segment yields no
// specific account and no caveat.
function specificAccountsInRoleArns(resources) {
  const accts = [];
  for (const r of Array.isArray(resources) ? resources : []) {
    const s = String(r == null ? '' : r);
    const m = /^arn:aws:iam::([0-9]{1,20}):role\//.exec(s);
    if (m && !accts.includes(m[1])) accts.push(m[1]);
  }
  return accts.sort();
}


// --- Partition-aware PassRole target parsing (IAM-1102 / T91) -----------------
// iam:PassRole passes a role only to a service in the SAME account AND the SAME
// partition as the role; the service launch runs in the CALLER's account +
// partition. Reasoning about cross-account/cross-partition viability therefore
// needs the role ARN's partition and account, not just the account. Any partition
// (aws / aws-us-gov / aws-cn / ...) is captured, unlike the aws-only helpers above.
const ROLE_ARN_PARTS_RE = /^arn:([^:]*):iam::([^:]*):role\/(.*)$/i;

// Classify one PassRole RESOURCE token. Returns exactly one shape:
//   { star:true }                    -> "*" (reaches any account/partition)
//   { other:true }                   -> not a role ARN we can pin (conservative)
//   { partition, account, path, raw} -> a role ARN (account/partition may be "*")
function parsePassResource(r) {
  const s = String(r == null ? '' : r);
  if (s === '*') return { star: true, raw: s };
  const m = ROLE_ARN_PARTS_RE.exec(s);
  if (!m) return { other: true, raw: s };
  return { partition: m[1], account: m[2], path: m[3], raw: s };
}

function partitionReaches(resPartition, subjectPartition) {
  return resPartition === subjectPartition || String(resPartition).includes('*');
}
function accountReaches(resAccount, subjectAccount) {
  return String(resAccount).includes('*') || resAccount === subjectAccount;
}

// Could this passable-role RESOURCE reach a role in the subject's OWN account +
// partition (i.e. could iam:PassRole hand a same-account role to a same-account
// service)? A bare "*" reaches anything; a role ARN reaches the subject only when
// BOTH its partition and account admit the subject's. A non-role-ARN we cannot pin
// is treated as NOT a same-account reach (conservative - it never manufactures
// viability). Requires a known subjectAccount.
function resourceReachesSubject(res, subjectAccount, subjectPartition) {
  if (res.star) return true;
  if (res.other) return false;
  return partitionReaches(res.partition, subjectPartition)
    && accountReaches(res.account, subjectAccount);
}

// T91-09 deny-residual: does an in-scope, UNCONDITIONAL Deny on iam:PassRole
// remove EVERY role in the subject's account+partition from the passable set? If
// so, even an Allow "*" cannot pass a same-account role, so the direct same-account
// path is not viable. A conditional deny is NOT treated as a guaranteed removal
// (it may not always apply) - being conservative here avoids a false negative.
function denyRemovesAllSubjectRoles(denies, subjectAccount, subjectPartition) {
  if (!subjectAccount) return false;
  const base = `arn:${subjectPartition}:iam::${subjectAccount}:role/`;
  const probeA = `${base}__probe_alpha__`;
  const probeB = `${base}__probe_beta_9x__`;
  for (const d of Array.isArray(denies) ? denies : []) {
    const deniesPassRole = (d.actions || []).some((a) => actionGrants(a, PASS_ROLE_ACTION));
    if (!deniesPassRole) continue;
    if (hasNonEmptyCondition(d)) continue; // conditional deny may not always apply
    for (const r of (d.resources || [])) {
      const pat = String(r);
      // A pattern covers ALL subject-account roles iff it matches two DISTINCT
      // role paths in that account+partition (so a single specific role ARN, which
      // matches only its own path, does not qualify).
      if (globMatch(pat, probeA) && globMatch(pat, probeB)) return true;
    }
  }
  return false;
}

// A single principal has ONE value for each principal-scoped request key for the
// life of its credentials, so these keys are INVARIANT across the legs of a
// takeover chain the same principal would execute (suite-3 test 75).
const PRINCIPAL_INVARIANT_KEYS = new Set([
  'aws:principalaccount',
  'aws:principalorgid',
  'aws:principalorgpaths',
  'aws:principalarn',
  'aws:userid',
]);

// Exact-equality operators that pin a principal-invariant key to a HARD literal
// value (base form, after parseOperator). These are the operators for which a
// single principal must carry exactly one of the listed values, so two legs that
// pin the SAME key to disjoint values can never be satisfied by one principal.
// This MUST mirror the exact-equality members of conditions.js
// POSITIVE_STRING_MATCH_OPERATORS - crucially aws:PrincipalArn's idiomatic exact
// operator is ArnEquals, NOT StringEquals (suite-3 test 75 ArnEquals twin /
// release-gate #3). Like-family operators (StringLike / ArnLike) admit wildcards
// and so do NOT pin a single literal - they are intentionally excluded, matching
// the documented decision that wildcard-match operators create no hard
// contradiction. StringEqualsIgnoreCase is exact but case-insensitive (tracked
// per-pin so a case-only variance is not mistaken for a contradiction).
const EXACT_EQUALITY_PIN_OPERATORS = new Set([
  'stringequals',
  'stringequalsignorecase',
  'arnequals',
]);
// The exact-equality NEGATIONS of the operators above. StringNotEquals /
// ArnNotEquals (and the IgnoreCase form) pin the principal-invariant key to
// "anything EXCEPT the listed literal(s)". A single principal that must be == X
// on one leg and != X on another leg cannot exist, so a negated pin is just as
// load-bearing as a positive pin for the cross-leg satisfiability check (suite-3
// test 75 negation twin / release-gate #3): ignoring it manufactures a false
// critical takeover no single principal can execute. Like-family negations
// (StringNotLike / ArnNotLike) admit wildcards and pin no single literal, so -
// mirroring the positive-side exclusion of StringLike / ArnLike - they are
// intentionally excluded and create no hard contradiction.
const NEGATED_EQUALITY_PIN_OPERATORS = new Set([
  'stringnotequals',
  'stringnotequalsignorecase',
  'arnnotequals',
]);
const CASE_INSENSITIVE_PIN_OPERATORS = new Set([
  'stringequalsignorecase',
  'stringnotequalsignorecase',
]);

// Extract the exact-equality pins a statement's Condition places on any
// principal-invariant key: keyLower -> array of { values:Set, ci:boolean,
// negated:boolean }, one entry per constraining operator block (AND-ed within the
// statement). Only an exact-equality operator (positive == or its exact-negation
// !=) with NO set-operator prefix and NO ...IfExists suffix pins a hard
// constraint every principal must satisfy: an IfExists pin is skipped when the
// key is absent, and a ForAllValues/ForAnyValue set qualifier changes the match
// semantics, so neither creates a dependable cross-leg contradiction and both are
// intentionally ignored. Like-family operators (StringLike / ArnLike and their
// Not- forms) admit wildcards and pin no single literal, so they are ignored.
// Condition keys are case-insensitive, so keys are lowercased.
function principalPinsOf(stmt) {
  const pins = new Map();
  const cond = stmt && stmt.condition;
  if (!cond || typeof cond !== 'object') return pins;
  for (const op of Object.keys(cond)) {
    const { base, setOperator, ifExists } = parseOperator(op);
    if (setOperator !== null || ifExists) continue;
    const positive = EXACT_EQUALITY_PIN_OPERATORS.has(base);
    const negated = NEGATED_EQUALITY_PIN_OPERATORS.has(base);
    if (!positive && !negated) continue;
    const ci = CASE_INSENSITIVE_PIN_OPERATORS.has(base);
    const block = cond[op];
    if (!block || typeof block !== 'object') continue;
    for (const key of Object.keys(block)) {
      if (!PRINCIPAL_INVARIANT_KEYS.has(key.toLowerCase())) continue;
      const raw = block[key];
      const vals = Array.isArray(raw) ? raw.map((v) => String(v)) : [String(raw)];
      const list = pins.get(key.toLowerCase()) || [];
      list.push({ values: new Set(vals), ci, negated });
      pins.set(key.toLowerCase(), list);
    }
  }
  return pins;
}

// Does the constraint's value set contain `cand` (case-sensitively, or
// case-insensitively for the IgnoreCase operators)?
function constraintContains(c, cand, candLc) {
  if (c.ci) {
    for (const v of c.values) if (v.toLowerCase() === candLc) return true;
    return false;
  }
  return c.values.has(cand);
}

// Can a single principal value satisfy EVERY constraint on one key at once?
// A POSITIVE constraint (==) requires the principal's single value to be one of a
// finite set; a NEGATED constraint (!=) requires it to be NONE of a finite set.
//
// A satisfying value must be a member of every positive set, so it can only be
// one of the literals a positive constraint lists - that finite pool is the only
// place a satisfying candidate can live. Each candidate is then checked against
// ALL constraints (positive: must be in; negated: must be out).
//
// When there is NO positive constraint the domain is effectively unbounded (any
// account id / ARN / userid), and a finite list of "!=" exclusions can always be
// avoided by some other value, so an all-negated key is satisfiable. This keeps
// the satisfiable control (both legs pin the SAME key with !=A) FIRING - only a
// genuine == X / != X (or two disjoint ==) contradiction reads as unsatisfiable.
// Kept conservative so a case-only variance is NOT mistaken for a contradiction.
function keyConstraintsSatisfiable(constraints) {
  const positives = constraints.filter((c) => !c.negated);
  if (positives.length === 0) return true;
  const candidates = new Set();
  for (const c of positives) for (const v of c.values) candidates.add(v);
  for (const cand of candidates) {
    const candLc = cand.toLowerCase();
    let ok = true;
    for (const c of constraints) {
      const inSet = constraintContains(c, cand, candLc);
      // positive => must be in the set; negated => must be out of the set.
      if (c.negated ? inSet : !inSet) { ok = false; break; }
    }
    if (ok) return true;
  }
  return false;
}

// Given a chosen SET of statements the one principal must satisfy jointly (an
// AND across these statements), can a single principal meet every
// principal-invariant pin at once? For each invariant key constrained by two or
// more of the chosen statements, the principal's single value must satisfy every
// one of those constraints simultaneously. An unsatisfiable key means no
// principal can satisfy this exact combination.
function pinsJointlySatisfiable(stmts) {
  const perKey = new Map(); // keyLower -> array of { values:Set, ci:boolean }
  for (const stmt of stmts) {
    for (const [k, list] of principalPinsOf(stmt)) {
      if (!perKey.has(k)) perKey.set(k, []);
      for (const c of list) perKey.get(k).push(c);
    }
  }
  for (const constraints of perKey.values()) {
    if (constraints.length < 2) continue; // only one stmt constrains it -> no contradiction
    if (!keyConstraintsSatisfiable(constraints)) return false;
  }
  return true;
}

// suite-3 test 75 (+ iteration-2 alternative-statement fix): can ONE principal
// execute the whole modify-then-assume chain? The chain needs the principal to
// satisfy SOME grant statement AND SOME trust statement AND SOME assume
// statement - only ONE statement per leg-group is required to obtain that
// capability. Statements WITHIN a group are therefore ALTERNATIVES (an OR), not
// a conjunction: a principal in account A that satisfies grant-A, trust-A and
// one of several assume statements (assume-A) executes a real takeover even
// though a *different* assume statement pins account B. Satisfiability is thus
// EXISTENTIAL across the choice of one statement per group: viable iff there
// exists (grant, trust, assume) whose principal-invariant pins share a
// non-empty intersection. It is unsatisfiable (test 75) only when NO such
// combination exists - e.g. the single modify leg pins account 123456789012 and
// the single assume leg pins 999900001111, so every triple contradicts.
// Alternatives are never AND-ed together, which would fabricate a contradiction
// out of statements the principal never needs to satisfy at the same time.
function principalConditionsSatisfiable(grantLegs, trustLegs, assumeLegs) {
  for (const g of grantLegs) {
    for (const t of trustLegs) {
      for (const a of assumeLegs) {
        if (pinsJointlySatisfiable([g.stmt, t.stmt, a.stmt])) return true;
      }
    }
  }
  return false;
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
  // Surviving contributing (stmt, actions, resources) for each leg. Resources are
  // retained per statement so a WILDCARD modify grant can be matched against a
  // concrete assumable role (suite-3 test 74) rather than requiring an exact
  // per-role bucketing up front.
  const grantLegsAll = [];
  const trustLegsAll = [];
  const assumeLegsAll = [];
  const collect = (arr, stmt, actions) => arr.push({ stmt, actions, resources: stmt.resources });
  for (const stmt of allows) {
    const g = grantedPatternsFor(stmt, ROLE_TAKEOVER_GRANT_ACTIONS);
    if (g.length > 0) {
      const d = applyDenyToActions(denies, g, stmt);
      if (!d.blocked) collect(grantLegsAll, stmt, d.actions);
    }
    const t = grantedPatternsFor(stmt, TRUST_MODIFY_ACTIONS);
    if (t.length > 0) {
      const d = applyDenyToActions(denies, t, stmt);
      if (!d.blocked) collect(trustLegsAll, stmt, d.actions);
    }
    const a = grantedPatternsFor(stmt, ROLE_TAKEOVER_ASSUME_ACTIONS);
    if (a.length > 0) {
      const d = applyDenyToActions(denies, a, stmt);
      if (!d.blocked) collect(assumeLegsAll, stmt, d.actions);
    }
  }

  // A takeover is only ever asserted against a CONCRETE role the principal can
  // assume. A concrete anchor role may be named by ANY contributing leg - the
  // permission-grant, the trust-modify, OR the assume leg - because the compound
  // is symmetric: whichever leg happens to be concrete pins the role, and the
  // other legs may be wildcards that provably subsume it. Test 74 is the forward
  // case (wildcard modify + concrete assume); its mirror (concrete modify/trust +
  // a bounded wildcard assume such as role/deployment/*) reaches the SAME concrete
  // role and must yield the SAME one takeover. Harvesting anchors only from assume
  // legs missed that mirror (a false negative on a critical compound path). A
  // WILDCARD assume scope still names no concrete role itself; the anchor comes
  // from the concrete modify/trust leg and is CONFIRMED below only if an assume leg
  // covers it. Deterministic order.
  const anchorRoles = [];
  for (const leg of [...grantLegsAll, ...trustLegsAll, ...assumeLegsAll]) {
    for (const r of leg.resources) {
      if (isConcreteRoleArn(r) && !anchorRoles.includes(r)) anchorRoles.push(r);
    }
  }
  anchorRoles.sort();

  for (const role of anchorRoles) {
    // A leg contributes to THIS role when one of its resources covers the
    // concrete role (exact, or a role-ARN wildcard that subsumes it).
    const grantLegs = grantLegsAll.filter((l) => l.resources.some((r) => resourceCoversRole(r, role)));
    const trustLegs = trustLegsAll.filter((l) => l.resources.some((r) => resourceCoversRole(r, role)));
    // The assume leg CONFIRMS the anchor: the principal must actually be able to
    // assume this concrete role. A bounded wildcard (account-pinned or path-scoped)
    // that covers the role confirms it; a MAXIMALLY-BROAD "*"/"*:role/*" assume
    // scope does NOT - it stays the ASSUME-ROLE-EXPANSION shape (test 142), never a
    // same-role takeover, even though it glob-covers the role.
    const assumeLegs = assumeLegsAll.filter((l) => l.resources.some(
      (r) => resourceCoversRole(r, role) && !isAllRolesAssumeScope(r),
    ));
    // All three legs must reach the same concrete role, or there is no chain.
    if (grantLegs.length === 0 || trustLegs.length === 0 || assumeLegs.length === 0) continue;

    // suite-3 test 75: reject the correlation when the legs carry mutually
    // exclusive same-key conditions on a principal-invariant key - no single
    // principal could execute the whole chain. The standalone modify capability
    // findings (PUT-INLINE-POLICY / TRUST-POLICY-MODIFY) remain, un-subsumed.
    if (!principalConditionsSatisfiable(grantLegs, trustLegs, assumeLegs)) continue;

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
export function analyzeEscalations(model, options) {
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
    // suite-3 test 97: a structurally never-match statement (empty ForAnyValue
    // set) grants nothing, so it never contributes to an escalation path.
    const allows = model.statements.filter(
      (s) => s.effect === 'Allow' && isIdentityStmt(s) && !statementNeverMatches(s),
    );
    const denies = model.statements.filter((s) => s.effect === 'Deny' && isIdentityStmt(s));

    const findings = [];
    // IAM-1005 / IAM-1102 (11B): an optional analysis context (subjectAccount +
    // partition) flows to the detectors; only detectPassRolePaths reads it
    // (cross-account / cross-partition PassRole viability). partition defaults to
    // 'aws' when unspecified.
    const ctx = {
      subjectAccount: (options && options.subjectAccount) || null,
      partition: (options && typeof options.partition === 'string' && options.partition.trim())
        ? options.partition.trim() : 'aws',
    };
    for (const detect of DETECTORS) detect(allows, findings, denies, ctx);

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
