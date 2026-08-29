
// 12-digit AWS account id (bare). Shared by escalation.js + escalation-reachability.js.
export const CONCRETE_ACCOUNT_ID_RE = /^[0-9]{12}$/;
// escalation-catalogs.js - escalation trigger catalogs + metadata.
// Extracted verbatim from escalation.js (behavior-preserving refactor). Pure data + pure classifiers; no imports.

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
  // S2-crossaccount-scoped-surface (A): a sts:AssumeRole SCOPED to a specific role
  // that lives in a DIFFERENT account than the analyzed principal. This is NOT the
  // broad ASSUME-ROLE-EXPANSION wildcard shape (a single named role is the routine,
  // intended use of AssumeRole WITHIN an account), but crossing the account boundary
  // is a real, surfaceable capability - so it is emitted at LOW severity, only when
  // the subject account is KNOWN. Whether it yields elevated privilege depends on the
  // target role's trust policy + permissions, which are out of scope here.
  'CROSS-ACCOUNT-ASSUME-ROLE': Object.freeze({
    id: 'CROSS-ACCOUNT-ASSUME-ROLE',
    order: 10,
    title: 'Cross-account role assumption (scoped sts:AssumeRole into another account)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html',
  }),
  // Stage-13 EFO-3 / Stage-14: overwriting the code (or code-selecting configuration)
  // of an EXISTING compute resource runs attacker code under that resource's already-
  // bound execution/service role, so it needs NO iam:PassRole - a self-contained
  // code-exec / lateral-movement primitive (Rhino "UpdateExistingLambdaFunctionCode"
  // and its siblings). Covers lambda:UpdateFunctionCode / UpdateFunctionConfiguration,
  // codebuild:UpdateProject, glue:UpdateJob, cloudformation:UpdateStack - all "update
  // existing" exec actions the engine already models as requiresPassRole:false, but
  // which only got credit on the PassRole-paired path; a standalone grant used to read
  // CLEAN. Emitted at HIGH (elevation depends on the existing resource's role power,
  // out of scope here - the same unknown-target cap as CREDENTIAL-CREATION / TRUST-
  // POLICY-MODIFY). The PassRole-PAIRED case still fires PASSROLE-* (critical) and this
  // standalone finding is deduped away there.
  'COMPUTE-CODE-OVERWRITE': Object.freeze({
    id: 'COMPUTE-CODE-OVERWRITE',
    order: 11,
    title: 'Overwrite existing compute code/config (runs under its existing role, no PassRole)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html',
  }),
});

export const ESCALATION_IDS = Object.freeze(Object.keys(ESCALATIONS));


export {
  PASS_ROLE_SERVICES, PASS_ROLE_ACTION, classifyEcsRole, ECS_LAUNCH_ACTIONS, ecsRoleClasses,
  POLICY_VERSION_ACTIONS, ATTACH_POLICY_ACTIONS, PUT_INLINE_POLICY_ACTIONS, TRUST_MODIFY_ACTIONS,
  CREDENTIAL_ACTIONS, ASSUME_ROLE_ACTIONS, ROLE_TAKEOVER_GRANT_ACTIONS, ROLE_TAKEOVER_ASSUME_ACTIONS,
};
