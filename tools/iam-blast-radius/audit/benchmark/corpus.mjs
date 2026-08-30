// Ground-truth privilege-escalation benchmark corpus.
//
// The 21 methods in Rhino Security Labs' ORIGINAL catalog: Spencer Gietzen,
// "AWS IAM Privilege Escalation - Methods and Mitigation" (Part 1, 2018), the set
// wired into Pacu's iam__privesc_scan. Rhino's repo
// (github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation) has since grown to
// 28 numbered methods (Part 2 adds SageMaker / CodeStar and others); several of
// those are covered in SECOND_TIER below, and the full 28 are a tracked follow-up.
// Each entry is a MINIMAL policy that grants exactly one method, at its HARDEST
// resource-scoped form (concrete ARNs, no bare "*" resource) so a catch cannot
// ride on a generic WILDCARD-RESOURCE finding.
//
// The invariant every entry asserts: the engine must NOT read CLEAN on a real,
// modeled privesc primitive (threat-model T8). `finding` additionally names the
// specific detector that must fire, so a catch is a NAMED escalation, not just
// the incomplete-coverage backstop.
//
// This corpus is data, consumed by benchmark.test.js. Keep it ASCII-only.

const ACCT = '123456789012';
const iam = (s) => `arn:aws:iam::${ACCT}:${s}`;
const svc = (s) => `arn:aws:${s}`;
const A = (Action, Resource) => ({ Effect: 'Allow', Action, Resource });

export const SUBJECT_ACCOUNT = ACCT;

// method: short name from the Rhino catalog.
// finding: the specific detector id that MUST appear (a named escalation, not the backstop).
export const CORPUS = [
  { id: 'CreateAccessKey', method: 'iam:CreateAccessKey on another user',
    statements: [A('iam:CreateAccessKey', iam('user/victim'))], finding: 'CREDENTIAL-CREATION' },
  { id: 'CreateLoginProfile', method: 'iam:CreateLoginProfile on another user',
    statements: [A('iam:CreateLoginProfile', iam('user/victim'))], finding: 'CREDENTIAL-CREATION' },
  { id: 'UpdateLoginProfile', method: 'iam:UpdateLoginProfile on another user',
    statements: [A('iam:UpdateLoginProfile', iam('user/victim'))], finding: 'CREDENTIAL-CREATION' },
  { id: 'AttachUserPolicy', method: 'iam:AttachUserPolicy (attach admin to self/user)',
    statements: [A('iam:AttachUserPolicy', iam('user/victim'))], finding: 'ATTACH-POLICY' },
  { id: 'AttachGroupPolicy', method: 'iam:AttachGroupPolicy (attach admin to a group)',
    statements: [A('iam:AttachGroupPolicy', iam('group/devs'))], finding: 'ATTACH-POLICY' },
  { id: 'AttachRolePolicy', method: 'iam:AttachRolePolicy (attach admin to a role)',
    statements: [A('iam:AttachRolePolicy', iam('role/target'))], finding: 'ATTACH-POLICY' },
  { id: 'PutUserPolicy', method: 'iam:PutUserPolicy (inline admin on a user)',
    statements: [A('iam:PutUserPolicy', iam('user/victim'))], finding: 'PUT-INLINE-POLICY' },
  { id: 'PutGroupPolicy', method: 'iam:PutGroupPolicy (inline admin on a group)',
    statements: [A('iam:PutGroupPolicy', iam('group/devs'))], finding: 'PUT-INLINE-POLICY' },
  { id: 'PutRolePolicy', method: 'iam:PutRolePolicy (inline admin on a role)',
    statements: [A('iam:PutRolePolicy', iam('role/target'))], finding: 'PUT-INLINE-POLICY' },
  { id: 'AddUserToGroup', method: 'iam:AddUserToGroup (join a privileged group)',
    statements: [A('iam:AddUserToGroup', iam('group/admins'))], finding: 'GROUP-MEMBERSHIP' },
  { id: 'UpdateAssumeRolePolicy', method: 'iam:UpdateAssumeRolePolicy + sts:AssumeRole (hijack a role trust)',
    statements: [A('iam:UpdateAssumeRolePolicy', iam('role/target')), A('sts:AssumeRole', iam('role/target'))],
    finding: 'TRUST-POLICY-MODIFY' },
  { id: 'CreatePolicyVersion', method: 'iam:CreatePolicyVersion (new default policy version)',
    statements: [A('iam:CreatePolicyVersion', iam('policy/app-policy'))], finding: 'POLICY-VERSION' },
  { id: 'SetDefaultPolicyVersion', method: 'iam:SetDefaultPolicyVersion (roll back to a permissive version)',
    statements: [A('iam:SetDefaultPolicyVersion', iam('policy/app-policy'))], finding: 'POLICY-VERSION' },
  { id: 'PassRole_RunInstances', method: 'iam:PassRole + ec2:RunInstances (EC2 as a privileged role)',
    statements: [A('iam:PassRole', iam('role/ec2-admin')), A('ec2:RunInstances', svc(`ec2:us-east-1:${ACCT}:instance/*`))],
    finding: 'PASSROLE-EC2' },
  { id: 'PassRole_Lambda_Invoke', method: 'iam:PassRole + lambda:CreateFunction + InvokeFunction',
    statements: [A('iam:PassRole', iam('role/lambda-ex')), A('lambda:CreateFunction', svc(`lambda:us-east-1:${ACCT}:function:app`)), A('lambda:InvokeFunction', svc(`lambda:us-east-1:${ACCT}:function:app`))],
    finding: 'PASSROLE-LAMBDA' },
  { id: 'PassRole_Lambda_EventSource', method: 'iam:PassRole + lambda:CreateFunction + CreateEventSourceMapping',
    statements: [A('iam:PassRole', iam('role/lambda-ex')), A('lambda:CreateFunction', svc(`lambda:us-east-1:${ACCT}:function:app`)), A('lambda:CreateEventSourceMapping', '*'), A('dynamodb:PutItem', svc(`dynamodb:us-east-1:${ACCT}:table/t`))],
    finding: 'PASSROLE-LAMBDA' },
  { id: 'PassRole_Glue_CreateDevEndpoint', method: 'iam:PassRole + glue:CreateDevEndpoint',
    statements: [A('iam:PassRole', iam('role/glue-ex')), A('glue:CreateDevEndpoint', svc(`glue:us-east-1:${ACCT}:devEndpoint/e`))],
    finding: 'PASSROLE-SERVICE' },
  { id: 'Glue_UpdateDevEndpoint', method: 'glue:UpdateDevEndpoint (SSH-key injection into an existing dev endpoint)',
    statements: [A('glue:UpdateDevEndpoint', svc(`glue:us-east-1:${ACCT}:devEndpoint/e`))], finding: 'COMPUTE-CODE-OVERWRITE' },
  { id: 'Lambda_UpdateFunctionCode', method: 'lambda:UpdateFunctionCode (overwrite an existing function)',
    statements: [A('lambda:UpdateFunctionCode', svc(`lambda:us-east-1:${ACCT}:function:app`))], finding: 'COMPUTE-CODE-OVERWRITE' },
  { id: 'PassRole_CloudFormation', method: 'iam:PassRole + cloudformation:CreateStack',
    statements: [A('iam:PassRole', iam('role/cfn-ex')), A('cloudformation:CreateStack', svc(`cloudformation:us-east-1:${ACCT}:stack/s/*`))],
    finding: 'PASSROLE-SERVICE' },
  { id: 'PassRole_DataPipeline', method: 'iam:PassRole + datapipeline:CreatePipeline + Activate',
    statements: [A('iam:PassRole', iam('role/dp-ex')), A('datapipeline:CreatePipeline', '*'), A('datapipeline:PutPipelineDefinition', '*'), A('datapipeline:ActivatePipeline', '*')],
    finding: 'PASSROLE-SERVICE' },
];

export const SOURCE = 'Rhino Security Labs / Spencer Gietzen, "AWS IAM Privilege Escalation - Methods and Mitigation" Part 1 (2018), the original 21 methods; Rhino repo now enumerates 28. Pacu iam__privesc_scan.';

// --- Second tier: well-known privesc primitives beyond the original Rhino 21 ---
// Same fail-closed invariant (never CLEAN). `finding` names the specific detector
// where the engine already emits one; `finding: null` marks a method currently
// caught ONLY by the incomplete-coverage backstop (never CLEAN, but not yet a
// named detector) -- an honest record and a candidate for a future named detector,
// never a silent pass. Every entry is at its hardest resource-scoped form.
export const SECOND_TIER = [
  // Named: PassRole to more compute services (PASSROLE-SERVICE family).
  { id: 'PassRole_ECS_RunTask', method: 'iam:PassRole + ecs:RunTask / RegisterTaskDefinition',
    statements: [A('iam:PassRole', iam('role/ecs-task')), A('ecs:RunTask', svc(`ecs:us-east-1:${ACCT}:task-definition/app:1`)), A('ecs:RegisterTaskDefinition', '*')],
    finding: 'PASSROLE-SERVICE' },
  { id: 'PassRole_SageMaker_Notebook', method: 'iam:PassRole + sagemaker:CreateNotebookInstance',
    statements: [A('iam:PassRole', iam('role/sm')), A('sagemaker:CreateNotebookInstance', svc(`sagemaker:us-east-1:${ACCT}:notebook-instance/n`)), A('sagemaker:CreatePresignedNotebookInstanceUrl', '*')],
    finding: 'PASSROLE-SERVICE' },
  { id: 'PassRole_CodeBuild', method: 'iam:PassRole + codebuild:CreateProject + StartBuild',
    statements: [A('iam:PassRole', iam('role/cb')), A('codebuild:CreateProject', '*'), A('codebuild:StartBuild', '*')],
    finding: 'PASSROLE-SERVICE' },
  { id: 'PassRole_Glue_CreateJob', method: 'iam:PassRole + glue:CreateJob',
    statements: [A('iam:PassRole', iam('role/glue')), A('glue:CreateJob', '*')], finding: 'PASSROLE-SERVICE' },
  // Named: direct role assumption + resource-policy write.
  { id: 'AssumeRole_wildcard', method: 'sts:AssumeRole on * (assume any role)',
    statements: [A('sts:AssumeRole', '*')], finding: 'ASSUME-ROLE-EXPANSION' },
  { id: 'Lambda_AddPermission', method: 'lambda:AddPermission (function resource-policy write)',
    statements: [A('lambda:AddPermission', svc(`lambda:us-east-1:${ACCT}:function:app`))], finding: 'RESOURCE-POLICY-WRITE' },
  // Backstop-only: never CLEAN, but no named detector yet (candidates).
  { id: 'PassRole_EventBridge_PutTargets', method: 'iam:PassRole + events:PutTargets (EventBridge invokes target as role)',
    statements: [A('iam:PassRole', iam('role/eb')), A('events:PutRule', '*'), A('events:PutTargets', '*')], finding: 'PASSROLE-SERVICE' },
  { id: 'PassRole_Batch_SubmitJob', method: 'iam:PassRole + batch:RegisterJobDefinition + SubmitJob',
    statements: [A('iam:PassRole', iam('role/batch')), A('batch:RegisterJobDefinition', '*'), A('batch:SubmitJob', '*')], finding: null },
  { id: 'SSM_SendCommand', method: 'ssm:SendCommand (run commands on EC2 as the instance role)',
    statements: [A('ssm:SendCommand', svc(`ec2:us-east-1:${ACCT}:instance/*`))], finding: 'COMPUTE-SESSION-TAKEOVER' },
  { id: 'SSM_StartSession', method: 'ssm:StartSession (interactive shell on EC2 as the instance role)',
    statements: [A('ssm:StartSession', svc(`ec2:us-east-1:${ACCT}:instance/*`))], finding: 'COMPUTE-SESSION-TAKEOVER' },
  { id: 'EC2InstanceConnect_SendSSHKey', method: 'ec2-instance-connect:SendSSHPublicKey (push key, SSH in as the instance role)',
    statements: [A('ec2-instance-connect:SendSSHPublicKey', svc(`ec2:us-east-1:${ACCT}:instance/*`))], finding: 'COMPUTE-SESSION-TAKEOVER' },
];

// --- Rhino Part 2 (repo methods 22-28) ------------------------------------------
// Completes coverage of Rhino's current 28-method repo. Several overlap Part 1 /
// the second tier (22 DataPipeline, 26 Lambda-layer, 27 SageMaker-new); they are
// re-encoded here so "all 28 numbered methods" is checked end to end. Every entry
// still fails closed (never CLEAN). CodeStar (23-25) is caught by the backstop
// only and NOT given a named detector: AWS deprecated and closed CodeStar in 2024,
// so a named detector for a removed service is not warranted (deprecated: true).
export const PART2 = [
  { id: 'R22_DataPipeline', method: '22. Passing a role to Data Pipeline',
    statements: [A('iam:PassRole', iam('role/dp')), A('datapipeline:CreatePipeline', '*'), A('datapipeline:PutPipelineDefinition', '*')],
    finding: 'PASSROLE-SERVICE' },
  { id: 'R23_CodeStar_FromTemplate', method: '23. Creating a CodeStar project from a template',
    statements: [A('codestar:CreateProjectFromTemplate', '*')], finding: null, deprecated: true },
  { id: 'R24_CodeStar_PassRole', method: '24. Passing a role to a new CodeStar project',
    statements: [A('iam:PassRole', iam('role/cs')), A('codestar:CreateProject', '*')], finding: null, deprecated: true },
  { id: 'R25_CodeStar_TeamMember', method: '25. Creating a CodeStar project and associating a team member',
    statements: [A('codestar:CreateProject', '*'), A('codestar:AssociateTeamMember', '*')], finding: null, deprecated: true },
  { id: 'R26_Lambda_Layer', method: '26. Adding a malicious Lambda layer (lambda:UpdateFunctionConfiguration)',
    statements: [A('lambda:UpdateFunctionConfiguration', svc(`lambda:us-east-1:${ACCT}:function:app`))], finding: 'COMPUTE-CODE-OVERWRITE' },
  { id: 'R27_SageMaker_NewNotebook', method: '27. Passing a role to a new SageMaker notebook',
    statements: [A('iam:PassRole', iam('role/sm')), A('sagemaker:CreateNotebookInstance', svc(`sagemaker:us-east-1:${ACCT}:notebook-instance/n`)), A('sagemaker:CreatePresignedNotebookInstanceUrl', '*')],
    finding: 'PASSROLE-SERVICE' },
  { id: 'R28_SageMaker_ExistingNotebook', method: '28. Gaining access to an existing SageMaker notebook (presigned URL)',
    statements: [A('sagemaker:CreatePresignedNotebookInstanceUrl', svc(`sagemaker:us-east-1:${ACCT}:notebook-instance/n`))],
    finding: 'COMPUTE-SESSION-TAKEOVER' },
];
