// rules-classify.js - action/verb/service classification, sensitive-action catalogs, and resource-account condition helpers for the rule engine. Extracted (behavior-preserving).
import { globMatch } from './glob.js';
import { parseArn } from './resource-arn.js';

export const CAPABILITY_LIMIT =
  'Capability from this policy alone, not effective access. A single policy ' +
  'cannot establish effective permissions: other identity policies, resource ' +
  'policies, permission boundaries, SCPs, session policies, and any Condition ' +
  'keys may narrow or block it. This finding does not prove the permission is ' +
  'reachable or exploitable.';

export const CONDITION_LIMIT =
  ' The matching statement carries a Condition block, so the grant may be ' +
  'constrained at runtime; confidence is reduced accordingly.';

// IAM-704 (tests 13/14): a statement written with NotAction / NotResource
// grants everything EXCEPT the listed actions/resources. The excluded set is
// NOT an allowed capability, and the granted (inverse) set cannot be enumerated
// exactly from the policy text alone, so a finding on a complement statement is
// complement-derived: its confidence is reduced and this caveat is appended.
export const COMPLEMENT_LIMIT =
  ' This statement uses a COMPLEMENT (NotAction / NotResource): it grants every ' +
  'action / resource EXCEPT the ones listed. The excluded set is not an allowed ' +
  'capability, and the granted set is its inverse and cannot be enumerated ' +
  'exactly from the policy text, so this finding is complement-derived and its ' +
  'confidence is reduced.';

// Confidence ladder (most -> least certain). lowerConfidence() steps DOWN by
// `notches`, clamping at 'low'. Used to reduce a finding's policy-evidence /
// path-exploitability a notch for a runtime Condition and again for a complement
// (NotAction/NotResource) grant, taking the compounded reduction.
export const CONFIDENCE_LADDER = Object.freeze(['high', 'medium', 'low']);
export function lowerConfidence(level, notches) {
  let i = CONFIDENCE_LADDER.indexOf(level);
  if (i < 0) i = 0;
  return CONFIDENCE_LADDER[Math.min(CONFIDENCE_LADDER.length - 1, i + notches)];
}

// The linear, ReDoS-safe wildcard matcher (globMatch) is imported from the shared
// ./glob.js - one canonical matcher for the whole engine (S3-dos-budget).

// IAM action matching is case-insensitive ("s3:getobject" == "s3:GetObject").
export function actionGrants(pattern, concreteAction) {
  return globMatch(String(pattern).toLowerCase(), String(concreteAction).toLowerCase());
}

// --- Action-shape classifiers ------------------------------------------------

// The full wildcard: grants every action in every service.
export function isFullWildcard(pattern) {
  return pattern === '*';
}

// A full service wildcard, e.g. "s3:*" or "iam:*": grants every action in one
// service. Deliberately NOT a partial wildcard like "s3:Get*".
export function isServiceWildcard(pattern) {
  return /^[A-Za-z0-9_-]+:\*$/.test(pattern);
}

// IAM action verbs that only READ; used to decide whether a wildcard-resource
// grant is a meaningful risk. Anything not matching is treated as a write /
// mutating / privileged action (the safe over-approximation direction).
export const READ_VERB = /^(get|list|describe|view|lookup|search|head|read|batchget)/i;

// The verb portion of an action, i.e. what follows the first ':'. Returns '' if
// there is no service prefix (a bare "*" or a malformed token).
export function actionVerb(pattern) {
  const idx = pattern.indexOf(':');
  return idx === -1 ? '' : pattern.slice(idx + 1);
}

// The service portion, i.e. what precedes the first ':', lowercased.
export function actionService(pattern) {
  const idx = pattern.indexOf(':');
  return idx === -1 ? '' : pattern.slice(0, idx).toLowerCase();
}

// Verbs that DELETE / TERMINATE / DESTROY. Matched against the leading run of
// the action verb so "DeleteObject", "Delete*", "TerminateInstances" all trip.
export const DESTRUCTIVE_VERB = /^(delete|terminate|remove|destroy|purge|deregister)/i;

// Security/observability services whose destructive verbs are reported by the
// DETECTION-IMPAIRMENT rule instead of the generic destructive rule, to avoid
// double-flagging the same action with two overlapping generic findings.
export const DETECTION_SERVICES = new Set(['cloudtrail', 'guardduty', 'config']);

// --- Sensitive concrete-action catalogs --------------------------------------
// Representative concrete actions. A statement pattern "grants" the sensitive
// action when the pattern glob-matches it. This handles "iam:*",
// "iam:Put*", and the exact action alike, all via one matcher.

// Stage-13 EFO-2: resource-policy-write / cross-account-grant actions. Each rewrites
// (or adds a grant to) a RESOURCE's own policy - a bucket/key/function/topic/queue/
// repo/secret - so the holder can grant an EXTERNAL or arbitrary principal access to
// that resource: cross-account exfil, key-control, or a persistence backdoor. These
// are distinct from DIRECT-IAM-ADMIN (identity-policy edits, iam:*); AWS classifies
// them as "Permissions management" but no identity detector consumed them, so a
// concrete-resource grant used to read CLEAN (T8 fail-open). Service wildcards
// (s3:*, kms:*) are deliberately NOT matched here - they are already owned by
// WILDCARD-ACTION (never clean), so RESOURCE-POLICY-WRITE targets the SPECIFIC-action
// gap without double-flagging every wildcard grant.
export const RESOURCE_POLICY_WRITE_ACTIONS = Object.freeze([
  's3:PutBucketPolicy',
  's3:PutBucketAcl',
  's3:PutObjectAcl',
  's3:PutAccessPointPolicy',
  'kms:PutKeyPolicy',
  'kms:CreateGrant',
  'lambda:AddPermission',
  'lambda:AddLayerVersionPermission',
  'sns:AddPermission',
  'sqs:AddPermission',
  'ecr:SetRepositoryPolicy',
  'ecr-public:SetRepositoryPolicy',
  'secretsmanager:PutResourcePolicy',
  'events:PutPermission',
  'glacier:SetVaultAccessPolicy',
  'backup:PutBackupVaultAccessPolicy',
  'mediastore:PutContainerPolicy',
  'serverlessrepo:PutApplicationPolicy',
  'codeartifact:PutDomainPermissionsPolicy',
  'codeartifact:PutRepositoryPermissionsPolicy',
  'ses:PutIdentityPolicy',
]);

export const IAM_ADMIN_ACTIONS = Object.freeze([
  'iam:PutUserPolicy',
  'iam:PutRolePolicy',
  'iam:PutGroupPolicy',
  'iam:AttachUserPolicy',
  'iam:AttachRolePolicy',
  'iam:AttachGroupPolicy',
  'iam:CreatePolicy',
  'iam:CreatePolicyVersion',
  'iam:SetDefaultPolicyVersion',
  'iam:CreateUser',
  'iam:CreateRole',
  'iam:CreateAccessKey',
  // Stage-15: iam:UpdateAccessKey flips a target user's access key Active/Inactive - a
  // standalone credential-manipulation write (reactivate a compromised key = persistence;
  // deactivate a user's only key = DoS), no PassRole. Cataloged Write yet silent while the
  // sibling CreateAccessKey fires - a cataloged-but-silent CLEAN read (fail-open).
  'iam:UpdateAccessKey',
  'iam:CreateLoginProfile',
  'iam:UpdateLoginProfile',
  'iam:UpdateAssumeRolePolicy',
  // NOTE: iam:AddUserToGroup is deliberately NOT here. Adding a user to a group
  // is an INDIRECT privilege assignment (the group's attached policies decide the
  // effect), not a direct self-policy edit like Put/Attach*Policy. It has its own
  // dedicated GROUP-MEMBERSHIP rule (IAM-1005, suite-2 test 36 / suite-3 test 86)
  // so it is not mislabeled as generic direct-IAM administration.
  'iam:DeleteUserPolicy',
  'iam:DeleteRolePolicy',
  // Stage-14 (FAILOPEN-IAM-DETACH-POLICY): detaching a managed policy is the inverse
  // IAM-attachment write of iam:Attach*Policy (already above) - a de-restriction /
  // guardrail-removal / persistence primitive. These were cataloged L.PERMISSIONS
  // (incomplete:false) yet silent -> a cataloged-but-silent CLEAN read (fail-open).
  'iam:DetachUserPolicy',
  'iam:DetachRolePolicy',
  'iam:DetachGroupPolicy',
]);

// IAM-1005: group-membership privilege assignment. iam:AddUserToGroup adds a user
// (named in the API request, NOT resource-scoped by this ARN) to the group named
// by the Resource. Its blast radius is whatever policies that group carries -
// inferred, at best, from the group NAME, never confirmed from this policy alone.
export const GROUP_MEMBERSHIP_ACTIONS = Object.freeze(['iam:AddUserToGroup']);

// Group-name tokens that SUGGEST (never confirm) elevated privilege. Matched
// case-insensitively as substrings of the group name. Used only to phrase an
// inferred, medium-confidence note - the group's real permissions are unknown.
export const PRIVILEGED_GROUP_NAME_TOKENS = Object.freeze([
  'admin', 'administrator', 'poweruser', 'power-user', 'root', 'superuser',
  'privileged', 'infra', 'infrastructure', 'security', 'devops', 'sre',
  'operator', 'billing', 'finance',
]);

// Extract the group name (last path segment) from an IAM group ARN, e.g.
// arn:aws:iam::123456789012:group/team/PlatformAdmins -> "PlatformAdmins".
// Returns null for a non-group / wildcard-only resource.
export function groupNameFromArn(resource) {
  const s = String(resource == null ? '' : resource);
  const m = /:group\/(.+)$/.exec(s);
  if (!m) return null;
  const name = m[1].split('/').pop();
  return name && name !== '*' ? name : null;
}

export function groupNameSuggestsPrivilege(name) {
  if (!name) return false;
  const lower = name.toLowerCase();
  return PRIVILEGED_GROUP_NAME_TOKENS.some((t) => lower.includes(t));
}

// Sensitive READ actions (data / secret exfiltration). These fire regardless of
// resource breadth because reading a secret is the exfil act itself; severity
// scales with how broad the resource scope is. NOTE: kms:Decrypt is deliberately
// NOT here - it does not enumerate or retrieve secrets, it decrypts ciphertext
// the caller already holds, and is reported by its own KMS-DECRYPT rule
// (IAM-103) so the two capabilities are not conflated.
export const SECRET_READ_ACTIONS = Object.freeze([
  'secretsmanager:GetSecretValue',
  'ssm:GetParameter',
  'ssm:GetParameters',
  'ssm:GetParametersByPath',
]);

// KMS decryption capability. Distinct from secret-retrieval (SECRET_READ_ACTIONS):
// kms:Decrypt turns ciphertext the principal can supply into plaintext for keys
// it is allowed to use; it neither lists nor retrieves stored secrets. Reported as
// its own Decryption-capability finding (IAM-103).
export const KMS_DECRYPT_ACTIONS = Object.freeze([
  'kms:Decrypt',
]);

// Bulk object reads. These are only flagged as exfil when the resource scope is
// broad ("s3:GetObject on *"), because a scoped object read is routine.
export const BULK_READ_ACTIONS = Object.freeze([
  's3:GetObject',
  's3:GetObjectVersion',
]);

// Object/bucket reads that DATA-READ (IAM-706) covers when the resource is NAMED
// or policy-VARIABLE scoped (not broad). DATA-EXFIL owns the broad-resource bulk
// read (Resource "*"); this catalog is the same object reads plus bucket listing,
// evaluated only for the resource-scoped case DATA-EXFIL deliberately leaves as
// routine, and only when naming or a policy variable warrants a lower-certainty
// data-read capability finding (see ruleDataReadScoped).
export const DATA_READ_ACTIONS = Object.freeze([
  's3:GetObject',
  's3:GetObjectVersion',
  's3:ListBucket',
  // S2-crossaccount-scoped-surface (B2): the equivalent WHOLE-CONTAINER read /
  // list / scan / query primitives for the other datastores in the catalog, so a
  // scoped bulk read of a table / stream / database is evaluated the same way a
  // bucket read is (single-item reads such as dynamodb:GetItem are deliberately
  // EXCLUDED - they are the table analog of an s3 bucket/key single-object read).
  'dynamodb:Scan',
  'dynamodb:Query',
  'kinesis:GetRecords',
  'rds-data:ExecuteStatement',
  'rds-data:BatchExecuteStatement',
]);

// S2-crossaccount-scoped-surface (B): bare 12-digit AWS account id.
export const CONCRETE_ACCOUNT_ID_RE = /^[0-9]{12}$/;

// S2-crossaccount-scoped-surface (B3): the concrete 12-digit account a resource ARN
// belongs to, or null when it is not a well-formed ARN or its account field is not a
// bare 12-digit id (a wildcard/empty account cannot be soundly compared across the
// account boundary). S3 canonical BUCKET ARNs (arn:aws:s3:::bucket/*) carry NO
// account, so they return null here - their owning account is genuinely not
// recoverable from the policy text, and a cross-account claim is never fabricated.
// Pure parse of inert policy data; never interpreted as code.
export function concreteResourceAccount(resource) {
  const arn = parseArn(resource);
  if (!arn) return null;
  return CONCRETE_ACCOUNT_ID_RE.test(arn.account) ? arn.account : null;
}

// S2-crossaccount-scoped-surface (iteration-5, S3 fail-open close): the condition
// keys that pin the OWNING account of a resource whose ARN lacks one (canonical S3
// bucket ARNs carry no account field). IAM condition key NAMES are case-insensitive,
// so these are compared lowercased.
export const RESOURCE_ACCOUNT_COND_KEYS = Object.freeze([
  'aws:resourceaccount',
  's3:resourceaccount',
]);
// Only EQUALITY string operators pin a single concrete owner. A StringNotEquals /
// StringLike / wildcard value does not establish "the resource is owned by exactly
// this account", so it must not be used to resolve (or to clear) the account.
export const RESOURCE_ACCOUNT_EQ_OPS = Object.freeze([
  'stringequals',
  'stringequalsignorecase',
  'stringequalsifexists',
  'stringequalsignorecaseifexists',
]);

// Recover the concrete 12-digit owning account of a resource from an explicit
// aws:ResourceAccount / s3:ResourceAccount equality condition on the statement, but
// ONLY when the condition derivably pins a SINGLE concrete account. Returns that
// account id, or null when the statement does not pin exactly one (absent, a
// multi-value/wildcard set, a non-account value, or two different pinned accounts).
// This lets a bare S3 bucket read whose owner the operator asserted via condition be
// classified same- vs cross-account soundly, instead of failing open to CLEAN. Pure
// read of inert normalized policy data (`stmt.condition`); never interpreted as code.
export function resourceAccountFromCondition(stmt) {
  const cond = stmt && stmt.condition;
  if (!cond || typeof cond !== 'object' || Array.isArray(cond)) return null;
  const pinned = new Set();
  for (const op of Object.keys(cond)) {
    if (!RESOURCE_ACCOUNT_EQ_OPS.includes(String(op).toLowerCase())) continue;
    const block = cond[op];
    if (!block || typeof block !== 'object' || Array.isArray(block)) continue;
    for (const key of Object.keys(block)) {
      if (!RESOURCE_ACCOUNT_COND_KEYS.includes(String(key).toLowerCase())) continue;
      const raw = block[key];
      const values = Array.isArray(raw) ? raw : [raw];
      for (const v of values) {
        // Any non-account / wildcard value means the owner is NOT pinned to a single
        // concrete account -> unresolvable (fail closed, do not fabricate an owner).
        if (typeof v !== 'string' || !CONCRETE_ACCOUNT_ID_RE.test(v)) return null;
        pinned.add(v);
      }
    }
  }
  return pinned.size === 1 ? [...pinned][0] : null;
}

// S2-crossaccount-scoped-surface (B3): is this granted (action, resource) pair a
// WHOLE-CONTAINER read - a bucket / table / stream / database bulk read - rather than
// a single concrete object read (e.g. s3:GetObject on bucket/key)? Only whole-
// container reads are surfaced cross-account; a single concrete object read stays
// QUIET. For S3 object actions the distinction is the object KEY: a wildcarded key
// (bucket/*) reads the whole container, a concrete key (bucket/report.csv) is one
// object. s3:ListBucket targets the bucket itself (a container list). The extended
// datastore primitives (dynamodb:Scan/Query, kinesis:GetRecords, rds-data:*) are
// themselves bulk reads, so any concrete container ARN they scope IS a whole-
// container read. Deterministic pure string logic.
export function isWholeContainerRead(actionPattern, resource) {
  const svc = actionService(actionPattern);
  if (svc === 's3') {
    const verb = actionVerb(actionPattern).toLowerCase();
    if (verb === 'listbucket') return true; // lists the container
    const arn = parseArn(resource);
    if (!arn) return false;
    const slash = arn.resourceId.indexOf('/');
    if (slash === -1) return false; // bucket-only ARN for an object action: matches no object
    const key = arn.resourceId.slice(slash + 1);
    return key.includes('*') || key.includes('?');
  }
  // dynamodb:Scan/Query, kinesis:GetRecords, rds-data:* - bulk/container reads.
  return true;
}

// Lowercased substrings whose presence in a resource ARN INFERS - never proves -
// that the data behind it is sensitive (IAM-706, acceptance test 7). Curated and
// conservative: every token is clearly sensitivity-suggestive, and the set is
// deliberately chosen to leave neutral names ("example", "reports", "app-data")
// alone so a routine least-privilege scoped read stays quiet. The finding always
// says the sensitivity is inferred from naming, not established.
export const SENSITIVE_NAME_TOKENS = Object.freeze([
  'production',
  'backup',
  'secret',
  'credential',
  'confidential',
  'private',
  'customer',
  'payroll',
  'finance',
  'export',
  'sensitive',
  'archive',
  'pii',
]);

// The first sensitivity token a resource ARN contains (lowercased substring), or
// null. Pure string comparison of inert policy data - never interpreted as code.
export function resourceInfersSensitive(resource) {
  const r = String(resource).toLowerCase();
  for (const tok of SENSITIVE_NAME_TOKENS) {
    if (r.includes(tok)) return tok;
  }
  return null;
}

// Does a resource ARN carry an IAM policy variable (${...})? A variable-scoped
// resource cannot be resolved to a concrete ARN from the policy text alone
// (IAM-706, acceptance test 21), so the exact objects in scope stay uncertain and
// the variable must be preserved verbatim in evidence.
export function resourceHasVariable(resource) {
  return String(resource).includes('${');
}

export const DETECTION_ACTIONS = Object.freeze([
  'cloudtrail:StopLogging',
  'cloudtrail:DeleteTrail',
  'cloudtrail:UpdateTrail',
  'cloudtrail:PutEventSelectors',
  'guardduty:DeleteDetector',
  'guardduty:UpdateDetector',
  'guardduty:StopMonitoringMembers',
  'guardduty:DeletePublishingDestination',
  'config:StopConfigurationRecorder',
  'config:DeleteConfigurationRecorder',
  'config:DeleteDeliveryChannel',
]);

// --- Rule catalog metadata ---------------------------------------------------
// Ordering here defines the deterministic within-statement finding order.


// --- Finding factory ---------------------------------------------------------
// Guarantees every finding carries the full canonical shape (architecture.md):
// id, severity, title, statementSid, actions, resources, conditions,
// policyEvidence, pathExploitability, why, limit, remediation, ruleVersion,
// docRef.

export function statementSid(stmt) {
  return typeof stmt.sid === 'string' && stmt.sid.length > 0
    ? stmt.sid
    : `(index ${stmt.index})`;
}
