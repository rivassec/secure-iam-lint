// IAM Blast Radius - risk-rule catalog (IAM-004).
//
// Fifth stage of the pipeline (see docs/architecture.md data-flow):
//   text -> validate() -> parse() -> buildModel() -> [ rules, escalation,
//   family-aware analyzers ] -> { findings[], graph }
//
// analyzeRules() scans a normalized, frozen model (from buildModel()) and emits
// a deterministic list of risk findings using the canonical finding shape from
// docs/architecture.md. It covers the four IAM-004 rule families:
//
//   1. Wildcard grants        - Action "*" / "service:*", Resource "*".
//   2. Direct IAM admin       - iam:*, iam:PutUserPolicy, iam:AttachRolePolicy,
//                               iam:CreatePolicyVersion, ... (self-service to
//                               rewrite one's own permissions).
//   3. Destructive + exfil    - delete*/terminate* families; s3:GetObject on "*",
//                               secrets/KMS decrypt (read of sensitive data).
//   4. Detection impairment   - cloudtrail/guardduty/config stop/delete.
//
// TRUTHFULNESS INVARIANT (docs/architecture.md #6, threat-model T8): a single
// policy CANNOT establish effective permissions. Every finding is a CAPABILITY
// observation about this policy in isolation, and every finding's `limit` says
// so. A finding never claims the permission is reachable, effective, or
// exploitable - only that this policy, on its own, would grant it. Overstating
// certainty is itself a blocking security harm.
//
// SEVERITY MODEL (IAM-102). `critical` is RESERVED for compound escalation
// paths that plausibly cross a privilege boundary (see escalation.js:
// PassRole+service-execution, and AssumeRole whose scope is effectively all
// roles). No rule in THIS module emits a compound path, so nothing here is
// critical. A standalone wildcard-action grant ("*" / "service:*"), direct-IAM
// single-action administration, broad kms:Decrypt, and secrets access are all
// serious but standalone capabilities, so they cap at `high`. Asserting
// critical for a standalone grant would claim more than the evidence supports
// (threat-model T8).
//
// Findings are emitted ONLY for Allow statements: a Deny reduces access and is
// never a blast-radius grant. Conditions lower confidence (the grant may be
// gated) but never suppress a finding (the condition may not constrain it).
//
// Analyzed policies are HOSTILE input. Wildcard matching uses a linear
// two-pointer glob matcher (NOT a regex compiled from input) to avoid ReDoS.
// Every string from the policy is treated as inert data and only ever compared,
// never interpreted as code or markup.
//
// Public API:
//   RULES                       -> frozen catalog metadata (id/title/severity/...)
//   RULE_IDS                     -> frozen array of every id this module can emit
//   analyzeRules(model)          -> { ok, errors[], findings[] }   (frozen)
//   analyzeRulesFromText(text)   -> { ok, errors[], findings[] }   (full pipeline)
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. Deterministic:
// same model -> same findings, same order, every run (no Date/Math.random).

import { modelFromText } from './model.js';
// Same-policy explicit-Deny precedence (IAM-302). AWS resolves access with
// explicit Deny overriding Allow; the rule catalog must honor that just as the
// escalation engine does. We reuse escalation.js's already-tested primitives so
// the two engines apply IDENTICAL deny semantics (no drift): applyDenyToActions
// removes definitively-blocked actions, denyActionApplies/hasNonEmptyCondition
// let us detect a NotResource "fence" that narrows a broad grant to a small set.
import {
  applyDenyToActions,
  denyActionApplies,
  hasNonEmptyCondition,
} from './escalation.js';
import { statementNeverMatches } from './conditions.js';
// ONE shared, ReDoS-safe, linear wildcard matcher (S3-dos-budget). isGlobBudgetError
// lets analyzeRules re-throw the cooperative wall-clock budget sentinel instead of
// masking it as a generic internal error (see the analyzeRules catch below).
// chargeWork (S4-rules-dos): the cross-account whole-container scan in
// ruleDataReadScoped iterates stmt.resources x matched WITHOUT reaching globMatch, so
// before this it charged the deterministic work budget ZERO units and neither the 60M
// browser ceiling nor the CLI/Action --budget-ms deadline (both sampled only inside
// chargeWork) could abort a runaway. The rule now charges its real inner-loop work so
// BOTH budgets participate and a pathological input fails CLOSED mid-loop.
import { globMatch, isGlobBudgetError, chargeWork } from './glob.js';
// S1-breadth-classify: ONE shared semantic Resource-ARN classifier for the whole
// engine. The rules breadth predicate (isBroadArnResource) and the masked-grant
// undecidability gate both read breadth from classifyResource(), so the two surfaces
// cannot "agree wrongly" on a shallow signal (the accreted enumerative predicate +
// probe battery, and masked-grant's startsWith('arn:') gate, are both retired).
import { classifyResource, RESOURCE_CLASS, parseArn } from './resource-arn.js';

// --- Shared capability caveat (one canonical non-overstated wording) ---------
// Kept as one constant so every finding's `limit` field carries identical,
// non-overstated language about what a single policy can and cannot prove.
const CAPABILITY_LIMIT =
  'Capability from this policy alone, not effective access. A single policy ' +
  'cannot establish effective permissions: other identity policies, resource ' +
  'policies, permission boundaries, SCPs, session policies, and any Condition ' +
  'keys may narrow or block it. This finding does not prove the permission is ' +
  'reachable or exploitable.';

const CONDITION_LIMIT =
  ' The matching statement carries a Condition block, so the grant may be ' +
  'constrained at runtime; confidence is reduced accordingly.';

// IAM-704 (tests 13/14): a statement written with NotAction / NotResource
// grants everything EXCEPT the listed actions/resources. The excluded set is
// NOT an allowed capability, and the granted (inverse) set cannot be enumerated
// exactly from the policy text alone, so a finding on a complement statement is
// complement-derived: its confidence is reduced and this caveat is appended.
const COMPLEMENT_LIMIT =
  ' This statement uses a COMPLEMENT (NotAction / NotResource): it grants every ' +
  'action / resource EXCEPT the ones listed. The excluded set is not an allowed ' +
  'capability, and the granted set is its inverse and cannot be enumerated ' +
  'exactly from the policy text, so this finding is complement-derived and its ' +
  'confidence is reduced.';

// Confidence ladder (most -> least certain). lowerConfidence() steps DOWN by
// `notches`, clamping at 'low'. Used to reduce a finding's policy-evidence /
// path-exploitability a notch for a runtime Condition and again for a complement
// (NotAction/NotResource) grant, taking the compounded reduction.
const CONFIDENCE_LADDER = Object.freeze(['high', 'medium', 'low']);
function lowerConfidence(level, notches) {
  let i = CONFIDENCE_LADDER.indexOf(level);
  if (i < 0) i = 0;
  return CONFIDENCE_LADDER[Math.min(CONFIDENCE_LADDER.length - 1, i + notches)];
}

// The linear, ReDoS-safe wildcard matcher (globMatch) is imported from the shared
// ./glob.js - one canonical matcher for the whole engine (S3-dos-budget).

// IAM action matching is case-insensitive ("s3:getobject" == "s3:GetObject").
function actionGrants(pattern, concreteAction) {
  return globMatch(String(pattern).toLowerCase(), String(concreteAction).toLowerCase());
}

// --- Action-shape classifiers ------------------------------------------------

// The full wildcard: grants every action in every service.
function isFullWildcard(pattern) {
  return pattern === '*';
}

// A full service wildcard, e.g. "s3:*" or "iam:*": grants every action in one
// service. Deliberately NOT a partial wildcard like "s3:Get*".
function isServiceWildcard(pattern) {
  return /^[A-Za-z0-9_-]+:\*$/.test(pattern);
}

// IAM action verbs that only READ; used to decide whether a wildcard-resource
// grant is a meaningful risk. Anything not matching is treated as a write /
// mutating / privileged action (the safe over-approximation direction).
const READ_VERB = /^(get|list|describe|view|lookup|search|head|read|batchget)/i;

// The verb portion of an action, i.e. what follows the first ':'. Returns '' if
// there is no service prefix (a bare "*" or a malformed token).
function actionVerb(pattern) {
  const idx = pattern.indexOf(':');
  return idx === -1 ? '' : pattern.slice(idx + 1);
}

// The service portion, i.e. what precedes the first ':', lowercased.
function actionService(pattern) {
  const idx = pattern.indexOf(':');
  return idx === -1 ? '' : pattern.slice(0, idx).toLowerCase();
}

// Verbs that DELETE / TERMINATE / DESTROY. Matched against the leading run of
// the action verb so "DeleteObject", "Delete*", "TerminateInstances" all trip.
const DESTRUCTIVE_VERB = /^(delete|terminate|remove|destroy|purge|deregister)/i;

// Security/observability services whose destructive verbs are reported by the
// DETECTION-IMPAIRMENT rule instead of the generic destructive rule, to avoid
// double-flagging the same action with two overlapping generic findings.
const DETECTION_SERVICES = new Set(['cloudtrail', 'guardduty', 'config']);

// --- Sensitive concrete-action catalogs --------------------------------------
// Representative concrete actions. A statement pattern "grants" the sensitive
// action when the pattern glob-matches it. This handles "iam:*",
// "iam:Put*", and the exact action alike, all via one matcher.

const IAM_ADMIN_ACTIONS = Object.freeze([
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
]);

// IAM-1005: group-membership privilege assignment. iam:AddUserToGroup adds a user
// (named in the API request, NOT resource-scoped by this ARN) to the group named
// by the Resource. Its blast radius is whatever policies that group carries -
// inferred, at best, from the group NAME, never confirmed from this policy alone.
const GROUP_MEMBERSHIP_ACTIONS = Object.freeze(['iam:AddUserToGroup']);

// Group-name tokens that SUGGEST (never confirm) elevated privilege. Matched
// case-insensitively as substrings of the group name. Used only to phrase an
// inferred, medium-confidence note - the group's real permissions are unknown.
const PRIVILEGED_GROUP_NAME_TOKENS = Object.freeze([
  'admin', 'administrator', 'poweruser', 'power-user', 'root', 'superuser',
  'privileged', 'infra', 'infrastructure', 'security', 'devops', 'sre',
  'operator', 'billing', 'finance',
]);

// Extract the group name (last path segment) from an IAM group ARN, e.g.
// arn:aws:iam::123456789012:group/team/PlatformAdmins -> "PlatformAdmins".
// Returns null for a non-group / wildcard-only resource.
function groupNameFromArn(resource) {
  const s = String(resource == null ? '' : resource);
  const m = /:group\/(.+)$/.exec(s);
  if (!m) return null;
  const name = m[1].split('/').pop();
  return name && name !== '*' ? name : null;
}

function groupNameSuggestsPrivilege(name) {
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
const SECRET_READ_ACTIONS = Object.freeze([
  'secretsmanager:GetSecretValue',
  'ssm:GetParameter',
  'ssm:GetParameters',
  'ssm:GetParametersByPath',
]);

// KMS decryption capability. Distinct from secret-retrieval (SECRET_READ_ACTIONS):
// kms:Decrypt turns ciphertext the principal can supply into plaintext for keys
// it is allowed to use; it neither lists nor retrieves stored secrets. Reported as
// its own Decryption-capability finding (IAM-103).
const KMS_DECRYPT_ACTIONS = Object.freeze([
  'kms:Decrypt',
]);

// Bulk object reads. These are only flagged as exfil when the resource scope is
// broad ("s3:GetObject on *"), because a scoped object read is routine.
const BULK_READ_ACTIONS = Object.freeze([
  's3:GetObject',
  's3:GetObjectVersion',
]);

// Object/bucket reads that DATA-READ (IAM-706) covers when the resource is NAMED
// or policy-VARIABLE scoped (not broad). DATA-EXFIL owns the broad-resource bulk
// read (Resource "*"); this catalog is the same object reads plus bucket listing,
// evaluated only for the resource-scoped case DATA-EXFIL deliberately leaves as
// routine, and only when naming or a policy variable warrants a lower-certainty
// data-read capability finding (see ruleDataReadScoped).
const DATA_READ_ACTIONS = Object.freeze([
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
const CONCRETE_ACCOUNT_ID_RE = /^[0-9]{12}$/;

// S2-crossaccount-scoped-surface (B3): the concrete 12-digit account a resource ARN
// belongs to, or null when it is not a well-formed ARN or its account field is not a
// bare 12-digit id (a wildcard/empty account cannot be soundly compared across the
// account boundary). S3 canonical BUCKET ARNs (arn:aws:s3:::bucket/*) carry NO
// account, so they return null here - their owning account is genuinely not
// recoverable from the policy text, and a cross-account claim is never fabricated.
// Pure parse of inert policy data; never interpreted as code.
function concreteResourceAccount(resource) {
  const arn = parseArn(resource);
  if (!arn) return null;
  return CONCRETE_ACCOUNT_ID_RE.test(arn.account) ? arn.account : null;
}

// S2-crossaccount-scoped-surface (iteration-5, S3 fail-open close): the condition
// keys that pin the OWNING account of a resource whose ARN lacks one (canonical S3
// bucket ARNs carry no account field). IAM condition key NAMES are case-insensitive,
// so these are compared lowercased.
const RESOURCE_ACCOUNT_COND_KEYS = Object.freeze([
  'aws:resourceaccount',
  's3:resourceaccount',
]);
// Only EQUALITY string operators pin a single concrete owner. A StringNotEquals /
// StringLike / wildcard value does not establish "the resource is owned by exactly
// this account", so it must not be used to resolve (or to clear) the account.
const RESOURCE_ACCOUNT_EQ_OPS = Object.freeze([
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
function resourceAccountFromCondition(stmt) {
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
function isWholeContainerRead(actionPattern, resource) {
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
const SENSITIVE_NAME_TOKENS = Object.freeze([
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
function resourceInfersSensitive(resource) {
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
function resourceHasVariable(resource) {
  return String(resource).includes('${');
}

const DETECTION_ACTIONS = Object.freeze([
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

export const RULES = Object.freeze({
  'WILDCARD-ACTION': Object.freeze({
    id: 'WILDCARD-ACTION',
    order: 0,
    title: 'Wildcard action grant',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
  }),
  'WILDCARD-RESOURCE': Object.freeze({
    id: 'WILDCARD-RESOURCE',
    order: 1,
    title: 'Wildcard / overly broad resource scope',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html',
  }),
  'DIRECT-IAM-ADMIN': Object.freeze({
    id: 'DIRECT-IAM-ADMIN',
    order: 2,
    title: 'Direct IAM administration',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagement.html',
  }),
  'DATA-EXFIL': Object.freeze({
    id: 'DATA-EXFIL',
    order: 3,
    title: 'Sensitive data read / exfiltration',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
  }),
  'KMS-DECRYPT': Object.freeze({
    id: 'KMS-DECRYPT',
    order: 4,
    title: 'KMS decryption capability',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html',
  }),
  'DESTRUCTIVE-ACTION': Object.freeze({
    id: 'DESTRUCTIVE-ACTION',
    order: 5,
    title: 'Destructive action grant',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
  }),
  'DETECTION-IMPAIRMENT': Object.freeze({
    id: 'DETECTION-IMPAIRMENT',
    order: 6,
    title: 'Detection / logging impairment',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html',
  }),
  'NOTACTION-ALLOW': Object.freeze({
    id: 'NOTACTION-ALLOW',
    order: 7,
    title: 'Allow with NotAction (broad inverse grant)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html',
  }),
  // IAM-706: a lower-certainty, resource-scoped data-read capability. Neutral
  // framing on purpose ("data-read", NOT "exfiltration"): it covers a read scoped
  // to a NAMED bucket whose name only INFERS sensitivity, or to a policy-VARIABLE
  // resource whose ARN cannot be resolved. Distinct from DATA-EXFIL (broad-scope
  // bulk read / secret retrieval, high). Ordered last so it never displaces the
  // established rules within a statement.
  'DATA-READ': Object.freeze({
    id: 'DATA-READ',
    order: 8,
    title: 'Data-read capability (resource-scoped, inferred sensitivity)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html',
  }),
  // IAM-1005: indirect privilege assignment via group membership. Distinct from
  // DIRECT-IAM-ADMIN (a direct self-policy edit): iam:AddUserToGroup grants only
  // whatever the target group already carries, which this single policy cannot
  // establish. Ordered last so it never displaces the established rules.
  'GROUP-MEMBERSHIP': Object.freeze({
    id: 'GROUP-MEMBERSHIP',
    order: 9,
    title: 'Group-membership privilege assignment (iam:AddUserToGroup)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_manage_add-remove-users.html',
  }),
  // S2-crossaccount-scoped-surface (B): a whole-container read (bucket / table /
  // stream / database bulk read) whose concrete resource account differs from the
  // analyzed/subject account. Surfaced REGARDLESS of resource name (the sensitivity
  // wordlist only RAISES severity, it never gates reporting). LOW/INFO band: it
  // crosses the account boundary, but whether the objects are actually reachable
  // depends on the target account's resource policy (bucket/table policy), which is
  // not in scope here. Ordered last so it never displaces the established rules.
  'CROSS-ACCOUNT-DATA-READ': Object.freeze({
    id: 'CROSS-ACCOUNT-DATA-READ',
    order: 10,
    title: 'Cross-account whole-container data read',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html',
  }),
  // S2-crossaccount-scoped-surface (iteration-5, S3 fail-open close): a whole-
  // container read (bucket/* or bucket list) on a CANONICAL S3 bucket ARN
  // (arn:aws:s3:::bucket/*), which carries NO account field and no aws:ResourceAccount
  // / s3:ResourceAccount condition pinning its owner. Its owning account is genuinely
  // not recoverable from the policy text, so the tool CANNOT clear it as same-account
  // - it must not read CLEAN (fail closed). Surfaced at INFO as an UNDETERMINED
  // (account-blind) cross-account read: the sibling CROSS-ACCOUNT-DATA-READ makes a
  // CONFIRMED cross-account claim (a resolvable, differing account), whereas this one
  // is explicit that the account is unknown and MUST NOT be read as a proven crossing
  // (threat-model T8). Ordered last so it never displaces the established rules.
  'CROSS-ACCOUNT-DATA-READ-UNDETERMINED': Object.freeze({
    id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED',
    order: 11,
    title: 'Whole-container S3 read with an undeterminable owning account',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html',
  }),
});

export const RULE_IDS = Object.freeze(Object.keys(RULES));

// --- Finding factory ---------------------------------------------------------
// Guarantees every finding carries the full canonical shape (architecture.md):
// id, severity, title, statementSid, actions, resources, conditions,
// policyEvidence, pathExploitability, why, limit, remediation, ruleVersion,
// docRef.

function statementSid(stmt) {
  return typeof stmt.sid === 'string' && stmt.sid.length > 0
    ? stmt.sid
    : `(index ${stmt.index})`;
}

function makeFinding(ruleId, stmt, fields) {
  const meta = RULES[ruleId];
  const conditioned = stmt.condition !== null && stmt.condition !== undefined;
  // Split certainty (IAM-104), replacing the single `confidence` field:
  //   policyEvidence     - how strongly this policy text establishes the grant.
  //                        Drives graph edge certainty (see graph.js).
  //   pathExploitability - how likely the grant actually yields the flagged
  //                        impact. These rule findings are DIRECT capabilities
  //                        (a wildcard scope, a broad data read, direct IAM
  //                        admin): the grant itself IS the risk, with no unknown
  //                        target role gating it, so exploitability defaults to
  //                        the same base as the evidence. A Condition on the
  //                        statement is a runtime gate that weakens BOTH a notch
  //                        (rules.js models Conditions; graph.js layers on
  //                        same-policy Deny precedence for the edge certainty).
  const evidenceBase = fields.policyEvidence;
  const exploitBase = fields.pathExploitability || fields.policyEvidence;

  // IAM-704: complement (NotAction / NotResource) presentation. NEVER surface the
  // EXCLUDED set as the finding's allowed actions/resources (tests 13, 14):
  //   - NotAction: there are no positive granted actions to list; the grant is
  //     "everything except the excluded set", so the granted-action summary is
  //     '*' (never the excluded list), and the excluded list rides in
  //     excludedActions.
  //   - NotResource: there is no literal granted resource ARN; resources is left
  //     empty and the carve-out rides in excludedResources (never presented as
  //     the granted resource).
  // Complement grants are approximate, so confidence drops a notch (on top of
  // any Condition notch) and the limit spells out the complement caveat.
  const usesNotAction = Array.isArray(stmt.notActions) && stmt.notActions.length > 0;
  const usesNotResource = Array.isArray(stmt.notResources) && stmt.notResources.length > 0;
  const complement = [];
  if (usesNotAction) complement.push('NotAction');
  if (usesNotResource) complement.push('NotResource');
  const complementDerived = complement.length > 0;

  const actions = usesNotAction ? ['*'] : fields.actions.slice();
  const resources = usesNotResource ? [] : (fields.resources || []).slice();

  let peNotches = 0;
  let pxNotches = 0;
  if (conditioned) { peNotches += 1; pxNotches += 1; }
  if (complementDerived) { peNotches += 1; pxNotches += 1; }

  const finding = {
    id: meta.id,
    severity: fields.severity,
    // The title is tool-authored rule metadata (never attacker text) and is NOT part of
    // the SARIF semantic identity / partialFingerprint (sarif.mjs hashes findingIdentity,
    // not the title), so a per-finding title override cannot forge or churn a fingerprint.
    // It lets ONE rule id carry a SERVICE-ACCURATE title when a single id spans several
    // datastores (NEW-01: CROSS-ACCOUNT-DATA-READ-UNDETERMINED describes an S3 bucket OR a
    // dynamodb/kinesis/rds-data container). Absent an override it falls back to meta.title,
    // so every existing caller is byte-unchanged.
    title: typeof fields.title === 'string' && fields.title.length > 0 ? fields.title : meta.title,
    statementSid: statementSid(stmt),
    statementIndex: stmt.index,
    actions,
    resources,
    conditions: stmt.condition, // null when absent; inert data otherwise
    policyEvidence: lowerConfidence(evidenceBase, peNotches),
    pathExploitability: lowerConfidence(exploitBase, pxNotches),
    why: fields.why,
    limit:
      CAPABILITY_LIMIT +
      (conditioned ? CONDITION_LIMIT : '') +
      (complementDerived ? COMPLEMENT_LIMIT : ''),
    remediation: fields.remediation,
    ruleVersion: meta.ruleVersion,
    docRef: meta.docRef,
  };
  // The excluded set is inert policy data, preserved so nothing is lost - but it
  // is a SEPARATE field, explicitly the EXCLUDED (not allowed) set.
  if (usesNotAction) finding.excludedActions = stmt.notActions.slice();
  if (usesNotResource) finding.excludedResources = stmt.notResources.slice();
  if (complementDerived) finding.complement = complement.slice();
  return finding;
}

// The resource scope a finding reports: prefer explicit Resource, fall back to
// NotResource (annotating the inverse), else an explicit "unspecified" marker.
function resourceScope(stmt) {
  if (stmt.resources.length > 0) return stmt.resources;
  if (stmt.notResources.length > 0) return stmt.notResources;
  return ['(no Resource/NotResource specified)'];
}

// Is a single Resource ARN broad - i.e. does it match all / nearly-all ARNs so a
// grant on it reaches essentially every resource rather than a specific one? This is
// the rules-engine breadth predicate; it is now a thin wrapper over the ONE shared
// semantic classifier (engine/resource-arn.js). A value is broad when classifyResource
// returns BROAD (the bare "*", a wildcard in the partition/service/account, a
// whole-collection identifier wildcard like role/*, a bucket-name-segment wildcard, or
// a no-delimiter typed-resource glob like function*/role*). A concrete, account-scoped
// resource whose only wildcard sits after a concrete top-level name
// (arn:aws:s3:::my-bucket/prefix/*, arn:aws:iam::123456789012:role/app-*) is NARROW.
//
// A MALFORMED value (not "*" and not a well-formed ARN, or leading/trailing whitespace,
// or a would-be-narrow ARN on a service the engine does not model) is NOT broad here -
// firing a confident broad finding on an undecidable value would overstate certainty
// (threat-model T8). masked-grant.js reads the SAME classifier and routes MALFORMED to
// coverage.summary.incomplete, so every non-"*"/non-well-formed-ARN value is fail-CLOSED
// (broad-and-firing, or undecidable-and-incomplete) and never a bare CLEAN.
export function isBroadArnResource(resource) {
  return classifyResource(resource) === RESOURCE_CLASS.BROAD;
}

// Is the resource scope broad enough that "on everything" is a fair reading?
// True when the statement uses NotResource (Allow everything except a few), or
// ANY listed Resource is the bare "*" or an ARN-wildcard that matches all /
// nearly-all ARNs (see isBroadArnResource) - all grant across essentially every
// ARN. Fixing the ARN-wildcard case closes a DATA-EXFIL fail-open (T8): a bulk
// read on arn:aws:s3:::*/* is just as account-wide as one on "*".
function resourceIsBroad(stmt) {
  return (
    stmt.notResources.length > 0 ||
    stmt.resources.some(isBroadArnResource)
  );
}

// Is a single action pattern a non-read (mutating/privileged) action - the kind
// for which a wildcard resource is a meaningful, remediable risk? A read/
// enumeration verb (get/list/describe/...) is treated as read; anything else -
// including a wildcard or an unknown/malformed verb - is the safe
// over-approximation "write". Enumeration actions (iam:ListRoles,
// ec2:DescribeInstances, s3:ListAllMyBuckets) are reads: many legitimately
// REQUIRE Resource:* because they have no resource-level scoping, so a wildcard
// on them is normal, not remediable (suite-3 tests 92/93/94).
function isNonReadAction(p) {
  if (isFullWildcard(p)) return true;
  if (isServiceWildcard(p)) return true;
  const verb = actionVerb(p);
  if (verb === '' || verb === '*') return true; // unknown scope -> treat as write
  return !READ_VERB.test(verb);
}

// Does the statement grant at least one non-read (mutating/privileged) action?
// Used to decide whether a wildcard resource is a meaningful risk vs. a routine
// read-only wildcard (e.g. ec2:Describe* on "*").
function grantsNonReadAction(stmt) {
  if (stmt.notActions.length > 0) return true; // Allow NotAction => includes writes
  return stmt.actions.some(isNonReadAction);
}

// The explicit actions in a statement for which a wildcard resource is actually
// dangerous and remediable, i.e. the non-read (mutating/privileged) subset. In a
// statement mixing a required-wildcard enumeration action with a dangerous one -
// e.g. ["iam:ListRoles", "iam:PassRole"] on Resource "*" (suite-3 test 95) - only
// iam:PassRole belongs in the WILDCARD-RESOURCE finding: recommending "scope
// Resource to specific ARNs" for iam:ListRoles is impossible remediation, since
// ListRoles has no resource-level scoping. Per-action, not one conclusion for the
// whole statement. Only reached when grantsNonReadAction(stmt) is already true,
// so the result is non-empty for the explicit-actions path.
function remediableWildcardActions(stmt) {
  return stmt.actions.filter(isNonReadAction);
}

// --- Same-policy explicit-Deny precedence (IAM-302) --------------------------
// AWS resolves access with explicit Deny overriding Allow, so a rule finding -
// a CAPABILITY of the analyzed identity - is not real when a same-policy Deny
// removes the whole granted capability. rules.js deliberately stays Deny-UNAWARE
// when it EMITS findings: the graph (graph.js) needs the un-suppressed finding to
// draw the `blocked-by-deny` edge that shows the user the grant exists but is
// blocked (a Phase-2 invariant). Instead, this module exposes
// ruleFindingDenySuppressed() so the pipeline (analyze.js) can drop a
// fully-denied rule finding from the AUTHORITATIVE TABLE while the graph still
// receives the full finding set. Escalation findings already have Deny folded in
// by escalation.js, so this only concerns rule findings.

// Does a same-policy Deny "fence" a broad Allow of `action` down to a NARROW,
// specific set - so the effective resource scope is no longer broad? A Deny with
// NotResource denies the action on EVERY resource EXCEPT the listed ones, so an
// unconditional, certainly-applicable NotResource Deny confines the broad Allow
// to exactly those spared resources. When that spared set is itself narrow (no
// bare "*"), the action is no longer broadly resource-scoped and a broad-scope
// finding (e.g. DATA-EXFIL bulk read) must not fire (IAM-301 negative corpus:
// notresource-deny-fences-exfil). A conditional Deny is not treated as a
// definitive fence (it may not apply at runtime).
function denyFencesToNarrow(denies, action, allowStmt) {
  if (!denies || denies.length === 0) return false;
  for (const deny of denies) {
    if (hasNonEmptyCondition(deny)) continue;
    if (deny.notResources.length === 0) continue; // only a NotResource Deny fences
    // A NotResource Deny denies the action on EVERY resource EXCEPT its SPARED set
    // (deny.notResources). It only narrows the broad Allow if that spared set is
    // PROVEN NARROW. Crediting the Deny as a fence SUPPRESSES a finding, so the burden
    // is to PROVE narrowness: any spared element that is not a NARROW verdict from the
    // shared classifier - BROAD (the bare "*", or an ARN-wildcard like arn:aws:s3:::*/*
    // that spares all S3 objects) OR MALFORMED (an undecidable value like a bare token,
    // where narrowness rests on the UNVERIFIED grammar the HYBRID default refuses to
    // trust) - leaves the spared set NOT provably narrow, so the Deny's EFFECTIVE
    // denied set covers ~nothing / is undecidable and must NOT be credited as a
    // narrowing fence. Two bug-for-bug fail-opens this closes: a BROAD spared set
    // ({Deny NotResource:'arn:aws:s3:::*/*'} denies everything EXCEPT all S3 objects =
    // denies NOTHING) and a MALFORMED spared set ({Deny NotResource:'not-an-arn'} whose
    // scope is undecidable) both used to suppress DATA-EXFIL. Breadth read from the ONE
    // shared classifier, never re-implemented here; fail closed on anything but NARROW.
    if (deny.notResources.some((r) => classifyResource(r) !== RESOURCE_CLASS.NARROW)) continue;
    const a = denyActionApplies(deny, action);
    if (a.applies && a.certain) return true;
  }
  return false;
}

// A bulk object-read action (s3:GetObject family): its exfil risk is only
// flagged when the resource scope is BROAD, so a NotResource Deny that fences the
// broad Allow to a narrow set removes the risk entirely. Secret-read actions
// (Secrets Manager / SSM), by contrast, fire regardless of scope, so a resource
// fence does not neutralize them.
function isBulkReadAction(action) {
  return BULK_READ_ACTIONS.some((concrete) => actionGrants(action, concrete));
}

/**
 * Does same-policy explicit-Deny precedence fully remove the capability a RULE
 * finding reports, so it must not appear in the authoritative findings TABLE
 * (IAM-302)? True only when EVERY action the finding rests on is either
 * definitively blocked by an unconditional in-scope Deny, or (for a broad
 * bulk-read DATA-EXFIL) fenced down to a narrow resource set by a NotResource
 * Deny. A finding with any surviving action stays. Escalation findings (which
 * carry `escalation` enrichment) already have Deny folded in by escalation.js
 * and are never suppressed here. Deterministic; never throws.
 *
 * @param {object} finding a rule/escalation finding (canonical shape)
 * @param {object} model normalized, frozen model from buildModel()
 * @returns {boolean}
 */
export function ruleFindingDenySuppressed(finding, model) {
  if (!finding || typeof finding !== 'object') return false;
  // Only rule-catalog findings are Deny-unaware here; escalation findings arrive
  // pre-resolved. Guard on the rule catalog + absence of escalation enrichment.
  if (finding.escalation) return false;
  if (!Object.prototype.hasOwnProperty.call(RULES, finding.id)) return false;
  if (!model || !Array.isArray(model.statements)) return false;
  if (typeof finding.statementIndex !== 'number') return false;

  const allowStmt = model.statements.find((s) => s && s.index === finding.statementIndex);
  if (!allowStmt) return false;
  // Same identity-statement Deny set the escalation engine uses (a Deny that
  // names a Principal is a resource/trust-policy statement, not an identity
  // constraint on the analyzed subject).
  const denies = model.statements.filter((s) => s.effect === 'Deny' && s.principal == null);
  if (denies.length === 0) return false;

  const actions = Array.isArray(finding.actions) ? finding.actions : [];
  if (actions.length === 0) return false;

  // Drop the actions an unconditional, in-scope Deny definitively blocks.
  const survivors = applyDenyToActions(denies, actions, allowStmt).actions;

  // A broad bulk-read whose scope a NotResource Deny fences to a narrow set no
  // longer holds as a broad-exfil capability (secret reads are unaffected).
  const stillReal = survivors.filter((a) => {
    if (finding.id === 'DATA-EXFIL' && isBulkReadAction(a)) {
      return !denyFencesToNarrow(denies, a, allowStmt);
    }
    return true;
  });

  return stillReal.length === 0;
}

/**
 * Filter a statement's candidate resource-scopable READ actions down to those
 * that SURVIVE same-policy explicit Deny as a BROAD read. Mirrors
 * ruleFindingDenySuppressed() at the statement level (identical Deny semantics,
 * no drift): an action an unconditional, in-scope Deny definitively blocks
 * (applyDenyToActions removes it) is gone; a bulk object-read whose broad scope a
 * NotResource Deny fences to a narrow set (denyFencesToNarrow) is no longer a
 * broad read. When nothing survives, the statement's broad Resource is Deny-
 * covered - not a surviving broad read - so analyze.js's broad-uncovered net must
 * NOT flip coverage incomplete on it (IAM-301 negative corpus:
 * explicit-deny-suppresses-exfil, notresource-deny-fences-exfil).
 *
 * The net keys off the FENCED effective scope, not the literal "*" resource: a
 * read that is fully denied, or fenced down to a narrow surviving set, does not
 * count as a surviving broad read. Deterministic; never throws.
 *
 * @param {string[]} readActions candidate resource-scopable read actions of allowStmt
 * @param {object} allowStmt the Allow statement (normalized)
 * @param {object} model normalized, frozen model from buildModel()
 * @returns {string[]} the subset of readActions that survive as a broad read
 */
export function survivingBroadReadActions(readActions, allowStmt, model) {
  if (!Array.isArray(readActions) || readActions.length === 0) return [];
  if (!allowStmt || !model || !Array.isArray(model.statements)) return readActions.slice();
  // Same identity-statement Deny set ruleFindingDenySuppressed / the escalation
  // engine use (a Deny that names a Principal is a resource/trust-policy
  // statement, not an identity constraint on the analyzed subject).
  const denies = model.statements.filter((s) => s.effect === 'Deny' && s.principal == null);
  if (denies.length === 0) return readActions.slice();
  // Drop the actions an unconditional, in-scope Deny definitively blocks.
  const survivors = applyDenyToActions(denies, readActions, allowStmt).actions;
  // A bulk object-read whose broad scope a NotResource Deny fences to a narrow
  // set is no longer broad (secret reads and non-bulk reads are unaffected).
  return survivors.filter((a) => {
    if (isBulkReadAction(a)) return !denyFencesToNarrow(denies, a, allowStmt);
    return true;
  });
}

// --- Per-rule evaluation of a single Allow statement -------------------------

// 1. Wildcard action. Both "*" (all services) and "service:*" are HIGH: a
// standalone wildcard-action grant is a broad capability, but critical is
// reserved for compound escalation paths (IAM-102 severity model), so the
// widest standalone grant does not by itself earn critical.
function ruleWildcardAction(stmt, out) {
  const full = stmt.actions.filter(isFullWildcard);
  const service = stmt.actions.filter((p) => !isFullWildcard(p) && isServiceWildcard(p));
  if (full.length === 0 && service.length === 0) return;
  if (full.length > 0) {
    out.push(
      makeFinding('WILDCARD-ACTION', stmt, {
        severity: 'high',
        policyEvidence: 'high',
        actions: full,
        resources: resourceScope(stmt),
        why:
          'Action "*" grants every action in every AWS service, including IAM ' +
          'administration, destructive operations, data reads, and disabling of ' +
          'CloudTrail/GuardDuty/Config. This is the widest possible grant.',
        remediation:
          'Replace "*" with the specific actions the principal needs; start from ' +
          'CloudTrail/Access Analyzer usage and grant least privilege.',
      }),
    );
    return; // "*" subsumes any service:* in the same statement.
  }
  out.push(
    makeFinding('WILDCARD-ACTION', stmt, {
      severity: 'high',
      policyEvidence: 'high',
      actions: service,
      resources: resourceScope(stmt),
      why:
        `Service wildcard(s) ${service.join(', ')} grant every action in the ` +
        'named service(s), including any destructive, data-read, or ' +
        'administrative actions those services expose.',
      remediation:
        'Enumerate the specific actions required and drop the "service:*" ' +
        'wildcard(s) in favor of an explicit action list.',
    }),
  );
}

// 2. Wildcard / overly broad resource on a non-read grant.
function ruleWildcardResource(stmt, out) {
  if (!resourceIsBroad(stmt)) return;
  if (!grantsNonReadAction(stmt)) return; // read-only wildcard is routine
  // Three broadness shapes with distinct wording: the bare "*" (all resources),
  // an ARN-wildcard that matches all/nearly-all ARNs (e.g. arn:aws:s3:::*/*), and
  // a NotResource carve-out. All three are inherently broad on a non-read grant.
  const broadStar = stmt.resources.includes('*');
  const broadArn = stmt.resources.some(isBroadArnResource); // true for bare "*" too
  out.push(
    makeFinding('WILDCARD-RESOURCE', stmt, {
      // Severity keys on the NORMALIZED effective breadth (resourceIsBroad), NOT on the
      // raw stmt.resources syntax. A NotResource-only grant has an EMPTY stmt.resources
      // yet reaches every resource EXCEPT a listed few - as account-wide as "*" - so
      // keying on stmt.resources alone under-rated it to 'medium' and it slipped the
      // default 'high' gate (a syntax-keyed-severity fail-open). Every shape that
      // reaches here already passed the resourceIsBroad guard, so this is HIGH.
      severity: resourceIsBroad(stmt) ? 'high' : 'medium',
      policyEvidence: 'high',
      // Per-action (suite-3 test 95): for the explicit-actions path list ONLY the
      // remediable non-read actions, so a required-wildcard enumeration action
      // (iam:ListRoles) is not presented with impossible "scope the ARN"
      // remediation. The NotAction path keeps its excluded-set semantics.
      actions: stmt.notActions.length > 0 ? stmt.notActions : remediableWildcardActions(stmt),
      resources: resourceScope(stmt),
      why: broadStar
        ? 'Resource "*" leaves the granted action(s) broadly resource-scoped: ' +
          'they apply to every resource in the account rather than a specific ARN.'
        : broadArn
        ? 'An ARN-wildcard Resource that matches all / nearly-all ARNs leaves the ' +
          'granted action(s) broadly resource-scoped: they apply across the whole ' +
          'service / account rather than a specific ARN.'
        : 'NotResource leaves the granted action(s) broadly resource-scoped: ' +
          'they apply to every resource EXCEPT the few listed - typically far ' +
          'broader than intended.',
      remediation:
        'Scope Resource to the specific ARNs (or ARN prefixes) the principal ' +
        'must act on; avoid "*" and prefer Resource over NotResource.',
    }),
  );
}

// Collect the statement patterns that glob-match any action in `catalog`.
// `includeServiceWildcards` controls whether a "service:*" pattern is allowed
// to match (true for IAM admin, which must catch "iam:*"; false for the
// destructive/exfil/detection rules, where "service:*" is already reported by
// WILDCARD-ACTION and re-flagging it would be noise).
function matchPatterns(stmt, catalog, includeServiceWildcards) {
  const matched = [];
  for (const p of stmt.actions) {
    if (isFullWildcard(p)) continue; // "*" is owned by WILDCARD-ACTION
    if (!includeServiceWildcards && isServiceWildcard(p)) continue;
    if (catalog.some((sensitive) => actionGrants(p, sensitive))) matched.push(p);
  }
  return matched;
}

// 3. Direct IAM administration (includes iam:* per the requirement).
function ruleDirectIamAdmin(stmt, out) {
  const matched = matchPatterns(stmt, IAM_ADMIN_ACTIONS, true);
  if (matched.length === 0) return;
  out.push(
    makeFinding('DIRECT-IAM-ADMIN', stmt, {
      // High, not critical: direct-IAM single-action administration is a
      // standalone escalation primitive, but critical is reserved for compound
      // privilege-boundary-crossing paths (IAM-102 severity model).
      severity: 'high',
      policyEvidence: 'high',
      actions: matched,
      resources: resourceScope(stmt),
      why:
        'Grants direct IAM administration (e.g. attach/put policy, create policy ' +
        'version, create access key / login profile). A principal that can edit ' +
        'IAM can grant itself any other permission - a privilege-escalation ' +
        'primitive on its own.',
      remediation:
        'Remove self-service IAM write access; route policy changes through a ' +
        'reviewed pipeline and constrain with a permission boundary.',
    }),
  );
}

// 4a. Sensitive data read / exfil.
function ruleDataExfil(stmt, out) {
  const secret = matchPatterns(stmt, SECRET_READ_ACTIONS, false);
  const bulkAll = matchPatterns(stmt, BULK_READ_ACTIONS, false);
  const broad = resourceIsBroad(stmt);
  const bulk = broad ? bulkAll : [];
  const matched = secret.concat(bulk);
  if (matched.length === 0) return;
  const highSeverity = broad || secret.length > 0;
  const whyParts = [];
  if (secret.length > 0) {
    whyParts.push(
      'read secret material (Secrets Manager / SSM parameters)',
    );
  }
  if (bulk.length > 0) {
    whyParts.push('bulk-reads object storage across a broad resource scope');
  }
  out.push(
    makeFinding('DATA-EXFIL', stmt, {
      severity: highSeverity ? 'high' : 'medium',
      policyEvidence: 'high',
      actions: matched,
      resources: resourceScope(stmt),
      why:
        `Grants actions that ${whyParts.join(' and ')}. A principal with this ` +
        'can copy sensitive data out of the account.',
      remediation:
        'Scope the read to the specific secrets/keys/objects required and gate ' +
        'with conditions (e.g. source VPC/identity); avoid granting on "*".',
    }),
  );
}

// 4a-bis. KMS decryption capability. Kept SEPARATE from DATA-EXFIL (IAM-103):
// kms:Decrypt does not enumerate or retrieve secrets - it decrypts ciphertext
// the principal can supply, for KMS keys it is permitted to use. Fires whether
// or not the resource scope is broad (the capability exists either way);
// severity is higher when the key scope is broad.
function ruleKmsDecrypt(stmt, out) {
  const matched = matchPatterns(stmt, KMS_DECRYPT_ACTIONS, false);
  if (matched.length === 0) return;
  const broad = resourceIsBroad(stmt);
  out.push(
    makeFinding('KMS-DECRYPT', stmt, {
      severity: broad ? 'high' : 'medium',
      policyEvidence: 'high',
      actions: matched,
      resources: resourceScope(stmt),
      why:
        'Grants kms:Decrypt, a decryption capability: it turns ciphertext the ' +
        'principal can supply into plaintext for KMS keys the principal is ' +
        'permitted to use. This does not by itself enumerate or retrieve stored ' +
        'secrets; its impact depends on which keys are in scope and what ' +
        'ciphertext the principal can reach.',
      remediation:
        'Scope kms:Decrypt to the specific key ARNs required and gate it with ' +
        'condition keys (e.g. kms:ViaService, kms:EncryptionContext) so the key ' +
        'is only usable in the intended context.',
    }),
  );
}

// S1-R1-deny-fence-surviving: the WHOLE-CONTAINER read classifier, extracted from
// ruleDataReadScoped's body into a STATEMENT-INDEPENDENT helper so the identical
// breadth/account logic serves TWO callers with NO drift:
//   1. ruleDataReadScoped - classifies the Allow's OWN resource list (subject-gated,
//      unchanged), and
//   2. survivingSparedContainerReads (analyze.js post-pass) - classifies the PROVEN
//      SURVIVING spared set of a NotResource Deny fence, which no per-statement rule
//      could ever see (the rule loop is Deny-unaware when it emits findings).
//
// Given a set of concrete resource ARNs + the matched read actions, it partitions the
// WHOLE-CONTAINER reads (bucket/*, table/<id>, stream/<id>, ... - a single concrete
// OBJECT read like bucket/key is excluded by isWholeContainerRead and stays QUIET) into:
//   - undetResources: canonical S3 bucket ARNs whose owning account is UNRESOLVABLE
//     (no account field, no pinning condition). Collected REGARDLESS of subjectAccount -
//     an account-blind bucket read cannot be cleared same-account whether or not a subject
//     was supplied (threat-model: S3 bucket ARNs are account-blind), so silence here is a
//     fail-OPEN. Whether a sensitivity-token / ${...}-variable bare bucket is ALSO
//     collected is caller-dependent via opts.collectSensitiveVariable: the ruleDataReadScoped
//     caller (flag false) leaves it to that rule's own DATA-READ fall-through (avoids a
//     double report), but the survivingSparedContainerReads caller (flag true) MUST collect
//     it because its BROAD Allow has no DATA-READ fall-through, so excluding it would let the
//     highest-value exfil targets read silently CLEAN behind a fence (R1 iteration-2).
//   - crossResources / crossAccounts: account-BEARING (or condition-pinned) whole-
//     container reads whose owner DIFFERS from a KNOWN subject account. Only surfaced
//     when the subject is KNOWN; a resolvable owner with an UNKNOWN subject cannot be
//     compared and stays conservatively QUIET (same as the threat-model's scoped-read
//     rule). A resolved SAME-account owner is QUIET.
// crossSensitive RAISES the cross finding's severity; it never gates reporting.
//
// `broad` mirrors DATA-EXFIL's precondition: when true, a broad S3 object BULK read
// (s3:GetObject/GetObjectVersion) is DATA-EXFIL's to report LOUDLY, so it is skipped
// here to avoid a double report. Callers classifying an already-fenced NARROW spared
// set pass broad=false (DATA-EXFIL was suppressed by the fence, so the fenced remnant
// MUST surface here). Deterministic; never throws. `chargeUnit` (>0) charges the work
// budget per resource so both the deterministic ceiling and the wall-clock deadline can
// abort a runaway mid-loop.
function classifyContainerReads(resources, actions, opts) {
  const condAccount = opts && opts.condAccount != null ? opts.condAccount : null;
  const subjectAccount = opts && opts.subjectAccount != null ? opts.subjectAccount : null;
  const broad = !!(opts && opts.broad);
  const chargeUnit = opts && Number.isFinite(opts.chargeUnit) ? opts.chargeUnit : 0;
  // collectSensitiveVariable=true tells the classifier to ALSO collect account-less S3
  // spared buckets whose name infers sensitivity or that carry a ${...} policy variable
  // into the UNDETERMINED set. See the undet-collection guard below for why this flag is
  // caller-dependent (the fence caller needs it, ruleDataReadScoped must NOT set it).
  const collectSensitiveVariable = !!(opts && opts.collectSensitiveVariable);
  // Arrays preserve deterministic insertion order; the parallel Sets give O(1)
  // membership so the dedup is LINEAR, not an O(resources^2) includes() scan.
  const crossResources = [];
  const crossResourceSet = new Set();
  const crossAccounts = [];
  const crossAccountSet = new Set();
  let crossSensitive = false;
  const undetResources = [];
  const undetResourceSet = new Set();
  if (!Array.isArray(resources) || !Array.isArray(actions) || actions.length === 0) {
    return { crossResources, crossAccounts, crossSensitive, undetResources };
  }
  for (const r of resources) {
    // Charge the real inner-loop work so BOTH the deterministic work budget and the
    // CLI/Action wall-clock deadline (each sampled only inside chargeWork) can abort
    // this scan mid-loop. The filter below performs one isWholeContainerRead parse per
    // matched action, so `chargeUnit` (actions.length at the call site) is the exact
    // per-resource cost. Proportional, so a normal-size policy charges negligibly.
    if (chargeUnit > 0) chargeWork(chargeUnit);
    const wholeContainerActions = actions.filter((p) => isWholeContainerRead(p, r));
    if (wholeContainerActions.length === 0) continue; // single object -> QUIET
    // A BROAD S3 object bulk read (s3:GetObject/GetObjectVersion on a broad ARN) is
    // already reported LOUDLY by DATA-EXFIL for this same statement; don't double-
    // report it here. The non-S3 datastore primitives (dynamodb/kinesis/rds-data) and
    // s3:ListBucket are NOT in DATA-EXFIL's broad bulk catalog, so a broad cross-account
    // read of THOSE would otherwise stay silently CLEAN. Match by grant semantics (a
    // broad "s3:Get*" also grants s3:GetObject), not literal action equality.
    if (broad
      && wholeContainerActions.every((p) => BULK_READ_ACTIONS.some((a) => actionGrants(p, a)))) {
      continue;
    }
    // Resolve the owning account: the ARN's account, else an explicit ResourceAccount
    // condition. Only a canonical S3 bucket ARN leaves this null.
    const acct = concreteResourceAccount(r) || condAccount;
    if (acct) {
      // A resolvable owner can only be compared to a KNOWN subject; without one we
      // cannot tell same- from cross-account, so stay conservatively QUIET.
      if (!subjectAccount) continue;
      if (acct === subjectAccount) continue; // resolved SAME-account -> QUIET
      if (!crossResourceSet.has(r)) { crossResourceSet.add(r); crossResources.push(r); }
      if (!crossAccountSet.has(acct)) { crossAccountSet.add(acct); crossAccounts.push(acct); }
      if (resourceInfersSensitive(r)) crossSensitive = true;
      continue;
    }
    // Account UNRESOLVABLE. Two account-less whole-container shapes reach here, and the
    // surfacing is SERVICE-AGNOSTIC (NEW-01, sibling of R1): (1) a canonical S3 bucket ARN
    // (arn:aws:s3:::bucket/*, or a bucket-list target), which carries NO account field by
    // construction; and (2) ANY other datastore ARN (dynamodb table / kinesis stream /
    // rds-data cluster) whose account segment is EMPTY or a WILDCARD - concreteResourceAccount
    // returns null for it just as it does for the S3 bucket, so it lands on this exact branch.
    // Neither can be cleared as same-account, so neither may read CLEAN. Gating this collection
    // on arn.service==='s3' was a fail-OPEN: an account-less dynamodb:Scan / kinesis:GetRecords
    // / rds-data:ExecuteStatement whole-container read (the same archetypal exfil primitive)
    // was dropped and read CLEAN. Whether a sensitivity-token / ${...}-variable resource is
    // COLLECTED here is caller-dependent (unchanged from the S3 case):
    //   - ruleDataReadScoped (collectSensitiveVariable=false): a sensitively-named or
    //     variable-scoped NARROW read ALREADY surfaces via that rule's DATA-READ
    //     fall-through (rules.js DATA-READ finding), so re-collecting it here would
    //     double-report. Only a neutrally-named, non-variable bucket is collected.
    //   - survivingSparedContainerReads (collectSensitiveVariable=true): its Allow is
    //     BROAD, so ruleDataReadScoped short-circuits at `if (broad) return;` and the
    //     DATA-READ fall-through NEVER runs for the spared set - there is no other path.
    //     Excluding sensitive/variable buckets here would therefore let the HIGHEST-value
    //     exfil targets (production-secrets, customer-exports, payroll-backup, and
    //     ${...}-scoped buckets) read silently CLEAN behind a fence - a strict inversion
    //     of the direct-grant behaviour (R1 iteration-2 fail-open). So the fence caller
    //     collects them too; no double report occurs because no DATA-READ fires for it.
    const arn = parseArn(r);
    const alreadySurfacedViaDataRead = !collectSensitiveVariable
      && (resourceInfersSensitive(r) || resourceHasVariable(r));
    // Require a well-formed ARN (as the S3 path always did): a non-ARN / bare "*" resource
    // is handled by the broad-wildcard rules, not surfaced as an account-undetermined read.
    // No service gate: any parseable ARN whose owner is unresolvable is collected.
    if (arn
      && !alreadySurfacedViaDataRead
      && !undetResourceSet.has(r)) {
      undetResourceSet.add(r);
      undetResources.push(r);
    }
  }
  return { crossResources, crossAccounts, crossSensitive, undetResources };
}

// NEW-01: does an undetermined-account resource set consist ENTIRELY of canonical S3
// bucket ARNs (service s3)? When it does, the finding keeps its exact S3-specific
// title/why/remediation (byte-unchanged from the S3-only fix, so the S3 golden baselines
// and the S3 regression suite do not drift). When ANY non-S3 datastore ARN
// (dynamodb/kinesis/rds-data with an empty/wildcard account) is present, the wording
// generalizes so a non-S3 resource is never mislabeled as an "S3 read" (threat-model T8:
// truthful output). Pure inspection of inert ARN strings; deterministic.
function undetAllCanonicalS3(resources) {
  return resources.every((r) => {
    const a = parseArn(r);
    return !!(a && a.service === 's3');
  });
}

// The title/why/remediation for a CROSS-ACCOUNT-DATA-READ-UNDETERMINED finding, chosen by
// whether the surfaced resources are S3-only (exact legacy wording) or include a non-S3
// datastore (service-agnostic wording). `fenced` picks the surviving-spared (R1 post-pass)
// framing over the directly-granted (ruleDataReadScoped) framing. Returning `title:null`
// for the S3-only case leaves makeFinding on its meta.title fallback, so that path is
// byte-identical to before this change.
function undetFindingText(resources, fenced) {
  if (undetAllCanonicalS3(resources)) {
    if (fenced) {
      return {
        title: null,
        why:
          'A broad Allow of this read (Resource "*" / wildcard) is fenced by a same-' +
          'policy NotResource Deny down to a canonical S3 bucket ARN that carries NO ' +
          'account field, and no aws:ResourceAccount / s3:ResourceAccount condition pins ' +
          'the owner. The Deny removes the broad exfil reach (so DATA-EXFIL does not ' +
          'fire), but the SURVIVING spared scope is still a WHOLE-container read (bucket/* ' +
          'or a bucket list) whose owning account cannot be determined from this policy - ' +
          'so the tool CANNOT clear it as a same-account read. This does NOT prove the ' +
          'bucket is in another account (the crossing is undetermined, not confirmed); it ' +
          'means a "no findings" / "complete" verdict here is not a safety claim for the ' +
          'read the fence leaves standing.',
        remediation:
          'Make the surviving read explicit and bounded: pin the owning account with an ' +
          'aws:ResourceAccount (or s3:ResourceAccount) condition, or use an account-' +
          'bearing S3 access-point ARN, and scope the read to the specific keys required. ' +
          'If the spared bucket is not intended to be readable, remove it from the Deny\'s ' +
          'NotResource carve-out (which is what keeps it reachable).',
      };
    }
    return {
      title: null,
      why:
        'Grants a whole-container read (bucket/* or a bucket list) on a canonical ' +
        'S3 bucket ARN that carries NO account field, and no aws:ResourceAccount / ' +
        's3:ResourceAccount condition pins the owner. The bucket\'s owning account ' +
        'therefore cannot be determined from this policy, so the tool CANNOT clear ' +
        'it as a same-account read - it may be a cross-account read of another ' +
        'account\'s bucket. This does NOT prove the bucket is in another account ' +
        '(the crossing is undetermined, not confirmed); it means a "no findings" / ' +
        '"complete" verdict here is not a safety claim for this read.',
      remediation:
        'Make the owning account explicit so the read can be cleared or flagged: ' +
        'pin it with an aws:ResourceAccount (or s3:ResourceAccount) condition, or ' +
        'use an account-bearing S3 access-point ARN. If the bucket is in another ' +
        'account, scope the read to the specific keys required and gate it with ' +
        'conditions; if it is your own, the condition removes this ambiguity.',
    };
  }
  // Service-agnostic wording (a non-S3 datastore ARN is present). Covers a canonical S3
  // bucket AND an empty/wildcard-account dynamodb/kinesis/rds-data ARN in one statement.
  const title = 'Whole-container read with an undeterminable owning account';
  if (fenced) {
    return {
      title,
      why:
        'A broad Allow of this read (Resource "*" / wildcard) is fenced by a same-policy ' +
        'NotResource Deny down to a resource whose owning account cannot be determined ' +
        'from this policy: the resource ARN carries no concrete account field (a canonical ' +
        'S3 bucket ARN, or an empty/wildcard account segment on a table / stream / database ' +
        'ARN) and no aws:ResourceAccount / s3:ResourceAccount condition pins the owner. The ' +
        'Deny removes the broad exfil reach (so DATA-EXFIL does not fire), but the SURVIVING ' +
        'spared scope is still a WHOLE-container read (bucket/*, a bucket list, or a table / ' +
        'stream / database bulk read) whose owning account cannot be determined - so the ' +
        'tool CANNOT clear it as a same-account read. This does NOT prove the resource is in ' +
        'another account (the crossing is undetermined, not confirmed); it means a "no ' +
        'findings" / "complete" verdict here is not a safety claim for the read the fence ' +
        'leaves standing.',
      remediation:
        'Make the surviving read explicit and bounded: pin the owning account with an ' +
        'aws:ResourceAccount (or s3:ResourceAccount) condition, or use an account-bearing ' +
        'resource ARN (an S3 access-point ARN, or a table / stream / database ARN carrying ' +
        'the owning account), and scope the read to the specific keys/items required. If a ' +
        'spared resource is not intended to be readable, remove it from the Deny\'s ' +
        'NotResource carve-out (which is what keeps it reachable).',
    };
  }
  return {
    title,
    why:
      'Grants a whole-container read (bucket/*, a bucket list, or a table / stream / ' +
      'database bulk read) on a resource whose owning account cannot be determined from ' +
      'this policy: the resource ARN carries no concrete account field (a canonical S3 ' +
      'bucket ARN, or an empty/wildcard account segment on a table / stream / database ' +
      'ARN) and no aws:ResourceAccount / s3:ResourceAccount condition pins the owner. The ' +
      'tool therefore CANNOT clear it as a same-account read - it may be a cross-account ' +
      'read of another account\'s resource. This does NOT prove the resource is in another ' +
      'account (the crossing is undetermined, not confirmed); it means a "no findings" / ' +
      '"complete" verdict here is not a safety claim for this read.',
    remediation:
      'Make the owning account explicit so the read can be cleared or flagged: pin it ' +
      'with an aws:ResourceAccount (or s3:ResourceAccount) condition, or use an account-' +
      'bearing resource ARN (an S3 access-point ARN, or a table / stream / database ARN ' +
      'carrying the owning account). If the resource is in another account, scope the read ' +
      'to the specific keys/items required and gate it with conditions; if it is your own, ' +
      'the account-bearing ARN or condition removes this ambiguity.',
  };
}

// 4a-ter. Resource-scoped / variable-scoped data read (IAM-706, acceptance
// tests 7 + 21). DATA-EXFIL only flags a bulk object read when the resource
// scope is BROAD (Resource "*"); a read scoped to a NAMED bucket or a policy-
// VARIABLE resource is left as routine there. This rule fills that gap with a
// LOWER-CERTAINTY, neutrally-framed "data-read capability" finding, and ONLY when
// there is a reason to surface it:
//   - the resource name INFERS sensitivity (e.g. "production-exports") - stated
//     as inferred-from-naming, never as proven; or
//   - the resource is policy-VARIABLE scoped (e.g. ${aws:username}) - the ARN
//     cannot be resolved from the policy text, so the objects in scope are
//     uncertain and the variable is preserved verbatim.
// A neutrally-named, concrete scoped read (routine least privilege) stays quiet,
// so this never fires on the safe/scoped-read fixtures. Severity is medium and
// confidence medium-or-lower - a scoped read is strictly less than a wildcard /
// broad-exfil grant and must never escalate to critical or claim every object is
// readable (S3 encryption config + KMS key policy are absent from the context).
function ruleDataReadScoped(stmt, out, ctx) {
  // A NotResource complement (resources empty) is not a named read.
  if (stmt.resources.length === 0) return;
  const matched = matchPatterns(stmt, DATA_READ_ACTIONS, false);
  if (matched.length === 0) return;

  // S2-crossaccount-scoped-surface iteration-2 (finding #2, fail-open close): the
  // SAME-account name/variable path below is DATA-EXFIL's job when the scope is broad
  // and returns early, BUT the cross-account whole-container detection MUST run FIRST,
  // regardless of broadness. A wildcard resource-id in a KNOWN foreign account
  // (e.g. arn:aws:kinesis:...:999999999999:stream/*) is a strictly-BROADER cross-
  // account read than a concrete one (stream/events), yet before this fix it routed
  // through the resourceIsBroad early-return and read CLEAN while the narrower read
  // fired - evadable by simply widening the ARN. The strictly-broader read must never
  // be CLEAN while the narrower one fires, so cross-account is evaluated before the
  // broad early-return.
  const broad = resourceIsBroad(stmt);

  // --- S2-crossaccount-scoped-surface (B): cross-account whole-container read. -----
  // Only meaningful when the analyzed/subject account is KNOWN (via context/trust).
  // A WHOLE-CONTAINER read (bucket/*, table/<id>, stream/<id>, ...) whose concrete
  // resource account differs from the subject account is surfaced REGARDLESS of the
  // resource name - the sensitivity wordlist below only RAISES severity, it never
  // gates whether this cross-account finding is reported (fail closed: a scoped read
  // that leaves the account must not read CLEAN). A single concrete OBJECT read
  // (bucket/key) stays QUIET (isWholeContainerRead excludes it), and same-account
  // scoped container reads fall through to the QUIET name/variable-gated path below.
  // Without a known subject we cannot tell same- from cross-account, so we stay
  // conservative and skip straight to that same-account path.
  const rawSubject = ctx && ctx.subjectAccount != null ? String(ctx.subjectAccount) : null;
  const subjectAccount = rawSubject && CONCRETE_ACCOUNT_ID_RE.test(rawSubject)
    ? rawSubject : null;
  if (subjectAccount) {
    // The owner an explicit aws:ResourceAccount / s3:ResourceAccount condition pins
    // (or null). This RECOVERS the account for a canonical S3 bucket ARN, whose ARN
    // carries none, so an operator-asserted owner classifies it same- vs cross-account
    // soundly instead of failing open to CLEAN.
    const condAccount = resourceAccountFromCondition(stmt);
    // Classify the Allow's OWN resource list for whole-container cross-account /
    // account-undetermined reads (S1-R1: the shared, stmt-independent classifier - the
    // survivingSparedContainerReads post-pass runs the SAME body on a Deny's spared set).
    const { crossResources, crossAccounts, crossSensitive, undetResources } =
      classifyContainerReads(stmt.resources, matched, {
        condAccount, subjectAccount, broad, chargeUnit: matched.length,
      });
    if (undetResources.length > 0) {
      // S3-only keeps the exact legacy wording (title:null -> meta.title); a present non-S3
      // datastore ARN generalizes it so nothing is mislabeled as an "S3 read" (NEW-01).
      const text = undetFindingText(undetResources, false);
      out.push(
        makeFinding('CROSS-ACCOUNT-DATA-READ-UNDETERMINED', stmt, {
          // INFO: the account crossing is UNPROVEN (the owner is unknown), so this must
          // never be presented as loudly as a confirmed cross-account read.
          severity: 'info',
          // The whole-container grant is plainly present -> evidence HIGH. Whether it
          // actually crosses an account boundary, and whether the data is reachable, both
          // depend on facts absent from an account-less resource ARN -> exploitability LOW.
          policyEvidence: 'high',
          pathExploitability: 'low',
          actions: matched,
          resources: undetResources.slice(),
          title: text.title,
          why: text.why,
          remediation: text.remediation,
        }),
      );
    }
    if (crossResources.length > 0) {
      const scope = crossAccounts.length === 1
        ? 'account ' + crossAccounts[0]
        : 'accounts ' + crossAccounts.join(', ');
      out.push(
        makeFinding('CROSS-ACCOUNT-DATA-READ', stmt, {
          // LOW/INFO band. The sensitivity wordlist RAISES info -> low; it never
          // gates whether this cross-account finding is reported.
          severity: crossSensitive ? 'low' : 'info',
          // The grant + concrete cross-account ARN are plainly present -> evidence
          // HIGH. Whether the objects are actually reachable depends on the target
          // account's resource policy (bucket/table policy), out of scope -> low.
          policyEvidence: 'high',
          pathExploitability: 'low',
          actions: matched,
          resources: crossResources.slice(),
          why:
            'Grants a whole-container read (bucket / table / stream / database bulk ' +
            'read) on a resource in ' + scope + ', a DIFFERENT AWS account than the ' +
            'analyzed principal (account ' + subjectAccount + '). This is a cross-' +
            'account data-read capability regardless of the resource name. Whether ' +
            'the data is actually reachable depends on the target account\'s resource ' +
            'policy (e.g. the bucket policy / table resource policy) and any KMS key ' +
            'policy, none of which are in the supplied context, so it does not prove ' +
            'the data is readable - only that this identity policy grants the read.',
          remediation:
            'Confirm the principal is intended to read data in ' + scope + '. If so, ' +
            'scope the read to the specific objects/keys required and gate it with ' +
            'conditions (e.g. aws:ResourceAccount, aws:SourceVpc). If not, remove the ' +
            'cross-account resource from the scope.',
        }),
      );
      return; // the cross-account fact subsumes the same-account name/variable path
    }
  }

  // The SAME-account name/variable-gated path is DATA-EXFIL's job when the scope is
  // broad; only NON-broad named/variable reads reach it. (Broad cross-account reads
  // were already handled above, before this early return.)
  if (broad) return;

  const sensitiveTokens = [];
  let hasVariable = false;
  for (const r of stmt.resources) {
    const tok = resourceInfersSensitive(r);
    if (tok && !sensitiveTokens.includes(tok)) sensitiveTokens.push(tok);
    if (resourceHasVariable(r)) hasVariable = true;
  }
  // Only surface a finding when sensitivity is inferable from naming OR the read
  // is variable-scoped. Otherwise a scoped read is routine and produces nothing.
  if (sensitiveTokens.length === 0 && !hasVariable) return;

  const whyParts = [];
  if (sensitiveTokens.length > 0) {
    whyParts.push(
      'the resource name(s) suggest sensitive data (matched "' +
        sensitiveTokens.join('", "') +
        '"), so sensitivity is INFERRED from naming and is NOT proven',
    );
  }
  if (hasVariable) {
    whyParts.push(
      'the resource ARN contains an IAM policy variable (e.g. ${aws:username}) ' +
        'that cannot be resolved to a concrete ARN from the policy text alone, so ' +
        'the exact objects in scope remain uncertain',
    );
  }
  out.push(
    makeFinding('DATA-READ', stmt, {
      severity: 'medium',
      policyEvidence: 'medium',
      // A variable-scoped read carries extra irreducible uncertainty about which
      // objects are actually reachable, so its path-exploitability sits a notch
      // below a named-but-concrete scoped read.
      pathExploitability: hasVariable ? 'low' : 'medium',
      actions: matched,
      resources: resourceScope(stmt),
      why:
        'Grants a data-read capability: the principal can read objects from the ' +
        'named or variable-scoped resource because ' +
        whyParts.join('; and ') +
        ". This is a scoped read, not a broad exfiltration grant, and the " +
        "account's S3 encryption configuration and any KMS key policy are not in " +
        'the supplied context, so it does not prove every object is readable.',
      remediation:
        'Confirm the principal needs read access to this data; scope the read to ' +
        'the specific object prefixes required and gate it with conditions (e.g. ' +
        'aws:SourceVpc / aws:SourceVpce) so the data cannot be pulled from ' +
        'arbitrary networks.',
    }),
  );
}

// S1-R1-deny-fence-surviving (iteration 4): does SOME same-policy Deny - OTHER than the
// NotResource fence that spared `r` - ENTIRELY remove the read of `r`, so it is not a
// surviving capability? Used to subtract the rest of the Deny set from the fence's spared
// set (AWS explicit-Deny precedence): a bucket a fence spares can still be net-UNREADABLE
// because another Deny covers it. Returns true only when `r` is entirely denied for EVERY
// fenced action (if any fenced action can still read `r`, the capability survives - we fail
// closed toward REPORTING, never over-suppressing a genuine spare). A single Deny D
// entirely denies `r` when it is unconditional (a conditional Deny may not apply at runtime,
// so it is never definitive) AND certainly applies to the action AND its resource scope
// covers all of `r`:
//   - Resource-form Deny (positive Resource list): some Resource pattern glob-covers `r`
//     (a bare "*" blanket, an ARN-wildcard superset, or the exact ARN all qualify);
//   - NotResource-form Deny: it denies everything EXCEPT its spared set, so it entirely
//     denies `r` iff its spared set is DISJOINT from `r` - no NotResource pattern is related
//     to `r` in either direction (neither globMatch(p, r) nor globMatch(r, p)). The fence
//     that spared `r` naturally excludes itself here (it is related to `r`), as does any
//     other fence whose carve-out overlaps `r` (part of `r` stays readable -> not entire).
// Deterministic; never throws. globMatch treats the pattern's wildcards specially and the
// value literally, and IAM ARNs are case-sensitive, so the comparisons are exact.
function denyEntirelyDeniesResource(deny, r, action) {
  if (hasNonEmptyCondition(deny)) return false;
  const app = denyActionApplies(deny, action);
  if (!app.applies || !app.certain) return false;
  if (deny.notResources.length > 0) {
    // Denies all-except-spared: entire only if the spared set is disjoint from r.
    const relatedToSpare = deny.notResources.some(
      (p) => globMatch(p, r) || globMatch(r, p),
    );
    return !relatedToSpare;
  }
  if (deny.resources.length > 0) {
    // Positive Resource Deny: entire only if some pattern covers all of r.
    return deny.resources.some((p) => globMatch(p, r));
  }
  // A Deny with neither Resource nor NotResource does not bound a resource -> not definitive.
  return false;
}

// r survives only if, for EVERY fenced action, NO other same-policy Deny entirely denies it.
function sparedResourceFullyDeniedElsewhere(r, fencedActions, denies) {
  return fencedActions.every(
    (action) => denies.some((deny) => denyEntirelyDeniesResource(deny, r, action)),
  );
}

// S1-R1-deny-fence-surviving (iteration 6): does the BROAD Allow actually grant read
// access to a spared resource `r`? A broad Allow comes in two shapes and the grant test
// differs per shape (the surviving read is the spared set INTERSECT the Allow's OWN grant -
// a bucket the Allow never grants is not a surviving capability, threat-model T8):
//   - POSITIVE Resource list (Resource:"*" / arn:aws:s3:::prod-*/*): the Allow grants `r`
//     iff some Resource pattern glob-covers it (case-sensitive; IAM ARNs are case-sensitive).
//     The bare "*" covers every spared ARN (a no-op filter); an ARN-wildcard can leave a
//     spared bucket ENTIRELY OUTSIDE the grant.
//   - NotResource COMPLEMENT (empty stmt.resources): the Allow grants every resource EXCEPT
//     its carve-out, so it grants `r` UNLESS its OWN NotResource entirely excludes it. Mirror
//     of denyEntirelyDeniesResource's NotResource arm: the Allow entirely fails to grant `r`
//     iff some Allow-NotResource pattern glob-covers all of `r` (globMatch(pat, r)); a
//     disjoint or merely-partial exclusion leaves part of `r` granted -> still a surviving
//     read -> fail CLOSED toward reporting. `r` is itself a proven-NARROW spared pattern, so
//     it is compared literally by globMatch exactly as the positive-list path compares it.
// Deterministic; never throws.
function allowGrantsSparedResource(allowStmt, isComplementAllow, r) {
  if (isComplementAllow) {
    return !allowStmt.notResources.some((pat) => globMatch(pat, r));
  }
  return allowStmt.resources.some((pat) => globMatch(pat, r));
}

/**
 * S1-R1-deny-fence-surviving: surface the WHOLE-CONTAINER read that SURVIVES a
 * NotResource-Deny fence on a broad Allow - the residual capability no per-statement
 * rule can see.
 *
 * The rule catalog is deliberately Deny-UNAWARE when it EMITS findings (RULE_FUNCTIONS
 * take (stmt,out,ctx), no denies), so a broad exfil Allow (s3:GetObject Resource:*) that
 * a Deny NotResource fences down to one spared bucket is handled ONLY by SUPPRESSION:
 * denyFencesToNarrow proves the spared set NARROW, ruleFindingDenySuppressed drops
 * DATA-EXFIL, and survivingBroadReadActions keeps the coverage net quiet. Nothing then
 * examines the PROVEN SURVIVING spared resource for ITS OWN risk - a live whole-bucket
 * read (the archetypal exfil primitive) read CLEAN/exit-0 (R1 fail-open, threat-model T8).
 *
 * This helper is invoked from the analyze.js post-pass (which HAS the denies in scope,
 * exactly where survivingBroadReadActions already runs) and reuses the SAME breadth /
 * account classifier as ruleDataReadScoped (classifyContainerReads - no drift). For each
 * broad Allow whose matched read actions a NotResource Deny fences to a proven-narrow
 * spared set, it classifies the PROVEN SURVIVING set - the spared NotResource resources
 * INTERSECTED with the broad Allow's own resource scope (not the raw NotResource array, and
 * not the Allow's "*"), so a spared bucket the Allow never grants (an ARN-wildcard Allow that
 * does not cover the spare) yields no fabricated finding - and derives a finding when the
 * surviving read is a whole container:
 *   - CROSS-ACCOUNT-DATA-READ-UNDETERMINED (account-blind S3 bucket) - surfaced whether
 *     or not a subject account is supplied (like DATA-EXFIL, it never needed one), OR
 *   - CROSS-ACCOUNT-DATA-READ (resolvable owner != KNOWN subject).
 * Never DATA-EXFIL (ruleFindingDenySuppressed's bulk-fence exemption is hardcoded
 * id===DATA-EXFIL, which would instantly re-suppress it). A genuinely single-object
 * spared read, a same-account-resolvable whole-bucket spared read, and an
 * unrelated-service / condition-mismatched Deny all stay QUIET (the classifier + the
 * fence proof handle each). Deterministic; never throws.
 *
 * @param {object} model normalized, frozen model from buildModel()
 * @param {{subjectAccount?:string}} [ctx] optional analysis context
 * @returns {Array<object>} derived findings (canonical shape); [] when none
 */
export function survivingSparedContainerReads(model, ctx) {
  const out = [];
  if (!model || !Array.isArray(model.statements)) return out;
  // The same identity-statement Deny set ruleFindingDenySuppressed / the escalation
  // engine use (a Deny that names a Principal is a resource/trust-policy statement, not
  // an identity constraint on the analyzed subject).
  const denies = model.statements.filter((s) => s && s.effect === 'Deny' && s.principal == null);
  if (denies.length === 0) return out;
  const rawSubject = ctx && ctx.subjectAccount != null ? String(ctx.subjectAccount) : null;
  const subjectAccount = rawSubject && CONCRETE_ACCOUNT_ID_RE.test(rawSubject) ? rawSubject : null;

  for (const stmt of model.statements) {
    if (!stmt || stmt.effect !== 'Allow') continue;
    if (statementNeverMatches(stmt)) continue;
    // Only a BROAD Allow is fenced down to a spared set (a narrow Allow's effective scope
    // is its own resources - already ruleDataReadScoped's job). Mirrors DATA-EXFIL's broad
    // precondition, so this fires exactly where the fence suppressed the broad read. A broad
    // Allow has TWO shapes and BOTH must be handled (iteration-6 fail-open): a POSITIVE
    // Resource list carrying a broad ARN (Resource:"*" / arn:aws:s3:::*/*), and a NotResource
    // COMPLEMENT (empty stmt.resources, non-empty stmt.notResources - grants every resource
    // EXCEPT the carve-out). The complement shape formerly bailed here on empty stmt.resources
    // and read CLEAN, because the broad-uncovered NotResource net that comment claimed covered
    // it SKIPS a fence-narrowed action (survivingBroadReadActions returns [] for it). Both
    // shapes are resourceIsBroad() and both can be fenced down to a live spared read; the only
    // per-shape difference is how the Allow's OWN grant is tested against a spared ARN
    // (allowGrantsSparedResource) and how the finding renders its resources (findingStmt below).
    if (!resourceIsBroad(stmt)) continue;
    const isComplementAllow = stmt.resources.length === 0 && stmt.notResources.length > 0;
    const matched = matchPatterns(stmt, DATA_READ_ACTIONS, false);
    if (matched.length === 0) continue;

    // The matched read actions whose broad Allow a NotResource Deny fences to a PROVEN
    // narrow spared set (denyFencesToNarrow proves narrowness + certain application). An
    // unrelated-service Deny (Deny ec2:* NotResource:s3bucket) does not fence an s3 read,
    // so it contributes nothing - no bogus S3 finding.
    const fencedActions = matched.filter((a) => denyFencesToNarrow(denies, a, stmt));
    if (fencedActions.length === 0) continue;

    // The PROVEN SURVIVING resource set = the union of the spared NotResource sets of the
    // denies that ACTUALLY fence one of the fenced actions (same proof denyFencesToNarrow
    // used: unconditional, spared set every-element NARROW, certain application). Restated
    // locally so only a fence that truly narrows a matched action contributes its spare.
    const spared = [];
    const sparedSet = new Set();
    for (const deny of denies) {
      if (hasNonEmptyCondition(deny)) continue;
      if (deny.notResources.length === 0) continue;
      if (deny.notResources.some((r) => classifyResource(r) !== RESOURCE_CLASS.NARROW)) continue;
      const fencesAMatchedAction = fencedActions.some((a) => {
        const app = denyActionApplies(deny, a);
        return app.applies && app.certain;
      });
      if (!fencesAMatchedAction) continue;
      for (const r of deny.notResources) {
        if (!sparedSet.has(r)) { sparedSet.add(r); spared.push(r); }
      }
    }
    if (spared.length === 0) continue;

    // R1 iteration-3 (over-correction close): classify the PROVEN SURVIVING
    // Allow-INTERSECT-Deny set, NEVER the raw NotResource union. denyFencesToNarrow proves
    // the spared set NARROW and that the Deny certainly applies, but a spared ARN is only
    // actually READABLE if the broad Allow's OWN resource scope grants it. When the Allow is
    // the bare "*", every spared ARN is a subset and this filter is a no-op (the only fenced
    // shape the core R1 repro exercises). But an ARN-WILDCARD broad Allow (e.g.
    // arn:aws:s3:::prod-*/*) can leave a spared bucket ENTIRELY OUTSIDE its grant: the
    // prod-* objects are DENIED (not in the spared set) and the spared acme-competitor bucket
    // is NOT granted by the Allow -> net ZERO readable. Classifying the raw spared set there
    // fabricates a finding on a bucket the policy grants no access to (threat-model T8:
    // truthfulness). Keep only spared resources the Allow actually matches (case-sensitive
    // ARN globMatch against each Allow Resource pattern, as IAM ARNs are case-sensitive);
    // a spared resource outside the Allow's grant is not a surviving capability and is dropped.
    // Shape-aware (iteration-6): a POSITIVE-Resource Allow grants a spared ARN when a Resource
    // pattern glob-covers it; a NotResource-COMPLEMENT Allow grants it UNLESS its own carve-out
    // entirely excludes it (allowGrantsSparedResource). For the complement repro the carve-out
    // (excluded/*) is disjoint from the spared acme-competitor bucket, so the spared read
    // survives; a complement Allow whose carve-out IS the spared bucket yields net-ZERO -> drop.
    const survivingAllow = spared.filter((r) => allowGrantsSparedResource(stmt, isComplementAllow, r));
    if (survivingAllow.length === 0) continue;

    // R1 iteration-4 (over-correction close): a spared resource is a surviving capability
    // only if the READ genuinely survives the WHOLE Deny set, not the single fence that
    // spared it. AWS explicit-Deny precedence can remove the spare AGAIN through another
    // same-policy Deny, leaving it net-UNREADABLE - reporting it then is a fabricated
    // finding (threat-model T8 noise). The previous step unioned each fence's spared set;
    // here we SUBTRACT everything the rest of the Deny set removes, so the result is the
    // true surviving set (spared-by-fence MINUS denied-elsewhere) rather than the raw union.
    // Three concrete over-reports this closes, all net-ZERO readable and each proven per the
    // SAME deny primitives (unconditional + denyActionApplies certain, no drift):
    //   - two NotResource fences on the same action sparing DIFFERENT buckets (reading
    //     bucket-a is denied by the bucket-b fence and vice-versa: the surviving set is the
    //     INTERSECTION of the fences' spared sets, not their union);
    //   - a fence plus an explicit Resource-Deny on the SAME spared bucket;
    //   - a fence plus a BLANKET Deny (Resource "*", or a whole-service s3:* Resource "*").
    // A resource is dropped ONLY when it is ENTIRELY denied for EVERY fenced action (if any
    // fenced action can still read it, the capability survives - fail closed toward
    // REPORTING, never over-suppress a real spare: the iter-4 true-positive twins - an
    // unrelated extra Deny, and two fences sparing the SAME bucket - must still fire).
    const surviving = survivingAllow.filter(
      (r) => !sparedResourceFullyDeniedElsewhere(r, fencedActions, denies),
    );
    if (surviving.length === 0) continue;

    // Classify the SURVIVING spared resources. broad=false: the spared set is proven
    // NARROW and DATA-EXFIL was already suppressed by the fence, so the broad-bulk dedup
    // guard must NOT skip it (the fenced remnant MUST surface). The undetermined path is
    // subjectAccount-INDEPENDENT (unlike ruleDataReadScoped's subject-gated own-resource
    // path): a fenced whole-container read must not become CLEAN merely because the fence
    // narrowed it to one bucket and no subject was supplied.
    // collectSensitiveVariable: true - unlike ruleDataReadScoped, the fenced BROAD Allow
    // has NO DATA-READ fall-through (it early-returns on broadness), so a sensitively-named
    // or ${...}-variable spared bucket has no other surfacing path; collect it here or it
    // reads silently CLEAN (R1 iteration-2 fail-open: the highest-value exfil targets were
    // the ONLY fenced shape staying clean).
    const condAccount = resourceAccountFromCondition(stmt);
    const { crossResources, crossAccounts, crossSensitive, undetResources } =
      classifyContainerReads(surviving, fencedActions, {
        condAccount, subjectAccount, broad: false,
        chargeUnit: fencedActions.length, collectSensitiveVariable: true,
      });

    // The finding must render the SURVIVING SPARED resources positively. makeFinding treats a
    // statement that carries NotResource as a complement grant and forces resources:[] (the
    // carve-out rides in excludedResources), so passing the raw complement Allow would NOT
    // render the spared bucket. A rendering shim carries the statement's identity (sid / index
    // / condition) with NO complement axis, so the surviving set passed in `resources` renders
    // exactly as it does for the Resource:"*" form (browser==CLI + star==complement parity). A
    // positive-Resource Allow renders directly (usesNotResource already false).
    const findingStmt = isComplementAllow
      ? { sid: stmt.sid, index: stmt.index, condition: stmt.condition, notActions: [], notResources: [] }
      : stmt;

    if (undetResources.length > 0) {
      // S3-only spared set keeps the exact legacy wording; a present non-S3 datastore ARN
      // generalizes it (NEW-01, fenced framing). The undetermined path is subject-account-
      // INDEPENDENT (see above), so this surfaces whether or not a subject was supplied.
      const text = undetFindingText(undetResources, true);
      out.push(
        makeFinding('CROSS-ACCOUNT-DATA-READ-UNDETERMINED', findingStmt, {
          severity: 'info',
          policyEvidence: 'high',
          pathExploitability: 'low',
          actions: fencedActions,
          resources: undetResources.slice(),
          title: text.title,
          why: text.why,
          remediation: text.remediation,
        }),
      );
    }
    if (crossResources.length > 0) {
      const scope = crossAccounts.length === 1
        ? 'account ' + crossAccounts[0]
        : 'accounts ' + crossAccounts.join(', ');
      out.push(
        makeFinding('CROSS-ACCOUNT-DATA-READ', findingStmt, {
          severity: crossSensitive ? 'low' : 'info',
          policyEvidence: 'high',
          pathExploitability: 'low',
          actions: fencedActions,
          resources: crossResources.slice(),
          why:
            'A broad Allow of this read is fenced by a same-policy NotResource Deny down to ' +
            'a whole-container read (bucket / table / stream / database bulk read) on a ' +
            'resource in ' + scope + ', a DIFFERENT AWS account than the analyzed principal ' +
            '(account ' + subjectAccount + '). The Deny removes the broad exfil reach (so ' +
            'DATA-EXFIL does not fire), but the SURVIVING spared scope is a cross-account ' +
            'data-read capability regardless of the resource name. Whether the data is ' +
            'actually reachable depends on the target account\'s resource policy (e.g. the ' +
            'bucket / table policy) and any KMS key policy, none of which are in the supplied ' +
            'context, so it does not prove the data is readable - only that this identity ' +
            'policy leaves the read standing.',
          remediation:
            'Confirm the principal is intended to read data in ' + scope + '. If so, scope ' +
            'the surviving read to the specific objects/keys required and gate it with ' +
            'conditions (e.g. aws:ResourceAccount, aws:SourceVpc). If not, remove the cross-' +
            'account resource from the Deny\'s NotResource carve-out that keeps it reachable.',
        }),
      );
    }
  }
  return out;
}

// 4b. Destructive actions (generic delete/terminate families), excluding the
// security services handled by DETECTION-IMPAIRMENT.
function ruleDestructive(stmt, out) {
  const matched = [];
  for (const p of stmt.actions) {
    if (isFullWildcard(p)) continue;
    if (isServiceWildcard(p)) continue; // reported by WILDCARD-ACTION
    if (DETECTION_SERVICES.has(actionService(p))) continue; // -> detection rule
    if (DESTRUCTIVE_VERB.test(actionVerb(p))) matched.push(p);
  }
  if (matched.length === 0) return;
  out.push(
    makeFinding('DESTRUCTIVE-ACTION', stmt, {
      severity: 'high',
      policyEvidence: 'high',
      actions: matched,
      resources: resourceScope(stmt),
      why:
        `Grants destructive action(s) ${matched.join(', ')} (delete / terminate ` +
        'family). Misuse or compromise can cause irreversible data or ' +
        'infrastructure loss.',
      remediation:
        'Restrict destructive actions to the specific resources that may be ' +
        'destroyed, require MFA/approval conditions, and enable deletion ' +
        'protection / versioning where available.',
    }),
  );
}

// 4c. Detection / logging impairment.
function ruleDetectionImpairment(stmt, out) {
  const matched = matchPatterns(stmt, DETECTION_ACTIONS, false);
  if (matched.length === 0) return;
  out.push(
    makeFinding('DETECTION-IMPAIRMENT', stmt, {
      severity: 'high',
      policyEvidence: 'high',
      actions: matched,
      resources: resourceScope(stmt),
      why:
        `Grants action(s) that stop or delete security telemetry ` +
        `(${matched.join(', ')}). An attacker can blind CloudTrail / GuardDuty / ` +
        'Config to hide subsequent activity.',
      remediation:
        'Deny these actions organization-wide via an SCP; restrict management of ' +
        'trails/detectors/recorders to a dedicated security role.',
    }),
  );
}

// 5. Allow + NotAction: grants every action EXCEPT the few listed - an easy
// over-grant to under-estimate.
function ruleNotActionAllow(stmt, out) {
  if (stmt.notActions.length === 0) return;
  out.push(
    makeFinding('NOTACTION-ALLOW', stmt, {
      severity: 'high',
      policyEvidence: 'high',
      actions: stmt.notActions,
      resources: resourceScope(stmt),
      why:
        `Allow with NotAction grants EVERY action except ${stmt.notActions.join(', ')}. ` +
        'It does not scope down to a service and usually grants far more than ' +
        'intended, including administrative and destructive actions.',
      remediation:
        'Replace the NotAction Allow with an explicit Action list of only the ' +
        'permissions actually required.',
    }),
  );
}

// IAM-1005 (suite-2 test 36 / suite-3 test 86): dedicated group-membership
// finding. Fires on a CONCRETE grant of iam:AddUserToGroup (or a partial wildcard
// like iam:Add*) - never on a bare "iam:*" / "*", which DIRECT-IAM-ADMIN and
// WILDCARD-ACTION already own (matchPatterns with includeServiceWildcards=false).
function ruleGroupMembership(stmt, out) {
  const matched = matchPatterns(stmt, GROUP_MEMBERSHIP_ACTIONS, false);
  if (matched.length === 0) return;
  // Infer (never confirm) the group's privilege from the Resource group name(s).
  const groupNames = [];
  let anyPrivilegedName = false;
  for (const r of stmt.resources) {
    const name = groupNameFromArn(r);
    if (name) {
      groupNames.push(name);
      if (groupNameSuggestsPrivilege(name)) anyPrivilegedName = true;
    }
  }
  const namePhrase = groupNames.length
    ? `the group name (${groupNames.join(', ')})`
    : 'the group name';
  out.push(
    makeFinding('GROUP-MEMBERSHIP', stmt, {
      // High: the ability to add a user to a POTENTIALLY privileged group is a
      // real privilege-assignment primitive. It is NOT critical: whether it
      // elevates depends on the group's (unknown) attached policies.
      severity: 'high',
      // The grant itself is plainly present (evidence high); whether it elevates
      // depends on the target group's unknown permissions - so exploitability is
      // MEDIUM, the inferred-privilege confidence the requirement calls for.
      policyEvidence: 'high',
      pathExploitability: 'medium',
      actions: matched,
      resources: resourceScope(stmt),
      why:
        'Grants iam:AddUserToGroup: the principal can add a user to the IAM group ' +
        'named by the Resource. The user to add is supplied in the API request and ' +
        'is NOT scoped by this ARN, so any user reachable by the request can be ' +
        'placed into the group; the Resource scopes only WHICH group. The blast ' +
        'radius is whatever policies that group carries - ' +
        (anyPrivilegedName
          ? `${namePhrase} suggests it may be privileged (inferred from the name at ` +
            'medium confidence only), '
          : `inferred at medium confidence from ${namePhrase} alone, `) +
        'which this single policy does not establish. Not equivalent to ' +
        'iam:AttachUserPolicy / iam:PutUserPolicy (a direct policy edit): this ' +
        'assigns privilege only indirectly, through the group.',
      remediation:
        'Scope iam:AddUserToGroup to the specific non-privileged group ARNs it ' +
        'must manage, keep privileged groups out of self-service membership, and ' +
        'review the target group\'s attached policies to confirm its actual reach.',
    }),
  );
}

const RULE_FUNCTIONS = [
  ruleWildcardAction,
  ruleWildcardResource,
  ruleDirectIamAdmin,
  ruleDataExfil,
  ruleKmsDecrypt,
  ruleDataReadScoped,
  ruleDestructive,
  ruleDetectionImpairment,
  ruleNotActionAllow,
  ruleGroupMembership,
];

// --- Public entry points -----------------------------------------------------

/**
 * Analyze a normalized, frozen model for risk findings. Never throws.
 *
 * @param {object} model normalized, frozen model from buildModel()
 * @returns {{ok:boolean, errors:Array<{code:string,message:string,path:?string}>,
 *            findings:Array<object>}} frozen result; findings in deterministic
 *            order (statement index, then rule order).
 */
export function analyzeRules(model, options) {
  const errors = [];
  try {
    if (!model || typeof model !== 'object' || !Array.isArray(model.statements)) {
      errors.push({ code: 'NO_MODEL', message: 'analyzeRules() requires a normalized model.', path: null });
      return Object.freeze({ ok: false, errors: Object.freeze(errors), findings: Object.freeze([]) });
    }

    // S2-crossaccount-scoped-surface (B): an optional analysis context (subjectAccount)
    // flows to the rules; only ruleDataReadScoped reads it (cross-account whole-
    // container read surfacing). Absent/invalid subject -> conservative quiet.
    const ctx = {
      subjectAccount: (options && options.subjectAccount) || null,
    };

    const findings = [];
    for (const stmt of model.statements) {
      // Only Allow statements grant blast radius; a Deny restricts access.
      if (stmt.effect !== 'Allow') continue;
      // suite-3 test 97: a structurally never-match Allow (e.g. an empty
      // ForAnyValue set) grants nothing, so it produces no capability or
      // wildcard-resource finding.
      if (statementNeverMatches(stmt)) continue;
      for (const fn of RULE_FUNCTIONS) fn(stmt, findings, ctx);
    }

    // Deterministic order: by statement index, then by fixed rule order.
    findings.sort((a, b) => {
      if (a.statementIndex !== b.statementIndex) return a.statementIndex - b.statementIndex;
      return RULES[a.id].order - RULES[b.id].order;
    });

    for (const f of findings) deepFreeze(f);
    return Object.freeze({ ok: true, errors: Object.freeze(errors), findings: Object.freeze(findings) });
  } catch (e) {
    // Propagate the cooperative wall-clock budget sentinel (S3-dos-budget) so scan()
    // reports the specific "analysis aborted (resource budget)" fail-closed verdict
    // rather than masking it as a generic internal error.
    if (isGlobBudgetError(e)) throw e;
    errors.push({ code: 'INTERNAL', message: 'Rule analysis failed unexpectedly.', path: null });
    return Object.freeze({ ok: false, errors: Object.freeze(errors), findings: Object.freeze([]) });
  }
}

// A concrete S3 OBJECT-level action ARN must name objects (a key or key prefix),
// e.g. arn:aws:s3:::bucket/* or arn:aws:s3:::bucket/prefix/*. Every S3 action with
// "Object" in its name (GetObject, PutObject, DeleteObjectVersion, ...) operates on
// objects; bucket-level actions (ListBucket, GetBucketPolicy) and the account-level
// ListAllMyBuckets do not. Wildcard action patterns (s3:*, s3:Get*) are owned by
// the WILDCARD-ACTION rule and are not treated as object-level here.
function isS3ObjectAction(pattern) {
  if (isFullWildcard(pattern) || isServiceWildcard(pattern)) return false;
  if (actionService(pattern) !== 's3') return false;
  const verb = actionVerb(pattern);
  if (verb.includes('*')) return false; // a verb wildcard is not a concrete action
  return /object/i.test(verb);
}

// A concrete S3 BUCKET-only resource ARN: arn:aws:s3:::<bucket> with NO key path
// and no wildcard. This identifies the bucket, not any object inside it, so an
// object-level action scoped to it matches no object-read/write request. A bare
// "*", an all-buckets "arn:aws:s3:::*", or an object ARN ("bucket/*") is NOT
// bucket-only and is intentionally excluded (fail closed: only a clear mismatch).
function isS3BucketOnlyArn(resource) {
  return /^arn:aws:s3:::[^/*]+$/.test(String(resource == null ? '' : resource));
}

// A resource an S3 OBJECT-level action can actually match: the bare "*" (all
// resources) or an S3 object ARN carrying a key path (arn:aws:s3:::bucket/...,
// including bucket/*). If a statement offers at least one of these, the object
// action IS effectively scoped and no mismatch exists - the common least-privilege
// pair {s3:GetObject+s3:ListBucket on [bucket, bucket/*]} must stay finding-free.
function isObjectCapableResource(resource) {
  const r = String(resource == null ? '' : resource);
  if (r === '*') return true;
  return /^arn:aws:s3:::[^/]+\/.*/.test(r);
}

/**
 * IAM-1006 (suite-2 test 50): detect object-action vs bucket-only-ARN mismatches.
 * The engine has no full action-to-resource-type catalog, so - rather than
 * silently reporting a complete, empty analysis of a grant that matches nothing -
 * it surfaces the specific, sound case it CAN determine: a concrete S3 object-level
 * action (s3:GetObject family) scoped to a concrete bucket-only ARN. The result
 * feeds a non-blocking COVERAGE warning (marks coverage incomplete; lowers
 * confidence) with bucket-vs-object remediation; it never fabricates a confirmed
 * object-read finding. One entry per Allow statement that mixes >=1 object action
 * with >=1 bucket-only resource. Deterministic; never throws.
 *
 * @param {object} model normalized, frozen model from buildModel()
 * @returns {Array<{statementIndex:number, statementSid:string, actions:string[],
 *            resources:string[], code:string, note:string, remediation:string}>}
 */
export function actionResourceTypeMismatches(model) {
  const out = [];
  if (!model || !Array.isArray(model.statements)) return out;
  for (const stmt of model.statements) {
    if (!stmt || stmt.effect !== 'Allow') continue;
    if (!Array.isArray(stmt.actions) || !Array.isArray(stmt.resources)) continue;
    const objectActions = stmt.actions.filter(isS3ObjectAction);
    if (objectActions.length === 0) continue;
    const bucketOnly = stmt.resources.filter(isS3BucketOnlyArn);
    if (bucketOnly.length === 0) continue;
    // If the statement ALSO offers an object-capable resource (bucket/* or "*"),
    // the object action is effectively scoped and there is no mismatch - the
    // bucket-only ARN is legitimately present for a sibling bucket action
    // (e.g. s3:ListBucket). Only warn when NO resource can serve the object action.
    if (stmt.resources.some(isObjectCapableResource)) continue;
    const example = `${bucketOnly[0]}/*`;
    out.push({
      statementIndex: stmt.index,
      statementSid: statementSid(stmt),
      actions: objectActions.slice(),
      resources: bucketOnly.slice(),
      code: 'ACTION_RESOURCE_TYPE_MISMATCH',
      note:
        `Object-level S3 action(s) ${objectActions.join(', ')} are scoped to the ` +
        `bucket-only ARN(s) ${bucketOnly.join(', ')}, which identify the bucket, ` +
        'not the objects inside it. Object actions require an object-key resource ' +
        `ARN (e.g. ${example}), so as written this grant matches no object request. ` +
        'This is a coverage warning, not a confirmed object-read capability.',
      remediation:
        'Distinguish bucket actions from object actions: object actions ' +
        `(s3:GetObject, s3:PutObject, ...) need an object ARN such as ${example} ` +
        '(or a specific key prefix); bucket actions (s3:ListBucket, ' +
        's3:GetBucketPolicy) use the bucket ARN itself.',
    });
  }
  return out;
}

/**
 * Convenience: run the full text -> validate -> parse -> model -> rules
 * pipeline. Never throws.
 *
 * @param {string} text raw pasted/imported policy text
 * @returns {{ok:boolean, errors:Array, findings:Array<object>}}
 */
export function analyzeRulesFromText(text, options) {
  const m = modelFromText(text);
  if (!m.ok) {
    return Object.freeze({ ok: false, errors: m.errors, findings: Object.freeze([]) });
  }
  return analyzeRules(m.model, options);
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

export default analyzeRules;
