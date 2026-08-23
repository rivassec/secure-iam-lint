// IAM Blast Radius - risk-rule catalog (IAM-004).
//
// Fifth stage of the pipeline (see docs/architecture.md data-flow):
//   text -> validate() -> parse() -> buildModel() -> [ evaluator, rules,
//   escalation ] -> { findings[], graph }
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

// --- Shared capability caveat (mirrors evaluator.js wording) -----------------
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
  'iam:AddUserToGroup',
  'iam:DeleteUserPolicy',
  'iam:DeleteRolePolicy',
]);

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
]);

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
    title: meta.title,
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

// Is the resource scope broad enough that "on everything" is a fair reading?
// True when Resource contains the bare "*", or the statement uses NotResource
// (Allow everything except a few) - both grant across essentially all ARNs.
function resourceIsBroad(stmt) {
  return stmt.resources.includes('*') || stmt.notResources.length > 0;
}

// Does the statement grant at least one non-read (mutating/privileged) action?
// Used to decide whether a wildcard resource is a meaningful risk vs. a routine
// read-only wildcard (e.g. ec2:Describe* on "*").
function grantsNonReadAction(stmt) {
  if (stmt.notActions.length > 0) return true; // Allow NotAction => includes writes
  for (const p of stmt.actions) {
    if (isFullWildcard(p)) return true;
    if (isServiceWildcard(p)) return true;
    const verb = actionVerb(p);
    if (verb === '' || verb === '*') return true; // unknown scope -> treat as write
    if (!READ_VERB.test(verb)) return true;
  }
  return false;
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
    if (deny.notResources.includes('*')) continue; // spared set is everything -> no narrowing
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
  const broadStar = stmt.resources.includes('*');
  out.push(
    makeFinding('WILDCARD-RESOURCE', stmt, {
      severity: broadStar ? 'high' : 'medium',
      policyEvidence: 'high',
      actions: stmt.notActions.length > 0 ? stmt.notActions : stmt.actions,
      resources: resourceScope(stmt),
      why: broadStar
        ? 'Resource "*" leaves the granted action(s) broadly resource-scoped: ' +
          'they apply to every resource in the account rather than a specific ARN.'
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
function ruleDataReadScoped(stmt, out) {
  // Broad scope is DATA-EXFIL's job; a NotResource complement is not a named read.
  if (resourceIsBroad(stmt)) return;
  if (stmt.resources.length === 0) return;
  const matched = matchPatterns(stmt, DATA_READ_ACTIONS, false);
  if (matched.length === 0) return;

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
export function analyzeRules(model) {
  const errors = [];
  try {
    if (!model || typeof model !== 'object' || !Array.isArray(model.statements)) {
      errors.push({ code: 'NO_MODEL', message: 'analyzeRules() requires a normalized model.', path: null });
      return Object.freeze({ ok: false, errors: Object.freeze(errors), findings: Object.freeze([]) });
    }

    const findings = [];
    for (const stmt of model.statements) {
      // Only Allow statements grant blast radius; a Deny restricts access.
      if (stmt.effect !== 'Allow') continue;
      for (const fn of RULE_FUNCTIONS) fn(stmt, findings);
    }

    // Deterministic order: by statement index, then by fixed rule order.
    findings.sort((a, b) => {
      if (a.statementIndex !== b.statementIndex) return a.statementIndex - b.statementIndex;
      return RULES[a.id].order - RULES[b.id].order;
    });

    for (const f of findings) deepFreeze(f);
    return Object.freeze({ ok: true, errors: Object.freeze(errors), findings: Object.freeze(findings) });
  } catch (e) {
    errors.push({ code: 'INTERNAL', message: 'Rule analysis failed unexpectedly.', path: null });
    return Object.freeze({ ok: false, errors: Object.freeze(errors), findings: Object.freeze([]) });
  }
}

/**
 * Convenience: run the full text -> validate -> parse -> model -> rules
 * pipeline. Never throws.
 *
 * @param {string} text raw pasted/imported policy text
 * @returns {{ok:boolean, errors:Array, findings:Array<object>}}
 */
export function analyzeRulesFromText(text) {
  const m = modelFromText(text);
  if (!m.ok) {
    return Object.freeze({ ok: false, errors: m.errors, findings: Object.freeze([]) });
  }
  return analyzeRules(m.model);
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
