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
// resource breadth because reading a secret or decrypting is the exfil act
// itself; severity scales with how broad the resource scope is.
const SECRET_READ_ACTIONS = Object.freeze([
  'secretsmanager:GetSecretValue',
  'kms:Decrypt',
  'ssm:GetParameter',
  'ssm:GetParameters',
  'ssm:GetParametersByPath',
]);

// Bulk object reads. These are only flagged as exfil when the resource scope is
// broad ("s3:GetObject on *"), because a scoped object read is routine.
const BULK_READ_ACTIONS = Object.freeze([
  's3:GetObject',
  's3:GetObjectVersion',
]);

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
  'DESTRUCTIVE-ACTION': Object.freeze({
    id: 'DESTRUCTIVE-ACTION',
    order: 4,
    title: 'Destructive action grant',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
  }),
  'DETECTION-IMPAIRMENT': Object.freeze({
    id: 'DETECTION-IMPAIRMENT',
    order: 5,
    title: 'Detection / logging impairment',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html',
  }),
  'NOTACTION-ALLOW': Object.freeze({
    id: 'NOTACTION-ALLOW',
    order: 6,
    title: 'Allow with NotAction (broad inverse grant)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html',
  }),
});

export const RULE_IDS = Object.freeze(Object.keys(RULES));

// --- Finding factory ---------------------------------------------------------
// Guarantees every finding carries the full canonical shape (architecture.md):
// id, severity, title, statementSid, actions, resources, conditions,
// confidence, why, limit, remediation, ruleVersion, docRef.

function statementSid(stmt) {
  return typeof stmt.sid === 'string' && stmt.sid.length > 0
    ? stmt.sid
    : `(index ${stmt.index})`;
}

function makeFinding(ruleId, stmt, fields) {
  const meta = RULES[ruleId];
  const conditioned = stmt.condition !== null && stmt.condition !== undefined;
  return {
    id: meta.id,
    severity: fields.severity,
    title: meta.title,
    statementSid: statementSid(stmt),
    statementIndex: stmt.index,
    actions: fields.actions.slice(),
    resources: (fields.resources || []).slice(),
    conditions: stmt.condition, // null when absent; inert data otherwise
    confidence: conditioned ? 'medium' : fields.confidence,
    why: fields.why,
    limit: CAPABILITY_LIMIT + (conditioned ? CONDITION_LIMIT : ''),
    remediation: fields.remediation,
    ruleVersion: meta.ruleVersion,
    docRef: meta.docRef,
  };
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

// --- Per-rule evaluation of a single Allow statement -------------------------

// 1. Wildcard action. "*" is critical (all services); "service:*" is high.
function ruleWildcardAction(stmt, out) {
  const full = stmt.actions.filter(isFullWildcard);
  const service = stmt.actions.filter((p) => !isFullWildcard(p) && isServiceWildcard(p));
  if (full.length === 0 && service.length === 0) return;
  if (full.length > 0) {
    out.push(
      makeFinding('WILDCARD-ACTION', stmt, {
        severity: 'critical',
        confidence: 'high',
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
      confidence: 'high',
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
      confidence: 'high',
      actions: stmt.notActions.length > 0 ? stmt.notActions : stmt.actions,
      resources: resourceScope(stmt),
      why: broadStar
        ? 'Resource "*" applies the granted (non-read) action(s) to every ' +
          'resource in the account, so the grant is unscoped.'
        : 'NotResource makes the granted (non-read) action(s) apply to every ' +
          'resource EXCEPT the few listed - typically far broader than intended.',
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
      severity: 'critical',
      confidence: 'high',
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
      'reads secret material (Secrets Manager / KMS decrypt / SSM parameters)',
    );
  }
  if (bulk.length > 0) {
    whyParts.push('bulk-reads object storage across a broad resource scope');
  }
  out.push(
    makeFinding('DATA-EXFIL', stmt, {
      severity: highSeverity ? 'high' : 'medium',
      confidence: 'high',
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
      confidence: 'high',
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
      confidence: 'high',
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
      confidence: 'high',
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
