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
import {
  ruleWildcardAction, ruleWildcardResource, matchPatterns, ruleDirectIamAdmin, ruleResourcePolicyWrite, ruleDataExfil, ruleKmsDecrypt, classifyContainerReads, undetAllCanonicalS3, undetFindingText, ruleDataReadScoped, denyEntirelyDeniesResource, sparedResourceFullyDeniedElsewhere, allowGrantsSparedResource, survivingSparedContainerReads, ruleDestructive, ruleDetectionImpairment, ruleNotActionAllow, ruleGroupMembership,
} from './rules-detectors.js';
export * from './rules-detectors.js';
import {
  makeFinding, resourceScope, isBroadArnResource, resourceIsBroad, isNonReadAction, grantsNonReadAction, remediableWildcardActions, denyFencesToNarrow, isBulkReadAction, ruleFindingDenySuppressed, survivingBroadReadActions,
} from './rules-finding.js';
export * from './rules-finding.js';
import {
  CAPABILITY_LIMIT, CONDITION_LIMIT, COMPLEMENT_LIMIT, CONFIDENCE_LADDER, lowerConfidence, actionGrants, isFullWildcard, isServiceWildcard, READ_VERB, actionVerb, actionService, DESTRUCTIVE_VERB, DETECTION_SERVICES, IAM_ADMIN_ACTIONS, GROUP_MEMBERSHIP_ACTIONS, PRIVILEGED_GROUP_NAME_TOKENS, groupNameFromArn, groupNameSuggestsPrivilege, SECRET_READ_ACTIONS, KMS_DECRYPT_ACTIONS, BULK_READ_ACTIONS, DATA_READ_ACTIONS, CONCRETE_ACCOUNT_ID_RE, concreteResourceAccount, RESOURCE_ACCOUNT_COND_KEYS, RESOURCE_ACCOUNT_EQ_OPS, resourceAccountFromCondition, isWholeContainerRead, SENSITIVE_NAME_TOKENS, resourceInfersSensitive, resourceHasVariable, DETECTION_ACTIONS, statementSid,
} from './rules-classify.js';
export * from './rules-classify.js';
import {
  RULES, RULE_IDS,
} from './rules-catalog.js';
export * from './rules-catalog.js';
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

const RULE_FUNCTIONS = [
  ruleWildcardAction,
  ruleWildcardResource,
  ruleDirectIamAdmin,
  ruleResourcePolicyWrite,
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
