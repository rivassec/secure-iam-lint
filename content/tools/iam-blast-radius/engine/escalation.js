// IAM Blast Radius - privilege-escalation path engine (IAM-005).
//
// Fifth stage of the pipeline (see docs/architecture.md data-flow):
//   text -> validate() -> parse() -> buildModel() -> [ rules, escalation,
//   family-aware analyzers ] -> { findings[], graph }
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
//     effectively ALL roles across an ARBITRARY account (a bare "*", or a role
//     ARN whose account AND role-name segments are both wildcards, such as
//     arn:aws:iam::*:role/*, or a NotResource inverse, or an unspecified scope) ->
//     `critical`. A CONCRETE-account all-roles wildcard (arn:aws:iam::123:role/*)
//     is account-confined -> `high`. A PARTIAL role-name wildcard (role/app-*)
//     reaches many roles but not all -> also `high`.
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
import {
  detectRoleTakeover,
} from './escalation-takeover.js';
export * from './escalation-takeover.js';
import {
  detectPolicyVersion, detectAttachPolicy, detectPutInlinePolicy, detectTrustModify, detectCredentialCreation, detectComputeCodeOverwrite, detectAssumeRoleExpansion, detectCrossAccountScopedAssume,
} from './escalation-families.js';
export * from './escalation-families.js';
import {
  makeEscalation, downgrade, evidenceOf, contributingStatementsFrom, prereqGroup, prereqTechnique, prerequisitesOf, survivingGrantedActions,
} from './escalation-finding.js';
export * from './escalation-finding.js';
import {
  denyActionApplies, denyResourcesCover, denyResourceCoverage, denyEffectOnAction, applyDenyToActions,
} from './escalation-deny.js';
export * from './escalation-deny.js';
import {
  CAPABILITY_LIMIT, TARGET_UNKNOWN_LIMIT, CONDITION_LIMIT, DENY_NARROW_LIMIT, PASSED_TO_SERVICE_UNCERTAIN_LIMIT,
} from './escalation-consts.js';
export * from './escalation-consts.js';
import { concreteRoleTargetAccount, isConcreteRoleArn, resourceCoversRole, isAllRolesAssumeScope, specificAccountsInRoleArns, parsePassResource, partitionReaches, accountReaches, partitionModelable, subjectPartitionKnown, accountModelable, otherResourceIsUnmodelable, isUnmodelablePassResource, isConfidentPinnedResource, globCanProducePrefix, subjectRoleArnPrefix, resourceReachesSubject, rolePathIsWildcardEquivalent, principalPinsOf, constraintContains, keyConstraintsSatisfiable, principalPinsOfMemo, pinsJointlySatisfiable, principalConditionsSatisfiable, ROLE_ARN_PARTS_RE, KNOWN_PARTITIONS, IAM_ARN_LENIENT_RE, PRINCIPAL_INVARIANT_KEYS, EXACT_EQUALITY_PIN_OPERATORS, NEGATED_EQUALITY_PIN_OPERATORS, CASE_INSENSITIVE_PIN_OPERATORS, SATISFIABILITY_TRIPLE_WORK } from './escalation-reachability.js';
export * from './escalation-reachability.js';
import { passedToServiceEntries, normalizeOperator, operatorPermitsService, passRolePermitsService, hasNonEmptyCondition } from './escalation-conditions.js';
export { hasNonEmptyCondition } from './escalation-conditions.js';
import { statementSid } from './escalation-statement.js';
import { resourceScope, isStarResource, grantTokenIsBroad, resourceListIsBroadForAssume, assumeScopeIsAllRoles, assumeAccountReach } from './escalation-scope.js';
import { statementNeverMatches, parseOperator } from './conditions.js';
// ONE shared, ReDoS-safe, linear wildcard matcher (S3-dos-budget). Replaces the
// byte-identical globMatch copy this file used to carry; isGlobBudgetError lets the
// analyzer re-throw the cooperative wall-clock budget sentinel instead of masking it
// as a generic internal error (see the analyzeEscalations catch below).
import { globMatch, isGlobBudgetError, chargeWork } from './glob.js';
// Low-level action-pattern matchers extracted to their own leaf module
// (behavior-preserving refactor). Imported for internal use AND re-exported so
// external consumers (graph.js) keep importing them from './escalation.js'.
import { actionGrants, hasPolicyVariable, grantedPatternsFor } from './escalation-action-grants.js';
export { actionGrants, hasPolicyVariable } from './escalation-action-grants.js';

// --- Shared caveat language --------------------------------------------------
// One constant so every escalation's `limit` carries identical, non-overstated
// wording about what a single policy can and cannot prove. Contains the phrase
// "not effective access" that the truthfulness tests assert on.

// The linear, ReDoS-safe wildcard matcher (globMatch) now lives in ./glob.js and
// is imported at the top of this module - one canonical matcher shared by every
// engine file instead of three drifting copies (S3-dos-budget).

// Escalation catalogs/metadata extracted to their own leaf module; imported
// for internal use and ESCALATIONS/ESCALATION_IDS re-exported (public API).
import {
  PASS_ROLE_SERVICES, PASS_ROLE_ACTION, classifyEcsRole, ECS_LAUNCH_ACTIONS, ecsRoleClasses,
  POLICY_VERSION_ACTIONS, ATTACH_POLICY_ACTIONS, PUT_INLINE_POLICY_ACTIONS, TRUST_MODIFY_ACTIONS,
  CREDENTIAL_ACTIONS, ASSUME_ROLE_ACTIONS, ROLE_TAKEOVER_GRANT_ACTIONS, ROLE_TAKEOVER_ASSUME_ACTIONS,
  ESCALATIONS, ESCALATION_IDS, CONCRETE_ACCOUNT_ID_RE,
} from './escalation-catalogs.js';
export { ESCALATIONS, ESCALATION_IDS } from './escalation-catalogs.js';
// --- Condition helpers -------------------------------------------------------






// --- Resource-scope helpers --------------------------------------------------



// Order-invariant danger ranking of an exec statement's RESOURCE scope, used ONLY
// as a tiebreak when several equally-un-denied service-execution statements exist
// for one service (S2-passrole-allstmts iter5). Higher = broader/more dangerous.
// The compound path must reflect the WORST-case exec grant, and its selection must
// not depend on statement ORDER: a lowest-INDEX tiebreak let a reorder swap which
// exec (broad "*" vs narrow) the path consumed, which - together with subsumption -
// flipped the CLI exit 0<->1 on byte-content-identical statements. Ranking by
// resource breadth (a content property) first makes the selected exec deterministic
// across reorderings; the lowest-index tiebreak only settles equal-breadth ties.
function execResourceBroadness(stmt) {
  if (stmt.notResources.length > 0) return 2; // NotResource inverse - broad-except-a-few
  if (stmt.resources.length === 0) return 2; // unspecified scope
  if (stmt.resources.includes('*')) return 2; // bare "*"
  if (stmt.resources.some((r) => r.includes('*') || r.includes('?'))) return 1; // glob ARN
  return 0; // concrete ARN(s)
}

// Order-invariant TECHNIQUE severity of an exec statement's SURVIVING (post-Deny)
// actions for a pass-role service. The compound path's tier is a MOST-SEVERE-across-
// statements property, mirroring the pass side: a co-located staging-only exec must
// never mask a launch-capable exec in another statement - regardless of statement
// ORDER, resource breadth, or index (S2-passrole-allstmts axis 2). Only ECS splits
// launch (ecs:RunTask / ecs:StartTask -> runs code as the passed role, CRITICAL) from
// staging (ecs:RegisterTaskDefinition -> only stages a definition, HIGH); every other
// pass-role service's exec actions are each a full code-execution technique, so they
// rank uniformly (1). Ranked ABOVE resource breadth and index in exec selection so a
// launch grant in ANY statement keeps the path critical. `effectiveActions` are the
// granted PATTERNS that survived Deny, so membership is tested with actionGrants (a
// wildcard covering ecs:RunTask counts as launch), not string equality.
function execTechniqueSeverity(svc, effectiveActions) {
  if (svc.service === 'ecs') {
    const hasLaunch = ECS_LAUNCH_ACTIONS.some(
      (la) => (effectiveActions || []).some((p) => actionGrants(p, la)),
    );
    return hasLaunch ? 1 : 0;
  }
  return 1; // every other service's exec actions are all full code-execution techniques
}



// --- Explicit-Deny analysis (same-policy precedence) -------------------------
// AWS resolves access with explicit-Deny precedence: an in-scope, applicable
// Deny overrides every Allow. The escalation engine builds paths from Allow
// statements, but a same-policy Deny of a required action can remove or narrow
// the path. Applies AWS explicit-Deny precedence: an unconditional, concrete,
// in-scope Deny is definitive; a conditional / variable / partial-scope Deny is
// treated as "may block" (reduces confidence) rather than a false certainty.

// Does a Deny statement's Action/NotAction apply to concrete `action`?
// Returns { applies, certain }. NotAction on a Deny denies everything EXCEPT the
// listed actions. Variable-bearing patterns cannot be resolved from text -> the
// match is possible but not certain.

// --- Finding factory ---------------------------------------------------------


// Build a canonical finding (docs/architecture.md shape) plus escalation-only
// enrichment: `escalation` (technique/service/target-unknown) and `evidence`
// (per-statement support for the graph builder in IAM-006). Extra fields are
// permitted alongside the canonical shape.

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

function detectPassRolePaths(allows, out, denies, ctx) {
  const rawSubjectAccount = ctx && ctx.subjectAccount != null ? String(ctx.subjectAccount) : null;
  const subjectAccount = rawSubjectAccount && CONCRETE_ACCOUNT_ID_RE.test(rawSubjectAccount)
    ? rawSubjectAccount
    : null;
  // The subject's partition (aws / aws-us-gov / aws-cn / ...). Defaults to 'aws'.
  // S2-passrole-allstmts (SUBJECT axis): the subject partition is validated with the
  // SAME KNOWN_PARTITIONS rigor already applied to role-ARN partitions. It is fed into
  // an EXACT-equality compare (partitionReaches), so a non-canonical spelling of the
  // subject's OWN partition ('AWS', 'Aws', '*', 'aws-gov', 'AWS-US-GOV', ...) would make
  // a viable same-account, same-real-partition critical PassRole->service path read as
  // cross-partition and get CONFIDENTLY demoted critical->medium (PARTITION_MISMATCH) -
  // the exact fail-open T8 forbids, and it makes analyze() MORE permissive than the
  // partition-sanitizing scan() adapter for byte-identical input (browser==CLI parity
  // violation). So an unrecognized SUBJECT partition token must fail CLOSED as
  // unknown-viability, never drive a confident demotion. `partitionKnown` gates every
  // pure-partition demotion below; a non-canonical token defaults to 'aws' ONLY for
  // account-level reasoning (which never depends on the partition spelling).
  //
  // S5-partition-parity: an ABSENT partition is a DEFAULTED partition, NOT a
  // confidently-supplied one, and must be treated EXACTLY like a non-canonical token -
  // unknown-viability, never a confident cross-partition demotion. The browser (the
  // primary UI) forwards subjectAccount but NO partition (app.js/worker.js ->
  // analyze({ subjectAccount })), so if the absent case defaulted to partitionKnown=true
  // the engine would CONFIDENTLY demote a same-account cross-partition PassRole to medium
  // with a false "principal is in partition aws ... NOT a viable path" why and coverage
  // complete - while the CLI scan() adapter's partitionProvided guard correctly reported
  // partial/exit 3/requiredUnknowns:['subjectPartition']. That made analyze() (browser)
  // MORE permissive than scan() (CLI) for byte-identical no-partition input (threat-model
  // T8, browser==CLI parity). An account id does not encode a partition, so a DEFAULTED
  // partition can never confidently establish same-vs-cross partition: it fails CLOSED.
  // `partitionKnown` is therefore true ONLY for an EXPLICITLY-supplied CANONICAL token
  // (an explicit 'aws' still legitimately demotes a cross-partition role); an absent OR
  // non-canonical token is unknown. This folds the scan() adapter's partitionProvided
  // guard into the shared engine (the single source of truth), so no direct/third-party
  // analyze() consumer can reach the confident demotion the adapter used to compensate
  // for. `subjectPartition` still defaults to 'aws' for the account-level reasoning that
  // never depends on the partition spelling.
  const rawSubjectPartition = ctx && typeof ctx.partition === 'string' ? ctx.partition.trim() : '';
  const partitionExplicit = rawSubjectPartition !== '';
  const partitionKnown = partitionExplicit && subjectPartitionKnown(rawSubjectPartition);
  const subjectPartition = subjectPartitionKnown(rawSubjectPartition) ? rawSubjectPartition : 'aws';
  // Gather the Allow statements that grant iam:PassRole (concrete or via iam:*).
  const passStmts = [];
  for (const stmt of allows) {
    const matched = grantedPatternsFor(stmt, [PASS_ROLE_ACTION]);
    if (matched.length > 0) passStmts.push(stmt);
  }
  if (passStmts.length === 0) return; // PassRole alone is never flagged, and
  // without any PassRole grant there is no pass path at all.

  // S2-passrole-allstmts axis 3 (iter-5 DoS): the "does an unconditional in-scope Deny
  // remove EVERY subject role?" verdict depends only on (denies, subjectAccount,
  // subjectPartition) - all invariant for this call - so compute it EXACTLY ONCE here
  // (charged against the work budget) and reuse it for every (svc x passStmt) selection
  // iteration and the metadata block below. Previously it was recomputed 8 x nPassStmts
  // times (a full scan of every Deny resource each time), an unbudgeted multiplicative
  // scan that ran unbounded on a within-caps policy yet returned a COMPLETE verdict
  // (fail-open DoS, threat-model T5/T8). The value is a pure function of these inputs,
  // so hoisting it changes no verdict - only the cost.
  const subjectDenied = subjectAccount
    ? denyRemovesAllSubjectRoles(denies, subjectAccount, subjectPartition)
    : false;

  for (const svc of PASS_ROLE_SERVICES) {
    // Gather EVERY Allow granting a role-consuming action for this service, then
    // apply same-policy explicit-Deny precedence PER statement. A Deny that fully
    // covers ONE exec statement must not hide a path that a DIFFERENT, un-denied
    // exec statement still grants (multi-statement policies) - suppressing on the
    // first-selected statement alone would be a false-safe / false negative
    // (docs/architecture.md #6, threat-model T8). We therefore keep a surviving
    // exec statement (not fully denied) and suppress only when EVERY exec
    // candidate is definitively, in-scope denied. Among survivors we prefer a
    // fully-clear one over a merely narrowed one, then the BROADEST resource scope
    // (order-invariant worst-case), then the lowest statement index as the final
    // deterministic settle. Preferring the broadest exec by CONTENT (not by index)
    // means reordering byte-content-identical statements cannot swap which exec the
    // path consumes and so cannot flip the verdict (S2-passrole-allstmts iter5); a
    // live path is also never reported as narrower than the broadest grant it holds.
    let execStmt = null;
    let effectiveExecActions = null;
    let execNarrowed = false;
    let execBroad = -1;
    let execTech = -1;
    let execAnyCandidate = false;
    for (const stmt of allows) {
      const m = grantedPatternsFor(stmt, svc.execActions);
      if (m.length === 0) continue;
      execAnyCandidate = true;
      const d = applyDenyToActions(denies, m, stmt);
      if (d.blocked) continue; // this exec statement is fully, in-scope denied
      // MOST-SEVERE first: a launch-capable exec (critical) outranks a staging-only
      // exec (high) no matter its order, resource breadth, or index (axis 2). Only
      // within an equal technique tier do the not-narrowed / broadest / lowest-index
      // settles apply. This mirrors the pass-side viability-tier ranking so a launch
      // grant in ANY statement is never masked by a co-located broader staging grant.
      const techHere = execTechniqueSeverity(svc, d.actions);
      const broadHere = execResourceBroadness(stmt);
      const better =
        execStmt === null ||
        (techHere > execTech) ||
        (techHere === execTech && execNarrowed && !d.narrowed) ||
        (techHere === execTech && execNarrowed === d.narrowed && broadHere > execBroad) ||
        (techHere === execTech && execNarrowed === d.narrowed && broadHere === execBroad && stmt.index < execStmt.index);
      if (better) {
        execStmt = stmt;
        effectiveExecActions = d.actions;
        execNarrowed = d.narrowed;
        execBroad = broadHere;
        execTech = techHere;
      }
    }
    if (!execAnyCandidate) continue; // no service-execution action -> not this path
    if (!execStmt) continue; // every exec statement definitively denied -> path removed

    // Gather EVERY PassRole grant that can feed THIS service (respecting
    // PassedToService operator semantics: allowlist vs denylist vs uncertain),
    // then apply the SAME per-statement Deny precedence. As with the exec side, a
    // Deny that removes one PassRole grant must not suppress the path when another
    // permitting PassRole grant survives un-denied.
    // PassRole VIABILITY is an ALL-STATEMENTS property (S2-passrole-allstmts),
    // exactly like the DENY reasoning above. The T91 account/partition/deny-residual
    // viability check downstream runs on the SINGLE selected passStmt; if selection
    // ignored viability it could pick a cross-account decoy in a lower-indexed
    // statement, demote the whole path critical->medium, and slip a VIABLE
    // same-account PassRole in a DIFFERENT statement under the exit gate (a false
    // negative, threat-model T8). Reordering byte-identical statements would then
    // flip the verdict. To close the CLASS: rank a candidate that KEEPS the critical
    // (viable same-account) outcome ABOVE one that would be demoted/capped, then keep
    // the existing not-narrowed-then-lowest-index tiebreak within a viability tier.
    // A path is only demoted when NO candidate statement yields a viable pass.
    let passStmt = null;
    let pinned = false;
    let passUncertain = false;
    let passNarrowed = false;
    let passTier = -1;
    let passAnyPermits = false;
    for (const stmt of passStmts) {
      const p = passRolePermitsService(stmt.condition, svc.principal);
      if (!p.permits) continue;
      passAnyPermits = true;
      const eff = denyEffectOnAction(denies, PASS_ROLE_ACTION, stmt);
      if (eff === 'blocked') continue; // this PassRole grant is fully, in-scope denied
      const narrowed = eff === 'may-block';
      // Rank by viability TIER: 2 = confidently viable same-account (stays critical),
      // 1 = UNKNOWN viability (unmodelable ARN token or concrete-account-unknown-subject
      // -> fails closed, NOT demoted below threshold), 0 = confidently demoted
      // cross-account/partition. Prefer the most-severe still-correct outcome so a
      // viable (or unknown-but-fail-closed) grant in ANY statement is never hidden by a
      // lower-indexed confidently-cross-account decoy - independent of statement ORDER
      // and of ARN spelling. Within a tier keep the not-narrowed-then-lowest-index
      // tiebreak. MIRRORS the downstream metadata demotion/cap exactly.
      const tierHere = passStmtViabilityTier(stmt, subjectAccount, subjectPartition, partitionKnown, subjectDenied);
      const better =
        passStmt === null ||
        (tierHere > passTier) || // a more-severe still-correct outcome wins over a decoy
        (tierHere === passTier && passNarrowed && !narrowed) ||
        (tierHere === passTier && passNarrowed === narrowed && stmt.index < passStmt.index);
      if (better) {
        passStmt = stmt;
        pinned = p.pinned;
        passUncertain = p.uncertain;
        passNarrowed = narrowed;
        passTier = tierHere;
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
    // Only CONFIDENTLY-modelable pinned role ARNs (known partition + 12-digit account,
    // no wildcard) may drive a confident cross-account/partition demotion. A role ARN
    // whose partition/account token is non-canonical (uppercase partition, embedded
    // whitespace, non-12-digit account) is UNMODELABLE: it could be a same-account role
    // under a spelling we cannot compare, so demoting it critical->medium would be a
    // fail-open (threat-model T8). Such targets fail CLOSED as unknown-viability instead.
    const concreteSpecific = parsedPassResources.filter(isConfidentPinnedResource);
    const unmodelableTargets = parsedPassResources.filter(isUnmodelablePassResource);
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
      // subjectDenied hoisted+charged once at the top of detectPassRolePaths (axis 3
      // iter-5 DoS); reuse it here rather than re-scanning every Deny resource per svc.
      const viable = anyReaches && !subjectDenied;
      if (!viable && unmodelableTargets.length > 0) {
        // UNKNOWN viability (not a confident cross-account/partition verdict): a passed
        // role ARN's partition/account token is not modelable, so we cannot establish
        // same-vs-cross account. Keep the severity (do NOT demote below threshold) and
        // fail CLOSED via requiredUnknowns, exactly like the subject-unknown
        // concrete-account cap - scan() then reports partial/exit 3, never CLEAN. This
        // is order-independent and needs no decoy: normalize/validate the ARN tokens
        // with the same rigor as the subjectAccount/partition inputs before trusting a
        // demotion.
        pathExploitability = 'low'; // cap; never asserts a confident viable/critical path
        const hasBadPartition = unmodelableTargets.some((r) => !partitionModelable(r.partition));
        const hasBadAccount = unmodelableTargets.some((r) => !accountModelable(r.account));
        if (hasBadPartition) requiredUnknowns.push('passRoleTargetPartition');
        if (hasBadAccount) requiredUnknowns.push('passRoleTargetAccount');
        if (requiredUnknowns.length === 0) requiredUnknowns.push('passRoleTargetArn');
        extraWhy +=
          ` PassRole target viability is UNKNOWN: a passed-role ARN carries a ` +
          'non-canonical partition/account spelling (unrecognized partition, ' +
          'non-12-digit account, or embedded case/whitespace) that cannot be compared ' +
          `to the analyzed principal's account/partition, so whether this is a ` +
          'same-account (viable) or cross-account (not viable) pass cannot be ' +
          'established. Reported as unknown viability (fail closed), not a confident ' +
          'not-viable demotion; supply canonical role ARNs to resolve it.';
      } else if (!viable && (concreteSpecific.length > 0 || subjectDenied)) {
        // A pure partition mismatch: every pinned resource matches the subject
        // ACCOUNT but sits in a different partition (and no deny-residual involved).
        const partitionOnly = !subjectDenied
          && concreteSpecific.length > 0
          && concreteSpecific.every(
            (r) => r.account === subjectAccount && !partitionReaches(r.partition, subjectPartition),
          );
        if (partitionOnly && !partitionKnown) {
          // The mismatch is PURELY a partition difference, but the SUBJECT partition is
          // NOT confidently known - either a non-canonical token was supplied (defaulted
          // to 'aws' for account reasoning) OR no partition was supplied at all (the
          // DEFAULTED case, S5-partition-parity: the browser forwards subjectAccount but
          // never a partition). Neither a non-canonical NOR a defaulted subject partition
          // can drive a confident cross-partition demotion: an account id does not encode
          // a partition, so the path may be a same-partition, fully-viable critical pass
          // we cannot compare, and demoting it critical->medium would be the exact
          // fail-open T8 forbids and would make analyze() (the browser) more permissive
          // than the partition-sanitizing scan() adapter for byte-identical input. Fail
          // CLOSED as UNKNOWN viability instead: keep the severity, cap exploitability,
          // and record the required-unknown so scan() reports partial/exit 3 (never
          // CLEAN). This MIRRORS the unmodelable-target-ARN handling above and folds the
          // scan.mjs unconfirmed-partition guard into the shared engine (the single source
          // of truth), so no direct/third-party analyze() consumer can reach the demotion
          // the adapter used to compensate for.
          pathExploitability = 'low';
          if (!requiredUnknowns.includes('subjectPartition')) requiredUnknowns.push('subjectPartition');
          extraWhy += partitionExplicit
            ? ' PassRole target viability is UNKNOWN: the analyzed principal\'s partition ' +
              'was supplied in a non-canonical spelling that is not a recognized AWS ' +
              'partition, so it cannot be compared to the passed role\'s partition. Whether ' +
              'this is a same-partition (viable) or cross-partition (not viable) pass cannot ' +
              'be established. Reported as unknown viability (fail closed), not a confident ' +
              'not-viable demotion; supply a canonical partition (aws, aws-us-gov, aws-cn, ' +
              'aws-iso...) to resolve it.'
            : ' PassRole target viability is UNKNOWN: the analyzed principal\'s partition ' +
              'was not supplied, so it cannot be compared to the passed role\'s partition ' +
              '(an account id does not encode a partition). Whether this is a same-partition ' +
              '(viable) or cross-partition (not viable) pass cannot be established. Reported ' +
              'as unknown viability (fail closed), not a confident not-viable demotion; ' +
              'supply the analyzed principal\'s partition (aws, aws-us-gov, aws-cn, ' +
              'aws-iso...) to resolve it.';
        } else if (partitionOnly) {
          accountMismatch = true;
          severity = severity === 'critical' ? 'medium' : 'low';
          pathExploitability = 'low';
          warningCodes.push('PARTITION_MISMATCH');
          extraWhy +=
            ` Partition mismatch: the passed role(s) are in partition ` +
            `${[...new Set(concreteSpecific.map((r) => r.partition))].join(', ')} but the ` +
            `analyzed principal is in partition ${subjectPartition}. iam:PassRole cannot ` +
            'pass a role across partitions, so this is NOT a viable direct ' +
            `PassRole-to-${svc.service} path.`;
        } else {
          accountMismatch = true;
          severity = severity === 'critical' ? 'medium' : 'low';
          pathExploitability = 'low';
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





















// Does ONE Deny resource token PROVABLY remove EVERY role in the subject's
// account+partition? Two forms qualify, both matching all subject-account role ARNs
// with NO literal constraint on the role NAME:
//   - a bare "*" (matches every ARN, including all subject role ARNs), or
//   - a role ARN arn:<p>:iam::<a>:role/<path> whose partition reaches the subject,
//     whose account reaches the subject, and whose <path> is wildcard-equivalent to
//     "*" (rolePathIsWildcardEquivalent).
// Anything not provably all-roles (a narrower role-path glob, a foreign/other token,
// a different concrete account/partition) returns false so the viable same-account
// path stays CRITICAL - never a confident demotion the Deny does not support.
function denyResourceRemovesAllSubjectRoles(r, subjectAccount, subjectPartition) {
  // S2-passrole-allstmts axis 3 (DoS, iter-5): CHARGE the deterministic work budget
  // one unit per Deny-resource token inspected (proportional to its length, mirroring
  // denyResourcesCover / denyResourceCoverage). Before this charge the per-Deny-resource
  // scan below (parsePassResource regex + partition/account/rolePath compares) advanced
  // the work counter ZERO times, so a within-caps policy whose cost is nDeny x
  // resPerDeny (routed here, NOT through the charged denyResourceCoverage - e.g. a
  // NotResource-shaped Allow that early-returns 'partial' before the charged scan) ran
  // unbounded yet returned a COMPLETE verdict - a fail-OPEN DoS (threat-model T5/T8), and
  // on the browser (no wall-clock watchdog) the sole participating ceiling is this work
  // counter. With the charge the scan is sampled by analyze()'s work budget and fails
  // CLOSED (RESOURCE_BUDGET_EXCEEDED -> coverage incomplete -> scan exit 3) if genuinely
  // huge, instead of running unbounded. The multiplicative 8 x nPassStmts re-scan is
  // separately removed by memoizing the result once per detectPassRolePaths call.
  chargeWork(String(r).length + 1);
  const res = parsePassResource(r);
  if (res.star) return true; // bare "*" covers all subject role ARNs
  if (res.other) return false; // not a role ARN we can pin - conservative (fail closed)
  return partitionReaches(res.partition, subjectPartition)
    && accountReaches(res.account, subjectAccount)
    && rolePathIsWildcardEquivalent(res.path);
}

// T91-09 deny-residual: does an in-scope, UNCONDITIONAL Deny on iam:PassRole
// remove EVERY role in the subject's account+partition from the passable set? If
// so, even an Allow "*" cannot pass a same-account role, so the direct same-account
// path is not viable. A conditional deny is NOT treated as a guaranteed removal
// (it may not always apply) - being conservative here avoids a false negative.
// The removal must be PROVABLE: only a Deny whose role-path imposes no literal
// constraint (wildcard-equivalent to "*") counts; a narrow anchored decoy Deny does
// not (S2-passrole-allstmts axis 3).
function denyRemovesAllSubjectRoles(denies, subjectAccount, subjectPartition) {
  if (!subjectAccount) return false;
  for (const d of Array.isArray(denies) ? denies : []) {
    const deniesPassRole = (d.actions || []).some((a) => actionGrants(a, PASS_ROLE_ACTION));
    if (!deniesPassRole) continue;
    if (hasNonEmptyCondition(d)) continue; // conditional deny may not always apply
    for (const r of (d.resources || [])) {
      if (denyResourceRemovesAllSubjectRoles(r, subjectAccount, subjectPartition)) return true;
    }
  }
  return false;
}

// S2-passrole-allstmts: which VIABILITY TIER would selecting THIS PassRole statement
// yield downstream? Evaluated per candidate so the passStmt selection prefers the
// most-severe still-correct outcome and never lets a lower-indexed confidently
// cross-account decoy hide a viable (or unknown-but-fail-closed) grant in a different
// statement - making the verdict independent of statement ORDER and of ARN spelling.
//   2 = confidently VIABLE same-account -> stays critical.
//   1 = UNKNOWN viability -> fails CLOSED (requiredUnknowns) but NOT demoted below the
//       threshold. Two sub-cases: (a) subject known but a passable role ARN's
//       partition/account token is UNMODELABLE (non-canonical spelling), or (b) subject
//       unknown and every passable resource pins a concrete 12-digit account.
//   0 = confidently DEMOTED cross-account/partition (below threshold).
// This MIRRORS EXACTLY the demotion/cap conditions in detectPassRolePaths, so the
// selection and the metadata block can never disagree about a statement.
// `subjectDenied` is the deny-removes-all-subject-roles verdict, computed ONCE per
// detectPassRolePaths call and threaded in (S2-passrole-allstmts axis 3, iter-5 DoS): it
// is invariant across all (svc x passStmt) selection iterations, so recomputing it here
// - 8 x nPassStmts times, each a full scan of every Deny resource - was redundant
// multiplicative work with no budget participation (fail-open DoS, T5/T8). The single
// shared computation is now charged (denyResourceRemovesAllSubjectRoles) and reused.
function passStmtViabilityTier(passStmt, subjectAccount, subjectPartition, partitionKnown, subjectDenied) {
  const parsed = passStmt.resources.map(parsePassResource);
  if (subjectAccount) {
    const anyReaches = parsed.some((r) => resourceReachesSubject(r, subjectAccount, subjectPartition));
    const viable = anyReaches && !subjectDenied;
    if (viable) return 2;
    // Not confidently viable: an unmodelable target ARN token makes the verdict UNKNOWN
    // (fail closed, tier 1) and takes precedence over a confident demotion - it could be
    // a same-account role under a spelling we cannot compare.
    if (parsed.some(isUnmodelablePassResource)) return 1;
    const concreteSpecific = parsed.filter(isConfidentPinnedResource);
    // A demotion that is PURELY a partition mismatch, when the SUBJECT partition is not
    // confidently known (a non-canonical token, OR an absent/defaulted partition -
    // S5-partition-parity - both defaulted to 'aws'), is UNKNOWN viability
    // (fail closed, tier 1), NOT a confident cross-partition demotion (tier 0): the path
    // may be a same-partition, fully-viable pass under a spelling we cannot compare.
    // MIRRORS the partitionOnly && !partitionKnown branch in detectPassRolePaths exactly,
    // so selection and the metadata block can never disagree about a statement.
    if (!partitionKnown && !subjectDenied && concreteSpecific.length > 0
        && concreteSpecific.every(
          (r) => r.account === subjectAccount && !partitionReaches(r.partition, subjectPartition),
        )) {
      return 1;
    }
    const demoted = concreteSpecific.length > 0 || subjectDenied;
    return demoted ? 0 : 2;
  }
  // Subject unknown: capped/fail-closed (tier 1) only when EVERY passable resource pins
  // a concrete 12-digit account - so viability hinges entirely on an account we cannot
  // confirm. A "*"/account-wildcard (or an unpinnable resource) reaches the subject
  // whatever it is, so that statement keeps full viability (tier 2).
  const allPinConcreteAccount = parsed.length > 0
    && parsed.every(
      (r) => !r.star && !r.other && CONCRETE_ACCOUNT_ID_RE.test(String(r.account)),
    );
  return allPinConcreteAccount ? 1 : 2;
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

const DETECTORS = [
  detectPassRolePaths,
  detectPolicyVersion,
  detectAttachPolicy,
  detectPutInlinePolicy,
  detectTrustModify,
  detectCredentialCreation,
  detectComputeCodeOverwrite,
  detectAssumeRoleExpansion,
  detectCrossAccountScopedAssume,
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
    // (cross-account / cross-partition PassRole viability).
    //
    // S5-partition-parity: the partition is forwarded RAW - an ABSENT partition stays
    // absent (empty string), it is NOT defaulted to 'aws' here. Defaulting it to 'aws'
    // upstream erased the "not supplied" state, so detectPassRolePaths could not tell a
    // DEFAULTED partition from an EXPLICIT 'aws' and CONFIDENTLY demoted a same-account
    // cross-partition PassRole to medium - making analyze() (the browser) MORE permissive
    // than the scan() adapter, which never lost that distinction (threat-model T8,
    // browser==CLI parity). detectPassRolePaths owns the distinction now: it treats an
    // absent/non-canonical partition as unknown-viability (fail closed) and defaults to
    // 'aws' ONLY for account-level reasoning (which never depends on the partition
    // spelling). An explicit canonical partition still drives a confident demotion.
    const ctx = {
      subjectAccount: (options && options.subjectAccount) || null,
      partition: (options && typeof options.partition === 'string')
        ? options.partition.trim() : '',
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
    // The cooperative wall-clock budget sentinel must PROPAGATE, not be masked as a
    // generic internal error, so scan() can report the specific fail-closed
    // "analysis aborted (resource budget)" verdict (S3-dos-budget).
    if (isGlobBudgetError(e)) throw e;
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
export function analyzeEscalationsFromText(text, options) {
  const m = modelFromText(text);
  if (!m.ok) {
    return Object.freeze({ ok: false, errors: m.errors, findings: Object.freeze([]) });
  }
  return analyzeEscalations(m.model, options);
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
