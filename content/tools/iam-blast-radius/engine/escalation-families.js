// escalation-families.js - the non-passrole escalation detectors (policy-version, attach/put-inline policy, trust-modify, credential-creation, assume-role-expansion, cross-account-scoped-assume). Extracted (behavior-preserving).
import { applyDenyToActions } from './escalation-deny.js';
import { assumeAccountReach, assumeScopeIsAllRoles, resourceListIsBroadForAssume, resourceScope } from './escalation-scope.js';
import { concreteRoleTargetAccount } from './escalation-reachability.js';
import { evidenceOf, makeEscalation, prereqGroup, prereqTechnique, prerequisitesOf } from './escalation-finding.js';
import { grantedPatternsFor } from './escalation-action-grants.js';
import { hasNonEmptyCondition } from './escalation-conditions.js';
import { ASSUME_ROLE_ACTIONS, ATTACH_POLICY_ACTIONS, CREDENTIAL_ACTIONS, POLICY_VERSION_ACTIONS, PUT_INLINE_POLICY_ACTIONS, TRUST_MODIFY_ACTIONS, CONCRETE_ACCOUNT_ID_RE } from './escalation-catalogs.js';

export function detectPolicyVersion(allows, out, denies) {
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

export function detectAttachPolicy(allows, out, denies) {
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

export function detectPutInlinePolicy(allows, out, denies) {
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

export function detectTrustModify(allows, out, denies) {
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

export function detectCredentialCreation(allows, out, denies) {
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

// Stage-13 EFO-3 / Stage-14: overwriting the code (or code-selecting configuration) of
// an EXISTING compute resource runs attacker-supplied code under that resource's
// ALREADY-BOUND execution/service role - a standalone code-exec / lateral-movement
// primitive that needs NO iam:PassRole (Rhino "UpdateExistingLambdaFunctionCode" and its
// siblings). These are the SAME "update existing" exec actions the PassRole path models
// (requiresPassRole:false); detecting them here surfaces the capability when NO viable
// iam:PassRole->service path exists (where detectPassRolePaths returns early or the
// service is not permitted, and never credited it - a T8 fail-open).
//   lambda:UpdateFunctionCode / UpdateFunctionConfiguration - new code, or a layer swap /
//     handler repoint / NODE_OPTIONS env, run under the function's existing role.
//   codebuild:UpdateProject   - new buildspec/commands run under the project's role.
//   glue:UpdateJob            - new job script runs under the job's role.
//   cloudformation:UpdateStack- a changed template acts through the stack's role.
// (Create*/RunInstances create a NEW workload and genuinely need iam:PassRole to attach a
// role, so they stay on the compound PassRole path and are NOT listed here.)
// Severity ordering for the dedup viability gate (Stage-15): a covering PASSROLE-*
// finding only suppresses the standalone overwrite finding when it is at least as
// severe (>= high) - a demoted, non-viable medium does not.
const SEVERITY_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

const COMPUTE_CODE_OVERWRITE_ACTIONS = Object.freeze([
  'lambda:UpdateFunctionCode',
  'lambda:UpdateFunctionConfiguration',
  'codebuild:UpdateProject',
  'glue:UpdateJob',
  // glue:UpdateDevEndpoint: mutate an existing Glue dev endpoint (inject SSH public key /
  // custom libraries) and connect to run code as the endpoint's already-bound role - a
  // standalone code-exec primitive needing no iam:PassRole, same shape as glue:UpdateJob.
  'glue:UpdateDevEndpoint',
  'cloudformation:UpdateStack',
]);

export function detectComputeCodeOverwrite(allows, out, denies) {
  for (const stmt of allows) {
    // A bare "*" action is owned by WILDCARD-ACTION (and every PASSROLE-* critical it
    // implies); this detector targets SPECIFIC overwrite actions (service wildcards like
    // `lambda:*` are kept - they name a concrete service's overwrite capability). Mirrors
    // matchPatterns' `isFullWildcard` skip so an admin "*" is not double-flagged here with
    // a meaningless service:"*".
    const matched = grantedPatternsFor(stmt, COMPUTE_CODE_OVERWRITE_ACTIONS).filter((a) => a !== '*');
    if (matched.length === 0) continue;
    const deny = applyDenyToActions(denies, matched, stmt);
    if (deny.blocked) continue; // same-policy explicit Deny removes the path
    // Dedup: when a VIABLE iam:PassRole->service path already credited THIS statement's
    // overwrite grant, detectPassRolePaths (which runs first) has emitted a PASSROLE-*
    // finding (critical) covering it - PASSROLE-LAMBDA for lambda, PASSROLE-SERVICE for
    // codebuild/glue/cloudformation. Do not also emit the standalone HIGH finding there;
    // the paired case stays critical-only. When no such path exists (no PassRole, or a
    // PassRole that does not permit this service), no PASSROLE-* covers it and this fires.
    //
    // Stage-15 CRITICAL + Stage-16 per-action: the covering PASSROLE-* must itself be
    // BLOCKING (severity >= high) AND must credit the SAME SERVICE as the overwrite
    // action. A cross-account / non-viable PassRole is DEMOTED to PASSROLE-*:medium but
    // still overlaps the statement; suppressing on overlap ALONE let an inert cross-account
    // PassRole DECOY demote the pair to a sub-threshold medium and drop the standalone high
    // -> CLEAN (fail-open, worsened by supplying the correct subjectAccount). And a PassRole
    // path for service A (e.g. lambda) must not suppress an overwrite of service B (e.g.
    // glue) co-located in the same statement (a redundancy loss). So collect the set of
    // services credited by a BLOCKING (>= high) PASSROLE-* overlapping this statement, and
    // emit only for overwrite actions whose service is NOT already covered. The >= high gate
    // preserves the safety invariant: suppression only removes an action a blocking finding
    // already covers, so the verdict can never become a bare CLEAN through this dedup.
    const coveredServices = new Set();
    for (const f of out) {
      if (!/^PASSROLE-/.test(f.id)) continue;
      if (SEVERITY_RANK[f.severity] < SEVERITY_RANK.high) continue;
      const overlaps = f.statementIndex === stmt.index
        || (f.contributingStatements || []).some((cs) => cs.statementIndex === stmt.index);
      if (overlaps && f.escalation && f.escalation.service) coveredServices.add(f.escalation.service);
    }
    const actions = deny.actions.filter((a) => !coveredServices.has(String(a).split(':')[0]));
    if (actions.length === 0) continue; // every overwrite action is covered -> paired critical-only
    // Service is the prefix of the first surviving action (all surviving actions here are
    // NOT covered by a blocking PassRole path).
    const service = String(actions[0]).split(':')[0] || null;
    out.push(
      makeEscalation('COMPUTE-CODE-OVERWRITE', stmt, {
        // High, not critical (mirrors IAM-102): a standalone direct primitive, not a
        // compound privilege-boundary crossing. Critical is reserved for the compound
        // PassRole->service path (execution under a DIFFERENT, freshly-attached role).
        severity: 'high',
        // Grant present (evidence high). ELEVATION requires the existing resource's
        // execution role to be more privileged than the caller - a target whose power is
        // not in scope here (same unknown-target cap as CREDENTIAL-CREATION /
        // TRUST-POLICY-MODIFY) -> exploitability medium.
        policyEvidence: 'high',
        pathExploitability: 'medium',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'overwrite-existing-compute-code',
        service,
        requiredActions: actions.slice(),
        prerequisites: prerequisitesOf([
          prereqTechnique('overwrite-existing-compute-code', [prereqGroup(actions, 'primitive')], {}),
        ]),
        actions,
        resources: resourceScope(stmt),
        evidence: [evidenceOf(stmt, 'primitive', actions)],
        why:
          'Grants an "update existing compute" action (e.g. lambda:UpdateFunctionCode / ' +
          'UpdateFunctionConfiguration, codebuild:UpdateProject, glue:UpdateJob, ' +
          'cloudformation:UpdateStack). Overwriting the code (or code-selecting ' +
          'configuration) of an EXISTING resource runs attacker-supplied code under that ' +
          'resource\'s already-bound execution/service role - no iam:PassRole is required. ' +
          'Whether that role is more privileged than the caller is not known from this ' +
          'policy, but the code-execution primitive is present.',
        remediation:
          'Scope these update actions to specific resource ARNs, restrict them to a ' +
          'dedicated deployment role, and protect high-value compute (whose execution ' +
          'roles are privileged) with change review and a permission boundary.',
      }),
    );
  }
}

export function detectAssumeRoleExpansion(allows, out, denies) {
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


// S2-crossaccount-scoped-surface (A): surface a SCOPED sts:AssumeRole* whose target
// role lives in a DIFFERENT account than the analyzed principal. detectAssumeRole
// Expansion deliberately skips scoped (non-wildcard) assume grants as routine; that
// is correct WITHIN an account, but a scoped assume of a role in ANOTHER account is
// a cross-account privilege transition that otherwise read as CLEAN. Emitted at LOW
// severity + a can-assume graph edge, and ONLY when the subject account is KNOWN
// (via context/trust); an unknown subject stays conservative = the existing quiet
// behavior. Same-account scoped assume stays QUIET (the routine-use design). The
// finding states exploitability depends on the target role's trust policy +
// permissions, which are not in scope here.
export function detectCrossAccountScopedAssume(allows, out, denies, ctx) {
  const rawSubject = ctx && ctx.subjectAccount != null ? String(ctx.subjectAccount) : null;
  const subjectAccount = rawSubject && CONCRETE_ACCOUNT_ID_RE.test(rawSubject)
    ? rawSubject : null;
  if (!subjectAccount) return; // unknown subject -> conservative: stay QUIET
  for (const stmt of allows) {
    const matched = grantedPatternsFor(stmt, ASSUME_ROLE_ACTIONS);
    if (matched.length === 0) continue;
    // A broad / wildcard role scope is the ASSUME-ROLE-EXPANSION shape (already
    // emitted, with its own cross-account reasoning). Here we handle ONLY the
    // scoped-but-cross-account case that detector skips.
    if (resourceListIsBroadForAssume(stmt)) continue;
    const deny = applyDenyToActions(denies, matched, stmt);
    if (deny.blocked) continue; // same-policy explicit Deny removes the path
    const crossAccounts = [];
    // Collect the concrete cross-account role ARN(s) actually matched, in policy
    // order. The finding's `resources` MUST be this cross-account subset, NOT the
    // full statement scope: the graph builder keys the can-assume edge off
    // firstResource(f), so scoping to the cross subset makes the edge target the
    // cross-account role (not a same-account role that happens to be listed first),
    // drops the spurious same-account can-assume edge the HYBRID design keeps QUIET,
    // and makes the edge target order-independent. Mirrors the CROSS-ACCOUNT-DATA-READ
    // path (rules.js crossResources.slice()).
    const crossResources = [];
    for (const r of stmt.resources) {
      const acct = concreteRoleTargetAccount(r);
      if (!acct || acct === subjectAccount) continue; // same-account scoped -> QUIET
      if (!crossAccounts.includes(acct)) crossAccounts.push(acct);
      if (!crossResources.includes(r)) crossResources.push(r);
    }
    if (crossResources.length === 0) continue; // same-account scoped -> QUIET (routine)
    const actions = deny.actions;
    const scope = crossAccounts.length === 1
      ? 'account ' + crossAccounts[0]
      : 'accounts ' + crossAccounts.join(', ');
    out.push(
      makeEscalation('CROSS-ACCOUNT-ASSUME-ROLE', stmt, {
        // LOW: a scoped assume of ONE named role is not the broad expansion path; it
        // is surfaced only because it crosses the account boundary. Severity (scope)
        // is orthogonal to the two certainty signals below.
        severity: 'low',
        // The grant and the concrete cross-account role ARN are plainly in the policy
        // text -> policy evidence HIGH. But whether the assume succeeds and yields
        // elevated privilege depends on the target role's trust policy (it must trust
        // this principal) and the target role's permissions - neither is in scope here
        // -> path exploitability LOW.
        policyEvidence: 'high',
        pathExploitability: 'low',
        conditioned: hasNonEmptyCondition(stmt),
        denyNarrowed: deny.narrowed,
        technique: 'cross-account-assume-role',
        requiredActions: actions.slice(),
        prerequisites: prerequisitesOf([
          prereqTechnique('cross-account-assume-role', [prereqGroup(actions, 'primitive')], {}),
        ]),
        actions,
        // Cross-account subset only (see crossResources above): keeps the can-assume
        // graph edge on the cross-account role and off any same-account role.
        resources: crossResources.slice(),
        evidence: [evidenceOf(stmt, 'primitive', actions, 'cross-account role target')],
        why:
          'Grants sts:AssumeRole scoped to a specific role in ' + scope + ', which ' +
          'is a DIFFERENT AWS account than the analyzed principal (account ' +
          subjectAccount + '). Assuming a role in another account is a cross-account ' +
          'privilege transition: the principal would operate with the target role\'s ' +
          'permissions. Whether this is EXPLOITABLE depends on the target role\'s ' +
          'trust policy (it must permit this principal) and on the target role\'s ' +
          'permissions, neither of which is in scope here - so this is surfaced as a ' +
          'low-severity cross-account capability, not a confirmed escalation.',
        remediation:
          'Confirm the principal is intended to assume a role in ' + scope + '. If so, ' +
          'ensure the target role\'s trust policy trusts only the intended principals ' +
          'and gate the assumption with conditions (e.g. sts:ExternalId, ' +
          'aws:SourceAccount). If not, remove the cross-account role from the Resource ' +
          'scope.',
      }),
    );
  }
}
