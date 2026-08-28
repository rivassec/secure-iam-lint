// IAM Blast Radius - role-trust policy analyzer (IAM-801, Phase 8).
//
// A ROLE TRUST POLICY is a resource-based policy attached to a role that says
// WHO MAY ASSUME the role (docs/trust-policy-semantics.md). It is NOT an
// identity policy: it never conveys the assumed role's permissions. The family
// gate (family.js) detects the role-trust shape and routes it here INSTEAD OF
// the identity rules/escalation engine; identity rules are never run on a trust
// policy (they would emit spurious identity-style findings - e.g. a broad
// Resource finding for the Resource a trust policy legitimately omits).
//
// The load-bearing invariant (trust-policy-semantics.md section 0), enforced on
// EVERY finding this module emits:
//
//   A trust policy conveys WHO MAY ASSUME the role, never the assumed role's
//   permissions. The assumed role's actual privileges are OUT OF SCOPE / UNKNOWN
//   from this document. Overstating that an assumer "inherits the role's power"
//   is a truthfulness harm (threat-model T8).
//
// This module CLASSIFIES the trust policy text; it never asserts a runtime AWS
// STS allow/deny. Condition polarity is read from the text only (a StringEquals
// aws:PrincipalOrgID reads as a constraint; a StringNotEquals reads as an
// expansion) - never as a proven runtime outcome.
//
// Pure, deterministic. No network APIs. No eval/Function. No DOM. Same model ->
// same findings, every run. Hostile Principal/ARN/condition values are only ever
// read as strings; never interpreted as code or markup.
//
// The ONE dependency is escalation.js's same-policy Deny resolver (denyActionApplies
// + hasNonEmptyCondition), reused so trust Deny precedence (IAM-806) matches the
// identity engine's IAM-302 semantics EXACTLY rather than drifting a parallel copy
// (the same reason rules.js and graph.js import that resolver). It is cycle-safe:
// escalation.js imports only model.js, never trust.js/family.js/conditions.js.
import { denyActionApplies, hasNonEmptyCondition } from './escalation.js';
import {
  makeFinding, principalSummary, principalValueIsBroad, principalIsBroad, subsetPrincipals, principalsFromEntries, makeInvalidPrincipalFinding,
} from './trust-findings.js';
export * from './trust-findings.js';
import {
  parseOperatorParts, toValues, conditionSignals, hasConfusedDeputyConstraint, publicScopeConstraint,
} from './trust-conditions.js';
export * from './trust-conditions.js';
import {
  trustDenyStatements, canonicalPrincipalKey, buildDenyCoverage, principalEntryDeniedBy, trustFindingDenyState, summarizeTrustDeny,
} from './trust-deny.js';
export * from './trust-deny.js';
import {
  isTrustStatement, classifyPrincipals, add, awsPrincipalType, serviceType, federatedType,
} from './trust-classify.js';
export * from './trust-classify.js';
import {
  isAllGlobOrEmpty, hasGlob, accountOrOrgValueNarrows, arnAccountPinned, arnPinnedAccount, namedPrincipalAccounts, ARN_RESOURCE_TYPE_KEYWORDS, arnValueNarrows, principalPinsAccount, principalArnValueIsBroad, valueNarrowsKey, isAllAddressIp, err, deepFreeze, statementSid,
} from './trust-principal-helpers.js';
export * from './trust-principal-helpers.js';
import {
  TRUST_ACTIONS, ASSUME_ACTIONS, AUX_SESSION_ACTIONS, KNOWN_PRINCIPAL_TYPES, SOURCE_BINDING_SERVICES, TRUST_IDS, RULE_VERSION, TRUST_LIMIT, DOC_PRINCIPAL, DOC_CONDITION_KEYS, DOC_CONFUSED_DEPUTY, DOC_OIDC, NEGATED_OPERATORS, POSITIVE_STRING_MATCH_OPERATORS,
} from './trust-catalogs.js';
export * from './trust-catalogs.js';
// S3-dos-budget-all: trust.js had ZERO chargeWork() calls, so its policy-derived
// combinatorial loops (findingsForStatement's per-principal passes and, above all,
// trustFindingDenyState's principals x assume-actions x trust-Deny triple loop) NEVER
// advanced the shared work counter and NEVER sampled the wall-clock deadline - both
// ceilings are read only inside chargeWork(). A within-caps, validate-passing trust
// policy (N distinct trusted principals x M trust-Deny statements) therefore drove BOTH
// analyze() (browser default, auto-detected role-trust) and scan() (CLI, family:trust,
// budgetMs) to multiple seconds and returned a COMPLETE verdict - the Phase-17 lesson
// repeating on the sibling family after escalation.js was charged (threat-model T5/T8).
// Charging these loops makes the trust family participate in the SAME budget as the
// identity engine so a runaway fails CLOSED (aborted + incomplete on the browser;
// RESOURCE_BUDGET_EXCEEDED -> exit 3 on the CLI) instead of a slow COMPLETE pass.
// isGlobBudgetError lets analyzeTrust's catch re-throw a budget abort instead of
// masking it as an INTERNAL trust-analysis failure (which would bypass analyze()'s
// graceful fail-closed mapping and the CLI clock re-throw).
import { chargeWork, isGlobBudgetError } from './glob.js';

// The sts: action set that makes a statement a TRUST statement (compared
// case-insensitively). Mirrors docs/trust-policy-semantics.md section 3 and the
// TRUST_ACTIONS set family.js uses to detect the role-trust shape.

// Whether a positive-operator condition VALUE actually NARROWS the value space of
// the key it is matched against. A value that matches everything is not a real
// scoping / confused-deputy constraint and must never lower a trust finding.
//
// The plain cases (defect 2): the empty string and a value made only of "*"
// wildcards ("*", "**") match everything for ANY key. The subtler cases
// (adversarial iteration-4 under-claim): a StringLike/ArnLike value that contains
// a literal character but STILL matches the whole value space after wildcard
// expansion - e.g. ArnLike aws:SourceArn "arn:aws:*:*:*:*" (any ARN), StringLike
// aws:PrincipalOrgID "o-*" (every org id), StringLike aws:SourceAccount "1*"
// (an account id is never pinned by a wildcard; AWS also states wildcards in
// aws:SourceAccount have no valid use case), ArnLike aws:PrincipalArn
// "arn:aws:iam::*:*" (every IAM principal in every account). These slipped past
// the pure-wildcard guard and downgraded a dangerous trust a full severity band,
// so the check is now KEY-AWARE about what "narrowing" means for each key.
//
// A default-path value (sts:ExternalId, an OIDC sub reaching the default arm)
// that is made ENTIRELY of glob metacharacters ('*'/'?') pins NO literal content
// and so narrows nothing: '*'/'**' match every string, '?*'/'*?'/'**?'/'*?*'
// match every non-empty string (functionally identical to '*' - they differ only
// by excluding the empty string no caller sends), and '?'/'??' force a length but
// leave the content arbitrary. None is a real confused-deputy correlation value.
// The original guard rejected only '' and pure-'*', so a StringLike sts:ExternalId
// "?*" was credited as a narrowing constraint and dropped a whole-account external
// trust high->low - a vacuous ExternalId any attacker satisfies (adversarial-critic
// IAM-804 iteration 4 finding 2). Only a value carrying at least one LITERAL
// character narrows (a partial ExternalId still forces the caller to present that
// literal substring). Mirrors conditions.js valueNarrowsKey default arm.
function findingsForStatement(stmt) {
  const allPrincipals = classifyPrincipals(stmt.principal);
  const found = [];

  // S3-trust-calibration (1) - defense in depth. model.js normalizePrincipal() now
  // rejects an empty principal object / empty value array before analysis, so a
  // member-less principal cannot reach here through the real pipeline. But this
  // module is also called on hand-built models (tests, alternate callers), so treat
  // a principal.byType that classifies to ZERO members - not the wildcard "*"
  // (anyPrincipal) and carrying no unknown type key the family gate would own - as
  // MALFORMED and fail CLOSED, rather than falling through every substantive branch
  // to an empty finding list (a fail-OPEN that reports CLEAN on sts:AssumeRole). It
  // is surfaced as TRUST-INVALID-PRINCIPAL so analyze() also marks coverage
  // incomplete (the trusted set is undetermined, never a confident clean pass).
  if (!allPrincipals.anonymous &&
      allPrincipals.entries.length === 0 &&
      allPrincipals.unknownTypes.length === 0) {
    const path = `Statement[${stmt.index}].Principal`;
    const finding = makeFinding(stmt, allPrincipals, {
      id: 'TRUST-INVALID-PRINCIPAL',
      severity: 'high',
      title: 'Empty / member-less Principal (fail closed)',
      why:
        'The trust policy names a Principal element that contains NO principal value ' +
        '(an empty principal object {} or an empty principal value array). This is not ' +
        'a valid IAM Principal - AWS requires at least one principal value - so the ' +
        'trusted set is UNDETERMINED from this document. It must NOT be read as a ' +
        'benign, non-firing trust: the statement is fail-closed and surfaced as a ' +
        'coverage warning rather than a clean pass.',
      remediation:
        'Name at least one concrete principal (an account id / :root ARN, a specific ' +
        'role/user ARN, a Service principal, or a Federated provider ARN) in the ' +
        'Principal element, or use Principal "*" only if truly public trust is ' +
        'intended. An empty principal object or empty value array is invalid.',
      docRef: DOC_PRINCIPAL,
      pathExploitability: 'low',
    });
    finding.invalidPrincipalPaths = Object.freeze([
      Object.freeze({ path, value: '(empty principal)', key: null, index: null }),
    ]);
    found.push(finding);
    return found;
  }

  // IAM-903: fail closed on an INVALID partial-wildcard Principal-element ARN
  // (arn:aws:iam::123456789012:role/application/*, .../role/app-*,
  // arn:aws:iam::*:role/*, .../user/dev-*). The IAM Principal element cannot use a
  // partial wildcard to denote multiple principals - AWS rejects it at save time -
  // so it must NOT be silently accepted as an ordinary TRUST-CROSS-ACCOUNT high and
  // must NOT be expanded into trust for every role the pattern appears to match
  // (threat-model T8: overstated certainty on an unanalyzable shape). Emit a
  // distinct, clearly-caveated TRUST-INVALID-PRINCIPAL finding (analyze.js also
  // raises a coverage warning from it) and REMOVE these values before the
  // substantive branches, so no downstream branch (org-expansion / public /
  // cross-account / breadth) ever reasons about them. A wildcard in an
  // aws:PrincipalArn CONDITION value is a different, valid construct and is left
  // untouched (it is handled in conditionSignals, not here).
  let principals = allPrincipals;
  // IAM-903 + IAM-1006: fail closed on any INVALID partial-wildcard Principal
  // member, whichever key it appears under. A partial wildcard is invalid in the
  // AWS ARN, the Service, and the Federated Principal keys alike: the element does
  // not wildcard-match, so a globbed member matches NOTHING and the trusted set is
  // UNDETERMINED (threat-model T8 - never present a never-matching wildcard as a
  // complete, valid trust). Each invalid member is removed before the substantive
  // branches so no downstream branch (org-expansion / public / cross-account /
  // breadth / TRUST-SERVICE / TRUST-FEDERATED) ever reasons about it, and every
  // invalid member is surfaced as a caveated finding + coverage warning. A wildcard
  // in a CONDITION value (aws:PrincipalArn, OIDC :sub, ...) is a different, valid
  // construct handled in conditionSignals, not here.
  const INVALID_WILDCARD_TYPES = ['aws-principal-arn-wildcard', 'service-wildcard', 'federated-wildcard'];
  if (INVALID_WILDCARD_TYPES.some((t) => allPrincipals.categories.has(t))) {
    // IAM-1004: locate each invalid member precisely. When the Principal value is
    // an ARRAY, one poisoned member (e.g. index 1) must be identified by its
    // position - never silently dropped so only the valid member(s) are reported
    // as a complete result. Location follows the coverage path convention
    // (Statement[N].Principal.<key>[<i>]). A scalar Principal normalizes to a
    // 1-element array, so a single invalid value reads Principal.<key>[0].
    if (allPrincipals.categories.has('aws-principal-arn-wildcard')) {
      found.push(makeInvalidPrincipalFinding(
        stmt,
        subsetPrincipals(allPrincipals, ['aws-principal-arn-wildcard']),
        {
          title: 'Invalid wildcard Principal ARN (fail closed)',
          buildWhy: (invalidWho, invalidPaths) =>
            `The trust policy names an AWS Principal ARN that uses a partial wildcard ` +
            `to denote multiple principals (${invalidWho}). This is NOT a valid IAM ` +
            'Principal element: a principal ARN cannot use a partial "*"/"?" wildcard to ' +
            'match multiple user/role principals (AWS rejects such a policy at save ' +
            'time), and the standalone Principal "*" is the ONLY wildcard the element ' +
            'accepts. The trusted set is therefore UNDETERMINED from this document: it ' +
            'is not a single specific principal, and it must NOT be read as trust for ' +
            'every role the pattern appears to match. This statement is fail-closed and ' +
            'is surfaced as a coverage warning rather than an ordinary cross-account ' +
            'trust finding. The invalid element is located at ' +
            `${invalidPaths.join(', ')}: when a Principal AWS array mixes valid and ` +
            'invalid members, the invalid member is identified by its array index and ' +
            'the statement is NOT reported as a complete result for only the valid ' +
            'member(s).',
          remediation:
            'A principal ARN wildcard is invalid here. If the intent is to trust one ' +
            'specific role/user, name its exact ARN as the Principal. If the intent is ' +
            'to trust a SET of principals matching a pattern (and that is appropriate ' +
            'for the threat model), use Principal: "*" together with an aws:PrincipalArn ' +
            'condition (e.g. ArnLike aws:PrincipalArn arn:aws:iam::123456789012:role/' +
            'application/*) plus a confused-deputy constraint where a third party is ' +
            'involved - the wildcard is valid in that condition value, not in the ' +
            'Principal element itself.',
        },
      ));
    }
    // IAM-1006: a partial wildcard in a Service principal member.
    if (allPrincipals.categories.has('service-wildcard')) {
      found.push(makeInvalidPrincipalFinding(
        stmt,
        subsetPrincipals(allPrincipals, ['service-wildcard']),
        {
          title: 'Invalid wildcard Service principal (fail closed)',
          buildWhy: (invalidWho, invalidPaths) =>
            `The trust policy names a Service principal that contains a partial ` +
            `wildcard (${invalidWho}). This is NOT a valid Principal element: an AWS ` +
            'Service principal is an EXACT service identifier (e.g. lambda.amazonaws.com) ' +
            'and the Principal element does not wildcard-match service names, so a member ' +
            'carrying a "*"/"?" matches NO service and grants no service-role ' +
            'relationship. It must NOT be read as a normal, complete service trust. The ' +
            'trusted set is UNDETERMINED from this document: this statement is ' +
            'fail-closed and surfaced as a coverage warning rather than a valid service ' +
            `trust. The invalid element is located at ${invalidPaths.join(', ')}: when a ` +
            'Service array mixes valid and invalid members, the invalid member is ' +
            'identified by its array index and the statement is NOT reported as a ' +
            'complete result for only the valid member(s).',
          remediation:
            'A wildcard is invalid in a Service principal. Name each exact service ' +
            'identifier you intend to trust (e.g. lambda.amazonaws.com, ' +
            'ec2.amazonaws.com), one per member; the Service principal element does not ' +
            'support "*"/"?" wildcard matching.',
        },
      ));
    }
    // IAM-1006: a partial wildcard in a Federated principal member.
    if (allPrincipals.categories.has('federated-wildcard')) {
      found.push(makeInvalidPrincipalFinding(
        stmt,
        subsetPrincipals(allPrincipals, ['federated-wildcard']),
        {
          title: 'Invalid wildcard Federated principal (fail closed)',
          buildWhy: (invalidWho, invalidPaths) =>
            `The trust policy names a Federated principal that contains a partial ` +
            `wildcard (${invalidWho}). This is NOT a valid Principal element: a Federated ` +
            'principal is a SPECIFIC identity-provider ARN (an IAM OIDC/SAML provider, ' +
            'e.g. arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent' +
            '.com) or a built-in OIDC hostname, and the Principal element does not ' +
            'wildcard-match provider ARNs, so a member carrying a "*"/"?" matches NO ' +
            'provider and establishes no federated trust. It must NOT be read as a ' +
            'normal, complete federated trust. The trusted set is UNDETERMINED from this ' +
            'document: this statement is fail-closed and surfaced as a coverage warning. ' +
            `The invalid element is located at ${invalidPaths.join(', ')}: when a ` +
            'Federated array mixes valid and invalid members, the invalid member is ' +
            'identified by its array index and the statement is NOT reported as a ' +
            'complete result for only the valid member(s).',
          remediation:
            'A wildcard is invalid in a Federated principal. Name the exact identity-' +
            'provider ARN you intend to trust (e.g. arn:aws:iam::123456789012:oidc-' +
            'provider/<provider-host>); the Federated principal element does not support ' +
            '"*"/"?" wildcard matching. Scope which workloads may assume the role with a ' +
            "condition on the provider's :sub / :aud claim instead.",
        },
      ));
    }
    // Continue with only the VALID principals (a statement may legitimately name a
    // concrete account/root/service alongside an invalid wildcard); if none remain,
    // the invalid finding(s) are the whole story for this statement.
    const validTypes = [...allPrincipals.categories].filter((t) => !INVALID_WILDCARD_TYPES.includes(t));
    principals = subsetPrincipals(allPrincipals, validTypes);
    if (principals.entries.length === 0) return found;
  }

  const sig = conditionSignals(stmt.condition, principals);
  const who = principalSummary(principals);
  // A would-be constraint carrying a bypassable qualifier (...IfExists /
  // ForAllValues:) is NOT credited above and does not lower severity; name it so
  // the finding explains WHY the present-looking condition is not a guardrail
  // (adversarial-critic IAM-803 iteration 2 defect 1).
  const bypassNote = sig.bypassedQualifiers.length > 0
    ? ` A condition on ${[...sig.bypassedQualifiers].sort().join(', ')} uses an ` +
      '...IfExists suffix or a ForAllValues: set qualifier, which PASSES when the ' +
      'key is ABSENT from the request: the caller bypasses it by omitting the key, ' +
      'so it is NOT credited as an effective constraint and does not lower this finding.'
    : '';

  // 0) Auxiliary-session-only statement (no assume action). sts:TagSession /
  // sts:SetSourceIdentity are trust actions for family routing, but they do NOT
  // grant assumption (trust-policy-semantics.md section 3): each only PERMITS a
  // session feature (passing session tags / setting a source identity) on an
  // assume that some OTHER grant authorizes. AWS evaluates the assume action and
  // the auxiliary action for the SAME caller, so a caller lacking an sts:AssumeRole*
  // grant for this role never reaches these actions - the statement is inert on its
  // own. It must therefore NOT be emitted as a public / cross-account / federated
  // assume relationship at critical/high with "may assume" wording (that asserts an
  // assumption the action does not grant - adversarial-critic IAM-805 iteration 3
  // finding 1, threat-model T8). Downgrade to a single informational session-control
  // finding whose prose never claims assumption, and return before the assume-
  // oriented headlines below.
  const hasAssumeAction = stmt.actions.some((a) => ASSUME_ACTIONS.has(String(a).toLowerCase()));
  if (!hasAssumeAction) {
    const auxActions = stmt.actions
      .filter((a) => AUX_SESSION_ACTIONS.has(String(a).toLowerCase()))
      .map((a) => String(a));
    const auxList = auxActions.join(', ') || '(none)';
    found.push(makeFinding(stmt, principals, {
      id: 'TRUST-SESSION-CONTROL',
      severity: 'info',
      title: 'Session-control trust action only (no assume grant)',
      why:
        `The trust policy grants only an auxiliary session action (${auxList}) to ${who}, ` +
        'and NO assume action (sts:AssumeRole / sts:AssumeRoleWithSAML / ' +
        'sts:AssumeRoleWithWebIdentity). sts:TagSession only permits passing session ' +
        'tags on an assume, and sts:SetSourceIdentity only permits setting a source ' +
        'identity - each is REQUIRED in the trust policy for that feature to work but ' +
        'grants nothing on its own. AWS evaluates the assume action and this auxiliary ' +
        'action for the SAME caller, so a principal that cannot already assume this role ' +
        'via a separate grant never reaches this action. This statement therefore does ' +
        'NOT let the named principal assume the role; it is inert without a separate ' +
        'assume grant.' + bypassNote,
      remediation:
        'No assume relationship is created by this statement alone. If session tags or ' +
        'a source identity are intended, pair this with a scoped sts:AssumeRole* grant to ' +
        'the specific principals that must assume the role. If no assume grant for this ' +
        'principal exists elsewhere, this statement has no effect and can be removed.',
      docRef: DOC_PRINCIPAL,
      pathExploitability: 'low',
    }));
    return found;
  }

  // 1) Dangerous polarity headline: a negated aws:PrincipalOrgID reads as an
  // EXPANSION - it permits principals OUTSIDE the named org (trust-policy-
  // semantics 4.2, acceptance test 10). It is the CRITICAL org-WIDE story ONLY
  // when the named Principal is itself BROAD (a wildcard "*" / public principal):
  // then it trusts an organization-wide set of outside principals. When the named
  // Principal is BOUNDED (a specific account / root / role / user ARN), AWS still
  // evaluates Principal AND Condition, so the trusted set is at most that bounded
  // Principal - a cross-account case, not an org-wide expansion. Asserting
  // org-wide expansion at critical on a single-ARN Principal contradicts the
  // finding's own single-ARN evidence (adversarial defect IAM-802-C), so we fall
  // through to the cross-account branch (which carries the expansion-polarity
  // note) instead of returning a critical headline here.
  if (sig.orgExclusion && principalIsBroad(principals)) {
    found.push(makeFinding(stmt, principals, {
      id: 'TRUST-ORG-EXPANSION',
      severity: 'critical',
      title: 'Role trust condition excludes an organization (expansion polarity)',
      why:
        'The trust policy gates assume-role on aws:PrincipalOrgID with a NEGATED ' +
        '(StringNotEquals) operator, which reads as an EXPANSION: it permits ' +
        'principals OUTSIDE the named organization (subject to other request ' +
        'context), not a restriction to it. Combined with a broad/wildcard ' +
        `Principal, this trusts an organization-wide set of outside principals: ${who}.`,
      remediation:
        'Do not rely on a negated aws:PrincipalOrgID as a guardrail. If the intent ' +
        'is to confine trust to the organization, use a POSITIVE StringEquals ' +
        'aws:PrincipalOrgID and a specific, non-wildcard Principal. (The key is ' +
        'present with dangerous polarity - this is not a "missing PrincipalOrgID" case.)',
      docRef: DOC_CONDITION_KEYS,
      pathExploitability: 'medium',
    }));
    return found; // the org-exclusion is the authoritative critical finding.
  }

  // 2) Anonymous / public trust (Principal '*'): unrestricted role trust
  // (trust-policy-semantics 2.1 / 5, acceptance test 15). BUT a positive scoping
  // condition (aws:PrincipalOrgID StringEquals, aws:PrincipalArn,
  // aws:PrincipalAccount) narrows the wildcard so it is NOT anonymous/public -
  // in that case the finding must account for the condition and not overstate
  // (defect 3).
  if (principals.anonymous) {
    const scope = publicScopeConstraint(sig);
    if (scope) {
      found.push(makeFinding(stmt, principals, {
        id: 'TRUST-PUBLIC',
        severity: scope.severity,
        title: 'Wildcard-principal role trust narrowed by a scoping condition',
        why:
          'The trust policy names Principal "*", but a positive scoping condition ' +
          `(${scope.names}) is present that limits which principals may assume the ` +
          'role. It therefore does NOT trust anonymous or arbitrary other-account ' +
          'principals - only principals matching the condition are trusted. AWS ' +
          'still recommends against a wildcard Principal on an Allow: narrowing a ' +
          '"*" with a condition is fragile, and removing or mis-scoping the ' +
          'condition would expose the role. The breadth of trust equals the ' +
          `breadth of the condition (${scope.breadthDesc}).`,
        remediation:
          'Replace Principal "*" with the explicit accounts, roles, or federated ' +
          'identities that must assume this role rather than relying on a condition ' +
          'to narrow a wildcard principal; keep the scoping condition as defense in depth.',
        docRef: DOC_PRINCIPAL,
        pathExploitability: scope.severity === 'high' ? 'medium' : 'low',
      }));
      return found;
    }
    found.push(makeFinding(stmt, principals, {
      id: 'TRUST-PUBLIC',
      severity: 'critical',
      title: 'Public role trust (any principal may assume)',
      why:
        'The trust policy names Principal "*", so ANY AWS principal - including ' +
        'anonymous/other-account principals - is trusted to assume this role. AWS ' +
        'strongly warns against a wildcard principal on an Allow in a role trust ' +
        'policy because it lets outside principals become a principal in your account.' +
        bypassNote,
      remediation:
        'Replace Principal "*" with the specific accounts, roles, or federated ' +
        'identities that must assume this role, and add a confused-deputy ' +
        'constraint (e.g. sts:ExternalId, aws:SourceArn) where a third party is ' +
        'involved.',
      docRef: DOC_PRINCIPAL,
      pathExploitability: 'medium',
    }));
    return found;
  }

  // 3) Federated OIDC / SAML trust: subject scope drives severity
  // (trust-policy-semantics 4.4/4.5, acceptance test 17). This branch does NOT
  // early-return: a statement can name a Federated provider ALONGSIDE an external
  // AWS account/root/principal-ARN, and that co-present cross-account trust is a
  // SEPARATE relationship that must be surfaced at its own severity below (the
  // graph already draws its can-assume edge - adversarial defect IAM-802-A). The
  // finding names only the federated principals via a filtered subset.
  if (principals.categories.has('federated-oidc') || principals.categories.has('federated-saml')) {
    const fed = subsetPrincipals(principals, ['federated-oidc', 'federated-saml']);
    const fedWho = principalSummary(fed);
    const broad = sig.subScope !== 'tight'; // broad, or no subject condition at all
    found.push(makeFinding(stmt, fed, {
      id: 'TRUST-FEDERATED',
      severity: broad ? 'high' : 'low',
      title: 'Federated identity role trust',
      why: broad
        ? 'The trust policy federates assume-role to an external identity provider ' +
          `(${fedWho}) with a BROAD or absent subject scope. A subject such as ` +
          'repo:org/* (or no subject condition) trusts an organization-wide set of ' +
          'workloads rather than one specific workload. ' +
          (sig.audConstraint ? 'The audience (aud) check is a valid constraint and is recognized. ' : '') +
          bypassNote
        : 'The trust policy federates assume-role to an external identity provider ' +
          `(${fedWho}) with a TIGHTLY-scoped subject (bound to a specific ` +
          'repository + ref/branch/environment). ' +
          (sig.audConstraint ? 'The audience (aud) check is a valid constraint and is recognized. ' : ''),
      remediation: broad
        ? 'Constrain the subject (sub) condition to the intended repository AND ' +
          'branch/environment (e.g. repo:org/repo:ref:refs/heads/main), not an ' +
          'org-wide wildcard. Keep the audience (aud) check in place.'
        : 'Subject scope looks specific; keep the audience (aud) and subject (sub) ' +
          'conditions in place and review periodically.',
      docRef: DOC_OIDC,
      pathExploitability: broad ? 'medium' : 'low',
    }));
  }

  // 4) External AWS account / root / principal-ARN / canonical-user trust: HIGH
  // when unconditioned; LOWERED to low/medium by a confused-deputy constraint
  // (trust-policy-semantics 2.2-2.4 / 5, acceptance test 16).
  const externalCats = ['aws-account', 'aws-root', 'aws-principal-arn', 'canonical-user']
    .filter((c) => principals.categories.has(c));
  if (externalCats.length > 0) {
    const ext = subsetPrincipals(principals, externalCats);
    const extWho = principalSummary(ext);
    const constrained = hasConfusedDeputyConstraint(sig);
    const constraintName = sig.externalId ? 'sts:ExternalId'
      : sig.sourceArnAccount ? 'aws:SourceArn / aws:SourceAccount'
      : sig.orgConstraint ? 'aws:PrincipalOrgID (StringEquals)'
      : null;
    // Is the EXTERNAL principal this finding is about itself BROAD - a wildcard
    // ARN not pinned to a single account (arn:aws:iam::*:role/*, spanning every
    // role in every account, which principalValueIsBroad classifies as org-wide)?
    // A confused-deputy constraint (sts:ExternalId / aws:SourceArn /
    // aws:SourceAccount / aws:PrincipalOrgID StringEquals) correlates HOW the
    // assume call is made but does NOT bound WHICH or HOW-MANY principals of an
    // unbounded principal set are trusted, so on a broad principal it must NOT
    // drop severity to low - the whole-fleet breadth stays HIGH (at most the
    // constraint lowers path-exploitability). The confused-deputy -> low band is
    // reserved for an account-BOUNDED external principal. This reuses
    // principalIsBroad()/arnAccountPinned() to match the breadth gate branch 1
    // (org-exclusion) already applies (adversarial-critic IAM-805 iteration 4
    // finding IAM805-1: a two-band high->low under-claim on a global wildcard-ARN
    // principal gated only by a non-secret, non-bounding correlation value, while
    // the identical Principal "*" + ExternalId correctly stays critical - a purely
    // principal-string-TYPE asymmetry, not an actual-breadth difference).
    const extIsBroad = principalIsBroad(ext);
    // A confused-deputy constraint lowers to low ONLY for an account-bounded
    // external principal; on a broad principal it is present but non-lowering.
    const constrainedLowers = constrained && !extIsBroad;
    // A positive aws:PrincipalArn condition pins WHICH principal(s) WITHIN the
    // trusted account may assume the role - a genuine SUB-account scope - so it is
    // honored here rather than ignored: otherwise the finding falsely asserts "any
    // identity the trusted account authorizes can assume" when the same-statement
    // condition pins exactly one role (adversarial iteration-4 wrong-provenance
    // over-claim). Read SYMMETRICALLY with the Principal "*" path
    // (publicScopeConstraint): a broad (wildcarded) aws:PrincipalArn stays high; an
    // exact aws:PrincipalArn drops to medium. Breadth is the Principal-AND-Condition
    // INTERSECTION (principalArnValueIsBroad): a glob in the account segment the
    // named Principal already pins adds no breadth (adversarial iteration-2 finding
    // 3: arn:aws:iam::*:role/deploy under root:999 is a single role -> medium, not
    // high). A confused-deputy constraint, if also present, is the stronger
    // mitigation and still wins (low).
    //
    // aws:PrincipalAccount is deliberately NOT a sub-account scope: it is ACCOUNT-
    // granularity - the SAME granularity an account/root Principal already carries -
    // so it never narrows below whole-account and must NOT lower this finding below
    // the unconditioned high baseline (adversarial iteration-2 finding 1: root:123 +
    // PrincipalAccount==123 is fully redundant, still whole-account). It is surfaced
    // as a note on the whole-account finding, not treated as a narrowing scope.
    const principalScopePresent = sig.principalArnScope !== null;
    const principalScopeName = 'aws:PrincipalArn';
    const scopeSeverity = sig.principalArnScope === 'broad' ? 'high' : 'medium';
    // S3-trust-calibration (3): a positive aws:PrincipalArn only NARROWS this
    // finding when it scopes WITHIN the trusted account. A tight aws:PrincipalArn
    // whose pinned account is FOREIGN to the named Principal (sig.principalArnForeign)
    // is itself a cross-account ARN: it names a principal OUTSIDE the trusted
    // account, so the whole-account external trust is not narrowed at all and must
    // stay HIGH (it must NOT be scored one band below the direct-external baseline).
    // A SAME-account exact aws:PrincipalArn is a genuine sub-account narrowing and
    // still drops to medium as designed.
    const principalScopeNarrows = principalScopePresent && !sig.principalArnForeign;
    // A present aws:PrincipalAccount that does NOT narrow below whole-account: named
    // so the (still-high) finding explains why the present-looking condition is not
    // a sub-account guardrail, instead of silently ignoring it.
    const noteAccountScope = sig.principalAccount
      ? ' A positive aws:PrincipalAccount condition is also present, but it is ' +
        'ACCOUNT-granularity - exactly what an account/root Principal already ' +
        'carries - so it does NOT narrow below the whole account and does not lower ' +
        'this finding.'
      : '';
    // MFA / SourceIp are request-context DEFENSE IN DEPTH: present, they harden
    // HOW the call is made but do NOT narrow WHICH principal in the trusted
    // account is trusted, so they never drop this below high (IAM-802-B). They
    // lower path-exploitability one band, no more.
    const defenseInDepth = !constrained && !principalScopePresent && (sig.mfa || sig.sourceIp);
    const defenseName = defenseInDepth
      ? (sig.mfa && sig.sourceIp ? 'aws:MultiFactorAuthPresent and aws:SourceIp'
        : sig.mfa ? 'aws:MultiFactorAuthPresent' : 'aws:SourceIp')
      : null;
    const noteDefense = defenseInDepth
      ? ` A request-context control (${defenseName}) is present; it is defense in ` +
        'depth and does NOT narrow which principal in the trusted account may ' +
        'assume the role, so it does not lower this below high.'
      : '';
    // A negated aws:PrincipalOrgID on a BOUNDED principal reached this branch
    // (IAM-802-C): it is an EXPANSION-polarity condition, never a protective org
    // restriction, and it does not widen trust beyond the named principal.
    const noteOrgExclusion = sig.orgExclusion
      ? ' A negated aws:PrincipalOrgID (StringNotEquals) is also present: it reads ' +
        'as an EXPANSION (principals OUTSIDE the named organization), NOT a ' +
        'restriction to it, and it does not narrow the named principal.'
      : '';
    // A confused-deputy constraint present on a BROAD principal: named so the
    // (still-high) finding explains why the present-looking constraint does not
    // lower it, instead of silently ignoring it (mirrors noteDefense /
    // noteAccountScope). Non-empty only when constrained && extIsBroad.
    const noteBroadConstraint = (constrained && extIsBroad)
      ? ` A confused-deputy constraint (${constraintName}) is also present, but the ` +
        'named Principal is a wildcard ARN that is NOT pinned to a single account ' +
        '(it spans principals across every AWS account). The constraint correlates ' +
        'the assume call but does NOT bound WHICH or HOW MANY of that unbounded ' +
        'principal set may assume the role, so it lowers exploitability only and ' +
        'does not drop this below high.'
      : '';
    // A present aws:PrincipalArn that pins a principal in a DIFFERENT account than
    // the trusted Principal: named on the (still-high) baseline finding so it
    // explains why the present-looking scoping condition is not a sub-account
    // narrowing, instead of silently understating the trust. Non-empty only when a
    // foreign-account principal-ARN scope is present.
    const noteForeignScope = (principalScopePresent && sig.principalArnForeign)
      ? ' A positive aws:PrincipalArn condition is also present, but it pins a ' +
        'principal ARN in a DIFFERENT account than the trusted Principal (a ' +
        'cross-account ARN). AWS evaluates Principal AND Condition, so it does NOT ' +
        'narrow WHICH principal within the trusted account may assume the role, and ' +
        'it does not lower this finding below high.'
      : '';

    let severity;
    if (constrainedLowers) severity = 'low';
    else if (principalScopeNarrows) severity = scopeSeverity;
    else severity = 'high';

    let pathExpl;
    if (constrained || defenseInDepth) pathExpl = 'low';
    else if (principalScopeNarrows) pathExpl = scopeSeverity === 'high' ? 'medium' : 'low';
    else pathExpl = 'medium';

    let whyText;
    let remediationText;
    let docRefUsed;
    if (constrainedLowers) {
      whyText =
        `The trust policy delegates assume-role to an external/other-account ` +
        `principal (${extWho}), gated by a confused-deputy constraint ` +
        `(${constraintName}). ${sig.externalId ? 'sts:ExternalId is a per-customer confused-deputy mitigation - a correlation value the third party sends on each AssumeRole call; it is NOT authentication and NOT a secret. ' : ''}` +
        'The constraint lowers exploitability but the trusted account still ' +
        'delegates to any identity its administrator authorizes.';
      remediationText =
        'Scope the trusted Principal to the specific role/user ARNs that must ' +
        'assume this role and keep the confused-deputy constraint. Do not treat ' +
        'the external ID as a secret; rotate the trust if the vendor relationship ends.';
      docRefUsed = DOC_CONFUSED_DEPUTY;
    } else if (principalScopeNarrows) {
      whyText =
        `The trust policy names an external/other-account principal (${extWho}), ` +
        `but a positive principal-scoping condition (${principalScopeName}) pins ` +
        'WHICH principal(s) in the trusted account may assume the role. It therefore ' +
        'does NOT trust the whole account: only principals matching the condition are ' +
        `trusted (${scopeSeverity === 'high' ? 'a wildcarded set of principals within the pinned account' : 'a specific principal (a single role/user)'}). ` +
        'Narrowing a broad account/root Principal with a condition is fragile - ' +
        'removing or mis-scoping the condition would widen trust back to the whole ' +
        'named account.' + noteAccountScope + noteDefense + noteOrgExclusion;
      remediationText =
        'Name the specific role/user ARNs that must assume this role directly as the ' +
        'Principal instead of trusting the whole account and narrowing with an ' +
        'aws:PrincipalArn/aws:PrincipalAccount condition; keep the scoping condition ' +
        'as defense in depth, and add a confused-deputy constraint (sts:ExternalId) ' +
        'if a third party is involved.';
      docRefUsed = DOC_PRINCIPAL;
    } else {
      // High baseline: either a genuinely unconditioned external trust, OR a BROAD
      // wildcard-ARN principal whose confused-deputy constraint is present but does
      // not lower it (noteBroadConstraint carries that explanation). The "no
      // confused-deputy constraint" clause is therefore conditional - it must not
      // claim absence when a (non-lowering) constraint IS present.
      whyText =
        `The trust policy delegates assume-role to an external/other-account ` +
        `principal (${extWho})` +
        (constrained ? '.' : ' with no confused-deputy constraint.') +
        ' An account/root principal trusts the WHOLE account (not only its root ' +
        'user); a wildcard-ARN principal that spans every account trusts a ' +
        'correspondingly unbounded set: any identity the trusted account(s) ' +
        'authorize can assume this role.' +
        noteAccountScope + noteDefense + noteOrgExclusion + noteBroadConstraint +
        noteForeignScope + bypassNote;
      remediationText =
        'Scope the trusted Principal to specific role/user ARNs, and add a ' +
        'confused-deputy constraint (sts:ExternalId for a third party, or ' +
        'aws:SourceArn/aws:SourceAccount for a service caller).';
      docRefUsed = DOC_PRINCIPAL;
    }
    found.push(makeFinding(stmt, ext, {
      id: 'TRUST-CROSS-ACCOUNT',
      severity,
      title: 'External / cross-account role trust',
      why: whyText,
      remediation: remediationText,
      docRef: docRefUsed,
      pathExploitability: pathExpl,
    }));
  }

  // 5) Service-principal trust (e.g. lambda.amazonaws.com): normal AWS service
  // trust - informational only, never an external/escalation finding, and never
  // an inference about the role's permissions (trust-policy-semantics 2.5 / 5,
  // acceptance test 18, the negative control).
  if (principals.categories.has('service')) {
    const svc = subsetPrincipals(principals, ['service']);
    // S3-trust-calibration (2): split the service principals into those that
    // REQUIRE a confused-deputy source binding (SOURCE_BINDING_SERVICES) and are
    // NOT source-bound here, versus ordinary/execution-role service trusts.
    // sig.sourceArnAccount is true ONLY for a POSITIVE, value-narrowing (non-
    // bypassable, non-match-all) aws:SourceArn / aws:SourceAccount match, so a
    // vacuous / negated / ...IfExists / ForAllValues / match-all source condition
    // still counts as UNBOUND and fails closed here (the same non-vacuous gate the
    // cross-account confused-deputy branch uses).
    const sourceBound = sig.sourceArnAccount;
    const isCd = (e) => SOURCE_BINDING_SERVICES.has(String(e.value).toLowerCase());
    const unboundCd = sourceBound ? [] : svc.entries.filter(isCd);
    const infoEntries = svc.entries.filter((e) => !unboundCd.includes(e));

    if (unboundCd.length > 0) {
      const cd = principalsFromEntries(unboundCd);
      const cdWho = unboundCd.map((e) => e.value).join(', ');
      found.push(makeFinding(stmt, cd, {
        id: 'TRUST-SERVICE',
        // HIGH (not info): a confused-deputy-relevant service trust with no source
        // binding is a real cross-service exposure, and it must be BLOCKING - it
        // must never read clean / exit 0 on the default threshold. pathExploitability
        // stays medium because viability depends on whether the calling service
        // supports and populates the source request context (hedged, truthful).
        severity: 'high',
        title: 'Service role trust without a confused-deputy source binding',
        why:
          `The trust policy lets an AWS service principal (${cdWho}) assume this role ` +
          'with NO effective aws:SourceArn / aws:SourceAccount binding. This service ' +
          'acts on behalf of a SOURCE resource/account that a caller in another account ' +
          'can control, so without a source binding an actor who can make the service ' +
          'act - for example by configuring it (an EventBridge rule, an S3 bucket, an ' +
          'SNS topic, ...) in their own account - may be able to induce it to assume ' +
          'this role on their behalf: the cross-service confused-deputy problem. ' +
          'Whether the exposure is reachable is subject to whether the calling service ' +
          'supports and populates the source request context. The assumed role\'s own ' +
          'permissions are out of scope / unknown from this document.' + bypassNote,
        remediation:
          'Add a confused-deputy source binding to this trust statement: aws:SourceArn ' +
          '(ArnEquals / ArnLike) scoped to the specific calling source resource, and/or ' +
          'aws:SourceAccount (StringEquals) scoped to the source account, using the keys ' +
          'the calling service supports.',
        docRef: DOC_CONFUSED_DEPUTY,
        pathExploitability: 'medium',
      }));
    }
    if (infoEntries.length > 0) {
      const info = principalsFromEntries(infoEntries);
      const svcOnly = infoEntries.map((e) => e.value).join(', ');
      found.push(makeFinding(stmt, info, {
        id: 'TRUST-SERVICE',
        severity: 'info',
        title: 'AWS service role trust',
        why:
          `The trust policy lets an AWS service principal (${svcOnly}) assume this ` +
          'role - a normal service-role relationship. No external-account or public ' +
          'trust is present. Whether this is risky depends entirely on the role\'s ' +
          'own permissions, which are not in this document.',
        remediation:
          'For a service trust that acts on a specific resource, consider adding an ' +
          'aws:SourceArn / aws:SourceAccount confused-deputy constraint. Otherwise ' +
          'no change is indicated by the trust policy alone.',
        docRef: DOC_PRINCIPAL,
        pathExploitability: 'low',
      }));
    }
  }

  return found;
}

// --- Same-policy explicit-Deny precedence for trust (IAM-806) ----------------
//
// A role trust policy can carry an explicit Deny that removes an assume grant the
// same policy's Allow appears to make (AWS explicit-Deny precedence: an in-scope
// Deny always wins). analyzeTrust is deliberately Deny-UNAWARE when it emits
// findings - a Deny is never itself a positive trust grant (see the analyzeTrust
// loop and the trust.test.js contract "analyzeTrust never runs on a Deny trust
// statement"), exactly as rules.js is Deny-unaware on the identity side. The
// pipeline (analyze.js) then applies precedence to the AUTHORITATIVE TABLE via
// trustFindingDenyState(), and the trust graph (graph.js buildTrustGraph) draws a
// blocked-by-deny `denies` edge - the same split the identity engine uses
// (ruleFindingDenySuppressed + graph addDenyEdges, IAM-302). Ignoring the Deny
// would over-claim "any principal may assume" a role a same-policy Deny renders
// unassumable (threat-model T8, a truthfulness harm).

// All same-policy trust Deny statements (Deny effect + trust shape).
export function analyzeTrust(model) {
  const errors = [];
  try {
    if (!model || typeof model !== 'object' || !Array.isArray(model.statements)) {
      errors.push(err('NO_MODEL', 'analyzeTrust() requires a normalized model.'));
      return Object.freeze({ ok: false, errors: Object.freeze(errors), findings: Object.freeze([]) });
    }

    const findings = [];
    // S3-dos-budget-all: charge the top-level statement walk so even the family's outer
    // loop participates in the budget (findingsForStatement / classifyPrincipals charge
    // the per-principal work beneath it).
    chargeWork(model.statements.length);
    for (const stmt of model.statements) {
      // Only Allow trust statements grant a trust relationship; a Deny restricts
      // who may assume and is never itself a positive trust grant. A same-policy
      // Deny is NOT discarded, though: its precedence over an Allow trust grant is
      // applied downstream (analyze.js via trustFindingDenyState suppresses a
      // fully-neutralized finding from the table; graph.js buildTrustGraph draws
      // the blocked-by-deny `denies` edge; coverage surfaces it via
      // summarizeTrustDeny). This mirrors the identity engine (rules.js stays
      // Deny-unaware; analyze.js + graph.js apply IAM-302 precedence).
      if (stmt.effect !== 'Allow') continue;
      if (!isTrustStatement(stmt)) continue;
      for (const f of findingsForStatement(stmt)) findings.push(f);
    }

    // Deterministic order: by statement index, then by trust id order.
    const idOrder = new Map(TRUST_IDS.map((id, i) => [id, i]));
    findings.sort((a, b) => {
      if (a.statementIndex !== b.statementIndex) return a.statementIndex - b.statementIndex;
      return (idOrder.get(a.id) ?? 99) - (idOrder.get(b.id) ?? 99);
    });

    for (const f of findings) deepFreeze(f);
    return Object.freeze({ ok: true, errors: Object.freeze(errors), findings: Object.freeze(findings) });
  } catch (e) {
    // S3-dos-budget-all: a tripped resource budget is NOT an internal trust fault. If
    // this catch masked it as an ok:false INTERNAL error, trustResult() would return a
    // plain fail() instead of analyze()'s graceful fail-closed abortedResult, and the
    // CLI wall-clock ('clock') abort would never reach scan()'s RESOURCE_BUDGET_EXCEEDED
    // mapping. Re-throw budget errors so the outer analyze() try/catch maps them (work
    // -> aborted+incomplete; clock -> re-thrown to the Node adapter). Only genuine
    // faults become an INTERNAL trust-analysis error.
    if (isGlobBudgetError(e)) throw e;
    errors.push(err('INTERNAL', 'Trust analysis failed unexpectedly.'));
    return Object.freeze({ ok: false, errors: Object.freeze(errors), findings: Object.freeze([]) });
  }
}

export default analyzeTrust;
