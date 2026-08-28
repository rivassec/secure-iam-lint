// IAM Blast Radius - resource-based-policy evaluator (Phase 12, IAM-1201).
//
// A resource-based policy is analyzed from the RESOURCE's perspective: WHO may
// act on THIS attached resource, under what conditions (docs/resource-policy-
// semantics.md section 0). It is NOT an identity policy and must never be run
// through the identity rules/escalation engine - doing so would emit confident
// but wrong identity-style findings (threat-model T8).
//
// This module is the family-aware entry point the orchestrator (analyze.js)
// routes a `resource` family to, exactly as it routes role-trust to trust.js and
// permissions-boundary/session to envelope.js. IAM-1201 is the FOUNDATIONAL
// tranche: it ACCEPTS the resource family, requires the explicit attached-
// resource context (type + ARN), DETECTS the service, and ROUTES here. The
// specific resource finding families (public-access + transport, confused-deputy,
// same-account grants, KMS key-policy, condition composition, NotPrincipal
// hazard) are the subsequent Phase-12 stories (IAM-1202..1206); this tranche
// deliberately emits no risk findings yet and reports coverage as INCOMPLETE so a
// public grant is never silently presented as a complete, empty analysis.
//
// Load-bearing invariants enforced here (resource-policy-semantics.md section 10):
//   - Resource-policy context is EXPLICIT: the attached resource type + ARN are
//     required inputs. Missing/invalid context fails closed
//     (RESOURCE_CONTEXT_REQUIRED); the analyzer never guesses the resource type.
//   - Fail closed on a genuinely-unmodeled resource shape
//     (UNSUPPORTED_RESOURCE_SHAPE); "unsupported != safe".
//
// Pure, deterministic, dependency-free. No network APIs. No eval/Function. No
// DOM. Same input (+ same context) -> same output, every run.

import { classifyPrincipals } from './trust.js';
import {
  MESSAGING_DATA_PLANE_VECTORS, SNS_CONTROL_ACTIONS, SQS_CONTROL_ACTIONS, messagingActionParts, isMessagingServiceWildcard, messagingControlSet, namesSourceOwner, messagingPerServiceRules,
} from './resource-messaging-rules.js';
export * from './resource-messaging-rules.js';
import {
  KMS_VIA_SERVICE_KEY, KMS_GRANT_IS_FOR_AWS_RESOURCE_KEY, kmsActionName, kmsChannelDecoyKeys, namesGrantIsForAwsResource, kmsHasAccountDelegation, kmsHasAnonymousAllow, kmsPerServiceRules,
} from './resource-kms-rules.js';
export * from './resource-kms-rules.js';
import {
  S3_BUCKET_CONTROL_ACTIONS, isS3BucketControlAction, S3_REQUEST_PROPERTY_KEYS, S3_RESOURCE_ACCOUNT_KEYS, isRequestPropertyOnlyCondition, collectRequestPropertyDenyKeys, s3NonPrincipalDecoyKeys, s3PerServiceRules,
} from './resource-s3-rules.js';
export * from './resource-s3-rules.js';
import {
  enumeratePrincipals, accountOfEntry, isTransportOnlyCondition, hasTransportOnlyDeny,
} from './resource-shared.js';
export * from './resource-shared.js';
import {
  S3_OBJECT_ACTIONS, isS3ObjectAction, s3ResourceScope, summarizeEntries, makeResourceFinding,
} from './resource-finding.js';
export * from './resource-finding.js';
import {
  principalSubKind, SUBKIND_LABELS, FAIL_CLOSED_PRINCIPAL_TYPES, FAIL_CLOSED_PRINCIPAL_META,
} from './resource-principal-classification.js';
export * from './resource-principal-classification.js';
import {
  PRINCIPAL_SCOPING_KEYS, KMS_PRINCIPAL_SCOPING_KEYS, isPrincipalScopingKey, operatorNegatesScope, principalScopingAnalysis, NETWORK_SELECTOR_KEYS, selectorCategory, conditionKeyInventory, describeConditionComposition,
} from './resource-conditions.js';
export * from './resource-conditions.js';
import {
  POSITIVE_MATCH_OPERATORS, accountFromSourceValue, isMatchAllSourceValue, toSourceValueList, commonSourceAccount, sourceAccountSet, sourceBindingAnalysis,
} from './resource-source-binding.js';
export * from './resource-source-binding.js';
import {
  parseArn, serviceForArn, parseResourceContext,
} from './arn-util.js';
export * from './arn-util.js';
import {
  RESOURCE_CODES, RESOURCE_SERVICES, MODELED_RESOURCE_SERVICES, RESOURCE_IDS, RESOURCE_RULE_VERSION, RESOURCE_LIMIT, DOC_PRINCIPAL, DOC_CROSS_ACCOUNT, DOC_S3_BPA, DOC_CONFUSED_DEPUTY, DOC_EVAL_LOGIC, DOC_S3_ACTIONS, DOC_S3_POLICY_KEYS, DOC_KMS_KEY_POLICY, DOC_KMS_OVERVIEW, DOC_KMS_CONDITIONS, DOC_KMS_GRANTS, DOC_SNS_ACCESS, DOC_SQS_ACCESS, RESOURCE_SERVICE_LABELS,
} from './resource-catalogs.js';
export * from './resource-catalogs.js';
import { parseOperator, NEGATED_OPERATORS } from './conditions.js';
// S3-dos-budget-all: the resource family analyzer is the sibling of trust.js/
// escalation.js and must participate in the SAME deterministic work / wall-clock budget
// so no family surface is a budget-blind fail-open (threat-model T5/T8, the "fix the
// CLASS" mandate). Its per-principal work is already charged transitively through the
// now-charged classifyPrincipals (trust.js); these charges make its outer statement
// walks participate too, so a runaway on the resource path fails CLOSED
// (RESOURCE_BUDGET_EXCEEDED) exactly like the identity/trust paths rather than grinding
// unbudgeted. chargeWork is a no-op when no budget is armed, so verdicts never change.
import { chargeWork } from './glob.js';

// Stable, machine-readable coverage codes owned by the resource family. Kept here
// (not in family.js) so the resource module owns its own vocabulary; family.js
// re-exports/uses them for the gate.


// --- Same-account named-principal grants (IAM-1204) --------------------------
//
// Within a single account AWS evaluates the UNION of identity-based and resource-
// based permissions: a resource-policy Allow to a same-account principal can grant
// access even when that principal's identity policy is SILENT (an implicit deny in
// the identity policy does not, on its own, defeat a direct same-account resource-
// policy grant). This is why a same-account resource grant is materially different
// from an identity grant (resource-policy-semantics.md section 1.1 / 7.2; test 32).
// An applicable explicit Deny - in the identity policy, a permissions boundary, an
// SCP/RCP, or the resource policy itself - still blocks. The analyzer reports the
// direct grant with that caveat, keeps each principal typed distinctly, and NEVER
// collapses an assumed-role session to its underlying role (test 33).


function resourceFindings(model, ctx) {
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  const findings = [];
  const service = ctx.service || null;
  const attachedArn = ctx.arn || null;
  // IAM-1204: the resource's OWNING account (explicit context account, else the
  // ARN's account for SNS/SQS/KMS, else null). Used to classify a named principal
  // as same-account vs cross-account. Null -> the relationship is undetermined and
  // the analyzer hedges (never assumes same-account).
  const resourceAccount = ctx.ownerAccount != null && /^\d{12}$/.test(String(ctx.ownerAccount))
    ? String(ctx.ownerAccount)
    : null;
  const isS3 = service === RESOURCE_SERVICES.S3_BUCKET || service === RESOURCE_SERVICES.S3_OBJECT;
  // The explicit context account is what lets S3 (whose ARN carries no account)
  // resolve same-vs-cross; distinguishing it drives the "undetermined" reason text.
  const explicitOwnerAccount = resourceAccount !== null
    && !/^\d{12}$/.test(String(ctx.account || ''));
  const serviceLabel = RESOURCE_SERVICE_LABELS[service] || 'attached resource';
  const transportOnlyDeny = hasTransportOnlyDeny(model);

  // S3-dos-budget-all: charge the statement walk so the resource family's outer loop
  // participates in the budget (per-principal work beneath it is charged in
  // classifyPrincipals, called once per statement below).
  chargeWork(statements.length);
  for (const stmt of statements) {
    // A resource finding describes who a GRANT reaches. Deny statements are not
    // positive grants (a transport-only Deny is handled as an annotation, not a
    // finding; general Deny suppression is out of this tranche's scope).
    if (!stmt || stmt.effect !== 'Allow') continue;
    const c = classifyPrincipals(stmt.principal);
    const conditioned = stmt.condition && typeof stmt.condition === 'object'
      && !Array.isArray(stmt.condition) && Object.keys(stmt.condition).length > 0;

    // 0) Fail-closed unmodeled / invalid Principal types (IAM-1208 fix 4). Emitted
    // FIRST - before the anonymous branch's `continue` below - so a CanonicalUser or
    // an invalid wildcard-ARN / service-wildcard / federated-wildcard principal
    // co-listed with any other type on the same statement still surfaces >=1
    // finding and is never silently dropped (no zero-findings fail-open). One
    // finding per distinct fail-closed type present, in deterministic order, each
    // reusing the canonical resource-finding shape (carries RESOURCE_LIMIT). These
    // types are NOT handled by the anonymous / named-account / service branches
    // below (which filter to their own specific types), so this is additive, never
    // double-counting.
    for (const failType of FAIL_CLOSED_PRINCIPAL_TYPES) {
      const typedEntries = c.entries.filter((e) => e.type === failType);
      if (typedEntries.length === 0) continue;
      const meta = FAIL_CLOSED_PRINCIPAL_META[failType];
      findings.push(makeResourceFinding(stmt, typedEntries, {
        id: 'RESOURCE-UNSUPPORTED-PRINCIPAL',
        severity: meta.severity,
        title: meta.title,
        // The principal element IS literally present in the policy (policyEvidence
        // high - we observed it), but its reach is unmodeled/undetermined, so
        // path-exploitability is low; the finding surfaces the grant, never asserts
        // its effect.
        policyEvidence: 'high',
        pathExploitability: 'low',
        why: meta.why(summarizeEntries(typedEntries), serviceLabel, stmt.actions.join(', ')),
        remediation: meta.remediation,
        docRef: DOC_PRINCIPAL,
        service,
        attachedArn,
        transportOnlyDeny,
      }));
    }

    // 1) Anonymous / public principal -> PUBLIC-ACCESS. A bare "*" or {AWS:"*"}
    // Allow grants access to everyone, INCLUDING anonymous, unauthenticated callers
    // (unconditioned -> critical). BUT a "*" narrowed by a principal-scoping
    // condition (aws:PrincipalArn / aws:PrincipalAccount / aws:PrincipalOrgID /
    // aws:SourceAccount / aws:SourceArn) is NOT unconditioned public: the condition
    // restricts use to authenticated principals matching the named constraint, so
    // anonymous/unauthenticated reach is exactly what it excludes (section 3.1;
    // suite-3 test 85). We must not assert "anyone / including anonymous" in that
    // case - report broad "*" syntax NARROWED by the named condition instead. A
    // transport/network selector is NOT a principal-scoping key and never triggers
    // this narrowing (section 5).
    if (c.anonymous) {
      const anonEntries = c.entries.filter((e) => e.type === 'anonymous');
      const { scopingKeys, expansionKeys, bypassKeys } = principalScopingAnalysis(stmt.condition, service);
      // A KMS key policy's "*" is NOT anonymous/public: KMS has no unauthenticated
      // request path, so "*" = every AWS identity in every account (cross-account
      // still double-authorized). This service-scoped reframe changes ONLY the KMS
      // wording/doc of the same PUBLIC-ACCESS finding (never its id, never a
      // suppression) and is structurally unreachable for S3/SNS/SQS, which stay
      // genuinely anonymous-public (IAM-1403; per-service semantics section 3.1,
      // trap 1 / trap 4).
      const isKms = service === RESOURCE_SERVICES.KMS_KEY;
      // A NEGATED principal-scoping operator (StringNotEquals aws:PrincipalOrgID,
      // ArnNotEquals aws:PrincipalArn, Null-absent, ...) is an EXCLUSION/expansion,
      // NOT a narrowing, and dominates: it must never downgrade the "*" grant to
      // "narrowed" (adversarial-critic IAM-1202 iteration 4). When such a key is
      // present the grant stays PUBLIC-ACCESS/critical and no key is credited as
      // scoping. Only a POSITIVE principal-scoping key (and no expansion) narrows.
      const principalExpanded = expansionKeys.length > 0;
      const scopeKeys = principalExpanded ? [] : scopingKeys;
      const principalScoped = scopeKeys.length > 0;
      // A principal condition that uses ...IfExists / ForAllValues on a positive
      // operator is present but BYPASSABLE (it passes when the key is absent), so it
      // does NOT narrow the "*" grant and anonymous callers are NOT excluded. It must
      // never be credited as scoping (that would downgrade critical->high and assert
      // "anonymous excluded"). Only when nothing genuinely scopes or expands does the
      // bypassable condition drive the finding.
      const principalBypassed =
        !principalExpanded && !principalScoped && bypassKeys.length > 0;
      let title;
      let severity;
      let why;
      let remediation;
      if (principalExpanded) {
        // A NEGATED operator on a principal-scoping key = EXCLUSION, not narrowing:
        // "*" + StringNotEquals aws:PrincipalOrgID permits every principal EXCEPT the
        // named org (everyone OUTSIDE your org), and a negated match also succeeds for
        // a request that lacks the key, so anonymous callers are NOT excluded. This is
        // at least as broad as public and must NOT read as "narrowed / authenticated
        // only / anonymous excluded". Mirrors the trust family's TRUST-ORG-EXPANSION
        // critical severity for the identical condition (resource-policy-semantics.md
        // section 9; adversarial-critic IAM-1202 iteration 4).
        severity = 'critical';
        title = 'Public resource access broadened by a negated principal condition';
        why =
          `The resource policy grants Principal "*" permission to ${stmt.actions.join(', ')} ` +
          `on this ${serviceLabel}, gated by a NEGATED principal condition ` +
          `(${expansionKeys.join(', ')}). A negated operator (e.g. StringNotEquals / ` +
          'ArnNotEquals) is an EXCLUSION, not a narrowing: it permits every principal ' +
          'EXCEPT the listed values (for example every principal OUTSIDE the named ' +
          'organization), which is BROADER than the "*" scoped to that value, not ' +
          'narrower. Because a negated match also succeeds for a request that lacks the ' +
          'key, anonymous / unauthenticated callers are NOT excluded - so this grant is ' +
          'at least as broad as public access and additionally reaches principals the ' +
          'negation was meant to keep out. It must NOT be read as restricting access to ' +
          'authenticated principals.';
        remediation =
          'Do not gate a Principal "*" Allow with a negated condition operator ' +
          '(StringNotEquals / ArnNotEquals / *NotEquals / a Null-absent test) on a ' +
          'principal-identity key - it broadens rather than restricts. Name the specific ' +
          'accounts, roles, or services that must access this resource, or use a POSITIVE ' +
          'match (e.g. StringEquals aws:PrincipalOrgID) if you intend to scope to an ' +
          'organization. A TLS-only Deny (aws:SecureTransport) is not an access control.';
      } else if (principalScoped) {
        // Broad "*" syntax narrowed to authenticated principals by an identity
        // condition. Not anonymous/public; do not claim "anyone" reach.
        severity = 'high';
        title = 'Broad principal syntax ("*") narrowed by a principal condition';
        why =
          `The resource policy uses Principal "*" (broad principal syntax) to grant ` +
          `${stmt.actions.join(', ')} on this ${serviceLabel}, but the Allow is NARROWED ` +
          `by a principal-scoping condition (${scopeKeys.join(', ')}). That condition ` +
          'restricts use to AUTHENTICATED principals matching the named constraint, so ' +
          'this is NOT unconditioned anonymous / public access - anonymous, ' +
          'unauthenticated callers are exactly what the condition excludes, and no ' +
          'unauthenticated-reach claim is made. The reach is only as broad as the condition ' +
          'value allows; the condition value (including any wildcard within it) is a ' +
          'valid condition constraint, not a partial-ARN principal wildcard. Review the ' +
          'condition value to confirm it scopes access as intended.';
        remediation =
          'Prefer naming the specific accounts, roles, or services in the Principal ' +
          'element rather than Principal "*" gated by a condition; the "*" + condition ' +
          'pattern is broader and easier to get wrong than a named principal. Confirm ' +
          'the condition value (e.g. the aws:PrincipalArn pattern) scopes access to ' +
          'exactly the intended principals, and tighten it if it is broader than needed.';
      } else if (principalBypassed && !isKms) {
        // "*" gated ONLY by a positive principal condition that uses ...IfExists or a
        // ForAllValues: qualifier. Such an operator PASSES when the key is absent, so a
        // caller who omits the key satisfies it: it does NOT restrict access to
        // authenticated principals and anonymous / unauthenticated callers are NOT
        // excluded. Stays PUBLIC-ACCESS / critical - the present condition must never be
        // read as a narrowing (adversarial-critic: principalScopingAnalysis fail-open;
        // mirrors the source-binding bypass guard). KMS ("*" = every AWS identity, no
        // anonymous path) is handled by the KMS branch below, also critical.
        severity = 'critical';
        title = 'Public resource access (principal condition is bypassable, not a restriction)';
        why =
          `The resource policy grants Principal "*" permission to ${stmt.actions.join(', ')} ` +
          `on this ${serviceLabel}, gated by a principal condition (${bypassKeys.join(', ')}) ` +
          'that uses an ...IfExists suffix or a ForAllValues: set qualifier. That operator ' +
          'evaluates TRUE when the key is ABSENT from the request, so a caller who simply ' +
          'omits the key satisfies it: the condition does NOT restrict access to ' +
          'authenticated principals and anonymous / unauthenticated callers are NOT ' +
          'excluded. This is public access - the present condition must NOT be read as ' +
          'narrowing it or as excluding anonymous callers.';
        remediation =
          'Do not rely on a ...IfExists / ForAllValues principal condition to restrict a ' +
          'Principal "*" Allow - it is satisfied by omitting the key. Name the specific ' +
          'accounts, roles, or services in the Principal element, or use a POSITIVE, ' +
          'non-IfExists match (e.g. StringEquals aws:PrincipalOrgID) that fails closed ' +
          'when the key is absent.';
      } else if (isKms) {
        // KMS "*" is a severe over-grant but is NOT anonymous/public: KMS has no
        // unauthenticated path, so "*" = every AWS identity in every account. Drop the
        // "anonymous / unauthenticated / anyone on the internet" wording (trap 1);
        // Resource:"*" = the attached key only (never every key in the account).
        severity = 'critical';
        title = 'KMS key policy grants key use to every AWS identity in every account';
        why =
          `The resource policy grants Principal "*" ({"AWS":"*"}) permission to ` +
          `${stmt.actions.join(', ')} on this ${serviceLabel}. On a KMS key policy this ` +
          'wildcard principal does NOT mean anonymous or public access: KMS has no ' +
          'unauthenticated request path (every KMS API call is SigV4-signed), so "*" ' +
          'represents every AWS identity in every account. Any principal in any AWS ' +
          'account can use this key - subject to cross-account double-authorization, ' +
          'i.e. a caller in another account must ALSO be allowed by its own account\'s ' +
          'IAM policies - which is a severe over-grant of the key rather than reach by ' +
          'callers who present no AWS credentials. The Resource element ("*") in a KMS key policy ' +
          'means THIS attached key only (the key the policy is attached to), not every ' +
          'KMS key in the account, so it is not an identity-style all-resources ' +
          'wildcard and creates no per-key blast surface.';
        remediation =
          'Remove Principal "*" / {"AWS":"*"} and name the specific accounts, roles, ' +
          'or services that must use this key. To scope WHO may use the key, use a ' +
          'principal-account / org condition (kms:CallerAccount, aws:PrincipalAccount, ' +
          'or aws:PrincipalOrgID); note that kms:ViaService pins only the SERVICE ' +
          'CHANNEL a request flows through, not the caller, so it does not by itself ' +
          'restrict which accounts can use the key.';
      } else {
        // Bare, unconditioned "*" -> genuine anonymous / public access.
        severity = 'critical';
        title = 'Public resource access (any principal, including anonymous)';
        why =
          `The resource policy grants Principal "*" (anonymous / public access) ` +
          `permission to ${stmt.actions.join(', ')} on this ${serviceLabel}. AWS treats ` +
          'a wildcard principal on an Allow as public access - including anonymous, ' +
          'unauthenticated callers - so anyone can perform the granted actions on the ' +
          'attached resource.';
        remediation =
          'Remove Principal "*" and name the specific accounts, roles, or services ' +
          'that must access this resource. If public access is genuinely intended, ' +
          'confirm it explicitly and (for S3) verify Block Public Access settings. A ' +
          'TLS-only Deny (aws:SecureTransport) is good hygiene but is not an access ' +
          'control and does not make the resource private.';
      }
      // IAM-1205 (test 49): describe the Condition's boolean composition (AND across
      // distinct keys, OR within a key's value list) and name the network + principal
      // selectors distinctly, so a "*" narrowed by aws:SourceVpce:[A,B] AND
      // aws:PrincipalTag/environment is never read as "VPCe OR tag". Descriptive only;
      // the classification above (public / narrowed / expanded) is unchanged.
      why += describeConditionComposition(stmt.condition);
      if (transportOnlyDeny) {
        // The transport Deny does not neutralize the Allow. Its framing depends on
        // whether the Allow is public (bare "*") or already principal-scoped, and (for
        // KMS) avoids the "publicly accessible" wording the KMS "*" is not.
        if (principalScoped) {
          why +=
            ' A same-policy Deny gated only on aws:SecureTransport=false is a ' +
            'TRANSPORT constraint (it forces HTTPS) and constrains transport, not WHO ' +
            'may act; it neither widens nor narrows the principal-scoping condition ' +
            'above.';
        } else if (isKms) {
          why +=
            ' A same-policy Deny gated only on aws:SecureTransport=false is a ' +
            'TRANSPORT constraint (it forces HTTPS) and constrains transport, not WHO ' +
            'may act; it does NOT make this key private - the "*" grant (every AWS ' +
            'identity in every account) stays in effect over TLS, so the Deny must not ' +
            'be read as suppressing the grant.';
        } else {
          why +=
            ' A same-policy Deny gated only on aws:SecureTransport=false is a ' +
            'TRANSPORT constraint (it forces HTTPS); it does NOT make this public ' +
            'grant private - the resource stays publicly accessible over TLS, so the ' +
            'Deny must not be read as suppressing the public Allow.';
        }
      }
      if (isS3 && !principalScoped) {
        // S3 Block Public Access is only relevant to a genuinely-public grant.
        why +=
          ' Whether this public grant is actually reachable ALSO depends on S3 ' +
          'Block Public Access, a separate account/bucket-level control that is not ' +
          'supplied here; unsupported context does not mean the resource is safe.';
      }
      findings.push(makeResourceFinding(stmt, anonEntries, {
        id: 'PUBLIC-ACCESS',
        severity,
        title,
        why,
        remediation,
        docRef: isS3 ? DOC_S3_BPA : (isKms ? DOC_KMS_OVERVIEW : DOC_PRINCIPAL),
        // A grant is literally in the policy; a same-policy transport Deny does not
        // lower it, but reachability still depends on the condition / BPA / other
        // layers, so a conditioned Allow caps path-exploitability at medium.
        pathExploitability: (conditioned && !principalBypassed) ? 'medium' : 'high',
        service,
        attachedArn,
        transportOnlyDeny,
        // The principal-scoping condition keys that narrow this "*" grant to
        // authenticated principals (empty for a genuinely-public grant). Carried on
        // the resource enrichment so the graph/render never assert anonymous reach.
        principalScopedBy: scopeKeys,
        // A KMS "*" grant reaches every AWS identity in every account but NOT an
        // anonymous/unauthenticated caller (KMS has no unauthenticated path), so the
        // resource-enrichment `anonymous` flag is cleared for KMS - the metadata must
        // not contradict the finding text (trap 1). S3/SNS/SQS keep the structural
        // anonymous flag.
        anonymousReach: isKms ? false : undefined,
      }));
      continue;
    }

    // 2) Named AWS account / root / principal-ARN principal -> RESOURCE-CROSS-ACCOUNT.
    // "Cross-account" is decided ONLY by comparing the principal's account to the
    // resource's OWNING account, which needs BOTH accounts:
    //   - The principal's account comes from its ARN / bare id (accountOfEntry).
    //   - The resource's account comes from the attached-resource ARN. But S3
    //     bucket/object ARNs (arn:aws:s3:::bucket[/key]) structurally carry NO
    //     account id, so for S3 the resource account is NOT determinable from the
    //     context (resourceAccount === null).
    // When either account is unknown, the same-vs-cross-account relationship is
    // INDETERMINATE. We must NOT assert "cross-account" on that evidence: a routine
    // same-account S3 bucket grant would otherwise be mislabeled external (asserting
    // beyond evidence, Phase-12 guardrail). We still SURFACE the named-principal
    // grant (fail closed toward surfacing; never assume same-account), but HEDGE the
    // wording. A CONFIRMED cross-account grant is asserted ONLY when the resource
    // account is known AND every named principal's account is known and differs.
    // A KNOWN same-account principal (resource account known and EQUAL) is now
    // reported as a direct same-account grant (RESOURCE-SAME-ACCOUNT-GRANT, IAM-1204,
    // test 32/33) rather than dropped.
    const externalTypes = new Set(['aws-account', 'aws-root', 'aws-principal-arn']);
    let namedEntries = c.entries.filter((e) => externalTypes.has(e.type));

    // 2-KMS) KMS key-policy account delegation (IAM-1205; test 51). On a KMS KEY
    // policy an ACCOUNT / account-root principal (arn:aws:iam::<acct>:root or the bare
    // 12-digit id) is the "Enable IAM User Permissions"-style account delegation, NOT
    // a same/cross-account named-principal grant: it delegates authority to the
    // OWNING ACCOUNT (the account and its IAM-empowered administrators, not the root
    // user only, and not public), and it does so by ALLOWING the account to use IAM
    // policies to reach the key - which individual principals are actually reachable
    // is unknown without those identity policies. Resource:* in a key policy is the
    // ATTACHED key only, not every key in the account. Peel account/root entries into
    // the KMS-specific finding and leave specific user/role/session ARNs on the normal
    // same/cross-account path below. Only for kms-key; a SPECIFIC IAM user/role ARN on
    // a KMS key is a named grant, not the account-delegation statement.
    if (service === RESOURCE_SERVICES.KMS_KEY) {
      const acctEntries = namedEntries.filter(
        (e) => e.type === 'aws-account' || e.type === 'aws-root',
      );
      if (acctEntries.length > 0) {
        const who = summarizeEntries(acctEntries);
        // Classify same-vs-cross account for the OWNING account when both sides are
        // known. A KMS key ARN carries its account (field 4), so resourceAccount is
        // usually known; an EXTERNAL account root on a key is a cross-account KMS
        // delegation (higher concern) vs the standard owning-account default.
        const acctNumbers = acctEntries.map(accountOfEntry);
        const allKnown = acctNumbers.every((a) => a !== null);
        const external = resourceAccount !== null && allKnown &&
          acctNumbers.every((a) => a !== resourceAccount);
        const sameOwning = resourceAccount !== null && allKnown &&
          acctNumbers.every((a) => a === resourceAccount);
        const acts = stmt.actions.join(', ');
        const broad = stmt.actions.some((a) => /^kms:\*$/i.test(String(a)) || String(a) === '*');
        const scopePhrase = broad
          ? 'the FULL set of KMS actions (kms:*) on'
          : `the listed KMS actions (${acts}) on`;
        let why =
          `This KMS key policy grants an AWS account principal (${who}) ${scopePhrase} ` +
          'this key. On a KMS key policy an account / account-root principal is an ' +
          'ACCOUNT DELEGATION: it delegates authority over the key to the OWNING ' +
          'ACCOUNT - the account and its IAM-empowered administrators - and is NOT ' +
          'public access (the principal is one AWS account, not "*") and is NOT ' +
          'limited to the root user only (an account / ":root" principal represents ' +
          'the account and its administrators, not solely the root user). Critically, ' +
          'this account-principal statement does not by itself grant any individual ' +
          'IAM principal permission to use the key; it ALLOWS the account to use IAM ' +
          'identity policies to delegate access to the key (KMS-specific semantics - ' +
          'unlike other resource policies, without this statement the account\'s IAM ' +
          'allow policies could not govern the key). Which individual principals are ' +
          'actually reachable is UNKNOWN here without the account\'s identity policies, ' +
          'permissions boundaries, and other layers, so this is potential authority ' +
          'delegated to the account, not a proven per-principal grant. The Resource ' +
          'element ("*") in a KMS key policy means THIS attached key only (the key the ' +
          'policy is attached to), not every KMS key in the account - so it is not an ' +
          'identity-style all-resources wildcard and creates no per-key blast surface.';
        if (external) {
          why +=
            ' The delegated account DIFFERS from the key\'s owning account, so this is a ' +
            'CROSS-ACCOUNT KMS delegation: authority over the key is delegated to an ' +
            'external account, and a request from that account must also be allowed by ' +
            'its own identity policies.';
        } else if (!sameOwning) {
          why +=
            ' The key\'s owning account could not be confirmed equal to the delegated ' +
            'account from the inputs, so whether this is the standard owning-account ' +
            'delegation or a cross-account delegation is not determined here.';
        }
        findings.push(makeResourceFinding(stmt, acctEntries, {
          id: 'RESOURCE-KMS-ACCOUNT-DELEGATION',
          severity: external ? 'high' : 'medium',
          title: 'KMS key policy delegates broad key authority to an AWS account',
          why,
          remediation:
            'This is the standard KMS account-delegation pattern (commonly the ' +
            '"Enable IAM User Permissions" statement); it is expected on most keys and ' +
            'lets the account govern the key through IAM policies. Confirm the delegated ' +
            'account is the intended owner, keep the delegated actions no broader than ' +
            'needed, and control who can actually use the key through least-privilege ' +
            'IAM identity policies plus (where required) explicit key-policy Deny ' +
            'statements. Do not read this statement as public access or as root-user-' +
            'only access, and do not expand Resource:"*" beyond the attached key.',
          docRef: DOC_KMS_KEY_POLICY,
          pathExploitability: 'medium',
          service,
          attachedArn,
          transportOnlyDeny,
        }));
        // S3-dos-budget-all (iter-5): remove the peeled account entries via Set
        // membership, not Array.includes() (which made this O(V^2) over an
        // attacker-sized Principal.AWS list), and charge the traversal so the
        // deterministic budget participates in this principal-dedup scan.
        chargeWork(namedEntries.length + acctEntries.length);
        const acctEntrySet = new Set(acctEntries);
        namedEntries = namedEntries.filter((e) => !acctEntrySet.has(e));
      }
    }

    // Same-account entries: the resource-owning account is KNOWN and the principal's
    // account is KNOWN and EQUAL. Everything else (different account, or an
    // unpinnable principal account, or an unknown resource account) is potentially
    // cross-account and routes to RESOURCE-CROSS-ACCOUNT (confirmed or hedged there).
    const sameAccountEntries = resourceAccount === null ? [] : namedEntries.filter((e) => {
      const acct = accountOfEntry(e);
      return acct !== null && acct === resourceAccount;
    });
    // S3-dos-budget-all (iter-5): same-account partition via Set membership (was an
    // O(V^2) Array.includes() over the Principal-derived entries) + budget charge so
    // this policy-derived traversal is bounded by the deterministic work ceiling.
    chargeWork(namedEntries.length + sameAccountEntries.length);
    const sameAccountEntrySet = new Set(sameAccountEntries);
    const grantEntries = namedEntries.filter((e) => !sameAccountEntrySet.has(e));

    // 2a) Same-account direct grant (IAM-1204): the resource policy names a principal
    // in the SAME account as the resource. Within one account AWS evaluates the UNION
    // of identity + resource permissions, so this grant can be effective even when the
    // principal's identity policy is SILENT (an implicit deny in the identity policy /
    // permissions boundary does not, on its own, defeat it); an applicable EXPLICIT
    // Deny in any layer still blocks. Each principal is typed distinctly and an
    // assumed-role session is identified as one exact session, never the role ARN
    // (test 33). Not generalized across principal types or to cross-account.
    if (sameAccountEntries.length > 0) {
      const who = summarizeEntries(sameAccountEntries);
      const kinds = [...new Set(sameAccountEntries.map(principalSubKind))];
      const kindPhrase = kinds.map((k) => SUBKIND_LABELS[k] || 'AWS principal').join('; ');
      const hasSession = kinds.includes('role-session') || kinds.includes('federated-user-session');
      let why =
        `The resource policy grants a SAME-ACCOUNT principal (${who} - ${kindPhrase}) ` +
        `permission to ${stmt.actions.join(', ')} on this ${serviceLabel}, in the ` +
        `resource-owning account ${resourceAccount}. This is a DIRECT resource-policy ` +
        'grant, and its evaluation differs from an identity-policy grant: within a ' +
        'single account AWS allows an action if an identity policy, a resource policy, ' +
        'or both allow it, so an IMPLICIT deny in this principal\'s identity policy or ' +
        'permissions boundary (i.e. simply not granting the action there) does not, on ' +
        'its own, limit this direct same-account resource-policy grant. An applicable ' +
        'EXPLICIT Deny - in the identity policy, a permissions boundary, an SCP/RCP, or ' +
        'this resource policy - still blocks. Each principal is enumerated distinctly ' +
        'and is not generalized to other principal types or to cross-account principals.';
      if (hasSession) {
        why +=
          ' A named assumed-role / federated-user SESSION principal identifies ONE ' +
          'exact session (role + session name) and is NOT collapsed to the underlying ' +
          'role ARN; same-account resource-policy grants to a session principal have ' +
          'distinct permissions-boundary / session-policy behavior from a grant to the ' +
          'role itself.';
      }
      findings.push(makeResourceFinding(stmt, sameAccountEntries, {
        id: 'RESOURCE-SAME-ACCOUNT-GRANT',
        severity: 'medium',
        title: 'Direct same-account resource-policy grant (resource-vs-identity evaluation)',
        why,
        remediation:
          'Confirm the named same-account principal is intended to have this direct ' +
          'resource-policy access. Remember a resource-policy Allow can grant even when ' +
          'the principal\'s identity policy is silent, so removing the identity grant ' +
          'does NOT revoke it - tighten or remove this statement to change the access, ' +
          'and rely on an explicit Deny only where a hard block is required. Scope the ' +
          'granted actions and resource to the minimum needed.',
        docRef: DOC_EVAL_LOGIC,
        pathExploitability: 'medium',
        service,
        attachedArn,
        transportOnlyDeny,
      }));
    }

    if (grantEntries.length > 0) {
      // Confirmed cross-account requires the resource account AND every principal's
      // account to be known, and all to differ from the resource account. Any
      // unknown account (S3 resource, or an unpinnable principal) -> hedge.
      const confirmedCrossAccount = resourceAccount !== null && grantEntries.every((e) => {
        const acct = accountOfEntry(e);
        return acct !== null && acct !== resourceAccount;
      });
      const who = summarizeEntries(grantEntries);
      let title;
      let why;
      if (confirmedCrossAccount) {
        title = 'Cross-account resource grant to an external principal';
        why =
          `The resource policy grants an EXTERNAL principal (${who}) permission to ` +
          `${stmt.actions.join(', ')} on this ${serviceLabel}. This is a cross-account ` +
          'grant: the resource side names the outside principal, but AWS also requires ' +
          'the caller\'s own account to allow the action against this resource ARN, so ' +
          'the resource-policy Allow is a necessary - not sufficient - condition for ' +
          'access. The external principal is enumerated as-is and never collapsed with ' +
          'the resource owner.';
      } else {
        // Indeterminate: name the reason the relationship is undetermined so the
        // hedge is explainable. If the resource-owning account is unknown that
        // dominates (for S3, because the bucket/object ARN carries no account and no
        // explicit owner account was supplied); otherwise the owning account IS known
        // and the gap is an unpinnable principal account.
        const reason = resourceAccount === null
          ? (isS3
              ? 'the attached S3 resource ARN does not include an account id and no owning account was supplied'
              : 'the resource-owning account could not be determined')
          : 'the account of one or more named principals could not be determined';
        title = 'Resource grant to a named AWS principal (account relationship undetermined)';
        why =
          `The resource policy grants a named AWS principal (${who}) permission to ` +
          `${stmt.actions.join(', ')} on this ${serviceLabel}. Because ${reason}, ` +
          'whether this principal is in the resource-owning account or a DIFFERENT ' +
          'account CANNOT be determined from the inputs; it is treated as potentially ' +
          'cross-account and is never assumed to be same-account. If it is cross-account, ' +
          'AWS also requires the caller\'s own account to allow the action against this ' +
          'resource ARN, so the resource-policy Allow is a necessary - not sufficient - ' +
          'condition for access. The named principal is enumerated as-is and never ' +
          'collapsed with the resource owner.';
      }
      findings.push(makeResourceFinding(stmt, grantEntries, {
        id: 'RESOURCE-CROSS-ACCOUNT',
        severity: 'high',
        title,
        why,
        remediation:
          'Confirm the named account/principal is intended to access this resource ' +
          'and, where it is external, scope the granted actions and resource to the ' +
          'minimum needed and add a confused-deputy / org constraint (e.g. ' +
          'aws:PrincipalOrgID, aws:SourceArn) where appropriate. Remove the grant if ' +
          'the trust is not required.',
        docRef: DOC_CROSS_ACCOUNT,
        pathExploitability: 'medium',
        service,
        attachedArn,
        transportOnlyDeny,
      }));
    }

    // 3) Service principal -> confused-deputy analysis (IAM-1203). A resource policy
    // granting an AWS SERVICE principal is NOT public write - the principal is a
    // service, not "*" - but AWS authorizes the SERVICE, not the actor who
    // configured the calling service, so without a source binding it is a
    // cross-service CONFUSED-DEPUTY exposure (resource-policy-semantics.md section 4;
    // test 26). A proper source binding (aws:SourceArn AND/OR aws:SourceAccount /
    // aws:SourceOrgID, ANDed with a positive operator) is a negative control
    // (test 27); a SourceArn-account vs SourceAccount MISMATCH is an internally
    // inconsistent, likely-ineffective constraint (test 53). One RESOURCE-CONFUSED-
    // DEPUTY finding id, three deterministic cases - never a public-write finding.
    const serviceEntries = c.entries.filter((e) => e.type === 'service');
    if (serviceEntries.length > 0) {
      const binding = sourceBindingAnalysis(stmt.condition);
      const svcWho = summarizeEntries(serviceEntries);
      const acts = stmt.actions.join(', ');
      // A binding is internally inconsistent when the resolvable-account SET pinned by
      // aws:SourceArn and the resolvable-account SET pinned by aws:SourceAccount are
      // BOTH non-empty and FULLY DISJOINT (no account appears on both sides). Comparing
      // SETs on BOTH axes - not a single common account on either - is what makes the
      // detection SYMMETRIC: it catches a multi-account SourceArn whose accounts all
      // differ from SourceAccount AND a multi-account SourceAccount whose every value
      // differs from the SourceArn account. commonSourceAccount() collapses either
      // multi-valued key to null, so a single-common-value guard would mis-credit those
      // as clean source-bound controls. If ANY account matches across the two sets, or
      // either set is empty (no resolvable account on that axis), it is NOT a mismatch.
      const arnAccounts = binding.sourceArn.accounts;
      const acctAccounts = binding.sourceAccount.accounts;
      // S3-dos-budget-all (iter-5): the disjoint-set test was O(V^2) via
      // Array.includes() over two attacker-sized account sets. A Set makes it O(V), and
      // charging the traversal length makes the deterministic budget sample this
      // policy-derived scan (it never reaches the shared matcher).
      chargeWork(arnAccounts.length + acctAccounts.length);
      const acctAccountSet = new Set(acctAccounts);
      const mismatch = binding.sourceArn.bound && binding.sourceAccount.bound &&
        arnAccounts.length > 0 && acctAccounts.length > 0 &&
        arnAccounts.every((a) => !acctAccountSet.has(a));
      const anyBinding = binding.sourceArn.bound || binding.sourceAccount.bound ||
        binding.sourceOrg || binding.sourceOwner;
      const bypassedNote = binding.bypassedKeys.length > 0
        ? ` A source condition key IS present (${binding.bypassedKeys.join(', ')}) but ` +
          'does NOT bind the source: it uses a negated operator, a bypassable ' +
          '...IfExists / ForAllValues qualifier, or a match-all value, so it is ' +
          'trivially evaded and cannot be credited as a confused-deputy constraint.'
        : '';

      let severity;
      let title;
      let why;
      let remediation;
      let pathExploitability;
      let state;

      if (mismatch) {
        // Test 53: SourceArn's account and SourceAccount disagree - the constraint
        // is internally inconsistent and likely ineffective. Do NOT praise it as
        // source-bound; do NOT turn the mismatch into a public-write finding.
        state = 'mismatched';
        severity = 'medium';
        pathExploitability = 'medium';
        title = 'Service principal source binding is internally inconsistent (SourceArn vs SourceAccount account mismatch)';
        why =
          `The resource policy grants an AWS service principal (${svcWho}) permission ` +
          `to ${acts} on this ${serviceLabel} with BOTH aws:SourceArn and ` +
          'aws:SourceAccount conditions, but they DISAGREE: aws:SourceAccount pins ' +
          `account ${acctAccounts.join(', ')} while the account component of ` +
          `aws:SourceArn resolves to ${arnAccounts.join(', ')} (none of which match). ` +
          'AWS ANDs distinct condition ' +
          'keys, so a request would have to satisfy both a source in one account and a ' +
          'source-account in another - a combination that is internally inconsistent ' +
          'and likely never matches a legitimate request, making the intended ' +
          'confused-deputy binding likely ineffective (exact behavior is subject to how ' +
          'the calling service populates the source request context). This is NOT a ' +
          'correctly source-bound control, and it is NOT public write - the principal ' +
          'is a service, not "*".';
        remediation =
          'Make aws:SourceArn and aws:SourceAccount agree: the account component of the ' +
          'aws:SourceArn value must equal the aws:SourceAccount value. Set them to the ' +
          'account that actually owns the calling source resource, then re-verify the ' +
          'confused-deputy binding.';
      } else if (anyBinding) {
        // Test 27: a proper source binding (positive SourceArn / SourceAccount /
        // SourceOrgID). Negative control - informational/low; NO missing-binding
        // warning. Do NOT infer whether the referenced source resource exists.
        state = 'source-bound';
        severity = 'info';
        pathExploitability = 'low';
        title = 'Service principal grant is source-bound (confused-deputy constraint present)';
        why =
          `The resource policy grants an AWS service principal (${svcWho}) permission ` +
          `to ${acts} on this ${serviceLabel}, constrained by a source-binding ` +
          `condition (${binding.boundKeys.join(', ')}). That is the AWS-recommended ` +
          'confused-deputy mitigation: it limits the service to acting only on behalf ' +
          'of the named source. Where two operators are present (e.g. ArnEquals ' +
          'aws:SourceArn AND StringEquals aws:SourceAccount) AWS combines them with ' +
          'logical AND. This is a NEGATIVE control, not an exposure. The analyzer does ' +
          'NOT infer whether the referenced source resource actually exists, and this ' +
          'binding governs only the confused-deputy vector - it does not by itself ' +
          'establish that the overall grant is safe.';
        remediation =
          'No confused-deputy change is indicated: the service grant is source-bound. ' +
          'Keep the aws:SourceArn / aws:SourceAccount constraint in sync with the ' +
          'intended calling source, and confirm the granted actions and resource scope ' +
          'are the minimum the integration needs.';
      } else {
        // Test 26: a service principal with NO effective source binding -> confused-
        // deputy exposure. NOT public write (a service is not "*"). Name the missing
        // aws:SourceArn / aws:SourceAccount binding; subject to service support.
        state = 'unbound';
        severity = 'medium';
        pathExploitability = 'medium';
        title = 'Service principal grant without a confused-deputy source binding';
        why =
          `The resource policy grants an AWS service principal (${svcWho}) permission ` +
          `to ${acts} on this ${serviceLabel} with NO source binding ` +
          '(aws:SourceArn / aws:SourceAccount / aws:SourceOrgID). AWS authorizes the ' +
          'SERVICE principal, not the actor who configured the calling service, so an ' +
          'unauthorized actor who can make that service act (for example by configuring ' +
          'it in their own account) and who knows this resource may be able to induce ' +
          'the service to act on this resource on their behalf - the cross-service ' +
          'confused-deputy problem. This is a service-principal exposure, NOT public ' +
          'write: the principal is a specific AWS service, not "*", so the resource is ' +
          'not "publicly writable". Whether the exposure is reachable is subject to ' +
          'whether the calling service supports and populates the source request ' +
          'context.' + bypassedNote;
        remediation =
          'Add a confused-deputy source binding to this statement: aws:SourceArn ' +
          '(ArnEquals / ArnLike) scoped to the specific calling source resource, and/or ' +
          'aws:SourceAccount (StringEquals) scoped to the source account (aws:SourceOrgID ' +
          '/ aws:SourceOrgPaths for an org-wide source). Use the keys the calling ' +
          'service supports.';
      }

      findings.push(makeResourceFinding(stmt, serviceEntries, {
        id: 'RESOURCE-CONFUSED-DEPUTY',
        severity,
        title,
        why,
        remediation,
        docRef: DOC_CONFUSED_DEPUTY,
        pathExploitability,
        service,
        attachedArn,
        transportOnlyDeny,
        sourceBinding: {
          state,
          boundKeys: binding.boundKeys,
          bypassedKeys: binding.bypassedKeys,
          sourceArnAccount: binding.sourceArn.account,
          sourceAccount: binding.sourceAccount.account,
        },
      }));
    }
  }

  // 4) Bucket-vs-object resource typing (IAM-1204; test 50 in the resource context).
  // Independent of principal type, so it runs as a second pass over the Allow
  // statements (the principal loop `continue`s for anonymous grants, which would
  // otherwise skip this check). An S3 OBJECT-level action granted on a BUCKET-only
  // resource ARN, with no object-scoped resource in the statement that the action
  // could match, is an action/resource-type mismatch: the bucket ARN does not
  // identify objects, so it does NOT confirm object access (section 2.1). Only for
  // the S3 family; a wildcard action is never guessed into a mismatch.
  if (isS3) {
    for (const stmt of statements) {
      if (!stmt || stmt.effect !== 'Allow') continue;
      const actions = Array.isArray(stmt.actions) ? stmt.actions : [];
      // S3-dos-budget-all: charge the per-statement action/resource scan so this second
      // pass over the policy participates in the budget too (proportional to the real
      // token count it inspects).
      chargeWork(actions.length + (Array.isArray(stmt.resources) ? stmt.resources.length : 0) + 1);
      const objectActions = actions.filter(isS3ObjectAction);
      if (objectActions.length === 0) continue;
      const resources = Array.isArray(stmt.resources) ? stmt.resources : [];
      const scopes = resources.map(s3ResourceScope).filter((x) => x !== null);
      const hasObjectScope = scopes.includes('object');
      const bucketOnly = resources.filter((r) => s3ResourceScope(r) === 'bucket');
      // A mismatch only when the object action has NO object-scoped S3 resource to
      // match AND at least one bucket-only S3 resource is present.
      if (hasObjectScope || bucketOnly.length === 0) continue;
      findings.push(makeResourceFinding(stmt, [], {
        id: 'RESOURCE-ACTION-RESOURCE-MISMATCH',
        severity: 'low',
        // The object action does NOT confirm object access on a bucket ARN, so the
        // policy evidence for object access is explicitly LOW (test 50).
        policyEvidence: 'low',
        pathExploitability: 'low',
        title: 'S3 object action granted on a bucket-only resource (action/resource-type mismatch)',
        why:
          `The resource policy grants ${objectActions.join(', ')} - an S3 OBJECT-level ` +
          `action - scoped to a BUCKET-only ARN (${bucketOnly.join(', ')}) that has no ` +
          'object key (no "/*" and no "/key"). A bucket ARN does not identify objects, ' +
          'so this statement does NOT confirm object read/write: an S3 object action ' +
          'requires an object-scoped resource such as arn:aws:s3:::<bucket>/*. This is ' +
          'an action/resource-type mismatch, not proven object access - treat the ' +
          'object-access capability as unconfirmed, and note the statement may simply ' +
          'be misconfigured.',
        remediation:
          'Scope object actions (e.g. s3:GetObject, s3:PutObject) to an object ARN ' +
          '(arn:aws:s3:::<bucket>/* or a specific key), and keep bucket actions (e.g. ' +
          's3:ListBucket, s3:GetBucketPolicy) on the bucket ARN. Object actions and ' +
          'bucket actions require different resource scopes; splitting them into ' +
          'separate statements makes the intended scope explicit.',
        docRef: DOC_S3_ACTIONS,
        service,
        attachedArn,
        transportOnlyDeny,
      }));
    }
  }

  return findings;
}

// --- Per-service dispatch scaffolding (IAM-1401) -----------------------------
//
// After parseResourceContext() accepts a context, the analyzer selects a
// per-service rule set by the DETECTED service token (serviceForArn:
// s3-bucket / s3-object / kms-key / sns / sqs) and runs it IN ADDITION to the
// generic principal-centric resourceFindings() loop - never instead of it, and
// never routing to identity rules. The generic loop stays the SAFETY NET: an
// unmodeled sub-shape still yields the generic PUBLIC-ACCESS / CROSS-ACCOUNT /
// CONFUSED-DEPUTY / UNSUPPORTED-PRINCIPAL findings and the INCOMPLETE coverage
// flag, so a per-service rule can only ever ADD or REFINE, never SUPPRESS.
//
// This tranche (IAM-1401) is PURE ROUTING: every per-service handler is a stub
// that emits NO findings yet. The concrete finding rules are the subsequent
// Phase-14 stories - S3 (IAM-1402), KMS (IAM-1403), and the shared SNS/SQS
// messaging family (IAM-1404). The dispatch table exists to PROVE the wiring and
// to make dispatch bleed (trap 4) structurally impossible:
//   - Each handler is keyed by an EXACT service token. Selection is a single
//     Map.get(service) with no fall-through, so a handler is structurally
//     incapable of running for a service it is not registered under - the KMS
//     "Principal * is not anonymous" reframing (IAM-1403) cannot alter the
//     S3 / SNS / SQS anonymous-public classification because the KMS handler is
//     only ever reached for the kms-key token.
//   - A service with NO registered handler (generic / unknown) contributes
//     nothing and relies on the generic path. Dispatch NEVER throws.
// Each service maps to its own distinct handler function reference; S3 bucket and
// object share one handler (they are the same bucket policy at different resource
// scope), and SNS and SQS share one messaging handler (near-identical resource-
// policy semantics, differing only in action namespace - grounding section 4).

// --- S3 bucket-policy per-service finding rules (IAM-1402) --------------------
//
// The S3 bucket policy is the canonical anonymous-public-exposure surface: S3
// object reads can be made by UNAUTHENTICATED HTTP clients, so Principal:"*" on S3
// is public in the strongest sense (docs/resource-per-service-semantics.md
// section 1). These rules run IN ADDITION to the generic principal-centric loop
// (which already emits the critical PUBLIC-ACCESS / RESOURCE-CROSS-ACCOUNT /
// RESOURCE-SAME-ACCOUNT-GRANT / RESOURCE-ACTION-RESOURCE-MISMATCH findings). They
// add the S3-specific REFINEMENTS the generic path cannot produce, never suppress a
// generic finding, and are scoped to the s3-bucket / s3-object tokens only.

// Bucket-CONTROL actions: the grantee can REWRITE the bucket's own resource policy
// or ACLs (resource-policy takeover / self-expansion), a far higher blast radius
// than a data-plane action (section 1.5). Lowercased action name after the s3:
// prefix. Wildcards (s3:*, s3:Put*) are intentionally NOT classified here - s3:* to
// "*" already surfaces as the generic critical PUBLIC-ACCESS, and the analyzer never
// guesses a control-plane takeover from a wildcard (mirrors S3_OBJECT_ACTIONS).

// --- KMS key-policy per-service finding rules (IAM-1403) ---------------------
//
// A KMS key policy is the primary access control for the key and its semantics
// differ sharply from S3 (docs/resource-per-service-semantics.md section 3). These
// rules run IN ADDITION to the generic principal-centric loop, which already emits
// the KMS "*" over-grant as PUBLIC-ACCESS with KMS-correct wording (the
// not-anonymous reframe lives in resourceFindings, scoped to the kms-key token),
// plus RESOURCE-KMS-ACCOUNT-DELEGATION / RESOURCE-CROSS-ACCOUNT /
// RESOURCE-SAME-ACCOUNT-GRANT. They add the KMS-specific refinements the generic
// path cannot produce (channel-not-scoping, CreateGrant delegation, PutKeyPolicy
// takeover, the silent-policy inversion), never suppress a generic finding, and are
// scoped to the kms-key token only (trap 4: cannot alter S3/SNS/SQS).

// kms:ViaService pins the SERVICE CHANNEL a request flows through, NOT the caller
// (trap 2). kms:GrantIsForAWSResource narrows kms:CreateGrant to AWS-service-created
// grants. Lowercased.

// --- Shared SNS topic + SQS queue messaging per-service finding rules (IAM-1404) -
//
// SNS topic access policies and SQS queue access policies are messaging resource
// policies with near-identical semantics that differ only in their action namespace
// (docs/resource-per-service-semantics.md section 4), so Phase 14 models them with
// ONE shared rule family registered for BOTH the sns and sqs tokens. These rules run
// IN ADDITION to the generic principal-centric loop, which already emits the
// genuinely-anonymous SNS/SQS "*" grant as critical PUBLIC-ACCESS (SQS docs label a
// Principal "*" grant "all users (anonymous users)"; SNS treats it as a public
// wildcard-principal grant), the "*"-narrowed-by-a-principal-condition high finding,
// RESOURCE-CROSS-ACCOUNT, and RESOURCE-CONFUSED-DEPUTY for a service principal. They
// add the messaging-specific REFINEMENTS the generic path cannot produce (the named
// data-plane exfiltration/injection/drain vector, the topic/queue policy-takeover
// action ranking, and the deprecated aws:SourceOwner note), never suppress a generic
// finding, and are scoped to the sns / sqs tokens only (trap 4: the KMS not-anonymous
// carve-out is a distinct handler and is structurally incapable of running here, so a
// genuinely-anonymous SNS/SQS "*" grant stays critical PUBLIC-ACCESS via the generic
// path).

// Dangerous messaging DATA-PLANE actions and the specific blast-radius vector each
// grants to an anonymous "*" principal. Keyed by "<ns>:<action>" lowercased.

// The per-service dispatch table: an exact service token -> its rule-set handler.
// A Map (not a plain object) so a lookup for a non-registered token - including a
// dangerous key such as "__proto__" / "constructor" - returns undefined rather
// than an inherited/prototype value (fail closed to "no per-service rules"). Not
// exported directly; perServiceRuleSetFor() is the read accessor.
const PER_SERVICE_RULES = new Map([
  [RESOURCE_SERVICES.S3_BUCKET, s3PerServiceRules],
  [RESOURCE_SERVICES.S3_OBJECT, s3PerServiceRules],
  [RESOURCE_SERVICES.KMS_KEY, kmsPerServiceRules],
  [RESOURCE_SERVICES.SNS, messagingPerServiceRules],
  [RESOURCE_SERVICES.SQS, messagingPerServiceRules],
]);

/**
 * The per-service rule-set handler registered for a service token, or null when
 * none is (generic / unknown / unmodeled / a non-string / a dangerous key). Pure
 * lookup; never throws. Exported so the dispatch wiring is directly testable and
 * so callers can tell whether a service has per-service rules without running
 * them.
 *
 * @param {*} service a service token (one of RESOURCE_SERVICES) or anything else
 * @returns {((model:object, ctx:object)=>Array<object>)|null}
 */
export function perServiceRuleSetFor(service) {
  if (typeof service !== 'string' || service.length === 0) return null;
  const handler = PER_SERVICE_RULES.get(service);
  return typeof handler === 'function' ? handler : null;
}

/**
 * Run the per-service rule set registered for the accepted context's service
 * token, IN ADDITION to the generic findings. Returns a (possibly empty) array of
 * findings in the canonical resource-finding shape. A service with no registered
 * handler (generic / unknown) contributes nothing. Defensive and fail-closed
 * toward the generic path: it NEVER throws and never mutates the generic finding
 * set - the generic findings + INCOMPLETE coverage always stand on their own, so
 * a per-service rule can only add to them, never remove one. A handler that
 * returned a non-array is ignored (treated as "no per-service findings"), so a
 * malformed handler can never corrupt the combined result.
 *
 * @param {object} model normalized, frozen model
 * @param {object} ctx the accepted resource context (parseResourceContext ok:true)
 * @returns {Array<object>} per-service findings (empty in the IAM-1401 tranche)
 */
export function dispatchPerServiceRules(model, ctx) {
  const service = ctx && typeof ctx.service === 'string' ? ctx.service : null;
  const handler = perServiceRuleSetFor(service);
  if (!handler) return [];
  const out = handler(model, ctx);
  return Array.isArray(out) ? out : [];
}

/**
 * Analyze a resource-based policy from the resource's perspective.
 *
 * IAM-1202 + IAM-1203 (principal-centric): enumerates WHO can act on the attached
 * resource and emits PUBLIC-ACCESS (anonymous "*" principal), RESOURCE-CROSS-ACCOUNT
 * (external cross-account principal), and RESOURCE-CONFUSED-DEPUTY (a service
 * principal - confused-deputy exposure when unbound, negative control when source-
 * bound, or an inconsistent-binding warning on a SourceArn/SourceAccount mismatch)
 * findings, each carrying the potential-blast-radius-not-effective-access
 * limitation. A same-policy aws:SecureTransport Deny is classified as TRANSPORT-only
 * and never neutralizes a public Allow (test 28). IAM-1204 adds same-account direct
 * grants + S3 bucket-vs-object typing; IAM-1205 adds KMS key-policy account
 * delegation (Resource:* = the attached key only, test 51) + resource-policy
 * condition composition (AND across keys, OR within values, test 49). Never runs
 * identity rules. Coverage stays INCOMPLETE (the remaining service-specific family -
 * the Deny + NotPrincipal hazard - is IAM-1206). Never throws.
 *
 * @param {object} model normalized, frozen model
 * @param {{type?:string, arn?:string}|null} resourceContext attached-resource context
 * @returns {{ok:boolean, findings:Array<object>, errors:Array, context:(object|null),
 *            coverage:object}}
 */
export function analyzeResource(model, resourceContext) {
  const parsed = parseResourceContext(resourceContext);
  const principals = enumeratePrincipals(model);

  // Fail closed at the module boundary when the attached-resource context was
  // REJECTED (missing/invalid ARN -> RESOURCE_CONTEXT_REQUIRED, or a modeled-but-
  // unsupported shape -> UNSUPPORTED_RESOURCE_SHAPE). The orchestrator's family gate
  // normally blocks a bad context before we are reached, but this function must
  // honor the "missing/invalid resource-context fails closed" contract on its own:
  // return ok:false, emit NO findings, carry the parser's ACTUAL failure code, and
  // state plainly that the context was rejected - never claim the policy was
  // "accepted and routed" or the context "recorded" when it was neither.
  if (!parsed.ok) {
    const rejectedNote =
      'Resource-based policy analysis did NOT run: the attached-resource context was ' +
      'REJECTED (' + parsed.code + '). ' + (parsed.message || '') + ' No resource ' +
      'context was accepted, routed, or recorded, and NO findings were produced. The ' +
      'absence of a finding here does NOT mean the resource is safe - the analyzer ' +
      'fails closed rather than guess the resource this policy is attached to.';
    return {
      ok: false,
      findings: [],
      errors: [Object.freeze({ code: parsed.code, message: parsed.message || null })],
      context: null,
      coverage: Object.freeze({
        service: parsed.service || null,
        arn: resourceContext && typeof resourceContext.arn === 'string' ? resourceContext.arn : null,
        type: null,
        principalTypes: Object.freeze(principals.types),
        anonymousPresent: principals.anonymousPresent,
        unknownPrincipalTypes: Object.freeze(principals.unknownTypes),
        incomplete: true,
        // The parser's REAL failure code (not the generic INCOMPLETE code), so the
        // boundary surfaces RESOURCE_CONTEXT_REQUIRED / UNSUPPORTED_RESOURCE_SHAPE.
        code: parsed.code,
        note: rejectedNote,
      }),
    };
  }

  const service = parsed.service;

  // Principal-centric (generic) findings for the validated, accepted context.
  // This is the SAFETY NET and always runs first.
  const genericFindings = resourceFindings(model, parsed);
  // Per-service dispatch (IAM-1401): select the rule set for the detected service
  // token and run it IN ADDITION to the generic loop, never instead of it. The S3
  // (IAM-1402), KMS (IAM-1403), and shared SNS/SQS messaging (IAM-1404) finding rules
  // add their service-specific refinements to the generic set here. Concatenated in a
  // fixed order (generic first, then per-service) so exports/coverage/UI all read
  // from this single combined finding set and the ordering stays deterministic.
  const perServiceFindings = dispatchPerServiceRules(model, parsed);
  const findings = genericFindings.concat(perServiceFindings);

  const note =
    'Resource-based policy accepted and routed to the resource evaluator (never ' +
    'the identity rules). The attached-resource context is recorded, the principals ' +
    'named are enumerated, and public-access + external-cross-account + same-account ' +
    'direct grants + service-principal confused-deputy grants are reported, plus S3 ' +
    'object-action / bucket-resource type mismatches, KMS key-policy account ' +
    'delegation (Resource:* = the attached key only), and resource-policy condition ' +
    'composition (AND across distinct keys, OR within a key\'s values). The policy is ' +
    'additionally routed to the per-service rule set for its detected service ' +
    '(Amazon S3, KMS, SNS, or SQS) alongside the generic evaluator; the S3 ' +
    'bucket-policy, KMS key-policy, and shared SNS topic / SQS queue messaging ' +
    'per-service finding rules are applied. The remaining ' +
    'service-specific resource rules (the Deny + NotPrincipal ' +
    'hazard) are not yet applied, so this analysis is ' +
    'INCOMPLETE: the absence of a finding does NOT mean the resource is safe. ' +
    'Effective access also depends on identity policies, permissions boundaries, ' +
    'session policies, SCPs/RCPs, and service controls that are not supplied here.';

  return {
    ok: true,
    findings,
    errors: [],
    // The validated attached-resource context (service + ARN + account), so the
    // orchestrator can build the external-principal -> resource graph (IAM-1202).
    // parsed.ok is guaranteed true here (the boundary fails closed above).
    context: Object.freeze({
      service: parsed.service,
      arn: parsed.arn,
      type: parsed.type,
      partition: parsed.partition,
      region: parsed.region,
      account: parsed.account,
      resourceId: parsed.resourceId,
      label: RESOURCE_SERVICE_LABELS[parsed.service] || 'attached resource',
    }),
    coverage: Object.freeze({
      service: service || null,
      arn: parsed.arn,
      type: parsed.type,
      principalTypes: Object.freeze(principals.types),
      anonymousPresent: principals.anonymousPresent,
      unknownPrincipalTypes: Object.freeze(principals.unknownTypes),
      incomplete: true,
      code: RESOURCE_CODES.RESOURCE_ANALYSIS_INCOMPLETE,
      note,
    }),
  };
}

export default analyzeResource;
