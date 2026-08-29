// rules-detectors.js - the identity-policy rule detectors (wildcard action/resource, direct-IAM-admin, data-exfil, kms-decrypt, scoped data-read + container-read spared-resource analysis, destructive, detection-impairment, notaction-allow, group-membership). Extracted (behavior-preserving).
import { actionGrants, actionService, actionVerb, concreteResourceAccount, groupNameFromArn, groupNameSuggestsPrivilege, isFullWildcard, isServiceWildcard, isWholeContainerRead, resourceAccountFromCondition, resourceHasVariable, resourceInfersSensitive, BULK_READ_ACTIONS, CONCRETE_ACCOUNT_ID_RE, DATA_READ_ACTIONS, DESTRUCTIVE_VERB, DETECTION_ACTIONS, DETECTION_SERVICES, GROUP_MEMBERSHIP_ACTIONS, IAM_ADMIN_ACTIONS, KMS_DECRYPT_ACTIONS, RESOURCE_POLICY_WRITE_ACTIONS, SECRET_READ_ACTIONS } from './rules-classify.js';
import { denyFencesToNarrow, grantsNonReadAction, makeFinding, remediableWildcardActions, resourceIsBroad, resourceScope, isBroadArnResource, ruleFindingDenySuppressed, survivingBroadReadActions } from './rules-finding.js';
import { chargeWork, globMatch } from './glob.js';
import { classifyResource, parseArn, RESOURCE_CLASS } from './resource-arn.js';
import { denyActionApplies } from './escalation-deny.js';
import { hasNonEmptyCondition } from './escalation-conditions.js';
import { statementNeverMatches } from './conditions.js';

export function ruleWildcardAction(stmt, out) {
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
export function ruleWildcardResource(stmt, out) {
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
export function matchPatterns(stmt, catalog, includeServiceWildcards) {
  const matched = [];
  for (const p of stmt.actions) {
    if (isFullWildcard(p)) continue; // "*" is owned by WILDCARD-ACTION
    if (!includeServiceWildcards && isServiceWildcard(p)) continue;
    if (catalog.some((sensitive) => actionGrants(p, sensitive))) matched.push(p);
  }
  return matched;
}

// 3. Direct IAM administration (includes iam:* per the requirement).
export function ruleDirectIamAdmin(stmt, out) {
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

// 3b. Resource-policy write / cross-account grant (Stage-13 EFO-2). Rewriting a
// resource's OWN policy (bucket/key/function/topic/queue/repo/secret) lets the
// holder grant an external or arbitrary principal access to it - a cross-account
// exfil / key-control / backdoor primitive. Distinct from DIRECT-IAM-ADMIN
// (identity-policy edits). Service wildcards are excluded (WILDCARD-ACTION owns
// them); this targets the specific-action fail-open that used to read CLEAN.
export function ruleResourcePolicyWrite(stmt, out) {
  const matched = matchPatterns(stmt, RESOURCE_POLICY_WRITE_ACTIONS, false);
  if (matched.length === 0) return;
  out.push(
    makeFinding('RESOURCE-POLICY-WRITE', stmt, {
      // High, not critical: a standalone permissions-management primitive (like
      // DIRECT-IAM-ADMIN). Critical is reserved for compound privilege-boundary
      // crossing paths (IAM-102 severity model). Whether an external principal is
      // actually added is a runtime action, not in this policy - so evidence high,
      // but it is a genuine, standalone grant-delegation capability.
      severity: 'high',
      policyEvidence: 'high',
      actions: matched,
      resources: resourceScope(stmt),
      why:
        'Grants a resource-policy write / cross-account grant action (e.g. ' +
        's3:PutBucketPolicy, s3:PutObjectAcl, kms:PutKeyPolicy, kms:CreateGrant, ' +
        'lambda:AddPermission, sns:AddPermission, secretsmanager:PutResourcePolicy). ' +
        'A principal that can rewrite a resource\'s own policy can grant an external ' +
        'or arbitrary principal access to that data store, key, function, or topic - ' +
        'a cross-account exfiltration, key-control, or persistence backdoor primitive.',
      remediation:
        'Restrict resource-policy writes to a dedicated administration role, scope ' +
        'the Resource to specific ARNs, and use SCPs / resource-control policies and ' +
        'aws:PrincipalOrgID conditions to prevent granting access to principals ' +
        'outside your organization.',
    }),
  );
}

// 4a. Sensitive data read / exfil.
export function ruleDataExfil(stmt, out) {
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
export function ruleKmsDecrypt(stmt, out) {
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
export function classifyContainerReads(resources, actions, opts) {
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
export function undetAllCanonicalS3(resources) {
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
export function undetFindingText(resources, fenced) {
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
export function ruleDataReadScoped(stmt, out, ctx) {
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
export function denyEntirelyDeniesResource(deny, r, action) {
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
export function sparedResourceFullyDeniedElsewhere(r, fencedActions, denies) {
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
export function allowGrantsSparedResource(allowStmt, isComplementAllow, r) {
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
export function ruleDestructive(stmt, out) {
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
export function ruleDetectionImpairment(stmt, out) {
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
export function ruleNotActionAllow(stmt, out) {
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
export function ruleGroupMembership(stmt, out) {
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
