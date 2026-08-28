// resource-catalogs.js - resource-policy code/service/id catalogs + doc-reference strings. Extracted (behavior-preserving; pure frozen data + string constants).

export const RESOURCE_CODES = Object.freeze({
  // The attached-resource context (type + ARN) is required for the resource
  // family and was missing, empty, or not a parseable ARN. Fail closed - the
  // analyzer never guesses which resource a resource policy is attached to.
  RESOURCE_CONTEXT_REQUIRED: 'RESOURCE_CONTEXT_REQUIRED',
  // The context parsed to a valid ARN, but for a service whose resource-policy
  // shape this analyzer does not yet model (anything outside S3 / SNS / SQS /
  // KMS in this tranche). Fail closed rather than apply S3/KMS reasoning to a
  // service whose nuances are unmodeled ("unsupported != safe").
  UNSUPPORTED_RESOURCE_SHAPE: 'UNSUPPORTED_RESOURCE_SHAPE',
  // Non-blocking: the resource family was accepted and routed here, but the
  // service-specific resource finding rules are not yet implemented in this
  // tranche, so coverage is INCOMPLETE (the zero-findings wording must flip -
  // an accepted resource policy is not a proven-safe one).
  RESOURCE_ANALYSIS_INCOMPLETE: 'RESOURCE_ANALYSIS_INCOMPLETE',
});

// The resource-service shapes this analyzer routes to the resource evaluator.
// s3 splits into bucket-scope vs object-scope (the bucket-vs-object typing that
// matters for object actions - resource-policy-semantics.md section 2.1). A
// recognized AWS ARN whose service is none of these classifies as 'generic' and
// fails closed as an unmodeled shape in this tranche.
export const RESOURCE_SERVICES = Object.freeze({
  S3_BUCKET: 's3-bucket',
  S3_OBJECT: 's3-object',
  SNS: 'sns',
  SQS: 'sqs',
  KMS_KEY: 'kms-key',
  GENERIC: 'generic',
});

// The services whose resource-policy shape is modeled (accepted) in this tranche.
// 'generic' is intentionally excluded: it is DETECTED (so coverage can name it)
// but fails closed as an unmodeled shape.
export const MODELED_RESOURCE_SERVICES = Object.freeze(new Set([
  RESOURCE_SERVICES.S3_BUCKET,
  RESOURCE_SERVICES.S3_OBJECT,
  RESOURCE_SERVICES.SNS,
  RESOURCE_SERVICES.SQS,
  RESOURCE_SERVICES.KMS_KEY,
]));

// Resource finding ids owned by the resource evaluator. IAM-1202 adds the
// principal-centric public-access + external-cross-account findings; IAM-1203 adds
// the service-principal confused-deputy finding; later Phase-12 stories
// (same-account, KMS, NotPrincipal) add their own ids. Exported so later phases and
// the evidence meta-test can aggregate the resource catalog the way they do
// RULE_IDS / ESCALATION_IDS / TRUST_IDS.
export const RESOURCE_IDS = Object.freeze([
  'PUBLIC-ACCESS',
  'RESOURCE-CROSS-ACCOUNT',
  'RESOURCE-CONFUSED-DEPUTY',
  // IAM-1204: a same-account IAM-user / role / assumed-role-session direct
  // resource-policy grant (resource-vs-identity evaluation distinction, test 32/33),
  // and an S3 object-action-on-a-bucket-only-ARN action/resource-type mismatch
  // (test 50 in the resource context).
  'RESOURCE-SAME-ACCOUNT-GRANT',
  'RESOURCE-ACTION-RESOURCE-MISMATCH',
  // IAM-1205: a KMS key policy's account / account-root principal statement (the
  // "Enable IAM User Permissions"-style account delegation, test 51) - broad KMS
  // authority delegated to the OWNING ACCOUNT, never modeled as public access,
  // root-user-only access, or a per-key node explosion.
  'RESOURCE-KMS-ACCOUNT-DELEGATION',
  // IAM-1208 (Phase 12.1, fix 4): a resource-policy Principal type that this
  // analyzer does not model a grant for must never be SILENTLY DROPPED (zero
  // findings would read as "safe"). A recognized-but-unmodeled CanonicalUser
  // principal, or an INVALID partial-wildcard AWS / Service / Federated principal
  // (a "*"/"?" the Principal element cannot use, which AWS rejects at save time),
  // is surfaced fail-closed - it always yields >=1 finding, mirroring the trust
  // family's "fail closed toward surfacing" (TRUST-INVALID-PRINCIPAL).
  'RESOURCE-UNSUPPORTED-PRINCIPAL',
  // IAM-1402 (Phase 14): S3 per-service refinements, ADDITIVE to the generic
  // findings above (never a suppression of them). A bucket-CONTROL action
  // (s3:PutBucketPolicy / PutBucketAcl / PutBucketPublicAccessBlock /
  // DeleteBucketPolicy) granted to an anonymous "*" or a principal outside the
  // bucket-owning account is a resource-policy TAKEOVER / self-expansion primitive
  // ranked above a data-plane action (never over-claimed as proven effective
  // takeover).
  'S3-BUCKET-POLICY-TAKEOVER',
  // IAM-1402 (Phase 14): a companion note on a genuinely-public S3 "*" grant that
  // carries an S3-specific condition/Deny which could be MISREAD as narrowing it to
  // authenticated principals but does not: a network selector (aws:SourceIp /
  // SourceVpc / SourceVpce - anonymous WITHIN that network), s3:ResourceAccount /
  // aws:ResourceAccount (pins the bucket-OWNER account, not the caller), or a
  // request-property Deny (aws:SecureTransport / s3:TlsVersion /
  // s3:x-amz-server-side-encryption - constrains the request, not WHO may act). It
  // states these do NOT privatize/narrow the public grant; it never downgrades the
  // generic critical PUBLIC-ACCESS finding.
  'S3-PUBLIC-NOT-NARROWED',
  // IAM-1403 (Phase 14): KMS key-policy per-service refinements, ADDITIVE to the
  // generic findings above and scoped to the kms-key token ONLY (the KMS
  // not-anonymous reframing is structurally incapable of altering the S3/SNS/SQS
  // anonymous-public classification - trap 4). A companion note on a genuinely-broad
  // KMS "*" grant that carries kms:ViaService (or a network selector) which could be
  // MISREAD as narrowing it to authenticated principals but does not: kms:ViaService
  // pins the SERVICE CHANNEL a request flows through, not WHO the caller is, so a "*"
  // narrowed only by it stays open to every account whose requests flow through that
  // service (grounding 3.3). Only kms:CallerAccount / aws:PrincipalAccount /
  // aws:PrincipalOrgID pin WHO. Never downgrades the generic KMS "*" over-grant.
  'KMS-VIASERVICE-NOT-SCOPING',
  // IAM-1403 (Phase 14): kms:CreateGrant granted to "*" or a cross-account / account-
  // undetermined principal is an onward-DELEGATION primitive - the grantee can create
  // grants that let OTHER principals (in any account/org, including AWS services) use
  // the key, and need not hold the permission itself (grounding 3.4). Ranked above
  // ordinary key use; NEVER over-claimed as a proven decrypt or as effective access.
  // kms:GrantIsForAWSResource narrows CreateGrant to AWS-service-created grants.
  'KMS-CREATE-GRANT-DELEGATION',
  // IAM-1403 (Phase 14): kms:PutKeyPolicy granted to "*" (critical) or a cross-account
  // / account-undetermined principal (high) is a key-policy TAKEOVER / self-expansion
  // primitive - the grantee can rewrite the key's own policy to grant itself (or
  // anyone) any further access (grounding 3.4, "much like" kms:CreateGrant). Never
  // fired for a confirmed same-account principal, and never over-claimed as effective.
  'KMS-KEY-POLICY-TAKEOVER',
  // IAM-1403 (Phase 14): the KMS silent-key-policy inversion (grounding 3.5). A key
  // policy that OMITS the account-delegation ("Enable IAM User Permissions") statement
  // and grants no anonymous "*" means IAM identity policies CANNOT govern the key
  // (unlike S3, where an absent bucket policy still lets the account's IAM policies
  // grant access) - only the key-policy-named principals can use it, and per-principal
  // effective access is fail-closed UNKNOWN from the key policy alone. Surfaced (never
  // silently dropped); the absence of a finding does NOT mean the key is safe/private.
  'KMS-SILENT-POLICY-UNKNOWN',
  // IAM-1404 (Phase 14): shared SNS topic + SQS queue messaging per-service
  // refinements, ADDITIVE to the generic findings above and scoped to the sns / sqs
  // tokens only (the KMS not-anonymous carve-out is structurally incapable of leaking
  // here - trap 4 - so a genuinely-anonymous SNS/SQS "*" grant stays critical
  // PUBLIC-ACCESS via the generic path). A genuinely-public (anonymous "*", not
  // narrowed by a principal-identity key) grant of a dangerous messaging DATA-PLANE
  // action names the specific vector the generic PUBLIC-ACCESS enumeration does not:
  // sns:Subscribe to "*" = anyone can attach an endpoint and EXFILTRATE every message
  // published to the topic; sns:Publish to "*" = anyone can INJECT messages to the
  // topic and its subscribers; sqs:ReceiveMessage (+ sqs:DeleteMessage) to "*" =
  // anyone can DRAIN/read the queue; sqs:SendMessage to "*" = anyone can INJECT/poison
  // the queue. Never downgrades or suppresses the generic critical PUBLIC-ACCESS.
  'MESSAGING-PUBLIC-EXPOSURE',
  // IAM-1404 (Phase 14): a messaging policy-CONTROL action - sns:AddPermission /
  // sns:RemovePermission / sns:SetTopicAttributes, sqs:AddPermission /
  // sqs:RemovePermission / sqs:SetQueueAttributes (or a full-service sns:* / sqs:*
  // wildcard that INCLUDES them) - granted to an anonymous "*" (critical) or to a
  // principal outside (or not confirmed inside) the resource-owning account (high) is
  // a resource-policy TAKEOVER / self-expansion primitive: the grantee can rewrite the
  // topic/queue access policy to grant itself (or anyone) any further access. Ranked
  // above a data-plane messaging action; NEVER over-claimed as proven effective
  // takeover (a cross-account grant still needs the caller's own account to allow it).
  'MESSAGING-POLICY-TAKEOVER',
  // IAM-1404 (Phase 14): aws:SourceOwner is a DEPRECATED legacy confused-deputy
  // source-binding key on Amazon SNS ("new services can integrate with Amazon SNS only
  // through aws:SourceArn and aws:SourceAccount"). It IS a present source binding (the
  // generic RESOURCE-CONFUSED-DEPUTY treats a service grant carrying it as source-bound,
  // not a missing binding), but this note recommends migrating to
  // aws:SourceArn/aws:SourceAccount. Informational; never a missing-binding warning and
  // never a public-write claim (a service principal is not "*").
  'MESSAGING-DEPRECATED-SOURCE-OWNER',
]);

// Rule revision for resource findings (provenance on every finding/export).
export const RESOURCE_RULE_VERSION = '1';

// The capability-not-effective caveat carried on EVERY resource finding
// (threat-model T8, resource-policy-semantics.md section 0/10.2). Contains the
// exact "not effective access" phrase the evidence-completeness gate asserts.
export const RESOURCE_LIMIT =
  'This is the direct resource-policy grant read from the RESOURCE\'s ' +
  'perspective (who may act on THIS attached resource) - potential blast radius, ' +
  'NOT effective access. Whether a principal can actually perform the action also ' +
  'depends on that principal\'s identity policies, permissions boundaries, session ' +
  'policies, SCPs/RCPs, and service-specific controls that are not supplied here; ' +
  'for cross-account access the caller\'s own account must ALSO allow it. An ' +
  'applicable explicit Deny in any layer still blocks.';

// AWS documentation references (display evidence; never fetched at runtime).
export const DOC_PRINCIPAL =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html';
export const DOC_CROSS_ACCOUNT =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html';
export const DOC_S3_BPA =
  'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html';
export const DOC_CONFUSED_DEPUTY =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html';
// Same-account union evaluation (a resource-policy Allow can grant even when the
// identity policy is silent; an applicable explicit Deny still blocks) - section 1.1.
export const DOC_EVAL_LOGIC =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html';
// S3 bucket-vs-object action/resource scoping (object actions need an object ARN).
export const DOC_S3_ACTIONS =
  'https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html';
// S3 bucket-policy condition keys (s3:x-amz-server-side-encryption SSE enforcement,
// s3:TlsVersion, s3:ResourceAccount / aws:ResourceAccount - the bucket-owner account,
// not the caller) - docs/resource-per-service-semantics.md sections 1.3-1.4, source 3.
export const DOC_S3_POLICY_KEYS =
  'https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html';
// KMS default key policy - "Enable IAM User Permissions": the account principal
// delegates authority to the account (via IAM), not the root user only; Resource:*
// is the attached key (resource-policy-semantics.md section 7.1 / 6).
export const DOC_KMS_KEY_POLICY =
  'https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html';
// KMS key-policy overview: "AWS":"*" = all AWS identities in all accounts (KMS has
// no unauthenticated path); Resource:"*" = this attached key; account-root delegates
// to the account + admins, not root-only (per-service semantics section 3.1-3.2).
export const DOC_KMS_OVERVIEW =
  'https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html';
// KMS condition keys: kms:ViaService pins the request CHANNEL (a service), NOT the
// caller; kms:CallerAccount pins the caller's ACCOUNT (per-service section 3.3).
export const DOC_KMS_CONDITIONS =
  'https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html';
// Grants in AWS KMS: kms:CreateGrant delegates key use cross-account/org and the
// grantee need not hold the permission itself; "much like" kms:PutKeyPolicy in blast
// radius; kms:GrantIsForAWSResource narrows it (per-service section 3.4).
export const DOC_KMS_GRANTS =
  'https://docs.aws.amazon.com/kms/latest/developerguide/grants.html';
// SNS access-control example cases: Publish/Subscribe; the S3 -> SNS aws:SourceAccount
// pattern; aws:PrincipalOrgID org-scoped publish; aws:SourceOwner deprecated in favor
// of aws:SourceArn / aws:SourceAccount (per-service semantics section 4).
export const DOC_SNS_ACCESS =
  'https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html';
// SQS basic policy examples: Principal "*" = "all users (anonymous users)";
// SendMessage / ReceiveMessage; cross-account exclusions (per-service section 4.1).
export const DOC_SQS_ACCESS =
  'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-sqs-policies.html';

// Human labels for the UI / exports. Falls back to the raw token.
export const RESOURCE_SERVICE_LABELS = Object.freeze({
  's3-bucket': 'Amazon S3 bucket',
  's3-object': 'Amazon S3 object',
  sns: 'Amazon SNS topic',
  sqs: 'Amazon SQS queue',
  'kms-key': 'AWS KMS key',
  generic: 'Other AWS resource',
});
