// trust-catalogs.js - trust/assume action sets + operator/principal catalogs. Extracted (behavior-preserving; pure frozen data).

export const TRUST_ACTIONS = Object.freeze(new Set([
  'sts:assumerole',
  'sts:assumerolewithsaml',
  'sts:assumerolewithwebidentity',
  'sts:tagsession',
  'sts:setsourceidentity',
]));

// The subset of TRUST_ACTIONS that actually grant the ability to ASSUME the role
// (trust-policy-semantics.md section 3). These are the ONLY actions that convey a
// trust relationship - "who may assume this role".
export const ASSUME_ACTIONS = Object.freeze(new Set([
  'sts:assumerole',
  'sts:assumerolewithsaml',
  'sts:assumerolewithwebidentity',
]));

// The AUXILIARY SESSION actions (trust-policy-semantics.md section 3). They are
// trust actions for FAMILY-ROUTING purposes (a statement naming one is role-trust
// shaped), but they are NOT themselves an assume grant. sts:TagSession only
// permits passing session tags on an assume, and sts:SetSourceIdentity only
// permits setting a source identity - each is REQUIRED in the trust policy for
// that feature to work, but grants nothing on its own. AWS evaluates the assume
// action and the auxiliary action for the SAME caller, so a caller with no
// sts:AssumeRole* grant for this role never reaches TagSession/SetSourceIdentity:
// an aux-only statement is inert without a separate assume grant. A statement
// whose ONLY actions are auxiliary therefore MUST NOT be scored as a public /
// cross-account / federated assume relationship (adversarial-critic IAM-805
// iteration 3 finding 1 - a false CRITICAL/HIGH that asserts an assumption the
// action does not grant, threat-model T8). findingsForStatement gates the
// assume-oriented headlines on the presence of an actual assume action and
// downgrades an aux-only statement to an informational session-control finding
// whose prose never claims assumption.
export const AUX_SESSION_ACTIONS = Object.freeze(new Set([
  'sts:tagsession',
  'sts:setsourceidentity',
]));

// The Principal type keys this analyzer models (trust-policy-semantics.md
// section 2). Any other top-level Principal key is an unmodeled type; the family
// gate fails closed on it before analysis reaches this module.
export const KNOWN_PRINCIPAL_TYPES = Object.freeze(new Set([
  'AWS', 'Service', 'Federated', 'CanonicalUser',
]));

// S3-trust-calibration (2): AWS service principals for which a role trust REQUIRES
// an aws:SourceArn / aws:SourceAccount confused-deputy binding. These services
// assume a role to act on behalf of a SOURCE resource/account that a caller in
// ANOTHER account controls (an EventBridge rule, an S3 bucket, an SNS topic, a
// CloudTrail trail, ...), so an unauthorized actor who can make the service act -
// e.g. by configuring it in their own account - can induce it to assume this role
// on their behalf: the cross-service confused-deputy problem. AWS documents
// aws:SourceArn / aws:SourceAccount as the required mitigation for exactly these
// services. A trust that names one of them WITHOUT a positive, non-vacuous source
// binding is a real exposure - NOT a benign informational service trust - so it is
// raised out of the info band (this is the ROLE-TRUST analogue of resource.js's
// RESOURCE-CONFUSED-DEPUTY unbound case).
//
// Ordinary EXECUTION-role service principals (lambda / ec2 / ecs-tasks / ... assume
// the role to run YOUR OWN workload IN your account; there is no cross-account
// source vector) are deliberately NOT listed, so a normal lambda.amazonaws.com
// trust stays an informational TRUST-SERVICE and this table never over-fires on the
// most common service trusts. Compared case-insensitively against the exact service
// identifier (a partial-wildcard Service member is already failed closed upstream as
// service-wildcard, so it never reaches this table).
export const SOURCE_BINDING_SERVICES = Object.freeze(new Set([
  'events.amazonaws.com',      // EventBridge (rules can be created cross-account)
  'scheduler.amazonaws.com',   // EventBridge Scheduler
  'pipes.amazonaws.com',       // EventBridge Pipes
  'cloudtrail.amazonaws.com',  // CloudTrail delivery to SNS / S3
  's3.amazonaws.com',          // S3 (batch operations / replication / notifications)
  'sns.amazonaws.com',         // SNS
  'ses.amazonaws.com',         // SES
  'config.amazonaws.com',      // AWS Config
]));

// The trust finding ids this module can emit. Kept as an exported, frozen set so
// tests (evidence.test.js catalog, etc.) can recognize trust findings without
// hard-coding the strings, and so the ids stay DISTINCT from the identity
// RULE_IDS / ESCALATION_IDS (fixture-matrix enumerates only those two).
export const TRUST_IDS = Object.freeze([
  // IAM-903: a Principal-element ARN carrying a partial wildcard is an INVALID
  // pattern; it fails closed to this finding (marked invalid + a coverage
  // warning), never a plain uncaveated TRUST-CROSS-ACCOUNT high. Ordered first so
  // it sorts ahead of the substantive trust findings for the same statement.
  'TRUST-INVALID-PRINCIPAL',
  'TRUST-PUBLIC',
  'TRUST-ORG-EXPANSION',
  'TRUST-CROSS-ACCOUNT',
  'TRUST-FEDERATED',
  'TRUST-SESSION-CONTROL',
  'TRUST-SERVICE',
]);

export const RULE_VERSION = '1';

// Every trust finding carries this limitation verbatim. It states the
// load-bearing invariant (target-role permissions unknown / out of scope) AND
// the capability-not-effective caveat ("not effective access") that the rest of
// the engine uses on every finding, so a trust finding can never be read as an
// effective-permissions or inherited-power claim.
export const TRUST_LIMIT =
  'This classifies the trust RELATIONSHIP from the policy text - who may assume ' +
  'the role - not effective access. A role trust policy never conveys the ' +
  "assumed role's permissions: the target role's actual privileges are OUT OF " +
  'SCOPE and remain UNKNOWN from this document. AWS also evaluates the caller ' +
  'identity, session policies, and boundaries, none of which are present here, ' +
  'so no one inherits the role\'s power merely by being trusted to assume it.';

export const DOC_PRINCIPAL =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html';
export const DOC_CONDITION_KEYS =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html';
export const DOC_CONFUSED_DEPUTY =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html';
export const DOC_OIDC =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html';

// Negated string/arn/ip operators: on an otherwise-constraining key they invert
// polarity to an EXPANSION ("everything except the listed values"). Mirrors
// conditions.js NEGATED_OPERATORS (kept local so trust.js stays dependency-free
// and cannot create an import cycle with conditions.js -> family.js).
export const NEGATED_OPERATORS = new Set([
  'stringnotequals', 'stringnotequalsignorecase', 'stringnotlike',
  'arnnotequals', 'arnnotlike', 'numericnotequals', 'datenotequals',
  'notipaddress',
]);

// Positive string/ARN equality-family operators. A confused-deputy / scoping
// constraint (ExternalId, SourceArn/SourceAccount, PrincipalOrgID StringEquals,
// PrincipalArn/PrincipalAccount) is only real when it matches a VALUE with one
// of these operators. A Null operator (tests key ABSENT/PRESENT, not equality),
// a Date/Numeric/Bool operator, or any other operator does NOT impose a
// value-scoping constraint on these keys, so it must never neutralize a trust
// finding (adversarial-critic defect 1: Null/DateGreaterThan on sts:ExternalId
// were silently downgrading an unconstrained whole-account trust high->low).
export const POSITIVE_STRING_MATCH_OPERATORS = new Set([
  'stringequals', 'stringequalsignorecase', 'stringlike',
  'arnequals', 'arnlike',
]);
