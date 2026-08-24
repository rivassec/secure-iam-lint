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
import { parseOperator, NEGATED_OPERATORS } from './conditions.js';

// Stable, machine-readable coverage codes owned by the resource family. Kept here
// (not in family.js) so the resource module owns its own vocabulary; family.js
// re-exports/uses them for the gate.
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
]);

// Rule revision for resource findings (provenance on every finding/export).
const RESOURCE_RULE_VERSION = '1';

// The capability-not-effective caveat carried on EVERY resource finding
// (threat-model T8, resource-policy-semantics.md section 0/10.2). Contains the
// exact "not effective access" phrase the evidence-completeness gate asserts.
const RESOURCE_LIMIT =
  'This is the direct resource-policy grant read from the RESOURCE\'s ' +
  'perspective (who may act on THIS attached resource) - potential blast radius, ' +
  'NOT effective access. Whether a principal can actually perform the action also ' +
  'depends on that principal\'s identity policies, permissions boundaries, session ' +
  'policies, SCPs/RCPs, and service-specific controls that are not supplied here; ' +
  'for cross-account access the caller\'s own account must ALSO allow it. An ' +
  'applicable explicit Deny in any layer still blocks.';

// AWS documentation references (display evidence; never fetched at runtime).
const DOC_PRINCIPAL =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html';
const DOC_CROSS_ACCOUNT =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html';
const DOC_S3_BPA =
  'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html';
const DOC_CONFUSED_DEPUTY =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html';
// Same-account union evaluation (a resource-policy Allow can grant even when the
// identity policy is silent; an applicable explicit Deny still blocks) - section 1.1.
const DOC_EVAL_LOGIC =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html';
// S3 bucket-vs-object action/resource scoping (object actions need an object ARN).
const DOC_S3_ACTIONS =
  'https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-actions.html';
// KMS default key policy - "Enable IAM User Permissions": the account principal
// delegates authority to the account (via IAM), not the root user only; Resource:*
// is the attached key (resource-policy-semantics.md section 7.1 / 6).
const DOC_KMS_KEY_POLICY =
  'https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html';

// Human labels for the UI / exports. Falls back to the raw token.
export const RESOURCE_SERVICE_LABELS = Object.freeze({
  's3-bucket': 'Amazon S3 bucket',
  's3-object': 'Amazon S3 object',
  sns: 'Amazon SNS topic',
  sqs: 'Amazon SQS queue',
  'kms-key': 'AWS KMS key',
  generic: 'Other AWS resource',
});

/**
 * Parse an AWS ARN into its components without hard-coding the commercial `aws`
 * partition (suite-2 test 47: GovCloud / China partitions are preserved).
 * Returns null when the value is not a syntactically valid ARN.
 *
 * ARN grammar: arn:partition:service:region:account-id:resource
 * The resource segment may itself contain ':' (e.g. key/... , type:id), so it is
 * everything after the fifth ':'.
 *
 * @param {string} value
 * @returns {{partition:string,service:string,region:string,account:string,resource:string}|null}
 */
export function parseArn(value) {
  if (typeof value !== 'string') return null;
  const s = value.trim();
  if (s.length === 0) return null;
  const parts = s.split(':');
  // arn : partition : service : region : account : resource(+)
  if (parts.length < 6) return null;
  if (parts[0] !== 'arn') return null;
  const partition = parts[1];
  const service = parts[2];
  if (partition.length === 0 || service.length === 0) return null;
  return {
    partition,
    service,
    region: parts[3],
    account: parts[4],
    resource: parts.slice(5).join(':'),
  };
}

/**
 * Classify the attached-resource SERVICE from a parsed ARN. Deterministic; never
 * throws. s3 splits into bucket vs object scope by the presence of an object key
 * ('/'), consistent with the bucket-vs-object typing in section 2.1. A KMS ARN is
 * a key policy only for a `key/...` resource; anything else recognized-but-not-
 * modeled classifies 'generic'.
 *
 * @param {{service:string,resource:string}} arn parsed ARN (from parseArn)
 * @returns {string} one of RESOURCE_SERVICES
 */
export function serviceForArn(arn) {
  if (!arn || typeof arn !== 'object') return RESOURCE_SERVICES.GENERIC;
  const svc = String(arn.service || '').toLowerCase();
  const resource = String(arn.resource || '');
  if (svc === 's3') {
    // Object ARNs carry a key after the bucket name (bucket/key or bucket/*);
    // a bucket-only ARN has no '/'.
    return resource.includes('/') ? RESOURCE_SERVICES.S3_OBJECT : RESOURCE_SERVICES.S3_BUCKET;
  }
  if (svc === 'sns') return RESOURCE_SERVICES.SNS;
  if (svc === 'sqs') return RESOURCE_SERVICES.SQS;
  if (svc === 'kms') {
    return /^key\//i.test(resource) ? RESOURCE_SERVICES.KMS_KEY : RESOURCE_SERVICES.GENERIC;
  }
  return RESOURCE_SERVICES.GENERIC;
}

/**
 * Validate and normalize the explicit attached-resource context supplied with a
 * resource-family analysis. The context is REQUIRED (the "resource-policy context
 * is explicit" invariant): a resource policy with no attached-resource context
 * cannot be analyzed and fails closed.
 *
 * Shape: { type?: string, arn: string }. The ARN is authoritative for service
 * detection; `type` is an optional UI hint recorded for evidence.
 *
 * @param {{type?:string, arn?:string}|null|undefined} context
 * @returns {{ok:boolean, code?:string, message?:string, service?:string,
 *            arn?:string, type?:(string|null), partition?:string, region?:string,
 *            account?:string, resourceId?:string}}
 */
export function parseResourceContext(context) {
  const ctx = (context && typeof context === 'object') ? context : null;
  const arnRaw = ctx && typeof ctx.arn === 'string' ? ctx.arn.trim() : '';
  const typeHint = ctx && typeof ctx.type === 'string' && ctx.type.length > 0
    ? ctx.type
    : null;
  // IAM-1204: the OWNING account of the attached resource may be supplied
  // explicitly (the "resource-policy context is explicit" invariant). This is
  // load-bearing for S3, whose bucket/object ARNs (arn:aws:s3:::bucket[/key])
  // structurally carry NO account id, so same-account vs cross-account cannot be
  // decided from the ARN alone. Only a bare 12-digit account id is accepted; any
  // other value is ignored (never guessed).
  const explicitAccount = ctx && typeof ctx.account === 'string' && /^\d{12}$/.test(ctx.account.trim())
    ? ctx.account.trim()
    : null;

  if (arnRaw.length === 0) {
    return {
      ok: false,
      code: RESOURCE_CODES.RESOURCE_CONTEXT_REQUIRED,
      message:
        'Resource-based policy analysis requires the attached-resource context ' +
        '(the resource type and ARN this policy is attached to). "Who can act on ' +
        'this resource" is only meaningful relative to a known attached resource, ' +
        'so the analyzer never guesses it. Supply the attached resource ARN and ' +
        'analyze again.',
    };
  }

  const arn = parseArn(arnRaw);
  if (!arn) {
    return {
      ok: false,
      code: RESOURCE_CODES.RESOURCE_CONTEXT_REQUIRED,
      message:
        `The attached-resource context "${arnRaw}" is not a valid ARN ` +
        '(expected arn:partition:service:region:account:resource). Supply the ' +
        'ARN of the resource this policy is attached to and analyze again.',
    };
  }

  const service = serviceForArn(arn);
  if (!MODELED_RESOURCE_SERVICES.has(service)) {
    return {
      ok: false,
      code: RESOURCE_CODES.UNSUPPORTED_RESOURCE_SHAPE,
      service,
      arn: arnRaw,
      type: typeHint,
      message:
        `The attached resource "${arnRaw}" is a resource-based-policy shape this ` +
        'analyzer does not yet model (only Amazon S3, SNS, SQS, and KMS key ' +
        'policies are modeled in this release). Analysis stops rather than apply ' +
        'S3/KMS-specific reasoning to a service whose semantics are unmodeled - ' +
        'unsupported does NOT mean safe.',
    };
  }

  // The owning account used for same-vs-cross-account classification: the explicit
  // context account wins (needed for S3), else the ARN's own account field (SNS /
  // SQS / KMS carry it), else null (undetermined -> the analyzer hedges and never
  // assumes same-account).
  const arnAccount = /^\d{12}$/.test(String(arn.account)) ? String(arn.account) : null;
  const ownerAccount = explicitAccount || arnAccount;

  return {
    ok: true,
    service,
    arn: arnRaw,
    type: typeHint || service,
    partition: arn.partition,
    region: arn.region,
    account: arn.account,
    ownerAccount,
    resourceId: arn.resource,
  };
}

/**
 * Enumerate the principal TYPES named across a resource policy's statements, as
 * inert evidence for the coverage panel/export (WHO the policy names). Reuses the
 * trust family's principal classifier so a service principal, an account/root
 * principal, a specific user/role/session ARN, a federated principal, a canonical
 * user, and anonymous "*" are each identified distinctly and never collapsed
 * (resource-policy-semantics.md section 3). Deterministic, sorted, deduped.
 *
 * @param {object} model normalized model
 * @returns {{types:string[], anonymousPresent:boolean, unknownTypes:string[]}}
 */
export function enumeratePrincipals(model) {
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  const types = new Set();
  const unknown = new Set();
  let anonymous = false;
  for (const s of statements) {
    const p = s && s.principal;
    if (!p) continue;
    const c = classifyPrincipals(p);
    if (c.anonymous) anonymous = true;
    for (const cat of c.categories) types.add(cat);
    for (const u of c.unknownTypes) unknown.add(u);
  }
  return {
    types: [...types].sort(),
    anonymousPresent: anonymous,
    unknownTypes: [...unknown].sort(),
  };
}

// The account that OWNS an attacker-controlled principal entry, extracted from its
// value WITHOUT hard-coding the commercial partition (test 47). An account/root/
// user/role/session ARN carries the account in ARN field 4; a bare 12-digit id is
// itself the account. Returns null when the account cannot be determined (e.g. an
// S3 canonical-user hash), in which case the caller fails closed toward surfacing
// (an unpinnable principal is treated as external, never assumed same-account).
function accountOfEntry(entry) {
  const type = entry && typeof entry === 'object' ? String(entry.type) : '';
  const value = entry && entry.value != null ? String(entry.value) : '';
  if (type === 'aws-account') return /^\d{12}$/.test(value) ? value : null;
  const arn = parseArn(value);
  if (arn && /^\d{12}$/.test(String(arn.account))) return arn.account;
  return null;
}

// A single Condition block is TRANSPORT-only when every operator it names checks
// aws:SecureTransport and nothing else (resource-policy-semantics.md section 5): a
// classic S3 `Deny ... Bool aws:SecureTransport=false` forces HTTPS but constrains
// the TRANSPORT, not WHO may act. It therefore must never be read as an identity
// constraint that makes a public Allow private. Case-insensitive on the key; keys
// other than aws:SecureTransport make the Deny more than transport-only (unknown ->
// fail closed to "not transport-only", so we never understate a real block).
function isTransportOnlyCondition(condition) {
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return false;
  const ops = Object.keys(condition);
  if (ops.length === 0) return false;
  for (const op of ops) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object') return false;
    for (const key of Object.keys(inner)) {
      if (String(key).toLowerCase() !== 'aws:securetransport') return false;
    }
  }
  return true;
}

// Condition keys that SCOPE WHO may act (principal-identity constraints), as
// distinct from transport/network selectors. When one of these gates an anonymous
// "*" Allow with a POSITIVE (value-matching) operator, the grant is NOT
// unconditioned anonymous/public access: the condition restricts use to
// AUTHENTICATED principals matching the named constraint, which is exactly what
// excludes anonymous, unauthenticated callers (resource-policy-semantics.md
// section 3.1; suite-3 test 85). This is deliberately the principal-identity subset
// - a transport/network selector (aws:SecureTransport, aws:SourceIp, aws:SourceVpc/e,
// ...) is NOT here and does not make a public grant private (section 5). The
// principal-IDENTITY keys (aws:PrincipalTag/*, aws:userid, aws:PrincipalOrgPaths,
// aws:PrincipalType, aws:PrincipalOrgID) each identify the CALLING principal, so an
// anonymous/unauthenticated caller - who carries none of them - is excluded by a
// positive match on any of them (adversarial-critic IAM-1202 iteration 4: omitting
// aws:PrincipalTag reported test 49's tag-scoped "*" as unconditioned public).
// Keys are matched case-insensitively. aws:PrincipalTag carries a `/<tag-key>`
// suffix, so it is matched by prefix.
const PRINCIPAL_SCOPING_KEYS = Object.freeze(new Set([
  'aws:principalarn',
  'aws:principalaccount',
  'aws:principalorgid',
  'aws:principalorgpaths',
  'aws:principaltype',
  'aws:userid',
  'aws:sourceaccount',
  'aws:sourcearn',
]));

// True when a condition key names a principal-identity scoping key. aws:PrincipalTag
// is written as `aws:PrincipalTag/<tag-key>` (the tag name is a suffix), so it is
// matched by prefix; every other scoping key is an exact match. Case-insensitive.
function isPrincipalScopingKey(keyLower) {
  if (PRINCIPAL_SCOPING_KEYS.has(keyLower)) return true;
  return keyLower.startsWith('aws:principaltag/');
}

// True when an operator NEGATES its principal-scoping match - i.e. it is one of the
// *NotEquals / *NotLike / NotIpAddress family, or a Null test that requires the key
// to be ABSENT. A negated operator on a principal-scoping key is an EXCLUSION, not a
// narrowing: `StringNotEquals aws:PrincipalOrgID o-abc` permits EVERY principal whose
// org is NOT o-abc (everyone outside your org), and because a negated match also
// succeeds for a request that LACKS the key, anonymous/unauthenticated callers are
// NOT excluded - the grant is at least as broad as public. This must never be
// credited as narrowing (adversarial-critic IAM-1202 iteration 4: negated operators
// were credited as positive narrowing constraints, downgrading a worse-than-public
// grant to "narrowed"). Reuses conditions.js' NEGATED_OPERATORS / parseOperator so
// the polarity read matches the trust family exactly.
function operatorNegatesScope(operator, value) {
  const { base } = parseOperator(operator);
  if (NEGATED_OPERATORS.has(base)) return true;
  if (base === 'null') {
    // Null:"true" tests the key is ABSENT (broadening); Null:"false" tests it is
    // PRESENT (does not broaden). Fail closed toward "expansion" on an
    // unresolvable/mixed value so an ambiguous Null never silently downgrades.
    const vals = (Array.isArray(value) ? value : [value]).map((v) => String(v).toLowerCase());
    return !(vals.length === 1 && vals[0] === 'false');
  }
  return false;
}

// Analyze the principal-scoping condition keys on a statement, separating those that
// genuinely NARROW an anonymous "*" grant (a principal-identity key under a positive
// operator) from those that EXPAND it (the same key under a negated/absent operator,
// which reads "everyone EXCEPT ..." and does not exclude anonymous). Both lists are
// original-cased, sorted, deduped. Never rejects or interprets the condition VALUE -
// a wildcard inside e.g. aws:PrincipalArn is a valid condition value, not a
// partial-ARN principal wildcard (test 85); only the OPERATOR polarity is read.
function principalScopingAnalysis(condition) {
  const scoping = new Set();
  const expanding = new Set();
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) {
    return { scopingKeys: [], expansionKeys: [] };
  }
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    for (const key of Object.keys(inner)) {
      if (!isPrincipalScopingKey(String(key).toLowerCase())) continue;
      if (operatorNegatesScope(op, inner[key])) expanding.add(key);
      else scoping.add(key);
    }
  }
  return {
    scopingKeys: [...scoping].sort(),
    expansionKeys: [...expanding].sort(),
  };
}

// --- Condition composition (IAM-1205; resource-policy-semantics.md section 9;
// suite-2 test 49) ------------------------------------------------------------
//
// A single Condition block is a BOOLEAN EXPRESSION: AWS combines distinct condition
// keys with logical AND, and multiple values listed for the SAME key with logical
// OR (for a single-valued context key). The analyzer must preserve that structure
// and never simplify it (e.g. a Principal "*" scoped by aws:SourceVpce:[A,B] AND
// aws:PrincipalTag/environment:"production" is "(VPCe A OR B) AND tag==production",
// NOT "VPCe OR tag"). This is a DESCRIPTIVE helper only: it never credits a
// condition as protective or changes a finding's classification/severity.

// Network / transport SELECTOR keys (where the request comes from), as distinct
// from the principal-IDENTITY scoping keys (who the caller is - PRINCIPAL_SCOPING_KEYS
// / aws:PrincipalTag). Used only to LABEL a key's role in the composition sentence
// (test 49 asks for "network + principal-tag selectors" to both be named). Matched
// case-insensitively. Not exhaustive; an unrecognized key is labeled 'other' and the
// sentence still states the AND/OR structure faithfully.
const NETWORK_SELECTOR_KEYS = Object.freeze(new Set([
  'aws:sourcevpce', 'aws:sourcevpc', 'aws:sourceip', 'aws:vpcsourceip',
]));

// The role a condition key plays in the composition sentence: 'network' (a
// network/transport selector), 'principal' (a principal-identity scoping key), or
// 'other'. keyLower is already lowercased.
function selectorCategory(keyLower) {
  if (NETWORK_SELECTOR_KEYS.has(keyLower)) return 'network';
  if (isPrincipalScopingKey(keyLower)) return 'principal';
  return 'other';
}

// Inventory the DISTINCT condition keys across every operator in a Condition block,
// recording for each whether it lists multiple values (OR-within-values) and which
// selector category it plays. Deterministic: deduped by lowercased key, first
// occurrence's original casing kept, sorted by original key. Returns [] for an
// empty/absent/non-object condition.
function conditionKeyInventory(condition) {
  const byKey = new Map();
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return [];
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    for (const rawKey of Object.keys(inner)) {
      const keyLower = String(rawKey).toLowerCase();
      const val = inner[rawKey];
      const orValues = Array.isArray(val) && val.length > 1;
      const existing = byKey.get(keyLower);
      if (existing) {
        existing.orValues = existing.orValues || orValues;
      } else {
        byKey.set(keyLower, {
          key: String(rawKey),
          orValues,
          category: selectorCategory(keyLower),
        });
      }
    }
  }
  return [...byKey.values()].sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
}

// A human sentence describing the boolean composition of a Condition block (AND
// across distinct keys, OR within a key's value list), naming the network and
// principal-identity selectors distinctly so the reader cannot collapse them into a
// single OR. Returns '' (no clause) unless the composition is non-trivial - i.e.
// there are at least two distinct keys OR at least one key lists multiple OR-ed
// values - so single-key conditions do not gain an awkward "1 key ANDed" clause.
// Purely descriptive; asserts nothing about whether a runtime request matches.
function describeConditionComposition(condition) {
  const entries = conditionKeyInventory(condition);
  if (entries.length === 0) return '';
  const nonTrivial = entries.length >= 2 || entries.some((e) => e.orValues);
  if (!nonTrivial) return '';
  const keyList = entries.map((e) => e.key);
  const orKeys = entries.filter((e) => e.orValues).map((e) => e.key);
  const networkKeys = entries.filter((e) => e.category === 'network').map((e) => e.key);
  const principalKeys = entries.filter((e) => e.category === 'principal').map((e) => e.key);
  let s =
    ` This statement's Condition is a boolean expression, not a checklist of ` +
    `alternatives: AWS combines the ${entries.length} distinct condition ` +
    `key${entries.length === 1 ? '' : 's'} (${keyList.join(', ')}) with logical AND, ` +
    `so EVERY one must be satisfied together`;
  if (orKeys.length > 0) {
    s +=
      `, while the multiple values listed for ${orKeys.length === 1 ? 'the key' : 'the keys'} ` +
      `${orKeys.join(', ')} are alternatives combined with logical OR (any one value matches)`;
  }
  s += '.';
  if (networkKeys.length > 0 && principalKeys.length > 0) {
    s +=
      ` Here a network selector (${networkKeys.join(', ')}) and a principal-identity ` +
      `selector (${principalKeys.join(', ')}) are BOTH required together (AND) - the broad ` +
      `principal syntax is constrained by the network selector AND the principal-tag ` +
      `selector, and this must NOT be simplified to ` +
      `"${[...networkKeys, ...principalKeys].join(' OR ')}".`;
  }
  return s;
}

// --- Confused-deputy source-binding analysis (IAM-1203) ----------------------
//
// When a resource policy grants an AWS SERVICE principal (events.amazonaws.com,
// cloudtrail.amazonaws.com, ...) access to the attached resource, AWS authorizes
// the SERVICE, not the actor who configured the calling service. Without a source
// binding the service can be induced to act on this resource on behalf of an actor
// the policy never intended - the cross-service confused-deputy problem. The AWS
// mitigation is one of the source condition keys, compared with a POSITIVE
// operator (resource-policy-semantics.md section 4):
//   aws:SourceArn      (ArnEquals / ArnLike)   - a specific source resource
//   aws:SourceAccount  (StringEquals)          - a specific source account
//   aws:SourceOrgID / aws:SourceOrgPaths       - a specific org / org path
// This mirrors the trust-family confused-deputy logic (trust.js), applied to a
// service principal on a resource policy.

// Positive string/ARN match operators that can PIN a source-binding value. MUST
// mirror trust.js / conditions.js POSITIVE_STRING_MATCH_OPERATORS: a Date/Numeric/
// Bool/negated operator on a source key does NOT bind the source, so it must never
// be credited as a confused-deputy constraint.
const POSITIVE_MATCH_OPERATORS = Object.freeze(new Set([
  'stringequals', 'stringequalsignorecase', 'stringlike', 'arnequals', 'arnlike',
]));

// The account (12-digit) a source-binding value pins, or null: a bare account id,
// or the account segment (ARN field 4) of a SourceArn value. Partition-agnostic
// (test 47). Used both to decide a binding is concrete and to compare SourceArn's
// account against SourceAccount for the mismatch case (test 53).
function accountFromSourceValue(value) {
  const s = String(value).trim();
  if (/^\d{12}$/.test(s)) return s;
  const arn = parseArn(s);
  if (arn && /^\d{12}$/.test(String(arn.account))) return arn.account;
  return null;
}

// A source-binding VALUE that pins nothing (a bare "*", empty, or an ARN whose
// account AND resource segments are both pure wildcards - arn:aws:*:*:*:*). Such a
// value lets every source through, so it is NOT a real confused-deputy binding and
// must not be credited (mirrors the trust-family "value must narrow" rule).
function isMatchAllSourceValue(value) {
  const s = String(value).trim();
  if (s === '' || s === '*') return true;
  if (/^arn:/i.test(s)) {
    const segs = s.split(':');
    const account = segs.length > 4 ? segs[4] : '';
    const resource = segs.length > 5 ? segs.slice(5).join(':') : '';
    const accountGlob = account === '' || /^[*?]+$/.test(account);
    const resourceGlob = resource === '' || /^[*?/:]+$/.test(resource);
    if (accountGlob && resourceGlob) return true;
  }
  return false;
}

function toSourceValueList(value) {
  if (Array.isArray(value)) {
    return value
      .filter((v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')
      .map((v) => String(v));
  }
  if (value === null || value === undefined) return [];
  return [String(value)];
}

// The single account pinned by a list of source values, or null when the list is
// empty, contains an unpinnable value, or pins more than one account (ambiguous ->
// no mismatch determination on that axis; never guess).
function commonSourceAccount(values) {
  if (values.length === 0) return null;
  const accts = values.map(accountFromSourceValue);
  if (accts.some((a) => a === null)) return null;
  const set = new Set(accts);
  return set.size === 1 ? [...set][0] : null;
}

// The DEDUPED set (as an ordered array) of every RESOLVABLE 12-digit account pinned
// by a list of source values. Unlike commonSourceAccount(), a multi-account value
// list yields the full set instead of collapsing to null, and unpinnable values
// (bare "*", account-less ARNs) are simply omitted rather than poisoning the result.
// Used to detect a SourceArn-vs-SourceAccount mismatch across a SET of source
// accounts, not only a single common one (a multi-account SourceArn whose accounts
// ALL disagree with SourceAccount is still an internally inconsistent binding).
function sourceAccountSet(values) {
  const out = [];
  for (const v of values) {
    const a = accountFromSourceValue(v);
    if (a !== null && !out.includes(a)) out.push(a);
  }
  return out;
}

// Analyze the source-binding condition keys on a statement that grants a service
// principal. Only a POSITIVE, NON-negated, NON-bypassable operator whose value
// space actually narrows counts as a binding; a negated/...IfExists/ForAllValues
// qualifier is trivially evaded (or is an exclusion) and is recorded in
// bypassedKeys so the exposure finding can name why a would-be binding does not
// count. IAM combines a key's multiple values with OR, so a co-listed match-all
// value defeats the whole binding (.every, matching the trust family).
function sourceBindingAnalysis(condition) {
  const out = {
    sourceArn: { bound: false, account: null, accounts: [] },
    sourceAccount: { bound: false, account: null, accounts: [] },
    sourceOrg: false,
    boundKeys: [],
    bypassedKeys: [],
  };
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return out;
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    const { base } = parseOperator(op);
    const negated = NEGATED_OPERATORS.has(base);
    const positive = POSITIVE_MATCH_OPERATORS.has(base);
    // A ...IfExists suffix or a ForAllValues: set qualifier PASSES when the key is
    // absent, so any binding it carries is trivially bypassed by omitting the key.
    const lowerOp = String(op).toLowerCase();
    const bypassable = lowerOp.includes('ifexists') || lowerOp.startsWith('forallvalues:');
    for (const rawKey of Object.keys(inner)) {
      const key = String(rawKey).toLowerCase();
      const isSourceKey =
        key === 'aws:sourcearn' || key === 'aws:sourceaccount' ||
        key === 'aws:sourceorgid' || key === 'aws:sourceorgpaths';
      if (!isSourceKey) continue;
      const values = toSourceValueList(inner[rawKey]);
      const binds = positive && !negated && !bypassable &&
        values.length > 0 && values.every((v) => !isMatchAllSourceValue(v));
      if (!binds) {
        out.bypassedKeys.push(rawKey);
        continue;
      }
      out.boundKeys.push(rawKey);
      if (key === 'aws:sourcearn') {
        out.sourceArn.bound = true;
        out.sourceArn.account = commonSourceAccount(values);
        for (const a of sourceAccountSet(values)) {
          if (!out.sourceArn.accounts.includes(a)) out.sourceArn.accounts.push(a);
        }
      } else if (key === 'aws:sourceaccount') {
        out.sourceAccount.bound = true;
        out.sourceAccount.account = commonSourceAccount(values);
        // Mirror the SourceArn side: track the full RESOLVABLE account SET (not only
        // the single common value, which commonSourceAccount() collapses to null for
        // a multi-valued key). This makes the SourceArn-vs-SourceAccount mismatch
        // check SYMMETRIC - a multi-account aws:SourceAccount whose every value
        // disagrees with the SourceArn account is still internally inconsistent and
        // must not be mis-credited as a clean source-bound control.
        for (const a of sourceAccountSet(values)) {
          if (!out.sourceAccount.accounts.includes(a)) out.sourceAccount.accounts.push(a);
        }
      } else {
        out.sourceOrg = true;
      }
    }
  }
  out.boundKeys.sort();
  out.bypassedKeys.sort();
  return out;
}

// Whether the policy contains a Deny whose ONLY gate is aws:SecureTransport - the
// transport-vs-identity crux of test 28. Used to ANNOTATE a public-access finding
// (the transport Deny does NOT neutralize it), never to suppress the finding.
function hasTransportOnlyDeny(model) {
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  return statements.some(
    (s) => s && s.effect === 'Deny' && isTransportOnlyCondition(s.condition),
  );
}

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

// Sub-kind of a named AWS principal entry, for wording that never conflates an IAM
// user, an IAM role, an assumed-role session, a federated-user session, a bare
// account, or an account-root principal (advanced invariant 5; tests 32/33). Reads
// the ARN's service + resource segment; partition-agnostic (test 47). An
// assumed-role-session ARN is identified as exactly one session and is NEVER
// rewritten to the role ARN.
function principalSubKind(entry) {
  const type = entry && typeof entry === 'object' ? String(entry.type) : '';
  if (type === 'aws-account') return 'account';
  if (type === 'aws-root') return 'account-root';
  const arn = parseArn(entry && entry.value != null ? String(entry.value) : '');
  const svc = arn ? String(arn.service).toLowerCase() : '';
  const res = arn ? String(arn.resource) : '';
  if (svc === 'sts' && /^assumed-role\//i.test(res)) return 'role-session';
  if (svc === 'sts' && /^federated-user\//i.test(res)) return 'federated-user-session';
  if (svc === 'iam' && /^user\//i.test(res)) return 'user';
  if (svc === 'iam' && /^role\//i.test(res)) return 'role';
  return 'principal';
}

// Human labels for each principal sub-kind (inert display evidence).
const SUBKIND_LABELS = Object.freeze({
  user: 'IAM user',
  role: 'IAM role',
  'role-session': 'assumed-role session (one exact session, not the underlying role)',
  'federated-user-session': 'federated-user session (one exact session)',
  account: 'AWS account (the account and its administrators, not the root user only)',
  'account-root': 'AWS account principal (the account and its administrators, not the root user only)',
  principal: 'AWS principal',
});

// --- Fail-closed unmodeled / invalid resource principals (IAM-1208 fix 4) ------
//
// A resource-policy Principal type that the resource evaluator does not model a
// finding for must never be SILENTLY DROPPED - zero findings would read as
// "nothing here is risky / the resource is safe", exactly the fail-open mistake
// the threat model forbids (T8; resource-policy-semantics.md 3.10 "the analyzer
// does not guess", 10.8 "unsupported != safe"). Two kinds fall here, both surfaced
// fail-closed, mirroring the trust family's "fail closed toward surfacing"
// (trust.js TRUST-INVALID-PRINCIPAL):
//   - canonical-user: a recognized S3 CanonicalUser principal (section 3.8). It
//     is a real principal type, but this analyzer does not model canonical-user
//     grants, so its reach is UNKNOWN - recognized-but-unmodeled, surfaced (not
//     dropped) so the reader knows a grant exists the analysis did not resolve.
//   - aws-principal-arn-wildcard / service-wildcard / federated-wildcard: an
//     INVALID Principal element - a partial "*"/"?" wildcard the Principal element
//     cannot use to match multiple principals/services/providers (section 3.3-3.7;
//     suite-2 test 48 / suite-3 tests 81-83). AWS rejects such a policy at save
//     time; the granted set is UNDETERMINED and it must be read as neither a
//     specific grant nor a broad one.
// Deterministic order (sorted) so a statement naming several of these emits its
// findings in a stable sequence.
const FAIL_CLOSED_PRINCIPAL_TYPES = Object.freeze([
  'aws-principal-arn-wildcard',
  'canonical-user',
  'federated-wildcard',
  'service-wildcard',
]);

const FAIL_CLOSED_PRINCIPAL_META = Object.freeze({
  'canonical-user': {
    severity: 'medium',
    title: 'Resource grant to a CanonicalUser principal (recognized but unmodeled - fail closed)',
    why: (who, serviceLabel, acts) =>
      `The resource policy grants a CanonicalUser principal (${who}) permission to ` +
      `${acts} on this ${serviceLabel}. A CanonicalUser id is a recognized Amazon ` +
      'S3 account-principal form, but this analyzer does NOT model canonical-user ' +
      'grants, so WHO the id resolves to and how far the grant reaches are UNKNOWN ' +
      'from this document. It is surfaced fail-closed rather than dropped: the ' +
      'absence of a modeled finding does NOT mean the grant is safe (unsupported ' +
      '!= safe), and the CanonicalUser grant is never silently ignored.',
    remediation:
      'Prefer an explicit AWS account or IAM principal (e.g. Principal { "AWS": ' +
      '"arn:aws:iam::<account-id>:root" }) over a raw CanonicalUser id so the grant ' +
      'is auditable and this analyzer (and your reviewers) can resolve who it ' +
      'reaches. If the CanonicalUser form is required, confirm out-of-band exactly ' +
      'which account/identity the canonical id belongs to and that it is intended ' +
      'to have this access.',
  },
  'aws-principal-arn-wildcard': {
    severity: 'high',
    title: 'Invalid wildcard Principal ARN on a resource policy (fail closed)',
    why: (who, serviceLabel, acts) =>
      `The resource policy names an AWS Principal ARN that uses a partial "*"/"?" ` +
      `wildcard to denote multiple principals (${who}) while granting ${acts} on ` +
      `this ${serviceLabel}. This is NOT a valid IAM Principal element: a principal ` +
      'ARN cannot use a partial wildcard to match multiple user/role principals ' +
      '(AWS rejects such a policy at save time), and the standalone Principal "*" is ' +
      'the ONLY wildcard the element accepts. The granted set is therefore ' +
      'UNDETERMINED from this document - it is neither a single specific principal ' +
      'nor trust/access for "every principal the pattern appears to match" - so the ' +
      'statement is surfaced fail-closed rather than expanded or dropped.',
    remediation:
      'A principal-ARN wildcard is invalid in the Principal element. Name the exact ' +
      'account/role/user ARN that should have this access. To scope a SET of ' +
      'principals matching a pattern, use Principal "*" together with an ' +
      'aws:PrincipalArn condition (e.g. ArnLike aws:PrincipalArn ' +
      'arn:aws:iam::<account-id>:role/app/*) - the wildcard is valid in that ' +
      'condition value, not in the Principal element itself.',
  },
  'service-wildcard': {
    severity: 'high',
    title: 'Invalid wildcard Service principal on a resource policy (fail closed)',
    why: (who, serviceLabel, acts) =>
      `The resource policy names a Service principal that contains a partial ` +
      `"*"/"?" wildcard (${who}) while granting ${acts} on this ${serviceLabel}. ` +
      'This is NOT a valid Principal element: an AWS Service principal is an EXACT ' +
      'service identifier (e.g. events.amazonaws.com) and the Principal element does ' +
      'not wildcard-match service names, so a member carrying a wildcard matches NO ' +
      'service and grants no service relationship. The granted set is UNDETERMINED, ' +
      'so the statement is surfaced fail-closed rather than read as a normal, ' +
      'complete service grant.',
    remediation:
      'A wildcard is invalid in a Service principal. Name each exact service ' +
      'identifier you intend to grant (e.g. events.amazonaws.com, ' +
      's3.amazonaws.com), one per member; the Service principal element does not ' +
      'support "*"/"?" matching. Add a confused-deputy source binding ' +
      '(aws:SourceArn / aws:SourceAccount) for each service that needs access.',
  },
  'federated-wildcard': {
    severity: 'high',
    title: 'Invalid wildcard Federated principal on a resource policy (fail closed)',
    why: (who, serviceLabel, acts) =>
      `The resource policy names a Federated principal that contains a partial ` +
      `"*"/"?" wildcard (${who}) while granting ${acts} on this ${serviceLabel}. ` +
      'This is NOT a valid Principal element: a Federated principal is a SPECIFIC ' +
      'identity-provider ARN (an IAM OIDC/SAML provider) or a built-in OIDC ' +
      'hostname, and the Principal element does not wildcard-match provider ARNs, so ' +
      'a member carrying a wildcard matches NO provider and establishes no ' +
      'relationship. The granted set is UNDETERMINED, so the statement is surfaced ' +
      'fail-closed rather than read as a complete federated grant. (AWS also treats ' +
      'OIDC/SAML Federated principals as valid only in role-trust policies, not on ' +
      'other resource-based policy types.)',
    remediation:
      'A wildcard is invalid in a Federated principal. Name the exact identity-' +
      'provider ARN you intend to grant (e.g. arn:aws:iam::<account-id>:oidc-' +
      'provider/<provider-host>); the Federated principal element does not support ' +
      '"*"/"?" matching. Note that OIDC/SAML federated principals belong in a role ' +
      'trust policy, not most resource policies.',
  },
});

// --- S3 bucket-vs-object action/resource typing (IAM-1204; test 50 in the
// resource context) -----------------------------------------------------------
//
// S3 object-level actions (s3:GetObject, s3:PutObject, ...) require an OBJECT-scoped
// resource (arn:aws:s3:::bucket/key or .../*); a bucket-only ARN does not identify
// objects (resource-policy-semantics.md section 2.1). A resource policy granting an
// object action on a bucket-only ARN is an action/resource-type mismatch, NOT
// confirmed object access. Curated set of common object actions (lowercased action
// name after the s3: prefix). A wildcarded action (s3:*, s3:Get*) is intentionally
// NOT classified - the analyzer never guesses a mismatch from a wildcard.
const S3_OBJECT_ACTIONS = Object.freeze(new Set([
  'getobject', 'putobject', 'deleteobject', 'getobjectacl', 'putobjectacl',
  'getobjectversion', 'getobjectversionacl', 'putobjectversionacl',
  'deleteobjectversion', 'getobjecttagging', 'putobjecttagging',
  'deleteobjecttagging', 'getobjectversiontagging', 'putobjectversiontagging',
  'deleteobjectversiontagging', 'restoreobject', 'getobjecttorrent',
  'getobjectretention', 'putobjectretention', 'getobjectlegalhold',
  'putobjectlegalhold', 'bypassgovernanceretention', 'getobjectattributes',
  'getobjectversionattributes', 'abortmultipartupload', 'listmultipartuploadparts',
  'replicateobject',
]));

function isS3ObjectAction(action) {
  const m = /^s3:(.+)$/.exec(String(action).toLowerCase());
  return m ? S3_OBJECT_ACTIONS.has(m[1]) : false;
}

// Scope of an S3 resource ARN string: 'object' (a key or /* follows the bucket),
// 'bucket' (bucket-only, no '/'), or null for a non-S3 / non-ARN string.
function s3ResourceScope(resourceStr) {
  const arn = parseArn(resourceStr);
  if (!arn || String(arn.service).toLowerCase() !== 's3') return null;
  return String(arn.resource).includes('/') ? 'object' : 'bucket';
}

// Human summary of a set of principal entries (inert; ARNs/ids embedded verbatim
// as data, only ever rendered via textContent downstream - never markup, T1).
function summarizeEntries(entries) {
  const vals = entries.map((e) => String(e.value)).filter((v) => v.length > 0);
  if (vals.length === 0) return 'the named principal(s)';
  if (vals.length <= 3) return vals.join(', ');
  return `${vals.slice(0, 3).join(', ')} (+${vals.length - 3} more)`;
}

// Build one resource finding in the canonical finding shape (architecture.md). The
// resource evaluator emits findings from the RESOURCE's perspective, so `resources`
// is the attached-resource scope this statement grants on, and every finding
// carries RESOURCE_LIMIT (potential blast radius, not effective access).
function makeResourceFinding(stmt, entries, opts) {
  const actions = Array.isArray(stmt.actions) ? stmt.actions.slice() : [];
  const resources = Array.isArray(stmt.resources) && stmt.resources.length > 0
    ? stmt.resources.slice()
    : (opts.attachedArn ? [opts.attachedArn] : ['(attached resource)']);
  const sid = (typeof stmt.sid === 'string' && stmt.sid.length > 0)
    ? stmt.sid
    : `(index ${stmt.index})`;
  const principalEvidence = entries.map((e) => Object.freeze(
    e.key !== undefined
      ? { type: e.type, value: String(e.value), key: e.key, index: e.index }
      : { type: e.type, value: String(e.value) },
  ));
  const evidence = [Object.freeze({
    statementIndex: stmt.index,
    statementSid: sid,
    role: 'resource',
    actions: actions.slice(),
    resources: resources.slice(),
    condition: stmt.condition === undefined ? null : stmt.condition,
    // The typed principals this statement grants access to (WHO can act on the
    // resource), each identified distinctly and never collapsed (section 3).
    principals: principalEvidence,
    note: null,
  })];
  return {
    id: opts.id,
    severity: opts.severity,
    title: opts.title,
    statementSid: sid,
    statementIndex: stmt.index,
    actions,
    resources,
    conditions: stmt.condition === undefined ? null : stmt.condition,
    // A resource-policy grant is literally in the policy (policyEvidence high);
    // reaching/using it depends on the caller + other layers not supplied here
    // (pathExploitability capped below - IAM-104 split confidence). An
    // action/resource-type mismatch is the exception: the object action does NOT
    // confirm object access, so its policyEvidence is explicitly lowered (test 50).
    policyEvidence: opts.policyEvidence || 'high',
    pathExploitability: opts.pathExploitability || 'medium',
    why: opts.why,
    limit: RESOURCE_LIMIT,
    remediation: opts.remediation,
    ruleVersion: RESOURCE_RULE_VERSION,
    docRef: opts.docRef,
    // Resource enrichment (analogous to the trust block on trust findings): the
    // attached resource + the principals this grant reaches. targetAccess is
    // ALWAYS the direct grant only; effective access is never inferred.
    resource: Object.freeze({
      service: opts.service || null,
      attachedArn: opts.attachedArn || null,
      principalTypes: [...new Set(entries.map((e) => e.type))].sort(),
      anonymous: entries.some((e) => e.type === 'anonymous'),
      // Principal-scoping condition keys narrowing an anonymous "*" grant to
      // authenticated principals; empty for a genuinely-public/unconditioned grant
      // and for non-anonymous findings. A non-empty value means the "*" is NARROWED
      // (test 85) and no anonymous/"anyone" reach may be asserted downstream.
      principalScopedBy: Object.freeze(Array.isArray(opts.principalScopedBy) ? opts.principalScopedBy.slice() : []),
      transportOnlyDeny: !!opts.transportOnlyDeny,
      // IAM-1203: for a service-principal confused-deputy finding, the source-binding
      // state read from the statement (which keys bind the calling service, which
      // were present but ineffective, and whether SourceArn/SourceAccount disagree).
      // null on every non-confused-deputy finding.
      sourceBinding: opts.sourceBinding
        ? Object.freeze({
            state: opts.sourceBinding.state,
            boundKeys: Object.freeze(opts.sourceBinding.boundKeys.slice()),
            bypassedKeys: Object.freeze(opts.sourceBinding.bypassedKeys.slice()),
            sourceArnAccount: opts.sourceBinding.sourceArnAccount,
            sourceAccount: opts.sourceBinding.sourceAccount,
          })
        : null,
    }),
    evidence,
    contributingStatements: [Object.freeze({
      statementIndex: stmt.index,
      statementSid: sid,
      actions: actions.slice(),
    })],
  };
}

// Principal-centric resource findings (IAM-1202 + IAM-1203): enumerate WHO can act
// on the attached resource and emit
//   - PUBLIC-ACCESS            for an anonymous ("*" / {AWS:"*"}) Allow principal,
//   - RESOURCE-CROSS-ACCOUNT   for an external AWS account/root/principal-ARN whose
//     account differs from (or cannot be pinned to) the resource's own account, and
//   - RESOURCE-CONFUSED-DEPUTY for a SERVICE principal (IAM-1203): a confused-deputy
//     exposure when unbound, a negative control when properly source-bound, or an
//     internally-inconsistent warning when SourceArn/SourceAccount disagree,
//   - RESOURCE-SAME-ACCOUNT-GRANT for a named principal in the resource's OWN account
//     (IAM-1204): the direct same-account resource-vs-identity grant, and
//   - RESOURCE-ACTION-RESOURCE-MISMATCH for an S3 object action scoped to a
//     bucket-only ARN (IAM-1204).
// Deterministic: statement order, then principal-entry order.
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
      const { scopingKeys, expansionKeys } = principalScopingAnalysis(stmt.condition);
      // A NEGATED principal-scoping operator (StringNotEquals aws:PrincipalOrgID,
      // ArnNotEquals aws:PrincipalArn, Null-absent, ...) is an EXCLUSION/expansion,
      // NOT a narrowing, and dominates: it must never downgrade the "*" grant to
      // "narrowed" (adversarial-critic IAM-1202 iteration 4). When such a key is
      // present the grant stays PUBLIC-ACCESS/critical and no key is credited as
      // scoping. Only a POSITIVE principal-scoping key (and no expansion) narrows.
      const principalExpanded = expansionKeys.length > 0;
      const scopeKeys = principalExpanded ? [] : scopingKeys;
      const principalScoped = scopeKeys.length > 0;
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
        // whether the Allow is public (bare "*") or already principal-scoped.
        why += principalScoped
          ? ' A same-policy Deny gated only on aws:SecureTransport=false is a ' +
            'TRANSPORT constraint (it forces HTTPS) and constrains transport, not WHO ' +
            'may act; it neither widens nor narrows the principal-scoping condition ' +
            'above.'
          : ' A same-policy Deny gated only on aws:SecureTransport=false is a ' +
            'TRANSPORT constraint (it forces HTTPS); it does NOT make this public ' +
            'grant private - the resource stays publicly accessible over TLS, so the ' +
            'Deny must not be read as suppressing the public Allow.';
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
        docRef: isS3 ? DOC_S3_BPA : DOC_PRINCIPAL,
        // A grant is literally in the policy; a same-policy transport Deny does not
        // lower it, but reachability still depends on the condition / BPA / other
        // layers, so a conditioned Allow caps path-exploitability at medium.
        pathExploitability: conditioned ? 'medium' : 'high',
        service,
        attachedArn,
        transportOnlyDeny,
        // The principal-scoping condition keys that narrow this "*" grant to
        // authenticated principals (empty for a genuinely-public grant). Carried on
        // the resource enrichment so the graph/render never assert anonymous reach.
        principalScopedBy: scopeKeys,
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
        namedEntries = namedEntries.filter((e) => !acctEntries.includes(e));
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
    const grantEntries = namedEntries.filter((e) => !sameAccountEntries.includes(e));

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
      const mismatch = binding.sourceArn.bound && binding.sourceAccount.bound &&
        arnAccounts.length > 0 && acctAccounts.length > 0 &&
        arnAccounts.every((a) => !acctAccounts.includes(a));
      const anyBinding = binding.sourceArn.bound || binding.sourceAccount.bound || binding.sourceOrg;
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

  // Principal-centric findings for the validated, accepted context.
  const findings = resourceFindings(model, parsed);

  const note =
    'Resource-based policy accepted and routed to the resource evaluator (never ' +
    'the identity rules). The attached-resource context is recorded, the principals ' +
    'named are enumerated, and public-access + external-cross-account + same-account ' +
    'direct grants + service-principal confused-deputy grants are reported, plus S3 ' +
    'object-action / bucket-resource type mismatches, KMS key-policy account ' +
    'delegation (Resource:* = the attached key only), and resource-policy condition ' +
    'composition (AND across distinct keys, OR within a key\'s values). The remaining ' +
    'service-specific resource rules (the Deny + NotPrincipal hazard) are not yet ' +
    'applied in this release, so this analysis is ' +
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
