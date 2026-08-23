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

// The sts: action set that makes a statement a TRUST statement (compared
// case-insensitively). Mirrors docs/trust-policy-semantics.md section 3 and the
// TRUST_ACTIONS set family.js uses to detect the role-trust shape.
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

// The trust finding ids this module can emit. Kept as an exported, frozen set so
// tests (evidence.test.js catalog, etc.) can recognize trust findings without
// hard-coding the strings, and so the ids stay DISTINCT from the identity
// RULE_IDS / ESCALATION_IDS (fixture-matrix enumerates only those two).
export const TRUST_IDS = Object.freeze([
  'TRUST-PUBLIC',
  'TRUST-ORG-EXPANSION',
  'TRUST-CROSS-ACCOUNT',
  'TRUST-FEDERATED',
  'TRUST-SESSION-CONTROL',
  'TRUST-SERVICE',
]);

const RULE_VERSION = '1';

// Every trust finding carries this limitation verbatim. It states the
// load-bearing invariant (target-role permissions unknown / out of scope) AND
// the capability-not-effective caveat ("not effective access") that the rest of
// the engine uses on every finding, so a trust finding can never be read as an
// effective-permissions or inherited-power claim.
const TRUST_LIMIT =
  'This classifies the trust RELATIONSHIP from the policy text - who may assume ' +
  'the role - not effective access. A role trust policy never conveys the ' +
  "assumed role's permissions: the target role's actual privileges are OUT OF " +
  'SCOPE and remain UNKNOWN from this document. AWS also evaluates the caller ' +
  'identity, session policies, and boundaries, none of which are present here, ' +
  'so no one inherits the role\'s power merely by being trusted to assume it.';

const DOC_PRINCIPAL =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html';
const DOC_CONDITION_KEYS =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html';
const DOC_CONFUSED_DEPUTY =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html';
const DOC_OIDC =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html';

// Negated string/arn/ip operators: on an otherwise-constraining key they invert
// polarity to an EXPANSION ("everything except the listed values"). Mirrors
// conditions.js NEGATED_OPERATORS (kept local so trust.js stays dependency-free
// and cannot create an import cycle with conditions.js -> family.js).
const NEGATED_OPERATORS = new Set([
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
const POSITIVE_STRING_MATCH_OPERATORS = new Set([
  'stringequals', 'stringequalsignorecase', 'stringlike',
  'arnequals', 'arnlike',
]);

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
function isAllGlobOrEmpty(v) {
  const s = String(v);
  return s === '' || /^[*?]+$/.test(s);
}

function hasGlob(s) {
  return s.includes('*') || s.includes('?');
}

// An account-id key (aws:SourceAccount / aws:PrincipalAccount) is a full 12-digit
// number; any wildcard leaves the account unpinned, so a globbed value does not
// narrow. An org-id key (aws:PrincipalOrgID) is o-<body>; a wildcard in the body
// ("o-*") matches every organization, so it does not narrow either. Only a
// complete literal value narrows these keys.
function accountOrOrgValueNarrows(value) {
  const s = String(value);
  if (s === '') return false;
  return !hasGlob(s);
}

// Whether an ARN's account segment (field index 4:
// arn:partition:service:region:ACCOUNT:resource) is PINNED to a single concrete
// account id. "arn:aws:iam::123456789012:role/app-*" pins account 123456789012;
// "arn:aws:iam::*:role/*" and "arn:aws:*:*:*:*" pin nothing (span every account).
// Shared by arnValueNarrows() (a condition-value narrowing test) and
// principalValueIsBroad() (a Principal-breadth test) so both agree on what
// "bounded to one account" means.
function arnAccountPinned(s) {
  const segs = String(s).split(':');
  const account = segs.length > 4 ? segs[4] : '';
  return account !== '' && !hasGlob(account);
}

// Common AWS ARN resource-TYPE keywords. In an ARN resource of the form
// "<type>/<id>" or "<type>:<id>", the LEADING token is a resource-type CATEGORY
// (role, secret, function, trail, ...), not a specific resource. A value whose
// only surviving literal is such a category keyword - e.g. arn:aws:iam::*:role/*
// (every role in every account) or arn:aws:secretsmanager:*:*:secret:* (every
// secret in every account) - bounds NOTHING (not which account, not which
// resource) and is therefore NOT a confused-deputy scope. Only a concrete
// resource IDENTIFIER narrows. Kept lowercase; matched case-insensitively.
const ARN_RESOURCE_TYPE_KEYWORDS = new Set([
  'role', 'user', 'group', 'policy', 'instance-profile', 'mfa',
  'server-certificate', 'saml-provider', 'oidc-provider', 'assumed-role',
  'federated-user', 'secret', 'function', 'layer', 'trail', 'key', 'alias',
  'topic', 'queue', 'table', 'instance', 'volume', 'snapshot',
  'security-group', 'subnet', 'vpc', 'stream', 'parameter', 'stack',
  'cluster', 'db', 'rule', 'log-group', 'event-bus', 'pipeline', 'project',
  'repository', 'distribution', 'certificate', 'domain', 'application',
]);

// An ARN key (aws:SourceArn / aws:PrincipalArn) narrows only when a globbed value
// still pins an identifying component. The account segment is the primary
// identifier; if it is a concrete id the ARN narrows. If the account is
// wildcarded/empty, the ARN narrows only when the resource part still pins a
// concrete resource IDENTIFIER (e.g. arn:aws:s3:::specific-bucket). It does NOT
// narrow when the only surviving literal is a bare resource-TYPE keyword before
// the wildcard: arn:aws:iam::*:role/* and arn:aws:secretsmanager:*:*:secret:*
// name a CATEGORY across every account (adversarial-critic IAM-804 iteration 2:
// the resource-literal fallback credited these as confused-deputy constraints and
// slammed a whole-account external trust high->low, stamping a vacuous condition
// into the evidence as a real mitigation - a wrong-provenance under-claim, the
// same class already fixed for pure wildcards). "arn:aws:*:*:*:*" and
// "arn:aws:iam::*:*" pin nothing identifying either, so none of these narrow.
function arnValueNarrows(value) {
  const s = String(value);
  if (s === '') return false;
  if (!hasGlob(s)) return true; // a fully literal ARN narrows
  if (arnAccountPinned(s)) return true;
  const segs = s.split(':');
  const resource = segs.length > 5 ? segs.slice(5).join(':') : '';
  // Tokenize the resource on path ('/') and sub-resource (':') separators, and
  // require a concrete resource IDENTIFIER token: one that carries a literal
  // (survives wildcard stripping) and is NOT merely a leading resource-TYPE
  // keyword. arn:aws:iam::*:role/* -> ['role','*']: 'role' is a category keyword
  // in first position, '*' is pure wildcard -> nothing concrete -> does not
  // narrow. arn:aws:s3:::specific-bucket/* -> ['specific-bucket','*']:
  // 'specific-bucket' is a concrete id -> narrows.
  const tokens = resource.split(/[/:]/);
  return tokens.some((t, i) => {
    const literal = t.replace(/[*?]/g, '').trim();
    if (literal.length === 0) return false; // a pure-wildcard token pins nothing
    // A bare resource-TYPE keyword in the leading position is a category, not an
    // identifier; it only narrows if a later concrete token accompanies it.
    if (i === 0 && ARN_RESOURCE_TYPE_KEYWORDS.has(literal.toLowerCase())) return false;
    return true;
  });
}

// Whether the NAMED Principal already pins this trust to specific AWS account(s),
// so a wildcard in a condition ARN's ACCOUNT segment (field 4) contributes NO
// breadth: AWS evaluates Principal AND Condition, so the account is fixed by the
// Principal, not by the condition (adversarial iteration-2 findings 3/4). Only an
// account/root Principal or an account-PINNED principal-ARN pins the account; an
// anonymous "*" or an org-wide (non-account-pinned) principal ARN pins nothing.
// Requires EVERY named principal to be account-bounded (`.every`): if any is
// public/org-wide, the account is not universally pinned and a condition account
// wildcard still widens (conservative - never under-claims). Takes a classified
// principal (classifyPrincipals output).
function principalPinsAccount(principals) {
  if (!principals || principals.anonymous) return false;
  const ext = principals.entries.filter((e) =>
    e.type === 'aws-root' || e.type === 'aws-account' || e.type === 'aws-principal-arn');
  if (ext.length === 0) return false;
  return ext.every((e) => {
    if (e.type === 'aws-root' || e.type === 'aws-account') return true;
    return arnAccountPinned(e.value);
  });
}

// Breadth of a positive aws:PrincipalArn scoping VALUE, INTERSECTED with the named
// Principal (AWS evaluates Principal AND Condition). A glob in an ARN segment the
// Principal already pins - notably the ACCOUNT (field 4) - contributes NO breadth:
// it is fixed by the Principal, not the condition. The value is BROAD only when a
// glob survives in a segment the Principal does NOT pin: the resource IDENTIFIER
// (matches a SET of principals within the account), the account when the Principal
// itself is unpinned/public, or partition/service/region (never pinned by a
// Principal). Uses hasGlob (both '*' AND '?') so a '?'-globbed resource such as
// role/admin? - which matches admin1, adminA, ... - is broad, consistent with the
// OIDC-subject fix (line ~495) and conditions.js (adversarial iteration-2
// finding 4; the pre-fix `values.some(v => v.includes('*'))` missed '?'). When the
// Principal pins the account, arn:aws:iam::*:role/deploy intersects to the single
// role arn:aws:iam::<pinned>:role/deploy - NOT broad (finding 3).
function principalArnValueIsBroad(value, principalPins) {
  const segs = String(value).split(':');
  const account = segs.length > 4 ? segs[4] : '';
  const resource = segs.length > 5 ? segs.slice(5).join(':') : '';
  const beforeAccount = segs.slice(0, 4); // arn, partition, service, region
  if (hasGlob(resource)) return true; // a globbed resource identifier -> a SET
  if (hasGlob(account) && !principalPins) return true; // account not pinned by Principal
  if (beforeAccount.some((s) => hasGlob(s))) return true; // partition/service/region glob
  return false;
}

// Dispatch the narrowing test for the trust-relevant scoping keys. Any other key
// (e.g. sts:ExternalId, an OIDC sub) narrows unless it is the empty string or a
// value made entirely of glob metacharacters ('*'/'?', e.g. "*", "?*", "*?") -
// a partial ExternalId carrying a literal still forces the caller to present a
// matching correlation value, so it stays a (weaker) confused-deputy constraint.
function valueNarrowsKey(key, value) {
  switch (key) {
    case 'aws:sourceaccount':
    case 'aws:principalaccount':
    case 'aws:principalorgid':
      return accountOrOrgValueNarrows(value);
    case 'aws:sourcearn':
    case 'aws:principalarn':
      return arnValueNarrows(value);
    default:
      return !isAllGlobOrEmpty(value);
  }
}

// An all-addresses IP/CIDR range constrains nothing (defect 2: IpAddress
// aws:SourceIp 0.0.0.0/0 - or the IPv6 equivalent - is not a real constraint).
function isAllAddressIp(v) {
  const s = String(v).trim().toLowerCase();
  return s === '*' || s === '0.0.0.0/0' || s === '0/0' ||
    s === '::/0' || s === '::0/0' || s === '::0' || s === '::';
}

function err(code, message, path) {
  return { code, message, path: path === undefined ? null : path };
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

function statementSid(stmt) {
  return typeof stmt.sid === 'string' && stmt.sid.length > 0
    ? stmt.sid
    : `(index ${stmt.index})`;
}

// A statement is a TRUST statement iff it names a Principal and every one of its
// actions is a trust action. (The family gate already guarantees the document is
// role-trust-shaped; this per-statement check keeps analysis grounded.) Exported
// so graph.js can find same-policy trust Deny statements (IAM-806) without
// re-deriving the shape test.
export function isTrustStatement(stmt) {
  if (!stmt || stmt.principal == null) return false;
  if (!Array.isArray(stmt.actions) || stmt.actions.length === 0) return false;
  return stmt.actions.every((a) => TRUST_ACTIONS.has(String(a).toLowerCase()));
}

/**
 * Classify a normalized Principal element into the typed forms of
 * docs/trust-policy-semantics.md section 2. Never throws.
 *
 * @param {object|null} principal normalized principal (model.js shape)
 * @returns {{anonymous:boolean, categories:Set<string>,
 *            entries:Array<{type:string,value:string}>, unknownTypes:Array<string>}}
 */
export function classifyPrincipals(principal) {
  const out = { anonymous: false, categories: new Set(), entries: [], unknownTypes: [] };
  if (!principal || typeof principal !== 'object') return out;
  if (principal.anyPrincipal) {
    out.anonymous = true;
    out.categories.add('anonymous');
    out.entries.push({ type: 'anonymous', value: '*' });
    return out;
  }
  const byType = principal.byType || {};
  for (const key of Object.keys(byType)) {
    const values = Array.isArray(byType[key]) ? byType[key] : [];
    if (key === 'AWS') {
      for (const v of values) add(out, awsPrincipalType(v), v);
    } else if (key === 'Service') {
      for (const v of values) add(out, 'service', v);
    } else if (key === 'Federated') {
      for (const v of values) add(out, federatedType(v), v);
    } else if (key === 'CanonicalUser') {
      for (const v of values) add(out, 'canonical-user', v);
    } else {
      out.unknownTypes.push(key);
    }
  }
  return out;
}

function add(out, type, value) {
  out.categories.add(type);
  // "*" under the AWS key is equivalent to Principal "*" - anonymous/public
  // access (trust-policy-semantics.md 2.1). Surface it on the anonymous flag so
  // it is treated as public trust, not as a specific AWS principal.
  if (type === 'anonymous') out.anonymous = true;
  out.entries.push({ type, value: String(value) });
}

// AWS principal string -> typed form. '*' is anonymous/public; a bare 12-digit
// id or a ...:root ARN delegates trust to the whole account; anything else is a
// specific user/role/session principal ARN (section 2.2-2.4).
function awsPrincipalType(v) {
  const s = String(v);
  if (s === '*') return 'anonymous';
  if (/:root$/i.test(s)) return 'aws-root';
  if (/^\d{12}$/.test(s)) return 'aws-account';
  return 'aws-principal-arn';
}

// Federated principal -> OIDC vs SAML (section 2.6/2.7). The four built-in OIDC
// providers are bare hostnames (not ARNs) and are treated as OIDC.
function federatedType(v) {
  const s = String(v).toLowerCase();
  if (s.includes('saml-provider')) return 'federated-saml';
  return 'federated-oidc';
}

// --- Condition polarity (text-only classification, never a runtime verdict) --

// Split a condition operator into its BASE operator plus the two qualifiers that
// matter for polarity: the ...IfExists suffix and the ForAllValues:/ForAnyValue:
// set prefix. The base alone is not enough to decide whether a positive match is
// an EFFECTIVE constraint, because two of these qualifiers PASS when the key is
// ABSENT from the request:
//
//   - `...IfExists`  applies only when the key IS present, so a request lacking
//     the key is not constrained by it.
//   - `ForAllValues:` is vacuously true when the key is absent, so it likewise
//     may not constrain a request that omits the key.
//
// A constraint carrying either qualifier is therefore trivially bypassed by
// omitting the key and must NEVER be credited as a real confused-deputy /
// scoping / principal / tight-subject constraint (adversarial-critic IAM-803
// iteration 2 defect 1: trust.js discarded these qualifiers and credited a
// bypassable StringEqualsIfExists / ForAllValues:StringEquals as fully effective,
// dropping a whole-account external trust high->low while the finding's own
// conditionClassification.credited was false - severity disagreeing with
// provenance). `ForAnyValue:` is NOT a bypass: it requires at least one supplied
// value to match, so it fails (does not pass) when the key is absent - it stays
// creditable. This mirrors conditions.js parseOperator + the ...IfExists /
// ForAllValues uncredit at conditions.js lines 296-300.
function parseOperatorParts(op) {
  let o = String(op).toLowerCase();
  let setOperator = null;
  if (o.startsWith('forallvalues:')) { setOperator = 'ForAllValues'; o = o.slice('forallvalues:'.length); }
  else if (o.startsWith('foranyvalue:')) { setOperator = 'ForAnyValue'; o = o.slice('foranyvalue:'.length); }
  let ifExists = false;
  if (o.endsWith('ifexists')) { ifExists = true; o = o.slice(0, -'ifexists'.length); }
  return { base: o, setOperator, ifExists };
}

function toValues(v) {
  if (Array.isArray(v)) return v.map((x) => String(x));
  if (v === null || v === undefined) return [];
  return [String(v)];
}

// Walk a statement's Condition block and derive the trust-relevant polarity
// signals. Text-only: it reports how the condition READS, never a runtime match.
function conditionSignals(condition, principals) {
  // Does the named Principal already pin the account? Used to intersect a
  // positive aws:PrincipalArn scoping value with the Principal so a wildcard the
  // Principal already pins (the account segment) does not inflate breadth.
  const pinsAccount = principalPinsAccount(principals);
  const sig = {
    orgExclusion: false, // StringNotEquals aws:PrincipalOrgID -> expansion
    orgConstraint: false, // StringEquals  aws:PrincipalOrgID -> constraint
    externalId: false, // sts:ExternalId (positive string match) -> confused-deputy constraint
    sourceArnAccount: false, // aws:SourceArn / aws:SourceAccount (positive string/arn match)
    mfa: false, // aws:MultiFactorAuthPresent true
    sourceIp: false, // aws:SourceIp (positive, non-all-addresses) -> constraint
    audConstraint: false, // OIDC/SAML audience check -> constraint
    subScope: null, // 'broad' | 'tight' | null (no OIDC/SAML subject condition)
    // Positive scoping conditions that narrow a wildcard (Principal "*")
    // principal to a bounded set (defect 3). Tracked so the public-trust branch
    // does not falsely claim anonymous/other-account principals are trusted when
    // a present condition excludes them.
    principalArnScope: null, // 'broad' | 'tight' | null (positive aws:PrincipalArn match)
    principalAccount: false, // positive aws:PrincipalAccount match (non-wildcard)
    // Would-be constraints defeated by a bypassable operator qualifier
    // (...IfExists / ForAllValues:). Tracked as "<key> (<operator>)" strings so a
    // finding that STAYS high can NAME the qualifier in its why text instead of
    // silently ignoring it (adversarial-critic IAM-803 iteration 2 defect 1).
    bypassedQualifiers: [],
  };
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return sig;

  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    const { base, setOperator, ifExists } = parseOperatorParts(op);
    const negated = NEGATED_OPERATORS.has(base);
    const positiveStringMatch = POSITIVE_STRING_MATCH_OPERATORS.has(base);
    // A ...IfExists suffix or a ForAllValues: set qualifier PASSES when the key is
    // absent from the request, so any constraint it carries is trivially bypassed
    // by omitting the key and must NOT be credited as effective. ForAnyValue: is
    // NOT a bypass (it needs a supplied value to match). Mirrors conditions.js
    // lines 296-300 so trust severity and conditionClassification.credited agree.
    const bypassable = ifExists || setOperator === 'ForAllValues';
    for (const rawKey of Object.keys(inner)) {
      const key = String(rawKey).toLowerCase();
      const values = toValues(inner[rawKey]);
      // A real value-scoping constraint requires a positive string/ARN match
      // operator AND that EVERY value actually NARROWS this key's value space
      // (key-aware: a globbed value that still matches everything - e.g.
      // arn:aws:*:*:*:*, o-*, 1*, arn:aws:iam::*:* - does not narrow).
      //
      // IAM combines the multiple values of ONE operator+key with OR, so the
      // condition constrains only when ALL of its values narrow: a single co-
      // listed match-all element (o-*, arn:aws:*:*:*:*, "*") lets every
      // principal through and makes the whole condition vacuous. Using .some
      // here would flip the constraint ON when just one element narrows even
      // though a co-listed match-all element defeats it - over-neutralizing the
      // finding and stamping a vacuous condition into the evidence as an
      // effective mitigation (wrong provenance). Mirror the .every quantifier
      // the parallel aws:SourceIp all-addresses guard already uses below
      // (adversarial-critic iteration-5 defect). An empty value list cannot
      // narrow, so it is excluded explicitly (.every is vacuously true on []).
      const scopesValue = positiveStringMatch && !bypassable && values.length > 0 &&
        values.every((v) => valueNarrowsKey(key, v));
      // Record a would-be POSITIVE constraint that a bypassable qualifier defeats,
      // so the (still-high) finding can name it. Negated/expansion operators are
      // excluded - they raise, never lower, so there is nothing to explain away.
      if (bypassable && !negated) {
        const isConstrainingKey =
          key === 'aws:principalorgid' || key === 'sts:externalid' ||
          key === 'aws:sourcearn' || key === 'aws:sourceaccount' ||
          key === 'aws:principalarn' || key === 'aws:principalaccount' ||
          key === 'aws:multifactorauthpresent' || key === 'aws:sourceip' ||
          key.endsWith(':aud') || key === 'saml:aud' ||
          key.endsWith(':sub') || key === 'saml:sub';
        if (isConstrainingKey) sig.bypassedQualifiers.push(`${rawKey} (${op})`);
      }
      if (key === 'aws:principalorgid') {
        if (negated) sig.orgExclusion = true;
        else if (scopesValue) sig.orgConstraint = true;
      } else if (key === 'sts:externalid') {
        if (scopesValue) sig.externalId = true;
      } else if (key === 'aws:sourcearn' || key === 'aws:sourceaccount') {
        if (scopesValue) sig.sourceArnAccount = true;
      } else if (key === 'aws:principalarn') {
        if (scopesValue) {
          // Breadth is the Principal-AND-Condition INTERSECTION, not the value in
          // isolation: a glob in a segment the named Principal already pins (the
          // account) adds no breadth (adversarial iteration-2 findings 3/4). Uses
          // hasGlob so a '?'-globbed resource is broad (finding 4).
          const broad = values.some((v) => principalArnValueIsBroad(v, pinsAccount));
          // A tight (exact-ARN) scope wins over a broad one if both appear.
          if (sig.principalArnScope !== 'tight') sig.principalArnScope = broad ? 'broad' : 'tight';
        }
      } else if (key === 'aws:principalaccount') {
        if (scopesValue) sig.principalAccount = true;
      } else if (key === 'aws:multifactorauthpresent') {
        if (base === 'bool' && !bypassable && values.length === 1 && values[0].toLowerCase() === 'true') sig.mfa = true;
      } else if (key === 'aws:sourceip') {
        // Only a positive IpAddress operator over non-all-addresses ranges is a
        // constraint; NotIpAddress (negated), an all-addresses range (0.0.0.0/0,
        // ::/0), and a bypassable ...IfExists/ForAllValues qualifier constrain nothing.
        if (base === 'ipaddress' && !bypassable && values.length > 0 && values.every((v) => !isAllAddressIp(v))) {
          sig.sourceIp = true;
        }
      } else if (key.endsWith(':aud') || key === 'saml:aud') {
        if (!negated && !bypassable) sig.audConstraint = true;
      } else if (key.endsWith(':sub') || key === 'saml:sub') {
        // Subject scope drives federated severity (trust-policy-semantics 4.4):
        // a value carrying a GLOB metacharacter - '*' (e.g. repo:org/*) OR the
        // single-char '?' (e.g. repo:org/myrep? or repo:org/?????????? - matches
        // many repos/workloads across an org, widening the trusted-workload set),
        // a negated operator, OR a bypassable ...IfExists/ForAllValues qualifier
        // (the tight value is trivially bypassed by omitting the sub claim) is
        // BROAD; only a specific value under a non-bypassable positive operator is
        // TIGHT. Uses hasGlob (both '*' and '?') so this severity decision AGREES
        // with conditions.js line 373 (which already tests both) - inspecting only
        // '*' made a '?'-globbed subject diverge: trust.js scored it low/tight
        // while conditions.js flagged it broad/uncredited, the exact
        // severity-vs-provenance contradiction the engine eliminates elsewhere
        // (adversarial-critic IAM-804 iteration 4 finding 1).
        const broad = negated || bypassable || values.length === 0 || values.some((v) => hasGlob(v));
        sig.subScope = broad ? 'broad' : 'tight';
      }
    }
  }
  return sig;
}

// A confused-deputy / principal-scoping CONSTRAINT that lowers a cross-account
// trust below high (trust-policy-semantics section 5 table). Only conditions
// that BOUND WHO is trusted qualify: sts:ExternalId (the canonical confused-
// deputy correlation value), aws:SourceArn/aws:SourceAccount (bound the calling
// service/resource), and a POSITIVE aws:PrincipalOrgID StringEquals (confines
// trust to org members).
//
// aws:MultiFactorAuthPresent and aws:SourceIp are deliberately NOT here
// (adversarial defect IAM-802-B): they harden the request context but do not
// narrow WHICH principal in the trusted account may assume the role - the whole
// external account is still trusted - so they must never drop a whole-account
// external trust from high to low. They are handled as defense-in-depth in the
// cross-account branch (they lower path-exploitability one band, never severity).
function hasConfusedDeputyConstraint(sig) {
  return sig.externalId || sig.sourceArnAccount || sig.orgConstraint;
}

// A positive scoping condition that narrows a wildcard Principal ("*") to a
// bounded set of principals (trust-policy-semantics 4.2 positive polarity;
// aws:PrincipalArn is an exact/prefix principal scope; aws:PrincipalOrgID
// (StringEquals) is an org-wide scope; aws:PrincipalAccount is ACCOUNT-granularity).
// When present alongside Principal "*", the trust is NOT anonymous/public: only
// principals matching the condition are trusted (defect 3). Returns null when no
// such scoping condition is present.
//
// Severity reflects the INTERSECTED breadth:
//   - aws:PrincipalOrgID StringEquals -> an organization-wide set -> broad (high).
//   - aws:PrincipalAccount -> Principal "*" + PrincipalAccount==X is whole-account
//     trust, IDENTICAL to naming account X as the Principal (account granularity
//     is exactly what a root/account Principal carries), so it is broad (high),
//     NOT a sub-account narrowing (adversarial iteration-2 finding 2). It never
//     drops to medium.
//   - a wildcarded aws:PrincipalArn -> a broad set within a scope -> broad (high).
//   - an EXACT aws:PrincipalArn -> a genuine single-principal sub-account scope ->
//     medium. This is the ONLY medium case.
// Never critical - a present condition excludes the anonymous/arbitrary principals
// a bare "*" would otherwise trust.
function publicScopeConstraint(sig) {
  const names = [];
  if (sig.orgConstraint) names.push('aws:PrincipalOrgID (StringEquals)');
  if (sig.principalArnScope) names.push('aws:PrincipalArn');
  if (sig.principalAccount) names.push('aws:PrincipalAccount');
  if (names.length === 0) return null;
  const broad = sig.orgConstraint || sig.principalAccount || sig.principalArnScope === 'broad';
  // Describe the DOMINANT (broadest) surviving scope accurately, so a whole-account
  // aws:PrincipalAccount is never mislabeled "a specific principal".
  const breadthDesc = sig.orgConstraint
    ? 'an organization-wide set of principals'
    : sig.principalAccount
      ? 'an entire AWS account - aws:PrincipalAccount is account-granularity, equivalent to naming that account as the Principal, so the whole account is trusted'
      : sig.principalArnScope === 'broad'
        ? 'a wildcarded set of principals within the scope'
        : 'a specific principal';
  return { severity: broad ? 'high' : 'medium', names: names.join(', '), breadthDesc };
}

// --- Finding construction ----------------------------------------------------

function makeFinding(stmt, principals, { id, severity, title, why, remediation, docRef, pathExploitability }) {
  const actions = stmt.actions.slice();
  const evidence = [Object.freeze({
    statementIndex: stmt.index,
    statementSid: statementSid(stmt),
    role: 'trust',
    actions: actions.slice(),
    resources: [],
    condition: stmt.condition === undefined ? null : stmt.condition,
    // The typed principals this statement trusts (inert data; display evidence).
    principals: principals.entries.map((e) => Object.freeze({ type: e.type, value: e.value })),
    note: null,
  })];
  return {
    id,
    severity,
    title,
    statementSid: statementSid(stmt),
    statementIndex: stmt.index,
    actions,
    resources: [], // a trust policy has no Resource; its absence is normal.
    conditions: stmt.condition === undefined ? null : stmt.condition,
    // Split confidence (IAM-104): the trust grant is literally in the policy
    // (policyEvidence high); reaching/using the role's power needs the assumer to
    // act AND the (unknown) target-role privileges (pathExploitability capped
    // below policyEvidence).
    policyEvidence: 'high',
    pathExploitability: pathExploitability || 'medium',
    why,
    limit: TRUST_LIMIT,
    remediation,
    ruleVersion: RULE_VERSION,
    docRef,
    // Trust enrichment (analogous to the escalation enrichment on identity
    // findings, but for the trust direction). targetPermissions is ALWAYS
    // 'unknown' and is never inferred.
    trust: {
      principalTypes: [...principals.categories].sort(),
      anonymous: principals.anonymous,
      targetPermissions: 'unknown',
    },
    evidence,
    contributingStatements: [Object.freeze({
      statementIndex: stmt.index,
      statementSid: statementSid(stmt),
      actions: actions.slice(),
    })],
  };
}

function principalSummary(principals) {
  return principals.entries.map((e) => e.value).join(', ') || '(none)';
}

// Whether a single Principal VALUE is ORG-WIDE / PUBLIC in breadth: the anonymous
// "*" (any principal in any account), or a wildcarded ARN that is NOT pinned to a
// single account (e.g. "arn:aws:iam::*:role/*" spans every account). An
// account-pinned wildcard ARN (e.g. "arn:aws:iam::123456789012:role/app-*") names
// many principals but is BOUNDED to one account, so it is NOT org-wide; a concrete
// account id / :root ARN / specific user-or-role ARN carries no wildcard and is
// likewise bounded. Reuses arnAccountPinned() so this test and the condition-value
// narrowing test agree on "bounded to one account".
function principalValueIsBroad(value) {
  const s = String(value);
  if (s === '*') return true; // anonymous / public
  if (!hasGlob(s)) return false; // a bounded, fully-literal principal
  // A wildcarded value is org-wide UNLESS it is pinned to a single account.
  return !arnAccountPinned(s);
}

// The NAMED Principal is BROAD when it is anonymous/public ("*") or names an
// org-wide / all-accounts wildcard (a wildcard ARN not pinned to one account).
// Breadth of the named principal (independent of any Condition) is what decides
// whether a negated aws:PrincipalOrgID reads as an org-WIDE external expansion
// (critical) or merely scopes an already-bounded principal. AWS evaluates
// Principal AND Condition, so a negated org condition can never widen trust beyond
// the named Principal (adversarial defect IAM-802-C: a StringNotEquals org on ONE
// specific role ARN is not org-wide). IAM-803 iteration 4 extends this: an
// ACCOUNT-PINNED wildcard ARN (arn:aws:iam::<acct>:role/app-*) is bounded to a
// single account, so it too is NOT broad - it must fall through to the
// cross-account branch (high, carrying the expansion-polarity note) rather than
// fire the org-wide critical headline, which would over-claim an "organization-
// wide set of outside principals" the single-account evidence contradicts AND
// score the bounded subset ABOVE the strictly broader whole-account trust.
function principalIsBroad(principals) {
  if (principals.anonymous) return true;
  return principals.entries.some((e) => principalValueIsBroad(e.value));
}

// A filtered VIEW of a classified principal restricted to a set of category
// types, so a finding names ONLY the principals it is actually about in its
// summary / evidence.principals / trust.principalTypes. Without this, a statement
// naming a Federated provider AND an AWS account would attribute the account to
// the federated finding (and vice versa) - the attribution overclaim behind
// adversarial defect IAM-802-A, where the co-present cross-account trust was
// dropped from the findings table while the graph still drew its can-assume edge.
function subsetPrincipals(principals, types) {
  const keep = new Set(types);
  const entries = principals.entries.filter((e) => keep.has(e.type));
  const categories = new Set(entries.map((e) => e.type));
  const anonymous = entries.some((e) => e.type === 'anonymous');
  return { anonymous, categories, entries, unknownTypes: [] };
}

// Emit the trust finding(s) for a single trust statement, following the
// documented severity model (trust-policy-semantics.md section 5). Returns an
// array (usually one finding; a statement mixing e.g. an external account AND a
// service principal can yield more than one).
function findingsForStatement(stmt) {
  const principals = classifyPrincipals(stmt.principal);
  const sig = conditionSignals(stmt.condition, principals);
  const found = [];
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

    let severity;
    if (constrainedLowers) severity = 'low';
    else if (principalScopePresent) severity = scopeSeverity;
    else severity = 'high';

    let pathExpl;
    if (constrained || defenseInDepth) pathExpl = 'low';
    else if (principalScopePresent) pathExpl = scopeSeverity === 'high' ? 'medium' : 'low';
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
    } else if (principalScopePresent) {
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
        noteAccountScope + noteDefense + noteOrgExclusion + noteBroadConstraint + bypassNote;
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
    const svcOnly = svc.entries.map((e) => e.value).join(', ');
    found.push(makeFinding(stmt, svc, {
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
export function trustDenyStatements(model) {
  if (!model || !Array.isArray(model.statements)) return [];
  return model.statements.filter((s) => s && s.effect === 'Deny' && isTrustStatement(s));
}

// AWS treats the account-ARN form `arn:aws:iam::<acct>:root` and the bare 12-digit
// account id `<acct>` as the SAME principal - both delegate trust to the whole
// account, and the `...:root` form does NOT limit trust to the root user
// (trust-policy-semantics.md 2.2). Reduce a whole-account delegation entry to a
// canonical `account:<id>` key so a Deny written in one form neutralizes an Allow
// written in the other (adversarial-critic IAM-806 iteration 4 defect 1: a bare
// account-id Deny failed to suppress a root-ARN Allow because the matcher compared
// principal strings verbatim, leaving a HIGH cross-account over-claim on a role AWS
// treats as unassumable). This is EXACT canonical equivalence, not a wildcard glob:
// every other principal type keeps its verbatim `<type>:<value>` identity.
function canonicalPrincipalKey(entry) {
  if (!entry || typeof entry !== 'object') return null;
  if (entry.type === 'aws-account') return `account:${entry.value}`;
  if (entry.type === 'aws-root') {
    const m = /^arn:[^:]*:iam::(\d{12}):root$/i.exec(String(entry.value));
    if (m) return `account:${m[1]}`;
    return `aws-root:${entry.value}`;
  }
  return `${entry.type}:${String(entry.value)}`;
}

// Does a Deny's classified Principal set cover this Allow-finding principal entry?
// A Deny Principal "*" (anonymous) covers EVERY principal, so it neutralizes any
// grant. Otherwise coverage is proven only by CANONICAL-form equivalence: the same
// account (root-ARN <-> bare account id, per canonicalPrincipalKey) or an exact
// typed-value match (same role ARN, provider, ...). A specific Deny never covers an
// anonymous ("*") Allow - only a "*" Deny does. We still do NOT try to prove a
// wildcard-ARN Deny globs over an Allow principal: an unproven wide match must not
// manufacture a FALSE "fully denied" (that would under-report a real trust, the
// inverse T8 harm), so it falls through to the "partial" caveat path instead.
function principalEntryDeniedBy(entry, denyPrincipals) {
  if (denyPrincipals.anonymous) return true;
  if (!entry || entry.type === 'anonymous') return false;
  const key = canonicalPrincipalKey(entry);
  if (key === null) return false;
  return denyPrincipals.entries.some((d) => canonicalPrincipalKey(d) === key);
}

/**
 * Same-policy explicit-Deny precedence for ONE trust finding. Returns:
 *   'full'    - every (principal, assume-action) the finding rests on is covered
 *               by an UNCONDITIONAL, certain, in-scope trust Deny: the grant is
 *               fully neutralized (suppress the finding; graph shows blocked-by-
 *               deny, no can-assume edge).
 *   'partial' - a same-policy trust Deny overlaps the grant but does not provably
 *               fully block it (conditional, or only some principals/actions
 *               covered, or an unproven wildcard match): the finding stays, but
 *               the residual Deny effect is surfaced as a coverage caveat.
 *   'none'    - no same-policy trust Deny touches the grant.
 *
 * Deterministic; never throws. Only assume actions matter: an assume grant is
 * neutralized when the assume action(s) are denied (an aux-only session action is
 * inert without a live assume, so TRUST-SESSION-CONTROL is always 'none').
 *
 * @param {object} finding a trust finding (TRUST-* canonical shape)
 * @param {object} model normalized, frozen model from buildModel()
 * @returns {'none'|'partial'|'full'}
 */
export function trustFindingDenyState(finding, model) {
  if (!finding || typeof finding !== 'object') return 'none';
  if (typeof finding.id !== 'string' || !finding.id.startsWith('TRUST-')) return 'none';
  if (!model || !Array.isArray(model.statements)) return 'none';

  const ev0 = Array.isArray(finding.evidence) && finding.evidence[0] ? finding.evidence[0] : null;
  const princs = ev0 && Array.isArray(ev0.principals) ? ev0.principals : [];
  const actions = (Array.isArray(finding.actions) ? finding.actions : [])
    .filter((a) => ASSUME_ACTIONS.has(String(a).toLowerCase()));
  if (princs.length === 0 || actions.length === 0) return 'none';

  const denies = trustDenyStatements(model);
  if (denies.length === 0) return 'none';

  const denyInfos = denies.map((s) => ({
    stmt: s,
    conditioned: hasNonEmptyCondition(s),
    principals: classifyPrincipals(s.principal),
  }));

  let full = true;
  let overlap = false;
  for (const p of princs) {
    for (const a of actions) {
      let coveredUnconditionally = false;
      for (const d of denyInfos) {
        if (!principalEntryDeniedBy(p, d.principals)) continue;
        const aa = denyActionApplies(d.stmt, a);
        if (!aa.applies) continue;
        overlap = true;
        if (!d.conditioned && aa.certain) coveredUnconditionally = true;
      }
      if (!coveredUnconditionally) full = false;
    }
  }
  if (full) return 'full';
  return overlap ? 'partial' : 'none';
}

/**
 * Summarize same-policy trust Deny for the coverage panel + exports (IAM-806
 * requirement (c): a neutralizing Deny is NEVER silently discarded from a
 * "complete" analysis). Returns { present, count, unmodeled, note }:
 *   - present:  any same-policy trust Deny statement exists.
 *   - unmodeled: a trust Deny's restricting effect is NOT fully translated into a
 *                suppression - it is conditional, or only PARTIALLY overlaps a
 *                grant. Fully-blocked grants ARE modeled (finding suppressed +
 *                blocked-by-deny edge), matching the identity engine, so they do
 *                not by themselves mark coverage incomplete.
 *   - note:     human-readable caveat text.
 *
 * @param {object} model normalized model
 * @param {Array<object>} findings raw trust findings (analyzeTrust output)
 * @returns {{present:boolean,count:number,unmodeled:boolean,note:(string|null)}}
 */
export function summarizeTrustDeny(model, findings) {
  const denies = trustDenyStatements(model);
  if (denies.length === 0) return { present: false, count: 0, unmodeled: false, note: null };

  const list = Array.isArray(findings) ? findings : [];
  let unmodeled = denies.some((s) => hasNonEmptyCondition(s));
  let anyFull = false;
  for (const f of list) {
    const state = trustFindingDenyState(f, model);
    if (state === 'partial') unmodeled = true;
    if (state === 'full') anyFull = true;
  }

  // The "fully neutralizes the overlapping assume grant" wording may be emitted
  // ONLY when a same-policy Deny actually resolved a finding to 'full'
  // (adversarial-critic IAM-806 iteration 4 defect 2: the note previously claimed
  // neutralization of an overlapping grant whenever a Deny was present and nothing
  // was unmodeled - even when the Deny overlapped NO grant, e.g. a Deny of account
  // 222 alongside an Allow of account 111). When no finding resolved to 'full', the
  // Deny restricts additional principals not otherwise granted; it neutralizes
  // nothing, and the note must say so.
  let effect;
  if (unmodeled) {
    effect =
      'At least one is conditional or only partially overlaps a grant, so its ' +
      'restricting effect is NOT fully reflected in the findings - unsupported ' +
      'does NOT mean safe.';
  } else if (anyFull) {
    effect =
      'Each fully neutralizes the overlapping assume grant, shown as a ' +
      'blocked-by-deny relationship rather than an assume finding.';
  } else {
    effect =
      'None overlaps an analyzed assume grant; each restricts additional ' +
      'principals not otherwise granted by this policy (shown as a blocked-by-' +
      'deny relationship).';
  }
  const note =
    `${denies.length} explicit Deny statement(s) in this trust policy restrict ` +
    'who may assume the role. ' +
    effect;

  return { present: true, count: denies.length, unmodeled, note };
}

/**
 * Analyze a role-trust policy model. Emits trust findings following the
 * documented severity model; NEVER runs identity rules and NEVER emits an
 * identity-style broad-Resource finding. Every finding carries the limitation
 * that the assumed role's permissions are out of scope / unknown.
 *
 * Never throws. Deterministic (findings sorted by statement index, then id).
 *
 * @param {object} model normalized, frozen model (from buildModel/modelFromText)
 * @returns {{ok:boolean, errors:Array, findings:Array<object>}}
 */
export function analyzeTrust(model) {
  const errors = [];
  try {
    if (!model || typeof model !== 'object' || !Array.isArray(model.statements)) {
      errors.push(err('NO_MODEL', 'analyzeTrust() requires a normalized model.'));
      return Object.freeze({ ok: false, errors: Object.freeze(errors), findings: Object.freeze([]) });
    }

    const findings = [];
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
    errors.push(err('INTERNAL', 'Trust analysis failed unexpectedly.'));
    return Object.freeze({ ok: false, errors: Object.freeze(errors), findings: Object.freeze([]) });
  }
}

export default analyzeTrust;
