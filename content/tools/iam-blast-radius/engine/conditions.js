// IAM Blast Radius - condition classification v1 (IAM-506).
//
// Classifies the keys in a statement's Condition block WITHOUT ever claiming a
// runtime AWS request will match or be denied. AWS resolves a condition against
// the live request context (source IP, MFA state, which service is calling,
// which values a multivalued key actually holds); none of that is present in a
// single pasted policy. So this module reports how the condition TEXT reads -
// it "appears to narrow", "appears to select", "appears to broaden", or is
// "context-required" (its effect cannot be resolved from the text) - and it is
// deliberately conservative: an unknown key, a negated operator, a wildcard
// value, a missing-key test, or an ...IfExists / ForAllValues footgun is NEVER
// credited as protective (threat-model T8: overstated certainty is a security
// harm; unsupported does NOT mean safe).
//
// It feeds two consumers:
//   - coverage.js: keys we do not model surface as `unsupportedConditions`
//     (context-required), which marks coverage incomplete.
//   - the finding evidence set: each finding carries a `conditionClassification`
//     so the path-exploitability story is explainable (why a condition does or
//     does not look like a guardrail) - NOT a runtime allow/deny claim.
//
// Interactive request-context simulation is explicitly OUT of scope for v1.
//
// Pure, deterministic, dependency-free. No network APIs. No eval/Function. No
// DOM. Same Condition object -> same classification, every run. Hostile keys and
// values are only ever read as strings and compared; never interpreted as code.

// The four classes a condition entry can carry.
export const CONDITION_CLASS = Object.freeze({
  CONSTRAINT: 'constraint', // narrows when / where / who
  SELECTOR: 'selector', // selects service / resource / principal / encryption-context
  EXPANSION: 'expansion', // negated / wildcarded / missing-key broadening
  CONTEXT_REQUIRED: 'context-required', // unknown / unresolvable - never protective
});

// How the entry reads, in capability-safe wording (never a runtime verdict).
export const CONDITION_APPEARS = Object.freeze({
  narrows: 'narrows',
  selects: 'selects',
  broadens: 'broadens',
  'context-required': 'context-required',
});

// Curated catalog of the condition KEYS this v1 models. Keyed by the lowercased
// condition key. Everything not here is context-required (unknown) - we never
// guess a key's semantics. `class` is the key's BASE class before operator
// modifiers (a negated operator or a missing-key test can move a constraint to
// expansion). This is the small, versioned surface the story asks for; more keys
// slot in by adding a row (a later phase may replace it behind this interface).
const KNOWN_KEYS = Object.freeze({
  // Constraints - narrow when / where / who.
  'aws:multifactorauthpresent': { class: CONDITION_CLASS.CONSTRAINT, role: 'mfa', label: 'MFA presence' },
  'aws:sourceip': { class: CONDITION_CLASS.CONSTRAINT, role: 'network', label: 'Source IP range' },
  'aws:sourcevpc': { class: CONDITION_CLASS.CONSTRAINT, role: 'network', label: 'Source VPC' },
  'aws:sourcevpce': { class: CONDITION_CLASS.CONSTRAINT, role: 'network', label: 'Source VPC endpoint' },
  'aws:principalorgid': { class: CONDITION_CLASS.CONSTRAINT, role: 'org', label: 'Principal organization' },
  'aws:requestedregion': { class: CONDITION_CLASS.CONSTRAINT, role: 'region', label: 'Requested region' },
  // Trust condition keys (IAM-803, docs/trust-policy-semantics.md section 4).
  // These are modeled with correct POLARITY so a role-trust policy's conditions
  // are UNDERSTOOD, not reported as unsupported: a positive value-match reads as
  // a constraint; a NEGATED operator on any of them (e.g. StringNotEquals
  // aws:PrincipalOrgID - the crux) flips to an EXPANSION via the negated-operator
  // branch below. sts:ExternalId is the confused-deputy correlation value (a
  // constraint; NOT authentication and NOT a secret - the classifier only reads
  // its presence/polarity, never treats it as a credential). aws:SourceArn /
  // aws:SourceAccount are the confused-deputy constraints for service-principal
  // trust. aws:PrincipalArn / aws:PrincipalAccount pin which principal is trusted.
  // Classification NEVER asserts a runtime STS allow/deny (threat-model T8).
  'sts:externalid': { class: CONDITION_CLASS.CONSTRAINT, role: 'confused-deputy', label: 'External ID (confused-deputy correlation value)' },
  'aws:sourcearn': { class: CONDITION_CLASS.CONSTRAINT, role: 'confused-deputy', label: 'Source ARN' },
  'aws:sourceaccount': { class: CONDITION_CLASS.CONSTRAINT, role: 'confused-deputy', label: 'Source account' },
  'aws:principalarn': { class: CONDITION_CLASS.CONSTRAINT, role: 'principal', label: 'Principal ARN' },
  'aws:principalaccount': { class: CONDITION_CLASS.CONSTRAINT, role: 'principal', label: 'Principal account' },
  // Selectors - pick which service / resource / encryption-context is in play.
  // A selector changes SCOPE; it is not automatically a guardrail, so it is
  // never credited as narrowing here (the escalation engine decides direction,
  // e.g. iam:PassedToService pinned to a non-matching service blocks a path).
  'iam:passedtoservice': { class: CONDITION_CLASS.SELECTOR, role: 'service', label: 'PassRole target service' },
  'iam:associatedresourcearn': { class: CONDITION_CLASS.SELECTOR, role: 'resource', label: 'Associated resource ARN' },
  'kms:viaservice': { class: CONDITION_CLASS.SELECTOR, role: 'service', label: 'KMS calling service' },
});

// OIDC / SAML federation claim keys (docs/trust-policy-semantics.md 4.4/4.5)
// carry a provider-host prefix rather than a fixed name, so they cannot live in
// the exact-match KNOWN_KEYS table: GitHub Actions uses
// `token.actions.githubusercontent.com:aud` / `:sub`, other OIDC providers use
// their own host, and SAML uses `saml:aud` / `saml:sub`. This resolver models
// them so a federated trust policy's aud/sub keys are UNDERSTOOD (not reported as
// unsupported). A positive `aud` (audience) check is a valid CONSTRAINT - AWS docs
// say recognize it, do not flag it "missing". A `sub` (subject) check narrows WHICH
// workload may assume the role; its breadth is value-driven and handled at
// classification time (a wildcarded `repo:org/*` subject is broad, not a dependable
// single-workload guardrail). Returns null for any non-federation key.
function federationMeta(keyLower) {
  if (keyLower.endsWith(':aud')) {
    return { class: CONDITION_CLASS.CONSTRAINT, role: 'federation-audience', label: 'Federated audience (aud)', federation: 'aud' };
  }
  if (keyLower.endsWith(':sub')) {
    return { class: CONDITION_CLASS.CONSTRAINT, role: 'federation-subject', label: 'Federated subject (sub)', federation: 'sub' };
  }
  return null;
}

// Base operators (after stripping set qualifier + IfExists) whose match is
// NEGATED - "everything EXCEPT the listed values" - so they broaden rather than
// restrict when used to gate an Allow. Exported so the resource evaluator
// (engine/resource.js) reuses the SAME polarity set when it decides whether a
// principal-scoping condition on a "*" Allow genuinely narrows the grant or is an
// exclusion/expansion (a negated operator flips constraint -> expansion), instead
// of a name-only key match (adversarial-critic IAM-1202 iteration 4).
export const NEGATED_OPERATORS = new Set([
  'stringnotequals',
  'stringnotequalsignorecase',
  'stringnotlike',
  'arnnotequals',
  'arnnotlike',
  'numericnotequals',
  'datenotequals',
  'notipaddress',
]);

// Positive string/ARN equality-family operators (base form, after parseOperator).
// A value-scoping TRUST key - a confused-deputy correlation value (sts:ExternalId),
// a service/resource scope (aws:SourceArn/aws:SourceAccount), an org scope
// (aws:PrincipalOrgID StringEquals), or a principal scope (aws:PrincipalArn/
// aws:PrincipalAccount) - only pins a VALUE, and so only reads as a dependable
// guardrail, when matched with one of these. A Date/Numeric/Bool/other operator on
// such a key does NOT scope its value (DateGreaterThan sts:ExternalId compares a
// date, it does not require a matching external-id correlation value), so it must
// never be credited here while trust.js keeps the finding HIGH - crediting it would
// re-open the severity-vs-provenance mismatch (adversarial-critic IAM-804 iteration
// 5: DateGreaterThan sts:ExternalId was credited=true though trust.js requires a
// positive string/ARN operator). MUST mirror trust.js POSITIVE_STRING_MATCH_OPERATORS.
const POSITIVE_STRING_MATCH_OPERATORS = new Set([
  'stringequals',
  'stringequalsignorecase',
  'stringlike',
  'arnequals',
  'arnlike',
]);

// The trust value-scoping keys whose crediting REQUIRES a positive string/ARN match
// operator (mirrors the keys trust.js gates through scopesValue). Any other key
// (aws:SourceIp via IpAddress, aws:MultiFactorAuthPresent via Bool, aws:SourceVpc/
// aws:SourceVpce/aws:RequestedRegion via string match, the OIDC/SAML aud/sub claims
// handled by trust.js with their own polarity) is intentionally NOT gated here.
const VALUE_SCOPING_TRUST_KEYS = new Set([
  'sts:externalid',
  'aws:sourcearn',
  'aws:sourceaccount',
  'aws:principalarn',
  'aws:principalaccount',
  'aws:principalorgid',
]);

/**
 * Split a condition operator into its parts. AWS lets an operator carry a set
 * qualifier prefix (ForAllValues:/ForAnyValue:) and an ...IfExists suffix; the
 * BASE operator remains after removing both. Case-insensitive.
 *
 * ForAllValues is a well-known footgun: it evaluates TRUE when the key is
 * absent from the request, so it may not constrain a request that omits the key.
 * ...IfExists only applies when the key IS present, so a request lacking the key
 * is not constrained. Both are surfaced so neither is mistaken for a guarantee.
 *
 * @param {string} operator raw operator as written in the policy
 * @returns {{base:string, setOperator:(string|null), ifExists:boolean}}
 */
export function parseOperator(operator) {
  let o = String(operator).toLowerCase();
  let setOperator = null;
  if (o.startsWith('forallvalues:')) {
    setOperator = 'ForAllValues';
    o = o.slice('forallvalues:'.length);
  } else if (o.startsWith('foranyvalue:')) {
    setOperator = 'ForAnyValue';
    o = o.slice('foranyvalue:'.length);
  }
  let ifExists = false;
  if (o.endsWith('ifexists')) {
    ifExists = true;
    o = o.slice(0, -'ifexists'.length);
  }
  return { base: o, setOperator, ifExists };
}

function toValueArray(value) {
  if (Array.isArray(value)) return value.filter((v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean').map((v) => String(v));
  if (value === null || value === undefined) return [];
  return [String(value)];
}

/**
 * suite-3 test 97: a ForAnyValue condition with an EMPTY policy value set can
 * never be satisfied - AWS ForAnyValue returns false when the policy specifies
 * no values, so at least one request value can never match "at least one of
 * nothing". The entry is therefore always false, and because a statement's
 * Condition block ANDs its entries together, the whole statement can NEVER match
 * any request: it grants nothing. Detect this structurally so rules/escalation/
 * graph skip the statement (no phantom capability or wildcard-resource finding
 * for an ineffective grant) BEFORE any rule/graph generation.
 *
 * NOTE: an empty ForAllValues set is NOT never-match - ForAllValues is vacuously
 * TRUE when the key is absent from the request, so an empty-set ForAllValues is
 * satisfiable and must NOT be suppressed (suppressing it would understate blast
 * radius, threat-model T8). Only ForAnyValue-empty is a hard never-match.
 *
 * @param {object} stmt normalized statement
 * @returns {boolean} true iff the statement can never match any request
 */
export function statementNeverMatches(stmt) {
  const cond = stmt && stmt.condition;
  if (!cond || typeof cond !== 'object') return false;
  for (const operator of Object.keys(cond)) {
    const { setOperator } = parseOperator(operator);
    if (setOperator !== 'ForAnyValue') continue;
    const block = cond[operator];
    if (!block || typeof block !== 'object') continue;
    for (const key of Object.keys(block)) {
      const raw = block[key];
      // Only an explicitly EMPTY array is a structural never-match. A missing
      // value or a scalar is not this case.
      if (Array.isArray(raw) && toValueArray(raw).length === 0) return true;
    }
  }
  return false;
}

// A value that does not constrain: the bare wildcard "*". (We deliberately do
// NOT try to interpret "0.0.0.0/0" or other value-level all-encompassing forms -
// that is request-context reasoning we do not claim.)
function hasWildcardValue(values) {
  return values.some((v) => v === '*');
}

// Key-aware narrowing test for the account/org/ARN condition keys, MIRRORING
// engine/trust.js valueNarrowsKey so a finding's conditionClassification.credited
// AGREES with the trust severity trust.js assigns (adversarial-critic IAM-803
// iteration 2 defect 2: hasWildcardValue only rejected the exact "*", so a
// match-everything glob on a key-aware field - StringLike aws:PrincipalOrgID
// "o-*", ArnLike aws:SourceArn "arn:aws:*:*:*:*" - was credited=true in the
// evidence panel even though trust.js correctly kept the finding high). These
// helpers must stay behaviorally identical to trust.js; both are kept local so
// each module stays dependency-free (same rationale as the duplicated
// NEGATED_OPERATORS set).
function hasGlob(s) {
  return s.includes('*') || s.includes('?');
}

// An account-id key (aws:SourceAccount / aws:PrincipalAccount) is a full 12-digit
// number and an org-id key (aws:PrincipalOrgID) is o-<body>; any glob leaves them
// unpinned ("o-*" matches every org), so only a complete literal narrows.
function accountOrOrgValueNarrows(value) {
  const s = String(value);
  if (s === '') return false;
  return !hasGlob(s);
}

// Common AWS ARN resource-TYPE keywords. In an ARN resource of the form
// "<type>/<id>" or "<type>:<id>", the LEADING token is a resource-type CATEGORY
// (role, secret, function, trail, ...), not a specific resource. A value whose
// only surviving literal is such a category keyword - e.g. arn:aws:iam::*:role/*
// (every role in every account) or arn:aws:secretsmanager:*:*:secret:* (every
// secret in every account) - bounds NOTHING (not which account, not which
// resource) and is therefore NOT a confused-deputy scope. Only a concrete
// resource IDENTIFIER narrows. This list and arnValueNarrows() below MUST stay
// behaviorally identical to engine/trust.js (ARN_RESOURCE_TYPE_KEYWORDS +
// arnValueNarrows) so a finding's conditionClassification.credited AGREES with
// the trust severity trust.js assigns (adversarial-critic IAM-804 iteration 3
// defect: this module credited a bare resource-type-keyword ARN like
// arn:aws:iam::*:role/* as a confused-deputy guardrail on a finding trust.js
// correctly keeps HIGH - a wrong-provenance over-credit). Kept lowercase; matched
// case-insensitively.
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
// still pins an identifying component: the account segment (ARN field index 4) is
// the primary identifier, else a concrete resource IDENTIFIER must survive in the
// resource part. It does NOT narrow when the only surviving literal is a bare
// resource-TYPE keyword before the wildcard: arn:aws:iam::*:role/* and
// arn:aws:secretsmanager:*:*:secret:* name a CATEGORY across every account.
// "arn:aws:*:*:*:*" / "arn:aws:iam::*:*" pin nothing either. MUST mirror
// engine/trust.js arnValueNarrows (adversarial-critic IAM-804 iteration 3).
function arnValueNarrows(value) {
  const s = String(value);
  if (s === '') return false;
  if (!hasGlob(s)) return true; // a fully literal ARN narrows
  const segs = s.split(':');
  const account = segs.length > 4 ? segs[4] : '';
  if (account !== '' && !hasGlob(account)) return true; // account segment pinned
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
    if (i === 0 && ARN_RESOURCE_TYPE_KEYWORDS.has(literal.toLowerCase())) return false;
    return true;
  });
}

// An all-addresses IP/CIDR range constrains nothing: IpAddress aws:SourceIp
// 0.0.0.0/0 (or the IPv6 equivalent) matches every source, so it is a vacuous
// match-everything value exactly like a wildcarded org id or ARN. MUST stay
// behaviorally identical to trust.js isAllAddressIp (trust.js lines 319-323) so a
// finding's conditionClassification.credited AGREES with the trust severity
// trust.js assigns: without this guard, conditions.js routed an all-addresses
// aws:SourceIp through valueNarrowsKey's default arm (which rejects only ''/all-
// glob) and credited it as a narrowing Source-IP guardrail on a HIGH cross-account
// trust whose own why-text says "no confused-deputy constraint" and never mentions
// SourceIp - the severity-vs-provenance contradiction already eliminated for
// ExternalId/org/ARN globs (adversarial-critic IAM-806 iteration 2). A vacuous
// 0.0.0.0/0 stamped into the evidence as a credited guardrail can falsely reassure
// a reviewer of a wide-open cross-account trust (threat-model T8).
function isAllAddressIp(v) {
  const s = String(v).trim().toLowerCase();
  return s === '*' || s === '0.0.0.0/0' || s === '0/0' ||
    s === '::/0' || s === '::0/0' || s === '::0' || s === '::';
}

// Dispatch the narrowing test for the trust-relevant scoping keys. Any other
// constraint key narrows unless it is empty or a value made entirely of glob
// metacharacters ('*'/'?'). The exact-"*" case is already handled by
// hasWildcardValue before this is consulted, but a match-everything glob that is
// not the bare "*" - e.g. StringLike sts:ExternalId "?*" (matches every non-empty
// string, functionally identical to "*") - reaches here and must NOT be credited:
// crediting it in the evidence panel while trust.js keeps the finding high (the
// trust.js default arm now rejects the same all-glob values) would re-open the
// severity-vs-provenance mismatch (adversarial-critic IAM-804 iteration 4 finding
// 2). MUST stay behaviorally identical to trust.js isAllGlobOrEmpty.
function valueNarrowsKey(keyLower, value) {
  switch (keyLower) {
    case 'aws:sourceaccount':
    case 'aws:principalaccount':
    case 'aws:principalorgid':
      return accountOrOrgValueNarrows(value);
    case 'aws:sourcearn':
    case 'aws:principalarn':
      return arnValueNarrows(value);
    case 'aws:sourceip': {
      // A source-IP range narrows only when it is a real (non-empty, non-all-glob)
      // range that is NOT an all-addresses range: 0.0.0.0/0 and the IPv6 forms
      // match every source and must classify as expansion/uncredited, mirroring
      // trust.js isAllAddressIp so the evidence panel agrees with trust severity.
      const s = String(value);
      return s !== '' && !/^[*?]+$/.test(s) && !isAllAddressIp(s);
    }
    default: {
      const s = String(value);
      return s !== '' && !/^[*?]+$/.test(s);
    }
  }
}

// Interpret a Null operator's value: "true" tests the key is ABSENT (broadening,
// a missing-key condition), "false" tests the key is PRESENT (presence-only).
// A mixed/other value is unresolvable.
function nullTestKind(values) {
  const set = new Set(values.map((v) => v.toLowerCase()));
  if (set.size === 1 && set.has('true')) return 'absent';
  if (set.size === 1 && set.has('false')) return 'present';
  return 'ambiguous';
}

// Interpret a Bool operator's value for a boolean key (e.g. MFA): "true" asserts
// the flag is set, "false" asserts it is not. Mixed/other -> unresolvable.
function boolKind(values) {
  const set = new Set(values.map((v) => v.toLowerCase()));
  if (set.size === 1 && set.has('true')) return 'true';
  if (set.size === 1 && set.has('false')) return 'false';
  return 'ambiguous';
}

function appearsFor(cls) {
  switch (cls) {
    case CONDITION_CLASS.CONSTRAINT: return CONDITION_APPEARS.narrows;
    case CONDITION_CLASS.SELECTOR: return CONDITION_APPEARS.selects;
    case CONDITION_CLASS.EXPANSION: return CONDITION_APPEARS.broadens;
    default: return CONDITION_APPEARS['context-required'];
  }
}

/**
 * Classify a single Condition entry (one operator + one key + its value(s)).
 *
 * Never throws. Returns a frozen record describing how the TEXT reads. `credited`
 * is true ONLY for a known constraint key expressed with a plain narrowing
 * operator (not negated, not wildcarded, not a missing-key/absent test, not
 * ...IfExists, not ForAllValues, and - for a boolean key - asserting the flag is
 * set). Selectors, expansions, and anything context-required are NEVER credited
 * as protective. `credited` is a text-reads-as-a-guardrail signal, not a runtime
 * guarantee.
 *
 * @param {string} operator the condition operator as written
 * @param {string} key the condition key as written
 * @param {*} value the operator/key value (string | array | other)
 * @param {Set<string>|null} presenceCheckedKeys lowercased keys that a SIBLING
 *   Null:{key:"false"} presence check (in the same statement's Condition block)
 *   requires to be PRESENT. When a ForAllValues set-operator constrains such a
 *   key, the "vacuously true when the key is absent" caveat does not apply - the
 *   presence check forecloses the omitted-key path - so it is annotated rather
 *   than warned about (suite-3 test 96 vs suite-2 test 41). Optional; when
 *   omitted (direct callers), no sibling context is assumed and the ForAllValues
 *   caveat is emitted as before. Never affects `credited` (fail-safe: an
 *   uncredited footgun is not re-credited by a sibling presence check).
 * @returns {object} frozen classification record
 */
export function classifyConditionEntry(operator, key, value, presenceCheckedKeys = null) {
  const { base, setOperator, ifExists } = parseOperator(operator);
  const keyStr = String(key);
  const keyLower = keyStr.toLowerCase();
  const values = toValueArray(value);
  // Exact-match modeled keys first, then the federation aud/sub resolver (whose
  // keys carry a provider-host prefix). Anything neither knows stays unknown ->
  // context-required, surfaced in coverage (unsupported does NOT mean safe).
  const meta = Object.prototype.hasOwnProperty.call(KNOWN_KEYS, keyLower)
    ? KNOWN_KEYS[keyLower]
    : federationMeta(keyLower);
  const known = meta !== null;

  const negated = NEGATED_OPERATORS.has(base);
  const wildcard = hasWildcardValue(values);
  const isNull = base === 'null';
  const isBool = base === 'bool';

  let cls;
  let credited = false;
  const notes = [];

  if (!known) {
    // Unknown key: we do not model its semantics. Context-required, never
    // credited. Still describe the operator shape so the note is useful.
    cls = CONDITION_CLASS.CONTEXT_REQUIRED;
    notes.push(`condition key "${keyStr}" is not modelled by this version; its effect cannot be resolved from the policy text`);
  } else if (isNull) {
    // A Null test is about key presence, independent of the key's own semantics.
    const kind = nullTestKind(values);
    if (kind === 'absent') {
      cls = CONDITION_CLASS.EXPANSION;
      notes.push(`Null test requires "${keyStr}" to be ABSENT from the request; this broadens rather than restricts`);
    } else if (kind === 'present') {
      cls = CONDITION_CLASS.CONSTRAINT;
      notes.push(`Null test requires "${keyStr}" to be present but does not constrain its value (presence-only)`);
    } else {
      cls = CONDITION_CLASS.CONTEXT_REQUIRED;
      notes.push(`Null test on "${keyStr}" has an unresolvable value`);
    }
  } else if (isBool) {
    // Boolean key (e.g. MFA). true -> constraint (flag asserted); false ->
    // broadening (flag explicitly not required / asserted absent).
    const kind = boolKind(values);
    if (kind === 'true') {
      cls = meta.class; // constraint
      credited = cls === CONDITION_CLASS.CONSTRAINT && !ifExists && !setOperator;
      notes.push(`asserts ${meta.label}`);
    } else if (kind === 'false') {
      cls = CONDITION_CLASS.EXPANSION;
      notes.push(`asserts ${meta.label} is NOT required; this does not restrict`);
    } else {
      cls = CONDITION_CLASS.CONTEXT_REQUIRED;
      notes.push(`Bool value on "${keyStr}" is unresolvable`);
    }
  } else if (negated) {
    // A negated operator excludes the listed values. On a constraint key that is
    // broadening ("anything except X"); on a selector it selects by exclusion.
    if (meta.class === CONDITION_CLASS.SELECTOR) {
      cls = CONDITION_CLASS.SELECTOR;
      notes.push(`selects ${meta.label} by EXCLUSION (denylist operator ${operator})`);
    } else {
      cls = CONDITION_CLASS.EXPANSION;
      notes.push(`negated operator ${operator} matches everything except the listed values; this broadens rather than restricts ${meta.label}`);
    }
  } else if (wildcard) {
    cls = CONDITION_CLASS.EXPANSION;
    notes.push(`value is a wildcard "*", which does not constrain ${meta.label}`);
  } else if (meta.federation === 'sub' && values.some((v) => v.includes('*') || v.includes('?'))) {
    // A federated SUBJECT that carries a glob (e.g. GitHub Actions
    // `repo:org/*`) scopes an organization-wide / pattern set of workloads, not
    // one specific workload. It narrows the subject SPACE but is not a dependable
    // single-workload guardrail, so it is classified as a constraint yet NOT
    // credited (docs/trust-policy-semantics.md 4.4: repo:org/* is broad; a repo +
    // ref/branch/environment binding is tight). This is a text reading of breadth,
    // never a claim that a specific token would or would not match at runtime.
    cls = CONDITION_CLASS.CONSTRAINT;
    notes.push(`selects a BROAD ${meta.label}: a wildcarded subject such as repo:org/* scopes an organization-wide or pattern set of workloads rather than one specific workload, so it is not credited as a dependable guardrail`);
    credited = false;
  } else if (meta.class === CONDITION_CLASS.CONSTRAINT &&
             !(values.length > 0 && values.every((v) => valueNarrowsKey(keyLower, v)))) {
    // A would-be constraint whose value(s) still match the key's WHOLE value
    // space (e.g. StringLike aws:PrincipalOrgID "o-*", ArnLike aws:SourceArn
    // "arn:aws:*:*:*:*") does not narrow - it is a vacuous match-everything glob.
    // Classify it as an expansion and never credit it, so the evidence panel does
    // not label a vacuous condition a guardrail on a finding trust.js keeps high
    // (IAM-803 iteration 2 defect 2). IAM ORs the multiple values of one
    // operator+key, so a co-listed match-all element defeats a pinned one; hence
    // .every (mirrors trust.js). An empty value list cannot narrow either.
    cls = CONDITION_CLASS.EXPANSION;
    notes.push(`value(s) for ${meta.label} match the key's whole value space (e.g. a wildcarded org id or ARN), so this does not narrow ${meta.label}`);
    credited = false;
  } else {
    cls = meta.class;
    if (cls === CONDITION_CLASS.CONSTRAINT) {
      notes.push(`appears to narrow by ${meta.label}`);
    } else {
      notes.push(`appears to select by ${meta.label}`);
    }
    // Credit a constraint only when it reads as a dependable guardrail.
    credited = cls === CONDITION_CLASS.CONSTRAINT;
    // A value-scoping trust key pins its value ONLY under a positive string/ARN
    // match operator. A Date/Numeric/other operator on such a key (e.g.
    // DateGreaterThan sts:ExternalId) does not scope the value, so it is NOT a
    // dependable guardrail - crediting it would over-credit a finding trust.js
    // correctly keeps HIGH (adversarial-critic IAM-804 iteration 5). Mirrors
    // trust.js scopesValue (positive-operator gate). The class stays CONSTRAINT
    // (the key IS a known scoping key), but credited flips off with a note.
    if (credited && VALUE_SCOPING_TRUST_KEYS.has(keyLower) && !POSITIVE_STRING_MATCH_OPERATORS.has(base)) {
      credited = false;
      notes.push(`operator "${operator}" is not a positive string/ARN match, so it does not scope ${meta.label} by value and is not credited as a guardrail`);
    }
  }

  // ...IfExists and ForAllValues weaken any would-be guardrail: they can pass
  // when the key is absent from the request. Never credit, and say so.
  if (credited && (ifExists || setOperator === 'ForAllValues')) {
    credited = false;
  }
  if (ifExists) {
    notes.push(`operator uses ...IfExists, so a request that lacks "${keyStr}" is NOT constrained`);
  }
  if (setOperator === 'ForAllValues') {
    // ForAllValues is vacuously TRUE when the key is absent from the request, so
    // on its own it "may not constrain a request that omits the key". But a
    // SIBLING Null:{key:"false"} presence check in the same Condition block
    // REQUIRES the key to be present: a request that omits it is denied and can
    // never reach that vacuous-when-absent branch. In that case the absent-key
    // caveat is factually wrong (suite-3 test 96 vs suite-2 test 41), so annotate
    // that the presence check forecloses the omitted-key path instead of warning
    // about it. We still do NOT credit the guardrail (fail-safe: credited stays
    // false above), we only stop emitting the false caveat.
    if (presenceCheckedKeys && presenceCheckedKeys.has(keyLower)) {
      notes.push('ForAllValues applies to the supplied values; a sibling Null presence check requires the key to be present, so the vacuous-when-absent path is foreclosed');
    } else {
      notes.push('ForAllValues matches when the key is absent, so it may not constrain a request that omits the key');
    }
  } else if (setOperator === 'ForAnyValue') {
    notes.push('ForAnyValue requires at least one supplied value to match');
  }

  return Object.freeze({
    operator: String(operator),
    baseOperator: base,
    setOperator,
    ifExists,
    key: keyStr,
    known,
    class: cls,
    role: meta ? meta.role : null,
    label: meta ? meta.label : null,
    negated: !!negated,
    wildcardValue: wildcard,
    nullTest: isNull ? nullTestKind(values) : null,
    appears: appearsFor(cls),
    credited: !!credited,
    // Capability-safe explanation; NEVER a runtime allow/deny claim.
    note: notes.join('; '),
  });
}

/**
 * Classify every entry in a statement's Condition block.
 *
 * The Condition shape is { operator: { key: value } }. We flatten it to one
 * record per (operator,key), in a deterministic order (operator then key), and
 * summarize. `contextRequiredKeys` is the sorted, de-duplicated set of keys the
 * classifier does not model - coverage.js reports these as unsupported
 * conditions (which marks coverage incomplete: unsupported does NOT mean safe).
 *
 * Never throws. Returns a frozen object; on an absent/empty/invalid Condition it
 * returns a stable "no conditions" shape.
 *
 * @param {object|null} condition normalized Condition object (or null)
 * @returns {object} frozen classification summary
 */
export function classifyConditions(condition) {
  const entries = [];
  if (condition && typeof condition === 'object' && !Array.isArray(condition)) {
    const operators = Object.keys(condition).sort();
    // First pass: collect the lowercased keys that a Null:{key:"false"} presence
    // check (anywhere in THIS statement's Condition block) requires to be
    // PRESENT. A ForAllValues set-operator on such a key does not have its
    // "vacuously true when absent" footgun, because a request omitting the key is
    // denied by the presence check (suite-3 test 96 vs suite-2 test 41). Scoped to
    // one statement's condition - never cross-statement.
    const presenceCheckedKeys = new Set();
    for (const op of operators) {
      if (parseOperator(op).base !== 'null') continue;
      const block = condition[op];
      if (!block || typeof block !== 'object' || Array.isArray(block)) continue;
      for (const key of Object.keys(block)) {
        if (nullTestKind(toValueArray(block[key])) === 'present') {
          presenceCheckedKeys.add(String(key).toLowerCase());
        }
      }
    }
    for (const op of operators) {
      const block = condition[op];
      if (!block || typeof block !== 'object' || Array.isArray(block)) continue;
      const keys = Object.keys(block).sort();
      for (const key of keys) {
        entries.push(classifyConditionEntry(op, key, block[key], presenceCheckedKeys));
      }
    }
  }

  const classes = {
    [CONDITION_CLASS.CONSTRAINT]: 0,
    [CONDITION_CLASS.SELECTOR]: 0,
    [CONDITION_CLASS.EXPANSION]: 0,
    [CONDITION_CLASS.CONTEXT_REQUIRED]: 0,
  };
  const contextRequired = new Set();
  let creditable = false;
  for (const e of entries) {
    classes[e.class] += 1;
    if (e.class === CONDITION_CLASS.CONTEXT_REQUIRED) contextRequired.add(e.key);
    if (e.credited) creditable = true;
  }

  return Object.freeze({
    present: entries.length > 0,
    entries: Object.freeze(entries),
    classes: Object.freeze(classes),
    contextRequiredKeys: Object.freeze([...contextRequired].sort()),
    hasCreditableConstraint: creditable,
    hasExpansion: classes[CONDITION_CLASS.EXPANSION] > 0,
  });
}

/**
 * Collect the sorted, de-duplicated set of context-required (unmodelled)
 * condition keys across every statement of a model. Feeds
 * coverage.unsupportedConditions. Never throws.
 *
 * @param {object|null} model normalized model (from buildModel)
 * @returns {Array<string>} sorted unique unmodelled condition keys
 */
export function unsupportedConditionKeys(model) {
  const out = new Set();
  const statements = model && Array.isArray(model.statements) ? model.statements : [];
  for (const stmt of statements) {
    const cc = classifyConditions(stmt && stmt.condition);
    for (const k of cc.contextRequiredKeys) out.add(k);
  }
  return [...out].sort();
}

export default classifyConditions;
