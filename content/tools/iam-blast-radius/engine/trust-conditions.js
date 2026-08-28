// trust-conditions.js - trust-policy Condition-block signal extraction (confused-deputy / public-scope constraints from condition operators+keys). Extracted (behavior-preserving).
import { arnPinnedAccount, hasGlob, isAllAddressIp, namedPrincipalAccounts, principalArnValueIsBroad, principalPinsAccount, valueNarrowsKey } from './trust-principal-helpers.js';
import { NEGATED_OPERATORS, POSITIVE_STRING_MATCH_OPERATORS } from './trust-catalogs.js';

export function parseOperatorParts(op) {
  let o = String(op).toLowerCase();
  let setOperator = null;
  if (o.startsWith('forallvalues:')) { setOperator = 'ForAllValues'; o = o.slice('forallvalues:'.length); }
  else if (o.startsWith('foranyvalue:')) { setOperator = 'ForAnyValue'; o = o.slice('foranyvalue:'.length); }
  let ifExists = false;
  if (o.endsWith('ifexists')) { ifExists = true; o = o.slice(0, -'ifexists'.length); }
  return { base: o, setOperator, ifExists };
}

export function toValues(v) {
  if (Array.isArray(v)) return v.map((x) => String(x));
  if (v === null || v === undefined) return [];
  return [String(v)];
}

// Walk a statement's Condition block and derive the trust-relevant polarity
// signals. Text-only: it reports how the condition READS, never a runtime match.
export function conditionSignals(condition, principals) {
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
    // S3-trust-calibration (3): a tight (exact) positive aws:PrincipalArn value
    // whose pinned account is NOT one of the named Principal's accounts. Such an
    // ARN is itself cross-account: it does NOT narrow WHICH principal within the
    // trusted account may assume the role (the intersection names a principal
    // OUTSIDE the trusted account), so it must not drop a cross-account external
    // trust below high. Only a SAME-account exact aws:PrincipalArn is a genuine
    // sub-account narrowing (the designed medium case).
    principalArnForeign: false,
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
          // S3-trust-calibration (3): a TIGHT (non-broad) aws:PrincipalArn value
          // that pins a CONCRETE account outside the named Principal's account set
          // is a cross-account ARN - it does not narrow within the trusted account.
          // Broad values are skipped (already high); a value with no concrete pinned
          // account (e.g. arn:aws:iam::*:role/deploy, whose account is fixed by the
          // Principal) is NOT foreign. IAM ORs the values, so ANY foreign value keeps
          // the trust cross-account (fail closed). Only meaningful when the Principal
          // names concrete account(s): with an anonymous "*" Principal there is no
          // reference account, so publicScopeConstraint's single-principal medium is
          // left intact (named.set is empty -> never foreign).
          const named = namedPrincipalAccounts(principals);
          if (named.set.size > 0) {
            for (const v of values) {
              if (principalArnValueIsBroad(v, pinsAccount)) continue;
              const acct = arnPinnedAccount(v);
              if (acct === null) continue;
              if (!named.set.has(acct)) sig.principalArnForeign = true;
            }
          }
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
export function hasConfusedDeputyConstraint(sig) {
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
export function publicScopeConstraint(sig) {
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
