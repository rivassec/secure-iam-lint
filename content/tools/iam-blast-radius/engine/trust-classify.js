// trust-classify.js - trust-statement detection + principal classification (isTrustStatement, classifyPrincipals + aws/service/federated principal typing). Extracted (behavior-preserving).
import { chargeWork } from './glob.js';
import { hasGlob } from './trust-principal-helpers.js';
import { TRUST_ACTIONS } from './trust-catalogs.js';

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
    // S3-dos-budget-all: charge one unit per principal member classified. This is the
    // single chokepoint every principal-heavy trust path funnels through
    // (findingsForStatement calls it once per Allow statement; trustFindingDenyState
    // classifies every Deny statement's Principal here too). Its O(members) forEach
    // does only string work and never reaches the shared matcher, so before this charge
    // a statement carrying thousands of trusted principals advanced the budget zero.
    // Charging here makes the per-principal iteration itself participate so an armed
    // work/clock budget is sampled proportional to the real member count.
    chargeWork(values.length);
    // IAM-1004: carry the principal-type key + the member's ARRAY INDEX on every
    // entry so an INVALID member of a Principal AWS array (e.g. array index 1) can
    // be located precisely (Principal.AWS[1]) rather than silently dropped or
    // reported without its position. Index is the position within THIS key's
    // normalized array (a scalar Principal normalizes to a 1-element array -> 0).
    if (key === 'AWS') {
      values.forEach((v, i) => add(out, awsPrincipalType(v), v, key, i));
    } else if (key === 'Service') {
      values.forEach((v, i) => add(out, serviceType(v), v, key, i));
    } else if (key === 'Federated') {
      values.forEach((v, i) => add(out, federatedType(v), v, key, i));
    } else if (key === 'CanonicalUser') {
      values.forEach((v, i) => add(out, 'canonical-user', v, key, i));
    } else {
      out.unknownTypes.push(key);
    }
  }
  return out;
}

export function add(out, type, value, key, index) {
  out.categories.add(type);
  // "*" under the AWS key is equivalent to Principal "*" - anonymous/public
  // access (trust-policy-semantics.md 2.1). Surface it on the anonymous flag so
  // it is treated as public trust, not as a specific AWS principal.
  if (type === 'anonymous') out.anonymous = true;
  // IAM-1004: key ('AWS'/'Service'/...) + index (position in that key's array)
  // give every entry a precise location so an invalid member is identifiable.
  const entry = { type, value: String(value) };
  if (key !== undefined) entry.key = key;
  if (index !== undefined) entry.index = index;
  out.entries.push(entry);
}

// AWS principal string -> typed form. '*' is anonymous/public; a bare 12-digit
// id or a ...:root ARN delegates trust to the whole account; anything else is a
// specific user/role/session principal ARN (section 2.2-2.4).
//
// IAM-903: a partial wildcard ('*'/'?') INSIDE an AWS Principal-element ARN
// (e.g. arn:aws:iam::123456789012:role/application/*, .../role/app-*,
// arn:aws:iam::*:role/*) is an INVALID pattern - the IAM Principal element does
// not support wildcard matching of a principal name/ARN; the ONLY wildcard a
// Principal accepts is the standalone "*" (already typed 'anonymous' above).
// AWS rejects a partial-wildcard principal ARN at save time, so it can neither be
// a specific principal nor be expanded into "every role in the path". Type it
// distinctly ('aws-principal-arn-wildcard') so findingsForStatement fails it
// closed (an invalid/coverage-warning finding, never a plain TRUST-CROSS-ACCOUNT
// high) instead of silently over-trusting an unbounded set. A wildcard in an
// aws:PrincipalArn CONDITION value is a DIFFERENT, VALID construct and is handled
// in conditionSignals, not here.
export function awsPrincipalType(v) {
  const s = String(v);
  if (s === '*') return 'anonymous';
  // A partial wildcard must be tested BEFORE the account-root / bare-account
  // shapes below: an ARN carrying a '*'/'?' anywhere (e.g. a wildcarded account
  // field in arn:aws:iam::*:root, or arn:aws:iam::123456789012:role/app-*) is an
  // INVALID Principal-element pattern regardless of how it ends. Testing :root$
  // first would mis-type arn:aws:iam::*:root as a VALID whole-account 'aws-root'
  // delegation and silently over-trust it, defeating the IAM-903 fail-closed
  // handling. The bare 12-digit account form (^\d{12}$) can never contain a glob,
  // so this reorder only ever reclassifies otherwise-invalid wildcard ARNs.
  if (hasGlob(s)) return 'aws-principal-arn-wildcard';
  if (/:root$/i.test(s)) return 'aws-root';
  if (/^\d{12}$/.test(s)) return 'aws-account';
  return 'aws-principal-arn';
}

// Service principal -> typed form. IAM-1006: a partial wildcard ('*'/'?') in a
// Service principal member is INVALID and fails closed exactly like a
// wildcard AWS Principal ARN. An AWS Service principal is an EXACT service
// identifier (e.g. lambda.amazonaws.com); the Principal element does NOT
// wildcard-match service names, so a member such as ec2-*.amazonaws.com matches
// no service and grants no service-role relationship. Typing it distinctly
// ('service-wildcard') routes it through the fail-closed handling in
// findingsForStatement instead of presenting a never-matching member as a
// normal, complete service trust.
export function serviceType(v) {
  return hasGlob(String(v)) ? 'service-wildcard' : 'service';
}

// Federated principal -> OIDC vs SAML (section 2.6/2.7). The four built-in OIDC
// providers are bare hostnames (not ARNs) and are treated as OIDC.
//
// IAM-1006: a partial wildcard ('*'/'?') in a Federated principal member (e.g.
// arn:aws:iam::123456789012:oidc-provider/*) is INVALID and fails closed like a
// wildcard AWS Principal ARN. A Federated principal is a SPECIFIC identity-
// provider ARN (an IAM OIDC/SAML provider) or a built-in OIDC hostname; the
// Principal element does not wildcard-match provider ARNs, so a globbed member
// matches no provider and establishes no federated trust. Type it distinctly
// ('federated-wildcard') so it is failed closed, not shown as a complete trust.
export function federatedType(v) {
  const s = String(v).toLowerCase();
  if (hasGlob(String(v))) return 'federated-wildcard';
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
