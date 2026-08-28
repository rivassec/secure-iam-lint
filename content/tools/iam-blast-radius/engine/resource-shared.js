// resource-shared.js - shared low-level resource helpers (enumeratePrincipals, accountOfEntry, transport-only Deny detection) used by both resourceFindings and the per-service rule modules. Extracted (behavior-preserving).
import { classifyPrincipals } from './trust.js';
import { parseArn } from './arn-util.js';

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
export function accountOfEntry(entry) {
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
export function isTransportOnlyCondition(condition) {
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

// Whether the policy contains a Deny whose ONLY gate is aws:SecureTransport - the
// transport-vs-identity crux of test 28. Used to ANNOTATE a public-access finding
// (the transport Deny does NOT neutralize it), never to suppress the finding.
export function hasTransportOnlyDeny(model) {
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  return statements.some(
    (s) => s && s.effect === 'Deny' && isTransportOnlyCondition(s.condition),
  );
}
