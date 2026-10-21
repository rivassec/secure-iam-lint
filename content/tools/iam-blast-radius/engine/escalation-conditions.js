// escalation-conditions.js - condition operator/service helpers. Extracted (behavior-preserving).
import { globMatch } from './glob.js';
import { CHINA_SERVICE_PRINCIPALS } from './escalation-catalogs.js';

// Partition sentinel: not asserted and no ARN evidence either way.
export const UNASSERTED_PARTITION = 'unasserted';

// Extract every Condition entry that binds iam:PassedToService (case-insensitive
// key), preserving the OPERATOR it appears under - the operator decides whether
// the values are an allowlist (StringEquals/StringLike) or a denylist
// (StringNotEquals/StringNotLike). Returns [{ op, values[] }]. Values are inert
// strings, only ever glob-compared to a service principal.
export function passedToServiceEntries(condition) {
  const entries = [];
  if (!condition || typeof condition !== 'object') return entries;
  for (const op of Object.keys(condition)) {
    const block = condition[op];
    if (!block || typeof block !== 'object') continue;
    for (const key of Object.keys(block)) {
      if (key.toLowerCase() !== 'iam:passedtoservice') continue;
      const values = [];
      const v = block[key];
      if (typeof v === 'string') values.push(v);
      else if (Array.isArray(v)) {
        for (const item of v) if (typeof item === 'string') values.push(item);
      }
      entries.push({ op, values });
    }
  }
  return entries;
}

// Normalize a condition operator to its base form: drop the set qualifier
// (ForAnyValue:/ForAllValues:) and the ...IfExists suffix so StringEquals,
// ForAnyValue:StringEquals and StringEqualsIfExists all classify the same.
export function normalizeOperator(op) {
  let o = String(op).toLowerCase();
  o = o.replace(/^forany(value)?:/, '').replace(/^forall(values)?:/, '');
  o = o.replace(/ifexists$/, '');
  return o;
}

// Given one PassedToService condition entry (operator + values), does it permit
// passing a role to `principal`? Returns 'permit' | 'deny' | 'uncertain'.
//   - Allowlist operators (StringEquals/StringLike, case-insensitive variants):
//     permit iff a value glob-matches the principal, else deny (only the listed
//     services may receive the role).
//   - Denylist operators (StringNotEquals/StringNotLike): permit iff NO value
//     matches (may pass to any service EXCEPT the listed ones).
//   - Null and any unrecognized operator: uncertain (cannot resolve from text;
//     do NOT assume allowlist semantics, which would invert the meaning).
// `partition` is the asserted token, or null when none was asserted / it was unrecognized.
export function operatorPermitsService(op, values, principal, partition = 'aws') {
  const base = normalizeOperator(op);
  const p = String(principal).toLowerCase();
  // Stage-14 CRITICAL: AWS folds the VALUE only for the *IgnoreCase base operators.
  // The plain and negated operators (StringEquals/StringNotEquals/StringLike/
  // StringNotLike/Arn(Not)Equals/Arn(Not)Like) are CASE-SENSITIVE on the value. Folding
  // the value for the NEGATED operators was a critical fail-open: an UPPERCASE denylist
  // value ("LAMBDA.AMAZONAWS.COM") over-matched the canonical lowercase principal, was
  // misread as a real deny, and SUPPRESSED a genuine PassRole escalation (read CLEAN).
  // The service principal `p` is itself canonical lowercase, so a case-sensitive value
  // match against it is exactly AWS's comparison. (Folding the value for the ALLOWLIST
  // operators only ever OVER-reported a permit -> fail-closed/safe; only the denylist
  // direction was fail-open. We fold exactly where AWS folds.)
  const ignoreCase = base === 'stringequalsignorecase' || base === 'stringnotequalsignorecase';
  const fold = (v) => (ignoreCase ? String(v).toLowerCase() : String(v));
  // Only Like/Arn* expand wildcards; (Not)Equals compares literally (R1-01).
  const glob = base === 'stringlike' || base === 'stringnotlike' || base.startsWith('arn');
  const hit = (v, t) => (glob ? globMatch(fold(v), t) : fold(v) === t);
  // Candidate spellings AWS might send (R2-01/R2-02, F2-08). China docs say some
  // services use .amazonaws.com.cn "instead of or in addition to" the canonical
  // form, so a pin never proves a sole spelling: under aws-cn (and null) BOTH arms
  // consider both spellings - the allow arm matches either (an unmatched allow
  // drops a grant, fail-open), and a deny counts only when it covers both.
  // UNASSERTED_PARTITION keeps Stage-18 deny semantics (canonical only).
  const pinnedCn = CHINA_SERVICE_PRINCIPALS[p];
  const wideSet = [p, pinnedCn || `${p}.cn`];
  const known = partition && partition !== UNASSERTED_PARTITION;
  const allowCandidates = partition === 'aws-cn' ? wideSet : (known ? [p] : wideSet);
  const candidates = partition === 'aws-cn' ? wideSet : (partition === null ? wideSet : [p]);
  // ${...} is caller-controlled and may resolve to the principal (T2-1).
  // ${*} ${?} ${$} are literal ESCAPES, not variables (R1-04): strip them before
  // the variable test. The escaped char never occurs in a service principal, so a
  // value carrying one can never match any candidate (both arms).
  const ESC_RE = /\$\{[*?$]\}/;
  const VAR_RE = /\$\{[^}]*\}/;
  const isVar = (v) => VAR_RE.test(String(v).replace(new RegExp(ESC_RE, 'g'), ''));
  const match = (v, t) => !ESC_RE.test(String(v)) && hit(v, t);
  const concrete = values.filter((v) => !isVar(v));
  const anyVar = concrete.length !== values.length;
  const covered = candidates.filter((c) => concrete.some((v) => match(v, c)));
  const matchAllow = anyVar || allowCandidates.some((c) => concrete.some((v) => match(v, c)));
  // Stage-17: a BYPASSABLE qualifier - an `...IfExists` suffix or a `ForAllValues:` set prefix -
  // makes the condition TRUE when the request key is ABSENT (IfExists) or the request set is
  // EMPTY (ForAllValues, vacuous truth). AWS therefore does NOT honor it as a real restriction:
  // the role can still be passed to a service that never populates iam:PassedToService. So an
  // ALLOWLIST operator carrying such a qualifier can never yield a definitive `deny` - crediting
  // it as one dropped the only permitting PassRole statement and read a real escalation CLEAN
  // (fail-open). Degrade the would-be `deny` to `uncertain`, matching how conditions.js /
  // trust-conditions.js / resource-conditions.js already refuse to credit these as narrowing.
  // (ForAnyValue: is NOT bypassable - vacuously FALSE over an empty set - and plain operators are
  // unaffected, so both keep their real `deny`.)
  const bypassable = /ifexists$/i.test(String(op)) || /^forall(values)?:/i.test(String(op));
  switch (base) {
    case 'stringequals':
    case 'stringequalsignorecase':
    case 'stringlike':
    case 'arnequals':
    case 'arnlike':
      return matchAllow ? 'permit' : (bypassable ? 'uncertain' : 'deny');
    case 'stringnotequals':
    case 'stringnotequalsignorecase':
    case 'stringnotlike':
    case 'arnnotequals':
    case 'arnnotlike':
      // Deny only when every candidate spelling is covered; partial coverage is uncertain.
      // Stage-18: deliberately ignores `bypassable` (a full-cover deny is a genuine AWS deny).
      if (covered.length === candidates.length) return 'deny';
      return covered.length > 0 ? 'uncertain' : 'permit';
    default:
      // Null, Date*, Bool, and anything unrecognized: meaning cannot be
      // determined from the policy text -> uncertain.
      return 'uncertain';
  }
}

// Does a PassRole statement's PassedToService condition permit passing a role to
// service principal `principal`? AWS ANDs multiple condition operators together,
// so a single operator that forbids this service blocks it. Returns:
//   { permits: boolean, pinned: boolean, uncertain: boolean }
//   - pinned=false  : no PassedToService condition -> can pass to ANY service
//                     (subject to the role's own trust policy, unknown here).
//   - pinned=true   : condition present; permits reflects allow/deny-list logic.
//   - uncertain=true: an operator (e.g. Null / unsupported) could not be
//                     resolved from the policy text; the path is kept but its
//                     confidence is reduced rather than asserting a false result.
export function passRolePermitsService(condition, principal, partition = 'aws') {
  const entries = passedToServiceEntries(condition);
  if (entries.length === 0) return { permits: true, pinned: false, uncertain: false };
  let uncertain = false;
  for (const e of entries) {
    const disp = operatorPermitsService(e.op, e.values, principal, partition);
    // A definitive deny under any AND-ed operator blocks this service outright.
    if (disp === 'deny') return { permits: false, pinned: true, uncertain: false };
    if (disp === 'uncertain') uncertain = true;
  }
  return { permits: true, pinned: true, uncertain };
}

export function hasNonEmptyCondition(stmt) {
  return (
    stmt.condition !== null &&
    stmt.condition !== undefined &&
    typeof stmt.condition === 'object' &&
    Object.keys(stmt.condition).length > 0
  );
}
