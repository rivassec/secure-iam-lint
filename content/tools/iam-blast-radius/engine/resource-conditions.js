// resource-conditions.js - principal-scoping + selector/inventory/composition analysis of resource-policy condition blocks. Extracted (behavior-preserving).
import { chargeWork } from './glob.js';
import { parseOperator, NEGATED_OPERATORS } from './conditions.js';
import { RESOURCE_SERVICES } from './resource-catalogs.js';
import { selfReferenceKeys, substitutePolicyVars, toValues } from './trust-conditions.js';
import { accountOrOrgValueNarrows, isAllGlobOrEmpty } from './trust-principal-helpers.js';

// Every AWS condition operator base (after ForAllValues:/ForAnyValue: and IfExists).
export const KNOWN_CONDITION_OPERATORS = Object.freeze(new Set([
  'stringequals', 'stringnotequals', 'stringequalsignorecase', 'stringnotequalsignorecase',
  'stringlike', 'stringnotlike',
  'numericequals', 'numericnotequals', 'numericlessthan', 'numericlessthanequals',
  'numericgreaterthan', 'numericgreaterthanequals',
  'dateequals', 'datenotequals', 'datelessthan', 'datelessthanequals',
  'dategreaterthan', 'dategreaterthanequals',
  'bool', 'binaryequals', 'ipaddress', 'notipaddress',
  'arnequals', 'arnlike', 'arnnotequals', 'arnnotlike', 'null',
]));

// T2-4: operators/blocks the resource evaluator cannot read (no policy text echoed). An unknown operator
// would otherwise fall through as "positive" and be credited as narrowing.
export function conditionShapeProblems(condition) {
  if (condition === null || condition === undefined) return [];
  if (typeof condition !== 'object' || Array.isArray(condition)) return ['a malformed Condition block'];
  const out = [];
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) out.push('a malformed operator block');
    else if (!KNOWN_CONDITION_OPERATORS.has(parseOperator(op).base)) out.push('an unknown operator');
  }
  return out;
}

const ACCOUNT_LIKE_KEYS = new Set(['aws:principalaccount', 'aws:sourceaccount', 'aws:principalorgid', 'kms:calleraccount']);

// T2-5: does this value actually narrow the scoping key? ${...} reads as '*'.
// An ARN narrows only with a concrete account, or (account-less) a literal resource.
function scopingValueNarrows(keyLower, raw) {
  const s = substitutePolicyVars(raw);
  if (ACCOUNT_LIKE_KEYS.has(keyLower)) return accountOrOrgValueNarrows(s);
  if (keyLower === 'aws:principalarn' || keyLower === 'aws:sourcearn') {
    const segs = s.split(':');
    if (segs.length < 6 || segs[0].toLowerCase() !== 'arn') return false;
    const account = segs[4];
    const resource = segs.slice(5).join(':');
    if (/^[0-9]{12}$/.test(account)) return true;
    return account === '' && resource !== '' && !/[*?]/.test(resource);
  }
  return !isAllGlobOrEmpty(s);
}

export const PRINCIPAL_SCOPING_KEYS = Object.freeze(new Set([
  'aws:principalarn',
  'aws:principalaccount',
  'aws:principalorgid',
  'aws:principalorgpaths',
  'aws:principaltype',
  'aws:userid',
  'aws:sourceaccount',
  'aws:sourcearn',
]));

// KMS-ONLY principal-account scoping key (IAM-1403; per-service semantics section
// 3.3). kms:CallerAccount pins the CALLER'S ACCOUNT ("all identities in an AWS
// account"): combined with Principal:"*" it narrows the grant to all authenticated
// identities in the named account, exactly like aws:PrincipalAccount. It is credited
// as narrowing ONLY on a kms-key policy - it is a KMS-specific key and is never
// treated as scoping on S3/SNS/SQS. Note kms:ViaService is deliberately NOT here: it
// pins the SERVICE CHANNEL, not the caller, so it never narrows WHO may act (trap 2).
export const KMS_PRINCIPAL_SCOPING_KEYS = Object.freeze(new Set([
  'kms:calleraccount',
]));

// True when a condition key names a principal-identity scoping key. aws:PrincipalTag
// is written as `aws:PrincipalTag/<tag-key>` (the tag name is a suffix), so it is
// matched by prefix; every other scoping key is an exact match. Case-insensitive.
// `service` (optional) credits the service-specific principal-account key set: on a
// kms-key policy, kms:CallerAccount narrows WHO (the KMS analog of
// aws:PrincipalAccount); it is never credited on any other service.
export function isPrincipalScopingKey(keyLower, service) {
  if (PRINCIPAL_SCOPING_KEYS.has(keyLower)) return true;
  if (keyLower.startsWith('aws:principaltag/')) return true;
  if (service === RESOURCE_SERVICES.KMS_KEY && KMS_PRINCIPAL_SCOPING_KEYS.has(keyLower)) return true;
  return false;
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
export function operatorNegatesScope(operator, value) {
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
// which reads "everyone EXCEPT ..." and does not exclude anonymous). Lists are
// original-cased, sorted, deduped. A wildcard inside e.g. aws:PrincipalArn is a valid
// condition value, not a partial-ARN principal wildcard (test 85), but a value that
// narrows nothing lands in openKeys (T2-5).
// `ignore` (lowercased keys): vacuous guards (J-4) that neither narrow nor expand.
export function principalScopingAnalysis(condition, service, ignore = null) {
  const scoping = new Set();
  const expanding = new Set();
  const bypassing = new Set();
  // T2-5: a positive match whose value narrows nothing (*, ${...}, Null:false).
  const open = new Set();
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) {
    return { scopingKeys: [], expansionKeys: [], bypassKeys: [], openKeys: [], tautologyKeys: [] };
  }
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    const keys = Object.keys(inner);
    // S3-dos-budget-all (defense in depth): charge per condition key inspected so this
    // linear-today scan participates in the cooperative work budget and a future
    // superlinear regression fails CLOSED rather than grinding uncharged (T5/T8).
    chargeWork(keys.length);
    // A ...IfExists suffix or a ForAllValues: set qualifier PASSES when the key is
    // ABSENT, so a POSITIVE principal match it carries is trivially bypassed by a
    // caller who omits the key: it does NOT restrict anonymous/unauthenticated access
    // and MUST NOT be credited as narrowing (mirrors the source-binding guard in
    // resource-source-binding.js and the trust family). A NEGATED bypassable operator
    // (e.g. StringNotEqualsIfExists) is already routed to expansion by
    // operatorNegatesScope below - its parseOperator base is a NEGATED op - so it stays
    // critical; only the positive-but-bypassable case is diverted here.
    const lowerOp = String(op).toLowerCase();
    const bypassable = lowerOp.includes('ifexists') || lowerOp.startsWith('forallvalues:');
    const isNull = parseOperator(op).base === 'null';
    for (const key of keys) {
      const keyLower = String(key).toLowerCase();
      if (!isPrincipalScopingKey(keyLower, service)) continue;
      if (ignore && ignore.includes(keyLower)) continue;
      if (operatorNegatesScope(op, inner[key])) expanding.add(key);
      else if (bypassable) bypassing.add(key);
      else if (isNull) open.add(key); // Null:false only asks the key exist
      else if (!/^(string|arn)/.test(parseOperator(op).base)) open.add(key); // V1-7: numeric/date/binary ranges pin nothing
      else {
        const vals = toValues(inner[key]);
        chargeWork(vals.length);
        if (vals.length > 0 && vals.every((v) => scopingValueNarrows(keyLower, v))) scoping.add(key);
        else open.add(key);
      }
    }
  }
  const scopingKeys = [...scoping].sort();
  const scopingSet = new Set(scopingKeys);
  return {
    scopingKeys,
    expansionKeys: [...expanding].sort(),
    bypassKeys: [...bypassing].sort(),
    openKeys: [...open].filter((k) => !scopingSet.has(k)).sort(),
    tautologyKeys: selfReferenceKeys(condition),
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
export const NETWORK_SELECTOR_KEYS = Object.freeze(new Set([
  'aws:sourcevpce', 'aws:sourcevpc', 'aws:sourceip', 'aws:vpcsourceip',
]));

// The role a condition key plays in the composition sentence: 'network' (a
// network/transport selector), 'principal' (a principal-identity scoping key), or
// 'other'. keyLower is already lowercased.
export function selectorCategory(keyLower) {
  if (NETWORK_SELECTOR_KEYS.has(keyLower)) return 'network';
  if (isPrincipalScopingKey(keyLower)) return 'principal';
  return 'other';
}

// Inventory the DISTINCT condition keys across every operator in a Condition block,
// recording for each whether it lists multiple values (OR-within-values) and which
// selector category it plays. Deterministic: deduped by lowercased key, first
// occurrence's original casing kept, sorted by original key. Returns [] for an
// empty/absent/non-object condition.
export function conditionKeyInventory(condition) {
  const byKey = new Map();
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return [];
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    const rawKeys = Object.keys(inner);
    // S3-dos-budget-all (defense in depth): charge per condition key inventoried so
    // this linear-today scan participates in the cooperative work budget.
    chargeWork(rawKeys.length);
    for (const rawKey of rawKeys) {
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
export function describeConditionComposition(condition) {
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

// R6-1: keys set only on service-to-service requests; absent when an IAM principal calls.
const SOURCE_ONLY_KEYS = new Set(['aws:sourceorgpaths', 'aws:sourceorgid', 'aws:sourceaccount', 'aws:sourcearn']);
// A ForAllValues: guard on a source-only key in a statement with no service principal is
// vacuously true (ForAllValues over an absent key passes), so it constrains nothing.
export function vacuousSourceGuards(stmt) {
  const cond = stmt && stmt.condition;
  if (!cond || typeof cond !== 'object' || Array.isArray(cond)) return [];
  const p = stmt.principal;
  if (p && p.byType && Array.isArray(p.byType.Service) && p.byType.Service.length > 0) return [];
  const byKey = new Map();
  for (const op of Object.keys(cond)) {
    const inner = cond[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    for (const k of Object.keys(inner)) {
      const kl = k.toLowerCase();
      if (!SOURCE_ONLY_KEYS.has(kl)) continue;
      const all = byKey.get(kl) ?? true;
      byKey.set(kl, all && op.toLowerCase().startsWith('forallvalues:'));
    }
  }
  return [...byKey.entries()].filter(([, v]) => v).map(([k]) => k).sort();
}

// R6-1/J-2: the ARNs a positive exact aws:PrincipalArn pin names (concrete, no IfExists / set
// operator), or null. A negated PrincipalArn entry that matches a pinned ARN contradicts it: null.
export function exactPrincipalArnPin(condition) {
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return null;
  let pins = null;
  const negs = [];
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    const ol = op.toLowerCase();
    for (const k of Object.keys(inner)) {
      if (k.toLowerCase() !== 'aws:principalarn') continue;
      const vals = toValues(inner[k]).map(String);
      if (NEGATED_OPERATORS.has(parseOperator(op).base)) { negs.push(...vals); continue; }
      if (!['arnequals', 'stringequals'].includes(ol)) continue;
      if (vals.length > 0 && vals.every((v) => /^arn:[a-z-]+:(iam|sts)::\d{12}:[^*?$]+$/.test(v))) pins = vals;
    }
  }
  if (!pins) return null;
  const hit = (pat, v) => new RegExp(`^${pat.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`).test(v);
  return pins.some((v) => negs.some((n) => hit(n, v))) ? null : pins;
}

// R6-2: principal-only keys, absent on a call made by an AWS service principal.
const PRINCIPAL_ONLY_KEY = (k) => ['aws:principalorgid', 'aws:principalorgpaths', 'aws:principalaccount',
  'aws:principalarn', 'aws:principaltype'].includes(k) || k.startsWith('aws:principaltag/');
// A statement whose principals are all Service principals, gated by a principal-only key under an
// operator that is false on an absent key (positive, no IfExists, not ForAllValues; or Null "false"),
// never matches: it is inert. Returns the inert keys, or [].
export function inertServiceStatement(stmt) {
  const p = stmt && stmt.principal;
  const by = p && p.byType ? p.byType : null;
  if (!by || p.anyPrincipal) return [];
  const types = Object.keys(by).filter((k) => Array.isArray(by[k]) && by[k].length > 0);
  if (types.length !== 1 || types[0] !== 'Service') return [];
  const cond = stmt.condition;
  if (!cond || typeof cond !== 'object' || Array.isArray(cond)) return [];
  const out = new Set();
  for (const op of Object.keys(cond)) {
    const inner = cond[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    const po = parseOperator(op);
    if (po.ifExists || po.setOperator === 'ForAllValues') continue;
    for (const k of Object.keys(inner)) {
      const kl = k.toLowerCase();
      if (!PRINCIPAL_ONLY_KEY(kl)) continue;
      const vals = toValues(inner[k]).map((v) => String(v).toLowerCase());
      if (po.base === 'null') { if (vals.length === 1 && vals[0] === 'false') out.add(kl); continue; }
      if (NEGATED_OPERATORS.has(po.base)) continue; // a negated match is TRUE on an absent key
      if (/^(string|arn)/.test(po.base)) out.add(kl);
    }
  }
  return [...out].sort();
}
