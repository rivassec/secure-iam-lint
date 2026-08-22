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
  // Selectors - pick which service / resource / encryption-context is in play.
  // A selector changes SCOPE; it is not automatically a guardrail, so it is
  // never credited as narrowing here (the escalation engine decides direction,
  // e.g. iam:PassedToService pinned to a non-matching service blocks a path).
  'iam:passedtoservice': { class: CONDITION_CLASS.SELECTOR, role: 'service', label: 'PassRole target service' },
  'iam:associatedresourcearn': { class: CONDITION_CLASS.SELECTOR, role: 'resource', label: 'Associated resource ARN' },
  'kms:viaservice': { class: CONDITION_CLASS.SELECTOR, role: 'service', label: 'KMS calling service' },
});

// Base operators (after stripping set qualifier + IfExists) whose match is
// NEGATED - "everything EXCEPT the listed values" - so they broaden rather than
// restrict when used to gate an Allow.
const NEGATED_OPERATORS = new Set([
  'stringnotequals',
  'stringnotequalsignorecase',
  'stringnotlike',
  'arnnotequals',
  'arnnotlike',
  'numericnotequals',
  'datenotequals',
  'notipaddress',
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

// A value that does not constrain: the bare wildcard "*". (We deliberately do
// NOT try to interpret "0.0.0.0/0" or other value-level all-encompassing forms -
// that is request-context reasoning we do not claim.)
function hasWildcardValue(values) {
  return values.some((v) => v === '*');
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
 * @returns {object} frozen classification record
 */
export function classifyConditionEntry(operator, key, value) {
  const { base, setOperator, ifExists } = parseOperator(operator);
  const keyStr = String(key);
  const keyLower = keyStr.toLowerCase();
  const values = toValueArray(value);
  const known = Object.prototype.hasOwnProperty.call(KNOWN_KEYS, keyLower);
  const meta = known ? KNOWN_KEYS[keyLower] : null;

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
  } else {
    cls = meta.class;
    if (cls === CONDITION_CLASS.CONSTRAINT) {
      notes.push(`appears to narrow by ${meta.label}`);
    } else {
      notes.push(`appears to select by ${meta.label}`);
    }
    // Credit a constraint only when it reads as a dependable guardrail.
    credited = cls === CONDITION_CLASS.CONSTRAINT;
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
    notes.push('ForAllValues matches when the key is absent, so it may not constrain a request that omits the key');
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
    for (const op of operators) {
      const block = condition[op];
      if (!block || typeof block !== 'object' || Array.isArray(block)) continue;
      const keys = Object.keys(block).sort();
      for (const key of keys) {
        entries.push(classifyConditionEntry(op, key, block[key]));
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
