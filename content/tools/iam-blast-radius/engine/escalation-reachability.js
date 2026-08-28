// escalation-reachability.js - the pass-role/assume REACHABILITY analysis: role-target parsing, partition/account reachability, and principal-pin satisfiability. Co-located as ONE module (per REFACTOR decision D2) because role-targets <-> role-coverage <-> pins are a strongly-connected cluster; splitting them created an import cycle. Extracted (behavior-preserving).
import { globMatch, chargeWork } from './glob.js';
import { parseOperator } from './conditions.js';
import { assumeScopeIsAllRoles } from './escalation-scope.js';
import { PASS_ROLE_SERVICES, CONCRETE_ACCOUNT_ID_RE } from './escalation-catalogs.js';

// S2-crossaccount-scoped-surface (A): the concrete 12-digit account a SCOPED role
// ARN targets, or null. Returns non-null ONLY for a concrete single-role ARN
// (isConcreteRoleArn) whose account field is a bare 12-digit id - a wildcard/other
// account axis is the broad ASSUME-ROLE-EXPANSION shape (handled there), and a
// non-12-digit account cannot be soundly compared across the account boundary.
// Pure string parse of inert policy data; never interpreted as code.
export function concreteRoleTargetAccount(resource) {
  if (!isConcreteRoleArn(resource)) return null;
  const parts = String(resource).split(':');
  if (parts.length < 6) return null;
  const account = parts[4];
  return CONCRETE_ACCOUNT_ID_RE.test(account) ? account : null;
}

// IAM-902: is `r` a CONCRETE role ARN (names one specific role, no wildcard)?
// A takeover chain is only asserted when the three primitives target the exact
// same named role. A wildcard role scope (arn:aws:iam::*:role/*, role/*, a bare
// "*", or any partial wildcard) is a DIFFERENT, broader shape - it is the
// province of ASSUME-ROLE-EXPANSION / the wildcard rules, not this same-role
// correlation - so it is excluded here (never expand a wildcard into "the same
// role"). Determinism: pure string test, no regex compiled from input.
export function isConcreteRoleArn(r) {
  const s = String(r == null ? '' : r);
  if (s.includes('*') || s.includes('?')) return false;
  return s.includes(':role/');
}

// suite-3 test 74: does a modify-leg resource COVER the concrete assumable role
// `role`? True for an exact match, or for a role-ARN wildcard pattern
// (arn:...:role/deployment/*) that subsumes the concrete role
// (arn:...:role/deployment/Prod). Only role-ARN patterns subsume roles - a bare
// "*" or a non-role ARN pattern is NOT treated as a same-role modify grant here
// (it stays the broader wildcard/expansion shape), so the takeover is never
// generalized to roles the modify leg does not actually name. ARN matching is
// case-sensitive (IAM resource ARNs are), so globMatch is used directly.
export function resourceCoversRole(resource, role) {
  const s = String(resource == null ? '' : resource);
  // S3-dos-budget-all: charge at entry. Three of the four branches below return
  // WITHOUT reaching globMatch (the exact-equality, non-role-ARN, and no-wildcard
  // early-returns), so a nested anchorRoles x legs x resources filter loop that hits
  // those branches accrued ZERO budget. Charge proportional to the token length so
  // the traversal is sampled even when the matcher is never called.
  chargeWork(s.length + 1);
  if (s === role) return true;
  if (!s.includes(':role/')) return false;
  if (!s.includes('*') && !s.includes('?')) return false;
  return globMatch(s, role);
}

// role-takeover test 142: a MAXIMALLY-BROAD assume scope ("all roles across
// arbitrary accounts") is the ASSUME-ROLE-EXPANSION shape, NOT a same-role
// takeover confirmation - even though it glob-covers any concrete role. Both axes
// must be fully open: the account field is arbitrary (wildcarded/empty) AND the
// role-name segment is exactly "*" (or the bare "*" / "role/*" shorthands). A
// scope pinned to a concrete account (arn:aws:iam::123456789012:role/deployment/*)
// or a specific role-name path is BOUNDED and DOES confirm an anchor a
// permission-grant/trust-modify leg names concretely (the C2 wildcard-assume
// mirror of test 74). Mirrors assumeScopeIsAllRoles(), evaluated per-resource so a
// concrete member in the same statement still confirms.
export function isAllRolesAssumeScope(resource) {
  const s = String(resource == null ? '' : resource);
  if (s === '*') return true;
  if (s === 'role/*') return true; // bare shorthand
  const marker = ':role/';
  const idx = s.lastIndexOf(marker);
  if (idx === -1) return false;
  if (s.slice(idx + marker.length) !== '*') return false; // role-name not fully open
  const parts = s.split(':');
  if (parts.length < 6) return false;
  const account = parts[4];
  return account === '' || account.includes('*') || account.includes('?'); // arbitrary account
}

// suite-3 test 91: the specific (non-wildcard) AWS account IDs a set of role
// ARNs pins in the account field of arn:aws:iam::<account>:role/... . Used to
// caveat a PassRole path: iam:PassRole passes a role only to a service in the
// SAME account as the role, so a path through an account-pinned role is viable
// only when the workload/principal runs in that same account - which a single
// identity policy does not establish. A wildcarded account segment yields no
// specific account and no caveat.
export function specificAccountsInRoleArns(resources) {
  // S3-dos-budget-all (iter-7): this dedup runs over a PassRole statement's Resource
  // list (validate.js caps it at MAX_RESOURCES=10000, still attacker-sized) and is
  // invoked once per service inside the PASS_ROLE_SERVICES loop (8x amplification via
  // the call site at ~line 1244). The old `accts.includes(m[1])` push made it O(R^2)
  // Array-scan-in-a-push-loop and reached NO matcher, so the deterministic work budget
  // (sampled ONLY inside chargeWork) accrued ZERO on this path: a within-caps PassRole
  // target list of many DISTINCT-account role ARNs ground for seconds yet returned a
  // COMPLETE verdict, and the Node wall-clock deadline (also sampled only in chargeWork)
  // was blind (the T5/T8 fail-open DoS class). A Set makes membership O(1) (traversal
  // O(R)), and charging one unit per resource inspected makes both ceilings SAMPLE the
  // traversal so a runaway fails CLOSED (aborted+incomplete) instead of grinding.
  // Mirrors the resource.js sourceAccountSet / trust.js iter-5 Set+charge fixes.
  const list = Array.isArray(resources) ? resources : [];
  chargeWork(list.length);
  const accts = [];
  const seen = new Set();
  for (const r of list) {
    const s = String(r == null ? '' : r);
    const m = /^arn:aws:iam::([0-9]{1,20}):role\//.exec(s);
    if (m && !seen.has(m[1])) {
      seen.add(m[1]);
      accts.push(m[1]);
    }
  }
  return accts.sort();
}

// --- Partition-aware PassRole target parsing (IAM-1102 / T91) -----------------
// iam:PassRole passes a role only to a service in the SAME account AND the SAME
// partition as the role; the service launch runs in the CALLER's account +
// partition. Reasoning about cross-account/cross-partition viability therefore
// needs the role ARN's partition and account, not just the account. Any partition
// (aws / aws-us-gov / aws-cn / ...) is captured, unlike the aws-only helpers above.
export const ROLE_ARN_PARTS_RE = /^arn:([^:]*):iam::([^:]*):role\/(.*)$/i;

// Classify one PassRole RESOURCE token. Returns exactly one shape:
//   { star:true }                    -> "*" (reaches any account/partition)
//   { other:true }                   -> not a role ARN we can pin (conservative)
//   { partition, account, path, raw} -> a role ARN (account/partition may be "*")
export function parsePassResource(r) {
  const s = String(r == null ? '' : r);
  if (s === '*') return { star: true, raw: s };
  const m = ROLE_ARN_PARTS_RE.exec(s);
  if (!m) return { other: true, raw: s };
  return { partition: m[1], account: m[2], path: m[3], raw: s };
}

export function partitionReaches(resPartition, subjectPartition) {
  return resPartition === subjectPartition || String(resPartition).includes('*');
}

export function accountReaches(resAccount, subjectAccount) {
  return String(resAccount).includes('*') || resAccount === subjectAccount;
}

// The AWS partitions the engine can reason about. MIRRORS scan.mjs KNOWN_PARTITIONS
// (kept in lock-step). Matched case-SENSITIVELY against the canonical lowercase ARN
// tokens: a case/whitespace variant ("AWS", " aws", "aws\t") is deliberately NOT a
// member, so it is treated as UNMODELABLE and fails closed rather than being trusted
// for a confident cross-partition demotion.
export const KNOWN_PARTITIONS = Object.freeze(new Set([
  'aws', 'aws-us-gov', 'aws-cn',
  'aws-iso', 'aws-iso-b', 'aws-iso-e', 'aws-iso-f',
]));

// S2-passrole-allstmts (ARN-spelling axis): a PassRole target ARN's partition and
// account tokens are extracted with a LENIENT, case-insensitive regex, so they can
// carry a non-canonical spelling (uppercase/mixed-case partition, embedded
// whitespace/tab, a non-12-digit account). The viability compare (resourceReachesSubject
// -> partitionReaches/accountReaches) uses EXACT string equality, so any such
// non-canonical SAME-account role reads as cross-account/cross-partition and would be
// confidently demoted (critical->medium) and slip under the exit gate as CLEAN - the
// exact fail-open the ordering fix closed, reached via spelling. A token is
// "modelable" only when we can compare it with confidence: a partition must be a
// recognized AWS partition (or a "*" wildcard that reaches any partition); an account
// must be a bare 12-digit id (or a "*" wildcard that reaches any account). Anything
// else is UNMODELABLE -> its viability is UNKNOWN and must fail closed, never demote.
export function partitionModelable(resPartition) {
  const s = String(resPartition);
  if (s.includes('*')) return true; // wildcard reaches any partition
  return KNOWN_PARTITIONS.has(s); // canonical, case-sensitive only
}

// Is the SUBJECT's OWN partition a CONFIDENTLY-known canonical AWS partition?
// (S2-passrole-allstmts, SUBJECT axis.) Deliberately STRICTER than the role-ARN
// partitionModelable(): a principal lives in exactly ONE partition, so a bare "*" is
// AMBIGUOUS for the subject (not "any") and is NOT accepted; a non-canonical spelling
// ('AWS', 'Aws', 'aws-gov', 'AWS-US-GOV', embedded case/whitespace) is likewise unknown.
// An unknown subject partition must NEVER drive a confident cross-partition PassRole
// demotion (it fails closed as unknown-viability instead) - the demoting exact-equality
// compare is only trustworthy when BOTH sides are canonical.
export function subjectPartitionKnown(token) {
  return KNOWN_PARTITIONS.has(String(token));
}

export function accountModelable(resAccount) {
  const s = String(resAccount);
  if (s.includes('*')) return true; // wildcard reaches any account
  return CONCRETE_ACCOUNT_ID_RE.test(s); // bare 12-digit only
}

// A LENIENT, case-insensitive IAM-ARN matcher (no ':role/' requirement, unlike
// ROLE_ARN_PARTS_RE) used ONLY to recover the partition/account of an {other}-shaped
// token so its MODELABILITY can be judged. Captures partition, account, and the trailing
// identifier of any arn:<p>:iam::<a>:<id>.
export const IAM_ARN_LENIENT_RE = /^arn:([^:]*):iam::([^:]*):(.*)$/i;

// Is an {other}-shaped PassRole token an IAM-ish ARN whose partition/account we CANNOT
// confidently compare (a non-canonical spelling: uppercase/mixed-case partition,
// embedded whitespace/tab, a non-12-digit account)? Such a token is UNKNOWN-viability,
// exactly like the parsed-role non-canonical case: we must NOT let it drive a confident
// cross-account demotion just because a case/whitespace variant failed the canonical
// same-account reach test (that is the fragile "coincidental-backstop" residual of the
// ARN-spelling class). A token that is not an IAM ARN at all (a different service, or a
// non-ARN) is NOT flagged here - it cannot name a role and is handled as a plain
// non-reach. S2-passrole-allstmts iter-4, axis 1.
export function otherResourceIsUnmodelable(raw) {
  const m = IAM_ARN_LENIENT_RE.exec(String(raw == null ? '' : raw));
  if (!m) return false; // not an IAM-ish ARN -> not "unmodelable"; provably non-reaching
  return !partitionModelable(m[1]) || !accountModelable(m[2]);
}

// Is this parsed PassRole role-ARN resource one whose partition/account we CANNOT
// confidently model (non-canonical spelling)? A "*" token is never unmodelable. An
// {other}-shaped token IS unmodelable when it is an IAM-ish ARN carrying a non-canonical
// partition/account (so a case/whitespace ARN-spelling variant fails CLOSED as unknown
// viability rather than being silently dropped into a confident cross-account demotion).
export function isUnmodelablePassResource(res) {
  if (res.star) return false;
  if (res.other) return otherResourceIsUnmodelable(res.raw);
  return !partitionModelable(res.partition) || !accountModelable(res.account);
}

// A role-ARN resource pinned to a CONFIDENTLY-modelable concrete partition+account
// (no wildcard, known partition, 12-digit account). Only such a resource may drive a
// confident cross-account/partition demotion; a wildcard reaches the subject and an
// unmodelable token fails closed instead.
export function isConfidentPinnedResource(res) {
  return !res.star && !res.other
    && !String(res.account).includes('*')
    && !String(res.partition).includes('*')
    && partitionModelable(res.partition)
    && accountModelable(res.account);
}

// Can the IAM wildcard glob `pattern` produce SOME string whose fixed leading
// characters are exactly `prefix` (the tail after `prefix` being an arbitrary,
// possibly-empty run)? Decided with a bounded (patternIndex x prefixIndex) DP - '*'
// absorbs zero-or-more prefix chars (and stays available), '?' consumes exactly one,
// any other char must equal the prefix char. Success is reaching prefixIndex === N
// (the whole prefix produced) with the pattern index ANYWHERE, because whatever glob
// remains after the prefix is always satisfiable by SOME suffix string. Each grid cell
// is visited at most once (a visited bitmap), so this is O(pattern x prefix) with the
// per-token length cap (validate.js MAX_STRING_LENGTH) bounding both - no backtracking
// blow-up (threat-model T5). Work is charged so an armed budget samples it.
// S2-passrole-allstmts axis 1: this is the SOUND, non-fixed-probe test for "could an
// {other}-shaped PassRole token name a role in the subject's OWN account+partition".
export function globCanProducePrefix(pattern, prefix) {
  const p = String(pattern);
  const pre = String(prefix);
  const P = p.length;
  const N = pre.length;
  if (N === 0) return true; // empty prefix is a prefix of every producible string
  const stride = N + 1;
  const seen = new Uint8Array((P + 1) * stride);
  const stack = [0]; // encode state (i,j) as i*stride + j
  seen[0] = 1;
  while (stack.length) {
    const state = stack.pop();
    const j = state % stride;
    if (j === N) return true; // whole prefix produced; leftover pattern is satisfiable
    chargeWork(1);
    const i = (state - j) / stride;
    if (i >= P) continue; // pattern exhausted before the prefix was fully produced
    const c = p[i];
    if (c === '*') {
      const a = (i + 1) * stride + j; // star matches the empty run, advance pattern
      if (!seen[a]) { seen[a] = 1; stack.push(a); }
      const b = i * stride + (j + 1); // star absorbs prefix[j], stays available
      if (!seen[b]) { seen[b] = 1; stack.push(b); }
    } else if (c === '?' || c === pre[j]) {
      const a = (i + 1) * stride + (j + 1); // one char consumed on both sides
      if (!seen[a]) { seen[a] = 1; stack.push(a); }
    }
  }
  return false;
}

// The fixed ARN prefix every role in the subject's OWN account+partition shares; a
// concrete subject role ARN is this prefix + a non-empty role name. Built from the
// (validated) subject partition + 12-digit account. `globCanProducePrefix` against it
// answers "could this token glob-match a subject role ARN".
export function subjectRoleArnPrefix(subjectAccount, subjectPartition) {
  return `arn:${subjectPartition}:iam::${subjectAccount}:role/`;
}

// Could this passable-role RESOURCE reach a role in the subject's OWN account +
// partition (i.e. could iam:PassRole hand a same-account role to a same-account
// service)? A bare "*" reaches anything; a role ARN reaches the subject only when
// BOTH its partition and account admit the subject's. An {other} token that
// ROLE_ARN_PARTS_RE could not pin as a concrete arn:...:role/<name> (it lacks the
// literal ':role/': e.g. arn:<acct>:role* / :r* / :role?* / :* / a leading-wildcard
// token) is NOT automatically foreign - a same-account wildcard/role-prefix glob
// matches every subject role ARN and is a fully-viable same-account pass. Credit such
// a token as REACHING the subject when, read as an IAM wildcard glob, it COULD name a
// role ARN in the subject's own account+partition (globCanProducePrefix). Only a token
// that provably CANNOT name a subject role (a different concrete account/partition, or
// a concrete non-role identifier like policy/…) fails to reach and may drive a
// demotion. Treating {other} as a flat non-reach (the old `return false`) let a
// co-located concrete FOREIGN role confidently demote a viable same-account critical
// path to medium -> scan exit 0 CLEAN (threat-model T8, fail-open). Requires a known
// subjectAccount.
export function resourceReachesSubject(res, subjectAccount, subjectPartition) {
  if (res.star) return true;
  if (res.other) {
    return globCanProducePrefix(res.raw, subjectRoleArnPrefix(subjectAccount, subjectPartition));
  }
  return partitionReaches(res.partition, subjectPartition)
    && accountReaches(res.account, subjectAccount);
}

// Is a Deny resource's role-NAME path component WILDCARD-EQUIVALENT to "*" - i.e.
// composed SOLELY of "*" characters, so it imposes NO literal or positional
// constraint and therefore matches every possible role name? Only such a component
// removes ALL subject roles. A leading-literal or anchored glob (role/_*, role/__*,
// role/*probe*, role/service-role/*, role/app-?) is STRICTLY NARROWER than "*" - it
// excludes at least one role name - and must NOT be treated as removing all roles.
// An empty path (role/ with nothing after) matches no role and is likewise not
// all-roles. Fail closed: anything but pure "*"(s) returns false.
// S2-passrole-allstmts axis 3: this replaces a two-fixed-probe heuristic that a
// narrow decoy Deny colliding with both probe strings could satisfy, which falsely
// concluded deny-all and confidently demoted a viable same-account path (T8).
export function rolePathIsWildcardEquivalent(path) {
  return /^\*+$/.test(String(path));
}

// A single principal has ONE value for each principal-scoped request key for the
// life of its credentials, so these keys are INVARIANT across the legs of a
// takeover chain the same principal would execute (suite-3 test 75).
export const PRINCIPAL_INVARIANT_KEYS = new Set([
  'aws:principalaccount',
  'aws:principalorgid',
  'aws:principalorgpaths',
  'aws:principalarn',
  'aws:userid',
]);

// Exact-equality operators that pin a principal-invariant key to a HARD literal
// value (base form, after parseOperator). These are the operators for which a
// single principal must carry exactly one of the listed values, so two legs that
// pin the SAME key to disjoint values can never be satisfied by one principal.
// This MUST mirror the exact-equality members of conditions.js
// POSITIVE_STRING_MATCH_OPERATORS - crucially aws:PrincipalArn's idiomatic exact
// operator is ArnEquals, NOT StringEquals (suite-3 test 75 ArnEquals twin /
// release-gate #3). Like-family operators (StringLike / ArnLike) admit wildcards
// and so do NOT pin a single literal - they are intentionally excluded, matching
// the documented decision that wildcard-match operators create no hard
// contradiction. StringEqualsIgnoreCase is exact but case-insensitive (tracked
// per-pin so a case-only variance is not mistaken for a contradiction).
export const EXACT_EQUALITY_PIN_OPERATORS = new Set([
  'stringequals',
  'stringequalsignorecase',
  'arnequals',
]);

// The exact-equality NEGATIONS of the operators above. StringNotEquals /
// ArnNotEquals (and the IgnoreCase form) pin the principal-invariant key to
// "anything EXCEPT the listed literal(s)". A single principal that must be == X
// on one leg and != X on another leg cannot exist, so a negated pin is just as
// load-bearing as a positive pin for the cross-leg satisfiability check (suite-3
// test 75 negation twin / release-gate #3): ignoring it manufactures a false
// critical takeover no single principal can execute. Like-family negations
// (StringNotLike / ArnNotLike) admit wildcards and pin no single literal, so -
// mirroring the positive-side exclusion of StringLike / ArnLike - they are
// intentionally excluded and create no hard contradiction.
export const NEGATED_EQUALITY_PIN_OPERATORS = new Set([
  'stringnotequals',
  'stringnotequalsignorecase',
  'arnnotequals',
]);

export const CASE_INSENSITIVE_PIN_OPERATORS = new Set([
  'stringequalsignorecase',
  'stringnotequalsignorecase',
]);

// Extract the exact-equality pins a statement's Condition places on any
// principal-invariant key: keyLower -> array of { values:Set, ci:boolean,
// negated:boolean }, one entry per constraining operator block (AND-ed within the
// statement). Only an exact-equality operator (positive == or its exact-negation
// !=) with NO set-operator prefix and NO ...IfExists suffix pins a hard
// constraint every principal must satisfy: an IfExists pin is skipped when the
// key is absent, and a ForAllValues/ForAnyValue set qualifier changes the match
// semantics, so neither creates a dependable cross-leg contradiction and both are
// intentionally ignored. Like-family operators (StringLike / ArnLike and their
// Not- forms) admit wildcards and pin no single literal, so they are ignored.
// Condition keys are case-insensitive, so keys are lowercased.
export function principalPinsOf(stmt) {
  const pins = new Map();
  const cond = stmt && stmt.condition;
  if (!cond || typeof cond !== 'object') return pins;
  for (const op of Object.keys(cond)) {
    const { base, setOperator, ifExists } = parseOperator(op);
    if (setOperator !== null || ifExists) continue;
    const positive = EXACT_EQUALITY_PIN_OPERATORS.has(base);
    const negated = NEGATED_EQUALITY_PIN_OPERATORS.has(base);
    if (!positive && !negated) continue;
    const ci = CASE_INSENSITIVE_PIN_OPERATORS.has(base);
    const block = cond[op];
    if (!block || typeof block !== 'object') continue;
    for (const key of Object.keys(block)) {
      if (!PRINCIPAL_INVARIANT_KEYS.has(key.toLowerCase())) continue;
      const raw = block[key];
      const vals = Array.isArray(raw) ? raw.map((v) => String(v)) : [String(raw)];
      // S3-dos-budget-all: condition-value arrays are NOT capped by count in
      // validate.js (only MAX_BYTES / MAX_STRING_LENGTH bound them), so `vals` can be
      // tens of thousands of entries within caps. Charge the deterministic work budget
      // for building the pin's value set(s) so this policy-derived loop participates in
      // both the browser work budget and the Node wall-clock deadline (both sampled
      // ONLY inside chargeWork) rather than accruing zero work on the satisfiability
      // path -> the fail-OPEN DoS class (T5/T8).
      chargeWork(vals.length);
      // For a case-INSENSITIVE operator, precompute a lowercased Set ONCE so
      // constraintContains is O(1) (`.has`) instead of an O(V) linear rescan of the
      // whole value Set per candidate. Without this the candidate x value scan in
      // keyConstraintsSatisfiable was O(V^2) on a within-caps input (measured multiple
      // seconds -> COMPLETE verdict). Building it once here keeps that check linear.
      const values = new Set(vals);
      const valuesLc = ci ? new Set(vals.map((v) => v.toLowerCase())) : null;
      const list = pins.get(key.toLowerCase()) || [];
      list.push({ values, valuesLc, ci, negated });
      pins.set(key.toLowerCase(), list);
    }
  }
  return pins;
}

// Does the constraint's value set contain `cand` (case-sensitively, or
// case-insensitively for the IgnoreCase operators)?
//
// S3-dos-budget-all: BOTH branches are O(1). The case-insensitive branch uses the
// lowercased Set principalPinsOf precomputes ONCE (`valuesLc`) rather than a linear
// per-candidate rescan of the whole value Set - the fix that removes the O(V^2)
// case-insensitive grind (constraintContains x |candidates|) that a within-caps
// role-takeover policy rode to a multi-second COMPLETE verdict.
export function constraintContains(c, cand, candLc) {
  if (c.ci) return c.valuesLc.has(candLc);
  return c.values.has(cand);
}

// Can a single principal value satisfy EVERY constraint on one key at once?
// A POSITIVE constraint (==) requires the principal's single value to be one of a
// finite set; a NEGATED constraint (!=) requires it to be NONE of a finite set.
//
// A satisfying value must be a member of every positive set, so it can only be
// one of the literals a positive constraint lists - that finite pool is the only
// place a satisfying candidate can live. Each candidate is then checked against
// ALL constraints (positive: must be in; negated: must be out).
//
// When there is NO positive constraint the domain is effectively unbounded (any
// account id / ARN / userid), and a finite list of "!=" exclusions can always be
// avoided by some other value, so an all-negated key is satisfiable. This keeps
// the satisfiable control (both legs pin the SAME key with !=A) FIRING - only a
// genuine == X / != X (or two disjoint ==) contradiction reads as unsatisfiable.
// Kept conservative so a case-only variance is NOT mistaken for a contradiction.
export function keyConstraintsSatisfiable(constraints) {
  const positives = constraints.filter((c) => !c.negated);
  if (positives.length === 0) return true;
  const candidates = new Set();
  for (const c of positives) for (const v of c.values) candidates.add(v);
  // S3-dos-budget-all: charge the deterministic work budget for the candidate x
  // constraint satisfiability scan BEFORE running it. Even with O(1) case-insensitive
  // lookups (valuesLc) this is an O(|candidates| x |constraints|) grind over
  // condition-value arrays that validate.js does NOT cap by count (only MAX_BYTES /
  // MAX_STRING_LENGTH), so |candidates| can reach the tens of thousands within caps.
  // The prior charge sites (pinsJointlySatisfiable per-statement, principalConditions-
  // Satisfiable's leg product) are a handful of units for this V-sized grind, so the
  // work budget and the CLI/Action wall-clock deadline (both sampled ONLY inside
  // chargeWork) never tripped and a runaway returned a COMPLETE verdict (fail-OPEN
  // DoS, T5/T8 - the same class one frame down from the leg loop). Charging the full
  // product up front makes a runaway fail CLOSED (RESOURCE_BUDGET_EXCEEDED ->
  // aborted+incomplete on the browser, exit 3 on the Node adapters) before it grinds.
  chargeWork(candidates.size * constraints.length);
  for (const cand of candidates) {
    const candLc = cand.toLowerCase();
    let ok = true;
    for (const c of constraints) {
      const inSet = constraintContains(c, cand, candLc);
      // positive => must be in the set; negated => must be out of the set.
      if (c.negated ? inSet : !inSet) { ok = false; break; }
    }
    if (ok) return true;
  }
  return false;
}

// Given a chosen SET of statements the one principal must satisfy jointly (an
// AND across these statements), can a single principal meet every
// principal-invariant pin at once? For each invariant key constrained by two or
// more of the chosen statements, the principal's single value must satisfy every
// one of those constraints simultaneously. An unsatisfiable key means no
// principal can satisfy this exact combination.
// S3-dos-budget-all (DOS-1): MEMOIZED principalPinsOf. The satisfiability triple
// loop (principalConditionsSatisfiable) evaluates the SAME statement's pins O(N^2)
// times as it pairs it against every other leg; re-parsing its Condition (parseOperator
// + Map/Set allocation) on each visit is the dominant CPU cost of the grind and it
// TRACKS NOTHING in the budget beyond a per-value charge. Computing each statement's
// pins ONCE (keyed by the statement's stable index) collapses that O(N^3) re-parse to
// O(distinct-statements), so the inner loop only merges already-built, read-only pin
// maps. Pins are never mutated by a caller (pinsJointlySatisfiable copies constraints
// into a fresh perKey map; keyConstraintsSatisfiable only reads them), so sharing one
// memoized object across triples is safe and does not change any verdict.
export function principalPinsOfMemo(stmt, memo) {
  const key = stmt.index;
  let pins = memo.get(key);
  if (pins === undefined) {
    pins = principalPinsOf(stmt);
    memo.set(key, pins);
  }
  return pins;
}

export function pinsJointlySatisfiable(stmts, memo) {
  // S3-dos-budget-all: charge the deterministic work budget for every statement's
  // pin extraction. principalPinsOf / keyConstraintsSatisfiable do only string/Set
  // work and NEVER reach the shared matcher (the sole other chargeWork site), so
  // before this charge the whole call was invisible to the budget. This function is
  // the innermost body of principalConditionsSatisfiable's grant x trust x assume
  // triple loop; with N legs per group that is N^3 calls, each doing real map work,
  // and none of it was sampled -> a within-caps role-takeover-heavy policy ran for
  // tens of seconds yet returned a COMPLETE verdict (fail-OPEN DoS, threat-model
  // T5/T8). Charging one unit per statement inspected makes the traversal itself
  // participate so a runaway fails CLOSED (RESOURCE_BUDGET_EXCEEDED -> aborted +
  // incomplete), on the browser (no wall-clock watchdog) as well as the Node adapters.
  chargeWork(Array.isArray(stmts) ? stmts.length : 0);
  const perKey = new Map(); // keyLower -> array of { values:Set, ci:boolean }
  for (const stmt of stmts) {
    // DOS-1: pins are memoized per statement (see principalPinsOfMemo) so the
    // Condition is parsed ONCE, not O(N^2) times across the enclosing triple loop.
    for (const [k, list] of principalPinsOfMemo(stmt, memo)) {
      if (!perKey.has(k)) perKey.set(k, []);
      for (const c of list) perKey.get(k).push(c);
    }
  }
  for (const constraints of perKey.values()) {
    if (constraints.length < 2) continue; // only one stmt constrains it -> no contradiction
    if (!keyConstraintsSatisfiable(constraints)) return false;
  }
  return true;
}

// suite-3 test 75 (+ iteration-2 alternative-statement fix): can ONE principal
// execute the whole modify-then-assume chain? The chain needs the principal to
// satisfy SOME grant statement AND SOME trust statement AND SOME assume
// statement - only ONE statement per leg-group is required to obtain that
// capability. Statements WITHIN a group are therefore ALTERNATIVES (an OR), not
// a conjunction: a principal in account A that satisfies grant-A, trust-A and
// one of several assume statements (assume-A) executes a real takeover even
// though a *different* assume statement pins account B. Satisfiability is thus
// EXISTENTIAL across the choice of one statement per group: viable iff there
// exists (grant, trust, assume) whose principal-invariant pins share a
// non-empty intersection. It is unsatisfiable (test 75) only when NO such
// combination exists - e.g. the single modify leg pins account 123456789012 and
// the single assume leg pins 999900001111, so every triple contradicts.
// Alternatives are never AND-ed together, which would fabricate a contradiction
// out of statements the principal never needs to satisfy at the same time.
export function principalConditionsSatisfiable(grantLegs, trustLegs, assumeLegs, pinMemo) {
  // S3-dos-budget-all (DOS-1): this is a genuine grant x trust x assume TRIPLE loop
  // over policy-derived leg sets. With ~N legs per group it is O(N^3) calls to
  // pinsJointlySatisfiable. Charge the FULL combinatorial product UP FRONT, WEIGHTED
  // BY THE REAL PER-TRIPLE COST (SATISFIABILITY_TRIPLE_WORK), so a pathological
  // product trips the deterministic budget BEFORE the exhaustive search grinds
  // through it, rather than only being sampled call-by-call.
  //
  // The previous version charged ONE unit per triple, so a 160-legs-per-group input
  // (160^3 = 4.1M << DEFAULT_WORK_LIMIT=60M) never tripped and analyze() ground ~3s
  // yet returned a COMPLETE verdict (measured; the DOS-1 fail-OPEN, threat-model
  // T5/T8). A single triple is NOT one unit of work: it allocates a perKey Map,
  // merges up to three statements' pin maps, builds a candidate Set, and runs the
  // keyConstraintsSatisfiable scan - dozens of primitive ops. Charging that true
  // per-triple cost makes the product cap out at ~DEFAULT_WORK_LIMIT /
  // SATISFIABILITY_TRIPLE_WORK ~= 9.4e5 triples (~97 legs per group), far above any
  // legitimate role-takeover policy (a real chain has a handful of legs per group)
  // yet well below the ~1e6 triples the measured grind needs to exceed the wall-clock
  // budget. So a legit small product still runs the exhaustive search to completion
  // and fires its finding, while a runaway fails CLOSED IMMEDIATELY
  // (RESOURCE_BUDGET_EXCEEDED -> aborted+incomplete on the browser, exit 3 on the Node
  // adapters) instead of hanging. pinsJointlySatisfiable ALSO charges per statement
  // and, with principalPinsOf now MEMOIZED, each surviving (sub-cap) triple is cheap
  // and finely sampled, so the Node wall-clock deadline can no longer overrun by more
  // than one work-check interval (the prior 2.7x overrun is closed).
  const gLen = Array.isArray(grantLegs) ? grantLegs.length : 0;
  const tLen = Array.isArray(trustLegs) ? trustLegs.length : 0;
  const aLen = Array.isArray(assumeLegs) ? assumeLegs.length : 0;
  chargeWork(gLen * tLen * aLen * SATISFIABILITY_TRIPLE_WORK);
  // One shared pin memo across the whole triple loop (and reused across anchor roles
  // when the caller threads it): each statement's Condition is parsed ONCE.
  const memo = pinMemo instanceof Map ? pinMemo : new Map();
  for (const g of grantLegs) {
    for (const t of trustLegs) {
      for (const a of assumeLegs) {
        if (pinsJointlySatisfiable([g.stmt, t.stmt, a.stmt], memo)) return true;
      }
    }
  }
  return false;
}

// DOS-1 calibration: the estimated real work of ONE satisfiability triple (perKey
// Map allocation + up-to-3 pin-map merges + candidate Set build + keyConstraints scan).
// Sized so gLen*tLen*aLen * this exceeds DEFAULT_WORK_LIMIT (60M) once the product
// reaches ~1e6 triples (100 legs per group) - the measured threshold where the grind
// approaches the wall-clock budget - so the N=100..200-legs-per-group attack family
// fails CLOSED up front while legitimate handful-of-legs chains stay well under the cap.
export const SATISFIABILITY_TRIPLE_WORK = 64;
