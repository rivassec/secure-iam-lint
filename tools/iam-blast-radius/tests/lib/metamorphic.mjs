// Metamorphic security properties for the analysis engine (review finding B1).
//
// WHY THIS EXISTS: the differential oracle (browser analyze() == CLI scan()) is
// CIRCULAR - scan() imports the same engine, so a SHARED semantic error is invisible
// to it (this is exactly how the A1 spoofed-duplicate-key fail-open hid). And the
// generic parity predicate only asks "is it fully clean?", never comparing finding
// CONTENT. Metamorphic properties fix both: they assert security-MONOTONIC relations
// between a policy and a MUTATED policy on ONE surface, so a shared engine bug that
// makes a risky policy read cleaner than its narrower sibling is caught with no second
// surface required.
//
// The load-bearing direction is FAIL-OPEN: a capability-BROADENING mutation must never
// turn a non-clean result into a clean one, and a capability-NARROWING/obfuscating
// mutation must never make a policy read cleaner than the original.
//
// Exported so both the unit test (metamorphic-properties.test.js) and the fuzzers
// (parity-fuzz.mjs / analyze.fuzz.cjs) can drive the same invariants.

export const SEV_RANK = Object.freeze({ info: 0, low: 1, medium: 2, high: 3, critical: 4 });

const ZW = '​'; // zero-width space (a format-control key twin, A1 class)

// A result is CLEAN iff analysis succeeded, was complete, and surfaced nothing.
// Fail-closed (ok:false) and incomplete both count as NOT-clean (the safe state).
export function isClean(r) {
  if (!r || r.ok === false) return false;
  if (r.coverage && r.coverage.summary && r.coverage.summary.incomplete) return false;
  return Array.isArray(r.findings) && r.findings.length === 0;
}

// Max finding severity rank, or -1 when there are no findings. Fail-closed / incomplete
// return Infinity (maximally "not clean") so a broaden can never look like a drop.
export function maxSevRank(r) {
  if (!r || r.ok === false) return Infinity;
  if (r.coverage && r.coverage.summary && r.coverage.summary.incomplete) return Infinity;
  const fs = r.findings || [];
  if (!fs.length) return -1;
  return Math.max(...fs.map((f) => (f.severity in SEV_RANK ? SEV_RANK[f.severity] : 0)));
}

// The set of {id:severity} finding keys - the CONTENT the coarse oracle never compared.
export function findingKeySet(r) {
  return new Set((r && r.findings ? r.findings : []).map((f) => `${f.id}:${f.severity}`));
}

export function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

// ---- Policy mutations (operate on a parsed policy, return a fresh clone) ----
const clone = (p) => JSON.parse(JSON.stringify(p));
const statements = (p) => (Array.isArray(p.Statement) ? p.Statement : [p.Statement]);

// These mutations widen CAPABILITY, which is only monotonic for ALLOW statements:
// broadening a DENY (or removing a Deny's narrowing Condition) makes it MORE
// restrictive (less capability = legitimately cleaner), so we touch ONLY Effect:Allow
// statements and leave Deny/malformed ones unchanged.
const isAllow = (s) => s && s.Effect === 'Allow';

// BROADENING: replace an Allow's Action with "*". Strictly widens capability.
export function broadenActions(policy) {
  const p = clone(policy);
  for (const s of statements(p)) if (isAllow(s) && 'Action' in s) s.Action = '*';
  return p;
}
// BROADENING: replace an Allow's Resource with "*".
export function broadenResources(policy) {
  const p = clone(policy);
  for (const s of statements(p)) if (isAllow(s) && 'Resource' in s) s.Resource = '*';
  return p;
}
// BROADENING: drop an Allow's Condition (a Condition can only narrow an Allow).
export function removeConditions(policy) {
  const p = clone(policy);
  for (const s of statements(p)) if (isAllow(s)) delete s.Condition;
  return p;
}
// INVARIANT: reversing statement order must not change the security result.
export function permuteStatements(policy) {
  const p = clone(policy);
  if (Array.isArray(p.Statement)) p.Statement = p.Statement.slice().reverse();
  return p;
}
// A benign, NARROWER decoy for the spoof-twin overwrite (Stage-11 #5).
const DECOY_ACCOUNT = 'arn:aws:iam::111111111111:root';

// OBFUSCATION (A1 class): add a zero-width twin of the first Principal-type /
// Condition-operator key. Must never make the policy read cleaner.
//
// Stage-11 #5: the twin key carries a DISTINCT, risk-LOWERING decoy value, not a
// copy of the real value. On a hypothetical UNGUARDED engine the ZW-twin key
// collapses onto k and (last-key-wins) OVERWRITES the real value with this benign
// decoy - erasing the risky grant (a public/broad Principal becomes one specific
// account). The shipped engine fails closed (SPOOFED_DUPLICATE_KEY), so the
// property holds; but if the A1 collision guard were ever removed, the decoy would
// LOWER the reported risk and checkSpoofMonotonic would CATCH the regression. An
// identical-value copy (the old behavior) is a no-op even on an unguarded engine,
// so it certified the guard as present without ever exercising it.
export function spoofTwinKey(policy) {
  const p = clone(policy);
  for (const s of statements(p)) {
    if (!s) continue;
    for (const [container, kind] of [[s.Principal, 'principal'], [s.NotPrincipal, 'principal'], [s.Condition, 'condition']]) {
      if (container && typeof container === 'object' && !Array.isArray(container)) {
        const k = Object.keys(container)[0];
        if (k !== undefined && !(k + ZW in container)) {
          container[k + ZW] = kind === 'principal' ? DECOY_ACCOUNT : { 'aws:PrincipalAccount': '111111111111' };
          return p;
        }
      }
    }
  }
  return p; // nothing to twin (e.g. Principal:"*"): unchanged, property trivially holds
}

// OBFUSCATION (Stage-11 #1 class): for each Allow statement that grants a concrete
// Action, ADD a Deny statement whose Action is that same action with a zero-width
// space inserted. Such a Deny is AWS-INERT - AWS matches the literal requested
// action against the Deny pattern that still carries the code point and does NOT
// match, so the Allow stays live. The engine must therefore NOT let this spoofed
// Deny suppress the finding into a clean pass. Models the reproduced critical
// fail-open directly, on ONE surface (no second surface needed).
export function addSpoofedDeny(policy) {
  const p = clone(policy);
  const stmts = statements(p);
  const extra = [];
  for (const s of stmts) {
    if (!isAllow(s) || !('Action' in s)) continue;
    const acts = Array.isArray(s.Action) ? s.Action : [s.Action];
    let changed = false;
    const spoofed = acts.map((a) => {
      // Only a multi-char token that does not already carry the code point can be
      // given an AWS-INERT spoofed twin. A wildcard "*" (or single char) cannot: a
      // Deny "*" is a REAL deny-all that legitimately clears the finding, which is
      // not the #1 attack - skip such statements rather than model a false positive.
      if (typeof a === 'string' && a.length > 1 && !a.includes(ZW)) {
        changed = true;
        return a.slice(0, 1) + ZW + a.slice(1);
      }
      return a;
    });
    if (!changed) continue;
    extra.push({
      Effect: 'Deny',
      Action: spoofed.length === 1 ? spoofed[0] : spoofed,
      Resource: s.Resource !== undefined ? s.Resource : '*',
    });
  }
  if (extra.length) p.Statement = stmts.concat(extra);
  return p;
}

// ---- Property checks: each returns { ok, msg } ----

// True iff the analysis COMPLETED and surfaced at least one concrete finding. Only then
// can a broadening/obfuscating mutation "hide" a real capability. An incomplete/failed
// base is a fail-closed CAUTION (e.g. a malformed condition), not a finding - removing
// the malformed part may legitimately clear it, which is not a fail-open.
function hasConcreteFinding(r) {
  return r && r.ok !== false
    && !(r.coverage && r.coverage.summary && r.coverage.summary.incomplete)
    && Array.isArray(r.findings) && r.findings.length > 0;
}

// A BROADENING mutation must never LOWER the reported risk of a policy that had a
// concrete finding - turning it clean, or dropping its max severity. (maxSevRank
// returns Infinity for incomplete/failed, so a broaden that fails CLOSED never trips.)
export function checkBroaden(analyze, policy, mutate, opts, label) {
  const base = analyze(JSON.stringify(policy), opts);
  if (!hasConcreteFinding(base)) return { ok: true, msg: `${label}: base not concrete, n/a` };
  const wide = analyze(JSON.stringify(mutate(policy)), opts);
  if (maxSevRank(wide) < maxSevRank(base)) {
    return { ok: false, msg: `${label}: broadening lowered reported risk ${maxSevRank(base)}->${maxSevRank(wide)} (wideClean=${isClean(wide)})` };
  }
  return { ok: true, msg: `${label}: ok` };
}

// Statement-order permutation must not change the VERDICT (clean-vs-not + max
// severity). Exact finding-SET order-invariance is a stronger, non-security property
// the subsumption/correlate step does not guarantee - a set difference that keeps the
// same clean status and max severity is not a fail-open and is out of scope here.
export function checkOrderInvariant(analyze, policy, opts) {
  const a = analyze(JSON.stringify(policy), opts);
  const b = analyze(JSON.stringify(permuteStatements(policy)), opts);
  if (isClean(a) !== isClean(b) || maxSevRank(a) !== maxSevRank(b)) {
    return { ok: false, msg: `order changed the verdict: clean ${isClean(a)}->${isClean(b)}, maxSev ${maxSevRank(a)}->${maxSevRank(b)}` };
  }
  return { ok: true, msg: 'order ok' };
}

// A spoofed-duplicate key (A1 class) must never make the policy read cleaner than the
// original, and must not lower max severity.
export function checkSpoofMonotonic(analyze, policy, opts) {
  const base = analyze(JSON.stringify(policy), opts);
  if (!hasConcreteFinding(base)) return { ok: true, msg: 'spoof: base not concrete, n/a' };
  const twin = analyze(JSON.stringify(spoofTwinKey(policy)), opts);
  if (maxSevRank(twin) < maxSevRank(base)) {
    return { ok: false, msg: `spoof-twin lowered reported risk ${maxSevRank(base)}->${maxSevRank(twin)} (A1-class fail-open)` };
  }
  return { ok: true, msg: 'spoof-monotonic ok' };
}

// An AWS-INERT spoofed Deny (a Deny whose action carries a zero-width space, so AWS
// never matches it) must never LOWER the reported risk of a policy that had a
// concrete finding. This is the direct metamorphic guard for the Stage-11 #1
// critical fail-open: an engine that de-spoofs the Deny and credits it as coverage
// would suppress the finding here; maxSevRank (Infinity for the fail-closed
// incomplete verdict) makes the fixed engine pass and a regressed one fail.
export function checkSpoofedDenyInert(analyze, policy, opts) {
  const base = analyze(JSON.stringify(policy), opts);
  if (!hasConcreteFinding(base)) return { ok: true, msg: 'spoofed-deny: base not concrete, n/a' };
  const withDeny = analyze(JSON.stringify(addSpoofedDeny(policy)), opts);
  if (maxSevRank(withDeny) < maxSevRank(base)) {
    return { ok: false, msg: `AWS-inert spoofed Deny lowered reported risk ${maxSevRank(base)}->${maxSevRank(withDeny)} (T8 #1 fail-open)` };
  }
  return { ok: true, msg: 'spoofed-deny-inert ok' };
}

// Run every applicable property over one policy; returns array of failures (empty = pass).
export function runAllProperties(analyze, policy, opts) {
  const fails = [];
  for (const [mut, label] of [[broadenActions, 'broaden-actions'], [broadenResources, 'broaden-resources'], [removeConditions, 'remove-conditions']]) {
    const r = checkBroaden(analyze, policy, mut, opts, label);
    if (!r.ok) fails.push(r.msg);
  }
  const o = checkOrderInvariant(analyze, policy, opts);
  if (!o.ok) fails.push(o.msg);
  const s = checkSpoofMonotonic(analyze, policy, opts);
  if (!s.ok) fails.push(s.msg);
  const d = checkSpoofedDenyInert(analyze, policy, opts);
  if (!d.ok) fails.push(d.msg);
  return fails;
}
