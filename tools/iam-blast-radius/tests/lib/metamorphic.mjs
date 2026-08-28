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

// BROADENING: replace every Action with "*". Strictly widens capability.
export function broadenActions(policy) {
  const p = clone(policy);
  for (const s of statements(p)) if (s && 'Action' in s) s.Action = '*';
  return p;
}
// BROADENING: replace every Resource with "*".
export function broadenResources(policy) {
  const p = clone(policy);
  for (const s of statements(p)) if (s && 'Resource' in s) s.Resource = '*';
  return p;
}
// BROADENING: drop every Condition (a Condition can only narrow an Allow).
export function removeConditions(policy) {
  const p = clone(policy);
  for (const s of statements(p)) if (s) delete s.Condition;
  return p;
}
// INVARIANT: reversing statement order must not change the security result.
export function permuteStatements(policy) {
  const p = clone(policy);
  if (Array.isArray(p.Statement)) p.Statement = p.Statement.slice().reverse();
  return p;
}
// OBFUSCATION (A1 class): add a zero-width twin of the first Principal-type /
// Condition-operator key. Must never make the policy read cleaner.
export function spoofTwinKey(policy) {
  const p = clone(policy);
  for (const s of statements(p)) {
    if (!s) continue;
    for (const container of [s.Principal, s.NotPrincipal, s.Condition]) {
      if (container && typeof container === 'object' && !Array.isArray(container)) {
        const k = Object.keys(container)[0];
        if (k !== undefined && !(k + ZW in container)) { container[k + ZW] = container[k]; return p; }
      }
    }
  }
  return p; // nothing to twin (e.g. Principal:"*"): unchanged, property trivially holds
}

// ---- Property checks: each returns { ok, msg } ----

// A BROADENING mutation must never turn a non-clean policy into a clean one, and must
// not lower the max severity below the original when both are concretely analyzed.
export function checkBroaden(analyze, policy, mutate, opts, label) {
  const base = analyze(JSON.stringify(policy), opts);
  const wide = analyze(JSON.stringify(mutate(policy)), opts);
  if (!isClean(base) && isClean(wide)) {
    return { ok: false, msg: `${label}: broadening turned a non-clean policy CLEAN (fail-open). base=[${[...findingKeySet(base)]}] wide=CLEAN` };
  }
  if (maxSevRank(wide) < maxSevRank(base) && maxSevRank(base) !== Infinity) {
    return { ok: false, msg: `${label}: broadening LOWERED max severity ${maxSevRank(base)}->${maxSevRank(wide)}` };
  }
  return { ok: true, msg: `${label}: ok` };
}

// Statement-order permutation must yield an identical finding set.
export function checkOrderInvariant(analyze, policy, opts) {
  const a = analyze(JSON.stringify(policy), opts);
  const b = analyze(JSON.stringify(permuteStatements(policy)), opts);
  if (isClean(a) !== isClean(b) || !setsEqual(findingKeySet(a), findingKeySet(b))) {
    return { ok: false, msg: `order-invariance broken: [${[...findingKeySet(a)]}] vs [${[...findingKeySet(b)]}]` };
  }
  return { ok: true, msg: 'order ok' };
}

// A spoofed-duplicate key (A1 class) must never make the policy read cleaner than the
// original, and must not lower max severity.
export function checkSpoofMonotonic(analyze, policy, opts) {
  const base = analyze(JSON.stringify(policy), opts);
  const twin = analyze(JSON.stringify(spoofTwinKey(policy)), opts);
  if (!isClean(base) && isClean(twin)) {
    return { ok: false, msg: `spoof-twin turned a non-clean policy CLEAN (A1-class fail-open)` };
  }
  if (maxSevRank(twin) < maxSevRank(base) && maxSevRank(base) !== Infinity) {
    return { ok: false, msg: `spoof-twin LOWERED max severity ${maxSevRank(base)}->${maxSevRank(twin)}` };
  }
  return { ok: true, msg: 'spoof-monotonic ok' };
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
  return fails;
}
