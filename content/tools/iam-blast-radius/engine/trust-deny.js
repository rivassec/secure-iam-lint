// trust-deny.js - explicit-Deny analysis for trust policies (which principals a Deny statement removes from a trust finding). Extracted (behavior-preserving).
import { chargeWork } from './glob.js';
import { denyActionApplies } from './escalation-deny.js';
import { hasNonEmptyCondition } from './escalation-conditions.js';
import { isTrustStatement, classifyPrincipals, add } from './trust-classify.js';
import { ASSUME_ACTIONS } from './trust-catalogs.js';

export function trustDenyStatements(model) {
  if (!model || !Array.isArray(model.statements)) return [];
  return model.statements.filter((s) => s && s.effect === 'Deny' && isTrustStatement(s));
}

// AWS treats the account-ARN form `arn:aws:iam::<acct>:root` and the bare 12-digit
// account id `<acct>` as the SAME principal - both delegate trust to the whole
// account, and the `...:root` form does NOT limit trust to the root user
// (trust-policy-semantics.md 2.2). Reduce a whole-account delegation entry to a
// canonical `account:<id>` key so a Deny written in one form neutralizes an Allow
// written in the other (adversarial-critic IAM-806 iteration 4 defect 1: a bare
// account-id Deny failed to suppress a root-ARN Allow because the matcher compared
// principal strings verbatim, leaving a HIGH cross-account over-claim on a role AWS
// treats as unassumable). This is EXACT canonical equivalence, not a wildcard glob:
// every other principal type keeps its verbatim `<type>:<value>` identity.
export function canonicalPrincipalKey(entry) {
  if (!entry || typeof entry !== 'object') return null;
  if (entry.type === 'aws-account') return `account:${entry.value}`;
  if (entry.type === 'aws-root') {
    const m = /^arn:[^:]*:iam::(\d{12}):root$/i.exec(String(entry.value));
    if (m) return `account:${m[1]}`;
    return `aws-root:${entry.value}`;
  }
  return `${entry.type}:${String(entry.value)}`;
}

// Build the O(1)-lookup coverage index for ONE Deny statement's classified
// Principal set: an `anonymous` flag (a Deny Principal "*" covers EVERY principal)
// plus a Set of the CANONICAL keys of every named entry (root-ARN <-> bare account
// id folded, per canonicalPrincipalKey). Precomputing this ONCE per Deny statement
// is the S3-dos-budget-all residual fix: principalEntryDeniedBy was an
// O(#deny-principals) `.entries.some(...)` rescan re-run on every (finding-principal,
// assume-action) pair, so a single Deny carrying thousands of principals multiplied
// the real cost by that count while the charge stayed 1-per-Deny-STATEMENT - an
// uncharged inner rescan that fooled BOTH the deterministic work ceiling and the
// Node wall-clock deadline (both sampled only inside chargeWork). Charging the Set's
// O(#deny-principals) construction here makes the charged work match the real work,
// and the O(1) `.has()` lookup below removes the quadratic entirely so a within-caps
// many-principals Deny no longer grinds for seconds. classifyPrincipals already
// charged the entry walk; this charge covers the additional canonical-key build so
// the cost the loop actually depends on is fully visible to the budget.
export function buildDenyCoverage(principals) {
  const keySet = new Set();
  chargeWork(principals.entries.length);
  for (const e of principals.entries) {
    const k = canonicalPrincipalKey(e);
    if (k !== null) keySet.add(k);
  }
  return { anonymous: !!principals.anonymous, keySet };
}

// Does a Deny's classified Principal set cover this Allow-finding principal entry?
// A Deny Principal "*" (anonymous) covers EVERY principal, so it neutralizes any
// grant. Otherwise coverage is proven only by CANONICAL-form equivalence: the same
// account (root-ARN <-> bare account id, per canonicalPrincipalKey) or an exact
// typed-value match (same role ARN, provider, ...). A specific Deny never covers an
// anonymous ("*") Allow - only a "*" Deny does. We still do NOT try to prove a
// wildcard-ARN Deny globs over an Allow principal: an unproven wide match must not
// manufacture a FALSE "fully denied" (that would under-report a real trust, the
// inverse T8 harm), so it falls through to the "partial" caveat path instead.
//
// `coverage` is the precomputed { anonymous, keySet } from buildDenyCoverage(): the
// lookup is O(1) (a Set membership test on the entry's canonical key), NOT the old
// O(#deny-principals) linear rescan. Behaviour is byte-identical to the previous
// `denyPrincipals.entries.some((d) => canonicalPrincipalKey(d) === key)` for every
// input (the Set holds exactly those canonical keys); only the cost model changed.
export function principalEntryDeniedBy(entry, coverage) {
  if (coverage.anonymous) return true;
  if (!entry || entry.type === 'anonymous') return false;
  const key = canonicalPrincipalKey(entry);
  if (key === null) return false;
  return coverage.keySet.has(key);
}

/**
 * Same-policy explicit-Deny precedence for ONE trust finding. Returns:
 *   'full'    - every (principal, assume-action) the finding rests on is covered
 *               by an UNCONDITIONAL, certain, in-scope trust Deny: the grant is
 *               fully neutralized (suppress the finding; graph shows blocked-by-
 *               deny, no can-assume edge).
 *   'partial' - a same-policy trust Deny overlaps the grant but does not provably
 *               fully block it (conditional, or only some principals/actions
 *               covered, or an unproven wildcard match): the finding stays, but
 *               the residual Deny effect is surfaced as a coverage caveat.
 *   'none'    - no same-policy trust Deny touches the grant.
 *
 * Deterministic; never throws. Only assume actions matter: an assume grant is
 * neutralized when the assume action(s) are denied (an aux-only session action is
 * inert without a live assume, so TRUST-SESSION-CONTROL is always 'none').
 *
 * @param {object} finding a trust finding (TRUST-* canonical shape)
 * @param {object} model normalized, frozen model from buildModel()
 * @returns {'none'|'partial'|'full'}
 */
export function trustFindingDenyState(finding, model) {
  if (!finding || typeof finding !== 'object') return 'none';
  if (typeof finding.id !== 'string' || !finding.id.startsWith('TRUST-')) return 'none';
  if (!model || !Array.isArray(model.statements)) return 'none';

  const ev0 = Array.isArray(finding.evidence) && finding.evidence[0] ? finding.evidence[0] : null;
  const princs = ev0 && Array.isArray(ev0.principals) ? ev0.principals : [];
  const actions = (Array.isArray(finding.actions) ? finding.actions : [])
    .filter((a) => ASSUME_ACTIONS.has(String(a).toLowerCase()));
  if (princs.length === 0 || actions.length === 0) return 'none';

  const denies = trustDenyStatements(model);
  if (denies.length === 0) return 'none';

  // Classify each Deny's principals ONCE and precompute its O(1) coverage index
  // (buildDenyCoverage charges the O(#deny-principals) canonical-key build). This is
  // the residual-DoS fix: the loop body below is now O(1) per (principal, action,
  // deny) instead of rescanning every Deny's principal list, so the many-principals-
  // in-one-Deny shape can no longer multiply the real cost past the charged cost.
  const denyInfos = denies.map((s) => ({
    stmt: s,
    conditioned: hasNonEmptyCondition(s),
    coverage: buildDenyCoverage(classifyPrincipals(s.principal)),
  }));

  // S3-dos-budget-all: this is the confirmed DoS driver - a genuine principals x
  // assume-actions x trust-Deny TRIPLE loop over policy-derived collections. Charge the
  // full combinatorial product UP FRONT (the "cap the product before the exhaustive
  // search" control) so a pathological product trips the deterministic work ceiling
  // immediately, and charge one unit per (principal, action, deny) inspected BELOW so
  // the wall-clock deadline the Node adapters arm is sampled at fine granularity and
  // cannot overrun by more than one work-check interval. The inner-principal factor is
  // charged where it is really spent (buildDenyCoverage above), so the charged work now
  // matches the real work for EVERY shape - including a single Deny carrying thousands
  // of principals. A runaway fails CLOSED on both surfaces instead of returning a
  // COMPLETE verdict after multiple seconds.
  chargeWork(princs.length * actions.length * denyInfos.length);
  let full = true;
  let overlap = false;
  for (const p of princs) {
    for (const a of actions) {
      let coveredUnconditionally = false;
      for (const d of denyInfos) {
        chargeWork(1);
        if (!principalEntryDeniedBy(p, d.coverage)) continue;
        const aa = denyActionApplies(d.stmt, a);
        if (!aa.applies) continue;
        overlap = true;
        if (!d.conditioned && aa.certain) coveredUnconditionally = true;
      }
      if (!coveredUnconditionally) full = false;
    }
  }
  if (full) return 'full';
  return overlap ? 'partial' : 'none';
}

/**
 * Summarize same-policy trust Deny for the coverage panel + exports (IAM-806
 * requirement (c): a neutralizing Deny is NEVER silently discarded from a
 * "complete" analysis). Returns { present, count, unmodeled, note }:
 *   - present:  any same-policy trust Deny statement exists.
 *   - unmodeled: a trust Deny's restricting effect is NOT fully translated into a
 *                suppression - it is conditional, or only PARTIALLY overlaps a
 *                grant. Fully-blocked grants ARE modeled (finding suppressed +
 *                blocked-by-deny edge), matching the identity engine, so they do
 *                not by themselves mark coverage incomplete.
 *   - note:     human-readable caveat text.
 *
 * @param {object} model normalized model
 * @param {Array<object>} findings raw trust findings (analyzeTrust output)
 * @returns {{present:boolean,count:number,unmodeled:boolean,note:(string|null)}}
 */
export function summarizeTrustDeny(model, findings) {
  const denies = trustDenyStatements(model);
  if (denies.length === 0) return { present: false, count: 0, unmodeled: false, note: null };

  const list = Array.isArray(findings) ? findings : [];
  let unmodeled = denies.some((s) => hasNonEmptyCondition(s));
  let anyFull = false;
  for (const f of list) {
    const state = trustFindingDenyState(f, model);
    if (state === 'partial') unmodeled = true;
    if (state === 'full') anyFull = true;
  }

  // The "fully neutralizes the overlapping assume grant" wording may be emitted
  // ONLY when a same-policy Deny actually resolved a finding to 'full'
  // (adversarial-critic IAM-806 iteration 4 defect 2: the note previously claimed
  // neutralization of an overlapping grant whenever a Deny was present and nothing
  // was unmodeled - even when the Deny overlapped NO grant, e.g. a Deny of account
  // 222 alongside an Allow of account 111). When no finding resolved to 'full', the
  // Deny restricts additional principals not otherwise granted; it neutralizes
  // nothing, and the note must say so.
  let effect;
  if (unmodeled) {
    effect =
      'At least one is conditional or only partially overlaps a grant, so its ' +
      'restricting effect is NOT fully reflected in the findings - unsupported ' +
      'does NOT mean safe.';
  } else if (anyFull) {
    effect =
      'Each fully neutralizes the overlapping assume grant, shown as a ' +
      'blocked-by-deny relationship rather than an assume finding.';
  } else {
    effect =
      'None overlaps an analyzed assume grant; each restricts additional ' +
      'principals not otherwise granted by this policy (shown as a blocked-by-' +
      'deny relationship).';
  }
  const note =
    `${denies.length} explicit Deny statement(s) in this trust policy restrict ` +
    'who may assume the role. ' +
    effect;

  return { present: true, count: denies.length, unmodeled, note };
}

/**
 * Analyze a role-trust policy model. Emits trust findings following the
 * documented severity model; NEVER runs identity rules and NEVER emits an
 * identity-style broad-Resource finding. Every finding carries the limitation
 * that the assumed role's permissions are out of scope / unknown.
 *
 * Never throws. Deterministic (findings sorted by statement index, then id).
 *
 * @param {object} model normalized, frozen model (from buildModel/modelFromText)
 * @returns {{ok:boolean, errors:Array, findings:Array<object>}}
 */
