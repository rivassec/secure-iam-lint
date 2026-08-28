// resource-source-binding.js - aws:SourceAccount/SourceArn/SourceOwner confused-deputy binding analysis. Extracted (behavior-preserving).
import { parseArn } from './arn-util.js';
import { parseOperator, NEGATED_OPERATORS } from './conditions.js';
import { chargeWork } from './glob.js';

export const POSITIVE_MATCH_OPERATORS = Object.freeze(new Set([
  'stringequals', 'stringequalsignorecase', 'stringlike', 'arnequals', 'arnlike',
]));

// The account (12-digit) a source-binding value pins, or null: a bare account id,
// or the account segment (ARN field 4) of a SourceArn value. Partition-agnostic
// (test 47). Used both to decide a binding is concrete and to compare SourceArn's
// account against SourceAccount for the mismatch case (test 53).
export function accountFromSourceValue(value) {
  const s = String(value).trim();
  if (/^\d{12}$/.test(s)) return s;
  const arn = parseArn(s);
  if (arn && /^\d{12}$/.test(String(arn.account))) return arn.account;
  return null;
}

// A source-binding VALUE that pins nothing (a bare "*", empty, or an ARN whose
// account AND resource segments are both pure wildcards - arn:aws:*:*:*:*). Such a
// value lets every source through, so it is NOT a real confused-deputy binding and
// must not be credited (mirrors the trust-family "value must narrow" rule).
export function isMatchAllSourceValue(value) {
  const s = String(value).trim();
  if (s === '' || s === '*') return true;
  if (/^arn:/i.test(s)) {
    const segs = s.split(':');
    const account = segs.length > 4 ? segs[4] : '';
    const resource = segs.length > 5 ? segs.slice(5).join(':') : '';
    const accountGlob = account === '' || /^[*?]+$/.test(account);
    const resourceGlob = resource === '' || /^[*?/:]+$/.test(resource);
    if (accountGlob && resourceGlob) return true;
  }
  return false;
}

export function toSourceValueList(value) {
  if (Array.isArray(value)) {
    return value
      .filter((v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')
      .map((v) => String(v));
  }
  if (value === null || value === undefined) return [];
  return [String(value)];
}

// The single account pinned by a list of source values, or null when the list is
// empty, contains an unpinnable value, or pins more than one account (ambiguous ->
// no mismatch determination on that axis; never guess).
export function commonSourceAccount(values) {
  if (values.length === 0) return null;
  // S3-dos-budget-all (defense in depth): charge per source value inspected so this
  // linear-today scan participates in the cooperative work budget (T5/T8).
  chargeWork(values.length);
  const accts = values.map(accountFromSourceValue);
  if (accts.some((a) => a === null)) return null;
  const set = new Set(accts);
  return set.size === 1 ? [...set][0] : null;
}

// The DEDUPED set (as an ordered array) of every RESOLVABLE 12-digit account pinned
// by a list of source values. Unlike commonSourceAccount(), a multi-account value
// list yields the full set instead of collapsing to null, and unpinnable values
// (bare "*", account-less ARNs) are simply omitted rather than poisoning the result.
// Used to detect a SourceArn-vs-SourceAccount mismatch across a SET of source
// accounts, not only a single common one (a multi-account SourceArn whose accounts
// ALL disagree with SourceAccount is still an internally inconsistent binding).
export function sourceAccountSet(values) {
  // S3-dos-budget-all (iter-5): this dedup runs over aws:SourceArn / aws:SourceAccount
  // condition-value arrays, which validate.js caps but which are still attacker-sized.
  // The old `out.includes(a)` push made it O(V^2); a Set makes it O(V), and charging
  // one work unit per value makes the deterministic budget SAMPLE the traversal (the
  // matcher is never reached from here, so without this the budget accrued zero and a
  // runaway would have returned a COMPLETE verdict - the T5 fail-open class).
  chargeWork(Array.isArray(values) ? values.length : 0);
  const out = [];
  const seen = new Set();
  for (const v of values) {
    const a = accountFromSourceValue(v);
    if (a !== null && !seen.has(a)) {
      seen.add(a);
      out.push(a);
    }
  }
  return out;
}

// Analyze the source-binding condition keys on a statement that grants a service
// principal. Only a POSITIVE, NON-negated, NON-bypassable operator whose value
// space actually narrows counts as a binding; a negated/...IfExists/ForAllValues
// qualifier is trivially evaded (or is an exclusion) and is recorded in
// bypassedKeys so the exposure finding can name why a would-be binding does not
// count. IAM combines a key's multiple values with OR, so a co-listed match-all
// value defeats the whole binding (.every, matching the trust family).
export function sourceBindingAnalysis(condition) {
  const out = {
    sourceArn: { bound: false, account: null, accounts: [] },
    sourceAccount: { bound: false, account: null, accounts: [] },
    sourceOrg: false,
    // aws:SourceOwner (IAM-1404): a DEPRECATED legacy confused-deputy source-binding
    // key (chiefly Amazon SNS). It is still a REAL source binding when present under a
    // positive, non-bypassable operator (the account id of the source owner), so it
    // makes the service grant source-bound rather than a missing binding - but it is
    // deprecated in favor of aws:SourceArn / aws:SourceAccount. Tracked separately from
    // sourceArn/sourceAccount so it never participates in the SourceArn-vs-SourceAccount
    // mismatch determination (it is a distinct key), only in whether ANY binding exists.
    sourceOwner: false,
    boundKeys: [],
    bypassedKeys: [],
  };
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return out;
  // S3-dos-budget-all (iter-5): dedup the accumulated account SETs through Sets, not
  // Array.includes(), so merging across many condition operators/keys stays O(V) not
  // O(V^2). The parallel arrays remain the public shape (ordered, first-seen); the
  // Sets are the membership index only.
  const arnAcctSeen = new Set();
  const srcAcctSeen = new Set();
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    const { base } = parseOperator(op);
    const negated = NEGATED_OPERATORS.has(base);
    const positive = POSITIVE_MATCH_OPERATORS.has(base);
    // A ...IfExists suffix or a ForAllValues: set qualifier PASSES when the key is
    // absent, so any binding it carries is trivially bypassed by omitting the key.
    const lowerOp = String(op).toLowerCase();
    const bypassable = lowerOp.includes('ifexists') || lowerOp.startsWith('forallvalues:');
    for (const rawKey of Object.keys(inner)) {
      const key = String(rawKey).toLowerCase();
      const isSourceKey =
        key === 'aws:sourcearn' || key === 'aws:sourceaccount' ||
        key === 'aws:sourceorgid' || key === 'aws:sourceorgpaths' ||
        key === 'aws:sourceowner';
      if (!isSourceKey) continue;
      const values = toSourceValueList(inner[rawKey]);
      const binds = positive && !negated && !bypassable &&
        values.length > 0 && values.every((v) => !isMatchAllSourceValue(v));
      if (!binds) {
        out.bypassedKeys.push(rawKey);
        continue;
      }
      out.boundKeys.push(rawKey);
      if (key === 'aws:sourcearn') {
        out.sourceArn.bound = true;
        out.sourceArn.account = commonSourceAccount(values);
        for (const a of sourceAccountSet(values)) {
          if (!arnAcctSeen.has(a)) {
            arnAcctSeen.add(a);
            out.sourceArn.accounts.push(a);
          }
        }
      } else if (key === 'aws:sourceaccount') {
        out.sourceAccount.bound = true;
        out.sourceAccount.account = commonSourceAccount(values);
        // Mirror the SourceArn side: track the full RESOLVABLE account SET (not only
        // the single common value, which commonSourceAccount() collapses to null for
        // a multi-valued key). This makes the SourceArn-vs-SourceAccount mismatch
        // check SYMMETRIC - a multi-account aws:SourceAccount whose every value
        // disagrees with the SourceArn account is still internally inconsistent and
        // must not be mis-credited as a clean source-bound control.
        for (const a of sourceAccountSet(values)) {
          if (!srcAcctSeen.has(a)) {
            srcAcctSeen.add(a);
            out.sourceAccount.accounts.push(a);
          }
        }
      } else if (key === 'aws:sourceowner') {
        out.sourceOwner = true;
      } else {
        out.sourceOrg = true;
      }
    }
  }
  out.boundKeys.sort();
  out.bypassedKeys.sort();
  return out;
}
