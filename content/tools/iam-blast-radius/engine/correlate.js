// Compound-finding correlation (IAM-105).
//
// After the rule catalog (rules.js) and the escalation engine (escalation.js)
// have each produced their findings, some of those findings are not
// INDEPENDENT risks - they are risk FACTORS of a larger compound escalation
// path. The canonical case: a PassRole -> service-execution path draws its
// grants from two statements; if one of those statements ALSO trips a
// standalone WILDCARD-ACTION / WILDCARD-RESOURCE rule (e.g. the Lambda-creation
// grant is scoped to Resource "*", or PassRole itself is scoped to role/*),
// that wildcard finding restates a scope condition the compound path already
// depends on. Reporting it as its own top-level row is duplicate noise that
// buries the real, higher-severity path.
//
// This module folds such SUBORDINATE findings into the primary compound
// finding as a `subsumed` sub-property (nothing is lost - the full subordinate
// finding is preserved for the per-row detail / export), leaving a single
// primary row that carries the risk-factor checklist. A wildcard finding whose
// statement is NOT consumed by any compound path is genuinely independent and
// is never dropped or altered.
//
// SERVICE-RELATEDNESS GATE (adversarial-iam-semantics fix). Sitting on the same
// STATEMENT as a compound path is necessary but NOT sufficient for a wildcard
// finding to be subordinate. IAM statements routinely bundle unrelated grants:
//   {"Action":["iam:PassRole","lambda:CreateFunction","s3:*"],"Resource":"*"}
// trips PASSROLE-LAMBDA (pass+exec) AND a standalone WILDCARD-ACTION["s3:*"] +
// WILDCARD-RESOURCE on the SAME statement. The s3:* capability is NOT a scope
// factor of the PassRole->Lambda path - it is an independent broad grant. Folding
// it under that path would (a) falsely assert it is a risk factor of that path,
// (b) remove it from the authoritative findings table, and (c) drop it from the
// IAM-106 broad-resource summary - understating blast radius (threat-model T8).
// So a wildcard finding is subsumed ONLY when EVERY action it covers belongs to a
// service the compound path(s) on that statement actually use (iam for the pass
// grant, the executed service for the exec grant). Same-service breadth (e.g.
// lambda:* granting the exec action) stays subordinate; an unrelated-service
// wildcard (s3:*), or a WILDCARD-RESOURCE whose action list ALSO covers an
// unrelated service, remains an independent top-level row and keeps counting in
// the risk summary.
//
// Contracts honored:
//   - Deterministic + pure. No Date.now()/Math.random(); inputs are treated as
//     immutable (they arrive deep-frozen); new objects are returned for the
//     primaries that gain a `subsumed` list, everything else passes through by
//     reference.
//   - Never drops a genuinely independent finding (architecture #6 / T8: an
//     over-eager merge that hid a real risk would overstate safety).

// The only compound path family in this phase: PassRole + service-execution.
// Its findings draw grants from >1 statement (pass + exec) and expose a
// riskFactors checklist. Single-action primitives (policy-version, attach,
// credential-creation, ...) are NOT compound and never subsume anything.
const COMPOUND_TECHNIQUE = 'passrole-service-execution';

// Standalone rule findings that can be subordinate to a compound path when they
// land on a statement the path consumes AND cover only services the path uses
// (see the service-relatedness gate above). Same-service breadth of a pass/exec
// grant is a SCOPE factor the compound path already accounts for via its
// risk-factor checklist; an unrelated-service grant is not.
const SUBORDINATE_RULE_IDS = new Set(['WILDCARD-ACTION', 'WILDCARD-RESOURCE']);

// A WILDCARD-ACTION finding for a bare "*" grants EVERY action, not just the one
// or two actions a compound path consumes on that statement. It is therefore a
// strictly broader, genuinely INDEPENDENT capability - not a mere scope risk
// factor of one PassRole->service path - and folding it under such a path would
// hide the single most important fact about the policy (it grants everything).
// So a full-"*" wildcard-action finding is never subsumed; it always stands as
// its own top-level row (architecture #6 / T8: never drop a genuinely
// independent finding). A narrower service-scoped wildcard action (e.g. the
// exec action itself) remains subordinate per IAM-105.
function isFullWildcardAction(f) {
  return (
    f &&
    f.id === 'WILDCARD-ACTION' &&
    Array.isArray(f.actions) &&
    f.actions.includes('*')
  );
}

function isSubordinateCandidate(f) {
  return SUBORDINATE_RULE_IDS.has(f.id) && !isFullWildcardAction(f);
}

function isCompoundPrimary(f) {
  return !!(
    f &&
    f.escalation &&
    f.escalation.technique === COMPOUND_TECHNIQUE &&
    Array.isArray(f.evidence) &&
    f.evidence.length > 0
  );
}

// The set of statement indices whose grants a compound path is built from.
function pathStatementIndices(primary) {
  const set = new Set();
  for (const ev of primary.evidence) {
    if (ev && typeof ev.statementIndex === 'number') set.add(ev.statementIndex);
  }
  return set;
}

// The AWS service prefix of an action token ("iam:PassRole" -> "iam",
// "s3:*" -> "s3"), lowercased. A bare "*" or a malformed token has no service
// prefix and returns '' - it never matches a concrete path service, so a
// wildcard finding carrying such a token is treated as unrelated (kept
// independent) unless the path itself grants an equally unbounded token.
function actionServiceOf(token) {
  const s = String(token == null ? '' : token);
  const idx = s.indexOf(':');
  return idx === -1 ? '' : s.slice(0, idx).toLowerCase();
}

// The set of services a compound path actually uses, taken from its per-statement
// evidence actions (the pass grant contributes "iam", the exec grant contributes
// the executed service, e.g. "lambda"). Multi-action evidence strings are comma-
// joined, so split them apart. This is the allowlist a subordinate wildcard
// finding's own action services are checked against.
function pathServicesOf(primary) {
  const set = new Set();
  for (const ev of primary.evidence) {
    if (!ev) continue;
    for (const part of String(ev.action == null ? '' : ev.action).split(',')) {
      set.add(actionServiceOf(part.trim()));
    }
  }
  return set;
}

// Does a subordinate wildcard finding cover ONLY services the compound path(s)
// on its statement use? finding.actions holds the wildcard's own action tokens
// (service wildcards for WILDCARD-ACTION; the statement's action list for
// WILDCARD-RESOURCE). Every one must resolve to a service in `pathServices`, or
// the finding introduces capability the path does not account for and must stay
// an independent top-level row.
function coversOnlyPathServices(finding, pathServices) {
  const tokens = Array.isArray(finding.actions) ? finding.actions : [];
  if (tokens.length === 0) return false; // no actions to relate -> not subordinate
  return tokens.every((t) => pathServices.has(actionServiceOf(t)));
}

// A compact, inert snapshot of a subordinate finding for the primary's detail
// panel / export. Keeps the full prose so nothing is lost when the row is
// folded away.
function subsumedView(f) {
  return deepFreeze({
    id: f.id,
    title: f.title,
    severity: f.severity,
    statementSid: f.statementSid,
    statementIndex: f.statementIndex,
    actions: Array.isArray(f.actions) ? f.actions.slice() : [],
    resources: Array.isArray(f.resources) ? f.resources.slice() : [],
    why: f.why,
    limit: f.limit,
    remediation: f.remediation,
    reason: 'Subordinate to a compound escalation path on the same statement: ' +
      'it broadens only the scope of a grant the path already uses (same-service ' +
      'breadth), so it is reported as a risk factor of that path rather than a ' +
      'separate row.',
  });
}

function withSubsumed(primary, subs) {
  const clone = {};
  for (const key of Object.keys(primary)) clone[key] = primary[key];
  clone.subsumed = subs.map(subsumedView);
  return deepFreeze(clone);
}

/**
 * Fold subordinate wildcard/broad-resource findings into the compound
 * escalation paths whose statements they sit on.
 *
 * @param {Array<object>} findings combined rule + escalation findings
 * @returns {Array<object>} new list: subordinate rows removed, their primary
 *          enriched with a frozen `subsumed` array. Order is otherwise the
 *          input order (the caller re-sorts for display).
 */
export function correlateFindings(findings) {
  const list = Array.isArray(findings) ? findings.slice() : [];
  const primaries = list.filter(isCompoundPrimary);
  if (primaries.length === 0) return list;

  // Precompute each primary's consumed-statement set and used-service set once.
  const primaryStmts = new Map(); // primary -> Set<statementIndex>
  const primaryServices = new Map(); // primary -> Set<service>
  for (const primary of primaries) {
    primaryStmts.set(primary, pathStatementIndices(primary));
    primaryServices.set(primary, pathServicesOf(primary));
  }

  // Reference-identity sets: which findings were folded away, and which
  // subordinate findings attach to each primary. A subordinate is subsumed only
  // when, for the compound path(s) that CONSUME its statement, the union of those
  // paths' used services covers EVERY service the finding's actions touch (the
  // service-relatedness gate). It is then removed from the top level once and
  // attached to each consuming primary (its scope factor is relevant to each);
  // primaries iterate in input order for determinism.
  const subsumed = new Set();
  const attachments = new Map(); // primary -> [subordinate findings]

  for (const f of list) {
    if (isCompoundPrimary(f)) continue;
    if (!isSubordinateCandidate(f)) continue;
    if (typeof f.statementIndex !== 'number') continue;

    const consuming = primaries.filter((p) => primaryStmts.get(p).has(f.statementIndex));
    if (consuming.length === 0) continue; // no path uses this statement -> independent

    // Union of the consuming paths' used services. Only if the finding covers
    // NOTHING outside that union is it a scope factor rather than an independent
    // capability (e.g. an unrelated s3:* bundled onto a PassRole statement).
    const union = new Set();
    for (const p of consuming) for (const svc of primaryServices.get(p)) union.add(svc);
    if (!coversOnlyPathServices(f, union)) continue; // unrelated capability -> stays top-level

    for (const p of consuming) {
      if (!attachments.has(p)) attachments.set(p, []);
      attachments.get(p).push(f);
    }
    subsumed.add(f);
  }

  const out = [];
  for (const f of list) {
    if (subsumed.has(f)) continue; // folded into a primary's risk factors
    if (attachments.has(f)) out.push(withSubsumed(f, attachments.get(f)));
    else out.push(f);
  }
  return out;
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Object.isFrozen(value)) return value;
  Object.freeze(value);
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

export default correlateFindings;
