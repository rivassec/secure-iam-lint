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

// --- IAM-201: same-statement capability subsumption --------------------------
//
// A second, narrower correlation. Independently of any compound escalation
// path, a generic WILDCARD-RESOURCE finding is often just the scope amplifier
// of a MORE-SPECIFIC capability that trips on the SAME statement: kms:Decrypt on
// "*", secretsmanager:GetSecretValue on "*", iam:* on "*", a delete-family grant
// on "*", cloudtrail:StopLogging on "*". In each case the broad-resource grant
// does not name an independent risk - it says the co-located capability applies
// to every resource. Reporting it as its own top-level WILDCARD-RESOURCE row is
// duplicate noise that buries the capability that actually matters.
//
// So a WILDCARD-RESOURCE on a statement that ALSO carries one of the capability
// findings below is folded INTO that capability finding (as a `subsumed` entry +
// a synthesized risk-factor checklist), exactly as IAM-105 folds subordinate
// wildcards into a compound path. Nothing is lost: the full subordinate finding
// is preserved in `subsumed[]` and its scope signal is captured in the primary's
// risk factors.
//
// SAFETY (threat-model T8 - never understate blast radius). Two guards:
//   1. Only WILDCARD-RESOURCE is subsumed here, never a full-"*" WILDCARD-ACTION
//      (that grants EVERY action and is strictly broader than any one
//      capability - it stays an independent top-level row).
//   2. Service-relatedness gate, as in the compound pass: the WILDCARD-RESOURCE
//      is subsumed ONLY when every service its action list touches is a service
//      some capability finding on that statement already covers. A broad-resource
//      grant that also spans an unrelated service (e.g. iam:PutUserPolicy AND
//      s3:PutObject, both on "*") keeps that unrelated breadth visible as its own
//      row rather than hiding it under the IAM finding.
// A WILDCARD-RESOURCE with NO more-specific capability on its statement (e.g.
// s3:PutObject on "*" alone) is genuinely standalone and never subsumed.
//
// Deterministic priority: when several capability findings sit on one statement,
// the WILDCARD-RESOURCE attaches to the highest-priority one in this fixed order.
const CAPABILITY_PRIMARY_IDS = [
  'KMS-DECRYPT',
  'DATA-EXFIL',
  'DIRECT-IAM-ADMIN',
  'DESTRUCTIVE-ACTION',
  'DETECTION-IMPAIRMENT',
];
const CAPABILITY_PRIORITY = new Map(
  CAPABILITY_PRIMARY_IDS.map((id, i) => [id, i]),
);

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

// Reason wording for the two DISTINCT subsumption relationships. Keeping them
// separate matters for truthfulness (adversarial-iam-semantics): only the
// compound pass has actually detected an escalation path, so only its wording
// may assert one. The capability pass folds a WILDCARD-RESOURCE into a
// standalone capability finding (KMS-DECRYPT, DATA-EXFIL, ...) that carries NO
// escalation enrichment and NO compound technique - claiming a "path"/"compound
// escalation path" there would assert a path the analysis never found (T8-style
// over-assertion). Its wording therefore speaks only of a more-specific
// capability finding, never of a path.
const COMPOUND_SUBSUMED_REASON =
  'Subordinate to a compound escalation path on the same statement: ' +
  'it broadens only the scope of a grant the path already uses (same-service ' +
  'breadth), so it is reported as a risk factor of that path rather than a ' +
  'separate row.';
const CAPABILITY_SUBSUMED_REASON =
  'Subordinate to the more-specific capability finding on the same statement: ' +
  'it only broadens the resource scope of that capability, so it is folded in ' +
  'as a risk factor of that finding rather than a separate row.';

// A compact, inert snapshot of a subordinate finding for the primary's detail
// panel / export. Keeps the full prose so nothing is lost when the row is
// folded away. `reason` names WHY the row was folded and is caller-supplied so
// the compound and capability passes can each state their true relationship.
function subsumedView(f, reason) {
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
    reason: String(reason == null ? COMPOUND_SUBSUMED_REASON : reason),
  });
}

function withSubsumed(primary, subs) {
  const clone = {};
  for (const key of Object.keys(primary)) clone[key] = primary[key];
  clone.subsumed = subs.map((s) => subsumedView(s, COMPOUND_SUBSUMED_REASON));
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
  const afterCompound = correlateCompoundPaths(findings);
  return correlateSameStatementCapabilities(afterCompound);
}

function correlateCompoundPaths(findings) {
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

// --- IAM-201 capability pass -------------------------------------------------

function isCapabilityPrimary(f) {
  return !!(f && CAPABILITY_PRIORITY.has(f.id));
}

// Case-insensitive scan for a Condition key anywhere in the statement's
// condition block ({ Operator: { "kms:ViaService": ... } }). Returns true when
// any inner key equals `needleLower`. Treats input as inert data only.
function conditionHasKey(condition, needleLower) {
  if (!condition || typeof condition !== 'object') return false;
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object') continue;
    for (const key of Object.keys(inner)) {
      if (String(key).toLowerCase() === needleLower) return true;
    }
  }
  return false;
}

// Synthesize the present/absent risk-factor checklist a capability finding
// exposes once it absorbs a WILDCARD-RESOURCE scope amplifier. Deterministic
// order: one factor per granted capability action, then the resource-scope
// factor, then any capability-specific scope-restriction factors (KMS).
function capabilityRiskFactors(primary, wr) {
  const factors = [];
  const actions = Array.isArray(primary.actions) ? primary.actions : [];
  for (const action of actions) {
    factors.push({ key: String(action), label: `${String(action)} granted`, present: true });
  }
  const broadStar = Array.isArray(wr.resources) && wr.resources.includes('*');
  factors.push({
    key: 'resource-wildcard',
    label: broadStar ? 'Resource:*' : 'Resource scope broad (NotResource-based)',
    present: true,
  });
  if (primary.id === 'KMS-DECRYPT') {
    factors.push({
      key: 'kms-viaservice',
      label: 'kms:ViaService restriction',
      present: conditionHasKey(primary.conditions, 'kms:viaservice'),
    });
    factors.push({
      key: 'kms-encryptioncontext',
      label: 'kms:EncryptionContext restriction',
      present: conditionHasKey(primary.conditions, 'kms:encryptioncontext'),
    });
  }
  return factors;
}

function withCapabilitySubsumed(primary, wr) {
  const clone = {};
  for (const key of Object.keys(primary)) clone[key] = primary[key];
  clone.riskFactors = capabilityRiskFactors(primary, wr);
  clone.subsumed = [subsumedView(wr, CAPABILITY_SUBSUMED_REASON)];
  return deepFreeze(clone);
}

/**
 * Fold a same-statement WILDCARD-RESOURCE scope amplifier into the more-specific
 * capability finding on that statement (IAM-201). Runs after the compound pass,
 * so a WILDCARD-RESOURCE already subsumed by an escalation path is gone from the
 * top level and never reaches here.
 *
 * @param {Array<object>} findings post-compound-pass finding list
 * @returns {Array<object>} new list: same-statement WILDCARD-RESOURCE rows folded
 *          into their capability primary; standalone wildcards untouched.
 */
function correlateSameStatementCapabilities(findings) {
  const list = Array.isArray(findings) ? findings.slice() : [];

  // Index capability primaries by statement index; keep only the highest-priority
  // one per statement as the attach target, but track every capability's services
  // on that statement for the relatedness gate.
  const capsByStmt = new Map(); // statementIndex -> [capability findings]
  for (const f of list) {
    if (!isCapabilityPrimary(f)) continue;
    if (typeof f.statementIndex !== 'number') continue;
    if (!capsByStmt.has(f.statementIndex)) capsByStmt.set(f.statementIndex, []);
    capsByStmt.get(f.statementIndex).push(f);
  }
  if (capsByStmt.size === 0) return list;

  const attachTo = new Map(); // capability finding -> WILDCARD-RESOURCE finding
  const subsumed = new Set(); // WILDCARD-RESOURCE findings folded away

  for (const f of list) {
    if (f.id !== 'WILDCARD-RESOURCE') continue;
    if (typeof f.statementIndex !== 'number') continue;
    const caps = capsByStmt.get(f.statementIndex);
    if (!caps || caps.length === 0) continue; // standalone broad-resource -> keep

    // Service-relatedness gate: every service the broad-resource grant touches
    // must be covered by some capability on this statement, else it also spans an
    // unrelated capability and must stay a visible independent row.
    const covered = new Set();
    for (const c of caps) {
      for (const a of (Array.isArray(c.actions) ? c.actions : [])) {
        covered.add(actionServiceOf(a));
      }
    }
    const wrActions = Array.isArray(f.actions) ? f.actions : [];
    if (wrActions.length === 0) continue;
    if (!wrActions.every((a) => covered.has(actionServiceOf(a)))) continue;

    // Attach to the highest-priority capability on this statement (deterministic).
    let target = caps[0];
    for (const c of caps) {
      if (CAPABILITY_PRIORITY.get(c.id) < CAPABILITY_PRIORITY.get(target.id)) target = c;
    }
    attachTo.set(target, f);
    subsumed.add(f);
  }

  if (subsumed.size === 0) return list;

  const out = [];
  for (const f of list) {
    if (subsumed.has(f)) continue; // folded into its capability primary
    if (attachTo.has(f)) out.push(withCapabilitySubsumed(f, attachTo.get(f)));
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
