// rules-finding.js - rule finding factory + resource-scope/broadness helpers + deny-fence suppression (makeFinding, resourceScope, denyFencesToNarrow, ruleFindingDenySuppressed, survivingBroadReadActions). Extracted (behavior-preserving).
import { actionGrants, actionVerb, isFullWildcard, isServiceWildcard, lowerConfidence, statementSid, CAPABILITY_LIMIT, CONDITION_LIMIT, COMPLEMENT_LIMIT, READ_VERB, BULK_READ_ACTIONS } from './rules-classify.js';
import { applyDenyToActions, denyActionApplies } from './escalation-deny.js';
import { hasNonEmptyCondition } from './escalation-conditions.js';
import { classifyResource, RESOURCE_CLASS } from './resource-arn.js';
import { chargeWork } from './glob.js';
import { RULES } from './rules-catalog.js';

export function makeFinding(ruleId, stmt, fields) {
  const meta = RULES[ruleId];
  const conditioned = stmt.condition !== null && stmt.condition !== undefined;
  // Split certainty (IAM-104), replacing the single `confidence` field:
  //   policyEvidence     - how strongly this policy text establishes the grant.
  //                        Drives graph edge certainty (see graph.js).
  //   pathExploitability - how likely the grant actually yields the flagged
  //                        impact. These rule findings are DIRECT capabilities
  //                        (a wildcard scope, a broad data read, direct IAM
  //                        admin): the grant itself IS the risk, with no unknown
  //                        target role gating it, so exploitability defaults to
  //                        the same base as the evidence. A Condition on the
  //                        statement is a runtime gate that weakens BOTH a notch
  //                        (rules.js models Conditions; graph.js layers on
  //                        same-policy Deny precedence for the edge certainty).
  const evidenceBase = fields.policyEvidence;
  const exploitBase = fields.pathExploitability || fields.policyEvidence;

  // IAM-704: complement (NotAction / NotResource) presentation. NEVER surface the
  // EXCLUDED set as the finding's allowed actions/resources (tests 13, 14):
  //   - NotAction: there are no positive granted actions to list; the grant is
  //     "everything except the excluded set", so the granted-action summary is
  //     '*' (never the excluded list), and the excluded list rides in
  //     excludedActions.
  //   - NotResource: there is no literal granted resource ARN; resources is left
  //     empty and the carve-out rides in excludedResources (never presented as
  //     the granted resource).
  // Complement grants are approximate, so confidence drops a notch (on top of
  // any Condition notch) and the limit spells out the complement caveat.
  const usesNotAction = Array.isArray(stmt.notActions) && stmt.notActions.length > 0;
  const usesNotResource = Array.isArray(stmt.notResources) && stmt.notResources.length > 0;
  const complement = [];
  if (usesNotAction) complement.push('NotAction');
  if (usesNotResource) complement.push('NotResource');
  const complementDerived = complement.length > 0;

  const actions = usesNotAction ? ['*'] : fields.actions.slice();
  const resources = usesNotResource ? [] : (fields.resources || []).slice();

  let peNotches = 0;
  let pxNotches = 0;
  if (conditioned) { peNotches += 1; pxNotches += 1; }
  if (complementDerived) { peNotches += 1; pxNotches += 1; }

  const finding = {
    id: meta.id,
    severity: fields.severity,
    // The title is tool-authored rule metadata (never attacker text) and is NOT part of
    // the SARIF semantic identity / partialFingerprint (sarif.mjs hashes findingIdentity,
    // not the title), so a per-finding title override cannot forge or churn a fingerprint.
    // It lets ONE rule id carry a SERVICE-ACCURATE title when a single id spans several
    // datastores (NEW-01: CROSS-ACCOUNT-DATA-READ-UNDETERMINED describes an S3 bucket OR a
    // dynamodb/kinesis/rds-data container). Absent an override it falls back to meta.title,
    // so every existing caller is byte-unchanged.
    title: typeof fields.title === 'string' && fields.title.length > 0 ? fields.title : meta.title,
    statementSid: statementSid(stmt),
    statementIndex: stmt.index,
    actions,
    resources,
    conditions: stmt.condition, // null when absent; inert data otherwise
    policyEvidence: lowerConfidence(evidenceBase, peNotches),
    pathExploitability: lowerConfidence(exploitBase, pxNotches),
    why: fields.why,
    limit:
      CAPABILITY_LIMIT +
      (conditioned ? CONDITION_LIMIT : '') +
      (complementDerived ? COMPLEMENT_LIMIT : ''),
    remediation: fields.remediation,
    ruleVersion: meta.ruleVersion,
    docRef: meta.docRef,
  };
  // The excluded set is inert policy data, preserved so nothing is lost - but it
  // is a SEPARATE field, explicitly the EXCLUDED (not allowed) set.
  if (usesNotAction) finding.excludedActions = stmt.notActions.slice();
  if (usesNotResource) finding.excludedResources = stmt.notResources.slice();
  if (complementDerived) finding.complement = complement.slice();
  return finding;
}

// The resource scope a finding reports: prefer explicit Resource, fall back to
// NotResource (annotating the inverse), else an explicit "unspecified" marker.
export function resourceScope(stmt) {
  if (stmt.resources.length > 0) return stmt.resources;
  if (stmt.notResources.length > 0) return stmt.notResources;
  return ['(no Resource/NotResource specified)'];
}

// Is a single Resource ARN broad - i.e. does it match all / nearly-all ARNs so a
// grant on it reaches essentially every resource rather than a specific one? This is
// the rules-engine breadth predicate; it is now a thin wrapper over the ONE shared
// semantic classifier (engine/resource-arn.js). A value is broad when classifyResource
// returns BROAD (the bare "*", a wildcard in the partition/service/account, a
// whole-collection identifier wildcard like role/*, a bucket-name-segment wildcard, or
// a no-delimiter typed-resource glob like function*/role*). A concrete, account-scoped
// resource whose only wildcard sits after a concrete top-level name
// (arn:aws:s3:::my-bucket/prefix/*, arn:aws:iam::123456789012:role/app-*) is NARROW.
//
// A MALFORMED value (not "*" and not a well-formed ARN, or leading/trailing whitespace,
// or a would-be-narrow ARN on a service the engine does not model) is NOT broad here -
// firing a confident broad finding on an undecidable value would overstate certainty
// (threat-model T8). masked-grant.js reads the SAME classifier and routes MALFORMED to
// coverage.summary.incomplete, so every non-"*"/non-well-formed-ARN value is fail-CLOSED
// (broad-and-firing, or undecidable-and-incomplete) and never a bare CLEAN.
export function isBroadArnResource(resource) {
  return classifyResource(resource) === RESOURCE_CLASS.BROAD;
}

// Is the resource scope broad enough that "on everything" is a fair reading?
// True when the statement uses NotResource (Allow everything except a few), or
// ANY listed Resource is the bare "*" or an ARN-wildcard that matches all /
// nearly-all ARNs (see isBroadArnResource) - all grant across essentially every
// ARN. Fixing the ARN-wildcard case closes a DATA-EXFIL fail-open (T8): a bulk
// read on arn:aws:s3:::*/* is just as account-wide as one on "*".
export function resourceIsBroad(stmt) {
  return (
    stmt.notResources.length > 0 ||
    stmt.resources.some(isBroadArnResource)
  );
}

// Is a single action pattern a non-read (mutating/privileged) action - the kind
// for which a wildcard resource is a meaningful, remediable risk? A read/
// enumeration verb (get/list/describe/...) is treated as read; anything else -
// including a wildcard or an unknown/malformed verb - is the safe
// over-approximation "write". Enumeration actions (iam:ListRoles,
// ec2:DescribeInstances, s3:ListAllMyBuckets) are reads: many legitimately
// REQUIRE Resource:* because they have no resource-level scoping, so a wildcard
// on them is normal, not remediable (suite-3 tests 92/93/94).
export function isNonReadAction(p) {
  if (isFullWildcard(p)) return true;
  if (isServiceWildcard(p)) return true;
  const verb = actionVerb(p);
  if (verb === '' || verb === '*') return true; // unknown scope -> treat as write
  return !READ_VERB.test(verb);
}

// Does the statement grant at least one non-read (mutating/privileged) action?
// Used to decide whether a wildcard resource is a meaningful risk vs. a routine
// read-only wildcard (e.g. ec2:Describe* on "*").
export function grantsNonReadAction(stmt) {
  if (stmt.notActions.length > 0) return true; // Allow NotAction => includes writes
  return stmt.actions.some(isNonReadAction);
}

// The explicit actions in a statement for which a wildcard resource is actually
// dangerous and remediable, i.e. the non-read (mutating/privileged) subset. In a
// statement mixing a required-wildcard enumeration action with a dangerous one -
// e.g. ["iam:ListRoles", "iam:PassRole"] on Resource "*" (suite-3 test 95) - only
// iam:PassRole belongs in the WILDCARD-RESOURCE finding: recommending "scope
// Resource to specific ARNs" for iam:ListRoles is impossible remediation, since
// ListRoles has no resource-level scoping. Per-action, not one conclusion for the
// whole statement. Only reached when grantsNonReadAction(stmt) is already true,
// so the result is non-empty for the explicit-actions path.
export function remediableWildcardActions(stmt) {
  return stmt.actions.filter(isNonReadAction);
}

// --- Same-policy explicit-Deny precedence (IAM-302) --------------------------
// AWS resolves access with explicit Deny overriding Allow, so a rule finding -
// a CAPABILITY of the analyzed identity - is not real when a same-policy Deny
// removes the whole granted capability. rules.js deliberately stays Deny-UNAWARE
// when it EMITS findings: the graph (graph.js) needs the un-suppressed finding to
// draw the `blocked-by-deny` edge that shows the user the grant exists but is
// blocked (a Phase-2 invariant). Instead, this module exposes
// ruleFindingDenySuppressed() so the pipeline (analyze.js) can drop a
// fully-denied rule finding from the AUTHORITATIVE TABLE while the graph still
// receives the full finding set. Escalation findings already have Deny folded in
// by escalation.js, so this only concerns rule findings.

// Does a same-policy Deny "fence" a broad Allow of `action` down to a NARROW,
// specific set - so the effective resource scope is no longer broad? A Deny with
// NotResource denies the action on EVERY resource EXCEPT the listed ones, so an
// unconditional, certainly-applicable NotResource Deny confines the broad Allow
// to exactly those spared resources. When that spared set is itself narrow (no
// bare "*"), the action is no longer broadly resource-scoped and a broad-scope
// finding (e.g. DATA-EXFIL bulk read) must not fire (IAM-301 negative corpus:
// notresource-deny-fences-exfil). A conditional Deny is not treated as a
// definitive fence (it may not apply at runtime).
export function denyFencesToNarrow(denies, action, allowStmt) {
  if (!denies || denies.length === 0) return false;
  for (const deny of denies) {
    if (hasNonEmptyCondition(deny)) continue;
    if (deny.notResources.length === 0) continue; // only a NotResource Deny fences
    // A NotResource Deny denies the action on EVERY resource EXCEPT its SPARED set
    // (deny.notResources). It only narrows the broad Allow if that spared set is
    // PROVEN NARROW. Crediting the Deny as a fence SUPPRESSES a finding, so the burden
    // is to PROVE narrowness: any spared element that is not a NARROW verdict from the
    // shared classifier - BROAD (the bare "*", or an ARN-wildcard like arn:aws:s3:::*/*
    // that spares all S3 objects) OR MALFORMED (an undecidable value like a bare token,
    // where narrowness rests on the UNVERIFIED grammar the HYBRID default refuses to
    // trust) - leaves the spared set NOT provably narrow, so the Deny's EFFECTIVE
    // denied set covers ~nothing / is undecidable and must NOT be credited as a
    // narrowing fence. Two bug-for-bug fail-opens this closes: a BROAD spared set
    // ({Deny NotResource:'arn:aws:s3:::*/*'} denies everything EXCEPT all S3 objects =
    // denies NOTHING) and a MALFORMED spared set ({Deny NotResource:'not-an-arn'} whose
    // scope is undecidable) both used to suppress DATA-EXFIL. Breadth read from the ONE
    // shared classifier, never re-implemented here; fail closed on anything but NARROW.
    //
    // NEW-BUDGET-DENYFENCE (HIGH DoS): charge work per spared element INSPECTED so this walk
    // SAMPLES both cooperative budgets (the deterministic 60M work ceiling and the Node
    // wall-clock deadline). denyFencesToNarrow is called ONCE PER MATCHED ACTION from three
    // call sites on the normal analyze() path (ruleFindingDenySuppressed, run per finding;
    // survivingBroadReadActions; survivingSparedContainerReads), so N matched actions x M
    // spared elements is an O(N*M) walk. classifyResource charges ZERO on the well-formed
    // NARROW-ARN path (parseArn is pure; the withoutBudget-wrapped globReachesMultipleAccounts
    // only runs on parse failure), so before this the whole walk advanced the budget zero and a
    // within-caps N x M deny fence ran ~unbudgeted (it aborted only when other charged work
    // slowly crossed the ceiling, tens of seconds later). The charge is PROPORTIONAL to the
    // string classifyResource actually scans (its length + 1, mirroring how glob.js charges a
    // compare by its char count), so the budget it consumes tracks real per-element cost and the
    // 60M ceiling trips at the engine's calibrated ~1-2s rather than tens of seconds. A small
    // deny fence inspects a handful of short elements and never newly trips the budget (verdicts
    // unchanged); a pathological one aborts mid-scan. chargeWork throws the tagged
    // GlobBudgetError, which propagates through this function's callers to analyzeRules (which
    // re-throws isGlobBudgetError) and analyze() (which maps the 'work' kind to the fail-closed
    // "aborted (resource budget)" verdict). The `+ 1` guarantees a nonzero charge even for an
    // empty element so the counter always advances.
    if (deny.notResources.some((r) => {
      chargeWork(String(r == null ? '' : r).length + 1);
      return classifyResource(r) !== RESOURCE_CLASS.NARROW;
    })) continue;
    const a = denyActionApplies(deny, action);
    if (a.applies && a.certain) return true;
  }
  return false;
}

// A bulk object-read action (s3:GetObject family): its exfil risk is only
// flagged when the resource scope is BROAD, so a NotResource Deny that fences the
// broad Allow to a narrow set removes the risk entirely. Secret-read actions
// (Secrets Manager / SSM), by contrast, fire regardless of scope, so a resource
// fence does not neutralize them.
export function isBulkReadAction(action) {
  return BULK_READ_ACTIONS.some((concrete) => actionGrants(action, concrete));
}

/**
 * Does same-policy explicit-Deny precedence fully remove the capability a RULE
 * finding reports, so it must not appear in the authoritative findings TABLE
 * (IAM-302)? True only when EVERY action the finding rests on is either
 * definitively blocked by an unconditional in-scope Deny, or (for a broad
 * bulk-read DATA-EXFIL) fenced down to a narrow resource set by a NotResource
 * Deny. A finding with any surviving action stays. Escalation findings (which
 * carry `escalation` enrichment) already have Deny folded in by escalation.js
 * and are never suppressed here. Deterministic; never throws.
 *
 * @param {object} finding a rule/escalation finding (canonical shape)
 * @param {object} model normalized, frozen model from buildModel()
 * @returns {boolean}
 */
export function ruleFindingDenySuppressed(finding, model) {
  if (!finding || typeof finding !== 'object') return false;
  // Only rule-catalog findings are Deny-unaware here; escalation findings arrive
  // pre-resolved. Guard on the rule catalog + absence of escalation enrichment.
  if (finding.escalation) return false;
  if (!Object.prototype.hasOwnProperty.call(RULES, finding.id)) return false;
  if (!model || !Array.isArray(model.statements)) return false;
  if (typeof finding.statementIndex !== 'number') return false;

  const allowStmt = model.statements.find((s) => s && s.index === finding.statementIndex);
  if (!allowStmt) return false;
  // Same identity-statement Deny set the escalation engine uses (a Deny that
  // names a Principal is a resource/trust-policy statement, not an identity
  // constraint on the analyzed subject).
  const denies = model.statements.filter((s) => s.effect === 'Deny' && s.principal == null);
  if (denies.length === 0) return false;

  const actions = Array.isArray(finding.actions) ? finding.actions : [];
  if (actions.length === 0) return false;

  // Drop the actions an unconditional, in-scope Deny definitively blocks.
  const survivors = applyDenyToActions(denies, actions, allowStmt).actions;

  // A broad bulk-read whose scope a NotResource Deny fences to a narrow set no
  // longer holds as a broad-exfil capability (secret reads are unaffected).
  //
  // S3-class-sweep (part B justification): the `finding.id === 'DATA-EXFIL' &&
  // isBulkReadAction(a)` gate is SERVICE-SCOPED (isBulkReadAction / BULK_READ_ACTIONS is
  // s3:GetObject[Version] only), but it is NOT a sibling of the S1 undetermined-read fail-open,
  // because it is a SUPPRESSION gate that fails CLOSED for every non-s3 sibling: this is the ONLY
  // path that DROPS an action from a finding, and its scope is exactly DATA-EXFIL's own bulk
  // catalog. DATA-EXFIL fires its bulk arm ONLY on those same s3 actions (ruleDataExfil), so the
  // gate can only ever remove an action DATA-EXFIL actually reported. A non-s3 bulk read
  // (dynamodb:Scan / kinesis:GetRecords / rds-data:*) is never a DATA-EXFIL and never matches
  // isBulkReadAction, so it falls to `return true` and is KEPT (fenced or not) - it is surfaced
  // by WILDCARD-RESOURCE (bare "*") or the SERVICE-AGNOSTIC CROSS-ACCOUNT-DATA-READ-UNDETERMINED /
  // survivingSparedContainerReads paths (S1/NEW-01), never silently cleared here. Widening this
  // gate to non-s3 would over-SUPPRESS, i.e. it is the fail-CLOSED direction; leaving it s3-scoped
  // is correct.
  const stillReal = survivors.filter((a) => {
    if (finding.id === 'DATA-EXFIL' && isBulkReadAction(a)) {
      return !denyFencesToNarrow(denies, a, allowStmt);
    }
    return true;
  });

  return stillReal.length === 0;
}

/**
 * Filter a statement's candidate resource-scopable READ actions down to those
 * that SURVIVE same-policy explicit Deny as a BROAD read. Mirrors
 * ruleFindingDenySuppressed() at the statement level (identical Deny semantics,
 * no drift): an action an unconditional, in-scope Deny definitively blocks
 * (applyDenyToActions removes it) is gone; a bulk object-read whose broad scope a
 * NotResource Deny fences to a narrow set (denyFencesToNarrow) is no longer a
 * broad read. When nothing survives, the statement's broad Resource is Deny-
 * covered - not a surviving broad read - so analyze.js's broad-uncovered net must
 * NOT flip coverage incomplete on it (IAM-301 negative corpus:
 * explicit-deny-suppresses-exfil, notresource-deny-fences-exfil).
 *
 * The net keys off the FENCED effective scope, not the literal "*" resource: a
 * read that is fully denied, or fenced down to a narrow surviving set, does not
 * count as a surviving broad read. Deterministic; never throws.
 *
 * @param {string[]} readActions candidate resource-scopable read actions of allowStmt
 * @param {object} allowStmt the Allow statement (normalized)
 * @param {object} model normalized, frozen model from buildModel()
 * @returns {string[]} the subset of readActions that survive as a broad read
 */
export function survivingBroadReadActions(readActions, allowStmt, model) {
  if (!Array.isArray(readActions) || readActions.length === 0) return [];
  if (!allowStmt || !model || !Array.isArray(model.statements)) return readActions.slice();
  // Same identity-statement Deny set ruleFindingDenySuppressed / the escalation
  // engine use (a Deny that names a Principal is a resource/trust-policy
  // statement, not an identity constraint on the analyzed subject).
  const denies = model.statements.filter((s) => s.effect === 'Deny' && s.principal == null);
  if (denies.length === 0) return readActions.slice();
  // Drop the actions an unconditional, in-scope Deny definitively blocks.
  const survivors = applyDenyToActions(denies, readActions, allowStmt).actions;
  // A bulk object-read whose broad scope a NotResource Deny fences to a narrow
  // set is no longer broad (secret reads and non-bulk reads are unaffected).
  return survivors.filter((a) => {
    if (isBulkReadAction(a)) return !denyFencesToNarrow(denies, a, allowStmt);
    return true;
  });
}

// --- Per-rule evaluation of a single Allow statement -------------------------

// 1. Wildcard action. Both "*" (all services) and "service:*" are HIGH: a
// standalone wildcard-action grant is a broad capability, but critical is
// reserved for compound escalation paths (IAM-102 severity model), so the
// widest standalone grant does not by itself earn critical.
