// escalation-finding.js - escalation finding factory + evidence/prerequisite builders. Extracted (behavior-preserving).
import { chargeWork } from './glob.js';
import { grantedPatternsFor } from './escalation-action-grants.js';
import { resourceScope } from './escalation-scope.js';
import { statementSid } from './escalation-statement.js';
import { applyDenyToActions } from './escalation-deny.js';
import { ESCALATIONS } from './escalation-catalogs.js';
import { CAPABILITY_LIMIT, CONDITION_LIMIT, DENY_NARROW_LIMIT, PASSED_TO_SERVICE_UNCERTAIN_LIMIT, TARGET_UNKNOWN_LIMIT } from './escalation-consts.js';

export function makeEscalation(id, anchor, fields) {
  const meta = ESCALATIONS[id];
  // Split certainty (IAM-104): every finding carries TWO orthogonal signals in
  // place of the old single `confidence`.
  //   policyEvidence     - how strongly THIS policy text establishes that the
  //                        required grants are present (both/all actions granted,
  //                        in scope, not overridden). Drives graph edge certainty.
  //   pathExploitability - how likely the path actually yields elevated privilege
  //                        given what is NOT in scope here: the target role's
  //                        (passed / assumed / re-trusted) unknown permissions,
  //                        service/instance-profile runtime behavior, and other
  //                        controls. A compound PassRole->service path has strong
  //                        policy evidence yet only MEDIUM exploitability because
  //                        the passable role's power is unknown.
  // Each caller supplies a base for both. A Condition beyond the confirming one,
  // a possibly-blocking same-policy Deny, and an unresolved iam:PassedToService
  // operator are runtime gates: each reduces BOTH signals a notch (never below
  // low, never auto-upgrade), since a gate weakens both the evidence that the
  // grant holds and the likelihood the path is reachable.
  let policyEvidence = fields.policyEvidence;
  let pathExploitability = fields.pathExploitability;
  let extraLimit = '';
  if (fields.conditioned) {
    policyEvidence = downgrade(policyEvidence);
    pathExploitability = downgrade(pathExploitability);
    extraLimit += CONDITION_LIMIT;
  }
  if (fields.denyNarrowed) {
    policyEvidence = downgrade(policyEvidence);
    pathExploitability = downgrade(pathExploitability);
    extraLimit += DENY_NARROW_LIMIT;
  }
  if (fields.passUncertain) {
    policyEvidence = downgrade(policyEvidence);
    pathExploitability = downgrade(pathExploitability);
    extraLimit += PASSED_TO_SERVICE_UNCERTAIN_LIMIT;
  }
  return {
    id: meta.id,
    severity: fields.severity,
    title: meta.title,
    statementSid: statementSid(anchor),
    statementIndex: anchor.index,
    actions: fields.actions.slice(),
    resources: (fields.resources || []).slice(),
    conditions: anchor.condition, // null when absent; inert data otherwise
    policyEvidence,
    pathExploitability,
    why: fields.why,
    limit: CAPABILITY_LIMIT + TARGET_UNKNOWN_LIMIT + extraLimit,
    remediation: fields.remediation,
    ruleVersion: meta.ruleVersion,
    docRef: meta.docRef,
    // --- escalation enrichment (beyond the canonical shape) ---
    escalation: {
      technique: fields.technique,
      service: fields.service || null,
      // IAM-703: `requiredActions` is a flat convenience list for the PRIMARY
      // technique, and it is GROUNDED - every entry is an action the analyzed
      // policy actually grants (never a catalog action the policy does not
      // contain). The authoritative AND/OR structure lives in `prerequisites`.
      requiredActions: (fields.requiredActions || []).slice(),
      // IAM-703: explicit AND/OR prerequisites. `prerequisites.anyOf` lists the
      // alternative TECHNIQUES that achieve this escalation (holding any ONE
      // suffices - they are NOT jointly required). Each technique's `allOf` lists
      // the grant groups it jointly needs; each group's `anyOf` lists the
      // interchangeable actions that satisfy that group. This replaces the old
      // flat requiredActions AND-list that wrongly implied unrelated alternative
      // techniques were all jointly required. Every action named here is granted
      // by the analyzed policy (grounded), never an absent catalog action.
      prerequisites: fields.prerequisites || null,
      targetPermissions: 'unknown',
    },
    evidence: fields.evidence.slice(),
    // IAM-701: explicit per-statement provenance for the header. Every action is
    // attributed ONLY to the statement that grants it, so a cross-statement
    // compound finding never implies the anchor Sid granted the whole set.
    contributingStatements: contributingStatementsFrom(fields.evidence),
    // IAM-105: compound escalation paths expose a present/absent risk-factor
    // checklist (the grants + scope conditions that constitute the path). null
    // for single-action primitives, which are not compound paths.
    riskFactors: Array.isArray(fields.riskFactors)
      ? fields.riskFactors.map((rf) => ({
          key: rf.key,
          label: rf.label,
          present: !!rf.present,
        }))
      : null,
  };
}

export function downgrade(confidence) {
  if (confidence === 'high') return 'medium';
  if (confidence === 'medium') return 'low';
  return 'low';
}

// IAM-701: contributed actions are represented as an ARRAY, never a comma-joined
// string. Where a statement contributes several actions (e.g. an exec statement
// granting lambda:CreateFunction + lambda:UpdateFunctionCode) they ride as
// distinct array elements so every downstream consumer (graph-edge evidence,
// correlate, render, export) can reason per-action without re-splitting a
// display string. `actions` accepts a string or an array and is normalized to an
// array here.
export function evidenceOf(stmt, role, actions, note) {
  const list = Array.isArray(actions) ? actions.slice() : [actions];
  return {
    statementIndex: stmt.index,
    statementSid: statementSid(stmt),
    role, // 'pass' | 'execute' | 'primitive'
    actions: list,
    resources: resourceScope(stmt),
    condition: stmt.condition,
    note: note || null,
  };
}

// IAM-701: per-statement provenance for a finding HEADER. A compound path is
// distributed across statements (PassRole in one, the service action in
// another); the scalar statementSid/statementIndex names only the anchor, so on
// its own it would attribute the whole combined action list to a single Sid.
// contributingStatements makes the mapping explicit and correct: one entry per
// contributing statement, each carrying ONLY the actions that statement grants
// (deduped, ordered by statement index). Derived from the same per-statement
// evidence[] records, so header and evidence[] can never drift.
export function contributingStatementsFrom(evidence) {
  // S3-dos-budget-all (iter-8, close-the-class): a finding's evidence[] records carry
  // per-statement `actions` lists that grow with the policy's action patterns (a single
  // statement can list up to MAX_ACTIONS=10000 grant patterns, all attributed to ONE
  // statementIndex). The old `entry.actions.includes(a)` dedup was an O(A^2) Array-scan
  // per statement with ZERO chargeWork - the SAME uncharged-quadratic dedup class as F1 /
  // survivingGrantedActions / specificAccountsInRoleArns / the role-takeover dedupe. It is
  // guarded upstream today (the matcher work that PRODUCED these actions is charged, so a
  // pathological list already trips the budget before reaching here), but leaving the last
  // includes-in-push O(n^2) in place is exactly the "another spelling" the fail-open hunter
  // re-opens the class on. A per-entry Set makes membership O(1) (traversal O(A)); charge
  // one unit per action inspected so this traversal ALSO participates in the work +
  // wall-clock budget and a future regression that reaches here with an under-charged
  // upstream fails CLOSED rather than grinding uncharged. Output (deduped, statement-index
  // order) is byte-identical to the includes version.
  const byIndex = new Map();
  for (const ev of Array.isArray(evidence) ? evidence : []) {
    if (!ev || typeof ev.statementIndex !== 'number') continue;
    let entry = byIndex.get(ev.statementIndex);
    if (!entry) {
      entry = {
        statementIndex: ev.statementIndex,
        statementSid: ev.statementSid,
        actions: [],
        seen: new Set(),
      };
      byIndex.set(ev.statementIndex, entry);
    }
    const evActions = Array.isArray(ev.actions) ? ev.actions : [];
    chargeWork(evActions.length);
    for (const a of evActions) {
      if (!entry.seen.has(a)) { entry.seen.add(a); entry.actions.push(a); }
    }
  }
  // Drop the internal `seen` Set from the returned entries so the shape is unchanged.
  return [...byIndex.keys()]
    .sort((x, y) => x - y)
    .map((i) => {
      const e = byIndex.get(i);
      return { statementIndex: e.statementIndex, statementSid: e.statementSid, actions: e.actions };
    });
}

// --- Prerequisite (AND/OR) helpers (IAM-703) ---------------------------------
// A `group` is an OR of interchangeable actions that satisfy one requirement of
// a technique (e.g. "any lambda code-run action"). A `technique` ANDs its groups
// together (allOf) and is one alternative way to achieve the escalation; the
// finding's prerequisites OR the techniques together (anyOf). Every action here
// must be one the policy actually grants - callers pass grounded action lists.
export function prereqGroup(anyOf, role) {
  return { role: role || null, anyOf: (Array.isArray(anyOf) ? anyOf : [anyOf]).slice() };
}

export function prereqTechnique(id, allOf, opts) {
  return {
    technique: id,
    allOf: (Array.isArray(allOf) ? allOf : [allOf]).slice(),
    requiresPassRole: !!(opts && opts.requiresPassRole),
    note: (opts && opts.note) || null,
  };
}

export function prerequisitesOf(techniques) {
  return { anyOf: (Array.isArray(techniques) ? techniques : [techniques]).slice() };
}

// Gather every concrete action in `catalog` that is granted by some Allow in
// `allows` and SURVIVES same-policy explicit-Deny precedence (deny-filtered).
// Deterministic order: statement order, then match order; deduped. Used to
// ground a standalone technique's prerequisites in the policy's real grants.
export function survivingGrantedActions(allows, denies, catalog) {
  // S3-dos-budget-all (iter-7): `found` accumulates the deny-surviving granted patterns
  // across every Allow, so it grows with the policy's distinct action patterns. The old
  // `found.includes(a)` Array-scan made the dedup O(found^2) with ZERO chargeWork on the
  // dedup itself (grantedPatternsFor / applyDenyToActions charge their own work, but the
  // includes-in-push dedup did not) - the same uncharged-quadratic dedup class as F1. A
  // Set makes membership O(1); charge one unit per surviving action so the dedup traversal
  // participates in the work + wall-clock budget.
  const found = [];
  const seen = new Set();
  for (const stmt of allows) {
    const m = grantedPatternsFor(stmt, catalog);
    if (m.length === 0) continue;
    const d = applyDenyToActions(denies, m, stmt);
    chargeWork(d.actions.length);
    for (const a of d.actions) if (!seen.has(a)) { seen.add(a); found.push(a); }
  }
  return found;
}
