// graph-helpers.js - graph-building helpers: certainty derivation from evidence, capability/verb classification, statement lookup, deny-narrowing. Extracted (behavior-preserving).
import { actionGrants, hasPolicyVariable } from './escalation-action-grants.js';
import { applyDenyToActions, denyResourceCoverage } from './escalation-deny.js';
import { NODE_TYPES, CERTAINTY, PRINCIPAL_ID } from './graph-catalogs.js';

export function principalNode() {
  return {
    id: PRINCIPAL_ID,
    type: NODE_TYPES.PRINCIPAL,
    label: 'Principal (subject of this policy)',
  };
}

// --- Helpers -----------------------------------------------------------------

export function err(code, message) {
  return { code, message, path: null };
}

// First resource of a finding's scope, used as a representative target-node key.
// Findings always carry a non-empty resources array (rules.js/escalation.js fall
// back to an explicit "(no Resource...)" marker), but guard anyway.
export function firstResource(finding) {
  if (Array.isArray(finding.resources) && finding.resources.length > 0) {
    return String(finding.resources[0]);
  }
  return '(unspecified)';
}

// --- Per-action capability typing (IAM-702) ----------------------------------
// A broad-resource (WILDCARD-RESOURCE) grant is NOT a single "can-write" reach:
// its statement can mix reads, decrypts, delegation, destroys, and genuine
// mutation. Typing every such action under one `can-write` edge aggregates
// unlike capabilities (acceptance suite tests 8, 24, 1) and reuses one edge
// semantic for many - a violation of cross-test invariant 7 ("no semantic edge
// reuse"). classifyCapability() maps one action pattern to the ONE capability it
// represents so the graph can draw a distinctly-typed edge per capability.
//
// These verb tests mirror rules.js's classifiers (kept local so graph.js has no
// new import surface). The over-approximation direction matches rules.js: an
// action that is not a recognized read/destroy/decrypt/delegation is treated as
// a mutating write (the safe direction - never under-state).
export const READ_VERB = /^(get|list|describe|view|lookup|search|head|read|batchget)/i;
export const DESTRUCTIVE_VERB = /^(delete|terminate|remove|destroy|purge|deregister)/i;

// The verb portion of an action (what follows the first ':'); '' for a bare "*".
export function verbOf(pattern) {
  const p = String(pattern);
  const idx = p.indexOf(':');
  return idx === -1 ? '' : p.slice(idx + 1);
}

// Classify ONE action pattern into its single capability kind. Case-insensitive
// (IAM action matching is), so "IAM:passrole" classifies as delegation just like
// "iam:PassRole".
//   'delegation' - iam:PassRole (pass a role to a service; a delegation, never a
//                  plain resource write). Alone this is NOT an execution path.
//   'decrypt'    - kms:Decrypt (turns ciphertext to plaintext; its own edge type,
//                  distinct from a data read - IAM-202).
//   'destroy'    - delete/terminate/remove/destroy/purge/deregister families.
//   'read'       - get/list/describe/... enumeration/read verbs.
//   'write'      - everything else (incl. "*", "service:*", create/update/put):
//                  a genuine broad mutation, the safe over-approximation.
export function classifyCapability(pattern) {
  const lower = String(pattern).toLowerCase();
  if (lower === 'iam:passrole') return 'delegation';
  if (lower === 'kms:decrypt') return 'decrypt';
  const verb = verbOf(pattern);
  if (DESTRUCTIVE_VERB.test(verb)) return 'destroy';
  if (READ_VERB.test(verb)) return 'read';
  return 'write';
}

// A finding-shaped evidence carrier for ONE typed edge, carrying only the subset
// of actions that belong to that edge's capability (never the whole aggregate) so
// the edge's evidence attributes exactly its own actions to the statement
// (provenance invariant, IAM-701/702). Reuses the granting finding's statement
// Sid/index, resources, and condition verbatim.
export function findingWithActions(f, actions) {
  return {
    id: f.id,
    statementSid: f.statementSid,
    statementIndex: f.statementIndex,
    actions: actions.slice(),
    resources: f.resources,
    conditions: f.conditions,
  };
}

// Map a finding's policyEvidence (IAM-104: the strength of the POLICY-TEXT
// evidence for the grant, formerly the single `confidence` field) to a BASE edge
// certainty class. Edge certainty is about whether THIS policy grants the edge,
// so it keys off policyEvidence, NOT pathExploitability (how likely the grant is
// actually exploitable is a separate signal that never strengthens/weakens what
// the policy text demonstrably says):
//   high   -> confirmed-by-policy    (granted by this policy text, unconditional)
//   medium -> context-required       (a Condition may gate it at runtime)
//   low    -> potentially-reachable  (multiple unknowns stack up)
//
// DENY-AWARENESS (see ruleCertainty / ESCALATION vs RULE findings below).
// escalation.js findings arrive with gating Conditions, unresolved PassedToService
// operators, AND possibly-blocking same-policy Denies ALREADY folded into
// `policyEvidence` (fully-blocked paths are suppressed there entirely), so for those
// findings this base mapping is authoritative. rules.js findings, by contrast,
// fold ONLY Conditions into policyEvidence - they are deliberately NOT Deny-aware (a
// Deny is never itself a blast-radius grant, so rules.js does not model it). That
// left rule edges overstating certainty: a wildcard/destructive/IAM-admin grant
// whose action a same-policy explicit Deny overrides would still read as
// `confirmed-by-policy`, a truthfulness harm (docs/architecture.md #6,
// threat-model T8). graph.js therefore applies AWS explicit-Deny precedence to
// rule findings here, mirroring what escalation.js already does for its own
// findings: see ruleCertainty(). A confirming Condition (e.g. an
// iam:PassedToService that PROVES a path) is not a gate, so it never lowers
// policyEvidence in those engines and is correctly read as confirmed.
export function certaintyFromEvidence(policyEvidence) {
  switch (policyEvidence) {
    case 'high':
      return CERTAINTY.CONFIRMED_BY_POLICY;
    case 'medium':
      return CERTAINTY.CONTEXT_REQUIRED;
    default:
      return CERTAINTY.POTENTIALLY_REACHABLE;
  }
}

// PassRole->service transition certainty (IAM-202). A PassRole path always needs
// an OUT-OF-SCOPE precondition the policy cannot prove: a usable target role
// actually exists and its trust policy accepts this service. So even when both
// grants are unconditional (policyEvidence high), the transition is
// `policy-supported`, NOT `confirmed-by-policy` - the policy supports the grants
// but does not confirm the transition end-to-end (threat-model T8: never
// overclaim). A gating Condition on the execution/pass statement still weakens it
// further (medium -> context-required, low -> potentially-reachable).
export function passRoleCertainty(policyEvidence) {
  switch (policyEvidence) {
    case 'high':
      return CERTAINTY.POLICY_SUPPORTED;
    case 'medium':
      return CERTAINTY.CONTEXT_REQUIRED;
    default:
      return CERTAINTY.POTENTIALLY_REACHABLE;
  }
}

// Weaken a base certainty by one notch when a same-policy Deny may (but is not
// proven to) block part of a rule finding's grant. confirmed -> conditional ->
// potential; potential and unknown are already the weakest and stay put. This
// never strengthens a class and never invents a hard block (that is the separate
// blocked-by-deny result), so it cannot overstate certainty.
export function downgradeCertainty(certainty) {
  switch (certainty) {
    case CERTAINTY.CONFIRMED_BY_POLICY:
    case CERTAINTY.POLICY_SUPPORTED:
      return CERTAINTY.CONTEXT_REQUIRED;
    case CERTAINTY.CONTEXT_REQUIRED:
      return CERTAINTY.POTENTIALLY_REACHABLE;
    default:
      return certainty;
  }
}

// Locate the Allow statement a rule finding was raised on (by preserved index),
// needed to evaluate a Deny's resource coverage against the granted scope.
export function findStatement(model, index) {
  if (typeof index !== 'number') return null;
  for (const s of model.statements) {
    if (s && s.index === index) return s;
  }
  return null;
}

// Does any same-policy Deny narrow an Allow+NotAction grant ("everything except a
// listed few")? Such a grant can be NARROWED by a Deny but never fully blocked (a
// Deny cannot cover every action), so this only ever downgrades. A Deny narrows
// it when, with resource scope overlapping the Allow (coverage !== 'none'), it
// denies at least one action the NotAction Allow still grants - i.e. an action
// NOT in the Allow's exclusion list (or a NotAction-Deny, which denies ~all, or a
// variable-bearing pattern whose runtime target is unknown).
export function denyNarrowsNotAction(denies, allowStmt) {
  for (const deny of denies) {
    if (denyResourceCoverage(deny, allowStmt) === 'none') continue;
    if (deny.notActions.length > 0) return true; // NotAction-Deny denies ~everything
    for (const dp of deny.actions) {
      if (hasPolicyVariable(dp)) return true; // may hit a granted action at runtime
      const excluded = allowStmt.notActions.some(
        (ex) => !hasPolicyVariable(ex) && actionGrants(ex, dp),
      );
      if (!excluded) return true; // denies an action the grant still allows
    }
  }
  return false;
}

// Certainty for a RULE finding's edge, applying same-policy explicit-Deny
// precedence (rules.js is intentionally not Deny-aware; graph.js is, so rule
// edges match escalation edges). Returns:
//   blocked-by-deny  - an unconditional, in-scope, concrete Deny definitively
//                      overrides EVERY granted action (the grant is fully denied).
//   downgraded base  - a Deny may block / partially narrows the grant.
//   base             - no same-policy Deny touches the grant.
export function ruleCertainty(finding, denies, model) {
  const base = certaintyFromEvidence(finding.policyEvidence);
  if (!denies || denies.length === 0) return base;
  const allowStmt = findStatement(model, finding.statementIndex);
  if (!allowStmt) return base;
  // Allow + NotAction: grants all-but-listed. Never fully blocked; may narrow.
  if (allowStmt.notActions.length > 0) {
    return denyNarrowsNotAction(denies, allowStmt) ? downgradeCertainty(base) : base;
  }
  const actions = Array.isArray(finding.actions) ? finding.actions : [];
  if (actions.length === 0) return base;
  // Positive-grant rules: reuse escalation.js's exact Deny-precedence resolver so
  // the two engines cannot drift. A narrow Deny of a broad wildcard action does
  // NOT apply (pattern-vs-pattern), so a wildcard edge stays confirmed while the
  // Deny is shown on its own `denies` edge - only a Deny that actually covers the
  // granted action(s) blocks or narrows the edge.
  const eff = applyDenyToActions(denies, actions, allowStmt);
  if (eff.blocked) return CERTAINTY.BLOCKED_BY_DENY;
  if (eff.narrowed) return downgradeCertainty(base);
  return base;
}

// Build the evidence record attached to an edge for one supporting finding.
export function evidenceFromFinding(finding) {
  return {
    findingId: finding.id,
    statementSid:
      typeof finding.statementSid === 'string' ? finding.statementSid : null,
    statementIndex:
      typeof finding.statementIndex === 'number' ? finding.statementIndex : null,
    actions: Array.isArray(finding.actions) ? finding.actions.slice() : [],
    resources: Array.isArray(finding.resources) ? finding.resources.slice() : [],
    condition:
      finding.conditions === undefined ? null : finding.conditions,
  };
}

// --- Builder state -----------------------------------------------------------
// A small accumulator so the per-finding mapping stays declarative. It owns node
// de-duplication, the node cap, and edge merging.
