// IAM Blast Radius - permissions-boundary + session family evaluator (IAM-1002).
//
// Phase 10 (P0). A permissions boundary and a session policy are STRUCTURALLY
// identical to an identity policy (no Principal element), but their SEMANTICS are
// the opposite of a grant:
//
//   - A permissions BOUNDARY Allow is a MAXIMUM-PERMISSIONS ENVELOPE (a ceiling).
//     It does not grant anything; it caps what an attached identity could ever be
//     permitted. Effective permissions are the INTERSECTION of this boundary and
//     the identity policy that must INDEPENDENTLY Allow the action.
//   - A SESSION-policy Allow is a session RESTRICTION/ceiling. It only narrows an
//     existing session; effective access is the INTERSECTION of the parent
//     role/identity policy and this session policy.
//
// Running the identity rules/escalation catalog on either shape would emit
// confident positive-capability findings and graph edges (can-read / can-write /
// can-pass / data-exfil / escalation paths) that a ceiling can NEVER establish -
// exactly the overstated-certainty harm threat-model T8 forbids. So this module
// is a DISTINCT, family-aware evaluator (like engine/trust.js for role-trust):
// analyze.js routes an explicit permissions-boundary / session selection here
// INSTEAD of the identity engine, and the orchestrator draws NO positive
// capability edges for these families (the graph is empty by construction).
//
// This module reports the ENVELOPE / CEILING BREADTH as findings (so the user
// sees how wide the ceiling is) but never as a grant, and always states the
// intersection semantics in each finding's `limit`. There are NO escalation
// findings here.
//
// SCOPE FENCE (Oliver 2026-08-23): these families are ENVELOPE/RESTRICTION with
// NO positive capability edges. Full resource-policy (S3/SNS/KMS) and RCP
// analysis is a later tranche and still fails closed honestly.
//
// Pure, deterministic, dependency-free. No network APIs. No eval/Function. No
// DOM. Same model (+ same family) -> same findings, same order, every run
// (no Date.now()/Math.random()).

import { FAMILIES } from './family.js';

// Finding ids emitted by this evaluator. Kept distinct from the identity
// RULE_IDS / ESCALATION_IDS and the trust TRUST_IDS: an envelope/ceiling finding
// is a different kind of observation (a maximum-permissions ceiling, not a
// grant), so it carries its own family-scoped id.
export const ENVELOPE_IDS = Object.freeze([
  'PERMISSIONS-BOUNDARY-ENVELOPE',
  'SESSION-CEILING',
]);

// The capability-not-effective caveat every finding carries (mirrors rules.js
// CAPABILITY_LIMIT wording so the evidence contract - /not effective access/ -
// holds across every family). Envelope/ceiling findings extend it with the
// family-specific intersection semantics.
const BOUNDARY_LIMIT =
  'A permissions boundary is a CEILING, not a grant, so this is the potential ' +
  'maximum-permissions envelope and NOT effective access. An identity or role ' +
  'policy must INDEPENDENTLY Allow an action for it to take effect; effective ' +
  'permissions are the INTERSECTION of this boundary and that identity policy, ' +
  'which is not supplied here.';

const SESSION_LIMIT =
  'A session policy only NARROWS an existing session and grants nothing on its ' +
  'own, so this is a potential session ceiling and NOT effective access. ' +
  'Effective permissions are the INTERSECTION of the parent role/identity policy ' +
  '(not supplied) and this session ceiling; without that parent context no ' +
  'capability can be established here.';

const BOUNDARY_DOC =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html';
const SESSION_DOC =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session';

function statementSid(stmt) {
  return typeof stmt.sid === 'string' && stmt.sid.length > 0
    ? stmt.sid
    : `(index ${stmt.index})`;
}

// Is a single action token broad (a service-wide or global wildcard)? A bare "*"
// or any "service:*" / "service:Prefix*" pattern reads as broad breadth. Compared
// as inert data with a suffix check (never a regex compiled from input -> no
// ReDoS).
function actionIsBroad(action) {
  const a = String(action);
  if (a === '*') return true;
  return a.indexOf('*') !== -1;
}

// A statement describes a BROAD envelope/ceiling when its actions or its resource
// scope are wildcarded (or it uses NotAction/NotResource complement breadth). A
// scoped statement (specific action + specific resource) is a NARROW ceiling.
function statementIsBroad(stmt) {
  const actions = Array.isArray(stmt.actions) ? stmt.actions : [];
  const resources = Array.isArray(stmt.resources) ? stmt.resources : [];
  const broadActions = actions.some(actionIsBroad)
    || (Array.isArray(stmt.notActions) && stmt.notActions.length > 0);
  // Resource breadth means a WHOLE-account bare "*" (or a NotResource "everything
  // except" carve-out) - not a scoped object-key wildcard like "bucket/*", which
  // is an ordinary narrow grant to one resource's children.
  const broadResources = resources.includes('*')
    || (Array.isArray(stmt.notResources) && stmt.notResources.length > 0);
  return broadActions || broadResources;
}

// The granted-action summary. Like rules.js, a NotAction statement grants
// "everything except" - never surface the excluded set as the granted actions.
function actionSummary(stmt) {
  if (Array.isArray(stmt.notActions) && stmt.notActions.length > 0) return ['*'];
  if (Array.isArray(stmt.actions) && stmt.actions.length > 0) return stmt.actions.slice();
  return ['*'];
}

// The resource scope a finding reports (never the NotResource carve-out as a
// granted resource). Empty array is a valid evidence value.
function resourceSummary(stmt) {
  if (Array.isArray(stmt.resources) && stmt.resources.length > 0) return stmt.resources.slice();
  return [];
}

function buildBoundaryFinding(stmt) {
  const broad = statementIsBroad(stmt);
  const actions = actionSummary(stmt);
  const resources = resourceSummary(stmt);
  const finding = {
    id: 'PERMISSIONS-BOUNDARY-ENVELOPE',
    // A wildcard boundary provides essentially no upper-bound protection (a wide
    // ceiling) -> high breadth. A scoped boundary is a tight ceiling -> low. Never
    // critical: critical is reserved for compound escalation paths (a ceiling can
    // never be one), and a boundary grants nothing.
    severity: broad ? 'high' : 'low',
    title: 'Permissions-boundary maximum-permissions envelope',
    statementSid: statementSid(stmt),
    statementIndex: stmt.index,
    actions,
    resources,
    conditions: stmt.condition,
    policyEvidence: 'high',
    // A boundary alone yields no attack path; it is a ceiling, so exploitability
    // is low by construction (the identity policy that could exploit it is out of
    // scope and unsupplied).
    pathExploitability: 'low',
    why:
      (broad
        ? 'This permissions boundary permits a broad maximum-permissions envelope. '
        : 'This permissions boundary permits a scoped maximum-permissions envelope. ') +
      'A boundary is the CEILING of what an attached identity could ever be ' +
      'granted; it does not itself grant anything. A wildcard boundary provides ' +
      'no meaningful upper bound.',
    limit: BOUNDARY_LIMIT,
    remediation:
      'Scope the boundary to the least-privilege maximum the attached identities ' +
      'should ever reach. A permissions boundary is only useful as an upper bound ' +
      'when it is narrower than the identity policies it caps.',
    ruleVersion: '1',
    docRef: BOUNDARY_DOC,
  };
  if (Array.isArray(stmt.notActions) && stmt.notActions.length > 0) {
    finding.excludedActions = stmt.notActions.slice();
  }
  if (Array.isArray(stmt.notResources) && stmt.notResources.length > 0) {
    finding.excludedResources = stmt.notResources.slice();
  }
  return finding;
}

function buildSessionFinding(stmt) {
  const broad = statementIsBroad(stmt);
  const actions = actionSummary(stmt);
  const resources = resourceSummary(stmt);
  const finding = {
    id: 'SESSION-CEILING',
    // A session policy only RESTRICTS an existing session, so even a broad ceiling
    // grants nothing. A broad ceiling is low (it fails to narrow), a scoped one is
    // informational.
    severity: broad ? 'low' : 'info',
    title: 'Session-policy ceiling (session restriction)',
    statementSid: statementSid(stmt),
    statementIndex: stmt.index,
    actions,
    resources,
    conditions: stmt.condition,
    policyEvidence: 'high',
    pathExploitability: 'low',
    why:
      'This session policy caps the session to at most the listed scope. A session ' +
      'policy is a RESTRICTION on an existing session, not a grant: effective ' +
      'access is the INTERSECTION of the parent role/identity policy and this ' +
      'ceiling.',
    limit: SESSION_LIMIT,
    remediation:
      'Supply the parent role/identity policy to reason about effective access. ' +
      'On its own the session policy cannot read, write, or assume anything - it ' +
      'can only narrow what the parent already allows.',
    ruleVersion: '1',
    docRef: SESSION_DOC,
  };
  if (Array.isArray(stmt.notActions) && stmt.notActions.length > 0) {
    finding.excludedActions = stmt.notActions.slice();
  }
  if (Array.isArray(stmt.notResources) && stmt.notResources.length > 0) {
    finding.excludedResources = stmt.notResources.slice();
  }
  return finding;
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return Object.freeze(value);
}

/**
 * Evaluate a permissions-boundary or session policy as an ENVELOPE / CEILING.
 *
 * Emits one envelope/ceiling finding per ALLOW statement describing its breadth,
 * with the intersection semantics spelled out in `limit`. Emits NO escalation
 * findings and NO positive capability information; the orchestrator draws no
 * capability edges for these families. Deny statements are skipped (a ceiling's
 * Deny narrows the ceiling further and is never a positive envelope observation).
 *
 * Never throws. Deterministic.
 *
 * @param {object} model normalized, frozen model (from modelFromText)
 * @param {string} family FAMILIES.PERMISSIONS_BOUNDARY or FAMILIES.SESSION
 * @returns {{ok:boolean, errors:Array, findings:Array<object>}}
 */
export function analyzeEnvelope(model, family) {
  try {
    const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
    const build = family === FAMILIES.SESSION ? buildSessionFinding : buildBoundaryFinding;
    const findings = [];
    for (const stmt of statements) {
      // Only Allow statements describe a positive ceiling breadth; a Deny in a
      // boundary/session narrows the ceiling and is not an envelope observation.
      if (stmt.effect !== 'Allow') continue;
      findings.push(build(stmt));
    }
    // Deterministic order: by originating statement index (findings already come
    // in statement order, but pin it explicitly for byte-stability).
    findings.sort((a, b) => a.statementIndex - b.statementIndex);
    return Object.freeze({
      ok: true,
      errors: Object.freeze([]),
      findings: deepFreeze(findings),
    });
  } catch (e) {
    return Object.freeze({
      ok: false,
      errors: Object.freeze([
        { code: 'INTERNAL', message: 'Envelope analysis failed unexpectedly.', path: null },
      ]),
      findings: Object.freeze([]),
    });
  }
}

export default analyzeEnvelope;
