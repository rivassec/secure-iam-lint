// IAM Blast Radius - SCP ceiling / guardrail evaluator (IAM-1301, Phase 13).
//
// A Service Control Policy (SCP) is an AWS Organizations policy that sets the
// MAXIMUM available permissions for the IAM users and roles in member accounts.
// It is STRUCTURALLY almost identical to an identity policy, but its SEMANTICS
// are a CEILING / GUARDRAIL, never a grant (docs/scp-rcp-semantics.md section 0):
//
//   - An SCP Allow statement is a MAXIMUM-PERMISSIONS ENVELOPE (a ceiling). It
//     does not grant anything; it caps the widest set of actions the ceiling
//     will let through at that level. Effective access is the INTERSECTION of
//     this ceiling and an identity policy that must INDEPENDENTLY Allow the
//     action (and every other level's SCP must also permit it).
//   - An SCP Deny statement is a GUARDRAIL: it removes actions from the ceiling.
//     A Deny at any level wins. A Deny + NotAction denies everything EXCEPT the
//     listed carve-out; the carve-out is NOT a set of allowed actions.
//
// Running the identity rules / escalation catalog on an SCP would emit confident
// positive-capability findings and graph edges (can-read / can-write / can-pass /
// data-exfil / escalation) that a CEILING can NEVER establish - exactly the
// overstated-certainty harm the threat model forbids (T8). So this module is a
// DISTINCT, family-aware evaluator (mirroring engine/envelope.js for the
// permissions-boundary / session ceiling families): analyze.js routes an SCP
// selection here INSTEAD of the identity engine, and the orchestrator draws NO
// positive capability edges for this family (the graph is empty by construction).
//
// This module reports the CEILING / GUARDRAIL SHAPE as findings (so the user
// sees how wide the ceiling is and what the guardrails forbid) but NEVER as a
// grant, and always states the intersection semantics in each finding's `limit`.
// There are NO escalation findings here. A NotAction list is surfaced as an
// excluded CARVE-OUT, never as allowed capabilities.
//
// Pure, deterministic, dependency-free. No network APIs. No eval/Function. No
// DOM. Same model (+ same family) -> same findings, same order, every run
// (no Date.now()/Math.random()).

// parseOperator strips the set-operator qualifier (ForAllValues:/ForAnyValue:)
// and the ...IfExists suffix, returning the lowercased BASE comparator. Operator
// POLARITY must be judged on that base form: a valid AWS spelling like
// `ForAnyValue:StringEquals` is still a POSITIVE string comparator, but a naive
// startsWith('string') on the raw key would miss it and credit an inverted fence
// as protective. Reuse the canonical parser so every polarity check sees through
// the qualifier prefix.
import { parseOperator } from './conditions.js';

// Finding ids emitted by this evaluator. Kept distinct from the identity
// RULE_IDS / ESCALATION_IDS, the trust TRUST_IDS, and the envelope ENVELOPE_IDS:
// an SCP finding is a different kind of observation (a permission ceiling or a
// guardrail, not a grant), so it carries its own family-scoped id.
export const SCP_IDS = Object.freeze([
  'SCP-CEILING',
  'SCP-GUARDRAIL',
]);

// The ceiling-not-grant + intersection caveat every SCP finding carries. Mirrors
// the envelope.js BOUNDARY_LIMIT contract (/not effective access/, /INTERSECTION/)
// so the evidence contract holds across every ceiling family, and adds the SCP-
// specific "SCPs set permission ceilings and do not grant permissions" wording the
// acceptance suite (test 19) requires.
const SCP_LIMIT =
  'An SCP is a permission CEILING / GUARDRAIL, not a grant: SCPs set permission ' +
  'ceilings on member accounts and do NOT grant permissions. This describes the ' +
  'ceiling shape (an Allow envelope or a Deny guardrail) and is NOT effective ' +
  'access. Effective access is the INTERSECTION of identity policies (which must ' +
  'INDEPENDENTLY Allow an action and are not supplied here) and this ceiling; a ' +
  'permission is effective only if it is allowed by an identity policy AND ' +
  'permitted by every applicable SCP.';

const SCP_DOC =
  'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html';
const REGION_DENY_DOC =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-requested-region.html';
const IFEXISTS_DOC =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html';

function statementSid(stmt) {
  return typeof stmt.sid === 'string' && stmt.sid.length > 0
    ? stmt.sid
    : `(index ${stmt.index})`;
}

// Is a single action token broad (a service-wide or global wildcard)? A bare "*"
// or any pattern containing "*" reads as broad breadth. Compared as inert data
// with an index check (never a regex compiled from input -> no ReDoS).
function actionIsBroad(action) {
  const a = String(action);
  if (a === '*') return true;
  return a.indexOf('*') !== -1;
}

// A statement describes a BROAD ceiling/guardrail when its actions or resource
// scope are wildcarded (or it uses a NotAction / NotResource complement). A
// scoped statement (specific action + specific resource) is a NARROW ceiling.
function statementIsBroad(stmt) {
  const actions = Array.isArray(stmt.actions) ? stmt.actions : [];
  const resources = Array.isArray(stmt.resources) ? stmt.resources : [];
  const broadActions = actions.some(actionIsBroad)
    || (Array.isArray(stmt.notActions) && stmt.notActions.length > 0);
  const broadResources = resources.includes('*')
    || (Array.isArray(stmt.notResources) && stmt.notResources.length > 0);
  return broadActions || broadResources;
}

// The action summary a finding reports. Like envelope.js, a NotAction statement
// covers "everything except" - never surface the excluded set as the covered
// actions. For an Allow that is the envelope breadth; for a Deny it is the denied
// set. The excluded list rides separately as excludedActions (a CARVE-OUT).
function actionSummary(stmt) {
  if (Array.isArray(stmt.notActions) && stmt.notActions.length > 0) return ['*'];
  if (Array.isArray(stmt.actions) && stmt.actions.length > 0) return stmt.actions.slice();
  return ['*'];
}

function resourceSummary(stmt) {
  if (Array.isArray(stmt.resources) && stmt.resources.length > 0) return stmt.resources.slice();
  return [];
}

// --- Condition inspection (guardrail evidence, never a grant) -----------------
// SCP guardrails commonly carry aws:RequestedRegion region conditions and
// ...IfExists operators. We read the normalized condition map (operator -> {key:
// value}) as INERT DATA. Casing of operators/keys is preserved by the model, so
// we compare case-insensitively.

const REGION_KEY = 'aws:requestedregion';

// Global services whose single us-east-1 endpoint makes them the canonical
// NotAction carve-out in a region guardrail (docs/scp-rcp-semantics.md section 5).
// Used only to explain WHY a carve-out exists; never to assert a grant.
const GLOBAL_SERVICE_PREFIXES = [
  'iam:', 'cloudfront:', 'route53:', 'support:', 'organizations:',
  'budgets:', 'globalaccelerator:', 'waf:',
];

// Extract the aws:RequestedRegion value list from a normalized condition map,
// plus operator POLARITY evidence: whether ANY operator gating that key is a
// negated ...IfExists form (the fail-closed guardrail that also denies when the
// key is ABSENT), and whether the key rides under a POSITIVE string comparator
// (StringEquals / StringLike, no 'Not') - the INVERTED region fence (see below).
// Returns { present, regions[], negatedIfExists, positive } - regions is a fresh
// string array.
function inspectRegionCondition(condition) {
  const out = { present: false, regions: [], negatedIfExists: false, positive: false };
  if (!condition || typeof condition !== 'object') return out;
  for (const op of Object.getOwnPropertyNames(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object') continue;
    for (const key of Object.getOwnPropertyNames(inner)) {
      if (String(key).toLowerCase() !== REGION_KEY) continue;
      out.present = true;
      const val = inner[key];
      if (Array.isArray(val)) {
        for (const v of val) out.regions.push(String(v));
      } else if (val !== null && val !== undefined) {
        out.regions.push(String(val));
      }
      // Judge polarity on the BASE comparator, with the set-operator qualifier
      // (ForAllValues:/ForAnyValue:) and ...IfExists suffix stripped. A raw key
      // such as `ForAnyValue:StringEquals` is a valid AWS spelling of a POSITIVE
      // string comparator; testing the raw key with startsWith('string') would
      // miss the qualifier prefix and credit an inverted fence as protective.
      const { base, ifExists } = parseOperator(op);
      const negatedOp = base.indexOf('not') !== -1;
      // A NEGATED ...IfExists (e.g. StringNotEqualsIfExists, or its set-qualified
      // spelling) in a Deny still denies when the key is absent
      // (docs/scp-rcp-semantics.md section 6).
      if (negatedOp && ifExists) {
        out.negatedIfExists = true;
      }
      // Operator POLARITY (mirrors rcp.js orgScopePositive): a region Deny gated by
      // a POSITIVE string comparator (StringEquals / StringLike, no 'Not') fires the
      // Deny WHEN the requested Region MATCHES the listed set - it denies INSIDE the
      // listed regions and PERMITS every region outside them, the INVERSE of a region
      // lock (whose correct form is StringNotEquals: deny UNLESS the region is in the
      // allowed set). Only string comparators carry this polarity (regions are
      // string-typed); a positive-operator region fence is a likely misconfiguration,
      // NEVER a protective lock. The set-operator qualifier is stripped above, so a
      // ForAnyValue:/ForAllValues:-qualified positive comparator is caught too.
      if (base.startsWith('string') && !negatedOp) {
        out.positive = true;
      }
    }
  }
  return out;
}

function hasOrgControlAction(stmt) {
  const all = [].concat(
    Array.isArray(stmt.actions) ? stmt.actions : [],
    Array.isArray(stmt.notActions) ? stmt.notActions : [],
  );
  return all.some((a) => String(a).toLowerCase().startsWith('organizations:'));
}

// Does the Deny's NotAction carve-out exempt any recognized global service? Used
// only to decide whether a negated-IfExists region deny is over-broad (no global-
// service exception) - the hazard test 43 flags. Never asserts a grant.
function hasGlobalServiceCarveOut(stmt) {
  const excluded = Array.isArray(stmt.notActions) ? stmt.notActions : [];
  return excluded.some((a) => {
    const low = String(a).toLowerCase();
    return GLOBAL_SERVICE_PREFIXES.some((p) => low.startsWith(p));
  });
}

// --- Finding builders --------------------------------------------------------

function buildCeilingFinding(stmt) {
  const broad = statementIsBroad(stmt);
  const finding = {
    id: 'SCP-CEILING',
    // A wildcard SCP Allow is a WIDE ceiling (little protection); a scoped Allow
    // is a TIGHT ceiling. NEVER critical: a ceiling grants nothing, and critical
    // is reserved for compound escalation paths (which a ceiling can never be).
    severity: broad ? 'high' : 'low',
    title: 'SCP maximum-permissions ceiling (Allow envelope)',
    statementSid: statementSid(stmt),
    statementIndex: stmt.index,
    actions: actionSummary(stmt),
    resources: resourceSummary(stmt),
    conditions: stmt.condition,
    policyEvidence: 'high',
    pathExploitability: 'low',
    why:
      (broad
        ? 'This SCP Allow permits a broad maximum-permissions ceiling. '
        : 'This SCP Allow permits a scoped maximum-permissions ceiling. ') +
      'An SCP Allow is the widest set of actions the ceiling will let through at ' +
      'this level; it does NOT grant anything. A wildcard SCP Allow provides no ' +
      'meaningful upper bound. An identity policy must still independently allow ' +
      'the action, and every level\'s SCP must also permit it.',
    limit: SCP_LIMIT,
    remediation:
      'Scope the ceiling to the least-privilege maximum member accounts should ' +
      'ever reach. Keep the FullAWSAccess default in mind - removing it without a ' +
      'replacement Allow blocks all actions. An SCP Allow is only useful as an ' +
      'upper bound when it is narrower than the identity policies it caps.',
    ruleVersion: '1',
    docRef: SCP_DOC,
  };
  if (Array.isArray(stmt.notActions) && stmt.notActions.length > 0) {
    // NotAction on an Allow widens the ceiling to "everything except" - the list
    // is a carve-out from the envelope, never the set of allowed actions.
    finding.excludedActions = stmt.notActions.slice();
  }
  if (Array.isArray(stmt.notResources) && stmt.notResources.length > 0) {
    finding.excludedResources = stmt.notResources.slice();
  }
  return finding;
}

function buildGuardrailFinding(stmt) {
  const region = inspectRegionCondition(stmt.condition);
  const isRegion = region.present;
  const isOrg = hasOrgControlAction(stmt);
  const carveOut = hasGlobalServiceCarveOut(stmt);
  // The over-broad regional-deny HAZARD (acceptance-suite-2 test 43): a negated
  // ...IfExists on aws:RequestedRegion in a Deny also denies requests that OMIT
  // the key (global-service calls to us-east-1), and without a NotAction global-
  // service carve-out it can block global services broadly.
  const overBroadRegionHazard = isRegion && region.negatedIfExists && !carveOut;
  // The INVERTED region-fence HAZARD (mirrors rcp.js invertedOrgScopeHazard): a
  // region Deny gated by a POSITIVE comparator (StringEquals-style, not negated)
  // fires WHEN the requested Region matches the listed set - it denies INSIDE the
  // listed regions and PERMITS every region outside them, the INVERSE of a region
  // lock (whose correct form is StringNotEquals). This is a likely misconfiguration
  // and must NEVER be credited as a protective lock. It is still a Deny (grants
  // nothing). Positive and negated-IfExists polarity are mutually exclusive.
  const invertedRegionHazard = isRegion && region.positive;

  let guardrailKind;
  if (isRegion) guardrailKind = 'region';
  else if (isOrg) guardrailKind = 'organization';
  else guardrailKind = 'general';

  const denies = actionSummary(stmt); // the DENIED set (Deny effect)
  const hasCarveList = Array.isArray(stmt.notActions) && stmt.notActions.length > 0;

  let title;
  let why;
  let remediation;
  let docRef = SCP_DOC;

  if (isRegion) {
    const regionList = region.regions.length > 0 ? region.regions.join(', ') : '(none listed)';
    if (invertedRegionHazard) {
      // Positive-operator region fence: denies INSIDE the listed regions and PERMITS
      // everything outside them - the INVERSE of a region lock. Narrate the real
      // effect ("permits every region except..."); never credit it as protective.
      title = 'SCP region guardrail (potentially inverted region Deny)';
      why =
        'This SCP Deny is gated by a POSITIVE operator on aws:RequestedRegion, so ' +
        `it denies actions WHEN the requested Region IS one of {${regionList}} and ` +
        'PERMITS every region except those - the INVERSE of a region lock and a ' +
        'likely MISCONFIGURATION (a positive-operator region Deny such as ' +
        'StringEquals denies only inside the listed regions and leaves every other ' +
        'region un-guardrailed; the intended region lock uses a NEGATED operator ' +
        'like StringNotEquals, which denies UNLESS the requested Region is in the ' +
        'allowed set). ' +
        (hasCarveList
          ? 'The NotAction list is a carve-out (services exempt from the deny); it ' +
            'is NOT a set of allowed actions. '
          : '') +
        'A guardrail removes actions from the ceiling; it never grants.';
      remediation =
        'Fix the operator polarity: a region lock should use a NEGATED comparator ' +
        '(StringNotEquals on aws:RequestedRegion) so it denies UNLESS the requested ' +
        'Region is in your allowed set. As written (a positive StringEquals-style ' +
        'comparator) it denies only inside the listed regions and permits every ' +
        'other region - the inverse of the intended control. It is still a Deny (it ' +
        'grants nothing), but it does not provide the region lock it appears to.';
      docRef = REGION_DENY_DOC;
    } else {
      title = overBroadRegionHazard
        ? 'SCP region guardrail (potentially over-broad regional Deny)'
        : 'SCP region guardrail (Deny)';
      why =
        'This SCP Deny is a REGION GUARDRAIL: it denies actions whose requested ' +
        `Region is outside the allowed set {${regionList}}. ` +
        (hasCarveList
          ? 'The NotAction list is a global-service CARVE-OUT (services exempt from ' +
            'the region deny, because their single endpoint lives in us-east-1); it ' +
            'is NOT a set of allowed actions. '
          : '') +
        (region.negatedIfExists
          ? 'The guardrail uses a negated ...IfExists operator in a Deny, so it ' +
            'ALSO denies requests that omit aws:RequestedRegion entirely - including ' +
            'global-service requests (IAM, CloudFront, Route 53, Support) routed to ' +
            'us-east-1 - because a negated ...IfExists in a Deny still denies when ' +
            'the key is absent. '
          : '') +
        (overBroadRegionHazard
          ? 'With no global-service carve-out this can block global services ' +
            'broadly (a potentially over-broad regional Deny). '
          : '') +
        'A guardrail removes actions from the ceiling; it never grants.';
      remediation = overBroadRegionHazard
        ? 'Add explicit global-service exceptions (a NotAction listing iam:*, ' +
          'cloudfront:*, route53:*, support:*, organizations:* and any other global ' +
          'services in use) or adopt the documented regional-control pattern so ' +
          'global services routed to us-east-1 are not denied.'
        : 'Confirm the allowed-Region set and the global-service carve-out match ' +
          'your intended footprint. Keep this guardrail paired with identity ' +
          'policies that grant the actions you do want - an SCP only removes access.';
      docRef = region.negatedIfExists ? IFEXISTS_DOC : REGION_DENY_DOC;
    }
  } else if (isOrg) {
    title = 'SCP organization guardrail (Deny)';
    why =
      'This SCP Deny is an ORGANIZATION GUARDRAIL: it blocks organization-control ' +
      'actions (for example leaving the organization) for member accounts. It ' +
      'removes those actions from the ceiling and never grants anything.';
    remediation =
      'Keep this guardrail attached at the level whose member accounts must not ' +
      'take these organization actions. It caps behavior; grants still come from ' +
      'identity policies.';
  } else {
    title = 'SCP guardrail (Deny)';
    why =
      'This SCP Deny is a GUARDRAIL: it removes the listed actions from the ' +
      'ceiling for member accounts. ' +
      (hasCarveList
        ? 'The NotAction list is a CARVE-OUT (denies everything EXCEPT the listed ' +
          'actions); the carve-out is NOT a set of allowed actions. '
        : '') +
      'A guardrail subtracts from the ceiling; it never grants.';
    remediation =
      'Confirm the denied set matches the guardrail you intend. An SCP Deny only ' +
      'removes access - grants still require identity policies within the ceiling.';
  }

  const finding = {
    id: 'SCP-GUARDRAIL',
    // A guardrail is protective (informational) - it subtracts from the ceiling.
    // Two exceptions are misconfiguration HAZARDS raised to medium so they are
    // visible (never high/critical - a guardrail is not an attack path):
    //   - the over-broad regional-Deny (negated ...IfExists, no global carve-out);
    //   - the INVERTED region fence (positive operator: denies inside the listed
    //     regions and permits everything outside - the inverse of a region lock).
    severity: (overBroadRegionHazard || invertedRegionHazard) ? 'medium' : 'info',
    title,
    statementSid: statementSid(stmt),
    statementIndex: stmt.index,
    actions: denies,
    resources: resourceSummary(stmt),
    conditions: stmt.condition,
    policyEvidence: 'high',
    pathExploitability: 'low',
    guardrailKind,
    why,
    limit: SCP_LIMIT,
    remediation,
    ruleVersion: '1',
    docRef,
  };
  // A NotAction on a Deny is the CARVE-OUT (deny everything EXCEPT these). Surface
  // it as an excluded set - NEVER as allowed actions (docs/scp-rcp-semantics.md
  // section 4: the excluded set is not a grant).
  if (hasCarveList) finding.excludedActions = stmt.notActions.slice();
  if (Array.isArray(stmt.notResources) && stmt.notResources.length > 0) {
    finding.excludedResources = stmt.notResources.slice();
  }
  if (isRegion) {
    finding.negatedIfExists = region.negatedIfExists;
    if (invertedRegionHazard) {
      // A positive-operator fence denies the LISTED regions (fires when the region
      // matches). Record them as the DENIED set - NEVER as allowedRegions, so a
      // broken fence is never surfaced as a protective allow-list.
      finding.deniedRegions = region.regions.slice();
      finding.regionPositiveOperator = true;
    } else {
      finding.allowedRegions = region.regions.slice();
    }
  }
  if (overBroadRegionHazard || invertedRegionHazard) finding.hazard = true;
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
 * Evaluate an SCP as a CEILING / GUARDRAIL family.
 *
 * Emits one finding per statement:
 *   - Allow -> an SCP-CEILING finding describing the maximum-permissions envelope
 *     breadth (never a grant).
 *   - Deny  -> an SCP-GUARDRAIL finding describing what the ceiling forbids
 *     (region guardrail, organization guardrail, or generic Deny), with any
 *     NotAction list surfaced as an excluded carve-out and the negated-IfExists
 *     over-broad-regional-Deny hazard flagged.
 *
 * Emits NO escalation findings and NO positive capability information; the
 * orchestrator draws no capability edges for this family (empty graph). Every
 * finding states the intersection semantics in `limit` (SCPs never grant).
 *
 * Never throws. Deterministic (findings ordered by originating statement index).
 *
 * @param {object} model normalized, frozen model (from modelFromText)
 * @returns {{ok:boolean, errors:Array, findings:Array<object>}}
 */
export function analyzeScp(model) {
  try {
    const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
    const findings = [];
    for (const stmt of statements) {
      if (stmt.effect === 'Deny') {
        findings.push(buildGuardrailFinding(stmt));
      } else {
        findings.push(buildCeilingFinding(stmt));
      }
    }
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
        { code: 'INTERNAL', message: 'SCP analysis failed unexpectedly.', path: null },
      ]),
      findings: Object.freeze([]),
    });
  }
}

export default analyzeScp;
