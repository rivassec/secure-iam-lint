// IAM Blast Radius - RCP resource-control guardrail evaluator (IAM-1302, Phase 13).
//
// A Resource Control Policy (RCP) is the resource-side sibling of an SCP: an AWS
// Organizations policy that sets the MAXIMUM available permissions for the
// RESOURCES in your organization. Like an SCP it is a CEILING / GUARDRAIL, never a
// grant (docs/scp-rcp-semantics.md sections 0, 7, 8):
//
//   - RCPs are DENY-ONLY in practice. The default RCPFullAWSAccess is a pass-through
//     Allow; an RCP does its work through Deny statements that CAP who may access
//     org resources (including callers from outside the organization).
//   - An RCP grants nothing. AWS: "No permissions are granted by an RCP ... an RCP
//     never grants permissions." Effective access is the INTERSECTION of the RCP
//     guardrail with the identity-based and resource-based policies that must
//     INDEPENDENTLY allow the action; a corresponding Allow must exist elsewhere.
//   - The canonical RCP is the org confused-deputy guardrail: a Deny scoped by
//     aws:SourceOrgID (StringNotEqualsIfExists), aws:PrincipalIsAWSService (Bool),
//     and aws:SourceAccount presence (Null). Those three conditions act TOGETHER
//     (logical AND): the guardrail denies a request made by an AWS service
//     principal, when aws:SourceAccount is present, unless the source org is your
//     org. They are ONE guardrail, not three independent denies.
//
// Running the identity rules / resource capability rules on an RCP would emit
// confident positive-capability findings (e.g. "S3 is publicly writable" from the
// Principal:"*" + Action:"s3:*") that a deny-only CEILING can NEVER establish -
// exactly the overstated-certainty harm the threat model forbids (T8). So this is
// a DISTINCT, family-aware evaluator (mirroring engine/scp.js and engine/
// envelope.js for the ceiling families): analyze.js routes an RCP selection here
// INSTEAD of the identity/resource engine, and the orchestrator draws NO positive
// capability edges for this family (the graph is empty by construction).
//
// This module reports the DENY GUARDRAIL SHAPE as findings (so the user sees what
// the ceiling forbids and the confused-deputy protection it encodes) but NEVER as
// a grant or as S3/public-access, and always states the intersection semantics in
// each finding's `limit`. There are NO capability findings here. A Principal:"*"
// is NOT reported as public access - an RCP Deny with Principal:"*" is the widest
// SUBJECT of the guardrail (everyone the deny can reach), not a grant to anyone.
//
// Pure, deterministic, dependency-free. No network APIs. No eval/Function. No DOM.
// Same model (+ same family) -> same findings, same order, every run.

// parseOperator strips the set-operator qualifier (ForAllValues:/ForAnyValue:) and
// the ...IfExists suffix, returning the lowercased BASE comparator. Operator
// POLARITY must be judged on that base form: `ForAnyValue:StringEquals` is a valid
// AWS spelling of a POSITIVE string comparator, but a naive startsWith('string')
// on the raw key would miss the qualifier prefix and credit an inverted org-scope
// fence as protective. Reuse the canonical parser so every polarity check sees
// through the qualifier prefix.
import { parseOperator } from './conditions.js';

// Finding ids emitted by this evaluator. Kept distinct from the identity RULE_IDS
// / ESCALATION_IDS, the trust TRUST_IDS, the envelope ENVELOPE_IDS, and the SCP
// SCP_IDS: an RCP finding is a different kind of observation (an org resource-
// control guardrail, deny-only, never a grant), so it carries its own family id.
export const RCP_IDS = Object.freeze([
  'RCP-GUARDRAIL',
]);

// The ceiling-not-grant + intersection caveat every RCP finding carries. Mirrors
// the SCP_LIMIT / envelope BOUNDARY_LIMIT contract (/ceiling/, /INTERSECTION/,
// /not grant/, /not effective access/) so the evidence contract holds across every
// ceiling family, and adds the RCP-specific "a corresponding Allow must exist
// elsewhere" wording the acceptance suite (test 52) requires.
const RCP_LIMIT =
  'An RCP is an organization RESOURCE-control guardrail / permission CEILING, not ' +
  'a grant: RCPs are DENY-ONLY and set the maximum permissions on who may access ' +
  'your organization\'s resources - they do NOT grant permissions. This describes ' +
  'the guardrail shape (a Deny) and is NOT effective access. A corresponding Allow ' +
  '(an identity-based and/or resource-based policy) must exist elsewhere for any ' +
  'access to occur; effective access is the INTERSECTION of those policies (which ' +
  'are not supplied here) and this guardrail. A permission is effective only if it ' +
  'is allowed by an identity/resource policy AND not denied by any applicable RCP.';

const RCP_DOC =
  'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html';
const CONFUSED_DEPUTY_DOC =
  'https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html';

function statementSid(stmt) {
  return typeof stmt.sid === 'string' && stmt.sid.length > 0
    ? stmt.sid
    : `(index ${stmt.index})`;
}

// The action summary a finding reports - the DENIED set (RCP is deny-only). A
// NotAction complement is surfaced as "everything except" and rides separately as
// excludedActions (a CARVE-OUT); the excluded list is NEVER the allowed actions
// (docs/scp-rcp-semantics.md section 4).
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
// RCP guardrails carry the org-scope confused-deputy keys. We read the normalized
// condition map (operator -> {key: value}) as INERT DATA. Operator/key casing is
// preserved by the model, so we compare case-insensitively. The three keys are
// read TOGETHER; they are one guardrail (logical AND), not independent denies.

const ORG_SOURCE_KEYS = new Set(['aws:sourceorgid', 'aws:sourceorgpaths']);
const PRINCIPAL_ORG_KEY = 'aws:principalorgid';
const IS_AWS_SERVICE_KEY = 'aws:principalisawsservice';
const SOURCE_ACCOUNT_KEY = 'aws:sourceaccount';

// Walk the normalized condition map once and record which guardrail signals are
// present, preserving the operator each key rides under (evidence, not grants):
//   - orgScope: an aws:SourceOrgID / aws:SourceOrgPaths / aws:PrincipalOrgID key,
//     and whether it uses a negated ...IfExists operator (fail-closed: a negated
//     ...IfExists in a Deny still denies when the key is absent).
//   - orgScopePositive: whether an org-scope key rides under a POSITIVE string
//     comparator (StringEquals / StringLike, no 'Not'). In a Deny that fires WHEN
//     the org MATCHES - the INVERSE of a guardrail (it denies your own org and
//     leaves outsiders un-guardrailed), a likely misconfiguration. This is the
//     operator POLARITY the narration must honor: "deny UNLESS the org matches"
//     holds only for a negated comparator; a positive comparator is inverted.
//   - principalIsAwsService: a Bool aws:PrincipalIsAWSService key + its "true"/
//     "false" value (does the guardrail target AWS service principals or not?).
//   - sourceAccountNullCheck: a Null aws:SourceAccount existence check (the
//     guardrail applies only when aws:SourceAccount is present).
// Returns a plain data record; all string lists are fresh arrays.
function inspectRcpConditions(condition) {
  const out = {
    orgScopeKeys: [],
    orgScopeNegatedIfExists: false,
    orgScopePositive: false, // an org-scope key under a positive string comparator
    principalOrgId: false,
    principalIsAwsService: null, // null=absent, 'true'/'false'=value
    sourceAccountNullValue: null, // null=absent, 'true'/'false'=Null-check value
    keys: [],
  };
  if (!condition || typeof condition !== 'object') return out;
  for (const op of Object.getOwnPropertyNames(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object') continue;
    const opLower = String(op).toLowerCase();
    // Judge polarity on the BASE comparator, with the set-operator qualifier
    // (ForAllValues:/ForAnyValue:) and ...IfExists suffix stripped. A raw key such
    // as `ForAnyValue:StringEquals` is a valid AWS spelling of a POSITIVE string
    // comparator; testing the raw key with startsWith('string') would miss the
    // qualifier prefix and credit an inverted org-scope fence as protective.
    const { base, ifExists } = parseOperator(op);
    const negatedOp = base.indexOf('not') !== -1;
    const negatedIfExists = negatedOp && ifExists;
    // Operator POLARITY for an org-scope Deny (evidence, never a grant): a POSITIVE
    // string comparator (StringEquals / StringLike, no 'Not') fires the Deny WHEN
    // the org key MATCHES - the INVERSE of the intended "deny unless the org
    // matches" guardrail. Only string comparators carry this polarity (org ids are
    // string-typed); a Null existence check is not a polarity and is read below.
    // The set-operator qualifier is stripped above, so a ForAnyValue:/ForAllValues:-
    // qualified positive comparator is caught too.
    const positiveStringOp = base.startsWith('string') && !negatedOp;
    const recordOrgScope = (key) => {
      out.orgScopeKeys.push(String(key));
      if (negatedIfExists) out.orgScopeNegatedIfExists = true;
      if (positiveStringOp) out.orgScopePositive = true;
    };
    for (const key of Object.getOwnPropertyNames(inner)) {
      const keyLower = String(key).toLowerCase();
      out.keys.push(String(key));
      if (ORG_SOURCE_KEYS.has(keyLower)) {
        recordOrgScope(key);
      } else if (keyLower === PRINCIPAL_ORG_KEY) {
        recordOrgScope(key);
        out.principalOrgId = true;
      } else if (keyLower === IS_AWS_SERVICE_KEY) {
        const v = inner[key];
        out.principalIsAwsService = Array.isArray(v) ? String(v[0]) : String(v);
      } else if (keyLower === SOURCE_ACCOUNT_KEY && opLower === 'null') {
        const v = inner[key];
        out.sourceAccountNullValue = Array.isArray(v) ? String(v[0]) : String(v);
      }
    }
  }
  return out;
}

// Does this Deny carry the org confused-deputy signature? An org-source (or
// principal-org) key TOGETHER with the AWS-service-principal scoping is the
// hallmark of the confused-deputy RCP (docs/scp-rcp-semantics.md section 8).
function isConfusedDeputy(info) {
  return info.orgScopeKeys.length > 0 && info.principalIsAwsService !== null;
}

// Is the guardrail's Principal the wildcard "*"? (The subject the deny can reach -
// NEVER reported as public access; an RCP Deny grants nothing.)
function principalIsWildcard(stmt) {
  return !!(stmt.principal && stmt.principal.anyPrincipal);
}

// --- Finding builder ---------------------------------------------------------

function buildGuardrailFinding(stmt) {
  const info = inspectRcpConditions(stmt.condition);
  const confusedDeputy = isConfusedDeputy(info);
  const wildcardPrincipal = principalIsWildcard(stmt);
  const denies = actionSummary(stmt); // the DENIED set (Deny effect)
  const hasCarveList = Array.isArray(stmt.notActions) && stmt.notActions.length > 0;

  // Operator-polarity hazard (mirrors scp.js overBroadRegionHazard): an org-scope
  // Deny whose comparator is POSITIVE (StringEquals-style, not negated) fires WHEN
  // the org matches - it denies your OWN organization and leaves outsiders
  // un-guardrailed, the INVERSE of confused-deputy / org-perimeter protection.
  // Flag it as a likely misconfiguration; it is still a Deny (never a grant).
  const invertedOrgScopeHazard = info.orgScopeKeys.length > 0 && info.orgScopePositive;

  let guardrailKind;
  if (confusedDeputy) guardrailKind = 'confused-deputy';
  else if (info.orgScopeKeys.length > 0) guardrailKind = 'organization';
  else guardrailKind = 'general';

  let title;
  let why;
  let remediation;
  let docRef = RCP_DOC;

  if (confusedDeputy) {
    const targetsService = info.principalIsAwsService === 'true';
    const orgKeyList = info.orgScopeKeys.join(', ');
    title = invertedOrgScopeHazard
      ? 'RCP resource-control guardrail (potentially inverted org-scope Deny)'
      : 'RCP resource-control guardrail (org confused-deputy Deny)';
    why =
      'This RCP Deny is an ORGANIZATION RESOURCE-CONTROL GUARDRAIL ' +
      (invertedOrgScopeHazard
        ? 'whose org-scope condition uses a POSITIVE operator, so it does NOT ' +
          'implement standard confused-deputy protection. '
        : 'implementing confused-deputy protection. ') +
      'Its conditions act TOGETHER (logical AND), as a ' +
      'single guardrail - not three independent denies: it denies access to the ' +
      'in-scope organization resources ' +
      (targetsService
        ? 'made by an AWS service principal (aws:PrincipalIsAWSService = true, the ' +
          'potential confused deputy) '
        : 'made by a non-service principal (aws:PrincipalIsAWSService = false) ') +
      (info.sourceAccountNullValue === 'false'
        ? 'ONLY when aws:SourceAccount is present in the request context (Null ' +
          'aws:SourceAccount = false), so service integrations that never set it ' +
          'are not broken, '
        : '') +
      (invertedOrgScopeHazard
        ? `WHEN the source organization matches (${orgKeyList}) - it fires for ` +
          'requests FROM the matching organization and PERMITS everyone else, the ' +
          'INVERSE of confused-deputy protection and a likely MISCONFIGURATION (a ' +
          'positive-operator org-scope Deny such as StringEquals denies your own ' +
          'org and leaves outside callers un-guardrailed; the intended form is a ' +
          'negated operator like StringNotEqualsIfExists). '
        : `UNLESS the source organization matches (${orgKeyList}). `) +
      (info.orgScopeNegatedIfExists
        ? 'Because the org check is a negated ...IfExists in a Deny, absence of the ' +
          'org key STILL denies (fail-closed) - an attacker cannot dodge the ' +
          'guardrail by omitting the context key. '
        : '') +
      'A corresponding Allow (identity-based and/or resource-based) must exist ' +
      'elsewhere for any access to occur; this guardrail only removes access and ' +
      'never grants. ' +
      (wildcardPrincipal
        ? 'The Principal "*" is the widest SUBJECT the deny can reach (everyone the ' +
          'guardrail evaluates), NOT public access or a grant to anyone. '
        : '');
    remediation = invertedOrgScopeHazard
      ? 'Fix the operator polarity: an org-scope Deny should use a NEGATED ' +
        'comparator (StringNotEqualsIfExists on aws:SourceOrgID / aws:PrincipalOrgID) ' +
        'so it denies UNLESS the request is from your organization. As written (a ' +
        'positive StringEquals-style comparator) it denies your OWN org and leaves ' +
        'external callers un-guardrailed - the inverse of the intended control. It ' +
        'is still a Deny (it grants nothing), but it does not provide the ' +
        'confused-deputy protection it appears to.'
      : 'Keep this guardrail attached at the organization root / OU whose resources ' +
        'must only be reached from within the org. It is a preventative control, not ' +
        'a grant - pair it with the identity/resource policies that actually allow ' +
        'the intended access. Confirm the org id and the aws:SourceAccount presence ' +
        'check match your service-integration footprint so legitimate callers are ' +
        'not blocked.';
    docRef = CONFUSED_DEPUTY_DOC;
  } else if (info.orgScopeKeys.length > 0) {
    const orgKeyList = info.orgScopeKeys.join(', ');
    title = invertedOrgScopeHazard
      ? 'RCP organization-perimeter guardrail (potentially inverted org-scope Deny)'
      : 'RCP organization-perimeter guardrail (Deny)';
    why =
      'This RCP Deny is an ORGANIZATION-PERIMETER RESOURCE GUARDRAIL: it denies ' +
      (invertedOrgScopeHazard
        ? `access to the in-scope organization resources WHEN the request's source ` +
          `/ principal organization matches (${orgKeyList}) - it fires for requests ` +
          'FROM the matching organization and PERMITS everyone else, the INVERSE of ' +
          'org-perimeter protection and a likely MISCONFIGURATION (a positive-' +
          'operator org-scope Deny such as StringEquals denies your own org and ' +
          'leaves outside callers un-guardrailed; the intended form is a negated ' +
          'operator like StringNotEqualsIfExists). '
        : `access to the in-scope organization resources unless the request's ` +
          `source / principal organization matches (${orgKeyList}). `) +
      (info.orgScopeNegatedIfExists
        ? 'Because the org check is a negated ...IfExists in a Deny, absence of the ' +
          'org key STILL denies (fail-closed). '
        : '') +
      'A corresponding Allow must exist elsewhere for any access to occur; the ' +
      'guardrail only removes access and never grants. ' +
      (wildcardPrincipal
        ? 'The Principal "*" is the widest SUBJECT the deny can reach, NOT public ' +
          'access or a grant. '
        : '');
    remediation = invertedOrgScopeHazard
      ? 'Fix the operator polarity: an org-perimeter Deny should use a NEGATED ' +
        'comparator (StringNotEqualsIfExists on aws:PrincipalOrgID / aws:SourceOrgID) ' +
        'so it denies UNLESS the caller is within your organization. As written it ' +
        'denies your OWN org and leaves external callers un-guardrailed. It grants ' +
        'nothing, but it does not provide the perimeter protection it appears to.'
      : 'Keep this guardrail attached at the organization scope whose resources must ' +
        'stay reachable only from within the org perimeter. It caps access; grants ' +
        'still require identity/resource policies.';
  } else {
    title = 'RCP resource-control guardrail (Deny)';
    why =
      'This RCP Deny is an ORGANIZATION RESOURCE-CONTROL GUARDRAIL: it removes the ' +
      'listed actions from the ceiling on who may access the in-scope organization ' +
      'resources. ' +
      (hasCarveList
        ? 'The NotAction list is a CARVE-OUT (denies everything EXCEPT the listed ' +
          'actions); the carve-out is NOT a set of allowed actions. '
        : '') +
      'A corresponding Allow must exist elsewhere for any access; the guardrail ' +
      'only removes access and never grants. ' +
      (wildcardPrincipal
        ? 'The Principal "*" is the widest SUBJECT the deny can reach, NOT public ' +
          'access or a grant. '
        : '');
    remediation =
      'Confirm the denied set matches the resource guardrail you intend. An RCP Deny ' +
      'only removes access - grants still require identity/resource policies within ' +
      'the ceiling.';
  }

  const finding = {
    id: 'RCP-GUARDRAIL',
    // A guardrail is protective (informational): it subtracts from the resource
    // ceiling and grants nothing. The one exception is the inverted org-scope Deny
    // hazard (a positive-operator org-scope comparator that denies your OWN org and
    // leaves outsiders un-guardrailed): a misconfiguration - raise it to medium so
    // it is visible. Never high/critical - an RCP is not an attack path and a
    // ceiling can never be a compound escalation.
    severity: invertedOrgScopeHazard ? 'medium' : 'info',
    title,
    statementSid: statementSid(stmt),
    statementIndex: stmt.index,
    actions: denies,
    resources: resourceSummary(stmt),
    // Preserve the FULL condition object so the three-key interaction is not lost
    // and is never re-read as independent denies downstream.
    conditions: stmt.condition,
    policyEvidence: 'high',
    pathExploitability: 'low',
    guardrailKind,
    denyOnly: true,
    why,
    limit: RCP_LIMIT,
    remediation,
    ruleVersion: '1',
    docRef,
  };
  // Structured, deterministic guardrail evidence (kept as data, never a grant):
  // the org-scope keys, whether the org check is fail-closed (negated IfExists),
  // whether the guardrail targets AWS service principals, and whether it gates on
  // aws:SourceAccount presence. This preserves the condition INTERACTION for the
  // evidence panel / exports without ever inverting a deny into a capability.
  if (info.orgScopeKeys.length > 0) finding.orgScopeKeys = info.orgScopeKeys.slice();
  finding.orgScopeNegatedIfExists = info.orgScopeNegatedIfExists;
  if (info.principalIsAwsService !== null) {
    finding.targetsAwsServicePrincipals = info.principalIsAwsService === 'true';
  }
  if (info.sourceAccountNullValue !== null) {
    // Null aws:SourceAccount = false  -> the guardrail applies only when the key
    // is PRESENT. Record it as the presence-required signal (evidence).
    finding.sourceAccountPresenceRequired = info.sourceAccountNullValue === 'false';
  }
  if (confusedDeputy) finding.confusedDeputy = true;
  // Inverted org-scope polarity: a positive-operator org-scope Deny is a likely
  // misconfiguration (denies your own org, leaves outsiders un-guardrailed). Record
  // it as structured evidence + a hazard flag (mirrors scp.js overBroadRegionHazard).
  // It is still deny-only and grants nothing; the hazard only raises visibility.
  if (invertedOrgScopeHazard) {
    finding.hazard = true;
    finding.orgScopePositiveOperator = true;
  }
  if (wildcardPrincipal) finding.wildcardPrincipalSubject = true;
  if (hasCarveList) finding.excludedActions = stmt.notActions.slice();
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
 * Evaluate an RCP as a DENY-ONLY resource-control GUARDRAIL family.
 *
 * Emits one RCP-GUARDRAIL finding per statement (RCPs are deny-only in practice;
 * an Allow is only the RCPFullAWSAccess pass-through default). Each finding
 * describes what the ceiling FORBIDS - an org confused-deputy guardrail, an
 * organization-perimeter guardrail, or a generic resource Deny - preserving the
 * confused-deputy condition INTERACTION (aws:SourceOrgID + aws:PrincipalIsAWSService
 * + Null aws:SourceAccount) as one guardrail, never three independent denies.
 *
 * Emits NO capability findings, NO S3/public-access finding, and NO positive
 * capability information; the orchestrator draws no capability edges for this
 * family (empty graph). Every finding states the intersection semantics in
 * `limit` (RCPs never grant; a corresponding Allow must exist elsewhere).
 *
 * A pass-through Allow (the RCPFullAWSAccess default) contributes no finding: it
 * is the default that lets everything through RCP evaluation, not a guardrail.
 *
 * Never throws. Deterministic (findings ordered by originating statement index).
 *
 * @param {object} model normalized, frozen model (from modelFromText)
 * @returns {{ok:boolean, errors:Array, findings:Array<object>}}
 */
export function analyzeRcp(model) {
  try {
    const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
    const findings = [];
    for (const stmt of statements) {
      // RCPs do their work through Deny. An Allow is the pass-through default
      // (RCPFullAWSAccess) - it is not a guardrail and never a grant, so it
      // contributes no finding (there is nothing the ceiling forbids).
      if (stmt.effect === 'Deny') {
        findings.push(buildGuardrailFinding(stmt));
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
        { code: 'INTERNAL', message: 'RCP analysis failed unexpectedly.', path: null },
      ]),
      findings: Object.freeze([]),
    });
  }
}

export default analyzeRcp;
