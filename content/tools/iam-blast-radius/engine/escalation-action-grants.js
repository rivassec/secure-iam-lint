// escalation-action-grants.js - low-level action-pattern matching helpers.
// Extracted verbatim from escalation.js as part of the behavior-preserving
// refactor (REFACTOR-PLAN.md). No logic change; pure move + re-export.
import { globMatch } from './glob.js';

// IAM action matching is case-insensitive ("s3:getobject" == "s3:GetObject").
// Exported so graph.js (IAM-006) can apply the SAME same-policy Deny precedence
// to rule findings that this module already applies to escalation findings.
export function actionGrants(pattern, concreteAction) {
  return globMatch(String(pattern).toLowerCase(), String(concreteAction).toLowerCase());
}

// A bare "*" action grant (Action:"*") grants EVERY action in every service,
// which necessarily includes iam:PassRole, sts:AssumeRole, and every direct-IAM
// self-administration action. It is therefore a superset of every escalation
// trigger this module recognizes, and MUST surface the paths it contains: an
// Action:"*" policy is de-facto AdministratorAccess. (Earlier this module
// skipped a bare "*" on the assumption that WILDCARD-ACTION "*" was already the
// single widest CRITICAL finding, so re-listing the named paths would be noise.
// IAM-102 removed that compensating critical - WILDCARD-ACTION is now `high` -
// so skipping "*" here left the risk summary affirmatively reporting
// "privilege-escalation paths: 0" for full admin, a strictly narrower iam:*
// policy yielding more paths than "*". That is an inaccurate security claim
// (threat-model T8: understating blast radius is as harmful as overstating it),
// so a bare "*" is now matched like any other pattern via actionGrants().)

// IAM policy variables (${...}) resolve only at runtime. A variable-bearing
// pattern cannot be matched from the policy text; treat it as uncertain so we
// never manufacture a false path (or hide one). Handled per-use below.
export function hasPolicyVariable(pattern) {
  return String(pattern).includes('${');
}

// Does statement `stmt` (an Allow) grant at least one action matching any of the
// concrete actions in `catalog`? Returns the matching statement patterns. A bare
// "*" glob-matches every catalog action (Action:"*" grants all of them), so it
// is reported like any other matching pattern - see the note above on why a
// full wildcard is no longer skipped here.
export function grantedPatternsFor(stmt, catalog) {
  const matched = [];
  for (const p of stmt.actions) {
    if (hasPolicyVariable(p)) continue; // cannot resolve from text -> skip
    if (catalog.some((concrete) => actionGrants(p, concrete))) matched.push(p);
  }
  // An Allow with NotAction grants everything EXCEPT the listed actions, so it
  // grants these sensitive actions unless one is explicitly excluded. This is a
  // genuine (broad) grant of the escalation action.
  if (stmt.notActions.length > 0) {
    for (const concrete of catalog) {
      const excluded = stmt.notActions.some(
        (p) => !hasPolicyVariable(p) && actionGrants(p, concrete),
      );
      // Not excluded => this NotAction-Allow grants the sensitive action. Report
      // the concrete action it fails to exclude (guard against dupes).
      if (!excluded && !matched.includes(concrete)) matched.push(concrete);
    }
  }
  return matched;
}
