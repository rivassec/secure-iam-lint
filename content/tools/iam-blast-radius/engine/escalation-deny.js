// escalation-deny.js - explicit-Deny precedence for escalation analysis. Extracted (behavior-preserving).
import { actionGrants, hasPolicyVariable } from './escalation-action-grants.js';
import { chargeWork, globMatch } from './glob.js';
import { grantTokenIsBroad, isStarResource } from './escalation-scope.js';
import { hasNonEmptyCondition } from './escalation-conditions.js';

export function denyActionApplies(stmt, action) {
  // S3-dos-budget-all (Team1): charge per Action/NotAction pattern INSPECTED. A
  // policy-variable pattern short-circuits via `continue` BEFORE actionGrants (the
  // only charged call here), so a Deny whose Action/NotAction list is entirely
  // ${...} variables advanced the budget zero times. denyActionApplies is called
  // once per (deny x required-action) in denyEffectOnAction/applyDenyToActions, so an
  // all-variable Deny made that whole dimension free -> a within-caps policy could run
  // unbounded yet return a COMPLETE verdict (fail-OPEN, T5/T8). Charge one unit per
  // pattern so the scan participates whether or not the matcher is reached.
  if (stmt.notActions.length > 0) {
    let concreteExcluded = false;
    let hasVar = false;
    for (const p of stmt.notActions) {
      chargeWork(1);
      if (hasPolicyVariable(p)) { hasVar = true; continue; }
      if (actionGrants(p, action)) concreteExcluded = true;
    }
    if (concreteExcluded) return { applies: false, certain: true };
    // Not concretely excluded: NotAction-Deny applies to (touches) this action. A
    // variable in the exclusion list might exclude it at runtime -> uncertain.
    // NOTE: `applies:true` here means the Deny narrows the grant, NOT that it
    // fully covers it. Whether it can HARD-BLOCK is decided in denyEffectOnAction,
    // which refuses full coverage for a NotAction-Deny against a broad/wildcard
    // grant token (the preserved actions stay allowed) - do not "optimize" this to
    // block a wildcard grant here, or false denies return (threat-model T8).
    return { applies: true, certain: !hasVar };
  }
  let concreteMatch = false;
  let hasVar = false;
  for (const p of stmt.actions) {
    chargeWork(1);
    if (hasPolicyVariable(p)) { hasVar = true; continue; }
    if (actionGrants(p, action)) concreteMatch = true;
  }
  if (concreteMatch) return { applies: true, certain: true };
  if (hasVar) return { applies: true, certain: false }; // might match at runtime
  return { applies: false, certain: true };
}



// Does any concrete Deny resource pattern glob-cover `ar`? Scans every Deny resource.
//
// S3-dos-budget (iter-3): this scan is charged AGAINST THE DETERMINISTIC WORK BUDGET
// for the WHOLE inspection (one unit per Deny resource examined), UP FRONT and
// INDEPENDENT of whether globMatch is actually reached. A Deny resource that carries
// an IAM policy variable (${...}) is skipped by the `!hasPolicyVariable(dr)` guard, so
// globMatch - the only place chargeWork used to run - never fires for it. Without this
// explicit charge the entire nested deny-coverage traversal (O(ruleFindings x
// findingActions x denies x denyResources)) accrued ZERO work when the Deny scope was
// variable-bearing, analyze()'s work budget (sampled only inside chargeWork) never
// tripped, and a within-caps ${...}-scoped policy drove analyze() to multiple seconds
// yet returned a COMPLETE, non-aborted verdict - a fail-OPEN (threat-model T5/T8). The
// concrete/wildcard-deny path already fails closed in ~70ms because globMatch charges
// its own compare cost; this base charge makes the policy-variable path reach the SAME
// aborted+incomplete state instead of running unbounded. globMatch still charges its
// own per-character cost on the concrete branch, so this does not double-count that.
export function denyResourcesCover(denyResources, ar) {
  const arLen = String(ar).length;
  let covered = false;
  for (const dr of denyResources) {
    if (!hasPolicyVariable(dr)) {
      // Concrete Deny resource: globMatch runs and charges its own (dr+ar) compare
      // cost, exactly as before.
      if (globMatch(dr, ar)) { covered = true; break; }
    } else {
      // Policy-variable Deny resource: globMatch is (correctly) short-circuited -
      // a ${...} pattern cannot be resolved from the policy text - but INSPECTING it
      // (the hasPolicyVariable string scan, and the traversal that reaches it) is
      // real O(dr) work. Charge the SAME magnitude globMatch would have charged for
      // a concrete dr of this size so the variable branch accrues budget at the same
      // rate as the concrete branch. This is the crux of S3-dos-budget iter-3: without
      // it, a Deny whose Resource is entirely policy variables makes this scan free,
      // analyze()'s work budget never trips, and a within-caps ${...}-scoped policy
      // runs multiple seconds yet returns a COMPLETE verdict (fail-OPEN, T5/T8).
      chargeWork(String(dr).length + arLen + 1);
    }
  }
  return covered;
}

// How completely does `denyStmt` cover the resource scope granted by `allowStmt`?
// Returns 'full' | 'partial' | 'none'. Only 'full' (paired with an unconditional,
// certain action match) suppresses a path; 'partial' reduces confidence.
export function denyResourceCoverage(denyStmt, allowStmt) {
  // Charge one unit per invocation so the OUTER traversal (per deny, per action, per
  // finding) accrues budget even on the early-return branches below - a policy whose
  // cost is the sheer NUMBER of deny-coverage calls (not the per-call scan) is still
  // bounded (S3-dos-budget iter-3).
  chargeWork(1);
  // A Deny scoped by NotResource, or with no Resource/NotResource, cannot be
  // proven to fully cover the Allow scope from the policy text -> partial.
  if (denyStmt.notResources.length > 0) return 'partial';
  if (denyStmt.resources.length === 0) return 'partial';
  // S2-passrole-allstmts axis 3 (DoS, iter-5): CHARGE the O(nDenyResources) star scan
  // just below - it inspects EVERY Deny resource - so this call advances the work budget
  // proportional to the Deny resource list even on the branches that return before the
  // already-charged denyResourcesCover scan (:786). The star scan and the allowRes.length
  // ===0 -> 'partial' gate (the NotResource-shaped Allow) previously let this whole call
  // run its per-resource scan for ZERO budget; invoked 8 x nPassStmts x nDeny times
  // (once per PassRole Allow x service x Deny) with a large Deny resource list, a
  // within-caps policy ran unbounded yet returned a COMPLETE verdict (fail-open T5/T8),
  // and on the browser (no wall-clock watchdog) this work counter is the only ceiling.
  // Charging here makes the star scan participate so the run fails CLOSED
  // (RESOURCE_BUDGET_EXCEEDED) if genuinely huge. This does NOT double-count
  // denyResourcesCover's per-character compare charges (a distinct, later cost).
  chargeWork(denyStmt.resources.length);
  // A Deny on "*" covers every resource the Allow could reach.
  if (denyStmt.resources.some(isStarResource)) return 'full';

  const allowRes = allowStmt.resources;
  // Allow scoped by NotResource or unspecified is broad; a concrete Deny list
  // cannot be shown to cover all of it -> partial overlap at most.
  if (allowStmt.notResources.length > 0 || allowRes.length === 0) return 'partial';

  // Both have concrete Resource lists. Full coverage requires every Allow
  // resource to be a concrete literal (no wildcard / no policy variable) that
  // some concrete Deny pattern matches. Otherwise the coverage is uncertain.
  let anyOverlap = false;
  const allCovered = allowRes.every((ar) => {
    if (hasPolicyVariable(ar) || ar.includes('*') || ar.includes('?')) {
      // Wildcarded / variable Allow scope: a concrete Deny may still overlap
      // part of it, but cannot be proven to cover all -> not full.
      if (denyResourcesCover(denyStmt.resources, ar)) anyOverlap = true;
      return false;
    }
    const covered = denyResourcesCover(denyStmt.resources, ar);
    if (covered) anyOverlap = true;
    return covered;
  });
  if (allCovered) return 'full';
  return anyOverlap ? 'partial' : 'none';
}

// Classify how the model's Deny statements affect one required `action` granted
// by `allowStmt`. Returns 'blocked' | 'may-block' | 'clear'.
export function denyEffectOnAction(denies, action, allowStmt) {
  let result = 'clear';
  for (const deny of denies) {
    // S3-dos-budget (iter-3): charge one unit per deny inspected so the denies
    // dimension of the O(findings x actions x denies x resources) scan is bounded
    // by the deterministic budget even on branches where both the action match and
    // the resource match short-circuit globMatch (all-policy-variable Deny).
    chargeWork(1);
    const a = denyActionApplies(deny, action);
    if (!a.applies) continue;
    const coverage = denyResourceCoverage(deny, allowStmt);
    if (coverage === 'none') continue;
    const conditioned = hasNonEmptyCondition(deny);
    // A NotAction-Deny cannot FULLY cover a broad/wildcard grant token (the
    // NotAction-preserved action(s) remain allowed), so against such a grant it
    // can only narrow, never block. Full action coverage - the precondition for
    // a hard block - therefore requires either a positive-Action Deny (whose
    // pattern demonstrably covers the grant token) or a concrete grant token.
    const notActionVsBroadGrant = deny.notActions.length > 0 && grantTokenIsBroad(action);
    if (!conditioned && a.certain && coverage === 'full' && !notActionVsBroadGrant) {
      return 'blocked'; // definitive, in-scope explicit Deny -> path removed
    }
    result = 'may-block'; // conditional / partial / uncertain / narrowing -> narrows path
  }
  return result;
}

// Apply same-policy Deny precedence to a finding's matched concrete actions.
// Returns { actions, blocked, narrowed }:
//   - actions : matched actions with definitively-blocked ones removed
//   - blocked : true if EVERY matched action was definitively blocked (suppress)
//   - narrowed: true if any action was removed or may be blocked (downgrade)
export function applyDenyToActions(denies, matchedActions, allowStmt) {
  if (denies.length === 0) {
    return { actions: matchedActions.slice(), blocked: false, narrowed: false };
  }
  const kept = [];
  let narrowed = false;
  for (const a of matchedActions) {
    const e = denyEffectOnAction(denies, a, allowStmt);
    if (e === 'blocked') { narrowed = true; continue; }
    if (e === 'may-block') narrowed = true;
    kept.push(a);
  }
  return { actions: kept, blocked: kept.length === 0, narrowed };
}
