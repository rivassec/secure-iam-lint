// escalation-takeover.js - role-takeover detector (a role whose trust + permissions let an actor grant itself the role then assume it). Extracted (behavior-preserving).
import { applyDenyToActions } from './escalation-deny.js';
import { chargeWork } from './glob.js';
import { evidenceOf, makeEscalation, prereqGroup, prereqTechnique, prerequisitesOf } from './escalation-finding.js';
import { grantedPatternsFor } from './escalation-action-grants.js';
import { hasNonEmptyCondition } from './escalation-conditions.js';
import { isAllRolesAssumeScope, isConcreteRoleArn, principalConditionsSatisfiable, resourceCoversRole } from './escalation-reachability.js';
import { ROLE_TAKEOVER_GRANT_ACTIONS, ROLE_TAKEOVER_ASSUME_ACTIONS, TRUST_MODIFY_ACTIONS } from './escalation-catalogs.js';

export function detectRoleTakeover(allows, out, denies) {
  // Surviving contributing (stmt, actions, resources) for each leg. Resources are
  // retained per statement so a WILDCARD modify grant can be matched against a
  // concrete assumable role (suite-3 test 74) rather than requiring an exact
  // per-role bucketing up front.
  const grantLegsAll = [];
  const trustLegsAll = [];
  const assumeLegsAll = [];
  const collect = (arr, stmt, actions) => arr.push({ stmt, actions, resources: stmt.resources });
  for (const stmt of allows) {
    const g = grantedPatternsFor(stmt, ROLE_TAKEOVER_GRANT_ACTIONS);
    if (g.length > 0) {
      const d = applyDenyToActions(denies, g, stmt);
      if (!d.blocked) collect(grantLegsAll, stmt, d.actions);
    }
    const t = grantedPatternsFor(stmt, TRUST_MODIFY_ACTIONS);
    if (t.length > 0) {
      const d = applyDenyToActions(denies, t, stmt);
      if (!d.blocked) collect(trustLegsAll, stmt, d.actions);
    }
    const a = grantedPatternsFor(stmt, ROLE_TAKEOVER_ASSUME_ACTIONS);
    if (a.length > 0) {
      const d = applyDenyToActions(denies, a, stmt);
      if (!d.blocked) collect(assumeLegsAll, stmt, d.actions);
    }
  }

  // A takeover is only ever asserted against a CONCRETE role the principal can
  // assume. A concrete anchor role may be named by ANY contributing leg - the
  // permission-grant, the trust-modify, OR the assume leg - because the compound
  // is symmetric: whichever leg happens to be concrete pins the role, and the
  // other legs may be wildcards that provably subsume it. Test 74 is the forward
  // case (wildcard modify + concrete assume); its mirror (concrete modify/trust +
  // a bounded wildcard assume such as role/deployment/*) reaches the SAME concrete
  // role and must yield the SAME one takeover. Harvesting anchors only from assume
  // legs missed that mirror (a false negative on a critical compound path). A
  // WILDCARD assume scope still names no concrete role itself; the anchor comes
  // from the concrete modify/trust leg and is CONFIRMED below only if an assume leg
  // covers it. Deterministic order.
  const anchorRoles = [];
  const anchorSeen = new Set();
  for (const leg of [...grantLegsAll, ...trustLegsAll, ...assumeLegsAll]) {
    for (const r of leg.resources) {
      // S3-dos-budget-all: this nested legs x resources scan calls only isConcreteRoleArn
      // (a regex/substring test) and (formerly) Array.includes - neither reaches the shared
      // matcher, so before this charge the whole anchor-harvest was invisible to the budget.
      // With many contributing legs each carrying a large resource list it is a real O(legs x
      // resources) traversal; charge one unit per (leg, resource) pair so it participates and
      // a runaway fails CLOSED. iter-7: the dedup membership is a Set (was `anchorRoles.includes`,
      // an O(anchors) Array-scan that made the harvest O(R^2) over many DISTINCT concrete role
      // ARNs while charging only O(R) - the same uncharged-quadratic dedup class as F1); a Set
      // keeps membership O(1) so the charged cost matches the true cost.
      chargeWork(1);
      if (isConcreteRoleArn(r) && !anchorSeen.has(r)) {
        anchorSeen.add(r);
        anchorRoles.push(r);
      }
    }
  }
  anchorRoles.sort();

  // DOS-1: one pin memo shared across EVERY anchor role. A statement's
  // principal-invariant pins do not depend on which role we are testing, so parsing
  // each contributing statement's Condition once here (rather than re-parsing it for
  // every (anchor role x triple)) keeps the satisfiability check from re-doing the
  // same work across roles as well as within a single triple loop.
  const pinMemo = new Map();
  for (const role of anchorRoles) {
    // A leg contributes to THIS role when one of its resources covers the
    // concrete role (exact, or a role-ARN wildcard that subsumes it).
    const grantLegs = grantLegsAll.filter((l) => l.resources.some((r) => resourceCoversRole(r, role)));
    const trustLegs = trustLegsAll.filter((l) => l.resources.some((r) => resourceCoversRole(r, role)));
    // The assume leg CONFIRMS the anchor: the principal must actually be able to
    // assume this concrete role. A bounded wildcard (account-pinned or path-scoped)
    // that covers the role confirms it; a MAXIMALLY-BROAD "*"/"*:role/*" assume
    // scope does NOT - it stays the ASSUME-ROLE-EXPANSION shape (test 142), never a
    // same-role takeover, even though it glob-covers the role.
    const assumeLegs = assumeLegsAll.filter((l) => l.resources.some(
      (r) => resourceCoversRole(r, role) && !isAllRolesAssumeScope(r),
    ));
    // All three legs must reach the same concrete role, or there is no chain.
    if (grantLegs.length === 0 || trustLegs.length === 0 || assumeLegs.length === 0) continue;

    // suite-3 test 75: reject the correlation when the legs carry mutually
    // exclusive same-key conditions on a principal-invariant key - no single
    // principal could execute the whole chain. The standalone modify capability
    // findings (PUT-INLINE-POLICY / TRUST-POLICY-MODIFY) remain, un-subsumed.
    if (!principalConditionsSatisfiable(grantLegs, trustLegs, assumeLegs, pinMemo)) continue;

    // Per-statement evidence: one record per contributing statement/leg, each
    // carrying ONLY the actions that statement grants toward this chain (IAM-701
    // provenance - never attribute all three actions to one statement).
    const evidence = [];
    for (const { stmt, actions } of grantLegs) {
      evidence.push(
        evidenceOf(stmt, 'grant-permissions', actions, `can attach/write a permission policy onto ${role}`),
      );
    }
    for (const { stmt, actions } of trustLegs) {
      evidence.push(
        evidenceOf(stmt, 'modify-trust', actions, `can rewrite the trust policy of ${role} to trust an attacker-controlled principal`),
      );
    }
    for (const { stmt, actions } of assumeLegs) {
      evidence.push(
        evidenceOf(stmt, 'assume', actions, `can assume ${role} once its trust policy permits it`),
      );
    }

    // Grounded action lists per leg (deduped, statement order preserved).
    // S3-dos-budget-all (iter-7): `arr` is grantLegs/trustLegs/assumeLegs.flatMap(l =>
    // l.actions), i.e. granted-pattern lists whose size grows with the policy's action
    // counts (up to MAX_ACTIONS per statement), and this runs once per anchor role. The
    // old `seen.includes(x)` Array-scan made each dedupe O(n^2) with ZERO chargeWork -
    // the same uncharged-quadratic dedup class as F1. A Set makes membership O(1)
    // (traversal O(n)); charge one unit per element so the traversal participates in the
    // work + wall-clock budget and a pathological action list fails CLOSED, not grinds.
    const dedupe = (arr) => {
      chargeWork(Array.isArray(arr) ? arr.length : 0);
      const seenSet = new Set();
      const out = [];
      for (const x of arr) if (!seenSet.has(x)) { seenSet.add(x); out.push(x); }
      return out;
    };
    const grantActions = dedupe(grantLegs.flatMap((l) => l.actions));
    const trustActions = dedupe(trustLegs.flatMap((l) => l.actions));
    const assumeActions = dedupe(assumeLegs.flatMap((l) => l.actions));
    const combinedActions = dedupe([...grantActions, ...trustActions, ...assumeActions]);

    // Anchor = lowest contributing statement index (deterministic header anchor).
    let anchor = null;
    for (const { stmt } of [...grantLegs, ...trustLegs, ...assumeLegs]) {
      if (anchor === null || stmt.index < anchor.index) anchor = stmt;
    }

    // Any contributing leg carrying a Condition gates the chain (lower confidence).
    const conditioned = [...grantLegs, ...trustLegs, ...assumeLegs].some(
      ({ stmt }) => hasNonEmptyCondition(stmt),
    );
    const denyNarrowed = [...grantLegs, ...trustLegs, ...assumeLegs].some(
      ({ stmt, actions }) => applyDenyToActions(denies, actions, stmt).narrowed,
    );

    // AND semantics (IAM-703): all three prerequisite groups are jointly required.
    const prerequisites = prerequisitesOf([
      prereqTechnique(
        'role-takeover-chain',
        [
          prereqGroup(grantActions, 'grant-permissions'),
          prereqGroup(trustActions, 'modify-trust'),
          prereqGroup(assumeActions, 'assume'),
        ],
        { requiresPassRole: false },
      ),
    ]);

    const riskFactors = [
      { key: 'grant-permissions', label: `Permission-grant primitive on ${role} (${grantActions.join(' / ')})`, present: true },
      { key: 'modify-trust', label: `Trust-policy rewrite on ${role} (${trustActions.join(' / ')})`, present: true },
      { key: 'assume', label: `Role assumption of ${role} (${assumeActions.join(' / ')})`, present: true },
      { key: 'same-role', label: 'All three primitives target the same role ARN', present: true },
    ];

    out.push(
      makeEscalation('ROLE-TAKEOVER', anchor, {
        // Critical (IAM-102/902): a compound chain that grants a role permissions,
        // re-trusts it, and assumes it plausibly crosses a privilege boundary - the
        // reserved-critical bar - and does so without iam:PassRole.
        severity: 'critical',
        // All three grants are literally present in the policy text -> policy
        // evidence HIGH. Whether the assumption actually elevates depends on what
        // the permission-grant leg then writes onto the role and any permission
        // boundary / SCP capping it (out of scope) -> exploitability MEDIUM.
        policyEvidence: 'high',
        pathExploitability: 'medium',
        conditioned,
        denyNarrowed,
        technique: 'role-takeover-chain',
        service: null,
        requiredActions: combinedActions,
        prerequisites,
        actions: combinedActions,
        resources: [role],
        evidence,
        riskFactors,
        why:
          `Grants a compound role-takeover chain on ${role}: a permission-grant ` +
          `primitive (${grantActions.join(' / ')}) to give the role permissions, ` +
          `iam:UpdateAssumeRolePolicy to rewrite its trust policy so the principal ` +
          `may assume it, and sts:AssumeRole to then assume it. Together these let ` +
          `the principal take the role over - grant it permissions, make it ` +
          `assumable, and assume it - WITHOUT needing iam:PassRole. The role's ` +
          `current permissions and any permission boundary on it are not in scope.`,
        remediation:
          'Separate role-permission management (iam:PutRolePolicy / ' +
          'iam:AttachRolePolicy), trust-policy management ' +
          '(iam:UpdateAssumeRolePolicy), and role assumption (sts:AssumeRole) ' +
          'across distinct administrative identities so no single principal can ' +
          'grant, re-trust, and assume the same role; scope each to specific role ' +
          'ARNs and protect high-value roles with a permission boundary and change ' +
          'review.',
      }),
    );
  }
}
