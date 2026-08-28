# secure-iam-lint - Behavior-Preserving Refactor Plan (cross-model reviewed)

Status: 2026-08-27. Reviewed + reconciled with Openclaw (gpt-5.5) and Gentoo (Claude, checked-out repo). This file is self-contained: a fresh session can execute it cold.

## 0. Goal + gate

Split the oversized shipped files into human-manageable modules **without changing behavior**. This is the LAST blocker before v1.0.0.

Oliver's decision gate (explicit): he tags v1.0.0 only when the code is **(1) refactored to human-manageable file sizes AND (2) passing our tests**. Security work (Phases 2-5) is already complete and clean; only this refactor remains.

Metric convention: **lines of code (LOC), not characters** (non-blank; `grep -cve '^\s*$'`). LOC guideline: ~400 comfortable / 500 review / decompose at 750.

## 1. The invariant + the safety net

Every split PR is a **pure move + re-export**: relocate code to new files, re-export the public surface from the original filename (the orchestrator), change NO logic. The proof that a move was pure:

Per-PR gate - ALL must stay green (any delta == a behavior leak to find + fix before merge):
1. `cd tools/iam-blast-radius && node --test "tests/**/*.test.js" "audit/**/*.test.js"` -> currently 2778 pass / 0 fail / 0 todo.
2. `node --test audit/golden-corpus/golden-oracle.test.js` + `GOLDEN_RELEASE_GATE=1 node --test audit/golden-corpus/release-gate.test.js` (16/16).
3. `node audit/lint/lint.mjs` (fail-open lint - no NEW hotspot class).
4. **`npx madge --circular content/tools/iam-blast-radius/engine` (or eslint `import/no-cycle`)** -> zero cycles. CRITICAL (Gentoo): tests-green is NOT sufficient proof of a pure move. ESM circular imports cause TDZ/undefined-binding failures that are LOAD-ORDER-dependent; the suite passes under the test runner's import order and can still break under the CLI's or the GitHub Action's order. Add a real cycle check to the gate.
5. `git add -A && git commit -q -m "refactor: split <file> (pure move)"` on `wip/appsec-phase2-4-20260827`; then push the private backup:
   `GIT_SSH_COMMAND='ssh -i ~/.ssh/git_rivassec -o IdentitiesOnly=yes' git push backup wip/appsec-phase2-4-20260827`

## 2. Current sizes (wip tree, post Phase 2-5) + a branch caveat

| File | LOC (wip) | target modules |
|---|---|---|
| content/tools/iam-blast-radius/engine/escalation.js | 3016 | ~11 (see S6) |
| content/tools/iam-blast-radius/engine/resource.js | 2977 | ~6 |
| content/tools/iam-blast-radius/engine/rules.js | 1979 | ~5 |
| content/tools/iam-blast-radius/engine/trust.js | 1853 | ~4 |
| content/tools/iam-blast-radius/engine/graph.js | 1808 | ~4 (DEFER) |
| action/index.mjs | 1535 | ~2 (DEFER) |
| cli/sarif.mjs | 1233 | ~2 (DEFER) |

CAVEAT (Gentoo): line numbers below are from the wip tree and drift as you cut. Gentoo reviewed the PUBLIC branch (f4149e5, pre-Phase-2-5) where the same files are smaller/line-shifted (rules.js 1562 there vs 1979 on wip). The STRUCTURE (section seams, call graph) is identical on both branches; only line numbers differ. Execute on wip. **Re-grep every line number immediately before each extraction** - never trust a stale number.

## 3. MANDATORY step 0 per file (before drawing any boundary)

Both reviewers independently: do NOT slice by section-header line-range alone (that is exactly how the cycle bugs below slipped in). For EACH file about to be split:

1. `grep -rn "from './<file>.js'" content/tools/iam-blast-radius/engine cli action` -> the EXTERNAL symbols other files import from it. Every one of these MUST be re-exported from the orchestrator, or the split is not a 1-file PR (it breaks the importers). 
2. `grep -n "functionName" <file>` in BOTH directions for the functions near a proposed module boundary -> the real call graph, to place leaf helpers correctly and keep imports one-directional.
3. Diff that symbol list against the planned re-export list; reconcile before cutting.

## 4. File order + why

Order is a DEPENDENCY constraint, not just LOC size (Gentoo): resource.js -> trust.js -> escalation.js, and rules.js + graph.js -> escalation.js. **escalation.js is the dependency root** - its new export surface must stabilize before its dependents are touched.

1. escalation.js FIRST (dependency root). To de-risk the workflow, START with a tiny leaf extraction from it (e.g. `escalation-action-grants.js`) as PR 1a before the harder detector modules.
2. rules.js, trust.js, resource.js (dependents; any order after escalation stabilizes).
3. DEFER graph.js, action/index.mjs, cli/sarif.mjs past v1.0.0 (Openclaw): lower security urgency + higher risk near release (graph has ordering/snapshot assumptions; sarif fingerprint churn near release is dangerous). Revisit as a fast-follow. Oliver's "human-manageable" bar decides whether they block the tag.

## 5. AGREED escalation.js decomposition (the detailed one)

Public API the orchestrator (escalation.js keeps the name) MUST re-export - list the ACTUAL external imports, not just the "public API":
- `ESCALATIONS`, `ESCALATION_IDS`, `analyzeEscalations`, `analyzeEscalationsFromText`, `default = analyzeEscalations`
- PLUS the 6 symbols other engine files import (Gentoo, grep-confirmed): `applyDenyToActions`, `denyActionApplies`, `denyResourceCoverage`, `hasNonEmptyCondition`, `actionGrants`, `hasPolicyVariable`
  - imported by: rules.js:56 (applyDenyToActions, denyActionApplies, hasNonEmptyCondition); trust.js:33 (denyActionApplies, hasNonEmptyCondition); graph.js:70-77 (analyzeEscalations, applyDenyToActions, denyResourceCoverage, actionGrants, hasPolicyVariable, hasNonEmptyCondition)
  - Re-exporting these from the orchestrator keeps this a TRUE 1-file PR (dependents' import paths do not change). If you do NOT re-export them, it becomes a 4-file PR (escalation + rules + trust + graph). Re-export is the pure-move choice.

The leaf floor (extract FIRST; tighter than my first draft, per Openclaw - avoid an `escalation-shared` junk drawer):
- `escalation-catalogs.js`: classifyEcsRole(:269), ecsRoleClasses(:289), ESCALATIONS(:344), ESCALATION_IDS(:446), single-action/broad catalog consts, `deepFreeze`(:3142) (keep near catalogs unless widely used).
- `escalation-action-grants.js`: actionGrants(:136), grantedPatternsFor(:166), hasPolicyVariable(:157).
- `escalation-scope.js`: resourceScope(:552), isStarResource(:723), grantTokenIsBroad(:737), resourceListIsBroadForAssume(:561), assumeScopeIsAllRoles(:626), assumeAccountReach(:652).
- `escalation-statement.js`: statementSid(:886).
- `escalation-conditions.js`: passedToServiceEntries(:455), normalizeOperator(:478), operatorPermitsService(:494), passRolePermitsService(:528), hasNonEmptyCondition(:541), constraintContains(:2640), keyConstraintsSatisfiable(:2660).
- `escalation-principal-pins.js`: principalPinsOf(:2592), principalPinsOfMemo(:2707), pinsJointlySatisfiable(:2717), principalConditionsSatisfiable(:2761). SAFE to move as-is (both reviewers confirmed): these take `memo`/`pinMemo` as an EXPLICIT parameter (`new Map()` created per call-site), so there is NO module-private cache / closure-capture lifetime risk.
- `escalation-role-targets.js` (Openclaw - own leaf so passrole/families/partition all import it without importing each other): parsePassResource(:2227), concreteRoleTargetAccount(:2022), isConcreteRoleArn(:2127), resourceCoversRole(:2141), isAllRolesAssumeScope(:2165), specificAccountsInRoleArns(**:2186** - plan draft mislabeled this :2227; corrected).
- `escalation-role-coverage.js` (Openclaw - the fix for the deny<->partition cycle): partitionReaches(:2235), accountReaches(:2238), resourceReachesSubject(:2398), subjectRoleArnPrefix(:2378), globCanProducePrefix(:2343), rolePathIsWildcardEquivalent(:2418), partitionModelable(:2264), subjectPartitionKnown(:2278), accountModelable(:2281), otherResourceIsUnmodelable(:2302), isUnmodelablePassResource(:2313), isConfidentPinnedResource(:2323). BOTH deny-role-removal AND partition/passrole detectors import this leaf; it imports nobody above it.

Mid layer (import the leaves; NOT each other):
- `escalation-deny.js`: denyActionApplies(:682), denyResourcesCover(:758), denyResourceCoverage(:785), denyEffectOnAction(:837), applyDenyToActions(:869), denyResourceRemovesAllSubjectRoles(:2432), denyRemovesAllSubjectRoles(:2463). CONFIRMED (grep): denyResourceRemovesAllSubjectRoles calls partitionReaches/accountReaches -> imports escalation-role-coverage.js (NOT escalation-partition.js) to avoid a cycle.
- `escalation-finding.js`: makeEscalation(:896), downgrade(:987), evidenceOf(:1000), contributingStatementsFrom(:1021), prereqGroup(:1070), prereqTechnique(:1074), prerequisitesOf(:1083), survivingGrantedActions(:1091). May import escalation-catalogs; catalogs must NOT import finding.

Detectors (import finding/deny/conditions/role-targets/role-coverage; NOT each other):
- `escalation-passrole.js`: detectPassRolePaths(:1132-1714, ~580 LOC), passStmtViabilityTier(:2495), execResourceBroadness(:580), execTechniqueSeverity(:600). CONFIRMED (Gentoo, grep): detectPassRolePaths calls partitionModelable/accountModelable/resourceReachesSubject/subjectPartitionKnown/partitionReaches -> imports escalation-role-coverage.js (one-directional; fine). Do NOT internally sub-split detectPassRolePaths in the first PR (Openclaw) - preserve behavior first; a second behavior-preserving inner split is a separate follow-up if it is still unreviewable.
- `escalation-families.js`: detectPolicyVersion(:1715), detectAttachPolicy(:1759), detectPutInlinePolicy(:1803), detectTrustModify(:1847), detectCredentialCreation(:1887), detectAssumeRoleExpansion(:1937), detectCrossAccountScopedAssume(:2040), concreteRoleTargetAccount-adjacent role helpers if not already in role-targets.
- `escalation-takeover.js`: detectRoleTakeover(:2822) + its private pin helpers if not already in principal-pins/role-coverage.

Orchestrator (escalation.js): analyzeEscalations(:3051), analyzeEscalationsFromText(:3134) + the re-export block (all of section-5 top list). **The `DETECTORS` array (:2999-3009) MOVES HERE** (Gentoo - CRITICAL): it currently sits physically inside the partition byte-range but is iterated by analyzeEscalations; leaving it there forces partition to import detectPassRolePaths back -> passrole<->partition CYCLE. Build DETECTORS in the orchestrator from imports of all detect* functions.

Acyclic import graph (target shape, Openclaw):
```
catalogs, action-grants, scope, statement, conditions, principal-pins, role-targets, role-coverage   (leaves)
      -> deny, finding
      -> passrole, families, takeover   (detectors)
      -> escalation.js orchestrator (owns DETECTORS + re-exports)
      -> external callers (rules/trust/graph/resource)
```
Rules: leaves import only lower leaves (catalogs imports only deepFreeze-tier utils). deny/finding import leaves, NOT detectors. detectors import finding/deny/leaves, NOT each other. NOTHING internal imports `./escalation.js` (import the leaf directly, never through the orchestrator's re-exports).

Extraction ORDER: 1 catalogs+deepFreeze -> 2 action-grants/scope/statement -> 3 conditions -> 4 principal-pins -> 5 role-targets -> 6 role-coverage -> 7 finding -> 8 deny -> 9 passrole -> 10 families -> 11 takeover -> 12 orchestrator (DETECTORS + re-exports). Each step is its own stop point (gate green + commit + push backup).

## 6. Other files (module-level seams; run step 0 first)

rules.js (1979) -> orchestrator + rules-catalogs.js (action-shape classifiers + sensitive catalogs + rule-catalog metadata, ~129-556), rules-finding-factory.js (~557-725), rules-deny-precedence.js (deny-fence/surviving-spared, ~726-883 + Phase-3/4 additions - the churn), rules-eval-*.js (per-rule eval ~884-1916 split by rule group).

trust.js (1853) -> orchestrator + trust-principals.js (**classifyPrincipals(:464) + the unenumerated ~580 LOC front-matter before :582 - Gentoo caught this; classifyPrincipals is imported by resource.js:30 AND called 7x inside trust.js, so it must be a real module OR the orchestrator stays ~600 LOC**) + trust-conditions.js (polarity ~598-848) + trust-findings.js (construction ~849-1644) + trust-deny.js (~1645+).

resource.js (2977) -> orchestrator + resource-principals.js (**lines 1-520 + the 1935-1963 gap - Gentoo caught these are unassigned; likely classifyPrincipals-adjacent parsing**) + resource-conditions.js (condition composition + confused-deputy + named-principal, ~520-1061) + resource-s3-typing.js (~1062-1934) + resource-service-rules/{s3-bucket-policy.js ~1964-2269, kms-key-policy.js ~2270-2621, sns-sqs.js ~2622+}.

graph.js (1808, DEFER) -> graph-identity.js (~86-1307) + graph-trust.js (~1398-1846) + graph-shared.js (vocab/helpers/ordering). CAUTION (Gentoo): buildResourceGraph(:1707) is a THIRD public entry point mis-filed under the role-trust section - pull it out (its own graph-resource.js or the orchestrator), do not silently bundle it into graph-trust.js. addDenyEdges(:1229-1307, identity section) is called from buildTrustGraph -> a real cross-module dep; decide shared-vs-identity-owned explicitly before cutting.

## 7. Known hazards (both reviewers)

- Circular imports (the #1 risk): the deny<->partition edge via role reachability; the DETECTORS-array placement; any detector<->detector edge. Mitigations: the role-coverage/role-targets leaves + DETECTORS-in-orchestrator + `madge --circular` in the gate.
- "Pure move" that isn't: external re-export gaps (do step 0), module-private consts/memo caches (move WITH the function; here the memo funcs are param-based = safe), closure-local constants + TDZ/declaration-order quirks, test-path assumptions (if a test imports a private helper by path, either keep a wrapper re-export or update the test in the same PR - the latter is no longer a "pure move", flag it).
- Stale line numbers: re-grep before every extraction.
- Do NOT internally split detectPassRolePaths in PR 1.

## 8. Agreement + dissent

Openclaw and Gentoo AGREE on: leaf-first ordering, the deny/partition cycle risk + a lower reachability leaf, tighter leaf modules (no junk drawer), escalation-first, re-export discipline, don't-sub-split-detectPassRolePaths-yet. No material dissent. Complementary additions: Openclaw = defer graph/action/sarif, the acyclic graph shape, role-targets leaf. Gentoo = DETECTORS-array cycle, external re-export gaps (4-file-PR reality), classifyPrincipals front-matter, buildResourceGraph mislabel, `madge --circular` in the gate, escalation-first-because-dependency-root, line-number staleness. All folded in above.

## 9. State

- Work: `wip/appsec-phase2-4-20260827` (Phases 2-5 complete + verified). Private backup: `rivassec/secure-iam-lint-wip` (remote `backup`). Public `phase-17-appsec-remediation` pristine at `f4149e5` for the curated release commit.
- After the refactor: run a final RC validation (every-file scan + teams) on the refactored tree, confirm the full suite + golden-corpus + release-gate green, then Oliver curates a commit onto phase-17 -> PR base main -> tag v1.0.0 -> Marketplace (all Oliver's manual steps).

## 10. STEP 0 VERIFIED for escalation.js (2026-08-27, grep-confirmed)

- madge available (8.0.0); BASELINE `madge --circular` on the engine = clean (24 files, 0 cycles). So the per-PR cycle gate works and any cycle introduced will be caught.
- Exact EXTERNAL re-export set the orchestrator MUST provide (grep-confirmed, complete):
  - `analyzeEscalations` (public; imported by analyze.js:16, graph.js)
  - `applyDenyToActions`, `denyResourceCoverage`, `denyActionApplies` -> land in escalation-deny.js
  - `hasNonEmptyCondition` -> escalation-conditions.js
  - `actionGrants`, `hasPolicyVariable` -> escalation-action-grants.js
  - importers: graph.js (analyzeEscalations, applyDenyToActions, denyResourceCoverage, actionGrants, hasPolicyVariable, hasNonEmptyCondition); rules.js (applyDenyToActions, denyActionApplies, hasNonEmptyCondition); trust.js (denyActionApplies, hasNonEmptyCondition); analyze.js (analyzeEscalations).
  - => the orchestrator imports these from the 3 leaf modules above and re-exports them, so rules/trust/graph/analyze import paths do NOT change (true 1-file PR). Confirms Gentoo's finding exactly.
- NOTE: `statementSid` is a FILE-LOCAL helper name duplicated across many engine modules (50 non-escalation matches) - it is NOT imported from escalation.js; do not treat those as external users. Not a good "first leaf".
- First-extraction readiness: escalation-action-grants.js (actionGrants, grantedPatternsFor, hasPolicyVariable) or escalation-catalogs.js is the cleanest PR 1a; the re-export list above is ready.
