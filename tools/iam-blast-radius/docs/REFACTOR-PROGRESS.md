# Refactor progress ledger (overnight 2026-08-27 -> 28)

## STATUS @ 90fd589 (2026-08-27 ~23:45) -- autonomous run paused for supervised handoff

Tree GREEN: suite 2778 pass / 0 fail / 0 todo, release-gate 16/16, madge 0 cycles. wip @ 90fd589 pushed to backup (rivassec/secure-iam-lint-wip).

KEY FINDING (the whole overnight unlock): the earlier "coupled cores" (pins 50-fail, role-coverage 962-fail, rules-catalogs 3-fail) were NEVER deep coupling. The tests import engine internals DIRECTLY from each engine file; moving a symbol out without re-exporting it broke those test imports. FIX = add `export * from './<newmod>.js';` to the orchestrator after every extraction. Proven on 3 previously-"impossible" data modules this session.

CLEAN DATA MODULES extracted this session (all export-* , all gated green + committed + pushed):
- trust-catalogs.js       (131 LOC)  trust.js   1853 -> 1727   -- bc364f3
- rules-catalog.js        (127 LOC)  rules.js   2002 -> 1880   -- 334791b
- resource-catalogs.js    (222 LOC)  resource.js 2977 -> 2760  -- 90fd589
(earlier session, escalation.js 3016 -> 2545: action-grants/catalogs/scope/statement/conditions leaves.)

WHAT REMAINS = SUPERVISED, not autonomous. The remaining size is in FUNCTION bodies, and mechanical extraction of function clusters hits real architectural decisions that need Oliver's call:
1. parseArn OWNERSHIP: source-binding (and much of resource.js) calls parseArn, which is defined in resource.js AND duplicated in resource-arn.js:175 (two copies, imported by rules.js+analyze.js). A functional split needs parseArn moved to ONE canonical leaf FIRST, then everyone imports it. Deciding the canonical home + de-duping is an architecture call. (source-binding extraction was attempted + cleanly rolled back for exactly this reason.)
2. pins/role-coverage/role-targets CYCLE: rolePathIsWildcardEquivalent (coverage) -> parsePassResource (targets) -> accountReaches/partitionReaches (coverage) is a genuine mutual dependency. export-* fixes the test-import half, but the cycle itself needs these co-located in ONE reachability module (or an interface seam). Needs supervised design.
3. Giant single functions (resourceFindings ~760 LOC, detectPassRolePaths) cannot be split by moving - they need real decomposition (judgment on seams), which is the separate in-repo REFACTOR-PLAN sub-split work.

RECOMMENDED NEXT (supervised session): (a) extract a canonical arn-util leaf (parseArn/serviceForArn/parseResourceContext) + de-dupe resource-arn.js, then the resource conditions/source-binding/service-rule clusters fall out cleanly with export-*; (b) co-locate the escalation reachability trio into one module to break the cycle; (c) decompose the two giant functions per the in-repo plan. Each still gated by the per-extraction protocol below. v1.0.0 tag gate (refactored AND green) NOT yet met - files still 1727-2760 LOC.

## AGREED DECISIONS (2026-08-28, owner + Openclaw) + progress
- D1 parseArn: NEW leaf arn-util.js (DONE). The two parseArn copies are NOT dupes (drifted: .resource vs .resourceId, empty-seg handling) -> de-dup is OUT of v1.0.0; tracked in docs/POST-V1-ISSUES.md.
- D2 escalation cycle: co-locate pins+role-targets+role-coverage into ONE escalation-reachability.js (SCC module), no interface seam.
- D3 giant fns: LEAVE resourceFindings/detectPassRolePaths intact for v1.0.0 (file-level manageable only). Owner: file-level scope.
- [x] arn-util.js (parseArn/serviceForArn/parseResourceContext, imports 3 catalogs, export *) resource.js 2760->2610
- [x] resource-source-binding.js (7 syms, imports parseArn+parseOperator/NEGATED_OPERATORS+chargeWork, export *) resource.js 2610->2445
- [ ] resource-conditions (scoping/selector/inventory helpers), resource-service-rules (s3/kms/sns-sqs)
- [ ] escalation-reachability.js (SCC: pins+role-targets+role-coverage together)

## Autonomous state machine (original)

State machine for the autonomous refactor. Each tick: do the NEXT unchecked item per REFACTOR-PLAN.md, gate, commit, push backup, check it off. On a stall: roll back the failed extraction (`git checkout -- <touched>`), mark the current file PARTIAL at its last green module, and SKIP to the next FILE (Oliver's directive). Hold public push / PR / tag.

ROOT CAUSE of the earlier defers (SOLVED): TESTS import engine internals directly from the file (step-0 grep must include tools/iam-blast-radius/tests). FIX: after every extraction add `export * from './<newmod>.js';` to the orchestrator - preserves ALL exports for tests + external importers. This makes the previously-deferred pins/role-coverage/rules-catalogs extractable too (re-attempt them).

Per-extraction protocol (MANDATORY every time): (1) re-grep exact CURRENT line numbers of the target functions - they DRIFT after every edit, never trust stale numbers; (2) Write the new leaf module (import only what it needs; export every symbol used outside it); (3) Edit the orchestrator: add `import {...} from './<new>.js'` + re-export the EXTERNALLY-imported names, remove the moved block; (4) GATE - `npx madge --circular content/tools/iam-blast-radius/engine` = 0 cycles AND `cd tools/iam-blast-radius && node --test 'tests/**/*.test.js' 'audit/**/*.test.js'` = 2778 pass/0 fail/0 todo (count must not drop) AND `GOLDEN_RELEASE_GATE=1 node --test audit/golden-corpus/release-gate.test.js` 16/16 AND `node audit/lint/lint.mjs` no NEW class; (5) green -> `git add -A && git commit -m "refactor(<file>): extract <module> (pure move)"` + `GIT_SSH_COMMAND='ssh -i ~/.ssh/git_rivassec -o IdentitiesOnly=yes' git push backup wip/appsec-phase2-4-20260827` + check the box; red -> 1 fix attempt, else roll back + skip to next FILE.

## FILE 1: escalation.js -- PARTIAL (5 clean leaves extracted: action-grants/catalogs/scope/statement/conditions; 3016->2399... currently 2545 LOC. The coupled detector/partition/pins region (principal-pins, role-coverage, role-targets, passrole, families, takeover, finding, deny) resisted mechanical extraction - 2 catastrophic full-suite regressions (pins 50-fail, role-coverage 962-fail) despite madge/node-c clean => shared load-order/state coupling. NEEDS A SUPERVISED PASS, not overnight-autonomous. Moving to FILE 2.)
- [x] escalation-action-grants.js (actionGrants, hasPolicyVariable, grantedPatternsFor) -- 47b9955
- [x] escalation-catalogs.js (classifyEcsRole, ecsRoleClasses, ESCALATIONS, ESCALATION_IDS, catalog consts, deepFreeze)
- [x] escalation-scope.js (resourceScope, isStarResource, grantTokenIsBroad, resourceListIsBroadForAssume, assumeScopeIsAllRoles, assumeAccountReach)
- [x] escalation-statement.js (statementSid)
- [x] escalation-conditions.js (5 clean helpers; constraintContains+keyConstraintsSatisfiable moved to principal-pins to avoid a cycle) (passedToServiceEntries, normalizeOperator, operatorPermitsService, passRolePermitsService, hasNonEmptyCondition, constraintContains, keyConstraintsSatisfiable)
- [~] escalation-principal-pins.js DEFERRED (extraction broke 50 tests in the full-suite run w/ 0 madge cycles - likely a load-order/shared-state coupling; needs careful manual handling, left in escalation.js) (principalPinsOf, principalPinsOfMemo, pinsJointlySatisfiable, principalConditionsSatisfiable, constraintContains, keyConstraintsSatisfiable) -- memo is a PARAM, safe
- [ ] escalation-role-targets.js (parsePassResource, concreteRoleTargetAccount, isConcreteRoleArn, resourceCoversRole, isAllRolesAssumeScope, specificAccountsInRoleArns)
- [ ] escalation-role-coverage.js (partitionReaches, accountReaches, resourceReachesSubject, subjectRoleArnPrefix, globCanProducePrefix, rolePathIsWildcardEquivalent, partitionModelable, subjectPartitionKnown, accountModelable, otherResourceIsUnmodelable, isUnmodelablePassResource, isConfidentPinnedResource) -- CYCLE FIX: deny + passrole/partition both import this
- [ ] escalation-finding.js (makeEscalation, downgrade, evidenceOf, contributingStatementsFrom, prereqGroup, prereqTechnique, prerequisitesOf, survivingGrantedActions)
- [ ] escalation-deny.js (denyActionApplies, denyResourcesCover, denyResourceCoverage, denyEffectOnAction, applyDenyToActions, denyResourceRemovesAllSubjectRoles, denyRemovesAllSubjectRoles) -- imports role-coverage, NOT partition
- [ ] escalation-passrole.js (detectPassRolePaths + passStmtViabilityTier, execResourceBroadness, execTechniqueSeverity) -- do NOT internally sub-split detectPassRolePaths in this PR
- [ ] escalation-families.js (detectPolicyVersion/AttachPolicy/PutInlinePolicy/TrustModify/CredentialCreation/AssumeRoleExpansion/CrossAccountScopedAssume + role-ARN helpers not already moved)
- [ ] escalation-takeover.js (detectRoleTakeover)
- [ ] escalation.js orchestrator: DETECTORS array (~:2999) MOVES here + build from imports; keep analyzeEscalations/analyzeEscalationsFromText + all re-exports. VERIFY final escalation.js < ~400 LOC.

## FILE 2: rules.js (after escalation) - run step-0 grep first
- [x] rules-catalog.js (RULES + RULE_IDS pure data, export *) -- the earlier "3 subtle fails" were just tests importing RULES from rules.js; export * fixed it / rules-finding-factory.js / rules-deny-precedence.js / rules-eval-*.js (see REFACTOR-PLAN.md sec 6)

## FILE 3: trust.js - run step-0 grep first
- [x] trust-catalogs.js (pure-const, export *) -- FIRST trust module
- [ ] trust-principals.js (classifyPrincipals + front-matter, imported by resource.js) / trust-conditions.js / trust-findings.js / trust-deny.js

## FILE 4: resource.js - run step-0 grep first
- [x] resource-catalogs.js (RESOURCE_CODES/SERVICES/IDS/LABELS + DOC_* strings, 20 syms, export *) -- 45-272, 222 LOC out
- [ ] resource-principals.js (lines 1-520 + 1935-1963 gap) / resource-conditions.js / resource-s3-typing.js / resource-service-rules/{s3-bucket-policy,kms-key-policy,sns-sqs}.js

## AFTER all files: final RC validation (every-file scan + release-gate + suite) on the refactored tree, then present a resumable morning summary. HOLD public push/PR/tag.
