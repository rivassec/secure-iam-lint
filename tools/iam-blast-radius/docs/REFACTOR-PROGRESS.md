# Refactor progress ledger (overnight 2026-08-27 -> 28)

State machine for the autonomous refactor. Each tick: do the NEXT unchecked item per REFACTOR-PLAN.md, gate, commit, push backup, check it off. On a stall: roll back the failed extraction (`git checkout -- <touched>`), mark the current file PARTIAL at its last green module, and SKIP to the next FILE (Oliver's directive). Hold public push / PR / tag.

Per-extraction protocol (MANDATORY every time): (1) re-grep exact CURRENT line numbers of the target functions - they DRIFT after every edit, never trust stale numbers; (2) Write the new leaf module (import only what it needs; export every symbol used outside it); (3) Edit the orchestrator: add `import {...} from './<new>.js'` + re-export the EXTERNALLY-imported names, remove the moved block; (4) GATE - `npx madge --circular content/tools/iam-blast-radius/engine` = 0 cycles AND `cd tools/iam-blast-radius && node --test 'tests/**/*.test.js' 'audit/**/*.test.js'` = 2778 pass/0 fail/0 todo (count must not drop) AND `GOLDEN_RELEASE_GATE=1 node --test audit/golden-corpus/release-gate.test.js` 16/16 AND `node audit/lint/lint.mjs` no NEW class; (5) green -> `git add -A && git commit -m "refactor(<file>): extract <module> (pure move)"` + `GIT_SSH_COMMAND='ssh -i ~/.ssh/git_rivassec -o IdentitiesOnly=yes' git push backup wip/appsec-phase2-4-20260827` + check the box; red -> 1 fix attempt, else roll back + skip to next FILE.

## FILE 1: escalation.js (dependency root - do FIRST)
- [x] escalation-action-grants.js (actionGrants, hasPolicyVariable, grantedPatternsFor) -- 47b9955
- [x] escalation-catalogs.js (classifyEcsRole, ecsRoleClasses, ESCALATIONS, ESCALATION_IDS, catalog consts, deepFreeze)
- [ ] escalation-scope.js (resourceScope, isStarResource, grantTokenIsBroad, resourceListIsBroadForAssume, assumeScopeIsAllRoles, assumeAccountReach)
- [ ] escalation-statement.js (statementSid)
- [ ] escalation-conditions.js (passedToServiceEntries, normalizeOperator, operatorPermitsService, passRolePermitsService, hasNonEmptyCondition, constraintContains, keyConstraintsSatisfiable)
- [ ] escalation-principal-pins.js (principalPinsOf, principalPinsOfMemo, pinsJointlySatisfiable, principalConditionsSatisfiable) -- memo is a PARAM, safe
- [ ] escalation-role-targets.js (parsePassResource, concreteRoleTargetAccount, isConcreteRoleArn, resourceCoversRole, isAllRolesAssumeScope, specificAccountsInRoleArns)
- [ ] escalation-role-coverage.js (partitionReaches, accountReaches, resourceReachesSubject, subjectRoleArnPrefix, globCanProducePrefix, rolePathIsWildcardEquivalent, partitionModelable, subjectPartitionKnown, accountModelable, otherResourceIsUnmodelable, isUnmodelablePassResource, isConfidentPinnedResource) -- CYCLE FIX: deny + passrole/partition both import this
- [ ] escalation-finding.js (makeEscalation, downgrade, evidenceOf, contributingStatementsFrom, prereqGroup, prereqTechnique, prerequisitesOf, survivingGrantedActions)
- [ ] escalation-deny.js (denyActionApplies, denyResourcesCover, denyResourceCoverage, denyEffectOnAction, applyDenyToActions, denyResourceRemovesAllSubjectRoles, denyRemovesAllSubjectRoles) -- imports role-coverage, NOT partition
- [ ] escalation-passrole.js (detectPassRolePaths + passStmtViabilityTier, execResourceBroadness, execTechniqueSeverity) -- do NOT internally sub-split detectPassRolePaths in this PR
- [ ] escalation-families.js (detectPolicyVersion/AttachPolicy/PutInlinePolicy/TrustModify/CredentialCreation/AssumeRoleExpansion/CrossAccountScopedAssume + role-ARN helpers not already moved)
- [ ] escalation-takeover.js (detectRoleTakeover)
- [ ] escalation.js orchestrator: DETECTORS array (~:2999) MOVES here + build from imports; keep analyzeEscalations/analyzeEscalationsFromText + all re-exports. VERIFY final escalation.js < ~400 LOC.

## FILE 2: rules.js (after escalation) - run step-0 grep first
- [ ] rules-catalogs.js / rules-finding-factory.js / rules-deny-precedence.js / rules-eval-*.js (see REFACTOR-PLAN.md sec 6)

## FILE 3: trust.js - run step-0 grep first
- [ ] trust-principals.js (classifyPrincipals + front-matter, imported by resource.js) / trust-conditions.js / trust-findings.js / trust-deny.js

## FILE 4: resource.js - run step-0 grep first
- [ ] resource-principals.js (lines 1-520 + 1935-1963 gap) / resource-conditions.js / resource-s3-typing.js / resource-service-rules/{s3-bucket-policy,kms-key-policy,sns-sqs}.js

## AFTER all files: final RC validation (every-file scan + release-gate + suite) on the refactored tree, then present a resumable morning summary. HOLD public push/PR/tag.
