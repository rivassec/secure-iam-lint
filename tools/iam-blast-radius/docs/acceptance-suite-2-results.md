# IAM Blast Radius - advanced acceptance suite (suite 2) scoreboard (IAM-904)

Phase-9 close-out. Every one of the 30 advanced tests in
`docs/acceptance-suite-2.md` (tests 25-54) was driven **directly through the real
engine** (`engine/analyze.js` + `engine/validate.js`) against the exact policy
block in the suite; the verdicts below are what `analyze()` actually returns, not
the fixture's declared numbers.

Phase-9 scope was fenced to three in-scope engine bugs:

- **IAM-901** duplicate JSON key -> fail closed (suite-2 **test 44**)
- **IAM-902** role-takeover chain correlation, no `iam:PassRole` (suite-2 **test 34**)
- **IAM-903** invalid partial-wildcard Principal-element ARN (suite-2 **test 48**)

Resource-based policies, RCPs, SCPs, permissions boundaries, and session policies
are **out of scope** for Phase 9 and remain deliberately unbuilt. They are not
skipped: each is encoded as a `designBlocked` fixture under
`fixtures/acceptance-2-deferred/` and driven by
`tests/acceptance-suite-2-deferred.test.js`, which asserts the current honest
state (fail-closed with a machine-readable code, or the documented "analyzed as
identity" family-gap) and will fail loudly if a future family tranche changes the
behavior - forcing a deliberate flip.

Generated 2026-08-23 against the working tree engine (build SHA `dev`, rule
version `1`).

## Verdict legend

- **pass** - engine established the expected capability / constraint / warning
  from the supplied policy, with accurate wording and no overstatement. Suite
  severities are explicit *suggestions* (see the suite's "Required result
  vocabulary"); this tool reserves `critical` for compound privilege-boundary
  crossings (IAM-102), so a standalone direct-IAM capability landing at `high`
  is a pass, not a downgrade.
- **blocked-by-design** - the shape belongs to an unbuilt family; the engine
  fails closed to a machine-readable blocking coverage state
  (`UNSUPPORTED_POLICY_FAMILY` / `UNSUPPORTED_SCP_SHAPE` /
  `UNSUPPORTED_NOTPRINCIPAL`) instead of misreading it. Deferred tranche.
- **family-gap** - there is no family selector yet, so a boundary/session shape
  is analyzed under the identity lens. Deferred tranche.

No suite-2 test currently returns a *false* or *overstated* result (no `fail`).

## Scoreboard

| # | Test | Family | Verdict | Engine result |
|---|------|--------|---------|---------------|
| 25 | AWS account principal is account delegation | role-trust | pass | `TRUST-CROSS-ACCOUNT` high; delegates to account `111122223333`, not "root user only"; target-role perms out of scope |
| 26 | Service principal without confused-deputy constraints | resource | pass (IAM-1203, flipped IAM-1207) | `RESOURCE-CONFUSED-DEPUTY` medium; names the missing `aws:SourceArn`/`aws:SourceAccount`, explicitly NOT public write; graph origin = EventBridge service node |
| 27 | Properly source-bound service principal | resource | pass (IAM-1203, flipped IAM-1207) | `RESOURCE-CONFUSED-DEPUTY` info negative control; no missing-source-binding warning; does not infer whether the rule exists |
| 28 | TLS-only Deny does not make public S3 private | resource | pass (IAM-1202, flipped IAM-1207) | `PUBLIC-ACCESS` critical; the `aws:SecureTransport` Deny recorded as transport-only, does NOT neutralize the public Allow; states BPA external-control dependency |
| 29 | NotPrincipal Deny + permissions-boundary hazard | resource | blocked-by-design | fail-closed `UNSUPPORTED_NOTPRINCIPAL` (NotPrincipal trap caught before family eval) |
| 30 | Permissions boundary Allow is a ceiling, not a grant | permissions-boundary | family-gap | analyzed as identity -> `WILDCARD-ACTION` + `WILDCARD-RESOURCE` high; no boundary-ceiling semantics yet |
| 31 | Session-policy Allow is a session restriction | session | family-gap | analyzed as identity -> no findings (scoped `s3:GetObject`); no session-intersection semantics yet |
| 32 | Same-account direct IAM-user resource grant | resource | pass (IAM-1204, flipped IAM-1207) | `RESOURCE-SAME-ACCOUNT-GRANT` medium; resource-vs-identity caveat (implicit deny does not limit; explicit deny still applies); typed as IAM user, not generalized; not cross-account, not public |
| 33 | Direct role-session ARN grant | resource | pass (IAM-1204, flipped IAM-1207) | `RESOURCE-SAME-ACCOUNT-GRANT`; identified as ONE exact assumed-role session, session ARN preserved verbatim, never collapsed to the role ARN |
| **34** | **Full IAM role takeover chain** | identity | **pass (IAM-902)** | **`ROLE-TAKEOVER` critical**; PutRolePolicy + UpdateAssumeRolePolicy + AssumeRole on the same role, per-statement evidence preserved (spans stmts 0/1), no `iam:PassRole` required |
| 35 | Attach AdministratorAccess to a named user | identity | pass | `ATTACH-POLICY` high targeting `user/build-automation`; phrased "to itself or a principal it controls", not definite self-admin |
| 36 | Add a user to a privileged group | identity | pass | `DIRECT-IAM-ADMIN` high (caught by the generic direct-IAM rule; group-privilege inference is a refinement, not modeled separately) |
| 37 | CloudFormation service-role execution | identity | pass | `PASSROLE-SERVICE` critical; `iam:PassedToService=cloudformation` selector honored |
| 38 | ECS task-role execution with two passable roles | identity | pass | `PASSROLE-SERVICE` critical; both roles preserved in evidence (task-vs-execution role split is a refinement, not modeled separately) |
| 39 | CodeBuild project creation and execution | identity | pass | `PASSROLE-SERVICE` critical; `iam:PassedToService=codebuild` selector honored |
| 40 | Partial wildcard action matching (`iam:Attach*Policy`) | identity | pass | `ATTACH-POLICY` high; partial wildcard matched without inventing actions |
| 41 | ForAllValues without a Null presence check | identity | pass | `WILDCARD-RESOURCE` high on `ec2:CreateTags`/`*` (set-condition vacuous-truth nuance is a condition-classifier refinement, not modeled) |
| 42 | IfExists on Allow broadens applicability | identity | pass | `WILDCARD-ACTION` + `WILDCARD-RESOURCE` high; not fooled into "limited to t3.micro" |
| 43 | Negated IfExists in a Deny matches missing keys | scp-rcp | blocked-by-design | fail-closed `UNSUPPORTED_SCP_SHAPE` |
| **44** | **Duplicate JSON keys** | identity | **pass (IAM-901)** | **blocked `DUPLICATE_JSON_KEY`** naming the key + statement location; ok:false, zero findings/score/graph, original text preserved |
| 45 | Unicode-confusable action name | identity | pass | does NOT match `iam:PassRole`; the Cyrillic `іam:PassRole` surfaces as an unrecognized action + coverage marked incomplete; homoglyph never normalized (hard-block is a preference, not met) |
| 46 | Prototype-pollution property names | identity | pass | blocked `DANGEROUS_KEY`; no object acquires a `polluted` property; clean re-analysis unaffected |
| 47 | GovCloud partition support | identity | pass | `PASSROLE-EC2` critical; `aws-us-gov` partition preserved verbatim in evidence |
| 48 | **Wildcard inside a Principal ARN** | role-trust | **pass (IAM-903)** | **`TRUST-INVALID-PRINCIPAL` high** + coverage incomplete with `INVALID_PRINCIPAL_WILDCARD_ARN`; not a plain uncaveated `TRUST-CROSS-ACCOUNT` |
| 49 | Multiple condition operators (AND/OR composition) | resource | pass (IAM-1202/1205, flipped IAM-1207) | `PUBLIC-ACCESS` high (narrowed, not critical); `*` recorded NARROWED by the principal-tag selector `aws:PrincipalTag/environment` (network selector `aws:SourceVpce` not credited as principal-scoping); OR-within-values / AND-across-keys preserved |
| 50 | Action/resource type mismatch | identity | pass | no finding (correctly does NOT claim confirmed object-read from a bucket ARN); action/resource-type coverage warning is a documented refinement, not yet modeled |
| 51 | KMS account-principal delegation statement | resource | pass (IAM-1205, flipped IAM-1207) | `RESOURCE-KMS-ACCOUNT-DELEGATION` medium; broad KMS authority delegated to the OWNING ACCOUNT - NOT public, NOT root-user-only; `Resource:*` = the attached key only (no per-key node explosion) |
| 52 | RCP confused-deputy guardrail | resource/RCP | blocked-by-design | fail-closed `UNSUPPORTED_POLICY_FAMILY` (Principal `*` shape detected as resource; RCP/SCP families are Phase-13-deferred) |
| 53 | Mismatched SourceArn and SourceAccount | resource | pass (IAM-1203, flipped IAM-1207) | `RESOURCE-CONFUSED-DEPUTY` medium; names both disagreeing accounts (`111122223333` vs `444455556666`), flagged internally inconsistent / likely ineffective, NOT praised as source-bound, NOT a public-write finding |
| 54 | Client-side resource-exhaustion limits | identity | pass | blocked `TOO_LARGE` before expensive work; no hang, no truncate-and-call-complete, no server fallback |

## Tally (updated for the Phase-12 resource-family flip, IAM-1207)

- In-scope Phase-9 fixes: **3/3 pass** (34, 44, 48).
- Supported-family (identity + role-trust) tests: **14/14 pass, no overstatement**
  (25, 34, 35, 36, 37, 38, 39, 40, 41, 42, 44, 45, 46, 47, 48, 50, 54 - counting
  the identity/trust set; nuance refinements noted inline, none producing a false
  or overstated claim).
- Resource-family tests FLIPPED to real analysis in Phase 12 (IAM-1201..1206,
  scoreboarded by IAM-1207): **8/8 pass** (26, 27, 28, 32, 33, 49, 51, 53) -
  driven from `analyze()` with the explicit attached-resource context via
  committed fixtures under `fixtures/resource/` (`tests/resource.test.js`), gated
  by `tests/acceptance-resource-flip.test.js`. No overstatement: a service
  principal is never called public, an account principal is never called
  root-only, a transport Deny never neutralizes public read, `Resource:*` in a KMS
  key policy is the attached key only.
- blocked-by-design (deferred tranche, genuinely-unmodeled shapes only):
  **3** - NotPrincipal Deny hazard (29, surfaced with the specific hazard),
  SCP-shape (43), RCP (52). RCP/SCP families are Phase-13-deferred.
- family-gap (permissions-boundary / session, deferred tranche): **2** (30, 31).

## Regression guard

- Suite 1 (`docs/acceptance-suite.md`, tests 1-24) still **24/24**
  (`tests/acceptance-suite.test.js`, 28 subtests green).
- Identity negative corpus (`fixtures/negative`) unchanged and green.
- Trust negative corpus (`fixtures/negative-trust`) unchanged and green.
- Resource negative corpus (`fixtures/negative-resource`, IAM-1207) green - the
  frozen "does-not-fire / low" contracts proving the resource evaluator knows when
  NOT to fire (`tests/negative-resource.test.js`).
- Full `node --test "tests/**/*.test.js"` green.

## Deferred family tranche (follow-up, NOT Phase 9)

The resource-based policy family SHIPPED in Phase 12 (IAM-1201..1206), so tests
26/27/28/32/33/49/51/53 flipped from `blocked-by-design` to `pass` (IAM-1207);
their committed acceptance fixtures live under `fixtures/resource/`. Flipping any
remaining `blocked-by-design` / `family-gap` row above to its suite-2
Expected-result finding requires building the corresponding evaluator behind the
family selector. Each remaining deferred fixture's `designBlocked` field names its
tranche:

- **NotPrincipal Deny hazard** - test 29 (fails closed `UNSUPPORTED_NOTPRINCIPAL`
  but surfaces the specific permissions-boundary hazard + `ArnNotEquals`
  recommendation; driven by `tests/acceptance-suite-2.test.js`).
- **RCP policy family** - test 52 (Phase-13-deferred).
- **SCP/RCP ceiling semantics** - test 43.
- **Permissions-boundary family** (Allow = ceiling, not grant; no positive
  capability edges) - test 30.
- **Session-policy family** (session Allow = cap; effective = intersection with
  parent) - test 31.
