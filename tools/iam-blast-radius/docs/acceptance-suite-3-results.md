# IAM Blast Radius - regression and gap-hunting suite (suite 3) scoreboard (IAM-1008)

Phase-10 capstone. Every one of the 46 tests in `docs/acceptance-suite-3.md`
(tests 55-100, campaigns A-F) is accounted for with **no silent skips**. Each
test is either fixture-backed and driven **directly through the real engine**
(`engine/analyze.js` + `engine/validate.js`), or a documented procedure/UI-only
case whose covering test file(s) are named and asserted to exist.

The completeness gate + verdict driver is
`tests/acceptance-suite-3-results.test.js`: it enumerates 55-100, asserts each is
covered exactly once, and for every fixture-backed case asserts the verdict it
declares below equals the verdict `analyze()` actually derives (so this
scoreboard cannot drift from real engine behavior). Deep per-test semantics stay
enforced by the dedicated harnesses (`acceptance-suite-3-fixtures.test.js`,
`phase10-parser-hardening.test.js`, `phase10-family-selection.test.js`,
`phase10-envelope.test.js`, `phase10-iam-ecs.test.js`, `acceptance-suite-3.test.js`).

Generated against the working-tree engine (build SHA `dev`, rule version `1`,
action catalog `2026.08.22`).

## Verdict legend (docs/acceptance-suite-3.md "Result states")

- **COMPLETE** - supported semantics fully evaluated; no overstatement.
- **COMPLETE_WITH_WARNINGS** - findings usable, with a bounded non-blocking
  coverage limitation (an unmodelled/context-required condition, an invalid
  principal member flagged rather than dropped, a duplicate-Sid warning).
- **BLOCKED** - input, family, or unsupported semantics can materially change the
  conclusion; the engine fails closed (validation error, or a machine-readable
  blocking coverage state) and presents no findings/score/graph as complete.
- **procedure** - not a single-policy engine assertion (paste/import parity, UI
  state invalidation, export-surface parity, generated limit sweeps); covered by
  the named unit/Playwright test file(s), never silently skipped.

No suite-3 test currently returns a false or overstated result.

## Coverage summary

- Fixture-backed, driven through analyze()/validate(): **40** tests.
- Procedure / UI-only, documented with covering file(s): **6** tests
  (63, 70, 71, 79, 98, 100).
- Campaign A 55-63, B 64-71, C 72-80, D 81-85, E 86-91, F 92-100: all pass per
  the suite-3 release gate.

## Campaign A - strict parser and import equivalence

| # | Test | Verdict | Engine result |
|---|------|---------|---------------|
| 55 | Duplicate Action, dangerous value first | BLOCKED | `DUPLICATE_JSON_KEY` at `Statement[0].Action`; no S3/IAM finding |
| 56 | Duplicate Action, dangerous value last | BLOCKED | `DUPLICATE_JSON_KEY` at `Statement[0].Action`; order-independent |
| 57 | Escaped `Action` decodes to Action | BLOCKED | `DUPLICATE_JSON_KEY` after escape decode; not a raw-span compare |
| 58 | Duplicate nested Condition key | BLOCKED | `DUPLICATE_JSON_KEY` at `Statement[0].Condition.StringEquals.aws:PrincipalOrgID` |
| 59 | Condition keys differ only in case | BLOCKED | `DUPLICATE_JSON_KEY`; case-insensitive key collision, both spellings preserved |
| 60 | Duplicate Sids | COMPLETE | valid JSON; `DUPLICATE_SID` coverage flag raised; statement indexes stay distinct; `WILDCARD-RESOURCE` on the 2nd statement |
| 61 | JSONC comments + trailing commas | BLOCKED | `INVALID_JSON`; never silently repaired |
| 62 | UTF-8 BOM | COMPLETE | exactly one leading BOM stripped, then parses; embedded U+FEFF preserved |
| 63 | Paste / import / parser parity | procedure | `tests/phase10-parser-hardening.test.js` + `tests/e2e/parser-hardening.spec.js`: identical result across ingestion paths; filename has no semantic effect |

## Campaign B - required policy-family selection

| # | Test | Verdict | Engine result |
|---|------|---------|---------------|
| 64 | No family selected | BLOCKED | `POLICY_FAMILY_REQUIRED`; `detected=unknown`, never a shape-based identity default |
| 65 | Boundary selected (Allow-heavy) | COMPLETE | `PERMISSIONS-BOUNDARY-ENVELOPE` (envelope/ceiling); no `can-read`/`can-write`/`can-delete` capability edge |
| 66 | Session policy selected | COMPLETE | `SESSION-CEILING` (info); session restriction, no positive capability edge without parent context |
| 67 | Identity mode rejects Principal | BLOCKED | `UNSUPPORTED_PRINCIPAL` at `Statement[0].Principal`; Principal never dropped |
| 68 | Trust mode rejects Resource | BLOCKED | `UNSUPPORTED_TRUST_RESOURCE` at `Statement[0].Resource` |
| 69 | Resource policy selected (deferred) | BLOCKED | `UNSUPPORTED_POLICY_FAMILY` naming the family; input preserved |
| 70 | Family switching clears prior analysis | procedure | `tests/phase10-family-selection.test.js` + `tests/e2e/ui-shell.spec.js`: same bytes under two families differ; prior state invalidated |
| 71 | Family + status survive every export | procedure | `tests/phase10-family-selection.test.js`: selected family + status + catalog version + warnings in JSON/MD; statuses agree; blocked export never authoritative |

## Campaign C - IAM role-takeover correlation

| # | Test | Verdict | Engine result |
|---|------|---------|---------------|
| 72 | Exact same-role takeover | COMPLETE | one critical `ROLE-TAKEOVER`; `PUT-INLINE-POLICY`+`TRUST-POLICY-MODIFY` subsumed with evidence preserved; no `iam:PassRole` needed |
| 73 | Different target roles must not correlate | COMPLETE | no compound path; separate modify + assume capabilities remain |
| 74 | Wildcard modifier overlaps exact assumable role | COMPLETE | `ROLE-TAKEOVER` anchored on concrete `deployment/Prod`, not generalized to `deployment/*` |
| 75 | Mutually exclusive conditions prevent correlation | COMPLETE | no compound path (same-key `aws:PrincipalAccount` pins unsatisfiable); both condition expressions preserved |
| 76 | Exact Deny removes one prerequisite | COMPLETE | no full takeover; residual `PUT-INLINE-POLICY` kept; suppressed critical not counted |
| 77 | AttachRolePolicy alternative to PutRolePolicy | COMPLETE_WITH_WARNINGS | critical `ROLE-TAKEOVER` via policy attachment; `iam:PolicyARN` evidence preserved; condition context-required (incomplete) |
| 78 | Role modification without AssumeRole | COMPLETE | high role-control/persistence; no self-assumption path |
| 79 | Cross-statement evidence integrity | procedure | `tests/acceptance-suite-3-fixtures.test.js` (test-72 evidence block): modify actions map to stmt 0, `sts:AssumeRole` to stmt 1; no synthetic statement |
| 80 | Duplicate permission statements do not duplicate paths | COMPLETE | one `ROLE-TAKEOVER`; both equivalent modify statements available as evidence; no duplicate graph edge |

## Campaign D - principal validation

| # | Test | Verdict | Engine result |
|---|------|---------|---------------|
| 81 | Asterisk inside role Principal ARN | COMPLETE_WITH_WARNINGS | `TRUST-INVALID-PRINCIPAL` at `Statement[0].Principal.AWS[0]`; `INVALID_PRINCIPAL_WILDCARD_ARN`; never expanded to a trust edge |
| 82 | Question-mark wildcard inside user Principal ARN | COMPLETE_WITH_WARNINGS | `TRUST-INVALID-PRINCIPAL`; validation covers `?` as well as `*` |
| 83 | One invalid member poisons a Principal array | COMPLETE_WITH_WARNINGS | invalid member flagged at array index 1 (`TRUST-INVALID-PRINCIPAL`), valid member not silently dropped |
| 84 | Short-form account principal remains valid | COMPLETE | `TRUST-CROSS-ACCOUNT`; 12-digit account id not misclassified as an invalid ARN |
| 85 | Principal `*` narrowed by PrincipalArn condition | BLOCKED | resource-policy family deferred -> fail closed `UNSUPPORTED_POLICY_FAMILY`; the condition-value wildcard is not mis-flagged as an invalid Principal |

## Campaign E - IAM and ECS semantic precision

| # | Test | Verdict | Engine result |
|---|------|---------|---------------|
| 86 | AddUserToGroup targets group membership | COMPLETE | `GROUP-MEMBERSHIP` (not AttachUserPolicy/PutUserPolicy); user selected in request, group is the resource |
| 87 | ECS task role and execution role are separate nodes | COMPLETE | critical `PASSROLE-SERVICE`; task role and execution role kept distinct |
| 88 | Only execution role is passable | COMPLETE | `PASSROLE-SERVICE`; execution-role influence only, not application credentials |
| 89 | Only task role is passable | COMPLETE | `PASSROLE-SERVICE` task-role execution path; target perms unknown |
| 90 | RegisterTaskDefinition without RunTask | COMPLETE | `PASSROLE-SERVICE` staging capability; no confirmed launch (RunTask absent) |
| 91 | Cross-account PassRole target | COMPLETE | `PASSROLE-EC2` with the same-account-service caveat; foreign-account role path not asserted as fully viable |

## Campaign F - false-positive control, state isolation, rendering safety, limits

| # | Test | Verdict | Engine result |
|---|------|---------|---------------|
| 92 | iam:ListRoles legitimately requires Resource `*` | COMPLETE | no `WILDCARD-RESOURCE`; required wildcard, no impossible remediation |
| 93 | ec2:DescribeInstances legitimately uses Resource `*` | COMPLETE | no broad-write edge, no remediable wildcard finding |
| 94 | s3:ListAllMyBuckets legitimately uses Resource `*` | COMPLETE | account-level enumeration; not object-read/exfil/destructive |
| 95 | Mixed actions require per-action resource evaluation | COMPLETE | `WILDCARD-RESOURCE` lists only `iam:PassRole`; `iam:ListRoles` excluded from remediable finding |
| 96 | ForAllValues with explicit Null protection | COMPLETE_WITH_WARNINGS | `WILDCARD-RESOURCE` on CreateTags; vacuous-truth warning suppressed vs test 41 (Null presence check); `aws:TagKeys` context-required (incomplete) |
| 97 | Empty ForAnyValue never matches | COMPLETE_WITH_WARNINGS | no phantom capability / wildcard finding; unmatchable statement noted (incomplete) |
| 98 | Dangerous-to-safe state isolation | procedure | `tests/phase10-parser-hardening.test.js` + `tests/e2e/ui-shell.spec.js`: re-analysis fully replaces prior state; no stale critical resurrected |
| 99 | Rendering and export injection | COMPLETE | firing policy; hostile Sid/ARN render inert (safe DOM), Markdown neutralizes active links/HTML, JSON round-trips verbatim |
| 100 | Exact limits, determinism, early-abort ordering | procedure | `tests/phase10-parser-hardening.test.js`: byte-cap precedes JSON parse; statement-count boundary (limit accepted, limit+1 `TOO_LARGE`); deterministic |

## Release gate (docs/acceptance-suite-3.md)

1. Duplicate-key variants fail before normal parsing regardless of order, depth,
   escape spelling, or ingestion path - **met** (55-59, 61, 63).
2. Family selection is mandatory, exported, state-safe, semantically
   authoritative - **met** (64-71).
3. Role-takeover correlation requires compatible actions, overlapping role scope,
   simultaneously satisfiable conditions, unsuppressed permissions - **met**
   (72-80).
4. Partial Principal wildcards rejected across strings and arrays without
   rejecting valid account principals or condition patterns - **met** (81-85).
5. ECS task and execution roles remain distinct - **met** (87-89).
6. Required wildcard resources do not generate impossible remediation - **met**
   (92-95).
7. Every UI/export surface preserves source evidence and safely renders
   attacker-controlled strings - **met** (99, plus 71 export parity).
8. Limit behavior is deterministic, early, no partial-success ambiguity - **met**
   (100, 54).

## Deferred (honest fail-closed, next tranche)

Full resource-policy analysis (S3 / SNS / KMS bucket-, topic-, key-policies) and
RCP analysis remain deliberately unbuilt. In suite 3, test 85 (resource-policy
Principal `*` + PrincipalArn condition) fails closed with
`UNSUPPORTED_POLICY_FAMILY` rather than manufacturing a public-access result. The
matching suite-2 resource-policy/RCP set (26/27/28/32/33/49/51/52/53) stays
BLOCKED with `designBlocked` markers under `fixtures/acceptance-2-deferred/`,
driven by `tests/acceptance-suite-2-deferred.test.js`, so a future
resource-policy-family tranche must flip them deliberately.
