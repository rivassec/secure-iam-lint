# IAM Blast Radius - resource-policy family scoreboard (Phase 12, IAM-1207)

The resource-based policy family shipped in Phase 12 (IAM-1201..1206). This
scoreboard records the resource-family acceptance tests that FLIPPED from
fail-closed (deferred `UNSUPPORTED_POLICY_FAMILY`) to real resource analysis, plus
the resource NEGATIVE corpus that proves the evaluator knows when NOT to fire.

Every resource finding is analyzed from the RESOURCE's perspective (who may act on
THIS attached resource) and carries the potential-blast-radius-NOT-effective-access
caveat (threat-model T8; `docs/resource-policy-semantics.md` sec 0/10.2). The
attached-resource context (type + ARN) is EXPLICIT and required; a missing context
fails closed (`RESOURCE_CONTEXT_REQUIRED`), and a valid ARN for an unmodeled
service fails closed (`UNSUPPORTED_RESOURCE_SHAPE`). "Unsupported != safe":
accepted resource analysis stays INCOMPLETE (`RESOURCE_ANALYSIS_INCOMPLETE`).

Generated against the working-tree engine (build SHA `dev`, rule version `1`).

## Flipped acceptance tests (fail-closed -> real resource analysis)

Driven from `analyze()` with the explicit attached-resource context. Committed
fixtures live under `fixtures/resource/`; each is asserted in detail by
`tests/resource.test.js` and gated as a set by
`tests/acceptance-resource-flip.test.js`.

| Suite | # | Test | Resource context | Verdict | Engine result |
|-------|---|------|------------------|---------|---------------|
| 2 | 26 | Service principal without confused-deputy constraints | SNS topic | pass | `RESOURCE-CONFUSED-DEPUTY` medium; missing `aws:SourceArn`/`aws:SourceAccount` named; NOT public write; origin = EventBridge service node |
| 2 | 27 | Properly source-bound service principal | SNS topic | pass | `RESOURCE-CONFUSED-DEPUTY` info negative control; no missing-binding warning; does not infer whether the rule exists |
| 2 | 28 | TLS-only Deny does not make public S3 private | S3 object | pass | `PUBLIC-ACCESS` critical; `aws:SecureTransport` Deny recorded transport-only, does NOT neutralize the public Allow; BPA dependency stated |
| 2 | 32 | Same-account direct IAM-user resource grant | S3 bucket (owner acct) | pass | `RESOURCE-SAME-ACCOUNT-GRANT` medium; resource-vs-identity caveat; typed as IAM user; not cross-account, not public |
| 2 | 33 | Direct role-session ARN grant | S3 object (owner acct) | pass | `RESOURCE-SAME-ACCOUNT-GRANT`; ONE exact assumed-role session, ARN preserved, never collapsed to the role ARN |
| 2 | 49 | Multiple condition operators (AND/OR composition) | S3 object | pass | `PUBLIC-ACCESS` high (narrowed, not critical); `*` NARROWED by `aws:PrincipalTag/environment`; network selector not credited as principal-scoping; OR-within-values / AND-across-keys preserved |
| 2 | 51 | KMS account-principal delegation statement | KMS key | pass | `RESOURCE-KMS-ACCOUNT-DELEGATION` medium; broad authority to the OWNING ACCOUNT, NOT public, NOT root-only; `Resource:*` = the attached key (no per-key node explosion) |
| 2 | 53 | Mismatched SourceArn and SourceAccount | S3 object | pass | `RESOURCE-CONFUSED-DEPUTY` medium; names both disagreeing accounts; internally inconsistent / likely ineffective; not praised as source-bound, not public-write |
| 3 | 69 | Resource policy selected (public `*`) | S3 object | pass | `PUBLIC-ACCESS` critical; routed to the resource evaluator, not identity; coverage INCOMPLETE |
| 3 | 85 | Principal `*` narrowed by PrincipalArn condition | S3 object | pass | `PUBLIC-ACCESS` high (not unconditioned-critical); `*` NARROWED by `ArnLike aws:PrincipalArn`; condition-value wildcard preserved, not mis-flagged as an invalid Principal |

Related resource coverage also committed under `fixtures/resource/`: test 50
(S3 object action on a bucket-only ARN -> `RESOURCE-ACTION-RESOURCE-MISMATCH`,
`tests/resource.test.js`), external-account grant, unmodeled-service fail-closed,
and context-required fail-closed.

## Resource negative corpus (does-not-fire / low)

Frozen "does-not-fire / low" contracts + `rationale`, wired into the blocking
suite by `tests/negative-resource.test.js` (mirrors `tests/negative-trust.test.js`
and `tests/negative.test.js`). Each proves the evaluator does NOT overclaim.

| Fixture | Must find | Capped at | Proves |
|---------|-----------|-----------|--------|
| `sourcebound-service-not-exposure` | `RESOURCE-CONFUSED-DEPUTY` | info / low | a correctly source-bound service (SourceArn + SourceAccount ANDed) is a negative control, not an exposure; never public |
| `same-account-scoped-grant-not-crossaccount` | `RESOURCE-SAME-ACCOUNT-GRANT` | medium | a same-account SQS grant is a direct grant, not cross-account, not public |
| `private-bucket-named-principal-not-public` | `RESOURCE-SAME-ACCOUNT-GRANT` | medium | a bucket policy naming one in-account user is private, not `PUBLIC-ACCESS`, not cross-account |
| `kms-account-delegation-not-public-not-rootonly` | `RESOURCE-KMS-ACCOUNT-DELEGATION` | high | KMS account-root delegation is broad account authority, not public, not root-only; `Resource:*` = the attached key |
| `org-constrained-star-not-critical` | `PUBLIC-ACCESS` | high (not critical) | `*` narrowed by a positive `aws:PrincipalOrgID` excludes anonymous callers; surfaced but not unconditioned-critical |

Every entry additionally asserts: analysis is not fail-closed, EVERY finding is a
resource-family id (never an identity-rule finding on a resource policy), every
finding carries the not-effective-access caveat, and `analyze()` is deterministic.

## Remaining fail-closed (genuinely unmodeled)

The only resource-adjacent shapes that still fail closed are genuinely unmodeled:

- **NotPrincipal Deny hazard** (suite-2 test 29): fails closed
  `UNSUPPORTED_NOTPRINCIPAL` but SURFACES the specific permissions-boundary hazard
  + `ArnNotEquals`/`aws:PrincipalArn` recommendation
  (`tests/acceptance-suite-2.test.js`).
- **RCP / SCP families** (suite-2 tests 52 / 43): Phase-13-deferred.
- **Unmodeled resource services** (any ARN outside S3 / SNS / SQS / KMS):
  `UNSUPPORTED_RESOURCE_SHAPE`.
- **Missing attached-resource context**: `RESOURCE_CONTEXT_REQUIRED`.

## Regression guard

- Suites 1/2/3 no regression.
- Identity negative corpus (`fixtures/negative`) green.
- Trust negative corpus (`fixtures/negative-trust`) green.
- Resource negative corpus (`fixtures/negative-resource`) green.
- Full `node --test "tests/**/*.test.js"` green.
