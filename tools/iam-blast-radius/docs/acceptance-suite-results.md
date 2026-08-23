# IAM Blast Radius - acceptance-suite final scoreboard (IAM-707)

Phase 7 close-out. Every one of the 24 acceptance-suite tests (with test 22
expanded into subcases 22A / 22B / 22C) now has a committed fixture under
`fixtures/acceptance/` and is driven from real `analyze()` output by
`tests/acceptance-suite.test.js`, alongside the six per-defect Phase-7 harnesses
(`acceptance-provenance`, `acceptance-edge-typing`, `acceptance-compound`,
`acceptance-complement`, `acceptance-dedup`, `acceptance-data-read`).

Baseline for the "was" column is the 2026-08-22 battle test
(`~/knowledge/personal/iam-blast-radius-battle-test-2026-08-22.md`).

## Scoreboard

| # | Test | Was (2026-08-22) | Now | Fixture |
|---|------|------------------|-----|---------|
| 1 | Cross-stmt PassRole->EC2 | FAIL | FIXED - PASSROLE-EC2 critical; per-statement provenance in header + graph edges | test-01 |
| 2 | PassRole cond -> Lambda not EC2 | PARTIAL | FIXED - Lambda path only; EC2 suppressed by iam:PassedToService selector; no false "missing PassedToService" | test-02 |
| 3 | Separate Lambda techniques | FAIL | FIXED - anyOf: PassRole+CreateFunction AND standalone UpdateFunctionCode (PassRole-free) | test-03 |
| 4 | Managed-policy version | PARTIAL | FIXED - POLICY-VERSION only (no DIRECT-IAM-ADMIN double-fire); action arrays; object-Statement normalized | test-04 |
| 5 | Access-key creation | PARTIAL | FIXED - credential/impersonation edge only (no can-modify\|policy:self); prerequisites grounded (no absent actions) | test-05 |
| 6 | Broad cross-account AssumeRole | PASS | PASS (preserved) - ASSUME-ROLE-EXPANSION high, policyEvidence high, pathExploitability medium | test-06 |
| 7 | S3 read constrained by KMS | FAIL | FIXED - DATA-READ (inferred sensitivity, medium) + constrained KMS-DECRYPT coexist | test-07 |
| 8 | Explicit Deny blocks action | FAIL | FIXED - no capability finding; only a `denies` edge; suppressed grant excluded from totals/edges | test-08 |
| 9 | Partial Deny | PARTIAL | FIXED - DESTRUCTIVE-ACTION high over residual broad scope; narrow deny recorded as `denies` edge | test-09 |
| 10 | Negated org condition (trust) | BLOCKED | DESIGN-BLOCKED (role-trust family) - fail-closed UNSUPPORTED_POLICY_FAMILY | test-10 |
| 11 | Case-insensitive + scalar | PASS | PASS (preserved) - single-statement PASSROLE-EC2; original casing kept for evidence | test-11 |
| 12 | iam:* expansion | FAIL | FIXED - ONE primary DIRECT-IAM-ADMIN (high) with subsumed primitives; no 7-row flood; catalog version surfaced | test-12 |
| 13 | Allow with NotAction | FAIL | FIXED - complement modeled; excluded set never shown as allowed; reduced (complement-derived) confidence | test-13 |
| 14 | Allow with NotResource | FAIL | FIXED - NotResource carve-out never presented as the granted resource | test-14 |
| 15 | Public role trust | BLOCKED | DESIGN-BLOCKED (role-trust family) - fail-closed UNSUPPORTED_POLICY_FAMILY | test-15 |
| 16 | Third-party trust + ExternalId | BLOCKED | DESIGN-BLOCKED (role-trust family) - fail-closed UNSUPPORTED_POLICY_FAMILY | test-16 |
| 17 | Over-broad OIDC trust | BLOCKED | DESIGN-BLOCKED (role-trust family) - fail-closed UNSUPPORTED_POLICY_FAMILY | test-17 |
| 18 | Normal service trust (neg ctrl) | BLOCKED | DESIGN-BLOCKED (role-trust family) - fail-closed UNSUPPORTED_POLICY_FAMILY | test-18 |
| 19 | SCP deny guardrail | FAIL (misdetect) | FIXED - detected as SCP/RCP shape; fail-closed UNSUPPORTED_SCP_SHAPE (no identity fallback). Full SCP ceiling semantics = later feature | test-19 |
| 20 | Mixed policy family | PASS | PASS (preserved) - fail-closed AMBIGUOUS_POLICY_SHAPE citing Statement[1] | test-20 |
| 21 | Policy variables | FAIL | FIXED - DATA-READ with `${aws:username}` preserved verbatim (not resolved/classified) | test-21 |
| 22A | Malformed JSON | PASS | PASS (preserved) - INVALID_JSON, ok:false, no findings/graph/model | test-22a |
| 22B | Missing Effect/Action | PASS | PASS (preserved) - INVALID_EFFECT + MISSING_ACTION, never interpreted as Allow | test-22b |
| 22C | Unsupported version 2008 | FAIL | FIXED - UNSUPPORTED_POLICY_VERSION; version preserved verbatim, never rewritten | test-22c |
| 23 | Duplicate/subsumed | PASS | PASS (preserved) - one primary PASSROLE-LAMBDA + risk factors; WILDCARD-RESOURCE subsumed; counts agree | test-23 |
| 24 | Graph semantic typing | FAIL | FIXED - typed edges (can-read/can-decrypt/delegation/can-destroy); no generic can-write aggregation; PassRole alone no exec path | test-24 |

## Tally

- **PASS preserved (originally passing, guarded against regression):** 6 tests -
  6, 11, 20, 22A, 22B, 23.
- **FIXED this phase (were FAIL/PARTIAL):** 15 tests - 1, 2, 3, 4, 5, 7, 8, 9,
  12, 13, 14, 19, 21, 22C, 24.
- **DESIGN-BLOCKED (fail-closed by design):** 5 tests - 10, 15, 16, 17, 18.

All 26 cases have committed fixtures; none is silently skipped.

## Design-blocked cases and the queued follow-up

Tests 10, 15, 16, 17, 18 are **role trust policies**. The engine does not yet
model the role-trust family, so it FAILS CLOSED (`UNSUPPORTED_POLICY_FAMILY`)
rather than mis-analyze a trust document with identity rules. Each fixture
carries a `designBlocked` marker naming the queued follow-up
(**role-trust family analysis**, the immediate next feature per Oliver,
2026-08-22) and the intended finding a later story must produce. The
acceptance-suite harness asserts the CURRENT blocked behavior, so a future story
flips these deliberately - never via a silent skip.

Test 19 is fail-closed for the SCP/RCP shape (`UNSUPPORTED_SCP_SHAPE`). The
Phase-7 requirement (block rather than fall back to identity rules) is MET; full
SCP **ceiling** semantics remains a separate later feature.

## Cross-test invariants

The 12 cross-test invariants from `docs/acceptance-suite.md` are encoded as
reusable helpers in `tests/acceptance-suite.test.js` and applied across every
applicable acceptance fixture:

1. family-explicit, 2. evidence-immutable, 3. AND/OR-explicit,
4. unknown-visible, 5. denies-are-not-grants, 6. condition-polarity,
7. no-semantic-edge-reuse, 8. dedup-explainable, 9. exports-agree (JSON +
Markdown carry the same finding set/severities; counts agree), 10.
invalid-fails-closed, 11. local-only (static no-network gate over the shipped
engine sources), 12. determinism (byte-identical export on re-analysis).

## Verification

- `node --test "tests/**/*.test.js"` -> **763 pass, 0 fail, 0 skipped**.
- `gate:no-network` + `gate:no-unsafe-dom` clean on the shipped tree.
- Originally-passing tests (6, 11, 20, 22A, 22B, 23) and the negative corpus
  (`fixtures/negative`) unchanged and green.
- Playwright browser matrix remains CI's job (no browser run claimed here).
