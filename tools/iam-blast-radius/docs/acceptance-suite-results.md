# IAM Blast Radius - acceptance-suite final scoreboard (IAM-707 + IAM-806)

Phase 7 close-out, updated at the Phase-8 close-out (IAM-806). Every one of the
24 acceptance-suite tests (with test 22 expanded into subcases 22A / 22B / 22C)
has a committed fixture under `fixtures/acceptance/` and is driven from real
`analyze()` output by `tests/acceptance-suite.test.js`, alongside the six
per-defect Phase-7 harnesses (`acceptance-provenance`, `acceptance-edge-typing`,
`acceptance-compound`, `acceptance-complement`, `acceptance-dedup`,
`acceptance-data-read`) and the Phase-8 trust harnesses (`trust`,
`trust-federated`, `negative-trust`).

Phase-8 update: the role-trust family is now a SUPPORTED family (engine/trust.js
+ family-aware routing, stories IAM-801..805). Acceptance tests 10, 15, 16, 17,
18 - previously fail-closed BY DESIGN as `UNSUPPORTED_POLICY_FAMILY` - are flipped
to their REAL expected trust findings and severities (IAM-806) and now PASS.
`NotPrincipal` remains fail-closed (`UNSUPPORTED_NOTPRINCIPAL`); it is an
expansion trap and was NOT flipped.

Baseline for the "was" column is the 2026-08-22 battle test
(`~/knowledge/personal/iam-blast-radius-battle-test-2026-08-22.md`); the "Now"
column reflects the Phase-8 state.

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
| 10 | Negated org condition (trust) | BLOCKED | FIXED (Phase 8) - TRUST-ORG-EXPANSION critical; StringNotEquals aws:PrincipalOrgID classified as expansion/exclusion (never "missing"); target-role perms out of scope; external-origin can-assume graph | test-10 |
| 11 | Case-insensitive + scalar | PASS | PASS (preserved) - single-statement PASSROLE-EC2; original casing kept for evidence | test-11 |
| 12 | iam:* expansion | FAIL | FIXED - ONE primary DIRECT-IAM-ADMIN (high) with subsumed primitives; no 7-row flood; catalog version surfaced | test-12 |
| 13 | Allow with NotAction | FAIL | FIXED - complement modeled; excluded set never shown as allowed; reduced (complement-derived) confidence | test-13 |
| 14 | Allow with NotResource | FAIL | FIXED - NotResource carve-out never presented as the granted resource | test-14 |
| 15 | Public role trust | BLOCKED | FIXED (Phase 8) - TRUST-PUBLIC critical; no identity broad-Resource finding (Resource legitimately omitted); external-origin can-assume from ext:anonymous, no principal-subject node | test-15 |
| 16 | Third-party trust + ExternalId | BLOCKED | FIXED (Phase 8) - TRUST-CROSS-ACCOUNT low; sts:ExternalId recognized as a confused-deputy constraint (never "missing", never called auth/secret); target-role perms out of scope | test-16 |
| 17 | Over-broad OIDC trust | BLOCKED | FIXED (Phase 8) - TRUST-FEDERATED high; aud a valid constraint, repo:example-org/* sub broad (not credited); recommends repo+ref/env; no "every repo can assume" claim | test-17 |
| 18 | Normal service trust (neg ctrl) | BLOCKED | FIXED (Phase 8) - TRUST-SERVICE informational only; no public/external/escalation finding; no target-role-permission inference (negative control) | test-18 |
| 19 | SCP deny guardrail | FAIL (misdetect) | FIXED - PASS (flipped IAM-1303). Under an explicit SCP selection: two `SCP-GUARDRAIL` findings (organization-departure deny + region deny); the NotAction global-service list is surfaced as a carve-out (`excludedActions`), NEVER as allowed; ceiling-not-grant + INTERSECTION caveat; zero capability edges (`tests/phase13-scp.test.js`, gated by `tests/acceptance-scp-rcp-flip.test.js`). Under auto-detect still fail-closed `UNSUPPORTED_SCP_SHAPE` (no identity fallback) | test-19 (auto), family-scp/test-19 (explicit) |
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
- **FIXED in Phase 7 (were FAIL/PARTIAL):** 15 tests - 1, 2, 3, 4, 5, 7, 8, 9,
  12, 13, 14, 19, 21, 22C, 24.
- **FIXED in Phase 8 (role-trust family, were DESIGN-BLOCKED):** 5 tests - 10,
  15, 16, 17, 18.

All 26 cases have committed fixtures and PASS from real `analyze()` output; none
is silently skipped. `DESIGN_BLOCKED_IDS` in `tests/acceptance-suite.test.js` is
now empty - the mechanism is retained so a future unsupported family can be
encoded as design-blocked (never a skip), but no acceptance test currently uses
it.

## Phase-8 role-trust close-out (IAM-806)

Tests 10, 15, 16, 17, 18 are **role trust policies**. Through Phase 7 the engine
did not model the role-trust family and FAILED CLOSED
(`UNSUPPORTED_POLICY_FAMILY`) rather than mis-analyze a trust document with
identity rules. Phase 8 (IAM-801..805) shipped `engine/trust.js` and family-aware
routing, and IAM-806 flipped these five fixtures from their `designBlocked`
markers to their REAL expected findings + severities, per
`docs/trust-policy-semantics.md` and the Phase-8 trust severity model:

- Every trust finding carries the load-bearing limitation that the assumed
  role's permissions are OUT OF SCOPE / UNKNOWN (a trust policy conveys who may
  assume the role, never the role's power).
- The graph origin is the EXTERNAL principal(s) - `ext:anonymous`,
  `ext:arn:...:root`, `ext:arn:...:oidc-provider/...`, `svc:lambda.amazonaws.com`
  - via a typed `can-assume` edge to a single `role:trust-target` node whose
  privileges are marked unknown; there is NO identity "principal subject" origin
  and NO generic `can-write` aggregation.
- Condition polarity is classification-only: `StringNotEquals aws:PrincipalOrgID`
  reads as an expansion/exclusion (test 10, critical), `sts:ExternalId` as a
  confused-deputy constraint (test 16, never "missing"/auth/secret), OIDC `aud`
  as a constraint and a `repo:org/*` `sub` as broad-uncredited (test 17).

`NotPrincipal` was NOT flipped: it stays fail-closed with
`UNSUPPORTED_NOTPRINCIPAL` (expansion trap), asserted in `family.test.js` and
`trust.test.js`.

Test 19 (SCP deny guardrail) FLIPPED in Phase 13. Under an explicit SCP selection
it is now analyzed by the family-aware SCP ceiling/guardrail evaluator
(`engine/scp.js`, IAM-1301): two `SCP-GUARDRAIL` findings (an organization-departure
deny + a region deny), the global-service NotAction list surfaced as a carve-out
(never as allowed capabilities), the ceiling-not-grant + INTERSECTION caveat on
every finding, and zero positive capability edges. The committed fixture is
`fixtures/family-scp/test-19-scp-deny-guardrail.json`, driven by
`tests/phase13-scp.test.js` and gated by the flip scoreboard
`tests/acceptance-scp-rcp-flip.test.js`. Under **auto-detect** (no explicit family)
it still fails closed with `UNSUPPORTED_SCP_SHAPE` - the Phase-7 requirement (block
rather than fall back to identity rules) is preserved, so the shape is
analyzed-or-explicitly-fail-closed, never mis-read. See
`docs/family-coverage-matrix.md`.

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

- `node --test "tests/**/*.test.js"` -> **880 pass, 0 fail, 0 skipped**
  (Phase-8 close-out; was 763 at the Phase-7 close-out).
- All 26 acceptance cases PASS from real `analyze()` output; the 12 cross-test
  invariants (including evidence-immutable provenance, condition-polarity,
  unknown-visible, denies-are-not-grants, no-semantic-edge-reuse, exports-agree,
  determinism) are applied across every acceptance fixture, trust fixtures
  included.
- `gate:no-network` + `gate:no-unsafe-dom` clean on the shipped tree.
- Originally-passing tests (6, 11, 20, 22A, 22B, 23), the identity negative
  corpus (`fixtures/negative`), and the trust negative corpus
  (`fixtures/negative-trust`) unchanged and green; the 15 Phase-7 fixes not
  regressed.
- Playwright browser matrix remains CI's job (no browser run claimed here).
