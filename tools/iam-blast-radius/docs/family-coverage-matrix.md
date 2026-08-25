# IAM Blast Radius - full-family coverage matrix (Phase 13 capstone, IAM-1303)

This is the capstone record for Phase 13. It confirms that the analyzer now covers
the **full AWS IAM policy-family set** - and, critically, that every family is
either **analyzed correctly** by a family-aware evaluator or **explicitly fails
closed** on a genuinely-unmodeled shape with a **machine-readable code**. No family
is silently mis-read as an ordinary identity grant.

The load-bearing invariant across the ceiling families (permissions boundary,
session, SCP, RCP) is the same one `engine/envelope.js` established: **an Allow in
a ceiling policy is a MAXIMUM-PERMISSIONS ENVELOPE, not a grant, and a Deny is a
GUARDRAIL.** Effective access is the INTERSECTION of the ceiling with the
identity/resource policies that are not supplied to a single-document analysis.
A ceiling/guardrail family NEVER emits a positive capability finding or graph edge.

Generated for IAM-1303 against the working-tree engine (`content/tools/iam-blast-radius/engine/`).

## How to read this table

- **Analyzed** = a family-aware evaluator runs and produces findings framed for
  that family. Where a family is unlockable only by an **explicit** selection (the
  UI family selector), that is noted - it is exactly how the resource family is
  unlocked by its explicit attached-resource context.
- **Fail-closed (code)** = the shape is recognized but deliberately not analyzed;
  `analyze()` returns `ok:true` with `coverage.blocked:true`, zero findings, an
  empty graph, and the named machine-readable code. "Unsupported != safe."
- Auto-detect never guesses a ceiling family from an identity-shaped document: a
  permissions boundary / session / allow-list SCP is structurally identical to an
  identity policy, so auto-detect resolves those to identity (or fails closed),
  and the ceiling reading is reached only by explicit selection. This is a
  deliberate anti-overstatement control (threat model T8).

## The matrix

| Policy family | Evaluator | Analyzed? | Auto-detect behavior | Fail-closed code (when not analyzed) | Finding ids | Suite anchor |
|---|---|---|---|---|---|---|
| Identity | `engine/rules.js` + `engine/escalation.js` | Yes (auto) | Analyzed as identity | n/a | `PASSROLE-*`, `ROLE-TAKEOVER`, `WILDCARD-ACTION/RESOURCE`, `DIRECT-IAM-ADMIN`, `ATTACH-POLICY`, `POLICY-VERSION`, `CREDENTIAL-*`, `ASSUME-ROLE-EXPANSION`, `DATA-READ`, `DESTRUCTIVE-ACTION`, ... | suite-1 1-14/19-24, suite-2 34-48/50/54 |
| Role trust | `engine/trust.js` | Yes (auto, Phase 8) | Analyzed as role-trust | `UNSUPPORTED_PRINCIPAL_TYPE` / `INVALID_PRINCIPAL_WILDCARD_ARN` on unmodeled principal shapes | `TRUST-PUBLIC`, `TRUST-CROSS-ACCOUNT`, `TRUST-ORG-EXPANSION`, `TRUST-FEDERATED`, `TRUST-SERVICE`, `TRUST-INVALID-PRINCIPAL` | suite-1 10/15/16/17/18, suite-2 25/48 |
| Resource (S3 / SNS / SQS / KMS) | `engine/resource.js` | Yes (explicit attached-resource context, Phase 12) | Fail-closed | `UNSUPPORTED_POLICY_FAMILY` (auto) / `RESOURCE_CONTEXT_REQUIRED` (selected, no context) | `PUBLIC-ACCESS`, `RESOURCE-CONFUSED-DEPUTY`, `RESOURCE-SAME-ACCOUNT-GRANT`, `RESOURCE-KMS-ACCOUNT-DELEGATION` | suite-2 26/27/28/32/33/49/51/53, suite-3 69/85 |
| Permissions boundary | `engine/envelope.js` | Yes (explicit selection, Phase 10) | family-gap: reads as identity (no Principal to distinguish) | `UNSUPPORTED_POLICY_FAMILY` if selected on a Principal-bearing/ambiguous shape | `PERMISSIONS-BOUNDARY-ENVELOPE` (ceiling) | suite-2 30 |
| Session policy | `engine/envelope.js` | Yes (explicit selection, Phase 10) | family-gap: reads as identity | `UNSUPPORTED_POLICY_FAMILY` if selected on a Principal-bearing/ambiguous shape | `SESSION-CEILING` (restriction) | suite-2 31 |
| SCP (Service Control Policy) | `engine/scp.js` (reuses `envelope.js` ceiling semantics) | Yes (explicit SCP selection, Phase 13) | Fail-closed | `UNSUPPORTED_SCP_SHAPE` (auto) | `SCP-CEILING` (Allow envelope), `SCP-GUARDRAIL` (Deny: organization / region) | suite-1 19, suite-2 43 |
| RCP (Resource Control Policy) | `engine/rcp.js` | Yes (explicit SCP/RCP selection, Phase 13) | Fail-closed | `UNSUPPORTED_POLICY_FAMILY` (auto; Principal `*` reads as resource) | `RCP-GUARDRAIL` (deny-only: confused-deputy / organization) | suite-2 52 |

Other machine-readable fail-closed codes that guard mis-reads regardless of family:
`AMBIGUOUS_POLICY_SHAPE` (some statements name a Principal and some do not, e.g.
suite-1 test 20), `UNSUPPORTED_NOTPRINCIPAL` (the Deny + NotPrincipal permissions-
boundary trap, suite-2 test 29), `UNSUPPORTED_POLICY_VERSION` (legacy `2008-10-17`,
suite-1 22C), `DUPLICATE_JSON_KEY` / `INVALID_JSON` / `DANGEROUS_KEY` / `TOO_LARGE`
(parser-hardening, suite-2 44/46/54).

## Ceiling / guardrail invariant verification (the Phase-13 heart)

For every SCP/RCP observation the analyzer emits, the following are enforced by
`tests/phase13-scp.test.js`, `tests/phase13-rcp.test.js`, and the flip gate
`tests/acceptance-scp-rcp-flip.test.js`:

- **Never a grant.** Zero positive capability edges and zero graph nodes from an
  SCP/RCP. No finding is `critical` (a ceiling grants nothing). No escalation
  enrichment. No identity/escalation/resource-capability finding id appears.
- **NotAction is a carve-out.** A `Deny` + `NotAction` list (e.g. the global-service
  region carve-out in suite-1 test 19) is surfaced as `excludedActions` and is
  NEVER reported as the allowed/covered actions.
- **Condition polarity is honest.** `StringNotEquals` / `StringNotEqualsIfExists`
  on `aws:RequestedRegion` is a region guardrail; a negated `...IfExists` in a
  Deny (suite-2 test 43) is a FAIL-CLOSED guardrail flagged as a potentially
  over-broad regional-Deny hazard (it denies even when the key is absent), never a
  grant inside or outside the regions.
- **RCP conditions act together.** The confused-deputy triplet
  (`StringNotEqualsIfExists aws:SourceOrgID` + `Null aws:SourceAccount` +
  `Bool aws:PrincipalIsAWSService`, suite-2 test 52) is preserved as ONE guardrail
  (logical AND), not three independent denies; the Principal `*` is recorded as the
  deny's subject, never a public-access grant.
- **Intersection caveat.** Every ceiling/guardrail finding's `limit` states it is a
  ceiling, that SCPs/RCPs do not grant, and that effective access is the
  INTERSECTION with identity/resource policies not supplied here.

## No-regression confirmation (IAM-1303)

- **Suite 1** (`docs/acceptance-suite.md`, tests 1-24): green
  (`tests/acceptance-suite.test.js`). Test 19 flipped to real SCP guardrail
  analysis under explicit selection while auto-detect stays fail-closed.
- **Suite 2** (`docs/acceptance-suite-2.md`, tests 25-54): scoreboard
  `docs/acceptance-suite-2-results.md` updated; tests 43/52 flipped from
  `blocked-by-design` to `pass`. Only 29 (NotPrincipal), 30, 31 remain deferred.
- **Suite 3** (`docs/acceptance-suite-3.md`): green
  (`tests/acceptance-suite-3*.test.js`).
- **Negative corpora** unchanged and green: identity (`fixtures/negative`), trust
  (`fixtures/negative-trust`), resource (`fixtures/negative-resource`).
- **Auto-detect fail-closed contract** for SCP/RCP shapes preserved
  (`tests/phase13-scp.test.js`, `tests/phase13-rcp.test.js`): the mixed
  FullAWSAccess + region-Deny SCP and the RCP shape still fail closed under
  auto-detect and never manufacture a grant.
- Full `node --test "tests/**/*.test.js"` green.
