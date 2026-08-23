# Fixture format

Each fixture is a `.json` file:

```json
{
  "name": "human label",
  "note": "what this exercises",
  "policy": { "Version": "2012-10-17", "Statement": [ ... ] },
  "expect": {
    "valid": true,
    "findingIds": ["WILDCARD-ACTION", "DIRECT-IAM-ADMIN"],
    "notFindingIds": ["PASSROLE-LAMBDA"],
    "graphEdges": [ {"from": "Principal", "to": "Service:lambda", "type": "can-pass"} ]
  }
}
```

- `model`: optional expected normalized model (from `buildModel`/`modelFromText`,
  IAM-002). When present, the parsed model MUST deep-equal it (statements in
  order, each with `index`, `sid`, `effect`, `actions`, `notActions`,
  `resources`, `notResources`, `condition`, `principal`).
- `findingIds`: rule/escalation IDs that MUST be produced (positive).
- `notFindingIds`: IDs that MUST NOT be produced (negative / boundary).
- `exactFindingIds`: optional strongest form - the COMPLETE set of risk-rule
  IDs (IAM-004, from `rules.js`) the fixture must produce, no more and no less.
  Escalation IDs (IAM-005) are ignored by the rules test, so a fixture may list
  `findingIds` for escalation while `exactFindingIds` covers only rule-catalog IDs.
- `graphEdges`: optional expected edges (order-independent).
- `errorCodes`: optional list of `validate()` error codes that MUST appear
  (e.g. `INVALID_JSON`, `TOO_DEEP`, `TOO_LARGE`, `DANGEROUS_KEY`,
  `TOO_MANY_STATEMENTS`). An empty list asserts zero validation errors.
- A fixture supplies EITHER `policy` (an object, stringified before feeding the
  string-based `validate(text)` API) OR `policyRaw` (verbatim text, used for
  non-JSON / prototype-pollution / depth cases that cannot be expressed as a
  clean JS object).
- For `malformed/` and `adversarial/`, set `expect.valid=false` and/or assert
  no uncaught exception and inert rendering.

Every finding/escalation rule ships with at least: one positive fixture, one
negative fixture, one boundary fixture, one malformed-input fixture.
Categories: safe, wildcard, explicit-deny, not-action, not-resource,
direct-iam, destructive, exfil, detection, notaction-allow,
pass-role, assume-role, malformed, adversarial (XSS/proto-pollution/DoS),
family (policy-family classification + fail-closed, IAM-501).

## Fixture-matrix completeness meta-test (IAM-504 + IAM-602)

`tests/fixture-matrix.test.js` is a release gate that enumerates every rule
(rules.js risk catalog + escalation.js path catalog) and FAILS (not skips) if
any of them ships without the coverage its risk category requires. Coverage is
DERIVED from real analyze() output, so a mislabeled fixture cannot paper over a
gap. Applicability ("where semantically applicable") and its rationale live in
`APPLICABILITY` in that test.

Per-rule cells (each id, where applicable): `positive`, `negative` (the primary
when-NOT-to-fire coverage), `boundary` (an edge/near-miss `*-boundary.json`
fixture the engine relates to the rule), `deny` (explicit-Deny interaction),
`condition`, `notAction`, `notResource`, and `hostile` (a positive witness whose
Sid/ARN/Condition carry HTML/JS payloads that must ride through analyze() as
inert DATA).

Tree-wide cells (coverage that must exist across the corpus, spanning rule
categories - not one per id): `family-mismatch` and `deterministic-export`.
`family-mismatch` proves the engine fails closed on an unmodeled family
(resource / role-trust / NotPrincipal / ambiguous) instead of firing an identity
rule on the dangerous actions it carries. A witness declares the rule ids it
covers via `expect.familyMismatchFor`, and the gate double-locks the claim:
analyze(policy) must fail closed (coverage.blocked, zero findings) AND the same
policy reshaped to identity form (Principal/NotPrincipal stripped) must actually
fire each declared id - so a family-mismatch claim can never be vacuous. The
corpus must witness at least one capability rule and one escalation path.

```json
{ "expect": { "notFindingIds": ["WILDCARD-ACTION"],
  "familyMismatchFor": ["WILDCARD-ACTION"] } }
```

Most cells are witnessed by the existing category fixtures. Fixtures added for
IAM-504 gaps live in their capability/escalation dir (e.g. `exfil/`,
`detection/`, `pass-role/`) and are ordinary `expect`-carrying fixtures. The
two `hostile` witnesses live in `adversarial/` and add:

```json
{ "expect": { "valid": true, "hostile": true,
  "assertInertRendering": true,
  "hostileFor": ["<RULE-ID>", "..."] } }
```

- `hostile: true` marks the fixture as a hostile-string-rendering witness.
- `hostileFor` lists the rule ids it witnesses; each MUST fire AND carry a
  hostile string verbatim in a finding field (proof the payload is inert data).

Evidence completeness (`tests/evidence.test.js`) asserts every finding exposes
the full explainable-evidence set - policy family, statement index + Sid,
normalized action(s)/resource(s), relevant condition, rule id, split certainty,
and the capability-not-effective limitation - and that the JSON export carries
it verbatim. Privacy invariants (`tests/privacy-invariants.test.js` +
`tests/e2e/privacy-invariants.spec.js`) gate zero egress, no storage/URL writes,
Clear/pagehide wipe, self-describing exports, hostile HTML/SVG/MD/Unicode
inertness, and browser-worker vs Node-module parity.

## Policy-family corpus (`family/`, IAM-501)

`family/` exercises the policy-family model: auto-detect from shape and
fail-closed on shapes the engine does not model. Each fixture adds a
`familyExpect` block consumed by `tests/family.test.js`:

```json
{
  "policy": { "Version": "2012-10-17", "Statement": [ ... ] },
  "familyExpect": {
    "detected": "identity|resource|role-trust|ambiguous",
    "family": "effective family (== detected unless a manual override is set)",
    "blocked": true,
    "supported": false,
    "blockingCodes": [ { "code": "UNSUPPORTED_POLICY_FAMILY", "path": "Statement[0].Principal" } ]
  }
}
```

- Auto-detect resolves identity policies (no Principal/NotPrincipal) to the
  `identity` family; they analyze normally (paste-and-go preserved).
- Resource / role-trust / ambiguous-mixed shapes, and any `NotPrincipal`
  element, FAIL CLOSED: `analyze()` returns `ok:true` with an empty result and
  `coverage.blocked = true`, carrying a machine-readable code + exact JSON path
  (`UNSUPPORTED_POLICY_FAMILY`, `UNSUPPORTED_NOTPRINCIPAL`,
  `AMBIGUOUS_POLICY_SHAPE`, `OVERRIDE_SHAPE_MISMATCH`). No confident findings are
  produced on a shape the engine does not understand.
- A statement carrying BOTH `Principal` and `NotPrincipal` is a hard schema
  error (`PRINCIPAL_AND_NOTPRINCIPAL`, `expect.valid = false`); use
  `familyExpect.modelError` / `familyExpect.modelErrorPath` for that case.

## Negative regression corpus (`negative/`, IAM-301)

`negative/` is the "does-not-fire / does-not-overstate" truth corpus. Each
fixture pairs a policy with the outcome that is CORRECT per real AWS semantics
(not necessarily what the engine produces today) plus a `rationale` citing the
AWS behavior that makes the expectation true. These assert the engine knows
when NOT to fire, or to lower severity/exploitability.

These fixtures deliberately do **not** use the shared `expect` block, so the
existing category-iterating suites (`analyze.test.js`, `graph.test.js`) treat
them only as valid-input shape/determinism checks and do not enforce their
outcomes. They stay INERT until IAM-302 adds `tests/negative.test.js`, which
reads the `negativeExpect` block below and fixes the engine to satisfy it. The
`negativeExpect` outcomes are FROZEN TRUTH: IAM-302 changes the engine, never
these expectations.

```json
{
  "name": "human label",
  "note": "what this exercises",
  "phase": 3,
  "story": "IAM-301",
  "policy": { "Version": "2012-10-17", "Statement": [ ... ] },
  "negativeExpect": {
    "mustFind": ["PASSROLE-LAMBDA"],
    "mustNotFind": ["DIRECT-IAM-ADMIN"],
    "maxSeverity": { "ASSUME-ROLE-EXPANSION": "high" },
    "maxPathExploitability": { "DATA-EXFIL": "medium" }
  },
  "rationale": "the AWS behavior that makes the expectation correct"
}
```

- `mustFind`: finding IDs the engine MUST produce (e.g. compound path still
  detected across statements). May be empty.
- `mustNotFind`: finding IDs the engine MUST NOT produce (false positive / does
  not fire). May be empty.
- `maxSeverity`: `{id: ceiling}` - if that finding is produced, its `severity`
  MUST NOT exceed the ceiling (`critical`>`high`>`medium`>`low`>`info`).
- `maxPathExploitability`: `{id: ceiling}` - if produced, `pathExploitability`
  MUST NOT exceed the ceiling (`high`>`medium`>`low`); used for
  condition-narrowed grants.
- `rationale`: REQUIRED. Cites the concrete AWS semantics; this is the
  integrity gate (an incorrect expectation is blocking).

## Trust negative corpus (`negative-trust/`, IAM-805)

`negative-trust/` is the role-trust analogue of `negative/`: the
"does-not-fire / low" truth corpus for ROLE-TRUST policies. Each fixture pairs
a trust policy with the outcome that is CORRECT per real AWS trust semantics
(grounded in `docs/trust-policy-semantics.md`) plus a `rationale` citing the
AWS behavior that makes the expectation true. It is the credibility artifact
proving the trust analyzer knows when NOT to fire - the load-bearing guard
against overclaiming (threat-model T8: a trust policy conveys WHO MAY ASSUME a
role, never the assumed role's permissions).

Each fixture carries `"family": "role-trust"` and reuses the exact
`negativeExpect` schema documented above (`mustFind` / `mustNotFind` /
`maxSeverity` / `maxPathExploitability`). `tests/negative-trust.test.js` (a
mirror of `tests/negative.test.js`) drives every fixture through `analyze()`
and enforces the frozen contract, plus trust-specific invariants: no
identity-style finding on a trust policy, every trust finding marks the target
role's permissions out-of-scope/unknown, and no "missing ExternalId" /
"missing aws:PrincipalOrgID" remediation. The `negativeExpect` outcomes are
FROZEN TRUTH: fix `engine/trust.js`, never these expectations.

Cases covered: normal service trust (informational only), tightly-scoped OIDC
(repo + ref, not HIGH), tightly-scoped SAML subject, ExternalId-protected
vendor cross-account (confused-deputy constraint), org-constrained trust
(`StringEquals aws:PrincipalOrgID`), and SourceArn / SourceAccount-constrained
service trust.
