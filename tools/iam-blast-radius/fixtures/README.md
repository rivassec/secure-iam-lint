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
pass-role, assume-role, malformed, adversarial (XSS/proto-pollution/DoS).

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
