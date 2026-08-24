# IAM Blast Radius — Record and Residual Test Bundle

This bundle turns the two recorded incidents and the remaining deferred work into repeatable acceptance tests.

## Coverage

| Track | Cases | Purpose |
| --- | ---: | --- |
| Boundary assertion regression | 8 | Prevent a prose word from colliding with a rule-name assertion and verify family-switch state isolation |
| Critic workflow robustness | 15 | Make critic errors, missing responses, ledger failures, retries, and recovery fail closed |
| T91 cross-account PassRole | 9 | Remove the false critical path without suppressing viable same-account and wildcard cases |
| Deferred policy families | 10 | Preserve explicit fail-closed behavior until resource, RCP, SCP-ceiling, and NotPrincipal semantics land |
| **Total** | **42** | |

## Files

- `TEST_PLAN.md` — complete procedures, expected results, and release gate.
- `cases/analyzer-cases.json` — analyzer and browser cases in machine-readable form.
- `cases/workflow-cases.json` — critic and ledger fault-injection cases.
- `schemas/critic-result.schema.json` — explicit critic outcome contract.
- `schemas/review-ledger-entry.schema.json` — minimum durable ledger contract.
- `templates/family-switch.spec.template.mjs` — Playwright assertion pattern that avoids the original collision.
- `templates/critic-fail-closed.test.template.mjs` — Node test structure for workflow fault injection.

## Adapter boundary

The templates are intentionally repository-neutral. Map the selectors and imported workflow functions to the real application. The semantic cases and schemas are the authoritative portion of the bundle.

## Required principle

Unknown, unavailable, malformed, timed out, and failed are explicit non-pass states. An empty array, missing result, or rejected promise is never equivalent to critic approval.
