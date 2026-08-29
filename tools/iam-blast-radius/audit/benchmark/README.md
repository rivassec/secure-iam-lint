# Ground-truth privilege-escalation benchmark

This directory measures `secure-iam-lint` against the canonical published catalog
of AWS IAM privilege-escalation methods, as an objective, reproducible coverage
claim.

## Result

**21 / 21 published privesc methods caught, 0 read CLEAN** - each by a specific
named detector, not the incomplete-coverage backstop.

Reproduce (from `tools/iam-blast-radius/`):

```bash
node --test audit/benchmark/benchmark.test.js
# ... # privesc-benchmark: 21/21 named-detector catches, 0 CLEAN
```

## Source

The method list is the canonical set from Rhino Security Labs - Spencer Gietzen,
"AWS IAM Privilege Escalation - Methods and Mitigation" (2018) - the same 21
methods automated in Pacu's `iam__privesc_scan` module. `corpus.mjs` encodes one
minimal policy per method.

## Methodology (why the number is honest)

- **Hardest form.** Every policy is scoped to concrete resource ARNs (no bare
  `"*"` resource), so a catch cannot ride on a generic `WILDCARD-RESOURCE`
  finding. The privesc primitive itself is what must be detected.
- **Two assertions per method.** (1) `scan()` never exits CLEAN - the fail-closed
  invariant (threat-model T8); and (2) the specific expected detector fires
  (e.g. `PASSROLE-EC2`, `ATTACH-POLICY`, `COMPUTE-CODE-OVERWRITE`) - so the catch
  is a *named* escalation a user can act on, not merely "coverage incomplete".
- **This gate finds gaps.** Building it surfaced one: `glue:UpdateDevEndpoint`
  (inject an SSH key into an existing Glue dev endpoint, then run code as its
  bound role) was caught only by the incomplete-coverage backstop. It is
  mechanically identical to the compute-code-overwrite family already modeled, so
  it was promoted to a specific `COMPUTE-CODE-OVERWRITE` detector. The benchmark
  then read 21/21 by named detector.

## Scope note

This measures coverage of the *modeled* privesc catalog: the tool reports the AWS
evaluation layers a policy reaches, not effective permissions (it has no account
state - group memberships, existing role trusts, SCPs beyond the supplied policy).
A method landing here means the tool surfaces the primitive from the policy text
alone. New published methods should be added to `corpus.mjs`; if the engine does
not yet catch one, that is a gap to close (or an explicit, documented
out-of-model limitation), never a silent pass.
