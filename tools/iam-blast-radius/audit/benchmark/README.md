# Ground-truth privilege-escalation benchmark

This directory measures `secure-iam-lint` against the published catalog of AWS
IAM privilege-escalation methods from Rhino Security Labs, as an objective,
reproducible coverage claim.

## Result

**All 28 of Rhino's currently-cataloged privesc methods fail closed, 0 read
CLEAN.** Rhino's original Part 1 (21 methods) are each caught by a specific named
detector. Rhino Part 2 (repo methods 22-28) are all caught too: 4 by named
detector, 3 by the incomplete-coverage backstop - and all 3 are CodeStar, a
service AWS deprecated and closed in 2024, so no named detector is warranted.
An additional second-tier set (11 primitives beyond Rhino's 28) also never reads
CLEAN: 10 by named detector, 1 by the backstop (AWS Batch, a named-detector
candidate). The SSM / EC2-Instance-Connect / existing-SageMaker-notebook cases are
now named by the COMPUTE-SESSION-TAKEOVER detector (v1.1.0).

Reproduce (from `tools/iam-blast-radius/`):

```bash
node --test audit/benchmark/benchmark.test.js
# ... # privesc-benchmark: 21/21 named-detector catches, 0 CLEAN
```

## Source

The method list is Rhino Security Labs' original catalog - Spencer Gietzen, "AWS
IAM Privilege Escalation - Methods and Mitigation" Part 1 (2018) - the 21 methods
automated in Pacu's `iam__privesc_scan` module. Rhino's repo
(`github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation`) now enumerates 28
methods; this corpus covers the original 21 by name, with more in the second tier.
`corpus.mjs` encodes one minimal policy per method.

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

## Second tier (beyond the original 21)

`corpus.mjs` also carries a `SECOND_TIER` set of well-known privesc primitives
outside Rhino's original list. Every one still fails closed (never CLEAN):

- **Named (10):** `PassRole + ecs:RunTask`, `+ sagemaker:CreateNotebookInstance`,
  `+ codebuild:CreateProject`, `+ glue:CreateJob`, `+ events:PutTargets`
  (all `PASSROLE-SERVICE`); `sts:AssumeRole *` (`ASSUME-ROLE-EXPANSION`);
  `lambda:AddPermission` (`RESOURCE-POLICY-WRITE`); and `ssm:SendCommand`,
  `ssm:StartSession`, `ec2-instance-connect:SendSSHPublicKey`
  (`COMPUTE-SESSION-TAKEOVER`, v1.1.0 - which also names Rhino method 28, the
  existing-SageMaker-notebook presigned URL).
- **Backstop-only (1), a candidate for a named detector:** `PassRole +
  batch:RegisterJobDefinition`. Caught today only by the incomplete-coverage
  backstop - never CLEAN, but not yet a named finding: batch's job role is assumed
  via ECS (`ecs-tasks`), so its PassRole principal semantics need care before it is
  added to the service catalog. Recorded honestly rather than hidden, and gated so
  it can never silently become CLEAN.

## Scope note

This measures coverage of the *modeled* privesc catalog: the tool reports the AWS
evaluation layers a policy reaches, not effective permissions (it has no account
state - group memberships, existing role trusts, SCPs beyond the supplied policy).
A method landing here means the tool surfaces the primitive from the policy text
alone. New published methods should be added to `corpus.mjs`; if the engine does
not yet catch one, that is a gap to close (or an explicit, documented
out-of-model limitation), never a silent pass.
