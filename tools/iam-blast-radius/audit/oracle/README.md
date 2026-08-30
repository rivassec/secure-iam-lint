# AWS differential oracle

Cross-checks the engine against AWS's own policy evaluator instead of against
tests we wrote. AWS IAM is the ground truth for whether a policy grants an action;
this harness asks AWS and compares.

## What it does

For each benchmark policy it calls `iam:SimulateCustomPolicy` - which evaluates the
policy DOCUMENT you supply and returns allowed / explicitDeny / implicitDeny per
action - then runs the engine on the same policy and checks two things:

- **Fail-closed (enforced).** If AWS says a dangerous action is *allowed*, the
  engine must not read CLEAN on that policy. An AWS-confirmed grant the engine calls
  clean is a real fail-open, backed by AWS ground truth. Any such case exits non-zero.
- **False positives (advisory).** If the engine names an action in a finding but AWS
  says that action is *explicitly denied* by the same policy, it is reported as a
  review candidate - not a failure, since the engine models potential blast radius
  and may over-warn deliberately.

## Safety

Read-only. `SimulateCustomPolicy` evaluates only the policy JSON passed to it; it
creates and modifies nothing and reads no account state. It is still an API call in
whatever account the profile points at, so the harness **refuses to guess** - you
pass the profile explicitly.

## Usage

From `tools/iam-blast-radius/`:

```bash
# Offline logic check (canned AWS response, no network, no creds):
node audit/oracle/aws-differential.mjs --dry-run

# Real differential against AWS (pick a profile you are authorized to use):
node audit/oracle/aws-differential.mjs --profile <name> [--region us-east-1]
```

Real runs need the AWS CLI on PATH. The corpus of policies comes from
`../benchmark/corpus.mjs` (Rhino Part 1 + Part 2 + the second tier).

## Note on scope

This validates the ACTION-level grant (does the policy allow the dangerous action
at all), which is what `SimulateCustomPolicy` answers reliably. It does not model
cross-account PassRole viability, service-linked behavior, or condition-key runtime
values - those remain the engine's own conservative, fail-closed judgments.
