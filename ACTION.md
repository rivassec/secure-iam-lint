# IAM Blast Radius GitHub Action

Scan your AWS IAM policies for their **potential blast radius** on pull requests
and pushes, and **fail closed** when the tool cannot analyze a policy - so
"could not analyze" never becomes a green check in your CI.

This Action wraps the same client-side engine that powers
<https://rivassec.com/tools/iam-blast-radius/>. It reports *potential* reach -
privilege-escalation paths, role-assumption reach, and data exposure - **not
effective permissions**. A single policy cannot see every AWS evaluation layer
(SCPs, permissions boundaries, session policies, resource policies, identity vs
resource intersection), so a finding means "this policy could grant this reach",
not "this principal effectively has it". Findings are graded by certainty, and
unknown / unsupported / malformed / could-not-analyze are **explicit states**,
never silently treated as "safe".

## What it does

- Reads policy **files** you point it at (Terraform-rendered JSON, static policy
  documents) and analyzes each one for a single, explicitly-declared policy
  family.
- Writes a SARIF 2.1.0 file and sets step outputs. It does **not** upload SARIF
  by default (see [Uploading to the Security tab](#uploading-to-the-security-tab)).
- Fails the check on any blocking finding **and** on any fail-closed
  could-not-analyze state.

### What it does NOT do

- It never runs Terraform, `npm install`, shell scripts, or any command your
  repo provides. Untrusted pull-request policy content stays **data**, never
  code. If you need Terraform-rendered policies, render them to JSON in an
  earlier step.
- It never auto-detects the policy family. You declare `family` explicitly;
  a wrong guess could fail open (treating an SCP or resource policy as an
  identity policy), so the Action refuses to guess.
- It makes no network calls, uses no `eval` or dynamic import, and does not log
  full policy documents (to avoid leaking ARNs / account ids into logs or the
  Security tab of private repos).

## Exit codes (the load-bearing contract)

The Action exposes the CLI exit code as the `exit-code` output and fails the
check on anything non-zero. A fail-closed "could not analyze" (exit `3`) is
**distinct** from a clean scan (exit `0`) and MUST NEVER collapse into success.

| Exit | Meaning | Check result |
| ---- | ------- | ------------ |
| `0` | Analyzed successfully; no findings at/above `fail-on`. | pass |
| `1` | Analyzed successfully; findings at/above `fail-on`. | FAIL |
| `2` | Usage / config error (missing/empty `family`, missing/empty `paths`, no matching files). | FAIL |
| `3` | Fail-closed could-not-analyze (unknown / unsupported / malformed / incomplete; includes a bad/unsupported `family` token or a policy whose shape does not match the declared family). | FAIL |
| `4` | Internal invariant error. | FAIL |

Multi-file runs use **worst-exit-code** semantics: if any file fails closed
(`3`) or produces blocking findings (`1`), the aggregate is that worst code. One
file failing closed while the aggregate reported `0` would be a fail-open bug;
the Action does not do that. An empty glob or a missing file is a usage error
(`2`), not a clean scan.

## Usage

### Without SARIF upload (default; `contents: read` only)

This scans policies and fails the job on findings or fail-closed states. It needs
only read access to your repository - no `security-events: write`.

```yaml
name: IAM policy scan
on: [pull_request]

permissions:
  contents: read

jobs:
  iam-blast-radius:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rivassec/secure-iam-lint@v1
        with:
          paths: policies/**/*.json
          family: identity
          fail-on: high
```

### Uploading to the Security tab

Add `github/codeql-action/upload-sarif` as a separate step to send results to the
GitHub code-scanning Security tab. **That step's job needs
`security-events: write`** - a permission the Action itself never requires. Keep
the scan step read-only and grant the write scope only where SARIF is uploaded.

```yaml
name: IAM policy scan
on: [pull_request]

permissions:
  contents: read
  security-events: write   # required ONLY for the upload-sarif step below

jobs:
  iam-blast-radius:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rivassec/secure-iam-lint@v1
        with:
          paths: policies/**/*.json
          family: identity
          fail-on: high
          sarif-output: iam-blast-radius.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()          # upload even when the scan step failed the job
        with:
          sarif_file: iam-blast-radius.sarif
```

Mixed repositories (identity policies and resource policies and SCPs in one tree)
run the Action **multiple times** with different `paths` globs and a different
`family` each time - one family per run, never auto-detected.

## Inputs

| Input | Required | Default | Description |
| ----- | -------- | ------- | ----------- |
| `paths` | yes | - | Newline-separated files or globs to scan (e.g. `policies/**/*.json`). An empty match is a usage error (exit `2`), not a clean scan. |
| `family` | yes | - | Policy family, declared explicitly and never auto-detected: `identity`, `role-trust`, `resource`, `permissions-boundary`, `session`, `scp`, `rcp`. |
| `subject-account` | no | - | AWS account id (12 digits) for account-aware checks (e.g. PassRole viability). |
| `partition` | no | - | AWS partition (`aws`, `aws-us-gov`, `aws-cn`, `aws-iso*`). No default on purpose: an omitted partition is "not asserted", not `aws`. A cross-partition role-viability verdict is trusted only when you supply a real partition; otherwise it is treated as unknown and fails closed (exit `3`). |
| `fail-on` | no | `high` | Minimum severity that fails the check: `critical`, `high`, `medium`, `low`, `info`, `none`. `none` does not turn a fail-closed `3` into `0`. |
| `sarif-output` | no | `iam-blast-radius.sarif` | Path to write the SARIF 2.1.0 output file. |

## Outputs

| Output | Description |
| ------ | ----------- |
| `sarif-path` | Path to the generated SARIF file. |
| `exit-code` | Aggregate exit code (worst code across all scanned files). |
| `findings-count` | Total findings emitted across all scanned files. |
| `blocking-findings-count` | Total findings at/above the `fail-on` threshold. |
| `analysis-status` | Aggregate analysis status: `complete`, `partial`, or `failed`. |

Outputs are always written **before** the Action fails the check, so a failing
job can still inspect `exit-code`, `analysis-status`, and the SARIF file.

## SARIF: security findings vs analyzer state

The SARIF separates real security findings from fail-closed analyzer state so a
consumer cannot misread one for the other:

- **Security findings** carry a `security-severity` property and a stable
  `ruleId` (the finding type). Severity maps to SARIF level: `critical`/`high`
  -> `error`, `medium` -> `warning`, `low`/`info` -> `note`.
- **Analyzer-state (fail-closed) results** carry `kind: "fail"`,
  `properties.category: "analysis-state"`, and `properties.failClosed: true`,
  and they **never** carry a `security-severity`. Their presence coincides with
  exit `3`.

Fingerprints (`partialFingerprints`) are computed on normalized semantic identity
(finding type + family + statement identity + normalized
action/resource/principal/condition), never on message text, line number, or key
order, so results dedupe cleanly across whitespace and path-mode changes.

## Permissions

- Default required permission is **`contents: read`**. The Action reads files and
  writes a SARIF file in the workspace; nothing more.
- Grant **`security-events: write` only** in a job that runs
  `github/codeql-action/upload-sarif`, and only on that job.

## Security guidance for consumers

### Pin by commit SHA for production

`@v1` is a moving major tag - convenient, but it can change under you. For
security-sensitive workflows, pin the Action (and `actions/checkout`,
`github/codeql-action/upload-sarif`) by full commit SHA:

```yaml
      - uses: rivassec/secure-iam-lint@<full-40-char-sha>  # v1.x.y
```

A moving `v1` tag is convenience, not maximum assurance; a pinned SHA is.

### Do NOT use `pull_request_target` for untrusted PRs

`pull_request_target` runs with a **read/write token and repository secrets** in
the context of your base branch while checking out the fork's code. Scanning
attacker-controlled PR policy content under that privileged token is a
well-known privilege-escalation foot-gun. Use the ordinary **`pull_request`**
trigger with a read-only token (as in the examples above). The engine is
deterministic with no network, `eval`, or dynamic import, so residual risk from
hostile policy content is limited - but the privileged trigger is still the wrong
tool. Keep the token read-only and treat every policy string as data.

## Supported families

One family per run, declared explicitly (never auto-detected):

| Family | Covers |
| ------ | ------ |
| `identity` | IAM identity (user/group/role) policies: escalation, PassRole chains, credential creation, data exfiltration reach. |
| `role-trust` | Role trust policies (`sts:AssumeRole`): who can assume the role. Synonym: `trust`. |
| `resource` | Resource-based policies (S3, KMS, SNS, SQS, per-service): public/cross-account exposure. |
| `permissions-boundary` | Permissions-boundary policies: analyzed as a ceiling, not a grant. |
| `session` | Session policies: analyzed as a session restriction, not a grant. |
| `scp` | Organizations Service Control Policies: guardrail semantics. |
| `rcp` | Organizations Resource Control Policies: guardrail semantics. |

A token outside this set, or a policy whose shape does not match the declared
family, fails closed with exit `3` rather than being guessed.

## Limits

The engine enforces defensive input caps. Exceeding a cap is a fail-closed
could-not-analyze (exit `3`), never a silent pass:

| Limit | Value |
| ----- | ----- |
| Max input size | 1 MiB (1048576 bytes) of raw UTF-8 per file |
| Max JSON nesting depth | 64 (enforced before parse, to bound recursion) |
| Max statements per policy | 1000 |
| Max actions per policy | 10000 |
| Max resources per policy | 10000 |

These are far larger than any real IAM policy (the AWS managed-policy hard cap is
about 6 KB) yet cheap to reject, and they bound the work an adversarial PR can
force. This Action is an MVP: built-in SARIF upload, Terraform plan parsing,
family auto-detection, baseline suppressions, and PR review comments are
intentionally out of scope.

## Versioning

Releases use immutable `vMAJOR.MINOR.PATCH` tags with a moving `v1` major tag for
convenience. The `v1` tag moves only for backward-compatible releases; the
changelog calls out any change to exit-code behavior, SARIF schema, rule ids, or
fingerprints. Pin by SHA when you need those guarantees frozen.

## License

MIT - see [LICENSE](LICENSE).
