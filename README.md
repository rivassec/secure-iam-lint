# secure-iam-lint

[![CI](https://github.com/rivassec/secure-iam-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/rivassec/secure-iam-lint/actions/workflows/ci.yml) [![Security](https://github.com/rivassec/secure-iam-lint/actions/workflows/security.yml/badge.svg)](https://github.com/rivassec/secure-iam-lint/actions/workflows/security.yml)

**An AWS IAM policy blast-radius analyzer.** Paste an IAM policy and see its
*potential blast radius* - privilege-escalation paths, role-assumption reach, and
data exposure - computed entirely client-side, with a strict Content-Security-Policy
that blocks all outbound connections. It reports *potential* reach, not effective
permissions, and it **fails closed**: unknown, unsupported, malformed, and
could-not-analyze are explicit states, never silently treated as "safe".

Live: <https://rivassec.com/tools/iam-blast-radius/>

## What it does

- Analyzes seven AWS policy families - identity, role-trust, resource
  (S3/KMS/SNS/SQS, per-service), permissions-boundary, session, SCP, RCP - each
  analyzed or explicitly failed closed, never fail-open.
- Correlates privilege-escalation chains (e.g. `iam:PassRole` -> `ec2:RunInstances`),
  with account/partition-aware PassRole viability.
- Grades findings by certainty and reports the AWS evaluation layers a single
  policy cannot see, so "potential" never masquerades as "effective".
- Ships as vanilla ES-module JavaScript with **no build step**; the committed
  code is exactly what runs. Validated by 1,488 unit + security tests and three
  external adversarial suites.

## Repository layout

    content/tools/iam-blast-radius/   # the shipped web tool (served verbatim; engine + UI)
      engine/                         # the analysis engine (pure, DOM-free, Node-importable)
    tools/iam-blast-radius/           # dev harness (NOT served)
      tests/  fixtures/               # node --test suite + fixtures
      docs/                           # architecture, threat-model, per-family semantics, roadmap
      ralph/                          # the fail-closed build workflows
      prd.json  progress.md

This layout is inherited from the tool's origin in the rivassec.com blog repo and
is intentionally preserved so the same tree can be served on the blog and consumed
as a package. A cleaner top-level layout (`engine/`, `web/`, `cli/`, `action/`)
lands with the CLI work below.

## Develop

    cd tools/iam-blast-radius
    node --test "tests/**/*.test.js"     # requires Node >= 21
    npm run gate:no-network              # no network APIs in shipped JS
    npm run gate:no-unsafe-dom           # no innerHTML/eval/unsafe DOM

## Use it in CI

The same engine runs headless, with a fail-closed exit-code contract so
"could not analyze" never passes a gate silently.

- **GitHub Action** - drop `secure-iam-lint` into any workflow to scan IAM
  policies on PRs. It reports *potential blast radius, not effective
  permissions*, and fails the check on findings **and** on fail-closed
  could-not-analyze states (a distinct exit `3`, never a green check). Default
  required permission is `contents: read`; SARIF upload to the Security tab is
  opt-in. See **[ACTION.md](ACTION.md)** for the two example workflows (with and
  without SARIF upload), input/output tables, SHA-pinning and
  `pull_request_target` guidance, supported families, and limits.
- **Headless CLI + SARIF 2.1.0** - the `iam-br` CLI the Action wraps, with the
  full `0`/`1`/`2`/`3`/`4` exit-code contract. See
  `tools/iam-blast-radius/docs/sarif-cli-design.md`. `--format json` is a
  **byte-faithful machine artifact** (not display-safe): it emits policy-derived
  strings verbatim so downstream tooling gets exact bytes, and hostile
  Unicode/bidi rides through inert. When a human reads findings, use
  `--format sarif` (or the browser tool) - both neutralize the visual spoof
  class - and never trust raw `cat report.json` in a bidi-aware terminal as a
  review surface.

## GitHub Action

Scan IAM policy files in CI. The Action reads policy **files only** - it never
runs Terraform, npm, a shell, or any repo-provided command - and it reports
*potential blast radius, not effective permissions*. Full input/output tables,
limits and family notes live in **[ACTION.md](ACTION.md)**.

### Usage

```yaml
name: IAM policy scan
on: [pull_request]

permissions:
  contents: read

jobs:
  iam-blast-radius:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: rivassec/secure-iam-lint@v1
        with:
          paths: policies/**/*.json
          family: identity
```

`permissions: contents: read` is all the Action needs. `@v1` is a moving major
tag; for security-sensitive workflows pin the full commit SHA instead:

```yaml
      # Resolve the commit for a release tag and pin it (keep the version comment):
      #   git ls-remote https://github.com/rivassec/secure-iam-lint 'refs/tags/v1.2.0^{}'
      - uses: rivassec/secure-iam-lint@v1.2.0
```

Each GitHub Release lists the exact commit SHA for that tag; copy it into the
`uses:` line in place of `v1.2.0` for a pin that cannot move.

### Inputs and outputs

| Input | Required | Notes |
| ----- | -------- | ----- |
| `paths` | yes | Newline-separated files or globs, e.g. `policies/**/*.json`. |
| `family` | yes | `identity`, `role-trust`, `resource`, `permissions-boundary`, `session`, `scp`, `rcp` or `scp-rcp` (also `trust` for `role-trust`). Never auto-detected: one family per run, so a mixed repo runs the Action once per family. |
| `resource-arn`, `resource-type`, `resource-account` | for `resource` | The resource the policy is attached to. Without `resource-arn` the `resource` family fails closed. |
| `subject-account` | no | 12-digit account id for account-aware checks (e.g. `iam:PassRole` viability). |
| `partition` | no | `aws`, `aws-us-gov`, `aws-cn`, ... Deliberately has **no default**: an omitted partition is "not asserted", and any verdict that depends on it fails closed (exit `3`). |
| `fail-on` | no | Minimum severity that fails the check (default `high`; `none` disables). |
| `sarif-output` | no | SARIF 2.1.0 path, relative to the workspace (default `iam-blast-radius.sarif`). |
| `baseline`, `baseline-output` | no | Read / write a committed baseline of accepted results, so only NEW results fail. Each result is accepted individually; usage, internal and most fail-closed states never are. See [ACTION.md](ACTION.md#accepting-known-results-baseline). |
| `budget-ms`, `max-files`, `max-total-bytes`, `max-sarif-results`, `max-sarif-bytes` | no | Resource ceilings; breaching one fails closed rather than reporting a partial scan clean. See [ACTION.md](ACTION.md). |

Outputs: `exit-code`, `analysis-status` (`complete` / `partial` / `failed`),
`findings-count`, `blocking-findings-count`, `sarif-path`, plus `baselined-count` /
`baseline-stale-count` when a baseline is given. Outputs are written before the step
fails, so they are readable under `continue-on-error` - but prefer a baseline, which
still fails on new results. A mixed repo runs one step per family (see
[ACTION.md](ACTION.md#mixed-repos-one-step-per-family)).

### Exit-code contract

| Exit | Meaning | Check |
| ---- | ------- | ----- |
| `0` | Analyzed; nothing at or above `fail-on`. | pass |
| `1` | Analyzed; findings at or above `fail-on`. | **fail** |
| `2` | Usage or configuration error (missing `family`/`paths`, no matching files). | **fail** |
| `3` | **Fail closed**: could not analyze (malformed, unsupported, unknown, incomplete, over a resource ceiling, unreadable subtree, truncated walk). | **fail** |
| `4` | Internal error. | **fail** |

Exit `3` is never a green check. Multi-file runs report the worst code, so one
unanalysable file fails the run even when every other file is clean. Note that the
`resource` family currently always reports incomplete coverage (it sees the
resource policy but not the identity side), so it reports exit `3` by design.

### Supported runners

The Action is a JavaScript action on the `node24` runtime, supplied by the runner;
nothing is installed or bundled. **GitHub.com-hosted runners** are the supported
baseline. Self-hosted runners and GitHub Enterprise Server must provide an Actions
runner recent enough to offer `node24`; they are not part of the tested matrix.

### Uploading SARIF to code scanning (safe pattern)

Uploading to the Security tab needs `security-events: write`, which should never
sit next to a step that processes untrusted policy content. Split the work in two
jobs: `scan` runs read-only on every trigger and hands the SARIF over as an
artifact; `upload` is the only job holding `security-events: write`, and it is
skipped for fork pull requests (which could not receive that token anyway).

```yaml
name: IAM policy scan
on:
  push:
    branches: [main]
  pull_request:          # NOT pull_request_target - see below

permissions: {}

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: rivassec/secure-iam-lint@v1   # or the full-SHA pin above
        with:
          paths: policies/**/*.json
          family: identity
          sarif-output: iam-blast-radius.sarif
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        if: always()                        # keep the SARIF even when the scan failed
        with:
          name: iam-blast-radius-sarif
          path: iam-blast-radius.sarif
          if-no-files-found: ignore
          retention-days: 1

  upload:
    needs: scan
    # always(): upload even when `scan` failed (findings / fail-closed). The `scan` job
    # still shows as failed, so the check stays red - uploading never turns it green.
    # Same-repo PRs and pushes only: fork PRs are skipped.
    if: >-
      ${{ always() &&
          (github.event_name != 'pull_request' ||
           github.event.pull_request.head.repo.full_name == github.repository) }}
    runs-on: ubuntu-latest
    permissions:
      contents: read          # upload-sarif reads repo metadata
      security-events: write  # the ONLY job with this permission
    steps:
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: iam-blast-radius-sarif
      - uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        with:
          sarif_file: iam-blast-radius.sarif
          category: iam-blast-radius    # keep stable so alerts track across runs
```

Notes:

- The `upload` job does not check out or execute repository code; it only forwards
  a file. If `scan` was cancelled or produced no SARIF, there is nothing to
  download and the upload job fails visibly rather than uploading a stale file.
- Do **not** switch this to `pull_request_target`: it runs with a write token and
  secrets while checking out attacker-controlled fork content. The skipped-for-forks
  `if:` above is what keeps `security-events: write` away from fork PRs.
- Use a distinct `category` per scan (for example one per `family`) when you run
  the Action more than once, so uploads do not overwrite each other.
- The pins above are the versions current at the v1.1.0 release; let Dependabot
  keep your copies current (it also rewrites the `# vX.Y.Z` comments).

## History

This repository began as a Python IAM-policy linter (2025). It was repurposed in
2026 to host the far more capable JavaScript blast-radius analyzer. The original
Python linter is preserved at the `v0-python-legacy` tag and the
`legacy/python-linter` branch.

## License

MIT - see [LICENSE](LICENSE).
