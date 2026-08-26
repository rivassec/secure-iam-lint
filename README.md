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
  `tools/iam-blast-radius/docs/sarif-cli-design.md`.

## History

This repository began as a Python IAM-policy linter (2025). It was repurposed in
2026 to host the far more capable JavaScript blast-radius analyzer. The original
Python linter is preserved at the `v0-python-legacy` tag and the
`legacy/python-linter` branch.

## License

MIT - see [LICENSE](LICENSE).
