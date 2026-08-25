# GitHub Action plan - make IAM Blast Radius usable in other people's CI

Status: plan (not yet built). Target AFTER Phase 14. Reviewed with Openclaw
(gpt-5.5). Builds on `sarif-cli-design.md` (the CLI + SARIF are the prerequisite
plumbing this Action wraps). ASCII only.

## Goal

Ship a GitHub Action so other repos can scan their AWS IAM policies
(Terraform-rendered JSON, policy files) on PRs and get results in the PR / their
Security tab - carrying the tool's fail-closed guarantee into a consumer's CI:
"could not analyze" must never become a green check in someone else's pipeline.

## Prerequisite (Phase 15): the headless CLI + SARIF

Per `sarif-cli-design.md`. The Action is a thin wrapper over the CLI, so the CLI
must exist first with:
- exit-code contract: `0` clean / `1` findings >= threshold / `2` usage error /
  `3` fail-closed could-not-analyze / `4` internal error.
- `analysisStatus: complete|partial|failed` in the result.
- SARIF 2.1.0 output separating security findings from analyzer-state
  (fail-closed) findings.
The scan logic must be a callable module (not only a process) so the Action can
import it and read a structured result, not scrape stdout.

## Action-layer decisions (Phase 16)

### 1. JavaScript action (`runs.using: node20`), not Docker or composite
- `main: action/index.mjs`; imports the CLI scan module directly. No build step,
  no bundled `dist`, no runtime npm deps if avoidable.
- Docker loses: slow start, larger supply-chain surface, harder to audit, poor
  fit for pure ESM.
- Composite loses: shell quoting/glob handling is brittle and it is easy to
  accidentally swallow the exit code in shell glue - fatal for a fail-closed tool.

### 2. Default does NOT upload SARIF
- Default: scan -> write SARIF file -> set outputs -> pass/fail on exit code.
- Users add `github/codeql-action/upload-sarif` themselves when they want the
  Security tab. This keeps the Action's default permission at `contents: read`;
  `security-events: write` is opt-in, granted by the consumer's workflow, not
  demanded by us. Built-in upload is DEFERRED (more API code, more fork-PR
  permission foot-guns).

### 3. Exit `3` must fail the check (the load-bearing rule)
- The Action fails on `1`, `2`, `3`, and `4`.
- Single most important thing to get right: NEVER turn CLI exit `3` (fail-closed
  "could not analyze") into a warning, annotation-only result, SARIF-only result,
  or green check. This is the whole point of the tool, enforced in a stranger's CI.

### 4. No execution of consumer repo content
- The Action reads policy FILES only. It never runs Terraform, `npm install`,
  shell scripts, or any repo-provided command. Users who want Terraform-rendered
  policies produce JSON in a prior step. Untrusted PR content stays DATA, not code.

### 5. Require `family` in the MVP (no auto-detection)
- Auto-detecting the policy family can fail OPEN (guess identity when the file was
  an SCP/RCP/resource policy). Mixed repos run the Action multiple times with
  different globs/families.

## MVP `action.yml`

    name: IAM Blast Radius
    description: Scan AWS IAM policies for potential blast radius; fail closed on unknown analysis states.
    inputs:
      paths:            { description: Newline-separated files or globs to scan., required: true }
      family:           { description: identity|role-trust|resource|permissions-boundary|session|scp|rcp, required: true }
      subject-account:  { description: AWS account id for account-aware checks (e.g. PassRole viability)., required: false }
      partition:        { description: AWS partition., required: false, default: aws }
      fail-on:          { description: Minimum severity that fails the check., required: false, default: high }
      sarif-output:     { description: SARIF output path., required: false, default: iam-blast-radius.sarif }
    outputs:
      sarif-path:              { description: Path to the generated SARIF file. }
      exit-code:               { description: IAM Blast Radius exit code. }
      findings-count:          { description: Number of findings emitted. }
      blocking-findings-count: { description: Findings at/above fail-on threshold. }
      analysis-status:         { description: complete, partial, or failed. }
    runs:
      using: node20
      main: action/index.mjs

`upload-sarif` input stays out until built-in upload is actually implemented.
Use `paths` (plural) - real repos have many policy files.

## Wrapper exit handling (the correct pattern)

    const result = await scan(inputs)   // callable module, returns {exitCode, reason, sarif, counts, status}
    writeSarif(result.sarif, inputs.sarifOutput)
    setOutputs(result)                  // ALWAYS write outputs first
    if (result.exitCode !== 0) {
      core.setFailed(`IAM Blast Radius failed (exit ${result.exitCode}): ${result.reason}`)
      process.exitCode = result.exitCode
    }

Banned: `try { await scan() } catch { process.exit(0) }`. Never downgrade exit `3`.

## Multi-file aggregation (fail-open trap)

Scanning many files uses WORST-exit-code semantics: if any file fails closed
(exit `3`) or produces blocking findings (exit `1`), the aggregate is that worst
code. One file failing closed while the aggregate exits `0` is a top fail-open bug.
Missing files / empty glob is NOT a clean scan - it is a usage error (exit `2`).

## Consumer security guidance (goes in README)

- Pin by full commit SHA for production; `@v1` is convenience, not max assurance.
- Do NOT use `pull_request_target` for untrusted PR scans; prefer `pull_request`
  with a read-only token.
- Grant `security-events: write` only in workflows that upload SARIF.
- Default required permission is `contents: read`.
- Residual risk from attacker-controlled PR policy content is limited (engine is
  deterministic, no eval, no network, no dynamic import), but still: enforce file
  size + statement-count caps, cap SARIF result count, treat every policy string
  as data, and do NOT log full policy documents (avoid leaking ARNs/account ids
  into logs or the Security tab of private repos).

Recommended consumer workflow (least privilege):

    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<sha>
      - uses: rivassec/iam-blast-radius-action@<sha>
        with: { paths: policies/**/*.json, family: identity, fail-on: high, sarif-output: iam-br.sarif }
      - uses: github/codeql-action/upload-sarif@<sha>   # only if they want the Security tab
        if: always()
        with: { sarif_file: iam-br.sarif }
        # this step's job needs: security-events: write

## Biggest fail-open / permission-leak risks (adversarial targets)

1. CLI exit `3` becomes Action success (top risk).
2. Wrapper catches an error and continues / exits 0.
3. Multi-file: one file fails closed but aggregate exits `0`.
4. Empty/missing glob treated as a clean scan.
5. Analyzer-state SARIF emitted as `note` while the Action exits `0`.
6. Family omitted and auto-detected wrong (why MVP requires family).
7. `pull_request_target` running a privileged token against fork PR content.
8. Built-in upload forcing `security-events: write` on users who only wanted a file.
9. Action logging full policy documents from private repos.

## Self-tests (in-repo workflows)

A test matrix asserting BOTH the step outcome AND the exit-code output:
- known-good -> success, exit `0`, SARIF generated.
- known-bad (`continue-on-error: true`) -> step outcome failure, exit `1`, SARIF has expected ruleId.
- malformed -> failure, exit `3`, analyzer-state SARIF result present.
- unsupported family/state -> failure, exit `3`.
- usage error (bad family / missing paths) -> exit `2`.
- internal error fixture (if injectable) -> exit `4`.
One push-to-main workflow exercises the real SARIF upload (`contents: read` +
`security-events: write`); do not expect it to behave identically on fork PRs.
`act` is fine for wrapper smoke tests but is NOT authoritative for code-scanning
upload, token permissions, or the fork-PR model - do not use it as the release gate.

## Versioning + Marketplace

- Immutable `vMAJOR.MINOR.PATCH` release tags; a moving `v1` major tag for
  convenience; SHA pinning recommended for security-sensitive workflows.
- Move `v1` only for backward-compatible releases. Changelog MUST call out
  changes to: exit-code behavior, SARIF schema, rule ids, fingerprints.
- Minimal credible listing: what it does ("potential blast radius, not effective
  permissions"), fail-closed behavior + exit codes, required permissions (default
  `contents: read`; upload path `security-events: write`), two example workflows
  (with and without SARIF upload), input/output tables, pinning guidance, the
  `pull_request_target` warning, supported families, and the limits (max file
  size / statements / results).

## Build sequence

Phase 15 (prereq): CLI + SARIF per `sarif-cli-design.md`, scan logic as a
callable module, exit-code matrix + browser-graph purity test.

Phase 16 (the Action):
1. Ensure scan logic is importable as a module returning a structured result.
2. `action/index.mjs` wrapper (input parsing, glob resolution).
3. `action.yml` (MVP shape above).
4. Multi-file aggregation with strict worst-exit-code semantics.
5. Emit SARIF to requested path; write outputs BEFORE failing.
6. Self-test workflows (clean / finding / malformed=fail-closed / usage error).
7. README: usage, permissions, SHA-pinning, `pull_request_target` warning.

Oliver's manual steps (outward-facing): tag `v1.0.0`, move `v1`, submit the
Marketplace listing. I prepare everything up to the tag; publishing stays your call.

## Deferred (not in MVP)

Built-in SARIF upload, family auto-detection, Terraform plan parsing, OIDC/AWS
integration, config-file discovery, baseline suppressions, PR review comments,
inline annotations beyond SARIF, monorepo auto-discovery, upload retry logic.
