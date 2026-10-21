# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Nothing yet.

## [1.2.0] - 2026-10-20

### Added

- **Baseline mode**: `baseline` / `baseline-output` Action inputs and CLI options
  accept a reviewed findings file so known findings don't fail the gate; acceptance
  dies on any identity change (file, rule, severity, principals, condition values).
  Format version 2; see the fingerprint entry below.
- **DB-AUTH** finding: `rds-db:connect` is IAM database auth (credential-equivalent);
  high unless every resource pins a concrete `dbuser:<cluster>/<user>`.
- **PASSROLE-UNSCOPED** finding: `iam:PassRole` on `*` (or any all-roles pattern)
  reports even without a companion launch action - it combines with whatever compute
  permission the holder has elsewhere.
- **OBJECT-ACL-WRITE** finding: `s3:PutObjectAcl` / `s3:PutObjectVersionAcl` can set
  objects public or grant them cross-account unless the bucket enforces
  BucketOwnerEnforced (which a policy can't show); high on `bucket/*` or broader,
  medium on a single named object.
- Condition modeling: `s3:ResourceAccount` / `aws:ResourceAccount` (a negated
  account guard is called out as covering same-account resources too) and the
  Cognito `cognito-identity.amazonaws.com:amr` sign-in state.
- Action catalog refresh (service coverage incl. `kinesis`, `rds-db`, `eks-auth`);
  unmodeled write/permissions actions from the AWS reference stay withheld so an
  Allow on them remains fail-closed `UNKNOWN_ACTION`.
- China-partition service principals: documented `.amazonaws.com.cn` spellings for
  `ec2` and `datapipeline`; under `aws-cn` the matcher considers both spellings for
  every service.

### Changed

- **SARIF fingerprints are now `iamBlastRadius/semanticIdentity/v2`** (breaking for
  dismissed alerts and baselines, once). The statement position is no longer part of
  a finding's identity, so inserting a statement above an accepted finding no longer
  re-opens it; identical findings in one file are told apart by an occurrence
  ordinal. `UNKNOWN_ACTION` / `UNSUPPORTED_CONDITION` fingerprints now include the
  full sorted offending set (dismissing one no longer covers a different one). The
  hash is SHA-256 truncated to 128 bits (was non-cryptographic cyrb53).
- Trust findings carry their trusted principals, and the SARIF fingerprint and
  baseline id bind to them: accepting a trust never covers a different account.
- Under `aws-cn`, an `iam:PassedToService` deny covering only one spelling (e.g.
  `StringNotEquals ec2.amazonaws.com.cn`) is no longer credited: the PassRole
  path reports and the scan fails closed (exit 3), since AWS may send either.
- `iam:PassedToService` matching is operator-correct (`(Not)Equals` compares
  literally; only `Like`/`Arn*` expand wildcards) and partition-aware: the
  matcher tests the spellings the asserted partition can send (`aws-cn` may
  use `<svc>.amazonaws.com.cn`, varying per service), and an unasserted or
  unrecognized partition is never coerced to `aws` before matching.
- `UNSUPPORTED_CONDITION` identities (fingerprints and baseline ids) include a
  canonical serialization of the affected statements' Condition blocks, so an
  acceptance never survives a condition-value edit.
- **Baseline file format is version 2.** Version 1 baselines are refused (exit `2`)
  with a message to regenerate; keys follow the same identity change. `baseline-output`
  warns when it writes `critical` entries.
- **DATA-EXFIL severity scales with resource breadth**: a single named secret or
  parameter is `medium`; `*`, account-wide patterns, path reads and anything
  ambiguous (variables, wildcard accounts, `NotResource`) stay `high`.
- Release version bumped to `1.2.0` (`package.json` and
  `VERSION_MANIFEST.releaseVersion`).

## [1.1.0] - 2026-10-09

### Added

- **COMPUTE-SESSION-TAKEOVER** escalation detector (13th family): names the "gain
  code-execution on an EXISTING role-bearing compute resource, then use its role"
  primitive - `ssm:SendCommand` / `ssm:StartSession`,
  `ec2-instance-connect:SendSSHPublicKey` /
  `ec2-instance-connect:SendSerialConsoleSSHPublicKey`, and
  `sagemaker:CreatePresignedNotebookInstanceUrl` (Rhino method 28). Needs no
  `iam:PassRole` and no code change; fires at high. Previously these were caught
  fail-closed only by the incomplete-coverage backstop; now they surface as a named
  finding. The privesc benchmark's SSM / EC2-Instance-Connect / existing-SageMaker
  -notebook cases move from backstop to named accordingly.
- **GitHub Action: `node24` runtime.** `action.yml` now declares `runs.using: node24`
  (was `node20`, which GitHub is retiring). The Action is still a plain ESM entry
  point (`action/index.mjs`) with no build step, bundled `dist`, or runtime npm
  dependencies; the Node runtime is provided by the runner. GitHub.com-hosted
  runners are the supported baseline. The npm package's `engines.node` is unchanged.
- **Action self-test coverage** (`.github/workflows/action-selftest.yml`): new cases
  assert both the step outcome and the `exit-code` output for an internal error
  (exit `4`, via an unreadable policy file), a mixed valid + malformed `paths` list
  (exit `3`, never `0`), an omitted `partition` on a verdict that depends on it
  (exit `3`, with an asserted-partition control at exit `1`), and one fixture per
  policy family (identity, role-trust, resource with and without `resource-arn`,
  permissions-boundary, session, SCP, RCP).
- **README "GitHub Action" section** for the GitHub Marketplace listing: usage
  (`rivassec/secure-iam-lint@v1` and a full-commit-SHA pin), required permissions,
  inputs/outputs, the exit-code contract (exit `3` is fail-closed, never a green
  check), and the supported-runner statement.
- **SARIF upload guidance**: README and `ACTION.md` now show a least-privilege
  pattern - a read-only `scan` job and a separate `upload` job that alone holds
  `security-events: write`, skips fork pull requests, never uses
  `pull_request_target`, pins `upload-sarif` by commit SHA, and keeps the check
  failed when the scan fails.

### Changed

- Release version bumped to `1.1.0` (`package.json` and
  `VERSION_MANIFEST.releaseVersion`).

## [1.0.0] - 2026-08-29

First stable release. `package.json` is at `1.0.0`; the `v1.0.0` git tag - which
marks the release and makes the compare/tag links below resolve - is pending.

### Added

- **Browser-pure analyzer** (`analyze()`): pastes an AWS IAM policy and computes
  its *potential* blast radius - privilege-escalation paths, role-assumption
  reach, and data exposure - entirely client-side under a strict
  Content-Security-Policy that blocks the page from making network requests
  (`connect-src 'none'`) and loads no third-party scripts.
- **Node CLI** (`iam-br`) and a headless `scan()` API sharing the same engine,
  with policy-family selection (identity / resource / role-trust / scp-rcp /
  session / permissions-boundary) and exit codes suitable for CI gating.
- **SARIF exporter** and a **GitHub Action** for CI integration.
- Escalation-path detection (12 families) and capability rules, graded by
  certainty, reporting the AWS evaluation layers rather than asserting effective
  permissions.

### Security

- **Fail-closed guarantee**: `analyze()` / `scan()` never read CLEAN on a policy
  that carries a real capability; when a verdict cannot be determined the engine
  reports incomplete coverage, and the browser is never more permissive than the
  CLI (enforced by a determinism + parity fuzzer).
- Hardened through a multi-round adversarial security review that found and fixed
  a series of fail-open classes, including: unicode / case-fold / homoglyph
  action-token spoofs; de-spoofed Deny / condition-key suppression; bypassable
  `iam:PassedToService` qualifiers; cross-account resource-policy-write grants;
  standalone compute-code-overwrite escalation; and cataloged-but-silent IAM
  actions. Each fix ships with a regression test.
- CI supply-chain hardening: CodeQL SAST, ClusterFuzzLite fuzzing, OpenSSF
  Scorecard, Dependabot, a committed fail-open-lint gate (guard-target +
  active-hotspot baseline), and npm publish with build provenance via trusted
  publishing (OIDC, no long-lived token).
- Independently validated on three axes: a security-mutation harness reintroduces
  each fixed fail-open into the engine and confirms the test suite catches it
  (9/9 killed); a ground-truth benchmark grades the analyzer against the published
  Rhino Security Labs privilege-escalation catalog - all 28 numbered methods fail
  closed, none read CLEAN; and a differential-oracle harness cross-checks the
  engine against AWS's own `iam:SimulateCustomPolicy` evaluator - an offline
  self-check runs in CI, and pointed at a real AWS account it verifies the engine
  never reads CLEAN on a policy AWS reports as allowing the action.

[Unreleased]: https://github.com/rivassec/secure-iam-lint/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/rivassec/secure-iam-lint/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/rivassec/secure-iam-lint/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rivassec/secure-iam-lint/releases/tag/v1.0.0
