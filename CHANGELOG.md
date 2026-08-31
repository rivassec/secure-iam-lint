# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/rivassec/secure-iam-lint/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/rivassec/secure-iam-lint/releases/tag/v1.0.0
