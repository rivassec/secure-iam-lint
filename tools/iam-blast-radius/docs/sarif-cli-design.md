# SARIF export + headless CLI/CI mode - design record

Status: design (not yet built). Captures the SARIF + CLI direction, reviewed
with Openclaw (gpt-5.5). ASCII only.

## Position

Build the CLI first, SARIF second. The CLI owns CI gating semantics; SARIF is an
interchange format for GitHub code scanning and other consumers, NOT the source
of truth for whether a build should fail. A CI gate must be enforced by the CLI
exit code, never by a downstream tool's interpretation of the SARIF.

## Architecture: one engine, two adapters

The shipped `engine/*.js` stays pure browser-safe ES modules. Adapters wrap it:

- Browser adapter: DOM, file paste, Markdown/JSON export (exists today).
- CLI adapter (`cli/iam-br.mjs`): `node:fs`, stdin/stdout/stderr, argv, exit codes.
- SARIF adapter: consumes engine output only; no I/O, no Node APIs.

Hard rule: nothing in the browser-imported engine graph may import `node:fs`,
`node:path`, `process`, `Buffer`, or any Node-shimmed dependency. Enforced by a
test that statically scans the browser dependency graph for `node:` / bare-Node
imports (extends the existing no-network / no-unsafe-DOM gate philosophy).

## Fail-closed states are first-class output (the load-bearing decision)

Do NOT encode `unknown / unsupported / malformed / timeout / invalid` as "no
findings." The engine result carries an explicit analysis status alongside
findings, e.g.:

- `status: "complete" | "partial" | "failed"`
- `analysisStates: [...]` (the specific fail-closed reasons)
- `findings: [...]`

CI must fail on `partial` or `failed`. This is the whole point of the tool - the
same principle the blog post is about - carried into the CI gate: "could not
analyze" must never pass a gate silently.

## CLI exit-code contract

- `0` analyzed successfully, no findings at/above threshold
- `1` analyzed successfully, findings at/above threshold
- `2` CLI usage / input error
- `3` fail-closed analysis state (unknown / unsupported / malformed / incomplete)
- `4` internal invariant error

CI treats `1`, `2`, `3`, `4` as failed. Note `3` is DISTINCT from `1`: a
fail-closed "could not analyze" is not the same as "clean," and must not be
collapsed into success. No `--ignore-unknown` in the MVP (do not build the
foot-gun that lets unknown pass a gate).

## CLI UX

    iam-br --family identity --subject-account 123456789012 --partition aws policy.json
    iam-br --family resource --format sarif --output results.sarif policy.json
    iam-br --family scp --threshold high < policy.json

Flags: `--family` (identity|role-trust|resource|permissions-boundary|session|scp|rcp),
`--subject-account`, `--partition` (aws|aws-us-gov|aws-cn), `--format` (json|sarif),
`--output`, `--threshold` (critical|high|medium|low|info|none), `--artifact-uri`,
`--repo-root`, `--pretty`, `--quiet`, `--version`, `--help`.

Defaults: read stdin if no path; JSON to stdout; diagnostics to stderr; default
threshold `high`. Missing `--family` is a usage error (exit 2) - do NOT
auto-detect family (auto-detection is the kind of guess this tool refuses).

## SARIF 2.1.0 mapping

- `runs[0].tool.driver.name` = `IAM Blast Radius`; `semanticVersion` = tool version.
- `tool.driver.rules[]` = one `reportingDescriptor` per finding TYPE (not instance).
- `result.ruleId` = stable finding-type id; `result.message.text` = deterministic summary.
- `result.properties`: `certainty` (preserved exactly), `evidence`, `policyFamily`,
  optional `blastRadius` (graph node/edge refs), `jsonPointer` (statement identity).

Severity -> level + security-severity:

- critical -> `level: error`, `security-severity: "9.0"`
- high     -> `level: error`, `security-severity: "7.0"`
- medium   -> `level: warning`, `security-severity: "5.0"`
- low      -> `level: note`, `security-severity: "2.0"`
- info     -> `level: note`, omit security-severity (or "0.0")

Location model (no real file when a policy is pasted):

- File input: `artifactLocation.uri` = repo-relative if `--repo-root`, else as supplied.
- Stdin: `uri: "stdin"` unless `--artifact-uri` given.
- Browser/pasted: default `uri: "pasted-policy.json"`, caller-overridable.
- JSON pointer in `properties.jsonPointer`; `region.startLine/startColumn` when
  available, else point at the whole artifact.

Analyzer-state (fail-closed) findings are SEPARATED from security findings so a
CI consumer cannot misread them:

- Unsupported family / model gap: `ruleId: analysis.unsupported_policy_family`,
  `level: error`, `kind: fail`, `properties.category: "analysis-state"`,
  `properties.analysisState: "unsupported"`, `properties.failClosed: true`,
  NO `security-severity`.
- Unknown viability (analysis completed, certainty unknown): emit the finding
  with `certainty: unknown` and gate per configured threshold policy.
- Required context missing (correctness cannot be established): emit an
  analyzer-state result AND the CLI exits `3`.

## partialFingerprints (stable dedup)

Fingerprint on normalized SEMANTIC identity: finding type + policy family + JSON
pointer / statement identity + normalized action/resource/principal/condition +
subject-account/partition only when they affect viability. NEVER fingerprint on
message text, line number alone, timestamps, absolute local paths, or object key
order.

## Packaging (no bundler)

Native ESM: `"type": "module"`, `"bin": { "iam-br": "./bin/iam-br.mjs" }`,
`#!/usr/bin/env node`, files directly runnable. Avoid dependencies unless clearly
worth the supply-chain cost; any SARIF schema validator stays dev-only.

## Deterministic tests

- Same engine fixtures pass in browser AND Node (proves one-engine claim).
- CLI stdin input; CLI file input; JSON golden snapshots.
- SARIF output validated against the SARIF 2.1.0 schema (dev-only validator).
- Stable `partialFingerprints` across whitespace, key-order, and
  absolute-vs-repo-relative path modes.
- Exit-code matrix: assert each of 0/1/2/3/4 is produced by a crafted input -
  especially that a fail-closed input yields `3`, never `0`.

## Biggest fail-OPEN risks for the CI gate (adversarial targets)

1. A fail-closed state (`partial`/`failed`) collapsing to exit `0`. Highest risk.
2. `--threshold none` or a future `--ignore-unknown` letting unknown pass. Do not build it.
3. A `node:` import leaking into the browser engine graph (breaks CSP purity).
4. Non-deterministic fingerprints causing duplicate/alert-churn in code scanning.

## MVP scope vs deferrals

MVP: CLI adapter over the existing engine, `--family` + context flags, JSON
output, the full exit-code contract, the browser-graph purity test. Then the
SARIF adapter + schema-validated golden tests. Defer: multi-policy pack input
(that is the separate layered-analysis design), auto family detection (never),
`--repo-root` region mapping refinements.
