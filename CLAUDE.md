# Working on secure-iam-lint

Notes for agents and humans changing this repo. The README covers what the tool does;
this file covers the rules that are not obvious from the code.

## The one rule

The tool is **fail-closed**: exit 0 clean, 1 findings, 2 usage, 3 could-not-analyze,
4 internal. Policy files are attacker-controlled (a fork PR owns the JSON). Never make a
change that can turn a 1 or 3 into 0 without an explicit, documented opt-in (like
`baseline`). "Unsupported does NOT mean safe."

## Before you push

Run `scripts/ci-local.sh` (about 20 s). It mirrors the CI test, hardened-runtime, graph and
csp jobs, and restores `audit/lint/hotspots.json`, which the audit suite rewrites as a side
effect. It exits 0 only when every gate ran and passed; a skipped gate is exit 2.
`--quick` skips the audit and golden suites. Dev deps for madge / typecheck:
`(cd tools/iam-blast-radius && npm ci --ignore-scripts)`.

Not covered locally: Playwright e2e (runs in CI only when web files change), actionlint,
zizmor, osv-scanner, CodeQL, fuzzing. Two `audit/golden-corpus/packaging.test.js` cases
((b) `npx iam-br`, (d) bin shim) fail on some dev boxes even on unmodified `main`;
`ci-local.sh` reports them as KNOWN.

## Traps that cost retries

- **Golden snapshots.** After an intended SARIF / output change, regenerate with
  `node audit/golden-corpus/capture.mjs --update` (in `tools/iam-blast-radius`), then
  PROVE only the intended field changed: strip that field from old and new snapshots and
  compare. Never regenerate to make an unexplained diff go away.
- **Fail-open lint allowlist** (`audit/lint/allowlist.json`) entries are pinned to a line.
  Editing the file above them moves the line; re-pin after edits. Only allowlist a hotspot
  that really is fail-closed (e.g. it rejects the whole input as exit 2), with a reason.
  Prefer restructuring (e.g. one shared helper) over a new allowlist entry.
- **Typecheck ratchet** counts errors per signature. A JSDoc block must sit directly above
  its function: a helper inserted between a JSDoc block and its function attaches the
  `@param`s to the wrong function and fails the ratchet.
- **gitleaks**: a 64-hex value next to a field named like `key` trips `generic-api-key`.
  Name such fields `id` / `...Id` (see `cli/baseline.mjs`).
- **`cli/sarif.mjs` is pure** (no Node APIs, no I/O). Compute anything that needs
  `node:crypto` elsewhere and pass it in on the result (see `result.baseline`).
- **Every string in SARIF output is attacker-influenced.** Message tokens go through the
  existing sanitizers (`inertLeaf`, `inertTokenList`, `sanitizeStateMessage`); the
  suite asserts no `](` survives anywhere in the serialized SARIF.
- **Runner log lines** (stderr in `action/index.mjs`) must never echo an input value: a
  value starting `::` forges a workflow command. Key hints by reason code.
- **Engine import cycles**: `madge` runs in CI. `escalation-reachability.js` imports
  `conditions.js`, so shared constants are mirrored with a test pinning them equal.
- **Action catalog**: `scripts/gen-aws-action-catalog.mjs` regenerates
  `engine/catalog-aws-ref.js` from the AWS Service Authorization Reference (network,
  dev-only). Bump `ACTION_CATALOG_VERSION`/`DATE` in `catalog.js` and the manifest in
  `version.js`. Curated `CATALOG_DATA` entries always win over the generated data.

## Reproducing a bug report

Check out the reported tag in a worktree and run the real entry points, not just the
engine. The Action reads inputs from env, and hyphenated names (`INPUT_FAIL-ON`,
`INPUT_SARIF-OUTPUT`) must go through `env` (zsh refuses to `export` them):

```sh
env GITHUB_WORKSPACE=$PWD GITHUB_OUTPUT=$PWD/out.txt INPUT_PATHS=p/case.json \
  INPUT_FAMILY=identity INPUT_PARTITION=aws "INPUT_FAIL-ON=high" \
  "INPUT_SARIF-OUTPUT=res.sarif" node action/index.mjs; echo "exit=$?"
```

Run each problem case next to a control that differs only in the thing under test.

## Branches and PRs

Personal repo: commit as `rivassec <rivassec@rivassec.com>`. Stack dependent PRs by
basing each on the previous branch, and bring base changes forward by **merging** the base
into the next branch (no rebase + force-push on shared PR branches).
