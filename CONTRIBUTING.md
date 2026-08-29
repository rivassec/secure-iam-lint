# Contributing to secure-iam-lint

Thanks for your interest. secure-iam-lint is an AWS IAM policy blast-radius
analyzer: a browser-pure engine, a Node CLI (`iam-br`), a `scan()` API, a SARIF
exporter, and a GitHub Action. Its one non-negotiable promise is **FAIL CLOSED**:
`analyze()` / `scan()` must never read CLEAN on a policy that carries a real
capability. Every change is judged against that.

## Ground rules

- **Fail closed, always.** When the engine cannot determine a verdict, it reports
  UNKNOWN / incomplete coverage - never a clean pass. A change that lets a genuine
  capability read CLEAN (or makes the browser more permissive than the CLI) is a
  security regression and will not be merged.
- **Deterministic.** Same input -> same output, same order, every run. No
  `Date.now()` / `Math.random()` in the engine. No network, no `eval`, no DOM in
  the engine or CLI.
- **Browser == CLI.** The browser `analyze()` and the CLI `scan()` share one
  engine and must agree. A parity fuzzer enforces this.
- **Every behavior change needs a test.** Prefer a failing test first (TDD).

## Getting set up

Requires Node.js >= 21 for the dev gate below (the built-in test runner's glob
expansion, e.g. `"tests/**/*.test.js"`, landed in Node 21). The shipped CLI itself
runs on Node >= 20 (per `package.json` `engines`).

```bash
git clone https://github.com/rivassec/secure-iam-lint
cd secure-iam-lint/tools/iam-blast-radius
npm ci --no-audit --no-fund
```

## The gate (run before you open a PR)

All of these must stay green - any delta is a behavior leak to find and fix first.
Run from `tools/iam-blast-radius/`:

```bash
# Unit + integration suite (also under the hardened runtime)
node --test "tests/**/*.test.js"
node --disallow-code-generation-from-strings --disable-proto=throw --test "tests/**/*.test.js"

# Audit suite + golden corpus release gate
node --test "audit/**/*.test.js"
GOLDEN_RELEASE_GATE=1 node --test audit/golden-corpus/release-gate.test.js

# Fail-open lint gates (guard targets + active-hotspot baseline)
node audit/lint/lint.mjs --check-targets
node audit/lint/lint.mjs --check-hotspots

# No circular ESM imports (load-order-dependent TDZ safety)
npx madge --circular --extensions js,mjs ../../content/tools/iam-blast-radius/engine ../../cli ../../action

# Browser==CLI parity fuzzer
node tests/fuzz/parity-fuzz.mjs
```

CI runs this same set on every PR, plus CodeQL, ClusterFuzzLite, and OpenSSF
Scorecard.

## Adding or changing a detector

The engine is decomposed into small modules (rules in `rules-*.js`, escalation in
`escalation-*.js`). A new finding id must be:

1. registered in the catalog (`rules-catalog.js` or `escalation-catalogs.js`),
2. emitted by a detector wired into the rule/detector list,
3. covered by fixtures for each applicable cell of the fixture matrix
   (`tests/fixture-matrix.test.js` will fail if coverage is missing),
4. captured in the golden corpus if it changes any baseline
   (`node audit/golden-corpus/capture.mjs --update`, then review the diff).

## Pull requests

- Keep PRs focused. One logical change at a time.
- Describe *what security property* the change preserves or adds, and include the
  test that proves it.
- New code reads like the surrounding code: match its naming, comment density, and
  fail-closed idioms.
- ASCII only in source, tests, and docs (no smart quotes / em dashes).

## Reporting a vulnerability

Do **not** open a public issue for a security problem. Use GitHub private
vulnerability reporting: <https://github.com/rivassec/secure-iam-lint/security/advisories/new>
(or the repository "Security" tab -> "Report a vulnerability"). See
[SECURITY.md](SECURITY.md) for the full process.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
