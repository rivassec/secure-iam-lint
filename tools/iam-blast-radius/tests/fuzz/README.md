# Fuzzing

Two complementary fuzzers guard the one immutable safety contract - the browser
engine (`analyze()`) may **never** be more permissive than the CLI (`scan()`):

```
scanClean(scan(p))  ||  !analyzeClean(analyze(p))     MUST hold for every policy p
```

The forbidden state is the CLI failing closed while the browser reports a clean
pass - a silent browser fail-OPEN (threat-model T8).

## 1. `parity-fuzz.mjs` - deterministic differential fuzzer (nightly)

A seeded, structure-aware generator that emits mutation-heavy policies biased
toward the known fail-open surface (empty `NotAction`/`NotResource` complements,
never-match conditions, malformed condition blocks, `__proto__`/`constructor`
keys, deep nesting, over-limit sizes, BOM/Unicode noise, truncated JSON). A given
`--seed` yields the exact same sequence and verdict on every machine, and a
violation prints a self-contained reproducer.

- Run: `node tests/fuzz/parity-fuzz.mjs [--seed N] [--count N] [--budget-ms N]`
- CI: `.github/workflows/fuzz-parity.yml` (scheduled).

## 2. `analyze.fuzz.cjs` - ClusterFuzzLite / Jazzer.js (per-PR)

A coverage-guided libFuzzer target (via Jazzer.js) that drives the *same*
invariant on mutated input. A finding is a parity violation **or** either surface
throwing instead of failing closed. Runs in ClusterFuzzLite `code-change` mode on
PRs touching the engine / CLI / fuzz target.

- Build/config: `.clusterfuzzlite/` (Dockerfile + build.sh + project.yaml).
- CI: `.github/workflows/cflite_pr.yml`.
- The pure-ESM engine (`content/`, `cli/`) is excluded from Jazzer.js
  instrumentation (its Babel transform cannot parse those sources); the target
  still drives them via dynamic `import()`.

`corpus/` holds a small seed corpus of valid policies.
