# failopen-lint

A deterministic, dependency-free scanner that hunts the recurring FAIL-OPEN
TAXONOMY in the shipped IAM Blast Radius tool. It reads every shipped file and
prints hotspots as `file:line + class + snippet`, exiting non-zero when any
non-allowlisted hotspot fires.

## What it is NOT

**This lint ROUTES ATTENTION. It does not prove safety.**

A clean run (exit 0) does NOT mean the tool fails closed. It only means these
syntactic smells were not found by regex/brace heuristics. Conversely, a firing
hotspot is a place a human must READ - not an automatic bug. Several detectors
(`unbounded-walk`, `budget-bypass`, `silent-catch-clean`) legitimately fire on
code that is fine in context; that is what the allowlist is for. The lint's job
is to make sure the fail-open shapes we keep re-introducing never slip in
un-reviewed, not to be a proof engine.

The engine's real fail-closed guarantees live in the shipped code, its tests,
the security-probes, and the threat model - not here.

## Limitations (read before trusting a clean run)

This lint ROUTES ATTENTION via best-effort syntactic patterns over blanked
source (strings/comments stripped); it does NOT understand control flow, types,
or semantics. It is readily evadable, and a clean run is NOT a safety proof. It
will MISS, among others: a cap/guard hidden behind a helper wrapper
(`if (overCap(list)) ...`); severity chosen by a `switch`/`if` ladder instead of
a ternary; recursion written as an arrow function or via mutual recursion (the
recursion detector only matches `function NAME(){... NAME() ...}`); a truncation
against a renamed array or a cap that is not `MAX_*`/`limit`/`max`; a drop
assembled through template-interpolation or computed member access; and any
fail-open reached only at runtime. Conversely it will FIRE on plenty of code
that is fine in context (display-string truncation, guarded recursion, cleanup
`catch`es) - that is what the allowlist is for. Treat every hotspot as "a human
must read this line", and treat exit 0 as "these particular smells were not
found", never as "the tool fails closed". A missing/moved shipped target also
forces a non-zero exit (a dropped analysis target is itself a fail-open), and the
scan writes its `--json` result to `hotspots.json` next to `lint.mjs` as the
coverage-matrix indexer's AST-hotspots feed.

## Scope

Scanned files (the shipped, must-fail-closed surface):

- `content/tools/iam-blast-radius/engine/*.js`
- `content/tools/iam-blast-radius/app.js`, `.../worker.js`
- `cli/*.mjs`
- `action/index.mjs`

No build step, no runtime dependencies (Node built-ins only), ASCII only,
deterministic: same tree in -> same findings out, sorted by `(file, line, class)`.

## Run

```
node tools/iam-blast-radius/audit/lint/lint.mjs
```

Options:

- `--json` - machine-readable output (`{scanned, missing, active, suppressed}`).
- `--allowlist <path>` - use a specific allowlist file (default:
  `allowlist.json` next to `lint.mjs`).

Exit code: `1` if any non-allowlisted hotspot fired, else `0`.

Self-tests:

```
node --test tools/iam-blast-radius/audit/lint/failopen-lint.test.js
```

## Detectors (the taxonomy)

1. **raw-realpath-mismatch** - an entry-point comparison of `import.meta.url`
   against `pathToFileURL(...argv...)` WITHOUT `realpathSync`. `import.meta.url`
   is realpath-resolved by Node; `argv[1]` is the raw invocation path, so a
   symlinked launch makes the guard return false -> zero analysis, exit 0.
2. **syntax-keyed-severity** - a `severity`/`level` assignment whose condition
   tests an IAM syntax token (`stmt.resources`, `notResources`, `notAction`,
   `broadArn`/`broadStar`) instead of a normalized breadth helper. Bare
   identifiers in the condition are resolved to their `const`/`let` definition
   so `broadArn = stmt.resources.some(...)` is seen for what it is. A grant that
   is broad only via `NotResource` gets under-scored.
3. **silent-catch-clean** - a `catch` block that returns a clean/empty-findings
   sentinel (`[]`, `findings: []`, `'clean'`, `exit(0)`) or swallows silently,
   with no `throw` / fail-closed / incomplete marker.
4. **candidate-drop** - a cap/truncation-guarded drop that ships no fail-closed
   truncation signal (`incomplete`/`truncated`/`partial`/...) nearby. Fires on: a
   cap comparison against a `MAX_*` constant in EITHER operand order (`list.length
   > MAX_*` and the reversed `MAX_* < list.length`) that gates a
   `return`/`continue`/`break`; a `.slice`/`.splice` truncation to a `MAX_*`
   constant, a numeric literal, or a `limit`/`max`-named variable (a full-length
   `.slice(0, x.length)` copy is NOT a cap and is excluded); and an enumeration
   `continue`/`return`/`filter` that DROPS an unreadable / parse-failed /
   glob-failed item with no adjacent bookkeeping (a swallowed input file silently
   shrinks the analyzed set). A drop that instead fails closed (throws, returns
   `ok:false`, pushes an error) is excluded.
5. **exit0-offpath** - any `process.exit(0)` (allowlist the single final
   decision point).
6. **budget-bypass** - an ENGINE loop over `statements`/`actions`/`resources`
   that nests another iteration (`.filter`/`.map`/`.some`/`.every`/inner `for`)
   but charges no `chargeWork`/budget anywhere in the enclosing function.
7. **unbounded-walk** - a recursive function with no visible depth/node/size cap
   in its body. Best-effort and noisy by design; allowlist expected.
8. **coverage-incomplete-lost** - a local `incomplete`/`truncated`/`undecidable`
   flag assigned but never carried out via a `return` or a returned object
   property -> the "we did not finish" signal is computed then dropped.

## Ground truth

The lint MUST surface these four already-confirmed locations (do NOT fix them
here; they are the canary the lint exists to catch). `failopen-lint.test.js`
asserts each one:

- `cli/iam-br.mjs:804` and `action/index.mjs:1397` - raw-realpath-mismatch
- `content/tools/iam-blast-radius/engine/rules.js:900` - syntax-keyed-severity
- `content/tools/iam-blast-radius/engine/rules.js:1092` - budget-bypass
- `action/index.mjs` walkFiles MAX_FILES truncation - candidate-drop, FIXED by
  story S2-action-enumeration (the caps now return `truncated: true` and the
  unreadable-dir catch records the path -> fail-closed exit 3); the lint asserts
  its ABSENCE at the enumeration caps now, so a regression is caught

## Allowlist

`allowlist.json` (JSON array, or `{ "allow": [...] }`) lists reviewed false
positives. A finding is suppressed when an entry's `file` and `class` match and,
if `line` is given, the line matches too (omit `line` to accept a whole class in
a file). Suppressed findings still print, tagged `[allowlisted]`, but do not
affect the exit code. Each entry SHOULD carry a `reason`.

```json
[
  { "file": "cli/iam-br.mjs", "class": "silent-catch-clean", "line": 668,
    "reason": "best-effort stream cleanup; failure cannot mask a finding" }
]
```

The seed `allowlist.json` is empty on purpose: the four ground-truth hotspots
must never be allowlisted away.
