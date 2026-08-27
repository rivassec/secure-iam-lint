# Golden-corpus fail-closed audit harness

An **oracle-first** audit harness for the IAM Blast Radius engine + CLI + Action. It
exists to catch the recurring **fail-OPEN** bug classes (a risky policy read as clean,
a candidate silently dropped, a fail-closed verdict collapsed to exit 0).

## What proves what (read this first)

- **`golden-oracle.test.js` (PRIMARY) proves fail-closed PROPERTIES.** These are
  metamorphic / oracle assertions derived from *behaviour*, not from a captured
  artifact, so they hold **regardless of the current baseline**. They are the
  load-bearing mechanism.
- **`packaging.test.js` (PRIMARY for the entrypoint class) proves REAL invocations
  fail closed.** It `npm pack`s the publishable package, installs the tarball, and
  drives the bin four ways (direct `node`, `npx`, a bin symlink, the npm bin shim) plus
  an Action-style spawn. This is the only channel that can see the entrypoint-guard
  fail-open, because that bug is invisible to an in-process `run(argv, io)` call.
- **`capture.mjs` + `diff.mjs` (SECONDARY) are only a CHANGE-DETECTOR.** A byte/JSON
  snapshot proves *stability*, nothing more. Because today's engine carries KNOWN
  fail-open bugs, a snapshot would happily **freeze wrong behaviour** - which is exactly
  why it is secondary. Drift is flagged for review, not auto-trusted.

**NEITHER channel proves the policy, or the engine, is "safe."** A green run means
"the analyzable surface was analyzed and nothing at/above the bar fired," never
"analyzed and proven safe" (threat-model T8, and the `complete`/`CLEAN` caveat).

## Layout

```
manifest.mjs          the corpus metadata + fail-closed class per case (source of truth)
corpus/               29 killer policy files (raw IAM JSON, byte-faithful)
golden-oracle.test.js PRIMARY: the five fail-closed property assertions
packaging.test.js     PRIMARY: npm pack -> install -> 4-way bin + Action-style spawns
capture.mjs           SECONDARY: writes normalized snapshots to baselines/
diff.mjs              SECONDARY: re-derives + compares; non-zero on drift
diff.test.js          runs the snapshot diff under node --test
baselines/            committed snapshots (regenerate deliberately with capture --update)
```

## Case classes (what the oracle asserts)

| class | property |
|-------|----------|
| `risky` | a finding at/above `threshold`; CLI exit != 0; **never clean** |
| `clean` | genuinely narrow/routine; exit 0 (nothing at/above threshold) |
| `quiet` | a deliberately-silent scoped capability; exit 0 **and zero findings** |
| `malformed` | rejected before/at model build; status != complete; exit 3; never clean |

The five properties (spec (b)): (1) zero-analysis => exit != 0 and not clean;
(2) risky => finding at/above threshold and exit != 0; (3) malformed => coverage
incomplete/error, never clean; (4) `analyze()` (browser) never more permissive than
`scan()` (CLI) on the same input; (5) clean/quiet => exit 0 only when genuinely nothing
risky.

## Known-open bugs surfaced by this harness

The build spec names six confirmed fail-open bugs (do NOT fix them here - the harness
must *surface* them). Cases/tests that hit one are registered as node:test **`todo`** so
the suite stays green today while documenting the fail-open; each has a non-`todo`
**PIN** test asserting the current buggy value so a silent change is still caught.
**Fixing a bug flips its `todo` to a real pass** (and will trip the PIN - update it then).

| # | bug class | location | how this harness surfaces it | state |
|---|-----------|----------|------------------------------|-------|
| 1 | raw-realpath-mismatch | `cli/iam-br.mjs:804`, `action/index.mjs:1397` | `packaging.test.js` (b) npx, (c) bin symlink, (d) bin shim all exit 0 (zero analysis) - only direct `node <realpath>` works | `todo` x3 + PIN x3 |
| 2 | syntax-keyed-severity | `engine/rules.js:900` | case `notresource-write-severity` (16): a broad NotResource **write** scored `medium` -> slipped under the `high` threshold -> exit 0 | FIXED (story S3-rules-breadth B): severity keys on effective breadth (NotResource-only broad non-read = HIGH); case 16 is now a regular `risky` P2 case + release-gate re-check |
| 3 | budget-bypass | `engine/rules.js:1107` (ruleDataReadScoped loop) | case `huge-near-caps` (14) exercises the O(actions x resources) loop; documented (the DoS budget still trips here via other loops, so the case fails closed today - the untaxed loop is a latent DoS, not yet an observable wrong verdict) | documented |
| 3b | budget-bypass (NEW-BUDGET-DENYFENCE) | `engine/rules.js` `denyFencesToNarrow` | case `notresource-deny-fence-dos-budget` (29): a within-caps ~9998 x ~3000 deny-fence policy whose `.some(classifyResource !== NARROW)` narrowness walk charged ZERO work (classifyResource is pure on the NARROW-ARN path) - an uncharged O(N*M) walk called once per matched action that bypassed BOTH engine budgets (~40s, a direct analyze() consumer had no COMPLETE-verdict protection) | FIXED (story S1-NEW-BUDGET-chargeWork): `denyFencesToNarrow` charges work per spared element inspected so both budgets bound it; case 29 fails closed + release-gate re-check (and an ordinary deny-fence stays uncorrected) |
| 4 | candidate-drop (MAX_FILES) | `action/index.mjs` walkFiles enumeration caps | FIXED (story S2-action-enumeration): an unreadable subtree (readdir failure) is recorded and a MAX_FILES-truncated walk sets `truncated`, so runAction synthesizes fail-closed exit-3 units (ENUMERATION_UNREADABLE / ENUMERATION_TRUNCATED); `action-enumeration-failclosed.test.js` pins the real-fs behavior and `failopen-lint.test.js` asserts the lint no longer flags it | guarded |
| 5 | coverage-incomplete-lost | (taxonomy) | oracle P3 asserts malformed cases propagate `coverage.summary.incomplete` on the browser path | guarded |
| 6 | browser-cli-parity-break | (taxonomy) | oracle P4 asserts `analyze()` is never more permissive than `scan()` over every case | guarded |

Bug #1 is the headline finding: because npm's `.bin/` shim is itself a symlink and
`npx` resolves through it, **the shipped tool fails OPEN (exit 0, zero analysis) via the
normal `npx` and bin-shim invocation paths** - only `node <realpath>` currently works.

## Two run modes: remediation-window vs RELEASE GATE

The `todo`s above keep the suite **green during the remediation window** while documenting
the open fail-opens - but that means a plain green run can still mean "known holes are
still allowed", and the PINs even encode the vulnerable baseline as the "expected" value.
`release-gate.test.js` closes that gap.

- **Plain run (remediation window)** - `todo`s stay green, gate checks skip:

  ```
  node --test "audit/golden-corpus/*.test.js"
  ```

- **Release gate (enforced)** - HARD-FAILS if ANY known-open case still reproduces its
  fail-open, so at release time green cannot mean "known holes still allowed":

  ```
  GOLDEN_RELEASE_GATE=1 node --test audit/golden-corpus/release-gate.test.js
  ```

  The gate is INACTIVE (every check skips) unless `GOLDEN_RELEASE_GATE=1`, so it never
  disturbs the normal run. When set it asserts each known-open case is FIXED:

  | known-open | bug | gate check |
  |------------|-----|------------|
  | `notresource-write-severity` (16, FIXED) | syntax-keyed-severity (`engine/rules.js`) | S3-rules-breadth re-check: `scan()` must exit 1 (NotResource-only broad non-read gates at high) |
  | `vacuous-notresource-deny-exfil` (17, FIXED) | vacuous-Deny-suppression (`engine/rules.js` `denyFencesToNarrow`) | S3-rules-breadth re-check: `scan()` must exit 1 (a vacuous NotResource Deny must not suppress DATA-EXFIL) |
  | entrypoint guard | raw-realpath-mismatch (`cli/iam-br.mjs:804`, `action/index.mjs:1397`) | a SYMLINKED CLI launch must analyze (`WILDCARD-ACTION`) and exit non-zero - a cheap reproduction of the same class packaging.test.js covers via npx/bin-shim |

  Ship only when the enforced gate is green. Fixing a bug then flips its plain-run `todo`
  to a real pass (refresh the matching PIN and re-bless the baselines at the same time).

The SECONDARY snapshot (`capture.mjs`) also records a **richer normalized finding** per
case - actions, resource scope, condition presence, a stable evidence/why hash, and
coverage incomplete-flag + counts - so `diff.mjs` catches a changed scope / evidence /
message, not only a changed id or severity. An unparseable `--format json` / `--format
sarif` emission is a HARD capture failure, never a blessable baseline. Re-bless
deliberately with `node capture.mjs --update`.

## Commands

Run the whole harness (from `tools/iam-blast-radius/`):

```
node --test "audit/golden-corpus/*.test.js"
```

Individually:

```
node --test audit/golden-corpus/golden-oracle.test.js   # fail-closed properties
node --test audit/golden-corpus/packaging.test.js        # real npm-pack invocations
node --test audit/golden-corpus/diff.test.js             # snapshot change-detector
```

Secondary snapshot channel:

```
node audit/golden-corpus/capture.mjs            # dry-run: print snapshots
node audit/golden-corpus/capture.mjs --update   # (re)write baselines DELIBERATELY
node audit/golden-corpus/diff.mjs               # exit != 0 on any drift
```

A green suite reports `todo` for each currently-open bug. When a bug is fixed, remove the
matching `todo` marker (and refresh its PIN + the baselines) so the fix is locked green.
