# IAM Blast Radius - Phases 11-13 execution plan

Status: PLANNED (2026-08-24). Governs the remaining roadmap after Phase 10:
the T91 residual, the critic fail-closed control upgrade, the resource-policy
family, and the org-control (SCP/RCP) ceilings. Built with the same Ralph-loop
orchestration as Phases 7-10 (see `ralph/phase{7..10}-workflow.js`), with the
control changes in Phase 11A applied to every phase from 11 onward.

Canonical inputs each phase reads: this file, `docs/architecture.md` +
`docs/threat-model.md` (immutable), `prd.json` (per-story spec), the three
acceptance suites (`docs/acceptance-suite.md`, `-2.md`, `-3.md`), and any
grounding doc the phase produces.

---

## 1. How the critics work (fail-closed model - NEW as of Phase 11A)

### 1.1 The loop, per story, per iteration

```
impl agent  ->  deterministic gate  ->  [ parallel critic panel ]  ->  arbiter
   (writes)        (must PASS)              (all must PASS)            (accept / hold)
```

A story is only ACCEPTED when the deterministic gate passes AND every critic
returns `PASS`. Anything else re-enters the loop (bounded) or holds the story.

### 1.2 Critic outcome model (explicit states)

Each critic call resolves to exactly one outcome. This replaces the old
"null == no blocking findings" behavior that let the IAM-1005 529 storm
auto-accept an unreviewed story.

| Outcome | Meaning | Effect on acceptance |
|---|---|---|
| `PASS` | Critic ran, found nothing blocking | permits acceptance |
| `BLOCKER` | Critic ran, found >=1 blocking finding | re-impl with feedback |
| `ERROR` | Critic call failed (API 5xx / server error) | **fail closed** - retry, never accept |
| `TIMEOUT` | Critic exceeded its wall-clock budget | **fail closed** - retry, never accept |
| `INVALID_RESPONSE` | Returned null / malformed / schema-invalid | **fail closed** - retry, never accept |

**Acceptance rule:** a story is accepted iff `gate.pass === true` AND every
critic outcome is `PASS`. A single `BLOCKER`, `ERROR`, `TIMEOUT`, or
`INVALID_RESPONSE` blocks acceptance. Absence of a result is never approval.

### 1.3 Control-failure handling (ERROR / TIMEOUT / INVALID_RESPONSE)

1. **Prevent auto-acceptance** - the story cannot be promoted on a non-PASS.
2. **Bounded retry** - re-invoke only the failed critic(s), up to `criticMaxRetry`
   (default 2), with backoff; do not re-run PASS/BLOCKER critics.
3. **Ledger entry (always)** - write a `progress.md` row recording: story id,
   iteration, per-critic outcome, retry attempts, and the failure reason
   (e.g. `529 Overloaded x3`). A story with no ledger row is itself a defect.
4. **Hold, do not promote** - if a critic is still non-PASS after retries, mark
   the story `human-review` (NOT accepted), surface it in the phase result, and
   require a successful review before the story is considered done.

### 1.4 The critic panel

Every code story runs four critics in parallel; UI stories add a fifth; grounding
-doc stories run a single AWS-verifier instead.

| Critic | Runs on | Blocks when |
|---|---|---|
| **qa-semantics** | all code | An IAM/security claim is wrong per AWS grammar/eval; provenance wrong (action attributed to a statement that doesn't grant it); a targeted suite test still fails; exports disagree; a prior suite/negative-corpus case regressed. Verifies by **driving `analyze()` directly**, not by trusting fixtures. |
| **security** | all code | Network API in shipped JS; `innerHTML`/`eval`/unsafe DOM; DOM/attrs built unsafely from policy input; `__proto__`/`constructor` not rejected; inline style/script/on-handler in HTML; injection fixtures no longer inert; policy content leaks to storage/URL/network; Markdown export emits active links/HTML from attacker strings. |
| **reliability** | all code | A regressed test; nondeterminism (same input+family -> different semantic JSON); uncaught exception on malformed/adversarial input; a hang; DoS caps not holding; stale state after re-analysis; both negative corpora not intact. |
| **adversarial** | all code | It *constructs* hostile + near-miss policies against `analyze()` and blocks on any false-positive, false-negative, over/under-claim, or unsafe render it can produce. Diversity, not redundancy - it targets the story's specific failure modes. |
| **compat-a11y** | UI stories | Control not keyboard-operable / unlabeled; state changes not announced (aria-live); experimental API without fallback; serious a11y barrier; untrusted strings rendered as anything but text; Playwright specs not updated for the new UI. |
| **aws-verifier** | grounding-doc stories | A documented AWS semantic (principal type, condition polarity, eval rule) is missing/wrong or a cited source doesn't support the claim; shipped code changed by a doc story. |

Critics are **read-only** (they run tests and drive the engine; they never edit
source). Findings use a fixed schema: `{id, severity, location, criterion,
evidence, required_outcome, blocking}`. Only `blocking:true` findings force a
re-impl; the arbiter feeds them verbatim to the next engineer.

### 1.5 The arbiter is a tested module, not ad-hoc code (NEW - IAM-1101 / 11A)

The Section-1.2/1.3 outcome model is implemented ONCE as a testable repo module,
`ralph/review-decision.mjs` (`classifyResponse` + `decide` + `runReview` +
`InMemoryLedger`), and unit-gated by **all 15**
`docs/record-tests/cases/workflow-cases.json` fault-injection cases in
`tests/critic-fail-closed.test.js`. It is the empirical fix for the IAM-1005
529-storm auto-accept: `ERROR`/`TIMEOUT`/`INVALID_RESPONSE`/`null`/missing critic
results classify as explicit non-pass states, a story is accepted **iff** every
required critic returns an explicit `PASS` **and** a durable, schema-valid ledger
row is committed, and every fault (including a failed ledger write) blocks
acceptance while still writing a ledger record. Its emitted objects conform to
both bundle schemas (`critic-result.schema.json`, `review-ledger-entry.schema.json`),
verified in-test by a self-contained subset validator.

**Authoring standard for every phase workflow (12/13 onward):** the arbiter block
in `ralph/phase*-workflow.js` MUST reuse this model rather than re-deriving accept
logic. Because the Workflow-tool loader injects globals (`agent`/`parallel`/`log`/
`phase`) and does not import cross-file modules into a workflow body,
`ralph/phase11-workflow.js` carries an `arbitrate(panel, criticResponses)` helper
that is a byte-for-byte behavioral mirror of `decide()` (all-PASS -> `approved`;
any missing/`ERROR`/`TIMEOUT`/`INVALID_RESPONSE` -> `review_error`, fail-closed
retry, never accept; any blocker -> `blocked`). Copy that block verbatim into new
phase workflows and keep it in lockstep with `review-decision.mjs`; that module's
15-case suite is the source of truth.

---

## 2. How often engineer agents are replaced (Ralph loop)

**Every iteration.** Each implementation attempt is a fresh, stateless
`impl` agent - it is thrown away and replaced on the next iteration. Nothing
carries in the agent's head between iterations; all durable state lives in:

- the **repo working tree** (the code/tests/fixtures the prior engineer wrote), and
- the **feedback string** (the blocking findings from the last critic round).

A new engineer for iteration N reads the story spec + the repo + only the
blocking feedback, and fixes ONLY those findings. This is the Ralph loop: the
engineer is disposable and interchangeable; the accumulated artifact + the
critic feedback are the memory.

### Replacement / termination policy

| Parameter | Value | Meaning |
|---|---|---|
| Engineer lifetime | 1 iteration | replaced every loop pass |
| `maxIter` per story | 4-6 (see per-story tables) | max engineer replacements before the story is held |
| Accept | gate PASS + all critics PASS | story done, loop exits |
| Hold (`human-review`) | `maxIter` reached with an unresolved BLOCKER, **or** a critic still non-PASS (ERROR/TIMEOUT/INVALID) after `criticMaxRetry` | story surfaced for human review, NOT promoted |
| Serial stories | shared engine/UI files | one story at a time; later stories build on accepted earlier ones |

Grounding-doc stories follow the same loop with the aws-verifier in place of the
panel. The final **independent re-test** agent at the end of each phase is not an
engineer - it re-derives the full three-suite scoreboard from `analyze()` and is
trusted only after I (the orchestrator) spot-verify it against the engine.

---

## 3. The remaining phases

### Phase 11 - Residuals + control hardening (small; do first)

11A must land before Phase 12 so a control failure cannot silently pass an
unreviewed story in the large build.

Acceptance is now anchored to the external **record-test bundle**
(`docs/record-tests/`, 2026-08-24): 42 cases across boundary regression (8),
critic workflow robustness (15), T91 (9), and deferred families (10), plus the
`critic-result` + `review-ledger-entry` schemas.

| Story | Scope | maxIter |
|---|---|---|
| **IAM-1101 (11A)** | **Critic fail-closed** (workflow infra, not the shipped tool): a testable `ralph/review-decision.mjs` implementing the Section-1 outcome model (PASS/BLOCKER/ERROR/TIMEOUT/INVALID_RESPONSE, all-PASS acceptance, bounded critic retry, mandatory ledger, hold-not-promote). **Gate: all 15 `docs/record-tests/cases/workflow-cases.json` fault-injection cases pass** (adapt `templates/critic-fail-closed.test.template.mjs`), conforming to both bundle schemas. Future-phase arbiters call/mirror it. | 5 |
| **IAM-1102 (11B)** | **T91 subject-account-aware PassRole viability**: subject-account context (explicit or inferred). Target-role account != known subject account -> suppress the compound path, report ineffective/incompatible. Unknown subject -> viability UNKNOWN, never `critical`. **Gate: all 9 `T91-*` bundle cases pass** (same-account/wildcard viable cases preserved). Flip the scoreboard to 39/39. | 5 |
| **IAM-1103 (11C)** | **Invalid-family fail-closed + record regression fixtures** (NEW, from the bundle's DEF-05 fail-OPEN): an unknown family value (`scp`/`rcp`) currently falls back to identity analysis and emits capability findings; must fail closed (`INVALID_FAMILY`), never analyze as identity. Canonicalize the family vocabulary. Commit the 8 `BND-*` + 10 `DEF-*` cases as regression fixtures under the adapter name-map (below). UI-only record cases -> named Playwright assertions. | 4 |

**Adapter name-map (behavior authoritative, not the literal label; engine ids
are shipped + covered by 1208 tests, so map at the fixture layer):**
`BOUNDARY-ENVELOPE` -> `PERMISSIONS-BOUNDARY-ENVELOPE`;
`UNSUPPORTED_OR_INVALID_NOTPRINCIPAL` -> `UNSUPPORTED_NOTPRINCIPAL`;
`MIXED_OR_INVALID_POLICY_FAMILY` -> `AMBIGUOUS_POLICY_SHAPE`.

**Baseline against the current engine (2026-08-24 record-test run):** analyzer
cases = 13 behavior-correct (incl. the 3 name-mapped), 4 expected-fail (T91, fix
= 11B), 1 new bug (DEF-05, fix = 11C), 9 UI/procedure skips. Workflow cases =
15, all failing today by design (current harness has no fail-closed model - the
IAM-1005 incident) -> 11A's gate.

**Tests:** deterministic gate (S4.1) + the bundle cases as committed fixtures +
the two bundle schemas enforced + re-run all three suites; full `node --test`
green; no regression to suites 1/2/3 or the negative corpora.

*Closes: both release-record corrections (T91 -> 39/39; the review control), plus
the DEF-05 invalid-family fail-open.*

### Phase 12 - Resource-based policy family (the big one)

The next major capability; scale comparable to the trust family or larger.
Grounding doc first. Requires a new **resource-context input** (resource type +
ARN) - the suite's "resource-policy context is explicit" invariant.

| Story | Scope | maxIter |
|---|---|---|
| **IAM-1200** | Grounding doc `docs/resource-policy-semantics.md` (AWS-verified): resource-policy evaluation from the resource's perspective, per-service principal/resource shapes (S3 bucket/object, SNS, SQS, KMS key), confused-deputy, transport-vs-identity constraints, account-delegation semantics. aws-verifier gated. | 3 |
| **IAM-1201** | Resource-policy family detection + acceptance (currently fail-closed) + resource-type/ARN context input (UI + engine); route to a resource evaluator, never identity rules. | 5 |
| **IAM-1202** | Principal-centric analysis + public-access: external accounts/roles/users, services, federated, anonymous `*`; public-access finding; a transport Deny (`aws:SecureTransport`) is a transport constraint, NOT an identity constraint (T28). | 5 |
| **IAM-1203** | Confused-deputy: missing `SourceArn`/`SourceAccount` on a service principal = exposure (T26); source-bound = negative control (T27); mismatched = misconfigured/ineffective (T53). | 5 |
| **IAM-1204** | Same-account grants: user / role / assumed-role-session principals and the resource-vs-identity evaluation distinction (T32/T33); bucket-vs-object resource-type awareness (closes T50). | 4 |
| **IAM-1205** | KMS key-policy semantics: account-root delegation is neither public nor root-only; `Resource:*` = the attached key (no per-key node explosion) (T51); multi-condition composition AND-keys/OR-values (T49). | 4 |
| **IAM-1206** | `NotPrincipal`: model the Deny+NotPrincipal permissions-boundary hazard as a high-confidence semantic warning (or keep fail-closed) - never an ordinary exclusion (T29). | 4 |
| **IAM-1207** | Resource negative corpus (`fixtures/negative-resource/`, frozen "does-not-fire" contracts) + fixturize + re-run all three suites + scoreboard. | 5 |

**Tests:** deterministic gate each story; a per-story fixture set; a **resource negative corpus** (the credibility artifact, like the identity + trust corpora); Playwright e2e for the resource-context input UI; re-run of all three suites. *Closes suite-2 26/27/28/29/32/33/49/51/53 + suite-3 69/85.*

### Phase 13 - Org-control ceilings (SCP + RCP)

Reuses the permissions-boundary "ceiling, not grant" pattern, org-scoped.

| Story | Scope | maxIter |
|---|---|---|
| **IAM-1301** | Full SCP ceiling semantics: an SCP Allow is a permission CEILING not a grant; deny guardrails; `NotAction` complements; region/condition guardrails; never manufacture granted capability (closes suite-1 T19, suite-2 T43). | 5 |
| **IAM-1302** | RCP: org-level resource guardrails, deny-only, confused-deputy at org scope (T52). | 4 |
| **IAM-1303** | Fixturize + re-run all three suites + final scoreboard; confirm the only remaining fail-closed set is anything genuinely out of scope, all with machine-readable UNSUPPORTED_* codes. | 4 |

**Tests:** deterministic gate; SCP/RCP fixtures asserting ceiling/guardrail (never grant) semantics; re-run all three suites.

---

## 4. What tests run (every phase)

### 4.1 Deterministic gate (blocks before critics; must fully pass)
- `cd tools/iam-blast-radius && node --test "tests/**/*.test.js"` - the FULL unit
  + security + acceptance suite (1208+ tests today), all pass, capture any
  regressed test names.
- `gate:no-network` - grep shipped JS for `fetch`/`XMLHttpRequest`/`WebSocket`/
  `EventSource`/`sendBeacon`/remote `import` -> must be empty.
- `gate:no-unsafe-dom` - grep shipped JS for `innerHTML`/`outerHTML`/
  `insertAdjacentHTML`/`eval`/`new Function` -> must be empty.
- `csp_audit.py content/tools` - no inline style/script/on-handler.
- All `fixtures/**/*.json` parse as JSON.

### 4.2 Per-story + suite tests
- Per-story acceptance fixtures (positive / negative / boundary), driven from
  real `analyze()` output.
- The three acceptance suites (suite-1 1-24, suite-2 25-54, suite-3 55-100) via
  their harnesses; the completeness gate forbids silent skips.
- Negative corpora (must never regress): `fixtures/negative` (identity),
  `fixtures/negative-trust` (trust), and `fixtures/negative-resource` (Phase 12+).
- Cross-test invariants (12 from suite-1/2, 12 from suite-3): evidence
  provenance, condition polarity, denies-are-not-grants, no-semantic-edge-reuse,
  exports-agree (JSON/MD/UI), determinism (byte-identical semantic JSON on
  re-analysis), invalid-fails-closed, local-only.

### 4.3 Browser + CI
- Playwright e2e across **Chromium / Firefox / WebKit** (CI job "Playwright
  browser acceptance"): UI wiring, mandatory family selection, family-switch
  invalidation, injection-inert rendering, new resource-context input.
- CI workflows: `IAM Blast Radius CI` (node --test + gates + Playwright,
  path-filtered) and `Deploy Pelican Site` (build + CSP audit + lychee +
  gh-pages). Both must be green before a phase is considered shipped.

### 4.4 Final independent re-test (per phase)
A dedicated agent re-derives the full three-suite scoreboard directly from
`engine/analyze.js`, reports per-suite pass counts + regressions, and writes the
scoreboard doc. The orchestrator spot-verifies it against the engine before
committing (verify-don't-trust; this is how the IAM-802/803 stale findings and
the IAM-1005 unreviewed accept were caught).

### 4.5 Post-merge verification (orchestrator, not an agent)
After merge to `main`: watch `Deploy Pelican Site` to green; Cloudflare purge
(dynamic file list); curl the live assets to confirm the new engine is served;
watch `IAM Blast Radius CI` (incl. Playwright) to green - a green deploy does not
imply green e2e, they are independent (the Phase-10 test-assertion collision was
caught here).

---

## 5. Sequencing + scale

11 (small, days) -> 12 (large, the resource-policy family - long autonomous run,
multi-story) -> 13 (medium, reuses the ceiling pattern). 11A is a prerequisite
for 12/13. Input-model additions (subject-account in 11B, resource-context in
12) are designed once and reused. Each phase ends with all three suites green,
a refreshed scoreboard, and a combined verified deploy.
