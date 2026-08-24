# Targeted Regression and Residual Test Plan

## Track A — Boundary assertion collision and family switching

### BND-01 — Rule-name assertion ignores legitimate prose

1. Analyze the boundary fixture in `cases/analyzer-cases.json`.
2. Confirm the finding prose contains: `A wildcard boundary provides no meaningful upper bound`.
3. Assert that a finding whose stable rule identifier is `WILDCARD-RESOURCE` does not exist.

Expected:

- Test passes even though the word `wildcard` appears in explanatory prose.
- Assertions use a structured rule identifier or rule-name field, not `not.toContainText(/Wildcard/i)` against the whole findings region.

### BND-02 — Exact forbidden rule would still fail

Inject or render a controlled finding with rule ID `WILDCARD-RESOURCE` while in boundary mode.

Expected:

- The narrow assertion fails.
- The BND-01 fix must not weaken the test into a no-op.

### BND-03 — Identity-to-boundary switch clears rule state

1. Analyze the wildcard fixture as Identity.
2. Confirm `WILDCARD-RESOURCE` exists where appropriate.
3. Switch to Permissions boundary without changing the policy bytes.
4. Reanalyze.

Expected:

- Identity findings, selected edges, evidence drawers, and export state are cleared.
- Boundary result contains `BOUNDARY-ENVELOPE` or the implemented stable equivalent.
- No capability edge is manufactured.

### BND-04 — Boundary-to-identity inverse switch

Repeat BND-03 in reverse.

Expected:

- Boundary prose and envelope findings do not remain in the Identity result.
- The engine recomputes rather than relabeling existing output.

### BND-05 — Session ceiling uses the same semantic isolation

Analyze the same bytes as Session.

Expected:

- Session ceiling semantics create zero positive capability edges.
- Boundary rule identifiers do not leak into the session result.

### BND-06 — Three-browser acceptance

Run BND-01 through BND-05 in Chromium, Firefox, and WebKit.

Expected:

- Identical semantic assertions in all browsers.
- A failure replicated across browsers is counted as one logical test defect plus three executions, not three product defects.

### BND-07 — Export state after family switch

Download JSON and Markdown after each family switch.

Expected:

- Selected family, status, rules, evidence, and graph counts describe only the latest analysis.
- Legitimate prose containing `wildcard` remains present.
- `WILDCARD-RESOURCE` is absent from boundary/session rule identifiers.

### BND-08 — Selector change before reanalysis

Change the selected family after a completed analysis but do not click Analyze.

Expected:

- Prior results are immediately marked stale or removed.
- Export controls are disabled until the new family/input pair is analyzed.
- The page never shows Identity findings beneath a Boundary label.

---

## Track B — Critic workflow must fail closed

### CRT-01 — Entire critic panel returns HTTP 529

Expected:

- Review state is `ERROR` or `REVIEW_ERROR`, never `PASS`.
- Work item is not auto-accepted or promoted.
- Ledger row is written with every critic attempt and 529 outcome.

### CRT-02 — One required critic fails, others pass

Expected:

- Overall decision is non-pass.
- Successful critic results remain recorded.
- Do not apply an implicit quorum unless a documented quorum policy explicitly permits it.

### CRT-03 — Null findings with no explicit status

Response example: `{"findings": null}`.

Expected:

- Schema validation fails with `INVALID_RESPONSE`.
- Null is not normalized into `[]` before the decision is made.

### CRT-04 — Explicit PASS with empty findings

Response includes `status: PASS`, `findings: []`, critic identity, attempt, and completion timestamp.

Expected:

- Accepted as one valid critic pass.
- Empty findings alone would not be sufficient without explicit status and required metadata.

### CRT-05 — 529 then successful retry

Expected:

- No acceptance occurs after the first failure.
- Bounded retry succeeds.
- Ledger records both attempts and the final decision.

### CRT-06 — Retry budget exhausted

Expected:

- Overall non-pass with stable error code such as `CRITIC_RETRY_EXHAUSTED`.
- No infinite loop or unbounded backoff.

### CRT-07 — Timeout

Expected:

- Explicit `TIMEOUT` state.
- Cancellation/abort signal is applied.
- Missing response cannot become an empty blocker list.

### CRT-08 — HTTP 200 with provider error envelope

Expected:

- Treat provider-declared error as `ERROR`, regardless of HTTP status.
- Do not parse absent findings as approval.

### CRT-09 — Malformed critic JSON

Expected:

- `INVALID_RESPONSE` and non-pass.
- Raw response is recorded only according to redaction and retention policy.

### CRT-10 — Missing panel member

Expected:

- Required critic set and received critic set are compared explicitly.
- Missing member blocks approval and appears in the ledger.

### CRT-11 — Ledger write fails

Expected:

- No acceptance or promotion before durable ledger commit.
- Workflow is retryable and does not lose the review result.

### CRT-12 — Crash after critic success but before ledger commit

Expected:

- Recovery resumes from an idempotent checkpoint.
- Exactly one durable decision row is eventually written.
- Approval occurs only after the ledger is durable.

### CRT-13 — Duplicate callback or retry completion

Expected:

- Idempotency key prevents duplicate critic results and duplicate ledger rows.
- A late error cannot overwrite an already committed valid attempt without an explicit transition policy.

### CRT-14 — Empty critic panel configuration

Expected:

- Configuration error, not JavaScript `every([]) === true` approval.
- Required critic count must be at least one for critic-gated work.

### CRT-15 — Ledger row completeness for every terminal state

Exercise PASS, BLOCKER, ERROR, TIMEOUT, INVALID_RESPONSE, and retry-exhausted outcomes.

Expected ledger fields:

- Work-item ID
- Workflow/run ID
- Required critic IDs
- Per-attempt critic results
- Terminal decision
- Error codes where applicable
- Start/completion timestamps
- Retry count
- Artifact or change identifier
- Schema version

---

## Track C — T91 cross-account PassRole viability

### T91-01 — Exact foreign role with known subject account

Subject account: `123456789012`; passable role account: `999900001111`.

Expected:

- No `PASSROLE-EC2:critical` viable path.
- Emit an incompatible/cross-account PassRole warning or suppress the compound path with visible reasoning.
- Preserve the raw permission as policy evidence.

### T91-02 — Same-account positive control

Subject and role account: `123456789012`.

Expected:

- Existing critical PassRole-to-EC2 behavior remains.
- Fixing T91 must not suppress valid same-account paths.

### T91-03 — Foreign role plus iam:PassedToService

Add `iam:PassedToService = ec2.amazonaws.com` to the foreign role grant.

Expected:

- Service selector does not override the same-account limitation.
- No viable critical path.

### T91-04 — Wildcard account includes the subject account

Use `arn:aws:iam::*:role/workloads/*`.

Expected:

- Do not suppress the path solely because the ARN contains an account wildcard; the scope includes same-account roles.
- Retain critical/high potential with explicit broad-scope evidence.

### T91-05 — Mixed same-account and foreign role list

Expected:

- Viable path is scoped to the same-account role.
- Foreign role is excluded from the passable target set.
- Graph does not merge both roles into one unknown node.

### T91-06 — Partition mismatch

Subject context is commercial `aws`; role is `aws-us-gov`.

Expected:

- No direct viable PassRole path.
- Report partition/account incompatibility without rewriting the ARN.

### T91-07 — Subject account absent

Expected:

- Do not assert a critical viable path from an exact role-account ARN without knowing the subject account.
- Mark account compatibility unknown and reduce path-exploitability confidence.

### T91-08 — Local service role plus separate foreign AssumeRole permission

Policy allows passing a local EC2 role and separately allows the current principal to call `sts:AssumeRole` on a foreign role.

Expected:

- Do not infer that the passed local role inherits the current principal's foreign AssumeRole permission.
- Keep the two subject identities distinct.

### T91-09 — Explicit Deny on same-account PassRole, foreign Allow remains

Expected:

- No viable EC2 PassRole path.
- The remaining foreign-only Allow does not restore viability.

---

## Track D — Deferred families remain explicitly fail-closed

### DEF-01 — S3 resource policy

Expected: `UNSUPPORTED_POLICY_FAMILY`; no public-access result or graph.

### DEF-02 — SNS resource policy

Expected: `UNSUPPORTED_POLICY_FAMILY`; no confused-deputy conclusion.

### DEF-03 — KMS key policy

Expected: `UNSUPPORTED_POLICY_FAMILY`; no identity-policy wildcard interpretation.

### DEF-04 — RCP

Expected: `UNSUPPORTED_POLICY_FAMILY`; deny statements never become grants.

### DEF-05 — Full SCP ceiling semantics

Expected: block when the requested analysis exceeds supported SCP syntax/semantics; no identity capability edges.

### DEF-06 — NotPrincipal in role trust

Expected: blocked as unsupported/invalid for the selected family.

### DEF-07 — NotPrincipal in resource policy

Expected: blocked until resource-family and NotPrincipal semantics are implemented together.

### DEF-08 — Mixed identity/resource document

Expected: mixed-family blocking error; no fallback to whichever statement is understood.

### DEF-09 — Unsupported-to-supported family switch

Expected: unsupported warning clears before the supported Identity result; blocked graph/export state cannot leak.

### DEF-10 — Blocked export contract

Expected:

- JSON and Markdown may export diagnostic information.
- Both must say `BLOCKED` and name the selected unsupported family or element.
- No normal risk score, authoritative findings summary, or attack-path graph is included.

---

## Release gate

The bundle passes only when:

1. The boundary browser test targets stable rule identity and still proves the forbidden rule is absent.
2. Every required critic has an explicit valid PASS before approval.
3. Every critic terminal outcome writes a durable ledger record.
4. Ledger failure prevents approval.
5. Exact foreign-only PassRole targets do not create viable critical paths when account context disproves compatibility.
6. Same-account and wildcard-inclusive positive controls continue to detect valid paths.
7. Deferred families and NotPrincipal remain blocked without partial-success language.
8. Chromium, Firefox, WebKit, JSON export, and Markdown export agree on semantic state.
