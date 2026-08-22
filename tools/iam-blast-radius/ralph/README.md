# Ralph loop - IAM Blast Radius

One implementation agent per story, then independent critics fan out on the
same change; an arbiter accepts or rejects. The loop lives in the Claude Code
Workflow script `ralph/build-workflow.js` (run via the Workflow tool).

## Per-story state machine
1. Read immutable contracts (docs/architecture.md, docs/threat-model.md),
   prd.json, progress.md.
2. Implementation agent writes the module + unit tests + fixtures for ONE story.
3. Deterministic gate (Bash): `node --test`, the no-network grep, the
   no-innerHTML/eval grep, JSON validity of fixtures.
4. Parallel critics review the SAME change independently, structured findings:
   - iam-semantics: false allow/deny, escalation correctness vs AWS docs
   - security-privacy: XSS, network egress, prototype pollution, unsafe DOM
   - reliability: coverage, edge cases, determinism, false certainty
   - compatibility-ux: browser APIs used, a11y, keyboard, graph-optional
5. Arbiter: reject if ANY critic has a valid blocking finding; else accept.
6. On reject, implementation agent addresses findings (<= maximumIterations).
7. On accept, update progress.md; next story with fresh context.
8. On stall (cap hit with blockers), mark story human-review in progress.md.

## Rules
- The orchestrator CANNOT weaken acceptance criteria to pass a story.
- A critic finding is valid only with {location, criterion, evidence,
  required_outcome, severity, blocking}. "Make it more secure" is invalid.
- Binary accept (zero blocking findings), not averaged scores.
- Deterministic gates are truth; critics add semantic/security judgment.
- Toolchain-gated release items (Playwright matrix, mutation score, npm
  audit/OSV) are CI's job, recorded in progress.md, not asserted by agents.
