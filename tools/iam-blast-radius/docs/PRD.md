# IAM Blast Radius - PRD

A privacy-preserving, 100% client-side IAM policy analyzer hosted on
rivassec.com at `/tools/iam-blast-radius/`. It shows the **potential blast
radius** of supplied IAM policy context - never "effective permissions,"
which cannot be computed from an isolated policy.

## Why it is honest by design
AWS evaluates identity + resource + trust policies, permission boundaries,
SCPs, and session policies together, with explicit Deny overriding Allow. A
single-policy analyzer therefore cannot claim complete effective permissions.
The tool states this prominently and grades every conclusion by certainty.

## Modes
- **Quick analysis:** paste one policy; show potential capabilities and
  escalation paths, with an explicit "not effective permissions" banner.
- **Contextual analysis (Phase 3):** import a bundle (identity, trust,
  resource, boundary, SCP, session policies + ARNs); grade edges as
  confirmed / conditional / potential / blocked-by-deny / unknown.

## MVP (this build)
1. IAM JSON input only (paste + .json upload).
2. Findings: wildcard, destructive, exfiltration, direct-IAM admin.
3. 5-10 carefully tested privilege-escalation paths.
4. Evidence-backed findings table (authoritative, accessible).
5. Basic attack-path graph (progressive enhancement, never the only view).
6. JSON/Markdown report export.
7. Strict CSP + zero network egress.
8. Chromium, Firefox, WebKit testing.

Explicitly NOT in MVP: Terraform/HCL (Phase 4), managed-policy catalogs,
full multi-policy effective-permission evaluation (Phase 3 partial).

## Release gate (a build is releasable only when)
- IAM semantics: 100% (no false allow/deny)
- Security: no high/critical findings; zero network egress verified
- Privacy/network: 100%
- Core engine reliability: statement coverage 100%, branch >=95%,
  mutation score for evaluator >=90%, 0 known critical FP/FN, 0 unhandled
  exceptions, 0 non-deterministic results
- Compatibility: Chromium + Firefox + WebKit pass
- Accessibility: no serious/critical violations; findings table works with
  no graph and degrades gracefully with JS disabled
- Dependency security: no unaccepted high/critical
- Docs: limitations + rule version visible in the UI

## Toolchain-gated items (require CI/browser, not the authoring loop)
Playwright browser matrix, real-device smoke, mutation testing, and
`npm audit`/OSV run in CI. The Ralph authoring loop delivers code + unit
tests + fixtures + the CI config; those gates are green in CI, not asserted
by the authoring agents. See progress.md for gate status per story.

## Deploy
Static assets under `content/extra/tools/iam-blast-radius/`, mapped to
`/tools/iam-blast-radius/` by Pelican. Route CSP header via Cloudflare.
The Ralph loop produces a review branch + preview; it NEVER publishes to the
blog directly. See DEPLOY.md.
