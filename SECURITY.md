# Security Policy

`secure-iam-lint` (IAM Blast Radius) analyzes AWS IAM policy JSON. The browser
tool runs entirely client-side with zero network egress; the CLI and GitHub
Action run locally and make no AWS API calls. It handles no credentials and has
no backend. See `tools/iam-blast-radius/docs/threat-model.md` for the full threat
model and trust boundary.

## Supported versions

Security fixes land on `main` and ship in the next tagged release. `main` and the
latest release are the supported lines; pin to a commit SHA or a release tag if
you need reproducibility.

| Version        | Supported   |
| -------------- | ----------- |
| `main`         | yes         |
| latest release | yes         |
| older releases | no          |

## Reporting a vulnerability

Please report suspected vulnerabilities privately, NOT via a public issue or
pull request.

- Preferred: GitHub private vulnerability reporting. Open a private advisory at
  <https://github.com/rivassec/secure-iam-lint/security/advisories/new> (or the
  repository's "Security" tab -> "Report a vulnerability"). This is visible only
  to the maintainer.

Include a description, the affected file or component, reproduction steps or a
proof of concept, and the impact you observed. A minimal IAM policy that
triggers the issue is ideal.

### What to expect

secure-iam-lint is maintained by one person in their spare time, so these are
best-effort targets rather than guarantees:

- Acknowledgement of your report within **7 days**.
- An initial assessment (severity and whether it is in scope) within **30 days**.
- For confirmed issues, a fix on `main` and a published advisory crediting the
  reporter, unless you prefer to remain anonymous.

GitHub emails the maintainer the moment a private advisory is filed, so
acknowledgement is usually much faster than the target.

## Scope

In scope:

- Cross-site scripting or code execution from hostile policy content in the
  browser tool (threat-model T1/T2).
- Any network egress of analyzed policy content (threat-model T4).
- Prototype pollution or resource-exhaustion / denial of service reachable from
  policy input (T3/T5).
- A fail-OPEN analysis result: the engine reporting CLEAN / exit 0 for a policy
  that carries a real, in-model capability it should have surfaced (T8).
- Unsafe file handling in the CLI or Action (path traversal, following symlinks
  out of the workspace, unbounded reads).

Out of scope:

- Findings that require an attacker who already has write access to the machine
  running the CLI or Action. The tool runs as the invoking user on the user's
  own files; there is no privilege boundary to cross.
- The correctness of AWS's own IAM evaluation. This tool models a documented
  subset and states its limitations in every finding.
- Dev-only tooling advisories that cannot reach the shipped artifact, which has
  zero runtime dependencies.
