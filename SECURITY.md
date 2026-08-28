# Security Policy

`secure-iam-lint` (IAM Blast Radius) analyzes AWS IAM policy JSON. The browser
tool runs entirely client-side with zero network egress; the CLI and GitHub
Action run locally and make no AWS API calls. It handles no credentials and has
no backend. See `tools/iam-blast-radius/docs/threat-model.md` for the full threat
model and trust boundary.

## Supported versions

The project is pre-1.0. Security fixes land on `main`, which is the only
supported line. Pin to a commit SHA if you need reproducibility.

| Version         | Supported    |
| --------------- | ------------ |
| `main`          | yes          |
| tagged releases | latest only  |

## Reporting a vulnerability

Please report suspected vulnerabilities privately, NOT via a public issue or
pull request.

- Preferred: GitHub private vulnerability reporting. Open the repository's
  "Security" tab and choose "Report a vulnerability". This opens a private
  advisory visible only to the maintainer.

Include a description, the affected file or component, reproduction steps or a
proof of concept, and the impact you observed. A minimal IAM policy that
triggers the issue is ideal.

### What to expect

- Acknowledgement within 5 business days.
- An initial assessment (severity and whether it is in scope) within 10 business
  days.
- For confirmed issues, a fix on `main` and a published advisory crediting the
  reporter, unless you prefer to remain anonymous.

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
