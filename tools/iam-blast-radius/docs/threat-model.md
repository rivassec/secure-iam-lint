# IAM Blast Radius - Threat Model (immutable contract)

The tool analyzes attacker-controlled IAM JSON in the victim's browser. The
policy text is HOSTILE. The security critic blocks any story that violates
this file.

## Assets
- The user's pasted/imported policy content (must never leave the device).
- The integrity of the user's browser session (no XSS, no code exec).

## Trust boundary
Everything after page load runs locally. There is no backend. There are no
credentials. There is no server to attack. The adversary is the *content*.

## Threats and required controls

T1. **DOM XSS via policy fields** (SIDs, ARNs, condition values contain
`<script>`, `<img onerror>`, SVG payloads).
-> Build DOM with `createElement`+`textContent` only. Never `innerHTML`/
`insertAdjacentHTML`/`outerHTML` from input. Never set `href`/`src`/`style`/
event attributes from input. SVG graph text via `textContent` on SVG text
nodes, numeric attributes only, never inject markup.

T2. **Code injection** -> No `eval`, `new Function`, `setTimeout(string)`,
dynamic `<script>`, or remote `import()`. CSP `script-src 'self'` backs this.

T3. **Prototype pollution** via `__proto__`/`constructor`/`prototype` keys in
parsed JSON -> Reject these keys in validation; parse with a reviver or use
`Object.create(null)` maps; never deep-merge input into objects.

T4. **Data exfiltration** of the analyzed policy -> Zero network egress
(architecture invariant 1). CSP `connect-src 'none'` (Cloudflare header) +
code-level absence of network APIs. No `localStorage`/`IndexedDB`/cookies for
policy content. Explicit "Clear analysis" button; clear in-memory state on
`pagehide`/navigation. No service worker caching analyzed content.

T5. **Resource exhaustion / DoS** (multi-MB policies, thousands of
statements, deep nesting, circular refs) -> Enforce limits BEFORE parse:
max input bytes, max JSON depth, max statements/actions/resources, max graph
nodes. Run analysis in a Web Worker with a wall-clock budget; terminate on
overrun and report gracefully. Reject circular structures.

T6. **Unsafe export** -> Prefer JSON/Markdown export. If HTML export is
offered, escape all interpolated policy values. Downloads via Blob only.

T7. **Supply chain** -> Minimal, self-hosted, pinned deps. The SHIPPED tool
(engine + app + worker + CLI + Action) has ZERO runtime dependencies and NO
build step (architecture invariants 2 + 7): what is committed is what runs, so
there is no build-time transform and no transitive-runtime compromise surface.
Dev-only tooling (test/e2e/mutation) has its top-level versions exact-pinned in
`package.json` (no `^`/`~`), but there is NO committed `package-lock.json`, so
transitive dev-dependency versions are not lockfile-pinned and CI installs them
with `npm install` (not `npm ci`). This is accepted because that tooling never
ships to consumers: the shipped artifact has zero runtime dependencies, so an
unpinned transitive dev dep cannot reach a consumer's build or runtime.
Controls ENFORCED in CI today (`.github/workflows/security.yml` + `ci.yml`):
- GH Actions pinned to full commit SHAs; the `zizmor` unpinned-uses audit gates
  it (any un-pinned `uses:` fails the Security workflow).
- `gitleaks` scans the full git history for secrets.
- `actionlint` lints every workflow.
NOT yet implemented (tracked; this file must NOT claim them as present until the
workflow actually runs them): SBOM generation, `npm audit` / OSV dependency-
advisory scanning, and an automated license allowlist. These would cover only
the dev-only deps (the shipped artifact has none), so they rank below the
zero-runtime-dep + no-build guarantees above.

T8. **Misleading conclusions as a security harm** -> The tool must not claim
effective permissions from insufficient context. Overstated certainty is a
blocking finding (a user could wrongly clear a real risk). Distinguish
confirmed / conditional / potential / blocked / unknown.

## CSP (route header, Cloudflare - see DEPLOY.md)
```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none';
frame-ancestors 'none'; form-action 'none'; worker-src 'self'; manifest-src 'self'
```
A `<meta>` CSP in index.html is a weaker fallback (cannot enforce
frame-ancestors); the code-level no-network guarantee is the real control.

## Out of scope (MVP)
Live AWS calls, credential handling, server-side anything, Terraform/HCL
(later milestone), managed-policy catalogs (later).
