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

T7. **Supply chain** -> Minimal, pinned, self-hosted deps; SBOM; `npm audit`
+ OSV in CI; license allowlist; GH Actions pinned to commit SHAs; no runtime
dependency download; reproducible build.

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
