# Deploy - IAM Blast Radius

## Pelican wiring (already added to pelicanconf.py)
`pelicanconf.py` adds `tools` to `STATIC_PATHS`, so
`content/tools/iam-blast-radius/**` ships verbatim to `/tools/iam-blast-radius/**`
(no remap, no Pelican processing). No build step: committed vanilla JS/CSS/HTML
is what ships. `scripts/csp_audit.py` must stay clean (no inline
style/script/on-handlers).

## Cloudflare route CSP header (Oliver - AUTHORITATIVE source of truth)
Pelican/Pages cannot set per-route headers. The HTTP response header set by
Cloudflare on this route is the authoritative CSP. Add a Cloudflare Response
Header Transform Rule for `URI Path starts with /tools/iam-blast-radius/` with
this EXACT value (single line - keep byte-for-byte identical to the
`AUTHORITATIVE-CSP-HEADER` line mirrored in `index.html`):
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; worker-src 'self'; manifest-src 'self'
```
The page also ships a `<meta http-equiv="Content-Security-Policy">` tag. It is a
documented, WEAKER FALLBACK only (for a file opened without this header). The
meta equals the authoritative header MINUS `frame-ancestors 'none'`, which is
ignored inside a meta tag and enforceable only via the HTTP header. The meta
must never add or drop any other directive.

These three copies - the Cloudflare header (this file), the
`AUTHORITATIVE-CSP-HEADER` comment in `index.html`, and the live `<meta>` tag -
must not silently diverge. A drift guard (`tests/csp-consistency.test.js`) fails
the suite if they disagree. There is no build step to rewrite them: the
committed `index.html` is what ships, and per-deploy asset coherence relies on
the Cloudflare cache purge.

The real network-isolation guarantee is not the CSP at all: the shipped JS
contains no network APIs whatsoever (enforced by a grep gate in CI). The CSP is
defense in depth on top of that.

## Route hygiene (this path only)
- No analytics, no comment widget, no ads, no CDN scripts.
- No service worker caching analyzed content.
- No localStorage/IndexedDB/cookies for policy content.

## Input preprocessing (documented behaviors)
- **UTF-8 BOM (IAM-1007 / suite-3 test 62):** `validate()` strips EXACTLY ONE
  leading `U+FEFF` byte-order mark, then validates normally. A file saved as
  "UTF-8 with BOM" (bytes `EF BB BF`) is therefore accepted on the paste path,
  matching the import path (a browser's `FileReader.readAsText` already consumes
  a leading BOM during UTF-8 decoding). Only the first code unit is removed; a
  `U+FEFF` embedded anywhere else in the text is preserved verbatim (never
  silently mutated). A second consecutive leading BOM is NOT stripped and falls
  through to the normal `INVALID_JSON` rejection. Regression-tested in
  `tests/phase10-parser-hardening.test.js`.
- **Ingestion parity (test 63):** paste, `.json` import, and the programmatic
  test harness all funnel through the same `validate()` + `analyze()`; the
  imported filename never influences policy-family selection or any finding.

## Release flow
Ralph loop -> review branch + local preview -> human review -> Oliver merges
and adds the Cloudflare header. Never auto-publish.
