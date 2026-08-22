# Deploy - IAM Blast Radius

## Pelican wiring (already added to pelicanconf.py)
`pelicanconf.py` adds `tools` to `STATIC_PATHS`, so
`content/tools/iam-blast-radius/**` ships verbatim to `/tools/iam-blast-radius/**`
(no remap, no Pelican processing). No build step: committed vanilla JS/CSS/HTML
is what ships. `scripts/csp_audit.py` must stay clean (no inline
style/script/on-handlers).

## Cloudflare route CSP header (Oliver - required for real enforcement)
Pelican/Pages cannot set per-route headers. Add a Cloudflare Response Header
Transform Rule for `URI Path starts with /tools/iam-blast-radius/`:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none';
  base-uri 'none'; frame-ancestors 'none'; form-action 'none';
  worker-src 'self'; manifest-src 'self'
```
The page also ships a `<meta>` CSP fallback (weaker; cannot enforce
frame-ancestors). The real network-isolation guarantee is that the shipped
JS contains no network APIs at all (enforced by a grep gate in CI).

## Route hygiene (this path only)
- No analytics, no comment widget, no ads, no CDN scripts.
- No service worker caching analyzed content.
- No localStorage/IndexedDB/cookies for policy content.

## Release flow
Ralph loop -> review branch + local preview -> human review -> Oliver merges
and adds the Cloudflare header. Never auto-publish.
