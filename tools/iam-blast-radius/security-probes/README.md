# Security probe harness (battle-test)

Adversarial probes used to battle-test the IAM Blast Radius tool. These are
manual/reproducible harnesses, not part of the blocking CI (`node --test`
ignores `.mjs`; Playwright's testDir is `tests/e2e/`). The unit suite
(`tests/`) and the negative corpus (`tests/negative.test.js`) are the
gating regression tests; browser-level XSS/egress are also covered by the
e2e specs in `tests/e2e/`.

## engine-probes.mjs (node, no deps)
Prototype pollution (4 vectors), ReDoS timing, resource exhaustion (20k
statements / deep nesting / 5MB), crash/malformed inputs (must never throw),
determinism under adversarial input.

```
node security-probes/engine-probes.mjs
# expect: ENGINE PROBES: 21 passed, 0 failed
```

## browser-probes.mjs (Playwright)
Real-browser probes: XSS execution (dialog listener) + DOM injection across
8 payload types, network-egress detection (any non-origin request during
analysis), DoS responsiveness, export safety. Runs against a URL (local
served copy or the live site).

```
npm install --no-save @playwright/test@1.55.0 && npx playwright install chromium
# local:
python3 -m http.server 8099 --directory ../../content &
node security-probes/browser-probes.mjs http://127.0.0.1:8099/tools/iam-blast-radius/
# live:
node security-probes/browser-probes.mjs https://rivassec.com/tools/iam-blast-radius/
```

Note: against the LIVE site the egress check will report
`static.cloudflareinsights.com` - that is Cloudflare Web Analytics auto-
injecting a beacon (blocked by the route CSP `script-src 'self'`), not the
tool. Disable Web Analytics/RUM for the zone to remove it entirely.
