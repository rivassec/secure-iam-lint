# IAM Blast Radius - Architecture (immutable contract)

Privacy-preserving, 100% client-side IAM policy analyzer. Ships as static
assets on the Pelican blog and served at `/tools/iam-blast-radius/`.
Every agent MUST treat this file as binding. Do not weaken it to pass a story.

## Non-negotiable invariants

1. **Zero network egress.** No `fetch`, `XMLHttpRequest`, `WebSocket`,
   `EventSource`, `navigator.sendBeacon`, `import()` of remote URLs, no
   `<img src=remote>`, no analytics. Policy content NEVER leaves the browser.
   This is guaranteed IN CODE, not only by CSP. A grep gate enforces it.
2. **No build step for shipped code.** Shipped files are vanilla ES-module
   JS + CSS + HTML under `content/tools/iam-blast-radius/`. They are
   served verbatim by Pelican (`STATIC_PATHS` 'tools' -> `/tools/`). What is
   committed is what runs.
3. **CSP-clean HTML.** No inline `style="..."`, no `<style>` blocks, no
   `on*=` event handlers in any HTML. All CSS in external `.css`; all event
   binding via `addEventListener` in external `.js`. (`scripts/csp_audit.py`
   fails the blog build otherwise.)
4. **Safe DOM only.** Never assign `innerHTML`/`outerHTML`/`insertAdjacentHTML`
   from analyzed input. Build DOM with `document.createElement` +
   `textContent`. Never `eval`, `Function()`, dynamic `<script>`, or
   `setAttribute` of `href`/`src`/`style` from input.
5. **Analyzed policies are HOSTILE input.** Validate against a strict schema.
   Reject dangerous keys (`__proto__`, `prototype`, `constructor`). Enforce
   limits: input bytes, JSON nesting depth, statement/action/resource counts,
   graph node count. Analysis runs in a Web Worker with a time/memory budget;
   terminate on overrun. A synchronous fallback exists for no-Worker envs.
6. **Truthful output.** The tool reports "potential blast radius based on the
   supplied policy context," never "effective permissions." A single policy
   cannot yield effective permissions; say so prominently.
7. **Near-zero dependencies.** Prefer none. Any dependency is self-hosted,
   pinned, license-checked, and isolated behind an interface (esp. any graph
   lib, behind a rendering interface so it is replaceable).
8. **Deterministic engine.** Same input -> same findings and same graph
   edges, every run. No `Date.now()`/`Math.random()` in analysis output.

## Module layout (shipped, `content/tools/iam-blast-radius/`)

```
index.html          CSP-clean shell; loads app.js as type=module
styles.css          all styling (no inline)
app.js              UI controller: input, DOM findings table, graph mount,
                    export, Clear button, spawns worker
worker.js           receives raw text, runs engine, posts back model+findings+graph
engine/
  validate.js       input-size/depth/key guards; strict schema validation
  parse.js          IAM JSON parser -> raw statements (tolerant of arrays/strings)
  model.js          Normalized IAM model (statements, effect, actions, resources,
                    conditions, notAction/notResource)
  evaluator.js      Allow/Deny/NotAction/NotResource semantics; explicit-deny
                    precedence; boundary/SCP/session constraint (Phase 3)
  rules.js          risk-rule catalog (wildcard, destructive, exfil, direct-IAM)
  escalation.js     attack-path rule families (PassRole+service, etc.)
  graph.js          node/edge model builder (data only; no rendering)
  render-graph.js   SVG renderer behind a rendering interface
  report.js         JSON + Markdown export (HTML export escaped, optional)
```

Dev-only (NOT served; outside content/): repo-root `tools/iam-blast-radius/` holds
`docs/`, `prd.json`, `progress.md`, `ralph/`, `fixtures/`, `tests/`,
`package.json`, CI. Tests import shipped modules by relative path.

## Data-flow

`paste/import -> validate -> parse -> normalized model -> evaluator + rules
+ escalation -> {findings[], graph{nodes,edges}} -> DOM findings table
(always) + SVG graph (progressive enhancement) -> JSON/MD export`.

The findings table is the source of truth and is fully usable with no graph
(accessibility + no-JS-graph requirement). The graph is never the only
representation.

## Finding object (canonical shape)

```json
{
  "id": "RULE-ID",
  "severity": "critical|high|medium|low|info",
  "title": "short label",
  "statementSid": "AllowLambdaDeployment | (index N)",
  "actions": ["iam:PassRole"],
  "resources": ["arn:aws:iam::...:role/app-*"],
  "conditions": {"...": "..."},
  "confidence": "high|medium|low",
  "why": "why it matters, plain language",
  "limit": "what context was missing / what this does NOT prove",
  "remediation": "concrete fix",
  "ruleVersion": "1",
  "docRef": "https://docs.aws.amazon.com/..."
}
```

## Graph model

Node types: Principal, Policy, Role, Service, ActionGroup, Resource,
DataStore, Account, ExternalPrincipal.
Edge types: allows, denies, can-assume, trusts, can-pass, can-modify,
can-execute-as, can-read, can-write, can-destroy.
Edge certainty (distinct visual styles, NOT blended into one score):
confirmed-by-context, conditionally-reachable, potentially-reachable,
blocked-by-deny, unknown-incomplete-context.
Every edge carries the exact supporting evidence (statement, action,
resource, condition) for a click/inspect panel and the findings table.

## Deploy wiring (Pelican)

`pelicanconf.py` adds `tools` to `STATIC_PATHS`, so
`content/tools/iam-blast-radius/` ships verbatim to `/tools/iam-blast-radius/`
(no remap, no Pelican processing). See DEPLOY.md for the Cloudflare route CSP
header (the enforceable network isolation).
