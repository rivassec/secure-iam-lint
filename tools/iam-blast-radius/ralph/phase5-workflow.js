export const meta = {
  name: 'iam-blast-radius-ralph-phase5',
  description: 'Phase 5: semantic assurance + delivery + staged SEO. Replaceable engineer agents; QA/Security/Reliability critics (+ compat-a11y on UI, SEO on the SEO story) gate every story.',
  phases: [{ title: 'Implement' }, { title: 'Gate' }, { title: 'Critics' }, { title: 'Arbiter' }],
}

const REPO = '/Users/oliver/dev/devsecops-notes'
const DEV = `${REPO}/tools/iam-blast-radius`
const SHIP = `${REPO}/content/tools/iam-blast-radius`
const CONTRACTS = `${DEV}/docs/architecture.md and ${DEV}/docs/threat-model.md (IMMUTABLE)`

// Serial (shared file tree, layered deps). SEO staged LAST.
const STORIES = [
  { id: 'IAM-501', maxIter: 6, ui: true,  seo: false },
  { id: 'IAM-502', maxIter: 5, ui: true,  seo: false },
  { id: 'IAM-503', maxIter: 6, ui: true,  seo: false },
  { id: 'IAM-504', maxIter: 6, ui: true,  seo: false },
  { id: 'IAM-505', maxIter: 4, ui: true,  seo: false },
  { id: 'IAM-506', maxIter: 5, ui: false, seo: false },
  { id: 'IAM-507', maxIter: 5, ui: false, seo: false },
  { id: 'IAM-508', maxIter: 3, ui: false, seo: false },
  { id: 'IAM-509', maxIter: 4, ui: true,  seo: true  },
]

const BASELINE = `You are a (replaceable) engineer on the live IAM Blast Radius tool in ${REPO}. Shipped vanilla ES-module JS/CSS/HTML: ${SHIP}/. Dev tests: ${DEV}/tests/; fixtures: ${DEV}/fixtures/. Read ${CONTRACTS} and the full story from ${DEV}/prd.json FIRST.

This MODIFIES a working, deployed tool. The full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN and MUST stay green; update tests/fixtures only for behavior this story INTENTIONALLY changes; never weaken assertions or regress a prior invariant.

HARD RULES (unchanged): no network APIs in shipped JS; no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; DOM via createElement+textContent; reject __proto__/constructor; deterministic engine; no inline style/script/on-handlers in HTML; reports "potential blast radius" NOT "effective permissions"; never assert beyond evidence. NO build step (committed JS is what ships; asset coherence relies on the per-deploy cache purge). tsc absent; Playwright is CI's job (update specs, don't claim browser runs).

KEY DESIGN REFINEMENTS for this phase: policy-family is AUTO-DETECT default (preserve paste-and-go) that FAILS CLOSED on ambiguous/mixed/unsupported (incl NotPrincipal); coverage panel is COMPACT, precedes findings in DOM order; conditions are CLASSIFIED, never claimed as runtime allow/deny; the action catalog is a SMALL VERSIONED curated snapshot (not the full AWS build) with unknown-action reporting; the SEO story STAGES metadata but KEEPS noindex and adds NO sitemap entry (human flip later). Use precise wording ("potential blast radius"); no meta keywords; no absolute privacy claims.`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'noNetwork', 'noUnsafeDom', 'cspClean', 'fixturesValidJson', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

function critics(story) {
  const c = [
    { key: 'qa-correctness', prompt: `QA + IAM-semantics critic for ${story.id}. Review the diff (cd ${REPO} && git diff) and run cd ${DEV} && node --test "tests/**/*.test.js". Verify: every IAM/security CLAIM is accurate per AWS grammar + evaluation logic; family detection is correct and fails closed on ambiguous/mixed/unsupported (NotPrincipal rejected, not ignored); coverage honestly reflects what was and wasn't analyzed ("unsupported != safe"); conditions are classified not claimed-as-runtime-decisions; the fixture matrix covers the story's rules; NO regression in previously-passing tests. Blocking on any false/overstated claim, silent omission of an unsupported element, or missing required fixture. Read-only; do NOT edit.` },
    { key: 'security', prompt: `Security critic for ${story.id} using ${CONTRACTS}. Review diff + grep ${SHIP}. Blocking if: any network API in shipped JS; innerHTML/eval/unsafe DOM; DOM/attrs built unsafely from input; __proto__ not rejected; inline style/script/on-handler in HTML; XSS/proto-pollution/injection fixtures no longer inert; policy content leaks to storage/URL/error payloads; a post-dispatch worker crash reprocesses hostile input on the main thread. Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${story.id}. Run the full suite; confirm zero uncaught exceptions on malformed/adversarial fixtures, deterministic output, single-flight worker correctness (stale results ignored, no main-thread retry after dispatch), DoS caps hold, and NO regression in prior tests. Flag nondeterminism or a regressed test as blocking. Read-only except running tests; do NOT edit source.` },
  ]
  if (story.ui) c.push({ key: 'compat-a11y', prompt: `Compatibility + accessibility critic for ${story.id}. Statically review ${SHIP} HTML/CSS/JS + the e2e specs. Blocking if: experimental APIs w/o fallback; the coverage panel or findings not usable/keyboard-accessible without the graph; missing aria-busy/live announcements for analysis states; a serious/critical a11y barrier; samples not keyboard-loadable; Playwright specs not updated for new UI. Read-only; do NOT edit.` })
  if (story.seo) c.push({ key: 'seo', prompt: `SEO critic for ${story.id}. Verify the STAGED metadata: precise wording ("potential blast radius"; NEVER "policy simulator"/"effective permissions"); NO meta keywords; NO absolute claims ("100% private"/"mathematically prove"/"zero exfiltration"); twitter:* via name= not property=; SoftwareApplication JSON-LD is truthful and every claim is VISIBLE on the page; no rich-result promises; canonical is self-referential. CRITICAL: noindex MUST still be present and NO sitemap entry added (this story only stages; the flip is a human decision) - blocking if noindex was removed or a sitemap entry added. Read-only; do NOT edit.` })
  return c
}

const results = []
for (const story of STORIES) {
  log(`=== ${story.id} starting ===`)
  let accepted = false, feedback = '', lastGate = null, lastFindings = []
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nImplement story ${story.id} (full spec + acceptance in ${DEV}/prd.json). Modify shipped module(s) under ${SHIP}/, update tests + fixtures for intentional changes, keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: 'Implement', agentType: 'general-purpose' }
    )
    lastGate = await agent(
      `Deterministic gate for ${story.id}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (full regression - ALL must pass); (b) grep ${SHIP} for network APIs -> noNetwork; (c) grep ${SHIP} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> noUnsafeDom; (d) cd ${REPO} && python3 scripts/csp_audit.py content/tools -> cspClean; (e) all ${DEV}/fixtures/**/*.json parse -> fixturesValidJson. pass=true iff all hold. List concrete failures incl regressed test names. Do NOT edit.`,
      { label: `gate:${story.id}:i${iter}`, phase: 'Gate', agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
    )
    if (!lastGate || !lastGate.pass) { feedback = `Gate failed: ${JSON.stringify(lastGate && lastGate.failures || ['gate null'])}`; log(`${story.id} i${iter}: gate FAIL`); continue }
    const cr = await parallel(critics(story).map((c) => () =>
      agent(c.prompt, { label: `critic:${c.key}:${story.id}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA })))
    lastFindings = cr.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))
    const blocking = lastFindings.filter((f) => f.blocking)
    if (blocking.length === 0) { accepted = true; log(`${story.id} ACCEPTED i${iter}`); break }
    feedback = blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
    log(`${story.id} i${iter}: ${blocking.length} blocking (${[...new Set(blocking.map(f=>f.critic))].join(',')}), re-impl`)
  }
  await agent(
    `Update ${DEV}/progress.md: add/set a row for ${story.id} to ${accepted ? 'accepted' : 'human-review'} with iterations + remaining blockers. ${accepted ? '' : `Blockers:\n${feedback}`} Edit only that row/notes.`,
    { label: `ledger:${story.id}`, phase: 'Arbiter', agentType: 'general-purpose', effort: 'low' }
  )
  results.push({ story: story.id, accepted, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length })
}
return { built: results, acceptedCount: results.filter((r) => r.accepted).length, total: results.length,
  note: 'Phase 5. Re-run security probes + e2e + deploy + Cloudflare purge after. SEO staged (noindex kept). Oliver actions: disable Rocket Loader, Web Analytics toggle, flip noindex when ready.' }
