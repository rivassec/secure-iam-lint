export const meta = {
  name: 'iam-blast-radius-ralph-phase2',
  description: 'Phase 2 Ralph loop: smarter analyzer output (severity remodel, wording precision, confidence split, correlation, risk summary, compact table, graph transition node, DoS caps)',
  phases: [{ title: 'Implement' }, { title: 'Gate' }, { title: 'Critics' }, { title: 'Arbiter' }],
}

const REPO = '/Users/oliver/dev/devsecops-notes'
const DEV = `${REPO}/tools/iam-blast-radius`
const SHIP = `${REPO}/content/tools/iam-blast-radius`
const CONTRACTS = `${DEV}/docs/architecture.md and ${DEV}/docs/threat-model.md (IMMUTABLE - never weaken to pass)`

// Serial order: engine content -> correlation -> presentation. Shared file tree.
const STORIES = [
  { id: 'IAM-108', maxIter: 4, ui: false },
  { id: 'IAM-103', maxIter: 4, ui: false },
  { id: 'IAM-102', maxIter: 4, ui: false },
  { id: 'IAM-104', maxIter: 4, ui: false },
  { id: 'IAM-105', maxIter: 5, ui: false },
  { id: 'IAM-106', maxIter: 4, ui: true },
  { id: 'IAM-101', maxIter: 5, ui: true },
  { id: 'IAM-107', maxIter: 5, ui: true },
]

const BASELINE = `You are working in the git repo ${REPO} on the EXISTING, deployed IAM Blast Radius tool. Shipped vanilla ES-module JS/CSS/HTML is under ${SHIP}/; dev tests under ${DEV}/tests/, fixtures under ${DEV}/fixtures/. Read the immutable contracts first: ${CONTRACTS}, and the full story from ${DEV}/prd.json.

PHASE 2 = MODIFYING working code. The existing test suite (run: cd ${DEV} && node --test "tests/**/*.test.js") is currently GREEN and MUST stay green. Update unit/e2e tests and fixtures ONLY to reflect behavior THIS story intentionally changes (e.g. new severity levels, split confidence fields, compact table layout, risk-factor sub-properties). Do NOT weaken, skip, or delete assertions to make unrelated tests pass, and do NOT regress any Phase-1 invariant.

HARD RULES (unchanged): no network APIs in shipped JS (fetch/XHR/WebSocket/EventSource/sendBeacon/remote import); no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; build DOM with createElement+textContent; reject __proto__/constructor keys; deterministic engine (no Date.now/Math.random in analysis output); no inline style/script/on-handlers in HTML; report "potential blast radius" NOT "effective permissions", and never assert more than the evidence supports. tsc is not installed; tests run on node --test. Playwright is CI's job - update specs but do not claim browser runs.`

const GATE_SCHEMA = {
  type: 'object',
  properties: {
    pass: { type: 'boolean' }, nodeTest: { type: 'string' },
    noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' },
    failures: { type: 'array', items: { type: 'string' } },
  },
  required: ['pass', 'noNetwork', 'noUnsafeDom', 'fixturesValidJson', 'failures'],
}
const FINDING_SCHEMA = {
  type: 'object',
  properties: {
    critic: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' },
          required_outcome: { type: 'string' }, blocking: { type: 'boolean' },
        },
        required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'],
      },
    },
  },
  required: ['critic', 'findings'],
}

function critics(storyId, ui) {
  const c = [
    { key: 'iam-semantics', prompt: `Adversarial IAM-semantics critic for ${storyId}. Review the diff (cd ${REPO} && git diff). Verify every security CLAIM is technically accurate vs real AWS behavior: severities not overstated beyond evidence; wording precise (cross-account AssumeRole scope, iam:PassedToService constrains-not-guarantees, kms:Decrypt != secret retrieval, no false Allow/Deny); compound-path correlation never drops a genuinely independent finding and never invents a path. Any inaccurate or overstated claim is blocking. Read-only; do NOT edit.` },
    { key: 'security-privacy', prompt: `Security+privacy critic for ${storyId} using ${CONTRACTS}. Review the diff and grep ${SHIP}. Blocking if: any network API; innerHTML/eval/unsafe DOM; DOM built unsafely from input; __proto__ not rejected; inline style/script/on-handler in HTML; XSS/proto-pollution fixtures no longer inert. Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${storyId}. Run cd ${DEV} && node --test "tests/**/*.test.js" and confirm the WHOLE suite passes (Phase-1 + new), zero uncaught exceptions on malformed/adversarial fixtures, deterministic output, and that DoS input caps (IAM-108) actually bound huge inputs. Flag any regression in previously-passing tests as blocking. Read-only except running tests; do NOT edit source.` },
  ]
  if (ui) c.push({ key: 'compatibility-ux', prompt: `Compatibility+a11y critic for ${storyId}. Statically review ${SHIP} HTML/CSS/JS. Blocking if: experimental APIs without fallback; findings table not usable without the graph; no keyboard access; graph the only representation; reduced-motion ignored; serious/critical a11y barrier; the compact table (IAM-101) hides prose with no accessible way to reach it. Confirm Playwright specs updated for layout changes. Read-only; do NOT edit.` })
  return c
}

const results = []
for (const story of STORIES) {
  log(`=== ${story.id} starting ===`)
  let accepted = false, feedback = '', lastGate = null, lastFindings = []
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nImplement Phase-2 story ${story.id} (full spec + acceptance in ${DEV}/prd.json). Modify the shipped module(s) under ${SHIP}/, update unit tests under ${DEV}/tests/ and fixtures under ${DEV}/fixtures/ to match intentional changes, and keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking items, without weakening acceptance or contracts:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: 'Implement', agentType: 'general-purpose' }
    )
    lastGate = await agent(
      `Deterministic gate for ${story.id}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (capture full pass/fail; this is the regression guard - ALL tests must pass); (b) grep ${SHIP} for network APIs -> noNetwork; (c) grep ${SHIP} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> noUnsafeDom; (d) all ${DEV}/fixtures/**/*.json parse -> fixturesValidJson. pass=true iff node --test fully green AND noNetwork AND noUnsafeDom AND fixturesValidJson. List concrete failures (incl. any regressed test names). Do NOT edit.`,
      { label: `gate:${story.id}:i${iter}`, phase: 'Gate', agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
    )
    if (!lastGate || !lastGate.pass) { feedback = `Gate failed: ${JSON.stringify(lastGate && lastGate.failures || ['gate null'])}`; log(`${story.id} i${iter}: gate FAIL`); continue }
    const cr = await parallel(critics(story.id, story.ui).map((c) => () =>
      agent(c.prompt, { label: `critic:${c.key}:${story.id}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA })))
    lastFindings = cr.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))
    const blocking = lastFindings.filter((f) => f.blocking)
    if (blocking.length === 0) { accepted = true; log(`${story.id} ACCEPTED i${iter}`); break }
    feedback = blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
    log(`${story.id} i${iter}: ${blocking.length} blocking, re-impl`)
  }
  await agent(
    `Update ${DEV}/progress.md: add/set a row for Phase-2 story ${story.id} to ${accepted ? 'accepted' : 'human-review'} with iterations used and remaining blockers. ${accepted ? '' : `Blockers:\n${feedback}`} Edit only that row/notes.`,
    { label: `ledger:${story.id}`, phase: 'Arbiter', agentType: 'general-purpose', effort: 'low' }
  )
  results.push({ story: story.id, accepted, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length })
}
return { built: results, acceptedCount: results.filter((r) => r.accepted).length, total: results.length,
  note: 'Phase 2 modifies existing code; gate ran the full regression suite each story. Re-run security probes + Playwright + deploy + Cloudflare purge after.' }
