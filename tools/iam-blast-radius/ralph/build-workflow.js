export const meta = {
  name: 'iam-blast-radius-ralph',
  description: 'Autonomous Ralph loop building the IAM Blast Radius MVP: one impl agent per story, deterministic gate, parallel critics, arbiter, iteration caps',
  phases: [
    { title: 'Implement' },
    { title: 'Gate' },
    { title: 'Critics' },
    { title: 'Arbiter' },
  ],
}

const REPO = '/Users/oliver/dev/devsecops-notes'
const DEV = `${REPO}/tools/iam-blast-radius`          // dev: prd/docs/tests/fixtures
const SHIP = `${REPO}/content/tools/iam-blast-radius` // shipped: html/css/js
const CONTRACTS = `${DEV}/docs/architecture.md and ${DEV}/docs/threat-model.md (IMMUTABLE - never weaken to pass)`

// Mirror of prd.json (scripts have no fs; agents read the full prd.json from disk).
const STORIES = [
  { id: 'IAM-001', maxIter: 4, ui: false },
  { id: 'IAM-002', maxIter: 4, ui: false },
  { id: 'IAM-003', maxIter: 4, ui: false },
  { id: 'IAM-004', maxIter: 4, ui: false },
  { id: 'IAM-005', maxIter: 4, ui: false },
  { id: 'IAM-006', maxIter: 4, ui: false },
  { id: 'IAM-007', maxIter: 5, ui: true },
  { id: 'IAM-008', maxIter: 5, ui: true },
]

const BASELINE = `You are working in the git repo ${REPO}. Shipped vanilla ES-module JS/CSS/HTML goes under ${SHIP}/ (this is what deploys, verbatim, no build step). Dev-only tests go under ${DEV}/tests/, fixtures under ${DEV}/fixtures/. Read the immutable contracts first: ${CONTRACTS}, and the full story from ${DEV}/prd.json. HARD RULES: no network APIs anywhere in shipped JS (no fetch/XHR/WebSocket/EventSource/sendBeacon/remote import); no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; build DOM with createElement+textContent; reject __proto__/constructor keys; engine must be deterministic (no Date.now/Math.random in analysis output); no inline style/script/on-handlers in HTML. Do NOT add runtime dependencies. Tests run on node's built-in runner (node --test); tsc is NOT installed so do not rely on a build. Playwright/browser tests are CI's job - write the code and (for UI stories) a Playwright spec + a .github workflow, but do not claim browser tests ran.`

const GATE_SCHEMA = {
  type: 'object',
  properties: {
    pass: { type: 'boolean' },
    nodeTest: { type: 'string' },
    noNetwork: { type: 'boolean' },
    noUnsafeDom: { type: 'boolean' },
    fixturesValidJson: { type: 'boolean' },
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
          id: { type: 'string' },
          severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
          location: { type: 'string' },
          criterion: { type: 'string' },
          evidence: { type: 'string' },
          required_outcome: { type: 'string' },
          blocking: { type: 'boolean' },
        },
        required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'],
      },
    },
  },
  required: ['critic', 'findings'],
}

function critics(storyId, ui) {
  const c = [
    { key: 'iam-semantics', prompt: `Adversarial IAM-semantics critic for story ${storyId}. Review the change in ${REPO} (run: cd ${REPO} && git diff). Verify IAM correctness against real AWS behavior: no false Allow/Deny; explicit-Deny precedence honored; NotAction/NotResource semantics correct; escalation rules require the real action combination (e.g. iam:PassRole ALONE is never an escalation - it needs a service-execution action and must respect Resource/NotResource/iam:PassedToService); missing context represented as 'unknown', never inferred. Any false allow/deny conclusion is blocking. Read-only: do NOT edit files.` },
    { key: 'security-privacy', prompt: `Security+privacy critic for story ${storyId}, using ${CONTRACTS}. Review the diff (cd ${REPO} && git diff) and grep the shipped tree ${SHIP}. Blocking if: any network API present; any innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; DOM/attributes built from analyzed input unsafely; __proto__/constructor not rejected; missing input-size/depth/count limits; policy content persisted to storage; inline style/script/on-handler in HTML. Confirm the XSS and prototype-pollution fixtures would render/behave inertly. Read-only: do NOT edit files.` },
    { key: 'reliability', prompt: `Reliability critic for story ${storyId}. Run cd ${DEV} && node --test tests/ and inspect coverage of the new code. Blocking if: any uncaught exception on malformed/adversarial fixtures; non-deterministic output; missing positive OR negative OR boundary OR malformed fixture for a new rule; false certainty (claims effective permissions from a single policy). Note (non-blocking, for the ledger) any release-gate items that need CI (mutation score, coverage %). Read-only except you may run tests; do NOT edit source.` },
  ]
  if (ui) c.push({ key: 'compatibility-ux', prompt: `Compatibility+accessibility critic for story ${storyId}. Statically review the shipped HTML/CSS/JS in ${SHIP}. Blocking if: uses experimental/non-standard browser APIs without a fallback; findings table is not usable without the graph; no keyboard access; graph is the only representation of data; reduced-motion not respected; a serious/critical a11y barrier. You cannot launch browsers - review code + confirm a Playwright spec and CI workflow exist. Read-only: do NOT edit files.` })
  return c
}

const results = []

for (const story of STORIES) {
  log(`=== ${story.id} starting ===`)
  let accepted = false
  let feedback = ''
  let lastGate = null
  let lastFindings = []

  for (let iter = 1; iter <= story.maxIter; iter++) {
    // 1. Implement
    await agent(
      `${BASELINE}\n\nImplement story ${story.id} (read its full spec + acceptance from ${DEV}/prd.json). Write the shipped module(s) under ${SHIP}/, unit tests under ${DEV}/tests/, and any missing positive/negative/boundary/malformed fixtures under ${DEV}/fixtures/. Make node --test pass.${feedback ? `\n\nThis is iteration ${iter}. Address ONLY these blocking items from the previous round, without weakening acceptance criteria or the contracts:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: 'Implement', agentType: 'general-purpose' }
    )

    // 2. Deterministic gate
    lastGate = await agent(
      `Deterministic gate for story ${story.id}. Run exactly:\n(a) cd ${DEV} && node --test tests/  -> capture pass/fail\n(b) grep the shipped tree for network APIs: grep -rInE 'fetch\\(|XMLHttpRequest|WebSocket|EventSource|sendBeacon|import\\(["'"'"'\`]https?:' ${SHIP}/  -> noNetwork=true iff NO matches\n(c) grep for unsafe DOM/eval: grep -rInE 'innerHTML|outerHTML|insertAdjacentHTML|\\beval\\(|new Function' ${SHIP}/  -> noUnsafeDom=true iff NO matches\n(d) validate every ${DEV}/fixtures/**/*.json parses as JSON -> fixturesValidJson\npass=true iff node --test passed AND noNetwork AND noUnsafeDom AND fixturesValidJson. List concrete failures. Do NOT edit files.`,
      { label: `gate:${story.id}:i${iter}`, phase: 'Gate', agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
    )
    if (!lastGate || !lastGate.pass) {
      feedback = `Deterministic gate failed: ${JSON.stringify(lastGate && lastGate.failures || ['gate agent returned null'])}`
      log(`${story.id} iter ${iter}: gate FAILED`)
      continue
    }

    // 3. Critics fan out (parallel)
    const critived = await parallel(
      critics(story.id, story.ui).map((c) => () =>
        agent(c.prompt, { label: `critic:${c.key}:${story.id}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA })
      )
    )
    lastFindings = critived.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))

    // 4. Arbiter
    const blocking = lastFindings.filter((f) => f.blocking)
    if (blocking.length === 0) {
      accepted = true
      log(`${story.id} ACCEPTED on iteration ${iter}`)
      break
    }
    feedback = blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
    log(`${story.id} iter ${iter}: ${blocking.length} blocking findings, re-implementing`)
  }

  // 5. Ledger update
  await agent(
    `Update ${DEV}/progress.md for story ${story.id}: set status to ${accepted ? 'accepted' : 'human-review'}, record iterations used and remaining blocking findings. ${accepted ? '' : `Remaining blockers:\n${feedback}`} Edit only that table row and the notes; do not touch other rows.`,
    { label: `ledger:${story.id}`, phase: 'Arbiter', agentType: 'general-purpose', effort: 'low' }
  )

  results.push({ story: story.id, accepted, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length, gate: lastGate })
}

return {
  built: results,
  acceptedCount: results.filter((r) => r.accepted).length,
  total: results.length,
  note: 'Playwright browser matrix, mutation score, npm audit/OSV, and the Cloudflare CSP header are CI/human gates recorded in progress.md, not asserted by this loop.',
}
