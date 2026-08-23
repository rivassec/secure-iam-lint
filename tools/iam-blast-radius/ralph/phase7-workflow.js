export const meta = {
  name: 'iam-blast-radius-ralph-phase7',
  description: 'Phase 7 correctness fix-pass: close the 24-case complex acceptance suite (Bucket 1 bugs) + fixturize all 24 + cross-test invariants, then full re-test. Role-trust family is the queued NEXT feature, NOT this run.',
  phases: [{ title: 'Implement' }, { title: 'Gate' }, { title: 'Critics' }, { title: 'Arbiter' }, { title: 'Re-test' }],
}

const REPO = '/Users/oliver/dev/devsecops-notes'
const DEV = `${REPO}/tools/iam-blast-radius`
const SHIP = `${REPO}/content/tools/iam-blast-radius`
const CONTRACTS = `${DEV}/docs/architecture.md and ${DEV}/docs/threat-model.md (IMMUTABLE)`
const SUITE = `${DEV}/docs/acceptance-suite.md (the normative 24-case complex acceptance suite + 12 cross-test invariants)`
const MAP = '~/knowledge/personal/iam-blast-radius-battle-test-2026-08-22.md (per-test verdicts from the battle test against the current engine)'

// Serial: all stories edit the shared engine/render/test tree; layered deps
// (provenance -> edge typing -> compound -> complement/version -> dedup -> data-read -> fixturize+retest).
const STORIES = [
  { id: 'IAM-701', maxIter: 4 },
  { id: 'IAM-702', maxIter: 4 },
  { id: 'IAM-703', maxIter: 4 },
  { id: 'IAM-704', maxIter: 4 },
  { id: 'IAM-705', maxIter: 4 },
  { id: 'IAM-706', maxIter: 4 },
  { id: 'IAM-707', maxIter: 5 },
]

const BASELINE = `You are a (replaceable) engineer on the LIVE, LAUNCHED IAM Blast Radius tool in ${REPO}. Shipped vanilla ES-module JS/CSS/HTML: ${SHIP}/. Dev tests: ${DEV}/tests/; fixtures: ${DEV}/fixtures/. Read ${CONTRACTS}, the full story (id + requirements + acceptance) from ${DEV}/prd.json, and the relevant tests in ${SUITE} FIRST. Verdicts context: ${MAP}.

This MODIFIES a working, deployed, INDEXED tool. The full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN and MUST stay green; update tests/fixtures only for behavior a story INTENTIONALLY changes; never weaken an assertion or regress a prior invariant. The following tests were already PASSING and must not regress: suite tests 6, 11, 20, 22A, 22B, 23, plus the entire fixtures/negative corpus.

HARD RULES: no network APIs in shipped JS (connect-src is 'none'); no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; DOM via createElement+textContent; reject __proto__/constructor; DETERMINISTIC engine (byte-equivalent semantic JSON on re-analyze); no inline style/script/on-handlers in HTML; reports "potential blast radius" NOT "effective permissions"; NEVER assert beyond the evidence. NO build step (committed JS is what ships). tsc is not installed; Playwright/e2e is CI's job (update specs, do not claim you ran a browser).

PHASE-7 THESIS: this is a CORRECTNESS fix-pass, not new coverage. Close the Bucket-1 bugs in the acceptance suite while preserving the engine's honesty. Role-trust family analysis (suite tests 10/15/16/17/18) is the QUEUED NEXT FEATURE and is OUT OF SCOPE here - those must stay fail-closed. Full SCP ceiling analysis is also later; test 19 only needs fail-closed detection (not identity fallback). Every finding, edge, and evidence record you touch must trace back to the exact statement that grants it. When in doubt, fail closed or reduce confidence rather than overclaim.`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'noNetwork', 'noUnsafeDom', 'cspClean', 'fixturesValidJson', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

function critics(story) {
  return [
    { key: 'qa-iam-semantics', prompt: `QA + IAM-semantics critic for ${story.id}. Read the story in ${DEV}/prd.json and the specific suite tests it targets in ${SUITE}. Review the diff (cd ${REPO} && git diff -- content/tools tools/iam-blast-radius) and run cd ${DEV} && node --test "tests/**/*.test.js". VERIFY BY DRIVING analyze() DIRECTLY (write a scratch .mjs importing ${SHIP}/engine/analyze.js and feed the exact suite policies) - do not trust the fixtures alone. Blocking if: any action is attributed to a statement that does not grant it (provenance); any graph edge aggregates unlike capabilities or reuses a generic type where a specific one applies; a compound path uses a flat AND-list where alternatives exist, or lists an action absent from the policy; a NotAction/NotResource excluded set is shown as allowed; an unsupported version or SCP-shape is silently analyzed; a severity is inconsistent with a single documented scoring model; exports (JSON/Markdown/UI counts) disagree; OR any suite test the story claims to fix is still wrong. Also blocking if a role-trust test (10/15/16/17/18) stopped failing closed (out of scope this phase). Read-only; do NOT edit.` },
    { key: 'security', prompt: `Security critic for ${story.id} using ${CONTRACTS}. Review diff + grep ${SHIP}. Blocking if: any network API in shipped JS; innerHTML/outerHTML/insertAdjacentHTML/eval/new Function/unsafe DOM; DOM/attrs built unsafely from policy input; __proto__/constructor not rejected; inline style/script/on-handler in HTML; XSS/proto-pollution/injection fixtures no longer inert; policy content leaks to storage/URL/network/error payloads; new data-read "inferred sensitivity" text overclaims (asserts data IS sensitive rather than naming-inferred) or exfiltrates. Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${story.id}. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression). Confirm: zero uncaught exceptions on malformed/adversarial + all acceptance fixtures; determinism (re-analyze the suite policies twice, semantic JSON byte-equivalent excluding timestamps); single-flight worker correctness unaffected; DoS caps hold; and NO regression in previously-passing tests (suite 6/11/20/22A/22B/23 + fixtures/negative). Flag any nondeterminism, uncaught throw, or regressed test as blocking. Read-only except running tests; do NOT edit source.` },
  ]
}

const results = []
for (const story of STORIES) {
  log(`=== ${story.id} starting ===`)
  let accepted = false, feedback = '', lastGate = null, lastFindings = []
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nImplement story ${story.id} (full spec + acceptance in ${DEV}/prd.json). Modify shipped module(s) under ${SHIP}/engine (and render-graph.js/report.js where exports/UI counts are affected), ADD the acceptance fixtures the story requires under ${DEV}/fixtures/acceptance/, wire them into a test, and keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: 'Implement', agentType: 'general-purpose' }
    )
    lastGate = await agent(
      `Deterministic gate for ${story.id}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (full regression - ALL must pass; capture regressed test names); (b) grep ${SHIP} for network APIs (fetch/XMLHttpRequest/WebSocket/EventSource/sendBeacon/import of https) -> noNetwork; (c) grep ${SHIP} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> noUnsafeDom; (d) cd ${REPO} && python3 scripts/csp_audit.py content/tools -> cspClean; (e) all ${DEV}/fixtures/**/*.json parse as JSON -> fixturesValidJson. pass=true iff all hold. List concrete failures incl regressed test names. Do NOT edit.`,
      { label: `gate:${story.id}:i${iter}`, phase: 'Gate', agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
    )
    if (!lastGate || !lastGate.pass) { feedback = `Gate failed: ${JSON.stringify(lastGate && lastGate.failures || ['gate null'])}`; log(`${story.id} i${iter}: gate FAIL`); continue }
    const cr = await parallel(critics(story).map((c) => () =>
      agent(c.prompt, { label: `critic:${c.key}:${story.id}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA })))
    lastFindings = cr.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))
    const blocking = lastFindings.filter((f) => f.blocking)
    if (blocking.length === 0) { accepted = true; log(`${story.id} ACCEPTED i${iter}`); break }
    feedback = blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
    log(`${story.id} i${iter}: ${blocking.length} blocking (${[...new Set(blocking.map((f) => f.critic))].join(',')}), re-impl`)
  }
  await agent(
    `Update ${DEV}/progress.md: add/set a row for ${story.id} to ${accepted ? 'accepted' : 'human-review'} with iteration count + any remaining blockers. ${accepted ? '' : `Blockers:\n${feedback}`} Edit only that row/notes.`,
    { label: `ledger:${story.id}`, phase: 'Arbiter', agentType: 'general-purpose', effort: 'low' }
  )
  results.push({ story: story.id, accepted, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length })
}

// Final independent full re-test across the whole 24-case suite (Oliver: "re-test everything at the end").
phase('Re-test')
const RETEST_SCHEMA = { type: 'object', properties: { nodeTestGreen: { type: 'boolean' }, perTest: { type: 'array', items: { type: 'object', properties: { test: { type: 'string' }, verdict: { type: 'string', enum: ['pass', 'fail', 'blocked-by-design'] }, note: { type: 'string' } }, required: ['test', 'verdict'] } }, regressions: { type: 'array', items: { type: 'string' } }, summary: { type: 'string' } }, required: ['nodeTestGreen', 'perTest', 'regressions', 'summary'] }
const retest = await agent(
  `Independent final re-test of the IAM Blast Radius engine against the FULL 24-case suite (+22A/B/C) in ${SUITE}. Do this yourself, do not trust prior agents: (1) cd ${DEV} && node --test "tests/**/*.test.js" -> nodeTestGreen + any failing test names into regressions. (2) Write a scratch .mjs that imports ${SHIP}/engine/analyze.js, parses each \`\`\`json policy under every "## Test N" heading in ${SUITE}, runs analyze(), and evaluates it against that test's Expected-result prose. For each test emit verdict: pass (fixed/correct), fail (still wrong - describe), or blocked-by-design (role-trust 10/15/16/17/18 fail-closed + full-SCP-semantics; correct to remain blocked this phase). (3) Confirm the originally-passing tests (6,11,20,22A,22B,23) and fixtures/negative did NOT regress - list any that did in regressions. Return the per-test scoreboard + a one-paragraph summary. Read-only; do NOT edit source.`,
  { label: 'final-retest', phase: 'Re-test', agentType: 'general-purpose', schema: RETEST_SCHEMA }
)

return {
  built: results,
  acceptedCount: results.filter((r) => r.accepted).length,
  total: results.length,
  retest,
  note: 'Phase 7 correctness fix-pass. After this: re-run security probes + e2e in CI, deploy, and PURGE Cloudflare cache (local token). Role-trust family is the QUEUED next feature. Oliver open items unchanged: disable Rocket Loader on the tool path, Web Analytics/RUM toggle.',
}
