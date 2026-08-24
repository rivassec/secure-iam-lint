export const meta = {
  name: 'iam-blast-radius-ralph-phase10',
  description: 'Phase 10: MANDATORY policy-family selection + boundary/session semantics + fold the Suite-III gaps (takeover overlap/condition-compat, principal arrays, IAM/ECS precision, condition/false-positive precision, parser+render+limits), then re-run ALL THREE suites. Resource-policy/RCP families stay fail-closed.',
  phases: [{ title: 'Implement' }, { title: 'Gate' }, { title: 'Critics' }, { title: 'Arbiter' }, { title: 'Re-test' }],
}

const REPO = '/Users/oliver/dev/devsecops-notes'
const DEV = `${REPO}/tools/iam-blast-radius`
const SHIP = `${REPO}/content/tools/iam-blast-radius`
const CONTRACTS = `${DEV}/docs/architecture.md and ${DEV}/docs/threat-model.md (IMMUTABLE)`
const S1 = `${DEV}/docs/acceptance-suite.md (suite 1, tests 1-24)`
const S2 = `${DEV}/docs/acceptance-suite-2.md (suite 2, tests 25-54)`
const S3 = `${DEV}/docs/acceptance-suite-3.md (suite 3, regression+gap, tests 55-100)`

// Serial: shared engine/UI files, layered (mandatory-selection contract first). ui=extra compat/a11y critic.
const STORIES = [
  { id: 'IAM-1001', maxIter: 6, ui: true },
  { id: 'IAM-1002', maxIter: 5, ui: true },
  { id: 'IAM-1003', maxIter: 5, ui: false },
  { id: 'IAM-1004', maxIter: 4, ui: false },
  { id: 'IAM-1005', maxIter: 4, ui: false },
  { id: 'IAM-1006', maxIter: 4, ui: false },
  { id: 'IAM-1007', maxIter: 4, ui: true },
  { id: 'IAM-1008', maxIter: 5, ui: false },
]

const BASELINE = `You are a (replaceable) engineer on the LIVE, LAUNCHED, DEPLOYED IAM Blast Radius tool in ${REPO}. Shipped vanilla ES-module JS/CSS/HTML: ${SHIP}/. Dev tests: ${DEV}/tests/; fixtures: ${DEV}/fixtures/. Read ${CONTRACTS}, the story in ${DEV}/prd.json, and the target tests in ${S2} / ${S3} FIRST.

Full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN (956+) and MUST stay green; update tests/fixtures only for behavior a story INTENTIONALLY changes; never weaken an assertion. PROTECTED (must not regress): all suite-1 fixtures (1-24), the Phase-9 fixes (suite-2 44/34/48), the identity negative corpus (fixtures/negative), the trust negative corpus (fixtures/negative-trust).

HARD RULES: no network APIs in shipped JS; no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; DOM via createElement+textContent; reject __proto__/constructor; DETERMINISTIC engine; no inline style/script/on-handlers in HTML (wire via addEventListener in app.js); reports "potential blast radius" NOT "effective permissions"; NEVER assert beyond evidence; fail closed on unmodeled shapes. NO build step. Playwright/e2e is CI's job (update specs, don't claim you ran a browser).

PHASE-10 DESIGN (decided by Oliver 2026-08-23): policy-family selection is now MANDATORY - the UI must NOT analyze until the user explicitly picks a family; NEVER default to identity by shape. Auto-detect becomes an explicit opt-in menu choice, not a silent default. Keep the ENGINE api back-compatible so the existing 956 unit tests + suite-1/suite-2 fixtures do not need mass rewrites (unspecified family may still auto-detect at the engine level; the mandatory behavior is the UI contract). Permissions-boundary + session families are ENVELOPE/RESTRICTION with NO positive capability edges. SCOPE FENCE: do NOT build full resource-policy (S3/SNS/KMS) or RCP analysis - selecting those fails closed honestly; that is the remaining later tranche.`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'noNetwork', 'noUnsafeDom', 'cspClean', 'fixturesValidJson', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

function critics(story) {
  const c = [
    { key: 'qa-semantics', prompt: `QA + IAM-semantics critic for ${story.id}. Read the story in ${DEV}/prd.json + its target tests in ${S2}/${S3}. Review the diff (cd ${REPO} && git diff -- content/tools tools/iam-blast-radius) and run cd ${DEV} && node --test "tests/**/*.test.js". VERIFY BY DRIVING analyze() DIRECTLY (scratch .mjs importing ${SHIP}/engine/analyze.js, exercising the explicit family). Blocking if: the UI analyzes without an explicit family, or defaults to identity by shape (mandatory-selection contract broken); a permissions-boundary/session family emits ANY positive capability edge or escalation finding; a family shape-guard is wrong (Identity+Principal, Trust+Resource, Resource/SCP not failing closed); a targeted suite-3 test is still wrong; provenance/evidence wrong; exports omit family/status or disagree across surfaces; OR any suite-1 / suite-2 / Phase-9 / negative-corpus case regressed. Read-only; do NOT edit.` },
    { key: 'security', prompt: `Security critic for ${story.id} using ${CONTRACTS}. Review diff + grep ${SHIP}. Blocking if: any network API in shipped JS; innerHTML/eval/unsafe DOM; the family <select> or any handler wired via inline on-handler or built unsafely; __proto__/constructor not rejected; inline style/script in HTML (csp_audit must pass); a duplicate-key / injection scan that can ReDoS or hang on hostile input; policy content or selected family leaking to storage/URL/network; XSS/proto-pollution fixtures no longer inert; Markdown export producing active links/executable HTML from attacker-controlled strings (test 99). Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${story.id}. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression). Confirm: zero uncaught exceptions on malformed/adversarial + all fixtures; determinism (same input+family -> semantically identical JSON); family switching fully invalidates prior state (no stale results); parser/limit checks terminate fast (no hang) and early-abort ordering holds (size before parse, parse before semantics); suite-1/2 + Phase-9 fixtures + both negative corpora unchanged; DoS caps hold. Flag nondeterminism, an uncaught throw, a hang, stale state, or a regressed test as blocking. Read-only except running tests; do NOT edit source.` },
    { key: 'adversarial', prompt: `Adversarial critic for ${story.id} (scratch .mjs against ${SHIP}/engine/analyze.js + review of index.html/app.js for UI stories). Try to break the story's fix using the exact suite-3 hostile cases and near-misses: e.g. takeover wildcard-overlap vs truly-disjoint roles (74 vs 73); contradictory-condition non-correlation vs satisfiable (75); Principal array with one bad member (83) vs all-valid; case-insensitive duplicate condition keys (59) vs legitimately-different keys; empty ForAnyValue (97) vs non-empty; ForAllValues with Null (96, no warning) vs without (41, warning); cross-account PassRole (91) vs same-account; boundary/session selection must NEVER yield a capability edge; an unsupported-family selection must fail closed not analyze-as-identity; injection witnesses (99) must render inert. Blocking on any false-positive, false-negative, over/under-claim, or unsafe render. Report the exact policy + wrong output. Read-only; do NOT edit.` },
  ]
  if (story.ui) c.push({ key: 'compat-a11y', prompt: `Compatibility + accessibility critic for ${story.id}. Statically review ${SHIP} HTML/CSS/JS + the e2e specs. Blocking if: the family <select> lacks an associated <label> or is not keyboard-operable; the Analyze control's disabled/required state is not conveyed accessibly; analysis-state or error changes are not announced (aria-live); an experimental API without fallback; a serious/critical a11y barrier; untrusted strings rendered as anything but text; or the Playwright specs were not updated for the story's UI behavior (mandatory selection, boundary-> no edges, family-switch invalidation, injection-inert rendering). Read-only; do NOT edit.` })
  return c
}

const results = []
for (const story of STORIES) {
  log(`=== ${story.id} starting ===`)
  let accepted = false, feedback = '', lastFindings = []
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nImplement story ${story.id} (full spec + acceptance in ${DEV}/prd.json). Modify the shipped module(s)/HTML under ${SHIP}/ as the story requires, ADD the fixtures it names, wire tests (and Playwright specs for UI), keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: 'Implement', agentType: 'general-purpose' }
    )
    const gate = await agent(
      `Deterministic gate for ${story.id}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (full regression - ALL pass; capture regressed names); (b) grep ${SHIP} for network APIs -> noNetwork; (c) grep ${SHIP} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> noUnsafeDom; (d) cd ${REPO} && python3 scripts/csp_audit.py content/tools -> cspClean; (e) all ${DEV}/fixtures/**/*.json parse -> fixturesValidJson. pass=true iff all hold. List concrete failures incl regressed test names. Do NOT edit.`,
      { label: `gate:${story.id}:i${iter}`, phase: 'Gate', agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
    )
    if (!gate || !gate.pass) { feedback = `Gate failed: ${JSON.stringify(gate && gate.failures || ['gate null'])}`; log(`${story.id} i${iter}: gate FAIL`); continue }
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

phase('Re-test')
const RETEST_SCHEMA = { type: 'object', properties: { nodeTestGreen: { type: 'boolean' }, suite1Pass: { type: 'string' }, suite2Status: { type: 'string' }, suite3Pass: { type: 'string' }, stillFailing: { type: 'array', items: { type: 'string' } }, familyGaps: { type: 'array', items: { type: 'string' } }, regressions: { type: 'array', items: { type: 'string' } }, summary: { type: 'string' } }, required: ['nodeTestGreen', 'suite1Pass', 'suite3Pass', 'stillFailing', 'regressions', 'summary'] }
const retest = await agent(
  `Independent final re-test of ALL THREE suites. Do it yourself: (1) cd ${DEV} && node --test "tests/**/*.test.js" -> nodeTestGreen + failing names into regressions. (2) scratch .mjs importing ${SHIP}/engine/analyze.js; parse every policy block under each "## Test N" heading in ${S1}, ${S2}, ${S3}, run analyze() (pass the explicit family the test names for boundary/session/resource/scp cases), evaluate vs the Expected-result prose. suite1Pass="N/24". suite2Status = short status of the targeted fixes + family gaps. suite3Pass="N/M applicable" with per-campaign notes (A parser, B family-selection, C takeover, D principal, E IAM/ECS, F false-positive/safety). stillFailing = specific tests not meeting expectations (describe). familyGaps = resource-policy/RCP tests correctly fail-closed (expected). regressions = any suite-1/2 / Phase-9 / negative-corpus breakage. (3) Return the scoreboard + one-paragraph summary. Read-only; do NOT edit source.`,
  { label: 'final-retest-three-suites', phase: 'Re-test', agentType: 'general-purpose', schema: RETEST_SCHEMA }
)

return {
  built: results,
  acceptedCount: results.filter((r) => r.accepted).length,
  total: results.length,
  retest,
  note: 'Phase 10: mandatory family selection + boundary/session + Suite-III gap closure. After: re-verify, deploy (merge branch -> main, push), Cloudflare purge. Remaining tranche = full resource-policy (S3/SNS/KMS) + RCP analysis, still fail-closed.',
}
