export const meta = {
  name: 'iam-blast-radius-ralph-phase11',
  description: 'Phase 11 review-control + residual: 11A critic fail-closed decision model (gated by the 15 record-test workflow cases), 11B T91 subject-account PassRole (9 cases), 11C invalid-family fail-closed + record regression fixtures. FAIL-CLOSED ARBITER mirrors the audited ralph/review-decision.mjs model (15-case-gated) so this run protects itself and future phases inherit it.',
  phases: [{ title: 'Implement' }, { title: 'Gate' }, { title: 'Critics' }, { title: 'Arbiter' }, { title: 'Re-test' }],
}

// ========================= ARBITER AUTHORING STANDARD =========================
// (IAM-1101 / Phase 11A) The CANONICAL fail-closed accept/hold model lives in
// ralph/review-decision.mjs (`classifyResponse` + `decide`), unit-tested against
// all 15 docs/record-tests/cases/workflow-cases.json fault-injection cases via
// tests/critic-fail-closed.test.js. The Workflow-tool loader injects globals
// (agent/parallel/log/phase) and does NOT import cross-file modules into a
// workflow body, so this file MIRRORS that model inline via `arbitrate()` below.
// The mirror is a byte-for-byte behavioral copy of decide()'s rules:
//   * a critic that returned null/undefined => INVALID_RESPONSE (missing verdict
//     is NEVER approval);
//   * a returned verdict with >=1 blocking finding => BLOCKER;
//   * otherwise => PASS;
//   * ACCEPT iff every required critic PASSed; any missing/ERROR/TIMEOUT/INVALID
//     => review_error (fail closed, retry, never accept); any BLOCKER => blocked.
// EVERY future phase workflow (12/13) MUST reuse `arbitrate()` (copy this block)
// so a control failure can never auto-accept an unreviewed story (the IAM-1005
// 529-storm regression this whole story exists to kill). Keep it in lockstep
// with review-decision.mjs; that module's test suite is the source of truth.
function arbitrate(panel, criticResponses) {
  const CONTROL_FAILURE = ['ERROR', 'TIMEOUT', 'INVALID_RESPONSE']
  const statuses = panel.map((c, i) => {
    const r = criticResponses[i]
    if (!r) return { critic: c.key, status: 'INVALID_RESPONSE' } // missing verdict != approval
    const blocking = (r.findings || []).filter((f) => f.blocking)
    return { critic: c.key, status: blocking.length ? 'BLOCKER' : 'PASS' }
  })
  const failedCritics = statuses.filter((s) => CONTROL_FAILURE.includes(s.status)).map((s) => s.critic)
  const hasBlocker = statuses.some((s) => s.status === 'BLOCKER')
  const allPass = statuses.length > 0 && statuses.every((s) => s.status === 'PASS')
  let decision = 'review_error'
  if (allPass) decision = 'approved'
  else if (failedCritics.length) decision = 'review_error'
  else if (hasBlocker) decision = 'blocked'
  return { decision, accepted: decision === 'approved', failedCritics, statuses }
}

const REPO = '/Users/oliver/dev/devsecops-notes'
const DEV = `${REPO}/tools/iam-blast-radius`
const SHIP = `${REPO}/content/tools/iam-blast-radius`
const CONTRACTS = `${DEV}/docs/architecture.md and ${DEV}/docs/threat-model.md (IMMUTABLE)`
const PLAN = `${DEV}/docs/phases-11-13-execution-plan.md`
const BUNDLE = `${DEV}/docs/record-tests (cases/analyzer-cases.json, cases/workflow-cases.json, schemas/, templates/)`
const S1 = `${DEV}/docs/acceptance-suite.md`, S2 = `${DEV}/docs/acceptance-suite-2.md`, S3 = `${DEV}/docs/acceptance-suite-3.md`

const STORIES = [
  { id: 'IAM-1101', maxIter: 5, ui: false },
  { id: 'IAM-1102', maxIter: 5, ui: false },
  { id: 'IAM-1103', maxIter: 4, ui: true },
]

const BASELINE = `You are a (replaceable) engineer on the LIVE, DEPLOYED IAM Blast Radius tool in ${REPO}. Shipped vanilla ES-module JS/CSS/HTML: ${SHIP}/. Dev tests/fixtures/ralph: ${DEV}/. Read ${CONTRACTS}, the story in ${DEV}/prd.json, ${PLAN}, and ${BUNDLE} FIRST.

Full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN (1208+) and MUST stay green; update tests/fixtures only for intentional changes; never weaken an assertion. PROTECTED (no regression): suites 1/2/3, the identity + trust negative corpora.

HARD RULES: no network APIs in shipped JS; no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; DOM via createElement+textContent; reject __proto__/constructor; DETERMINISTIC engine; no inline style/script/on-handlers in HTML (addEventListener in app.js); reports "potential blast radius" NOT "effective permissions"; NEVER assert beyond evidence; fail closed on unmodeled/unknown/invalid shapes. NO build step. Playwright/e2e is CI's job.

PHASE-11 principle (from the record-test bundle): unknown, unavailable, malformed, timed out, and failed are EXPLICIT non-pass states - an empty array / missing result / rejected promise is NEVER equivalent to approval or safety. Apply it to both the review workflow (11A) and the analyzer (11C invalid-family).

ADAPTER NAME-MAP for bundle cases (behavior authoritative, keep the engine's shipped ids/codes; map at the fixture layer): BOUNDARY-ENVELOPE -> PERMISSIONS-BOUNDARY-ENVELOPE; UNSUPPORTED_OR_INVALID_NOTPRINCIPAL -> UNSUPPORTED_NOTPRINCIPAL; MIXED_OR_INVALID_POLICY_FAMILY -> AMBIGUOUS_POLICY_SHAPE. The engine's canonical family override values are: identity, resource, role-trust, permissions-boundary, session, scp-rcp.`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'noNetwork', 'noUnsafeDom', 'cspClean', 'fixturesValidJson', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

function critics(story) {
  const c = [
    { key: 'qa-semantics', prompt: `QA + IAM-semantics critic for ${story.id}. Read the story in ${DEV}/prd.json + its bundle cases in ${BUNDLE}. Review the diff (cd ${REPO} && git diff -- content/tools tools/iam-blast-radius) and run cd ${DEV} && node --test "tests/**/*.test.js". For 11A: verify the review-decision model treats ERROR/TIMEOUT/INVALID_RESPONSE/null as non-pass, accepts only on all-PASS, and passes all 15 workflow-cases.json. For 11B: drive analyze() directly and verify cross-account PassRole is no longer critical (ineffective/UNKNOWN) while same-account/wildcard stay viable; all 9 T91 cases pass. For 11C: verify an unknown family value fails closed (INVALID_FAMILY), never analyzes as identity; the BND/DEF cases pass under the name-map. Blocking on any wrong outcome, over/under-claim, missing bundle-case pass, exports disagreeing, or a suite/negative-corpus regression. Read-only; do NOT edit.` },
    { key: 'security', prompt: `Security critic for ${story.id} using ${CONTRACTS}. Review diff + grep ${SHIP}. Blocking if: network API in shipped JS; innerHTML/eval/unsafe DOM; DOM/attrs built unsafely from policy input; __proto__/constructor not rejected; inline style/script/on-handler in HTML (csp_audit must pass); injection fixtures no longer inert; the invalid-family or family-value handling introduces a fail-OPEN (analyzing unknown/invalid input as identity); policy content leaks. Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${story.id}. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression). Confirm: zero uncaught exceptions; determinism; suites 1/2/3 + both negative corpora intact; DoS caps hold. For 11A also confirm the review-decision module is deterministic and its ledger output conforms to review-ledger-entry.schema.json. Flag any regression, nondeterminism, uncaught throw, or hang as blocking. Read-only except running tests; do NOT edit source.` },
    { key: 'adversarial', prompt: `Adversarial critic for ${story.id} (scratch .mjs against ${SHIP}/engine/analyze.js, or against the 11A review-decision module). Try to break the fix: 11A - can any combination of missing/null/errored/timed-out/malformed critic results yield accepted=true, or skip the ledger row? (must not). 11B - a cross-account PassRole with an AMBIGUOUS subject account must not be silently suppressed, and a genuine same-account path must stay critical. 11C - every unknown/misspelled family value ('scp','rcp','identityy','') must fail closed, never analyze as identity; a VALID family must still work. Blocking on any fail-open, false-positive/negative, or unreviewed acceptance. Report the exact input + wrong output. Read-only; do NOT edit.` },
  ]
  if (story.ui) c.push({ key: 'compat-a11y', prompt: `Compatibility + accessibility critic for ${story.id}. Review ${SHIP} HTML/CSS/JS + e2e specs. Blocking if: an invalid-family selection is not surfaced accessibly; controls not keyboard-operable/labeled; state changes not announced (aria-live); untrusted strings rendered as anything but text; the family-switch / invalid-family Playwright specs (record-test BND/DEF UI cases) were not added/updated. Read-only; do NOT edit.` })
  return c
}

const results = []
for (const story of STORIES) {
  log(`=== ${story.id} starting ===`)
  let accepted = false, feedback = '', lastFindings = [], lastReason = ''
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nImplement story ${story.id} (full spec + acceptance in ${DEV}/prd.json). Modify the module(s)/HTML the story names (11A: ${DEV}/ralph/review-decision.mjs + tests/critic-fail-closed.test.js; 11B/11C: ${SHIP}/engine + fixtures), ADD the bundle-backed fixtures, wire tests (Playwright for UI), keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: 'Implement', agentType: 'general-purpose' }
    )
    const gate = await agent(
      `Deterministic gate for ${story.id}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (full regression - ALL pass; capture regressed names); (b) grep ${SHIP} for network APIs -> noNetwork; (c) grep ${SHIP} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> noUnsafeDom; (d) cd ${REPO} && python3 scripts/csp_audit.py content/tools -> cspClean; (e) all ${DEV}/fixtures/**/*.json parse -> fixturesValidJson. pass=true iff all hold. List concrete failures incl regressed test names. Do NOT edit.`,
      { label: `gate:${story.id}:i${iter}`, phase: 'Gate', agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
    )
    if (!gate || !gate.pass) { feedback = `Gate failed: ${JSON.stringify(gate && gate.failures || ['gate null/errored'])}`; lastReason = 'gate-fail'; log(`${story.id} i${iter}: gate FAIL`); continue }

    const panel = critics(story)
    const cr = await parallel(panel.map((c) => () =>
      agent(c.prompt, { label: `critic:${c.key}:${story.id}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA })))

    // FAIL-CLOSED ARBITER — mirrors the audited review-decision model
    // (ralph/review-decision.mjs, gated by the 15 record-test workflow cases).
    // A critic that returns null/undefined classifies as INVALID_RESPONSE =
    // NON-PASS; acceptance requires decision === 'approved' (EVERY critic PASSed).
    // This is the standard future phases mirror (see arbitrate() above).
    const verdict = arbitrate(panel, cr)
    const failedCritics = verdict.failedCritics
    lastFindings = cr.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))
    const blocking = lastFindings.filter((f) => f.blocking)

    if (verdict.accepted) { accepted = true; lastReason = 'all-pass'; log(`${story.id} ACCEPTED i${iter} (${verdict.decision}; all critics PASS)`); break }

    if (failedCritics.length > 0) {
      // Never accept on an unrendered verdict (decision === review_error). Retry the iteration.
      lastReason = `critic-nonpass: [${failedCritics.join(',')}] returned ERROR/TIMEOUT/INVALID_RESPONSE (decision=${verdict.decision})`
      feedback = `FAIL-CLOSED: critic(s) [${failedCritics.join(', ')}] did not return a verdict (treated as non-pass, NOT approval). Re-run.${blocking.length ? `\nAlso address:\n${blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')}` : ''}`
      log(`${story.id} i${iter}: FAIL-CLOSED - ${failedCritics.length} critic(s) non-pass (${failedCritics.join(',')}), ${blocking.length} blocking; re-run`)
    } else {
      lastReason = `${blocking.length} blocking`
      feedback = blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
      log(`${story.id} i${iter}: ${blocking.length} blocking (${[...new Set(blocking.map((f) => f.critic))].join(',')}), re-impl`)
    }
  }
  await agent(
    `Update ${DEV}/progress.md: add/set a row for ${story.id} to ${accepted ? 'accepted' : 'human-review'} with iteration count, and RECORD the per-critic outcome + reason of the last round ("${lastReason}") - a story held on critic non-pass (ERROR/TIMEOUT/INVALID) must say so explicitly. ${accepted ? '' : `Remaining:\n${feedback}`} Edit only that row/notes.`,
    { label: `ledger:${story.id}`, phase: 'Arbiter', agentType: 'general-purpose', effort: 'low' }
  )
  results.push({ story: story.id, accepted, reason: lastReason, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length })
}

phase('Re-test')
const RETEST_SCHEMA = { type: 'object', properties: { nodeTestGreen: { type: 'boolean' }, workflowCasesPass: { type: 'string' }, t91CasesPass: { type: 'string' }, invalidFamilyFailsClosed: { type: 'boolean' }, suite1Pass: { type: 'string' }, suite3Pass: { type: 'string' }, regressions: { type: 'array', items: { type: 'string' } }, summary: { type: 'string' } }, required: ['nodeTestGreen', 'workflowCasesPass', 't91CasesPass', 'invalidFamilyFailsClosed', 'regressions', 'summary'] }
const retest = await agent(
  `Independent final re-test for Phase 11. Do it yourself: (1) cd ${DEV} && node --test "tests/**/*.test.js" -> nodeTestGreen + failing names -> regressions. (2) workflowCasesPass = "N/15" from tests/critic-fail-closed.test.js driving ${DEV}/docs/record-tests/cases/workflow-cases.json (verify ERROR/TIMEOUT/INVALID/null never accept). (3) t91CasesPass = "N/9" driving the T91-* analyzer cases (cross-account no longer critical; same-account/wildcard preserved). (4) invalidFamilyFailsClosed = does analyze(policy,{family:'scp'}) (unknown value) now fail closed instead of analyzing as identity. (5) suite1Pass/suite3Pass via the three-suite harness; regressions = any suite-1/2/3 or negative-corpus breakage. Return the scoreboard + one-paragraph summary. Read-only; do NOT edit source.`,
  { label: 'final-retest-phase11', phase: 'Re-test', agentType: 'general-purpose', schema: RETEST_SCHEMA }
)

return {
  built: results,
  acceptedCount: results.filter((r) => r.accepted).length,
  total: results.length,
  retest,
  note: 'Phase 11: review-control (fail-closed critics) + T91 fix + invalid-family fail-closed. Arbiter is fail-closed (a non-returning critic never accepts). After: re-verify, deploy (merge branch -> main, push as rivassec identity), Cloudflare purge. Next: Phase 12 resource-policy family.',
}
