export const meta = {
  name: 'iam-blast-radius-ralph-phase13',
  description: 'Phase 13 org-control ceilings: SCP + RCP as ceiling/guardrail families (never grants). Grounding doc + SCP ceiling semantics + RCP resource guardrails + fixturize/re-run all three suites (full-family capstone). FAIL-CLOSED arbiter (Phase-11A standard). LAUNCH ONLY AFTER Phase 12 (resource family) merges.',
  phases: [{ title: 'Grounding' }, { title: 'Implement' }, { title: 'Gate' }, { title: 'Critics' }, { title: 'Arbiter' }, { title: 'Re-test' }],
}

// ===== FAIL-CLOSED ARBITER (verbatim from Phase-11A standard; keep in lockstep
// with ralph/review-decision.mjs - its 15-case suite is the source of truth). =====
function arbitrate(panel, criticResponses) {
  const CONTROL_FAILURE = ['ERROR', 'TIMEOUT', 'INVALID_RESPONSE']
  const statuses = panel.map((c, i) => {
    const r = criticResponses[i]
    if (!r) return { critic: c.key, status: 'INVALID_RESPONSE' }
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
const REF = `${DEV}/docs/scp-rcp-semantics.md (AWS-verified SCP/RCP reference, authored by IAM-1300)`
const S1 = `${DEV}/docs/acceptance-suite.md`, S2 = `${DEV}/docs/acceptance-suite-2.md`, S3 = `${DEV}/docs/acceptance-suite-3.md`

const STORIES = [
  { id: 'IAM-1300', kind: 'doc', maxIter: 3 },
  { id: 'IAM-1301', kind: 'code', maxIter: 5 },
  { id: 'IAM-1302', kind: 'code', maxIter: 4 },
  { id: 'IAM-1303', kind: 'code', maxIter: 5 },
]

const GUARD = `PHASE-13 IMMUTABLE GUARDRAIL: an SCP or RCP is a CEILING / GUARDRAIL, NEVER a grant. The analyzer must NEVER emit a positive capability finding or edge from an SCP/RCP. An SCP Allow is the maximum-permission envelope (reuse engine/envelope.js ceiling semantics); a Deny (incl. NotAction-deny, region guardrails, negated-IfExists) is a guardrail; effective access is the INTERSECTION of identity policies and this ceiling. An RCP is deny-only org resource guardrails. NotAction lists are NEVER reported as allowed. Report ceilings/guardrails + the 'ceiling, not grant' framing. Fail closed on genuinely-unmodeled sub-shapes. Identity/trust/resource/boundary/session families stay UNCHANGED.`

const BASELINE = `You are a (replaceable) engineer on the LIVE, DEPLOYED IAM Blast Radius tool in ${REPO}. Shipped vanilla ES-module JS/CSS/HTML: ${SHIP}/. Read ${CONTRACTS}, the story in ${DEV}/prd.json, ${REF}, and the target tests in ${S1}/${S2} FIRST.

Full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN and MUST stay green; update tests/fixtures only for intentional changes; never weaken an assertion. PROTECTED (no regression): suites 1/2/3, the identity + trust + resource negative corpora, the review-decision + shipped-tree-hygiene gates.

HARD RULES: no network APIs in shipped JS; no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; DOM via createElement+textContent; reject __proto__/constructor; DETERMINISTIC engine; no inline style/script/on-handlers in HTML; NEVER assert beyond evidence; fail closed on unmodeled/unknown/invalid shapes. NO build step. NEVER write scratch/debug/test files under content/tools/ (the shipped tree - hygiene gate fails CI + it would deploy); put scratch under ${DEV}/ or a git-ignored scratchpad. Playwright/e2e is CI's job.

${GUARD}`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' }, shippedTreeClean: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'noNetwork', 'noUnsafeDom', 'cspClean', 'fixturesValidJson', 'shippedTreeClean', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

function critics(story) {
  return [
    { key: 'qa-scp-semantics', prompt: `QA + SCP/RCP-semantics critic for ${story.id}. Read the story in ${DEV}/prd.json, ${REF}, and its tests in ${S1}/${S2}. Review the diff (cd ${REPO} && git diff -- content/tools tools/iam-blast-radius) and run cd ${DEV} && node --test "tests/**/*.test.js". Drive analyze() DIRECTLY with the SCP/RCP family. Blocking if: an SCP/RCP emits ANY positive capability finding/edge (must be ceiling/guardrail only); a NotAction-deny list is reported as allowed; a region/IfExists guardrail is mis-modelled; the ceiling-not-grant framing is missing; an RCP reports S3/public-access or a grant; a targeted suite test still wrong; effective-permissions overclaim; OR any suite-1/2/3 / negative-corpus regression. Read-only; do NOT edit.` },
    { key: 'security', prompt: `Security critic for ${story.id} using ${CONTRACTS}. Review diff + grep ${SHIP}. Blocking if: network API in shipped JS; innerHTML/eval/unsafe DOM; __proto__/constructor not rejected; inline style/script/on-handler in HTML (csp_audit must pass); a scratch/debug/test file under content/tools/ (shipped-tree-hygiene must pass); injection fixtures no longer inert; an SCP/RCP finding presented as effective/granted access. Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${story.id}. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression). Confirm zero uncaught exceptions; determinism; suites 1/2/3 + identity/trust/resource negative corpora + review-decision + hygiene gates intact; DoS caps hold. Flag any regression, nondeterminism, uncaught throw, or hang as blocking. Read-only except running tests; do NOT edit source.` },
    { key: 'adversarial', prompt: `Adversarial critic for ${story.id} (scratch .mjs UNDER ${DEV} - never under content/ - against ${SHIP}/engine/analyze.js). Try to break it: an SCP with an Allow must NOT produce a can-* capability edge or a "granted" finding; a Deny NotAction:[iam:*,...] must NOT report iam:* etc. as allowed; a negated-IfExists region Deny must surface the over-broad hazard, not a grant; an RCP deny must not become a public-access/S3 finding; a genuinely-unmodelled SCP/RCP sub-shape must fail closed, never analyze as identity. Blocking on any manufactured grant, false-positive/negative, over/under-claim, or fail-open. Report exact input + output. Read-only; do NOT edit.` },
  ]
}

const results = []
for (const story of STORIES) {
  log(`=== ${story.id} (${story.kind}) starting ===`)
  let accepted = false, feedback = '', lastFindings = [], lastReason = ''

  if (story.kind === 'doc') {
    for (let iter = 1; iter <= story.maxIter; iter++) {
      await agent(
        `You are grounding the IAM Blast Radius SCP/RCP families. Implement story ${story.id} (spec + acceptance in ${DEV}/prd.json): author ${DEV}/docs/scp-rcp-semantics.md. Use WebSearch/WebFetch to verify every claim against CURRENT AWS docs and cite sources. ASCII only; no secrets. Change NO shipped code; do NOT write under content/tools/.\n\n${GUARD}${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings:\n${feedback}` : ''}`,
        { label: `research:${story.id}:i${iter}`, phase: 'Grounding', agentType: 'general-purpose' }
      )
      const verify = await agent(
        `AWS-verifier critic for grounding doc ${story.id}. Read ${DEV}/docs/scp-rcp-semantics.md + the acceptance in ${DEV}/prd.json. Use WebSearch/WebFetch to CHECK its claims. Blocking if: any SCP ceiling / deny-guardrail / NotAction / region / RCP deny-only / confused-deputy / ceiling-not-grant semantic is missing or wrong; a cited source does not support the claim; or shipped code was changed. Read-only; do NOT edit.`,
        { label: `verify:${story.id}:i${iter}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA }
      )
      const v = arbitrate([{ key: 'aws-verifier' }], [verify])
      lastFindings = (verify && verify.findings || []).map((f) => ({ ...f, critic: verify.critic }))
      if (v.accepted) { accepted = true; lastReason = 'all-pass'; log(`${story.id} ACCEPTED i${iter}`); break }
      const blk = lastFindings.filter((f) => f.blocking)
      lastReason = v.decision === 'review_error' ? 'verifier non-pass (fail-closed)' : `${blk.length} blocking`
      feedback = v.decision === 'review_error' ? `FAIL-CLOSED: aws-verifier returned no verdict (non-pass, not approval). Re-run.` : blk.map((f) => `[${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
      log(`${story.id} i${iter}: ${lastReason}, revise`)
    }
  } else {
    for (let iter = 1; iter <= story.maxIter; iter++) {
      await agent(
        `${BASELINE}\n\nImplement story ${story.id} (spec + acceptance in ${DEV}/prd.json). Modify shipped module(s) under ${SHIP}/ (reuse engine/envelope.js ceiling semantics for SCP), ADD the fixtures the story names, wire tests, keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
        { label: `impl:${story.id}:i${iter}`, phase: 'Implement', agentType: 'general-purpose' }
      )
      const gate = await agent(
        `Deterministic gate for ${story.id}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (full regression - ALL pass; capture regressed names); (b) grep ${SHIP} for network APIs -> noNetwork; (c) grep ${SHIP} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> noUnsafeDom; (d) cd ${REPO} && python3 scripts/csp_audit.py content/tools -> cspClean; (e) all ${DEV}/fixtures/**/*.json parse -> fixturesValidJson; (f) node --test tests/shipped-tree-hygiene.test.js -> shippedTreeClean. pass=true iff all hold. List concrete failures. Do NOT edit.`,
        { label: `gate:${story.id}:i${iter}`, phase: 'Gate', agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
      )
      if (!gate || !gate.pass) { feedback = `Gate failed: ${JSON.stringify(gate && gate.failures || ['gate null/errored'])}`; lastReason = 'gate-fail'; log(`${story.id} i${iter}: gate FAIL`); continue }

      const panel = critics(story)
      const cr = await parallel(panel.map((c) => () =>
        agent(c.prompt, { label: `critic:${c.key}:${story.id}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA })))
      const verdict = arbitrate(panel, cr)
      lastFindings = cr.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))
      const blocking = lastFindings.filter((f) => f.blocking)

      if (verdict.accepted) { accepted = true; lastReason = 'all-pass'; log(`${story.id} ACCEPTED i${iter}`); break }
      if (verdict.failedCritics.length) {
        lastReason = `critic-nonpass: [${verdict.failedCritics.join(',')}]`
        feedback = `FAIL-CLOSED: critic(s) [${verdict.failedCritics.join(', ')}] returned no verdict (non-pass, NOT approval). Re-run.${blocking.length ? `\nAlso:\n${blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')}` : ''}`
        log(`${story.id} i${iter}: FAIL-CLOSED (${verdict.failedCritics.join(',')}), ${blocking.length} blocking; re-run`)
      } else {
        lastReason = `${blocking.length} blocking`
        feedback = blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
        log(`${story.id} i${iter}: ${blocking.length} blocking (${[...new Set(blocking.map((f) => f.critic))].join(',')}), re-impl`)
      }
    }
  }

  await agent(
    `Update ${DEV}/progress.md: set a row for ${story.id} to ${accepted ? 'accepted' : 'human-review'} with iteration count + the last-round reason ("${lastReason}"). ${accepted ? '' : `Remaining:\n${feedback}`} Edit only that row/notes.`,
    { label: `ledger:${story.id}`, phase: 'Arbiter', agentType: 'general-purpose', effort: 'low' }
  )
  results.push({ story: story.id, accepted, reason: lastReason, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length })
}

phase('Re-test')
const RETEST_SCHEMA = { type: 'object', properties: { nodeTestGreen: { type: 'boolean' }, suite1Pass: { type: 'string' }, suite2Status: { type: 'string' }, suite3Pass: { type: 'string' }, scpRcpStatus: { type: 'string' }, familyCoverage: { type: 'string' }, regressions: { type: 'array', items: { type: 'string' } }, summary: { type: 'string' } }, required: ['nodeTestGreen', 'suite1Pass', 'suite2Status', 'scpRcpStatus', 'regressions', 'summary'] }
const retest = await agent(
  `Independent final re-test for Phase 13 (full-family capstone). Do it yourself: (1) cd ${DEV} && node --test "tests/**/*.test.js" -> nodeTestGreen + failing names -> regressions; confirm shipped-tree-hygiene passes. (2) scratch .mjs UNDER ${DEV} importing ${SHIP}/engine/analyze.js; drive suites 1/2/3 (pass the family each test names). suite1Pass "N/24" (incl test 19 SCP now analyzed as a guardrail); suite2Status = tests 43 (SCP) + 52 (RCP) now analyzed as ceilings/guardrails (describe); suite3Pass "N/M applicable"; scpRcpStatus = summary of SCP/RCP behavior (ceiling-not-grant, no manufactured grants); familyCoverage = confirm identity/trust/resource/boundary/session/SCP/RCP each analyzed-or-explicitly-fail-closed. regressions = any suite-1/2/3 / identity-trust-resource negative-corpus breakage. Return the scoreboard + one-paragraph summary. Read-only; do NOT edit source.`,
  { label: 'final-retest-phase13', phase: 'Re-test', agentType: 'general-purpose', schema: RETEST_SCHEMA }
)

return {
  built: results,
  acceptedCount: results.filter((r) => r.accepted).length,
  total: results.length,
  retest,
  note: 'Phase 13 SCP/RCP org-control ceilings (full-family capstone). Fail-closed arbiter (Phase-11A). After: independent verify (esp. any critic-nonpass holds + shipped-tree hygiene), deploy (merge branch -> main as rivassec identity), Cloudflare purge. This completes the planned roadmap: identity/trust/resource/boundary/session/SCP/RCP.',
}
