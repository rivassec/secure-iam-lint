export const meta = {
  name: 'iam-blast-radius-ralph-phase12',
  description: 'Phase 12 resource-based policy family (S3/SNS/SQS/KMS): grounding doc + acceptance/context input + principal-centric/public-access + confused-deputy + same-account grants + KMS key policy + NotPrincipal hazard + resource negative corpus. FAIL-CLOSED arbiter (Phase-11A standard). SCP/RCP stay deferred to Phase 13.',
  phases: [{ title: 'Grounding' }, { title: 'Implement' }, { title: 'Gate' }, { title: 'Critics' }, { title: 'Arbiter' }, { title: 'Re-test' }],
}

// ===== FAIL-CLOSED ARBITER (verbatim from Phase-11A authoring standard; keep in
// lockstep with ralph/review-decision.mjs - its 15-case suite is the source of truth).
// A critic that returns null/undefined = INVALID_RESPONSE (missing verdict is NEVER
// approval). ACCEPT iff every critic PASSes; any missing/ERROR/TIMEOUT/INVALID =>
// review_error (fail closed, retry, never accept); any blocker => blocked. =====
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
const REF = `${DEV}/docs/resource-policy-semantics.md (AWS-verified resource-policy reference, authored by IAM-1200)`
const S2 = `${DEV}/docs/acceptance-suite-2.md`, S3 = `${DEV}/docs/acceptance-suite-3.md`

const STORIES = [
  { id: 'IAM-1200', kind: 'doc', maxIter: 3 },
  { id: 'IAM-1201', kind: 'code', maxIter: 5, ui: true },
  { id: 'IAM-1202', kind: 'code', maxIter: 5 },
  { id: 'IAM-1203', kind: 'code', maxIter: 5 },
  { id: 'IAM-1204', kind: 'code', maxIter: 4 },
  { id: 'IAM-1205', kind: 'code', maxIter: 4 },
  { id: 'IAM-1206', kind: 'code', maxIter: 4 },
  { id: 'IAM-1207', kind: 'code', maxIter: 5 },
]

const GUARD = `PHASE-12 IMMUTABLE GUARDRAILS: a resource policy is analyzed from the RESOURCE's perspective (who may act on THIS attached resource); resource-policy CONTEXT (attached resource type + ARN) is EXPLICIT and required. A SERVICE principal is NOT a public principal; an account principal is NOT root-user-only; Resource:* in a KMS key policy is the ATTACHED key, not every key. A transport constraint (aws:SecureTransport) is NOT an identity constraint. Every resource finding states that effective access depends on identity policies + other layers not supplied (potential blast radius, NOT effective permissions). Fail closed on genuinely-unmodeled resource shapes and on a missing required resource-context. SCP/RCP families stay DEFERRED (Phase 13) - do NOT build them here.`

const BASELINE = `You are a (replaceable) engineer on the LIVE, DEPLOYED IAM Blast Radius tool in ${REPO}. Shipped vanilla ES-module JS/CSS/HTML: ${SHIP}/. Read ${CONTRACTS}, the story in ${DEV}/prd.json, ${REF}, and the target tests in ${S2}/${S3} FIRST.

Full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN (1279+) and MUST stay green; update tests/fixtures only for intentional changes; never weaken an assertion. PROTECTED (no regression): suites 1/2/3, the identity + trust negative corpora, the Phase-11 review-decision + shipped-tree-hygiene gates.

HARD RULES: no network APIs in shipped JS; no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; DOM via createElement+textContent; reject __proto__/constructor; DETERMINISTIC engine; no inline style/script/on-handlers in HTML (addEventListener in app.js); NEVER assert beyond evidence; fail closed on unmodeled/unknown/invalid shapes. NO build step. NEVER write scratch/debug/test files under content/tools/ (the shipped tree - the hygiene gate fails CI and it would deploy); put any scratch harness under ${DEV}/ (repo-root dev tree) or a git-ignored scratchpad. Playwright/e2e is CI's job.

${GUARD}`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' }, shippedTreeClean: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'noNetwork', 'noUnsafeDom', 'cspClean', 'fixturesValidJson', 'shippedTreeClean', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

function critics(story) {
  const c = [
    { key: 'qa-resource-semantics', prompt: `QA + resource-policy-semantics critic for ${story.id}. Read the story in ${DEV}/prd.json, ${REF}, and its tests in ${S2}/${S3}. Review the diff (cd ${REPO} && git diff -- content/tools tools/iam-blast-radius) and run cd ${DEV} && node --test "tests/**/*.test.js". Drive analyze() DIRECTLY with the resource-context. Blocking if: a resource policy is analyzed with identity rules; a service principal is treated as public; an account principal treated as root-only; Resource:* in a KMS key policy explodes into per-key nodes; a transport Deny (SecureTransport) mistaken for an identity constraint; confused-deputy over/under-claimed; a same-account resource grant loses the resource-vs-identity caveat; NotPrincipal rendered as an ordinary exclusion; effective-permissions overclaim; a targeted suite test still wrong; OR any suite-1/2/3 / negative-corpus regression. Read-only; do NOT edit.` },
    { key: 'security', prompt: `Security critic for ${story.id} using ${CONTRACTS}. Review diff + grep ${SHIP}. Blocking if: network API in shipped JS; innerHTML/eval/unsafe DOM; the resource-context UI control wired via inline handler or built unsafely; __proto__/constructor not rejected; inline style/script in HTML (csp_audit must pass); a scratch/debug/test file under content/tools/ (shipped-tree-hygiene must pass); injection fixtures no longer inert; a resource finding presented as effective/proven access rather than potential blast radius. Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${story.id}. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression). Confirm zero uncaught exceptions; determinism; suites 1/2/3 + identity/trust negative corpora + review-decision + hygiene gates intact; DoS caps hold. Flag any regression, nondeterminism, uncaught throw, or hang as blocking. Read-only except running tests; do NOT edit source.` },
    { key: 'adversarial', prompt: `Adversarial critic for ${story.id} (scratch .mjs UNDER ${DEV} - never under content/ - against ${SHIP}/engine/analyze.js). Try to break the fix with the exact suite cases + near-misses: a service principal WITH correct SourceArn/SourceAccount must NOT fire confused-deputy (test 27) while WITHOUT it must (26); a mismatched SourceArn/SourceAccount must warn, not praise (53); Principal '*' + a transport Deny must stay public (28); a KMS account-root delegation must not read as public/root-only (51); a same-account grant must keep the resource-vs-identity caveat (32); an assumed-role-session principal must not collapse to the role (33); a missing resource-context must fail closed. Blocking on any false-positive/negative, over/under-claim, or fail-open. Report exact input + output. Read-only; do NOT edit.` },
  ]
  if (story.ui) c.push({ key: 'compat-a11y', prompt: `Compatibility + accessibility critic for ${story.id}. Review ${SHIP} HTML/CSS/JS + e2e specs. Blocking if: the resource-context control is not keyboard-operable / unlabeled; its required/missing state not conveyed accessibly; state changes not announced (aria-live); untrusted strings rendered as anything but text; the Playwright spec for the resource-context input + resource-family analysis was not added/updated. Read-only; do NOT edit.` })
  return c
}

const results = []
for (const story of STORIES) {
  log(`=== ${story.id} (${story.kind}) starting ===`)
  let accepted = false, feedback = '', lastFindings = [], lastReason = ''

  if (story.kind === 'doc') {
    for (let iter = 1; iter <= story.maxIter; iter++) {
      await agent(
        `You are grounding the IAM Blast Radius resource-policy family. Implement story ${story.id} (spec + acceptance in ${DEV}/prd.json): author ${DEV}/docs/resource-policy-semantics.md. Use WebSearch/WebFetch to verify every claim against CURRENT AWS docs and cite sources. ASCII only; no secrets. Change NO shipped code; do NOT write under content/tools/.\n\n${GUARD}${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings:\n${feedback}` : ''}`,
        { label: `research:${story.id}:i${iter}`, phase: 'Grounding', agentType: 'general-purpose' }
      )
      const verify = await agent(
        `AWS-verifier critic for grounding doc ${story.id}. Read ${DEV}/docs/resource-policy-semantics.md + the acceptance in ${DEV}/prd.json. Use WebSearch/WebFetch to CHECK its claims. Blocking if: any Principal type / per-service shape / confused-deputy / transport-vs-identity / account-delegation / NotPrincipal-hazard / KMS-Resource:* semantic is missing or wrong; a cited source does not support the claim; or shipped code was changed. Read-only; do NOT edit.`,
        { label: `verify:${story.id}:i${iter}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA }
      )
      const { accepted: acc, decision } = arbitrate([{ key: 'aws-verifier' }], [verify])
      lastFindings = (verify && verify.findings || []).map((f) => ({ ...f, critic: verify.critic }))
      if (acc) { accepted = true; lastReason = 'all-pass'; log(`${story.id} ACCEPTED i${iter}`); break }
      const blk = lastFindings.filter((f) => f.blocking)
      lastReason = decision === 'review_error' ? 'verifier non-pass (fail-closed)' : `${blk.length} blocking`
      feedback = decision === 'review_error'
        ? `FAIL-CLOSED: aws-verifier did not return a verdict (non-pass, not approval). Re-run.`
        : blk.map((f) => `[${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
      log(`${story.id} i${iter}: ${lastReason}, revise`)
    }
  } else {
    for (let iter = 1; iter <= story.maxIter; iter++) {
      await agent(
        `${BASELINE}\n\nImplement story ${story.id} (spec + acceptance in ${DEV}/prd.json). Modify shipped module(s)/HTML under ${SHIP}/, ADD the fixtures the story names (under ${DEV}/fixtures), wire tests (Playwright for UI), keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
        { label: `impl:${story.id}:i${iter}`, phase: 'Implement', agentType: 'general-purpose' }
      )
      const gate = await agent(
        `Deterministic gate for ${story.id}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (full regression - ALL pass; capture regressed names); (b) grep ${SHIP} for network APIs -> noNetwork; (c) grep ${SHIP} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> noUnsafeDom; (d) cd ${REPO} && python3 scripts/csp_audit.py content/tools -> cspClean; (e) all ${DEV}/fixtures/**/*.json parse -> fixturesValidJson; (f) no scratch/debug/test/.mjs stray under content/tools/iam-blast-radius (node --test tests/shipped-tree-hygiene.test.js) -> shippedTreeClean. pass=true iff all hold. List concrete failures. Do NOT edit.`,
        { label: `gate:${story.id}:i${iter}`, phase: 'Gate', agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
      )
      if (!gate || !gate.pass) { feedback = `Gate failed: ${JSON.stringify(gate && gate.failures || ['gate null/errored'])}`; lastReason = 'gate-fail'; log(`${story.id} i${iter}: gate FAIL`); continue }

      const panel = critics(story)
      const cr = await parallel(panel.map((c) => () =>
        agent(c.prompt, { label: `critic:${c.key}:${story.id}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA })))
      const verdict = arbitrate(panel, cr)
      lastFindings = cr.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))
      const blocking = lastFindings.filter((f) => f.blocking)

      if (verdict.accepted) { accepted = true; lastReason = 'all-pass'; log(`${story.id} ACCEPTED i${iter} (all critics PASS)`); break }
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
const RETEST_SCHEMA = { type: 'object', properties: { nodeTestGreen: { type: 'boolean' }, suite1Pass: { type: 'string' }, suite2Status: { type: 'string' }, suite3Pass: { type: 'string' }, resourceCasesPass: { type: 'string' }, regressions: { type: 'array', items: { type: 'string' } }, shippedTreeClean: { type: 'boolean' }, summary: { type: 'string' } }, required: ['nodeTestGreen', 'suite1Pass', 'suite2Status', 'suite3Pass', 'regressions', 'summary'] }
const retest = await agent(
  `Independent final re-test for Phase 12. Do it yourself: (1) cd ${DEV} && node --test "tests/**/*.test.js" -> nodeTestGreen + failing names -> regressions; confirm tests/shipped-tree-hygiene.test.js passes (shippedTreeClean). (2) scratch .mjs UNDER ${DEV} importing ${SHIP}/engine/analyze.js; drive suites 1/2/3 (pass the family + resource-context each test names). suite1Pass "N/24"; suite2Status = the resource-family tests 26/27/28/29/32/33/49/51/53 now analyzed correctly (describe) + any still fail-closed; suite3Pass "N/M applicable" incl 69/85; resourceCasesPass = summary of the resource-family behavior. regressions = any suite-1/2/3 / identity-or-trust negative-corpus breakage. Return the scoreboard + one-paragraph summary. Read-only; do NOT edit source.`,
  { label: 'final-retest-phase12', phase: 'Re-test', agentType: 'general-purpose', schema: RETEST_SCHEMA }
)

return {
  built: results,
  acceptedCount: results.filter((r) => r.accepted).length,
  total: results.length,
  retest,
  note: 'Phase 12 resource-policy family. Arbiter is fail-closed (Phase-11A standard). After: independent verify (esp. any critic-nonpass holds + shipped-tree hygiene), deploy (merge branch -> main as rivassec identity), Cloudflare purge. Next: Phase 13 SCP/RCP ceilings.',
}
