export const meta = {
  name: 'iam-blast-radius-ralph-phase12h',
  description: 'Phase 12.1 resource-family adversarial hardening (IAM-1208): fix the 4 edge over/under-claims the Phase-12 adversarial critic found in engine/resource.js (principal-identity-condition anonymous over-claim, multi-value source-set mismatch, null-context fail-open, dropped CanonicalUser/wildcard principals). FAIL-CLOSED arbiter (Phase-11A). Runs before Phase 13.',
  phases: [{ title: 'Implement' }, { title: 'Gate' }, { title: 'Critics' }, { title: 'Arbiter' }],
}

// ===== FAIL-CLOSED ARBITER (Phase-11A standard; lockstep with review-decision.mjs) =====
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
  return { decision, accepted: decision === 'approved', failedCritics }
}

const REPO = '/Users/oliver/dev/devsecops-notes'
const DEV = `${REPO}/tools/iam-blast-radius`
const SHIP = `${REPO}/content/tools/iam-blast-radius`
const CONTRACTS = `${DEV}/docs/architecture.md and ${DEV}/docs/threat-model.md (IMMUTABLE)`
const REF = `${DEV}/docs/resource-policy-semantics.md`
const S2 = `${DEV}/docs/acceptance-suite-2.md`, S3 = `${DEV}/docs/acceptance-suite-3.md`
const STORY = 'IAM-1208'

const GUARD = `PHASE-12.1: fix ONLY the 4 named resource-evaluator edge findings in engine/resource.js; do NOT regress the 8 suite-2 resource flips (26/27/28/32/33/49/51/53), suite-3 69/85, or any negative corpus. A resource policy is analyzed from the resource's perspective; a service principal is NOT public; a '*' narrowed by a principal-identity condition is NOT anonymous; effective access is never asserted (potential blast radius only); unmodeled/rejected inputs fail CLOSED and surface, never drop silently or return ok:true on a rejected context. NEVER write scratch/debug/test .mjs under content/tools/ AND never leave scratch-*.mjs in the tracked tree (put scratch in a git-ignored scratchpad; scratch-*.mjs is gitignored).`

const BASELINE = `You are a (replaceable) engineer on the LIVE, DEPLOYED IAM Blast Radius tool in ${REPO}. Shipped vanilla ES-module JS: ${SHIP}/. Read ${CONTRACTS}, story ${STORY} in ${DEV}/prd.json, ${REF}, and tests in ${S2}/${S3} FIRST. Full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN (1358) and MUST stay green; never weaken an assertion. HARD RULES: no network APIs in shipped JS; no innerHTML/eval/unsafe DOM; reject __proto__/constructor; deterministic; NEVER assert beyond evidence; fail closed on unmodeled/unknown/invalid. NO build step. ${GUARD}`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' }, shippedTreeClean: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'noNetwork', 'noUnsafeDom', 'cspClean', 'fixturesValidJson', 'shippedTreeClean', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

const panel = [
  { key: 'qa-resource-semantics', prompt: `QA + resource-semantics critic for ${STORY}. Read ${DEV}/prd.json (${STORY}) + ${REF}. Review the diff (cd ${REPO} && git diff -- content/tools tools/iam-blast-radius) and run cd ${DEV} && node --test "tests/**/*.test.js". Drive analyze() DIRECTLY. Blocking if any of the 4 fixes is wrong: (1) Principal '*' + PrincipalArn/PrincipalTag/userid/OrgPaths/PrincipalType still reported anonymous/public-critical (must be narrowed/high, no 'anonymous/anyone' wording) OR a genuinely public '*' no longer critical; (2) disjoint multi-value SourceArn/SourceAccount not warned as mismatched, OR a genuinely source-bound case wrongly downgraded; (3) analyzeResource(rejected/null ctx) not failing closed; (4) CanonicalUser/wildcard-ARN/service-wildcard/federated principals still dropped to zero findings; OR any suite-2 flip / suite-3 69/85 / negative-corpus regression. Read-only; do NOT edit.` },
  { key: 'security', prompt: `Security critic for ${STORY} using ${CONTRACTS}. Review diff + grep ${SHIP}. Blocking if: network API in shipped JS; innerHTML/eval/unsafe DOM; __proto__/constructor not rejected; inline style/script in HTML (csp_audit must pass); a scratch/debug/.mjs stray under content/tools/ (shipped-tree-hygiene must pass) OR a tracked scratch-*.mjs in the dev tree; a resource finding presented as effective/granted access. Read-only; do NOT edit.` },
  { key: 'reliability', prompt: `Reliability critic for ${STORY}. Run cd ${DEV} && node --test "tests/**/*.test.js". Confirm zero uncaught exceptions; determinism; suites 1/2/3 + identity/trust/resource negative corpora + review-decision + hygiene gates intact. Flag any regression/nondeterminism/throw/hang as blocking. Read-only except running tests; do NOT edit.` },
  { key: 'adversarial', prompt: `Adversarial critic for ${STORY} (scratch .mjs in a GIT-IGNORED scratchpad under ${DEV}, never content/, never a tracked scratch-*.mjs). Re-drive the exact repros + near-misses: Principal '*' + aws:PrincipalArn / aws:PrincipalTag / aws:userid must be narrowed-high not anonymous-critical, while '*' with only aws:SourceVpce (network-only) or no condition stays critical; multi-SourceArn-accounts all disjoint from SourceAccount(s) must be 'mismatched' medium (both directions), while a matching set stays source-bound info; analyzeResource(null) and blank/invalid ARN must fail closed (ok:false); a CanonicalUser grant and a wildcard-ARN principal ({AWS:'arn:aws:iam::*:root'}, {AWS:'...:role/app-*'}) must each surface >=1 fail-closed coverage finding, never zero. Blocking on any residual over/under-claim, fail-open, or silent drop. Report exact input + output. Read-only; do NOT edit.` },
]

let accepted = false, feedback = '', lastFindings = [], lastReason = ''
for (let iter = 1; iter <= 5; iter++) {
  await agent(
    `${BASELINE}\n\nImplement story ${STORY} (full spec + acceptance in ${DEV}/prd.json) - the 4 resource-evaluator edge fixes in ${SHIP}/engine/resource.js, ADD fixtures for each, keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
    { label: `impl:${STORY}:i${iter}`, phase: 'Implement', agentType: 'general-purpose' }
  )
  const gate = await agent(
    `Deterministic gate for ${STORY}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (full regression - ALL pass; capture regressed names); (b) grep ${SHIP} for network APIs -> noNetwork; (c) grep ${SHIP} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> noUnsafeDom; (d) cd ${REPO} && python3 scripts/csp_audit.py content/tools -> cspClean; (e) all ${DEV}/fixtures/**/*.json parse -> fixturesValidJson; (f) node --test tests/shipped-tree-hygiene.test.js AND git status shows no tracked scratch-*.mjs -> shippedTreeClean. pass=true iff all hold. Do NOT edit.`,
    { label: `gate:${STORY}:i${iter}`, phase: 'Gate', agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
  )
  if (!gate || !gate.pass) { feedback = `Gate failed: ${JSON.stringify(gate && gate.failures || ['gate null'])}`; lastReason = 'gate-fail'; log(`${STORY} i${iter}: gate FAIL`); continue }
  const cr = await parallel(panel.map((c) => () => agent(c.prompt, { label: `critic:${c.key}:${STORY}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA })))
  const verdict = arbitrate(panel, cr)
  lastFindings = cr.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))
  const blocking = lastFindings.filter((f) => f.blocking)
  if (verdict.accepted) { accepted = true; lastReason = 'all-pass'; log(`${STORY} ACCEPTED i${iter}`); break }
  if (verdict.failedCritics.length) {
    lastReason = `critic-nonpass: [${verdict.failedCritics.join(',')}]`
    feedback = `FAIL-CLOSED: critic(s) [${verdict.failedCritics.join(', ')}] returned no verdict (non-pass, NOT approval). Re-run.${blocking.length ? `\nAlso:\n${blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')}` : ''}`
    log(`${STORY} i${iter}: FAIL-CLOSED (${verdict.failedCritics.join(',')}), ${blocking.length} blocking`)
  } else {
    lastReason = `${blocking.length} blocking`
    feedback = blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
    log(`${STORY} i${iter}: ${blocking.length} blocking (${[...new Set(blocking.map((f) => f.critic))].join(',')}), re-impl`)
  }
}
await agent(
  `Update ${DEV}/progress.md: set the ${STORY} row to ${accepted ? 'accepted' : 'human-review'} with iteration count + last-round reason ("${lastReason}"). ${accepted ? '' : `Remaining:\n${feedback}`} Edit only that row.`,
  { label: `ledger:${STORY}`, phase: 'Arbiter', agentType: 'general-purpose', effort: 'low' }
)
return { story: STORY, accepted, reason: lastReason, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length, note: 'Phase 12.1 resource hardening. If accepted, then launch Phase 13 (SCP/RCP). Deploy (Phase 12 + 12.1 + 13) held for Oliver as rivassec identity.' }
