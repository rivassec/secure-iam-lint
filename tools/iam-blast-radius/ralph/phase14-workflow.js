export const meta = {
  name: 'iam-blast-radius-ralph-phase14',
  description: 'Phase 14: per-service resource-policy finding rules (IAM-1400..1404) for S3/KMS/SNS/SQS. Extends the generic resource evaluator with service-specific narrowing keys, dangerous-action ranking, confused-deputy controls, and fail-closed caveats (PAB, silent policy). FAIL-CLOSED arbiter (Phase-11A standard). Serial stories; each impl->gate->critic panel->arbiter; chain stops if a story cannot be honestly accepted.',
  phases: [{ title: 'IAM-1400' }, { title: 'IAM-1401' }, { title: 'IAM-1402' }, { title: 'IAM-1403' }, { title: 'IAM-1404' }, { title: 'Ledger' }],
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
const REF = `${DEV}/docs/resource-policy-semantics.md (generic resource grounding) and ${DEV}/docs/resource-per-service-semantics.md (AWS-verified per-service reference, 11 cited sources)`
const S1 = `${DEV}/docs/acceptance-suite.md`, S2 = `${DEV}/docs/acceptance-suite-2.md`, S3 = `${DEV}/docs/acceptance-suite-3.md`
const S4 = `${DEV}/docs/acceptance-suite-4.md (30 per-service cases, tests 101-130)`

// The 5 hardest correctness traps the setup research verified against AWS docs.
const TRAPS = `PER-SERVICE CORRECTNESS TRAPS (all AWS-doc-verified; getting any wrong is a blocker):
(1) KMS Principal:"*" is "all AWS identities in all accounts" - NOT anonymous/unauthenticated. The generic PUBLIC-ACCESS "including anonymous" wording is correct for S3/SQS but WRONG for KMS (KMS has no unauthenticated path).
(2) kms:ViaService pins the service CHANNEL, not the caller; a "*" narrowed ONLY by ViaService is still account-open. Only kms:CallerAccount / aws:PrincipalAccount / aws:PrincipalOrgID pin WHO.
(3) S3 request-property Denies (s3:x-amz-server-side-encryption, s3:TlsVersion) are constraints exactly like aws:SecureTransport - a Deny on them NEVER makes a public s3:GetObject Allow private.
(4) Dispatch bleed: the KMS not-anonymous carve-out must NOT leak to S3/SQS (SQS docs call Principal:"*" "all users (anonymous users)"; S3 is public). Keep S3/SQS "*" CRITICAL while softening ONLY KMS. Both directions are false-classification risks.
(5) kms:CreateGrant / s3:PutBucketPolicy / kms:PutKeyPolicy are delegation/takeover - rank as such, but NEVER over-claim as proven decrypt/effective access.`

const GUARD = `PHASE-14 GUARDRAIL: add SERVICE-SPECIFIC resource-policy findings on top of the generic resource evaluator (engine/resource.js). A resource policy is analyzed from the RESOURCE's perspective; findings report POTENTIAL blast radius / exposure, NEVER effective/granted access. A "*" narrowed by a genuine identity/org condition (aws:PrincipalOrgID, aws:PrincipalAccount, aws:SourceArn, aws:SourceAccount) is NOT anonymous/public-critical; a service principal is NOT public. Fail CLOSED on unmodeled/ambiguous/invalid input (surface it, never silently drop, never ok:true on a rejected context). Public Access Block and silent/empty policies are OUT of policy scope - emit the documented fail-closed caveat, never assert "private". The generic resource path and the identity/trust/boundary/session/SCP/RCP families stay UNCHANGED. ${TRAPS}`

const BASELINE = `You are a (replaceable) engineer on the LIVE, DEPLOYED IAM Blast Radius tool in ${REPO}. Shipped vanilla ES-module JS/CSS/HTML: ${SHIP}/. Read ${CONTRACTS}, the story in ${DEV}/prd.json, ${REF}, and ${S4} FIRST.

Full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN and MUST stay green; add tests/fixtures for new behavior; never weaken an assertion. PROTECTED (no regression): suites 1/2/3, the identity + trust + resource negative corpora, the review-decision + shipped-tree-hygiene gates.

HARD RULES: no network APIs in shipped JS; no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; DOM via createElement+textContent; reject __proto__/constructor; DETERMINISTIC engine; no inline style/script/on-handlers in HTML; NEVER assert beyond evidence; fail closed on unmodeled/unknown/invalid shapes. NO build step. NEVER write scratch/debug/test files under content/tools/ (the shipped tree - hygiene gate fails CI + it would deploy); put scratch under a git-ignored scratchpad, and a tracked scratch-*.mjs is also banned. Playwright/e2e is CI's job.

${GUARD}`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' }, shippedTreeClean: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'noNetwork', 'noUnsafeDom', 'cspClean', 'fixturesValidJson', 'shippedTreeClean', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

const STORIES = [
  { id: 'IAM-1400', kind: 'doc', maxIter: 3, focus: `Verify the grounding doc ${DEV}/docs/resource-per-service-semantics.md: every one of the 11 cited AWS sources resolves and actually supports the claim it backs; all 5 correctness traps are stated correctly; the fail-closed caveats (Public Access Block, silent/empty policy) are present and correct. This story changes DOCS only - no engine code.` },
  { id: 'IAM-1401', kind: 'code', maxIter: 5, focus: `Per-service DISPATCH scaffolding in engine/resource.js: route a resource policy to its service handler by the resourceContext.arn service (s3/kms/sns/sqs); anything else (unknown/unspecified service) uses the EXISTING generic path unchanged and NEVER throws. No new findings yet - pure routing. Zero regression to suites 1/2/3 or the resource negative corpus. Adversarial focus: dispatch bleed (trap 4) and unknown-service must fall back to generic, never error.` },
  { id: 'IAM-1402', kind: 'code', maxIter: 5, focus: `S3 bucket-policy rules + tests 101-108 as fixtures. Public s3:GetObject to "*" stays CRITICAL (101); "*" narrowed by aws:PrincipalOrgID is NOT anonymous (102); SourceIp-only "*" still anonymous-within-network near-miss (103); SSE/TLS-enforcing Deny does NOT privatize public access (104, trap 3); s3:PutBucketPolicy cross-account = takeover ranking (105, trap 5); cross-account read (106); same-account user grant (107); s3:ResourceAccount does NOT narrow the principal (108). PAB fail-closed caveat present.` },
  { id: 'IAM-1403', kind: 'code', maxIter: 5, focus: `KMS key-policy rules + tests 109-116 as fixtures. Principal:"*" is "all AWS identities", NOT anonymous - no "unauthenticated/anonymous" wording (109, trap 1); "*" narrowed only by kms:ViaService is STILL account-open, not scoped (111 vs 112, trap 2); kms:CreateGrant = onward-delegation ranking, never proven-decrypt (114, trap 5); silent/empty key policy = UNKNOWN, never "private" (115, fail-closed); the root "Enable IAM policies" full-control idiom is NOT a finding by itself.` },
  { id: 'IAM-1404', kind: 'code', maxIter: 5, focus: `SNS topic + SQS queue rules (shared messaging family - same semantics, different action namespace) + tests 117-130 as fixtures. Public sns:Subscribe/Publish + sqs:SendMessage/ReceiveMessage to "*" CRITICAL (117/122); SQS "*" IS anonymous per AWS docs (122, trap 4 - do NOT let KMS carve-out leak here); aws:SourceArn/SourceAccount = confused-deputy control that narrows (118/124); service principal NOT public (118/121/124); deprecated aws:SourceOwner handled; org-narrowed "*" not critical (120). Plus the fail-closed/adversarial cases 127-130 (silent-policy UNKNOWN, narrowed-* not critical, genuinely-public critical).` },
]

function critics(story) {
  if (story.kind === 'doc') {
    return [
      { key: 'aws-verifier', prompt: `AWS-verifier critic for ${story.id}. Read ${DEV}/docs/resource-per-service-semantics.md. For EACH of the 11 cited AWS sources, verify (WebFetch the AWS doc where feasible) that the citation resolves and actually supports the specific claim it backs. Blocking if: any citation is fabricated, dead, or does not support its claim; any of the 5 correctness traps is misstated (esp. KMS-not-anonymous, ViaService-not-caller-scoping); the Public Access Block or silent-policy fail-closed caveat is missing or claims "private". Read-only; do NOT edit.` },
      { key: 'completeness', prompt: `Completeness critic for ${story.id}. Cross-check ${DEV}/docs/resource-per-service-semantics.md against ${S4}: every service the acceptance suite tests (S3/KMS/SNS/SQS) has grounding coverage for its narrowing keys, dangerous actions, and confused-deputy control; no acceptance case relies on a rule the doc does not ground. Blocking on a material gap between the doc and the cases the code stories must pass. Read-only; do NOT edit.` },
    ]
  }
  return [
    { key: 'qa-resource-semantics', prompt: `QA + per-service-resource critic for ${story.id}. Read the story in ${DEV}/prd.json, ${REF}, and its target tests in ${S4}. Review the diff (cd ${REPO} && git diff -- content/tools tools/iam-blast-radius) and run cd ${DEV} && node --test "tests/**/*.test.js". Drive analyze() DIRECTLY with family=resource + the relevant resourceContext. Story focus: ${story.focus}. Blocking if any of the story's target cases is wrong, any of the 5 traps is violated, effective/granted access is asserted, a genuine narrowing condition is ignored, or ANY suite-1/2/3 / negative-corpus regression. Read-only; do NOT edit.` },
    { key: 'security', prompt: `Security critic for ${story.id} using ${CONTRACTS}. Review diff + grep ${SHIP}. Blocking if: network API in shipped JS; innerHTML/eval/unsafe DOM; __proto__/constructor not rejected; inline style/script/on-handler in HTML (csp_audit must pass); a scratch/debug/test file under content/tools/ (shipped-tree-hygiene must pass) OR a tracked scratch-*.mjs; injection fixtures no longer inert; a resource finding presented as effective/granted access. Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${story.id}. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression). Confirm zero uncaught exceptions; determinism; suites 1/2/3 + identity/trust/resource negative corpora + review-decision + hygiene gates intact; DoS caps hold. Flag any regression, nondeterminism, uncaught throw, or hang as blocking. Read-only except running tests; do NOT edit source.` },
    { key: 'adversarial', prompt: `Adversarial critic for ${story.id} (scratch .mjs UNDER a git-ignored scratchpad in ${DEV} - never under content/, never a tracked scratch-*.mjs - against ${SHIP}/engine/). Re-drive the story's repros AND near-misses, weaponizing the 5 traps: ${TRAPS}\nStory focus: ${story.focus}. Blocking on any over/under-claim, dispatch bleed, fail-open, silent drop, or manufactured effective-access. Report exact input + output. Read-only; do NOT edit.` },
  ]
}

const results = []
let chainBroken = false
for (const story of STORIES) {
  phase(story.id)
  let accepted = false, feedback = '', lastFindings = [], lastReason = ''
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nImplement story ${story.id} (full spec + acceptance in ${DEV}/prd.json). Focus: ${story.focus}\nAdd fixtures/tests for every new behavior and keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: story.id, agentType: 'general-purpose' }
    )
    const gate = await agent(
      `Deterministic gate for ${story.id}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (full regression - ALL pass; capture any regressed names into nodeTest + failures); (b) grep ${SHIP} for network APIs (fetch/XMLHttpRequest/WebSocket/sendBeacon/EventSource/import(http) -> noNetwork; (c) grep ${SHIP} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> noUnsafeDom; (d) cd ${REPO} && python3 scripts/csp_audit.py content/tools -> cspClean; (e) all ${DEV}/fixtures/**/*.json parse -> fixturesValidJson; (f) node --test tests/shipped-tree-hygiene.test.js AND git status shows no tracked scratch-*.mjs under content/tools -> shippedTreeClean. pass=true iff ALL hold. Do NOT edit.`,
      { label: `gate:${story.id}:i${iter}`, phase: story.id, agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
    )
    if (!gate || !gate.pass) { feedback = `Gate failed: ${JSON.stringify((gate && gate.failures) || ['gate null'])}`; lastReason = 'gate-fail'; log(`${story.id} i${iter}: gate FAIL`); continue }
    const panel = critics(story)
    const cr = await parallel(panel.map((c) => () => agent(c.prompt, { label: `critic:${c.key}:${story.id}`, phase: story.id, agentType: 'general-purpose', schema: FINDING_SCHEMA })))
    const verdict = arbitrate(panel, cr)
    lastFindings = cr.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))
    const blocking = lastFindings.filter((f) => f.blocking)
    if (verdict.accepted) { accepted = true; lastReason = 'all-pass'; log(`${story.id} ACCEPTED i${iter}`); break }
    if (verdict.failedCritics.length) {
      lastReason = `critic-nonpass: [${verdict.failedCritics.join(',')}]`
      feedback = `FAIL-CLOSED: critic(s) [${verdict.failedCritics.join(', ')}] returned no verdict (non-pass, NOT approval). Re-run.${blocking.length ? `\nAlso:\n${blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')}` : ''}`
      log(`${story.id} i${iter}: FAIL-CLOSED (${verdict.failedCritics.join(',')}), ${blocking.length} blocking`)
    } else {
      lastReason = `${blocking.length} blocking`
      feedback = blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
      log(`${story.id} i${iter}: ${blocking.length} blocking (${[...new Set(blocking.map((f) => f.critic))].join(',')}), re-impl`)
    }
  }
  results.push({ story: story.id, accepted, reason: lastReason, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length })
  if (!accepted) { chainBroken = true; log(`CHAIN STOP at ${story.id}: not accepted (${lastReason}). Later stories build on this base - halting.`); break }
}

phase('Ledger')
const summary = results.map((r) => `${r.story}: ${r.accepted ? 'accepted' : 'human-review'} (${r.reason})`).join('; ')
await agent(
  `Update ${DEV}/progress.md: set each of these rows to its outcome with last-round reason. ${summary}. ${chainBroken ? 'The chain halted early; leave un-reached stories pending.' : 'All Phase-14 stories accepted.'} Edit only those rows.`,
  { label: `ledger:phase14`, phase: 'Ledger', agentType: 'general-purpose', effort: 'low' }
)
return { phase: 14, stories: results, chainBroken, allAccepted: results.length === STORIES.length && results.every((r) => r.accepted), note: 'Per-service resource rules. Deploy (branch phase-14-resource-per-service) HELD for Oliver as rivassec identity. Next target after Phase 14: GitHub Action (SARIF/CLI + action.yml).' }
