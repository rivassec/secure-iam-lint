export const meta = {
  name: 'secure-iam-lint-phase5-remediation',
  description: 'Phase 5 (Oliver GO 2026-08-27): fix the two RC-3 findings before the pre-tag refactor. S1 NEW-BUDGET-DENYFENCE [HIGH DoS] - an uncharged O(actions x notResources) loop (classifyResource charges zero work on the narrow-ARN path) bypasses both engine budgets; reachable via 3 call sites on the normal analyze() path. S2 NEW-SARIF-AGGREGATE [MED-HIGH] - buildAggregateSarif has no aggregate result/byte budget so a multi-file Action run silently loses Security-tab findings past GitHub 5000-result / 10MB caps. Serial tiered loop, tests-first, golden-corpus release-gate wired in. NOT pushed - work stays on wip.',
  phases: [{ title: 'S1-NEW-BUDGET-chargeWork' }, { title: 'S2-NEW-SARIF-AGGREGATE-budget' }, { title: 'Ledger' }],
}

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

const REPO = '/Users/oliver/dev/secure-iam-lint'
const ENGINE = `${REPO}/content/tools/iam-blast-radius/engine`
const SHELL = `${REPO}/content/tools/iam-blast-radius`
const DEV = `${REPO}/tools/iam-blast-radius`
const CLI = `${REPO}/cli`
const AUDIT = `${DEV}/audit`

const PRINCIPLE = `FAIL CLOSED + the deterministic work budget must bound EVERY analyze() run (browser + API). Do NOT over-correct: a normal within-caps policy must NOT newly trip the budget or lose findings; the negative corpus + full suite stay green; browser==CLI parity holds.`

const BASELINE = `You are a security engineer on PHASE 5 of secure-iam-lint (${REPO}). Two RC-3 findings to fix before the pre-tag refactor. Shipped engine ${ENGINE}/*.js is imported by the browser (analyze()), CLI (${CLI}/*.mjs), and Action (${REPO}/action/index.mjs). Read ${DEV}/docs/threat-model.md + architecture.md FIRST. ${PRINCIPLE}\n\nHARD RULES: no network/innerHTML/eval/unsafe-DOM in shipped JS; no 'node:' import in the browser engine graph; deterministic; NO build step; scratch only under a git-ignored scratchpad in ${DEV}. TESTS-FIRST: a real-boundary regression per fix (shipped analyze()/scan() for the engine; real emitted .sarif for the exporter) + a golden-corpus oracle/release-gate case. Keep the full node --test suite (incl ${AUDIT}/**) green.`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, testsPassed: { type: 'number' }, browserPure: { type: 'boolean' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, goldenOracleGreen: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'browserPure', 'noNetwork', 'noUnsafeDom', 'cspClean', 'goldenOracleGreen', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

const STORIES = [
  { id: 'S1-NEW-BUDGET-chargeWork', tier: 'semantic', maxIter: 5, focus: `NEW-BUDGET-DENYFENCE [HIGH DoS]: an uncharged O(actions x notResources) loop bypasses BOTH engine budgets (the deterministic 60M work limit AND the wall-clock deadline). ${ENGINE}/rules.js denyFencesToNarrow (~:747-771, the \`.some((r)=>classifyResource(r)!==RESOURCE_CLASS.NARROW)\` walk at ~:766) calls classifyResource (${ENGINE}/resource-arn.js:278) which charges ZERO work on the well-formed NARROW-ARN path (parseArn is pure; the withoutBudget-wrapped globReachesMultipleAccounts is a RED HERRING - it only runs on parse failure and short-circuits). denyFencesToNarrow is invoked ONCE PER MATCHED ACTION from 3 call sites on the normal analyze() path: ruleFindingDenySuppressed (~:837, run on EVERY finding by analyze.js:919), survivingBroadReadActions (~:879, analyze.js:1009), survivingSparedContainerReads (~:1630 and a second copy ~:1642). So N matched actions x M narrow notResources = uncharged O(N*M): REPRODUCED N=9998 M=9998 -> 33s with the 60M budget NEVER tripping; N=9500 M=300 -> 3.38s full-pipeline, aborted=false. The browser 8s Worker watchdog masks it (fails closed VISIBLY, denies service) but any direct analyze() API consumer has NO protection - this falsifies the glob.js 'deterministic work limit bounds every run' invariant. FIX: charge work so both budgets can abort the loop - the cleanest is to thread chargeWork() into classifyResource's narrow-ARN path (import from ./glob.js), OR charge chargeWork() per notResources element inside denyFencesToNarrow's loop (proportional to real work) so the .some() walk samples the budget and aborts mid-scan; the sentinel must propagate (analyzeRules already re-throws isGlobBudgetError). CAUTION - do NOT over-charge: a normal within-caps policy must NOT newly trip the budget or change verdicts. TESTS-FIRST: a DoS regression in the repo's DoS-budget suite asserting the ~9998x9998 (or a smaller reliably-tripping) within-caps deny-fence policy ABORTS under the 60M work budget (analyze() fails closed) AND under --budget-ms, well under the prior 33s; an ordinary deny-fence policy completes with IDENTICAL verdicts. Add a golden-corpus/release-gate case. MUST-CLOSE: the within-caps N x M deny-fence policy aborts under both budgets. MUST-NOT-BREAK: ordinary policies unchanged (no new abort, identical findings); NEW-01/02/R1-R6 closures hold; browser==CLI parity.` },

  { id: 'S2-NEW-SARIF-AGGREGATE-budget', tier: 'semantic', maxIter: 4, focus: `NEW-SARIF-AGGREGATE [MED-HIGH]: ${REPO}/action/index.mjs buildAggregateSarif (~:962-973) concatenates one SARIF run per scanned file with NO aggregate budget, unlike the per-run MAX_SARIF_BYTES=8MiB + SARIF_OUTPUT_TRUNCATED guard in ${CLI}/sarif.mjs (~:940-955). GitHub code-scanning upload caps (confirmed): 10MB gzip (over -> visible upload rejection), 5000 RESULTS per upload (over -> GitHub SILENTLY drops the excess, NO error), 20 runs per file. REPRODUCED: 100 files x 50 findings = 5000 results at only ~3.25MB -> hits the RESULT cap far before the byte cap, worst exit 0, ZERO truncation marker -> Security-tab findings silently lost (the exact harm the per-run budget's own comments say it exists to prevent). The PR exit-code gate stays honest (Action doesn't upload SARIF; consumers opt into upload-sarif as a non-gating step) - so this is NOT a gate fail-open - but the Security-tab SIGNAL is silently truncated. FIX: give buildAggregateSarif / the finalize+writeSarif path a DOCUMENT-LEVEL budget mirroring the per-run one - cap aggregate result-count (below GitHub's 5000) AND aggregate byte size (below the 10MB gzip cap, with a safe uncompressed proxy), and when exceeded, TRUNCATE deterministically (keep highest-severity/blocking results first) and emit an aggregate SARIF_OUTPUT_TRUNCATED analyzer-state / notification so the truncation is VISIBLE in the SARIF, never silent; make the caps configurable via env overrides mirroring the existing max-files/max-total-bytes inputs; the Action exit code must remain driven ONLY by finding severity (never downgraded by truncation). TESTS-FIRST: a multi-run aggregate exceeding the result-count cap -> truncation marker present + result count bounded + a blocking finding still present (highest-severity kept) + exit code unchanged; an aggregate exceeding the byte cap -> same; an under-cap aggregate -> unchanged, no marker. MUST-NOT-BREAK: under-cap multi-file runs identical; exit-code contract (worst-exit-code, exit 3 never green) unchanged.` },
]

const gatePrompt = (id) => `Deterministic gate for ${id} in ${REPO}. Run ONCE: (a) cd ${DEV} && node --test "tests/**/*.test.js" "audit/**/*.test.js" -> testsPassed=pass count, regressions into failures; (b) browserPure: grep ${ENGINE} ${SHELL}/app.js ${SHELL}/worker.js for "node:"/fs/path/process/Buffer/require -> NONE; (c) noNetwork: grep ${ENGINE} ${CLI} ${REPO}/action for fetch/XMLHttpRequest/WebSocket/sendBeacon/EventSource -> none; (d) noUnsafeDom: grep ${SHELL} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> none; (e) cspClean: cd ${REPO} && python3 scripts/csp_audit.py content/tools/iam-blast-radius; (f) goldenOracleGreen: cd ${DEV} && node --test audit/golden-corpus/golden-oracle.test.js AND (if a release-gate case was added) GOLDEN_RELEASE_GATE=1 node --test audit/golden-corpus/release-gate.test.js. pass=true iff (a)-(f) hold. Do NOT edit.`

const hunter = { key: 'fail-open-hunter', prompt: (id, spec) => `Adversarial hunter for ${id} (scratch .mjs only in a git-ignored scratchpad under ${DEV}). Gate ALREADY ran node --test + golden oracle - do NOT re-run; BREAK the fix: (S1) another uncharged path that still runs unbounded on a within-caps policy (another classifier/loop the budget can't see; the same denyFencesToNarrow reachable a different way; a shape that still hits 10s+), OR an OVER-CHARGE that now spuriously aborts/changes verdicts on an ORDINARY policy. (S2) an aggregate shape that still silently exceeds the result/byte cap with no marker, OR a truncation that drops a BLOCKING finding / downgrades the exit code, OR an under-cap run that now wrongly gets a marker. Assert browser==CLI parity. Any residual unbounded-loop, silent-truncation, or over-correction is a BLOCKER with exact input + measured output (timing / result-count / exit). STORY FOCUS: ${spec}. Read-only.` }
const correctness = { key: 'correctness', prompt: (id, spec) => `Correctness critic for ${id}. Gate ALREADY ran node --test + golden oracle (consume; only run the story's repros). Blocking if: S1 - the within-caps N x M deny-fence policy still runs unbounded (does not abort under the 60M work budget AND under --budget-ms), OR an ordinary policy now spuriously aborts / changes verdicts, OR the DoS regression is missing/not-real-boundary; S2 - an over-cap aggregate still silently truncates with no marker OR drops a blocking finding OR alters the exit code, OR the under-cap case regressed, OR the test doesn't assert the real emitted SARIF; OR the gate/oracle regressed; OR NEW-01/02/R1-R6 closures broke. STORY FOCUS: ${spec}. Read-only.` }

const results = []
let chainBroken = false
for (const story of STORIES) {
  phase(story.id)
  let accepted = false, feedback = '', lastFindings = [], lastReason = ''
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nSTORY ${story.id} [semantic]. Precisely specified - implement exactly it, add tests-first + a golden-corpus oracle/release-gate case, keep the full node --test suite green.\nFOCUS: ${story.focus}${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance or adding noise:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: story.id, agentType: 'general-purpose', effort: 'high' }
    )
    const gate = await agent(gatePrompt(story.id), { label: `gate:${story.id}:i${iter}`, phase: story.id, agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA })
    if (!gate || !gate.pass) { feedback = `Gate failed: ${JSON.stringify((gate && gate.failures) || ['gate null'])}`; lastReason = 'gate-fail'; log(`${story.id} i${iter}: gate FAIL`); continue }
    const panel = [hunter, correctness]
    const cr = await parallel(panel.map((c) => () => agent(c.prompt(story.id, story.focus), { label: `critic:${c.key}:${story.id}`, phase: story.id, agentType: 'general-purpose', effort: 'high', schema: FINDING_SCHEMA })))
    const verdict = arbitrate(panel, cr)
    lastFindings = cr.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))
    const blocking = lastFindings.filter((f) => f.blocking)
    if (verdict.accepted) { accepted = true; lastReason = `all-pass (${gate.testsPassed} tests)`; log(`${story.id} ACCEPTED i${iter}`); break }
    if (verdict.failedCritics.length) {
      lastReason = `critic-nonpass: [${verdict.failedCritics.join(',')}]`
      feedback = `FAIL-CLOSED: critic(s) [${verdict.failedCritics.join(', ')}] returned no verdict. Re-run.${blocking.length ? `\nAlso:\n${blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')}` : ''}`
      log(`${story.id} i${iter}: FAIL-CLOSED (${verdict.failedCritics.join(',')}), ${blocking.length} blocking`)
    } else {
      lastReason = `${blocking.length} blocking`
      feedback = blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
      log(`${story.id} i${iter}: ${blocking.length} blocking, re-impl`)
    }
  }
  results.push({ story: story.id, accepted, reason: lastReason, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length })
  if (!accepted) { chainBroken = true; log(`CHAIN STOP at ${story.id}: not accepted (${lastReason}).`); break }
}

phase('Ledger')
const summary = results.map((r) => `${r.story}: ${r.accepted ? 'accepted' : 'human-review'} (${r.reason})`).join('; ')
await agent(
  `Append a Phase-5 section to ${DEV}/progress.md recording each story outcome + last-round reason. ${summary}. ${chainBroken ? 'Chain halted early; note un-reached stories pending.' : 'All Phase-5 stories accepted.'} Edit/append only that section.`,
  { label: 'ledger:phase5', phase: 'Ledger', agentType: 'general-purpose', effort: 'low' }
)
return { phase: 5, stories: results, chainBroken, allAccepted: results.length === STORIES.length && results.every((r) => r.accepted), note: 'Phase-5: NEW-BUDGET-DENYFENCE chargeWork (uncharged deny-fence classifier loop) + NEW-SARIF-AGGREGATE document-level budget + truncation marker. NOT pushed - work on wip/appsec-phase2-4-20260827. After acceptance: reproduce closed (the within-caps NxM deny-fence policy aborts under budget; an over-cap aggregate SARIF emits a truncation marker keeping blocking findings), GOLDEN_RELEASE_GATE=1 green, full suite green. Remaining pre-tag: the behavior-preserving REFACTOR (per iam-blast-radius-refactor-plan.md re-scope), then a final RC + v1.0.0.' }
