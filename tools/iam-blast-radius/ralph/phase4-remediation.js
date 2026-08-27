export const meta = {
  name: 'secure-iam-lint-phase4-remediation',
  description: 'Phase 4 (Oliver GO 2026-08-27, PRIORITIZED for a noon release decision): fix the two HIGH RC-2 residuals AT THE CLASS LEVEL (not the instance), plus a class-sweep to end the instance/sibling whack-a-mole. NEW-02 = SARIF positive-list fingerprint forgery (sibling of R2); NEW-01 = non-S3 undetermined-account whole-container read reads CLEAN (sibling of R1). The 3 LOW test-realism gaps are DEFERRED (non-blocking). Serial tiered loop, tests-first, golden-corpus release-gate wired in. NOT pushed - held for Oliver.',
  phases: [{ title: 'S1-NEW02-sarif-identity-injective' }, { title: 'S2-NEW01-undetermined-service-agnostic' }, { title: 'S3-class-sweep' }, { title: 'Ledger' }],
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

const PRINCIPLE = `FAIL CLOSED: never report clean/exit-0/no-findings/not-incomplete on a policy carrying real risk; never silently drop a candidate; SARIF identity must not be FORGEABLE from attacker-controlled policy text. Do NOT over-correct into FALSE POSITIVES/NOISE: same-account scoped reads stay QUIET (HYBRID); the negative corpus + full suite stay green; browser==CLI parity holds.`

const BASELINE = `You are a security engineer on PHASE 4 of secure-iam-lint (${REPO}) before v1.0.0. These are CLASS-LEVEL fixes for two HIGH residuals that are siblings of the Phase-3 fixes (the prior fixes were scoped too narrowly). Shipped engine ${ENGINE}/*.js is imported by the browser (analyze()), the CLI (${CLI}/*.mjs) and the Action (${REPO}/action/index.mjs). Read ${DEV}/docs/threat-model.md + architecture.md FIRST. ${PRINCIPLE}\n\nHARD RULES: no network/innerHTML/eval/unsafe-DOM in shipped JS; no 'node:' import in the browser engine graph; deterministic; NO build step; scratch only under a git-ignored scratchpad in ${DEV}. TESTS-FIRST: a real-boundary regression for every fix (shipped analyze()/scan() for engine; the REAL emitted .sarif bytes for the exporter) + (where noted) a golden-corpus oracle + release-gate case. Keep the full node --test suite (incl ${AUDIT}/**) green.`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, testsPassed: { type: 'number' }, browserPure: { type: 'boolean' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, goldenOracleGreen: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'browserPure', 'noNetwork', 'noUnsafeDom', 'cspClean', 'goldenOracleGreen', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

const STORIES = [
  { id: 'S1-NEW02-sarif-identity-injective', tier: 'semantic', maxIter: 5, focus: `NEW-02 [HIGH] SARIF positive-list fingerprint forgery (sibling of R2). ${CLI}/sarif.mjs findingIdentity (~:210-212) joins the POSITIVE lists with a plain NON-injective '|': actions=\${normList(f.actions).join('|')}, resources=\${normList(f.resources).join('|')}, principals=\${findingPrincipals(f).join('|')}. R2 already fixed this class for excludedActions/excludedResources via the INJECTIVE joinExcluded() (escapes \\ | \\n, ~:178-182). A resource/principal token containing a literal '|' or newline (S3 keys permit ~any byte; the engine applies NO charset restriction) forges the sorted-join identity of a distinct multi-element list -> identical partialFingerprint -> GitHub code-scanning dismissal of A auto-suppresses distinct live B. REPRODUCED: policy A resources [a/*,b/*] vs policy B single resource "a/*|b/*" -> byte-identical partialFingerprint through the REAL emitted .sarif. CLASS-LEVEL FIX: route EVERY attacker-controlled identity list through the injective joinExcluded() (or the same escaping helper) - actions, resources, AND principals (findingPrincipals funnels through the same line) - i.e. fix the whole findingIdentity join, not one field. Sonnet verified the OTHER identity channels are already safe (condition uses stableStringify; viability/escService/escTechnique are tool enums) - do NOT change those. TESTS-FIRST: assert the A-vs-B positive-list complements now produce DISTINCT partialFingerprints by comparing the ACTUAL emitted .sarif bytes (not just the helper); a '|' AND a newline token stay inert + non-forging; NON-complement / ordinary findings keep their SAME fingerprints (no churn). Add a golden-corpus oracle + release-gate case. MUST-NOT-BREAK: existing SARIF tests + fingerprints for ordinary findings unchanged.` },

  { id: 'S2-NEW01-undetermined-service-agnostic', tier: 'semantic', maxIter: 5, focus: `NEW-01 [HIGH] non-S3 undetermined-account whole-container read reads CLEAN (sibling of R1). ${ENGINE}/rules.js classifyContainerReads (~:1159-1167, the account-UNRESOLVABLE branch built by R1) collects the surviving-read finding ONLY when \`arn && arn.service === 's3'\`. A dynamodb/kinesis/rds-data ARN with an EMPTY or wildcard account segment makes concreteResourceAccount() return null - reaching this exact branch - for ANY service, but the S3-only gate drops it. REPRODUCED: unscoped dynamodb:Scan on an account-less table (\`arn:aws:dynamodb:us-east-1::table/orders\`) with --subject-account set -> exit 0, reason CLEAN, findings [] (must be non-clean). Controls: s3 account-less -> surfaces CROSS-ACCOUNT-DATA-READ-UNDETERMINED; dynamodb concrete-foreign -> CROSS-ACCOUNT-DATA-READ; dynamodb same-account -> quiet. CLASS-LEVEL FIX: make the undetermined-account surfacing SERVICE-AGNOSTIC - drop the arn.service==='s3' gate (or generalize to: any whole-container read that isWholeContainerRead with NO concrete account AND NO aws:ResourceAccount pin -> CROSS-ACCOUNT-DATA-READ-UNDETERMINED at info). Safe-direction / fail-closed. CAUTION: kinesis:GetRecords / rds-data:ExecuteStatement currently fail closed INCIDENTALLY via unrecognizedActions->coverage.incomplete; the new path must NOT DOUBLE-report for those (if the action is uncatalogued and already makes coverage incomplete, do not also emit a duplicate undetermined finding - or ensure the two coexist cleanly like the R1 mixed-resource case). TESTS-FIRST: dynamodb/kinesis/rds-data account-less whole-container read -> surfaced (non-clean); same-account resolvable -> QUIET; single-object -> QUIET (no over-correction); s3 behavior unchanged. Add golden-corpus oracle + release-gate case. MUST-NOT-BREAK: same-account/single-object quiet; s3 cases unchanged; negative corpus green.` },

  { id: 'S3-class-sweep', tier: 'semantic', maxIter: 4, focus: `CLASS-SWEEP to end the instance/sibling whack-a-mole (the RC keeps finding the mirror of each fix). AFTER S1+S2. Do a SYSTEMATIC audit for any OTHER instance of the two just-generalized classes: (A) grep the identity/fingerprint code (${CLI}/sarif.mjs findingIdentity/hashIdentity/findingPrincipals, and any partialFingerprint/semanticIdentity construction) for ANY remaining NON-injective join over attacker-controlled values - .join('|'), .join(','), template concatenation of policy-derived lists, or an unescaped multi-line parts array where a value could contain the delimiter/newline. Confirm each is either injective (joinExcluded/JSON.stringify/stableStringify) or provably non-attacker-controlled (tool enum). Fix any forgeable one the same way (joinExcluded); document the safe ones. (B) grep the engine for any OTHER SERVICE-GATED or single-shape invariant where a fail-closed/surfacing rule is scoped to one service/action/ARN-shape and a sibling shape would slip - e.g. \`service === '<x>'\`, \`=== 'DATA-EXFIL'\`-style id gates on suppression, BULK_READ_ACTIONS-only paths, s3-only special cases in coverage/undecidable logic - and determine whether a non-<x> sibling reads CLEAN. Reproduce any real one with node; if a NEW genuine fail-open is found, fix it at the class level with tests; if a construct is safe, document WHY (bounded by cap / not attacker-controlled / already fail-closed via another path). Deliverable: every identity-join and every service/id-gated suppression-or-surfacing invariant is either injective/generalized or explicitly justified. TESTS-FIRST for any fix. MUST-NOT-BREAK: no over-correction / no new noise; negative corpus + full suite green.` },
]

const gatePrompt = (id) => `Deterministic gate for ${id} in ${REPO}. Run ONCE: (a) cd ${DEV} && node --test "tests/**/*.test.js" "audit/**/*.test.js" -> testsPassed=pass count, regressions into failures; (b) browserPure: grep ${ENGINE} ${SHELL}/app.js ${SHELL}/worker.js for "node:" or fs/path/process/Buffer/require -> NONE; (c) noNetwork: grep ${ENGINE} ${CLI} ${REPO}/action for fetch/XMLHttpRequest/WebSocket/sendBeacon/EventSource -> none; (d) noUnsafeDom: grep ${SHELL} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> none; (e) cspClean: cd ${REPO} && python3 scripts/csp_audit.py content/tools/iam-blast-radius; (f) goldenOracleGreen: cd ${DEV} && node --test audit/golden-corpus/golden-oracle.test.js AND (if this story added a release-gate case) GOLDEN_RELEASE_GATE=1 node --test audit/golden-corpus/release-gate.test.js -> the now-fixed case must PASS. pass=true iff (a)-(f) hold. Do NOT edit.`

const hunter = { key: 'fail-open-hunter', prompt: (id, spec) => `Adversarial FAIL-OPEN hunter for ${id} (scratch .mjs only in a git-ignored scratchpad under ${DEV}). Gate ALREADY ran node --test + golden oracle - do NOT re-run; BREAK the fix: (1) another forgeable identity-join channel or another datastore/ARN-shape/service that still reads CLEAN when a real capability survives (find the NEXT sibling); (2) OVER-CORRECTION: a legitimate same-account/single-object read now wrongly flagged, an ordinary finding whose fingerprint churned, a bounded loop wrongly failed-closed. Assert browser==CLI parity. Any residual forgery/fail-open OR over-correction is a BLOCKER with exact input + measured output (fingerprint bytes / exit / findings). STORY FOCUS: ${spec}. Read-only.` }
const correctness = { key: 'correctness', prompt: (id, spec) => `Correctness critic for ${id}. Gate ALREADY ran node --test + golden oracle (consume; only run the story's specific repros). Blocking if: the fix is not CLASS-COMPLETE (S1: any positive identity list - actions/resources/principals - still uses a non-injective join, or the regression compares only the helper not the real .sarif; S2: any non-S3 datastore account-less whole-container read still reads CLEAN, or a double-report was introduced for kinesis/rds-data, or the subjectAccount-independent behavior regressed; S3: an identity-join or service-gated invariant was left unaudited/unjustified); it introduces a FALSE POSITIVE on a MUST-NOT-BREAK case (same-account/single-object quiet, ordinary-finding fingerprint churn, s3 unchanged); a tests-first artifact is missing or not real-boundary; or the gate/oracle regressed. STORY FOCUS: ${spec}. Read-only.` }

const results = []
let chainBroken = false
for (const story of STORIES) {
  phase(story.id)
  let accepted = false, feedback = '', lastFindings = [], lastReason = ''
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nSTORY ${story.id} [semantic]. Precisely specified - implement exactly it, add tests-first + (where noted) golden-corpus oracle/release-gate cases, keep the full node --test suite green.\nFOCUS: ${story.focus}${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance or adding noise:\n${feedback}` : ''}`,
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
  `Append a Phase-4 section to ${DEV}/progress.md recording each story outcome + last-round reason. ${summary}. ${chainBroken ? 'Chain halted early; note un-reached stories pending.' : 'All Phase-4 stories accepted.'} Edit/append only that section.`,
  { label: 'ledger:phase4', phase: 'Ledger', agentType: 'general-purpose', effort: 'low' }
)
return { phase: 4, stories: results, chainBroken, allAccepted: results.length === STORIES.length && results.every((r) => r.accepted), note: 'Phase-4 CLASS-LEVEL remediation of RC-2 residuals: NEW-02 all findingIdentity positive-list joins injective; NEW-01 undetermined-account whole-container surfacing service-agnostic; + class-sweep for remaining sibling instances. 3 LOW test-realism gaps DEFERRED (non-blocking). NOT pushed. After acceptance: reproduce closed (positive-list complements -> distinct fps; dynamodb account-less -> non-clean), GOLDEN_RELEASE_GATE=1 green, full suite green, then a FRESH RC (every-file re-scan + teams); do NOT push/tag - leave a resumable summary for Oliver.' }
