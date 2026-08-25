export const meta = {
  name: 'secure-iam-lint-phase17-appsec-remediation',
  description: 'Remediate the pre-v1.0.0 app-sec audit (two independent teams, do-not-ship). Fix the 2 HIGH fail-opens (DATA-EXFIL ARN-wildcard blindness; browser<-CLI fail-closed guard divergence), the MEDIUM glob DoS, and 2 LOW output-hygiene issues - AND capture the bug CLASS at CI level: a browser==CLI safety-parity gate, a must-warn corpus, and a complexity time-budget gate. FAIL-CLOSED arbiter with a dedicated fail-OPEN hunter. Serial stories; chain stops if a story cannot be honestly accepted.',
  phases: [{ title: 'S1-dataexfil-arn' }, { title: 'S2-guard-parity' }, { title: 'S3-dos-budget' }, { title: 'S4-sarif-sid' }, { title: 'S5-md-autolink' }, { title: 'S6-cicd-capture' }, { title: 'Ledger' }],
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

const REPO = '/Users/oliver/dev/secure-iam-lint'
const ENGINE = `${REPO}/content/tools/iam-blast-radius/engine`
const SHELL = `${REPO}/content/tools/iam-blast-radius`
const DEV = `${REPO}/tools/iam-blast-radius`
const CLI = `${REPO}/cli`

const PRINCIPLE = `The tool's whole promise is FAIL CLOSED: it must NEVER report clean/exit-0/no-findings on a policy that carries real risk (threat-model T8). Every fix here closes a fail-OPEN. But do NOT over-correct into false POSITIVES: the existing negative "must-not-fire" corpus (${DEV}/fixtures/negative*, tests negative*.test.js) and the full 1702-test suite MUST stay green. When unsure whether a shape is risky, prefer an explicit incomplete/fail-closed analyzer-state over either a silent clean OR a fabricated critical.`

const BASELINE = `You are a security engineer remediating a two-team app-sec audit of secure-iam-lint (${REPO}) before its v1.0.0 Marketplace release. Vanilla ES-module JS, NO build step; shipped engine ${ENGINE}/*.js is imported by BOTH the browser (${SHELL}/app.js,worker.js via analyze()) AND the CLI/Action (${CLI}/scan.mjs). Read ${DEV}/docs/threat-model.md + architecture.md FIRST. ${PRINCIPLE}\n\nHARD RULES: no network APIs / innerHTML / eval / unsafe DOM in shipped JS; no 'node:' import may leak into the browser engine graph (${ENGINE}/*.js, ${SHELL}/app.js, ${SHELL}/worker.js); reject __proto__/constructor; DETERMINISTIC; NO build step; NEVER write scratch/debug files under content/tools/ or leave a tracked scratch-*.mjs. Put all node --test tests under ${DEV}/tests/. Add a regression fixture for EVERY fix.`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, browserPure: { type: 'boolean' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, shippedTreeClean: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'browserPure', 'noNetwork', 'noUnsafeDom', 'cspClean', 'shippedTreeClean', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

const STORIES = [
  { id: 'S1-dataexfil-arn', maxIter: 5, focus: `HIGH fail-open: DATA-EXFIL bulk-read detection is blind to ARN-wildcard resources. resourceIsBroad() (${ENGINE}/rules.js ~530) treats only the bare '*' (or NotResource) as broad, so s3:GetObject on arn:aws:s3:::*/* (also arn:aws:s3:::*, arn:aws:s3:::*/prefix*, arn:aws:*, arn:*:*:*:*:*, wildcard-bucket) returns findings=[] status complete exit 0 CLEAN on BOTH CLI and browser. Verified: analyze({s3:GetObject on arn:aws:s3:::*/*}) -> 0 findings; Resource:'*' correctly fires DATA-EXFIL. FIX: make resourceIsBroad() + the ruleDataExfil breadth gate (~779) + ruleDataReadScoped fallback (~854) treat a resource that matches all/nearly-all ARNs (trailing-wildcard partition/service/bucket, arn with '*' segments) as broad. Add a fixtures/must-warn/ entry for EACH broad-ARN form asserting the bulk-read finding fires and exit is non-zero. Do NOT start flagging genuinely-scoped ARNs (arn:aws:s3:::my-bucket/prefix/*) as account-wide - keep the negative corpus green.` },
  { id: 'S2-guard-parity', maxIter: 6, focus: `HIGH fail-open + the STRUCTURAL fix: the shared engine analyze() fails OPEN on shapes the CLI adapter scan.mjs catches (EMPTY_NOTACTION_COMPLEMENT, EMPTY_NOTRESOURCE_COMPLEMENT, MALFORMED_CONDITION_VALUE, SUPPRESSED_NEVER_MATCH_ALLOW). Verified fail-open on the BROWSER path: {Allow,NotAction:[],Resource:'*'}; {Allow,Action:'s3:GetObject',NotResource:[]}; {Allow,Action:'*',Resource:'*',Condition:{'ForAnyValue:StringEquals':{'aws:PrincipalOrgID':[]}}} all -> analyze() ok:true findings=0 no-incomplete, while scan() exits 3. FIX: MOVE every one of those fail-closed guards from ${CLI}/scan.mjs into the shared engine (model.js/validate.js/analyze.js) so analyze() emits an explicit incomplete/blocked analyzer-state (coverage.incomplete=true) for each; then delete the now-redundant scan.mjs adapter-only paths so the two surfaces cannot drift. BUILD THE CI CAPTURE: ${DEV}/tests/browser-cli-parity.test.js asserting the INVARIANT over a corpus (the audit repros + existing fixtures): for every policy, if scan() is fail-closed/non-clean then analyze() must NOT be clean (ok:true && 0 findings && !incomplete). The browser engine may never be MORE permissive than the CLI on safety. Adversarial focus: enumerate scan.mjs's full guard set and prove analyze() now matches ALL of it.` },
  { id: 'S3-dos-budget', maxIter: 5, focus: `MEDIUM DoS: globMatch is O(n*m) (confirmed quadratic: pattern '*'+'a'*(N/2)+'b' vs 'a'*N doubles ~4x per 2x). Three copies (${ENGINE}/escalation.js ~128, evaluator.js ~77, rules.js ~109); reachable via denyResourceCoverage. validate.js caps total bytes but has NO per-individual-string cap, and the CLI (${CLI}/iam-br.mjs) + Action (${REPO}/action/index.mjs) run analysis synchronously with NO wall-clock budget (only the browser worker has the T5 budget). FIX: (a) add a per-string length cap to validate.js LIMITS - reject any single Action/Resource/NotAction/NotResource over a few KB (real ARNs/actions are short) and fail CLOSED; (b) dedupe the three globMatch copies into ONE shared matcher and make its backtrack linear (record the star index without re-scanning); (c) give the CLI + Action a wall-clock budget (AbortController/timeout) that reports a graceful fail-closed 'analysis aborted (resource budget)' incomplete state, never a clean pass. BUILD ${DEV}/tests/complexity-budget.test.js asserting the adversarial worst-cases (the quadratic glob input at a bounded size, a cap-sized policy) complete under a fixed ms budget. Add a must-warn/over-cap fixture asserting the per-string cap fails closed.` },
  { id: 'S4-sarif-sid', maxIter: 4, focus: `LOW: attacker-controlled policy Sid is injected verbatim into SARIF message.text (${CLI}/sarif.mjs ~227) which GitHub renders as markdown in the Security tab, AND folded into partialFingerprints (~161) - so a fork PR controlling Sid can craft a fingerprint COLLIDING with a dismissed base-branch alert to auto-suppress a real finding. FIX: sanitize the Sid before embedding (strip control chars/newlines, cap length ~128 + ellipsize, render as a distinct quoted token not free prose), apply the same to properties.statementSid, AND exclude attacker-controlled free-form fields from the partialFingerprints IDENTITY (fingerprint on finding type + family + normalized statement position/action/resource/principal - NOT the raw Sid) so a hostile Sid cannot force a collision. Add fixtures asserting a hostile Sid ([x](javascript:...), newlines, 10KB) is neutralized in message.text and does NOT change the fingerprint of an otherwise-identical finding.` },
  { id: 'S5-md-autolink', maxIter: 3, focus: `LOW: Markdown export (${ENGINE}/report.js breakAutolinks ~164) neutralizes www./:// autolinks but NOT bare email addresses, so a hostile policy field (Sid/ARN/condition value) containing local@domain.tld yields a clickable mailto: autolink in a shared report. FIX: in breakAutolinks() detect a bare local@domain.tld at a word boundary and break the pre-'@' boundary (backslash-escape) the same way as the other autolink classes. Add a fixture asserting an '@'-bearing policy value renders inert (no mailto: autolink) in Markdown export.` },
  { id: 'S6-cicd-capture', maxIter: 4, focus: `CI-LEVEL CAPTURE of the whole bug CLASS so it cannot recur. (1) Consolidate every must-warn fixture the fix stories added into a corpus with a single ${DEV}/tests/must-warn.test.js runner (mirror the existing negative*.test.js "must-not-fire" pattern) - each entry is a known-dangerous policy that MUST yield a finding / non-clean result on BOTH analyze() and scan(). (2) Ensure browser-cli-parity.test.js (from S2) and complexity-budget.test.js (from S3) are robust node --test files auto-run by the existing CI 'test' job. (3) Add a NIGHTLY differential-fuzz workflow ${REPO}/.github/workflows/fuzz-parity.yml (schedule + workflow_dispatch, least-privilege contents:read, pinned actions) that runs a seeded, deterministic generator (${DEV}/tests/fuzz/parity-fuzz.mjs) producing many mutated policies and asserting the analyze()==scan() safety-parity invariant, failing on any newly-discovered fail-open. (4) Document the three invariants (browser>=CLI safety parity, must-warn corpus, complexity budget) in ${DEV}/docs/threat-model.md as standing controls. Everything pinned + least-privilege; no new fail-open.` },
]

const panel = [
  { key: 'qa-correctness', prompt: `QA + correctness critic for STORY. Read ${DEV}/docs/threat-model.md + the story focus, review the diff (cd ${REPO} && git diff) and run cd ${DEV} && node --test "tests/**/*.test.js". Drive analyze() AND scan() DIRECTLY on the story's repro inputs. Blocking if: the fix does not actually close the named fail-open (the repro still returns clean); it introduces a FALSE POSITIVE (a genuinely-safe/ scoped policy now flagged, or the negative "must-not-fire" corpus regresses); the required must-warn fixture / parity / budget test is missing or does not assert the real invariant; or ANY existing test regresses. Read-only; do NOT edit.` },
  { key: 'fail-open-hunter', prompt: `Adversarial FAIL-OPEN hunter for STORY (scratch .mjs in a git-ignored scratchpad under ${DEV}, never content/). Your ONLY job: after the fix, find a NEW input that still makes analyze() (the browser engine path) report clean / ok:true / 0 findings / no-incomplete on a policy that carries the SAME class of risk the story fixes - i.e. prove the CLASS is not fully closed. Also confirm the browser==CLI parity invariant holds on your crafted inputs (analyze() must never be more permissive than scan()). For the DoS story, craft the worst-case input and MEASURE - a >2s analysis or an uncapped per-string is a fail. Any residual fail-open, parity violation, or unbounded time is a BLOCKER; report the exact input + output. Read-only; do NOT edit.` },
  { key: 'security', prompt: `Security critic for STORY. Review diff + grep the shipped tree. Blocking if: a network API / innerHTML / eval / unsafe DOM introduced in shipped JS; a 'node:' import leaked into the browser engine graph; __proto__/constructor not rejected; csp_audit fails; a scratch/debug/test file under content/tools/ (shipped-tree-hygiene) or a tracked scratch-*.mjs; the SARIF Sid sanitization is bypassable (injection still reaches message.text) or the fingerprint still collides on a hostile Sid; a new workflow that is not least-privilege or uses an unpinned action. Read-only; do NOT edit.` },
  { key: 'reliability', prompt: `Reliability critic for STORY. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression, 1702+ plus the new parity/must-warn/budget tests). Confirm zero uncaught exceptions, determinism, ALL prior suites + negative corpora + e2e-relevant invariants intact, and the DoS fix actually bounds wall-clock. Flag any regression / nondeterminism / throw / hang as blocking. Read-only except running tests.` },
]

const results = []
let chainBroken = false
for (const story of STORIES) {
  phase(story.id)
  let accepted = false, feedback = '', lastFindings = [], lastReason = ''
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nSTORY ${story.id}. Focus: ${story.focus}\nAdd a regression fixture/test for every change and keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts or introducing false positives:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: story.id, agentType: 'general-purpose', effort: 'high' }
    )
    const gate = await agent(
      `Deterministic gate for ${story.id} in ${REPO}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (ALL pass; capture regressed names into failures); (b) browserPure: grep ${ENGINE} ${SHELL}/app.js ${SHELL}/worker.js for "node:" imports or fs/path/process/Buffer/require usage -> NONE; (c) noNetwork: grep ${ENGINE} for fetch/XMLHttpRequest/WebSocket/sendBeacon/EventSource -> none; (d) noUnsafeDom: grep ${SHELL} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> none; (e) cspClean: cd ${REPO} && python3 scripts/csp_audit.py content/tools/iam-blast-radius; (f) shippedTreeClean: node --test tests/shipped-tree-hygiene.test.js AND no tracked scratch-*.mjs under content/tools. pass=true iff all hold. Do NOT edit.`,
      { label: `gate:${story.id}:i${iter}`, phase: story.id, agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA }
    )
    if (!gate || !gate.pass) { feedback = `Gate failed: ${JSON.stringify((gate && gate.failures) || ['gate null'])}`; lastReason = 'gate-fail'; log(`${story.id} i${iter}: gate FAIL`); continue }
    const cr = await parallel(panel.map((c) => () => agent(c.prompt.replace(/STORY/g, story.id), { label: `critic:${c.key}:${story.id}`, phase: story.id, agentType: 'general-purpose', effort: 'high', schema: FINDING_SCHEMA })))
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
  if (!accepted) { chainBroken = true; log(`CHAIN STOP at ${story.id}: not accepted (${lastReason}).`); break }
}

phase('Ledger')
const summary = results.map((r) => `${r.story}: ${r.accepted ? 'accepted' : 'human-review'} (${r.reason})`).join('; ')
await agent(
  `Append a Phase-17 app-sec-remediation section to ${DEV}/progress.md recording each story outcome + last-round reason. ${summary}. ${chainBroken ? 'Chain halted early; note un-reached stories as pending.' : 'All Phase-17 stories accepted.'} Edit/append only that section.`,
  { label: 'ledger:phase17', phase: 'Ledger', agentType: 'general-purpose', effort: 'low' }
)
return { phase: 17, stories: results, chainBroken, allAccepted: results.length === STORIES.length && results.every((r) => r.accepted), note: 'App-sec audit remediation + CI-level capture (browser==CLI parity gate, must-warn corpus, complexity budget, nightly differential fuzz). NOT pushed - held for Oliver. After acceptance: re-run BOTH audit teams to confirm closure, then tag v1.0.0.' }
