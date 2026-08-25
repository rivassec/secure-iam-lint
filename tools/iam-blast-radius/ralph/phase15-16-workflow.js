export const meta = {
  name: 'secure-iam-lint-phase15-16',
  description: 'Phase 15 (headless CLI + SARIF 2.1.0) + Phase 16 (GitHub Action) for secure-iam-lint. Wraps the EXISTING browser-safe engine (read-only, never mutated) with a Node CLI, a fail-closed exit-code contract (0 clean / 1 findings>=threshold / 2 usage / 3 could-not-analyze / 4 internal), a SARIF adapter that separates security findings from analyzer-state findings, a browser-graph purity guard, a JS action, action self-tests, and docs. FAIL-CLOSED arbiter (Phase-11A). Serial stories; chain stops if a story cannot be honestly accepted.',
  phases: [{ title: 'P15-scan' }, { title: 'P15-cli' }, { title: 'P15-sarif' }, { title: 'P15-purity' }, { title: 'P16-action' }, { title: 'P16-selftests' }, { title: 'P16-docs' }, { title: 'Ledger' }],
}

// ===== FAIL-CLOSED ARBITER (verbatim Phase-11A standard; lockstep with review-decision.mjs) =====
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

const REPO = '/Users/oliver/dev/secure-iam-lint'
const DEV = `${REPO}/tools/iam-blast-radius`
const SHIP = `${REPO}/content/tools/iam-blast-radius`
const ENGINE = `${SHIP}/engine`
const DOCS = `${DEV}/docs/sarif-cli-design.md and ${DEV}/docs/github-action-plan.md (the AUTHORITATIVE design; follow them)`

const EXITCODES = `EXIT-CODE CONTRACT (the load-bearing invariant): 0 = analyzed, no findings at/above threshold; 1 = findings at/above threshold; 2 = usage/config error (bad or MISSING --family, missing/empty input/paths); 3 = FAIL-CLOSED could-not-analyze (analysisStatus partial|failed: unknown/unsupported/malformed/incomplete); 4 = internal invariant error. A CI gate treats 1,2,3,4 as FAILED. Code 3 is DISTINCT from 0 and from 1 - a fail-closed 'could not analyze' MUST NEVER collapse to 0/clean. NO --ignore-unknown flag. NO auto-detection of family.`

const GUARD = `PHASE-15/16 GUARDRAIL: build ADAPTERS around the existing engine; do NOT change analysis behavior. The browser-served engine (${ENGINE}/*.js) + ${SHIP}/app.js + ${SHIP}/worker.js are imported READ-ONLY and MUST stay browser-safe: NO 'node:' imports, no Node built-ins (fs/path/process/Buffer), no network, no eval, no dynamic import, may leak into that browser graph. New Node code (scan module, CLI, SARIF adapter, action wrapper) lives OUTSIDE the browser graph. Everything is ES modules, NO build step, deterministic. Fail CLOSED: unknown/unsupported/malformed/could-not-analyze are explicit states that map to exit 3 and to analyzer-state SARIF results, NEVER to success. ${EXITCODES} Put all node --test tests under ${DEV}/tests/ so the existing harness runs them. NEVER write scratch/debug files under content/tools/ (hygiene gate) or leave tracked scratch-*.mjs.`

const BASELINE = `You are a (replaceable) engineer on the secure-iam-lint repo in ${REPO}. The tool is a client-side AWS IAM blast-radius analyzer; you are adding a headless CLI + SARIF + a GitHub Action WITHOUT changing analysis behavior. Read ${DOCS}, ${DEV}/docs/architecture.md + threat-model.md (IMMUTABLE), and the story focus FIRST. The full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN (1488) and MUST stay green; add tests for new behavior; never weaken an assertion. HARD RULES + ${GUARD}`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, browserPure: { type: 'boolean' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, engineUnmodified: { type: 'boolean' }, shippedTreeClean: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'browserPure', 'noNetwork', 'noUnsafeDom', 'engineUnmodified', 'shippedTreeClean', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

const STORIES = [
  { id: 'P15-scan', maxIter: 5, focus: `Create a CALLABLE scan module (e.g. ${REPO}/cli/scan.mjs) exporting a pure function that takes {text, family, subjectAccount, partition, threshold} and returns a structured result {analysisStatus:'complete'|'partial'|'failed', analysisStates:[...], findings:[...], blockingCount, exitCode}. It calls the existing browser engine analyze() (import READ-ONLY from ${ENGINE}/analyze.js) and DERIVES analysisStatus from the engine's existing fail-closed signals (coverage 'incomplete'/NO_FINDINGS_INCOMPLETE, INVALID_FAMILY / unsupported family, certainty 'unknown', rejected/invalid input). Deterministic, Node-only, no engine mutation. Add tests. Adversarial target: an unsupported family / malformed policy / unknown-viability input MUST yield analysisStatus 'failed' or 'partial' (exitCode 3), NEVER 'complete'+0.` },
  { id: 'P15-cli', maxIter: 5, focus: `Build the CLI (${REPO}/cli/iam-br.mjs, shebang node, importable + runnable) over the scan module. Flags: --family (REQUIRED), --subject-account, --partition (default aws), --threshold (default high), --format json|sarif (default json), --output, --artifact-uri, --version, --help. Read the policy from a file arg or STDIN. JSON to stdout, diagnostics to stderr. Implement the FULL exit-code contract (${EXITCODES}). Add an EXIT-CODE MATRIX test that crafts an input for each of 0/1/2/3/4 and asserts the code. Adversarial: missing --family MUST be exit 2 (never auto-detect); a fail-closed input MUST be exit 3 (never 0); --threshold none must not turn a fail-closed 3 into 0.` },
  { id: 'P15-sarif', maxIter: 5, focus: `SARIF 2.1.0 adapter (${REPO}/cli/sarif.mjs) used when --format sarif. Map findings -> results: ruleId = finding TYPE, reportingDescriptor per type in tool.driver.rules, message.text deterministic, severity->level+security-severity (critical error/9.0, high error/7.0, medium warning/5.0, low note/2.0, info note/omit), properties.certainty/evidence/policyFamily, location model (default artifactLocation.uri 'stdin' or 'pasted-policy.json', --artifact-uri override), partialFingerprints on normalized SEMANTIC identity (finding type+family+statement identity+normalized action/resource/principal/condition) NEVER on message text/line/timestamp/key order. Analyzer-state (fail-closed) findings are SEPARATED: kind:'fail', level:'error', properties.category:'analysis-state', properties.failClosed:true, NO security-severity. Add golden-output tests + a SARIF 2.1.0 structural validation test (required fields; no external dep required). Adversarial: an analyzer-state result must carry NO security-severity and must not be mistakable for a vuln; a fail-closed run's SARIF must coincide with exit 3.` },
  { id: 'P15-purity', maxIter: 4, focus: `Add a node --test 'browser-graph purity' guard under ${DEV}/tests/ that statically walks the browser engine import graph (${ENGINE}/*.js + ${SHIP}/app.js + ${SHIP}/worker.js) and asserts ZERO 'node:'-scheme imports and no Node built-in usage (fs/path/process/Buffer/require), so CLI/SARIF Node code can never leak into the browser-served engine. Adversarial: adding a 'node:fs' import anywhere in that graph MUST make this test fail.` },
  { id: 'P16-action', maxIter: 5, focus: `The GitHub Action. Create ${REPO}/action.yml at the REPO ROOT (using: node20, main: action/index.mjs) with inputs paths(required, newline/glob), family(required), subject-account, partition(default aws), fail-on(default high), sarif-output(default iam-blast-radius.sarif); outputs sarif-path, exit-code, findings-count, blocking-findings-count, analysis-status. Create ${REPO}/action/index.mjs: read inputs (prefer ZERO-DEP: INPUT_* env + write to GITHUB_OUTPUT/GITHUB_STEP_SUMMARY; do NOT add @actions/core as a runtime dep unless vendored), resolve globs, run the scan module per file, aggregate with STRICT WORST-EXIT-CODE semantics, write the SARIF file, WRITE ALL OUTPUTS FIRST, then fail the action iff exitCode != 0 (set process.exitCode). It MUST NOT execute any repo-provided command/script. Add tests for the aggregation + output writing. Adversarial: exit 3 MUST fail the action; a multi-file run where ONE file is fail-closed MUST fail (worst code); empty/missing glob MUST be exit 2; a caught error must NEVER become exit 0.` },
  { id: 'P16-selftests', maxIter: 4, focus: `Add a GitHub Actions self-test workflow (${REPO}/.github/workflows/action-selftest.yml, permissions: contents:read) that runs the action (uses: ./) against fixtures for: known-good (expect success, exit 0), known-bad findings (continue-on-error, assert step outcome=failure + outputs.exit-code=1 + SARIF has the expected ruleId), malformed/fail-closed (assert outcome=failure + exit-code=3 + an analysis-state SARIF result exists), and usage-error (missing family/paths, exit-code=2). Provide the fixture policy files under a test dir. Adversarial: the malformed fixture step MUST assert exit-code 3, not 0.` },
  { id: 'P16-docs', maxIter: 3, focus: `Document the Action in the README (or a linked ACTION.md): what it does ('potential blast radius, not effective permissions'; fail-closed exit codes), an example workflow WITH github/codeql-action/upload-sarif (needs security-events: write) and one WITHOUT (contents: read only), inputs + outputs tables, required-permissions note (default contents:read), SHA-pinning guidance + a pull_request_target warning, supported families, and limits. Do NOT include Marketplace publishing steps (that is Oliver's manual step). ASCII only.` },
]

function critics(story) {
  return [
    { key: 'qa-functionality', prompt: `QA critic for ${story.id}. Read ${DOCS} + the story focus, review the diff (cd ${REPO} && git diff && git status), run cd ${DEV} && node --test "tests/**/*.test.js", and EXERCISE the new code directly (run the CLI/scan/SARIF/action wrapper on crafted inputs). Story focus: ${story.focus}. Blocking if the story's behavior is wrong, the exit-code contract is violated, SARIF is malformed or mixes analyzer-state with security findings, or any existing test regresses. Read-only; do NOT edit.` },
    { key: 'security-purity', prompt: `Security + browser-purity critic for ${story.id}. Blocking if: a 'node:' import or Node built-in (fs/path/process/Buffer) leaked into the browser engine graph (${ENGINE}/*.js, ${SHIP}/app.js, ${SHIP}/worker.js); the shipped engine analysis behavior was modified; the action executes repo-provided content; the action's default requires more than contents:read; a network API/eval/unsafe-DOM was introduced in shipped JS; a scratch/debug file under content/tools/ (hygiene) or a tracked scratch-*.mjs. Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${story.id}. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression, 1488+). Confirm zero uncaught exceptions, determinism, all prior suites + hygiene + review-decision gates intact. Flag any regression/nondeterminism/throw/hang as blocking. Read-only except running tests.` },
    { key: 'adversarial-failopen', prompt: `Adversarial FAIL-OPEN hunter for ${story.id} (scratch .mjs in a git-ignored scratchpad under ${DEV}, never content/). Your ONLY goal: make a fail-closed condition pass a gate. Try: a fail-closed/unsupported/malformed input yielding exit 0 or analysisStatus 'complete'; --threshold none turning a 3 into 0; the CLI/action catching an error and exiting 0; a multi-file action run where one fail-closed file still aggregates to 0; empty/missing paths treated as clean; an analyzer-state SARIF result carrying security-severity or being indistinguishable from a real finding; missing --family being auto-detected. Any success is a BLOCKER; report exact input + output. Read-only; do NOT edit.` },
  ]
}

const results = []
let chainBroken = false
for (const story of STORIES) {
  phase(story.id)
  let accepted = false, feedback = '', lastFindings = [], lastReason = ''
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nImplement story ${story.id}. Focus: ${story.focus}\nAdd tests for every new behavior and keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: story.id, agentType: 'general-purpose' }
    )
    const gate = await agent(
      `Deterministic gate for ${story.id} in ${REPO}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (ALL pass; capture regressed names into failures); (b) browserPure: grep ${ENGINE} ${SHIP}/app.js ${SHIP}/worker.js for "node:" imports or fs/path/process/Buffer/require usage -> must be NONE; (c) noNetwork: grep ${ENGINE} for fetch/XMLHttpRequest/WebSocket/sendBeacon/EventSource -> none; (d) noUnsafeDom: grep ${SHIP} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> none; (e) engineUnmodified: cd ${REPO} && git diff --name-only shows NO change under content/tools/iam-blast-radius/engine/ (adapters must not modify the engine); (f) shippedTreeClean: node --test tests/shipped-tree-hygiene.test.js passes AND no tracked scratch-*.mjs. pass=true iff all hold. Do NOT edit.`,
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
  if (!accepted) { chainBroken = true; log(`CHAIN STOP at ${story.id}: not accepted (${lastReason}). Later stories depend on this - halting.`); break }
}

phase('Ledger')
const summary = results.map((r) => `${r.story}: ${r.accepted ? 'accepted' : 'human-review'} (${r.reason})`).join('; ')
await agent(
  `Update ${DEV}/progress.md: append a Phase 15/16 section recording each story outcome + last-round reason. ${summary}. ${chainBroken ? 'The chain halted early; note un-reached stories as pending.' : 'All Phase 15/16 stories accepted.'} Edit/append only that section.`,
  { label: `ledger:phase15-16`, phase: 'Ledger', agentType: 'general-purpose', effort: 'low' }
)
return { phases: '15-16', stories: results, chainBroken, allAccepted: results.length === STORIES.length && results.every((r) => r.accepted), note: 'CLI + SARIF + GitHub Action for secure-iam-lint. NOT pushed - held for Oliver (rivassec identity). After acceptance: review, push to secure-iam-lint, then Oliver tags v1.0.0 + Marketplace.' }
