export const meta = {
  name: 'iam-blast-radius-ralph-phase9',
  description: 'Phase 9 correctness fixes for 3 in-scope Suite-II gaps (44 duplicate-JSON-keys, 34 role-takeover-chain, 48 invalid-wildcard-Principal-ARN), then re-run BOTH acceptance suites. Deferred families (resource/boundary/session/RCP) stay honestly fail-closed.',
  phases: [{ title: 'Implement' }, { title: 'Gate' }, { title: 'Critics' }, { title: 'Arbiter' }, { title: 'Re-test' }],
}

const REPO = '/Users/oliver/dev/devsecops-notes'
const DEV = `${REPO}/tools/iam-blast-radius`
const SHIP = `${REPO}/content/tools/iam-blast-radius`
const CONTRACTS = `${DEV}/docs/architecture.md and ${DEV}/docs/threat-model.md (IMMUTABLE)`
const S1 = `${DEV}/docs/acceptance-suite.md (suite 1, tests 1-24)`
const S2 = `${DEV}/docs/acceptance-suite-2.md (suite 2, tests 25-54)`

const STORIES = [
  { id: 'IAM-901', maxIter: 4 },
  { id: 'IAM-902', maxIter: 4 },
  { id: 'IAM-903', maxIter: 4 },
  { id: 'IAM-904', maxIter: 4 },
]

const BASELINE = `You are a (replaceable) engineer on the LIVE, LAUNCHED, DEPLOYED IAM Blast Radius tool in ${REPO}. Shipped vanilla ES-module JS: ${SHIP}/. Dev tests: ${DEV}/tests/; fixtures: ${DEV}/fixtures/. Read ${CONTRACTS}, the story (id + requirements + acceptance) in ${DEV}/prd.json, and the specific tests in ${S2} FIRST.

This MODIFIES a working, deployed tool. The full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN and MUST stay green; update tests/fixtures only for behavior a story INTENTIONALLY changes; never weaken an assertion. PROTECTED (must not regress): all suite-1 acceptance fixtures (tests 1-24), the identity negative corpus (fixtures/negative), and the trust negative corpus (fixtures/negative-trust).

HARD RULES: no network APIs in shipped JS; no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; DOM via createElement+textContent; reject __proto__/constructor; DETERMINISTIC engine; no inline style/script/on-handlers in HTML; reports "potential blast radius" NOT "effective permissions"; NEVER assert beyond evidence; fail closed on unmodeled shapes. NO build step. Playwright/e2e is CI's job.

PHASE-9 SCOPE FENCE: fix ONLY the three named in-scope bugs. Do NOT attempt resource-based policies, permissions boundaries, session policies, or RCP families (those stay honestly fail-closed / a documented family-selector gap - a separate future tranche). Preserve every existing fail-closed behavior.`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'noNetwork', 'noUnsafeDom', 'cspClean', 'fixturesValidJson', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

function critics(story) {
  return [
    { key: 'qa-semantics', prompt: `QA + IAM-semantics critic for ${story.id}. Read the story in ${DEV}/prd.json and its target test in ${S2}. Review the diff (cd ${REPO} && git diff -- content/tools tools/iam-blast-radius) and run cd ${DEV} && node --test "tests/**/*.test.js". VERIFY BY DRIVING analyze() DIRECTLY (scratch .mjs importing ${SHIP}/engine/analyze.js). Blocking if: the targeted suite-2 test is still wrong; the fix over-reaches into a deferred family (resource/boundary/session/RCP) or breaks an existing fail-closed; a duplicate-key false-positive on legal policies; a takeover-chain false-positive on a partial set or cross-role actions; a valid Principal (specific ARN / account root / '*' / wildcard PrincipalArn CONDITION) wrongly flagged invalid; provenance wrong (actions attributed to the wrong statement); OR any suite-1 test regressed. Read-only; do NOT edit.` },
    { key: 'security', prompt: `Security critic for ${story.id} using ${CONTRACTS}. Review diff + grep ${SHIP}. Blocking if: any network API in shipped JS; innerHTML/eval/unsafe DOM; DOM/attrs built unsafely from policy input; __proto__/constructor not rejected; inline style/script/on-handler in HTML; the duplicate-key raw scan itself is unsafe (ReDoS / catastrophic backtracking / unbounded memory on hostile input); XSS/proto-pollution fixtures no longer inert. Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${story.id}. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression). Confirm: zero uncaught exceptions on malformed/adversarial + all fixtures; determinism; the duplicate-key scanner terminates fast on large/deeply-nested input (no hang); suite-1 fixtures + both negative corpora unchanged; DoS caps hold. Flag nondeterminism, an uncaught throw, a hang, or a regressed test as blocking. Read-only except running tests; do NOT edit source.` },
    { key: 'adversarial', prompt: `Adversarial critic for ${story.id}. Try to BREAK the fix (scratch .mjs feeding ${SHIP}/engine/analyze.js). For 901: a legal policy with the same key name in different objects must NOT trip DUPLICATE_JSON_KEY; a duplicate key nested inside a Condition must still be caught; a giant/deeply-nested duplicate-key input must not hang. For 902: PutRolePolicy+UpdateAssumeRolePolicy+AssumeRole spread across THREE roles (not the same) must NOT fire critical takeover; the same three on ONE role via wildcard resource must be judged correctly; PassRole must NOT be required. For 903: aws:PrincipalArn wildcard in a CONDITION (valid) must NOT be flagged; account-root and specific-role Principals must NOT be flagged; only a wildcard in the Principal ELEMENT ARN fires. Blocking if you find a false-positive, false-negative, or a hang. Report the exact policy + wrong output. Read-only; do NOT edit.` },
  ]
}

const results = []
for (const story of STORIES) {
  log(`=== ${story.id} starting ===`)
  let accepted = false, feedback = '', lastFindings = []
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nImplement story ${story.id} (full spec + acceptance in ${DEV}/prd.json). Modify shipped module(s) under ${SHIP}/engine (validate.js/parse.js for 901; correlate.js/escalation.js for 902; trust.js/family.js for 903), ADD the fixtures the story requires, wire tests, keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
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

// Final independent re-test of BOTH suites (Oliver: "re-run the 2 examples to ensure it works").
phase('Re-test')
const RETEST_SCHEMA = { type: 'object', properties: { nodeTestGreen: { type: 'boolean' }, suite1Pass: { type: 'string' }, fixed: { type: 'array', items: { type: 'string' } }, stillFailing: { type: 'array', items: { type: 'string' } }, familyGaps: { type: 'array', items: { type: 'string' } }, regressions: { type: 'array', items: { type: 'string' } }, summary: { type: 'string' } }, required: ['nodeTestGreen', 'suite1Pass', 'fixed', 'stillFailing', 'regressions', 'summary'] }
const retest = await agent(
  `Independent final re-test of BOTH acceptance suites. Do it yourself: (1) cd ${DEV} && node --test "tests/**/*.test.js" -> nodeTestGreen + failing names into regressions. (2) Write a scratch .mjs importing ${SHIP}/engine/analyze.js; parse every policy block under each "## Test N" heading in ${S1} and ${S2}, run analyze(), evaluate vs the Expected-result prose. suite1Pass = "N/24". fixed = the suite-2 tests among 44/34/48 that now pass (describe). stillFailing = any of 44/34/48 not fixed (describe why). familyGaps = suite-2 tests correctly fail-closed on a deferred family (resource/boundary/session/RCP) - expected, not failures. regressions = any suite-1 test or negative-corpus case that broke. (3) Return the scoreboard + one-paragraph summary. Read-only; do NOT edit source.`,
  { label: 'final-retest-both-suites', phase: 'Re-test', agentType: 'general-purpose', schema: RETEST_SCHEMA }
)

return {
  built: results,
  acceptedCount: results.filter((r) => r.accepted).length,
  total: results.length,
  retest,
  note: 'Phase 9 correctness fixes for 3 in-scope Suite-II gaps. After: re-verify, deploy (push main), Cloudflare purge. Deferred family tranche (resource/boundary/session/RCP + user-selectable family) remains the next larger effort Suite II specs out.',
}
