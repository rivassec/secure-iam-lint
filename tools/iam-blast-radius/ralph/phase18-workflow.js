export const meta = {
  name: 'secure-iam-lint-phase18-appsec-round2',
  description: 'Round-2 remediation after a THREE-team re-audit (Opus + Openclaw + Gentoo Claude Code) still returned do-not-ship. The Phase-17 fixes closed INSTANCES not CLASSES; Phase 18 closes the classes systematically: all model-shape fail-opens, all unbudgeted DoS loops, the Action output/path hardening, symmetric SARIF sanitization, and CI-gate coverage of cli/+action/. FAIL-CLOSED arbiter with a dedicated fail-OPEN hunter that must prove each CLASS is closed, not just the named instance.',
  phases: [{ title: 'S1-shape-failclosed' }, { title: 'S2-passrole-allstmts' }, { title: 'S3-dos-budget-all' }, { title: 'S4-action-hardening' }, { title: 'S5-sarif-symmetric' }, { title: 'S6-cigate-doc' }, { title: 'Ledger' }],
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

const PRINCIPLE = `FAIL CLOSED: the tool must NEVER report clean/exit-0/no-findings/not-incomplete on a policy carrying real risk (T8), and must NEVER exceed its work/wall-clock budget on attacker input. clean := analyze() ok:true && findings.length===0 && !coverage.summary.incomplete (this is exactly the browser-cli-parity invariant). Do NOT over-correct into false POSITIVES: the negative "must-not-fire" corpus (${DEV}/fixtures/negative*, negative*.test.js) + the full suite MUST stay green. THE LESSON FROM PHASE 17: fixes that patch the named instance but leave the CLASS open are REJECTED - the fail-open hunter will find another spelling. Fix the class.`

const BASELINE = `You are a security engineer on ROUND 2 of remediating secure-iam-lint (${REPO}) before v1.0.0. Three independent audit teams still returned do-not-ship. Shipped engine ${ENGINE}/*.js is imported by BOTH the browser (analyze() via ${SHELL}/app.js,worker.js) AND the CLI/Action (${CLI}/scan.mjs, ${REPO}/action/index.mjs). Read ${DEV}/docs/threat-model.md + architecture.md FIRST. ${PRINCIPLE}\n\nHARD RULES: no network/innerHTML/eval/unsafe-DOM in shipped JS; no 'node:' import may leak into the browser engine graph (${ENGINE}/*.js, app.js, worker.js); reject __proto__/constructor; deterministic; NO build step; NEVER write scratch/debug files under content/tools/ or a tracked scratch-*.mjs. Tests under ${DEV}/tests/. A regression fixture for EVERY fix.`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, browserPure: { type: 'boolean' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, shippedTreeClean: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'browserPure', 'noNetwork', 'noUnsafeDom', 'cspClean', 'shippedTreeClean', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

const STORIES = [
  { id: 'S1-shape-failclosed', maxIter: 8, focus: `Close the MODEL-SHAPE fail-open CLASS systematically in the shared engine (model.js/validate.js/masked-grant.js/rules.js) so analyze() (browser) and scan() (CLI) both fail closed (emit a finding OR coverage.summary.incomplete=true) on ANY under-specified or malformed statement shape - do NOT patch only the two named cases. CONFIRMED fail-opens that must close (analyze() currently clean): (1) a statement with Action but NO Resource AND NO NotResource key at all -> resourceIsBroad reads empty arrays as narrow -> DATA-EXFIL/WILDCARD-RESOURCE suppressed (add a hasResource/hasNotResource flag symmetric to notActionPresent; resource-scope-UNSPECIFIED must be treated as maximally broad OR incomplete). (2) a non-scalar / malformed Condition VALUE - an object {}, a nested array/object, or null where a scalar or array-of-scalars belongs (e.g. Condition:{StringEquals:{aws:PrincipalOrgID:{}}}) -> currently clean; validate condition values in shared modeling: allow only a primitive scalar or an array of primitive scalars, else fail closed with an analyzer-state. Then HUNT the class yourself for more shapes (missing Effect, empty Action AND empty NotAction, malformed Principal, etc.) and fail them closed too. Add must-warn fixtures for each and a parity assertion.` },
  { id: 'S2-passrole-allstmts', maxIter: 6, focus: `Close the statement-ORDER-dependent PassRole viability fail-open (HIGH, T8). detectPassRolePaths (${ENGINE}/escalation.js ~1085-1104) selects ONE PassRole statement per service by lowest index, then the T91 account-viability check (~1223-1247) evaluates only that one; if it is cross-account, the compound path is demoted critical->medium (PASSROLE_CROSS_ACCOUNT_INCOMPATIBLE) and slips under the gate to exit 0 CLEAN, HIDING a viable same-account PassRole in a different statement. Reordering byte-identical statements flips exit 0<->1. FIX: make PassRole viability an ALL-STATEMENTS property (mirror the existing all-statements DENY reasoning at escalation.js:1042-1051) - evaluate account-viability across EVERY candidate PassRole statement for the service and keep the MOST severe (viable same-account) outcome, emitting the finding for the viable statement; only demote if NO statement yields a viable same-account pass. Add a regression fixture that reorders a cross-account decoy vs a viable same-account grant and asserts exit 1/critical REGARDLESS of statement order.` },
  { id: 'S3-dos-budget-all', maxIter: 7, focus: `Close the DoS CLASS: make EVERY combinatorial/glob/loop path in the engine + adapters participate in a budget, and remove the Action ReDoS. CONFIRMED uncharged/uncapped paths: (1) detectRoleTakeover / principalConditionsSatisfiable triple loop (${ENGINE}/escalation.js ~2056-2065,2078-2253) calls chargeWork ZERO times -> 400 statements = ~43s; (2) denyActionApplies inner loop unbudgeted (Team1); (3) the GitHub Action paths-glob is compiled to an ANCHORED backtracking RegExp (${REPO}/action/index.mjs ~132) -> ReDoS on a crafted paths input BEFORE any scan budget applies. FIX: call chargeWork() inside EVERY such inner loop (audit the whole file for loops over policy-derived collections that lack it) AND/OR cap the combinatorial product before the exhaustive search; replace the Action glob RegExp with a LINEAR matcher (or hard-cap glob length + wildcard count before new RegExp); ensure the CLI + Action wall-clock budget is enforced with fine granularity (not 5x overrun) and the browser main-thread fallback has a watchdog. Add complexity-budget tests: role-takeover-heavy policy, deny-heavy policy, and a pathological Action paths input each MUST complete under a fixed ms budget or fail closed.` },
  { id: 'S4-action-hardening', maxIter: 5, focus: `Harden the GitHub Action output + path handling (${REPO}/action/index.mjs). CONFIRMED: (1) GITHUB_OUTPUT file-command injection - the heredoc delimiter (~346-358) is a predictable \`ghadelim_\${k}_EOF\`, so an attacker-influenced value (e.g. sarif-output) can break out and forge/suppress GITHUB_OUTPUT keys -> randomize the delimiter (crypto.randomUUID) AND reject newline/control chars in any interpolated value. (2) Arbitrary file WRITE outside the workspace via unsanitized sarif-output (~599-603) - '..' and absolute paths both succeed, contradicting ACTION.md -> resolve sarif-output against GITHUB_WORKSPACE and REJECT (fail closed, exit 2) any path that escapes it or is absolute. Add tests asserting a break-out sarif-output value cannot forge an output key and a '../x' / '/etc/x' sarif-output is rejected.` },
  { id: 'S5-sarif-symmetric', maxIter: 4, focus: `Apply the SARIF anti-injection defense SYMMETRICALLY (${CLI}/sarif.mjs + the note construction in ${ENGINE}/rules.js). CONFIRMED: the security-finding branch sanitizes attacker text (sanitizeSid/renderActionClause backtick-wrapping) but the DISJOINT analyzer-state branch (sarif.mjs ~461-464) emits s.message VERBATIM, and the ACTION_RESOURCE_TYPE_MISMATCH note (rules.js ~1400-1405) interpolates raw Action names + Resource ARNs -> a crafted Action 's3:GetObject[CLICK](https://evil)' renders as a live Markdown link in GitHub's Security tab. FIX: route EVERY SARIF message.text (analyzer-state, notes, evidenceOf) through the same neutralization; ideally sanitize at the point each note/message is constructed so all consumers inherit it. Also fold the escalation service/technique into partialFingerprints so distinct PassRole routes do not collide/suppress. Add a test asserting no raw [..](..)/![..](..) survives into ANY message.text and that distinct escalation routes get distinct fingerprints.` },
  { id: 'S6-cigate-doc', maxIter: 4, focus: `Extend CI enforcement to the shipped CLI + Action, fix the doc/reality mismatch, and land the deferred nightly fuzzer. CONFIRMED: (1) the gate:no-network + gate:no-unsafe-dom greps (${DEV}/package.json) + csp_audit + shipped-tree-hygiene scope ONLY content/tools/iam-blast-radius/ - the shipped cli/ + action/ (the code that runs in consumers' CI) are UNGATED -> extend the no-network + no-unsafe-DOM (eval/Function/child_process for the Node side) grep roots to cli/ + action/ (accounting for the legitimate node: fs/process the CLI needs, but forbidding network/eval), and wire them into ci.yml. (2) ${DEV}/docs/threat-model.md claims 'npm audit + OSV in CI' / an SBOM that do NOT exist in security.yml -> correct the doc to match reality (or add the control). (3) Build the deferred nightly differential-fuzz workflow ${REPO}/.github/workflows/fuzz-parity.yml (schedule + workflow_dispatch, least-priv contents:read, pinned actions) running a seeded deterministic generator (${DEV}/tests/fuzz/parity-fuzz.mjs) that asserts the analyze()==scan() safety-parity invariant across many mutated policies. No new fail-open; least-privilege; pinned.` },
]

const panel = [
  { key: 'qa-correctness', prompt: `QA + correctness critic for STORY. Read ${DEV}/docs/threat-model.md + the story focus, run cd ${DEV} && node --test "tests/**/*.test.js", and drive analyze() AND scan() (and the Action wrapper where relevant) DIRECTLY on the story's confirmed repro inputs. Blocking if: the fix does not actually close the named fail-open/DoS/hardening item (the repro still succeeds); it introduces a FALSE POSITIVE (a genuinely-safe policy now flagged, or the negative corpus regresses); a required fixture/parity/budget test is missing or does not assert the real invariant; or ANY existing test regresses. Read-only; do NOT edit.` },
  { key: 'fail-open-hunter', prompt: `Adversarial FAIL-OPEN + DoS hunter for STORY (scratch .mjs in a git-ignored scratchpad under ${DEV}, never content/). Your job: after the fix, find a NEW input in the SAME CLASS the story targets that still makes analyze() clean on a risky policy (ok:true && 0 findings && !coverage.summary.incomplete) OR still exceeds a wall-clock/work budget (>2s or uncapped). Also assert the browser==CLI parity invariant (analyze() never more permissive than scan()). Enumerate variant spellings/shapes aggressively - the Phase-17 lesson is that instance patches leave the class open. Any residual fail-open, parity violation, or unbounded time is a BLOCKER; report exact input + measured output. Read-only; do NOT edit.` },
  { key: 'security', prompt: `Security critic for STORY. Review diff + grep the shipped tree. Blocking if: network/innerHTML/eval/unsafe-DOM introduced in shipped JS; a 'node:' import leaked into the browser engine graph; __proto__/constructor not rejected; csp_audit fails; a scratch/debug/test file under content/tools/ or a tracked scratch-*.mjs; the SARIF sanitization still lets a raw markdown link through ANY message path; the Action output/path hardening is bypassable (heredoc break-out still forges a key, or a '..'/absolute sarif-output still writes outside the workspace); a new/edited workflow that is not least-privilege or uses an unpinned action. Read-only; do NOT edit.` },
  { key: 'reliability', prompt: `Reliability critic for STORY. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression, 1836+ plus new tests). Confirm zero uncaught exceptions, determinism, all prior suites + negative corpora + browser-cli-parity + must-warn + complexity-budget gates intact, and any DoS fix actually bounds wall-clock. Flag any regression/nondeterminism/throw/hang as blocking. Read-only except running tests.` },
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
      `Deterministic gate for ${story.id} in ${REPO}. Run: (a) cd ${DEV} && node --test "tests/**/*.test.js" (ALL pass; regressed names into failures); (b) browserPure: grep ${ENGINE} ${SHELL}/app.js ${SHELL}/worker.js for "node:" imports or fs/path/process/Buffer/require -> NONE; (c) noNetwork: grep ${ENGINE} ${CLI} ${REPO}/action for fetch/XMLHttpRequest/WebSocket/sendBeacon/EventSource -> none; (d) noUnsafeDom: grep ${SHELL} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> none; (e) cspClean: cd ${REPO} && python3 scripts/csp_audit.py content/tools/iam-blast-radius; (f) shippedTreeClean: node --test tests/shipped-tree-hygiene.test.js AND no tracked scratch-*.mjs under content/tools. pass=true iff all hold. Do NOT edit.`,
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
      feedback = `FAIL-CLOSED: critic(s) [${verdict.failedCritics.join(', ')}] returned no verdict. Re-run.${blocking.length ? `\nAlso:\n${blocking.map((f) => `[${f.critic}/${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')}` : ''}`
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
  `Append a Phase-18 app-sec-round2 section to ${DEV}/progress.md recording each story outcome + last-round reason. ${summary}. ${chainBroken ? 'Chain halted early; note un-reached stories pending.' : 'All Phase-18 stories accepted.'} Edit/append only that section.`,
  { label: 'ledger:phase18', phase: 'Ledger', agentType: 'general-purpose', effort: 'low' }
)
return { phase: 18, stories: results, chainBroken, allAccepted: results.length === STORIES.length && results.every((r) => r.accepted), note: 'Round-2 app-sec remediation (class-complete). NOT pushed - held for Oliver. After acceptance: re-run all THREE audit teams; only tag v1.0.0 once all three + my repro are clean.' }
