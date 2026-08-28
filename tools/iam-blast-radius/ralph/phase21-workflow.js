export const meta = {
  name: 'secure-iam-lint-phase21-roundtrip',
  description: 'Round-5 remediation after the Phase-20 3-team re-audit (all reproduced): the verdict CORE was confirmed clean, but three edge findings remain - a genuine Action fail-open (symlinked policy files silently excluded), a design decision Oliver resolved to HYBRID (surface CROSS-ACCOUNT scoped dangerous capabilities at low/info, keep same-account quiet), and a CLI-only special-file cap bypass. Tiered efficient loop: semantic stories get impl->gate->fail-open-hunter->correctness->arbiter; mechanical get impl->gate->one check. Gate runs the suite ONCE per iteration; critics consume it. Precise specs upfront.',
  phases: [{ title: 'S1-symlink-failclosed' }, { title: 'S2-crossaccount-scoped-surface' }, { title: 'S3-readfilecap-special' }, { title: 'Ledger' }],
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

const PRINCIPLE = `FAIL CLOSED: the tool must NEVER report clean/exit-0/no-findings/not-incomplete on a policy carrying real risk, and must NEVER silently drop a candidate policy file from the aggregate. clean := analyze() ok:true && findings.length===0 && !coverage.summary.incomplete. Do NOT over-correct into false POSITIVES / NOISE: the negative "must-not-fire" corpus + full suite MUST stay green, and per Oliver's HYBRID decision, SAME-account scoped reads/assume-role stay QUIET.`

const BASELINE = `You are a security engineer on ROUND 5 (Phase 21) of secure-iam-lint (${REPO}) before v1.0.0. A 3-team re-audit confirmed the verdict CORE is clean; these are the last edge findings. Shipped engine ${ENGINE}/*.js is imported by BOTH the browser (analyze()) AND the CLI/Action (${CLI}/scan.mjs, ${REPO}/action/index.mjs). Read ${DEV}/docs/threat-model.md + architecture.md FIRST. ${PRINCIPLE}\n\nHARD RULES: no network/innerHTML/eval/unsafe-DOM in shipped JS; no 'node:' import may leak into the browser engine graph; deterministic; NO build step; NEVER write scratch/debug files under content/tools/ (use a git-ignored scratchpad under ${DEV}). A regression fixture/test for EVERY fix.`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, testsPassed: { type: 'number' }, browserPure: { type: 'boolean' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, shippedTreeClean: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'browserPure', 'noNetwork', 'noUnsafeDom', 'cspClean', 'shippedTreeClean', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

const STORIES = [
  { id: 'S1-symlink-failclosed', tier: 'semantic', maxIter: 5, focus: `Close the Action symlink-exclusion FAIL-OPEN (${REPO}/action/index.mjs). walkFiles (~1066-1093) does \`if (ent.isSymbolicLink()) continue;\` (~1081) with ZERO bookkeeping - a symlinked policy file that MATCHES the scan glob is silently dropped from enumeration; if the other real files analyze clean the aggregate reports analysisStatus:"complete" / exit 0. REPRODUCED (Gentoo): a fork PR adds benign policies/ok.json + policies/admin.json as a SYMLINK to an in-repo permissive policy; the consumer glob paths:policies/**/*.json matches admin.json by name; it is silently excluded; the run passes green - exactly the "one file quietly falls out of the aggregate" the threat model forbids. FIX (keep the traversal-safety - do NOT follow symlinks): walkFiles must RECORD excluded symlink entries (return them, e.g. {files, excludedSymlinks}); resolveFiles / runAction must then check whether any excluded symlink's path MATCHES one of the scan patterns (a would-be policy file) and if so FAIL CLOSED - mark the aggregate coverage incomplete + emit a SYMLINK_EXCLUDED analyzer-state / a stable code, and return a NON-ZERO exit (exit 3), NEVER a silent complete/exit 0. A symlink NOT matching any scan pattern (unrelated file) must NOT trip it (no false-fail on a monorepo full of unrelated symlinks). Add a REAL-filesystem regression test (create an ACTUAL symlink via fs.symlinkSync in a temp dir, not a mocked listFiles) asserting a glob-matching symlinked policy file -> incomplete + exit 3, and an unrelated symlink -> unaffected. Keep existing Action tests green.` },

  { id: 'S2-crossaccount-scoped-surface', tier: 'semantic', maxIter: 6, focus: `Oliver's HYBRID decision: the tool emits affirmative CLEAN/exit-0 on scoped-but-real dangerous capabilities, with severity driven by a resource-NAME wordlist an adversary evades. Surface the CROSS-ACCOUNT cases at LOW/INFO; keep SAME-account scoped capabilities QUIET (unchanged). Two reproduced sub-cases:
(A) sts:AssumeRole to a specific role in ANOTHER account reads CLEAN. ${ENGINE}/escalation.js detectAssumeRoleExpansion (~1894) only emits for broad/wildcard scopes (\`if (!resourceListIsBroadForAssume(stmt)) continue;\`). FIX: also emit a LOW/INFO finding (e.g. CROSS-ACCOUNT-ASSUME-ROLE) + a can-assume graph edge when a scoped sts:AssumeRole* targets a role ARN whose account != the subject/analyzed account (only when the subject account is KNOWN - via context/trust; if unknown, stay conservative = current quiet behavior). The finding must state exploitability depends on the target role's trust policy + permissions. Keep SAME-account scoped assume-role QUIET (the existing "routine use" design + escalation.test.js:451).
(B) a whole-container/datastore read on a CROSS-account resource reads CLEAN, and severity is name-gated. ${ENGINE}/rules.js ruleDataExfil (~832-866) requires BROAD scope; ruleDataReadScoped (~910-967) covers only 3 S3 actions (DATA_READ_ACTIONS ~259-263) gated on a 13-token SENSITIVE_NAME_TOKENS wordlist (~271-287). FIX: (1) the wordlist must RAISE severity, NEVER GATE reporting; (2) extend DATA_READ_ACTIONS beyond the 3 S3 actions to the equivalent whole-container read/list/scan/query primitives for dynamodb, rds/rds-data, kinesis (from the catalog); (3) a whole-container read (bucket/*, table/<id>, table/*, ...) whose resource account != subject account -> a LOW/INFO cross-account data-read finding regardless of resource name. Keep SAME-account scoped container reads QUIET, and a single concrete object read (bucket/key) QUIET.
Also: ensure 'complete'/'CLEAN' is NOT an affirmative safety claim on these - document in ${DEV}/docs/threat-model.md exactly which scoped capabilities are intentionally not surfaced (same-account scoped reads/assume-role), so 'complete' cannot be read as 'analyzed and safe'.
MUST-CLOSE: sts:AssumeRole -> arn:aws:iam::999999999999:role/X with subjectAccount 123456789012 -> a finding (not clean); a cross-account whole-bucket read (s3:GetObject on another account's bucket/*) + cross-account dynamodb:Scan -> a finding; a neutrally-named CROSS-account whole-bucket read -> surfaced (raise-not-gate). MUST-STAY-QUIET (no new noise): same-account scoped sts:AssumeRole; same-account whole-bucket read (s3:GetObject bucket/* same account); a single concrete object read. Keep all existing broad-scope findings (DATA-EXFIL on *, ASSUME-ROLE-EXPANSION on role/*) + the negative/must-not-fire corpus green.` },

  { id: 'S3-readfilecap-special', tier: 'mechanical', maxIter: 3, focus: `CLI-only DoS-control bypass (NOT Marketplace-reachable - the Action's walkFiles skips symlinks + non-regular files and git cannot commit device/FIFO nodes; only the standalone CLI positional path reaches it). ${CLI}/iam-br.mjs readFileCapped (~701-707) derives its 1 MiB cap solely from statSync(path).size and then unconditionally readFileSync's, with NO isFile()/lstat guard. statSync FOLLOWS symlinks and reports size 0 for char/block devices, FIFOs, /proc entries - so a zero-size special file (/dev/zero) or a symlink to one passes the pre-guard and is read UNBOUNDED (a never-EOF source hangs the process; --budget-ms only wraps analyze(), not the read). FIX: in readFileCapped, lstatSync the path (do NOT follow the link for the type check) and REJECT if it is not a regular file (isFile() false -> a tagged NON_REGULAR_FILE / could-not-read fail-closed error, matching the existing read-error exit path); AND bound the read itself (open + read up to MAX_BYTES via a fd/stream like readStdin at ~637-693, or fs.readSync into a capped buffer) so even a regular file cannot materialize beyond MAX_BYTES mid-read. Preserve existing fail-closed exit codes and the oversized-regular-file rejection. Add a test: a FIFO or /dev/zero path (and a symlink to one) is rejected WITHOUT hanging (use a short timeout), a normal file still reads, an oversized regular file still rejected. Mechanical - no verdict/severity change.` },
]

const gatePrompt = (id) => `Deterministic gate for ${id} in ${REPO}. Run ONCE: (a) cd ${DEV} && node --test "tests/**/*.test.js" -> testsPassed = pass count, regressed names into failures; (b) browserPure: grep ${ENGINE} ${SHELL}/app.js ${SHELL}/worker.js for "node:" imports or fs/path/process/Buffer/require -> NONE; (c) noNetwork: grep ${ENGINE} ${CLI} ${REPO}/action for fetch/XMLHttpRequest/WebSocket/sendBeacon/EventSource -> none; (d) noUnsafeDom: grep ${SHELL} for innerHTML/outerHTML/insertAdjacentHTML/eval/new Function -> none; (e) cspClean: cd ${REPO} && python3 scripts/csp_audit.py content/tools/iam-blast-radius; (f) shippedTreeClean: node --test tests/shipped-tree-hygiene.test.js AND no tracked scratch-*.mjs under content/tools. pass=true iff all hold. Do NOT edit.`

const hunter = { key: 'fail-open-hunter', prompt: (id, spec) => `Adversarial FAIL-OPEN hunter for ${id} (scratch .mjs only in a git-ignored scratchpad under ${DEV}). The gate ALREADY ran the full node --test suite - do NOT re-run it; focus on BREAKING the fix. For S1: try another way to smuggle a policy file past the aggregate (symlink dir, nested symlink, symlink whose name matches the glob) OR make the fix false-fail on an unrelated symlink. For S2: find a CROSS-account scoped dangerous capability that still reads clean (another read verb/service, another assume-role shape) OR a SAME-account/benign case the fix now WRONGLY flags (noise regression). For S3: a special-file/symlink that still bypasses the cap or hangs. Assert browser==CLI parity. Any residual fail-open, silent-drop, or over-correction/noise is a BLOCKER with exact input + measured output. STORY FOCUS: ${spec}. Read-only; do NOT edit.` }
const correctness = { key: 'correctness', prompt: (id, spec) => `Correctness critic for ${id}. The gate ALREADY ran node --test (consume it; only run the story's SPECIFIC repros). Blocking if: the fix does not close the named case (must-close still clean/silent-drop); it introduces a FALSE POSITIVE / NOISE (a must-stay-quiet same-account case now flagged, or the negative corpus regresses); a required fixture/test is missing or does not assert the real invariant (S1: a REAL-filesystem symlink test; S2: both must-close cross-account AND must-stay-quiet same-account; S3: a non-hanging special-file rejection); or the gate reported a regression. STORY FOCUS: ${spec}. Read-only; do NOT edit.` }
const mechCheck = { key: 'mech-correctness', prompt: (id, spec) => `Focused check for MECHANICAL story ${id}. The gate already ran node --test. Verify ONLY: (1) the exact change was made and is correct; (2) it did NOT change any verdict/severity/parser/fail-closed/exit-code semantics; (3) the targeted test exists (incl. the non-hanging special-file case); (4) no banned pattern / new dep / scratch file. Blocking on any of these or a gate regression. STORY FOCUS: ${spec}. Read-only; do NOT edit.` }

const results = []
let chainBroken = false
for (const story of STORIES) {
  phase(story.id)
  const semantic = story.tier === 'semantic'
  let accepted = false, feedback = '', lastFindings = [], lastReason = ''
  for (let iter = 1; iter <= story.maxIter; iter++) {
    await agent(
      `${BASELINE}\n\nSTORY ${story.id} [${story.tier}]. Precisely specified - implement exactly it, add a regression fixture/test for every change, keep the full node --test suite green.\nFOCUS: ${story.focus}${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance or adding noise:\n${feedback}` : ''}`,
      { label: `impl:${story.id}:i${iter}`, phase: story.id, agentType: 'general-purpose', effort: semantic ? 'high' : 'medium' }
    )
    const gate = await agent(gatePrompt(story.id), { label: `gate:${story.id}:i${iter}`, phase: story.id, agentType: 'general-purpose', effort: 'low', schema: GATE_SCHEMA })
    if (!gate || !gate.pass) { feedback = `Gate failed: ${JSON.stringify((gate && gate.failures) || ['gate null'])}`; lastReason = 'gate-fail'; log(`${story.id} i${iter}: gate FAIL`); continue }
    const panel = semantic ? [hunter, correctness] : [mechCheck]
    const cr = await parallel(panel.map((c) => () => agent(c.prompt(story.id, story.focus), { label: `critic:${c.key}:${story.id}`, phase: story.id, agentType: 'general-purpose', effort: semantic ? 'high' : 'medium', schema: FINDING_SCHEMA })))
    const verdict = arbitrate(panel, cr)
    lastFindings = cr.filter(Boolean).flatMap((r) => (r.findings || []).map((f) => ({ ...f, critic: r.critic })))
    const blocking = lastFindings.filter((f) => f.blocking)
    if (verdict.accepted) { accepted = true; lastReason = `all-pass (${gate.testsPassed} tests)`; log(`${story.id} ACCEPTED i${iter} [${story.tier}]`); break }
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
  results.push({ story: story.id, tier: story.tier, accepted, reason: lastReason, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length })
  if (!accepted) { chainBroken = true; log(`CHAIN STOP at ${story.id}: not accepted (${lastReason}).`); break }
}

phase('Ledger')
const summary = results.map((r) => `${r.story}[${r.tier}]: ${r.accepted ? 'accepted' : 'human-review'} (${r.reason})`).join('; ')
await agent(
  `Append a Phase-21 section to ${DEV}/progress.md recording each story outcome + last-round reason. ${summary}. ${chainBroken ? 'Chain halted early; note un-reached stories pending.' : 'All Phase-21 stories accepted.'} Edit/append only that section.`,
  { label: 'ledger:phase21', phase: 'Ledger', agentType: 'general-purpose', effort: 'low' }
)
return { phase: 21, stories: results, chainBroken, allAccepted: results.length === STORIES.length && results.every((r) => r.accepted), note: 'Round-5 edge remediation (symlink fail-closed, cross-account scoped surfacing per Oliver HYBRID, readFileCapped special-file guard). NOT pushed - held for Oliver. After acceptance: reproduce all closed, re-run 3 teams; only tag v1.0.0 once clean.' }
