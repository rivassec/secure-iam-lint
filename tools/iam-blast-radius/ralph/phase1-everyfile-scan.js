export const meta = {
  name: 'secure-iam-lint-phase1-everyfile-scan',
  description: 'Phase 1 (Oliver-approved): a comprehensive EVERY-FILE security scan of all 31 shipped files before any patching, shaped by Openclaw peer critique. Memory-conscious tiering: a CHEAP per-file mechanical pass over responsibility clusters (each reviewer armed with its files + the indexer coverage-matrix row + the fail-open lint hotspots + the taxonomy, emitting OBLIGATIONS not just findings), then DEEP cross-file flow reviewers + a statefulness/repeat-call reviewer + a test-realism/mock-bypass reviewer (because the worst bugs are boundary bugs, not file-local), then a dedup-by-BUG-CLASS synthesis that attacks contradictions in the obligation map, then adversarial verification of every candidate before it is reported. READ-ONLY: no engine/cli/action edits, no patching - output is a consolidated, verified, deduped findings list for Oliver to approve before Phase 2.',
  phases: [{ title: 'PerFile' }, { title: 'CrossFile' }, { title: 'Synthesis' }, { title: 'Verify' }],
}

const REPO = '/Users/oliver/dev/secure-iam-lint'
const ENGINE = `${REPO}/content/tools/iam-blast-radius/engine`
const SHELL = `${REPO}/content/tools/iam-blast-radius`
const DEV = `${REPO}/tools/iam-blast-radius`
const CLI = `${REPO}/cli`
const AUDIT = `${DEV}/audit`

const PRINCIPLE = `FAIL CLOSED: the tool must NEVER report clean/exit-0/no-findings/not-incomplete on a policy carrying real risk, NEVER silently drop a candidate policy file/statement/finding, and NEVER exit 0 having performed zero analysis. clean := analyze() ok:true && findings.length===0 && !coverage.summary.incomplete. Over-correction into FALSE POSITIVES / NOISE is also a defect: same-account scoped reads/assume-role stay QUIET per Oliver's HYBRID decision, and the negative must-not-fire corpus must stay green.`

const TAXONOMY = `FAIL-OPEN TAXONOMY (bug classes; dedup findings by these): zero-analysis-success (exit 0 / clean having analyzed nothing); candidate-drop (a policy file/statement/finding dropped PRE-analysis with no fail-closed signal); coverage-incomplete-lost (an undecidable/truncated input whose incompleteness is computed but not propagated POST-analysis); finding-suppression (a real finding not emitted or dropped by the reporter/SARIF); iam-effective-breadth-miss (breadth judged on syntax - Resource vs NotResource, Action vs NotAction, wildcard-ARN grammar, cross-account, Deny/condition interaction - rather than effective reach; syntax-keyed-severity is a symptom of this); budget-bypass (a hot loop that never charges the work/time budget so DoS caps do not fire); raw-realpath-mismatch (a guard comparing a raw path to a realpath-resolved one); state-mutation/repeat-call (global caches, shared mutable rule data, mutation of the parsed policy, order-dependent output, analyze() called twice giving different results); browser-cli-parity-break (browser analyze() more permissive than the CLI on the same input); test-realism-gap (tests calling internals instead of shipped entrypoints, fixtures bypassing packaging, mocks hiding fs/process behavior, SARIF tested structurally but not as a gate-consumed artifact); output-consumer-suppression (a real risk lost in SARIF severity/threshold mapping, fingerprints, or Action annotation/threshold as CONSUMED).`

const BASELINE = `You are a security reviewer on the Phase-1 EVERY-FILE scan of secure-iam-lint (${REPO}) before v1.0.0. Shipped engine ${ENGINE}/*.js is imported by BOTH the browser (analyze() in ${SHELL}/app.js + worker.js) AND the CLI (${CLI}/iam-br.mjs, scan.mjs, sarif.mjs) AND the GitHub Action (${REPO}/action/index.mjs). Read ${DEV}/docs/threat-model.md + architecture.md FIRST. ${PRINCIPLE}\n\n${TAXONOMY}\n\nTOOLS TO USE (already built + hardened): the coverage matrix ${AUDIT}/indexer/index.json (+ coverage-matrix.md) gives each file's imports/callers/entrypoints/tests/astHotspots; the fail-open lint hotspots are ${AUDIT}/lint/hotspots.json (40 hotspots). Use these to route, but reason from the CODE.\n\nALREADY-CONFIRMED (do NOT re-report as new; only note if a file interacts): (1) raw-realpath-mismatch at ${CLI}/iam-br.mjs:804 + ${REPO}/action/index.mjs:1397 (fails open via node/npx/symlink/bin-shim); (2) syntax-keyed-severity broad-NotResource at ${ENGINE}/rules.js:900; (3) budget-bypass uncharged loop at ${ENGINE}/rules.js:1092; (4) candidate-drop walkFiles truncation at ${REPO}/action/index.mjs:1279/1287; plus LOW ci.yml npm-install and shipped-tree-root hygiene. NEW lint leads worth checking: candidate-drop at action/index.mjs:303 + 1260, cli/sarif.mjs:391/655/677, render-graph.js:463, trust.js:389; and ${ENGINE}/evaluator.js appears to be a graph ORPHAN (imported by no shipped file) - determine if it is dead code or dynamically loaded.\n\nREAD-ONLY: do NOT edit any shipped file; you may write scratch .mjs repros ONLY under a git-ignored scratchpad in ${DEV}. A candidate finding must be CODE-GROUNDED (exact file:line) and carry a concrete repro sketch + the fail-closed property it violates.`

const FINDING_SCHEMA = { type: 'object', properties: {
  reviewer: { type: 'string' },
  obligations: { type: 'array', items: { type: 'object', properties: { file: { type: 'string' }, obligation: { type: 'string' }, holds: { type: 'string', enum: ['yes', 'no', 'unclear'] } }, required: ['file', 'obligation', 'holds'] } },
  candidates: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, klass: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, flow: { type: 'string' }, evidence: { type: 'string' }, repro_sketch: { type: 'string' }, violated_property: { type: 'string' }, confidence: { type: 'string', enum: ['high', 'medium', 'low'] } }, required: ['id', 'klass', 'severity', 'location', 'evidence', 'repro_sketch', 'violated_property', 'confidence'] } },
  covered: { type: 'boolean' }, unreviewed_dependencies: { type: 'array', items: { type: 'string' } },
}, required: ['reviewer', 'candidates', 'covered'] }

// 31 shipped files grouped into responsibility clusters for the cheap per-file pass.
const CLUSTERS = [
  { key: 'core-pipeline', files: 'analyze.js, validate.js, parse.js, envelope.js, model.js, coverage.js (engine)' },
  { key: 'iam-breadth', files: 'rules.js, resource.js, resource-arn.js, masked-grant.js, catalog.js, glob.js (engine)' },
  { key: 'escalation-graph', files: 'escalation.js, trust.js, graph.js, correlate.js, evaluator.js (engine)' },
  { key: 'conditions-policytype', files: 'conditions.js, scp.js, rcp.js, family.js (engine)' },
  { key: 'render-report', files: 'report.js, render-graph.js, format-control.js, version.js (engine)' },
  { key: 'entry-cli-action', files: `app.js + worker.js (${SHELL}), cli/iam-br.mjs, cli/scan.mjs, cli/sarif.mjs, action/index.mjs` },
]

// Deep cross-file reviewers - where the boundary bugs live.
const FLOWS = [
  { key: 'flow-cli-exit', focus: `END-TO-END CLI FLOW: package entrypoint -> invokedDirectly guard -> argv/stdin/glob file selection -> readFileCapped -> validate/parse -> analyze -> scan verdict -> threshold -> process exit code -> SARIF. Hunt any path where a risky policy or a dropped/unreadable/oversized/special candidate yields exit 0 / CLEAN, or where the browser-shared engine and the CLI diverge. Cross ${CLI}/iam-br.mjs + scan.mjs + sarif.mjs + the engine.` },
  { key: 'flow-action', focus: `END-TO-END ACTION FLOW: action/index.mjs entrypoint -> input parsing -> walkFiles enumeration (symlink handling, MAX_FILES truncation, readdir failures at :303/:1260) -> per-file analyze -> aggregate worstExitCode -> incomplete-unit synthesis -> GITHUB_OUTPUT/annotations. Hunt any candidate silently dropped from the aggregate producing a green exit, and any enumeration/cap path lacking a fail-closed signal.` },
  { key: 'flow-iam-breadth', focus: `IAM EFFECTIVE-BREADTH across files: rules.js + resource.js + resource-arn.js + masked-grant.js + escalation.js + conditions.js. Hunt any effective-breadth judged on SYNTAX (Resource vs NotResource, Action vs NotAction, wildcard-ARN grammar, Deny/condition interaction, cross-account) rather than effective reach, letting a broad grant score below the default gate or read CLEAN. The rules.js:900 NotResource case is known - find OTHER shapes (NotAction, Deny-narrowing, condition-scoping, other services/actions).` },
  { key: 'flow-parser-dos', focus: `PARSER / DoS / PROTOTYPE-POLLUTION: validate.js + parse.js + envelope.js + glob.js + rules.js hot loops. Hunt uncharged hot loops (budget-bypass beyond rules.js:1092), unbounded recursion/walk, ReDoS, __proto__/constructor pollution at any depth, and huge-input cliffs. Confirm both the browser 60M work budget AND the CLI --budget-ms abort where required.` },
  { key: 'flow-sarif-consumer', focus: `SARIF + OUTPUT-CONSUMER SEMANTICS: cli/sarif.mjs + report.js + the Action threshold mapping. Hunt a real finding LOST as CONSUMED output: severity->SARIF-level or ->threshold mapping that drops a blocking result, fingerprint collisions merging distinct risks, suppression via bad path/rule/fingerprint (the sarif.mjs:391/655/677 drop leads), or annotations that under-report. Test SARIF as a GATE-CONSUMED artifact, not just structurally.` },
  { key: 'flow-browser-export', focus: `BROWSER / EXPORT / XSS + PARITY: app.js + worker.js + report.js + render-graph.js + format-control.js. Hunt DOM/SVG injection sinks, Markdown/autolink/bidi export unsafety, CSP assumptions, and any case where browser analyze() is MORE PERMISSIVE than the CLI on the same input (parity break). render-graph.js:463 is a candidate-drop lead.` },
  { key: 'statefulness', focus: `STATE-MUTATION / REPEAT-CALL safety across the engine: global/module-level caches, shared mutable rule/catalog data, mutation of the parsed policy object, order-dependent output, and analyze()/scan() called TWICE on the same or different input in one process giving DIFFERENT or leaking results (relevant to the Action which calls per-file in a loop). Construct a repeat-call repro; any nondeterminism or cross-call leakage that could hide a finding is a candidate.` },
  { key: 'test-realism', focus: `TEST-REALISM / MOCK-BYPASS audit of ${DEV}/tests: which fail-closed guarantees are tested only via in-process import (never a spawned subprocess / real fs / packaging) - like the entrypoint guard that survived 5 rounds? Which fixtures bypass packaging? Which mocks hide filesystem/process behavior? Is SARIF tested as a gate-consumed artifact? Report the highest-risk UNTESTED-AT-THE-REAL-BOUNDARY guarantees as candidates (klass test-realism-gap) with the specific missing real-invocation test.` },
]

phase('PerFile')
const perFile = await parallel(CLUSTERS.map((c) => () => agent(
  `${BASELINE}\n\nMECHANICAL PER-FILE PASS for cluster [${c.key}] covering: ${c.files}. For EACH file: read it + its ${AUDIT}/indexer row (imports/callers/entrypoints/tests) + its ${AUDIT}/lint/hotspots.json entries. Emit, per file, the key FAIL-CLOSED OBLIGATIONS it must uphold for its callers (e.g. "every enumerated candidate increments analyzed|skipped|errored exactly once"; "severity reflects effective breadth, not a syntax token"; "an undecidable input sets coverage.incomplete and that propagates") and whether each holds yes/no/unclear. Raise a candidate for every 'no' and every genuinely suspicious 'unclear'. covered=false or empty obligations for a file = you did NOT review it (say so in unreviewed_dependencies). Be fast and mechanical; the deep cross-file pass handles flows. Do NOT re-report the 6 already-confirmed findings as new.`,
  { label: `perfile:${c.key}`, phase: 'PerFile', agentType: 'general-purpose', model: 'haiku', effort: 'low', schema: FINDING_SCHEMA }
)))

phase('CrossFile')
const crossFile = await parallel(FLOWS.map((f) => () => agent(
  `${BASELINE}\n\nDEEP CROSS-FILE REVIEW [${f.key}]. Follow the flow END-TO-END across files and actively try to construct a real fail-open OR a real over-correction/noise; write scratch repros under the git-ignored scratchpad if useful. FOCUS: ${f.focus}\n\nReport candidates with exact file:line, the bug CLASS from the taxonomy, a concrete repro sketch, and the fail-closed property violated. Boundary bugs (emergent across files) are the priority - that is why this pass exists. Do NOT re-report the 6 already-confirmed findings as new (reference them only if your flow reveals an ADDITIONAL distinct shape).`,
  { label: `crossfile:${f.key}`, phase: 'CrossFile', agentType: 'general-purpose', effort: 'high', schema: FINDING_SCHEMA }
)))

phase('Synthesis')
const allCand = [...perFile, ...crossFile].filter(Boolean).flatMap((r) => (r.candidates || []).map((c) => ({ ...c, reviewer: r.reviewer })))
const obligationNos = [...perFile, ...crossFile].filter(Boolean).flatMap((r) => (r.obligations || []).filter((o) => o.holds === 'no' || o.holds === 'unclear'))
const SYNTH_SCHEMA = { type: 'object', properties: { deduped: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, klass: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, evidence: { type: 'string' }, repro_sketch: { type: 'string' }, violated_property: { type: 'string' }, merged_from: { type: 'array', items: { type: 'string' } } }, required: ['id', 'klass', 'severity', 'location', 'evidence', 'repro_sketch', 'violated_property'] } }, contradictions: { type: 'array', items: { type: 'string' } }, coverage_gaps: { type: 'array', items: { type: 'string' } } }, required: ['deduped'] }
const synth = await agent(
  `${BASELINE}\n\nSYNTHESIS. Here are ${allCand.length} raw candidate findings from the per-file + cross-file passes, plus ${obligationNos.length} obligations reviewers marked no/unclear:\nCANDIDATES:\n${JSON.stringify(allCand).slice(0, 60000)}\nOBLIGATIONS(no/unclear):\n${JSON.stringify(obligationNos).slice(0, 15000)}\n\nProduce a DEDUPED candidate list keyed by BUG CLASS (not by file): merge duplicates across reviewers (record merged_from ids), drop the 6 already-confirmed findings, drop non-issues and pure design-opinions (note them separately as contradictions/coverage_gaps). Cross-check the obligation 'no/unclear' map against the candidates - an obligation that fails with no matching candidate is itself a coverage gap to surface. Keep only code-grounded, plausibly-reproducible NEW candidates. Rank by severity.`,
  { label: 'synthesis', phase: 'Synthesis', agentType: 'general-purpose', effort: 'high', schema: SYNTH_SCHEMA }
)

phase('Verify')
const toVerify = (synth && synth.deduped || []).filter((c) => ['critical', 'high', 'medium'].includes(c.severity))
const VERDICT_SCHEMA = { type: 'object', properties: { id: { type: 'string' }, reproduced: { type: 'boolean' }, real_fail_open: { type: 'boolean' }, adjusted_severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info', 'not-a-bug'] }, observed: { type: 'string' }, verdict_reason: { type: 'string' } }, required: ['id', 'reproduced', 'real_fail_open', 'adjusted_severity', 'observed', 'verdict_reason'] }
const verified = await parallel(toVerify.map((c) => () => agent(
  `${BASELINE}\n\nADVERSARIAL VERIFICATION of ONE candidate. Try to REFUTE it: reproduce it against the real code (write a scratch repro under the git-ignored scratchpad; for guard/entrypoint bugs SPAWN a real subprocess, do not just import). Default to real_fail_open=false unless you OBSERVE the fail-closed violation (exact command + observed exit/findings/output). Distinguish a genuine NEW fail-open from an accepted-risk design edge (bare-bucket->incomplete; external-PrincipalArn medium; same-account scoped quiet; S3 same-account whole-bucket -> CROSS-ACCOUNT-DATA-READ-UNDETERMINED:info) which are NOT bugs. CANDIDATE: ${JSON.stringify(c)}`,
  { label: `verify:${c.id}`, phase: 'Verify', agentType: 'general-purpose', effort: 'high', schema: VERDICT_SCHEMA }
).then((v) => ({ ...c, verdict: v }))))

const confirmed = verified.filter(Boolean).filter((c) => c.verdict && c.verdict.real_fail_open && c.verdict.adjusted_severity !== 'not-a-bug')
const lows = (synth && synth.deduped || []).filter((c) => ['low', 'info'].includes(c.severity))
return {
  phase: 1,
  perFileReviewers: CLUSTERS.length, crossFileReviewers: FLOWS.length,
  rawCandidates: allCand.length, dedupedCandidates: (synth && synth.deduped || []).length, verifiedCount: verified.filter(Boolean).length,
  confirmedNew: confirmed.map((c) => ({ id: c.id, klass: c.klass, severity: c.verdict.adjusted_severity, location: c.location, observed: c.verdict.observed })),
  lowsUnverified: lows.map((c) => ({ id: c.id, klass: c.klass, location: c.location })),
  contradictions: synth && synth.contradictions || [], coverageGaps: synth && synth.coverage_gaps || [],
  note: 'Phase-1 every-file scan, READ-ONLY. confirmedNew = adversarially reproduced NEW fail-opens (beyond the 6 already-confirmed). These + the 6 known -> the consolidated set for Oliver to approve before Phase 2 remediation. No patching performed. evaluator.js orphan status reported in coverageGaps if unresolved.',
}
