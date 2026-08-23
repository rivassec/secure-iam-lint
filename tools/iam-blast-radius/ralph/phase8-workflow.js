export const meta = {
  name: 'iam-blast-radius-ralph-phase8',
  description: 'Phase 8 role-trust family: grounding doc (AWS-verified) then 6 serial Ralph stories teaching the engine to analyze role-trust policies (public/cross-account/OIDC/SAML/service), flip the 5 design-blocked acceptance tests, full re-test. Guardrail: trust grants who-may-assume, never target-role permissions.',
  phases: [{ title: 'Grounding' }, { title: 'Implement' }, { title: 'Gate' }, { title: 'Critics' }, { title: 'Arbiter' }, { title: 'Re-test' }],
}

const REPO = '/Users/oliver/dev/devsecops-notes'
const DEV = `${REPO}/tools/iam-blast-radius`
const SHIP = `${REPO}/content/tools/iam-blast-radius`
const CONTRACTS = `${DEV}/docs/architecture.md and ${DEV}/docs/threat-model.md (IMMUTABLE)`
const SUITE = `${DEV}/docs/acceptance-suite.md (24-case acceptance suite; role-trust = tests 10/15/16/17/18)`
const REF = `${DEV}/docs/trust-policy-semantics.md (the AWS-verified trust reference authored by story IAM-800)`

// IAM-800 is a grounding DOC story (research + verify, no node --test gate).
// IAM-801..806 are CODE stories (impl -> code-gate -> 4 critics -> arbiter). Serial: shared engine/family/graph tree, layered.
const STORIES = [
  { id: 'IAM-800', kind: 'doc', maxIter: 3 },
  { id: 'IAM-801', kind: 'code', maxIter: 5 },
  { id: 'IAM-802', kind: 'code', maxIter: 5 },
  { id: 'IAM-803', kind: 'code', maxIter: 5 },
  { id: 'IAM-804', kind: 'code', maxIter: 5 },
  { id: 'IAM-805', kind: 'code', maxIter: 5 },
  { id: 'IAM-806', kind: 'code', maxIter: 5 },
]

const TRUST_GUARDRAILS = `PHASE-8 THESIS + IMMUTABLE TRUST GUARDRAILS (every story, every agent):
- A role-trust policy grants WHO MAY ASSUME the role, NEVER the assumed role's permissions. Every trust finding MUST state the target role's privileges are unknown / out of scope. Overclaiming that an assumer inherits the role's power is a truthfulness harm (threat-model T8).
- FAIL CLOSED on unmodeled trust shapes: NotPrincipal stays rejected (UNSUPPORTED_NOTPRINCIPAL), unknown Principal types, and mixed identity+trust stay AMBIGUOUS. Never analyze a trust policy with identity rules; never emit identity-style broad-Resource findings on a trust policy.
- CONDITION POLARITY is the crux: aws:PrincipalOrgID StringEquals = constraint, StringNotEquals = EXPANSION (critical); sts:ExternalId present = confused-deputy CONSTRAINT (never "missing", never called auth/secrecy); SourceArn/SourceAccount/MFA/SourceIp = constraints; OIDC aud = constraint, sub scope (repo:org/* broad vs repo+ref tight) drives severity. Classify only - never assert a runtime AWS allow/deny.
- TRUST SEVERITY MODEL (documented, coherent): Principal '*' public = critical; unconditioned external cross-account/root = high; external + confused-deputy constraint (ExternalId etc.) = low/medium; OIDC broad sub = high; normal service trust = informational.
- GRAPH: trust origin is EXTERNAL principals -> can-assume -> this role (target privileges unknown), NOT "principal subject of this policy". Reuse typed edges; do NOT reintroduce a generic can-write aggregation (Phase-7 fix).
- SCOPE FENCE: role-trust ONLY. Resource-based policies (S3/KMS key policies) are a separate future family - out of scope this phase.`

const BASELINE = `You are a (replaceable) engineer on the LIVE, LAUNCHED, DEPLOYED IAM Blast Radius tool in ${REPO}. Shipped vanilla ES-module JS/CSS/HTML: ${SHIP}/. Dev tests: ${DEV}/tests/; fixtures: ${DEV}/fixtures/. Read ${CONTRACTS}, the story (id + requirements + acceptance) in ${DEV}/prd.json, ${REF}, and the relevant tests in ${SUITE} FIRST.

This MODIFIES a working, deployed tool whose full suite (cd ${DEV} && node --test "tests/**/*.test.js") is GREEN and MUST stay green. Update tests/fixtures only for behavior a story INTENTIONALLY changes; never weaken an assertion or regress a prior invariant. Protected: all Phase-7 acceptance fixtures (the 15 fixed + 6 originally-passing), the identity + trust negative corpora.

HARD RULES: no network APIs in shipped JS (connect-src 'none'); no innerHTML/outerHTML/insertAdjacentHTML/eval/new Function; DOM via createElement+textContent; reject __proto__/constructor; DETERMINISTIC engine; no inline style/script/on-handlers in HTML; reports "potential blast radius" NOT "effective permissions"; NEVER assert beyond evidence. NO build step (committed JS is what ships). Playwright/e2e is CI's job (update specs, do not claim you ran a browser).

${TRUST_GUARDRAILS}`

const GATE_SCHEMA = { type: 'object', properties: { pass: { type: 'boolean' }, nodeTest: { type: 'string' }, noNetwork: { type: 'boolean' }, noUnsafeDom: { type: 'boolean' }, cspClean: { type: 'boolean' }, fixturesValidJson: { type: 'boolean' }, failures: { type: 'array', items: { type: 'string' } } }, required: ['pass', 'noNetwork', 'noUnsafeDom', 'cspClean', 'fixturesValidJson', 'failures'] }
const FINDING_SCHEMA = { type: 'object', properties: { critic: { type: 'string' }, findings: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] }, location: { type: 'string' }, criterion: { type: 'string' }, evidence: { type: 'string' }, required_outcome: { type: 'string' }, blocking: { type: 'boolean' } }, required: ['id', 'severity', 'location', 'criterion', 'evidence', 'required_outcome', 'blocking'] } } }, required: ['critic', 'findings'] }

function critics(story) {
  return [
    { key: 'qa-trust-semantics', prompt: `QA + IAM-TRUST-semantics critic for ${story.id}. Read the story in ${DEV}/prd.json, ${REF}, and its target tests in ${SUITE}. Review the diff (cd ${REPO} && git diff -- content/tools tools/iam-blast-radius) and run cd ${DEV} && node --test "tests/**/*.test.js". VERIFY BY DRIVING analyze() DIRECTLY (scratch .mjs importing ${SHIP}/engine/analyze.js, feed the exact suite trust policies) - do not trust fixtures alone. Blocking if: any finding claims or implies the assumed role's permissions (must stay out-of-scope/unknown); Principal type or trust action misparsed; condition polarity wrong (StringNotEquals org read as protective; ExternalId reported "missing" or called auth/secrecy; OIDC aud/sub mis-scoped); a trust policy analyzed with identity rules or emitting a broad-Resource finding; NotPrincipal/unknown-Principal/mixed no longer fail closed; severity inconsistent with the documented trust model; exports (JSON/MD/UI) disagree; OR any targeted suite test still wrong. Read-only; do NOT edit.` },
    { key: 'security', prompt: `Security critic for ${story.id} using ${CONTRACTS}. Review diff + grep ${SHIP}. Blocking if: any network API in shipped JS; innerHTML/eval/unsafe DOM; DOM/attrs built unsafely from policy input (incl. Principal ARNs, OIDC sub strings, condition values - treat all as hostile); __proto__/constructor not rejected; inline style/script/on-handler in HTML; XSS/proto-pollution/injection fixtures no longer inert; policy content leaks to storage/URL/network/error payloads; a trust finding presented as granting the assumer the role's powers (truthfulness harm). Read-only; do NOT edit.` },
    { key: 'reliability', prompt: `Reliability critic for ${story.id}. Run cd ${DEV} && node --test "tests/**/*.test.js" (full regression). Confirm: zero uncaught exceptions on malformed/adversarial + all trust fixtures; determinism (re-analyze trust policies twice, semantic JSON byte-equivalent excluding timestamps); IDENTITY-family behavior + Phase-7 acceptance fixtures unchanged; identity + trust negative corpora pass; DoS caps hold. Flag any nondeterminism, uncaught throw, or regressed test as blocking. Read-only except running tests; do NOT edit source.` },
    { key: 'adversarial-trust', prompt: `Adversarial trust critic for ${story.id}. Your job is to BREAK the analyzer: construct trust policies (write scratch .mjs feeding ${SHIP}/engine/analyze.js) that expose OVER-claim or UNDER-claim. Try: a scary-looking trust NEUTRALIZED by ExternalId/SourceArn/org-constraint (must NOT be high/critical); a benign-looking trust that is actually dangerous (StringNotEquals org, Principal '*', OIDC repo:org/* sub, missing aud) (must fire); service trust that must stay informational; a trust doc that could be mis-scored as identity. Blocking if you find a policy the analyzer over- or under-claims on, or where evidence/condition provenance is wrong, or where target-role permissions leak into a claim. Report the exact policy + wrong output. Read-only; do NOT edit source.` },
  ]
}

const results = []
for (const story of STORIES) {
  log(`=== ${story.id} (${story.kind}) starting ===`)
  let accepted = false, feedback = '', lastFindings = []

  if (story.kind === 'doc') {
    for (let iter = 1; iter <= story.maxIter; iter++) {
      await agent(
        `You are grounding the IAM Blast Radius role-trust feature. Implement story ${story.id} (full spec + acceptance in ${DEV}/prd.json): author ${DEV}/docs/trust-policy-semantics.md. Use WebSearch/WebFetch to verify every claim against CURRENT AWS documentation and cite sources. ASCII only; no secrets. Change NO shipped code.\n\n${TRUST_GUARDRAILS}${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings:\n${feedback}` : ''}`,
        { label: `research:${story.id}:i${iter}`, phase: 'Grounding', agentType: 'general-purpose' }
      )
      const verify = await agent(
        `Verifier critic for grounding doc ${story.id}. Read ${DEV}/docs/trust-policy-semantics.md and the acceptance in ${DEV}/prd.json. Use WebSearch/WebFetch to CHECK its claims against current AWS docs. Blocking if: any Principal type, trust action, or v1 condition key is missing or mis-described; ANY condition polarity is wrong (esp. StringNotEquals aws:PrincipalOrgID = expansion, sts:ExternalId = confused-deputy mitigation not secrecy/auth); the confused-deputy explanation, trust severity model, or the "trust != target-role permissions" invariant is absent or wrong; a cited source does not support the claim; or shipped code was changed. Read-only; do NOT edit.`,
        { label: `verify:${story.id}:i${iter}`, phase: 'Critics', agentType: 'general-purpose', schema: FINDING_SCHEMA }
      )
      lastFindings = (verify && verify.findings || []).map((f) => ({ ...f, critic: verify.critic }))
      const blocking = lastFindings.filter((f) => f.blocking)
      if (blocking.length === 0) { accepted = true; log(`${story.id} ACCEPTED i${iter}`); break }
      feedback = blocking.map((f) => `[${f.severity}] ${f.location}: ${f.evidence} -> ${f.required_outcome}`).join('\n')
      log(`${story.id} i${iter}: ${blocking.length} blocking, revise doc`)
    }
  } else {
    for (let iter = 1; iter <= story.maxIter; iter++) {
      await agent(
        `${BASELINE}\n\nImplement story ${story.id} (full spec + acceptance in ${DEV}/prd.json). Modify shipped module(s) under ${SHIP}/engine (family.js + a trust evaluation path; graph.js/render-graph.js/report.js where graph/exports are affected), ADD fixtures the story requires, wire tests, keep the full node --test suite green.${feedback ? `\n\nIteration ${iter}: address ONLY these blocking findings, without weakening acceptance/contracts:\n${feedback}` : ''}`,
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
  }

  await agent(
    `Update ${DEV}/progress.md: add/set a row for ${story.id} to ${accepted ? 'accepted' : 'human-review'} with iteration count + any remaining blockers. ${accepted ? '' : `Blockers:\n${feedback}`} Edit only that row/notes.`,
    { label: `ledger:${story.id}`, phase: 'Arbiter', agentType: 'general-purpose', effort: 'low' }
  )
  results.push({ story: story.id, accepted, remainingBlockers: accepted ? 0 : lastFindings.filter((f) => f.blocking).length })
}

// Final independent full re-test across the whole 24-case suite (role-trust now expected to PASS).
phase('Re-test')
const RETEST_SCHEMA = { type: 'object', properties: { nodeTestGreen: { type: 'boolean' }, perTest: { type: 'array', items: { type: 'object', properties: { test: { type: 'string' }, verdict: { type: 'string', enum: ['pass', 'fail', 'blocked-by-design'] }, note: { type: 'string' } }, required: ['test', 'verdict'] } }, regressions: { type: 'array', items: { type: 'string' } }, summary: { type: 'string' } }, required: ['nodeTestGreen', 'perTest', 'regressions', 'summary'] }
const retest = await agent(
  `Independent final re-test of the IAM Blast Radius engine against the FULL 24-case suite (+22A/B/C) in ${SUITE}. Do this yourself: (1) cd ${DEV} && node --test "tests/**/*.test.js" -> nodeTestGreen + failing names into regressions. (2) Write a scratch .mjs importing ${SHIP}/engine/analyze.js, parse each policy under every "## Test N" heading, run analyze(), evaluate vs the Expected-result prose. Role-trust tests 10/15/16/17/18 should now be PASS (not blocked). For each test emit pass / fail (describe) / blocked-by-design (only if genuinely still deferred, e.g. NotPrincipal or full-SCP-semantics). (3) Confirm NO regression to the Phase-7 fixes (1,2,3,4,5,7,8,9,12,13,14,19,21,22C,24), the originally-passing (6,11,20,22A,22B,23), or the identity/trust negative corpora - list any regression. Return the per-test scoreboard + a one-paragraph summary. Read-only; do NOT edit source.`,
  { label: 'final-retest', phase: 'Re-test', agentType: 'general-purpose', schema: RETEST_SCHEMA }
)

return {
  built: results,
  acceptedCount: results.filter((r) => r.accepted).length,
  total: results.length,
  retest,
  note: 'Phase 8 role-trust family. After this: re-run e2e in CI, deploy (push main), PURGE Cloudflare. NotPrincipal + full SCP ceiling semantics remain deferred. Resource-based policies (S3/KMS) are the next family after this if desired.',
}
