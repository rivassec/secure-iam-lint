// IAM-707: acceptance-suite fixturization (all 24 tests + 22A/B/C subcases) +
// the 12 cross-test invariants harness + full re-test.  Runs under `node --test`.
//
// This is the SINGLE gating harness that ties docs/acceptance-suite.md to
// committed fixtures under fixtures/acceptance/ and drives every case from real
// analyze() output (never from the fixture's own declared numbers alone). It:
//
//   1. COMPLETENESS GATE - asserts every one of the 24 acceptance tests (with 22
//      expanded into subcases 22A/22B/22C) has exactly one committed fixture, and
//      that no fixture claims a test id outside that set. A missing or duplicate
//      fixture FAILS here - there are no silent skips.
//   2. PER-FIXTURE semantics - drives each fixture through analyze() and asserts
//      its expect / coverageExpect / errorExpect / severityExpect / graphExpect.
//   3. DESIGN-BLOCKED cases - historically the role-trust family (tests 10, 15,
//      16, 17, 18) was fail-closed BY DESIGN and each fixture carried a
//      `designBlocked` marker. IAM-801 landed the family-aware trust evaluator, so
//      role-trust is now SUPPORTED and those tests are driven by their real
//      expect/severityExpect like any other fixture. DESIGN_BLOCKED_IDS is now
//      empty; the mechanism is retained so a FUTURE unsupported family can be
//      encoded as design-blocked without a silent skip.
//   4. CROSS-TEST INVARIANTS - the 12 invariants from docs/acceptance-suite.md,
//      encoded as reusable helpers and applied across every applicable fixture.
//
// The 6 originally-passing tests (6, 11, 20, 22A, 22B, 23) are fixturized here as
// regression guards; the negative corpus (fixtures/negative) is unaffected.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';
import { actionGrants, hasPolicyVariable } from '../../../content/tools/iam-blast-radius/engine/escalation.js';
import { FAMILIES } from '../../../content/tools/iam-blast-radius/engine/family.js';

const here = dirname(fileURLToPath(import.meta.url));
const acceptanceDir = join(here, '..', 'fixtures', 'acceptance');
const engineDir = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius', 'engine');

// The complete set of acceptance-suite ids this harness must cover. Test 22 is
// three subcases (malformed JSON / missing Effect+Action / unsupported version);
// every other test is a single case. 26 ids total.
const REQUIRED_IDS = Object.freeze([
  '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14',
  '15', '16', '17', '18', '19', '20', '21', '22A', '22B', '22C', '23', '24',
]);

// Tests that are fail-closed BY DESIGN (no evaluator yet) - their fixtures must
// carry a designBlocked marker and the harness asserts the blocked behavior, not
// an eventual finding, so a later story flips them intentionally (never a skip).
// IAM-801 shipped the role-trust evaluator, so tests 10/15/16/17/18 moved out of
// this set and are now driven by their real expectations. The set is empty but
// retained for a future unsupported family.
const DESIGN_BLOCKED_IDS = new Set([]);

const KNOWN_FAMILIES = new Set(Object.values(FAMILIES));

function loadFixtures() {
  return readdirSync(acceptanceDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `acceptance/${f}`, data: JSON.parse(readFileSync(join(acceptanceDir, f), 'utf8')) }));
}

function normId(v) {
  return String(v).toUpperCase();
}

function fixtureText(data) {
  return typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
}

function lowerSet(arr) {
  return new Set((Array.isArray(arr) ? arr : []).map((s) => String(s).toLowerCase()));
}

function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}

// Positive capability edge types (as opposed to informational denies/allows).
const CAPABILITY_EDGE_TYPES = new Set([
  'can-assume', 'can-pass', 'can-modify', 'can-read', 'can-write',
  'can-destroy', 'can-decrypt', 'can-execute-as', 'trusts', 'delegation',
]);

// Capability class of an action - mirrors engine/graph.js classifyCapability and
// the edge-typing harness, kept local so this harness independently pins the
// intended classification (cross-test invariant 7).
const READ_VERB = /^(get|list|describe|view|lookup|search|head|read|batchget)/i;
const DESTRUCTIVE_VERB = /^(delete|terminate|remove|destroy|purge|deregister)/i;
function capabilityClass(action) {
  const lower = String(action).toLowerCase();
  if (lower === 'iam:passrole') return 'delegation';
  if (lower === 'kms:decrypt') return 'decrypt';
  const idx = lower.indexOf(':');
  const verb = idx === -1 ? '' : lower.slice(idx + 1);
  if (DESTRUCTIVE_VERB.test(verb)) return 'destroy';
  if (READ_VERB.test(verb)) return 'read';
  return 'write';
}

// Does statement `stmt` grant action token `action`? (mirrors the provenance /
// compound harness helpers).
function statementGrants(stmt, action) {
  if (!stmt) return false;
  const a = String(action);
  for (const p of stmt.actions) {
    if (hasPolicyVariable(p)) continue;
    if (actionGrants(p, a) || actionGrants(a, p)) return true;
  }
  if (stmt.notActions.length > 0) {
    const excluded = stmt.notActions.some((p) => !hasPolicyVariable(p) && actionGrants(p, a));
    if (!excluded) return true;
  }
  return false;
}

function edgeAttributedActions(edge) {
  const s = new Set();
  for (const ev of (edge.evidence || [])) for (const a of (ev.actions || [])) s.add(String(a).toLowerCase());
  return s;
}

// ---------------------------------------------------------------------------
// The 12 cross-test invariants (docs/acceptance-suite.md), encoded as reusable
// assertion helpers. Each is a no-op where it does not apply (e.g. invariants
// about findings/edges are vacuous for a blocked or invalid analysis), so they
// can be applied uniformly across every acceptance fixture.
// ---------------------------------------------------------------------------

// (1) Policy family is explicit. Every successful analysis names a known family
// and records the detected family; no result silently omits it.
function invFamilyExplicit(result, ctx) {
  if (!result.ok) return;
  assert.ok(KNOWN_FAMILIES.has(result.family),
    `${ctx} [inv1 family-explicit]: result.family "${result.family}" is not a known family`);
  assert.ok(result.coverage && typeof result.coverage.detected === 'string' && result.coverage.detected.length > 0,
    `${ctx} [inv1 family-explicit]: coverage.detected must be present`);
}

// (2) Evidence is immutable. Every action attributed to a statement (in the
// finding header/contributingStatements, in escalation evidence[], and in every
// graph-edge evidence record) is actually granted by that exact statement, and
// every referenced statement index exists in the normalized model.
function invEvidenceImmutable(result, ctx) {
  if (!result.ok || !result.model) return;
  const byIndex = new Map();
  for (const s of result.model.statements) byIndex.set(s.index, s);

  for (const f of result.findings) {
    const cs = Array.isArray(f.contributingStatements) ? f.contributingStatements : null;
    if (cs) {
      for (const entry of cs) {
        const stmt = byIndex.get(entry.statementIndex);
        assert.ok(stmt, `${ctx} [inv2 evidence]: ${f.id} contributingStatements references missing statement ${entry.statementIndex}`);
        for (const a of (entry.actions || [])) {
          assert.ok(statementGrants(stmt, a),
            `${ctx} [inv2 evidence]: ${f.id} attributes "${a}" to statement ${entry.statementIndex} which does not grant it`);
        }
      }
    } else if (typeof f.statementIndex === 'number') {
      const stmt = byIndex.get(f.statementIndex);
      assert.ok(stmt, `${ctx} [inv2 evidence]: ${f.id} references missing statement ${f.statementIndex}`);
    }
    for (const ev of (Array.isArray(f.evidence) ? f.evidence : [])) {
      const stmt = byIndex.get(ev.statementIndex);
      assert.ok(stmt, `${ctx} [inv2 evidence]: ${f.id} evidence references missing statement ${ev.statementIndex}`);
      for (const a of (ev.actions || [])) {
        assert.ok(statementGrants(stmt, a),
          `${ctx} [inv2 evidence]: ${f.id} evidence attributes "${a}" to statement ${ev.statementIndex} which does not grant it`);
      }
    }
  }
  for (const e of result.graph.edges) {
    for (const ev of (e.evidence || [])) {
      if (typeof ev.statementIndex !== 'number') continue;
      const stmt = byIndex.get(ev.statementIndex);
      assert.ok(stmt, `${ctx} [inv2 evidence]: edge ${e.type} references missing statement ${ev.statementIndex}`);
      for (const a of (ev.actions || [])) {
        assert.ok(statementGrants(stmt, a),
          `${ctx} [inv2 evidence]: edge ${e.type} attributes "${a}" to statement ${ev.statementIndex} which does not grant it`);
      }
    }
  }
}

// (3) AND and OR are explicit. Every escalation finding exposes an anyOf list of
// techniques, each an allOf of action groups - never a flat list that would
// imply unrelated alternatives are jointly required.
function invAndOrExplicit(result, ctx) {
  if (!result.ok) return;
  for (const f of result.findings) {
    if (!f.escalation) continue;
    const pr = f.escalation.prerequisites;
    assert.ok(pr && Array.isArray(pr.anyOf) && pr.anyOf.length > 0,
      `${ctx} [inv3 and/or]: ${f.id} escalation.prerequisites.anyOf must be a non-empty array`);
    for (const tech of pr.anyOf) {
      assert.ok(typeof tech.technique === 'string' && tech.technique.length > 0,
        `${ctx} [inv3 and/or]: ${f.id} technique id`);
      assert.equal(typeof tech.requiresPassRole, 'boolean',
        `${ctx} [inv3 and/or]: ${f.id} technique.requiresPassRole boolean`);
      assert.ok(Array.isArray(tech.allOf) && tech.allOf.length > 0,
        `${ctx} [inv3 and/or]: ${f.id} technique.allOf non-empty`);
      for (const g of tech.allOf) {
        assert.ok(Array.isArray(g.anyOf) && g.anyOf.length > 0,
          `${ctx} [inv3 and/or]: ${f.id} allOf group.anyOf non-empty`);
      }
    }
  }
}

// (4) Unknown is visible. Every finding carries a non-empty limitation statement
// (the capability-not-effective caveat) so a high/critical finding never reads as
// an effective-permissions claim.
function invUnknownVisible(result, ctx) {
  if (!result.ok) return;
  for (const f of result.findings) {
    assert.ok(typeof f.limit === 'string' && f.limit.trim().length > 0,
      `${ctx} [inv4 unknown-visible]: ${f.id} must carry a non-empty limitation statement`);
  }
}

// (5) Denies are not grants. No positive capability edge may cite a Deny-effect
// statement as its evidence; a suppressed grant only ever shows as a `denies`
// edge.
function invDeniesNotGrants(result, ctx) {
  if (!result.ok || !result.model) return;
  const byIndex = new Map();
  for (const s of result.model.statements) byIndex.set(s.index, s);
  for (const e of result.graph.edges) {
    if (!CAPABILITY_EDGE_TYPES.has(e.type)) continue;
    for (const ev of (e.evidence || [])) {
      const stmt = byIndex.get(ev.statementIndex);
      if (stmt) {
        assert.notEqual(stmt.effect, 'Deny',
          `${ctx} [inv5 denies-not-grants]: capability edge ${e.type} cites Deny statement ${ev.statementIndex}`);
      }
    }
  }
}

// (6) Conditions have polarity. The classifier is wired on every finding; a
// finding that carries a Condition exposes a non-empty classification (so a
// negated / selector / expansion operator is not silently treated as a plain
// restriction). This asserts the machinery is present and applied; per-operator
// polarity correctness is pinned in conditions.test.js.
function invConditionPolarity(result, ctx) {
  if (!result.ok) return;
  for (const f of result.findings) {
    const cc = f.conditionClassification;
    assert.ok(cc && typeof cc === 'object',
      `${ctx} [inv6 condition-polarity]: ${f.id} must expose conditionClassification`);
    const hasCondition = f.conditions && typeof f.conditions === 'object' && Object.keys(f.conditions).length > 0;
    if (hasCondition) {
      assert.equal(cc.present, true,
        `${ctx} [inv6 condition-polarity]: ${f.id} carries a Condition but classification is not marked present`);
      assert.ok(Array.isArray(cc.entries) && cc.entries.length > 0,
        `${ctx} [inv6 condition-polarity]: ${f.id} classification has no entries`);
    }
  }
}

// (7) No semantic edge reuse. No single (non-denies) edge aggregates actions of
// more than one capability class.
function invNoSemanticEdgeReuse(result, ctx) {
  if (!result.ok) return;
  for (const e of result.graph.edges) {
    if (e.type === 'denies') continue;
    const classes = new Set([...edgeAttributedActions(e)].map(capabilityClass));
    assert.ok(classes.size <= 1,
      `${ctx} [inv7 no-edge-reuse]: edge ${e.type} ${e.from}->${e.to} aggregates unlike capabilities [${[...classes].join(', ')}]`);
  }
}

// (8) Deduplication is explainable. A finding that subsumes others keeps each
// subsumed finding fully accessible (id + prose preserved); a risk-factor
// checklist entry is a structured present/absent item.
function invDedupExplainable(result, ctx) {
  if (!result.ok) return;
  for (const f of result.findings) {
    for (const s of (Array.isArray(f.subsumed) ? f.subsumed : [])) {
      assert.ok(typeof s.id === 'string' && s.id.length > 0, `${ctx} [inv8 dedup]: subsumed finding keeps an id`);
      assert.equal(typeof s.why, 'string', `${ctx} [inv8 dedup]: subsumed ${s.id} keeps why`);
      assert.equal(typeof s.limit, 'string', `${ctx} [inv8 dedup]: subsumed ${s.id} keeps limit`);
      assert.equal(typeof s.remediation, 'string', `${ctx} [inv8 dedup]: subsumed ${s.id} keeps remediation`);
    }
    for (const rf of (Array.isArray(f.riskFactors) ? f.riskFactors : [])) {
      assert.equal(typeof rf.present, 'boolean', `${ctx} [inv8 dedup]: risk factor present flag`);
      assert.ok((rf.label && String(rf.label).length > 0) || (rf.key && String(rf.key).length > 0),
        `${ctx} [inv8 dedup]: risk factor must be labeled`);
    }
  }
}

// (9) Exports agree. The Browser/JSON/Markdown outputs carry the SAME finding set
// and severities (browser parity is an e2e concern; here JSON + Markdown are
// checked against the analyze() result, and the counts agree).
function invExportsAgree(result, ctx) {
  if (!result.ok) return;
  const findings = result.findings;
  assert.equal(result.counts.findings, findings.length,
    `${ctx} [inv9 exports-agree]: counts.findings (${result.counts.findings}) != findings.length (${findings.length})`);

  const json = JSON.parse(toJSON(result));
  assert.equal(json.findings.length, findings.length,
    `${ctx} [inv9 exports-agree]: JSON export findings length mismatch`);
  for (let i = 0; i < findings.length; i++) {
    assert.equal(json.findings[i].id, findings[i].id, `${ctx} [inv9 exports-agree]: JSON finding ${i} id`);
    assert.equal(json.findings[i].severity, findings[i].severity, `${ctx} [inv9 exports-agree]: JSON finding ${i} severity`);
  }

  const md = toMarkdown(result);
  const headerCount = (md.match(/^### \d+\. \[/gm) || []).length;
  assert.equal(headerCount, findings.length,
    `${ctx} [inv9 exports-agree]: Markdown finding headers (${headerCount}) != findings (${findings.length})`);
  for (const f of findings) {
    assert.ok(md.includes(`- Rule: ${f.id}`), `${ctx} [inv9 exports-agree]: Markdown missing rule ${f.id}`);
    assert.ok(md.includes(`[${String(f.severity).toUpperCase()}]`),
      `${ctx} [inv9 exports-agree]: Markdown missing severity ${f.severity}`);
  }
}

// (10) Invalid input fails closed. A validation failure returns ok:false with no
// findings/graph/model; a coverage-blocked shape returns ok:true but zero
// findings and no positive capability edges - partial results are never presented
// as a complete analysis.
function invInvalidFailsClosed(result, ctx, data) {
  const expectValid = !!(data.expect && data.expect.valid);
  if (!expectValid) {
    assert.equal(result.ok, false, `${ctx} [inv10 fail-closed]: invalid input must yield ok:false`);
    assert.equal(result.findings.length, 0, `${ctx} [inv10 fail-closed]: invalid input must produce no findings`);
    assert.equal(result.graph.edges.length, 0, `${ctx} [inv10 fail-closed]: invalid input must produce no graph edges`);
    assert.equal(result.model, null, `${ctx} [inv10 fail-closed]: invalid input must produce no model`);
    return;
  }
  if (result.ok && result.coverage && result.coverage.blocked) {
    assert.equal(result.findings.length, 0, `${ctx} [inv10 fail-closed]: a blocked analysis must produce no findings`);
    assert.equal(result.counts.findings, 0, `${ctx} [inv10 fail-closed]: a blocked analysis counts zero findings`);
    for (const e of result.graph.edges) {
      assert.ok(!CAPABILITY_EDGE_TYPES.has(e.type),
        `${ctx} [inv10 fail-closed]: a blocked analysis must emit no positive capability edge (got ${e.type})`);
    }
  }
}

// (12) Determinism holds. Re-analyzing the same policy produces byte-equivalent
// semantic JSON (report.js emits no timestamps, so the whole export compares).
function invDeterminism(result, ctx, data) {
  const text = fixtureText(data);
  const a = analyze(text);
  const b = analyze(text);
  assert.equal(toJSON(a), toJSON(b), `${ctx} [inv12 determinism]: re-analysis is not byte-identical`);
}

function applyInvariants(result, ctx, data) {
  invFamilyExplicit(result, ctx);
  invEvidenceImmutable(result, ctx);
  invAndOrExplicit(result, ctx);
  invUnknownVisible(result, ctx);
  invDeniesNotGrants(result, ctx);
  invConditionPolarity(result, ctx);
  invNoSemanticEdgeReuse(result, ctx);
  invDedupExplainable(result, ctx);
  invExportsAgree(result, ctx);
  invInvalidFailsClosed(result, ctx, data);
  invDeterminism(result, ctx, data);
}

// ---------------------------------------------------------------------------
// (11) Original input stays local. A one-time static gate over the shipped engine
// sources: no network API can appear in the code that analyzes hostile policy
// text (connect-src 'none' is the deploy control; this asserts the code-level
// guarantee the architecture invariant requires).
// ---------------------------------------------------------------------------

const NETWORK_TOKENS = [
  /\bfetch\s*\(/, /\bXMLHttpRequest\b/, /\bWebSocket\b/, /\bEventSource\b/,
  /\bnavigator\s*\.\s*sendBeacon\b/, /\bimport\s*\(\s*['"`]https?:/,
];

test('inv11 local-only: shipped engine sources contain no network API', () => {
  const files = readdirSync(engineDir).filter((f) => f.endsWith('.js'));
  assert.ok(files.length > 0, 'expected engine source files');
  for (const f of files) {
    const src = readFileSync(join(engineDir, f), 'utf8');
    for (const re of NETWORK_TOKENS) {
      assert.ok(!re.test(src), `engine/${f}: forbidden network API matching ${re}`);
    }
  }
});

// ---------------------------------------------------------------------------
// Completeness gate: every required acceptance-suite id has exactly one fixture,
// and no fixture claims an id outside the required set. Zero silent skips.
// ---------------------------------------------------------------------------

test('completeness: all 24 acceptance tests (+22A/B/C) have exactly one fixture', () => {
  const fixtures = loadFixtures();
  const byId = new Map();
  for (const { file, data } of fixtures) {
    assert.ok(data.acceptanceTest !== undefined, `${file}: missing acceptanceTest tag`);
    const id = normId(data.acceptanceTest);
    assert.ok(!byId.has(id), `duplicate fixture for acceptance test ${id}: ${file} and ${byId.get(id)}`);
    byId.set(id, file);
  }
  for (const id of REQUIRED_IDS) {
    assert.ok(byId.has(id), `missing acceptance fixture for test ${id}`);
  }
  for (const id of byId.keys()) {
    assert.ok(REQUIRED_IDS.includes(id), `fixture claims unexpected acceptance test id ${id} (${byId.get(id)})`);
  }
  assert.equal(byId.size, REQUIRED_IDS.length,
    `expected ${REQUIRED_IDS.length} acceptance fixtures, found ${byId.size}`);
});

// ---------------------------------------------------------------------------
// Per-fixture: drive analyze() and assert declared expectations + all applicable
// cross-test invariants. Every fixture gets its own named test - none skipped.
// ---------------------------------------------------------------------------

for (const { file, data } of loadFixtures()) {
  const id = normId(data.acceptanceTest);
  test(`${file}: acceptance test ${id} - semantics + cross-test invariants (IAM-707)`, () => {
    const result = analyze(fixtureText(data));
    const expect = data.expect || {};

    // Basic expect: valid / findingIds / notFindingIds.
    assert.equal(result.ok, !!expect.valid, `${file}: expect.valid ${expect.valid} vs ok ${result.ok}`);
    if (result.ok) {
      const ids = new Set(result.findings.map((f) => f.id));
      for (const want of (expect.findingIds || [])) {
        assert.ok(ids.has(want), `${file}: MUST find ${want}; got [${[...ids].join(', ')}]`);
      }
      for (const notWant of (expect.notFindingIds || [])) {
        assert.ok(!ids.has(notWant), `${file}: MUST NOT find ${notWant}; got [${[...ids].join(', ')}]`);
      }
    }

    // errorExpect (22A/22B): required validation error codes are present.
    if (data.errorExpect) {
      assert.equal(result.ok, false, `${file}: errorExpect implies ok:false`);
      const codes = new Set((result.errors || []).map((e) => e.code));
      for (const want of (data.errorExpect.errorCodes || [])) {
        assert.ok(codes.has(want), `${file}: expected error code ${want}; got [${[...codes].join(', ')}]`);
      }
    }

    // coverageExpect (blocked shapes: SCP, version, family, ambiguous, role-trust).
    if (data.coverageExpect) {
      const cov = data.coverageExpect;
      assert.ok(result.coverage, `${file}: coverageExpect requires a coverage object`);
      assert.equal(result.coverage.blocked, !!cov.blocked, `${file}: coverage.blocked`);
      if (cov.detectedFamily) {
        assert.equal(result.coverage.detected, cov.detectedFamily, `${file}: detected family`);
      }
      const blocking = (result.coverage.blockingCodes || []);
      const gotCodes = new Set(blocking.map((b) => b.code));
      for (const want of (cov.blockingCodes || [])) {
        assert.ok(gotCodes.has(want), `${file}: expected blocking code ${want}; got [${[...gotCodes].join(', ')}]`);
      }
      if (cov.blockingPathIncludes) {
        const paths = blocking.map((b) => String(b.path || ''));
        assert.ok(paths.some((p) => p.includes(cov.blockingPathIncludes)),
          `${file}: expected a blocking code path including "${cov.blockingPathIncludes}"; got [${paths.join(', ')}]`);
      }
      if (cov.noFindings) {
        assert.equal(result.findings.length, 0, `${file}: blocked analysis must produce no findings`);
      }
      if (cov.noCapabilityEdges) {
        for (const e of result.graph.edges) {
          assert.ok(!CAPABILITY_EDGE_TYPES.has(e.type),
            `${file}: blocked analysis must emit no capability edge (got ${e.type})`);
        }
      }
      if (cov.preservedVersion !== undefined) {
        assert.ok(result.model, `${file}: a blocked-but-parsed policy still exposes its model`);
        assert.equal(result.model.version, cov.preservedVersion,
          `${file}: Version must be preserved verbatim, never rewritten`);
      }
    }

    // severityExpect: severity + split-confidence bounds on a named finding.
    if (data.severityExpect) {
      const se = data.severityExpect;
      const f = result.findings.find((x) => x.id === se.findingId);
      assert.ok(f, `${file}: severityExpect finding ${se.findingId} not found`);
      if (Array.isArray(se.severityOneOf)) {
        assert.ok(se.severityOneOf.includes(f.severity),
          `${file}: ${se.findingId} severity "${f.severity}" not in [${se.severityOneOf.join(', ')}]`);
      }
      if (se.policyEvidence) {
        assert.equal(f.policyEvidence, se.policyEvidence, `${file}: ${se.findingId} policyEvidence`);
      }
      if (Array.isArray(se.pathExploitabilityOneOf)) {
        assert.ok(se.pathExploitabilityOneOf.includes(f.pathExploitability),
          `${file}: ${se.findingId} pathExploitability "${f.pathExploitability}" not in [${se.pathExploitabilityOneOf.join(', ')}]`);
      }
      for (const r of (se.resourcesInclude || [])) {
        assert.ok(lowerSet(f.resources).has(String(r).toLowerCase()),
          `${file}: ${se.findingId} resources must include ${r}`);
      }
    }

    // graphExpect: required / forbidden edges (by type/from/to).
    if (data.graphExpect) {
      const edges = result.graph.edges;
      const match = (e, w) => (!w.type || e.type === w.type) && (!w.from || e.from === w.from) && (!w.to || e.to === w.to);
      for (const w of (data.graphExpect.include || [])) {
        assert.ok(edges.some((e) => match(e, w)), `${file}: expected graph edge ${JSON.stringify(w)}`);
      }
      for (const w of (data.graphExpect.exclude || [])) {
        assert.ok(!edges.some((e) => match(e, w)), `${file}: graph must NOT contain edge ${JSON.stringify(w)}`);
      }
    }

    // Design-blocked (role-trust family): the fixture must be tagged, and the
    // CURRENT behavior must be a coverage block. This encodes the expected
    // fail-closed state so the queued role-trust feature flips it intentionally.
    if (DESIGN_BLOCKED_IDS.has(id)) {
      assert.ok(data.designBlocked && typeof data.designBlocked.feature === 'string' && data.designBlocked.feature.length > 0,
        `${file}: a design-blocked test must name its follow-up feature in designBlocked.feature`);
      assert.ok(result.ok && result.coverage && result.coverage.blocked,
        `${file}: design-blocked test ${id} must currently fail closed (blocked coverage)`);
    }

    // All applicable cross-test invariants.
    applyInvariants(result, `${file} (test ${id})`, data);
  });
}
