// Unit tests for IAM-007: analysis orchestration used by the UI shell.
// Runs on node's built-in runner: `node --test`.
//
// The UI's worker + synchronous fallback both delegate to analyze(); these
// tests exercise that pure pipeline with NO DOM/Worker present, covering the
// IAM-007 acceptance that is testable off-browser:
//   - every fixture (positive/negative/boundary/malformed/adversarial) is
//     handled with zero uncaught exceptions
//   - positive findingIds are produced; notFindingIds are absent
//   - deterministic (same input -> deep-equal output, twice)
//   - hostile SIDs/ARNs ride through the pipeline as inert DATA (verbatim
//     strings), so the createElement+textContent renderer receives inert text
//   - the presentation helpers (sortFindings / findingToRow) expose a stable,
//     string-only row contract for the accessible table
//
// Browser-level acceptance (csp_audit, grep gate, real DOM inertness, a11y)
// is covered by the Playwright spec + CI workflow, not this suite.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  analyze,
  sortFindings,
  findingToRow,
  FINDING_COLUMNS,
  FINDING_DETAIL_FIELDS,
  SEVERITY_ORDER,
  CATALOG_VERSION,
  summarize,
  SUMMARY_CATEGORIES,
} from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate, LIMITS } from '../../../content/tools/iam-blast-radius/engine/validate.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

function loadFixtures(category) {
  const dir = join(fixturesDir, category);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({
      file: `${category}/${f}`,
      data: JSON.parse(readFileSync(join(dir, f), 'utf8')),
    }));
}

const ALL_CATEGORIES = readdirSync(fixturesDir, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const RESULT_KEYS = ['ok', 'errors', 'findings', 'model', 'graph', 'catalogVersion', 'counts'];

test('analyze() returns a frozen, well-shaped result for every fixture and never throws', () => {
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const text = fixtureText(data);
      let result;
      assert.doesNotThrow(() => { result = analyze(text); }, `${file} must not throw`);
      for (const k of RESULT_KEYS) {
        assert.ok(k in result, `${file}: result missing key ${k}`);
      }
      assert.equal(typeof result.ok, 'boolean', `${file}: ok is boolean`);
      assert.ok(Array.isArray(result.findings), `${file}: findings is array`);
      assert.ok(Array.isArray(result.errors), `${file}: errors is array`);
      assert.ok(Object.isFrozen(result), `${file}: result frozen`);
      assert.ok(Object.isFrozen(result.findings), `${file}: findings frozen`);
      assert.equal(result.catalogVersion, CATALOG_VERSION, `${file}: catalog version`);
      // Counts agree with the payload.
      assert.equal(result.counts.findings, result.findings.length, `${file}: findings count`);
      assert.equal(result.counts.edges, result.graph.edges.length, `${file}: edges count`);
      assert.equal(result.counts.nodes, result.graph.nodes.length, `${file}: nodes count`);
      // Well-formed inputs must not report a failure and vice-versa.
      const expectValid = data.expect && data.expect.valid;
      if (expectValid === true) assert.equal(result.ok, true, `${file}: expected valid`);
      if (expectValid === false) assert.equal(result.ok, false, `${file}: expected invalid`);
    }
  }
});

test('analyze() produces expected findingIds and omits notFindingIds', () => {
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const expect = data.expect || {};
      if (!Array.isArray(expect.findingIds) && !Array.isArray(expect.notFindingIds)) continue;
      const result = analyze(fixtureText(data));
      const ids = new Set(result.findings.map((f) => f.id));
      for (const want of expect.findingIds || []) {
        assert.ok(ids.has(want), `${file}: expected finding ${want}; got [${[...ids].join(', ')}]`);
      }
      for (const notWant of expect.notFindingIds || []) {
        assert.ok(!ids.has(notWant), `${file}: finding ${notWant} must NOT be present`);
      }
    }
  }
});

test('analyze() is deterministic (same input -> deep-equal output, twice)', () => {
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const text = fixtureText(data);
      const a = analyze(text);
      const b = analyze(text);
      assert.deepEqual(a, b, `${file}: analyze() must be deterministic`);
    }
  }
});

test('every finding carries the canonical fields the table + export rely on', () => {
  // IAM-104: split confidence -> policyEvidence + pathExploitability.
  const required = ['id', 'severity', 'title', 'statementSid', 'policyEvidence', 'pathExploitability', 'why', 'limit', 'remediation', 'ruleVersion'];
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const result = analyze(fixtureText(data));
      for (const f of result.findings) {
        for (const key of required) {
          assert.ok(key in f, `${file}: finding ${f.id} missing ${key}`);
        }
        assert.ok(Object.prototype.hasOwnProperty.call(SEVERITY_ORDER, f.severity),
          `${file}: finding ${f.id} has known severity`);
      }
    }
  }
});

test('hostile SIDs/ARNs pass through as inert verbatim data', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'xss-in-sid-and-arn.json'), 'utf8'));
  const result = analyze(fixtureText(fx));
  assert.equal(result.ok, true, 'adversarial fixture is valid input');

  // The hostile Sid/ARNs must survive verbatim somewhere in the model (as data,
  // never parsed/transformed). We assert the exact payload strings are present
  // as string values, which is what the renderer will place via textContent.
  const stmt = result.model.statements[0];
  assert.equal(stmt.sid, '<img src=x onerror=alert(1)>', 'Sid preserved verbatim as data');
  assert.ok(
    stmt.resources.includes('arn:aws:s3:::<script>alert(document.domain)</script>/*'),
    'script-bearing ARN preserved verbatim as data',
  );

  // No finding turned the payload into anything other than a plain string.
  for (const f of result.findings) {
    for (const cell of findingToRow(f)) {
      assert.equal(typeof cell.text, 'string', 'every rendered cell is a plain string');
    }
  }
});

// ---------------------------------------------------------------------------
// IAM-106: risk-summary header. summarize() is a pure, deterministic projection
// of the display-ordered findings into the four highlighted capability-family
// counts plus the single highest-risk escalation path. app.js renders it above
// the authoritative findings table with createElement+textContent only.
// ---------------------------------------------------------------------------

test('summarize() matches expected counts + highest-risk path for annotated fixtures', () => {
  let checked = 0;
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const expectedSummary = data.expect && data.expect.summary;
      if (!expectedSummary) continue;
      checked += 1;
      const result = analyze(fixtureText(data));
      assert.equal(result.ok, true, `${file}: expected a valid analysis`);
      const summary = summarize(result.findings);

      // Counts of the four families, taken over the DISPLAYED (post-correlation)
      // findings, so subsumed subordinate findings never inflate a count.
      const byKey = Object.fromEntries(summary.categories.map((c) => [c.key, c.count]));
      for (const [key, want] of Object.entries(expectedSummary.counts)) {
        assert.equal(byKey[key], want, `${file}: summary count ${key}`);
      }

      // Highest-risk path (null when no escalation path is present).
      if (expectedSummary.highestRisk === null) {
        assert.equal(summary.highestRisk, null, `${file}: expected no highest-risk path`);
      } else {
        assert.ok(summary.highestRisk, `${file}: expected a highest-risk path`);
        assert.equal(summary.highestRisk.id, expectedSummary.highestRisk.id, `${file}: highest-risk id`);
        assert.equal(summary.highestRisk.severity, expectedSummary.highestRisk.severity, `${file}: highest-risk severity`);
        assert.equal(summary.highestRisk.path, expectedSummary.highestRisk.path, `${file}: highest-risk path line`);
      }
    }
  }
  assert.ok(checked >= 4, `expected several annotated summary fixtures, checked ${checked}`);
});

test('summarize() total equals the finding count for every fixture', () => {
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const result = analyze(fixtureText(data));
      if (!result.ok) continue;
      const summary = summarize(result.findings);
      assert.equal(summary.total, result.findings.length, `${file}: summary total`);
      // The category contract is stable and always fully populated.
      assert.equal(summary.categories.length, SUMMARY_CATEGORIES.length, `${file}: category count`);
      for (const c of summary.categories) {
        assert.equal(typeof c.count, 'number', `${file}: ${c.key} count is a number`);
        assert.ok(c.count >= 0, `${file}: ${c.key} count non-negative`);
      }
    }
  }
});

test('summarize() is deterministic and safe on empty / missing input', () => {
  const empty = summarize([]);
  assert.deepEqual(empty, summarize([]), 'empty summary is deterministic');
  assert.equal(empty.total, 0, 'empty total is 0');
  assert.equal(empty.highestRisk, null, 'empty has no highest-risk path');
  for (const c of empty.categories) assert.equal(c.count, 0, `${c.key} is 0 for empty input`);
  // Never throws on non-array input.
  assert.doesNotThrow(() => summarize(undefined), 'undefined tolerated');
  assert.doesNotThrow(() => summarize(null), 'null tolerated');
});

test('summarize() counts never exceed the finding count (curated, not double-counted)', () => {
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const result = analyze(fixtureText(data));
      if (!result.ok) continue;
      const summary = summarize(result.findings);
      const sum = summary.categories.reduce((acc, c) => acc + c.count, 0);
      assert.ok(sum <= summary.total, `${file}: summed category counts <= total findings`);
    }
  }
});

// ---------------------------------------------------------------------------
// IAM-108: input caps (DoS). An over-cap policy must be REJECTED before any
// analysis runs, so analyze() returns ok:false with no findings/graph, and the
// pipeline resolves well under the 5s budget instead of hanging the tab.
// ---------------------------------------------------------------------------

test('oversized-statements fixture: validate() errors, analyze() ok:false, no hang', () => {
  const fx = JSON.parse(
    readFileSync(join(fixturesDir, 'adversarial', 'oversized-statements.json'), 'utf8'),
  );
  const text = fixtureText(fx);

  const v = validate(text);
  assert.equal(v.ok, false, 'validate() must reject an over-cap policy');
  assert.ok(
    v.errors.some((e) => e.code === 'TOO_MANY_STATEMENTS'),
    'validate() must report TOO_MANY_STATEMENTS',
  );

  const result = analyze(text);
  assert.equal(result.ok, false, 'analyze() must be ok:false for an over-cap policy');
  assert.equal(result.findings.length, 0, 'no findings on rejection');
  assert.equal(result.graph.edges.length, 0, 'no graph edges on rejection');
  assert.equal(result.graph.nodes.length, 0, 'no graph nodes on rejection');
  assert.equal(result.model, null, 'no model on rejection');
});

test('a 20000-statement policy resolves (rejected) well under 5s, never hangs', () => {
  // Far past LIMITS.MAX_STATEMENTS. Building this in-memory keeps the fixture
  // tree small; the point is that validate() rejects on a cheap pre-parse /
  // count guard rather than trying to analyze 20000 statements.
  const stmts = new Array(20000).fill('{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}');
  const text = `{"Version":"2012-10-17","Statement":[${stmts.join(',')}]}`;

  const start = Date.now();
  const v = validate(text);
  const result = analyze(text);
  const elapsed = Date.now() - start;

  assert.equal(v.ok, false, 'validate() must reject a 20000-statement policy');
  // Rejected by either the statement-count cap or the byte cap - both are
  // pre-analysis DoS guards; either is an acceptable fast rejection.
  assert.ok(
    v.errors.some((e) => e.code === 'TOO_MANY_STATEMENTS' || e.code === 'TOO_LARGE'),
    `expected TOO_MANY_STATEMENTS or TOO_LARGE, got ${v.errors.map((e) => e.code).join(',')}`,
  );
  assert.equal(result.ok, false, 'analyze() must be ok:false');
  assert.ok(elapsed < 5000, `pipeline must resolve under 5s; took ${elapsed}ms`);
});

test('LIMITS.MAX_STATEMENTS is the documented cap the fixture sits just past', () => {
  assert.equal(typeof LIMITS.MAX_STATEMENTS, 'number');
  const fx = JSON.parse(
    readFileSync(join(fixturesDir, 'adversarial', 'oversized-statements.json'), 'utf8'),
  );
  assert.equal(
    fx.policy.Statement.length,
    LIMITS.MAX_STATEMENTS + 1,
    'fixture must sit exactly one statement past the cap',
  );
});

test('malformed input fails gracefully with structured errors and empty output', () => {
  for (const { file, data } of loadFixtures('malformed')) {
    const result = analyze(fixtureText(data));
    assert.equal(result.ok, false, `${file}: malformed input must not be ok`);
    assert.ok(result.errors.length > 0, `${file}: malformed input reports errors`);
    assert.equal(result.findings.length, 0, `${file}: no findings on failure`);
    assert.equal(result.graph.edges.length, 0, `${file}: no graph edges on failure`);
    assert.equal(result.model, null, `${file}: no model on failure`);
  }
});

test('analyze() never throws on non-string / empty / junk input', () => {
  const junk = [undefined, null, 42, {}, [], '', '   ', 'not json', '{"Statement":', '[]'];
  for (const input of junk) {
    let result;
    assert.doesNotThrow(() => { result = analyze(input); }, `input ${String(input)} must not throw`);
    assert.equal(result.ok, false, `input ${String(input)} should be rejected`);
    assert.ok(result.errors.length > 0, `input ${String(input)} reports errors`);
  }
});

// ---------------------------------------------------------------------------
// IAM-105: compound-finding correlation + risk-factor checklist.
//
// A standalone wildcard/broad-resource finding that sits on a statement a
// compound escalation path consumes must be folded INTO that path (as a
// `subsumed` sub-property + reflected in the path's risk-factor checklist),
// not reported as a duplicate top-level row. A wildcard finding on a statement
// NO compound path consumes must remain an independent top-level finding.
// Fixtures carry an `expect.compound` block describing the expected folding.
// ---------------------------------------------------------------------------

function findByIdAndStmt(findings, id, statementIndex) {
  return findings.find((f) => f.id === id && f.statementIndex === statementIndex);
}

test('compound escalation paths subsume subordinate wildcard rows (IAM-105)', () => {
  let checked = 0;
  for (const category of ALL_CATEGORIES) {
    for (const { file, data } of loadFixtures(category)) {
      const c = data.expect && data.expect.compound;
      if (!c) continue;
      checked++;
      const result = analyze(fixtureText(data));
      assert.equal(result.ok, true, `${file}: expected a valid analysis`);

      // The primary compound finding is present exactly once at top level.
      const primaries = result.findings.filter((f) => f.id === c.primaryId);
      assert.equal(primaries.length, 1, `${file}: exactly one ${c.primaryId} primary row`);
      const primary = primaries[0];

      // It carries a risk-factor checklist.
      assert.ok(Array.isArray(primary.riskFactors) && primary.riskFactors.length > 0,
        `${file}: primary ${c.primaryId} must expose a risk-factor checklist`);
      for (const rf of primary.riskFactors) {
        assert.equal(typeof rf.key, 'string', `${file}: risk factor has a key`);
        assert.equal(typeof rf.label, 'string', `${file}: risk factor has a label`);
        assert.equal(typeof rf.present, 'boolean', `${file}: risk factor present is boolean`);
      }

      // Each expected checklist item is present with the expected state.
      for (const want of c.riskFactors || []) {
        const rf = primary.riskFactors.find((x) => x.key === want.key);
        assert.ok(rf, `${file}: risk factor ${want.key} expected on ${c.primaryId}`);
        assert.equal(rf.present, want.present,
          `${file}: risk factor ${want.key} present=${want.present}`);
      }

      // Each subsumed finding is folded into the primary AND absent as a
      // top-level row with that (id, statementIndex).
      const subsumed = Array.isArray(primary.subsumed) ? primary.subsumed : [];
      for (const s of c.subsumes || []) {
        assert.ok(
          subsumed.some((x) => x.id === s.id && x.statementIndex === s.statementIndex),
          `${file}: ${s.id}@${s.statementIndex} must be attached to ${c.primaryId}.subsumed`,
        );
        assert.ok(
          !findByIdAndStmt(result.findings, s.id, s.statementIndex),
          `${file}: subsumed ${s.id}@${s.statementIndex} must NOT be a top-level row`,
        );
      }

      // Genuinely independent wildcard findings are never dropped.
      for (const ind of c.independentFindings || []) {
        assert.ok(
          findByIdAndStmt(result.findings, ind.id, ind.statementIndex),
          `${file}: independent ${ind.id}@${ind.statementIndex} must remain top-level`,
        );
        assert.ok(
          !subsumed.some((x) => x.id === ind.id && x.statementIndex === ind.statementIndex),
          `${file}: independent ${ind.id}@${ind.statementIndex} must NOT be subsumed`,
        );
      }

      // Subsumed views preserve the prose (nothing lost).
      for (const s of subsumed) {
        assert.equal(typeof s.why, 'string', `${file}: subsumed finding keeps why`);
        assert.equal(typeof s.limit, 'string', `${file}: subsumed finding keeps limit`);
        assert.equal(typeof s.remediation, 'string', `${file}: subsumed finding keeps remediation`);
      }
    }
  }
  assert.ok(checked > 0, 'at least one fixture must exercise compound correlation');
});

test('single-action escalation primitives carry no COMPOUND-PATH checklist (IAM-105 / IAM-705)', () => {
  // IAM-105 intent: a standalone single-action primitive must NOT fabricate a
  // compound multi-grant PassRole risk-factor checklist (pass-role /
  // exec-resource-wildcard / passed-to-service-restriction). IAM-705 refines this:
  // because every concrete IAM primitive (iam:CreatePolicyVersion, ...) also trips
  // the generic DIRECT-IAM-ADMIN rule on the same statement, the primitive now
  // subsumes that generic finding and carries exactly ONE risk factor recording it
  // (`direct-iam-admin`). That is the generic-into-specific dedup, NOT a compound
  // path - assert the compound pass-role factors are absent and the only factor is
  // the direct-iam-admin dedup marker.
  const result = analyze(fixtureText(JSON.parse(
    readFileSync(join(fixturesDir, 'policy-version', 'create-policy-version-positive.json'), 'utf8'),
  )));
  const pv = result.findings.find((f) => f.id === 'POLICY-VERSION');
  assert.ok(pv, 'expected a POLICY-VERSION finding');
  // No fabricated compound (PassRole) checklist keys.
  const COMPOUND_KEYS = new Set([
    'pass-role', 'lambda:CreateFunction', 'pass-role-resource-wildcard',
    'exec-resource-wildcard', 'passed-to-service-restriction',
  ]);
  for (const rf of pv.riskFactors || []) {
    assert.ok(!COMPOUND_KEYS.has(rf.key), `POLICY-VERSION must not carry compound-path factor ${rf.key}`);
  }
  // The only risk factor is the IAM-705 generic-subsumption marker.
  assert.deepEqual((pv.riskFactors || []).map((r) => r.key), ['direct-iam-admin']);
  // ... and the generic DIRECT-IAM-ADMIN it restates is folded in (not dropped).
  assert.ok(
    Array.isArray(pv.subsumed) && pv.subsumed.some((s) => s.id === 'DIRECT-IAM-ADMIN'),
    'the co-located generic DIRECT-IAM-ADMIN is subsumed into the specific primitive',
  );
  // The generic is no longer a duplicate top-level row.
  assert.ok(
    !result.findings.some((f) => f.id === 'DIRECT-IAM-ADMIN'),
    'DIRECT-IAM-ADMIN must not also appear as its own top-level row',
  );
});

// --- presentation helpers ----------------------------------------------------

test('findingToRow returns one string cell per column, in column order', () => {
  const finding = {
    id: 'WILDCARD-ACTION',
    severity: 'critical',
    title: 'Wildcard action',
    statementSid: '(index 0)',
    actions: ['*'],
    resources: ['*'],
    policyEvidence: 'high',
    pathExploitability: 'high',
    why: 'why text',
    limit: 'limit text',
    remediation: 'fix it',
  };
  const row = findingToRow(finding);
  assert.equal(row.length, FINDING_COLUMNS.length, 'one cell per column');
  for (let i = 0; i < row.length; i++) {
    assert.equal(row[i].key, FINDING_COLUMNS[i].key, `cell ${i} key matches column`);
    assert.equal(typeof row[i].text, 'string', `cell ${i} text is a string`);
  }
  assert.equal(row[0].text, 'critical');
  assert.equal(row[3].text, '*'); // actions joined

  // IAM-101: the main table is limited to scannable fields. The three prose
  // fields are NOT columns anymore - they moved into the per-row detail.
  const columnKeys = new Set(FINDING_COLUMNS.map((c) => c.key));
  for (const prose of ['why', 'limit', 'remediation']) {
    assert.ok(!columnKeys.has(prose), `${prose} must not be a table column`);
  }
  assert.deepEqual(
    FINDING_COLUMNS.map((c) => c.key),
    ['severity', 'title', 'statement', 'actions', 'resources', 'policyEvidence', 'pathExploitability'],
    'compact column contract',
  );
  // The prose fields are relocated to the detail-field contract, not dropped.
  assert.deepEqual(
    FINDING_DETAIL_FIELDS.map((f) => f.key),
    ['why', 'limit', 'remediation'],
    'prose moved to the per-row detail contract',
  );
});

test('sortFindings orders by severity, then statement index, deterministically', () => {
  const input = [
    { id: 'B', severity: 'low', statementIndex: 0 },
    { id: 'A', severity: 'critical', statementIndex: 5 },
    { id: 'C', severity: 'critical', statementIndex: 1 },
    { id: 'D', severity: 'high', statementIndex: 0 },
  ];
  const out = sortFindings(input);
  assert.deepEqual(out.map((f) => f.id), ['C', 'A', 'D', 'B']);
  // Pure: input not mutated.
  assert.equal(input[0].id, 'B');
  // Deterministic.
  assert.deepEqual(sortFindings(input), out);
});
