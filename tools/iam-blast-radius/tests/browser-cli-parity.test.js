// IAM Blast Radius - browser<->CLI guard-parity invariant (IAM-1508, S2-guard-parity).
//
// THE INVARIANT (immutable safety contract): the BROWSER engine (analyze(), called
// by app.js/worker.js) may NEVER be MORE PERMISSIVE than the CLI (scan()) on safety.
// Concretely, for every policy: if scan() is fail-closed / non-clean, then analyze()
// must NOT be clean, where
//
//   scan clean     := exitCode === 0 && analysisStatus === 'complete'
//   analyze clean  := ok === true && findings.length === 0
//                     && !coverage.summary.incomplete
//
// This is the CI capture for the S2-guard-parity story. Before the fix, four
// fail-closed guards lived ONLY in the CLI adapter (cli/scan.mjs), which re-parsed
// the raw text independently of the engine. The browser path never saw them, so
// analyze() reported ok:true / 0 findings / complete (a CLEAN pass) on masked
// full-admin and broad-resource grants that scan() correctly failed closed (exit 3)
// - a silent browser fail-OPEN (threat-model T8). The fix MOVED detection into the
// shared engine (engine/masked-grant.js -> coverage.summary.maskedGrants); the
// adapter now READS that coverage instead of re-parsing. This suite proves:
//
//   Part A - every one of scan()'s masked-grant guards now fires on the BROWSER
//            path too (analyze() marks coverage incomplete with the matching code),
//            over the audit repros, the four shapes, and their BOM variants.
//   Part B - the full guard set is enumerated and each benign sibling stays clean
//            (no over-fire into false positives).
//   Part C - the corpus invariant holds over the audit repros + the ENTIRE fixture
//            tree: analyze() is never more permissive than scan().
//
// A regression that re-opens the browser fail-open (engine stops flagging a masked
// grant) fails Part A; a regression that re-introduces an adapter-only guard the
// engine does not share fails Part C.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { MASKED_GRANT_CODES } from '../../../content/tools/iam-blast-radius/engine/masked-grant.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

const BOM = '﻿';

// Families scan() accepts (mirrors scan.mjs SELECTABLE_FAMILIES). A fixture whose
// declared family is outside this set (or absent) is analyzed as 'identity' so the
// comparison drives the engine identically on both surfaces (never a usage error).
const SELECTABLE = new Set([
  'identity', 'resource', 'role-trust', 'permissions-boundary', 'scp-rcp', 'session',
  'scp', 'rcp', 'trust',
]);

function familyFor(data) {
  const f = (data && data.options && data.options.family) || (data && data.family);
  return (typeof f === 'string' && SELECTABLE.has(f.toLowerCase())) ? f : 'identity';
}

function policyText(data) {
  if (typeof data.policyRaw === 'string') return data.policyRaw;
  if (data.policy !== undefined) return JSON.stringify(data.policy);
  return null;
}

// The two surfaces' "clean" predicates. analyze clean is derived DIRECTLY from a
// fresh engine call (the browser path), NOT from scan's result, so a drift between
// the two is observable.
function analyzeClean(ar) {
  return !!(ar && ar.ok === true
    && Array.isArray(ar.findings) && ar.findings.length === 0
    && !(ar.coverage && ar.coverage.summary && ar.coverage.summary.incomplete));
}
function scanClean(sr) {
  return sr.exitCode === EXIT.CLEAN && sr.analysisStatus === ANALYSIS_STATUS.COMPLETE;
}

function coverageCodes(ar) {
  return (ar && ar.coverage && ar.coverage.summary && Array.isArray(ar.coverage.summary.codes))
    ? ar.coverage.summary.codes : [];
}
function coverageIncomplete(ar) {
  return !!(ar && ar.coverage && ar.coverage.summary && ar.coverage.summary.incomplete);
}

function loadAllFixtures() {
  const out = [];
  for (const d of readdirSync(fixturesDir, { withFileTypes: true })) {
    if (!d.isDirectory()) continue;
    for (const f of readdirSync(join(fixturesDir, d.name))) {
      if (!f.endsWith('.json')) continue;
      let data;
      try { data = JSON.parse(readFileSync(join(fixturesDir, d.name, f), 'utf8')); } catch { continue; }
      out.push({ file: `${d.name}/${f}`, data });
    }
  }
  return out;
}

function loadMaskedGrantFixtures() {
  const dir = join(fixturesDir, 'masked-grant');
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `masked-grant/${f}`, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
}

// The three fail-open repros the audit VERIFIED on the browser path (analyze()
// ok:true / findings 0 / no-incomplete) while scan() exited 3. Post-fix, both must
// be non-clean. Kept inline so the capture documents the exact reproductions.
const AUDIT_REPROS = [
  {
    label: 'empty NotAction complement -> full admin',
    text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', NotAction: [], Resource: '*' }] }),
    code: MASKED_GRANT_CODES.EMPTY_NOTACTION_COMPLEMENT,
    scanReason: 'EMPTY_NOTACTION_COMPLEMENT',
    scanStatus: ANALYSIS_STATUS.FAILED,
  },
  {
    label: 'empty NotResource complement -> every resource',
    text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', NotResource: [] }] }),
    code: MASKED_GRANT_CODES.EMPTY_NOTRESOURCE_COMPLEMENT,
    scanReason: 'EMPTY_NOTRESOURCE_COMPLEMENT',
    scanStatus: ANALYSIS_STATUS.FAILED,
  },
  {
    label: 'suppressed ForAnyValue never-match -> silent clean full admin',
    text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'aws:PrincipalOrgID': [] } } }] }),
    code: MASKED_GRANT_CODES.SUPPRESSED_NEVER_MATCH_ALLOW,
    scanReason: 'SUPPRESSED_NEVER_MATCH_ALLOW',
    scanStatus: ANALYSIS_STATUS.PARTIAL,
  },
];

// ---------------------------------------------------------------------------
// Part A - every audit repro now fails closed on BOTH surfaces (fix verified).
// ---------------------------------------------------------------------------

for (const repro of AUDIT_REPROS) {
  test(`Part A: audit repro (${repro.label}) - browser no longer fails OPEN`, () => {
    const ar = analyze(repro.text, { family: 'identity', requireExplicitFamily: true });
    // The engine (browser path) is NO LONGER clean on the masked grant.
    assert.equal(analyzeClean(ar), false, 'analyze() must not report a clean pass on a masked grant');
    assert.equal(coverageIncomplete(ar), true, 'coverage must be incomplete');
    assert.ok(coverageCodes(ar).includes(repro.code), `coverage carries ${repro.code}`);

    const sr = scan({ text: repro.text, family: 'identity' });
    assert.equal(scanClean(sr), false, 'scan() must not be clean');
    assert.equal(sr.exitCode, EXIT.FAIL_CLOSED, 'scan() exits 3');
    assert.equal(sr.reason, repro.scanReason);
    assert.equal(sr.analysisStatus, repro.scanStatus);
    assert.ok(sr.analysisStates.some((s) => s.code === repro.code), 'analyzer-state carries the code');
  });

  test(`Part A: audit repro (${repro.label}) - BOM prefix does not re-open the fail-open`, () => {
    const ar = analyze(BOM + repro.text, { family: 'identity', requireExplicitFamily: true });
    assert.equal(analyzeClean(ar), false, 'BOM must not open the browser guard');
    assert.ok(coverageCodes(ar).includes(repro.code));
    const sr = scan({ text: BOM + repro.text, family: 'identity' });
    assert.equal(sr.exitCode, EXIT.FAIL_CLOSED);
    assert.equal(sr.reason, repro.scanReason);
  });
}

// The malformed-condition-value guard (its own audit-class shape). A non-primitive
// array member is dropped by the engine and must fail closed on both surfaces.
test('Part A: malformed condition value ([{}]) fails closed on BOTH surfaces', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: '*', Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'aws:SourceVpc': [{}] } } }],
  });
  const ar = analyze(text, { family: 'identity', requireExplicitFamily: true });
  assert.equal(analyzeClean(ar), false);
  assert.ok(coverageCodes(ar).includes(MASKED_GRANT_CODES.MALFORMED_CONDITION_VALUE));
  const sr = scan({ text, family: 'identity' });
  assert.equal(sr.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(sr.reason, 'MALFORMED_CONDITION_VALUE');
});

// ---------------------------------------------------------------------------
// Part A' - the fixture-backed regression cases (one per fix) agree on both
// surfaces exactly as their manifest declares.
// ---------------------------------------------------------------------------

for (const { file, data } of loadMaskedGrantFixtures()) {
  const exp = data.expect || {};
  const text = policyText(data);
  const family = familyFor(data);
  if (exp.maskedGrant === true) {
    test(`Part A': fixture ${file} fails closed on both surfaces (${exp.code})`, () => {
      const ar = analyze(text, { family, requireExplicitFamily: true });
      assert.equal(analyzeClean(ar), false, 'analyze() must not be clean');
      assert.equal(coverageIncomplete(ar), !!exp.coverageIncomplete);
      assert.ok(coverageCodes(ar).includes(exp.code), `coverage carries ${exp.code}`);
      const mg = (ar.coverage.summary.maskedGrants || []).find((g) => g.code === exp.code);
      assert.ok(mg, `masked-grant entry present for ${exp.code}`);
      assert.equal(mg.path, exp.path, 'masked-grant JSON path matches');
      assert.equal(mg.kind, exp.kind, 'masked-grant kind matches');

      const sr = scan({ text, family });
      assert.equal(sr.exitCode, exp.scanExit);
      assert.equal(sr.reason, exp.scanReason);
      assert.equal(sr.analysisStatus, exp.scanStatus);
      assert.ok(sr.analysisStates.some((s) => s.code === exp.code));
    });
  } else if (exp.maskedGrant === false) {
    test(`Part A': benign control ${file} is NOT flagged (no over-fire)`, () => {
      const ar = analyze(text, { family, requireExplicitFamily: true });
      const mg = (ar.coverage && ar.coverage.summary && ar.coverage.summary.maskedGrants) || [];
      assert.equal(mg.length, 0, 'no masked-grant entry on a benign policy');
      for (const code of Object.values(MASKED_GRANT_CODES)) {
        assert.ok(!coverageCodes(ar).includes(code), `benign policy must not carry ${code}`);
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Part B - the guard set is exactly the four masked-grant codes, and the fixtures
// witness every one of them (no guard silently dropped from the engine).
// ---------------------------------------------------------------------------

test('Part B: the masked-grant guard set is exactly the four fail-closed codes', () => {
  assert.deepEqual(
    Object.values(MASKED_GRANT_CODES).slice().sort(),
    ['EMPTY_NOTACTION_COMPLEMENT', 'EMPTY_NOTRESOURCE_COMPLEMENT', 'MALFORMED_CONDITION_VALUE', 'SUPPRESSED_NEVER_MATCH_ALLOW'],
  );
});

test('Part B: every masked-grant guard is witnessed by a regression fixture', () => {
  const witnessed = new Set();
  for (const { data } of loadMaskedGrantFixtures()) {
    if (data.expect && data.expect.maskedGrant === true) witnessed.add(data.expect.code);
  }
  for (const code of Object.values(MASKED_GRANT_CODES)) {
    assert.ok(witnessed.has(code), `a regression fixture must witness ${code}`);
  }
});

// ---------------------------------------------------------------------------
// Part C - THE INVARIANT over the audit repros + the ENTIRE fixture corpus:
// analyze() (browser) is never MORE permissive than scan() (CLI).
// ---------------------------------------------------------------------------

function assertNotMorePermissive(text, family, label) {
  const ar = analyze(text, { family, requireExplicitFamily: true });
  const sr = scan({ text, family });
  // Forbid the exact fail-open: scan fails closed / non-clean while analyze reports
  // a clean pass. (scan being clean while analyze has sub-threshold findings is the
  // OTHER direction - CLI more permissive - which the invariant does not forbid.)
  assert.ok(
    scanClean(sr) || !analyzeClean(ar),
    `PARITY VIOLATION (browser more permissive than CLI) on ${label}: ` +
      `scan{exit:${sr.exitCode},status:${sr.analysisStatus}} analyze{ok:${ar.ok},` +
      `findings:${ar.findings && ar.findings.length},incomplete:${coverageIncomplete(ar)}}`,
  );
}

test('Part C: invariant holds over the audit repros', () => {
  for (const repro of AUDIT_REPROS) {
    assertNotMorePermissive(repro.text, 'identity', repro.label);
    assertNotMorePermissive(BOM + repro.text, 'identity', `${repro.label} (BOM)`);
  }
});

test('Part C: invariant holds over the ENTIRE fixture corpus', () => {
  let checked = 0;
  for (const { file, data } of loadAllFixtures()) {
    const text = policyText(data);
    if (text === null) continue; // proc/UI-only fixtures carry no policy
    assertNotMorePermissive(text, familyFor(data), file);
    checked += 1;
  }
  // Sanity: the corpus is non-trivial (guards against an empty walk silently passing).
  assert.ok(checked > 100, `expected a broad corpus, only checked ${checked}`);
});
