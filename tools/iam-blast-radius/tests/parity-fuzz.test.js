// S6-cigate-doc: the differential parity fuzzer, as a blocking regression.
//
// tests/fuzz/parity-fuzz.mjs is run at scale by the nightly fuzz-parity.yml
// workflow. This suite keeps the fuzzer HONEST inside the always-run
// `node --test` suite so it cannot silently rot:
//   1. a bounded, fixed-seed sweep asserts the analyze()==scan() safety-parity
//      invariant holds today over the generated corpus (no fail-open, no throw,
//      no wall-clock overrun);
//   2. DETERMINISM: the same seed yields the identical verdict twice, and two
//      different seeds both hold - so a nightly failure is always reproducible
//      from its printed seed;
//   3. the violation DETECTOR actually fires on a synthetic fail-open (a guard
//      that never triggers would make the whole fuzzer worthless).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  runFuzz, makeRng, generateCase, checkParity, isParityViolation, analyzeClean, scanClean,
} from './fuzz/parity-fuzz.mjs';

const WORKFLOW = readFileSync(
  fileURLToPath(new URL('../../../.github/workflows/fuzz-parity.yml', import.meta.url)), 'utf8');

// 1 + 2a. A bounded sweep holds, and is deterministic across two runs.
test('bounded fuzz sweep holds the parity invariant (fixed seed, reproducible)', () => {
  const a = runFuzz({ seed: 1, count: 400, budgetMs: 4000, ceilingMs: 8000 });
  const b = runFuzz({ seed: 1, count: 400, budgetMs: 4000, ceilingMs: 8000 });
  assert.equal(a.violations.length, 0, `seed=1 produced ${a.violations.length} violation(s): `
    + JSON.stringify(a.violations.slice(0, 3)));
  assert.equal(a.checked, 400);
  // Determinism: identical verdicts for identical seed.
  assert.deepEqual(a.violations, b.violations, 'same seed must produce the same verdict');
});

// 2b. Several other seeds also hold (breadth without a huge blocking-suite cost).
for (const seed of [2, 3, 7, 42, 1337]) {
  test(`bounded fuzz sweep holds for seed=${seed}`, () => {
    const r = runFuzz({ seed, count: 300, budgetMs: 4000, ceilingMs: 8000 });
    assert.equal(r.violations.length, 0,
      `seed=${seed} produced violation(s): ${JSON.stringify(r.violations.slice(0, 3))}`);
  });
}

// 2c. The generator is a pure function of the seed (same seed -> same first cases).
test('generator is deterministic in the seed', () => {
  const r1 = makeRng(99);
  const r2 = makeRng(99);
  for (let i = 0; i < 20; i += 1) {
    assert.deepEqual(generateCase(r1), generateCase(r2), `case ${i} diverged for equal seeds`);
  }
});

// 3. The violation detector fires on a synthetic fail-open, and does NOT fire on
// the three benign directions. Without this, a broken detector would let the
// fuzzer "pass" forever.
test('isParityViolation flags a browser-more-permissive fail-open and nothing else', () => {
  const cleanAnalyze = { ok: true, findings: [], coverage: { summary: { incomplete: false } } };
  const dirtyAnalyze = { ok: true, findings: [], coverage: { summary: { incomplete: true } } };
  const cleanScan = { exitCode: 0, analysisStatus: 'complete' };
  const dirtyScan = { exitCode: 3, analysisStatus: 'failed' };

  assert.equal(analyzeClean(cleanAnalyze), true);
  assert.equal(analyzeClean(dirtyAnalyze), false);
  assert.equal(scanClean(cleanScan), true);
  assert.equal(scanClean(dirtyScan), false);

  // The one forbidden combination: CLI non-clean, browser clean.
  assert.equal(isParityViolation(cleanAnalyze, dirtyScan), true, 'must flag the fail-open');
  // The three allowed combinations.
  assert.equal(isParityViolation(cleanAnalyze, cleanScan), false, 'both clean is fine');
  assert.equal(isParityViolation(dirtyAnalyze, dirtyScan), false, 'both non-clean is fine');
  assert.equal(isParityViolation(dirtyAnalyze, cleanScan), false, 'CLI more permissive is not this invariant');
});

// The known audit repros (empty NotAction / NotResource complements) must NOT be
// clean on either surface - checkParity returns null (invariant held) precisely
// because BOTH fail closed. This ties the fuzzer to the concrete fail-open class.
test('checkParity holds on the historical fail-open repros (both fail closed)', () => {
  const repros = [
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', NotAction: [], Resource: '*' }] }),
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', NotResource: [] }] }),
  ];
  for (const text of repros) {
    assert.equal(checkParity(text, 'identity', { budgetMs: 4000, ceilingMs: 8000 }), null,
      `repro unexpectedly flagged: ${text}`);
  }
});

// The nightly workflow's load-bearing security + wiring invariants, guarded so
// they cannot be quietly deleted (mirrors action-selftest.test.js's approach).
test('fuzz-parity.yml is least-privilege, pinned, scheduled, and deterministic', () => {
  // Triggers: nightly schedule + manual dispatch.
  assert.match(WORKFLOW, /^on:/m, 'has an on: block');
  assert.match(WORKFLOW, /schedule:/, 'runs on a schedule (nightly)');
  assert.match(WORKFLOW, /cron:/, 'schedule has a cron');
  assert.match(WORKFLOW, /workflow_dispatch:/, 'is manually dispatchable');

  // Least privilege: contents: read, and NO write scope anywhere.
  assert.match(WORKFLOW, /permissions:\s*\n\s*contents: read/, 'permissions are contents: read');
  assert.ok(!/\bwrite\b/.test(WORKFLOW.replace(/#.*$/gm, '')), 'no write permission granted');

  // Every external action is pinned to a full 40-char commit SHA.
  const uses = [...WORKFLOW.matchAll(/uses:\s*(\S+)/g)].map((m) => m[1]);
  assert.ok(uses.length >= 2, 'uses at least checkout + setup-node');
  for (const u of uses) {
    assert.match(u, /@[0-9a-f]{40}$/, `action ${u} must be pinned to a 40-char SHA`);
  }
  assert.match(WORKFLOW, /persist-credentials: false/, 'checkout does not persist credentials');

  // Actually invokes the seeded, deterministic fuzzer with both knobs.
  assert.match(WORKFLOW, /tests\/fuzz\/parity-fuzz\.mjs/, 'runs the parity fuzzer');
  assert.match(WORKFLOW, /--seed/, 'passes an explicit seed (deterministic)');
  assert.match(WORKFLOW, /--count/, 'passes an explicit count');

  // Template-injection safety: dispatch inputs are consumed via env:, never
  // interpolated directly into the run script body.
  const runBodies = [...WORKFLOW.matchAll(/run:\s*\|([\s\S]*?)(?=\n\s{6}\S|\n\s{4}-|\n\S|$)/g)]
    .map((m) => m[1]).join('\n');
  assert.ok(!/\$\{\{\s*github\.event\.inputs/.test(runBodies),
    'dispatch inputs must not be interpolated into run: (use env:)');
});
