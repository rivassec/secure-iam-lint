// IAM-1008 (Phase 10 capstone): Acceptance Suite III completeness gate +
// scoreboard driver for docs/acceptance-suite-3.md (tests 55-100).
//
// This is the single authoritative gate that ties EVERY suite-3 test to its
// coverage so there are NO SILENT SKIPS. Each of the 46 tests (55-100) is
// either:
//
//   - FIXTURE-BACKED: a committed fixture (in fixtures/acceptance-3/,
//     fixtures/family-selection/, or fixtures/family-envelope/) driven through
//     the REAL engine (validate() + analyze()). The verdict is DERIVED from the
//     analyze() result and asserted to equal the manifest's declared verdict, so
//     the scoreboard cannot drift from actual engine behavior.
//
//   - PROCEDURE / UI-ONLY: a documented reason it is not a single-policy engine
//     assertion (paste/import parity, UI state invalidation, export-surface
//     parity, generated limit sweeps). Each declares the test file(s) that DO
//     cover it, and this gate asserts those files exist - a documented pointer,
//     never a silent skip.
//
// The deep per-fixture semantics (findingIds, error codes/paths, coverage codes,
// role-takeover anchoring, principal-path locations) are enforced by the
// dedicated harnesses: tests/acceptance-suite-3-fixtures.test.js,
// tests/phase10-parser-hardening.test.js, tests/phase10-family-selection.test.js,
// tests/phase10-envelope.test.js, tests/phase10-iam-ecs.test.js, and
// tests/acceptance-suite-3.test.js. This file is the completeness + verdict gate
// that binds them to the suite-3 document.
//
// Scoreboard prose (per-test verdict + rationale) lives in
// docs/acceptance-suite-3-results.md and is kept in sync with this manifest.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const fixturesDir = join(root, 'fixtures');

// Verdict vocabulary (docs/acceptance-suite-3.md "Result states").
const VERDICTS = new Set(['COMPLETE', 'COMPLETE_WITH_WARNINGS', 'BLOCKED', 'TOO_LARGE']);

// Derive the suite-3 result state from the real engine output. Deterministic and
// schema-agnostic (works across every fixture's local expect schema):
//   - a validation failure OR a fail-closed coverage state -> BLOCKED
//   - a supported analysis with an incomplete-coverage flag -> COMPLETE_WITH_WARNINGS
//   - a supported, complete analysis                        -> COMPLETE
function deriveVerdict(vres, res) {
  if (!vres.ok || !res.ok) return 'BLOCKED';
  if (res.coverage && res.coverage.blocked) return 'BLOCKED';
  const incomplete = !!(res.coverage && res.coverage.summary && res.coverage.summary.incomplete);
  return incomplete ? 'COMPLETE_WITH_WARNINGS' : 'COMPLETE';
}

function fx(rel) {
  return { fixture: rel };
}
function proc(...coveredBy) {
  return { procedure: true, coveredBy };
}

// ---------------------------------------------------------------------------
// The manifest: every suite-3 test 55-100, its campaign, and its coverage.
// verdict is the DERIVED analyze() state for fixture-backed cases (asserted
// below); procedure cases record the covering test file(s).
// ---------------------------------------------------------------------------
const MANIFEST = {
  // Campaign A - strict parser and import equivalence.
  55: { campaign: 'A', verdict: 'BLOCKED', ...fx('acceptance-3/test-55-duplicate-action-dangerous-first.json') },
  56: { campaign: 'A', verdict: 'BLOCKED', ...fx('acceptance-3/test-56-duplicate-action-dangerous-last.json') },
  57: { campaign: 'A', verdict: 'BLOCKED', ...fx('acceptance-3/test-57-escaped-action-key-decodes.json') },
  58: { campaign: 'A', verdict: 'BLOCKED', ...fx('acceptance-3/test-58-duplicate-nested-condition-key.json') },
  59: { campaign: 'A', verdict: 'BLOCKED', ...fx('acceptance-3/test-59-condition-key-case-variant-duplicate.json') },
  60: { campaign: 'A', verdict: 'COMPLETE', ...fx('acceptance-3/test-60-duplicate-sids-flagged.json') },
  61: { campaign: 'A', verdict: 'BLOCKED', ...fx('acceptance-3/test-61-jsonc-comments-trailing-commas-invalid.json') },
  62: { campaign: 'A', verdict: 'COMPLETE', ...fx('acceptance-3/test-62-utf8-bom-stripped.json') },
  63: { campaign: 'A', verdict: 'COMPLETE', ...proc('tests/phase10-parser-hardening.test.js', 'tests/e2e/parser-hardening.spec.js') },

  // Campaign B - required policy-family selection.
  64: { campaign: 'B', verdict: 'BLOCKED', ...fx('family-selection/64-no-family-selected.json') },
  65: { campaign: 'B', verdict: 'COMPLETE', ...fx('family-envelope/test-65-boundary-allow-heavy.json') },
  66: { campaign: 'B', verdict: 'COMPLETE', ...fx('family-envelope/test-66-session-selected.json') },
  67: { campaign: 'B', verdict: 'BLOCKED', ...fx('family-selection/67-identity-rejects-principal.json') },
  68: { campaign: 'B', verdict: 'BLOCKED', ...fx('family-selection/68-trust-rejects-resource.json') },
  69: { campaign: 'B', verdict: 'BLOCKED', ...fx('family-selection/69-resource-family-unsupported.json') },
  70: { campaign: 'B', verdict: 'COMPLETE', ...proc('tests/phase10-family-selection.test.js', 'tests/e2e/ui-shell.spec.js') },
  71: { campaign: 'B', verdict: 'COMPLETE', ...proc('tests/phase10-family-selection.test.js') },

  // Campaign C - IAM role-takeover correlation.
  72: { campaign: 'C', verdict: 'COMPLETE', ...fx('acceptance-3/test-72-exact-same-role-takeover.json') },
  73: { campaign: 'C', verdict: 'COMPLETE', ...fx('acceptance-3/test-73-different-roles-no-correlation.json') },
  74: { campaign: 'C', verdict: 'COMPLETE', ...fx('acceptance-3/test-74-wildcard-modifier-overlaps-exact-assumable-role.json') },
  75: { campaign: 'C', verdict: 'COMPLETE', ...fx('acceptance-3/test-75-mutually-exclusive-conditions-prevent-correlation.json') },
  76: { campaign: 'C', verdict: 'COMPLETE', ...fx('acceptance-3/test-76-deny-removes-one-prerequisite.json') },
  77: { campaign: 'C', verdict: 'COMPLETE_WITH_WARNINGS', ...fx('acceptance-3/test-77-attachrolepolicy-alternative.json') },
  78: { campaign: 'C', verdict: 'COMPLETE', ...fx('acceptance-3/test-78-modify-without-assume.json') },
  79: { campaign: 'C', verdict: 'COMPLETE', ...proc('tests/acceptance-suite-3-fixtures.test.js') },
  80: { campaign: 'C', verdict: 'COMPLETE', ...fx('acceptance-3/test-80-duplicate-modify-statements-one-path.json') },

  // Campaign D - principal validation.
  81: { campaign: 'D', verdict: 'COMPLETE_WITH_WARNINGS', ...fx('acceptance-3/test-81-asterisk-inside-role-principal-arn.json') },
  82: { campaign: 'D', verdict: 'COMPLETE_WITH_WARNINGS', ...fx('acceptance-3/test-82-question-mark-inside-user-principal-arn.json') },
  83: { campaign: 'D', verdict: 'COMPLETE_WITH_WARNINGS', ...fx('acceptance-3/test-83-one-invalid-member-poisons-principal-array.json') },
  84: { campaign: 'D', verdict: 'COMPLETE', ...fx('acceptance-3/test-84-short-form-account-principal-valid.json') },
  85: { campaign: 'D', verdict: 'BLOCKED', ...fx('acceptance-3/test-85-principalarn-condition-wildcard-not-rejected.json') },

  // Campaign E - IAM and ECS semantic precision.
  86: { campaign: 'E', verdict: 'COMPLETE', ...fx('acceptance-3/test-86-add-user-to-group-membership.json') },
  87: { campaign: 'E', verdict: 'COMPLETE', ...fx('acceptance-3/test-87-ecs-task-and-execution-separate.json') },
  88: { campaign: 'E', verdict: 'COMPLETE', ...fx('acceptance-3/test-88-only-execution-role-passable.json') },
  89: { campaign: 'E', verdict: 'COMPLETE', ...fx('acceptance-3/test-89-only-task-role-passable.json') },
  90: { campaign: 'E', verdict: 'COMPLETE', ...fx('acceptance-3/test-90-register-without-runtask.json') },
  91: { campaign: 'E', verdict: 'COMPLETE', ...fx('acceptance-3/test-91-cross-account-passrole-target.json') },

  // Campaign F - false-positive control, state isolation, rendering safety, limits.
  92: { campaign: 'F', verdict: 'COMPLETE', ...fx('acceptance-3/test-92-iam-listroles-required-wildcard.json') },
  93: { campaign: 'F', verdict: 'COMPLETE', ...fx('acceptance-3/test-93-ec2-describeinstances-required-wildcard.json') },
  94: { campaign: 'F', verdict: 'COMPLETE', ...fx('acceptance-3/test-94-s3-listallmybuckets-required-wildcard.json') },
  95: { campaign: 'F', verdict: 'COMPLETE', ...fx('acceptance-3/test-95-mixed-per-action-resource.json') },
  96: { campaign: 'F', verdict: 'COMPLETE_WITH_WARNINGS', ...fx('acceptance-3/test-96-forallvalues-with-null-protection.json') },
  97: { campaign: 'F', verdict: 'COMPLETE_WITH_WARNINGS', ...fx('acceptance-3/test-97-empty-foranyvalue-never-matches.json') },
  98: { campaign: 'F', verdict: 'COMPLETE', ...proc('tests/phase10-parser-hardening.test.js', 'tests/e2e/ui-shell.spec.js') },
  99: { campaign: 'F', verdict: 'COMPLETE', ...fx('acceptance-3/test-99-rendering-export-injection.json') },
  100: { campaign: 'F', verdict: 'COMPLETE', ...proc('tests/phase10-parser-hardening.test.js') },
};

const REQUIRED_IDS = [];
for (let n = 55; n <= 100; n++) REQUIRED_IDS.push(n);

function fixtureText(data) {
  return typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
}

// ---------------------------------------------------------------------------
// Completeness gate: every suite-3 test 55-100 is accounted for exactly once,
// and no manifest entry falls outside that range. Zero silent skips.
// ---------------------------------------------------------------------------
test('completeness: suite-3 tests 55-100 are each accounted for exactly once', () => {
  const keys = Object.keys(MANIFEST).map(Number).sort((a, b) => a - b);
  for (const id of REQUIRED_IDS) {
    assert.ok(MANIFEST[id], `suite-3 test ${id} is not accounted for in the manifest (silent skip)`);
  }
  for (const id of keys) {
    assert.ok(REQUIRED_IDS.includes(id), `manifest claims a test id ${id} outside 55-100`);
  }
  assert.equal(keys.length, REQUIRED_IDS.length, `expected ${REQUIRED_IDS.length} suite-3 entries, found ${keys.length}`);
});

test('every manifest entry declares a valid verdict', () => {
  for (const [id, entry] of Object.entries(MANIFEST)) {
    assert.ok(VERDICTS.has(entry.verdict), `test ${id}: invalid verdict ${entry.verdict}`);
    assert.ok(['A', 'B', 'C', 'D', 'E', 'F'].includes(entry.campaign), `test ${id}: invalid campaign ${entry.campaign}`);
    const isFixture = typeof entry.fixture === 'string';
    const isProc = entry.procedure === true;
    assert.ok(isFixture !== isProc, `test ${id}: must be EITHER fixture-backed OR procedure, not both/neither`);
  }
});

// ---------------------------------------------------------------------------
// Fixture-backed cases: drive the committed fixture through the real engine and
// assert the DERIVED verdict equals the manifest's declared verdict.
// ---------------------------------------------------------------------------
for (const id of REQUIRED_IDS) {
  const entry = MANIFEST[id];
  if (!entry.fixture) continue;
  test(`suite-3 test ${id} (Campaign ${entry.campaign}): fixture drives to ${entry.verdict}`, () => {
    const path = join(fixturesDir, entry.fixture);
    assert.ok(existsSync(path), `test ${id}: committed fixture missing at ${entry.fixture}`);
    const data = JSON.parse(readFileSync(path, 'utf8'));
    const text = fixtureText(data);

    let vres;
    assert.doesNotThrow(() => { vres = validate(text); }, `test ${id}: validate() threw`);
    let res;
    assert.doesNotThrow(() => { res = analyze(text, data.options || {}); }, `test ${id}: analyze() threw`);

    const got = deriveVerdict(vres, res);
    assert.equal(got, entry.verdict,
      `test ${id}: derived verdict ${got} != declared ${entry.verdict} (${entry.fixture})`);

    // A BLOCKED verdict must never present findings as a complete result.
    if (entry.verdict === 'BLOCKED') {
      assert.equal(res.findings.length, 0, `test ${id}: a BLOCKED result must have zero findings`);
    }

    // Determinism: re-analysis is byte-identical (report-agnostic, at the result level).
    const again = analyze(text, data.options || {});
    assert.equal(JSON.stringify(res.findings), JSON.stringify(again.findings),
      `test ${id}: analyze() is not deterministic`);
  });
}

// ---------------------------------------------------------------------------
// Procedure / UI-only cases: documented, never silently skipped. The covering
// test file(s) must exist on disk.
// ---------------------------------------------------------------------------
for (const id of REQUIRED_IDS) {
  const entry = MANIFEST[id];
  if (!entry.procedure) continue;
  test(`suite-3 test ${id} (Campaign ${entry.campaign}): procedure covered by declared test file(s)`, () => {
    assert.ok(Array.isArray(entry.coveredBy) && entry.coveredBy.length > 0, `test ${id}: no coveredBy declared`);
    for (const rel of entry.coveredBy) {
      assert.ok(existsSync(join(root, rel)), `test ${id}: declared covering file missing: ${rel}`);
    }
  });
}
