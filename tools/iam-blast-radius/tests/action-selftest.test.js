// Tests for the GitHub Action self-test workflow (Phase 16, story P16-selftests).
//
// The self-test workflow (.github/workflows/action-selftest.yml) runs the real
// action against checked-in fixtures inside a runner and asserts the exit-code
// contract case-by-case. THAT workflow only runs on GitHub. These node --test tests
// are the local, deterministic proof that:
//
//   1. Each checked-in fixture ACTUALLY produces the exit code / SARIF shape the
//      workflow asserts - run through the same runAction() the action uses. If a
//      fixture is ever weakened (e.g. the "malformed" file is "fixed" into valid
//      JSON, or the admin policy is defanged), these tests fail here, in the fast
//      suite, instead of silently making the workflow's assertions vacuous.
//   2. The workflow file still encodes its load-bearing, adversarial invariants:
//      least-privilege permissions, the local action, and - the whole point - that
//      the MALFORMED case asserts exit-code 3 and NOT 0. A fail-closed state
//      collapsing to a green check is the top fail-open bug; a test guards the
//      workflow text so that guard cannot be quietly deleted.
//
// The fixtures + workflow live at the REPO ROOT (three levels up from this test),
// alongside action.yml, so `uses: ./` resolves to them.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { runAction, EXIT } from '../../../action/index.mjs';

// --- Locate the repo-root fixtures + workflow --------------------------------

const FIXTURE_DIR = new URL('../../../.github/action-selftest-fixtures/', import.meta.url);
const WORKFLOW_URL = new URL('../../../.github/workflows/action-selftest.yml', import.meta.url);

function fixture(name) {
  return readFileSync(fileURLToPath(new URL(name, FIXTURE_DIR)), 'utf8');
}

const CLEAN = 'clean-identity.json';
const ADMIN = 'admin-identity.json';
const MALFORMED = 'malformed.json';

// An in-memory IO surface backed by the REAL fixture contents on disk, keyed by the
// exact cwd-relative path the workflow passes as `paths`.
function ioForFixtures(names) {
  const files = {};
  for (const [rel, fx] of Object.entries(names)) files[rel] = fixture(fx);
  return {
    listFiles: () => Object.keys(files),
    readFile: (rel) => {
      if (Object.prototype.hasOwnProperty.call(files, rel)) return files[rel];
      const e = new Error(`ENOENT: ${rel}`);
      e.code = 'ENOENT';
      throw e;
    },
  };
}

// Build the INPUT_* env the workflow's `with:` block would produce for one case.
function envFor({ paths, family, failOn = 'high' }) {
  const env = { 'INPUT_FAIL-ON': failOn };
  if (paths !== undefined) env.INPUT_PATHS = paths;
  if (family !== undefined) env.INPUT_FAMILY = family;
  return env;
}

function sarifResults(r) {
  return r.sarifLog.runs.flatMap((run) => run.results || []);
}

// ============================================================================
// Fixture behavior MUST match what each workflow case asserts
// ============================================================================

test('known-good fixture: clean-identity.json -> exit 0, status complete, SARIF 2.1.0', () => {
  const path = '.github/action-selftest-fixtures/clean-identity.json';
  const r = runAction({ env: envFor({ paths: path, family: 'identity' }), io: ioForFixtures({ [path]: CLEAN }) });
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.equal(r.analysisStatus, 'complete');
  assert.equal(r.blockingCount, 0);
  assert.equal(r.outputs['exit-code'], '0');
  assert.equal(r.sarifLog.version, '2.1.0');
});

test('known-bad fixture: admin-identity.json -> exit 1 and SARIF carries ruleId DIRECT-IAM-ADMIN', () => {
  const path = '.github/action-selftest-fixtures/admin-identity.json';
  const r = runAction({ env: envFor({ paths: path, family: 'identity' }), io: ioForFixtures({ [path]: ADMIN }) });
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(r.blockingCount >= 1);
  // The exact ruleId the workflow greps for must actually be produced, else the
  // workflow's jq assertion would be vacuously unsatisfiable (a silent false pass).
  const ids = sarifResults(r).map((res) => res.ruleId);
  assert.ok(ids.includes('DIRECT-IAM-ADMIN'), `expected DIRECT-IAM-ADMIN in ${JSON.stringify(ids)}`);
});

test('malformed fixture: malformed.json FAILS CLOSED -> exit 3, NEVER 0 (adversarial)', () => {
  const path = '.github/action-selftest-fixtures/malformed.json';
  const r = runAction({ env: envFor({ paths: path, family: 'identity' }), io: ioForFixtures({ [path]: MALFORMED }) });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.notEqual(r.exitCode, EXIT.CLEAN); // the whole point: 3 must never collapse to 0
  assert.equal(r.analysisStatus, 'failed');
  // An analyzer-state (kind:fail, category analysis-state) result must exist, and it
  // must NOT carry a security-severity - exactly what the workflow's jq asserts.
  const states = sarifResults(r).filter(
    (res) => res.kind === 'fail' && res.properties && res.properties.category === 'analysis-state',
  );
  assert.ok(states.length >= 1);
  for (const res of states) {
    assert.equal(Object.prototype.hasOwnProperty.call(res.properties, 'security-severity'), false);
  }
});

test('usage-error case: empty family -> exit 2 (never auto-detected)', () => {
  const path = '.github/action-selftest-fixtures/clean-identity.json';
  // family is intentionally empty, exactly like the workflow's usage-error step
  // (family: ''). An empty required family must fail closed to a usage error, never a
  // guessed family.
  const r = runAction({ env: envFor({ paths: path, family: '' }), io: ioForFixtures({ [path]: CLEAN }) });
  assert.equal(r.exitCode, EXIT.USAGE);
  assert.equal(r.reason, 'MISSING_FAMILY');
});

// ============================================================================
// The workflow file must keep its load-bearing invariants
// ============================================================================

test('workflow: exists, least-privilege permissions, and runs the LOCAL action', () => {
  const wf = readFileSync(fileURLToPath(WORKFLOW_URL), 'utf8');
  assert.match(wf, /permissions:\s*\n\s*contents:\s*read/);
  // One local-action invocation per case (good/bad/malformed/usage) = 4+.
  const localUses = wf.match(/uses:\s*\.\/\s*$/gm) || [];
  assert.ok(localUses.length >= 4, `expected >=4 "uses: ./" invocations, found ${localUses.length}`);
});

test('workflow: the MALFORMED case asserts exit-code 3 AND explicitly not 0 (adversarial guard)', () => {
  const wf = readFileSync(fileURLToPath(WORKFLOW_URL), 'utf8');
  // The exit-3 assertion and the explicit not-0 fail-open guard must both survive.
  assert.match(wf, /code"\s*=\s*"3"/, 'malformed case must assert exit-code == 3');
  assert.match(wf, /code"\s*!=\s*"0"/, 'malformed case must explicitly reject exit-code 0 (fail-open guard)');
});

test('workflow: each failing case checks step outcome == failure (not just conclusion)', () => {
  const wf = readFileSync(fileURLToPath(WORKFLOW_URL), 'utf8');
  const outcomeFailure = wf.match(/outcome"\s*=\s*"failure"/g) || [];
  // known-bad, malformed, usage-error each assert outcome failure.
  assert.ok(outcomeFailure.length >= 3, `expected >=3 outcome==failure assertions, found ${outcomeFailure.length}`);
});

test('workflow: references every checked-in fixture and the ruleId its fixture produces', () => {
  const wf = readFileSync(fileURLToPath(WORKFLOW_URL), 'utf8');
  assert.match(wf, /action-selftest-fixtures\/clean-identity\.json/);
  assert.match(wf, /action-selftest-fixtures\/admin-identity\.json/);
  assert.match(wf, /action-selftest-fixtures\/malformed\.json/);
  // The ruleId the workflow greps for must be the one the admin fixture actually
  // emits (kept honest by the known-bad behavior test above).
  assert.match(wf, /DIRECT-IAM-ADMIN/);
});

// ============================================================================
// Fixtures are the shapes they claim to be (guards against silent "fixes")
// ============================================================================

test('fixtures: clean + admin are valid JSON; malformed is NOT parseable JSON', () => {
  assert.doesNotThrow(() => JSON.parse(fixture(CLEAN)));
  assert.doesNotThrow(() => JSON.parse(fixture(ADMIN)));
  // If someone "fixes" the malformed fixture into valid JSON, the fail-closed case
  // stops exercising exit 3 - fail here loudly.
  assert.throws(() => JSON.parse(fixture(MALFORMED)));
});
