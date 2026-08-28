// Story S6-R4-runner-selftests: RUNNER-level self-test coverage for the fail-open
// classes that were previously proven ONLY by the node --test unit suite.
//
// The runner self-test workflow (.github/workflows/action-selftest.yml) exercises the
// action INSIDE a real GitHub runner. Before this story it covered only admin / clean /
// malformed - yet the real fail-opens this whole tool exists to prevent lived in five
// other classes that were unit-tested but NEVER run at runner level:
//
//   1. a SYMLINKED entrypoint (npm .bin shim / npx / self-hosted-runner checkout) whose
//      realpath differs from argv[1] - the raw-realpath-mismatch that made the process
//      exit 0 having analyzed NOTHING (a false green check),
//   2. an UNREADABLE chmod-000 subtree hiding an admin policy -> must fail closed (exit 3),
//   3. a MAX_FILES-truncated enumeration (real IAM_BR_ENUM_MAX_FILES hook) -> exit 3,
//   4. the R6 directory-cap trip (real IAM_BR_ENUM_MAX_DIRS hook) -> exit 3,
//   5. a vacuous NotResource Deny (R1) that must NOT suppress DATA-EXFIL -> NON-clean.
//
// That workflow only runs on GitHub. These node --test tests are the local, deterministic
// guard that:
//
//   (A) the new FIXTURE actually produces the exit code / SARIF shape the workflow asserts,
//       run through the SAME runAction() the action uses - so a weakened fixture (e.g. the
//       vacuous-Deny file "fixed" into a clean policy) fails HERE, in the fast suite, instead
//       of silently making the workflow's assertions vacuous; and
//   (B) the workflow file still ENCODES each runner case with its load-bearing, adversarial
//       assertion (exit 3 / non-clean / explicitly not-0). "green-skips were the original bug
//       class": a text guard so a runner case cannot be quietly deleted or turned into a
//       no-op that stays green.
//
// The fixtures + workflow live at the REPO ROOT (three levels up from this test).

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  readFileSync, mkdtempSync, writeFileSync, rmSync, copyFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runAction, EXIT } from '../../../action/index.mjs';

const ACTION_PATH = fileURLToPath(new URL('../../../action/index.mjs', import.meta.url));

const FIXTURE_DIR = new URL('../../../.github/action-selftest-fixtures/', import.meta.url);
const WORKFLOW_URL = new URL('../../../.github/workflows/action-selftest.yml', import.meta.url);

function fixture(name) {
  return readFileSync(fileURLToPath(new URL(name, FIXTURE_DIR)), 'utf8');
}

function workflow() {
  return readFileSync(fileURLToPath(WORKFLOW_URL), 'utf8');
}

const VACUOUS = 'vacuous-notresource-deny.json';

function sarifResults(r) {
  return r.sarifLog.runs.flatMap((run) => run.results || []);
}

// An in-memory IO surface backed by the REAL fixture contents on disk, keyed by the
// exact cwd-relative path the workflow passes as `paths`.
function ioForFixture(rel, name) {
  const text = fixture(name);
  return {
    listFiles: () => [rel],
    readFile: (p) => {
      if (p === rel) return text;
      const e = new Error(`ENOENT: ${p}`);
      e.code = 'ENOENT';
      throw e;
    },
  };
}

function envFor({ paths, family, failOn = 'high' }) {
  const env = { 'INPUT_FAIL-ON': failOn };
  if (paths !== undefined) env.INPUT_PATHS = paths;
  if (family !== undefined) env.INPUT_FAMILY = family;
  return env;
}

// ============================================================================
// (A) The vacuous-NotResource-Deny fixture behaves as the runner case asserts
// ============================================================================

test('vacuous-NotResource-Deny fixture: NON-clean with a REAL finding (exit 1, complete, DATA-EXFIL) - R1', () => {
  const path = '.github/action-selftest-fixtures/vacuous-notresource-deny.json';
  const r = runAction({ env: envFor({ paths: path, family: 'identity' }), io: ioForFixture(path, VACUOUS) });

  // The whole point of R1: a vacuous Deny (NotResource arn:aws:s3:::*/* = denies nothing)
  // must NOT suppress DATA-EXFIL. It must read NON-clean.
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a vacuous Deny must never let the exfil primitive read clean');
  // ...and specifically as a REAL finding (exit 1 / status complete), NOT a fail-closed
  // analyzer-state (exit 3 / failed). This is why the runner case asserts analysis
  // OUTPUT + STATUS, not merely a non-zero code.
  assert.equal(r.exitCode, EXIT.FINDINGS, 'a vacuous Deny surfaces DATA-EXFIL as a finding (exit 1)');
  assert.equal(r.analysisStatus, 'complete', 'the analysis actually COMPLETED (distinguishes it from malformed=failed)');
  assert.ok(r.blockingCount >= 1, 'the DATA-EXFIL finding blocks at the high threshold');

  const security = sarifResults(r).filter(
    (res) => res.ruleId === 'DATA-EXFIL' && res.properties && res.properties.category === 'security',
  );
  assert.ok(security.length >= 1, 'SARIF must carry a real DATA-EXFIL security result');
  // It is a real security finding, NOT an analysis-state / could-not-analyze result.
  const asState = sarifResults(r).filter(
    (res) => res.properties && res.properties.category === 'analysis-state',
  );
  assert.equal(asState.length, 0, 'a vacuous Deny is a real finding, never a could-not-analyze analyzer-state');
});

test('vacuous-NotResource-Deny fixture: REAL spawned action + REAL SARIF bytes -> exit 1, complete, DATA-EXFIL security result', () => {
  // The runner case runs the action inside the runner and reads the SARIF FILE it writes.
  // Exercise that exact boundary here: spawn `node action/index.mjs` against a staged
  // on-disk workspace holding the real fixture, and assert the real exit code + the real
  // SARIF bytes / GITHUB_OUTPUT the runner would inspect - not just an in-process result.
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-r4-vacuous-ws-'));
  const outDir = mkdtempSync(path.join(tmpdir(), 'ibr-r4-vacuous-out-'));
  const outFile = path.join(outDir, 'out');
  writeFileSync(outFile, '');
  try {
    copyFileSync(fileURLToPath(new URL(VACUOUS, FIXTURE_DIR)), path.join(ws, 'vacuous.json'));
    const env = { ...process.env };
    for (const k of Object.keys(env)) {
      if (k.startsWith('INPUT_') || k.startsWith('GITHUB_') || k.startsWith('IAM_BR_')) delete env[k];
    }
    env.GITHUB_WORKSPACE = ws;
    env.GITHUB_OUTPUT = outFile;
    env.INPUT_PATHS = '**/*.json';
    env.INPUT_FAMILY = 'identity';

    const p = spawnSync('node', [ACTION_PATH], { cwd: ws, env, encoding: 'utf8' });
    assert.equal(p.status, 1, 'a vacuous Deny must fail the check with a real finding (exit 1), never a clean exit 0');

    const sarif = JSON.parse(readFileSync(path.join(ws, 'iam-blast-radius.sarif'), 'utf8'));
    const results = sarif.runs.flatMap((run) => run.results || []);
    const security = results.filter(
      (res) => res.ruleId === 'DATA-EXFIL' && res.properties && res.properties.category === 'security',
    );
    assert.ok(security.length >= 1, 'the SARIF file the runner reads must carry a real DATA-EXFIL security result');
    const asState = results.filter((res) => res.properties && res.properties.category === 'analysis-state');
    assert.equal(asState.length, 0, 'never a could-not-analyze analyzer-state (this is a real finding)');

    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /exit-code=1/, 'GITHUB_OUTPUT exit-code must be 1 (real finding)');
    assert.match(outputs, /analysis-status=complete/, 'GITHUB_OUTPUT analysis-status must be complete');
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

test('vacuous-NotResource-Deny fixture: is valid JSON (guards against a silent "fix" into a clean policy)', () => {
  // If someone rewrites this fixture into an effectively-safe policy, the R1 runner case
  // stops exercising the vacuous-Deny fail-open. Keep it honest: it must parse AND still
  // carry the broad Allow + vacuous NotResource Deny shape.
  const parsed = JSON.parse(fixture(VACUOUS));
  const stmts = parsed.Statement;
  assert.ok(Array.isArray(stmts) && stmts.length === 2, 'fixture must keep its Allow + Deny shape');
  const allow = stmts.find((s) => s.Effect === 'Allow');
  const deny = stmts.find((s) => s.Effect === 'Deny');
  assert.ok(allow && allow.Resource === '*', 'the broad exfil Allow (Resource:*) must survive');
  assert.ok(deny && typeof deny.NotResource === 'string' && deny.NotResource.includes('*'),
    'the vacuous NotResource Deny must survive');
});

// ============================================================================
// (B) The workflow encodes every new runner case with its adversarial assertion
// ============================================================================

test('workflow: runner case - SYMLINKED entrypoint (bin-shim/npx shape), analysis ran + non-zero', () => {
  const wf = workflow();
  // A DIRECT symlinked launch (the action is normally `uses: ./`, a real path), so the
  // case must invoke node through a symlink and prove analysis RAN (a real rule id) rather
  // than a zero-analysis false-clean exit 0.
  assert.match(wf, /ln -s/, 'the symlink case must create a symlink to model the bin-shim/npx launch');
  assert.match(wf, /IAM Blast Radius|action\/index\.mjs/, 'the symlink case must launch the action module directly');
  assert.match(wf, /DIRECT-IAM-ADMIN/, 'the symlink case must prove analysis RAN via a real finding rule id');
});

test('workflow: runner case - chmod-000 UNREADABLE subtree fails CLOSED (exit 3), never exit 0 complete', () => {
  const wf = workflow();
  assert.match(wf, /chmod 000/, 'the unreadable-subtree case must chmod 000 a directory');
  assert.match(wf, /ENUMERATION_UNREADABLE/, 'it must assert the ENUMERATION_UNREADABLE analyzer-state');
});

test('workflow: runner case - MAX_FILES truncation via the real IAM_BR_ENUM_MAX_FILES hook -> exit 3', () => {
  const wf = workflow();
  // Must use the REAL production env hook, not a test-only divergence.
  assert.match(wf, /IAM_BR_ENUM_MAX_FILES/, 'the truncation case must drive the real IAM_BR_ENUM_MAX_FILES hook');
  assert.match(wf, /ENUMERATION_TRUNCATED/, 'it must assert the ENUMERATION_TRUNCATED analyzer-state');
});

test('workflow: runner case - R6 directory-cap trip via the real IAM_BR_ENUM_MAX_DIRS hook -> exit 3', () => {
  const wf = workflow();
  assert.match(wf, /IAM_BR_ENUM_MAX_DIRS/, 'the dir-cap case must drive the real IAM_BR_ENUM_MAX_DIRS hook');
});

test('workflow: runner case - vacuous NotResource Deny is NON-clean with a REAL DATA-EXFIL finding (R1)', () => {
  const wf = workflow();
  assert.match(wf, /action-selftest-fixtures\/vacuous-notresource-deny\.json/,
    'the R1 case must reference the vacuous-NotResource-Deny fixture');
  assert.match(wf, /DATA-EXFIL/, 'the R1 case must assert the real DATA-EXFIL rule id (analysis output, not just non-zero)');
  // It asserts real analysis STATUS (complete) - distinguishing a real finding from a
  // fail-closed could-not-analyze - not merely a non-zero exit.
  assert.match(wf, /analysis-status.*complete|STATUS.*=.*"complete"/,
    'the R1 case must assert analysis-status complete (real finding, not a fail-closed state)');
});

test('workflow: every new runner case asserts fail-closed exit 3 OR the non-clean R1 finding (no green-skip)', () => {
  const wf = workflow();
  // The four enumeration/entrypoint classes fail closed (or fail with findings); each must
  // explicitly reject a collapse to exit 0. Count the "!= \"0\"" fail-open guards: the
  // pre-existing malformed case has one, plus one per new fail-open runner case (symlink,
  // unreadable, max-files, dir-cap, vacuous) = at least 6.
  const notZeroGuards = wf.match(/!=\s*"0"/g) || [];
  assert.ok(notZeroGuards.length >= 6,
    `expected >=6 explicit not-0 fail-open guards (malformed + 5 new runner cases), found ${notZeroGuards.length}`);
  // The three fail-closed enumeration/permission cases each assert exit 3.
  const exit3 = wf.match(/=\s*"3"/g) || [];
  assert.ok(exit3.length >= 4,
    `expected >=4 exit-code==3 assertions (malformed + chmod-000 + max-files + dir-cap), found ${exit3.length}`);
});
