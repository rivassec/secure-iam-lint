// S2-action-enumeration: REAL-FILESYSTEM enumeration fail-open regressions.
//
// walkFiles() had TWO ways to silently drop candidate policy files from the aggregate,
// each reproduced by the audit:
//
//   (A) HIGH candidate-drop: `readdirSync(...)` was wrapped in `try { } catch { continue }`,
//       so an UNREADABLE subdirectory (chmod 000, or an I/O error) had its ENTIRE subtree
//       skipped with ZERO bookkeeping. A chmod-000 subdir holding an `Action:*/Resource:*`
//       admin policy made the Action exit 0 / findings 0 / analysis-status=complete - the
//       admin policy was never analyzed yet GITHUB_OUTPUT reported a clean, complete run.
//
//   (B) LOW candidate-drop: the defensive MAX_FILES enumeration ceiling returned early with
//       NO fail-closed signal, so a truncated walk (an unknown set of files past the ceiling
//       never enumerated) could still report a clean/complete aggregate.
//
// The fix MIRRORS the S1 symlink-exclusion machinery: walkFiles RECORDS each unreadable
// directory and sets a `truncated` flag; runAction synthesizes fail-closed (exit 3)
// 'incomplete' analyzer-state units - ENUMERATION_UNREADABLE for an unreadable subtree a
// scan pattern could descend into, ENUMERATION_TRUNCATED for a cut-short walk - so the run
// can NEVER report a green aggregate when a subtree was skipped or enumeration was cut short.
//
// These tests drive the REAL main() code path (real fs, real walkFiles, real io) against a
// REAL on-disk chmod-000 directory and a REAL truncated walk - NOT a mocked listFiles - so
// they pin the actual enumeration behavior the audit reproduced.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync, readdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  main, EXIT,
  matchedUnreadableDirs,
  ENUMERATION_UNREADABLE_REASON, ENUMERATION_TRUNCATED_REASON,
} from '../../../action/index.mjs';

const CLEAN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow',
    Action: 'ec2:DescribeInstances',
    Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc',
  }],
});

// A permissive policy the fork PR wants smuggled in behind an unreadable directory (iam:* on
// *). It must NEVER be analyzed here (the directory holding it is unreadable); the point is
// that its subtree is dropped yet the run still fails closed instead of reporting a green pass.
const ADMIN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
});

// Save/restore the exact process globals main() reads and mutates, so tests do not leak.
function withProcess(envPatch, fn) {
  const savedEnv = { ...process.env };
  const savedExit = process.exitCode;
  for (const k of Object.keys(process.env)) {
    if (k.startsWith('INPUT_') || k.startsWith('GITHUB_') || k.startsWith('IAM_BR_')) {
      delete process.env[k];
    }
  }
  Object.assign(process.env, envPatch);
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      for (const k of Object.keys(process.env)) {
        if (k.startsWith('INPUT_') || k.startsWith('GITHUB_') || k.startsWith('IAM_BR_')) {
          delete process.env[k];
        }
      }
      Object.assign(process.env, savedEnv);
      process.exitCode = savedExit;
    });
}

function makeWorkspace() {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-enum-ws-'));
  const outFile = path.join(ws, '.gh_output');
  writeFileSync(outFile, '');
  return { ws, outFile };
}

function readSarif(ws) {
  return JSON.parse(readFileSync(path.join(ws, 'iam-blast-radius.sarif'), 'utf8'));
}

// Does the aggregate SARIF carry an analysis-state result whose code contains `token`?
function sarifHasEnumState(sarif, token) {
  for (const run of sarif.runs || []) {
    for (const res of run.results || []) {
      const props = res.properties || {};
      if (props.category === 'analysis-state' && props.analysisState === 'incomplete'
        && JSON.stringify(res).includes(token)) return true;
    }
  }
  return false;
}

// chmod-000 is only a real EACCES for a NON-root owner. Under root (some CI containers) the
// directory stays readable, so the reproduction cannot be staged - skip rather than false-pass.
function unreadableDirIsEnforceable(ws) {
  const probe = path.join(ws, '.__probe_unreadable__');
  mkdirSync(probe);
  writeFileSync(path.join(probe, 'x.json'), '{}');
  chmodSync(probe, 0o000);
  let enforced = false;
  try {
    readdirSync(probe);
  } catch {
    enforced = true;
  }
  chmodSync(probe, 0o755);
  rmSync(probe, { recursive: true, force: true });
  return enforced;
}

// --- (A) HIGH: an unreadable subtree a scan pattern could descend into --------

test('REPRODUCTION (A): a chmod-000 subdir hiding an admin policy -> run FAILS CLOSED (exit 3, incomplete), NOT exit 0 complete', async () => {
  const { ws, outFile } = makeWorkspace();
  try {
    if (!unreadableDirIsEnforceable(ws)) return; // running as root: cannot stage EACCES

    // A benign real policy that analyzes clean on its own.
    writeFileSync(path.join(ws, 'clean.json'), CLEAN_IDENTITY);
    // The admin policy lives inside a directory that becomes UNREADABLE, so its whole
    // subtree is invisible to enumeration - the exact candidate-drop the audit reproduced.
    const secret = path.join(ws, 'secret');
    mkdirSync(secret);
    writeFileSync(path.join(secret, 'danger.json'), ADMIN_IDENTITY);
    chmodSync(secret, 0o000);

    let code;
    try {
      code = await withProcess({
        GITHUB_WORKSPACE: ws,
        GITHUB_OUTPUT: outFile,
        INPUT_PATHS: '**/*.json',
        INPUT_FAMILY: 'identity',
        INPUT_FAIL_ON: 'high',
      }, () => main());
    } finally {
      chmodSync(secret, 0o755); // restore so rmSync can clean up
    }

    // FAIL CLOSED: an unreadable subtree the glob could match into can never be a clean pass.
    assert.equal(code, EXIT.FAIL_CLOSED, 'must fail closed to exit 3, not report exit 0');

    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /exit-code=3/, 'exit-code output must be 3');
    assert.match(outputs, /analysis-status=partial/, 'analysis-status must be partial (INCOMPLETE), never complete');

    assert.equal(
      sarifHasEnumState(readSarif(ws), ENUMERATION_UNREADABLE_REASON), true,
      'SARIF must carry an ENUMERATION_UNREADABLE analyzer-state',
    );
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});

test('an unreadable subdir UNRELATED to the scan glob does NOT false-fail (exit 0 clean)', async () => {
  const { ws, outFile } = makeWorkspace();
  try {
    if (!unreadableDirIsEnforceable(ws)) return;

    mkdirSync(path.join(ws, 'policies'));
    writeFileSync(path.join(ws, 'policies', 'ok.json'), CLEAN_IDENTITY);
    // `vendor` is unreadable but the rooted glob `policies/**/*.json` can never descend into
    // it, so nothing selectable was dropped -> must not fail the clean run.
    const vendor = path.join(ws, 'vendor');
    mkdirSync(vendor);
    writeFileSync(path.join(vendor, 'whatever.json'), ADMIN_IDENTITY);
    chmodSync(vendor, 0o000);

    let code;
    try {
      code = await withProcess({
        GITHUB_WORKSPACE: ws,
        GITHUB_OUTPUT: outFile,
        INPUT_PATHS: 'policies/**/*.json',
        INPUT_FAMILY: 'identity',
      }, () => main());
    } finally {
      chmodSync(vendor, 0o755);
    }

    assert.equal(code, EXIT.CLEAN, 'an unrelated unreadable dir must not fail the clean run');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /analysis-status=complete/, 'a run with only an unrelated unreadable dir stays complete');
    assert.equal(sarifHasEnumState(readSarif(ws), ENUMERATION_UNREADABLE_REASON), false,
      'no ENUMERATION_UNREADABLE state for an unrelated unreadable dir');
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});

// --- (B) LOW: a MAX_FILES-truncated walk ------------------------------------------

test('REPRODUCTION (B): a truncated enumeration (MAX_FILES ceiling hit) -> run FAILS CLOSED (exit 3), never a clean/complete pass', async () => {
  const { ws, outFile } = makeWorkspace();
  try {
    // More files than the (test-lowered) enumeration ceiling: the walk stops early, so an
    // unknown set of files is never enumerated. Every file is individually clean; the ONLY
    // thing that must fail the run is the truncation itself.
    for (let i = 0; i < 6; i++) {
      writeFileSync(path.join(ws, `p${i}.json`), CLEAN_IDENTITY);
    }

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: '**/*.json',
      INPUT_FAMILY: 'identity',
      IAM_BR_ENUM_MAX_FILES: '2', // lower the defensive enumeration bound to force truncation
    }, () => main());

    assert.equal(code, EXIT.FAIL_CLOSED, 'a truncated walk must fail closed to exit 3, not a clean pass');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /exit-code=3/, 'exit-code output must be 3');
    assert.match(outputs, /analysis-status=partial/, 'analysis-status must be partial (INCOMPLETE), never complete');
    assert.equal(
      sarifHasEnumState(readSarif(ws), ENUMERATION_TRUNCATED_REASON), true,
      'SARIF must carry an ENUMERATION_TRUNCATED analyzer-state',
    );
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});

// --- (B) BOUNDARY: the MAX_FILES truncation guard is exact (no off-by-one) ---------
//
// The guard must signal ENUMERATION_TRUNCATED only when a file BEYOND the ceiling actually
// exists. A tree of EXACTLY ceiling files is fully enumerated (nothing dropped) and MUST exit
// 0 complete; the (ceiling+1)-th file is the first true overflow and MUST fail closed.
//
// The walked tree must hold a PRECISE file count, so GITHUB_OUTPUT is placed OUTSIDE the
// workspace here (the default makeWorkspace() writes .gh_output INSIDE ws, which would add one
// to the count walkFiles sees). The workspace then contains exactly the N policy files created.
function makeBoundaryWorkspace() {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-enum-bws-'));
  const outDir = mkdtempSync(path.join(tmpdir(), 'ibr-enum-bout-'));
  const outFile = path.join(outDir, 'gh_output');
  writeFileSync(outFile, '');
  return { ws, outDir, outFile };
}

test('BOUNDARY: files == ceiling is fully enumerated -> exit 0 complete, NOT truncated', async () => {
  const { ws, outDir, outFile } = makeBoundaryWorkspace();
  try {
    const CEILING = 3;
    for (let i = 0; i < CEILING; i++) { // exactly CEILING files, nothing beyond
      writeFileSync(path.join(ws, `p${i}.json`), CLEAN_IDENTITY);
    }

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: '**/*.json',
      INPUT_FAMILY: 'identity',
      IAM_BR_ENUM_MAX_FILES: String(CEILING),
    }, () => main());

    assert.equal(code, EXIT.CLEAN, 'a tree of exactly MAX_FILES fully-enumerated files must exit 0');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /analysis-status=complete/, 'files == ceiling stays complete (nothing was dropped)');
    assert.equal(
      sarifHasEnumState(readSarif(ws), ENUMERATION_TRUNCATED_REASON), false,
      'files == ceiling must NOT carry an ENUMERATION_TRUNCATED state (off-by-one regression)',
    );
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

test('BOUNDARY: files == ceiling+1 genuinely overflows -> exit 3 ENUMERATION_TRUNCATED', async () => {
  const { ws, outDir, outFile } = makeBoundaryWorkspace();
  try {
    const CEILING = 3;
    for (let i = 0; i < CEILING + 1; i++) { // one file BEYOND the ceiling -> true truncation
      writeFileSync(path.join(ws, `p${i}.json`), CLEAN_IDENTITY);
    }

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: '**/*.json',
      INPUT_FAMILY: 'identity',
      IAM_BR_ENUM_MAX_FILES: String(CEILING),
    }, () => main());

    assert.equal(code, EXIT.FAIL_CLOSED, 'a file beyond the ceiling must fail closed to exit 3');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /exit-code=3/, 'exit-code output must be 3');
    assert.match(outputs, /analysis-status=partial/, 'analysis-status must be partial (INCOMPLETE)');
    assert.equal(
      sarifHasEnumState(readSarif(ws), ENUMERATION_TRUNCATED_REASON), true,
      'files == ceiling+1 must carry an ENUMERATION_TRUNCATED analyzer-state',
    );
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

// --- S4-R6-dirbomb: a DIRECTORY-count ceiling (deep+wide, few files) ---------------
//
// The file/symlink ceilings charge out.length / excludedSymlinks.length only. A tree of MANY
// directories but FEW files (the classic "dir bomb": N chains each modestly deep) does one
// readdir per directory yet never trips those file-count ceilings, so pre-fix the walk ran
// unbounded. walkFiles now also charges a CUMULATIVE directories-visited counter against
// IAM_BR_ENUM_MAX_DIRS; hitting it sets the SAME `truncated` flag, so runAction synthesizes the
// exit-3 ENUMERATION_TRUNCATED fail-closed unit - never a silent unbounded walk / clean pass.
//
// These drive the REAL main() code path (real fs, real walkFiles) against a REAL deep+wide
// on-disk tree, exactly the boundary the audit reproduced.

// Build a deep+wide tree: `chains` top-level chains, each `depth` directories deep, with ONE
// clean policy file at the bottom of each chain. Total directories = 1 (root) + chains*depth;
// total files = chains (far below any file ceiling), so ONLY the directory ceiling can fire.
// GITHUB_OUTPUT is placed OUTSIDE the workspace so the walked tree holds a PRECISE dir count.
function makeDirBombWorkspace(chains, depth) {
  const ws = mkdtempSync(path.join(tmpdir(), 'ibr-dirbomb-ws-'));
  const outDir = mkdtempSync(path.join(tmpdir(), 'ibr-dirbomb-out-'));
  const outFile = path.join(outDir, 'gh_output');
  writeFileSync(outFile, '');
  for (let c = 0; c < chains; c++) {
    let cur = ws;
    for (let d = 0; d < depth; d++) { cur = path.join(cur, `c${c}_d${d}`); }
    mkdirSync(cur, { recursive: true });
    writeFileSync(path.join(cur, 'leaf.json'), CLEAN_IDENTITY);
  }
  const dirCount = 1 + chains * depth; // root + every created subdirectory (popped exactly once)
  return { ws, outDir, outFile, dirCount, fileCount: chains };
}

test('REPRODUCTION (dirbomb): a deep+wide many-dir/few-file tree exceeding IAM_BR_ENUM_MAX_DIRS -> exit 3 ENUMERATION_TRUNCATED, never a clean pass', async () => {
  const { ws, outDir, outFile, dirCount, fileCount } = makeDirBombWorkspace(3, 4); // 13 dirs, 3 files
  try {
    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: '**/*.json',
      INPUT_FAMILY: 'identity',
      // Directory ceiling far below the tree's dir count; file ceiling left at its (huge)
      // default so ONLY the directory ceiling can trip - proving files aren't what fails here.
      IAM_BR_ENUM_MAX_DIRS: '5',
    }, () => main());

    assert.ok(dirCount > 5 && fileCount < 200000, 'test tree must overflow dirs but not files');
    assert.equal(code, EXIT.FAIL_CLOSED, 'a dir-count-truncated walk must fail closed to exit 3, not a clean pass');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /exit-code=3/, 'exit-code output must be 3');
    assert.match(outputs, /analysis-status=partial/, 'analysis-status must be partial (INCOMPLETE), never complete');
    assert.equal(
      sarifHasEnumState(readSarif(ws), ENUMERATION_TRUNCATED_REASON), true,
      'SARIF must carry an ENUMERATION_TRUNCATED analyzer-state for a dir-count-truncated walk',
    );
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

test('dirbomb BOUNDARY: dirs == IAM_BR_ENUM_MAX_DIRS is fully enumerated -> exit 0 complete, NOT truncated', async () => {
  const { ws, outDir, outFile, dirCount } = makeDirBombWorkspace(2, 3); // 1 + 2*3 = 7 dirs
  try {
    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: '**/*.json',
      INPUT_FAMILY: 'identity',
      IAM_BR_ENUM_MAX_DIRS: String(dirCount), // exactly at the ceiling -> off-by-one `>` completes
    }, () => main());

    assert.equal(code, EXIT.CLEAN, 'a tree of exactly MAX_DIRS directories must fully enumerate and exit 0');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /analysis-status=complete/, 'dirs == ceiling stays complete (nothing dropped)');
    assert.equal(
      sarifHasEnumState(readSarif(ws), ENUMERATION_TRUNCATED_REASON), false,
      'dirs == ceiling must NOT carry an ENUMERATION_TRUNCATED state (off-by-one regression)',
    );
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

test('dirbomb BOUNDARY: dirs == IAM_BR_ENUM_MAX_DIRS+1 genuinely overflows -> exit 3 ENUMERATION_TRUNCATED', async () => {
  const { ws, outDir, outFile, dirCount } = makeDirBombWorkspace(2, 3); // 7 dirs
  try {
    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: '**/*.json',
      INPUT_FAMILY: 'identity',
      IAM_BR_ENUM_MAX_DIRS: String(dirCount - 1), // one directory beyond the ceiling -> true overflow
    }, () => main());

    assert.equal(code, EXIT.FAIL_CLOSED, 'a directory beyond the ceiling must fail closed to exit 3');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /exit-code=3/, 'exit-code output must be 3');
    assert.match(outputs, /analysis-status=partial/, 'analysis-status must be partial (INCOMPLETE)');
    assert.equal(
      sarifHasEnumState(readSarif(ws), ENUMERATION_TRUNCATED_REASON), true,
      'dirs == ceiling+1 must carry an ENUMERATION_TRUNCATED analyzer-state',
    );
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

test('MUST-NOT-BREAK (dirbomb): a normal deep+wide tree UNDER the dir ceiling is unaffected -> exit 0 complete', async () => {
  const { ws, outDir, outFile, dirCount } = makeDirBombWorkspace(4, 5); // 21 dirs, 4 files
  try {
    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: '**/*.json',
      INPUT_FAMILY: 'identity',
      IAM_BR_ENUM_MAX_DIRS: String(dirCount + 1000), // comfortably above the tree -> no truncation
    }, () => main());

    assert.equal(code, EXIT.CLEAN, 'a readable tree under the dir ceiling must still exit 0');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /analysis-status=complete/, 'a tree under the dir ceiling stays complete');
    assert.equal(
      sarifHasEnumState(readSarif(ws), ENUMERATION_TRUNCATED_REASON), false,
      'a tree under the dir ceiling must NOT carry an ENUMERATION_TRUNCATED state',
    );
  } finally {
    rmSync(ws, { recursive: true, force: true });
    rmSync(outDir, { recursive: true, force: true });
  }
});

// --- MUST-NOT-BREAK: a fully-readable clean tree is unaffected ---------------------

test('MUST-NOT-BREAK: a fully-readable tree of genuinely clean policies still exits 0 complete', async () => {
  const { ws, outFile } = makeWorkspace();
  try {
    mkdirSync(path.join(ws, 'policies'));
    writeFileSync(path.join(ws, 'policies', 'a.json'), CLEAN_IDENTITY);
    writeFileSync(path.join(ws, 'policies', 'b.json'), CLEAN_IDENTITY);
    mkdirSync(path.join(ws, 'policies', 'sub'));
    writeFileSync(path.join(ws, 'policies', 'sub', 'c.json'), CLEAN_IDENTITY);

    const code = await withProcess({
      GITHUB_WORKSPACE: ws,
      GITHUB_OUTPUT: outFile,
      INPUT_PATHS: '**/*.json',
      INPUT_FAMILY: 'identity',
    }, () => main());

    assert.equal(code, EXIT.CLEAN, 'a clean readable tree must still exit 0');
    const outputs = readFileSync(outFile, 'utf8');
    assert.match(outputs, /analysis-status=complete/, 'a clean readable tree stays complete');
    const sarif = readSarif(ws);
    assert.equal(sarifHasEnumState(sarif, ENUMERATION_UNREADABLE_REASON), false);
    assert.equal(sarifHasEnumState(sarif, ENUMERATION_TRUNCATED_REASON), false);
  } finally {
    rmSync(ws, { recursive: true, force: true });
  }
});

// --- Pure matcher precision (mirrors matchedExcludedSymlinks / resolveFiles semantics) ---

test('matchedUnreadableDirs: gates on globCanMatchUnderDir, always flags the workspace root, dedups + sorts', () => {
  const dirs = ['policies', 'policies/sub', 'vendor', 'configs'];
  // Recursive-from-root glob can descend into every dir -> all flagged, sorted.
  assert.deepEqual(
    matchedUnreadableDirs(['**/*.json'], dirs),
    ['configs', 'policies', 'policies/sub', 'vendor'],
  );
  // A rooted glob only descends under its own prefix.
  assert.deepEqual(
    matchedUnreadableDirs(['policies/**/*.json'], dirs),
    ['policies', 'policies/sub'],
  );
  // No pattern can descend into any listed dir -> empty (no false-fail).
  assert.deepEqual(matchedUnreadableDirs(['other/*.json'], dirs), []);
  // The workspace ROOT ('') being unreadable ALWAYS fails closed, regardless of pattern.
  assert.deepEqual(matchedUnreadableDirs(['policies/**/*.json'], ['']), ['']);
  assert.deepEqual(matchedUnreadableDirs(['unrelated/*.yaml'], ['']), ['']);
  // Overlapping patterns dedup.
  assert.deepEqual(
    matchedUnreadableDirs(['policies/**/*.json', 'policies/*.json'], ['policies']),
    ['policies'],
  );
  // No unreadable dirs at all -> empty.
  assert.deepEqual(matchedUnreadableDirs(['**/*.json'], []), []);
  // An over-complex pattern is skipped here (resolveFiles fails it closed to a usage error).
  const longPat = `${'a/'.repeat(3000)}*.json`;
  assert.deepEqual(matchedUnreadableDirs([longPat], ['policies']), []);
});
