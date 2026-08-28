// Regression tests for STORY S3-readfilecap-special (threat-model T5, availability).
//
// The standalone CLI positional path reaches readFileCapped, which previously derived its
// MAX_BYTES cap SOLELY from statSync(path).size and then unconditionally readFileSync'd,
// with no type guard. statSync FOLLOWS symlinks and reports size 0 for char/block devices,
// FIFOs, and /proc entries, so a zero-size special file (/dev/zero) - or a symlink to one -
// passed the size pre-guard and was then read UNBOUNDED. A never-EOF source (/dev/zero,
// or a FIFO with no writer) HANGS the process, and --budget-ms only wraps analyze(), not
// the read. (This is CLI-only: the Action's walkFiles skips symlinks + non-regular files,
// and git cannot commit device/FIFO nodes, so it is not Marketplace-reachable.)
//
// The fix, pinned here:
//   1. readFileCapped lstatSyncs the path (does NOT follow the link) and REJECTS anything
//      that is not a regular file (a char/block device, FIFO, socket, directory, or a
//      symlink) as could-not-read (tagged NON_REGULAR_FILE), WITHOUT opening/reading it -
//      so a never-EOF special file can never hang the read.
//   2. The read itself is bounded (open + read at most MAX_BYTES+1 bytes) so a regular
//      file cannot materialize beyond MAX_BYTES mid-read.
//   3. A normal file still reads; an oversized regular file is still rejected.
//   4. Through run(), a special-file path is a could-not-read usage error (exit 2), never
//      a hang and never a clean/exit-0 pass.

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, symlinkSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { run, EXIT, readFileCapped } from '../../../cli/iam-br.mjs';
import { LIMITS } from '../../../content/tools/iam-blast-radius/engine/validate.js';

const MAX = LIMITS.MAX_BYTES;
const SHORT = 4000; // per-test timeout: a hang (the pre-fix bug) fails LOUDLY, never stalls CI.

const VALID_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' }],
});

// /dev/zero is a never-EOF char device present on every POSIX box in this suite's CI.
const DEV_ZERO = '/dev/zero';
const HAVE_DEV_ZERO = existsSync(DEV_ZERO);

function withTempDir(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'iam-br-special-'));
  try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

// =============================================================================
// 1. A char device (/dev/zero) is REJECTED, not read - and does NOT hang.
// =============================================================================

test('readFileCapped REJECTS /dev/zero as non-regular WITHOUT hanging', { timeout: SHORT }, () => {
  if (!HAVE_DEV_ZERO) return; // environment without /dev/zero: skip (still green elsewhere)
  assert.throws(
    () => readFileCapped(DEV_ZERO),
    (e) => e && e.code === 'NON_REGULAR_FILE',
    'a char device must be rejected as NON_REGULAR_FILE, never read unbounded',
  );
});

// =============================================================================
// 2. A SYMLINK to /dev/zero is REJECTED (lstat does not follow the link).
// =============================================================================

test('readFileCapped REJECTS a symlink to /dev/zero WITHOUT hanging', { timeout: SHORT }, () => {
  if (!HAVE_DEV_ZERO) return;
  withTempDir((dir) => {
    const link = join(dir, 'zero-link');
    symlinkSync(DEV_ZERO, link);
    assert.throws(
      () => readFileCapped(link),
      (e) => e && e.code === 'NON_REGULAR_FILE',
      'a symlink (even to a device) is not a regular file: reject via lstat, never follow',
    );
  });
});

// =============================================================================
// 3. A FIFO with no writer is REJECTED (would BLOCK on open without the type guard).
// =============================================================================

test('readFileCapped REJECTS a FIFO WITHOUT hanging (no writer attached)', { timeout: SHORT }, () => {
  withTempDir((dir) => {
    const fifo = join(dir, 'pipe');
    try {
      execFileSync('mkfifo', [fifo]); // POSIX; if unavailable, skip below
    } catch {
      return; // mkfifo not available -> skip (the /dev/zero cases still cover the class)
    }
    // Without the lstat type guard, openSync/readFileSync on a writerless FIFO BLOCKS
    // forever; the guard rejects it BEFORE any open, so this returns immediately.
    assert.throws(
      () => readFileCapped(fifo),
      (e) => e && e.code === 'NON_REGULAR_FILE',
      'a FIFO must be rejected as non-regular before any (blocking) open',
    );
  });
});

// =============================================================================
// 4. A DIRECTORY is rejected as non-regular (not an unbounded read, but not readable).
// =============================================================================

test('readFileCapped REJECTS a directory as non-regular', { timeout: SHORT }, () => {
  withTempDir((dir) => {
    assert.throws(
      () => readFileCapped(dir),
      (e) => e && e.code === 'NON_REGULAR_FILE',
    );
  });
});

// =============================================================================
// 5. A NORMAL regular file still reads (no over-correction into a false positive).
// =============================================================================

test('readFileCapped still reads a normal at/under-cap regular file', { timeout: SHORT }, () => {
  withTempDir((dir) => {
    const ok = join(dir, 'policy.json');
    writeFileSync(ok, VALID_POLICY);
    assert.equal(readFileCapped(ok), VALID_POLICY);
  });
});

test('readFileCapped reads a file whose size is EXACTLY the cap (boundary, no false trip)', { timeout: SHORT }, () => {
  withTempDir((dir) => {
    const atCap = join(dir, 'atcap.bin');
    writeFileSync(atCap, Buffer.alloc(MAX, 0x78)); // exactly MAX bytes -> must read
    const out = readFileCapped(atCap);
    assert.equal(out.length, MAX);
  });
});

// =============================================================================
// 6. An OVERSIZED regular file is still rejected (the cap is preserved).
// =============================================================================

test('readFileCapped still REJECTS an oversized regular file (INPUT_TOO_LARGE)', { timeout: SHORT }, () => {
  withTempDir((dir) => {
    const big = join(dir, 'big.bin');
    writeFileSync(big, Buffer.alloc(MAX + 1, 0x78)); // one byte over the cap
    assert.throws(
      () => readFileCapped(big),
      (e) => e && e.code === 'INPUT_TOO_LARGE',
    );
  });
});

// =============================================================================
// 7. Through run(): a special-file path is a could-not-read usage error (exit 2),
//    never a hang, never a clean/exit-0 pass.
// =============================================================================

test('run(): a /dev/zero positional path is exit 2 (could-not-read), never clean, never hangs', { timeout: SHORT }, async () => {
  if (!HAVE_DEV_ZERO) return;
  const out = [];
  const io = {
    // main() wires readFile -> readFileCapped; mirror that here so the type guard runs.
    readFile: (p) => readFileCapped(p),
    readStdin: async () => '',
    stdout: (s) => out.push(s),
    stderr: () => {},
    stdinIsTTY: true,
  };
  const code = await run(['--family', 'identity', DEV_ZERO], io);
  assert.equal(code, EXIT.USAGE, 'a non-regular file is a could-not-read usage error (exit 2)');
  assert.notEqual(code, EXIT.CLEAN, 'a special file must NEVER report clean/exit 0');
  assert.equal(out.join(''), '', 'no stdout report is emitted for a could-not-read input');
});

test('run(): a FIFO positional path is exit 2, never a hang, never clean', { timeout: SHORT }, async () => {
  await withTempDirAsync(async (dir) => {
    const fifo = join(dir, 'pipe');
    try {
      execFileSync('mkfifo', [fifo]);
    } catch {
      return; // mkfifo unavailable -> skip
    }
    const io = {
      readFile: (p) => readFileCapped(p),
      readStdin: async () => '',
      stdout: () => {},
      stderr: () => {},
      stdinIsTTY: true,
    };
    const code = await run(['--family', 'identity', fifo], io);
    assert.equal(code, EXIT.USAGE);
  });
});

async function withTempDirAsync(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'iam-br-special-'));
  try { return await fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}
