// Tests for S5-cli-hardening: confine `iam-br --output` and close the read/write
// FS-oracle (cli/iam-br.mjs).
//
// TWO classes are pinned here, each with the variant spellings enumerated by the
// audit so a patch of one spelling that leaves the class open is caught:
//
//   (1) --output arbitrary-file-write. The bare CLI's base dir is process.cwd().
//       An --output must FAIL CLOSED (exit 2, NO write) when it is:
//         (a) absolute (/etc/x), a Windows drive (C:\x), or a UNC root (\\srv\share),
//         (b) a '..' traversal that escapes cwd (../x, subdir/../../x),
//         (c) a write THROUGH a pre-planted symlinked directory,
//         (d) an already-existing file (no silent clobber).
//       A NORMAL relative path still writes under cwd. An invalid --output must NEVER
//       silently fall back to stdout + exit 0.
//
//   (2) FS-existence oracle on the read path. By default a read failure emits ONE
//       generic, byte-identical message for ENOENT / EISDIR / EACCES / ELOOP / ENOTDIR
//       (no errno, no path); the errno detail appears ONLY under --verbose/--debug.
//
// The lexical + oracle classes are exercised through run(argv, io) with an injected
// I/O surface (fast, deterministic). The symlink-escape, no-overwrite, and normal-
// write cases need a REAL filesystem, so they build a real-fs io over a temp dir and
// also spawn the actual binary (the exact surface the audit drove).

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, realpathSync,
  symlinkSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import {
  run, parseArgs, EXIT, outputIsContained, outputTargetContainedFs,
} from '../../../cli/iam-br.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = join(here, '..', '..', '..', 'cli', 'iam-br.mjs');

const ADMIN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
});

// --- Injected I/O harness (pure; no real filesystem) -------------------------
// `readFile` throws whatever error `readThrow` carries (used for the oracle tests).
function makeIo({ stdin = null, files = {}, readThrow = null, outputTargetContained } = {}) {
  const out = [];
  const err = [];
  const written = {};
  const io = {
    readFile(p) {
      if (readThrow) throw readThrow;
      if (Object.prototype.hasOwnProperty.call(files, p)) return files[p];
      const e = new Error(`ENOENT: no such file '${p}'`);
      e.code = 'ENOENT';
      throw e;
    },
    async readStdin() { return stdin == null ? '' : stdin; },
    writeFile(p, data) { written[p] = data; },
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    stdinIsTTY: stdin == null,
  };
  if (outputTargetContained) io.outputTargetContained = outputTargetContained;
  return { io, stdout: () => out.join(''), stderr: () => err.join(''), written };
}

async function runWith(argv, ioOpts) {
  const h = makeIo(ioOpts);
  const code = await run(argv, h.io);
  return { code, stdout: h.stdout(), stderr: h.stderr(), written: h.written };
}

// --- Real-fs io over an explicit base dir (mirrors main()'s wiring) ----------
function makeRealIo(baseDir, stdin) {
  const err = [];
  const out = [];
  const io = {
    readFile: (p) => readFileSync(p, 'utf8'),
    async readStdin() { return stdin; },
    outputTargetContained: (rel) => outputTargetContainedFs(baseDir, rel),
    writeFile: (p, data) => {
      const abs = resolve(baseDir, p);
      mkdirSync(dirname(abs), { recursive: true });
      writeFileSync(abs, data);
    },
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    stdinIsTTY: false,
  };
  return { io, stdout: () => out.join(''), stderr: () => err.join('') };
}

async function withTempDirs(fn) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'iam-br-s5-base-')));
  const outside = realpathSync(mkdtempSync(join(tmpdir(), 'iam-br-s5-outside-')));
  try {
    return await fn(base, outside);
  } finally {
    rmSync(base, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
}

// =============================================================================
// (1a)+(1b) LEXICAL escapes: absolute / drive / UNC / '..'-traversal / control.
// Rejected up front (exit 2, NO write, stdout empty). parseArgs owns this layer,
// so no real fs is needed.
// =============================================================================

const LEXICAL_ESCAPES = [
  ['..-traversal one level', '../escaped.json'],
  ['..-traversal after subdir', 'subdir/../../escaped2.json'],
  ['POSIX absolute', '/tmp/s5_abs_escape.json'],
  ['POSIX absolute /etc', '/etc/s5_escape.json'],
  ['leading backslash / UNC root', '\\\\server\\share\\x.json'],
  ['Windows drive-absolute', 'C:\\temp\\x.json'],
  ['Windows drive lower-case', 'c:/temp/x.json'],
  ['backslash ..-traversal', '..\\escaped.json'],
  ['control char (NUL)', 'foo\u0000bar.json'],
  ['control char (newline)', 'foo\nbar.json'],
];

for (const [label, badPath] of LEXICAL_ESCAPES) {
  test(`--output ${label} (${JSON.stringify(badPath)}) FAILS CLOSED exit 2, no write, no stdout`, async () => {
    const r = await runWith(['--family', 'identity', '--output', badPath], { stdin: ADMIN_IDENTITY });
    assert.equal(r.code, EXIT.USAGE, 'an out-of-bounds --output must be a usage error, never 0/clean');
    assert.notEqual(r.code, EXIT.CLEAN);
    assert.deepEqual(r.written, {}, 'nothing may be written for a rejected --output');
    assert.equal(r.stdout, '', 'must NOT silently fall back to stdout');
    assert.match(r.stderr, /invalid --output/);
  });
}

test('outputIsContained unit: accepts confined relatives, rejects every escape spelling', () => {
  for (const ok of ['out.json', 'sub/out.json', './out.json', 'a/b/c.json', 'a/../b.json']) {
    assert.equal(outputIsContained(ok), true, `${ok} should be contained`);
  }
  for (const [, bad] of LEXICAL_ESCAPES) {
    assert.equal(outputIsContained(bad), false, `${JSON.stringify(bad)} should be rejected`);
  }
  assert.equal(outputIsContained(''), false);
  assert.equal(outputIsContained(null), false);
});

// =============================================================================
// (1c) SYMLINK-directory escape: a lexically-clean relative path whose leading
// directory is a symlink to an OUTSIDE dir must FAIL CLOSED (exit 2, no write).
// =============================================================================

test('--output THROUGH a symlinked directory FAILS CLOSED exit 2, writes nothing outside', () => withTempDirs((base, outside) => {
  // base/link -> outside ; `--output link/pwned.json` would land in `outside`.
  symlinkSync(outside, join(base, 'link'), 'dir');
  const target = join(outside, 'pwned.json');
  assert.equal(existsSync(target), false, 'precondition: target does not exist');

  const h = makeRealIo(base, ADMIN_IDENTITY);
  return run(['--family', 'identity', '--output', 'link/pwned.json'], h.io).then((code) => {
    assert.equal(code, EXIT.USAGE, 'symlinked-dir escape must be a usage error, never 0/clean');
    assert.equal(existsSync(target), false, 'nothing may be written through the symlink');
    assert.match(h.stderr(), /refusing to write --output/);
  });
}));

test('outputTargetContainedFs unit: rejects a symlinked component, allows a fresh real path', () => withTempDirs((base, outside) => {
  symlinkSync(outside, join(base, 'link'), 'dir');
  assert.equal(outputTargetContainedFs(base, 'link/x.json'), false, 'symlinked dir must be rejected');
  assert.equal(outputTargetContainedFs(base, 'fresh/x.json'), true, 'a brand-new real path is allowed');
  assert.equal(outputTargetContainedFs(base, 'x.json'), true);
  // A base that cannot be resolved fails closed.
  assert.equal(outputTargetContainedFs(join(base, 'does-not-exist'), 'x.json'), false);
}));

// =============================================================================
// (1d) NO OVERWRITE: an existing target is refused (exit 2) and left BYTE-INTACT.
// =============================================================================

test('--output onto an EXISTING file FAILS CLOSED exit 2 and leaves it untouched', () => withTempDirs((base) => {
  const rel = 'existing.json';
  const abs = join(base, rel);
  writeFileSync(abs, 'ORIGINAL-PRECIOUS-CONTENT');

  const h = makeRealIo(base, ADMIN_IDENTITY);
  return run(['--family', 'identity', '--output', rel], h.io).then((code) => {
    assert.equal(code, EXIT.USAGE, 'clobbering an existing file must be refused, never 0/clean');
    assert.equal(readFileSync(abs, 'utf8'), 'ORIGINAL-PRECIOUS-CONTENT', 'the original file must be untouched');
    assert.match(h.stderr(), /refusing to write --output/);
  });
}));

test('outputTargetContainedFs unit: rejects an already-existing target', () => withTempDirs((base) => {
  writeFileSync(join(base, 'existing.json'), 'x');
  assert.equal(outputTargetContainedFs(base, 'existing.json'), false, 'existing file -> no overwrite');
}));

// =============================================================================
// MUST-ALLOW: a normal confined relative path still writes under cwd (exit 1 for
// the admin fixture), stdout stays empty, and the bytes are the formatted report.
// =============================================================================

test('a normal relative --output writes UNDER cwd (exit preserved, stdout empty)', () => withTempDirs((base) => {
  const h = makeRealIo(base, ADMIN_IDENTITY);
  return run(['--family', 'identity', '--output', 'report.json'], h.io).then((code) => {
    assert.equal(code, EXIT.FINDINGS, 'the write path never changes the scan exit code');
    assert.equal(h.stdout(), '', 'stdout is empty when writing to a file');
    const abs = join(base, 'report.json');
    assert.equal(existsSync(abs), true, 'the report was written under cwd');
    const parsed = JSON.parse(readFileSync(abs, 'utf8'));
    assert.equal(parsed.exitCode, 1);
  });
}));

test('a normal relative --output into a NEW subdir writes under cwd (dir is created)', () => withTempDirs((base) => {
  const h = makeRealIo(base, ADMIN_IDENTITY);
  return run(['--family', 'identity', '--output', 'sub/nested/report.json'], h.io).then((code) => {
    assert.equal(code, EXIT.FINDINGS);
    assert.equal(existsSync(join(base, 'sub', 'nested', 'report.json')), true);
  });
}));

// =============================================================================
// (2) FS-existence oracle on the read path: DEFAULT message is byte-identical
// across ENOENT / EISDIR / EACCES / ELOOP / ENOTDIR; errno appears only --verbose.
// =============================================================================

const READ_ERRNO_CLASSES = ['ENOENT', 'EISDIR', 'EACCES', 'ELOOP', 'ENOTDIR'];

test('read-error DEFAULT message is BYTE-IDENTICAL across every errno class (no oracle)', async () => {
  const results = [];
  for (const code of READ_ERRNO_CLASSES) {
    const e = new Error(`${code}: detailed node message with a path /some/where`);
    e.code = code;
    const r = await runWith(['--family', 'identity', 'policy.json'], { readThrow: e });
    results.push(r);
    assert.equal(r.code, EXIT.USAGE, `${code} must be exit 2`);
    assert.equal(r.stdout, '', 'no analysis output for a read error');
  }
  const first = results[0].stderr;
  assert.equal(first, 'iam-br: cannot read policy file (use --verbose for details).\n');
  for (let i = 1; i < results.length; i++) {
    assert.equal(results[i].stderr, first,
      `stderr for ${READ_ERRNO_CLASSES[i]} must be byte-identical to ${READ_ERRNO_CLASSES[0]}`);
  }
  // The generic default must NOT leak any errno string.
  for (const code of READ_ERRNO_CLASSES) {
    assert.doesNotMatch(first, new RegExp(code), `default message must not contain ${code}`);
  }
});

test('--verbose surfaces the errno detail (and only then does the message differ per class)', async () => {
  const enoent = new Error('ENOENT: no such file');
  enoent.code = 'ENOENT';
  const eisdir = new Error('EISDIR: illegal operation on a directory');
  eisdir.code = 'EISDIR';
  const rv1 = await runWith(['--family', 'identity', '--verbose', 'p.json'], { readThrow: enoent });
  const rv2 = await runWith(['--family', 'identity', '--debug', 'p.json'], { readThrow: eisdir });
  assert.equal(rv1.code, EXIT.USAGE);
  assert.equal(rv2.code, EXIT.USAGE);
  assert.match(rv1.stderr, /ENOENT/, '--verbose surfaces the errno');
  assert.match(rv2.stderr, /EISDIR/, '--debug is an alias for --verbose');
  assert.notEqual(rv1.stderr, rv2.stderr, 'the verbose messages legitimately differ per class');
});

test('parseArgs records --verbose and --debug into opts.verbose', () => {
  assert.equal(parseArgs(['--family', 'identity']).opts.verbose, false, 'default OFF');
  assert.equal(parseArgs(['--family', 'identity', '--verbose']).opts.verbose, true);
  assert.equal(parseArgs(['--family', 'identity', '--debug']).opts.verbose, true);
});

// =============================================================================
// E2E: drive the REAL binary from a scratch cwd (the exact surface the audit hit).
// =============================================================================

function spawnCliIn(cwd, args, input) {
  return spawnSync('node', [CLI_PATH, ...args], { cwd, input, encoding: 'utf8' });
}

test('E2E: the real binary rejects absolute/../symlink/overwrite --output and writes nothing out of bounds', () => withTempDirs((base, outside) => {
  // (a) absolute
  const abs = join(outside, 'ESCAPED_ABS.json');
  let p = spawnCliIn(base, ['--family', 'identity', '--output', abs], ADMIN_IDENTITY);
  assert.equal(p.status, 2, 'absolute --output must exit 2');
  assert.equal(existsSync(abs), false, 'no absolute-path write');

  // (b) ../ traversal (relative to cwd=base -> lands in `outside`'s parent chain)
  p = spawnCliIn(base, ['--family', 'identity', '--output', '../ESCAPED_REL.json'], ADMIN_IDENTITY);
  assert.equal(p.status, 2, '../ --output must exit 2');
  assert.equal(existsSync(join(base, '..', 'ESCAPED_REL.json')), false, 'no parent-dir write');

  // (c) symlink-through
  symlinkSync(outside, join(base, 'link'), 'dir');
  p = spawnCliIn(base, ['--family', 'identity', '--output', 'link/pwned.json'], ADMIN_IDENTITY);
  assert.equal(p.status, 2, 'symlinked-dir --output must exit 2');
  assert.equal(existsSync(join(outside, 'pwned.json')), false, 'no write through the symlink');

  // (d) overwrite
  const existing = join(base, 'existing.json');
  writeFileSync(existing, 'ORIGINAL-PRECIOUS-CONTENT');
  p = spawnCliIn(base, ['--family', 'identity', '--output', 'existing.json'], ADMIN_IDENTITY);
  assert.equal(p.status, 2, 'overwrite --output must exit 2');
  assert.equal(readFileSync(existing, 'utf8'), 'ORIGINAL-PRECIOUS-CONTENT', 'existing file untouched');

  // MUST-ALLOW: a normal relative path writes under cwd and preserves the exit code.
  p = spawnCliIn(base, ['--family', 'identity', '--output', 'report.json'], ADMIN_IDENTITY);
  assert.equal(p.status, 1, 'a valid write preserves the findings exit code');
  assert.equal(existsSync(join(base, 'report.json')), true, 'the report is written under cwd');
  assert.equal(p.stdout, '', 'stdout empty when writing to a file');
}));

test('E2E: the real binary read-error message is generic by default, errno only under --verbose', () => withTempDirs((base) => {
  const missing = spawnCliIn(base, ['--family', 'identity', join(base, 'nope.json')], '');
  const dirArg = spawnCliIn(base, ['--family', 'identity', base], ''); // EISDIR
  assert.equal(missing.status, 2);
  assert.equal(dirArg.status, 2);
  assert.equal(missing.stderr, dirArg.stderr, 'default stderr must be identical for ENOENT vs EISDIR');
  assert.doesNotMatch(missing.stderr, /ENOENT|EISDIR/, 'no errno leaks by default');

  const verbose = spawnCliIn(base, ['--family', 'identity', '--verbose', join(base, 'nope.json')], '');
  assert.equal(verbose.status, 2);
  assert.match(verbose.stderr, /ENOENT/, '--verbose surfaces the errno');
}));
