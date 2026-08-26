#!/usr/bin/env node
// IAM Blast Radius - headless CLI (Phase 15, story P15-cli).
//
// A Node-only ADAPTER (a "process face") over the pure `scan()` module, which is
// itself a read-only adapter over the shipped browser engine. This file adds ONLY
// I/O + argv plumbing: it reads a policy (file arg or STDIN), runs `scan()`, writes
// the formatted result (JSON to stdout by default, or SARIF), sends diagnostics to
// STDERR, and returns the load-bearing exit code. It changes NO analysis behavior.
//
// This module is NOT part of the browser-served engine graph. It may use Node
// built-ins, but the engine it imports (transitively via scan.mjs) stays
// browser-safe: nothing here is imported back by content/tools/.../{engine,app,worker}.
//
// EXIT-CODE CONTRACT (the load-bearing invariant, owned by scan.mjs, propagated here
// byte-for-byte and NEVER downgraded by an I/O or formatting concern):
//   0  analyzed, no findings at/above threshold        (analysisStatus complete)
//   1  analyzed, findings at/above threshold           (analysisStatus complete)
//   2  usage/config error (bad/missing --family, bad --format/--threshold, missing
//      or empty input/paths, unreadable file, unknown flag)
//   3  fail-closed could-not-analyze                   (analysisStatus partial|failed)
//   4  internal invariant error (scan returned 4, an out-of-range code, or an
//      unexpected throw anywhere in the pipeline)
// A CI gate treats 1,2,3,4 as FAILED. Code 3 is DISTINCT from 0 and from 1: a
// fail-closed "could not analyze" MUST NEVER collapse to 0/clean. There is NO
// --ignore-unknown flag and NO family auto-detection: a missing --family is exit 2.
//
// The output FORMAT never changes the exit code: a fail-closed run is exit 3 whether
// it is printed as JSON or SARIF.

import { readFileSync, writeFileSync, realpathSync, lstatSync, mkdirSync } from 'node:fs';
import * as nodePath from 'node:path';
import { pathToFileURL } from 'node:url';

import { scan, EXIT, SELECTABLE_FAMILIES, DEFAULT_BUDGET_MS } from './scan.mjs';
// The SARIF 2.1.0 adapter (story P15-sarif): a PURE projection of a scan() result.
// The CLI just picks it when --format sarif; the exit code is unaffected.
import { formatSarif } from './sarif.mjs';
// READ-ONLY: the canonical version manifest (browser-safe, no Node deps). Ties the
// CLI's --version to the same identifiers the engine reports, so they cannot drift.
import { VERSION_MANIFEST } from '../content/tools/iam-blast-radius/engine/version.js';

export { EXIT };
// Re-export the SARIF formatter so existing importers (tests, the Action wrapper)
// can keep importing it from the CLI module even though it now lives in sarif.mjs.
export { formatSarif };

// --- Static option tables -----------------------------------------------------

// Long flags that consume the following token (or an =value) as their value.
const VALUE_FLAGS = Object.freeze(new Set([
  '--family',
  '--subject-account',
  '--partition',
  '--threshold',
  '--format',
  '--output',
  '--artifact-uri',
  '--budget-ms',
]));

// Boolean flags (no value). `-h` is an alias for `--help`. `--debug` is an alias
// for `--verbose` (S5-cli-hardening: gates the errno detail on a read failure).
const BOOLEAN_FLAGS = Object.freeze(new Set(['--version', '--help', '--verbose', '--debug']));

const FORMATS = Object.freeze(new Set(['json', 'sarif']));

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

// --- --output confinement (S5-cli-hardening) ----------------------------------
// The bare CLI has no GITHUB_WORKSPACE, so the base directory is EXPLICITLY the
// process cwd (wired in main()). These mirror the Action's two-layer sarif-output
// guard (action/index.mjs sarifOutputIsContained + sarifTargetContainedFs) so the
// CLI closes the SAME arbitrary-file-write class:
//   (a) LEXICAL (pure string): reject absolute paths (POSIX '/', leading '\', UNC,
//       Windows drive 'C:'), any C0 control char, and any '..' that escapes the base.
//   (b) FILESYSTEM (symlink-aware): a lexically-safe RELATIVE path can still escape
//       if a leading directory component is a SYMLINK to an outside dir, so lstat-walk
//       each existing component and reject any symlink. Additionally REFUSE to
//       overwrite an already-existing target (the story's acceptance list).
// Both layers FAIL CLOSED to a usage error (exit 2) with NO write; an invalid
// --output must NEVER silently fall back to stdout + exit 0.

// (a) Pure lexical containment. Same language as the Action's sarifOutputIsContained.
export function outputIsContained(rel) {
  const s = String(rel == null ? '' : rel);
  if (s === '') return false;
  if (/[\u0000-\u001f]/.test(s)) return false; // any C0 control char (incl. CR/LF/NUL)
  if (s.startsWith('/') || s.startsWith('\\')) return false; // POSIX-absolute / UNC / leading '\'
  if (/^[A-Za-z]:/.test(s)) return false; // Windows drive-absolute (C:...)
  let depth = 0;
  for (const seg of s.split(/[/\\]/)) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      depth -= 1;
      if (depth < 0) return false; // escapes above the base
    } else {
      depth += 1;
    }
  }
  return true;
}

// (b) Filesystem-aware guard. Resolves each existing component of `rel` under
// `baseDir` through lstat and REJECTS if:
//   - the base cannot be realpath-resolved (cannot vouch -> fail closed), or
//   - any path component is a symbolic link (it could escape the base), or
//   - the final target already EXISTS (refuse to clobber an existing file).
// Returns true ONLY when the target does not yet exist and no component is a symlink,
// i.e. it is safe to create a NEW file at a real path inside the base. `rel` is
// assumed to have already passed outputIsContained() (relative, no '..', no controls).
// Uses the module-scoped node:fs / node:path imports directly (browser code never
// imports this file - see the header).
export function outputTargetContainedFs(baseDir, rel) {
  let baseReal;
  try {
    baseReal = realpathSync(baseDir); // resolve the base's own symlinks first
  } catch {
    return false; // cannot vouch for containment -> fail closed
  }
  const parts = String(rel).split(/[/\\]/).filter((p) => p !== '' && p !== '.');
  let cur = baseReal;
  for (let i = 0; i < parts.length; i++) {
    const next = nodePath.join(cur, parts[i]);
    let st;
    try {
      st = lstatSync(next); // lstat: inspect the link itself, never follow it
    } catch {
      // This component does not exist yet. Since `cur` is a real, symlink-free dir
      // inside the base, a new file/dir created here cannot escape, and no deeper
      // component can exist either -> safe to create.
      return true;
    }
    if (st.isSymbolicLink()) return false; // ANY symlink component can escape -> reject
    if (i === parts.length - 1) return false; // final target already exists -> no overwrite
    cur = next; // real intermediate dir confirmed; descend
  }
  return true;
}

// A single, coherent version string from the canonical manifest (no build step;
// what is committed is what runs, architecture invariant 2).
export function versionString(manifest = VERSION_MANIFEST) {
  const m = manifest || {};
  return `iam-br ${m.releaseVersion} (IAM Blast Radius) - rule-catalog ${m.ruleVersion}, ` +
    `action-catalog ${m.actionCatalogVersion}, build ${m.buildSha}`;
}

// The tool's SARIF semanticVersion. Kept as the rule-catalog version (the finding
// contract), distinct from the dated action-catalog snapshot.
function semanticVersion(manifest = VERSION_MANIFEST) {
  return (manifest && manifest.ruleVersion) || '0';
}

export const HELP_TEXT = `iam-br - IAM Blast Radius headless scanner (fail-closed CI gate)

USAGE
  iam-br --family <family> [options] [policy.json]
  cat policy.json | iam-br --family <family> [options]

Reads one AWS IAM policy document from a file argument or, if none is given,
from STDIN. Writes the result to STDOUT (JSON by default) and diagnostics to
STDERR. This tool reports POTENTIAL blast radius from the supplied policy
context; it never claims effective permissions.

REQUIRED
  --family <f>          Policy family. One of:
                          identity | resource | role-trust |
                          permissions-boundary | scp-rcp | session
                        The family is NEVER auto-detected; omitting it is a
                        usage error (exit 2).

OPTIONS
  --subject-account <id>  AWS account id (12 digits) for account-aware checks
                          (e.g. PassRole viability). An invalid id is ignored
                          (the dependent finding stays UNKNOWN and fails closed).
  --partition <p>         AWS partition (aws | aws-us-gov | aws-cn | aws-iso*).
                          When OMITTED the policy is evaluated as 'aws', but any
                          cross-partition role viability that depends on the
                          subject's partition is treated as UNKNOWN and FAILS
                          CLOSED (exit 3). Pass --partition explicitly to assert
                          it. An unrecognized token is treated as omitted.
  --threshold <t>         Minimum severity that COUNTS as a blocking finding:
                          critical | high | medium | low | info | none.
                          Default: high. 'none' only affects the 1-vs-0 decision
                          for a COMPLETE analysis; it can NEVER downgrade a
                          fail-closed exit 3 to 0.
  --format <fmt>          Output format: json | sarif. Default: json. The format
                          never changes the exit code.
  --budget-ms <ms>        Wall-clock budget for analyzing the policy, in
                          milliseconds (default: ${DEFAULT_BUDGET_MS}). If analysis
                          overruns, the scan FAILS CLOSED (exit 3,
                          RESOURCE_BUDGET_EXCEEDED); it never reports a clean pass.
  --output <path>         Write formatted output to <path> instead of STDOUT.
  --artifact-uri <uri>    Location URI recorded in SARIF output for the analyzed
                          policy (default: the file path, or 'stdin').
  --verbose, --debug      Include the underlying errno/detail in read/write error
                          diagnostics. OFF by default so a read failure does NOT
                          reveal whether a path is missing (ENOENT) vs a directory
                          (EISDIR) vs permission-denied (EACCES) - an FS-existence
                          oracle over arbitrary paths.
  --version               Print the version and exit 0.
  --help, -h              Print this help and exit 0.

EXIT CODES (a CI gate treats 1,2,3,4 as FAILED)
  0  analyzed, no findings at/above threshold
  1  analyzed, findings at/above threshold
  2  usage/config error (bad or missing --family, bad flag/value, missing input)
  3  FAIL-CLOSED: could not analyze (unknown/unsupported/malformed/incomplete)
  4  internal invariant error
`;

// --- Argument parsing ---------------------------------------------------------

/**
 * Parse argv (WITHOUT the leading `node script` pair) into options.
 *
 * @param {string[]} argv
 * @returns {{ok:boolean, help?:boolean, version?:boolean,
 *   opts?:object, error?:{reason:string, message:string}}}
 */
export function parseArgs(argv) {
  const args = Array.isArray(argv) ? argv : [];
  const opts = {
    family: undefined,
    subjectAccount: undefined,
    partition: undefined, // undefined => NOT asserted (see scan's fail-closed guard)
    threshold: 'high',
    format: 'json',
    output: undefined,
    artifactUri: undefined,
    budgetMs: DEFAULT_BUDGET_MS,
    file: undefined,
    // S5-cli-hardening: default OFF. When true, read/write error diagnostics may
    // include the underlying errno/detail; when false they stay generic so they do
    // not leak an FS-existence/permission oracle.
    verbose: false,
  };

  let help = false;
  let version = false;
  const positionals = [];

  for (let i = 0; i < args.length; i++) {
    const tok = args[i];
    if (tok === '--') {
      // Everything after `--` is positional.
      for (let j = i + 1; j < args.length; j++) positionals.push(args[j]);
      break;
    }
    if (tok === '-h' || tok === '--help') { help = true; continue; }
    if (tok === '--version') { version = true; continue; }

    if (typeof tok === 'string' && tok.startsWith('--')) {
      // Support --flag=value and --flag value.
      let name = tok;
      let inlineValue;
      const eq = tok.indexOf('=');
      if (eq !== -1) {
        name = tok.slice(0, eq);
        inlineValue = tok.slice(eq + 1);
      }
      if (BOOLEAN_FLAGS.has(name)) {
        if (name === '--help') help = true;
        else if (name === '--version') version = true;
        else if (name === '--verbose' || name === '--debug') opts.verbose = true;
        continue;
      }
      if (!VALUE_FLAGS.has(name)) {
        return usage(`unknown option '${name}'`);
      }
      let value;
      if (inlineValue !== undefined) {
        value = inlineValue;
      } else {
        value = args[++i];
        if (value === undefined) {
          return usage(`option '${name}' requires a value`);
        }
      }
      switch (name) {
        case '--family': opts.family = value; break;
        case '--subject-account': opts.subjectAccount = value; break;
        case '--partition': opts.partition = value; break;
        case '--threshold': opts.threshold = value; break;
        case '--format': opts.format = value; break;
        case '--output': opts.output = value; break;
        case '--artifact-uri': opts.artifactUri = value; break;
        case '--budget-ms': opts.budgetMs = value; break;
        default: return usage(`unknown option '${name}'`);
      }
      continue;
    }
    // A bare token (including '-' for stdin) is positional.
    positionals.push(tok);
  }

  // --version / --help short-circuit everything else (even a missing family).
  if (version) return { ok: true, version: true };
  if (help) return { ok: true, help: true };

  if (positionals.length > 1) {
    // Multi-policy input is deliberately deferred; scanning many files is the
    // Action's job (worst-exit-code aggregation), not this single-doc CLI.
    return usage(
      `expected at most one policy file, got ${positionals.length}. ` +
      'Scan multiple files by invoking iam-br once per file.',
    );
  }
  if (positionals.length === 1 && positionals[0] !== '-') {
    opts.file = positionals[0];
  }

  // Required: --family. NEVER auto-detected -> a missing family is a usage error.
  if (!isNonEmptyString(opts.family)) {
    return usage(
      'the --family option is required and is never auto-detected ' +
      '(identity | resource | role-trust | permissions-boundary | scp-rcp | session)',
    );
  }
  // Validate the family VALUE here too (like --format) so a bad value is a usage
  // error on stderr with no stdout, consistent with a missing family. scan()
  // enforces the same SELECTABLE_FAMILIES set for the programmatic / action path.
  const familyLower = opts.family.trim().toLowerCase();
  if (familyLower === 'auto' || familyLower === 'auto-detect') {
    return usage('family auto-detection is not permitted; select an explicit family '
      + '(identity | resource | role-trust | permissions-boundary | scp-rcp | session)');
  }
  if (!SELECTABLE_FAMILIES.has(familyLower)) {
    return usage(`unknown --family '${opts.family}' `
      + '(expected: identity | resource | role-trust | permissions-boundary | scp-rcp | session)');
  }
  // Format is a CLI-level concern (scan does not see it), so validate it here.
  if (!FORMATS.has(opts.format)) {
    return usage(`unknown --format '${opts.format}' (expected: json | sarif)`);
  }

  // Coerce --budget-ms to a number. Flag values arrive as strings; a non-numeric
  // value is a usage error. The default (DEFAULT_BUDGET_MS) is already a number and
  // passes through. A non-positive value is accepted (it forces an immediate
  // fail-closed abort - useful for a hard "no analysis over N ms" gate / tests).
  if (typeof opts.budgetMs === 'string') {
    const n = Number(opts.budgetMs.trim());
    if (!Number.isFinite(n)) {
      return usage(`invalid --budget-ms '${opts.budgetMs}' (expected a number of milliseconds)`);
    }
    opts.budgetMs = n;
  }

  // S5-cli-hardening: --output must be a CONFINED relative path inside the working
  // directory. Reject absolute paths (POSIX '/', leading '\', UNC, Windows drive
  // 'C:'), any control character, and any '..' that escapes the base - LEXICALLY,
  // up front, as a usage error (exit 2). The symlink-escape / no-overwrite guard is
  // enforced against the real filesystem at write time (run() -> io.outputTargetContained).
  // An invalid --output FAILS CLOSED to exit 2; it never silently falls back to stdout.
  if (opts.output !== undefined && !outputIsContained(opts.output)) {
    return usage(
      `invalid --output '${opts.output}': it must be a relative path inside the working `
      + "directory (no absolute path, no drive/UNC root, no '..' traversal, no control characters)",
    );
  }

  return { ok: true, opts };
}

function usage(message) {
  return { ok: false, error: { reason: 'USAGE', message } };
}

// --- Output formatting --------------------------------------------------------

// A deterministic JSON report envelope. Deliberately does NOT dump the engine's
// full `coverage` object (large + not part of the CLI contract); it surfaces the
// load-bearing verdict fields plus findings and analyzer-states.
export function toJsonReport(result, opts, manifest = VERSION_MANIFEST) {
  const o = opts || {};
  return {
    tool: 'iam-blast-radius',
    version: semanticVersion(manifest),
    family: result.family != null ? result.family : (o.family != null ? o.family : null),
    threshold: o.threshold != null ? o.threshold : 'high',
    // Echo the partition ONLY when the caller asserted one; omission is meaningful
    // (it is what keeps a cross-partition viability question fail-closed).
    partitionAsserted: isNonEmptyString(o.partition) ? o.partition.trim() : null,
    analysisStatus: result.analysisStatus,
    reason: result.reason != null ? result.reason : null,
    exitCode: result.exitCode,
    findingsCount: typeof result.findingsCount === 'number'
      ? result.findingsCount
      : (Array.isArray(result.findings) ? result.findings.length : 0),
    blockingCount: result.blockingCount,
    analysisStates: [...(result.analysisStates || [])],
    findings: [...(result.findings || [])],
  };
}

export function formatJson(result, opts, manifest = VERSION_MANIFEST) {
  return `${JSON.stringify(toJsonReport(result, opts, manifest), null, 2)}\n`;
}

function formatResult(result, opts, manifest) {
  return opts.format === 'sarif'
    ? formatSarif(result, opts, manifest)
    : formatJson(result, opts, manifest);
}

// A short, human-readable diagnostic line for STDERR. Deliberately carries NO
// policy content (threat-model: do not leak ARNs/account ids/policy text into
// logs) - only the verdict metadata.
function diagnosticLine(result) {
  return `iam-br: status=${result.analysisStatus} exit=${result.exitCode} ` +
    `reason=${result.reason} findings=${result.findingsCount} blocking=${result.blockingCount}`;
}

// --- Core run (testable; injectable I/O) --------------------------------------

/**
 * Run the CLI over an injected I/O surface and return the exit code.
 *
 * Never throws: any unexpected error fails CLOSED to exit 4 (never 0). The exit
 * code is derived SOLELY from scan()'s verdict (or a usage/internal condition);
 * output formatting and file writing can never change it.
 *
 * @param {string[]} argv     args without the leading node/script pair
 * @param {object} io
 * @param {(path:string)=>string} io.readFile         read a file to a string (may throw)
 * @param {()=>Promise<string>} io.readStdin          read STDIN to a string
 * @param {(path:string,data:string)=>void} io.writeFile write output to a file
 * @param {(rel:string)=>boolean} [io.outputTargetContained] fs-aware --output guard:
 *   true iff `rel` (already lexically confined) resolves to a NEW file under the base
 *   with no symlink component. Omitted by pure in-memory tests (no filesystem).
 * @param {(s:string)=>void} io.stdout                write to stdout
 * @param {(s:string)=>void} io.stderr                write to stderr
 * @param {boolean} [io.stdinIsTTY]                    true if stdin is an interactive TTY
 * @param {(input:object)=>object} [io.scan]           injectable scan (default: real scan)
 * @param {object} [io.manifest]                       injectable version manifest
 * @returns {Promise<number>} exit code (0..4)
 */
export async function run(argv, io) {
  const out = (io && io.stdout) || (() => {});
  const err = (io && io.stderr) || (() => {});
  const manifest = (io && io.manifest) || VERSION_MANIFEST;
  try {
    const parsed = parseArgs(argv);

    if (parsed.version) { out(`${versionString(manifest)}\n`); return EXIT.CLEAN; }
    if (parsed.help) { out(HELP_TEXT); return EXIT.CLEAN; }
    if (!parsed.ok) {
      err(`iam-br: ${parsed.error.message}\n`);
      err('iam-br: run with --help for usage.\n');
      return EXIT.USAGE;
    }

    const opts = parsed.opts;

    // S5-cli-hardening: confine --output BEFORE doing any work. parseArgs already
    // rejected the LEXICAL escapes (absolute/UNC/drive/'..'/control chars, exit 2).
    // Here the FILESYSTEM-aware guard rejects a symlinked-directory escape and refuses
    // to overwrite an existing file. It runs only when the caller injects a real-fs
    // resolver (main() does; pure in-memory unit tests do not and correctly skip it -
    // there is no filesystem to traverse). A resolver that throws FAILS CLOSED. Both
    // outcomes are a usage error (exit 2) with NO write - never a silent stdout+exit0.
    if (opts.output != null && io && typeof io.outputTargetContained === 'function') {
      let safe;
      try {
        safe = io.outputTargetContained(opts.output) === true;
      } catch {
        safe = false; // cannot vouch for containment -> fail closed
      }
      if (!safe) {
        err(`iam-br: refusing to write --output '${opts.output}': it resolves through a symlink `
          + 'or names an existing file. Choose a NEW relative path inside the working directory.\n');
        err('iam-br: run with --help for usage.\n');
        return EXIT.USAGE;
      }
    }

    // Resolve the policy text: a file argument, else STDIN.
    let text;
    if (opts.file != null) {
      try {
        text = io.readFile(opts.file);
      } catch (e) {
        // A missing or unreadable input path is a usage/config error (exit 2),
        // NOT a clean scan and NOT a fail-closed analysis. The DEFAULT message is
        // deliberately GENERIC (no errno, no path): distinguishing ENOENT / EISDIR /
        // EACCES / ELOOP would be an FS existence/type/permission oracle over
        // arbitrary paths. The errno detail is surfaced ONLY under --verbose/--debug.
        if (opts.verbose) {
          err(`iam-br: cannot read policy file '${opts.file}': ${(e && (e.code || e.message)) || 'error'}\n`);
        } else {
          err('iam-br: cannot read policy file (use --verbose for details).\n');
        }
        return EXIT.USAGE;
      }
    } else {
      if (io.stdinIsTTY) {
        err('iam-br: no policy file given and no data on stdin.\n');
        err('iam-br: pass a file path or pipe a policy in. Run with --help for usage.\n');
        return EXIT.USAGE;
      }
      text = await io.readStdin();
    }

    if (!isNonEmptyString(text)) {
      err('iam-br: empty policy input.\n');
      return EXIT.USAGE;
    }

    // Run the analysis. scan() owns the exit-code contract; the CLI propagates it.
    const scanFn = (io && io.scan) || scan;
    const result = scanFn({
      text,
      family: opts.family,
      subjectAccount: opts.subjectAccount,
      // Pass partition ONLY when explicitly supplied; an omitted partition must
      // stay "not asserted" so a cross-partition viability question fails closed
      // rather than being silently treated as a confident 'aws' assertion.
      partition: opts.partition,
      threshold: opts.threshold,
      // Wall-clock budget (S3-dos-budget): analysis that overruns fails CLOSED
      // (exit 3, RESOURCE_BUDGET_EXCEEDED), never a clean pass.
      budgetMs: opts.budgetMs,
    });

    // Defensive: the code must be an integer in the contract's range. Anything
    // else is an internal invariant violation -> fail closed to 4, NEVER 0.
    const code = (result && Number.isInteger(result.exitCode)) ? result.exitCode : EXIT.INTERNAL;
    if (![EXIT.CLEAN, EXIT.FINDINGS, EXIT.USAGE, EXIT.FAIL_CLOSED, EXIT.INTERNAL].includes(code)) {
      err('iam-br: internal error: scan returned an out-of-range exit code.\n');
      return EXIT.INTERNAL;
    }

    // Format + emit. A formatting/write failure is an internal error (exit 4); it
    // must NEVER downgrade a fail-closed 3 or a findings 1 into a clean 0.
    let formatted;
    try {
      formatted = formatResult(result, opts, manifest);
    } catch (e) {
      err(`iam-br: internal error: failed to format ${opts.format} output: ${(e && e.message) || 'error'}\n`);
      return EXIT.INTERNAL;
    }

    if (opts.output != null) {
      try {
        io.writeFile(opts.output, formatted);
      } catch (e) {
        // Same oracle discipline as the read path: the DEFAULT write-failure message is
        // generic (no absolute path, no errno). The detail is surfaced ONLY under
        // --verbose/--debug. A write failure is an internal error (exit 4); it must
        // NEVER downgrade a fail-closed 3 / findings 1 into a clean 0.
        if (opts.verbose) {
          err(`iam-br: cannot write output '${opts.output}': ${(e && e.message) || 'error'}\n`);
        } else {
          err('iam-br: cannot write output (use --verbose for details).\n');
        }
        return EXIT.INTERNAL;
      }
    } else {
      out(formatted);
    }

    // Diagnostics always to stderr; never affects the exit code.
    err(`${diagnosticLine(result)}\n`);
    return code;
  } catch (e) {
    // Catch-all: an unexpected throw anywhere fails CLOSED to an internal error.
    // This is the banned-pattern's inverse - we NEVER `catch { return 0 }`.
    err(`iam-br: internal error: ${(e && e.message) || 'unexpected failure'}\n`);
    return EXIT.INTERNAL;
  }
}

// --- Process entry point ------------------------------------------------------

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    try {
      process.stdin.setEncoding('utf8');
    } catch {
      // stdin may be unavailable; treat as empty.
      resolve('');
      return;
    }
    process.stdin.on('data', (chunk) => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

export async function main(argv = process.argv.slice(2)) {
  // S5-cli-hardening: the bare CLI has no GITHUB_WORKSPACE, so the --output base dir
  // is EXPLICITLY the process cwd. Resolved once here and used by both the fs-aware
  // containment guard and the write sink so they cannot disagree.
  const outputBase = process.cwd();
  const io = {
    readFile: (p) => readFileSync(p, 'utf8'),
    readStdin,
    // The fs-aware half of --output containment (symlink-escape + no-overwrite).
    // run() consults this BEFORE writing; parseArgs already handled the lexical layer.
    outputTargetContained: (rel) => outputTargetContainedFs(outputBase, rel),
    // Resolve the (already-confined) relative path against the base, create any parent
    // directories, then write. Resolving against the explicit base is defense in depth:
    // the path is confined, so this stays inside cwd.
    writeFile: (p, data) => {
      const abs = nodePath.resolve(outputBase, p);
      mkdirSync(nodePath.dirname(abs), { recursive: true });
      writeFileSync(abs, data);
    },
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
    stdinIsTTY: Boolean(process.stdin && process.stdin.isTTY),
  };
  const code = await run(argv, io);
  // Set exitCode (rather than process.exit) so buffered stdout/stderr flush.
  process.exitCode = code;
  return code;
}

// Run only when invoked directly (`iam-br ...` / `node cli/iam-br.mjs ...`), not
// when imported by a test or the Action wrapper.
const invokedDirectly = (() => {
  try {
    const entry = process.argv && process.argv[1];
    if (!entry) return false;
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main();
}

export default run;
