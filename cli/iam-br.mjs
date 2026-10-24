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

import { writeFileSync, realpathSync, lstatSync, fstatSync, mkdirSync, openSync, readSync, closeSync, constants as fsConstants } from 'node:fs';

// TOCTOU-safe open flags (CodeQL js/file-system-race). O_NOFOLLOW: a symlink
// swapped in at the final path component after our lstat fails the open (ELOOP)
// instead of being followed. O_NONBLOCK: a FIFO swapped in cannot block the open
// (O_RDONLY|O_NONBLOCK on a FIFO returns immediately even with no writer), so the
// availability guard holds even under a race. Both are undefined on Windows -
// `?? 0` degrades to O_RDONLY there (no atomic no-follow-open; that platform stays
// on the lstat guard alone), which is inert since this CLI/Action runs on POSIX CI.
const O_RDONLY = fsConstants.O_RDONLY ?? 0;
const O_NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const O_NONBLOCK = fsConstants.O_NONBLOCK ?? 0;
import * as nodePath from 'node:path';
import { pathToFileURL } from 'node:url';

import { scan, EXIT, SELECTABLE_FAMILIES, DEFAULT_BUDGET_MS } from './scan.mjs';
import { parseTrustedAccountIds } from './trusted-accounts.mjs';
// READ-ONLY: the SINGLE source of the input byte cap. The pre-guards below (readStdin /
// readFileCapped) reject an over-cap input BEFORE materializing it (threat-model T5);
// they import LIMITS.MAX_BYTES from the SAME module the engine's validate() enforces, so
// the pre-guard and the engine guard can never drift. validate.js is browser-safe (no
// node: deps), so importing it here never leaks Node into the browser engine graph.
import { LIMITS } from '../content/tools/iam-blast-radius/engine/validate.js';
// The SARIF 2.1.0 adapter (story P15-sarif): a PURE projection of a scan() result.
// The CLI just picks it when --format sarif; the exit code is unaffected.
import { formatSarif, artifactUri } from './sarif.mjs';
// v1.3.0: Pulumi preview / stack export input (one aggregate result over many documents).
import { scanPulumi, pulumiUnits, applyPulumiBaseline, PULUMI_LIMITS, PULUMI_WARNING } from './pulumi.mjs';
import { buildAggregateSarif } from '../action/action-aggregate.mjs';
import {
  applyBaseline, parseBaseline, buildBaseline, formatBaseline, baselineWriteProblem, MAX_BASELINE_BYTES,
} from './baseline.mjs';
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
  '--baseline',
  '--resource-type',
  '--resource-arn',
  '--resource-account',
  '--input',
  '--provider-account',
  '--trusted-account-id',
]));

// Boolean flags (no value). `-h` is an alias for `--help`. `--debug` is an alias
// for `--verbose` (S5-cli-hardening: gates the errno detail on a read failure).
const BOOLEAN_FLAGS = Object.freeze(new Set(['--version', '--help', '--verbose', '--debug']));

const FORMATS = Object.freeze(new Set(['json', 'sarif', 'baseline']));

// Tagged-error code raised by the input pre-guards (readStdin / readFileCapped) when the
// input exceeds LIMITS.MAX_BYTES. run() recognizes it and routes the run down the EXISTING
// TOO_LARGE/exit-3 fail-closed path (via scan -> validate), so an over-cap input can never
// report clean/exit-0 - and it is enforced BEFORE the whole input is materialized (T5).
const INPUT_TOO_LARGE = 'INPUT_TOO_LARGE';

// Tagged-error code raised by readFileCapped when the positional path is NOT a regular
// file (a symlink, char/block device like /dev/zero, FIFO, socket, directory, ...). It is
// deliberately DISTINCT from INPUT_TOO_LARGE: run() does NOT special-case it, so it flows
// down the SAME could-not-read fail-closed path as any other unreadable file (exit 2, no
// stdout, generic message unless --verbose) - a non-regular file must NEVER read clean.
const NON_REGULAR_FILE = 'NON_REGULAR_FILE';

function nonRegularFileError(path) {
  const e = new Error(`refusing to read '${path}': not a regular file`);
  e.code = NON_REGULAR_FILE;
  return e;
}

function inputTooLargeError(bytes) {
  const e = new Error(
    `input exceeds the ${LIMITS.MAX_BYTES}-byte limit` +
    (Number.isFinite(bytes) ? ` (${bytes} bytes)` : ''),
  );
  e.code = INPUT_TOO_LARGE;
  if (Number.isFinite(bytes)) e.bytes = bytes;
  return e;
}

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

// Symlink-safe, no-overwrite write of a CONFINED --output target. outputTargetContainedFs()
// is consulted in run() BEFORE this write and already rejects an existing leaf and any
// symlink COMPONENT, but that check and this write are not atomic: a co-located same-user
// attacker could, in the window between them, plant a symlink at the (previously absent)
// leaf so a default 'w' open would FOLLOW it and clobber an arbitrary file outside the
// workspace. Opening with O_EXCL ('wx') closes that race at open() time - POSIX requires
// open(O_CREAT|O_EXCL) on a symlink to FAIL, and it also refuses a pre-existing regular
// file, matching the no-overwrite policy the containment check already enforces. A
// planted symlink / racing file therefore fails CLOSED to the caller's exit-4 write-error
// path instead of redirecting the write. (Leaf only; a swapped ANCESTOR directory is a
// documented residual needing per-component openat/O_NOFOLLOW - out of scope here.)
export function writeFileContained(baseDir, rel, data) {
  const abs = nodePath.resolve(baseDir, rel);
  mkdirSync(nodePath.dirname(abs), { recursive: true });
  writeFileSync(abs, data, { flag: 'wx' });
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
  iam-br --input pulumi [options] preview-or-export.json
  cat policy.json | iam-br --family <family> [options]

Reads one AWS IAM policy document from a file argument or, if none is given,
from STDIN. Writes the result to STDOUT (JSON by default) and diagnostics to
STDERR. This tool reports POTENTIAL blast radius from the supplied policy
context; it never claims effective permissions.

REQUIRED
  --family <f>          Policy family. One of:
                          identity | resource | role-trust | trust |
                          permissions-boundary | scp-rcp | scp | rcp | session
                        (trust = role-trust; scp and rcp = scp-rcp.)
                        The family is NEVER auto-detected; omitting it is a
                        usage error (exit 2).

OPTIONS
  --trusted-account-id <id>  (repeatable, or comma-separated) a 12-digit account you trust.
                          For role-trust, a trust whose principals are all exact role/user
                          ARNs in listed accounts is rated medium instead of cross-account
                          high. Account-root principals stay high. Invalid id: exit 2.
  --subject-account <id>  AWS account id (12 digits) for account-aware checks
                          (e.g. PassRole viability). An invalid id is ignored
                          (the dependent finding stays UNKNOWN and fails closed).
                          For role-trust it is the account that owns EVERY role in
                          the run; split a glob that spans accounts.
  --resource-arn <arn>    For --family role-trust: the role's own ARN; required to
                          report a trust as same-account (else cross-account high).
                          For --family resource: the ARN of the resource the policy
  --resource-type <t>     is ATTACHED to (e.g. --resource-type s3-bucket
  --resource-account <id> --resource-arn arn:aws:s3:::my-bucket). Required to analyze
                          a resource policy; without it the resource family fails
                          closed (RESOURCE_CONTEXT_REQUIRED, exit 3).
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
  --format <fmt>          Output format: json | sarif | baseline. Default: json.
                          'baseline' prints a baseline file accepting every
                          result of this run (review it before committing).
                          The format never changes the exit code.
  --baseline <file>       Accept the results listed in a committed baseline file
                          (see --format baseline). Only accepted findings and
                          accepted UNKNOWN_ACTION / UNSUPPORTED_CONDITION states
                          stop counting; any other fail-closed state still exits
                          3. Keys are bound to the artifact URI, so pass the same
                          path (or --artifact-uri) the baseline was built with.
  --budget-ms <ms>        Wall-clock budget for analyzing the policy, in
                          milliseconds (default: ${DEFAULT_BUDGET_MS}). If analysis
                          overruns, the scan FAILS CLOSED (exit 3,
                          RESOURCE_BUDGET_EXCEEDED); it never reports a clean pass.
  --output <path>         Write formatted output to <path> instead of STDOUT.
  --artifact-uri <uri>    Location URI recorded in SARIF output for the analyzed
                          policy (default: the file path, or 'stdin'). With
                          --input pulumi: the fallback location (default
                          Pulumi.yaml) when a resource has no usable source line.
  --input <kind>          policy (default) | pulumi. 'pulumi' reads a
                          'pulumi preview --json' or 'pulumi stack export' file
                          and scans every IAM policy in it; --family and
                          --resource-* are not used. A default preview lists only
                          changed resources (scanScope "delta"): exit 0 then means
                          "no new risk in this change", not "stack clean". Use
                          'preview --show-sames' or a stack export for a full scan.
  --provider-account <p>=<id>
                          With --input pulumi (repeatable): the AWS account of the
                          provider named <p> (its resource name or full URN).
                          Cross-checked against the stack; a mismatch fails closed.
                          It resolves the account but never proves a same-account
                          trust on its own. When providers span several accounts,
                          omit --subject-account (it would mismatch the others).
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
    input: 'policy',
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
        case '--baseline': opts.baseline = value; break;
        case '--resource-type': opts.resourceType = value; break;
        case '--resource-arn': opts.resourceArn = value; break;
        case '--resource-account': opts.resourceAccount = value; break;
        case '--input': opts.input = value; break;
        case '--trusted-account-id': (opts.trustedAccountIds ||= []).push(value); break;
        case '--provider-account': {
          // R5-4: repeatable <provider-name-or-urn>=<account>; split on the last '='.
          const i = value.lastIndexOf('=');
          if (i <= 0) return usage("--provider-account expects <provider>=<12-digit account id>");
          (opts.providerAccounts ||= []).push({ key: value.slice(0, i), account: value.slice(i + 1) });
          break;
        }
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

  if (opts.trustedAccountIds) {
    const trusted = parseTrustedAccountIds(opts.trustedAccountIds);
    if (trusted.error) return usage(`--trusted-account-id: ${trusted.error}`);
  }
  if (opts.input !== 'policy' && opts.input !== 'pulumi') {
    return usage(`unknown --input '${opts.input}' (expected: policy | pulumi)`);
  }
  if (opts.input === 'pulumi') {
    const problem = pulumiArgProblem(opts);
    if (problem) return usage(problem);
  } else if (opts.providerAccounts) {
    return usage('--provider-account is only valid with --input pulumi');
  } else if (!isNonEmptyString(opts.family)) {
    // Required: --family. NEVER auto-detected -> a missing family is a usage error.
    return usage(
      'the --family option is required and is never auto-detected ' +
      '(identity | resource | role-trust | trust | permissions-boundary | scp-rcp | scp | rcp | session)',
    );
  }
  // Validate the family VALUE here too (like --format) so a bad value is a usage
  // error on stderr with no stdout, consistent with a missing family. scan()
  // enforces the same SELECTABLE_FAMILIES set for the programmatic / action path.
  const familyLower = opts.input === 'pulumi' ? null : opts.family.trim().toLowerCase();
  if (familyLower === 'auto' || familyLower === 'auto-detect') {
    return usage('family auto-detection is not permitted; select an explicit family '
      + '(identity | resource | role-trust | trust | permissions-boundary | scp-rcp | scp | rcp | session)');
  }
  if (familyLower !== null && !SELECTABLE_FAMILIES.has(familyLower)) {
    return usage(`unknown --family '${opts.family}' `
      + '(expected: identity | resource | role-trust | trust | permissions-boundary | scp-rcp | scp | rcp | session)');
  }
  // Format is a CLI-level concern (scan does not see it), so validate it here.
  if (!FORMATS.has(opts.format)) {
    return usage(`unknown --format '${opts.format}' (expected: json | sarif | baseline)`);
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

// --input pulumi: each document's family and context come from the file, so the
// single-policy flags are refused; baselines arrive with URN keys (round 3).
function pulumiArgProblem(opts) {
  if (isNonEmptyString(opts.family)) return '--family is not used with --input pulumi (each policy\'s family comes from its resource type)';
  if (opts.resourceType || opts.resourceArn || opts.resourceAccount) return '--resource-* is not used with --input pulumi (the attached resource is resolved from the stack)';
  if (!isNonEmptyString(opts.file)) return '--input pulumi needs the preview/export JSON as a file argument (stdin is not read)';
  return null;
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
    // E-1: the account a same-account verdict was judged against (valid ids only).
    subjectAccountAsserted: /^\d{12}$/.test(String(o.subjectAccount ?? '').trim()) ? String(o.subjectAccount).trim() : null,
    trustedAccountIdsAsserted: parseTrustedAccountIds(o.trustedAccountIds).ids || null,
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
  if (opts.format === 'baseline') {
    const doc = buildBaseline([{ file: artifactUri(opts), result }]);
    const text = formatBaseline(doc);
    const problem = baselineWriteProblem(doc, text);
    if (problem) throw new Error(`baseline too large to read back: ${problem}`);
    return text;
  }
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

    if (opts.input === 'pulumi') return runPulumi(opts, io, out, err, manifest);

    // Resolve the policy text: a file argument, else STDIN.
    // `oversize` records that a pre-guard tripped the MAX_BYTES cap BEFORE the whole
    // input was materialized (threat-model T5). It is routed down the existing
    // TOO_LARGE/exit-3 path below - never a clean pass.
    let text;
    let oversize = false;
    if (opts.file != null) {
      try {
        text = io.readFile(opts.file);
      } catch (e) {
        if (e && e.code === INPUT_TOO_LARGE) {
          // readFileCapped's byte pre-guard / bounded read rejected an over-cap file. Fail
          // CLOSED down the shared TOO_LARGE/exit-3 path, not the usage-error path. (A
          // NON_REGULAR_FILE rejection is NOT tagged INPUT_TOO_LARGE, so it falls to the
          // could-not-read usage-error branch below - a special file never reads clean.)
          oversize = true;
        } else {
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
      }
    } else {
      if (io.stdinIsTTY) {
        err('iam-br: no policy file given and no data on stdin.\n');
        err('iam-br: pass a file path or pipe a policy in. Run with --help for usage.\n');
        return EXIT.USAGE;
      }
      try {
        text = await io.readStdin();
      } catch (e) {
        if (e && e.code === INPUT_TOO_LARGE) {
          // The STDIN pre-guard aborted once accumulated bytes exceeded MAX_BYTES,
          // before buffering the whole stream. Fail CLOSED down the shared exit-3 path.
          oversize = true;
        } else {
          throw e; // any other stdin failure fails closed to INTERNAL via the catch-all
        }
      }
    }

    if (oversize) {
      // The input tripped the byte cap. Route it down the EXISTING TOO_LARGE/exit-3
      // path so the verdict is produced by the SAME engine gate the browser uses
      // (scan -> validate -> TOO_LARGE -> fail-closed exit 3), with no drift. The real
      // (potentially huge) input is NOT materialized - this bounded, inert filler only
      // stands in to trip validate()'s byte gate; it is rejected before any parse.
      text = 'x'.repeat(LIMITS.MAX_BYTES + 1);
    }

    if (!isNonEmptyString(text)) {
      err('iam-br: empty policy input.\n');
      return EXIT.USAGE;
    }

    // An opt-in baseline is read + validated BEFORE analysis: an unreadable or malformed
    // baseline is a usage error (exit 2), never "no baseline" (which would silently fail
    // every accepted result) and never a clean pass.
    const bl = readAcceptedKeys(opts, io, err);
    if (bl.exit != null) return bl.exit;
    const acceptedKeys = bl.keys;

    // Run the analysis. scan() owns the exit-code contract; the CLI propagates it.
    const scanFn = (io && io.scan) || scan;
    const scanned = scanFn({
      text,
      family: opts.family,
      subjectAccount: opts.subjectAccount,
      trustedAccountIds: opts.trustedAccountIds,
      // Pass partition ONLY when explicitly supplied; an omitted partition must
      // stay "not asserted" so a cross-partition viability question fails closed
      // rather than being silently treated as a confident 'aws' assertion.
      partition: opts.partition,
      threshold: opts.threshold,
      // Wall-clock budget (S3-dos-budget): analysis that overruns fails CLOSED
      // (exit 3, RESOURCE_BUDGET_EXCEEDED), never a clean pass.
      budgetMs: opts.budgetMs,
      // The resource family's attached-resource context (review finding D1): built from
      // --resource-type / --resource-arn (+ optional --resource-account). Omitted entirely
      // when neither is given, so non-resource families are unaffected and a resource
      // policy WITHOUT context still fails closed (RESOURCE_CONTEXT_REQUIRED).
      resourceContext: (opts.resourceArn || opts.resourceType)
        ? { type: opts.resourceType, arn: opts.resourceArn, account: opts.resourceAccount }
        : undefined,
    });
    // Attach baseline keys (always, so SARIF publishes them) and apply an opt-in baseline.
    // See cli/baseline.mjs for what a baseline can and cannot accept.
    const threshold = isNonEmptyString(opts.threshold) ? opts.threshold.trim().toLowerCase() : 'high';
    const result = applyBaseline(scanned, artifactUri(opts), acceptedKeys, threshold);
    if (result && result.baseline && result.baseline.mismatched.length > 0) {
      err(`iam-br: ${result.baseline.mismatched.length} baseline entr${result.baseline.mismatched.length === 1 ? 'y matches' : 'ies match'} a result by id `
        + 'but not by file / ruleId / severity; regenerate the baseline (--format baseline) and review it.\n');
      return EXIT.USAGE;
    }

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

// Read + validate an opt-in baseline BEFORE analysis: unreadable or malformed is exit 2,
// never "no baseline". Returns { keys } (null when none) or { exit }.
function readAcceptedKeys(opts, io, err) {
  if (opts.baseline == null) return { keys: null };
  let baselineText;
  try {
    baselineText = io.readFile(opts.baseline, MAX_BASELINE_BYTES);
  } catch (e) {
    if (opts.verbose) {
      err(`iam-br: cannot read baseline file '${opts.baseline}': ${(e && (e.code || e.message)) || 'error'}\n`);
    } else {
      err('iam-br: cannot read baseline file (use --verbose for details).\n');
    }
    return { exit: EXIT.USAGE };
  }
  const parsedBaseline = parseBaseline(baselineText);
  if (!parsedBaseline.ok) {
    err(`iam-br: ${parsedBaseline.message}\n`);
    return { exit: EXIT.USAGE };
  }
  return { keys: parsedBaseline.keys };
}

// --input pulumi: read the file (larger cap than one policy), scan every document,
// emit one aggregate report. Same exit contract; formatting never changes the code.
function runPulumi(opts, io, out, err, manifest) {
  const bl = readAcceptedKeys(opts, io, err);
  if (bl.exit != null) return bl.exit;
  let text;
  let tooLarge = false;
  try {
    text = io.readFile(opts.file, PULUMI_LIMITS.MAX_BYTES);
  } catch (e) {
    if (e && e.code === INPUT_TOO_LARGE) tooLarge = true;
    else {
      err(opts.verbose
        ? `iam-br: cannot read Pulumi file '${opts.file}': ${(e && (e.code || e.message)) || 'error'}\n`
        : 'iam-br: cannot read Pulumi file (use --verbose for details).\n');
      return EXIT.USAGE;
    }
  }
  const scanned = scanPulumi({
    text: tooLarge ? '' : text,
    oversize: tooLarge,
    subjectAccount: opts.subjectAccount,
    trustedAccountIds: opts.trustedAccountIds,
    partition: opts.partition,
    providerAccounts: opts.providerAccounts,
    threshold: opts.threshold,
    budgetMs: opts.budgetMs,
  });
  if (scanned.exitCode === EXIT.USAGE) {
    err(`iam-br: ${scanned.analysisStates[0] ? scanned.analysisStates[0].message : 'not Pulumi JSON'}\n`);
    return EXIT.USAGE;
  }
  // P8: keys per <urn>#<property> (always attached), opt-in acceptance per document.
  const threshold = isNonEmptyString(opts.threshold) ? opts.threshold.trim().toLowerCase() : 'high';
  const result = applyPulumiBaseline(scanned, bl.keys, threshold);
  if (result.baseline && result.baseline.mismatched.length > 0) {
    err(`iam-br: ${result.baseline.mismatched.length} baseline entr${result.baseline.mismatched.length === 1 ? 'y matches' : 'ies match'} a result by id `
      + 'but not by file / ruleId / severity; regenerate the baseline (--format baseline) and review it.\n');
    return EXIT.USAGE;
  }
  const code = Number.isInteger(result.exitCode) ? result.exitCode : EXIT.INTERNAL;
  let formatted;
  try {
    if (opts.format === 'baseline') {
      const doc = buildBaseline(pulumiUnits(result, opts.artifactUri));
      formatted = formatBaseline(doc);
      const problem = baselineWriteProblem(doc, formatted);
      if (problem) throw new Error(`baseline too large to read back: ${problem}`);
    } else {
      formatted = opts.format === 'sarif'
        ? `${JSON.stringify(buildAggregateSarif(pulumiUnits(result, opts.artifactUri), manifest), null, 2)}\n`
        : `${JSON.stringify(toPulumiJsonReport(result, opts, manifest), null, 2)}\n`;
    }
  } catch (e) {
    err(`iam-br: internal error: failed to format ${opts.format} output: ${(e && e.message) || 'error'}\n`);
    return EXIT.INTERNAL;
  }
  if (opts.output != null) {
    try {
      io.writeFile(opts.output, formatted);
    } catch (e) {
      err(opts.verbose ? `iam-br: cannot write output '${opts.output}': ${(e && e.message) || 'error'}\n`
        : 'iam-br: cannot write output (use --verbose for details).\n');
      return EXIT.INTERNAL;
    }
  } else {
    out(formatted);
  }
  // E-5: tool-authored text only (code + count), never an input value.
  for (const w of result.warnings || []) {
    const msg = Object.hasOwn(PULUMI_WARNING, w.code) && Number.isInteger(w.accounts) ? PULUMI_WARNING[w.code](w.accounts) : '';
    if (msg) err(`iam-br: warning ${w.code}: ${msg}\n`);
  }
  const stale = result.baseline ? result.baseline.stale.length : 0;
  if (stale > 0) err(`iam-br: ${stale} baseline entr${stale === 1 ? 'y no longer matches' : 'ies no longer match'} any result; remove them from the baseline file.\n`);
  err(`iam-br: input=pulumi scope=${result.scanScope} status=${result.analysisStatus} exit=${code} `
    + `reason=${result.reason} documents=${result.documents.length} findings=${result.findingsCount} blocking=${result.blockingCount}\n`);
  return code;
}

/**
 * Deterministic JSON report for --input pulumi: verdict, scan scope, then one entry per
 * policy document keyed by `<urn>#<property>`.
 * @param {object} result scanPulumi() result
 * @param {object} opts
 * @param {object} [manifest]
 * @returns {object}
 */
export function toPulumiJsonReport(result, opts, manifest = VERSION_MANIFEST) {
  const o = opts || {};
  return {
    tool: 'iam-blast-radius',
    version: semanticVersion(manifest),
    input: 'pulumi',
    pulumiKind: result.kind,
    scanScope: result.scanScope,
    scannedUrns: [...(result.scannedUrns || [])],
    threshold: o.threshold != null ? o.threshold : 'high',
    partitionAsserted: isNonEmptyString(o.partition) ? o.partition.trim() : null,
    subjectAccountAsserted: /^\d{12}$/.test(String(o.subjectAccount ?? '').trim()) ? String(o.subjectAccount).trim() : null,
    trustedAccountIdsAsserted: parseTrustedAccountIds(o.trustedAccountIds).ids || null,
    // R2-2: why each provider's account/partition was believed.
    providers: [...(result.providers || [])],
    // E-5: run-level warnings ({ code, accounts, message }); never part of the verdict.
    warnings: [...(result.warnings || [])],
    // Listed, not analyzed (e.g. source-bound Lambda permissions).
    unanalyzed: [...(result.unanalyzed || [])],
    // P9: role groups (informational; never part of the verdict).
    groups: [...(result.groups || [])],
    unresolvedEdges: [...(result.unresolvedEdges || [])],
    baseline: result.baseline
      ? { applied: result.baseline.applied, accepted: result.baseline.used.length, stale: result.baseline.stale.length }
      : null,
    analysisStatus: result.analysisStatus,
    reason: result.reason,
    exitCode: result.exitCode,
    findingsCount: result.findingsCount,
    blockingCount: result.blockingCount,
    analysisStates: [...(result.analysisStates || [])],
    documents: (result.documents || []).map((d) => ({
      artifact: d.artifact,
      urn: d.urn,
      property: d.property,
      type: d.type,
      family: d.family,
      op: d.op,
      managed: d.managed,
      location: d.location,
      analysisStatus: d.result.analysisStatus,
      reason: d.result.reason,
      exitCode: d.result.exitCode,
      findingsCount: d.result.findingsCount,
      blockingCount: d.result.blockingCount,
      analysisStates: [...(d.result.analysisStates || [])],
      findings: [...(d.result.findings || [])],
    })),
  };
}

// --- Process entry point ------------------------------------------------------

// Read STDIN, enforcing the MAX_BYTES cap BEFORE the whole stream is materialized
// (threat-model T5). We accumulate RAW Buffer chunks and count ENCODED bytes as they
// arrive; the moment the running total exceeds LIMITS.MAX_BYTES we STOP consuming and
// reject with a tagged INPUT_TOO_LARGE error - so an unbounded / multi-GB producer can
// never fill memory. Decoding to a UTF-8 string happens ONCE, at end, over the
// concatenated buffer - never per chunk - so a multibyte character split across a chunk
// boundary is neither miscounted (bytes are counted on the raw buffers) nor mis-decoded
// (the whole buffer is decoded together). `stream` is injectable for tests; it defaults
// to process.stdin. Deliberately does NOT call setEncoding - we want Buffer chunks.
export function readStdin(stream = process.stdin) {
  return new Promise((resolve, reject) => {
    if (!stream || typeof stream.on !== 'function') {
      // stdin unavailable; treat as empty (matches the prior fail-safe behavior).
      resolve('');
      return;
    }
    const chunks = [];
    let bytes = 0;
    let done = false;
    let idleTimer = null;

    const cleanup = () => {
      if (idleTimer) { clearTimeout(idleTimer); idleTimer = null; }
      try {
        stream.removeListener('data', onData);
        stream.removeListener('end', onEnd);
        stream.removeListener('error', onErr);
      } catch { /* best effort */ }
    };

    // Idle guard (review finding E3): --budget-ms wraps analyze(), NOT input acquisition,
    // so a producer that streams a few under-cap bytes and then never sends EOF would keep
    // this promise pending forever. Fail CLOSED if no data arrives for STDIN_IDLE_MS; the
    // timer re-arms on every chunk so a slow-but-progressing pipe is fine, and unref() lets
    // the process exit naturally.
    const STDIN_IDLE_MS = Number(process.env.IAM_BR_STDIN_IDLE_MS) || 60000;
    function onIdle() {
      if (done) return;
      done = true;
      chunks.length = 0;
      cleanup();
      try { stream.pause(); } catch { /* best effort */ }
      try { if (typeof stream.destroy === 'function') stream.destroy(); } catch { /* best effort */ }
      const e = new Error(`timed out waiting for stdin (no data for ${STDIN_IDLE_MS}ms)`);
      e.code = 'STDIN_IDLE_TIMEOUT';
      reject(e);
    }
    const armIdle = () => {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(onIdle, STDIN_IDLE_MS);
      if (typeof idleTimer.unref === 'function') idleTimer.unref();
    };

    function onData(chunk) {
      if (done) return;
      armIdle();
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytes += buf.length;
      if (bytes > LIMITS.MAX_BYTES) {
        // Over the cap: abort NOW, before buffering any more of the stream. Drop the
        // accumulated chunks so nothing over-cap lingers, stop the source, and fail
        // closed with the tagged error (run() routes it to exit 3).
        done = true;
        chunks.length = 0;
        cleanup();
        try { stream.pause(); } catch { /* best effort */ }
        try { if (typeof stream.destroy === 'function') stream.destroy(); } catch { /* best effort */ }
        reject(inputTooLargeError(bytes));
        return;
      }
      chunks.push(buf);
    }

    function onEnd() {
      if (done) return;
      done = true;
      cleanup();
      resolve(Buffer.concat(chunks).toString('utf8'));
    }

    function onErr(e) {
      if (done) return;
      done = true;
      cleanup();
      reject(e);
    }

    stream.on('data', onData);
    stream.on('end', onEnd);
    stream.on('error', onErr);
    armIdle(); // start the idle countdown even if the first byte never arrives
  });
}

// Read a policy FILE, enforcing the MAX_BYTES cap BEFORE and DURING the read
// (threat-model T5, availability). Two layers, both fail CLOSED:
//
//   1. TYPE guard (S3-readfilecap-special). lstatSync the path - do NOT follow the link -
//      and REJECT anything that is not a regular file. This is the load-bearing fix:
//      statSync FOLLOWS symlinks and reports size 0 for char/block devices, FIFOs, and
//      /proc entries, so a size-only pre-guard would pass a zero-size special file
//      (e.g. /dev/zero, or a symlink to it) and then readFileSync it UNBOUNDED - a
//      never-EOF source hangs the process, and --budget-ms only wraps analyze(), not this
//      read. lstat inspects the LINK itself (isFile() is false for a symlink, a device, a
//      FIFO, a socket, a directory), so all of these are rejected as could-not-read
//      (NON_REGULAR_FILE -> run() exit 2), never read.
//
//   2. BOUNDED read. Even a regular file can grow between the stat and the read (TOCTOU),
//      or be a "regular" pseudo-file (some /proc entries stat as regular, size 0) that
//      yields more than its stat size. So we open a fd and read at most MAX_BYTES + 1
//      bytes via readSync; if the source still produces more than MAX_BYTES we reject it
//      as INPUT_TOO_LARGE. This guarantees the read can never materialize beyond the cap
//      mid-read, independent of what statSync claimed. The oversized-regular-file
//      rejection (tagged INPUT_TOO_LARGE, routed to fail-closed exit 3) is preserved.
//
// A lstatSync failure (missing / unreadable path) propagates as the original error so
// run()'s usage-error path (exit 2) still handles it exactly as before.
export function readFileCapped(path, maxBytes = LIMITS.MAX_BYTES) {
  const lst = lstatSync(path); // do NOT follow the link: inspect the path's own type
  if (!lst.isFile()) {
    // Symlink, char/block device, FIFO, socket, directory, ... - never read it.
    throw nonRegularFileError(path);
  }
  // Cheap pre-reject of an oversized regular file (avoids opening it at all).
  const size = lst.size;
  if (Number.isFinite(size) && size > maxBytes) {
    throw inputTooLargeError(size);
  }
  // Bounded read: cap the bytes we will materialize regardless of the stat size.
  const cap = maxBytes;
  // TOCTOU-closing open (CodeQL js/file-system-race). Between the lstat above and
  // this open the path could be swapped. Open with O_NOFOLLOW | O_NONBLOCK (see the
  // flag definitions) and then fstat the OPEN FD - not the path - so the type/size
  // re-check and the read all bind to the exact inode we hold, with no check-then-use
  // gap. The lstat above still rejects a STATIC special file WITHOUT opening it (the
  // load-bearing availability guard); the fd re-check below catches a file that raced
  // in AFTER the lstat.
  let fd;
  try {
    fd = openSync(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  } catch (e) {
    // A symlink swapped in after the lstat trips O_NOFOLLOW (ELOOP): report it as the
    // same NON_REGULAR_FILE the static-symlink path returns. Any other open failure
    // (missing / unreadable path) propagates unchanged so run() still maps it to exit 2.
    if (e && e.code === 'ELOOP') throw nonRegularFileError(path);
    throw e;
  }
  try {
    // Re-check on the fd we actually hold: a device / FIFO / directory raced in after
    // the lstat is rejected here (O_NONBLOCK guaranteed the open did not hang), and an
    // oversized file is re-rejected on the fd's own size, all BEFORE any read.
    const fst = fstatSync(fd);
    if (!fst.isFile()) {
      throw nonRegularFileError(path);
    }
    if (Number.isFinite(fst.size) && fst.size > cap) {
      throw inputTooLargeError(fst.size);
    }
    const buf = Buffer.allocUnsafe(cap + 1); // one extra byte detects an over-cap source
    let total = 0;
    // Read until EOF or until we have pulled cap+1 bytes (whichever comes first).
    while (total <= cap) {
      const n = readSync(fd, buf, total, (cap + 1) - total, null);
      if (n === 0) break; // EOF
      total += n;
    }
    if (total > cap) {
      // The source produced more than MAX_BYTES despite the stat - reject, do not return
      // a truncated policy (that would silently drop content). Fail closed as TOO_LARGE.
      throw inputTooLargeError(total);
    }
    return buf.subarray(0, total).toString('utf8');
  } finally {
    closeSync(fd);
  }
}

export async function main(argv = process.argv.slice(2)) {
  // S5-cli-hardening: the bare CLI has no GITHUB_WORKSPACE, so the --output base dir
  // is EXPLICITLY the process cwd. Resolved once here and used by both the fs-aware
  // containment guard and the write sink so they cannot disagree.
  const outputBase = process.cwd();
  const io = {
    // readFileCapped rejects non-regular files (lstat) and enforces the MAX_BYTES cap via
    // an lstat pre-guard + a bounded fd read (T5); a never-EOF special file cannot hang it.
    readFile: (p, maxBytes) => readFileCapped(p, maxBytes),
    readStdin,
    // The fs-aware half of --output containment (symlink-escape + no-overwrite).
    // run() consults this BEFORE writing; parseArgs already handled the lexical layer.
    outputTargetContained: (rel) => outputTargetContainedFs(outputBase, rel),
    // Resolve the (already-confined) relative path against the base, create any parent
    // directories, then write. Resolving against the explicit base is defense in depth:
    // the path is confined, so this stays inside cwd.
    writeFile: (p, data) => writeFileContained(outputBase, p, data),
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
//
// import.meta.url is REALPATH-resolved by Node's ESM loader, while process.argv[1]
// is the RAW path Node was handed. Any symlink in the invocation path (an npm `.bin`
// shim, `npx`, a self-hosted-runner checkout, a macOS `/tmp` -> `/private/tmp` link)
// therefore makes a RAW-only compare MISS - main() would never run and the process
// would exit 0 having performed ZERO analysis, a false CLEAN on a real-risk policy.
// FAIL CLOSED: run when EITHER the raw entry OR its realpath-resolved form matches,
// and compute realpathSync in its OWN try so a resolve failure (ENOENT/ELOOP/EACCES)
// can never turn a genuine direct invocation into a silent no-op. An in-process
// import (test/Action wrapper) matches NEITHER, so it still does not auto-run main().
const invokedDirectly = (() => {
  try {
    const entry = process.argv && process.argv[1];
    if (!entry) return false;
    const rawHref = pathToFileURL(entry).href;
    if (import.meta.url === rawHref) return true;
    let realHref = null;
    try {
      realHref = pathToFileURL(realpathSync(entry)).href;
    } catch {
      realHref = null;
    }
    return realHref !== null && import.meta.url === realHref;
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main();
}

export default run;
