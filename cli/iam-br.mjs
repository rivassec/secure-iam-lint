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

import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { scan, EXIT, SELECTABLE_FAMILIES } from './scan.mjs';
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
]));

// Boolean flags (no value). `-h` is an alias for `--help`.
const BOOLEAN_FLAGS = Object.freeze(new Set(['--version', '--help']));

const FORMATS = Object.freeze(new Set(['json', 'sarif']));

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

// A single, coherent version string from the canonical manifest (no build step;
// what is committed is what runs, architecture invariant 2).
export function versionString(manifest = VERSION_MANIFEST) {
  const m = manifest || {};
  return `iam-br (IAM Blast Radius) rule-catalog ${m.ruleVersion}, ` +
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
  --output <path>         Write formatted output to <path> instead of STDOUT.
  --artifact-uri <uri>    Location URI recorded in SARIF output for the analyzed
                          policy (default: the file path, or 'stdin').
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
    file: undefined,
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

    // Resolve the policy text: a file argument, else STDIN.
    let text;
    if (opts.file != null) {
      try {
        text = io.readFile(opts.file);
      } catch (e) {
        // A missing or unreadable input path is a usage/config error (exit 2),
        // NOT a clean scan and NOT a fail-closed analysis.
        err(`iam-br: cannot read policy file '${opts.file}': ${(e && (e.code || e.message)) || 'error'}\n`);
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
        err(`iam-br: cannot write output '${opts.output}': ${(e && e.message) || 'error'}\n`);
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
  const io = {
    readFile: (p) => readFileSync(p, 'utf8'),
    readStdin,
    writeFile: (p, data) => writeFileSync(p, data),
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
