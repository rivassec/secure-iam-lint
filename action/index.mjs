#!/usr/bin/env node
// IAM Blast Radius - GitHub Action wrapper (Phase 16, story P16-action).
//
// A THIN, zero-runtime-dependency wrapper around the headless scan module
// (cli/scan.mjs) and the pure SARIF adapter (cli/sarif.mjs). It:
//   1. reads inputs from the INPUT_* env vars GitHub sets (no @actions/core dep),
//   2. resolves the newline/glob `paths` input to a concrete file set,
//   3. runs scan() per file READ-ONLY (never changing analysis behavior),
//   4. aggregates with STRICT WORST-EXIT-CODE semantics,
//   5. writes a single multi-run SARIF file,
//   6. WRITES ALL OUTPUTS FIRST (GITHUB_OUTPUT + step summary),
//   7. THEN fails the action iff the aggregate exit code != 0.
//
// It reads policy FILES only. It NEVER executes any repo-provided command, script,
// Terraform, or npm install - untrusted PR policy content stays DATA, not code.
// There is no child_process import anywhere in this module.
//
// FAIL CLOSED is the whole point (github-action-plan.md decision 3): CLI exit 3
// ("could not analyze") MUST fail the check; it must NEVER collapse to exit 0 / a
// green check. A caught error NEVER becomes exit 0 either - it fails closed to the
// internal-invariant code 4. An empty/missing glob is a usage error (exit 2), not a
// clean scan. In a multi-file run, ONE fail-closed file makes the whole run fail
// (worst exit code wins).
//
// Exit-code contract (owned by scan.mjs, aggregated here, never downgraded):
//   0 analyzed, no findings at/above fail-on
//   1 findings at/above fail-on
//   2 usage/config error (bad/missing family, missing/empty paths, missing files)
//   3 FAIL-CLOSED could-not-analyze (partial|failed)
//   4 internal invariant error
// A CI gate treats 1,2,3,4 as FAILED. Code 3 is DISTINCT from 0 and from 1.

import { scan, EXIT, DEFAULT_BUDGET_MS } from '../cli/scan.mjs';
import { buildSarifLog } from '../cli/sarif.mjs';
// READ-ONLY canonical version manifest (browser-safe, no Node deps) so the SARIF
// semanticVersion ties to the same identifiers the engine reports.
import { VERSION_MANIFEST } from '../content/tools/iam-blast-radius/engine/version.js';

export { EXIT };

// --- Small helpers ------------------------------------------------------------

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

function toCount(n) {
  return Number.isFinite(n) ? n : 0;
}

// --- Input reading (zero-dep @actions/core replacement) -----------------------

// GitHub sets an input named `foo-bar` into the env var `INPUT_FOO-BAR`
// (uppercased, spaces -> underscores, hyphens PRESERVED) - the exact transform
// @actions/core.getInput performs. We replicate it, then fall back to a
// hyphen->underscore variant defensively. Leading/trailing whitespace is trimmed
// (core trims by default); INTERNAL newlines are preserved so `paths` can be a
// multi-line block.
export function getInput(env, name) {
  const e = env || {};
  const primary = 'INPUT_' + String(name).replace(/ /g, '_').toUpperCase();
  let v = e[primary];
  if (v === undefined) {
    const alt = 'INPUT_' + String(name).replace(/[ -]/g, '_').toUpperCase();
    v = e[alt];
  }
  return v === undefined ? '' : String(v).trim();
}

// Read the whole action input set from the environment. Defaults mirror action.yml
// (fail-on high, sarif-output iam-blast-radius.sarif) so a locally invoked wrapper
// behaves identically to the runner-provided env.
//
// partition has NO DEFAULT on purpose: an OMITTED partition must stay "not
// asserted" (empty string here -> undefined at the scan boundary), NOT be
// collapsed to 'aws'. Collapsing it to 'aws' would make scan() treat a DEFAULTED
// partition as a confident caller assertion, disabling scan's cross-partition
// fail-closed guard: a critical PassRole finding demoted (critical->medium)
// against a partition the consumer never vouched for would slip under a 'high'
// threshold and report a green pass. This mirrors the CLI, which passes
// `partition: undefined` when --partition is omitted.
export function readInputs(env) {
  return {
    paths: getInput(env, 'paths'),
    family: getInput(env, 'family'),
    subjectAccount: getInput(env, 'subject-account'),
    partition: getInput(env, 'partition'),
    failOn: getInput(env, 'fail-on') || 'high',
    sarifOutput: getInput(env, 'sarif-output') || 'iam-blast-radius.sarif',
    // Wall-clock budget per policy, in ms (S3-dos-budget). A non-numeric or omitted
    // value falls back to the default; a policy whose analysis overruns fails CLOSED
    // (exit 3, RESOURCE_BUDGET_EXCEEDED), never a clean pass.
    budgetMs: budgetMsInput(getInput(env, 'budget-ms')),
  };
}

// Coerce the budget-ms input to a number, defaulting when absent/invalid.
function budgetMsInput(raw) {
  if (!isNonEmptyString(raw)) return DEFAULT_BUDGET_MS;
  const n = Number(String(raw).trim());
  return Number.isFinite(n) ? n : DEFAULT_BUDGET_MS;
}

// --- paths / glob resolution --------------------------------------------------

// Split the newline-separated `paths` input into trimmed, non-empty pattern lines.
export function splitPaths(raw) {
  if (typeof raw !== 'string') return [];
  return raw
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// A pattern is a glob (not a literal path) iff it contains a glob magic character.
export function hasMagic(pattern) {
  return /[*?[]/.test(String(pattern));
}

// Strip a single leading "./" so "./a/b" and "a/b" resolve identically.
function normalizePattern(pattern) {
  let p = String(pattern);
  if (p.startsWith('./')) p = p.slice(2);
  return p;
}

// Escape a single literal character for embedding in a RegExp.
function escapeRegexChar(c) {
  return /[.+^${}()|\\]/.test(c) ? `\\${c}` : c;
}

// Translate a POSIX-style glob into an ANCHORED RegExp. Path-aware:
//   **/ or trailing ** matches any number of path segments (incl. zero)
//   *   matches any run of non-'/' characters
//   ?   matches a single non-'/' character
//   [..] is a character class (a leading ! is negation)
// Deterministic; no external glob dependency.
export function globToRegExp(pattern) {
  const chars = [...String(pattern)];
  let re = '';
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (c === '*') {
      if (chars[i + 1] === '*') {
        const after = chars[i + 2];
        if (after === '/') {
          re += '(?:.*/)?'; // **/  -> any depth, including zero segments
          i += 2;
        } else if (after === undefined) {
          re += '.*'; // trailing ** -> anything to end
          i += 1;
        } else {
          re += '.*'; // ** not path-bounded -> anything
          i += 1;
        }
      } else {
        re += '[^/]*';
      }
    } else if (c === '?') {
      re += '[^/]';
    } else if (c === '[') {
      // Character class: copy through the matching ']'.
      let j = i + 1;
      let cls = '[';
      if (chars[j] === '!') { cls += '^'; j += 1; }
      if (chars[j] === ']') { cls += '\\]'; j += 1; }
      while (j < chars.length && chars[j] !== ']') {
        cls += chars[j] === '\\' ? '\\\\' : chars[j];
        j += 1;
      }
      if (j >= chars.length) {
        // Unterminated class -> treat the '[' as a literal.
        re += '\\[';
      } else {
        re += `${cls}]`;
        i = j;
      }
    } else {
      re += escapeRegexChar(c);
    }
  }
  return new RegExp(`^${re}$`);
}

// Resolve the pattern list against a flat list of cwd-relative POSIX file paths.
// Returns { files, error }. Fail-closed to a USAGE error (exit 2) when:
//   - there are no patterns at all (MISSING_PATHS),
//   - a LITERAL (non-glob) path names a file that is not present (MISSING_FILE),
//   - nothing matches at all (NO_FILES_MATCHED) - an empty/missing glob is NOT a
//     clean scan.
// A single glob that matches nothing is tolerated ONLY if another pattern matched;
// an all-empty result is still a usage error.
export function resolveFiles(patterns, fileList) {
  const list = Array.isArray(fileList) ? fileList : [];
  if (!Array.isArray(patterns) || patterns.length === 0) {
    return { files: [], error: { reason: 'MISSING_PATHS', message: 'No paths were supplied to scan.' } };
  }
  const listSet = new Set(list);
  const matched = new Set();
  for (const rawPattern of patterns) {
    const pattern = normalizePattern(rawPattern);
    if (hasMagic(pattern)) {
      const re = globToRegExp(pattern);
      for (const f of list) {
        if (re.test(f)) matched.add(f);
      }
    } else if (listSet.has(pattern)) {
      matched.add(pattern);
    } else {
      // An explicitly named file that does not exist is a config error, not a
      // clean scan. Fail closed to exit 2.
      return {
        files: [],
        error: { reason: 'MISSING_FILE', message: `A named policy path was not found: ${pattern}` },
      };
    }
  }
  const files = [...matched].sort();
  if (files.length === 0) {
    return {
      files: [],
      error: { reason: 'NO_FILES_MATCHED', message: 'No files matched the supplied paths/globs.' },
    };
  }
  return { files, error: null };
}

// --- Aggregation (STRICT worst-exit-code semantics) ---------------------------

// Rank of an exit code for "worst-code" aggregation. Higher = worse. The order is
// intentional, not incidental: an internal invariant error (4) dominates a
// fail-closed could-not-analyze (3), which dominates a usage error (2), which
// dominates blocking findings (1), which dominate a clean scan (0). Any code
// OUTSIDE 0..4 is treated as the internal-worst rank so a garbage code can never
// masquerade as (or collapse to) a clean 0.
function exitRank(code) {
  switch (code) {
    case EXIT.CLEAN: return 0;
    case EXIT.FINDINGS: return 1;
    case EXIT.USAGE: return 2;
    case EXIT.FAIL_CLOSED: return 3;
    case EXIT.INTERNAL: return 4;
    default: return 4;
  }
}

// Normalize any value to a code in the contract's range; anything unexpected
// (non-integer, out of range) fails closed to INTERNAL - NEVER to CLEAN.
function normalizeExitCode(code) {
  if (code === EXIT.CLEAN || code === EXIT.FINDINGS || code === EXIT.USAGE
    || code === EXIT.FAIL_CLOSED || code === EXIT.INTERNAL) {
    return code;
  }
  return EXIT.INTERNAL;
}

// The worst (highest-rank) exit code across a list. Empty list -> USAGE (nothing
// was scanned, which is itself a config problem), never CLEAN.
export function worstExitCode(codes) {
  const list = Array.isArray(codes) ? codes : [];
  if (list.length === 0) return EXIT.USAGE;
  let worst = EXIT.CLEAN;
  for (const raw of list) {
    const code = normalizeExitCode(raw);
    if (exitRank(code) > exitRank(worst)) worst = code;
  }
  return worst;
}

// Aggregate analysis status: failed dominates partial dominates complete. Empty
// -> 'failed' (nothing could be analyzed).
export function aggregateStatus(statuses) {
  const list = Array.isArray(statuses) ? statuses : [];
  if (list.length === 0) return 'failed';
  if (list.some((s) => s === 'failed')) return 'failed';
  if (list.some((s) => s === 'partial')) return 'partial';
  if (list.every((s) => s === 'complete')) return 'complete';
  // Any unrecognized status fails closed.
  return 'failed';
}

// --- Synthetic result shapes (for config errors + per-file internal errors) ---

// A minimal scan()-compatible result for a config/usage error that never reached a
// per-file scan (missing family, missing paths, unresolved glob). Shaped so
// buildSarifLog can project it into an analyzer-state SARIF result.
function usageResult(reason, message, family) {
  return Object.freeze({
    analysisStatus: 'failed',
    analysisStates: Object.freeze([Object.freeze({
      analysisState: 'malformed', code: reason, message, path: null,
    })]),
    findings: Object.freeze([]),
    findingsCount: 0,
    blockingCount: 0,
    exitCode: EXIT.USAGE,
    reason,
    family: family != null ? family : null,
  });
}

// A minimal internal-error result for a single file whose scan threw unexpectedly.
// Fails that unit closed to INTERNAL (exit 4) - NEVER a clean 0 - so the aggregate
// surfaces it as the worst code.
function internalFileResult(family, note) {
  return Object.freeze({
    analysisStatus: 'failed',
    analysisStates: Object.freeze([Object.freeze({
      analysisState: 'internal', code: 'INTERNAL',
      message: note || 'Scan threw unexpectedly for this file.', path: null,
    })]),
    findings: Object.freeze([]),
    findingsCount: 0,
    blockingCount: 0,
    exitCode: EXIT.INTERNAL,
    reason: 'INTERNAL',
    family: family != null ? family : null,
  });
}

// --- SARIF assembly -----------------------------------------------------------

// Build one multi-run SARIF 2.1.0 log: one run per scanned unit (each carrying its
// own file URI, rules, and results, including analyzer-state results for a
// fail-closed file). Reuses the pure per-result SARIF adapter unchanged. For a
// config error with no scanned files, a single run describes the usage error so
// the SARIF is never a silent empty/clean document.
export function buildAggregateSarif(units, manifest = VERSION_MANIFEST) {
  const list = Array.isArray(units) ? units : [];
  const runs = list.map((u) => {
    const opts = isNonEmptyString(u && u.file) ? { file: u.file } : { artifactUri: 'action-inputs' };
    return buildSarifLog(u.result, opts, manifest).runs[0];
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs,
  };
}

// --- Output + summary rendering ----------------------------------------------

// Render the GITHUB_OUTPUT file body for a { name: value } map. Single-line values
// use `name=value`; a value containing a newline uses the heredoc delimiter form
// (GitHub's multi-line output syntax). Our values are all single-line scalars.
export function formatOutputs(outputs) {
  let body = '';
  for (const [k, v] of Object.entries(outputs || {})) {
    const val = String(v);
    if (val.includes('\n')) {
      const delim = `ghadelim_${k}_EOF`;
      body += `${k}<<${delim}\n${val}\n${delim}\n`;
    } else {
      body += `${k}=${val}\n`;
    }
  }
  return body;
}

// A short, low-leakage markdown step summary. Carries ONLY verdict metadata - no
// policy content, ARNs, or account ids (threat-model: do not leak policy text into
// logs or the Security tab of a private repo).
export function formatSummary(outputs, exitCode) {
  const passed = exitCode === EXIT.CLEAN;
  const verdict = passed ? 'PASS (no blocking findings)' : `FAIL (exit ${exitCode})`;
  const o = outputs || {};
  return [
    '## IAM Blast Radius',
    '',
    `- Result: ${verdict}`,
    `- Analysis status: ${o['analysis-status']}`,
    `- Findings: ${o['findings-count']} (blocking: ${o['blocking-findings-count']})`,
    `- SARIF: ${o['sarif-path']}`,
    '',
    'Reports POTENTIAL blast radius from the supplied policy context only; not effective permissions.',
    '',
  ].join('\n');
}

// --- Core (pure over an injected IO surface; NEVER touches the process) --------

/**
 * Run the action's work and return a structured result WITHOUT writing anything or
 * touching the process. Deterministic given its inputs. Never throws: any
 * unexpected error fails CLOSED to exit 4 (INTERNAL), never 0.
 *
 * @param {object} args
 * @param {object} args.env       environment (INPUT_* map)
 * @param {object} args.io        { listFiles(): string[], readFile(rel): string }
 * @param {(input:object)=>object} [args.scanFn]  injectable scan (default: real scan)
 * @param {object} [args.manifest] injectable version manifest
 * @returns {{exitCode:number, reason:string, analysisStatus:string,
 *   findingsCount:number, blockingCount:number, sarifPath:string,
 *   outputs:object, sarifLog:object, units:Array}}
 */
export function runAction({ env, io, scanFn = scan, manifest = VERSION_MANIFEST } = {}) {
  try {
    const inputs = readInputs(env);

    // --- Adapter-owned usage validation (exit 2), before any scanning. --------
    if (!isNonEmptyString(inputs.family)) {
      return finalize([{
        file: null,
        result: usageResult(
          'MISSING_FAMILY',
          'The "family" input is required and is never auto-detected '
            + '(identity | role-trust | resource | permissions-boundary | session | scp | rcp).',
          null,
        ),
      }], inputs, manifest);
    }

    const patterns = splitPaths(inputs.paths);
    const { files, error } = resolveFiles(patterns, io && typeof io.listFiles === 'function' ? io.listFiles() : []);
    if (error) {
      return finalize([{
        file: null,
        result: usageResult(error.reason, error.message, inputs.family),
      }], inputs, manifest);
    }

    // --- Scan each resolved file READ-ONLY. -----------------------------------
    const units = [];
    for (const rel of files) {
      let result;
      try {
        const text = io.readFile(rel);
        if (!isNonEmptyString(text)) {
          // An empty/unreadable file is a usage error for that unit (exit 2), not a
          // clean scan.
          result = usageResult('EMPTY_FILE', `Policy file is empty or unreadable: ${rel}`, inputs.family);
        } else {
          result = scanFn({
            text,
            family: inputs.family,
            subjectAccount: inputs.subjectAccount || undefined,
            // Forward partition ONLY when the consumer EXPLICITLY supplied one. An
            // omitted partition is '' here and maps to undefined -> "not asserted"
            // in scan(), keeping cross-partition role viability fail-closed (exit 3)
            // rather than trusting a defaulted 'aws'. Mirrors the CLI.
            partition: inputs.partition || undefined,
            threshold: inputs.failOn,
            // Wall-clock budget (S3-dos-budget): overrun fails CLOSED, never clean.
            budgetMs: inputs.budgetMs,
          });
        }
      } catch (e) {
        // A per-file throw fails THAT unit closed to INTERNAL (exit 4) - never 0 -
        // so other files still process and the aggregate surfaces the worst code.
        result = internalFileResult(inputs.family, `Scan threw for a file: ${(e && e.message) || 'error'}`);
      }
      units.push({ file: rel, result });
    }

    return finalize(units, inputs, manifest);
  } catch (e) {
    // Catch-all: an unexpected error NEVER becomes exit 0. Fail closed to INTERNAL.
    const inputs = safeInputs(env);
    const units = [{ file: null, result: internalFileResult(inputs.family, `Action wrapper error: ${(e && e.message) || 'error'}`) }];
    return finalize(units, inputs, VERSION_MANIFEST);
  }
}

function safeInputs(env) {
  try { return readInputs(env); } catch { return { sarifOutput: 'iam-blast-radius.sarif', family: null }; }
}

// Aggregate a list of scanned units into the final structured result + outputs.
function finalize(units, inputs, manifest) {
  const codes = units.map((u) => (u.result && u.result.exitCode));
  const exitCode = worstExitCode(codes);
  const findingsCount = units.reduce((n, u) => n + toCount(u.result && u.result.findingsCount), 0);
  const blockingCount = units.reduce((n, u) => n + toCount(u.result && u.result.blockingCount), 0);
  const analysisStatus = aggregateStatus(units.map((u) => u.result && u.result.analysisStatus));

  // Reason for the failure message: the reason of the FIRST unit whose code equals
  // the worst aggregate code, else 'clean'.
  let reason = 'clean';
  if (exitCode !== EXIT.CLEAN) {
    const worstUnit = units.find((u) => normalizeExitCode(u.result && u.result.exitCode) === exitCode);
    reason = (worstUnit && worstUnit.result && worstUnit.result.reason) || 'FAILED';
  }

  const sarifPath = inputs.sarifOutput;
  const outputs = {
    'sarif-path': sarifPath,
    'exit-code': String(exitCode),
    'findings-count': String(findingsCount),
    'blocking-findings-count': String(blockingCount),
    'analysis-status': analysisStatus,
  };
  const sarifLog = buildAggregateSarif(units, manifest);

  return {
    exitCode, reason, analysisStatus, findingsCount, blockingCount,
    sarifPath, outputs, sarifLog, units,
  };
}

// --- Artifact emission (pure over injected sinks; testable) -------------------

/**
 * Emit the run's artifacts through injected sinks, in the CONTRACT ORDER:
 * SARIF file first, then ALL outputs, then the step summary. Returns an ordered
 * list of the operations performed (for assertions) plus whether a write failed.
 * Never throws: a sink failure is captured, not propagated, so the caller can still
 * decide the exit code (a write failure must never downgrade a non-clean verdict).
 *
 * @param {object} final   a runAction() result
 * @param {object} env     environment (GITHUB_OUTPUT / GITHUB_STEP_SUMMARY)
 * @param {object} sinks   { writeSarif(path,text), appendOutput(text), appendSummary(text) }
 * @returns {{ops:Array<{op:string}>, writeError:(string|null)}}
 */
export function emitArtifacts(final, env, sinks) {
  const e = env || {};
  const s = sinks || {};
  const ops = [];
  let writeError = null;
  try {
    // 1. SARIF file FIRST.
    if (typeof s.writeSarif === 'function') {
      s.writeSarif(final.sarifPath, `${JSON.stringify(final.sarifLog, null, 2)}\n`);
      ops.push({ op: 'sarif' });
    }
    // 2. ALL outputs (before any fail).
    if (isNonEmptyString(e.GITHUB_OUTPUT) && typeof s.appendOutput === 'function') {
      s.appendOutput(formatOutputs(final.outputs));
      ops.push({ op: 'output' });
    }
    // 3. Step summary.
    if (isNonEmptyString(e.GITHUB_STEP_SUMMARY) && typeof s.appendSummary === 'function') {
      s.appendSummary(formatSummary(final.outputs, final.exitCode));
      ops.push({ op: 'summary' });
    }
  } catch (err) {
    writeError = (err && err.message) || 'write error';
  }
  return { ops, writeError };
}

// --- Process entry point ------------------------------------------------------

// A recursive file walk producing cwd-relative POSIX paths. Skips .git and
// node_modules (never useful policy sources, and skipping them bounds the walk),
// and never follows symlinks (avoids cycles + traversal out of the workspace).
function walkFiles(nodeFs, nodePath, baseDir) {
  const out = [];
  const MAX_FILES = 200000; // defensive bound against a pathological tree
  const SKIP_DIRS = new Set(['.git', 'node_modules']);
  const stack = [''];
  while (stack.length > 0) {
    const relDir = stack.pop();
    const absDir = relDir ? nodePath.join(baseDir, relDir) : baseDir;
    let entries;
    try {
      entries = nodeFs.readdirSync(absDir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const ent of entries) {
      if (ent.isSymbolicLink()) continue; // never follow symlinks
      const rel = relDir ? `${relDir}/${ent.name}` : ent.name;
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        stack.push(rel);
      } else if (ent.isFile()) {
        out.push(rel);
        if (out.length >= MAX_FILES) return out;
      }
    }
  }
  return out;
}

export async function main() {
  const nodeFs = await import('node:fs');
  const nodePath = await import('node:path');

  // The workspace base: the runner-provided workspace, else the process cwd.
  const baseDir = process.env.GITHUB_WORKSPACE || process.cwd();

  const io = {
    listFiles: () => walkFiles(nodeFs, nodePath, baseDir),
    readFile: (rel) => nodeFs.readFileSync(nodePath.join(baseDir, rel), 'utf8'),
  };

  let final;
  try {
    final = runAction({ env: process.env, io });
  } catch (e) {
    // runAction is designed not to throw, but belt-and-suspenders: NEVER exit 0.
    process.stderr.write(`IAM Blast Radius internal error: ${(e && e.message) || 'error'}\n`);
    process.exitCode = EXIT.INTERNAL;
    return EXIT.INTERNAL;
  }

  // Write SARIF, then ALL outputs, then the summary - BEFORE failing the action.
  const sinks = {
    writeSarif: (rel, text) => {
      const sarifAbs = nodePath.isAbsolute(rel) ? rel : nodePath.join(baseDir, rel);
      nodeFs.mkdirSync(nodePath.dirname(sarifAbs), { recursive: true });
      nodeFs.writeFileSync(sarifAbs, text);
    },
    appendOutput: (text) => nodeFs.appendFileSync(process.env.GITHUB_OUTPUT, text),
    appendSummary: (text) => nodeFs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, text),
  };
  const { writeError } = emitArtifacts(final, process.env, sinks);
  if (writeError) {
    // A write failure must NEVER downgrade a fail-closed/finding verdict to a clean
    // pass. Surface it and fail closed to INTERNAL if the run was otherwise clean.
    process.stderr.write(`IAM Blast Radius: failed to write outputs: ${writeError}\n`);
    if (final.exitCode === EXIT.CLEAN) {
      process.exitCode = EXIT.INTERNAL;
      return EXIT.INTERNAL;
    }
  }

  // Fail the action iff the aggregate exit code is non-zero. A fail-closed exit 3
  // reaches here unchanged and fails the check - it is NEVER downgraded to 0.
  if (final.exitCode !== EXIT.CLEAN) {
    process.stderr.write(`IAM Blast Radius failed (exit ${final.exitCode}): ${final.reason}\n`);
    process.exitCode = final.exitCode;
  }
  return final.exitCode;
}

// Run only when invoked directly by the runner (`node action/index.mjs`), NOT when
// imported by a test or another module. Compares this module's URL to the process
// entry point exactly like cli/iam-br.mjs, so importing it here has no side effect.
const invokedDirectly = await (async () => {
  try {
    const entry = process.argv && process.argv[1];
    if (!entry) return false;
    const { pathToFileURL } = await import('node:url');
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main();
}

export default runAction;
