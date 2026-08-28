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

import { randomUUID } from 'node:crypto';
import {
  SARIF_KEEP_RANK, resultKeepPriority, aggEstBytes, aggEstResultBytes, aggEstRunBytes, aggEstRunScaffoldBytes, aggregateFamily, aggregateSarifTruncatedResult, truncationMessage, buildAggregateSarif, VALUE_CONTROL_CHAR_RE, KEY_CONTROL_CHAR_RE,
} from './action-aggregate.mjs';
export * from './action-aggregate.mjs';
import {
  splitPaths, hasMagic, normalizePattern, escapeRegexChar, MAX_GLOB_PATTERN_LENGTH, MAX_GLOB_WILDCARDS, countGlobWildcards, globPatternTooComplex, parseCharClass, TOK_STAR2SLASH, TOK_STAR2, TOK_STAR1, TOK_ONE, compileGlobTokens, globMatchPath, globCanMatchUnderDir, globToRegExp,
} from './action-glob.mjs';
export * from './action-glob.mjs';
import { scan, EXIT, DEFAULT_BUDGET_MS } from '../cli/scan.mjs';
import { buildSarifLog } from '../cli/sarif.mjs';
// READ-ONLY canonical version manifest (browser-safe, no Node deps) so the SARIF
// semanticVersion ties to the same identifiers the engine reports.
import { VERSION_MANIFEST } from '../content/tools/iam-blast-radius/engine/version.js';
// READ-ONLY: the SINGLE source of the input byte cap. The per-file statSync pre-guard
// (main()'s io.readFile) rejects an over-cap file BEFORE reading it into memory
// (threat-model T5), importing LIMITS.MAX_BYTES from the SAME module the engine's
// validate() enforces so the pre-guard and the engine guard can never drift.
import { LIMITS } from '../content/tools/iam-blast-radius/engine/validate.js';

export { EXIT };

// --- Small helpers ------------------------------------------------------------

import { isNonEmptyString, toCount, positiveIntInput, utf8ByteLength } from './action-utils.mjs';
export * from './action-utils.mjs';


// Does an on-disk size exceed the shared input byte cap? Pure (no fs), so the pre-guard
// decision is unit-testable without touching the filesystem.
export function exceedsInputByteCap(size) {
  return Number.isFinite(size) && size > LIMITS.MAX_BYTES;
}


// S4-action-hardening: is `rel` a SAFE sarif-output target - a RELATIVE path that
// stays INSIDE the workspace? The Action's documented contract (ACTION.md) is that it
// "writes a SARIF file in the workspace; nothing more". An ABSOLUTE path
// (/etc/x, C:\x, \\host\share, a leading backslash) or a RELATIVE path that escapes the
// workspace via ".." (../evil.sarif, a/../../b) is an arbitrary-file-write outside
// GITHUB_WORKSPACE and is rejected (fail closed, exit 2). A control character (NUL, CR,
// LF, ...) is also rejected: it can never occur in a legitimate path and would let the
// value forge/suppress GITHUB_OUTPUT lines downstream. Pure string logic (POSIX + the
// Windows absolute forms), so runAction stays process-free and unit-testable.
function sarifOutputIsContained(rel) {
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
      if (depth < 0) return false; // escapes above the workspace root
    } else {
      depth += 1;
    }
  }
  return true;
}

// S4-action-hardening (ROUND 2): the LEXICAL guard above is necessary but NOT
// sufficient. A sarif-output can be a perfectly RELATIVE, "..".-free, control-char-free
// path whose leading directory component - or the target file itself - is a SYMLINK
// checked into the repo tree (an untrusted PR can add `reports` as a symlink to an
// external dir, then a maintainer-set `sarif-output: reports/x.sarif` writes THROUGH it).
// `path.resolve(base, rel).startsWith(base + sep)` is TRUE for such a path (it is
// lexically inside), yet the real write lands OUTSIDE the workspace - the exact
// arbitrary-file-write the story set out to close. The lexical check cannot see
// symlinks; only the real filesystem can. This resolves each existing path component
// through `lstat` and REJECTS if any component (a directory on the way, or the final
// file being overwritten) is a symbolic link. It fails CLOSED (returns false) if the
// workspace base itself cannot be realpath-resolved. Pure over the injected node fs/path,
// so runAction stays testable via an injected io.sarifTargetContained and the real
// writeSarif sink calls it directly. `rel` is assumed to have ALREADY passed
// sarifOutputIsContained (relative, no "..", no control chars).
export function sarifTargetContainedFs(nodeFs, nodePath, baseDir, rel) {
  let baseReal;
  try {
    baseReal = nodeFs.realpathSync(baseDir); // resolve the workspace root's own symlinks
  } catch {
    return false; // cannot vouch for containment -> fail closed
  }
  const parts = String(rel).split(/[/\\]/).filter((p) => p !== '' && p !== '.');
  let cur = baseReal;
  for (const part of parts) {
    const next = nodePath.join(cur, part);
    let st;
    try {
      st = nodeFs.lstatSync(next); // lstat: inspect the link itself, never follow it
    } catch {
      // This component does not exist yet -> a real file/dir will be created here and
      // (since "cur" is a real, symlink-free directory) it cannot escape the workspace.
      // Deeper components cannot exist either, so the remaining path is symlink-free.
      return true;
    }
    if (st.isSymbolicLink()) return false; // ANY symlink component can escape -> reject
    cur = next; // real dir/file confirmed; descend into it
  }
  return true;
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
    sarifOutput: getInput(env, 'sarif-output') || DEFAULT_SARIF_OUTPUT,
    // Wall-clock budget per policy, in ms (S3-dos-budget). A non-numeric or omitted
    // value falls back to the default; a policy whose analysis overruns fails CLOSED
    // (exit 3, RESOURCE_BUDGET_EXCEEDED), never a clean pass.
    budgetMs: budgetMsInput(getInput(env, 'budget-ms')),
    // Aggregate resource ceiling across the WHOLE matched-file set (S6-action-aggregate-cap).
    // Both are positive integers; absent / non-numeric / <= 0 falls back to the sane default.
    maxFiles: positiveIntInput(getInput(env, 'max-files'), DEFAULT_MAX_FILES),
    maxTotalBytes: positiveIntInput(getInput(env, 'max-total-bytes'), DEFAULT_MAX_TOTAL_BYTES),
    // DOCUMENT-level output ceilings for the aggregate multi-run SARIF (S2-NEW-SARIF-AGGREGATE).
    // The per-run budget (cli/sarif.mjs MAX_SARIF_BYTES) bounds ONE run; NOTHING bounded the
    // CONCATENATION of one run per scanned file, so a within-caps fan-out could push the aggregate
    // past GitHub's code-scanning upload caps (SILENTLY dropping Security-tab findings). These
    // mirror max-files / max-total-bytes: positive integers, absent / non-numeric / <= 0 defaults.
    maxSarifResults: positiveIntInput(getInput(env, 'max-sarif-results'), DEFAULT_MAX_SARIF_RESULTS),
    maxSarifBytes: positiveIntInput(getInput(env, 'max-sarif-bytes'), DEFAULT_MAX_SARIF_BYTES),
  };
}

// Coerce the budget-ms input to a number, defaulting when absent/invalid.
function budgetMsInput(raw) {
  if (!isNonEmptyString(raw)) return DEFAULT_BUDGET_MS;
  const n = Number(String(raw).trim());
  return Number.isFinite(n) ? n : DEFAULT_BUDGET_MS;
}


// --- Aggregate SARIF DOCUMENT-level output budget (S2-NEW-SARIF-AGGREGATE) -----
// GitHub code-scanning enforces upload caps on the SARIF DOCUMENT, not the individual
// runs: ~5000 RESULTS per upload (over -> GitHub SILENTLY drops the excess, NO error, so
// Security-tab findings vanish) and ~10 MB GZIP per upload (over -> a visible rejection).
// cli/sarif.mjs already bounds ONE run (MAX_SARIF_BYTES=8 MiB + SARIF_OUTPUT_TRUNCATED), but
// buildAggregateSarif concatenates one run PER scanned file with NO document budget, so a
// within-caps fan-out (e.g. 100 files x 50 findings = 5000 results at only ~3.25 MB) hits the
// RESULT cap far below the byte cap and silently loses findings. These DEFAULTS mirror the
// per-run intent, kept comfortably BELOW GitHub's caps:
import { DEFAULT_MAX_SARIF_RESULTS, DEFAULT_MAX_SARIF_BYTES, SARIF_OUTPUT_TRUNCATED_REASON, INPUT_TOO_LARGE, DEFAULT_SARIF_OUTPUT, DEFAULT_MAX_FILES, DEFAULT_MAX_TOTAL_BYTES, AGGREGATE_CAP_REASON, SYMLINK_EXCLUDED_REASON, ENUMERATION_UNREADABLE_REASON, ENUMERATION_TRUNCATED_REASON, ENUMERATION_MAX_FILES, ENUMERATION_MAX_DIRS } from './action-consts.mjs';
export * from './action-consts.mjs';

// --- paths / glob resolution --------------------------------------------------

// Split the newline-separated `paths` input into trimmed, non-empty pattern lines.

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
    // S3-dos-budget-all: reject an over-complex (over-long / wildcard-dense) pattern
    // up front. `paths` is attacker-controlled and resolved BEFORE any scan budget, so
    // an unbounded pattern is a pre-budget DoS vector; fail CLOSED to a usage error
    // (exit 2), never silently match or skip it.
    if (globPatternTooComplex(pattern)) {
      return {
        files: [],
        error: {
          reason: 'INVALID_GLOB',
          message: `A path pattern is too long or has too many wildcards: ${pattern.slice(0, 80)}`,
        },
      };
    }
    if (hasMagic(pattern)) {
      // LINEAR, ReDoS-safe matcher (globMatchPath) - NOT a compiled backtracking RegExp.
      for (const f of list) {
        if (globMatchPath(pattern, f)) matched.add(f);
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

// A minimal fail-closed (exit 3) result for a single file rejected by the MAX_BYTES
// pre-guard (threat-model T5) BEFORE it was read into memory. It mirrors the engine's
// own TOO_LARGE verdict (validate() -> scan() maps TOO_LARGE to a MALFORMED, exit-3
// fail-closed), so the browser and Action surfaces agree: an over-cap policy is
// could-not-analyze (exit 3), NEVER a clean pass and never an internal error (exit 4).
// The message carries only the limit - never the filename or policy content.
function oversizeFileResult(family) {
  return Object.freeze({
    analysisStatus: 'failed',
    analysisStates: Object.freeze([Object.freeze({
      analysisState: 'malformed', code: 'TOO_LARGE',
      message: `Policy file exceeds the ${LIMITS.MAX_BYTES}-byte input limit and was `
        + 'rejected before being read into memory. Zero findings here does NOT mean the '
        + 'policy is safe - it means the policy could not be analyzed.',
      path: null,
    })]),
    findings: Object.freeze([]),
    findingsCount: 0,
    blockingCount: 0,
    exitCode: EXIT.FAIL_CLOSED,
    reason: 'TOO_LARGE',
    family: family != null ? family : null,
  });
}

// A synthetic fail-closed (exit 3) result appended when the AGGREGATE resource ceiling is
// breached mid-loop (S6-action-aggregate-cap). It carries an explicit 'incomplete'
// analyzer-state so the partial scan is surfaced as fail-closed - NEVER clean - and projects
// into SARIF as a kind:'fail' / category:'analysis-state' result with NO security-severity
// (the tool-level truncation notification), exactly like every other could-not-analyze
// state. analysisStatus is 'partial' (some files WERE analyzed, the rest were not); the exit
// code is FAIL_CLOSED so the aggregate worst-code is at least 3 and the check fails. The
// message carries ONLY counts + the configured ceiling - never a filename or policy content
// - so it stays deterministic and leaks nothing into the SARIF / Security tab.
function aggregateCapResult(reason, message, family) {
  return Object.freeze({
    analysisStatus: 'partial',
    analysisStates: Object.freeze([Object.freeze({
      analysisState: 'incomplete', code: reason, message, path: null,
    })]),
    findings: Object.freeze([]),
    findingsCount: 0,
    blockingCount: 0,
    exitCode: EXIT.FAIL_CLOSED,
    reason,
    family: family != null ? family : null,
  });
}

function symlinkExcludedResult(message, family) {
  return Object.freeze({
    analysisStatus: 'partial',
    analysisStates: Object.freeze([Object.freeze({
      analysisState: 'incomplete', code: SYMLINK_EXCLUDED_REASON, message, path: null,
    })]),
    findings: Object.freeze([]),
    findingsCount: 0,
    blockingCount: 0,
    exitCode: EXIT.FAIL_CLOSED,
    reason: SYMLINK_EXCLUDED_REASON,
    family: family != null ? family : null,
  });
}

// The excluded-symlink paths that MATCH at least one scan pattern, using the SAME match
// semantics resolveFiles uses (linear ReDoS-safe globMatchPath for magic patterns, literal
// equality otherwise). An over-complex pattern is skipped here (resolveFiles already fails
// it closed to a usage error). Returns a stable, de-duplicated, sorted list so the
// resulting fail-closed units are deterministic. An unrelated symlink (matching no pattern)
// is never returned -> no false-fail on a monorepo full of unrelated symlinks.
export function matchedExcludedSymlinks(patterns, excludedSymlinks) {
  const pats = Array.isArray(patterns) ? patterns : [];
  const rawLinks = Array.isArray(excludedSymlinks) ? excludedSymlinks : [];
  if (rawLinks.length === 0) return [];
  // Normalize each entry to { path, isDir }. A bare-string entry (the exported-unit contract,
  // used by tests) has UNKNOWN type (isDir === null) and is treated CONSERVATIVELY as a
  // possible directory. walkFiles supplies typed { path, isDir } objects so a KNOWN
  // non-directory symlink is not over-flagged as a subtree container.
  const links = rawLinks.map((l) => {
    if (typeof l === 'string') return { path: l, isDir: null };
    const path = l && l.path;
    let isDir = null;
    if (l && l.isDir === true) isDir = true;
    else if (l && l.isDir === false) isDir = false;
    return { path: isNonEmptyString(path) ? path : '', isDir };
  }).filter((l) => isNonEmptyString(l.path));
  const matched = new Set();
  for (const rawPattern of pats) {
    const pattern = normalizePattern(rawPattern);
    if (globPatternTooComplex(pattern)) continue; // resolveFiles fails this closed already
    const magic = hasMagic(pattern);
    for (const { path: link, isDir } of links) {
      // (1) The symlink's OWN path matches the scan pattern - a FILE symlink standing in for a
      //     policy file. (S1-symlink-failclosed: the original guard.)
      if (magic ? globMatchPath(pattern, link) : link === pattern) {
        matched.add(link);
        continue;
      }
      // (2) S1-DIRSYMLINK: a DIRECTORY symlink (or an unknown-typed entry) whose hidden subtree
      //     could CONTAIN a file the pattern selects. Its own path need not match the file glob
      //     (e.g. `configs` vs `configs/*.json` or `**/*.json`). A KNOWN non-directory symlink
      //     (isDir === false) cannot contain a subtree, so it is not treated as an ancestor.
      if (isDir !== false && globCanMatchUnderDir(pattern, link)) matched.add(link);
    }
  }
  return [...matched].sort();
}

// Build the fail-closed units for every excluded symlink that matches a scan pattern. Each
// matched symlink becomes its OWN unit (its path is recorded as the unit file so the SARIF
// run points at the excluded would-be policy file). Empty when nothing matched.
function symlinkExcludedUnits(patterns, excludedSymlinks, family) {
  return matchedExcludedSymlinks(patterns, excludedSymlinks).map((rel) => ({
    file: rel,
    result: symlinkExcludedResult(
      'A policy file matching a scan pattern is a SYMLINK and was excluded from analysis '
        + '(symlinks are never followed, for traversal safety). Because its path matched the '
        + 'scan paths, this run is INCOMPLETE and FAILS CLOSED (exit 3) - it is never reported '
        + 'as a clean pass. Zero findings does NOT mean the policy is safe; it means the policy '
        + `could not be analyzed. Replace the symlink with a real file to analyze it. Path: ${rel}`,
      family,
    ),
  }));
}

// --- S2-action-enumeration: enumeration fail-closed units ---------------------
//
// walkFiles enumerates the workspace tree. TWO ways it could DROP candidate policy files
// silently, each an enumeration fail-open the audit reproduced:
//   (A) an UNREADABLE directory (chmod 000 / I/O error) whose whole subtree is invisible -
//       the old `readdirSync(...) catch { continue }` skipped it with ZERO bookkeeping, so a
//       chmod-000 subdir holding an admin policy made the Action exit 0 / complete.
//   (B) the defensive MAX_FILES enumeration ceiling returned early with NO fail-closed signal,
//       so a truncated walk (files past the ceiling never enumerated) still read clean.
// Both are closed by MIRRORING the S1 symlink-exclusion machinery: walkFiles RECORDS each
// unreadable directory + a `truncated` flag, and runAction synthesizes fail-closed (exit 3)
// 'incomplete' analyzer-state units so a partial/cut-short enumeration is NEVER a clean
// aggregate. Same shape as symlinkExcludedResult / aggregateCapResult: analysisStatus
// 'partial' (some files WERE analyzed), analysisState 'incomplete', exitCode FAIL_CLOSED,
// no security-severity - a tool-level could-not-analyze notification, never a policy finding.

function enumerationUnreadableResult(message, family) {
  return Object.freeze({
    analysisStatus: 'partial',
    analysisStates: Object.freeze([Object.freeze({
      analysisState: 'incomplete', code: ENUMERATION_UNREADABLE_REASON, message, path: null,
    })]),
    findings: Object.freeze([]),
    findingsCount: 0,
    blockingCount: 0,
    exitCode: EXIT.FAIL_CLOSED,
    reason: ENUMERATION_UNREADABLE_REASON,
    family: family != null ? family : null,
  });
}

function enumerationTruncatedResult(message, family) {
  return Object.freeze({
    analysisStatus: 'partial',
    analysisStates: Object.freeze([Object.freeze({
      analysisState: 'incomplete', code: ENUMERATION_TRUNCATED_REASON, message, path: null,
    })]),
    findings: Object.freeze([]),
    findingsCount: 0,
    blockingCount: 0,
    exitCode: EXIT.FAIL_CLOSED,
    reason: ENUMERATION_TRUNCATED_REASON,
    family: family != null ? family : null,
  });
}

// The unreadable directories whose hidden subtree COULD contain a file a scan pattern selects
// - the SAME "invisible subtree" test the S1-DIRSYMLINK path uses (globCanMatchUnderDir), so an
// unreadable directory the glob can never descend into does NOT false-fail (parity with an
// unrelated directory symlink). The workspace ROOT (recorded as '') is a special case: if the
// base directory itself cannot be enumerated, NOTHING is listable and no pattern can be
// evaluated against any file, so it ALWAYS fails closed regardless of pattern. An over-complex
// pattern is skipped (resolveFiles already fails it closed to a usage error). Returns a stable,
// de-duplicated, sorted list so the resulting fail-closed units are deterministic.
export function matchedUnreadableDirs(patterns, unreadableDirs) {
  const pats = Array.isArray(patterns) ? patterns : [];
  const dirs = Array.isArray(unreadableDirs) ? unreadableDirs : [];
  if (dirs.length === 0) return [];
  const norm = pats
    .map((p) => normalizePattern(p))
    .filter((p) => !globPatternTooComplex(p));
  const matched = new Set();
  for (const rawDir of dirs) {
    const dir = String(rawDir == null ? '' : rawDir);
    if (dir === '') { matched.add(''); continue; } // workspace root unreadable -> always fail closed
    for (const pattern of norm) {
      if (globCanMatchUnderDir(pattern, dir)) { matched.add(dir); break; }
    }
  }
  return [...matched].sort();
}

// Build the fail-closed enumeration units: one ENUMERATION_UNREADABLE unit per unreadable
// directory a scan pattern could descend into, plus a single ENUMERATION_TRUNCATED unit when
// the walk hit its file ceiling and stopped early. Empty when enumeration was complete +
// fully readable. Folded into EVERY downstream return path so the exit-3 verdict is never lost.
function enumerationUnits(patterns, unreadableDirs, truncated, family) {
  const units = matchedUnreadableDirs(patterns, unreadableDirs).map((rel) => ({
    file: isNonEmptyString(rel) ? rel : null,
    result: enumerationUnreadableResult(
      'A directory a scan pattern could descend into could NOT be enumerated during the walk '
        + '(permission denied or I/O error), so its ENTIRE subtree was invisible and any policy '
        + 'file inside it was NOT analyzed. This run is INCOMPLETE and FAILS CLOSED (exit 3) - it '
        + 'is never reported as a clean pass. Zero findings does NOT mean the policies are safe; '
        + 'it means part of the tree could not be enumerated. Fix the directory permissions and '
        + `re-run. Path: ${isNonEmptyString(rel) ? rel : '(workspace root)'}`,
      family,
    ),
  }));
  if (truncated) {
    units.push({
      file: null,
      result: enumerationTruncatedResult(
        'File enumeration hit its defensive ceiling and STOPPED before the whole tree was '
          + 'walked, so an unknown set of files past the ceiling was NOT enumerated or analyzed. '
          + 'This run is INCOMPLETE and FAILS CLOSED (exit 3) - it is never reported as a clean '
          + 'pass. Split the scan or raise the enumeration ceiling for a legitimately huge tree.',
        family,
      ),
    });
  }
  return units;
}

// --- SARIF assembly -----------------------------------------------------------

// KEEP-priority for one SARIF result under the aggregate DOCUMENT budget. Higher = kept
// first when the budget forces truncation. An analyzer-state (fail-closed) result ranks
// ABOVE every security finding: dropping a "could not analyze" signal would be a fail-OPEN
// on the fail-closed contract, so the load-bearing analysis-state category survives first.
// Security findings then rank by SEVERITY (critical > high > medium > low > info), so a
// truncated aggregate keeps the highest-severity / BLOCKING findings a reviewer most needs
// and sheds the least-severe ones - never the reverse.
export function formatOutputs(outputs) {
  let body = '';
  for (const [k, v] of Object.entries(outputs || {})) {
    const key = String(k);
    const val = String(v);
    if (KEY_CONTROL_CHAR_RE.test(key)) {
      throw new Error(`unsafe control character in output key ${JSON.stringify(key)}`);
    }
    if (VALUE_CONTROL_CHAR_RE.test(val)) {
      throw new Error(`unsafe control character in output value for ${key}`);
    }
    if (val.includes('\n')) {
      const delim = `ghadelim_${randomUUID()}_EOF`;
      if (val.split('\n').includes(delim)) {
        throw new Error(`output ${key} collides with its heredoc delimiter`);
      }
      body += `${key}<<${delim}\n${val}\n${delim}\n`;
    } else {
      body += `${key}=${val}\n`;
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
    const rawInputs = readInputs(env);

    // --- sarif-output sanitization AT THE SOURCE (class-level, S4-action-hardening) --
    // A hostile sarif-output (absolute, workspace-escaping via "..", or carrying a
    // control char / newline) must NEVER survive into an output value or the file sink
    // on ANY return path. Confining it only at its own usage-error branch left the
    // class OPEN: an EARLIER early return (e.g. MISSING_FAMILY) carried the RAW hostile
    // value straight into outputs['sarif-path'] and the SARIF write target. Neutralize
    // it ONCE, before any early return, so every downstream path - usage error, scan,
    // or the catch-all - reports and writes only the safe default. `inputs` below is
    // the SANITIZED view used everywhere; `sarifSafe` records whether the caller's
    // value was itself rejectable (its own exit-2 usage error, emitted below).
    // Two-layer containment, folded into ONE gate so EVERY early return neutralizes a
    // hostile value uniformly:
    //   (a) LEXICAL - absolute / ".."-escape / control char (string-only, always run).
    //   (b) FILESYSTEM - a relative, ".."-free path whose leading dir component or the
    //       target file itself is a SYMLINK escaping the workspace. Only the real fs can
    //       see this, so it runs through the injected io.sarifTargetContained() when the
    //       caller provides one (main() does; unit tests with a pure in-memory io do not,
    //       and correctly skip it - there is no filesystem to traverse). A resolver that
    //       throws fails CLOSED (treated as an escape). This closes the CLASS: the lexical
    //       spellings AND the symlink shape of "arbitrary write outside the workspace".
    const lexicallySafe = sarifOutputIsContained(rawInputs.sarifOutput);
    let realPathSafe = true;
    if (lexicallySafe && io && typeof io.sarifTargetContained === 'function') {
      try {
        realPathSafe = io.sarifTargetContained(rawInputs.sarifOutput) === true;
      } catch {
        realPathSafe = false; // any resolver error -> cannot vouch -> fail closed
      }
    }
    const sarifSafe = lexicallySafe && realPathSafe;
    const inputs = sarifSafe ? rawInputs : { ...rawInputs, sarifOutput: DEFAULT_SARIF_OUTPUT };

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

    // --- sarif-output confinement (exit 2), before any scanning or writing. ----
    // The Action's contract is to write a SARIF FILE IN THE WORKSPACE. A caller-
    // supplied absolute path or one escaping the workspace via ".." (or one carrying a
    // control char) would be an arbitrary-file-write / output-forgery vector, so it
    // fails CLOSED as a usage error. The hostile value was ALREADY swapped for the safe
    // default in `inputs` above, so it never reaches an output line or the file sink.
    if (!sarifSafe) {
      return finalize([{
        file: null,
        result: usageResult(
          'UNSAFE_SARIF_OUTPUT',
          'The "sarif-output" input must be a RELATIVE path inside the workspace. '
            + 'An absolute path, one escaping the workspace via "..", one containing '
            + 'a control character, or one whose directory component or target file is a '
            + 'symlink escaping the workspace is rejected.',
          inputs.family,
        ),
      }], inputs, manifest);
    }

    const patterns = splitPaths(inputs.paths);

    // S1-symlink-failclosed: recover the symlink entries walkFiles excluded (it never
    // follows a symlink, for traversal safety) and, for EACH one whose path matches a scan
    // pattern, build an explicit fail-closed (exit 3) 'incomplete' unit. Without this, a
    // symlinked policy file that matches the glob is silently dropped from enumeration and,
    // if the other real files analyze clean, the aggregate would report complete / exit 0 -
    // the exact "one file quietly falls out of the aggregate" the threat model forbids. An
    // unrelated symlink (matching no pattern) contributes nothing, so a monorepo full of
    // unrelated symlinks does not false-fail. These units are folded into EVERY downstream
    // return path (usage-error resolveFiles branch AND the scan branch) so the exit-3 verdict
    // can never be lost.
    const excludedSymlinks = io && typeof io.listExcludedSymlinks === 'function'
      ? io.listExcludedSymlinks() : [];
    const symlinkUnits = symlinkExcludedUnits(patterns, excludedSymlinks, inputs.family);

    // S2-action-enumeration: recover the enumeration fail-closed signals walkFiles records -
    // directories that could not be read (their subtree invisible) and whether the walk was
    // truncated at its file ceiling - and build fail-closed (exit 3) 'incomplete' units for
    // them. Without this, a chmod-000 subtree holding an admin policy, or a truncated walk,
    // would let the aggregate report complete / exit 0 with candidate files silently dropped -
    // the exact "a candidate policy file quietly falls out of enumeration" the threat model
    // forbids. An unreadable dir no scan pattern could descend into contributes nothing (parity
    // with an unrelated directory symlink), so a monorepo with unrelated unreadable dirs does
    // not false-fail. These units are folded into EVERY downstream return path (the usage-error
    // resolveFiles branch AND the scan branch) so the exit-3 verdict can never be lost.
    const unreadableDirs = io && typeof io.listUnreadableDirs === 'function'
      ? io.listUnreadableDirs() : [];
    const enumTruncated = io && typeof io.enumerationTruncated === 'function'
      ? io.enumerationTruncated() === true : false;
    const enumUnits = enumerationUnits(patterns, unreadableDirs, enumTruncated, inputs.family);

    const { files, error } = resolveFiles(patterns, io && typeof io.listFiles === 'function' ? io.listFiles() : []);
    if (error) {
      return finalize([{
        file: null,
        result: usageResult(error.reason, error.message, inputs.family),
      }, ...symlinkUnits, ...enumUnits], inputs, manifest);
    }

    // --- Scan each resolved file READ-ONLY, under the AGGREGATE ceiling. -------
    // `files` is already in a STABLE sorted order (resolveFiles), so which files fall
    // under vs over the cap is deterministic. Two cumulative counters bound the whole set:
    // scannedCount (matched-file COUNT ceiling) and totalBytes (aggregate UTF-8 BYTE
    // ceiling). On breach the loop STOPS and a fail-closed 'incomplete' unit is appended;
    // the findings gathered so far are preserved. See the S6-action-aggregate-cap note.
    const units = [];
    let scannedCount = 0;
    let totalBytes = 0;
    let capBreach = null;
    for (const rel of files) {
      // COUNT ceiling: once maxFiles files have been fully analyzed, the NEXT file trips
      // the cap. Checked before any read/scan so no further work is done past the ceiling.
      if (scannedCount >= inputs.maxFiles) {
        capBreach = {
          message: `Aggregate file-count ceiling reached (max-files=${inputs.maxFiles}): `
            + `${files.length} file(s) matched but only the first ${scannedCount} were analyzed `
            + 'in a stable sorted order. The remaining '
            + `${files.length - scannedCount} file(s) were NOT analyzed, so this run is INCOMPLETE `
            + 'and FAILS CLOSED (exit 3) - it is never reported as a clean pass. Raise max-files '
            + 'for a legitimately large policy set.',
        };
        break;
      }

      let text;
      try {
        text = io.readFile(rel);
      } catch (e) {
        if (e && e.code === INPUT_TOO_LARGE) {
          // The statSync pre-guard rejected an over-cap file before reading it into
          // memory (T5). Fail THAT file closed to exit 3 (TOO_LARGE) - the engine's own
          // verdict - not exit 4, and never a clean pass.
          units.push({ file: rel, result: oversizeFileResult(inputs.family) });
        } else {
          // Any other read throw fails THAT unit closed to INTERNAL (exit 4) - never 0.
          units.push({ file: rel, result: internalFileResult(inputs.family, `Could not read a file: ${(e && e.message) || 'error'}`) });
        }
        // Either way the attempt consumes a count slot so the ceiling accounts for it.
        scannedCount += 1;
        continue;
      }

      // BYTE ceiling: if analyzing this file would push the cumulative UTF-8 byte total
      // past maxTotalBytes, STOP before scanning it. (A single file larger than the ceiling
      // trips here with zero prior scans - still a fail-closed exit 3, never a clean pass;
      // the engine's per-file 1 MiB cap already fails a genuinely oversized file closed.)
      const bytes = utf8ByteLength(text);
      if (totalBytes + bytes > inputs.maxTotalBytes) {
        capBreach = {
          message: `Aggregate byte ceiling reached (max-total-bytes=${inputs.maxTotalBytes}): `
            + `${scannedCount} of ${files.length} matched file(s), totalling ${totalBytes} bytes, `
            + 'were analyzed before the next file would exceed the budget. The remaining file(s) '
            + 'were NOT analyzed, so this run is INCOMPLETE and FAILS CLOSED (exit 3) - it is never '
            + 'reported as a clean pass. Raise max-total-bytes for a legitimately large policy set.',
        };
        break;
      }
      totalBytes += bytes;
      scannedCount += 1;

      let result;
      try {
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

    // On an aggregate-ceiling breach, append the explicit fail-closed 'incomplete' unit so
    // the partial scan reports exit 3 + an analyzer-state SARIF notification - NEVER clean.
    if (capBreach) {
      units.push({ file: null, result: aggregateCapResult(AGGREGATE_CAP_REASON, capBreach.message, inputs.family) });
    }

    // Fold in the fail-closed units for any scan-pattern-matching excluded symlink so a
    // clean set of real files can NEVER report exit 0 while a matching policy symlink was
    // dropped (S1-symlink-failclosed).
    for (const u of symlinkUnits) units.push(u);

    // Fold in the enumeration fail-closed units (unreadable subtree / truncated walk) so a
    // clean set of real files can NEVER report exit 0 while a candidate subtree was skipped or
    // enumeration was cut short (S2-action-enumeration).
    for (const u of enumUnits) units.push(u);

    return finalize(units, inputs, manifest);
  } catch (e) {
    // Catch-all: an unexpected error NEVER becomes exit 0. Fail closed to INTERNAL.
    const inputs = safeInputs(env);
    const units = [{ file: null, result: internalFileResult(inputs.family, `Action wrapper error: ${(e && e.message) || 'error'}`) }];
    return finalize(units, inputs, VERSION_MANIFEST);
  }
}

function safeInputs(env) {
  try {
    const inputs = readInputs(env);
    // Never let a hostile sarif-output survive the catch-all fail-closed path either.
    if (!sarifOutputIsContained(inputs.sarifOutput)) inputs.sarifOutput = DEFAULT_SARIF_OUTPUT;
    return inputs;
  } catch { return { sarifOutput: DEFAULT_SARIF_OUTPUT, family: null }; }
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
  // The exit code above is computed from the REAL units, BEFORE the SARIF is built - so the
  // aggregate DOCUMENT-level truncation below can never downgrade (or inflate) it. The caps
  // mirror the max-files / max-total-bytes inputs (S2-NEW-SARIF-AGGREGATE).
  const sarifLog = buildAggregateSarif(units, manifest, {
    maxResults: inputs.maxSarifResults,
    maxBytes: inputs.maxSarifBytes,
    family: inputs.family,
  });

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
//
// Returns { files, excludedSymlinks, unreadableDirs, truncated }.
//   - S1-symlink-failclosed: a symlink is NEVER followed (traversal safety), but the excluded
//     entry is RECORDED rather than silently dropped, so a symlinked policy file whose path
//     MATCHES a scan pattern cannot quietly fall out of the aggregate.
//   - S2-action-enumeration (A): a directory whose readdir FAILS (chmod 000 / I/O error) is
//     RECORDED in `unreadableDirs` (as its workspace-relative path; the root is '') instead of
//     being silently skipped, so an unreadable subtree that a scan pattern could descend into
//     fails the run CLOSED (exit 3) rather than reading complete/clean.
//   - S2-action-enumeration (B): hitting the ENUMERATION FILE ceiling sets `truncated`, so a
//     cut-short walk fails CLOSED (exit 3) instead of returning a partial file set as if it
//     were the whole tree.
//   - S4-R6-dirbomb: hitting the ENUMERATION DIRECTORY ceiling ALSO sets `truncated`, so a
//     deep/wide tree of many directories but few files (which the file/symlink ceilings never
//     catch) is bounded and fails CLOSED (exit 3) too, never a silent unbounded walk. The
//     ignore rules (.git / node_modules) run BEFORE a directory is counted (a skipped dir is
//     never pushed, so never popped/counted), so a normal large repo is not forced fail-closed.
//     walkFiles never DESCENDS into a symlink, so there is no directory cycle to guard against
//     (a symlinked dir is recorded, never pushed) - the dir counter cannot be inflated by a loop.
// runAction turns these signals into fail-closed units; an unreadable dir / truncation the
// scan patterns can never reach into does not false-fail (parity with an unrelated symlink).
function walkFiles(nodeFs, nodePath, baseDir, maxFiles = ENUMERATION_MAX_FILES, maxDirs = ENUMERATION_MAX_DIRS) {
  const out = [];
  const excludedSymlinks = [];
  const unreadableDirs = [];
  const MAX_FILES = Number.isInteger(maxFiles) && maxFiles > 0 ? maxFiles : ENUMERATION_MAX_FILES;
  const MAX_DIRS = Number.isInteger(maxDirs) && maxDirs > 0 ? maxDirs : ENUMERATION_MAX_DIRS;
  const SKIP_DIRS = new Set(['.git', 'node_modules']);
  const stack = [''];
  // Cumulative count of directories POPPED from the stack (root included). Structurally the
  // twin of out.length / excludedSymlinks.length: it charges every directory the walk actually
  // processes, so N shallow chains that each stay under any depth cap still multiply into it and
  // trip the ceiling. Ignore-listed dirs are never pushed, so they never reach this counter.
  let dirsVisited = 0;
  while (stack.length > 0) {
    const relDir = stack.pop();
    // Off-by-one guard (mirrors the out.length / excludedSymlinks.length twins below): charge
    // this directory, then trip only when we have POPPED a directory BEYOND the ceiling. Gating
    // on `>` (not `>=`) lets a tree of EXACTLY MAX_DIRS directories finish and exit 0; the
    // (MAX_DIRS+1)-th popped directory is the first true overflow. Checked BEFORE readdir so the
    // walk performs at most MAX_DIRS readdir ops - the unbounded-enumeration bound is real.
    dirsVisited += 1;
    if (dirsVisited > MAX_DIRS) {
      return { files: out, excludedSymlinks, unreadableDirs, truncated: true };
    }
    const absDir = relDir ? nodePath.join(baseDir, relDir) : baseDir;
    let entries;
    try {
      entries = nodeFs.readdirSync(absDir, { withFileTypes: true });
    } catch {
      // S2-action-enumeration (A): the subtree under this directory is now INVISIBLE. RECORD
      // the unreadable path (the root is '') instead of silently continuing, so runAction can
      // fail the run closed if a scan pattern could have descended into it. Never silently drop.
      unreadableDirs.push(relDir);
      continue;
    }
    for (const ent of entries) {
      const rel = relDir ? `${relDir}/${ent.name}` : ent.name;
      if (ent.isSymbolicLink()) {
        // Never DESCEND into the symlink (traversal safety - avoids cycles + escaping the
        // workspace), but RECORD it so a would-be policy file cannot be silently excluded
        // from the aggregate (S1-symlink-failclosed). Classify the target type with a SINGLE
        // stat (resolves the link but does NOT descend or read); a DIRECTORY symlink hides a
        // whole subtree and must fail closed if that subtree could contain a matching policy
        // file (S1-DIRSYMLINK). A dangling/unreadable link cannot expose a subtree -> isDir
        // false (only its own path can match a pattern).
        let isDir = false;
        try {
          isDir = nodeFs.statSync(nodePath.join(baseDir, rel)).isDirectory();
        } catch {
          isDir = false;
        }
        excludedSymlinks.push({ path: rel, isDir });
        // Off-by-one guard: signal truncation only when an entry BEYOND the ceiling actually
        // exists. Gating on `>` (not `>=`) lets a tree of EXACTLY MAX_FILES fully-enumerated
        // entries finish and exit 0; a legitimately fully-analyzable tree must not be reported
        // ENUMERATION_TRUNCATED. The (MAX_FILES+1)-th entry is the first true overflow.
        if (excludedSymlinks.length > MAX_FILES) {
          return { files: out, excludedSymlinks, unreadableDirs, truncated: true };
        }
        continue;
      }
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(ent.name)) continue;
        stack.push(rel);
      } else if (ent.isFile()) {
        out.push(rel);
        // Off-by-one guard (see the excludedSymlinks twin above): only the (MAX_FILES+1)-th
        // file is a genuine overflow. Gate on `>` so a tree of EXACTLY MAX_FILES fully-
        // enumerated files finishes with truncated:false and exits 0, and reserve the
        // ENUMERATION_TRUNCATED fail-close for a walk that truly ran past the ceiling.
        if (out.length > MAX_FILES) {
          return { files: out, excludedSymlinks, unreadableDirs, truncated: true };
        }
      }
    }
  }
  return { files: out, excludedSymlinks, unreadableDirs, truncated: false };
}

export async function main() {
  const nodeFs = await import('node:fs');
  const nodePath = await import('node:path');

  // The workspace base: the runner-provided workspace, else the process cwd.
  const baseDir = process.env.GITHUB_WORKSPACE || process.cwd();

  // Walk the tree ONCE (memoized) and expose the real files, the excluded symlink entries,
  // AND the enumeration fail-closed signals (unreadable directories + a truncation flag);
  // walkFiles never follows a symlink but records it, and records an unreadable subtree /
  // truncated walk, so no candidate policy file can silently drop from the aggregate.
  // The enumeration ceilings are configurable via IAM_BR_ENUM_MAX_FILES / IAM_BR_ENUM_MAX_DIRS
  // (positive integers) for a legitimately huge tree; absent/invalid each falls back to its
  // default (ENUMERATION_MAX_FILES / ENUMERATION_MAX_DIRS). The DIRECTORY ceiling bounds a
  // deep/wide many-directory-few-file tree the file ceiling would never catch (S4-R6-dirbomb).
  const enumMaxFiles = positiveIntInput(process.env.IAM_BR_ENUM_MAX_FILES, ENUMERATION_MAX_FILES);
  const enumMaxDirs = positiveIntInput(process.env.IAM_BR_ENUM_MAX_DIRS, ENUMERATION_MAX_DIRS);
  let walkResult;
  const walk = () => (walkResult || (walkResult = walkFiles(nodeFs, nodePath, baseDir, enumMaxFiles, enumMaxDirs)));
  const io = {
    listFiles: () => walk().files,
    listExcludedSymlinks: () => walk().excludedSymlinks,
    listUnreadableDirs: () => walk().unreadableDirs,
    enumerationTruncated: () => walk().truncated === true,
    // Enforce the MAX_BYTES cap via statSync BEFORE readFileSync (threat-model T5): an
    // over-cap policy file is rejected with a tagged INPUT_TOO_LARGE error and is never
    // read into memory. runAction routes that to a fail-closed exit-3 unit for the file.
    readFile: (rel) => {
      const abs = nodePath.join(baseDir, rel);
      if (exceedsInputByteCap(nodeFs.statSync(abs).size)) {
        const e = new Error('policy file exceeds the input byte limit');
        e.code = INPUT_TOO_LARGE;
        throw e;
      }
      return nodeFs.readFileSync(abs, 'utf8');
    },
    // S4-action-hardening (ROUND 2): the fs-aware half of sarif-output containment.
    // runAction folds this into its sarifSafe gate so a sarif-output that traverses (or
    // is) a symlink escaping the workspace fails CLOSED (exit 2, UNSAFE_SARIF_OUTPUT) and
    // is swapped for the safe default BEFORE any write - not just rejected at the sink.
    sarifTargetContained: (rel) => sarifTargetContainedFs(nodeFs, nodePath, baseDir, rel),
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
      // Defense in depth (S4-action-hardening): runAction already rejects an unsafe
      // sarif-output as a usage error, so `rel` here is a confined relative path. The
      // sink independently REFUSES to write outside the workspace - an absolute path or
      // one that resolves above baseDir throws (captured as a writeError, never a clean
      // pass) rather than performing an arbitrary-file-write. This is the last guard on
      // the ACTION.md contract "writes a SARIF file in the workspace; nothing more".
      const baseResolved = nodePath.resolve(baseDir);
      const sarifAbs = nodePath.resolve(baseResolved, rel);
      const within = sarifAbs === baseResolved
        || sarifAbs.startsWith(baseResolved + nodePath.sep);
      if (nodePath.isAbsolute(rel) || !within) {
        throw new Error(`refusing to write SARIF outside the workspace: ${rel}`);
      }
      // Symlink-aware last guard (S4-action-hardening ROUND 2): the LEXICAL `within`
      // check is TRUE for a path like `reports/x.sarif` even when `reports` is a symlink
      // to an external dir - the write would then land outside the workspace. runAction
      // already rejects such a value via io.sarifTargetContained, but the sink verifies
      // independently (defense in depth) that no existing path component is a symlink
      // escaping the workspace before writing anything.
      if (!sarifTargetContainedFs(nodeFs, nodePath, baseResolved, rel)) {
        throw new Error(`refusing to write SARIF through a symlink outside the workspace: ${rel}`);
      }
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
//
// import.meta.url is REALPATH-resolved by Node's ESM loader, while process.argv[1] is
// the RAW path. A symlink in the invocation path (an npm `.bin` shim, `npx`, a
// self-hosted-runner checkout, a macOS `/tmp` -> `/private/tmp` link) makes a RAW-only
// compare MISS - main() never runs and the process exits 0 having done ZERO analysis,
// a false green check on a real-risk policy. FAIL CLOSED: run when EITHER the raw entry
// OR its realpath-resolved form matches, with realpathSync in its OWN try so a resolve
// failure can never silence a genuine direct invocation. An in-process import matches
// NEITHER, so importing this module (test/wrapper) still does not auto-run main().
const invokedDirectly = await (async () => {
  try {
    const entry = process.argv && process.argv[1];
    if (!entry) return false;
    const { pathToFileURL } = await import('node:url');
    const rawHref = pathToFileURL(entry).href;
    if (import.meta.url === rawHref) return true;
    let realHref = null;
    try {
      const { realpathSync } = await import('node:fs');
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

export default runAction;
