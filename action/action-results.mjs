// action-results.mjs - exit-code aggregation (worstExitCode/aggregateStatus) + the fail-closed per-file/unit result builders (usage/internal/oversize/aggregate-cap/symlink-excluded/enumeration-unreadable/truncated). Extracted from index.mjs (behavior-preserving).
import { EXIT } from '../cli/scan.mjs';
import { LIMITS } from '../content/tools/iam-blast-radius/engine/validate.js';
import { isNonEmptyString } from './action-utils.mjs';
import { hasMagic, normalizePattern, globPatternTooComplex, globMatchPath, globCanMatchUnderDir } from './action-glob.mjs';
import { SYMLINK_EXCLUDED_REASON, ENUMERATION_UNREADABLE_REASON, ENUMERATION_TRUNCATED_REASON } from './action-consts.mjs';

export function exitRank(code) {
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
export function normalizeExitCode(code) {
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
export function usageResult(reason, message, family) {
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
export function internalFileResult(family, note) {
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
export function oversizeFileResult(family) {
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
export function aggregateCapResult(reason, message, family) {
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

export function symlinkExcludedResult(message, family) {
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
export function symlinkExcludedUnits(patterns, excludedSymlinks, family) {
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

export function enumerationUnreadableResult(message, family) {
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

export function enumerationTruncatedResult(message, family) {
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
export function enumerationUnits(patterns, unreadableDirs, truncated, family) {
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
