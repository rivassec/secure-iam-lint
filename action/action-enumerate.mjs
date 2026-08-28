// action-enumerate.mjs - file selection for the Action: resolveFiles (pattern->file resolution, fail-closed on missing/no-match) + walkFiles (symlink-safe, ceiling-bounded directory walk). Extracted from index.mjs (behavior-preserving).
import { hasMagic, normalizePattern, globPatternTooComplex, globMatchPath } from './action-glob.mjs';
import { ENUMERATION_MAX_FILES, ENUMERATION_MAX_DIRS } from './action-consts.mjs';

// Does an on-disk size exceed the shared input byte cap? Pure (no fs), so the pre-guard
// decision is unit-testable without touching the filesystem.
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
export function walkFiles(nodeFs, nodePath, baseDir, maxFiles = ENUMERATION_MAX_FILES, maxDirs = ENUMERATION_MAX_DIRS) {
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
