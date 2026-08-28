// action-consts.mjs - shared SARIF aggregate output ceilings + truncation code for the
// GitHub Action. Read by readInputs() (index.mjs) and the aggregate builder
// (action-aggregate.mjs). Extracted from index.mjs (behavior-preserving; pure data).
//
// The aggregate SARIF output caps, chosen to sit under GitHub code-scanning's ingest limits:
//   - RESULTS below 5000 (the silent-drop cap), and
//   - an uncompressed BYTE proxy below the 10 MB gzip cap. 9 MiB uncompressed is safe even for
//     incompressible content (9 MiB ~= 9.44 MB < 10 MB) and SARIF gzips far smaller in practice;
//     it also stays above the per-run 8 MiB cap so a single maximal run still fits.
// Both are CONFIGURABLE (max-sarif-results / max-sarif-bytes inputs) so a legitimately large
// aggregate can raise them rather than be false-truncated.
export const DEFAULT_MAX_SARIF_RESULTS = 4500;
export const DEFAULT_MAX_SARIF_BYTES = 9 * 1024 * 1024; // 9 MiB (9437184 bytes) uncompressed proxy
// The aggregate truncation analyzer-state code. Deliberately the SAME code the per-run budget
// emits (cli/sarif.mjs truncationState) so a consumer recognizes ONE "output was truncated"
// signal on either surface.
export const SARIF_OUTPUT_TRUNCATED_REASON = 'SARIF_OUTPUT_TRUNCATED';

// Tagged-error code raised by the per-file statSync pre-guard when a file exceeds
// LIMITS.MAX_BYTES. The scan loop recognizes it and fails THAT file closed to exit 3
// (TOO_LARGE) - the same verdict the engine's validate() would produce - never exit 4
// (an unreadable-file internal error) and never a clean pass.
export const INPUT_TOO_LARGE = 'INPUT_TOO_LARGE';

// The default SARIF output path (mirrors action.yml). Used as the fallback whenever a
// caller-supplied sarif-output is rejected as unsafe, so a hostile path never
// propagates to an output value or a file write.
export const DEFAULT_SARIF_OUTPUT = 'iam-blast-radius.sarif';

// --- Aggregate resource ceiling (S6-action-aggregate-cap) ---------------------
// resolveFiles + the per-file scan loop budget EACH file independently (the engine's
// per-file 1 MiB byte cap; a per-file work/wall-clock budgetMs). Nothing bounded the
// CUMULATIVE cost across MANY files beyond the static walkFiles MAX_FILES=200000: a fork
// PR matching thousands of near-cap policy files scales CI runtime linearly into tens of
// minutes (the plan's ~200 files ~= 20s -> thousands -> minutes). Each file still fails
// CLOSED, so this is NOT a fail-OPEN - it is an availability/cost DoS on the fork-PR
// surface. The ceiling is DETERMINISTIC on TWO axes measured in the loop:
//   - a matched-file COUNT ceiling (bounds the fixed per-file parser/setup overhead of
//     very many tiny files), AND
//   - an aggregate UTF-8 BYTE ceiling (bounds parser work; count alone misses a few giant
//     files, bytes alone misses the per-file overhead of a huge file count).
// No wall-clock is consulted here: a wall-clock-primary cap makes tests flaky and CI
// nondeterministic; the per-file budgetMs stays the ONLY time-based guard. Both ceilings
// are CONFIGURABLE (max-files / max-total-bytes inputs) with GENEROUS defaults, because a
// too-tight hardcoded cap would false-fail-closed on a legitimate large monorepo - an
// adoption-killing false positive for a Marketplace security gate. Files are traversed in
// the STABLE sorted order resolveFiles already produces, so which files fall under vs over
// the cap is reproducible. On breach the loop STOPS, the findings gathered so far are still
// emitted, and an explicit fail-closed 'incomplete' analyzer-state (exit 3) is appended -
// the partial scan is NEVER reported as clean.
export const DEFAULT_MAX_FILES = 1000;

export const DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024; // 64 MiB (67108864 bytes) aggregate

export const AGGREGATE_CAP_REASON = 'AGGREGATE_CAP_EXCEEDED';

// A synthetic fail-closed (exit 3) result appended when a SYMLINK whose path matches a
// scan pattern was excluded from enumeration (S1-symlink-failclosed). walkFiles never
// follows symlinks (traversal safety), so such a would-be policy file is invisible to the
// scan; if the OTHER real files analyze clean, the aggregate would otherwise report
// complete / exit 0 while a matching policy file quietly fell out - the exact drop the
// threat model forbids. This carries an explicit 'incomplete' analyzer-state so the run is
// surfaced as fail-closed (NEVER clean) and projects into SARIF as a kind:'fail' /
// category:'analysis-state' notification with NO security-severity, exactly like every
// other could-not-analyze state. analysisStatus is 'partial' (the OTHER files were
// analyzed; this one was not) and the exit code is FAIL_CLOSED so the aggregate worst-code
// is at least 3 and the check fails.
export const SYMLINK_EXCLUDED_REASON = 'SYMLINK_EXCLUDED';

export const ENUMERATION_UNREADABLE_REASON = 'ENUMERATION_UNREADABLE';

export const ENUMERATION_TRUNCATED_REASON = 'ENUMERATION_TRUNCATED';

// The defensive enumeration ceiling: an upper bound on how many files (or excluded symlink
// entries) walkFiles will record before it stops, so a pathological tree cannot make
// enumeration run unbounded. Hitting it is a FAIL-CLOSED condition (S2-action-enumeration):
// the walk sets `truncated` and runAction surfaces an ENUMERATION_TRUNCATED exit-3 unit, never
// a silent clean pass. Configurable via the IAM_BR_ENUM_MAX_FILES env override (a positive
// integer) for a legitimately huge tree; absent/invalid falls back to this default.
export const ENUMERATION_MAX_FILES = 200000;

// The defensive DIRECTORY ceiling (S4-R6-dirbomb): an upper bound on how many directories
// walkFiles will POP+process before it stops, so a deep/wide tree of MANY directories but FEW
// files (e.g. 1000 chains x 2000 deep = ~2M readdir ops, all well under MAX_FILES) cannot make
// enumeration run unbounded - the file/symlink ceilings never trip because almost no files
// exist, yet the walk does one readdir per directory. This is the CUMULATIVE dir-count twin of
// ENUMERATION_MAX_FILES: hitting it is the same FAIL-CLOSED condition (sets `truncated`, so
// runAction surfaces an exit-3 ENUMERATION_TRUNCATED unit, never a silent clean pass).
// Configurable via the IAM_BR_ENUM_MAX_DIRS env override (a positive integer) for a
// legitimately huge tree; absent/invalid falls back to this default. Sized generously so a
// normal large monorepo is never forced fail-closed, while a directory bomb is bounded.
export const ENUMERATION_MAX_DIRS = 500000;
