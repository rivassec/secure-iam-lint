// action-inputs.mjs - GitHub Action input reading + parsing (getInput/readInputs, budget + positive-int ceilings) and the confined SARIF-output path guard (sarifTargetContainedFs). Extracted from index.mjs (behavior-preserving).
import { isNonEmptyString, positiveIntInput } from './action-utils.mjs';
import { DEFAULT_BUDGET_MS } from '../cli/scan.mjs';
import { LIMITS } from '../content/tools/iam-blast-radius/engine/validate.js';
import { DEFAULT_MAX_FILES, DEFAULT_MAX_TOTAL_BYTES, DEFAULT_MAX_SARIF_RESULTS, DEFAULT_MAX_SARIF_BYTES, DEFAULT_SARIF_OUTPUT, INPUT_TOO_LARGE, AGGREGATE_CAP_REASON, SYMLINK_EXCLUDED_REASON, ENUMERATION_MAX_FILES, ENUMERATION_MAX_DIRS, ENUMERATION_UNREADABLE_REASON, ENUMERATION_TRUNCATED_REASON, SARIF_OUTPUT_TRUNCATED_REASON } from './action-consts.mjs';

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
export function sarifOutputIsContained(rel) {
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
    // The resource family's attached-resource context (review finding D1): built from
    // resource-arn / resource-type (+ optional resource-account). Omitted entirely when
    // neither is given, so a resource policy WITHOUT context still fails closed.
    resourceContext: (() => {
      const arn = getInput(env, 'resource-arn');
      const type = getInput(env, 'resource-type');
      const account = getInput(env, 'resource-account');
      return (arn || type)
        ? { type: type || undefined, arn: arn || undefined, account: account || undefined }
        : undefined;
    })(),
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
export function budgetMsInput(raw) {
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

// --- paths / glob resolution --------------------------------------------------

// Split the newline-separated `paths` input into trimmed, non-empty pattern lines.

// Resolve the pattern list against a flat list of cwd-relative POSIX file paths.
// Returns { files, error }. Fail-closed to a USAGE error (exit 2) when:
//   - there are no patterns at all (MISSING_PATHS),
//   - a LITERAL (non-glob) path names a file that is not present (MISSING_FILE),
//   - nothing matches at all (NO_FILES_MATCHED) - an empty/missing glob is NOT a
//     clean scan.
// A single glob that matches nothing is tolerated ONLY if another pattern matched;
