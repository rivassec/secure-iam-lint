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
import { resolveFiles, walkFiles } from './action-enumerate.mjs';
export * from './action-enumerate.mjs';
import {
  formatOutputs, formatSummary,
} from './action-output.mjs';
export * from './action-output.mjs';
import {
  exceedsInputByteCap, sarifOutputIsContained, sarifTargetContainedFs, getInput, readInputs, budgetMsInput,
} from './action-inputs.mjs';
export * from './action-inputs.mjs';
import {
  exitRank, normalizeExitCode, worstExitCode, aggregateStatus, usageResult, internalFileResult, oversizeFileResult, aggregateCapResult, symlinkExcludedResult, matchedExcludedSymlinks, symlinkExcludedUnits, enumerationUnreadableResult, enumerationTruncatedResult, matchedUnreadableDirs, enumerationUnits,
} from './action-results.mjs';
export * from './action-results.mjs';
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
import { DEFAULT_MAX_SARIF_RESULTS, DEFAULT_MAX_SARIF_BYTES, SARIF_OUTPUT_TRUNCATED_REASON, INPUT_TOO_LARGE, DEFAULT_SARIF_OUTPUT, DEFAULT_MAX_FILES, DEFAULT_MAX_TOTAL_BYTES, AGGREGATE_CAP_REASON, SYMLINK_EXCLUDED_REASON, ENUMERATION_UNREADABLE_REASON, ENUMERATION_TRUNCATED_REASON, ENUMERATION_MAX_FILES, ENUMERATION_MAX_DIRS } from './action-consts.mjs';
export * from './action-consts.mjs';



// --- Aggregation (STRICT worst-exit-code semantics) ---------------------------

// Rank of an exit code for "worst-code" aggregation. Higher = worse. The order is
// intentional, not incidental: an internal invariant error (4) dominates a
// fail-closed could-not-analyze (3), which dominates a usage error (2), which
// dominates blocking findings (1), which dominate a clean scan (0). Any code
// OUTSIDE 0..4 is treated as the internal-worst rank so a garbage code can never
// masquerade as (or collapse to) a clean 0.
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
            // Attached-resource context for the resource family (review finding D1).
            resourceContext: inputs.resourceContext,
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
    // Enforce the MAX_BYTES cap BEFORE the read (threat-model T5): an over-cap policy
    // file is rejected with a tagged INPUT_TOO_LARGE error and is never read into
    // memory. runAction routes that to a fail-closed exit-3 unit for the file.
    //
    // TOCTOU-closing (CodeQL js/file-system-race): open with O_NOFOLLOW | O_NONBLOCK
    // and fstat the OPEN FD - not the path - so the byte-cap check and the read bind
    // to the exact inode we hold; a rename / symlink swap between a path-stat and a
    // path-read cannot slip a different (or a blocking) file in. walkFiles already
    // excludes symlinks + non-regular files during enumeration, so this is defense in
    // depth on the read itself. O_NOFOLLOW/O_NONBLOCK are undefined on Windows -> 0
    // (the Action runs on Linux runners).
    readFile: (rel) => {
      const abs = nodePath.join(baseDir, rel);
      const C = nodeFs.constants;
      const flags = (C.O_RDONLY ?? 0) | (C.O_NOFOLLOW ?? 0) | (C.O_NONBLOCK ?? 0);
      const fd = nodeFs.openSync(abs, flags);
      try {
        const st = nodeFs.fstatSync(fd);
        // Re-check on the fd we hold (review finding E1): walkFiles already excludes
        // non-regular files, but never read a device/FIFO/dir on the open fd - O_NONBLOCK
        // stopped a FIFO from blocking the open, and this rejects it before any read so a
        // non-regular fd can never be read unbounded. Fail closed.
        if (!st.isFile()) {
          const e = new Error('refusing to read a non-regular file');
          e.code = INPUT_TOO_LARGE;
          throw e;
        }
        if (exceedsInputByteCap(st.size)) {
          const e = new Error('policy file exceeds the input byte limit');
          e.code = INPUT_TOO_LARGE;
          throw e;
        }
        return nodeFs.readFileSync(fd, 'utf8');
      } finally {
        nodeFs.closeSync(fd);
      }
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
