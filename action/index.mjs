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

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

// Tagged-error code raised by the per-file statSync pre-guard when a file exceeds
// LIMITS.MAX_BYTES. The scan loop recognizes it and fails THAT file closed to exit 3
// (TOO_LARGE) - the same verdict the engine's validate() would produce - never exit 4
// (an unreadable-file internal error) and never a clean pass.
const INPUT_TOO_LARGE = 'INPUT_TOO_LARGE';

// Does an on-disk size exceed the shared input byte cap? Pure (no fs), so the pre-guard
// decision is unit-testable without touching the filesystem.
export function exceedsInputByteCap(size) {
  return Number.isFinite(size) && size > LIMITS.MAX_BYTES;
}

// The default SARIF output path (mirrors action.yml). Used as the fallback whenever a
// caller-supplied sarif-output is rejected as unsafe, so a hostile path never
// propagates to an output value or a file write.
const DEFAULT_SARIF_OUTPUT = 'iam-blast-radius.sarif';

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
    sarifOutput: getInput(env, 'sarif-output') || DEFAULT_SARIF_OUTPUT,
    // Wall-clock budget per policy, in ms (S3-dos-budget). A non-numeric or omitted
    // value falls back to the default; a policy whose analysis overruns fails CLOSED
    // (exit 3, RESOURCE_BUDGET_EXCEEDED), never a clean pass.
    budgetMs: budgetMsInput(getInput(env, 'budget-ms')),
    // Aggregate resource ceiling across the WHOLE matched-file set (S6-action-aggregate-cap).
    // Both are positive integers; absent / non-numeric / <= 0 falls back to the sane default.
    maxFiles: positiveIntInput(getInput(env, 'max-files'), DEFAULT_MAX_FILES),
    maxTotalBytes: positiveIntInput(getInput(env, 'max-total-bytes'), DEFAULT_MAX_TOTAL_BYTES),
  };
}

// Coerce the budget-ms input to a number, defaulting when absent/invalid.
function budgetMsInput(raw) {
  if (!isNonEmptyString(raw)) return DEFAULT_BUDGET_MS;
  const n = Number(String(raw).trim());
  return Number.isFinite(n) ? n : DEFAULT_BUDGET_MS;
}

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

// Coerce a positive-integer input, defaulting when absent / non-numeric / non-integer /
// <= 0. A zero or negative ceiling is nonsensical (it would fail-closed on the very first
// file); such a value falls back to the sane default rather than bricking the Action.
function positiveIntInput(raw, dflt) {
  if (!isNonEmptyString(raw)) return dflt;
  const n = Number(String(raw).trim());
  return Number.isInteger(n) && n > 0 ? n : dflt;
}

// UTF-8 byte length of a string, for the aggregate BYTE ceiling. TextEncoder is a Node +
// Web global (no import, pure, deterministic); String.prototype.length UNDER-counts
// multibyte content, so bytes - not UTF-16 code units - are what the ceiling measures. One
// shared instance avoids per-file churn.
const AGG_UTF8 = new TextEncoder();
function utf8ByteLength(s) { return AGG_UTF8.encode(String(s)).length; }

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

// --- ReDoS-safe LINEAR path-glob matcher (S3-dos-budget-all) ------------------
// The action `paths` input is ATTACKER-CONTROLLED and is resolved BEFORE any scan
// wall-clock budget is armed, so a glob compiled to a backtracking RegExp is a
// pre-budget ReDoS: a crafted pattern such as `*a*a*a*...*b` (many '*' separated by
// a repeated literal) matched against a moderately long file path drives the anchored
// RegExp into exponential backtracking and hangs the whole Action - a denial of
// service that no downstream budget can stop because it fires during glob resolution.
// This matcher decides the SAME path-glob language with a DYNAMIC-PROGRAMMING
// automaton that is O(patternTokens x pathLength) with NO backtracking, so its cost
// is a bounded polynomial of the (capped) pattern and path lengths - the ReDoS class
// is removed, not merely the one crafted spelling. globToRegExp() is retained for its
// exported contract but is length/wildcard-capped below and is no longer on the
// resolveFiles hot path.

// Hard caps applied BEFORE any glob work. A pattern beyond these bounds is not a
// legitimate path filter; it fails CLOSED to a usage error rather than being matched.
const MAX_GLOB_PATTERN_LENGTH = 4096;
const MAX_GLOB_WILDCARDS = 256;

// Count the glob "magic" characters ('*', '?', '[') in a pattern - the axis a ReDoS
// pattern maximizes. Used purely to reject an over-complex pattern up front.
function countGlobWildcards(pattern) {
  let n = 0;
  const s = String(pattern);
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '*' || c === '?' || c === '[') n += 1;
  }
  return n;
}

// A pattern is REJECTABLE (too long, or too many wildcards) and must fail closed.
function globPatternTooComplex(pattern) {
  const s = String(pattern);
  return s.length > MAX_GLOB_PATTERN_LENGTH || countGlobWildcards(s) > MAX_GLOB_WILDCARDS;
}

// Parse a bracket char-class starting at `chars[start]` === '['. Returns
// { pred, next } where pred(ch) tests one character and `next` is the index of the
// char AFTER the closing ']'. If the class is unterminated, returns null so the caller
// treats '[' as a literal (mirrors globToRegExp's unterminated-class fallback).
function parseCharClass(chars, start) {
  let j = start + 1;
  let negate = false;
  if (chars[j] === '!') { negate = true; j += 1; }
  const singles = new Set();
  const ranges = []; // [lo, hi] inclusive code points
  // A ']' immediately after '[' (or '[!') is a literal member, not the terminator.
  if (chars[j] === ']') { singles.add(']'); j += 1; }
  let closed = false;
  while (j < chars.length) {
    const c = chars[j];
    if (c === ']') { closed = true; j += 1; break; }
    // Range a-z: a member, then '-', then a member that is not the closing ']'.
    if (chars[j + 1] === '-' && chars[j + 2] !== undefined && chars[j + 2] !== ']') {
      ranges.push([c.codePointAt(0), chars[j + 2].codePointAt(0)]);
      j += 3;
      continue;
    }
    singles.add(c);
    j += 1;
  }
  if (!closed) return null; // unterminated -> caller treats '[' as a literal
  const pred = (ch) => {
    let inSet = singles.has(ch);
    if (!inSet) {
      const cp = ch.codePointAt(0);
      for (const [lo, hi] of ranges) {
        if (cp >= lo && cp <= hi) { inSet = true; break; }
      }
    }
    return negate ? !inSet : inSet;
  };
  return { pred, next: j };
}

// Token kinds for the linear matcher.
const TOK_STAR2SLASH = 0; // '**/'  -> zero or more full path segments  ((?:.*/)?)
const TOK_STAR2 = 1;      // '**'   -> any run incl. '/'                (.*)
const TOK_STAR1 = 2;      // '*'    -> any run excl. '/'                ([^/]*)
const TOK_ONE = 3;        // '?' / class / literal -> exactly one char via pred

// Compile a glob pattern into a token list with the SAME semantics globToRegExp
// encodes. Deterministic; no RegExp is ever constructed. Returns an array of tokens.
function compileGlobTokens(pattern) {
  const chars = [...String(pattern)];
  const tokens = [];
  for (let i = 0; i < chars.length; i++) {
    const c = chars[i];
    if (c === '*') {
      if (chars[i + 1] === '*') {
        const after = chars[i + 2];
        if (after === '/') {
          tokens.push({ k: TOK_STAR2SLASH });
          i += 2; // consume the second '*' and the '/'
        } else {
          tokens.push({ k: TOK_STAR2 }); // trailing '**' or '**' not path-bounded
          i += 1; // consume the second '*'
        }
      } else {
        tokens.push({ k: TOK_STAR1 });
      }
    } else if (c === '?') {
      tokens.push({ k: TOK_ONE, pred: (ch) => ch !== '/' });
    } else if (c === '[') {
      const parsed = parseCharClass(chars, i);
      if (parsed === null) {
        tokens.push({ k: TOK_ONE, pred: (ch) => ch === '[' }); // literal '['
      } else {
        tokens.push({ k: TOK_ONE, pred: parsed.pred });
        i = parsed.next - 1; // -1 because the for-loop will i++
      }
    } else {
      tokens.push({ k: TOK_ONE, pred: (ch) => ch === c });
    }
  }
  return tokens;
}

// Decide whether `pattern` matches the whole path `text`, LINEARLY (dynamic
// programming, no backtracking). O(tokens x textLength). ReDoS-immune.
export function globMatchPath(pattern, text) {
  const tokens = compileGlobTokens(pattern);
  const t = String(text);
  const T = t.length;
  // dp[j] = can tokens[i..end] match text[j..end]. Seed for i === tokens.length:
  // only a fully-consumed text matches the empty token suffix.
  let dp = new Array(T + 1).fill(false);
  dp[T] = true;
  for (let i = tokens.length - 1; i >= 0; i--) {
    const tok = tokens[i];
    const ndp = new Array(T + 1).fill(false);
    if (tok.k === TOK_ONE) {
      for (let j = 0; j < T; j++) {
        if (dp[j + 1] && tok.pred(t[j])) ndp[j] = true;
      }
    } else if (tok.k === TOK_STAR1) {
      // '[^/]*': match zero (dp[j]) or one more non-'/' char and stay (ndp[j+1]).
      for (let j = T; j >= 0; j--) {
        let v = dp[j];
        if (!v && j < T && t[j] !== '/' && ndp[j + 1]) v = true;
        ndp[j] = v;
      }
    } else if (tok.k === TOK_STAR2) {
      // '.*': match zero (dp[j]) or one more char of any kind and stay (ndp[j+1]).
      for (let j = T; j >= 0; j--) {
        let v = dp[j];
        if (!v && j < T && ndp[j + 1]) v = true;
        ndp[j] = v;
      }
    } else { // TOK_STAR2SLASH: '(?:.*/)?'
      for (let j = T; j >= 0; j--) {
        let v = dp[j]; // zero path segments
        if (!v && j < T && ndp[j + 1]) v = true; // stay inside the '.*' run
        if (!v && j < T && t[j] === '/' && dp[j + 1]) v = true; // closing '/', advance token
        ndp[j] = v;
      }
    }
    dp = ndp;
  }
  return dp[0];
}

// Translate a POSIX-style glob into an ANCHORED RegExp. Path-aware:
//   **/ or trailing ** matches any number of path segments (incl. zero)
//   *   matches any run of non-'/' characters
//   ?   matches a single non-'/' character
//   [..] is a character class (a leading ! is negation)
// Deterministic; no external glob dependency.
export function globToRegExp(pattern) {
  // S3-dos-budget-all: retained for its exported contract, but HARD-CAPPED so it can
  // never be used to build a catastrophically-backtracking RegExp from an over-long or
  // wildcard-dense attacker pattern. Beyond the caps it throws a tagged error; callers
  // that resolve untrusted `paths` use the linear globMatchPath() instead and never
  // reach this. (An anchored RegExp of many adjacent '.*'/'[^/]*' quantifiers is the
  // ReDoS vector; the cap bounds the quantifier count so the fallback stays safe too.)
  if (globPatternTooComplex(pattern)) {
    const err = new Error('glob pattern exceeds complexity limits');
    err.code = 'INVALID_GLOB';
    throw err;
  }
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
//
// S4-action-hardening: two hardenings against GITHUB_OUTPUT injection.
//   1. A value containing any C0 control char OTHER than the newline that legitimately
//      triggers the heredoc form (NUL, CR, vertical tab, ...) is REJECTED (throw ->
//      caught by emitArtifacts as a writeError -> fail closed): such a char never
//      belongs in these scalar outputs and could split/forge `key=value` lines. The
//      key is likewise validated.
//   2. The heredoc delimiter is UNPREDICTABLE (a per-value random token), not the old
//      guessable `ghadelim_<key>_EOF`. With a random delimiter a crafted multi-line
//      value cannot close the heredoc early to inject forged/suppressed output lines;
//      as a further guard a value that still contains the chosen delimiter line is
//      rejected outright.
// Every C0 control char EXCEPT the newline (0x0a) that legitimately triggers the
// heredoc form: 0x00-0x09 and 0x0b-0x1f. A value carrying any of these is rejected.
const VALUE_CONTROL_CHAR_RE = /[\u0000-\u0009\u000b-\u001f]/;
// An output KEY is a bare identifier: any C0 control char (incl. newline) is unsafe.
const KEY_CONTROL_CHAR_RE = /[\u0000-\u001f]/;
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
    const { files, error } = resolveFiles(patterns, io && typeof io.listFiles === 'function' ? io.listFiles() : []);
    if (error) {
      return finalize([{
        file: null,
        result: usageResult(error.reason, error.message, inputs.family),
      }], inputs, manifest);
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
