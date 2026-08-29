#!/usr/bin/env node
// failopen-lint: a DETERMINISTIC fail-open hotspot scanner for the shipped
// IAM Blast Radius tool. It scans every shipped file for the recurring
// FAIL-OPEN TAXONOMY (the bug classes we keep hitting) and prints hotspots as
// file:line + class + the offending snippet. It exits non-zero when any
// non-allowlisted hotspot fires.
//
// IMPORTANT (see README.md): this lint ROUTES ATTENTION. A clean run does NOT
// prove the tool fails closed; it only means these syntactic smells were not
// found. A firing hotspot is a place a human must read, not an automatic bug.
//
// No runtime deps (Node built-ins only). ASCII only. Deterministic: same tree
// in -> same findings out, sorted by (file, line, class).

import { readFileSync, writeFileSync, existsSync, realpathSync, readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve, relative } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
// audit/lint -> up 4 = repo root (tools/iam-blast-radius/audit/lint).
const REPO_ROOT = resolve(HERE, '../../../../');

// ---------------------------------------------------------------------------
// Target files: the SHIPPED surface that must fail closed.
// ---------------------------------------------------------------------------
const ENGINE_DIR = 'content/tools/iam-blast-radius/engine';
// Scanned engine modules are derived from the directory itself, NOT a hand-maintained
// list: a decomposition that adds/renames a module is scanned automatically. A stale
// hardcoded list previously scanned 24 of 63 files, leaving 62% of the engine outside
// the fail-open tripwire. The coverage==tree property is asserted by failopen-lint.test.js
// so this cannot silently drift again.
// Stage-13 PERI-1: an engine module is any import-loadable source, NOT only a flat
// `.js`. A dropped `.mjs` / `.cjs` module was import-loadable yet invisible to this
// keyspace (the filter was literal `.endsWith('.js')`), so a shipped module carrying a
// silent-catch-clean fail-open could ship with every gate green. The keyspace now
// matches .js/.mjs/.cjs (excluding test files) via one shared predicate, so lint.mjs and
// failopen-lint.test.js (coverage==tree, deletion tripwire) can never disagree on it.
export function isEngineModule(f) {
  return /\.(js|mjs|cjs)$/.test(f) && !/\.test\.(js|mjs|cjs)$/.test(f);
}

// Stage-14 PERI-NONRECURSIVE-READDIR: walk a shipped source directory RECURSIVELY,
// returning repo-relative module paths. A non-recursive readdir left any SUBDIRECTORY
// module (e.g. engine/sub/x.js after the planned F6 decomposition) import-loadable yet
// invisible to the lint keyspace, the coverage==tree assertion, and the deletion
// tripwire. Exported so the guard tests derive the tree the SAME way.
export function walkModules(absDir, relBase) {
  const out = [];
  const ents = readdirSync(absDir, { withFileTypes: true });
  for (const e of ents) {
    const rel = `${relBase}/${e.name}`;
    if (e.isDirectory()) {
      out.push(...walkModules(resolve(absDir, e.name), rel));
    } else if (isEngineModule(e.name)) {
      out.push(rel);
    }
  }
  return out.sort();
}

const ENGINE_FILES_ON_DISK = walkModules(resolve(REPO_ROOT, ENGINE_DIR), ENGINE_DIR);

// Stage-14 PERI-ACTION-SUBTREE-LINT-KEYSPACE: the action/ subtree ships 8 loadable
// modules that index.mjs imports; only 'action/index.mjs' was hardcoded, leaving the
// rest unscanned. Derive action/ and cli/ the same recursive way as engine/ so every
// shipped CLI/action module is in the fail-open keyspace. (Deletion of any of these is
// also caught at import time - index.mjs / iam-br.mjs import them - so a manifest
// deletion tripwire is only maintained for the larger, refactor-churned engine/ tree.)
const ACTION_FILES_ON_DISK = walkModules(resolve(REPO_ROOT, 'action'), 'action');
const CLI_FILES_ON_DISK = walkModules(resolve(REPO_ROOT, 'cli'), 'cli');

// Stage-15 periphery: the content root ships browser-loadable modules beyond app.js /
// worker.js (e.g. samples.js, imported by app.js). Hardcoding only app.js + worker.js
// left the rest outside the keyspace. Walk the whole content root recursively; the
// engine/ subtree it also returns is deduped against ENGINE_FILES (which keeps the
// manifest deletion tripwire), so nothing is lost and every shipped content-root module
// is scanned.
const CONTENT_ROOT = 'content/tools/iam-blast-radius';
const CONTENT_ROOT_FILES = walkModules(resolve(REPO_ROOT, CONTENT_ROOT), CONTENT_ROOT);

// Stage-12 #2: deriving the target list SOLELY from readdir made --check-targets blind to
// DELETION - a removed engine module simply vanishes from the listing, so it can never be
// `missing`, and the whole 63-module guard surface could be gutted with the gate still
// green. The committed manifest is the deletion tripwire: TARGET_FILES is the UNION of
// what is on disk (so a NEW module is still auto-scanned) and what the manifest REQUIRES
// (so a DELETED module is existsSync-checked -> `missing` -> non-zero exit). The manifest
// is kept in lockstep with the directory by failopen-lint.test.js (coverage==tree in BOTH
// directions), so adding a module without listing it fails CI - it cannot silently drift.
const ENGINE_MANIFEST = JSON.parse(
  readFileSync(resolve(HERE, 'engine-manifest.json'), 'utf8'),
);
const ENGINE_FILES_REQUIRED = ENGINE_MANIFEST
  .map((f) => `${ENGINE_DIR}/${f}`);
const ENGINE_FILES = [...new Set([...ENGINE_FILES_ON_DISK, ...ENGINE_FILES_REQUIRED])].sort();

const TARGET_FILES = [...new Set([
  ...ENGINE_FILES,
  ...CONTENT_ROOT_FILES,
  ...CLI_FILES_ON_DISK,
  ...ACTION_FILES_ON_DISK,
])].sort();

const ENGINE_REL_PREFIX = `${ENGINE_DIR}/`;

// ---------------------------------------------------------------------------
// Tokenizer-aware helpers: strip strings/comments so brace matching and token
// scans do not trip on braces/keywords inside string literals or comments.
// ---------------------------------------------------------------------------

// Return the index just after the '}' that closes the '{' at openIdx.
// Skips braces inside // line comments, /* */ block comments, and
// ' " ` string literals. Returns text.length if unbalanced.
function matchBrace(text, openIdx) {
  let depth = 0;
  let i = openIdx;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    const c2 = text[i + 1];
    if (c === '/' && c2 === '/') {
      i = text.indexOf('\n', i);
      if (i === -1) return n;
      continue;
    }
    if (c === '/' && c2 === '*') {
      const end = text.indexOf('*/', i + 2);
      i = end === -1 ? n : end + 2;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      i = skipString(text, i, c);
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return i + 1;
    }
    i++;
  }
  return n;
}

function skipString(text, startIdx, quote) {
  let i = startIdx + 1;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '\\') { i += 2; continue; }
    if (c === quote) return i + 1;
    // Template-literal ${...} can contain braces/strings; walk it so we do not
    // desync. Simple depth walk is enough for routing.
    if (quote === '`' && c === '$' && text[i + 1] === '{') {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (text[i] === '{') depth++;
        else if (text[i] === '}') depth--;
        i++;
      }
      continue;
    }
    i++;
  }
  return n;
}

// Blank out string/comment content (preserving newlines + length) so regex
// token scans over a region ignore literals. Used for "does this block mention
// chargeWork?" style checks where a mention inside a string must not count.
function blankLiterals(text) {
  const out = text.split('');
  let i = 0;
  const n = text.length;
  const blank = (from, to) => {
    for (let k = from; k < to && k < n; k++) {
      if (out[k] !== '\n') out[k] = ' ';
    }
  };
  while (i < n) {
    const c = text[i];
    const c2 = text[i + 1];
    if (c === '/' && c2 === '/') {
      const end = text.indexOf('\n', i);
      const stop = end === -1 ? n : end;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (c === '/' && c2 === '*') {
      const end = text.indexOf('*/', i + 2);
      const stop = end === -1 ? n : end + 2;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      const end = skipString(text, i, c);
      blank(i + 1, end - 1);
      i = end;
      continue;
    }
    i++;
  }
  return out.join('');
}

// Byte offset -> 1-based line number.
function lineAt(text, idx) {
  let line = 1;
  for (let i = 0; i < idx && i < text.length; i++) {
    if (text[i] === '\n') line++;
  }
  return line;
}

function offsetOfLine(lineStarts, lineNo) {
  return lineStarts[lineNo - 1];
}

function computeLineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

function snippetOf(lines, lineNo) {
  const s = (lines[lineNo - 1] || '').trim();
  return s.length > 160 ? s.slice(0, 157) + '...' : s;
}

// ---------------------------------------------------------------------------
// Detectors. Each returns an array of { line, cls, snippet, note }.
// Every detector operates on one file's { rel, text, lines, blanked }.
// ---------------------------------------------------------------------------

// (1) raw-realpath-mismatch: an entry-point comparison of import.meta.url
// against pathToFileURL(...argv...) WITHOUT realpathSync. import.meta.url is
// realpath-resolved by Node; argv[1] is the raw invocation path, so a
// symlinked launch makes the two differ and the "am I the entry point?" guard
// silently returns false -> the CLI/Action does zero analysis and exits 0.
function detectRealpathMismatch(f) {
  const found = [];
  const re = /import\.meta\.url\s*===|pathToFileURL\s*\([^;]*\)\s*\.href\s*===/;
  for (let i = 0; i < f.lines.length; i++) {
    const raw = f.blankedLines[i];
    if (!re.test(raw)) continue;
    // Window around the comparison: must involve pathToFileURL(...) and must
    // NOT normalize with realpathSync anywhere close by.
    const lo = Math.max(0, i - 12);
    const hi = Math.min(f.lines.length, i + 13);
    const win = f.blankedLines.slice(lo, hi).join('\n');
    if (!/pathToFileURL\s*\(/.test(win)) continue;
    if (/realpathSync/.test(win)) continue;
    // Require an argv-derived operand somewhere in the window so we do not fire
    // on unrelated URL equality.
    if (!/argv|process\.argv|\bentry\b/.test(win)) continue;
    found.push({
      line: i + 1,
      cls: 'raw-realpath-mismatch',
      snippet: snippetOf(f.lines, i + 1),
      note: 'import.meta.url is realpath-resolved; argv path is raw -> symlinked launch fails open',
    });
  }
  return found;
}

// (2) syntax-keyed-severity: a severity/level assignment whose condition tests
// the presence of an IAM SYNTAX token (stmt.resources / stmt.notResources /
// notAction) rather than a NORMALIZED breadth helper. A broad NotResource
// grant scored off `stmt.resources` alone is under-rated.
const BREADTH_HELPER =
  /\b(resourceScope|resourceIsBroad|effectiveBreadth|normaliz\w*Breadth|breadthOf|normalizedBreadth|effectiveResources|breadth)\b/;
const SYNTAX_TOKEN =
  /\b(notResources?|notAction|broadArn|broadStar)\b|stmt\.resources|\.resources\b/;

function detectSyntaxKeyedSeverity(f) {
  const found = [];
  const re = /\b(severity|level)\s*[:=]\s*([^;,\n]*\?[^;,\n]*)/;
  for (let i = 0; i < f.lines.length; i++) {
    const raw = f.blankedLines[i];
    const m = re.exec(raw);
    if (!m) continue;
    const conditional = m[2];
    const cond = conditional.split('?')[0];
    // Resolve bare identifiers in the condition to their nearest preceding
    // const/let/var definition in this file, and fold the def text in as
    // evidence (so `broadArn` reveals it is `stmt.resources.some(...)`).
    let evidence = cond;
    const idents = cond.match(/[A-Za-z_$][A-Za-z0-9_$]*/g) || [];
    for (const id of idents) {
      const defRe = new RegExp(
        `\\b(?:const|let|var)\\s+${id}\\s*=\\s*([^;\\n]*)`,
      );
      for (let j = i - 1; j >= Math.max(0, i - 80); j--) {
        const dm = defRe.exec(f.blankedLines[j]);
        if (dm) { evidence += ' ' + dm[1]; break; }
      }
    }
    if (BREADTH_HELPER.test(evidence)) continue; // scored on normalized breadth -> OK
    if (!SYNTAX_TOKEN.test(evidence)) continue; // condition not an IAM syntax token
    found.push({
      line: i + 1,
      cls: 'syntax-keyed-severity',
      snippet: snippetOf(f.lines, i + 1),
      note: 'severity keyed on IAM syntax token, not normalized effective breadth',
    });
  }
  return found;
}

// (3) silent-catch-clean: a catch block that swallows and returns a
// clean/empty-findings sentinel (or is entirely empty) without re-throwing or
// marking the result fail-closed/incomplete.
const FAILCLOSED_TOKEN =
  /throw|incomplete|truncat|failClosed|fail-closed|partial|EXIT\.|exitCode|reject|process\.exit\s*\(\s*[1-9]/;
function detectSilentCatchClean(f) {
  const found = [];
  const re = /\bcatch\b\s*(\([^)]*\))?\s*\{/g;
  let m;
  while ((m = re.exec(f.blanked)) !== null) {
    const openIdx = f.blanked.indexOf('{', m.index);
    if (openIdx === -1) continue;
    const end = matchBrace(f.blanked, openIdx);
    const body = f.blanked.slice(openIdx + 1, end - 1);
    const inner = body.trim();
    const cleanReturn =
      /return\s*\[\s*\]/.test(body) ||
      /findings\s*:\s*\[\s*\]/.test(body) ||
      /return\s*(['"])clean\1/.test(body) ||
      /process\.exit\s*\(\s*0\s*\)/.test(body);
    const emptySwallow = inner === '';
    if (!cleanReturn && !emptySwallow) continue;
    if (FAILCLOSED_TOKEN.test(body)) continue;
    const line = lineAt(f.text, m.index);
    found.push({
      line,
      cls: 'silent-catch-clean',
      snippet: snippetOf(f.lines, line),
      note: emptySwallow
        ? 'catch swallows the error with no fail-closed marker'
        : 'catch returns a clean/empty-findings sentinel with no fail-closed marker',
    });
  }
  return found;
}

// (4) candidate-drop: a truncation/cap-guarded return/continue/break inside an
// enumeration/walk that ships NO fail-closed truncation signal (no
// incomplete/truncated/partial flag near the drop). A MAX_FILES cut that
// returns the partial list looks clean to the caller.
//
// Broadened (modestly) to also route attention at:
//   - reversed cap comparisons (MAX_x < list.length) as well as (list.length > MAX_x);
//   - .slice/.splice truncation to a MAX_ constant, a numeric literal, or a
//     limit/max-named variable (a bare `.length` copy is NOT a cap);
//   - an enumeration continue/return/filter that DROPS an unreadable / parse-failed /
//     glob-failed item with no adjacent bookkeeping (a swallowed input file silently
//     shrinks the analyzed set).
// Precision is kept reasonable: a bare `.length > 0` non-empty check, a full-length
// slice, and a plain continue with no I/O-failure context are all excluded.
const TRUNC_SIGNAL =
  /incomplete|truncat|partial|dropped|overflow|capped|limitHit|failClosed|coverage/;
function detectCandidateDrop(f) {
  const found = [];
  const flagged = new Set(); // at most one candidate-drop finding per line
  // A CAP comparison against a MAX_ constant in EITHER operand order.
  const capCompare = /(?:>=|>|<=|<)\s*MAX_[A-Z0-9_]+|MAX_[A-Z0-9_]+\s*(?:>=|>|<=|<)/;
  // A truncating slice/splice; second arg captured for cap classification.
  const capSlice = /\.(?:slice|splice)\s*\(\s*0\s*,\s*([A-Za-z_$][\w$.]*|\d+)/;
  const flow = /\b(return|continue|break)\b/;
  // A drop that discards an unreadable/parse-failed/glob-failed item.
  const dropFlow = /\b(?:continue|return)\b|\.filter\s*\(/;
  const ioTok = /readFileSync|readdirSync|\breadFile\b|JSON\.parse|globSync|\bglob\s*\(|\breaddir\b|statSync/;
  const failTok = /\bcatch\b|ENOENT|EACCES|unreadable|parse\w*(?:error|fail)|read\w*(?:error|fail)|glob\w*(?:error|fail)|!\s*existsSync/i;

  const winStr = (i, back, fwd) =>
    f.blankedLines
      .slice(Math.max(0, i - back), Math.min(f.lines.length, i + fwd))
      .join('\n');
  const push = (i, note) => {
    if (flagged.has(i + 1)) return;
    flagged.add(i + 1);
    found.push({ line: i + 1, cls: 'candidate-drop', snippet: snippetOf(f.lines, i + 1), note });
  };

  for (let i = 0; i < f.lines.length; i++) {
    const raw = f.blankedLines[i];
    const next = f.blankedLines[i + 1] || '';

    // (a) slice/splice truncation to a cap (MAX_ / numeric literal / limit|max var).
    const sm = capSlice.exec(raw);
    let isSlice = false;
    if (sm) {
      const arg = sm[1];
      if (/^\d+$/.test(arg)) isSlice = true;
      else if (/^MAX_[A-Z0-9_]+$/.test(arg)) isSlice = true;
      else if (!arg.includes('.') && /(?:limit|max)/i.test(arg)) isSlice = true;
    }
    // (b) cap comparison (either order) that gates a control-flow drop.
    const isCompareDrop = capCompare.test(raw) && (flow.test(raw) || flow.test(next));

    if (isSlice || isCompareDrop) {
      if (!TRUNC_SIGNAL.test(winStr(i, 3, 4))) {
        push(i, isSlice
          ? 'slice/splice truncation to a cap with no fail-closed truncation signal'
          : 'cap/truncation-guarded drop with no fail-closed truncation signal');
      }
      continue;
    }

    // (c) enumeration drops a failed-to-read/parse/glob item with no bookkeeping.
    // A drop that instead FAILS CLOSED (throws, returns ok:false, pushes an error,
    // rejects) is not a silent candidate-drop and is excluded.
    if (dropFlow.test(raw)) {
      const near = winStr(i, 3, 2);
      const failClosed =
        TRUNC_SIGNAL.test(winStr(i, 3, 4)) ||
        /ok\s*:\s*false|errors?\.push|push\(\s*err|\bthrow\b|\breject\b/i.test(near);
      if (ioTok.test(near) && failTok.test(near) && !failClosed) {
        push(i, 'enumeration drops an unreadable/parse-failed/glob-failed item with no fail-closed bookkeeping');
      }
    }
  }
  return found;
}

// (5) exit0-offpath: any process.exit(0). The CLI/Action must have exactly one
// final decision point; an exit(0) elsewhere can short-circuit before analysis.
// Allowlist the single legitimate decision point.
function detectExit0OffPath(f) {
  const found = [];
  const re = /process\.exit\s*\(\s*0\s*\)/g;
  let m;
  while ((m = re.exec(f.blanked)) !== null) {
    const line = lineAt(f.text, m.index);
    found.push({
      line,
      cls: 'exit0-offpath',
      snippet: snippetOf(f.lines, line),
      note: 'process.exit(0) away from the single final decision point',
    });
  }
  return found;
}

// (6) budget-bypass: a loop over statements/actions/resources in the ENGINE
// that nests another iteration (O(NxM)) but charges no work/time budget in the
// loop body, so DoS caps never fire on a large hostile policy.
const BUDGET_CALL = /chargeWork|checkBudget|deadline|budget/;
const NESTED_ITER = /\.(filter|map|some|every|forEach|reduce)\s*\(|\bfor\s*\(/;
function detectBudgetBypass(f) {
  if (!f.rel.startsWith(ENGINE_REL_PREFIX)) return [];
  const found = [];
  const loopRe =
    /\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+of\s+[\w.[\]]*\.(resources|actions|statements)\b[^)]*\)\s*\{/g;
  let m;
  while ((m = loopRe.exec(f.blanked)) !== null) {
    const openIdx = f.blanked.indexOf('{', m.index);
    if (openIdx === -1) continue;
    const end = matchBrace(f.blanked, openIdx);
    const body = f.blanked.slice(openIdx + 1, end - 1);
    if (!NESTED_ITER.test(body)) continue; // not the O(NxM) shape
    if (BUDGET_CALL.test(body)) continue; // loop body charges work -> OK
    // Widen to the enclosing function: if it charges work somewhere, treat the
    // hot loop as covered (dedup) rather than re-flagging every nested loop.
    const fnStart = f.blanked.lastIndexOf('function', m.index);
    if (fnStart !== -1) {
      const fnOpen = f.blanked.indexOf('{', fnStart);
      if (fnOpen !== -1 && fnOpen <= m.index) {
        const fnEnd = matchBrace(f.blanked, fnOpen);
        if (fnEnd >= end && BUDGET_CALL.test(f.blanked.slice(fnOpen, fnEnd))) {
          continue;
        }
      }
    }
    const line = lineAt(f.text, m.index);
    found.push({
      line,
      cls: 'budget-bypass',
      snippet: snippetOf(f.lines, line),
      note: 'nested per-item iteration with no chargeWork/budget charge in the loop body',
    });
  }
  return found;
}

// (7) unbounded-walk: a recursive function (or object walk) with no
// depth/node/size cap in its body. Deep/hostile nesting can exhaust the stack
// before any limit fires. Best-effort; noisy by nature -> allowlist expected.
const CAP_TOKEN =
  /\bdepth\b|MAX_[A-Z0-9_]+|\bcap\b|\blimit\b|\bbudget\b|chargeWork|node[Cc]ount|\.length\s*[<>]=?|maxNodes|maxDepth/;
function detectUnboundedWalk(f) {
  const found = [];
  // function NAME(...) { ... NAME( ... ) ... }  where body lacks a cap token.
  const fnRe = /\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\{/g;
  let m;
  while ((m = fnRe.exec(f.blanked)) !== null) {
    const name = m[1];
    const openIdx = f.blanked.indexOf('{', m.index);
    if (openIdx === -1) continue;
    const end = matchBrace(f.blanked, openIdx);
    const body = f.blanked.slice(openIdx + 1, end - 1);
    const selfCall = new RegExp(`\\b${name}\\s*\\(`);
    if (!selfCall.test(body)) continue; // not recursive
    if (CAP_TOKEN.test(body)) continue; // has some cap
    const line = lineAt(f.text, m.index);
    found.push({
      line,
      cls: 'unbounded-walk',
      snippet: snippetOf(f.lines, line),
      note: `recursion (${name}) with no visible depth/node/size cap`,
    });
  }
  return found;
}

// (8) coverage-incomplete-lost: an incomplete/truncated/undecidable flag is
// assigned inside a function but the function's return path never references it
// -> the "we did not finish" signal is computed and then dropped.
function detectCoverageIncompleteLost(f) {
  const found = [];
  const assignRe =
    /\b(?:let|var)\s+(incomplete|truncated|undecidable)\b|(\w+)\.(incomplete|truncated)\s*=(?!=)/g;
  let m;
  while ((m = assignRe.exec(f.blanked)) !== null) {
    const flagName = m[1] || m[3];
    // Only the local-variable form is decidable here (object-property writes
    // usually mutate a returned object and are fine). Skip property writes.
    if (!m[1]) continue;
    // Find the enclosing function block.
    const fnStart = f.blanked.lastIndexOf('function', m.index);
    if (fnStart === -1) continue;
    const openIdx = f.blanked.indexOf('{', fnStart);
    if (openIdx === -1 || openIdx > m.index) continue;
    const end = matchBrace(f.blanked, openIdx);
    if (end <= m.index) continue;
    const body = f.blanked.slice(openIdx + 1, end - 1);
    const flagRef = new RegExp(`\\b${flagName}\\b`);
    // Propagated if any return statement mentions the flag, OR the flag is
    // carried out via an object-literal property/shorthand (return { ...,
    // truncated, ... } / { truncated: ... }) that a wrapper then returns.
    const returns = body.match(/return[^;]*;/g) || [];
    const inReturn = returns.some((r) => flagRef.test(r));
    const asProperty = new RegExp(`\\b${flagName}\\s*[,:}]`).test(
      // exclude the declaration site itself
      body.replace(new RegExp(`(?:let|var)\\s+${flagName}\\b`), ''),
    );
    if (inReturn || asProperty) continue;
    const line = lineAt(f.text, m.index);
    found.push({
      line,
      cls: 'coverage-incomplete-lost',
      snippet: snippetOf(f.lines, line),
      note: `local '${flagName}' flag assigned but not referenced by any return in its function`,
    });
  }
  return found;
}

const DETECTORS = [
  detectRealpathMismatch,
  detectSyntaxKeyedSeverity,
  detectSilentCatchClean,
  detectCandidateDrop,
  detectExit0OffPath,
  detectBudgetBypass,
  detectUnboundedWalk,
  detectCoverageIncompleteLost,
];

// ---------------------------------------------------------------------------
// Allowlist: reviewed false positives. JSON array of
// { file, class, line?, reason }. A finding is suppressed when file+class
// match and (line omitted OR line matches). Line-optional entries let a
// reviewer accept a whole class in a file if warranted.
// ---------------------------------------------------------------------------
function loadAllowlist(path) {
  if (!existsSync(path)) return [];
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    throw new Error(`allowlist parse error (${path}): ${err.message}`);
  }
  const entries = Array.isArray(parsed) ? parsed : parsed.allow;
  if (!Array.isArray(entries)) {
    throw new Error(`allowlist must be a JSON array (or {allow:[...]}) at ${path}`);
  }
  return entries;
}

function isAllowlisted(allow, rel, finding) {
  return allow.some(
    (a) =>
      a.file === rel &&
      a.class === finding.cls &&
      (a.line === undefined || a.line === finding.line),
  );
}

// ---------------------------------------------------------------------------
// Scan a single file (used by the API and the CLI).
// ---------------------------------------------------------------------------
export function scanFile(rel, text) {
  const lines = text.split('\n');
  const blanked = blankLiterals(text);
  const blankedLines = blanked.split('\n');
  const f = { rel, text, lines, blanked, blankedLines };
  const out = [];
  for (const d of DETECTORS) out.push(...d(f));
  return out;
}

// Run the full scan over the shipped tree. Returns { findings, scanned,
// missing }. `findings` is deterministically sorted.
export function runLint({ root = REPO_ROOT, files = TARGET_FILES } = {}) {
  const findings = [];
  const scanned = [];
  const missing = [];
  for (const rel of files) {
    const abs = resolve(root, rel);
    if (!existsSync(abs)) { missing.push(rel); continue; }
    scanned.push(rel);
    const text = readFileSync(abs, 'utf8');
    for (const hit of scanFile(rel, text)) {
      findings.push({ file: rel, ...hit });
    }
  }
  findings.sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      a.line - b.line ||
      a.cls.localeCompare(b.cls),
  );
  return { findings, scanned, missing };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
// Fail-closed exit decision. A non-empty `missing` list (a shipped file that must
// fail closed is not where it should be -- a candidate-drop of the target itself)
// forces a NON-ZERO exit exactly like an active hotspot does. Exported for testing.
export function exitCodeFor({ active = [], missing = [] } = {}) {
  return active.length > 0 || missing.length > 0 ? 1 : 0;
}

// Stable path the coverage-matrix indexer consumes as its AST-hotspots feed.
const HOTSPOTS_OUT = resolve(HERE, 'hotspots.json');

// Stage-14 PERI-CHECK-TARGETS-NONGATING: the committed baseline of accepted active
// hotspots, keyed by "<file>::<cls>" -> count. --check-hotspots fails when the current
// scan exceeds it (a NEW class in a file, or MORE instances). Keyed by file+class (not
// line) so a refactor that shifts lines does not spuriously fail the gate. Regenerate
// deliberately with `node audit/lint/lint.mjs --write-hotspot-baseline`.
const HOTSPOT_BASELINE_OUT = resolve(HERE, 'hotspot-baseline.json');
function loadHotspotBaseline() {
  try { return JSON.parse(readFileSync(HOTSPOT_BASELINE_OUT, 'utf8')); }
  catch { return {}; }
}
export function hotspotCounts(active) {
  const m = new Map();
  for (const f of active) {
    const key = `${f.file}::${f.cls}`;
    m.set(key, (m.get(key) || 0) + 1);
  }
  return m;
}

// Pure comparison exported for testing: which current (file::cls) hotspots exceed the
// committed baseline (a NEW key, or MORE instances of an existing one). Empty => PASS.
export function hotspotRegressions(active, baseline) {
  const current = hotspotCounts(active);
  const out = [];
  for (const [key, n] of current) {
    if (n > ((baseline && baseline[key]) || 0)) out.push({ key, was: (baseline && baseline[key]) || 0, now: n });
  }
  return out;
}

function formatFinding(fnd, allowlisted) {
  const tag = allowlisted ? ' [allowlisted]' : '';
  return (
    `${fnd.file}:${fnd.line}  ${fnd.cls}${tag}\n` +
    `    ${fnd.snippet}\n` +
    `    -> ${fnd.note}`
  );
}

function mainCli(argv) {
  const args = argv.slice(2);
  const jsonOut = args.includes('--json');
  let allowPath = resolve(HERE, 'allowlist.json');
  const alIdx = args.indexOf('--allowlist');
  if (alIdx !== -1 && args[alIdx + 1]) allowPath = resolve(process.cwd(), args[alIdx + 1]);

  const allow = loadAllowlist(allowPath);
  const { findings, scanned, missing } = runLint();

  const active = [];
  const suppressed = [];
  for (const fnd of findings) {
    if (isAllowlisted(allow, fnd.file, fnd)) suppressed.push(fnd);
    else active.push(fnd);
  }

  // Emit the JSON feed the coverage-matrix indexer reads (its AST-hotspots column),
  // to a stable path next to lint.mjs, on every run. Best-effort: a write failure
  // must not change the lint verdict.
  const payload = { scanned: scanned.length, missing, active, suppressed };
  try { writeFileSync(HOTSPOTS_OUT, JSON.stringify(payload, null, 2) + '\n'); } catch { /* best effort */ }

  const exit = exitCodeFor({ active, missing });

  // Deliberately (re)write the committed hotspot baseline (--check-hotspots reads it).
  // Run this only when you have reviewed the active hotspots and accept them.
  if (args.includes('--write-hotspot-baseline')) {
    const counts = Object.fromEntries([...hotspotCounts(active).entries()].sort());
    writeFileSync(HOTSPOT_BASELINE_OUT, JSON.stringify(counts, null, 2) + '\n');
    process.stdout.write(
      `wrote hotspot-baseline.json (${Object.keys(counts).length} file::cls keys, ${active.length} active hotspots)\n`,
    );
    return 0;
  }

  // Stage-11 #9: an UNSPOOFABLE gate for the security-meaningful signal (MISSING
  // guard targets). CI used to grep the human RESULT line, but that line prints
  // alongside echoed source SNIPPETS, so a planted comment
  // (`// RESULT: ... 0 missing target(s)`) could forge a pass. This mode emits NO
  // snippets and returns the verdict purely as an EXIT CODE: 0 iff no shipped
  // guard target is missing/moved, IGNORING active (informational) hotspots. The
  // single line it prints is fixed-shape and carries no source text, so nothing a
  // scanned file contains can influence it. CI/release gate on this exit code.
  if (args.includes('--check-targets')) {
    const ok = missing.length === 0;
    process.stdout.write(
      `CHECK_TARGETS: scanned=${scanned.length} missing=${missing.length} -> ${ok ? 'PASS' : 'FAIL'}\n`,
    );
    return ok ? 0 : 1;
  }

  // Stage-14 PERI-CHECK-TARGETS-NONGATING: --check-targets only fails on a DELETED
  // guard target; the full active-hotspot lint ran non-gating (|| true) in CI, so
  // INTRODUCING a new fail-open hotspot in an in-keyspace file never failed CI. This
  // mode gates on active hotspots against a committed BASELINE (hotspot-baseline.json:
  // a { "<file>::<cls>": count } map of the known/accepted hotspots). A NEW (file,cls)
  // hotspot class, or MORE instances of an existing one, forces a non-zero exit; line
  // shifts from refactors are tolerated (the key is file+class, not line). Read-only:
  // it never rewrites the baseline. Exit 0 iff no active hotspot exceeds the baseline
  // (missing targets ALSO fail, folding in the --check-targets guarantee).
  if (args.includes('--check-hotspots')) {
    const regressions = hotspotRegressions(active, loadHotspotBaseline());
    const ok = regressions.length === 0 && missing.length === 0;
    process.stdout.write(
      `CHECK_HOTSPOTS: active=${active.length} new/increased=${regressions.length} missing=${missing.length} -> ${ok ? 'PASS' : 'FAIL'}\n`,
    );
    for (const r of regressions) process.stdout.write(`  NEW/INCREASED: ${r.key} (${r.was} -> ${r.now})\n`);
    return ok ? 0 : 1;
  }

  if (jsonOut) {
    process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
    return exit;
  }

  const lines = [];
  lines.push('failopen-lint: fail-open hotspot scan (routes attention, does NOT prove safety)');
  lines.push(`scanned ${scanned.length} shipped file(s); allowlist=${existsSync(allowPath) ? relative(REPO_ROOT, allowPath) : '(none)'}`);
  if (missing.length) {
    lines.push(`ERROR (fail-closed): ${missing.length} shipped target file(s) MISSING/MOVED: ${missing.join(', ')}`);
    lines.push('  a file that must fail closed is not where it should be -> forcing NON-ZERO exit (dropped target).');
  }
  lines.push('');

  if (active.length === 0) {
    lines.push('No non-allowlisted hotspots found.');
  } else {
    const byClass = new Map();
    for (const fnd of active) byClass.set(fnd.cls, (byClass.get(fnd.cls) || 0) + 1);
    for (const fnd of active) lines.push(formatFinding(fnd, false));
    lines.push('');
    lines.push('Summary by class:');
    for (const [cls, n] of [...byClass.entries()].sort()) lines.push(`  ${cls}: ${n}`);
  }
  if (suppressed.length) {
    lines.push('');
    lines.push(`(${suppressed.length} allowlisted hotspot(s) suppressed)`);
  }
  lines.push('');
  lines.push(`RESULT: ${active.length} active hotspot(s), ${missing.length} missing target(s) -> exit ${exit}`);
  process.stdout.write(lines.join('\n') + '\n');
  return exit;
}

// Run only when invoked directly. realpathSync BOTH sides so a symlinked
// launch still matches -- the very raw-realpath-mismatch bug this lint hunts.
function isDirect() {
  try {
    const entry = process.argv && process.argv[1];
    if (!entry) return false;
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    return false;
  }
}

if (isDirect()) {
  process.exitCode = mainCli(process.argv);
}
