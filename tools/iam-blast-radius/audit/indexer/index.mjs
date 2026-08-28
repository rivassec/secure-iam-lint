#!/usr/bin/env node
// IAM Blast Radius - shipped-file coverage-matrix INDEXER (dev tooling only).
//
// Emits one row per SHIPPED file (engine/*.js + app.js + worker.js + cli/*.mjs
// + action/index.mjs) describing: exports, in-repo imports, callers (shipped
// files that import this one), reachable entrypoints (browser-analyze / cli /
// action / sarif, by walking the import graph from those roots), tests touching
// it, and an AST-hotspots placeholder (consumes audit/lint output if present).
//
// Also emits an ORPHAN report:
//   - untested: shipped files with no test touching them.
//   - browserNodeBuiltins: files reachable from the browser root that import a
//     'node:' builtin (a browser/CLI parity / leak smell).
//
// Node built-ins only. Deterministic. Import parsing is regex-based (accepted
// per the build task). This matrix arms the Phase 1 per-file reviewers.
//
// Usage:
//   node tools/iam-blast-radius/audit/indexer/index.mjs [--json] [--out DIR]
//
// Default: prints a readable table to stdout AND writes index.json + a
// coverage-matrix.md table into this indexer directory. --json prints the raw
// JSON to stdout instead of the table. --out DIR overrides the write directory.

import {
  readFileSync, writeFileSync, readdirSync, existsSync, statSync, realpathSync,
} from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// audit/indexer -> audit -> iam-blast-radius -> tools -> REPO ROOT
const REPO_ROOT = path.resolve(HERE, '..', '..', '..', '..');

const CONTENT = path.join(REPO_ROOT, 'content', 'tools', 'iam-blast-radius');
const ENGINE = path.join(CONTENT, 'engine');
const CLI = path.join(REPO_ROOT, 'cli');
const ACTION = path.join(REPO_ROOT, 'action');
const TESTS = path.join(REPO_ROOT, 'tools', 'iam-blast-radius', 'tests');
const LINT_DIR = path.join(REPO_ROOT, 'tools', 'iam-blast-radius', 'audit', 'lint');

// --- helpers ---------------------------------------------------------------

const rel = (abs) => path.relative(REPO_ROOT, abs).split(path.sep).join('/');

function listFiles(dir, filterFn) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .map((name) => path.join(dir, name))
    .filter((p) => { try { return statSync(p).isFile(); } catch { return false; } })
    .filter(filterFn)
    .sort();
}

// --- 1. enumerate shipped files -------------------------------------------

function shippedFiles() {
  const engine = listFiles(ENGINE, (p) => p.endsWith('.js'));
  const topLevel = ['app.js', 'worker.js']
    .map((n) => path.join(CONTENT, n))
    .filter(existsSync);
  const cli = listFiles(CLI, (p) => p.endsWith('.mjs'));
  const action = [path.join(ACTION, 'index.mjs')].filter(existsSync);
  // Deterministic ordering: engine, then content top-level, cli, action.
  return [...engine, ...topLevel, ...cli, ...action];
}

// --- 2. parse imports + exports -------------------------------------------

// Matches: import ... from 'X'; export ... from 'X'; import 'X';
// and dynamic import('X') / await import("X").
function parseSpecifiers(src) {
  const specs = [];
  const push = (s) => { if (s) specs.push(s); };
  // static import/export ... from '...'
  const staticFrom = /(?:^|[\s;])(?:import|export)\b[^'";]*?\bfrom\s*['"]([^'"]+)['"]/gms;
  for (const m of src.matchAll(staticFrom)) push(m[1]);
  // bare side-effect import 'X'
  const bare = /(?:^|[\s;])import\s*['"]([^'"]+)['"]/g;
  for (const m of src.matchAll(bare)) push(m[1]);
  // dynamic import('X')
  const dyn = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const m of src.matchAll(dyn)) push(m[1]);
  return specs;
}

function classifySpec(spec, fromAbs) {
  if (spec.startsWith('node:')) return { kind: 'node-builtin', spec };
  if (spec.startsWith('.') || spec.startsWith('/')) {
    const resolved = path.resolve(path.dirname(fromAbs), spec);
    if (existsSync(resolved) && statSync(resolved).isFile()) {
      return { kind: 'in-repo', spec, resolved };
    }
    return { kind: 'in-repo-missing', spec, resolved };
  }
  return { kind: 'external', spec };
}

function parseExports(src) {
  const names = new Set();
  let hasDefault = false;
  // export function/const/let/var/class/async function NAME
  const decl = /^export\s+(?:async\s+)?(?:function\*?|const|let|var|class)\s+([A-Za-z_$][\w$]*)/gm;
  for (const m of src.matchAll(decl)) names.add(m[1]);
  // export { a, b as c, ... }  (optionally with `from`)
  const block = /^export\s*\{([^}]*)\}/gm;
  for (const m of src.matchAll(block)) {
    for (const raw of m[1].split(',')) {
      const part = raw.trim();
      if (!part) continue;
      const asMatch = part.match(/\bas\s+([A-Za-z_$][\w$]*)\s*$/);
      const name = asMatch ? asMatch[1] : part.split(/\s+/)[0];
      if (name === 'default') { hasDefault = true; continue; }
      if (/^[A-Za-z_$][\w$]*$/.test(name)) names.add(name);
    }
  }
  if (/^export\s+default\b/m.test(src)) hasDefault = true;
  const out = [...names].sort();
  if (hasDefault) out.push('default');
  return out;
}

// --- 3. load lint hotspots (placeholder feed) ------------------------------

function loadHotspots() {
  // Consume audit/lint output if present; else empty. Keyed by repo-rel path.
  const byFile = {};
  if (!existsSync(LINT_DIR)) return { present: false, byFile };
  const jsonFiles = listFiles(LINT_DIR, (p) => p.endsWith('.json'));
  for (const jf of jsonFiles) {
    let data;
    try { data = JSON.parse(readFileSync(jf, 'utf8')); } catch { continue; }
    // Tolerate a few shapes: the failopen-lint output ({scanned,missing,active,...},
    // keyed off `.active`), plus {hotspots:[{file,...}]} | {byFile:{path:[...]}} |
    // [{file,...}]. `.active` is the ACTUAL shape lint.mjs --json / hotspots.json emit.
    const rows = Array.isArray(data) ? data
      : Array.isArray(data.active) ? data.active
        : Array.isArray(data.hotspots) ? data.hotspots
          : null;
    if (rows) {
      for (const r of rows) {
        const f = r && (r.file || r.path);
        if (!f) continue;
        const key = f.split(path.sep).join('/');
        (byFile[key] ||= []).push(r);
      }
    } else if (data.byFile && typeof data.byFile === 'object') {
      for (const [k, v] of Object.entries(data.byFile)) {
        const key = k.split(path.sep).join('/');
        (byFile[key] ||= []).push(...(Array.isArray(v) ? v : [v]));
      }
    }
  }
  return { present: true, byFile };
}

// --- 4. tests touching a module -------------------------------------------

function testFiles() {
  const out = [];
  if (existsSync(TESTS)) {
    // Only top-level tests dir here (co-located tests handled separately).
    for (const name of readdirSync(TESTS)) {
      const p = path.join(TESTS, name);
      try { if (statSync(p).isFile() && /\.test\.[cm]?js$/.test(name)) out.push(p); }
      catch { /* skip */ }
    }
  }
  return out.sort();
}

// A test "touches" a module if it references the module's basename inside a
// string literal, anchored by a leading '/' or quote and a trailing quote so
// e.g. resource.js does not match resource-arn.js.
function testTouchIndex(shipped) {
  const tests = testFiles();
  const contents = tests.map((p) => ({ p, src: readFileSync(p, 'utf8') }));
  const byModule = {};
  for (const abs of shipped) {
    const base = path.basename(abs);
    const anchored = new RegExp(`[/'"]${base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"]`);
    const hits = [];
    for (const { p, src } of contents) {
      if (anchored.test(src)) hits.push(rel(p));
    }
    // Co-located tests: *.test.* sitting next to the module sharing its stem.
    const dir = path.dirname(abs);
    const stem = base.replace(/\.[cm]?js$/, '');
    for (const name of (existsSync(dir) ? readdirSync(dir) : [])) {
      if (new RegExp(`^${stem}\\.test\\.[cm]?js$`).test(name)) {
        const cp = rel(path.join(dir, name));
        if (!hits.includes(cp)) hits.push(cp);
      }
    }
    byModule[rel(abs)] = hits.sort();
  }
  return byModule;
}

// --- 5. build graph + entrypoint reachability ------------------------------

const ENTRY_ROOTS = {
  'browser-analyze': [path.join(CONTENT, 'app.js'), path.join(CONTENT, 'worker.js')],
  cli: [path.join(CLI, 'iam-br.mjs')],
  action: [path.join(ACTION, 'index.mjs')],
  sarif: [path.join(CLI, 'sarif.mjs')],
};

function reachableFrom(roots, importEdges) {
  // importEdges: Map<absPath, Set<absPath in-repo>>
  const seen = new Set();
  const stack = roots.filter(existsSync);
  while (stack.length) {
    const cur = stack.pop();
    if (seen.has(cur)) continue;
    seen.add(cur);
    for (const dep of (importEdges.get(cur) || [])) {
      if (!seen.has(dep)) stack.push(dep);
    }
  }
  return seen;
}

// --- main ------------------------------------------------------------------

function buildMatrix() {
  const shipped = shippedFiles();
  const shippedSet = new Set(shipped);

  const parsed = new Map(); // abs -> {exports, specs:[{kind,spec,resolved?}]}
  const importEdges = new Map(); // abs -> Set<abs in-repo> (all in-repo, incl. cross-dir)
  for (const abs of shipped) {
    const src = readFileSync(abs, 'utf8');
    const exports = parseExports(src);
    const specs = parseSpecifiers(src).map((s) => classifySpec(s, abs));
    parsed.set(abs, { exports, specs });
    const deps = new Set();
    for (const s of specs) {
      if (s.kind === 'in-repo') deps.add(s.resolved);
    }
    importEdges.set(abs, deps);
  }

  // callers: reverse of in-repo edges, restricted to shipped importers.
  const callers = new Map(); // abs -> Set<abs>
  for (const abs of shipped) callers.set(abs, new Set());
  for (const abs of shipped) {
    for (const dep of importEdges.get(abs)) {
      if (callers.has(dep)) callers.get(dep).add(abs);
    }
  }

  // entrypoint reachability
  const reachByEntry = {};
  for (const [name, roots] of Object.entries(ENTRY_ROOTS)) {
    reachByEntry[name] = reachableFrom(roots, importEdges);
  }
  const browserReach = reachByEntry['browser-analyze'];

  const hotspots = loadHotspots();
  const testsByModule = testTouchIndex(shipped);

  const rows = [];
  const orphanUntested = [];
  const browserNodeBuiltins = [];

  for (const abs of shipped) {
    const relPath = rel(abs);
    const { exports, specs } = parsed.get(abs);

    const inRepoImports = specs.filter((s) => s.kind === 'in-repo').map((s) => rel(s.resolved)).sort();
    const missingImports = specs.filter((s) => s.kind === 'in-repo-missing').map((s) => s.spec).sort();
    const nodeBuiltins = [...new Set(specs.filter((s) => s.kind === 'node-builtin').map((s) => s.spec))].sort();
    const externalImports = [...new Set(specs.filter((s) => s.kind === 'external').map((s) => s.spec))].sort();

    const callerList = [...callers.get(abs)].map(rel).sort();

    const entrypoints = Object.entries(reachByEntry)
      .filter(([, set]) => set.has(abs))
      .map(([name]) => name)
      .sort();

    const tests = testsByModule[relPath] || [];
    const spots = hotspots.byFile[relPath] || [];

    const inBrowser = browserReach.has(abs);
    if (inBrowser && nodeBuiltins.length > 0) {
      browserNodeBuiltins.push({ file: relPath, builtins: nodeBuiltins });
    }
    if (tests.length === 0) orphanUntested.push(relPath);

    rows.push({
      file: relPath,
      exports,
      exportCount: exports.length,
      imports: inRepoImports,
      importsMissing: missingImports,
      nodeBuiltins,
      externalImports,
      callers: callerList,
      callerCount: callerList.length,
      entrypoints,
      reachableFromBrowser: inBrowser,
      tests,
      testCount: tests.length,
      astHotspots: spots,
    });
  }

  return {
    meta: {
      generatedBy: 'tools/iam-blast-radius/audit/indexer/index.mjs',
      repoRoot: rel(REPO_ROOT) || '.',
      shippedFileCount: shipped.length,
      entryRoots: Object.fromEntries(
        Object.entries(ENTRY_ROOTS).map(([k, v]) => [k, v.filter(existsSync).map(rel)]),
      ),
      lintHotspotsPresent: hotspots.present,
      note: 'Deterministic. Import parsing is regex-based. Dev tooling only.',
    },
    matrix: rows,
    orphans: {
      untested: orphanUntested.sort(),
      browserNodeBuiltins: browserNodeBuiltins.sort((a, b) => a.file.localeCompare(b.file)),
    },
  };
}

// --- rendering -------------------------------------------------------------

function renderTable(result) {
  const lines = [];
  const H = (s) => lines.push(s);
  H('# IAM Blast Radius - shipped-file coverage matrix');
  H('');
  H(`Shipped files: ${result.meta.shippedFileCount}  |  lint hotspots feed: ${result.meta.lintHotspotsPresent ? 'present' : 'absent'}`);
  H('');
  H('| file | exp | imp | callers | entrypoints | tests | browser | node: |');
  H('|------|----:|----:|--------:|-------------|------:|:-------:|-------|');
  for (const r of result.matrix) {
    H(`| ${r.file} | ${r.exportCount} | ${r.imports.length} | ${r.callerCount} `
      + `| ${r.entrypoints.join(', ') || '-'} | ${r.testCount} `
      + `| ${r.reachableFromBrowser ? 'Y' : '-'} | ${r.nodeBuiltins.join(' ') || '-'} |`);
  }
  H('');
  H('## Orphan report');
  H('');
  H(`### Untested shipped files (${result.orphans.untested.length})`);
  if (result.orphans.untested.length === 0) H('(none)');
  else for (const f of result.orphans.untested) H(`- ${f}`);
  H('');
  H(`### Browser-reachable files importing node: builtins (${result.orphans.browserNodeBuiltins.length})`);
  if (result.orphans.browserNodeBuiltins.length === 0) H('(none)');
  else for (const e of result.orphans.browserNodeBuiltins) H(`- ${e.file}: ${e.builtins.join(', ')}`);
  H('');
  return lines.join('\n');
}

// --- CLI entry -------------------------------------------------------------

export { buildMatrix, renderTable, parseExports, parseSpecifiers, classifySpec };

function isMain() {
  // realpath-safe main check: compare resolved paths, not raw argv (see the
  // raw-realpath-mismatch fail-open class this audit tool exists to surface).
  const invoked = process.argv[1];
  if (!invoked) return false;
  try {
    const a = fileURLToPath(import.meta.url);
    const b = fileURLToPath(pathToFileURL(realpathSafe(invoked)));
    return path.resolve(a) === path.resolve(b);
  } catch {
    return import.meta.url === pathToFileURL(invoked).href;
  }
}
function realpathSafe(p) {
  try { return realpathSync(p); } catch { return p; }
}

if (isMain()) {
  const argv = process.argv.slice(2);
  const jsonOnly = argv.includes('--json');
  const outIdx = argv.indexOf('--out');
  const outDir = outIdx >= 0 ? path.resolve(argv[outIdx + 1]) : HERE;

  const result = buildMatrix();

  if (jsonOnly) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    const table = renderTable(result);
    process.stdout.write(table + '\n');
    writeFileSync(path.join(outDir, 'index.json'), JSON.stringify(result, null, 2) + '\n');
    writeFileSync(path.join(outDir, 'coverage-matrix.md'), table + '\n');
    process.stderr.write(`\nwrote ${rel(path.join(outDir, 'index.json'))} and ${rel(path.join(outDir, 'coverage-matrix.md'))}\n`);
  }
}
