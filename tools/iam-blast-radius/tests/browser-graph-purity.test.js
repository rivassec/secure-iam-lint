// Browser-graph purity gate (story P15-purity).
//
// The shipped engine is served VERBATIM to the browser under
// /tools/iam-blast-radius/ and MUST stay browser-safe: no `node:`-scheme
// imports, no Node built-in modules, no Node globals (process/Buffer/require/
// __dirname/__filename). The new headless CLI + SARIF adapter + Action wrapper
// are Node code that live OUTSIDE this graph; this test guarantees that Node
// code can never leak INTO the browser-served graph (which would break CSP /
// zero-egress purity and ship a broken engine to every visitor).
//
// It statically walks the browser import graph starting from the fixed roots
//   content/tools/iam-blast-radius/{app.js, worker.js, engine/*.js}
// following only relative specifiers (the browser graph), and asserts ZERO
// violations across every reachable module.
//
// Adversarial requirement (P15): adding a `node:fs` import ANYWHERE in that
// graph MUST make this test fail. That is proven two ways below without ever
// mutating the shipped tree:
//   - the detector flags synthetic Node-tainted sources, and
//   - an end-to-end walk over a synthetic temp graph (root -> child -> node:fs)
//     surfaces the violation through graph traversal, while a clean twin does not.
//
// This test is Node code and MAY use node: imports itself. The purity contract
// applies to the SHIPPED browser graph it inspects, not to the test harness.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const SHIP = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius');

// --- Specifier extraction ----------------------------------------------------
// Pull every static module specifier out of a source string, covering:
//   import ... from 'x' | export ... from 'x' | import 'x' (side-effect)
//   import('x') (dynamic) | require('x') (CommonJS)
// We only need the specifier strings; this is a lint-grade scan, not a parser.
function extractSpecifiers(src) {
  const specs = [];
  const patterns = [
    /\b(?:import|export)\b[^;'"]*?\bfrom\s*['"]([^'"]+)['"]/g, // from-clause (import/export)
    /\bimport\s*['"]([^'"]+)['"]/g,                            // side-effect import
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,                  // dynamic import()
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,                 // CommonJS require()
  ];
  for (const re of patterns) {
    let m;
    while ((m = re.exec(src)) !== null) specs.push(m[1]);
  }
  return specs;
}

// Node built-in module names that must never appear as a bare import specifier
// in the browser graph. `node:`-scheme forms are caught separately (any scheme).
const NODE_BUILTINS = new Set([
  'assert', 'async_hooks', 'buffer', 'child_process', 'cluster', 'console',
  'constants', 'crypto', 'dgram', 'diagnostics_channel', 'dns', 'domain',
  'events', 'fs', 'http', 'http2', 'https', 'inspector', 'module', 'net',
  'os', 'path', 'perf_hooks', 'process', 'punycode', 'querystring', 'readline',
  'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls', 'trace_events',
  'tty', 'url', 'util', 'v8', 'vm', 'wasi', 'worker_threads', 'zlib',
]);

// A bare builtin can also be written with a subpath, e.g. 'fs/promises' or
// 'stream/web'. Normalize to the leading segment for the builtin check.
function isNodeBuiltinSpecifier(spec) {
  if (spec.startsWith('node:')) return true; // any node: scheme (fs, path, ...)
  const head = spec.split('/')[0];
  return NODE_BUILTINS.has(head);
}

// --- Node-global / CommonJS usage patterns (beyond imports) ------------------
// Precise call/member patterns so prose in comments cannot trip them (e.g. the
// word "reprocessing", the DOM variable `path`, or "Policy node:" in a comment).
const GLOBAL_USAGE = [
  { re: /\bprocess\s*\./, label: 'process.<member> global usage' },
  { re: /\bBuffer\s*\.\s*from\b/, label: 'Buffer.from usage' },
  { re: /\bnew\s+Buffer\b/, label: 'new Buffer usage' },
  { re: /\brequire\s*\(/, label: 'CommonJS require() call' },
  { re: /\b__dirname\b/, label: '__dirname Node global' },
  { re: /\b__filename\b/, label: '__filename Node global' },
  { re: /\bglobalThis\s*\.\s*process\b/, label: 'globalThis.process usage' },
];

// Return a list of human-readable purity violations for one file's source.
function findViolations(src) {
  const violations = [];
  for (const spec of extractSpecifiers(src)) {
    if (spec.startsWith('node:')) {
      violations.push(`node:-scheme import '${spec}'`);
    } else if (isNodeBuiltinSpecifier(spec)) {
      violations.push(`Node built-in import '${spec}'`);
    }
  }
  for (const { re, label } of GLOBAL_USAGE) {
    if (re.test(src)) violations.push(label);
  }
  return violations;
}

// --- Static graph walk -------------------------------------------------------
// Seed from the given roots, follow ONLY relative specifiers (the browser
// graph), and return every reachable module's { path, src }. Non-relative
// specifiers are recorded but not traversed (a node: / bare import is a
// violation surfaced by findViolations, not a file to open).
function walkGraph(roots) {
  const seen = new Map(); // absPath -> src
  const stack = [...roots];
  while (stack.length) {
    const file = stack.pop();
    const abs = resolve(file);
    if (seen.has(abs)) continue;
    const src = readFileSync(abs, 'utf8');
    seen.set(abs, src);
    const baseDir = dirname(abs);
    for (const spec of extractSpecifiers(src)) {
      if (spec.startsWith('.')) {
        stack.push(resolve(baseDir, spec));
      }
    }
  }
  return seen;
}

// The fixed browser-graph roots: app.js, worker.js, and every engine/*.js.
function browserRoots() {
  const roots = [join(SHIP, 'app.js'), join(SHIP, 'worker.js')];
  const engineDir = join(SHIP, 'engine');
  for (const f of readdirSync(engineDir)) {
    if (f.endsWith('.js')) roots.push(join(engineDir, f));
  }
  return roots;
}

// --- Real-graph assertions ---------------------------------------------------

test('browser import graph contains ZERO node:/built-in/global-usage violations', () => {
  const graph = walkGraph(browserRoots());
  const failures = [];
  for (const [abs, src] of graph) {
    for (const v of findViolations(src)) {
      failures.push(`${relative(SHIP, abs)}: ${v}`);
    }
  }
  assert.deepEqual(
    failures,
    [],
    `Node code leaked into the browser-served engine graph:\n${failures.join('\n')}`,
  );
});

test('the graph walk actually traversed the engine (guards against a vacuous pass)', () => {
  const graph = walkGraph(browserRoots());
  const reached = new Set([...graph.keys()].map((p) => relative(SHIP, p)));
  // Core modules the walk MUST reach; if resolution silently broke, this fails
  // instead of the purity check passing over an empty/partial graph.
  const mustReach = [
    'app.js',
    'worker.js',
    'samples.js', // pulled in only via app.js -> proves relative traversal works
    'engine/analyze.js',
    'engine/model.js',
    'engine/validate.js',
    'engine/parse.js',
    'engine/report.js',
    'engine/render-graph.js',
    'engine/graph.js',
  ];
  for (const m of mustReach) {
    assert.ok(reached.has(m), `graph walk did not reach ${m} (${reached.size} files reached)`);
  }
});

// --- Detector unit checks (adversarial: synthetic tainted sources) -----------

test('findViolations flags every Node-tainting form', () => {
  const cases = [
    [`import { readFileSync } from 'node:fs';`, /node:-scheme import 'node:fs'/],
    [`import 'node:path';`, /node:-scheme import 'node:path'/],
    [`import fs from 'fs';`, /Node built-in import 'fs'/],
    [`import { join } from 'path';`, /Node built-in import 'path'/],
    [`import { readFile } from 'fs/promises';`, /Node built-in import 'fs\/promises'/],
    [`const fs = require('fs');`, /CommonJS require\(\) call/],
    [`if (process.env.CI) {}`, /process\.<member> global usage/],
    [`const b = Buffer.from('x');`, /Buffer\.from usage/],
    [`const b = new Buffer(4);`, /new Buffer usage/],
    [`const d = __dirname;`, /__dirname Node global/],
    [`const f = __filename;`, /__filename Node global/],
  ];
  for (const [src, expected] of cases) {
    const vs = findViolations(src);
    assert.ok(
      vs.some((v) => expected.test(v)),
      `expected a violation matching ${expected} for source: ${src} (got ${JSON.stringify(vs)})`,
    );
  }
});

test('findViolations does NOT false-positive on browser-legit prose/DOM patterns', () => {
  const benign = [
    `// worker must degrade... never main-thread reprocessing.`, // "process" in a word
    `const path = document.createElement('span'); path.textContent = 'x';`, // DOM var named path
    `// point at a single Policy node: the principal can rewrite.`, // "node:" as prose
    `import { analyze } from './engine/analyze.js';`, // relative browser import
    `import { SAMPLES } from './samples.js';`,
    `const processed = queue.map((x) => x);`, // "processed" identifier
  ];
  for (const src of benign) {
    assert.deepEqual(findViolations(src), [], `false positive on benign source: ${src}`);
  }
});

// --- End-to-end adversarial: a tainted import DEEP in a synthetic graph -------
// Proves the WALK (not just the regex) surfaces a node:fs import reachable only
// transitively (root -> child -> leaf), exactly the "anywhere in the graph"
// requirement, without touching the shipped tree.

test('a node:fs import buried in a transitive dependency is caught by the walk', () => {
  const dir = mkdtempSync(join(tmpdir(), 'iam-br-purity-'));
  try {
    const sub = join(dir, 'engine');
    mkdirSync(sub);
    // root -> engine/child.js -> engine/leaf.js (leaf smuggles node:fs)
    writeFileSync(join(dir, 'root.js'), `import { c } from './engine/child.js';\nexport const r = c;\n`);
    writeFileSync(join(sub, 'child.js'), `import { l } from './leaf.js';\nexport const c = l;\n`);
    writeFileSync(join(sub, 'leaf.js'), `import { readFileSync } from 'node:fs';\nexport const l = readFileSync;\n`);

    const graph = walkGraph([join(dir, 'root.js')]);
    const failures = [];
    for (const [abs, src] of graph) {
      for (const v of findViolations(src)) failures.push(`${relative(dir, abs)}: ${v}`);
    }
    assert.ok(
      failures.some((f) => /leaf\.js: node:-scheme import 'node:fs'/.test(f)),
      `walk failed to surface the buried node:fs import; failures=${JSON.stringify(failures)}`,
    );
    // And the guard reached all three files (the transitive taint was traversed).
    assert.equal(graph.size, 3, 'expected root + child + leaf in the synthetic graph');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a clean synthetic graph produces no violations (no false alarm end-to-end)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'iam-br-purity-clean-'));
  try {
    writeFileSync(join(dir, 'root.js'), `import { c } from './child.js';\nexport const r = c;\n`);
    writeFileSync(join(dir, 'child.js'), `export const c = (x) => x + 1;\n`);
    const graph = walkGraph([join(dir, 'root.js')]);
    const failures = [];
    for (const [, src] of graph) failures.push(...findViolations(src));
    assert.deepEqual(failures, [], `clean synthetic graph reported violations: ${JSON.stringify(failures)}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
