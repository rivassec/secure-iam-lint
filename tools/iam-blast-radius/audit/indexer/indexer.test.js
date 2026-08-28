// Tests for the shipped-file coverage-matrix INDEXER (dev tooling only).
// Run: node --test tools/iam-blast-radius/audit/indexer/indexer.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, existsSync, statSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';

import { buildMatrix, parseExports, parseSpecifiers, classifySpec } from './index.mjs';
import { runLint } from '../lint/lint.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..', '..', '..');
const CONTENT = path.join(REPO_ROOT, 'content', 'tools', 'iam-blast-radius');
const ENGINE = path.join(CONTENT, 'engine');
const CLI = path.join(REPO_ROOT, 'cli');
const ACTION = path.join(REPO_ROOT, 'action');
const rel = (abs) => path.relative(REPO_ROOT, abs).split(path.sep).join('/');

function expectedShipped() {
  const engine = readdirSync(ENGINE)
    .filter((n) => n.endsWith('.js'))
    .map((n) => rel(path.join(ENGINE, n)));
  const top = ['app.js', 'worker.js']
    .filter((n) => existsSync(path.join(CONTENT, n)))
    .map((n) => rel(path.join(CONTENT, n)));
  const cli = readdirSync(CLI)
    .filter((n) => n.endsWith('.mjs'))
    .map((n) => rel(path.join(CLI, n)));
  const action = ['index.mjs']
    .filter((n) => existsSync(path.join(ACTION, n)))
    .map((n) => rel(path.join(ACTION, n)));
  return new Set([...engine, ...top, ...cli, ...action]);
}

test('matrix covers every shipped file exactly', () => {
  const { matrix, meta } = buildMatrix();
  const expected = expectedShipped();
  const got = new Set(matrix.map((r) => r.file));

  // No shipped file silently dropped from the aggregate (candidate-drop class).
  for (const f of expected) {
    assert.ok(got.has(f), `shipped file missing from matrix: ${f}`);
  }
  // No phantom rows.
  for (const f of got) {
    assert.ok(expected.has(f), `matrix row is not a shipped file: ${f}`);
  }
  assert.equal(got.size, expected.size, 'matrix row count != shipped file count');
  assert.equal(meta.shippedFileCount, expected.size, 'meta.shippedFileCount mismatch');
});

test('the enumeration is non-empty and includes each surface family', () => {
  const { matrix } = buildMatrix();
  const files = matrix.map((r) => r.file);
  assert.ok(files.length >= 20, 'suspiciously few shipped files enumerated');
  assert.ok(files.some((f) => f.includes('/engine/')), 'no engine files');
  assert.ok(files.includes('content/tools/iam-blast-radius/app.js'), 'app.js missing');
  assert.ok(files.includes('content/tools/iam-blast-radius/worker.js'), 'worker.js missing');
  assert.ok(files.some((f) => f.startsWith('cli/')), 'no cli files');
  assert.ok(files.includes('action/index.mjs'), 'action/index.mjs missing');
});

test('core rule engines list >0 callers or entrypoints', () => {
  const { matrix } = buildMatrix();
  const byFile = new Map(matrix.map((r) => [r.file, r]));
  for (const base of ['resource.js', 'escalation.js', 'rules.js']) {
    const key = `content/tools/iam-blast-radius/engine/${base}`;
    const row = byFile.get(key);
    assert.ok(row, `${key} missing from matrix`);
    const reach = row.callerCount + row.entrypoints.length;
    assert.ok(reach > 0, `${base} has no callers and no entrypoints (unreachable engine)`);
  }
});

test('analyze.js is the hub: reachable from browser + cli + action', () => {
  const { matrix } = buildMatrix();
  const analyze = matrix.find(
    (r) => r.file === 'content/tools/iam-blast-radius/engine/analyze.js',
  );
  assert.ok(analyze, 'analyze.js row missing');
  for (const ep of ['browser-analyze', 'cli', 'action']) {
    assert.ok(analyze.entrypoints.includes(ep), `analyze.js not reachable from ${ep}`);
  }
});

test('every row carries the required columns', () => {
  const { matrix } = buildMatrix();
  for (const r of matrix) {
    for (const k of ['exports', 'imports', 'callers', 'entrypoints', 'tests', 'astHotspots']) {
      assert.ok(Array.isArray(r[k]), `${r.file}: ${k} is not an array`);
    }
    assert.equal(typeof r.reachableFromBrowser, 'boolean', `${r.file}: reachableFromBrowser`);
    assert.equal(r.exportCount, r.exports.length, `${r.file}: exportCount mismatch`);
    assert.equal(r.callerCount, r.callers.length, `${r.file}: callerCount mismatch`);
    assert.equal(r.testCount, r.tests.length, `${r.file}: testCount mismatch`);
  }
});

test('orphan report structure is present and internally consistent', () => {
  const { matrix, orphans } = buildMatrix();
  assert.ok(Array.isArray(orphans.untested), 'orphans.untested not an array');
  assert.ok(Array.isArray(orphans.browserNodeBuiltins), 'orphans.browserNodeBuiltins not an array');

  const byFile = new Map(matrix.map((r) => [r.file, r]));
  // Untested list must exactly equal rows with zero tests.
  const zeroTested = matrix.filter((r) => r.testCount === 0).map((r) => r.file).sort();
  assert.deepEqual([...orphans.untested].sort(), zeroTested, 'untested list mismatch');

  // Every browserNodeBuiltins entry must be a browser-reachable row that
  // actually imports the reported builtins.
  for (const e of orphans.browserNodeBuiltins) {
    const row = byFile.get(e.file);
    assert.ok(row, `orphan node-builtin entry for unknown file ${e.file}`);
    assert.ok(row.reachableFromBrowser, `${e.file} flagged but not browser-reachable`);
    assert.ok(e.builtins.length > 0, `${e.file} flagged with empty builtins`);
  }
});

test('output is deterministic across runs (same input -> same matrix)', () => {
  const a = JSON.stringify(buildMatrix());
  const b = JSON.stringify(buildMatrix());
  assert.equal(a, b, 'indexer output is non-deterministic');
});

test('export parser recognizes named, aliased, and default exports', () => {
  const src = [
    'export function alpha() {}',
    'export const beta = 1;',
    'export class Gamma {}',
    'export { delta, epsilon as zeta };',
    'export default alpha;',
  ].join('\n');
  const ex = parseExports(src);
  for (const n of ['alpha', 'beta', 'Gamma', 'delta', 'zeta']) {
    assert.ok(ex.includes(n), `missing export ${n}`);
  }
  assert.ok(ex.includes('default'), 'default export not detected');
});

test('specifier parser + classifier separate in-repo, node:, and external', () => {
  const engineFile = path.join(ENGINE, 'analyze.js');
  const src = [
    "import { modelFromText } from './model.js';",
    "import { randomUUID } from 'node:crypto';",
    "import x from 'some-external-pkg';",
    "const y = await import('node:fs');",
  ].join('\n');
  const specs = parseSpecifiers(src);
  assert.ok(specs.includes('./model.js'));
  assert.ok(specs.includes('node:crypto'));
  assert.ok(specs.includes('some-external-pkg'));
  assert.ok(specs.includes('node:fs'));

  assert.equal(classifySpec('./model.js', engineFile).kind, 'in-repo');
  assert.equal(classifySpec('node:crypto', engineFile).kind, 'node-builtin');
  assert.equal(classifySpec('some-external-pkg', engineFile).kind, 'external');
});

// (H11) the indexer must actually CONSUME the failopen-lint output. lint --json emits
// {scanned,missing,active,suppressed}; the indexer reads `.active`, keyed by file, into
// each row's astHotspots. Regression: previously it only understood {hotspots}|{byFile}
// |[...] and silently ignored real lint output, so astHotspots was always empty.
test('astHotspots is populated from the failopen-lint {active} feed', () => {
  // Generate the feed the way lint.mjs does (write {active} to audit/lint/hotspots.json)
  // so the test is self-contained and does not depend on a prior lint CLI run.
  const { findings } = runLint();
  assert.ok(findings.length > 0, 'lint produced zero findings -> nothing to feed the indexer');
  const feedPath = path.join(REPO_ROOT, 'tools', 'iam-blast-radius', 'audit', 'lint', 'hotspots.json');
  writeFileSync(feedPath, JSON.stringify({ scanned: 0, missing: [], active: findings, suppressed: [] }, null, 2) + '\n');

  const { matrix, meta } = buildMatrix();
  assert.equal(meta.lintHotspotsPresent, true, 'lint hotspots feed must be present');

  // Every file lint flagged must carry its hotspots on the matching matrix row.
  const flaggedFiles = new Set(findings.map((f) => f.file));
  const byFile = new Map(matrix.map((r) => [r.file, r]));
  let populatedRows = 0;
  for (const f of flaggedFiles) {
    const row = byFile.get(f);
    if (!row) continue; // lint targets and shipped-file set overlap but are not identical
    assert.ok(row.astHotspots.length > 0, `${f}: has lint findings but astHotspots is empty`);
    populatedRows += 1;
  }
  assert.ok(populatedRows > 0, 'no matrix row picked up lint hotspots -> indexer ignored the feed');

  // Concrete anchor: rules.js carries the syntax-keyed-severity + budget-bypass hotspots.
  const rules = byFile.get('content/tools/iam-blast-radius/engine/rules.js');
  assert.ok(rules && rules.astHotspots.length > 0, 'rules.js hotspots missing from the matrix');
});

test('callers relation is the inverse of in-repo imports', () => {
  const { matrix } = buildMatrix();
  const byFile = new Map(matrix.map((r) => [r.file, r]));
  for (const r of matrix) {
    for (const dep of r.imports) {
      const depRow = byFile.get(dep);
      // Cross-repo imports always resolve to a shipped row here.
      if (depRow) {
        assert.ok(
          depRow.callers.includes(r.file),
          `${dep} should list ${r.file} as a caller`,
        );
      }
    }
  }
});
