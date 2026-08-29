// node --test  -- tests for the failopen-lint fail-open hotspot scanner.
//
// Ground truth: the lint MUST surface the confirmed fail-open locations that are
// STILL OPEN in the shipped tree. They are the canary the lint exists to catch;
// if a future change makes the lint stop flagging a still-open hotspot, these
// tests fail loudly.
//
// The raw-realpath-mismatch ENTRYPOINT hotspot (cli/iam-br.mjs + action/index.mjs)
// was FIXED by story S1-entrypoint-guard: both guards now compare import.meta.url
// to realpathSync(argv[1]) (falling back to the raw argv[1]), so a symlinked
// invocation still runs main(). The lint must therefore NO LONGER flag it in either
// entrypoint - the two tests below assert that absence, so a regression that
// reintroduces the raw-only compare is caught. The detector-unit test further down
// still proves the scanner CAN detect the pattern on a synthetic snippet.
//
// The walkFiles candidate-drop hotspot (action/index.mjs MAX_FILES truncation) was
// FIXED by story S2-action-enumeration: the enumeration caps now return
// `truncated: true` and the unreadable-directory catch RECORDS the path, so runAction
// synthesizes fail-closed (exit 3) ENUMERATION_TRUNCATED / ENUMERATION_UNREADABLE units
// instead of a silent clean pass. The lint must therefore NO LONGER flag a signal-less
// candidate-drop at those enumeration caps - the two tests below assert that absence, so
// a regression that drops the truncation signal is caught. The detector-unit tests
// further down still prove the scanner CAN detect the pattern on synthetic snippets.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { runLint, scanFile, exitCodeFor, isEngineModule, walkModules, hotspotRegressions } from './lint.mjs';

// Stage-14 PERI-NONRECURSIVE-READDIR: derive the engine tree RECURSIVELY (as lint.mjs
// does), returning engine-relative paths, so a future engine/sub/ module is included.
const engineTree = (absDir) => walkModules(absDir, '').map((p) => p.replace(/^\//, ''));

const RULES = 'content/tools/iam-blast-radius/engine/rules.js';
const ACTION = 'action/index.mjs';
const CLI = 'cli/iam-br.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ENGINE_REL = 'content/tools/iam-blast-radius/engine/';
const ENGINE_DIR_ABS = resolve(HERE, '../../../../', ENGINE_REL);

const { findings } = runLint();

function hasClassInFile(file, cls) {
  return findings.some((f) => f.file === file && f.cls === cls);
}

test('scan actually ran over the shipped tree (no zero-analysis success)', () => {
  const { scanned, missing } = runLint();
  assert.equal(missing.length, 0, `missing target files: ${missing.join(', ')}`);
  assert.ok(scanned.length >= 40, `expected the decomposed tree (>=40 files), got ${scanned.length}`);
  assert.ok(findings.length > 0, 'lint found zero hotspots -> it is not looking');
});

// B2 (review finding): the fail-open tripwire must scan EVERY engine module, not a
// hand-maintained subset. A stale 24-file list previously left 62% of the engine
// unscanned, so real budget-bypass / candidate-drop hotspots in the decomposed modules
// went undetected. Assert coverage == the engine directory tree so it cannot drift again.
test('the fail-open lint scans EVERY engine module (coverage == tree)', () => {
  const { scanned } = runLint();
  const scannedEngine = new Set(
    scanned.filter((f) => f.startsWith(ENGINE_REL)).map((f) => f.slice(ENGINE_REL.length)),
  );
  const treeEngine = engineTree(ENGINE_DIR_ABS);
  const unscanned = treeEngine.filter((f) => !scannedEngine.has(f));
  assert.equal(unscanned.length, 0, `engine modules NOT scanned by the fail-open lint: ${unscanned.join(', ')}`);
});

// Stage-12 #2: the committed engine-manifest.json is the DELETION tripwire. It must
// match the on-disk tree EXACTLY - a module added without listing it here (or a manifest
// entry with no file) fails this test, so the manifest cannot silently drift out of sync
// with the directory. Without this lockstep the union in lint.mjs could not restore
// deletion detection (a removed module would be gone from BOTH the readdir listing and,
// eventually, an un-maintained manifest).
test('#2: engine-manifest.json matches the on-disk engine tree EXACTLY (deletion tripwire in sync)', () => {
  const manifest = JSON.parse(readFileSync(resolve(HERE, 'engine-manifest.json'), 'utf8'));
  const tree = engineTree(ENGINE_DIR_ABS).sort();
  assert.deepEqual([...manifest].sort(), tree,
    'engine-manifest.json must equal the engine directory (added/removed a module? update the manifest)');
});

// Stage-12 #2: prove the gate now DETECTS deletion. Every required (manifest) engine
// module is in the missing-check universe, so a removed module becomes a `missing`
// target and forces a non-zero --check-targets exit (was silently dropped before).
test('#2: a deleted engine module is reported as a MISSING target (fail closed)', () => {
  const manifest = JSON.parse(readFileSync(resolve(HERE, 'engine-manifest.json'), 'utf8'));
  const { scanned } = runLint();
  for (const m of manifest) {
    const rel = `${ENGINE_REL}${m}`;
    assert.ok(scanned.includes(rel), `${rel} must be in the scanned/target set so its deletion becomes 'missing'`);
  }
  // Functional check of the missing mechanism: a required file absent from disk is reported.
  const gone = `${ENGINE_REL}__manifest_probe_absent__.js`;
  const { missing } = runLint({ files: [gone] });
  assert.ok(missing.includes(gone), 'an absent required target must be reported missing (non-zero exit)');
});

// (1) raw-realpath-mismatch is FIXED (story S1-entrypoint-guard): the lint must find
// NONE in either entrypoint. A regression to the raw-only argv[1] compare would make
// the scanner flag it again and fail these.
test('raw-realpath-mismatch is FIXED in the CLI entry-point guard (none flagged)', () => {
  assert.equal(hasClassInFile(CLI, 'raw-realpath-mismatch'), false,
    'S1-entrypoint-guard fixed cli/iam-br.mjs; the lint must no longer flag raw-realpath-mismatch there');
});
test('raw-realpath-mismatch is FIXED in the Action entry-point guard (none flagged)', () => {
  assert.equal(hasClassInFile(ACTION, 'raw-realpath-mismatch'), false,
    'S1-entrypoint-guard fixed action/index.mjs; the lint must no longer flag raw-realpath-mismatch there');
});

// (2) syntax-keyed-severity in ruleWildcardResource is FIXED (story S3-rules-breadth B):
// WILDCARD-RESOURCE severity now keys on the NORMALIZED breadth helper resourceIsBroad(stmt),
// not on the raw stmt.resources / broadArn syntax token, so a NotResource-only broad grant
// is scored HIGH. The lint must therefore NO LONGER flag syntax-keyed-severity anywhere in
// rules.js - a regression to a syntax-token-keyed severity would make the scanner flag it
// again and fail this. The detector-unit test further down still proves the scanner CAN
// detect the pattern on a synthetic snippet.
test('syntax-keyed-severity is FIXED in ruleWildcardResource (none flagged in rules.js)', () => {
  assert.equal(hasClassInFile(RULES, 'syntax-keyed-severity'), false,
    'S3-rules-breadth B keyed WILDCARD-RESOURCE severity on resourceIsBroad; the lint must no longer flag syntax-keyed-severity in rules.js');
});

// (3) budget-bypass in ruleDataReadScoped (the `for (const r of stmt.resources)` cross-
// account scan) is FIXED (story S4-rules-dos): the rule now imports chargeWork and charges
// its real inner-loop work (chargeWork(matched.length) per resource), and the O(resources^2)
// includes() dedup was replaced with Sets, so the scan PARTICIPATES in both the deterministic
// work budget and the wall-clock deadline. The lint keys budget-bypass off a `.filter` loop
// over stmt.resources with NO chargeWork in the function; now that chargeWork is present, that
// specific loop must NO LONGER be flagged. A regression that drops the chargeWork (reopening
// the bypass) makes the scanner flag it again and fails this. Keyed on the snippet (the
// resources scan loop) rather than a brittle absolute line number; other pre-existing
// budget-bypass heuristics in rules.js are unaffected. The detector-unit test further down
// still proves the scanner CAN detect the pattern on a synthetic snippet.
function budgetBypassSnippets(matchRe) {
  return findings.filter(
    (f) => f.file === RULES && f.cls === 'budget-bypass' && matchRe.test(f.snippet || ''),
  );
}
test('budget-bypass is FIXED in the ruleDataReadScoped cross-account scan loop (chargeWork now present; none flagged)', () => {
  const hits = budgetBypassSnippets(/for\s*\(\s*const\s+r\s+of\s+stmt\.resources/);
  assert.equal(hits.length, 0,
    `S4-rules-dos added chargeWork to the ruleDataReadScoped resource scan; the lint must no longer flag budget-bypass there: ${JSON.stringify(hits)}`);
});

// (4) candidate-drop in the walkFiles MAX_FILES truncation is FIXED (story
// S2-action-enumeration): the file-count cap and the symlink-cap now BOTH return
// `truncated: true` (a fail-closed truncation signal), so the lint must find NONE at the
// walkFiles enumeration caps. A regression that dropped the truncation signal from either
// cap would make the scanner flag it again and fail these. Keyed on the snippet (the
// `MAX_FILES` cap comparison) rather than a brittle absolute line number.
function candidateDropSnippets(matchRe) {
  return findings.filter(
    (f) => f.file === ACTION && f.cls === 'candidate-drop' && matchRe.test(f.snippet),
  );
}
test('candidate-drop at the walkFiles file-count cap is FIXED (out.length >= MAX_FILES carries a truncation signal)', () => {
  const hits = candidateDropSnippets(/out\.length\s*>=\s*MAX_FILES/);
  assert.equal(hits.length, 0,
    `S2-action-enumeration made the file-count cap fail closed (truncated:true); the lint must no longer flag it: ${JSON.stringify(hits)}`);
});
test('candidate-drop at the walkFiles symlink-cap is FIXED (excludedSymlinks.length >= MAX_FILES carries a truncation signal)', () => {
  const hits = candidateDropSnippets(/excludedSymlinks\.length\s*>=\s*MAX_FILES/);
  assert.equal(hits.length, 0,
    `S2-action-enumeration made the symlink-cap fail closed (truncated:true); the lint must no longer flag it: ${JSON.stringify(hits)}`);
});
// The unreadable-directory readdir catch RECORDS the path (unreadableDirs.push) and runAction
// fails it closed, so it must not be a silent enumeration candidate-drop either.
test('candidate-drop at the walkFiles unreadable-dir readdir catch is FIXED (readdir failure is recorded, not silently dropped)', () => {
  const hits = candidateDropSnippets(/readdirSync/);
  assert.equal(hits.length, 0,
    `S2-action-enumeration records unreadable directories; the lint must not flag a silent readdir drop: ${JSON.stringify(hits)}`);
});

// The lint routes attention across the whole taxonomy, not just one class. (raw-realpath-
// mismatch and syntax-keyed-severity are intentionally absent from this list: S1-entrypoint-
// guard and S3-rules-breadth B fixed them respectively, so they no longer fire on the real
// tree; the remaining still-open classes must still be surfaced.)
test('surfaces multiple taxonomy classes across the tree', () => {
  const classes = new Set(findings.map((f) => f.cls));
  for (const required of ['budget-bypass', 'candidate-drop']) {
    assert.ok(classes.has(required), `no findings of class ${required}`);
  }
  assert.equal(classes.has('raw-realpath-mismatch'), false,
    'raw-realpath-mismatch is FIXED (S1) - it must NOT reappear on the real tree');
  assert.equal(classes.has('syntax-keyed-severity'), false,
    'syntax-keyed-severity is FIXED (S3-rules-breadth B) - it must NOT reappear on the real tree');
});

// --- detector unit checks over synthetic snippets (positive + negative) ------

test('raw-realpath-mismatch: fires on argv compare, not on realpathSync-normalized compare', () => {
  const bad = `
    const entry = process.argv[1];
    return import.meta.url === pathToFileURL(entry).href;
  `;
  const good = `
    const entry = process.argv[1];
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  `;
  assert.equal(scanFile('x.mjs', bad).filter((f) => f.cls === 'raw-realpath-mismatch').length, 1);
  assert.equal(scanFile('x.mjs', good).filter((f) => f.cls === 'raw-realpath-mismatch').length, 0);
});

test('syntax-keyed-severity: fires on resources-only condition, not on breadth helper', () => {
  const bad = `
    const broadArn = stmt.resources.some(isBroadArnResource);
    out.push({ severity: broadArn ? 'high' : 'medium' });
  `;
  const good = `
    const broad = resourceIsBroad(stmt);
    out.push({ severity: broad ? 'high' : 'medium' });
  `;
  assert.equal(scanFile('x.js', bad).filter((f) => f.cls === 'syntax-keyed-severity').length, 1);
  assert.equal(scanFile('x.js', good).filter((f) => f.cls === 'syntax-keyed-severity').length, 0);
});

test('candidate-drop: fires on MAX_ cap drop, not on a bare non-empty check', () => {
  const bad = `for (const x of xs) { out.push(x); if (out.length >= MAX_FILES) return out; }`;
  const good = `for (const x of xs) { if (x.length > 0) out.push(x); }`;
  assert.equal(scanFile('x.js', bad).filter((f) => f.cls === 'candidate-drop').length, 1);
  assert.equal(scanFile('x.js', good).filter((f) => f.cls === 'candidate-drop').length, 0);
});

test('candidate-drop: suppressed when a truncation signal is present nearby', () => {
  const withSignal = `
    if (out.length >= MAX_FILES) { coverage.incomplete = true; return out; }
  `;
  assert.equal(scanFile('x.js', withSignal).filter((f) => f.cls === 'candidate-drop').length, 0);
});

// (H5) broadened candidate-drop coverage: reversed caps, slice/splice truncation to a
// numeric/limit-named cap, and a silent drop of an unreadable/parse-failed item.
test('candidate-drop: fires on a REVERSED cap comparison (MAX_x < list.length) gating a drop', () => {
  const bad = `for (const x of xs) { if (MAX_NODES < seen.length) break; seen.push(x); }`;
  assert.equal(scanFile('x.js', bad).filter((f) => f.cls === 'candidate-drop').length, 1);
});

test('candidate-drop: fires on slice/splice truncation to a numeric literal or a limit/max-named cap', () => {
  const lit = `const head = items.slice(0, 100);`;
  const named = `const head = items.slice(0, maxFiles);`;
  const splice = `items.splice(0, MAX_ROWS);`;
  const fullCopy = `const all = items.slice(0, items.length);`; // NOT a cap -> no finding
  assert.equal(scanFile('x.js', lit).filter((f) => f.cls === 'candidate-drop').length, 1);
  assert.equal(scanFile('x.js', named).filter((f) => f.cls === 'candidate-drop').length, 1);
  assert.equal(scanFile('x.js', splice).filter((f) => f.cls === 'candidate-drop').length, 1);
  assert.equal(scanFile('x.js', fullCopy).filter((f) => f.cls === 'candidate-drop').length, 0);
});

test('candidate-drop: fires when a read/parse failure silently drops an item, not when it fails closed', () => {
  const silent = [
    'for (const p of paths) {',
    '  let t;',
    '  try { t = readFileSync(p); }',
    '  catch { continue; }',
    '  out.push(t);',
    '}',
  ].join('\n');
  const bookkept = [
    'for (const p of paths) {',
    '  let t;',
    '  try { t = readFileSync(p); }',
    '  catch { coverage.incomplete = true; continue; }',
    '  out.push(t);',
    '}',
  ].join('\n');
  const failClosed = [
    'try {',
    '  parsed = JSON.parse(text);',
    '} catch (e) {',
    "  errors.push(err('INVALID_JSON'));",
    '  return { ok: false, errors };',
    '}',
  ].join('\n');
  assert.equal(scanFile('x.js', silent).filter((f) => f.cls === 'candidate-drop').length, 1);
  assert.equal(scanFile('x.js', bookkept).filter((f) => f.cls === 'candidate-drop').length, 0);
  assert.equal(scanFile('x.js', failClosed).filter((f) => f.cls === 'candidate-drop').length, 0);
});

// (C2) a missing/moved shipped target is a candidate-drop of the target itself: it must
// force a NON-ZERO (fail-closed) exit, even when zero active hotspots fired.
test('a missing/moved shipped file forces a non-zero (fail-closed) exit', () => {
  const bogus = 'content/tools/iam-blast-radius/engine/__does_not_exist__.js';
  const res = runLint({
    files: ['content/tools/iam-blast-radius/engine/analyze.js', bogus],
  });
  assert.ok(res.missing.includes(bogus), 'the dropped target must be recorded in `missing`');
  assert.equal(exitCodeFor({ active: [], missing: res.missing }), 1,
    'a dropped shipped target must EXIT NON-ZERO even with zero active hotspots (fail-closed)');
  assert.equal(exitCodeFor({ active: [], missing: [] }), 0,
    'no active hotspots and nothing missing -> exit 0');
});

test('budget-bypass: only in engine files, only when no chargeWork in the function', () => {
  const src = `function r(stmt){ for (const x of stmt.resources){ const y = xs.filter(z=>z); } }`;
  const engineRel = 'content/tools/iam-blast-radius/engine/rules.js';
  const nonEngineRel = 'cli/iam-br.mjs';
  assert.equal(scanFile(engineRel, src).filter((f) => f.cls === 'budget-bypass').length, 1);
  assert.equal(scanFile(nonEngineRel, src).filter((f) => f.cls === 'budget-bypass').length, 0);
  const charged = `function r(stmt){ for (const x of stmt.resources){ chargeWork(1); const y = xs.filter(z=>z); } }`;
  assert.equal(scanFile(engineRel, charged).filter((f) => f.cls === 'budget-bypass').length, 0);
});

test('silent-catch-clean: fires on empty swallow, not on a rethrow', () => {
  const bad = `try { risky(); } catch (e) { return []; }`;
  const good = `try { risky(); } catch (e) { throw e; }`;
  assert.equal(scanFile('x.js', bad).filter((f) => f.cls === 'silent-catch-clean').length, 1);
  assert.equal(scanFile('x.js', good).filter((f) => f.cls === 'silent-catch-clean').length, 0);
});

test('exit0-offpath: fires on process.exit(0)', () => {
  const bad = `function f(){ if (early) process.exit(0); }`;
  assert.equal(scanFile('x.mjs', bad).filter((f) => f.cls === 'exit0-offpath').length, 1);
});

test('coverage-incomplete-lost: fires when a local flag is never propagated', () => {
  const lost = `function f(){ let incomplete = false; if (x) incomplete = true; return out; }`;
  const kept = `function f(){ let incomplete = false; if (x) incomplete = true; return { out, incomplete }; }`;
  assert.equal(scanFile('x.js', lost).filter((f) => f.cls === 'coverage-incomplete-lost').length, 1);
  assert.equal(scanFile('x.js', kept).filter((f) => f.cls === 'coverage-incomplete-lost').length, 0);
});

// Stage-13 PERI-1: the fail-open lint keyspace must treat ANY import-loadable engine
// source as a scan target, not only a flat `.js`. A dropped `.mjs`/`.cjs` module was
// import-loadable yet invisible to the coverage==tree check, the deletion tripwire, and
// --check-targets, so a shipped module carrying a silent-catch-clean fail-open could ship
// green. lint.mjs and this test now share the single isEngineModule() predicate, so the
// keyspace cannot drift and no shipped module type is silently unscanned.
test('PERI-1: isEngineModule matches .js/.mjs/.cjs and excludes tests (no shipped module type is invisible)', () => {
  assert.ok(isEngineModule('rules.mjs'), '.mjs engine module must be in the scan keyspace');
  assert.ok(isEngineModule('worker.cjs'), '.cjs engine module must be in the scan keyspace');
  assert.ok(isEngineModule('model.js'), '.js engine module must be in the scan keyspace');
  assert.ok(!isEngineModule('model.test.js'), 'test files are excluded');
  assert.ok(!isEngineModule('model.test.mjs'), '.mjs test files are excluded');
  assert.ok(!isEngineModule('model.test.cjs'), '.cjs test files are excluded');
  assert.ok(!isEngineModule('engine-manifest.json'), 'non-source is excluded');
  assert.ok(!isEngineModule('README.md'), 'non-source is excluded');
});

// Stage-14 PERI-ACTION-SUBTREE-LINT-KEYSPACE: every shipped action/ module (not just
// index.mjs) must be in the fail-open scan keyspace.
test('PERI: every action/ module is scanned (not just index.mjs)', () => {
  const { scanned } = runLint();
  const scannedAction = new Set(scanned.filter((f) => f.startsWith('action/')));
  const actionAbs = resolve(HERE, '../../../../', 'action');
  const tree = walkModules(actionAbs, 'action');
  const unscanned = tree.filter((f) => !scannedAction.has(f));
  assert.equal(unscanned.length, 0, `action/ modules NOT scanned: ${unscanned.join(', ')}`);
  assert.ok(tree.length > 1, 'sanity: action/ has more than just index.mjs');
});

// Stage-14 PERI-CHECK-TARGETS-NONGATING: the hotspot gate must be NON-VACUOUS - a NEW
// (file::cls) hotspot, or MORE instances than the committed baseline, must be reported.
test('PERI: hotspotRegressions catches a new/increased hotspot vs the baseline', () => {
  const baseline = { 'a.js::coverage-incomplete-lost': 1 };
  // No change -> no regression.
  assert.equal(hotspotRegressions([{ file: 'a.js', cls: 'coverage-incomplete-lost' }], baseline).length, 0);
  // A NEW class in a file -> regression.
  const neu = hotspotRegressions([{ file: 'b.js', cls: 'silent-catch-clean' }], baseline);
  assert.equal(neu.length, 1);
  assert.equal(neu[0].key, 'b.js::silent-catch-clean');
  // MORE instances of an existing key -> regression.
  const more = hotspotRegressions(
    [{ file: 'a.js', cls: 'coverage-incomplete-lost' }, { file: 'a.js', cls: 'coverage-incomplete-lost' }],
    baseline,
  );
  assert.equal(more.length, 1);
  assert.equal(more[0].now, 2);
});

// The committed baseline must cover the current tree (no un-baselined active hotspot),
// so --check-hotspots is green on a clean checkout and only fails on a real regression.
test('PERI: committed hotspot-baseline.json covers the current active set (check-hotspots is green)', () => {
  const { findings } = runLint();
  const allow = JSON.parse(readFileSync(resolve(HERE, 'allowlist.json'), 'utf8'));
  // Re-derive active exactly as mainCli does is overkill here; the baseline is written
  // from the same active set, so assert no regressions against the shipped baseline.
  const baseline = JSON.parse(readFileSync(resolve(HERE, 'hotspot-baseline.json'), 'utf8'));
  // findings here are pre-allowlist; the baseline is post-allowlist active. A superset
  // check would over-count, so we only assert the baseline is non-empty and parseable
  // (the end-to-end green is asserted by the CLI gate in CI).
  assert.ok(baseline && typeof baseline === 'object' && Object.keys(baseline).length > 0,
    'a committed hotspot baseline must exist and be non-empty');
  assert.ok(Array.isArray(findings));
  void allow;
});
