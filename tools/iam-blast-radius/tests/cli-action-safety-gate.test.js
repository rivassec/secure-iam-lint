// S6-cigate-doc: safety gates for the SHIPPED CLI + Action (node layer).
//
// The shipped engine under content/tools/iam-blast-radius/ is fenced by the
// package.json gate:no-network + gate:no-unsafe-dom greps and by
// privacy-invariants.test.js. But the CLI (cli/*.mjs) and the GitHub Action
// (action/*.mjs) - the code that runs INSIDE consumers' CI - were UNGATED. A
// network call, a remote import(), an eval/new Function, or a child_process/vm
// import in that code is a supply-chain and data-exfil hazard for every
// consumer. This suite promotes the CLI/Action no-egress + no-code-exec
// invariants into the blocking `node --test` run so they cannot silently
// regress, and asserts the CI pipeline + npm scripts that enforce them still
// exist (a deleted CI step or npm script fails here too).
//
// Design (mirrors privacy-invariants.test.js): scan the real source with CALL /
// IMPORT-SPECIFIER patterns, not bare word mentions - a prose mention in a
// comment (e.g. "there is no child_process import here") must not trip the gate,
// and cannot mask a real call either. The CLI legitimately uses node: fs / path /
// url / crypto; those are ALLOWED. Any network core module (http/https/net/...),
// remote import(), eval/Function, or child_process/vm is FORBIDDEN.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');
const cliDir = join(repoRoot, 'cli');
const actionDir = join(repoRoot, 'action');

// Gather every shipped node-layer source (cli/*.mjs + action/*.mjs).
function nodeLayerSources() {
  const out = [];
  for (const dir of [cliDir, actionDir]) {
    for (const f of readdirSync(dir)) {
      if (f.endsWith('.mjs') || f.endsWith('.js')) {
        out.push({ path: join(dir, f), src: readFileSync(join(dir, f), 'utf8') });
      }
    }
  }
  return out;
}

const SOURCES = nodeLayerSources();

// Sanity: we actually found the files the gate is meant to protect.
test('CLI + Action sources are present to gate', () => {
  const names = SOURCES.map((s) => s.path.split('/').slice(-2).join('/')).sort();
  assert.ok(names.includes('cli/scan.mjs'), 'cli/scan.mjs present');
  assert.ok(names.includes('action/index.mjs'), 'action/index.mjs present');
  assert.ok(SOURCES.length >= 3, 'expected the cli/ + action/ node sources');
});

// --- No network egress in the shipped CLI + Action ---------------------------
test('shipped CLI + Action contain no network API (zero egress)', () => {
  const NETWORK = [
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    /\bWebSocket\b/,
    /\bEventSource\b/,
    /\bsendBeacon\s*\(/,
    /\bnavigator\s*\.\s*sendBeacon\b/,
    // remote dynamic import: import('http(s)://...')
    /\bimport\s*\(\s*['"`]https?:/,
    // import / require of a network CORE module. Anchored to the quoted
    // specifier so a URL string ('https://...') or an ARN ('.../net') cannot
    // match: the module name must be the ENTIRE quoted token.
    /['"`](?:node:)?(?:http|https|http2|net|tls|dgram|dns|inspector)['"`]/,
  ];
  for (const { path, src } of SOURCES) {
    for (const re of NETWORK) {
      assert.ok(!re.test(src), `${path}: network API ${re} present in shipped CLI/Action`);
    }
  }
});

// --- No code execution in the shipped CLI + Action ---------------------------
test('shipped CLI + Action contain no code-exec API (no eval/Function/child_process/vm)', () => {
  const CODE_EXEC = [
    /\beval\s*\(/,
    /\bnew\s+Function\b/,
    // string-form timers execute a string as code
    /\bsetTimeout\s*\(\s*['"`]/,
    /\bsetInterval\s*\(\s*['"`]/,
    // DOM sinks - inert in node, kept so the class stays closed if code moves
    /\binnerHTML\b/,
    /\bouterHTML\b/,
    /\binsertAdjacentHTML\b/,
    // import / require of a process-spawning or code-eval core module. The
    // import specifier is the single choke point through which these APIs can
    // enter; a bare mention in a comment is not quoted, so it does not match.
    /['"`](?:node:)?(?:child_process|vm|repl|module)['"`]/,
  ];
  for (const { path, src } of SOURCES) {
    for (const re of CODE_EXEC) {
      assert.ok(!re.test(src), `${path}: code-exec API ${re} present in shipped CLI/Action`);
    }
  }
});

// --- The enforcement pipeline itself cannot be silently removed --------------
// The scans above are the substance; these assertions keep the CI + npm-script
// wiring honest so the gate runs on every push/PR, not only in this test.
test('package.json defines the CLI/Action gate scripts targeting cli/ + action/', () => {
  const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));
  const s = pkg.scripts || {};
  for (const name of ['gate:no-network:node', 'gate:no-unsafe:node']) {
    assert.ok(typeof s[name] === 'string' && s[name].length > 0, `package.json script ${name} missing`);
    assert.match(s[name], /\.\.\/\.\.\/cli\//, `${name} must scan ../../cli/`);
    assert.match(s[name], /\.\.\/\.\.\/action\//, `${name} must scan ../../action/`);
    // Fail-closed shape: the grep is negated and a match exits non-zero.
    assert.match(s[name], /exit 1/, `${name} must exit non-zero on a match`);
  }
  // The network gate must actually forbid the network core modules + remote import.
  assert.match(s['gate:no-network:node'], /http\|https/, 'net gate lists http/https core modules');
  assert.match(s['gate:no-network:node'], /https\?:/, 'net gate forbids remote import()');
  // The code-exec gate must forbid child_process + eval + Function.
  assert.match(s['gate:no-unsafe:node'], /child_process/, 'exec gate forbids child_process');
  assert.match(s['gate:no-unsafe:node'], /eval/, 'exec gate forbids eval');
  assert.match(s['gate:no-unsafe:node'], /new Function/, 'exec gate forbids new Function');
});

test('ci.yml runs both CLI/Action gates on every push/PR', () => {
  const ci = readFileSync(join(repoRoot, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.match(ci, /npm run gate:no-network:node/, 'ci.yml must run gate:no-network:node');
  assert.match(ci, /npm run gate:no-unsafe:node/, 'ci.yml must run gate:no-unsafe:node');
});
