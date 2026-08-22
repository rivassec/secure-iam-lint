// IAM-504: privacy invariants as release gates (node layer).
// Runs on node's built-in runner: `node --test`.
//
// These assertions promote the tool's privacy/threat-model guarantees into the
// blocking suite so they cannot silently regress:
//   - no network API anywhere in shipped JS (zero egress; architecture inv. 1)
//   - no localStorage/sessionStorage/IndexedDB/cookie WRITE in shipped JS
//     (T4: policy content is never persisted)
//   - no code path that writes policy text into the URL / history / window.name
//   - a failed analysis never leaks policy text into its error payload
//   - every export carries the not-effective caveat + coverage + catalog version
//     + build SHA (a downloaded report is self-describing and traceable)
//   - hostile HTML / SVG / Markdown / Unicode ride through as inert data (JSON
//     round-trips verbatim; Markdown cannot be structurally injected)
//
// The DOM/Worker runtime versions of these (real storage probes, live network,
// pagehide, browser-worker vs node parity) live in the Playwright specs; this
// file covers what `node --test` can assert on the shipped source + pure engine.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';

const here = dirname(fileURLToPath(import.meta.url));
const shippedDir = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius');
const fixturesDir = join(here, '..', 'fixtures');

// Gather every shipped .js file (app.js, worker.js, engine/*.js).
function shippedJsFiles() {
  const files = [];
  for (const f of readdirSync(shippedDir)) {
    if (f.endsWith('.js')) files.push(join(shippedDir, f));
  }
  const engineDir = join(shippedDir, 'engine');
  for (const f of readdirSync(engineDir)) {
    if (f.endsWith('.js')) files.push(join(engineDir, f));
  }
  return files;
}

const SHIPPED = shippedJsFiles().map((path) => ({ path, src: readFileSync(path, 'utf8') }));

// --- No network APIs in shipped JS -------------------------------------------
test('shipped JS contains no network API (zero egress)', () => {
  // Mirrors package.json gate:no-network; call PATTERNS, so a prose mention in a
  // comment cannot trip it (and cannot mask a real call either).
  const NETWORK = [
    /\bfetch\s*\(/,
    /\bXMLHttpRequest\b/,
    /\bWebSocket\b/,
    /\bEventSource\b/,
    /\bsendBeacon\s*\(/,
    /\bnavigator\s*\.\s*sendBeacon\b/,
    /\bimport\s*\(\s*['"`]https?:/,
  ];
  for (const { path, src } of SHIPPED) {
    for (const re of NETWORK) {
      assert.ok(!re.test(src), `${path}: network API ${re} present in shipped JS`);
    }
  }
});

// --- No storage writes in shipped JS -----------------------------------------
test('shipped JS never writes web storage / IndexedDB / cookies', () => {
  const STORAGE_WRITE = [
    /\b(?:local|session)Storage\s*\.\s*(?:setItem|removeItem|clear)\s*\(/,
    /\b(?:local|session)Storage\s*\[/, // bracket assignment/access form
    /\bindexedDB\b/,                    // JS API is lowercase; prose uses "IndexedDB"
    /\bopenDatabase\s*\(/,
    /\bdocument\s*\.\s*cookie\s*=/,
  ];
  for (const { path, src } of SHIPPED) {
    for (const re of STORAGE_WRITE) {
      assert.ok(!re.test(src), `${path}: storage write ${re} present in shipped JS`);
    }
  }
});

// --- No policy text into URL / history / window.name -------------------------
test('shipped JS never writes to the URL, history, or window.name', () => {
  const URL_WRITE = [
    /\blocation\s*\.\s*(?:href|search|hash|pathname|assign|replace)\s*[=(]/,
    /\bhistory\s*\.\s*(?:pushState|replaceState)\s*\(/,
    /\bwindow\s*\.\s*name\s*=/,
  ];
  for (const { path, src } of SHIPPED) {
    for (const re of URL_WRITE) {
      assert.ok(!re.test(src), `${path}: URL/history write ${re} present in shipped JS`);
    }
  }
});

// --- Failed analysis never leaks policy text into the error payload ----------
test('a failed analysis excludes policy text from its error payload', () => {
  const SECRET = 'SECRETTOKEN_DO_NOT_LEAK_9F3A';
  // Several failure modes, each carrying the sentinel in the (invalid) input.
  const inputs = [
    `{"Statement": ${SECRET} not json`,          // INVALID_JSON
    `{"Statement":[{"Effect":"Allow","${SECRET}":1}]}`, // structural garbage
    `${SECRET}`,                                  // bare non-JSON
  ];
  for (const text of inputs) {
    const res = analyze(text);
    const payload = JSON.stringify(res.errors || []);
    assert.ok(
      !payload.includes(SECRET),
      `error payload leaked policy text for input ${JSON.stringify(text).slice(0, 40)}...`,
    );
  }
});

// --- Exports are self-describing: caveat + coverage + versions ---------------
test('JSON export carries caveat + coverage + catalog version + build SHA', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'wildcard', 'admin-star.json'), 'utf8'));
  const parsed = JSON.parse(toJSON(analyze(JSON.stringify(fx.policy))));
  assert.match(parsed.caveat, /NOT compute effective permissions/);
  assert.ok(parsed.coverage && parsed.coverage.summary, 'coverage summary present');
  assert.equal(parsed.catalogVersion, '1');
  assert.ok(parsed.coverage.summary.versions.buildSha, 'build SHA present');
  assert.ok(parsed.coverage.summary.versions.catalogVersion, 'catalog version present');
  assert.ok(parsed.coverage.summary.versions.ruleVersion, 'rule version present');
});

test('Markdown export carries caveat + coverage section + build SHA + versions', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'wildcard', 'admin-star.json'), 'utf8'));
  const md = toMarkdown(analyze(JSON.stringify(fx.policy)));
  assert.match(md, /POTENTIAL blast radius/);
  assert.match(md, /## Analysis coverage/);
  assert.match(md, /Build SHA:/);
  assert.match(md, /Rule catalog version:/);
  assert.match(md, /Action-catalog version:/);
});

// --- Hostile HTML / SVG / MD / Unicode ride through inert ---------------------
test('hostile HTML/SVG payloads round-trip as inert string data in JSON export', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'xss-in-sid-and-arn.json'), 'utf8'));
  const json = toJSON(analyze(JSON.stringify(fx.policy)));
  const parsed = JSON.parse(json); // must be parseable -> payload is a value, not structure
  assert.equal(parsed.model.statements[0].sid, '<img src=x onerror=alert(1)>');
});

test('hostile Markdown control characters cannot inject document structure', () => {
  const NL = String.fromCharCode(10);
  const hostileSid = `benign${NL}## FORGED HEADING${NL}- forged bullet${NL}> forged quote`;
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: hostileSid, Effect: 'Allow', Action: '*', Resource: '*' }],
  });
  const md = toMarkdown(analyze(policy));
  const lines = md.split(NL);
  assert.ok(!lines.some((l) => /^##\s*FORGED/.test(l)), 'forged heading injected into Markdown');
  assert.ok(!lines.some((l) => /^- forged bullet/.test(l)), 'forged list item injected into Markdown');
  assert.ok(!lines.some((l) => /^>\s*forged quote/.test(l)), 'forged block quote injected into Markdown');
  // The benign prefix still rides through as inert text somewhere in the report.
  assert.match(md, /benign/);
});

test('hostile Unicode (BiDi / zero-width) rides through analysis as inert data', () => {
  const RLO = String.fromCharCode(0x202e); // right-to-left override
  const ZWSP = String.fromCharCode(0x200b); // zero-width space
  const BOM = String.fromCharCode(0xfeff);
  const sid = `a${RLO}b${ZWSP}c${BOM}`;
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: sid, Effect: 'Allow', Action: '*', Resource: '*' }],
  });
  const res = analyze(policy);
  assert.equal(res.ok, true, 'unicode payload must not break analysis');
  // JSON keeps it verbatim (inert); round-trips exactly.
  const parsed = JSON.parse(toJSON(res));
  assert.equal(parsed.model.statements[0].sid, sid);
});
