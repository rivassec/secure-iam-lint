// Regression tests for story C-doc-note (DOC-ONLY, Round 4 / Phase 20).
//
// Team1 flagged that CLI `--format json` emits policy-derived strings VERBATIM
// while SARIF / Markdown / DOM / SVG neutralize the Unicode/bidi visual-spoof
// class. The correct resolution is DOCUMENTATION, not neutralization: the JSON
// output is a BYTE-FAITHFUL machine artifact, and neutralizing it would corrupt
// the exact bytes (fingerprints / ARNs / action names) downstream tooling
// consumes. Hostile Unicode rides through the JSON INERT (it is data inside a
// JSON string - never executed, never interpolated into a page).
//
// This suite pins TWO things so neither drifts:
//   1. BEHAVIOR: `--format json` is byte-faithful (raw bidi survives), while
//      `--format sarif` neutralizes the same value. This guards against a
//      future well-meaning "sanitize the JSON too" change that would silently
//      break the machine contract AND falsify the docs below.
//   2. DOCS: threat-model.md, engine/format-control.js, and README each state
//      that `--format json` is a byte-faithful machine surface (NOT display-safe)
//      and route a HUMAN reviewer to `--format sarif` / a renderer instead.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { scan } from '../../../cli/scan.mjs';
import { formatJson, formatSarif } from '../../../cli/iam-br.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');
const MANIFEST = { ruleVersion: '1' };

// A strong-RTL LETTER (Hebrew aleph, U+05D0) is the right byte-faithful probe.
// It is a CVE-2021-42574 bidi visual-spoof vector (it reorders its neighbours),
// but - unlike a \p{Cf} bidi CONTROL (U+202E), which the narrow model-normalize
// class strips at analysis entry - a strong-RTL letter is PRESERVED through the
// model (MODEL_NORMALIZE_SPOOF never touches letters). So it rides into the
// finding string intact and, if the JSON path is byte-faithful, survives
// LITERALLY there (JSON.stringify does not escape it: >= U+0020, not a quote/
// backslash). The DISPLAY sinks (SARIF) clamp every non-ASCII code point to
// U+FFFD, so it must NOT survive there. This is the exact json-faithful /
// sarif-safe split the docs describe.
const RTL_LETTER = 'א';
const REPLACEMENT = '�';

// An admin-identity policy (iam:* on *) fires DIRECT-IAM-ADMIN, whose finding
// carries the statement Sid verbatim - the exact policy-derived channel under test.
function adminPolicy(sid) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: sid, Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
  });
}

// --- 1. BEHAVIOR: json is byte-faithful; sarif neutralizes ------------------------

test('C-doc-note: --format json emits policy-derived strings BYTE-FAITHFULLY (raw bidi survives)', () => {
  const sid = `Read${RTL_LETTER}OnlyAudit`;
  const result = scan({ text: adminPolicy(sid), family: 'identity' });
  const json = formatJson(result, { family: 'identity' }, MANIFEST);

  // The raw bidi override rides through the machine JSON intact - not stripped,
  // not replaced with U+FFFD. This is the machine contract (exact bytes).
  assert.ok(json.includes(RTL_LETTER), 'raw strong-RTL letter survives verbatim in --format json (byte-faithful)');
  assert.ok(!json.includes(REPLACEMENT), 'the JSON path does not U+FFFD-replace the value (no neutralization)');

  // And the finding string itself carries the exact original Sid.
  const report = JSON.parse(json);
  const sids = report.findings.map((f) => f.statementSid);
  assert.ok(sids.includes(sid), 'findings[].statementSid is the exact original bytes');
});

test('C-doc-note: --format sarif NEUTRALIZES the same value (the display surface for humans)', () => {
  const sid = `Read${RTL_LETTER}OnlyAudit`;
  const result = scan({ text: adminPolicy(sid), family: 'identity' });
  const sarif = formatSarif(result, { file: 'p.json' }, MANIFEST);

  // The SARIF display surface must not carry the raw bidi override; it is clamped
  // to U+FFFD. This is what makes SARIF (not raw JSON) the human review surface.
  assert.ok(!sarif.includes(RTL_LETTER), 'raw strong-RTL letter does NOT survive into --format sarif (neutralized)');
  assert.ok(sarif.includes(REPLACEMENT), 'the SARIF surface replaces the non-ASCII spoof char with U+FFFD');
});

test('C-doc-note: the two surfaces genuinely DIFFER on a hostile value (json faithful, sarif safe)', () => {
  const sid = `Grant${RTL_LETTER}Admin`;
  const result = scan({ text: adminPolicy(sid), family: 'identity' });
  const jsonHasRaw = formatJson(result, { family: 'identity' }, MANIFEST).includes(RTL_LETTER);
  const sarifHasRaw = formatSarif(result, { file: 'p.json' }, MANIFEST).includes(RTL_LETTER);
  assert.ok(jsonHasRaw && !sarifHasRaw,
    'json is byte-faithful (keeps raw bidi) while sarif is display-safe (strips it) - the exact distinction the docs describe');
});

// --- 2. DOCS: every surface that describes formats states the json contract -------

test('C-doc-note: threat-model.md documents --format json as a byte-faithful, non-display machine artifact', () => {
  const doc = readFileSync(join(here, '..', 'docs', 'threat-model.md'), 'utf8');
  assert.match(doc, /--format json/, 'threat-model.md must name --format json');
  assert.match(doc, /byte-faithful/i, 'threat-model.md must call the JSON output byte-faithful');
  // It must route a HUMAN to sarif / a renderer, and warn off raw `cat report.json`.
  assert.match(doc, /--format sarif/, 'threat-model.md must route humans to --format sarif');
  assert.match(doc, /cat report\.json/i, 'threat-model.md must warn against trusting raw `cat report.json` visually');
  // And it must NOT claim the JSON surface neutralizes (that would be false).
  assert.match(doc, /NOT (a )?display/i, 'threat-model.md must state the JSON output is NOT a display surface');
});

test('C-doc-note: format-control.js contract comment lists the neutralizing surfaces and excludes CLI plain-JSON', () => {
  const src = readFileSync(
    join(repoRoot, 'content', 'tools', 'iam-blast-radius', 'engine', 'format-control.js'),
    'utf8',
  );
  // The comment must name the display/export sinks that DO neutralize...
  for (const surface of [/Markdown/, /SARIF/, /DOM/, /SVG/]) {
    assert.match(src, surface, `format-control.js comment must list ${surface} as a neutralizing surface`);
  }
  // ...and must explicitly call out the CLI --format json plain-JSON surface as the
  // byte-faithful exception that is NOT neutralized.
  assert.match(src, /--format json/, 'format-control.js comment must name the --format json exception');
  assert.match(src, /byte-faithful/i, 'format-control.js comment must call the JSON surface byte-faithful');
});

test('C-doc-note: README documents the byte-faithful json vs display-safe sarif distinction', () => {
  const readme = readFileSync(join(repoRoot, 'README.md'), 'utf8');
  assert.match(readme, /byte-faithful/i, 'README must call --format json byte-faithful');
  assert.match(readme, /--format sarif/, 'README must route humans to --format sarif');
});
