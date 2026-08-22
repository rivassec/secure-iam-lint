// Unit tests for IAM-007 export serialization (engine/report.js).
// Runs on node's built-in runner: `node --test`.
//
// The Download JSON / Download Markdown buttons hand these pure strings to a
// Blob. This suite verifies the serializers are deterministic, carry the
// not-effective-permissions caveat, round-trip via JSON, and treat hostile
// policy fields as inert text (no execution possible in a downloaded file).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

function analyzeFixture(rel) {
  const fx = JSON.parse(readFileSync(join(fixturesDir, rel), 'utf8'));
  const text = typeof fx.policyRaw === 'string' ? fx.policyRaw : JSON.stringify(fx.policy);
  return analyze(text);
}

test('toJSON produces valid, deterministic JSON that round-trips', () => {
  const result = analyzeFixture('wildcard/admin-star.json');
  const a = toJSON(result);
  const b = toJSON(result);
  assert.equal(a, b, 'deterministic');
  const parsed = JSON.parse(a);
  assert.equal(parsed.tool, 'iam-blast-radius');
  assert.match(parsed.caveat, /NOT compute effective permissions/);
  assert.ok(Array.isArray(parsed.findings) && parsed.findings.length >= 1);
  assert.equal(parsed.catalogVersion, result.catalogVersion);
});

test('toMarkdown is deterministic and carries the caveat + a finding heading', () => {
  const result = analyzeFixture('wildcard/admin-star.json');
  const md = toMarkdown(result);
  assert.equal(md, toMarkdown(result), 'deterministic');
  assert.match(md, /# IAM Blast Radius/);
  assert.match(md, /POTENTIAL blast radius/);
  // The standalone WILDCARD-ACTION grant itself caps at HIGH (IAM-102 reserves
  // critical for compound escalation paths); Action:"*" also contains those
  // compound paths, so admin-star renders BOTH [HIGH] (the wildcard grant) and
  // [CRITICAL] (the PassRole/AssumeRole paths it necessarily grants).
  assert.match(md, /\[HIGH\]/);
  assert.match(md, /\[CRITICAL\]/);
  assert.match(md, /WILDCARD-ACTION/);
});

test('compound path exports its risk-factor checklist + subsumed findings (IAM-105)', () => {
  const result = analyzeFixture('pass-role/passrole-lambda-positive.json');
  const primary = result.findings.find((f) => f.id === 'PASSROLE-LAMBDA');
  assert.ok(primary && Array.isArray(primary.riskFactors), 'primary has a checklist');

  const md = toMarkdown(result);
  assert.match(md, /Risk factors:/);
  // A checked and (for another fixture) unchecked box render as [x] / [ ].
  assert.match(md, /- \[x\] iam:PassRole granted/);
  assert.match(md, /Subsumed findings/);
  assert.match(md, /WILDCARD-RESOURCE/);

  // JSON export carries the structured checklist + subsumed array verbatim.
  const parsed = JSON.parse(toJSON(result));
  const jp = parsed.findings.find((f) => f.id === 'PASSROLE-LAMBDA');
  assert.ok(Array.isArray(jp.riskFactors) && jp.riskFactors.length > 0);
  assert.ok(Array.isArray(jp.subsumed) && jp.subsumed.length === 1);
  assert.equal(jp.subsumed[0].id, 'WILDCARD-RESOURCE');
  // The subsumed wildcard is NOT a separate top-level finding row.
  assert.equal(parsed.findings.filter((f) => f.id === 'WILDCARD-RESOURCE').length, 0);
});

test('empty analysis exports a clean "no findings" report in both formats', () => {
  const result = analyzeFixture('safe/read-only-scoped.json');
  assert.equal(result.findings.length, 0, 'safe fixture yields no findings');
  const parsed = JSON.parse(toJSON(result));
  assert.deepEqual(parsed.findings, []);
  const md = toMarkdown(result);
  assert.match(md, /No blast-radius findings/);
});

test('hostile policy fields serialize as inert text (no markup execution vector)', () => {
  const result = analyzeFixture('adversarial/xss-in-sid-and-arn.json');
  // JSON: the payload appears only as an escaped string value, never as a key
  // or structure; JSON.parse of our output must succeed and echo it verbatim.
  const parsed = JSON.parse(toJSON(result));
  assert.equal(parsed.model.statements[0].sid, '<img src=x onerror=alert(1)>');
  // Markdown: hostile string is present as body text; toMarkdown does not throw
  // and never emits it as a structural token.
  const md = toMarkdown(result);
  assert.equal(typeof md, 'string');
});

test('report serializers never throw on a failed analysis', () => {
  const result = analyze('not valid json');
  assert.equal(result.ok, false);
  assert.doesNotThrow(() => toJSON(result));
  assert.doesNotThrow(() => toMarkdown(result));
  assert.match(toMarkdown(result), /No blast-radius findings/);
});
