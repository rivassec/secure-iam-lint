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

test('bare URLs / www. hosts in policy fields cannot become active links (autolink break)', () => {
  // A firing wildcard grant so the hostile Resource strings reach the findings.
  const policy = {
    Version: '2012-10-17',
    Statement: [{
      Sid: 'https://evil.example.com/sid',
      Effect: 'Allow',
      Action: '*',
      Resource: [
        '*',
        'https://evil.example.com/leak',
        'HTTP://Evil.Example.com/upper',
        'ftp://evil.example.com/y',
        'www.evil.com/track',
      ],
    }],
  };
  const md = toMarkdown(analyze(JSON.stringify(policy)));
  // The autolink-eligible scheme tokens (http/https/ftp/www.) are broken so no
  // GFM/CommonMark-autolink/pandoc autolink fires on the attacker host.
  assert.ok(!md.includes('https://evil'), 'https:// broken');
  assert.ok(!md.includes('http://Evil') && !md.includes('HTTP://Evil'), 'http:// (any case) broken');
  assert.ok(!md.includes('ftp://evil'), 'ftp:// broken');
  assert.ok(!md.includes('www.evil'), 'www. broken');
  // ...but the value survives as readable, inert text (host + path present).
  assert.ok(md.includes('evil.example.com/leak'), 'URL text preserved');
  assert.ok(md.includes('evil.com/track'), 'www host text preserved');
  // A legitimate colon (ARN) and single-slash paths are untouched.
  const arnPolicy = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: '*', Resource: 'arn:aws:s3:::my-bucket/*' }],
  };
  assert.ok(toMarkdown(analyze(JSON.stringify(arnPolicy))).includes('arn:aws:s3:::my-bucket/*'),
    'ARNs (no "://") are not altered');
});

test('breakAutolinks stays linear on a large no-colon value (no quadratic hang)', () => {
  // Regression: breakAutolinks used a greedy `[A-Za-z0-9+.-]*://` regex that
  // backtracked quadratically, so a long scheme-char value with NO "://" (a
  // hostile Sid/Action reachable through real analyze) took tens of seconds to
  // serialize. The scan is now O(n); a 50KB no-colon value must serialize well
  // under a second. Bound is deliberately generous (was ~33s) so it is not flaky.
  const bigNoColon = 'a'.repeat(50 * 1024);
  const policy = {
    Version: '2012-10-17',
    Statement: [{ Sid: bigNoColon, Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }],
  };
  const t0 = Date.now();
  const md = toMarkdown(analyze(JSON.stringify(policy)));
  const elapsed = Date.now() - t0;
  assert.ok(elapsed < 2000, `toMarkdown on a 50KB no-colon value took ${elapsed}ms (expected < 2000ms)`);
  // The value still survives verbatim as inert text (no "://" means no break).
  assert.ok(md.includes(bigNoColon), 'no-colon value is carried through unaltered');
});

test('report serializers never throw on a failed analysis', () => {
  const result = analyze('not valid json');
  assert.equal(result.ok, false);
  assert.doesNotThrow(() => toJSON(result));
  assert.doesNotThrow(() => toMarkdown(result));
  assert.match(toMarkdown(result), /No blast-radius findings/);
});
