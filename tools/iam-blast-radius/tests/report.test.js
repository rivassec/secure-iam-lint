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

test('bare email addresses in policy fields cannot become mailto: autolinks (S5-md-autolink)', () => {
  // S5-md-autolink (threat-model T1/T6): a bare "local@domain.tld" in a policy
  // value - the most realistic vector being an IAM username inside an ARN, e.g.
  // ".../user/alice@evil.example.com" - is turned into an ACTIVE mailto: link by
  // GFM / CommonMark-autolink / pandoc's bare-email autolink pass, giving an
  // attacker a clickable contact/tracking link out of a shared .md report.
  // breakAutolinks() must neutralize it while leaving the address readable.
  const fx = JSON.parse(readFileSync(
    join(fixturesDir, 'adversarial', 'bare-email-autolink.json'), 'utf8'));
  const md = toMarkdown(analyze(JSON.stringify(fx.policy)));

  // The contiguous "local@domain.tld" tokens must be broken so no bare-email
  // autolinker can recognize an address (the break is a backslash inserted
  // before the first domain char, immediately after '@').
  assert.ok(!md.includes('alice@evil.example.com'),
    'ARN-embedded email autolink broken');
  assert.ok(!md.includes('notify-alice@evil.example.com'),
    'Sid email autolink broken');
  assert.ok(!md.includes('carol@www.evil.example.com'),
    'www.-domain ARN email autolink broken');
  assert.ok(!/mailto:/i.test(md), 'no mailto: token emitted');
  // The break must be the "@\\<first domain char>" form: a backslash immediately
  // after '@' (survives inline parsing because it precedes a letter, and the
  // email recognizer then starts its domain scan on an invalid char). It must NOT
  // be an "@" -> "\\@" punctuation escape (cmark-gfm's autolink post-pass consumes
  // that and re-exposes the address, failing open).
  assert.ok(md.includes('alice@\\evil.example.com'),
    'ARN email broken via post-@ domain escape (survives cmark-gfm post-pass)');
  assert.ok(!md.includes('alice\\@'), 'must not use the consumed \\@ punctuation escape');
  // A www.-domain email (in the second Resource ARN) must be broken on BOTH the
  // email and the www. axes, or a residual "www." autolink fires after the mailto
  // break is applied. Confirm the raw address rendered here and is now inert.
  assert.ok(md.includes('carol@\\'), 'www.-domain ARN email reached the export and was mailto-broken');
  assert.ok(!md.includes('www.evil'), 'www.-domain email also breaks the www. autolink');

  // Iteration-2 blocker (GFM/pandoc extended-email domain grammar): the domain
  // char class must include '_' and the '@' trigger must consider a '_'-leading
  // domain, or these two classes ride verbatim into the export and pandoc GFM
  // autolinks them (ground-truth: `pandoc -f gfm -t html`).
  // (1) Underscore in a NON-FINAL label: DOMAIN_CHAR must accept '_' so the
  // forward domain scan reaches the dot (sawDot) and inserts the break.
  assert.ok(!md.includes('carol@x_y.evil.example.com'),
    'underscore-in-non-final-label email autolink broken');
  // (2) Underscore-LEADING domain: the trigger must fire even though the char
  // right after '@' is '_'. The surviving break is a backslash before the first
  // ALNUM domain char, so the leading '_' stays attached to '@' as "@_\\x...".
  // (A backslash before '_' itself would be a consumed punctuation escape that
  // re-exposes the address - fail-open - so it must NOT be used.)
  assert.ok(!md.includes('dave@_x.evil.example.com'),
    'underscore-leading-domain email autolink broken');
  assert.ok(md.includes('dave@_\\x'),
    'underscore-leading domain broken before first ALNUM char (survives cmark-gfm post-pass)');
  assert.ok(!md.includes('dave@\\_'),
    'must not backslash before "_" (a consumed punctuation escape that re-exposes the address)');

  // Iteration-3 blocker (GFM/pandoc autolink a HYPHEN-leading domain): DOMAIN_START
  // excluded '-' on the false premise "a label cannot begin with -". cmark-gfm/
  // pandoc's forward domain scan DOES continue over a leading hyphen, so these
  // hyphen-leading-domain addresses rode verbatim into the export and autolinked
  // (ground-truth: `pandoc -f gfm -t html`). The trigger must fire even though the
  // char right after '@' is '-'; the surviving break is a backslash before the
  // first ALNUM domain char, so the leading '-'/'--' stays attached to '@'.
  // (1) Single hyphen-leading domain.
  assert.ok(!md.includes('erin@-evil.example.com'),
    'hyphen-leading-domain email autolink broken');
  assert.ok(md.includes('erin@-\\evil'),
    'hyphen-leading domain broken before first ALNUM char (survives cmark-gfm post-pass)');
  // (2) Double hyphen-leading domain - the whole leading '--' run stays before the break.
  assert.ok(!md.includes('frank@--evil.example.com'),
    'double-hyphen-leading-domain email autolink broken');
  assert.ok(md.includes('frank@--\\evil'),
    'double-hyphen-leading domain broken before first ALNUM char');
  // (3) Hyphen-leading IPv4-shaped domain (dotted, digit first ALNUM).
  assert.ok(!md.includes('grace@-1.2.3.4'),
    'hyphen-leading IPv4-shaped-domain email autolink broken');
  assert.ok(md.includes('grace@-\\1.2.3.4'),
    'hyphen-leading IPv4-shaped domain broken before first ALNUM char');
  // The break must NOT be a consumed "\\@" or "\\-" punctuation escape (either is
  // consumed by cmark-gfm's autolink post-pass and re-exposes the address).
  assert.ok(!md.includes('erin\\@'), 'must not use the consumed \\@ punctuation escape (hyphen-domain)');
  assert.ok(!md.includes('@\\-'), 'must not backslash before "-" (a consumed punctuation escape)');

  // ...but every address survives as readable, inert text (host + local part).
  assert.ok(md.includes('evil.example.com'), 'domain text preserved');
  assert.ok(md.includes('alice@'), 'local part + @ preserved as text');

  // A legitimate '@' with no valid trailing domain (no dot) is a NON-autolink and
  // must be left untouched - no over-correction into noisy false escapes.
  const noDomain = {
    Version: '2012-10-17',
    Statement: [{ Sid: 'plain@localhost', Effect: 'Allow', Action: '*', Resource: '*' }],
  };
  assert.ok(toMarkdown(analyze(JSON.stringify(noDomain))).includes('plain@localhost'),
    'a bare "@host" with no dotted domain is not an autolink and is not altered');
});

test('bare email autolinks are broken for non-ASCII / homograph domains too (S5 residual class)', () => {
  // GFM/pandoc autolink emails whose domain uses non-ASCII (Unicode) letters; the
  // break must fire on those, not only the ASCII grammar. admin@<cyrillic-e>vil...
  // is visually identical to a real domain (a phishing homograph) and must render
  // inert. Also re-covers the '_'-in-domain and '-'-leading-domain classes.
  for (const email of [
    'carol@x_y.evil.example.com',   // underscore in a non-final label
    'x@-evil.example.com',          // hyphen-leading domain
    'admin@еvil.example.com',  // Cyrillic 'e' (U+0435) homograph
    'x@αlpha.example.com',     // Greek alpha
    'x@ａbc.example.com',       // fullwidth 'a'
  ]) {
    const pol = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*',
      Resource: `arn:aws:iam::111122223333:user/${email}` }] };
    const md = toMarkdown(analyze(JSON.stringify(pol)));
    assert.ok(!md.includes(email), `bare email must render inert, not contiguous: ${email}`);
    assert.ok(!/mailto:/i.test(md), `no mailto: token for ${email}`);
  }
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

// A hostile policy-derived payload carrying EVERY Markdown structure-forging
// vector: an inline link, an image link, a bare URL, a bare email, a "www." host,
// a pipe (would forge a table cell), and an embedded newline (would forge a
// heading/list item). Asserts the value emerged INERT in `md`.
const MD_COVERAGE_PAYLOAD =
  'X [click](https://evil.example/p) ![img](https://evil.example/i) ' +
  'https://evil.example/bare admin@evil.example www.evil.test | forged\n## forged';

function assertMdVectorsInert(md, ctx) {
  // No live inline/image link: the "](" join is backslash-escaped, so the raw
  // "](" that CommonMark/GFM/pandoc need for a link/image never appears.
  assert.ok(!md.includes(']('), `${ctx}: inline/image link join "](" must be escaped`);
  assert.ok(!md.includes('[click]('), `${ctx}: inline link must not survive`);
  // No bare-URL autolink (scheme broken to "h\ttps://").
  assert.ok(!md.includes('https://evil'), `${ctx}: bare URL scheme must be broken`);
  // No "www." autolink (broken to "w\ww.").
  assert.ok(!md.includes('www.evil'), `${ctx}: www. autolink must be broken`);
  // No bare-email mailto autolink (domain broken to "@\evil"); no mailto emitted.
  assert.ok(!md.includes('admin@evil'), `${ctx}: bare email must be broken`);
  assert.ok(!/mailto:/i.test(md), `${ctx}: no mailto: token`);
  // No forged table cell: every pipe is backslash-escaped, so no unescaped "|"
  // survives to split a row.
  assert.ok(!/(^|[^\\])\|/.test(md), `${ctx}: pipe must be escaped (no forged table cell)`);
  // No forged heading: the embedded newline is collapsed to a space by mdSafe, so
  // no line begins with the injected "## forged".
  assert.ok(!md.split('\n').some((l) => l.startsWith('## forged')),
    `${ctx}: embedded newline must not forge a heading`);
}

test('coverage blockingCodes path: hostile Version renders inert in Markdown (S3-md-coverage-escape)', () => {
  // Confirmed reproduction: an unsupported Version carrying every vector fails
  // closed (UNSUPPORTED_POLICY_VERSION), and family.js interpolates the Version
  // VERBATIM into the blocking-code message emitted on the coverage path.
  const fx = JSON.parse(readFileSync(
    join(fixturesDir, 'adversarial', 'md-coverage-escape.json'), 'utf8'));
  const result = analyze(JSON.stringify(fx.policy));
  const md = toMarkdown(result);
  // The coverage path actually fired (blocked + blocking code present).
  assert.match(md, /Coverage: BLOCKED/);
  assert.match(md, /UNSUPPORTED_POLICY_VERSION/);
  assertMdVectorsInert(md, 'blockingCodes message');
  // The Version text still survives as readable, inert content.
  assert.ok(md.includes('evil.example'), 'host text preserved as inert content');
});

test('coverage summary path: hostile unsupportedElement / trustDeny.note render inert (S3-md-coverage-escape class)', () => {
  // Close the CLASS: any future analyze() path that places attacker text in a
  // coverage-summary field must already emerge inert. Drive the renderer directly
  // with a synthetic analysis whose summary carries the hostile payload in
  // unsupportedElements[].{element,path}, trustDeny.note, missingLayers[].label,
  // unrecognizedActions/unsupportedConditions, and the family header lines.
  const analysis = {
    ok: true,
    catalogVersion: MD_COVERAGE_PAYLOAD,
    family: MD_COVERAGE_PAYLOAD,
    findings: [],
    counts: { findings: 0, edges: 0, nodes: 0 },
    coverage: {
      detected: MD_COVERAGE_PAYLOAD,
      override: MD_COVERAGE_PAYLOAD,
      supported: true,
      blocked: false,
      blockingCodes: [],
      summary: {
        incomplete: true,
        codes: [MD_COVERAGE_PAYLOAD],
        statements: { accepted: 1, rejected: 0, total: 1 },
        unrecognizedActions: [MD_COVERAGE_PAYLOAD],
        unsupportedConditions: [MD_COVERAGE_PAYLOAD],
        unsupportedElements: [{ element: MD_COVERAGE_PAYLOAD, path: MD_COVERAGE_PAYLOAD }],
        missingLayers: [{ key: 'x', label: MD_COVERAGE_PAYLOAD }],
        trustDeny: { present: true, note: MD_COVERAGE_PAYLOAD },
        graph: { truncated: false },
        versions: { buildSha: 'dev', ruleVersion: '1', catalogVersion: '1' },
      },
    },
  };
  const md = toMarkdown(analysis);
  assertMdVectorsInert(md, 'coverage summary fields');
});

test('coverage blockingCodes path: hostile code/path/message all render inert (synthetic)', () => {
  // The blocking-code loop emits code, path, AND message; all three must be
  // escaped, not only the confirmed message field.
  const analysis = {
    ok: true,
    findings: [],
    counts: { findings: 0, edges: 0, nodes: 0 },
    coverage: {
      detected: 'identity',
      supported: false,
      blocked: true,
      blockingCodes: [{
        code: MD_COVERAGE_PAYLOAD,
        path: MD_COVERAGE_PAYLOAD,
        message: MD_COVERAGE_PAYLOAD,
      }],
      summary: {
        incomplete: true,
        codes: [],
        statements: { accepted: 0, rejected: 1, total: 1 },
        unrecognizedActions: [],
        unsupportedConditions: [],
        unsupportedElements: [],
        missingLayers: [],
        trustDeny: { present: false, note: null },
        graph: { truncated: false },
        versions: { buildSha: 'dev', ruleVersion: '1', catalogVersion: '1' },
      },
    },
  };
  const md = toMarkdown(analysis);
  assert.match(md, /Coverage: BLOCKED/);
  assertMdVectorsInert(md, 'blockingCodes code/path/message');
});

// --- S3-md-coverage-escape iteration-2: Trojan-Source invisible/reordering spoof ---
//
// The structure-forging Markdown class (links/tables/headings) is closed above.
// This block closes the sibling spelling the fail-open hunter measured as a ship
// blocker: INVISIBLE / REORDERING format-control code points (bidi, zero-width,
// BOM, default-ignorable, Braille blank) rode through mdEscape/mdSafe AND
// JSON.stringify VERBATIM into the exported .md/.json - a Trojan-Source visual
// spoof (threat-model T8). The fix strips the class (matched by Unicode PROPERTY,
// not a hand-enumerated range) in mdSafe() and in a deep key+value pass in
// toJSON(). These tests assert EXACT codepoint removal (not merely visual
// inertness) on the coverage path, the finding path, the JSON object-KEY path
// (a hostile Condition operator becomes a model object key), and the synthetic
// coverage-summary fields - and assert legitimate RTL letters are preserved so
// the strip introduces no false positive / over-strip.

// Every invisible/reordering code point a report value could carry, including
// spellings ONLY a property-based matcher catches (astral tag U+E0061, CGJ
// U+034F, variation selector U+FE0F, the reserved-but-default-ignorable U+2065,
// Hangul filler U+115F, Khmer inherent vowel U+17B4, Mongolian vowel sep U+180E).
const INVISIBLE_SET = [
  0x202a, 0x202b, 0x202c, 0x202d, 0x202e, // bidi embeddings/override
  0x2066, 0x2067, 0x2068, 0x2069, // bidi isolates
  0x200b, 0x200c, 0x200d, 0x200e, 0x200f, // zero-width + LRM/RLM
  0x061c, // Arabic letter mark
  0x2060, 0x2064, 0x2065, // word joiner / invisible-plus / reserved
  0xfeff, // BOM / ZWNBSP
  0x00ad, // soft hyphen
  0x2800, // Braille pattern blank
  0x034f, // combining grapheme joiner
  0x115f, 0x17b4, 0x180e, // Hangul filler / Khmer / Mongolian vowel sep
  0xfe0f, // variation selector-16
  0xe0061, 0xe0000, // astral tag block
];
const INVISIBLE_PAYLOAD = INVISIBLE_SET.map((c) => String.fromCodePoint(c)).join('');
// A property scan (non-global so lastIndex statefulness cannot skip a match).
const FORMAT_CONTROL_RE = /[\p{Cf}\p{Default_Ignorable_Code_Point}⠀]/u;

function assertNoFormatControls(text, ctx) {
  const residual = [...text]
    .filter((ch) => FORMAT_CONTROL_RE.test(ch))
    .map((ch) => `U+${ch.codePointAt(0).toString(16)}`);
  assert.deepEqual(residual, [], `${ctx}: exported report must carry NO invisible/reordering code points, found: ${residual.join(' ')}`);
}

test('coverage path: Trojan-Source bidi/zero-width Version is stripped from MD + JSON (S3 iter-2)', () => {
  const fx = JSON.parse(readFileSync(
    join(fixturesDir, 'adversarial', 'md-coverage-bidi-spoof.json'), 'utf8'));
  const result = analyze(JSON.stringify(fx.policy));
  // Sanity: the invisible payload really does ride onto the coverage path.
  const md = toMarkdown(result);
  const js = toJSON(result);
  assert.match(md, /Coverage: BLOCKED/);
  assert.match(md, /UNSUPPORTED_POLICY_VERSION/);
  assertNoFormatControls(md, 'coverage/blockingCodes Markdown');
  assertNoFormatControls(js, 'coverage/blockingCodes JSON');
  // Readable inert text still survives (only width-less controls are removed).
  assert.ok(md.includes('evil.example'), 'readable host text preserved as inert content');
});

test('finding path: Trojan-Source bidi/zero-width Sid is stripped from MD + JSON (S3 iter-2)', () => {
  // Action:"*" produces findings, so the hostile Sid rides the FINDING path
  // (mdEscape(f.statementSid) + model in JSON) - disjoint from the coverage path.
  const pol = {
    Version: '2012-10-17',
    Statement: [{ Sid: `admin${INVISIBLE_PAYLOAD}root`, Effect: 'Allow', Action: '*', Resource: '*' }],
  };
  const result = analyze(JSON.stringify(pol));
  assert.ok(result.findings.length > 0, 'finding path actually fired');
  assertNoFormatControls(toMarkdown(result), 'finding-path Markdown');
  assertNoFormatControls(toJSON(result), 'finding-path JSON');
  // The Sid text stays legible once the invisibles are gone.
  assert.ok(toMarkdown(result).includes('adminroot'), 'Sid readable text preserved');
});

test('JSON object-KEY path: hostile Condition operator key is stripped in toJSON (S3 iter-2)', () => {
  // A Condition operator/key is carried through model.js copyGuarded as an OBJECT
  // KEY, and the model rides in the JSON export. A value-only sanitizer would leave
  // this spelling of the class OPEN, so toJSON deep-sanitizes keys too.
  const pol = {
    Version: '2012-10-17',
    Statement: [{
      Sid: 's', Effect: 'Allow', Action: '*', Resource: '*',
      Condition: { [`StringEquals${INVISIBLE_PAYLOAD}`]: { 'aws:username': 'x' } },
    }],
  };
  const js = toJSON(analyze(JSON.stringify(pol)));
  assertNoFormatControls(js, 'JSON with hostile Condition operator key');
  assert.ok(js.includes('StringEquals'), 'operator key readable text preserved');
});

test('coverage-summary fields: Trojan-Source payload stripped in Markdown (S3 iter-2 class)', () => {
  // Drive the renderer directly so every coverage-summary field carries the
  // invisible payload (unsupportedElements[].{element,path}, trustDeny.note,
  // missingLayers[].label, unrecognized/unsupported lists, header lines).
  const P = `X${INVISIBLE_PAYLOAD}Y`;
  const analysis = {
    ok: true, catalogVersion: P, family: P, findings: [],
    counts: { findings: 0, edges: 0, nodes: 0 },
    coverage: {
      detected: P, override: P, supported: true, blocked: false, blockingCodes: [],
      summary: {
        incomplete: true, codes: [P],
        statements: { accepted: 1, rejected: 0, total: 1 },
        unrecognizedActions: [P], unsupportedConditions: [P],
        unsupportedElements: [{ element: P, path: P }],
        missingLayers: [{ key: 'x', label: P }],
        trustDeny: { present: true, note: P },
        graph: { truncated: false },
        versions: { buildSha: 'dev', ruleVersion: '1', catalogVersion: '1' },
      },
    },
  };
  assertNoFormatControls(toMarkdown(analysis), 'coverage-summary Markdown');
  assertNoFormatControls(toJSON(analysis), 'coverage-summary JSON');
});

test('S4 iteration 3: strong-RTL letters are charset-clamped at the display sink (Trojan-Source, not preserved)', () => {
  // REVISED per the S4-unicode-spoof re-audit (BLOCKER 1). An earlier contract preserved
  // RTL letters verbatim on the premise that IAM tokens are alphanumeric. That premise IS
  // the vulnerability: a strong-RTL letter is the OTHER Trojan-Source mechanism
  // (CVE-2021-42574) - it makes the Unicode bidi algorithm REORDER the neutral / numeric
  // characters around it, so a downloaded .md can DISPLAY a grant in a different order than
  // it is stored, with NO format-control code point at all. IAM tokens are ASCII per the AWS
  // grammar, so the display sinks clamp every non-ASCII code point to U+FFFD. The RAW value
  // still rides the model + analysis unchanged (fail-closed viability + S2 fingerprints
  // intact); only the human-facing projection is charset-clamped.
  const rtl = 'alephאעתbet arabicبہ';
  const pol = {
    Version: '2012-10-17',
    Statement: [{ Sid: rtl, Effect: 'Allow', Action: '*', Resource: '*' }],
  };
  const md = toMarkdown(analyze(JSON.stringify(pol)));
  assert.ok(!md.includes(rtl), 'strong-RTL letters must NOT survive verbatim (they reorder the display)');
  for (const ch of 'אעתبہ') {
    assert.ok(!md.includes(ch), `strong-RTL letter U+${ch.codePointAt(0).toString(16)} must not survive into the .md`);
  }
  // The ASCII halves stay legible as inert text (only the non-ASCII is clamped).
  assert.match(md, /aleph/);
  assert.match(md, /bet/);
  assert.match(md, /arabic/);
});

test('report serializers never throw on a failed analysis', () => {
  const result = analyze('not valid json');
  assert.equal(result.ok, false);
  assert.doesNotThrow(() => toJSON(result));
  assert.doesNotThrow(() => toMarkdown(result));
  assert.match(toMarkdown(result), /No blast-radius findings/);
});
