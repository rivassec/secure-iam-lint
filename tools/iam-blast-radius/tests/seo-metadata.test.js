// SEO / indexing drift guard. LAUNCHED 2026-08-22: the page is now indexable
// (robots index,follow) and its canonical URL is injected into sitemap.xml by
// the deploy workflow (Pelican does not emit a sitemap entry for a static tool,
// and none is hand-added to the tool dir). This suite fails if the metadata is
// missing/inaccurate, a wording rule is broken (precise wording, no keywords,
// no absolute claims, structured data must match visible content), or if the
// page regresses out of the index (robots flipped back to noindex).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const shippedDir = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius');
const indexHtmlPath = join(shippedDir, 'index.html');
const html = readFileSync(indexHtmlPath, 'utf8');

const CANONICAL = 'https://rivassec.com/tools/iam-blast-radius/';

// --- small HTML helpers ----------------------------------------------------

function metaContent(html, attr, value) {
  // Order-independent: find a <meta ...> tag carrying `attr="value"` and return
  // its content="...". attr is name|property.
  const tagRe = /<meta\b[^>]*>/gi;
  for (const m of html.match(tagRe) || []) {
    const a = m.match(new RegExp(`\\b${attr}="([^"]*)"`, 'i'));
    if (a && a[1].toLowerCase() === value.toLowerCase()) {
      const c = m.match(/\bcontent="([^"]*)"/i);
      return c ? c[1] : null;
    }
  }
  return null;
}

function collapse(s) {
  return s.replace(/\s+/g, ' ').trim();
}

// Visible body text: everything after <body>, comments and tags stripped.
const bodyText = (() => {
  const bodyStart = html.indexOf('<body');
  let body = bodyStart === -1 ? html : html.slice(bodyStart);
  body = body.replace(/<!--[\s\S]*?-->/g, ' '); // drop comments
  body = body.replace(/<script[\s\S]*?<\/script>/gi, ' '); // drop ld+json etc.
  body = body.replace(/<[^>]+>/g, ' '); // drop tags
  return collapse(body);
})();

// --- gate: launched (indexable), no hand-added sitemap file ----------------

test('the page is indexable: robots is index,follow and noindex is gone', () => {
  assert.match(
    html,
    /<meta\s+name="robots"\s+content="index,\s*follow"\s*\/?>/i,
    'robots must be index,follow now that indexing is launched',
  );
  assert.doesNotMatch(
    html,
    /content="noindex"/i,
    'the noindex meta must be removed after the launch flip',
  );
});

test('the launch comment records the remaining Search Console step', () => {
  // The staged TODO(Oliver) comment is replaced by a launch note; the one
  // remaining human step (Search Console submission) must stay documented.
  // (Target the launch comment specifically - it is not the first HTML comment.)
  const launch = (html.match(/<!--[\s\S]*?-->/g) || []).find((c) => /search console/i.test(c));
  assert.ok(launch, 'launch comment (mentioning Search Console) not found');
  const c = launch.toLowerCase();
  assert.ok(c.includes('index'), 'launch comment must note the page is indexable');
});

test('no sitemap file was hand-added under the shipped tool dir', () => {
  assert.ok(
    !existsSync(join(shippedDir, 'sitemap.xml')),
    'a sitemap.xml must not be added to the tool dir (Pelican does not emit one for it either)',
  );
});

// --- canonical -------------------------------------------------------------

test('self-referential canonical is present and correct', () => {
  const m = html.match(/<link\s+rel="canonical"\s+href="([^"]+)"\s*\/?>/i);
  assert.ok(m, 'canonical link not found');
  assert.equal(m[1], CANONICAL, 'canonical must be the self URL of this tool');
});

// --- description + OG + Twitter --------------------------------------------

test('meta description is present, accurate, and uses "potential blast radius"', () => {
  const desc = metaContent(html, 'name', 'description');
  assert.ok(desc && desc.length >= 50, 'meta description missing or too short');
  assert.match(desc, /potential blast radius/i, 'description must use "potential blast radius"');
});

test('Open Graph tags are present', () => {
  assert.equal(metaContent(html, 'property', 'og:type'), 'website');
  assert.equal(metaContent(html, 'property', 'og:url'), CANONICAL);
  assert.ok(metaContent(html, 'property', 'og:title'), 'og:title missing');
  assert.ok(metaContent(html, 'property', 'og:description'), 'og:description missing');
  assert.ok(metaContent(html, 'property', 'og:image'), 'og:image missing');
});

test('Twitter Card tags are present and use name="twitter:*"', () => {
  assert.equal(metaContent(html, 'name', 'twitter:card'), 'summary_large_image');
  assert.ok(metaContent(html, 'name', 'twitter:title'), 'twitter:title missing');
  assert.ok(metaContent(html, 'name', 'twitter:description'), 'twitter:description missing');
  assert.ok(metaContent(html, 'name', 'twitter:image'), 'twitter:image missing');
});

test('OG/Twitter image references an existing self-hosted asset', () => {
  const img = metaContent(html, 'property', 'og:image');
  assert.match(img, /^https:\/\/rivassec\.com\//, 'og:image must be an absolute site URL');
  const relPath = img.replace('https://rivassec.com/', '');
  const onDisk = join(here, '..', '..', '..', 'content', relPath);
  assert.ok(existsSync(onDisk), `og:image asset not found on disk: content/${relPath}`);
});

// --- JSON-LD ---------------------------------------------------------------

const jsonLd = (() => {
  const m = html.match(/<script\s+type="application\/ld\+json">([\s\S]*?)<\/script>/i);
  return m ? { raw: m[1], data: JSON.parse(m[1]) } : null;
})();

test('SoftwareApplication JSON-LD is present, valid, and truthful', () => {
  assert.ok(jsonLd, 'application/ld+json block not found');
  const d = jsonLd.data;
  assert.equal(d['@type'], 'SoftwareApplication');
  assert.equal(d['@context'], 'https://schema.org');
  assert.equal(d.name, 'IAM Blast Radius');
  assert.equal(d.url, CANONICAL, 'JSON-LD url must match the canonical');
  assert.ok(typeof d.description === 'string' && d.description.length >= 50, 'JSON-LD description missing');
  // free tool: price 0 is truthful
  assert.equal(d.offers.price, '0');
});

test('every JSON-LD claim string is visible on the page (structured data matches content)', () => {
  // The description is the load-bearing claim; it must appear verbatim in the
  // visible docs so structured data never asserts something the page does not.
  assert.ok(
    bodyText.includes(collapse(jsonLd.data.description)),
    'JSON-LD description must also be visible in the page body (docs section)',
  );
});

// --- wording rules (SEO critic) -------------------------------------------

// The self-description surfaces the crawler and card renderers read. These must
// never claim the tool is a "policy simulator" or computes "effective
// permissions". (The visible body may reference AWS's own Policy Simulator by
// name in the comparison prose - that is a different product, not a self-claim.)
function selfDescriptionStrings(html) {
  return [
    (html.match(/<title>([^<]*)<\/title>/i) || [])[1] || '',
    metaContent(html, 'name', 'description') || '',
    metaContent(html, 'property', 'og:title') || '',
    metaContent(html, 'property', 'og:description') || '',
    metaContent(html, 'name', 'twitter:title') || '',
    metaContent(html, 'name', 'twitter:description') || '',
    jsonLd ? jsonLd.data.name : '',
    jsonLd ? jsonLd.data.description : '',
  ];
}

test('self-description never claims "policy simulator" or "effective permissions"', () => {
  for (const s of selfDescriptionStrings(html)) {
    assert.ok(!/policy simulator/i.test(s), `banned self-claim "policy simulator" in: ${s}`);
    assert.ok(!/effective permissions/i.test(s), `banned self-claim "effective permissions" in: ${s}`);
  }
});

test('no meta keywords anywhere', () => {
  assert.ok(
    !/<meta\s+name="keywords"/i.test(html),
    'meta keywords must not be added (SEO critic: no keywords)',
  );
});

test('no absolute privacy/proof claims anywhere in the page', () => {
  const banned = [/100% private/i, /mathematically prove/i, /zero exfiltration/i, /completely private/i];
  for (const re of banned) {
    assert.ok(!re.test(html), `absolute claim ${re} must not appear`);
  }
});

test('page does not promise rich results', () => {
  assert.ok(!/rich results?/i.test(html), 'must not promise rich results');
});

// --- docs section crawlable + covers required topics -----------------------

test('the crawlable docs section covers every required topic', () => {
  const docsStart = bodyText.indexOf('About this tool');
  assert.ok(docsStart !== -1, 'docs section ("About this tool") not found in visible body');
  const docs = bodyText.slice(docsStart).toLowerCase();
  for (const topic of [
    'supported policy families',
    'coverage behavior',
    'limitations',
    'privacy boundary',
    'examples',
    'rule catalog',
    'access analyzer',
    'policy simulator',
  ]) {
    assert.ok(docs.includes(topic.toLowerCase()), `docs section must cover: ${topic}`);
  }
});
