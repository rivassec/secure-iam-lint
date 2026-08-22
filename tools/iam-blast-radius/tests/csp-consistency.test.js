// IAM-508: CSP single source of truth (HTTP header authoritative).
//
// The Cloudflare HTTP response header is the authoritative CSP. The <meta>
// tag in index.html is a documented, weaker fallback. To keep the two from
// silently diverging, the exact authoritative header value is mirrored in
// three places:
//
//   1. docs/DEPLOY.md          - the value Oliver pastes into Cloudflare
//   2. index.html comment      - AUTHORITATIVE-CSP-HEADER: <value>
//   3. index.html <meta>       - the live fallback (header MINUS frame-ancestors)
//
// This suite is the drift guard: it fails if any of the three disagree, if the
// meta ever adds/drops a directive other than frame-ancestors, or if the meta
// tries to carry frame-ancestors (which a meta tag cannot enforce).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const indexHtmlPath = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius', 'index.html');
const deployMdPath = join(here, '..', 'docs', 'DEPLOY.md');

const html = readFileSync(indexHtmlPath, 'utf8');
const deploy = readFileSync(deployMdPath, 'utf8');

// A CSP string -> a Set of normalized directives ("name value1 value2"),
// order-independent, whitespace-collapsed, empty segments dropped.
function directives(csp) {
  return new Set(
    csp
      .split(';')
      .map((d) => d.trim().replace(/\s+/g, ' '))
      .filter(Boolean),
  );
}

function setEquals(a, b) {
  return a.size === b.size && [...a].every((x) => b.has(x));
}

// --- Extract the three copies ---------------------------------------------

const metaMatch = html.match(
  /http-equiv="Content-Security-Policy"\s+content="([^"]*)"/i,
);
const commentMatch = html.match(/AUTHORITATIVE-CSP-HEADER:\s*([^\n]+?)\s*$/m);
const deployMatch = deploy.match(/^Content-Security-Policy:\s*(.+)$/m);

test('all three CSP copies are present and extractable', () => {
  assert.ok(metaMatch, 'index.html <meta http-equiv=Content-Security-Policy> not found');
  assert.ok(commentMatch, 'index.html AUTHORITATIVE-CSP-HEADER comment line not found');
  assert.ok(deployMatch, 'DEPLOY.md authoritative "Content-Security-Policy:" line not found');
});

test('the comment mirror equals the DEPLOY.md authoritative header exactly', () => {
  const commentHeader = directives(commentMatch[1]);
  const deployHeader = directives(deployMatch[1]);
  assert.ok(
    setEquals(commentHeader, deployHeader),
    `index.html AUTHORITATIVE-CSP-HEADER and DEPLOY.md header diverged.\n` +
      `  comment: [${[...commentHeader].sort().join(' | ')}]\n` +
      `  deploy : [${[...deployHeader].sort().join(' | ')}]`,
  );
});

test('the authoritative header includes frame-ancestors (header-only directive)', () => {
  const deployHeader = directives(deployMatch[1]);
  assert.ok(
    deployHeader.has("frame-ancestors 'none'"),
    "authoritative header must carry frame-ancestors 'none'",
  );
});

test('the <meta> fallback equals the authoritative header MINUS frame-ancestors', () => {
  const meta = directives(metaMatch[1]);
  const header = directives(deployMatch[1]);

  // meta must not try to carry frame-ancestors (a meta tag cannot enforce it).
  assert.ok(
    ![...meta].some((d) => d.startsWith('frame-ancestors')),
    'meta CSP must not include frame-ancestors (unenforceable in a meta tag)',
  );

  // header minus frame-ancestors === meta, exactly. No other directive may be
  // added or dropped on either side.
  const expected = new Set([...header].filter((d) => !d.startsWith('frame-ancestors')));
  assert.ok(
    setEquals(meta, expected),
    `meta CSP is not the authoritative header minus frame-ancestors.\n` +
      `  meta    : [${[...meta].sort().join(' | ')}]\n` +
      `  expected: [${[...expected].sort().join(' | ')}]`,
  );
});
