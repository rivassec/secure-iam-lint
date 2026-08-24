// Shipped-tree hygiene gate (IAM-1101 adversarial finding, 2026-08-24).
// content/tools/iam-blast-radius/ ships VERBATIM to /tools/iam-blast-radius/ via
// Pelican STATIC_PATHS. A stray scratch/debug/test file dropped there by an agent
// deploys to production. This happened twice (a scratchpad/ dir in Phase 9, a
// scratch-*.mjs in engine/ in Phase 11). This test fails CI when the shipped tree
// contains anything that is not a legitimately-served asset, so a leak can never
// reach a deploy again.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const SHIP = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius');

// Extensions that are legitimately served for this static tool.
const ALLOWED_EXT = new Set(['.html', '.css', '.js', '.json', '.svg', '.png', '.ico', '.webmanifest', '.txt']);
// Name patterns that must never appear in the shipped tree.
const BANNED = [/^scratch/i, /-scratch/i, /debug/i, /\.test\./i, /\.spec\./i, /^tmp/i, /\.mjs$/i, /\.map$/i];

function walk(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}

test('shipped tree contains no scratch/debug/test/tmp/.mjs strays', () => {
  const files = walk(SHIP);
  const strays = files.filter((p) => BANNED.some((re) => re.test(p.split('/').pop())));
  assert.deepEqual(
    strays.map((p) => relative(SHIP, p)),
    [],
    'stray non-shipped files found under content/tools/iam-blast-radius/ (they would deploy to production)',
  );
});

test('every shipped file has a served extension (no orphan artifacts)', () => {
  const files = walk(SHIP);
  const bad = files.filter((p) => {
    const dot = p.lastIndexOf('.');
    const ext = dot === -1 ? '' : p.slice(dot).toLowerCase();
    return !ALLOWED_EXT.has(ext);
  });
  assert.deepEqual(
    bad.map((p) => relative(SHIP, p)),
    [],
    'shipped files with an unexpected extension (only html/css/js/json/svg/png/ico/webmanifest/txt are served)',
  );
});
