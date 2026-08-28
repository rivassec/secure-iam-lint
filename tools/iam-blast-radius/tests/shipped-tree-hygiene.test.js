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
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const SHIP = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius');
const REPO_ROOT = join(here, '..', '..', '..');

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

// ---------------------------------------------------------------------------
// S7-lows-and-orphan item 2: DEV-TREE debris gate.
//
// The gate above guards content/ (the served tree). But agents also drop scratch
// debris at the REPO ROOT and the TOOL ROOT (tools/iam-blast-radius/): loose *.log
// captures, scratchpad*.json dumps, and ad-hoc probe/confirm *.mjs harnesses. These
// never ship to production, but they rot the tree, pose as real modules, and (the
// deleted confirm.mjs/hz.mjs) even imported from an UNRELATED sibling repo by
// absolute path. This test keys on git-TRACKED state (untracked scratch under a
// gitignored scratchpad/ is fine; only committed debris fails) and bans the three
// debris classes anywhere in the guarded zone: the repo-root top level and the tool
// root, EXCLUDING the legitimate dev subtrees (tests/fixtures/ralph/docs/audit),
// which carry their own .mjs/.log/.json by design.
const GUARD_TOOL_PREFIX = 'tools/iam-blast-radius/';
const GUARD_EXCLUDED_SUBTREES = ['tests/', 'fixtures/', 'ralph/', 'docs/', 'audit/'];
// Debris basenames that must never be committed in the guarded zone.
const DEBRIS = [
  { re: /\.log$/i, kind: 'loose *.log capture' },
  { re: /^scratchpad.*\.(json|mjs|js|txt)$/i, kind: 'scratchpad* dump' },
  { re: /\.mjs$/i, kind: 'ad-hoc probe/confirm *.mjs (legit .mjs live under cli/, action/, audit/)' },
];

function trackedFiles() {
  const out = execFileSync('git', ['ls-files', '-z'], { cwd: REPO_ROOT, encoding: 'buffer' });
  return out.toString('utf8').split('\0').filter(Boolean);
}

// Is a repo-root-relative, forward-slashed path in the guarded zone?
function inGuardedZone(rel) {
  // Repo-root TOP LEVEL (no directory separator).
  if (!rel.includes('/')) return true;
  // Tool root, minus the legitimate dev subtrees.
  if (rel.startsWith(GUARD_TOOL_PREFIX)) {
    const remainder = rel.slice(GUARD_TOOL_PREFIX.length);
    return !GUARD_EXCLUDED_SUBTREES.some((d) => remainder.startsWith(d));
  }
  return false;
}

test('no tracked scratch/log/probe debris at the repo root or tool root', () => {
  const strays = [];
  for (const rel of trackedFiles()) {
    if (!inGuardedZone(rel)) continue;
    const base = rel.split('/').pop();
    const hit = DEBRIS.find((d) => d.re.test(base));
    if (hit) strays.push(`${rel}  <- ${hit.kind}`);
  }
  assert.deepEqual(
    strays,
    [],
    'tracked dev-tree debris found (loose *.log, scratchpad* dumps, or ad-hoc *.mjs probes). '
      + 'Put scratch under a gitignored scratchpad/, or delete it; do not commit it.',
  );
});
