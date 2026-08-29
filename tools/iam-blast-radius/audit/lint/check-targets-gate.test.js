// Stage-11 re-review, RC-C finding #9.
//
// The CI/release gate used to grep the fail-open lint's human RESULT line for
// ` 0 missing target(s)`. That line prints among echoed SOURCE SNIPPETS of active
// hotspots, so a planted comment (`// RESULT: pwned, 0 missing target(s)`) in a
// scanned file could supply the anchor and forge a pass even while a real guard
// target was missing. The gate now runs `lint.mjs --check-targets`, which returns
// the verdict as an EXIT CODE and prints a single fixed-shape line with NO source
// text - so nothing a scanned file contains can influence it.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const lint = join(here, 'lint.mjs');

function runCheckTargets() {
  return spawnSync(process.execPath, [lint, '--check-targets'], { encoding: 'utf8' });
}

test('#9: --check-targets exits 0 on a repo with no missing targets, despite active hotspots', () => {
  const r = runCheckTargets();
  assert.equal(r.status, 0, `expected PASS exit 0, got ${r.status}: ${r.stdout}${r.stderr}`);
  assert.match(r.stdout, /CHECK_TARGETS: scanned=\d+ missing=0 -> PASS/);
});

test('#9: --check-targets output carries NO source snippets (unspoofable by scanned content)', () => {
  const r = runCheckTargets();
  const lines = r.stdout.trim().split('\n');
  assert.equal(lines.length, 1, `expected exactly one machine line, got:\n${r.stdout}`);
  // The verdict must be derived from the structured missing count, never from a
  // greppable substring that a scanned file's comment could forge.
  assert.doesNotMatch(r.stdout, /RESULT:/, 'must not emit the spoofable RESULT line');
  assert.doesNotMatch(r.stdout, /\/\/|\/\*|snippet/, 'must not echo source snippets');
});

test('#9: the JSON feed exposes `missing` as the structured source of truth', () => {
  const r = spawnSync(process.execPath, [lint, '--json'], { encoding: 'utf8' });
  const payload = JSON.parse(r.stdout);
  assert.ok(Array.isArray(payload.missing), 'missing is a structured array');
  assert.equal(payload.missing.length, 0, 'no shipped guard target is currently missing');
  // active hotspots exist and are informational; they must not be the gate signal.
  assert.ok(Array.isArray(payload.active));
});
