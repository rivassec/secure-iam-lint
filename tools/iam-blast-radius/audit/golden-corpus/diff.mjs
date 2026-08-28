// SECONDARY snapshot DIFF (the change-detector's assertion side).
//
// Re-derives every corpus case's normalized snapshot (via capture.mjs) and compares it
// to the stored ./baselines/<id>.json. Exits NON-ZERO on any drift or missing/extra
// baseline so an UNINTENDED behaviour change is caught in CI. A drift is not inherently
// bad - it may be a deliberate fix - but it must be reviewed and then blessed with
// `node capture.mjs --update`. This proves STABILITY only, never safety (see README).
//
// Usage:
//   node diff.mjs        # exit 0 if every snapshot matches its baseline, else 1
//
// Also runnable under `node --test` as diff.test.js re-exports the check.

import { readFileSync, existsSync, readdirSync, realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { CASES } from './manifest.mjs';
import { snapshotFor, baselinePath, BASELINES_DIR } from './capture.mjs';

// Compare two JSON-able values; return a short path to the FIRST difference, or null.
export function firstDiff(a, b, path = '') {
  if (a === b) return null;
  const ta = a === null ? 'null' : Array.isArray(a) ? 'array' : typeof a;
  const tb = b === null ? 'null' : Array.isArray(b) ? 'array' : typeof b;
  if (ta !== tb) return `${path || '(root)'}: type ${ta} != ${tb}`;
  if (ta === 'array') {
    if (a.length !== b.length) return `${path}[]: length ${a.length} != ${b.length}`;
    for (let i = 0; i < a.length; i++) {
      const d = firstDiff(a[i], b[i], `${path}[${i}]`);
      if (d) return d;
    }
    return null;
  }
  if (ta === 'object') {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    if (ka.join(',') !== kb.join(',')) return `${path || '(root)'}: keys {${ka}} != {${kb}}`;
    for (const k of ka) {
      const d = firstDiff(a[k], b[k], path ? `${path}.${k}` : k);
      if (d) return d;
    }
    return null;
  }
  return `${path || '(root)'}: ${JSON.stringify(a)} != ${JSON.stringify(b)}`;
}

// Run the full comparison. Returns { ok, drifts:[{id,reason}], missing:[id], extra:[file] }.
export function runDiff() {
  const drifts = [];
  const missing = [];
  const liveFiles = new Set(CASES.map((c) => `${c.id}.json`));

  const extra = existsSync(BASELINES_DIR)
    ? readdirSync(BASELINES_DIR).filter((f) => f.endsWith('.json') && !liveFiles.has(f))
    : [];

  for (const c of CASES) {
    const bp = baselinePath(c.id);
    if (!existsSync(bp)) { missing.push(c.id); continue; }
    const baseline = JSON.parse(readFileSync(bp, 'utf8'));
    const current = snapshotFor(c);
    const reason = firstDiff(baseline, current);
    if (reason) drifts.push({ id: c.id, reason });
  }

  return { ok: drifts.length === 0 && missing.length === 0 && extra.length === 0, drifts, missing, extra };
}

function main() {
  if (!existsSync(BASELINES_DIR) || readdirSync(BASELINES_DIR).filter((f) => f.endsWith('.json')).length === 0) {
    process.stderr.write('diff: no baselines found. Run `node capture.mjs --update` to create them.\n');
    process.exitCode = 1;
    return;
  }
  const { ok, drifts, missing, extra } = runDiff();
  if (ok) {
    process.stdout.write(`diff: OK - all ${CASES.length} snapshots match their baselines.\n`);
    return;
  }
  for (const m of missing) process.stderr.write(`diff: MISSING baseline for '${m}' (run capture.mjs --update)\n`);
  for (const e of extra) process.stderr.write(`diff: EXTRA baseline '${e}' with no corpus case (run capture.mjs --update)\n`);
  for (const d of drifts) process.stderr.write(`diff: DRIFT in '${d.id}': ${d.reason}\n`);
  process.stderr.write('diff: snapshot drift detected. Review, then bless with `node capture.mjs --update` if intended.\n');
  process.exitCode = 1;
}

const invokedDirectly = (() => {
  try {
    const entry = process.argv[1];
    if (!entry) return false;
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch { return false; }
})();

if (invokedDirectly) main();
