#!/usr/bin/env node
// Zero-dep typecheck RATCHET (gates on error IDENTITY, not just count).
//
// Runs `tsc --checkJs` over the shipped engine and FAILS if any NEW type error appears
// relative to the committed baseline (audit/typecheck-baseline.json). The baseline is a
// per-(file, TS-code) signature -> count map of the pre-existing JSDoc friction (incomplete
// @typedef blocks; Object.freeze() -> Readonly<T> assignability). NONE are bugs: the full
// suite is green. This blocks a real typo / undefined access / arity mistake WITHOUT
// burning the frozen-for-release baseline down first.
//
// WHY identity, not count (review finding B6): a count-only gate is defeated by a PR that
// FIXES one pre-existing error and INTRODUCES a new unrelated one - the total is unchanged,
// so it passes while permanently baking in the swap. Keying on (file, code) signatures
// catches the new error (different file or code, or a higher count for that pair) even when
// the total is flat.
//
// Rule: if you FIX errors, regenerate the baseline (node audit/typecheck-ratchet.mjs
// --update) to lock the win in; a change that adds a NEW signature/instance fails until the
// new error is fixed (not the baseline).
//
// tsc is fetched via npx at a PINNED version (dev-time only; the shipped package stays
// zero-dependency). --skipLibCheck drops @types/node lib noise so only OUR code is measured.
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const TS_VERSION = '5.7.3';
const here = dirname(fileURLToPath(import.meta.url));
const engineDir = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius', 'engine');
const baselinePath = join(here, 'typecheck-baseline.json');

const files = readdirSync(engineDir).filter((f) => f.endsWith('.js')).map((f) => join(engineDir, f));

const args = [
  '--yes', '-p', `typescript@${TS_VERSION}`, 'tsc',
  '--checkJs', '--noEmit', '--allowJs', '--skipLibCheck',
  '--target', 'es2022', '--module', 'es2022',
  ...files,
];
const r = spawnSync('npx', args, { encoding: 'utf8' });
const out = `${r.stdout || ''}${r.stderr || ''}`;

// Build the current (file|TScode) -> count signature map. Line/col are stripped so an
// unrelated edit that shifts line numbers does not read as a new error.
const current = {};
for (const m of out.matchAll(/([^\s(]+\.js)\((\d+),\d+\): error (TS[0-9]+)/g)) {
  const sig = `${m[1].split('/').pop()}|${m[3]}`;
  current[sig] = (current[sig] || 0) + 1;
}
const total = Object.values(current).reduce((a, b) => a + b, 0);

// --update regenerates the baseline (use after FIXING errors, never to hide a new one).
if (process.argv.includes('--update')) {
  const sorted = Object.fromEntries(Object.entries(current).sort());
  writeFileSync(baselinePath, `${JSON.stringify(sorted, null, 2)}\n`);
  console.log(`typecheck baseline updated: ${total} error(s), ${Object.keys(current).length} signatures.`);
  process.exit(0);
}

const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
const baseTotal = Object.values(baseline).reduce((a, b) => a + b, 0);
console.log(`typecheck ratchet: ${total} error(s) / ${Object.keys(current).length} signatures (baseline ${baseTotal} / ${Object.keys(baseline).length}).`);

// NEW = a signature not in the baseline, or more instances than the baseline allows.
const introduced = [];
for (const [sig, n] of Object.entries(current)) {
  const allowed = baseline[sig] || 0;
  if (n > allowed) introduced.push(`${sig}: ${n} (baseline ${allowed}) +${n - allowed}`);
}
if (introduced.length) {
  console.error(`::error::typecheck introduced NEW type error(s) not in the baseline:`);
  for (const line of introduced) console.error(`  ${line}`);
  console.error('Fix the new error; do NOT run --update to mask it. Full tsc output:');
  console.error(out);
  process.exit(1);
}

// Report signatures the baseline expects that are now gone (fixed) -> prune with --update.
const fixed = Object.keys(baseline).filter((sig) => (current[sig] || 0) < baseline[sig]);
if (fixed.length) {
  console.log(`Baseline IMPROVED (${fixed.length} signature(s) reduced/cleared): run --update to lock it in.`);
}
process.exit(0);
