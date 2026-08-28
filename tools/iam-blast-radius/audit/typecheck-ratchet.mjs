#!/usr/bin/env node
// Zero-dep typecheck RATCHET.
//
// Runs `tsc --checkJs` over the shipped engine and FAILS only if the type-error count
// EXCEEDS the committed BASELINE. The baseline is pre-existing JSDoc friction - incomplete
// @typedef blocks (props the code legitimately sets, e.g. duplicateSids/resourceContext,
// that the typedef omits) and Object.freeze() -> Readonly<T> assignability against mutable
// @returns. NONE are bugs: the full test suite is green. This gate blocks any NEW type
// error a change introduces (a real typo / undefined access / arity mistake shows up as a
// count increase) WITHOUT requiring the frozen-for-release baseline to be burned down first.
//
// Rule: the baseline may only go DOWN. If you fix errors, lower BASELINE to lock the win in;
// if a change raises the count, this fails until you fix the new error (not the baseline).
//
// tsc is fetched via npx at a PINNED version (dev-time only; the shipped package stays
// zero-dependency). --skipLibCheck drops @types/node lib noise so only OUR code is measured.
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const BASELINE = 58;
const TS_VERSION = '5.7.3';

const here = dirname(fileURLToPath(import.meta.url));
const engineDir = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius', 'engine');
const files = readdirSync(engineDir).filter((f) => f.endsWith('.js')).map((f) => join(engineDir, f));

const args = [
  '--yes', '-p', `typescript@${TS_VERSION}`, 'tsc',
  '--checkJs', '--noEmit', '--allowJs', '--skipLibCheck',
  '--target', 'es2022', '--module', 'es2022',
  ...files,
];
const r = spawnSync('npx', args, { encoding: 'utf8' });
const out = `${r.stdout || ''}${r.stderr || ''}`;
const count = (out.match(/error TS[0-9]+/g) || []).length;

console.log(`typecheck ratchet: ${count} error(s) (baseline ${BASELINE}, ${files.length} files)`);

if (count > BASELINE) {
  // Surface which files regressed to make the new error easy to find.
  const offending = [...out.matchAll(/([^\s(]+\.js)\(\d+,\d+\): error TS/g)].map((m) => m[1]);
  const uniq = [...new Set(offending)].map((p) => p.split('/').pop());
  console.error(`::error::typecheck introduced ${count - BASELINE} NEW type error(s) over the baseline of ${BASELINE}.`);
  console.error(`Files with errors: ${uniq.join(', ')}`);
  console.error('Fix the new error (do NOT raise the baseline). Full output above.');
  console.error(out);
  process.exit(1);
}
if (count < BASELINE) {
  console.log(`Baseline IMPROVED by ${BASELINE - count}: lower the BASELINE constant in this file to ${count} to lock it in.`);
}
process.exit(0);
