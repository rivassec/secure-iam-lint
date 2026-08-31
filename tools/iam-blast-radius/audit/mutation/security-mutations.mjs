#!/usr/bin/env node
// Targeted security-mutation harness.
//
// Generic mutation testing asks "what fraction of all mutations do the tests
// kill?" For a fail-closed security tool the sharper question is: "if someone
// weakens a SPECIFIC fail-closed check, does a test go red?" Each mutation below
// reintroduces a concrete fail-OPEN class that a prior adversarial review found
// and fixed. The harness applies each mutation to the real engine source, runs
// the full suite, and asserts the suite FAILS (the mutant is "killed"). A
// surviving mutant -- suite still green with the check weakened -- is a direct
// fail-closed test-coverage gap and fails this harness.
//
// Direction discipline: every mutation here weakens the engine toward fail-OPEN.
// Most re-open a T8 CLEAN escape (a real capability could read CLEAN); at least one
// is a finding-suppression / precision regression where an independent backstop
// (incomplete-coverage) still fails closed at the CLI -- its note says so. We do not
// include over-report mutations; this harness measures whether our tests defend the
// fail-closed behavior at both the finding and the boundary level.
//
// Usage (from tools/iam-blast-radius/):
//   node audit/mutation/security-mutations.mjs
// Exit 0 iff every mutation is killed by the suite.

import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..', '..', '..'); // repo root
const ENGINE = resolve(REPO, 'content', 'tools', 'iam-blast-radius', 'engine');
const CWD = resolve(REPO, 'tools', 'iam-blast-radius'); // where the suite runs

// Each entry: a precise, single-occurrence source edit that re-opens a fail-open
// class. `find` MUST occur exactly once in `file` or the mutation is stale.
const MUTATIONS = [
  {
    id: 'condition-bypassable-qualifier-suppressed',
    file: 'escalation-conditions.js',
    find: `bypassable ? 'uncertain' : 'deny'`,
    replace: `bypassable ? 'deny' : 'deny'`,
    note: 'Stage-17: IfExists/ForAllValues qualifier bypass no longer surfaces as uncertain; a bypassable allowlist condition suppresses the finding instead of degrading to UNKNOWN.',
  },
  {
    id: 'condition-denylist-nonmatch-suppressed',
    file: 'escalation-conditions.js',
    find: `matchAny ? 'deny' : 'permit'`,
    replace: `matchAny ? 'deny' : 'deny'`,
    note: 'A service NOT named in a deny-condition is now treated as denied, suppressing a pass-role finding AWS would allow.',
  },
  {
    id: 'condition-overfold-casefold-spoof',
    file: 'escalation-conditions.js',
    find: `base === 'stringequalsignorecase' || base === 'stringnotequalsignorecase'`,
    replace: `true`,
    note: 'Stage-14: folding case for ALL operators (not just *IgnoreCase) lets a mixed-case spoofed value match a case-sensitive Deny and suppress the finding.',
  },
  {
    id: 'model-non-ascii-action-spoof-blind',
    file: 'model.js',
    find: `if (NON_ASCII_RE.test(String(v))) return true;`,
    replace: `if (false && NON_ASCII_RE.test(String(v))) return true;`,
    note: 'EFO-1: non-ASCII Action/NotAction tokens (e.g. Kelvin-sign homoglyph) no longer flip the spoof accumulator, so a spoofed action reads CLEAN.',
  },
  {
    id: 'model-despoof-deny-suppression-blind',
    file: 'model.js',
    find: `if (spoof && stripped !== value) spoof.hit = true;`,
    replace: `if (false && spoof && stripped !== value) spoof.hit = true;`,
    note: 'Stage-11 RC-A: de-spoofing a Deny/NotAction/condition-key token no longer records the spoof, so an AWS-inert Deny suppresses a real grant.',
  },
  {
    id: 'families-compute-overwrite-dedup-fail-open',
    file: 'escalation-families.js',
    find: `SEVERITY_RANK[f.severity] < SEVERITY_RANK.high`,
    replace: `SEVERITY_RANK[f.severity] < SEVERITY_RANK.low`,
    note: 'Stage-15: any lower-severity PASSROLE overlap dedups away the high COMPUTE-CODE-OVERWRITE finding, demoting a real escalation pair to CLEAN.',
  },
  {
    id: 'detector-resource-policy-write-blind',
    file: 'rules-detectors.js',
    find: `matchPatterns(stmt, RESOURCE_POLICY_WRITE_ACTIONS, false)`,
    replace: `[]`,
    note: 'EFO-2: the resource-policy-write detector goes blind, so a cross-account Put*Policy grant reads CLEAN.',
  },
  {
    id: 'deny-unbounded-false-certainty',
    file: 'escalation-deny.js',
    find: `return { applies: true, certain: !hasVar };`,
    replace: `return { applies: true, certain: true };`,
    // Precision/defense-in-depth, not a CLEAN escape: a variable-bearing NotAction-Deny is
    // asserted to certainly block, which silently DROPS the capability finding. The T8
    // boundary still holds (scan() exits FAIL_CLOSED via the independent incomplete-coverage
    // backstop), but the finding-level behavior must be pinned. Killed by
    // tests/notaction-deny-variable-failclosed.test.js.
    note: 'A NotAction-Deny with a policy variable is treated as a certain block, silently dropping the capability finding (incomplete-coverage backstop still fails closed at the CLI).',
  },
  {
    id: 'compute-session-takeover-blind',
    file: 'escalation-families.js',
    find: `const matched = grantedPatternsFor(stmt, COMPUTE_SESSION_TAKEOVER_ACTIONS).filter((a) => a !== '*');`,
    replace: `const matched = [];`,
    note: 'The COMPUTE-SESSION-TAKEOVER detector goes blind, so ssm:SendCommand / StartSession / ec2-instance-connect / sagemaker-notebook lose their named finding (incomplete-coverage backstop still fails closed at the CLI).',
  },
  {
    id: 'trust-conditioned-deny-counts-as-unconditional',
    file: 'trust-deny.js',
    find: `if (!d.conditioned && aa.certain) coveredUnconditionally = true;`,
    replace: `if (aa.certain) coveredUnconditionally = true;`,
    note: 'A CONDITIONAL trust-policy Deny is credited as unconditional coverage, so a Deny whose condition may not hold at runtime fully suppresses a TRUST-* finding.',
  },
];

function runSuite() {
  // Returns true if the suite PASSES (exit 0), false if it FAILS.
  try {
    execSync('node --test "tests/**/*.test.js"', {
      cwd: CWD,
      stdio: 'ignore',
      timeout: 180000,
    });
    return true;
  } catch {
    return false;
  }
}

function applyOne(m) {
  const path = resolve(ENGINE, m.file);
  const original = readFileSync(path, 'utf8');
  const count = original.split(m.find).length - 1;
  if (count !== 1) {
    return { ...m, result: 'STALE', detail: `find-string occurs ${count}x (expected exactly 1)` };
  }
  try {
    writeFileSync(path, original.replace(m.find, m.replace), 'utf8');
    const passed = runSuite();
    // Mutation is "killed" when the suite FAILS under it (passed === false).
    return { ...m, result: passed ? 'SURVIVED' : 'KILLED' };
  } finally {
    writeFileSync(path, original, 'utf8'); // always restore
  }
}

console.log(`Security-mutation harness: ${MUTATIONS.length} fail-open mutations\n`);

// Baseline sanity: the unmutated suite must be green, or every result is noise.
process.stdout.write('baseline (unmutated) suite ... ');
if (!runSuite()) {
  console.log('RED');
  console.error('ERROR: baseline suite is failing; fix that before running mutations.');
  process.exit(2);
}
console.log('green\n');

const results = [];
for (const m of MUTATIONS) {
  process.stdout.write(`  ${m.id} ... `);
  const r = applyOne(m);
  results.push(r);
  console.log(r.result === 'KILLED' ? 'killed' : r.result === 'STALE' ? `STALE (${r.detail})` : 'SURVIVED');
}

const survived = results.filter((r) => r.result === 'SURVIVED');
const stale = results.filter((r) => r.result === 'STALE');
const killed = results.filter((r) => r.result === 'KILLED');

console.log(`\nScore: ${killed.length}/${MUTATIONS.length} killed` +
  (stale.length ? `, ${stale.length} STALE` : '') +
  (survived.length ? `, ${survived.length} SURVIVED` : ''));

if (stale.length) {
  console.log('\nSTALE mutations (source moved; update find-string):');
  for (const r of stale) console.log(`  - ${r.id} [${r.file}]: ${r.detail}`);
}
if (survived.length) {
  console.log('\nSURVIVED mutations (fail-closed test GAP -- a real capability can read CLEAN):');
  for (const r of survived) console.log(`  - ${r.id} [${r.file}]\n      ${r.note}`);
}

process.exit(survived.length || stale.length ? 1 : 0);
