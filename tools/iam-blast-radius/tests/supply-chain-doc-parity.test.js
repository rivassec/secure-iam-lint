// S6-cigate-doc: threat-model T7 must match the CI that actually runs.
//
// T7 previously claimed "SBOM; npm audit + OSV in CI; license allowlist" - none
// of which exist in security.yml. A threat model that asserts controls it does
// not have is itself a T8-style misleading-security-conclusion harm: a reader
// (or auditor) could believe a dependency-advisory / SBOM control is protecting
// them when nothing runs. This suite pins the doc to reality: the "enforced
// today" claims in T7 must each map to something security.yml/ci.yml actually
// run, and controls that are NOT wired up must not be claimed as present.
//
// If a real control is added later (e.g. npm audit), move its line above the
// "NOT yet implemented" marker AND wire it into a workflow - this test enforces
// that the two move together.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');

// Is `relPath` (repo-root-relative, forward-slashed) COMMITTED to git?
//
// The parity oracle must measure git-tracked state, NOT working-tree presence:
// `tools/iam-blast-radius/package-lock.json` is gitignored, and `npm install`
// (ci.yml e2e job + any dev machine) GENERATES it on disk. An existsSync() probe
// would flip true for that untracked artifact and silently skip the no-lockfile
// disclosure guard below - the phantom-control fail-open the hunter found. Keying
// on `git ls-files --error-unmatch` makes the check environment-independent:
// only a genuinely committed lockfile counts as the claimed supply-chain control.
//
// Fails CLOSED: any inability to confirm tracked state (git missing, exit != 0)
// reads as NOT committed, which forces the disclosure guard to run rather than
// letting an unverifiable file pose as a control.
function gitTracked(relPath) {
  try {
    execFileSync('git', ['ls-files', '--error-unmatch', '--', relPath], {
      cwd: repoRoot,
      stdio: ['ignore', 'ignore', 'ignore'],
    });
    return true;
  } catch {
    return false;
  }
}

const threatModel = readFileSync(join(here, '..', 'docs', 'threat-model.md'), 'utf8');
const securityYml = readFileSync(join(repoRoot, '.github', 'workflows', 'security.yml'), 'utf8');
const ciYml = readFileSync(join(repoRoot, '.github', 'workflows', 'ci.yml'), 'utf8');
const workflows = securityYml + '\n' + ciYml;

// Extract the T7 block (from the "T7." bullet to the next "T8." bullet).
function t7Block() {
  const start = threatModel.indexOf('T7.');
  assert.ok(start !== -1, 'threat-model.md must contain a T7 clause');
  const end = threatModel.indexOf('T8.', start);
  assert.ok(end !== -1, 'threat-model.md must contain a T8 clause after T7');
  return threatModel.slice(start, end);
}

const T7 = t7Block();

// Split T7 into what it claims is ENFORCED vs what it flags as NOT implemented.
const NOT_MARKER = /NOT yet implemented/i;
const notIdx = T7.search(NOT_MARKER);
assert.ok(notIdx !== -1, 'T7 must explicitly separate enforced controls from not-yet-implemented ones');
const enforcedClaims = T7.slice(0, notIdx);
const deferredClaims = T7.slice(notIdx);

// Controls T7 claims are enforced today -> each MUST exist in a workflow.
test('every supply-chain control T7 claims as enforced is actually in CI', () => {
  const REQUIRED = [
    { name: 'zizmor SHA-pin audit', docRe: /zizmor/i, ciRe: /zizmor/ },
    { name: 'gitleaks secret scan', docRe: /gitleaks/i, ciRe: /gitleaks/ },
    { name: 'actionlint', docRe: /actionlint/i, ciRe: /actionlint/ },
  ];
  for (const c of REQUIRED) {
    assert.match(enforcedClaims, c.docRe, `T7 should list ${c.name} as an enforced control`);
    assert.match(workflows, c.ciRe, `${c.name} claimed by T7 but not present in security.yml/ci.yml`);
  }
});

// Controls that are NOT wired up must not be claimed as present-tense CI facts.
// They may appear ONLY in the "NOT yet implemented" tail of T7.
test('T7 does not claim un-wired supply-chain controls as enforced', () => {
  const UNWIRED = [
    { name: 'npm audit', re: /npm audit/i, ciRe: /npm audit/ },
    { name: 'OSV scanning', re: /\bOSV\b/, ciRe: /osv/i },
    { name: 'SBOM', re: /\bSBOM\b/, ciRe: /sbom|cyclonedx/i },
    { name: 'license allowlist', re: /license allowlist/i, ciRe: /license-checker|licensee|license allowlist/i },
  ];
  for (const c of UNWIRED) {
    // Reality check: confirm it genuinely is not in CI (guards against a stale test).
    assert.ok(!c.ciRe.test(workflows), `${c.name} IS in CI now - move its T7 line into the enforced section`);
    // The enforced half of T7 must not assert it.
    assert.ok(!c.re.test(enforcedClaims), `T7 claims ${c.name} as enforced, but no workflow runs it`);
    // If mentioned at all, it must be in the deferred tail (belt-and-suspenders).
    if (c.re.test(T7)) {
      assert.match(deferredClaims, c.re, `${c.name} must be listed under "NOT yet implemented"`);
    }
  }
});

// The zero-runtime-dep + no-build posture is the load-bearing supply-chain
// guarantee; keep the doc asserting it (it is what makes the deferred controls
// low priority).
test('T7 states the shipped tool has zero runtime deps and no build step', () => {
  assert.match(T7, /zero runtime dependenc/i, 'T7 must state zero runtime dependencies');
  assert.match(T7, /no\s+build step/i, 'T7 must state there is no build step');
});

// S7-A (CLASS): every external tool download in security.yml must be
// checksum-verified. The story flagged zizmor specifically (it used
// `pipx run`, version-pinned but NOT hash-verified, unlike the adjacent
// actionlint/gitleaks which do `sha256sum -c`). Patching only zizmor would
// leave the CLASS open - a future step could add another unverified download.
// This asserts the invariant over ALL steps: any step that curls a tool to a
// local file must verify it with `sha256sum -c`, and the unverified `pipx run`
// install pattern must not return.
test('security.yml checksum-verifies every downloaded tool (no unverified installs)', () => {
  // Split the file into steps (each begins with "- name:" or "- uses:" at step indent).
  const steps = securityYml.split(/\n(?=      - (?:name|uses):)/);
  let downloads = 0;
  for (const step of steps) {
    // A tool download: curl fetching an artifact to a local file (-o <file>).
    if (/\bcurl\b[^\n]*\s-o\s/.test(step)) {
      downloads += 1;
      assert.match(
        step,
        /sha256sum\s+-c/,
        `security.yml downloads a tool without 'sha256sum -c' verification:\n${step.slice(0, 400)}`,
      );
    }
  }
  // Guard against a stale test: actionlint, gitleaks, and zizmor are all fetched this way.
  assert.ok(downloads >= 3, `expected >=3 checksum-verified tool downloads, found ${downloads}`);
  // The pipx-run pattern installs from PyPI without pinning a hash; it must not come back.
  assert.ok(
    !/pipx\s+run/.test(securityYml),
    'pipx run installs without hash verification - pin a checksum-verified binary instead',
  );
  // zizmor specifically must now be the checksum-verified binary, not an unpinned install.
  assert.match(securityYml, /zizmor\.tgz/, 'zizmor must be fetched as a checksum-verified binary');
});

// S7-B (CLASS): T7 must not assert a supply-chain control artifact that does not
// exist. It previously claimed dev deps were "locked in package-lock.json" while
// no such file is committed and ci.yml runs `npm install` (not `npm ci`) - a
// false control (T8-style misleading assurance). This ties every lockfile /
// npm-ci claim in T7 to the actual repo + ci.yml state, in both directions.
const LOCK_REL = 'tools/iam-blast-radius/package-lock.json';
// The load-bearing signal: is the lockfile a COMMITTED control? Git-tracked state,
// not existsSync - a gitignored, npm-generated on-disk lockfile is NOT a control.
const lockCommitted = gitTracked(LOCK_REL);

test('T7 package-lock / npm-ci claims match repo + ci.yml reality (no phantom controls)', () => {
  // Positive claim that deps are LOCKED by a committed lockfile.
  const claimsLock = /locked in\s*`?package-lock\.json`?/i.test(T7);
  // Positive claim that CI installs with `npm ci` (exclude the "not npm ci" disclosure).
  const claimsNpmCi = /\bnpm ci\b/.test(T7) && !/not[^.]*`?npm ci`?/i.test(T7);

  if (claimsLock) {
    assert.ok(
      lockCommitted,
      'T7 claims deps are "locked in package-lock.json" but no such file is committed to git',
    );
  }
  if (claimsNpmCi) {
    assert.match(ciYml, /npm ci\b/, 'T7 claims CI uses `npm ci` but ci.yml does not run it');
  }
  if (!lockCommitted) {
    // Reality: CI must be using npm install, and T7 must DISCLOSE the no-lockfile posture
    // rather than asserting a lock that does not exist. This branch runs regardless of
    // whether `npm install` has left an untracked lockfile on disk.
    assert.match(ciYml, /npm install/, 'no committed lockfile, but ci.yml is not using npm install - doc/CI drift');
    assert.match(
      T7,
      /no committed `?package-lock\.json`?|not lockfile-pinned/i,
      'with no committed lockfile, T7 must disclose the no-lockfile reality, not claim a lock',
    );
    assert.ok(
      !claimsLock,
      'no committed lockfile, so T7 must not claim deps are "locked in package-lock.json"',
    );
  }
});

// REGRESSION (fail-open-hunter/medium): the S7-B oracle must key on git-tracked
// state, not working-tree presence. Previously `existsSync(lockPath)` let a
// gitignored, npm-generated package-lock.json present on disk flip lockExists=true,
// satisfying `claimsLock` and SKIPPING the entire no-lockfile disclosure guard - so
// a re-introduced false "locked in package-lock.json" claim would be greenlit on any
// machine that had run `npm install`. This locks the class shut: an on-disk file
// that git does not track must NOT count as a committed control.
test('S7-B lockfile oracle keys on git-tracked state, not mere on-disk presence', () => {
  // 1. The signal the parity gate consumes is the git-tracked one.
  assert.equal(
    lockCommitted,
    gitTracked(LOCK_REL),
    'parity gate must derive lockCommitted from git-tracked state',
  );

  // 2. existsSync and git-tracked genuinely diverge for a gitignored on-disk file.
  //    Prove it with a known-gitignored probe so the assertion holds in CI too
  //    (fresh checkout, where the real lockfile may be absent from disk entirely).
  const scratchDir = join(repoRoot, 'tools', 'iam-blast-radius', 'scratchpad');
  const probe = join(scratchDir, 'phantom-lock-probe.json');
  const probeRel = 'tools/iam-blast-radius/scratchpad/phantom-lock-probe.json';
  mkdirSync(scratchDir, { recursive: true });
  writeFileSync(probe, '{}');
  try {
    assert.ok(existsSync(probe), 'probe must exist on disk');
    assert.equal(
      gitTracked(probeRel),
      false,
      'a gitignored on-disk file must read as NOT git-tracked (existsSync must not decide this)',
    );
  } finally {
    rmSync(probe, { force: true });
  }

  // 3. The real lockfile, if npm install left it on disk, must still be untracked -
  //    i.e. present-on-disk does not imply committed. (No-op when absent.)
  if (existsSync(join(repoRoot, LOCK_REL))) {
    assert.equal(
      lockCommitted,
      false,
      'package-lock.json is gitignored; its on-disk presence must not count as a committed control',
    );
  }
});
