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
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');

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
