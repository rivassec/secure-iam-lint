// IAM-604: version-coherence self-test.
//
// The tool ships as loose files with no build step (architecture invariant 2)
// behind a per-deploy Cloudflare cache purge, so nothing at build time ties the
// several version identifiers together. They MUST agree, because reporting
// findings from an engine whose modules disagree about their own version is a
// threat-model T8 harm (mislabeled certainty). engine/version.js is the single
// canonical manifest; this suite asserts every shipped identifier matches it,
// that the comparator detects a crafted drift, and that the UI's block path
// (checkVersionCoherence -> not ok) is reachable.
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  VERSION_MANIFEST,
  IDENTIFIER_SPECS,
  diffVersions,
  checkVersionCoherence,
} from '../../../content/tools/iam-blast-radius/engine/version.js';
import { CATALOG_VERSION, analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { RULE_VERSION, BUILD_SHA } from '../../../content/tools/iam-blast-radius/engine/coverage.js';
import { ACTION_CATALOG_VERSION } from '../../../content/tools/iam-blast-radius/engine/catalog.js';

const here = dirname(fileURLToPath(import.meta.url));
const shippedDir = join(here, '..', '..', '..', 'content', 'tools', 'iam-blast-radius');
const fixturesDir = join(here, '..', 'fixtures');

// --- The manifest itself -----------------------------------------------------

test('version manifest is frozen and declares the expected fields', () => {
  assert.ok(Object.isFrozen(VERSION_MANIFEST), 'manifest must be frozen');
  assert.equal(typeof VERSION_MANIFEST.ruleVersion, 'string');
  assert.equal(typeof VERSION_MANIFEST.actionCatalogVersion, 'string');
  assert.equal(typeof VERSION_MANIFEST.buildSha, 'string');
  // The action-catalog snapshot is a dated tag (YYYY.MM.DD).
  assert.match(VERSION_MANIFEST.actionCatalogVersion, /^\d{4}\.\d{2}\.\d{2}$/);
});

// --- Live coherence (the shipped modules agree with the manifest) ------------

test('every shipped identifier matches the manifest', () => {
  assert.equal(CATALOG_VERSION, VERSION_MANIFEST.ruleVersion, 'analyze.CATALOG_VERSION');
  assert.equal(RULE_VERSION, VERSION_MANIFEST.ruleVersion, 'coverage.RULE_VERSION');
  assert.equal(
    ACTION_CATALOG_VERSION,
    VERSION_MANIFEST.actionCatalogVersion,
    'catalog.ACTION_CATALOG_VERSION',
  );
  assert.equal(BUILD_SHA, VERSION_MANIFEST.buildSha, 'coverage.BUILD_SHA');
});

test('checkVersionCoherence() reports ok with no mismatches on the shipped set', () => {
  const result = checkVersionCoherence();
  assert.equal(result.ok, true, JSON.stringify(result.mismatches));
  assert.deepEqual(result.mismatches, []);
  assert.ok(Object.isFrozen(result), 'result is frozen');
  assert.ok(Object.isFrozen(result.mismatches), 'mismatches list is frozen');
  // Every declared identifier spec is covered by the gathered live values.
  for (const spec of IDENTIFIER_SPECS) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(result.actual, spec.id),
      `live value gathered for ${spec.id}`,
    );
  }
});

// --- Drift detection (the gate is not vacuous) -------------------------------

test('diffVersions detects a drifted identifier', () => {
  const actual = {
    'analyze.CATALOG_VERSION': VERSION_MANIFEST.ruleVersion,
    'coverage.RULE_VERSION': '999', // drift
    'catalog.ACTION_CATALOG_VERSION': VERSION_MANIFEST.actionCatalogVersion,
    'coverage.BUILD_SHA': VERSION_MANIFEST.buildSha,
  };
  const mismatches = diffVersions(actual);
  assert.equal(mismatches.length, 1);
  assert.equal(mismatches[0].id, 'coverage.RULE_VERSION');
  assert.equal(mismatches[0].expected, VERSION_MANIFEST.ruleVersion);
  assert.equal(mismatches[0].actual, '999');
});

test('diffVersions flags a missing identifier (undefined) as a mismatch', () => {
  const mismatches = diffVersions({}); // nothing supplied
  assert.equal(mismatches.length, IDENTIFIER_SPECS.length);
  for (const m of mismatches) {
    assert.equal(m.actual, undefined);
  }
});

test('checkVersionCoherence(alteredManifest) reaches the not-ok block path', () => {
  // Simulate a torn deploy by comparing the live modules against a manifest that
  // expects a different rule version - the exact condition app.js blocks on.
  const altered = Object.freeze({
    ...VERSION_MANIFEST,
    ruleVersion: `${VERSION_MANIFEST.ruleVersion}-DRIFT`,
  });
  const result = checkVersionCoherence(altered);
  assert.equal(result.ok, false);
  const ids = result.mismatches.map((m) => m.id).sort();
  // Both rule-version-bound identifiers must show up as mismatched.
  assert.deepEqual(ids, ['analyze.CATALOG_VERSION', 'coverage.RULE_VERSION']);
});

// --- Finding-level coherence (every finding carries the manifest ruleVersion) -

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

function loadCorpus() {
  const all = [];
  const categories = readdirSync(fixturesDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
  for (const category of categories) {
    const dir = join(fixturesDir, category);
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir).filter((n) => n.endsWith('.json')).sort()) {
      const data = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      all.push({ file: `${category}/${f}`, text: fixtureText(data) });
    }
  }
  return all;
}

test('every finding across the corpus carries the manifest ruleVersion', () => {
  const corpus = loadCorpus();
  assert.ok(corpus.length > 0, 'corpus must not be empty');
  let seenFindings = 0;
  for (const { file, text } of corpus) {
    const result = analyze(text);
    for (const finding of result.findings || []) {
      seenFindings += 1;
      assert.equal(
        finding.ruleVersion,
        VERSION_MANIFEST.ruleVersion,
        `${file}: finding ${finding.id} ruleVersion must equal the manifest`,
      );
      // Subsumed sub-findings (IAM-105/201) are still shipped evidence and must
      // carry the same version.
      for (const sub of finding.subsumed || []) {
        if (Object.prototype.hasOwnProperty.call(sub, 'ruleVersion')) {
          assert.equal(sub.ruleVersion, VERSION_MANIFEST.ruleVersion,
            `${file}: subsumed ${sub.id} ruleVersion must equal the manifest`);
        }
      }
    }
  }
  assert.ok(seenFindings > 0, 'the corpus must exercise at least one finding');
});

// --- Worker fallback derives from the engine (no drift-prone literal) ---------

test('worker.js derives its fallback catalogVersion from CATALOG_VERSION', () => {
  const src = readFileSync(join(shippedDir, 'worker.js'), 'utf8');
  assert.match(src, /import\s*\{[^}]*CATALOG_VERSION[^}]*\}\s*from\s*'\.\/engine\/analyze\.js'/,
    'worker.js must import CATALOG_VERSION from the engine');
  assert.match(src, /catalogVersion:\s*CATALOG_VERSION/,
    'worker.js fallback must use CATALOG_VERSION, not a literal');
  // No competing hardcoded catalogVersion string literal may remain.
  assert.doesNotMatch(src, /catalogVersion:\s*['"][^'"]+['"]/,
    'worker.js must not hardcode a catalogVersion literal');
});
