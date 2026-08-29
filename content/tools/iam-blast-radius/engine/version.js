// IAM Blast Radius - version manifest + coherence self-test (IAM-604).
//
// This tool has NO build step (architecture invariant 2): whatever is committed
// is what ships, so nothing stamps a coherent set of version identifiers across
// the shipped modules at build time. Several identifiers already exist and MUST
// agree with one another for a report to be trustworthy:
//
//   - the rule/finding catalog version reported at the top of every result
//     (analyze.js CATALOG_VERSION) and carried on every rule/escalation finding
//     as `ruleVersion`,
//   - the rule version shown in the coverage panel + every export
//     (coverage.js RULE_VERSION),
//   - the dated action-catalog snapshot (catalog.js ACTION_CATALOG_VERSION),
//   - the committed deploy marker (coverage.js BUILD_SHA).
//
// Because the tool ships as loose files behind a per-deploy Cloudflare cache
// purge (no bundler ties them together), a partial / torn deploy could leave the
// shipped modules disagreeing - e.g. a new engine/analyze.js next to a stale
// engine/coverage.js. Reporting security findings against an internally
// inconsistent engine is a threat-model T8 harm (overstated / mislabeled
// certainty), so this module is the SINGLE canonical declaration of the expected
// identifiers, plus a checkVersionCoherence() self-test that re-verifies the live
// values still match. app.js runs the check at startup and FAILS CLOSED - it
// blocks analysis on any mismatch rather than analyze against a torn deploy.
//
// Pure + dependency-free: no DOM, no network, no eval/Function. Deterministic:
// same modules -> same result, every run. This module imports the shipped
// constants (which do NOT import it back), so there is no import cycle.

import { CATALOG_VERSION } from './analyze.js';
import { RULE_VERSION, BUILD_SHA } from './coverage.js';
import { ACTION_CATALOG_VERSION } from './catalog.js';

// The canonical, expected version set. When any shipped identifier is
// intentionally bumped, update it here AND at its declaration site; the
// self-test (and the node unit test) fail until the two agree, which is the
// whole point - drift cannot ship silently.
export const VERSION_MANIFEST = Object.freeze({
  // Release semver of the whole tool (CLI, SARIF, GitHub Action). The single
  // canonical release version; the root package.json `version` MUST equal this
  // (enforced by the version-coherence node test). Distinct from the internal
  // rule/action catalog versions below - bump on any user-facing release.
  releaseVersion: '1.0.0',
  // Rule/finding catalog version. analyze.js CATALOG_VERSION, coverage.js
  // RULE_VERSION, worker.js's fallback catalogVersion, and every rule/escalation
  // finding's `ruleVersion` all equal this.
  ruleVersion: '1',
  // Dated curated action-catalog snapshot (catalog.js ACTION_CATALOG_VERSION),
  // versioned on its own cadence, distinct from the rule version.
  actionCatalogVersion: '2026.08.22',
  // Committed deploy marker. Stage-11 #10: DERIVE from the single source
  // (coverage.js BUILD_SHA, imported above) instead of a second 'dev' literal.
  // The release stamps coverage.js BUILD_SHA; a separate literal here would ship a
  // TORN buildSha (stamped manifest, 'dev' in the coverage/SARIF output that reads
  // BUILD_SHA). One source -> the stamp propagates and the two can never diverge.
  buildSha: BUILD_SHA,
});

// Each shipped identifier and the manifest field it must equal. The `id` strings
// name the exact declaration site so a mismatch message points a maintainer
// straight at the file to fix.
export const IDENTIFIER_SPECS = Object.freeze([
  Object.freeze({ id: 'analyze.CATALOG_VERSION', manifestKey: 'ruleVersion' }),
  Object.freeze({ id: 'coverage.RULE_VERSION', manifestKey: 'ruleVersion' }),
  Object.freeze({ id: 'catalog.ACTION_CATALOG_VERSION', manifestKey: 'actionCatalogVersion' }),
  Object.freeze({ id: 'coverage.BUILD_SHA', manifestKey: 'buildSha' }),
]);

/**
 * Pure comparator: given a map of live identifier values keyed by their `id`
 * (see IDENTIFIER_SPECS) and a manifest, return the frozen list of mismatches
 * (each { id, expected, actual }). Empty list means fully coherent. Split out
 * from checkVersionCoherence() so it is unit-testable with a crafted mismatch
 * without having to mutate a shipped constant.
 *
 * @param {Object<string,string>} actual
 * @param {{ruleVersion:string, actionCatalogVersion:string, buildSha:string}} [manifest]
 * @returns {ReadonlyArray<{id:string, expected:string, actual:string}>}
 */
export function diffVersions(actual, manifest = VERSION_MANIFEST) {
  const values = actual || {};
  const mismatches = [];
  for (const spec of IDENTIFIER_SPECS) {
    const expected = manifest[spec.manifestKey];
    const got = Object.prototype.hasOwnProperty.call(values, spec.id)
      ? values[spec.id]
      : undefined;
    if (got !== expected) {
      mismatches.push(Object.freeze({ id: spec.id, expected, actual: got }));
    }
  }
  return Object.freeze(mismatches);
}

/**
 * Gather the live shipped identifiers and compare them to the manifest.
 *
 * @param {{ruleVersion:string, actionCatalogVersion:string, buildSha:string}} [manifest]
 * @returns {{ok:boolean, mismatches:ReadonlyArray<{id:string,expected:string,actual:string}>, actual:Object<string,string>}}
 */
export function checkVersionCoherence(manifest = VERSION_MANIFEST) {
  const actual = Object.freeze({
    'analyze.CATALOG_VERSION': CATALOG_VERSION,
    'coverage.RULE_VERSION': RULE_VERSION,
    'catalog.ACTION_CATALOG_VERSION': ACTION_CATALOG_VERSION,
    'coverage.BUILD_SHA': BUILD_SHA,
  });
  const mismatches = diffVersions(actual, manifest);
  return Object.freeze({ ok: mismatches.length === 0, mismatches, actual });
}
