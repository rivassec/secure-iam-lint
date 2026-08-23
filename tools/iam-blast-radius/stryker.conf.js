// IAM-604: Stryker mutation-testing config for the deterministic engine.
//
// Mutation testing seeds small faults ("mutants") into the source and checks the
// test suite kills them. A surviving mutant is a coverage gap - a fixture or
// assertion that would let a real regression through - NOT a broken tool. It is
// SLOW, so it runs NIGHTLY (see .github/workflows/iam-blast-radius-mutation.yml)
// and is intentionally NOT part of the PR-blocking CI (iam-blast-radius-ci.yml).
//
// Scope: the pure decision logic where a silent mutation is most dangerous -
// evaluator (Allow/Deny/NotAction/NotResource semantics), rules, escalation, and
// correlate (subsumption). Graph rendering / DOM / IO are out of scope.
//
// The command test runner reuses the EXACT `node --test` command the gating
// suite uses, so the mutation run measures the same corpus that gates the tool.
// Run locally with `npm run mutation` from tools/iam-blast-radius.
//
// ESM config (package.json is "type":"module"): Stryker auto-discovers
// stryker.conf.{js,mjs,cjs,json}; this default export is that config.

/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  packageManager: 'npm',

  // The command runner shells out to the real test command per mutant. No
  // test-framework plugin is needed, which keeps the dev dependency to a single
  // package (@stryker-mutator/core) and matches the no-build ethos.
  testRunner: 'command',
  commandRunner: {
    command: 'node --test "tests/**/*.test.js"',
  },

  // Only the deterministic decision engine. Paths are relative to this config
  // (the dev harness root); the shipped code lives two levels up under content/.
  mutate: [
    '../../content/tools/iam-blast-radius/engine/evaluator.js',
    '../../content/tools/iam-blast-radius/engine/rules.js',
    '../../content/tools/iam-blast-radius/engine/escalation.js',
    '../../content/tools/iam-blast-radius/engine/correlate.js',
  ],

  // Target: >=90% mutation score (story IAM-604). `break` fails the nightly run
  // when the score drops below 90 so the signal is visible; this never blocks a
  // PR because the workflow only runs on schedule / manual dispatch.
  thresholds: {
    high: 95,
    low: 90,
    break: 90,
  },

  // The full suite runs per mutant; give it headroom over the ~0.5s baseline.
  timeoutMS: 120000,
  timeoutFactor: 2,
  concurrency: 2,

  // Shipped code is plain JS with JSDoc; strip type-checks in the sandbox so a
  // mutant cannot fail for a spurious type reason instead of a killed test.
  disableTypeChecks: true,

  reporters: ['clear-text', 'progress', 'html'],
  htmlReporter: { fileName: 'reports/mutation/index.html' },
};
