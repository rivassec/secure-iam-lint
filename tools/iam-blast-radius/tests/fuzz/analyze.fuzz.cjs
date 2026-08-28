// ClusterFuzzLite / Jazzer.js coverage-guided fuzz target for the analyze() ==
// scan() SAFETY-PARITY invariant.
//
// This drives the SAME immutable contract the deterministic nightly fuzzer
// (parity-fuzz.mjs) and browser-cli-parity.test.js pin, but with coverage-guided
// mutated input instead of seeded generation:
//
//     scanClean(scan(p))  ||  !analyzeClean(analyze(p))     MUST hold
//
// The forbidden state is the CLI failing closed / non-clean while the browser
// engine reports a clean pass (browser strictly MORE permissive) - a silent
// browser fail-OPEN (threat-model T8). A finding is raised when:
//   - that parity is violated, or
//   - either surface THROWS instead of failing closed gracefully on hostile input.
//
// CommonJS target (the ClusterFuzzLite JS harness loads `module.exports.fuzz`);
// the engine + CLI adapter are pure ESM, loaded once via dynamic import and cached.

const { FuzzedDataProvider } = require('@jazzer.js/core');

// The families analyze()/scan() accept (an out-of-range pick simply exercises the
// require-explicit-family fail-closed path, which is also worth fuzzing).
const FAMILIES = [
  'identity', 'resource', 'role-trust', 'permissions-boundary', 'scp-rcp', 'session',
];

let engine = null;
async function load() {
  if (engine) return engine;
  const [{ analyze }, { scan, EXIT, ANALYSIS_STATUS }, parity] = await Promise.all([
    import('../../../../content/tools/iam-blast-radius/engine/analyze.js'),
    import('../../../../cli/scan.mjs'),
    import('./parity-fuzz.mjs'),
  ]);
  engine = { analyze, scan, EXIT, ANALYSIS_STATUS, isParityViolation: parity.isParityViolation };
  return engine;
}

module.exports.fuzz = async function fuzz(data) {
  const { analyze, scan, isParityViolation } = await load();

  const fdp = new FuzzedDataProvider(data);
  // Spend a few bytes selecting a family + a budget, the rest is the policy text.
  const family = FAMILIES[fdp.consumeIntegralInRange(0, FAMILIES.length - 1)];
  const budgetMs = fdp.consumeIntegralInRange(1, 500);
  const text = fdp.consumeRemainingAsString();

  let ar;
  try {
    ar = analyze(text, { family, requireExplicitFamily: true });
  } catch (e) {
    // analyze() MUST fail closed (return a result), never throw on hostile input.
    throw new Error(`analyze() threw (must fail closed): ${(e && e.message) || e}`);
  }

  let sr;
  try {
    sr = scan({ text, family, budgetMs });
  } catch (e) {
    throw new Error(`scan() threw (must fail closed): ${(e && e.message) || e}`);
  }

  if (isParityViolation(ar, sr)) {
    // Browser engine clean while the CLI fails closed: the exact silent fail-open
    // the contract forbids. Emit a self-contained reproducer.
    throw new Error(
      'SAFETY-PARITY VIOLATION: analyze() clean while scan() non-clean '
      + `(family=${family}) for text=${JSON.stringify(text).slice(0, 400)}`,
    );
  }
};
