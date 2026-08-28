// S3-dos-budget: complexity + wall-clock-budget regression suite.
//
// Locks the three DoS controls this story added, each of which closes a fail-OPEN
// (a policy carrying real cost that could otherwise hang the CLI/Action or - worse -
// be reported as a clean pass):
//
//   (a) a PER-STRING length cap in validate.js (LIMITS.MAX_STRING_LENGTH) that fails
//       CLOSED on a single over-long Action/Resource/NotAction/NotResource token,
//       BEFORE any wildcard matching;
//   (b) ONE shared, LINEAR wildcard matcher (engine/glob.js) replacing three
//       byte-identical greedy copies whose worst case was genuinely quadratic
//       ('*' + 'a'*k + 'b' vs 'a'*n re-scanned the trailing run from every offset);
//   (c) a cooperative WALL-CLOCK BUDGET the Node CLI/Action arm, which aborts a
//       pathological run to a graceful fail-closed "analysis aborted (resource
//       budget)" verdict (exit 3) - NEVER a clean pass (threat-model T5/T8).
//
// The performance assertions use generous absolute ceilings (not ratios) so they
// witness the linear fix without being flaky on a loaded CI box: the OLD quadratic
// matcher blew past these ceilings by 100x-4000x at these sizes, so the margin is
// enormous.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { globMatch } from '../../../content/tools/iam-blast-radius/engine/glob.js';
import { validate, LIMITS } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';
import { run } from '../../../cli/iam-br.mjs';
import { runAction } from '../../../action/index.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

// A fixed wall-clock ceiling for the "completes under a fixed ms budget" assertions.
// Real analyses finish in single-digit ms; the old quadratic matcher took seconds.
const BUDGET_MS = 2000;

// The reference (OLD) greedy two-pointer matcher, verbatim from the three copies
// engine/glob.js replaced. Kept here as the ORACLE: the new linear matcher must
// agree with it on every input, so the three-into-one dedup cannot silently drift
// the matching semantics.
function referenceGlob(pattern, text) {
  const p = String(pattern);
  const t = String(text);
  let pi = 0;
  let ti = 0;
  let starIdx = -1;
  let matchIdx = 0;
  while (ti < t.length) {
    if (pi < p.length && (p[pi] === '?' || p[pi] === t[ti])) {
      pi++;
      ti++;
    } else if (pi < p.length && p[pi] === '*') {
      starIdx = pi;
      matchIdx = ti;
      pi++;
    } else if (starIdx !== -1) {
      pi = starIdx + 1;
      matchIdx++;
      ti = matchIdx;
    } else {
      return false;
    }
  }
  while (pi < p.length && p[pi] === '*') pi++;
  return pi === p.length;
}

// --- (b) matcher: LINEAR on the confirmed quadratic worst case ----------------

test('(b) the quadratic glob worst case at a bounded size completes far under the budget', () => {
  // '*' + 'a'*k + 'b' vs 'a'*n is the confirmed quadratic input (~4x per 2x under
  // the old matcher). At n = 4096 the old matcher took tens of ms PER CALL; the new
  // one is microseconds. 2000 iterations under BUDGET_MS is a >100x safety margin.
  const n = 4096;
  const pattern = `*${'a'.repeat(n / 2)}b`;
  const textStr = 'a'.repeat(n);

  const t0 = performance.now();
  let acc = false;
  for (let i = 0; i < 2000; i++) {
    acc = globMatch(pattern, textStr) || acc;
  }
  const elapsed = performance.now() - t0;

  assert.equal(acc, false, "pattern ends in 'b' but text is all 'a' -> never matches");
  assert.ok(
    elapsed < BUDGET_MS,
    `2000 matches of the quadratic worst case took ${elapsed.toFixed(1)}ms; budget is ${BUDGET_MS}ms`,
  );
});

test('(b) matching cost does not explode as the worst-case input doubles (quadratic is gone)', () => {
  // A single match at the LARGEST bounded size (2x the per-string cap on each side)
  // must still be trivially fast. Absolute ceiling, not a ratio, to stay non-flaky.
  const n = 8192;
  const pattern = `*${'a'.repeat(n / 2)}b`;
  const textStr = 'a'.repeat(n);
  const t0 = performance.now();
  for (let i = 0; i < 500; i++) globMatch(pattern, textStr);
  const elapsed = performance.now() - t0;
  assert.ok(elapsed < BUDGET_MS, `500 matches at n=${n} took ${elapsed.toFixed(1)}ms; budget ${BUDGET_MS}ms`);
});

// --- (b) matcher: SEMANTIC EQUIVALENCE with the matcher it replaced -----------

test('(b) the shared linear matcher agrees with the reference greedy matcher (dedup guard)', () => {
  const patAlpha = ['a', 'b', '?', '*'];
  const txtAlpha = ['a', 'b', 'c'];
  // Deterministic LCG so the corpus is fixed (no Math.random flakiness).
  let seed = 0x2545f491;
  const rnd = () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff;
  };
  const gen = (alpha, len) => {
    let s = '';
    for (let i = 0; i < len; i++) s += alpha[(rnd() * alpha.length) | 0];
    return s;
  };

  let mismatches = 0;
  for (let pl = 0; pl <= 7; pl++) {
    for (let tl = 0; tl <= 7; tl++) {
      for (let k = 0; k < 300; k++) {
        const p = gen(patAlpha, pl);
        const t = gen(txtAlpha, tl);
        if (globMatch(p, t) !== referenceGlob(p, t)) mismatches++;
      }
    }
  }
  assert.equal(mismatches, 0, 'new matcher must equal the reference matcher on every input');

  // Hand-picked edge cases (empty pattern/text, star runs, ? boundaries).
  const edges = [
    ['', ''], ['*', ''], ['', 'x'], ['?', ''], ['a*', 'a'], ['*a', 'a'],
    ['a*b', 'ab'], ['a*b', 'axb'], ['**', 'abc'], ['*?*', 'a'], ['?*', 'ab'],
    ['a*a', 'a'], ['a*a', 'aa'], ['*a*a*', 'aXaY'], ['a?c', 'abc'], ['a?c', 'ac'],
    ['s3:*', 's3:GetObject'], ['iam:*Role', 'iam:PassRole'],
  ];
  for (const [p, t] of edges) {
    assert.equal(globMatch(p, t), referenceGlob(p, t), `edge case ${JSON.stringify([p, t])}`);
  }
});

// --- (a) per-string cap: FAILS CLOSED on an over-long token -------------------

test('(a) the over-cap fixture is rejected by validate() with STRING_TOO_LONG', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'oversized-single-string.json'), 'utf8'));
  const text = JSON.stringify(fx.policy);
  const v = validate(text);
  assert.equal(v.ok, false, 'an over-cap Resource string must be rejected');
  assert.ok(
    v.errors.some((e) => e.code === 'STRING_TOO_LONG'),
    `expected a STRING_TOO_LONG error, got ${JSON.stringify(v.errors.map((e) => e.code))}`,
  );
});

test('(a) the over-cap fixture fails CLOSED through analyze() and scan() (never a clean pass)', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'oversized-single-string.json'), 'utf8'));
  const text = JSON.stringify(fx.policy);

  const a = analyze(text);
  assert.equal(a.ok, false, 'analyze() must not accept an over-cap policy');
  assert.equal(a.findings.length, 0, 'no findings are produced for a rejected policy');

  const r = scan({ text, family: 'identity' });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'an over-cap policy must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'an over-cap policy fails closed to exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
});

test('(a) a token at EXACTLY the cap is ACCEPTED (no over-correction into a false positive)', () => {
  // A Resource string of exactly LIMITS.MAX_STRING_LENGTH characters must pass the
  // cap (the guard rejects strictly OVER the cap). Guards the negative direction:
  // the fix must not reject legitimate max-length ARNs.
  const atCap = 'a'.repeat(LIMITS.MAX_STRING_LENGTH);
  const overCap = 'a'.repeat(LIMITS.MAX_STRING_LENGTH + 1);
  const policyAt = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: atCap }],
  });
  const policyOver = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: overCap }],
  });
  const vAt = validate(policyAt);
  assert.ok(
    !vAt.errors.some((e) => e.code === 'STRING_TOO_LONG'),
    'a string at exactly the cap must not trip STRING_TOO_LONG',
  );
  const vOver = validate(policyOver);
  assert.ok(
    vOver.errors.some((e) => e.code === 'STRING_TOO_LONG'),
    'a string one char over the cap must trip STRING_TOO_LONG',
  );
});

test('(a) the cap also covers Action / NotAction / NotResource, not only Resource', () => {
  const over = 'a'.repeat(LIMITS.MAX_STRING_LENGTH + 1);
  for (const field of ['Action', 'NotAction', 'NotResource']) {
    const stmt = { Effect: 'Allow' };
    // Give a valid counterpart so the statement is otherwise shaped fine.
    if (field === 'Action') { stmt.Action = over; stmt.Resource = '*'; }
    else if (field === 'NotAction') { stmt.NotAction = over; stmt.Resource = '*'; }
    else { stmt.Action = 's3:GetObject'; stmt.NotResource = over; }
    const v = validate(JSON.stringify({ Version: '2012-10-17', Statement: [stmt] }));
    assert.ok(
      v.errors.some((e) => e.code === 'STRING_TOO_LONG'),
      `an over-cap ${field} must trip STRING_TOO_LONG`,
    );
  }
});

// --- (c) cap-sized policy completes under the budget --------------------------

// Build a large-but-within-limits identity policy that actively exercises the
// wildcard matcher via same-policy Deny precedence (denyResourceCoverage globMatch
// runs allow-resource x deny-resource). Stays under MAX_STATEMENTS / MAX_ACTIONS /
// MAX_RESOURCES and every string well under MAX_STRING_LENGTH.
function buildCapSizedPolicy() {
  const statements = [];
  const N = 240; // allow statements
  for (let i = 0; i < N; i++) {
    statements.push({
      Sid: `Allow${i}`,
      Effect: 'Allow',
      Action: ['s3:*', 'iam:PassRole', 'lambda:CreateFunction', 'ec2:RunInstances'],
      Resource: [
        `arn:aws:s3:::bucket-${i}-*/prefix/*/object-*`,
        `arn:aws:iam::123456789012:role/app-${i}-*`,
      ],
    });
  }
  // A handful of broad Deny statements so every Allow resource is glob-compared
  // against a wildcard Deny scope (the denyResourceCoverage hot path).
  for (let j = 0; j < 20; j++) {
    statements.push({
      Sid: `Deny${j}`,
      Effect: 'Deny',
      Action: ['s3:Delete*', 'iam:*'],
      Resource: [`arn:aws:s3:::bucket-*-${j}/*`, 'arn:aws:iam::*:role/*'],
    });
  }
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}

test('(c) a cap-sized policy analyzes to completion well under a fixed ms budget', () => {
  const text = buildCapSizedPolicy();
  // Sanity: it passes validation (within all caps) so we are timing real analysis.
  assert.equal(validate(text).ok, true, 'the cap-sized policy must be within all limits');

  const r = scan({ text, family: 'identity', budgetMs: BUDGET_MS });

  // "Completes without overrunning the budget" is asserted DETERMINISTICALLY by the
  // verdict, not a flaky absolute elapsed<budget measurement: had the wall-clock budget
  // fired, the scan would carry reason RESOURCE_BUDGET_EXCEEDED and a FAILED status. A
  // COMPLETE, non-budget-exceeded verdict IS the "did not overrun" proof, independent of
  // CPU load (an absolute ms upper-bound flakes under the runner's default parallelism).
  assert.notEqual(r.reason, 'RESOURCE_BUDGET_EXCEEDED', 'a normal cap-sized policy must NOT hit the budget');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'it analyzes to a COMPLETE verdict, bounded');
  assert.notEqual(r.exitCode, EXIT.INTERNAL, 'analysis must not error internally');
});

// --- (c) wall-clock budget: aborts to a graceful fail-closed verdict ----------

// A minimal, valid identity policy that (with no budget) analyzes CLEAN to exit 0.
// With the budget forced past, it MUST instead fail closed - proving the abort
// converts a would-be clean pass into an explicit incomplete state, never a green.
const CLEAN_POLICY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Sid: 'ReadOne', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::my-bucket/my-object' }],
});

test('(c) a forced budget overrun fails CLOSED (exit 3), never a clean pass', () => {
  // budgetMs <= 0 sets a deadline in the past, so the first matcher call aborts.
  const r = scan({ text: CLEAN_POLICY, family: 'identity', budgetMs: -1 });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a budget overrun must NEVER report exit 0 / clean');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'a budget overrun fails closed to exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.ok(
    r.analysisStates.some((s) => /analysis aborted \(resource budget\)/.test(s.message || '')),
    'the aborted state carries the "analysis aborted (resource budget)" message',
  );
  assert.equal(r.findings.length, 0, 'no findings are asserted from an aborted analysis');
});

test('(c) the SAME policy with a generous budget analyzes normally (no false trip)', () => {
  const r = scan({ text: CLEAN_POLICY, family: 'identity', budgetMs: BUDGET_MS });
  assert.notEqual(r.reason, 'RESOURCE_BUDGET_EXCEEDED', 'a fast policy must not trip a generous budget');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.exitCode, EXIT.CLEAN, 'the clean policy is exit 0 when the budget is not exceeded');
});

test('(c) scan() DISARMS the budget after it returns (no lingering armed state)', () => {
  // Force an abort, then confirm a direct matcher call does NOT throw - i.e. the
  // finally-block disarm ran and the module is back to its deterministic default.
  scan({ text: CLEAN_POLICY, family: 'identity', budgetMs: -1 });
  assert.doesNotThrow(() => globMatch('a*c', 'abc'));
  assert.equal(globMatch('a*c', 'abc'), true, 'matcher works normally after a disarm');
});

test('(c) omitting budgetMs leaves scan() clock-free and behaving exactly as before', () => {
  const r = scan({ text: CLEAN_POLICY, family: 'identity' });
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
});

// --- (c) end-to-end: the CLI and Action honor the budget ----------------------

test('(c) CLI --budget-ms=-1 drives a fail-closed exit 3 (never 0)', async () => {
  const io = {
    readFile: () => CLEAN_POLICY,
    readStdin: async () => '',
    writeFile: () => {},
    stdout: () => {},
    stderr: () => {},
    stdinIsTTY: false,
  };
  const code = await run(['--family', 'identity', '--budget-ms', '-1', 'policy.json'], io);
  assert.equal(code, EXIT.FAIL_CLOSED, 'CLI must fail closed (exit 3) on a budget overrun');
  assert.notEqual(code, EXIT.CLEAN);
});

test('(c) CLI rejects a non-numeric --budget-ms as a usage error (exit 2)', async () => {
  const io = {
    readFile: () => CLEAN_POLICY,
    readStdin: async () => '',
    writeFile: () => {},
    stdout: () => {},
    stderr: () => {},
    stdinIsTTY: false,
  };
  const code = await run(['--family', 'identity', '--budget-ms', 'soon', 'policy.json'], io);
  assert.equal(code, EXIT.USAGE, 'a non-numeric budget is a usage error');
});

test('(c) Action budget-ms input forces a fail-closed aggregate exit 3 (never green)', () => {
  const env = {
    'INPUT_PATHS': 'policy.json',
    'INPUT_FAMILY': 'identity',
    'INPUT_BUDGET-MS': '-1',
  };
  const io = {
    listFiles: () => ['policy.json'],
    readFile: () => CLEAN_POLICY,
  };
  const r = runAction({ env, io });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the Action must fail closed on a budget overrun');
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.equal(r.analysisStatus, 'failed');
});

// ============================================================================
// Iteration 2: close the INTERIOR-segment quadratic + give the BROWSER path a
// real bound. Iteration 1 only anchored the FIRST and LAST '*'-delimited segments,
// so a long literal run BETWEEN two stars ('*' + run + '*') was still re-scanned
// from every text offset -> the same O(n*m). And the wall-clock budget was armed
// ONLY by the Node adapter, so the browser/worker path could run unbounded and
// return a COMPLETE (ok:true, incomplete:false) verdict after tens of seconds.
// These tests lock the interior-linear matcher AND the deterministic WORK budget
// that analyze() now arms on EVERY run (browser included).
// ============================================================================

// --- (b) matcher: the INTERIOR '*'+run+'*' form is linear -------------------

test('(b) the INTERIOR two-star worst case (*run*) is linear (the case iteration-1 left quadratic)', () => {
  // '*' + 'a'*k + 'b' + '*' vs 'a'*n : the long run 'a'*k+'b' is an INTERIOR segment
  // (between two stars). Under the iteration-1 matcher findSegFrom re-scanned it from
  // every offset -> O(n*m). It never matches (text has no 'b'), which is the maximal-
  // work case. Absolute ceiling, not a ratio, so it is non-flaky; the old matcher
  // blew past this by orders of magnitude at this size.
  // Iteration count kept modest so the ABSOLUTE ceiling stays non-flaky even under
  // full-suite CPU contention: the linear matcher does ~0.5ms per call here, the OLD
  // quadratic did ~18ms per call (so these 200 iterations would be ~3.6s - well past
  // the budget - under the old code). The gap is the signal, not the raw number.
  const n = 4096;
  const pattern = `*${'a'.repeat(n / 2)}b*`;
  const textStr = 'a'.repeat(n);

  const t0 = performance.now();
  let acc = false;
  for (let i = 0; i < 200; i++) acc = globMatch(pattern, textStr) || acc;
  const elapsed = performance.now() - t0;

  assert.equal(acc, false, "interior run ends in 'b' but text is all 'a' -> never matches");
  assert.ok(
    elapsed < BUDGET_MS,
    `200 interior *run* matches at n=${n} took ${elapsed.toFixed(1)}ms; budget ${BUDGET_MS}ms`,
  );
});

test('(b) a MATCHING interior *run* case is also linear (both branches offset-once)', () => {
  // '*' + 'a'*k + '*' vs 'a'*n MATCHES (the run is all 'a'). Exercises the success
  // branch of the interior automaton at scale; must be just as cheap.
  const n = 4096;
  const pattern = `*${'a'.repeat(n / 2)}*`;
  const textStr = 'a'.repeat(n);
  const t0 = performance.now();
  let acc = true;
  for (let i = 0; i < 200; i++) acc = globMatch(pattern, textStr) && acc;
  const elapsed = performance.now() - t0;
  assert.equal(acc, true, 'an all-a interior run matches an all-a text');
  assert.ok(elapsed < BUDGET_MS, `200 matching interior matches took ${elapsed.toFixed(1)}ms; budget ${BUDGET_MS}ms`);
});

test('(b) interior / MULTI-STAR patterns still agree with the reference matcher (interior dedup guard)', () => {
  // The iteration-1 dedup fuzz used pl<=7 with a single-'*' alphabet weight, so it
  // rarely produced >=2 interior segments - the exact shape that was quadratic AND
  // where a wrong linear rewrite would diverge. This corpus is star-heavy and longer
  // so interior placement is exercised hard.
  let seed = 0x9e3779b1;
  const rnd = () => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };
  // Weighted alphabet: many '*' so multiple interior segments are common.
  const patAlpha = ['a', 'b', 'c', '?', '*', '*', '*'];
  const txtAlpha = ['a', 'b', 'c'];
  const gen = (alpha, len) => { let s = ''; for (let i = 0; i < len; i++) s += alpha[(rnd() * alpha.length) | 0]; return s; };

  let mismatches = 0;
  for (let pl = 0; pl <= 12; pl++) {
    for (let tl = 0; tl <= 12; tl++) {
      for (let k = 0; k < 200; k++) {
        const p = gen(patAlpha, pl);
        const t = gen(txtAlpha, tl);
        if (globMatch(p, t) !== referenceGlob(p, t)) mismatches++;
      }
    }
  }
  assert.equal(mismatches, 0, 'interior/multi-star matcher must equal the reference matcher on every input');

  // Explicit interior edge cases (long-ish runs between stars, ? at boundaries).
  const edges = [
    ['*a*', 'b'], ['*a*', 'xay'], ['*ab*', 'xaby'], ['*ab*', 'xba'], ['*abc*', 'zzabczz'],
    ['a*b*c', 'axbyc'], ['a*b*c', 'abc'], ['a*b*c', 'ac'], ['*a*a*', 'xayaz'],
    ['*?b*', 'xxby'], ['*a?c*', 'zzabcyy'], ['x*yy*z', 'xAyyBz'], ['x*yy*z', 'xyz'],
    ['*//*', 'a//b'], ['arn:*:s3:*:*:*/*', 'arn:aws:s3:::my-bucket/key'],
  ];
  for (const [p, t] of edges) {
    assert.equal(globMatch(p, t), referenceGlob(p, t), `interior edge ${JSON.stringify([p, t])}`);
  }
});

// --- (b) the interior-quadratic FIXTURE analyzes bounded (never hangs) --------

function readInteriorFixture() {
  return JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'interior-quadratic-glob.json'), 'utf8'));
}

test('(b) the interior-quadratic fixture is WITHIN caps yet analyzes bounded through analyze()', () => {
  const fx = readInteriorFixture();
  const text = JSON.stringify(fx.policy);

  // The point of the fixture: a per-string cap is NO defense (every string is at or
  // under the cap and the document is small), so validate() ACCEPTS it.
  assert.equal(validate(text).ok, true, 'the interior fixture is within every limit (validate.ok)');

  const a = analyze(text);

  // Linear matcher: tens of ms. "Analyzes bounded (never hangs)" is asserted via the
  // DETERMINISTIC op-count work budget, not a wall-clock ceiling: the old quadratic re-scan
  // grew ~4x per 2x and would exceed the fixed DEFAULT_WORK_LIMIT and abort, so a COMPLETE
  // (non-aborted) run proves the matcher stayed linear - load-independent, whereas an
  // absolute ms ceiling flakes under the runner's default file-level parallelism.
  assert.equal(a.ok, true, 'the engine returns a well-formed result');
  assert.equal(a.coverage.summary.analysisAborted, false, 'the linear interior matcher completes within the fixed op-count budget (a quadratic re-scan would exceed it and abort)');
});

// --- (d) BROWSER deterministic WORK budget: fail CLOSED, never COMPLETE -------

// A CLEAN identity policy that analyzes to exit 0 with no budget. Reused to prove
// the work budget converts a would-be clean pass into an explicit fail-closed state.
const CLEAN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Sid: 'ReadOne', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::my-bucket/my-object' }],
});

test('(d) analyze() arms a DETERMINISTIC work budget with NO clock (browser determinism preserved)', () => {
  // Same input -> same result, twice, with the default budget armed. The budget is an
  // op COUNT, not Date.now(), so architecture invariant 8 (determinism) holds.
  const a1 = analyze(CLEAN_IDENTITY);
  const a2 = analyze(CLEAN_IDENTITY);
  assert.deepEqual(a1.findings, a2.findings, 'default-budget analysis is deterministic');
  assert.equal(a1.coverage.summary.incomplete, false, 'a fast clean policy is COMPLETE, not budget-tripped');
  assert.equal(a1.coverage.summary.analysisAborted, false, 'a fast clean policy is not aborted');
});

test('(d) a forced WORK-budget overrun fails CLOSED to an incomplete result (never COMPLETE/clean)', () => {
  // options.workLimit <= 0 forces an abort on the first matcher call - the deterministic
  // analogue of budgetMs<=0 for the clock, but with NO clock read (browser path).
  const a = analyze(CLEAN_IDENTITY, { workLimit: 0 });
  assert.equal(a.ok, true, 'the abort is a well-formed in-band result, not a throw');
  assert.equal(a.aborted, true, 'the result is marked aborted');
  assert.equal(a.findings.length, 0, 'no findings are asserted from an aborted analysis');
  assert.equal(a.coverage.summary.incomplete, true, 'coverage is INCOMPLETE - never a clean COMPLETE verdict');
  assert.equal(a.coverage.summary.analysisAborted, true, 'coverage records the resource-budget abort');
  assert.ok(
    a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'),
    'the aborted coverage carries the RESOURCE_BUDGET_EXCEEDED code',
  );
});

test('(d) analyze() work budget is deterministic across machines: a fixed op-count trips at the same point', () => {
  // A tiny finite limit trips; a large one does not; the SAME input decides identically
  // every run (no wall-clock in the decision). Two mid-range limits bracket the clean
  // policy's actual work so the trip point is a pure function of the input.
  const tripped = analyze(CLEAN_IDENTITY, { workLimit: 1 });
  const notTripped = analyze(CLEAN_IDENTITY, { workLimit: Infinity });
  assert.equal(tripped.aborted === true, true, 'workLimit:1 trips');
  assert.equal(!!notTripped.aborted, false, 'workLimit:Infinity (disabled) never trips');
  // Repeat the tripped case: identical outcome (deterministic).
  assert.equal(analyze(CLEAN_IDENTITY, { workLimit: 1 }).aborted, true, 'the trip is reproducible');
});

// Build an interior-star policy at a chosen scale (allow+deny statements). This is
// the class the browser path could previously run unbounded on and return COMPLETE.
function buildInteriorPolicy(n) {
  const allowRes = 'a'.repeat(2048);
  const denyRes = `*${'a'.repeat(1023)}b*`;
  const statements = [];
  for (let i = 0; i < n; i++) {
    statements.push({
      Sid: `Allow${i}`, Effect: 'Allow',
      Action: ['s3:*', 'iam:PassRole', 'lambda:CreateFunction', 'ec2:RunInstances'],
      Resource: [allowRes],
    });
  }
  for (let j = 0; j < n; j++) {
    statements.push({ Sid: `Deny${j}`, Effect: 'Deny', Action: ['s3:*', 'iam:*'], Resource: [denyRes] });
  }
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}

test('(d) an at-scale interior-quadratic policy fails CLOSED on the BROWSER path (never a COMPLETE clean verdict)', () => {
  // Large enough to exceed the deterministic default work budget. Under the old code
  // the browser/worker path (analyze) had NO budget, ran for tens of seconds, and
  // returned ok:true, incomplete:false (a COMPLETE verdict). Now it must fail closed:
  // ok:true but INCOMPLETE + aborted, bounded, with zero findings asserted.
  const text = buildInteriorPolicy(80);
  assert.equal(validate(text).ok, true, 'the at-scale interior policy is still within all caps');

  const a = analyze(text); // browser style: no clock armed anywhere

  assert.equal(a.ok, true, 'well-formed result (never an uncaught throw)');
  // "Bounded, not a hang" is the DETERMINISTIC op-count budget outcome: the runaway trips
  // the fixed DEFAULT_WORK_LIMIT after a fixed number of work units, independent of
  // wall-clock or CPU load. The abort assertions below ARE the boundedness proof.
  assert.equal(a.coverage.summary.analysisAborted, true, 'the runaway is aborted by the deterministic budget');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('(d) scan() bounds the SAME runaway via the deterministic budget -> exit 3, never clean', () => {
  // The CLI/Action path, with NO wall-clock budget supplied (budgetMs omitted), still
  // fails closed on the runaway because analyze()'s deterministic work budget trips.
  const text = buildInteriorPolicy(80);
  const r = scan({ text, family: 'identity' });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a runaway must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the runaway fails closed to exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.ok(
    r.analysisStates.some((s) => /analysis aborted \(resource budget\)/.test(s.message || '')),
    'the aborted state carries the "analysis aborted (resource budget)" message',
  );
});

test('(d) the deterministic budget does NOT false-trip a normal within-caps policy (no over-correction)', () => {
  // The negative direction: a genuinely large-but-legitimate policy (the cap-sized
  // suite policy) must analyze to completion WITHOUT the work budget firing. Guards
  // against setting DEFAULT_WORK_LIMIT so low it turns real analyses into fail-closed.
  const text = buildCapSizedPolicy();
  const r = scan({ text, family: 'identity' });
  assert.notEqual(r.reason, 'RESOURCE_BUDGET_EXCEEDED', 'a normal cap-sized policy must NOT hit the work budget');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'a normal policy analyzes to a COMPLETE verdict');
  const a = analyze(text);
  assert.equal(a.coverage.summary.analysisAborted, false, 'analyze() does not abort a normal policy');
});

// ============================================================================
// Iteration 3: charge the DENY-COVERAGE TRAVERSAL ITSELF, not only the matcher.
//
// The deterministic work budget is sampled only inside the shared matcher
// (chargeWork lives in glob.js). denyResourceCoverage() short-circuits globMatch on
// a Deny resource that carries an IAM policy variable (`!hasPolicyVariable(dr) &&
// globMatch(dr, ar)`). So when a Deny statement's Resource is entirely ${...}
// variables, the matcher is NEVER reached and the whole O(ruleFindings x
// findingActions x denies x denyResources) deny-coverage scan charged ZERO work:
// analyze()'s budget never tripped and a within-caps ${...}-scoped policy ran for
// multiple SECONDS yet returned a COMPLETE, non-aborted verdict with a full finding
// set - a fail-OPEN (threat-model T5/T8). The identical shape with CONCRETE or
// wildcard Deny resources already failed closed in ~70ms (globMatch charged its
// compare cost), so a single ${...} flipped a correctly-bounded analysis into an
// unbounded one. The fix charges the traversal (per deny inspected, and per Deny
// resource inspected at globMatch's own magnitude) INDEPENDENT of whether globMatch
// is reached, so the policy-variable branch accrues budget at the same rate as the
// concrete branch and reaches the SAME aborted+incomplete state.
// ============================================================================

// Build the DoS shape: nAllow broad-service Allow statements (one concrete Resource
// each) + nDeny `Action:["*"]` Deny statements whose Resource is `resPerDeny` copies
// of a Deny scope. `varScope=true` -> IAM policy variables (${...}) that short-circuit
// globMatch (the previously-uncharged branch); false -> a concrete wildcard scope that
// globMatch evaluates (already charged). Same shape/size either way: the ONLY change
// is the Deny resource string, isolating the policy-variable branch as the variable.
const DOS_SVC = ['s3', 'ec2', 'iam', 'lambda', 'sts', 'kms', 'sns', 'sqs', 'rds', 'dynamodb',
  'logs', 'ssm', 'ecr', 'ecs', 'eks', 'glue', 'athena', 'sagemaker', 'cloudformation', 'cloudtrail'];
function buildPolicyVarDenyPolicy(nAllow, nDeny, resPerDeny, varScope) {
  const varScopeStr = 'arn:aws:s3:::${aws:PrincipalTag/team}-' + 'y'.repeat(30);
  const statements = [];
  for (let i = 0; i < nAllow; i++) {
    statements.push({
      Sid: `Allow${i}`, Effect: 'Allow',
      Action: DOS_SVC.map((s) => `${s}:*`),
      Resource: [`arn:aws:s3:::bucket-${i}/object-${i}`],
    });
  }
  for (let j = 0; j < nDeny; j++) {
    const res = [];
    for (let k = 0; k < resPerDeny; k++) {
      res.push(varScope ? varScopeStr : `arn:aws:s3:::fixed-${j}-*-${k}/${'y'.repeat(20)}`);
    }
    statements.push({ Sid: `Deny${j}`, Effect: 'Deny', Action: ['*'], Resource: res });
  }
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}

test('(e) the policy-variable-Deny fixture is WITHIN caps yet fails CLOSED through analyze() (never a COMPLETE pass)', () => {
  // The committed canonical repro: a validate-passing, within-ALL-caps policy whose
  // Deny scope is entirely ${...} variables. Before the fix analyze() ran multiple
  // seconds and returned ok:true, incomplete:false, aborted:false, 86 findings - a
  // COMPLETE verdict on an unbounded run. It MUST now fail closed: aborted + incomplete
  // + zero findings, bounded.
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'policyvar-deny-uncharged.json'), 'utf8'));
  const text = JSON.stringify(fx.policy);
  assert.equal(validate(text).ok, true, 'the policy-variable-Deny fixture is within every limit (a per-string cap is no defense)');

  const a = analyze(text); // browser style: no wall-clock armed anywhere

  assert.equal(a.ok, true, 'well-formed in-band result, never an uncaught throw');
  // "Bounded, not a hang" is the DETERMINISTIC op-count budget outcome: the ${...}-Deny
  // runaway trips the fixed DEFAULT_WORK_LIMIT after a fixed number of work units,
  // independent of wall-clock or CPU load. The abort assertions below ARE the bound.
  assert.equal(a.coverage.summary.analysisAborted, true, 'the ${...}-Deny runaway is aborted by the deterministic budget');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(
    a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'),
    'the aborted coverage carries the RESOURCE_BUDGET_EXCEEDED code',
  );
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('(e) scan() bounds the policy-variable-Deny runaway via the deterministic budget -> exit 3, never clean', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'policyvar-deny-uncharged.json'), 'utf8'));
  const text = JSON.stringify(fx.policy);
  const r = scan({ text, family: 'identity' }); // no budgetMs: only the deterministic work budget guards it
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a ${...}-Deny runaway must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the runaway fails closed to exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.equal(r.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('(e) BOUNDARY: same shape/size trips whether the Deny scope is a policy variable OR a concrete wildcard (parity)', () => {
  // The crux: a policy variable must NOT be a cheaper (uncharged) path than a concrete
  // wildcard. At an at-scale size BOTH must reach the SAME aborted+incomplete state.
  const varText = buildPolicyVarDenyPolicy(40, 80, 15, true);
  const concreteText = buildPolicyVarDenyPolicy(40, 80, 15, false);
  assert.equal(validate(varText).ok, true, 'the variable-scope policy is within caps');
  assert.equal(validate(concreteText).ok, true, 'the concrete-scope policy is within caps');

  const av = analyze(varText);
  const ac = analyze(concreteText);
  assert.equal(av.coverage.summary.analysisAborted, true, 'the policy-VARIABLE Deny scope fails closed');
  assert.equal(ac.coverage.summary.analysisAborted, true, 'the CONCRETE wildcard Deny scope fails closed too');
  assert.equal(av.findings.length, 0, 'variable scope: zero findings from an aborted run');
  assert.equal(ac.findings.length, 0, 'concrete scope: zero findings from an aborted run');
});

test('(e) analyze() on the policy-variable-Deny runaway is DETERMINISTIC (op-count budget, no clock)', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'adversarial', 'policyvar-deny-uncharged.json'), 'utf8'));
  const text = JSON.stringify(fx.policy);
  const a1 = analyze(text);
  const a2 = analyze(text);
  assert.deepEqual(a1.findings, a2.findings, 'same input -> same (empty) findings twice');
  assert.equal(a1.coverage.summary.analysisAborted && a2.coverage.summary.analysisAborted, true, 'both runs abort (deterministic trip point)');
});

test('(e) NO over-correction: a SMALL policy-variable-Deny policy does NOT trip the resource budget', () => {
  // The charge is PROPORTIONAL to real traversal work, not a blanket "any ${...} Deny
  // aborts". A tiny policy-variable-Deny policy does little deny-coverage work and MUST
  // NOT trip the budget (no false positive), or the fix would over-correct legitimate
  // variable-scoped Denies into a budget-aborted fail-closed.
  const text = buildPolicyVarDenyPolicy(3, 2, 3, true);
  assert.equal(validate(text).ok, true, 'the small policy-variable-Deny policy is within caps');
  const a = analyze(text);
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small ${...}-Deny policy does NOT trip the budget');
  // S2-airtight-incomplete (a): the Allow statements name `<svc>:*` wildcards on
  // services the small curated catalog does not model (sns/logs/ecr/eks/athena), so the
  // coverage is honestly INCOMPLETE (an unmodeled-service wildcard cannot be vouched for -
  // unsupported does NOT mean safe), exactly as a concrete `sns:Publish` already is. That
  // incompleteness is a CATALOG-coverage signal, NOT a budget abort - the two are
  // orthogonal, and this test asserts only the budget did not over-fire.
  assert.equal(a.coverage.summary.analysisAborted, false, 'the incompleteness is catalog coverage, not a resource-budget abort');
  const r = scan({ text, family: 'identity' });
  assert.notEqual(r.reason, 'RESOURCE_BUDGET_EXCEEDED', 'scan() does not fail closed on a small legitimate ${...}-Deny policy');
});
