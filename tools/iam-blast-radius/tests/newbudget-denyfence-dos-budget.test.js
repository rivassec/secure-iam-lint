// S1-NEW-BUDGET-chargeWork axis NEW-BUDGET-DENYFENCE (HIGH DoS): the deny-fence
// narrowness walk is now CHARGED so BOTH engine budgets bound it.
//
// THE BUG. denyFencesToNarrow (rules.js) proves a NotResource-Deny's spared set NARROW
// via `deny.notResources.some((r) => classifyResource(r) !== NARROW)`. classifyResource
// charges ZERO work on the well-formed NARROW-ARN path (parseArn is pure; the
// withoutBudget-wrapped globReachesMultipleAccounts only runs on a parse FAILURE and
// short-circuits), so that walk advanced neither cooperative budget. denyFencesToNarrow is
// invoked ONCE PER MATCHED read action from three call sites on the NORMAL analyze() path
// (ruleFindingDenySuppressed - run on every finding; survivingBroadReadActions;
// survivingSparedContainerReads), so a within-caps policy with N matched actions x M narrow
// notResources ran an uncharged O(N*M) walk: the deterministic 60M work budget was sampled
// far too rarely (the run aborted only when OTHER charged work slowly crossed the ceiling,
// tens of seconds later - REPRODUCED at ~40s) and any direct analyze() API consumer, which
// has no browser Worker watchdog, had no protection. This falsified glob.js's "deterministic
// work limit bounds every run" invariant (threat-model T5 DoS).
//
// THE FIX. denyFencesToNarrow charges work per spared element INSPECTED (proportional to the
// string classifyResource scans), so the .some() walk SAMPLES both budgets and aborts
// mid-scan. The tagged GlobBudget('work') sentinel propagates through analyzeRules (which
// re-throws isGlobBudgetError) to analyze(), which fails CLOSED to an "aborted (resource
// budget)" incomplete result - never a COMPLETE verdict from an unbudgeted loop.
//
// These exercise the REAL boundaries: the shipped analyze() engine and the CLI scan() core.
//
// Boundedness of the pathological input is asserted via the DETERMINISTIC op-count work
// budget (coverage.summary.analysisAborted === true / false), which is load-independent, NOT
// an absolute wall-clock ceiling (which flakes under the runner's file-level parallelism).
// The ONE genuinely wall-clock assertion (--budget-ms aborts) uses a generous multi-second
// margin, orders of magnitude below the ~40s pre-fix runtime.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';

const CTX = { family: 'identity' };

// N DISTINCT action patterns that each glob-grant a data-read concrete, generated as
// '?'-masks of a base action ('?' matches any single char, so every mask matches the base;
// the masks are distinct as strings). matchPatterns(stmt, DATA_READ_ACTIONS) therefore
// returns all N, so denyFencesToNarrow is called N times - once per matched action.
function maskedPatterns(base, count) {
  const out = new Set();
  const L = base.length;
  for (let mask = 0; mask < (1 << L) && out.size < count; mask++) {
    let s = '';
    for (let i = 0; i < L; i++) s += (mask & (1 << i)) ? '?' : base[i];
    out.add(s);
  }
  return [...out];
}

// One broad Allow (Resource:*) carrying N matched read-action patterns, fenced by one
// unconditional NotResource Deny whose M spared elements are ALL narrow, concrete S3 bucket
// ARNs (each a NARROW verdict), so the `.some(classifyResource !== NARROW)` walk inspects
// every one of the M elements on every one of the N calls => an O(N*M) narrowness walk.
// Within every validate() cap (MAX_ACTIONS/MAX_RESOURCES = 10000, MAX_STRING_LENGTH = 2048).
function buildDenyFencePolicy(nActions, mNotRes) {
  const acts = [];
  for (const p of maskedPatterns('s3:GetObject', Math.min(nActions, 4096))) acts.push(p);
  if (acts.length < nActions) {
    for (const p of maskedPatterns('dynamodb:Scan', nActions - acts.length)) acts.push(p);
  }
  const notRes = [];
  for (let i = 0; i < mNotRes; i++) notRes.push(`arn:aws:s3:::spared-bucket-${i}/*`);
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'AllowBroad', Effect: 'Allow', Action: acts.slice(0, nActions), Resource: '*' },
      { Sid: 'Fence', Effect: 'Deny', Action: 's3:GetObject', NotResource: notRes },
    ],
  });
}

// The canonical ORDINARY deny-fence policy (corpus 21 / the R1 story): a broad exfil Allow
// fenced to ONE whole bucket. Its verdict is fixed - a surviving whole-bucket read surfaces
// CROSS-ACCOUNT-DATA-READ-UNDETERMINED, never DATA-EXFIL - and MUST be unchanged by the fix.
const ORDINARY_FENCE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Sid: 'AllowReadBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Sid: 'DenyButCompetitor', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  ],
});

// A single-object spared read is routine least privilege -> genuinely CLEAN (whole-container
// excludes it). Must stay clean (no new abort, no fabricated finding).
const ORDINARY_SINGLE_OBJECT = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/report.csv' },
  ],
});

// The within-caps DoS shape: N ~= 9998 matched read actions x M = 9000 narrow spared
// elements. Deep past the 60M ceiling (~9x10^7 potential element-inspections), so it aborts
// DETERMINISTICALLY regardless of load.
const DOS_N = 9998;
const DOS_M = 9000;

function analyzeClean(ar) {
  return !!(ar && ar.ok === true
    && Array.isArray(ar.findings) && ar.findings.length === 0
    && !(ar.coverage && ar.coverage.summary && ar.coverage.summary.incomplete));
}
function scanClean(sr) {
  return sr.exitCode === EXIT.CLEAN && sr.analysisStatus === ANALYSIS_STATUS.COMPLETE;
}
function ids(ar) { return ar.ok ? ar.findings.map((f) => f.id) : []; }

// ---------------------------------------------------------------------------
// MUST-CLOSE: the within-caps N x M deny-fence policy ABORTS under the default 60M work
// budget - analyze() fails CLOSED, never a COMPLETE verdict from an unbudgeted loop.
// ---------------------------------------------------------------------------

test('MUST-CLOSE: within-caps N x M deny-fence policy ABORTS under the default 60M work budget (analyze fails closed)', () => {
  const text = buildDenyFencePolicy(DOS_N, DOS_M);
  assert.equal(validate(text).ok, true, 'the DoS policy is within every validate cap (a per-string/count cap is no defense against the O(N*M) walk)');

  const a = analyze(text, CTX); // browser style: default 60M work budget, no wall-clock armed
  assert.equal(a.ok, true, 'a well-formed in-band result (never an uncaught throw)');
  assert.equal(a.coverage.summary.analysisAborted, true, 'the now-charged deny-fence walk trips the deterministic work budget (was ~unbudgeted -> ~40s before the fix)');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'), 'the aborted coverage carries RESOURCE_BUDGET_EXCEEDED');
  assert.equal(a.findings.length, 0, 'no findings are asserted from an aborted analysis (fail closed)');
});

// ---------------------------------------------------------------------------
// The charge is FROM the deny-fence notResources walk (isolation): with the SAME N matched
// actions, a policy with M=1 spared element COMPLETES while M=9000 ABORTS. Everything except
// the M-scaled notResources walk is identical (matchPatterns work depends on N, not M), so
// the abort is caused by the now-charged deny-fence walk, not incidental other work.
// ---------------------------------------------------------------------------

test('the deny-fence notResources walk is what is charged: same N, M=1 completes but M=9000 aborts', () => {
  const small = analyze(buildDenyFencePolicy(DOS_N, 1), CTX);
  assert.equal(small.coverage.summary.analysisAborted, false, 'same N with a single spared element does little deny-fence work -> completes');
  const big = analyze(buildDenyFencePolicy(DOS_N, DOS_M), CTX);
  assert.equal(big.coverage.summary.analysisAborted, true, 'holding N fixed and scaling ONLY M (notResources) trips the budget -> the deny-fence walk is the charged dimension');
});

// ---------------------------------------------------------------------------
// MUST-CLOSE: the deny-fence walk PARTICIPATES in a forced work budget - a moderate policy
// that COMPLETES under the default budget ABORTS when a small work limit is forced. This
// proves the walk advances the counter (not merely that the huge shape eventually trips).
// ---------------------------------------------------------------------------

test('the deny-fence walk participates in the work budget: a forced small limit aborts a policy that otherwise completes', () => {
  const text = buildDenyFencePolicy(500, 200);
  assert.equal(validate(text).ok, true);
  assert.equal(analyze(text, CTX).coverage.summary.analysisAborted, false, 'this moderate shape completes under the default 60M budget');
  const a = analyze(text, { ...CTX, workLimit: 100000 });
  assert.equal(a.coverage.summary.analysisAborted, true, 'a small forced work budget ABORTS the now-charged deny-fence walk');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is incomplete, never a clean complete');
  assert.equal(a.findings.length, 0, 'no findings from an aborted analysis');
});

// ---------------------------------------------------------------------------
// MUST-CLOSE: the CLI scan() core fails CLOSED on the same input, under BOTH budgets.
// ---------------------------------------------------------------------------

test('MUST-CLOSE: scan() fails closed (exit 3) on the within-caps deny-fence DoS under the default work budget', () => {
  const text = buildDenyFencePolicy(DOS_N, DOS_M);
  const r = scan({ text, family: 'identity', threshold: 'info' });
  assert.equal(scanClean(r), false, 'a runaway O(N*M) deny-fence walk must never be a clean CLI pass');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the CLI fails closed at exit 3 (RESOURCE_BUDGET_EXCEEDED)');
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED', 'the fail-closed reason is the budget abort');
});

test('MUST-CLOSE: scan() with --budget-ms aborts the deny-fence DoS well under the prior ~40s', () => {
  // The ONE wall-clock assertion: an armed --budget-ms deadline aborts the now-charged walk.
  // The margin is enormous (a 2s budget vs a ~40s pre-fix run), so CPU contention cannot
  // realistically mask it. (The deterministic 60M work budget also trips this input in ~0.5s;
  // either ceiling reaching first is a fail-closed exit 3 - the invariant asserted here.)
  const text = buildDenyFencePolicy(DOS_N, DOS_M);
  const t0 = Date.now();
  const r = scan({ text, family: 'identity', threshold: 'info', budgetMs: 2000 });
  const elapsed = Date.now() - t0;
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'an armed --budget-ms deadline fails the DoS closed at exit 3');
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED', 'the abort reason is the resource budget');
  assert.ok(elapsed < 20000, `must abort well under the ~40s pre-fix runtime; took ${elapsed}ms`);
});

// ---------------------------------------------------------------------------
// MUST-NOT-BREAK: ordinary deny-fence policies are UNCHANGED - no new abort, identical
// verdicts. The proportional charge is negligible on a handful of short spared elements.
// ---------------------------------------------------------------------------

test('MUST-NOT-BREAK: the ordinary whole-bucket deny-fence completes with its IDENTICAL verdict (no new abort)', () => {
  const a = analyze(ORDINARY_FENCE, CTX);
  assert.equal(a.coverage.summary.analysisAborted, false, 'an ordinary deny-fence must NOT newly trip the budget');
  assert.equal(a.coverage.summary.incomplete, false, 'it reaches a COMPLETE verdict');
  assert.deepEqual(ids(a), ['CROSS-ACCOUNT-DATA-READ-UNDETERMINED'], 'the surviving whole-bucket read verdict is unchanged by the fix');
  assert.ok(!ids(a).includes('DATA-EXFIL'), 'the fence still removes the broad exfil reach (verdict unchanged)');
});

test('MUST-NOT-BREAK: an ordinary single-object spared deny-fence stays genuinely CLEAN (no new abort, no fabricated finding)', () => {
  const a = analyze(ORDINARY_SINGLE_OBJECT, CTX);
  assert.equal(a.coverage.summary.analysisAborted, false, 'no new abort on a tiny deny-fence policy');
  assert.equal(analyzeClean(a), true, 'a single concrete object spared read stays clean (verdict unchanged)');
  assert.deepEqual(a.findings, [], 'no fabricated findings');
});

test('MUST-NOT-BREAK: parity + surfacing hold on the ordinary deny-fence (browser == CLI)', () => {
  const a = analyze(ORDINARY_FENCE, { family: 'identity' });
  const r = scan({ text: ORDINARY_FENCE, family: 'identity', threshold: 'info' });
  assert.equal(analyzeClean(a), false, 'the surviving read surfaces on the browser surface');
  assert.equal(scanClean(r), false, 'and fails the CLI gate at info');
  assert.ok(r.findings.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'), 'both surfaces carry the same finding id');
});

// ---------------------------------------------------------------------------
// Determinism (architecture invariant 8): the op-count budget carries no clock, so the
// trip/complete decision is a pure function of the input.
// ---------------------------------------------------------------------------

test('deterministic: the DoS policy aborts identically twice (op-count budget, no clock in the decision)', () => {
  const text = buildDenyFencePolicy(DOS_N, DOS_M);
  const a1 = analyze(text, CTX);
  const a2 = analyze(text, CTX);
  assert.equal(a1.coverage.summary.analysisAborted, a2.coverage.summary.analysisAborted, 'same input -> same abort decision');
  assert.equal(a1.coverage.summary.incomplete, a2.coverage.summary.incomplete);
});

test('deterministic: the ordinary deny-fence yields deep-equal findings twice', () => {
  assert.deepEqual(analyze(ORDINARY_FENCE, CTX).findings, analyze(ORDINARY_FENCE, CTX).findings);
});

// ---------------------------------------------------------------------------
// PARITY: browser analyze() is never MORE permissive than the CLI scan() on the DoS input.
// ---------------------------------------------------------------------------

test('PARITY: analyze() is never more permissive than scan() on the deny-fence DoS (both fail closed)', () => {
  const text = buildDenyFencePolicy(DOS_N, DOS_M);
  const a = analyze(text, { family: 'identity' });
  const r = scan({ text, family: 'identity', threshold: 'info' });
  assert.ok(scanClean(r) || !analyzeClean(a), 'browser must not read clean while the CLI fails closed');
  assert.equal(analyzeClean(a), false, 'browser fails closed (aborted/incomplete)');
  assert.equal(scanClean(r), false, 'CLI fails closed (exit 3)');
});
