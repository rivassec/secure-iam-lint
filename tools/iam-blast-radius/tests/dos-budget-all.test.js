// S3-dos-budget-all: close the DoS CLASS across EVERY combinatorial/glob/loop path.
//
// Round-2 story. Three confirmed fail-OPEN DoS paths that a within-caps, validate-
// passing policy (or, for the Action, a crafted `paths` input) could ride to either a
// multi-second hang OR - worse - a COMPLETE "clean" verdict on an unbounded run
// (threat-model T5/T8):
//
//   (1) detectRoleTakeover / principalConditionsSatisfiable's grant x trust x assume
//       TRIPLE loop charged the deterministic work budget ZERO times (its body -
//       pinsJointlySatisfiable / principalPinsOf / keyConstraintsSatisfiable - never
//       reaches the shared matcher, the only prior chargeWork site). ~400 legs per
//       group = O(N^3) map-building work = tens of seconds, reported COMPLETE.
//   (2) denyActionApplies's Action/NotAction inner loop skipped charging on every
//       policy-variable pattern (the `continue` fires BEFORE actionGrants, the only
//       charged call), so an all-${...} Deny action list advanced the budget zero.
//   (3) the GitHub Action `paths` glob was compiled to an ANCHORED backtracking
//       RegExp and resolved BEFORE any scan budget was armed -> a crafted pattern
//       ('*a*a*...*b' vs a long non-matching path) is a pre-budget ReDoS that hangs
//       the whole Action.
//
// The fixes: charge the work budget inside EVERY such policy-derived loop (and cap the
// role-takeover combinatorial product up front), and replace the Action glob with a
// LINEAR, ReDoS-immune path matcher (globMatchPath) plus a length/wildcard cap. Each
// pathological input MUST now complete under a fixed ms budget or fail CLOSED, and the
// negative / no-over-correction cases MUST stay green.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';
import {
  runAction,
  resolveFiles,
  globMatchPath,
  globToRegExp,
} from '../../../action/index.mjs';
import { denyActionApplies } from '../../../content/tools/iam-blast-radius/engine/escalation.js';
import { setWorkLimit, getWorkLimit, isGlobBudgetError } from '../../../content/tools/iam-blast-radius/engine/glob.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';

// A fixed wall-clock ceiling for the glob ReDoS "resolves in LINEAR time" proofs only.
// There the wall-clock IS the semantic (linear O(tokens x length) vs. catastrophic
// exponential backtracking), and the margin is enormous - the linear matcher decides in
// sub-millisecond time, orders of magnitude below this ceiling, so CPU contention cannot
// realistically trip it. The analyze()-heavy "completes BOUNDED" checks do NOT use a
// wall-clock ceiling: they assert boundedness via the DETERMINISTIC op-count work budget
// (coverage.summary.analysisAborted === false), because a genuinely-heavy within-caps
// input runs ~1-2s single-threaded and an absolute ms ceiling flakes under the runner's
// default file-level parallelism (CPU contention), red-flagging good code on a busy/CI
// box. The op-count budget is load-independent and already proven reliable by the paired
// fail-closed tests that force a tight ceiling.
const BUDGET_MS = 2000;

const ANCHOR_ROLE = 'arn:aws:iam::123456789012:role/target';

// ---------------------------------------------------------------------------
// (1) role-takeover TRIPLE loop: grant x trust x assume is now budget-charged.
// ---------------------------------------------------------------------------

// Build a role-takeover-HEAVY policy whose grant x trust x assume product is large.
// Every GT statement grants BOTH the permission-grant and trust-modify primitives on
// the SAME concrete anchor role (so it is in grantLegs AND trustLegs); every A
// statement grants sts:AssumeRole on that role (assumeLegs). Each statement pins
// aws:PrincipalOrgID to a DISTINCT value with StringEquals, so NO (grant, trust,
// assume) triple is jointly satisfiable (a grant/trust leg and an assume leg always
// pin the invariant key to different literals) -> the search never short-circuits and
// walks the full grantLegs.length * trustLegs.length * assumeLegs.length product. With
// nGT=500, nA=499 that product is ~1.25e8, past the deterministic work budget, so the
// analysis MUST fail closed instead of grinding for tens of seconds.
function buildRoleTakeoverHeavyPolicy(nGT, nA) {
  const statements = [];
  for (let i = 0; i < nGT; i++) {
    statements.push({
      Sid: `GT${i}`,
      Effect: 'Allow',
      Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy'],
      Resource: [ANCHOR_ROLE],
      Condition: { StringEquals: { 'aws:PrincipalOrgID': `o-gt${i}` } },
    });
  }
  for (let j = 0; j < nA; j++) {
    statements.push({
      Sid: `A${j}`,
      Effect: 'Allow',
      Action: ['sts:AssumeRole'],
      Resource: [ANCHOR_ROLE],
      Condition: { StringEquals: { 'aws:PrincipalOrgID': `o-a${j}` } },
    });
  }
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}

test('(1) role-takeover-heavy policy is WITHIN caps yet fails CLOSED through analyze() (never a COMPLETE pass)', () => {
  const text = buildRoleTakeoverHeavyPolicy(500, 499);
  assert.equal(validate(text).ok, true, 'the role-takeover-heavy policy is within every limit');

  const a = analyze(text); // browser style: no wall-clock armed, only the work budget

  assert.equal(a.ok, true, 'well-formed in-band result, never an uncaught throw');
  // "Bounded, not a hang" is the DETERMINISTIC op-count budget outcome: the O(N^3)
  // triple-loop runaway trips the fixed DEFAULT_WORK_LIMIT and aborts after a fixed number
  // of work units, independent of wall-clock or CPU load. The abort assertions below ARE
  // the boundedness proof - no flaky wall-clock ceiling needed.
  assert.equal(a.coverage.summary.analysisAborted, true, 'the O(N^3) triple-loop runaway is aborted by the deterministic budget');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(
    a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'),
    'the aborted coverage carries the RESOURCE_BUDGET_EXCEEDED code',
  );
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('(1) scan() bounds the role-takeover-heavy runaway -> exit 3, never clean', () => {
  const text = buildRoleTakeoverHeavyPolicy(500, 499);
  const r = scan({ text, family: 'identity' }); // no budgetMs: only the deterministic work budget
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a role-takeover-heavy runaway must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the runaway fails closed to exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.equal(r.findings.length, 0);
});

test('(1) analyze() on the role-takeover-heavy runaway is DETERMINISTIC (op-count budget, no clock)', () => {
  const text = buildRoleTakeoverHeavyPolicy(500, 499);
  const a1 = analyze(text);
  const a2 = analyze(text);
  assert.deepEqual(a1.findings, a2.findings, 'same input -> same (empty) findings twice');
  assert.equal(
    a1.coverage.summary.analysisAborted && a2.coverage.summary.analysisAborted,
    true,
    'both runs abort at the same deterministic trip point',
  );
});

test('(1) NO over-correction: a SMALL role-takeover policy still analyzes to a COMPLETE verdict AND fires the finding', () => {
  // One statement carrying all three primitives on the concrete role, no conflicting
  // condition -> a genuine, satisfiable role-takeover chain. The proportional charge
  // must NOT trip on this legitimate compound path (no false fail-closed), and the
  // ROLE-TAKEOVER finding must still fire (no false negative).
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'Takeover',
      Effect: 'Allow',
      Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'],
      Resource: [ANCHOR_ROLE],
    }],
  });
  assert.equal(validate(text).ok, true);
  const a = analyze(text);
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small legit role-takeover policy does NOT trip the budget');
  assert.equal(a.coverage.summary.incomplete, false, 'it reaches a COMPLETE verdict');
  assert.ok(
    a.findings.some((f) => f.id === 'ROLE-TAKEOVER'),
    'the legitimate role-takeover chain still fires (no false negative from the DoS fix)',
  );
});

// ---------------------------------------------------------------------------
// (1b) role-takeover satisfiability, ONE FRAME DOWN: keyConstraintsSatisfiable's
// candidate x constraint scan. The iteration-2 fix charged the leg cross-product
// (principalConditionsSatisfiable) and the per-statement pin walk (pinsJointlySatis-
// fiable) but left the INNERMOST scan - keyConstraintsSatisfiable / constraintContains
// - both O(V^2) (a case-insensitive operator linearly RE-scanned the whole value Set
// per candidate) AND uncharged. Condition-value arrays are NOT capped by count in
// validate.js (only MAX_BYTES / MAX_STRING_LENGTH), so V reaches tens of thousands
// within caps; a single within-caps Allow ran multiple seconds yet returned a COMPLETE
// verdict (fail-OPEN DoS, T5/T8 - the same class the story targets, moved one frame
// down). The fix normalizes case-insensitive value sets to a lowercased Set ONCE (so
// constraintContains is O(1) and the scan is linear) AND charges the candidate x
// constraint product so the scan participates in the work budget and the wall-clock
// deadline. Same trigger shape as the finding.
// ---------------------------------------------------------------------------

// A single within-caps Allow carrying all three role-takeover primitives on ONE
// concrete role, with a large case-INSENSITIVE principal-invariant condition made
// unsatisfiable (positive == and negated != over the SAME V mixed-case values) so the
// candidate loop never early-returns -> the maximal-work case. V mixed-case short
// strings keep the policy within MAX_BYTES while V (the candidate-set size) is huge.
function buildRoleTakeoverCiPolicy(V) {
  const vals = [];
  for (let i = 0; i < V; i++) vals.push(`Aa${i}`);
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'Takeover',
      Effect: 'Allow',
      Action: ['iam:PutRolePolicy', 'iam:UpdateAssumeRolePolicy', 'sts:AssumeRole'],
      Resource: [ANCHOR_ROLE],
      Condition: {
        StringEqualsIgnoreCase: { 'aws:PrincipalAccount': vals },
        StringNotEqualsIgnoreCase: { 'aws:PrincipalAccount': vals },
      },
    }],
  });
}

// V=16000 is ~298KB (well within MAX_BYTES) yet before the fix drove analyze() to
// ~2.4s via the O(V^2) case-insensitive scan; after the fix it is linear (~30ms).
const CI_DOS_V = 16000;
// A per-run work ceiling the V=16000 candidate x constraint scan exceeds but a tiny
// policy does not - witnesses that the (previously uncharged) innermost scan now
// PARTICIPATES in the deterministic budget.
const CI_TIGHT_WORK_LIMIT = 50000;

test('(1b) within-caps case-insensitive role-takeover analyzes BOUNDED (the O(V^2) satisfiability grind is gone), never an unbounded COMPLETE', () => {
  const text = buildRoleTakeoverCiPolicy(CI_DOS_V);
  assert.equal(validate(text).ok, true, 'the case-insensitive role-takeover policy is within every limit');

  const a = analyze(text); // browser style: only the deterministic work budget

  assert.equal(a.ok, true, 'well-formed in-band result');
  // Boundedness / "not O(V^2)" is asserted via the DETERMINISTIC op-count work budget,
  // NOT a wall-clock ceiling. The candidate x constraint scan is charged, so the O(V^2)
  // regression this guards against (V=16000 -> ~2.56e8 units) would exceed the fixed
  // DEFAULT_WORK_LIMIT (6e7) and fail closed (analysisAborted). A run that does NOT abort
  // therefore proves the scan stayed linear, regardless of CPU load - an absolute ms
  // ceiling flaked here under the parallel full-suite run's CPU contention.
  assert.equal(a.coverage.summary.analysisAborted, false, 'linear scan completes within the fixed DEFAULT work budget (an O(V^2) grind would exceed it and abort)');
  // The unsatisfiable takeover chain suppresses ROLE-TAKEOVER, but the two standalone
  // modify primitives are genuine risks and MUST surface - never a clean/empty pass.
  if (!a.coverage.summary.incomplete) {
    assert.ok(a.findings.length >= 1, 'a COMPLETE verdict still carries the standalone modify findings (no fail-open clean pass)');
    assert.ok(a.findings.some((f) => f.id === 'PUT-INLINE-POLICY'), 'the iam:PutRolePolicy risk surfaces');
    assert.ok(a.findings.some((f) => f.id === 'TRUST-POLICY-MODIFY'), 'the iam:UpdateAssumeRolePolicy risk surfaces');
  } else {
    assert.equal(a.findings.length, 0, 'an incomplete verdict asserts no findings (fail closed)');
  }
});

test('(1b) the case-insensitive candidate x constraint scan PARTICIPATES in the work budget -> fails CLOSED at a tight ceiling, never clean', () => {
  const text = buildRoleTakeoverCiPolicy(CI_DOS_V);
  const a = analyze(text, { workLimit: CI_TIGHT_WORK_LIMIT });
  assert.equal(a.ok, true, 'well-formed in-band result');
  assert.equal(a.coverage.summary.analysisAborted, true, 'the now-charged innermost satisfiability scan trips the tight budget (proof it participates)');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'), 'the aborted coverage carries the RESOURCE_BUDGET_EXCEEDED code');
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('(1b) scan() on the case-insensitive role-takeover fails CLOSED under a wall-clock budget -> exit 3, never a clean exit 0', () => {
  const text = buildRoleTakeoverCiPolicy(CI_DOS_V);
  // budgetMs:0 -> deadline at "now" -> chargeWork's `>=` check aborts DETERMINISTICALLY
  // on the first checkpoint the now-charged scan crosses (pre-fix: the scan barely
  // charged, so budgetMs was a no-op and the run returned complete on a runaway).
  const r = scan({ text, family: 'identity', budgetMs: 0 });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a role-takeover runaway must NEVER report a clean exit 0');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the wall-clock deadline fires on the satisfiability path -> exit 3');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.reason, 'RESOURCE_BUDGET_EXCEEDED');
  assert.equal(r.findings.length, 0);
});

test('(1b) scan() on the case-insensitive role-takeover under the DEFAULT budget is bounded exit 1 / FINDINGS (never clean)', () => {
  const text = buildRoleTakeoverCiPolicy(CI_DOS_V);
  const r = scan({ text, family: 'identity' }); // no budgetMs: only the deterministic work budget
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'the standalone modify risks must never report clean');
  assert.equal(r.exitCode, EXIT.FINDINGS, 'the within-caps policy analyzes COMPLETE to exit 1 (findings)');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
});

test('(1b) NO over-correction: a SMALL case-insensitive role-takeover policy stays COMPLETE at the same tight ceiling AND still surfaces its findings', () => {
  const text = buildRoleTakeoverCiPolicy(3);
  assert.equal(validate(text).ok, true);
  const a = analyze(text, { workLimit: CI_TIGHT_WORK_LIMIT });
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small case-insensitive policy does NOT trip even the tight budget (proportional charge, no blanket abort)');
  assert.equal(a.coverage.summary.incomplete, false, 'it reaches a COMPLETE verdict');
  assert.ok(a.findings.some((f) => f.id === 'PUT-INLINE-POLICY'), 'the legitimate standalone modify risk still surfaces (no false negative from the DoS fix)');
  assert.ok(a.findings.some((f) => f.id === 'TRUST-POLICY-MODIFY'), 'the trust-modify risk still surfaces');
});

// ---------------------------------------------------------------------------
// (2) denyActionApplies inner loop now charges per pattern inspected.
// ---------------------------------------------------------------------------

test('(2) denyActionApplies charges the budget per Action pattern - an all-${...} Deny action list is NOT a free path', () => {
  // A Deny whose Action list is entirely policy variables: every pattern hits the
  // `continue` BEFORE actionGrants (the only prior charged call), so pre-fix this loop
  // advanced the budget zero times no matter how long the list. Arm a tight work limit
  // and confirm the charge now trips proportional to the list length.
  const prev = getWorkLimit();
  try {
    // The list length must exceed the work-check interval so the armed ceiling is
    // sampled; each entry is a policy variable that hits `continue` after the new
    // per-pattern charge and never reaches actionGrants.
    const bigVarActions = [];
    for (let i = 0; i < 50000; i++) bigVarActions.push(`svc:Action-\${aws:PrincipalTag/x-${i}}`);
    const denyStmt = { actions: bigVarActions, notActions: [] };
    setWorkLimit(1000); // far below the list length
    let threw = false;
    try {
      denyActionApplies(denyStmt, 's3:GetObject');
    } catch (e) {
      threw = isGlobBudgetError(e);
    }
    assert.equal(threw, true, 'a large all-variable Deny Action list must trip the armed work budget');
  } finally {
    setWorkLimit(prev);
  }
});

test('(2) NO over-correction: a small all-${...} Deny action list does NOT trip a generous budget', () => {
  const prev = getWorkLimit();
  try {
    const denyStmt = {
      actions: ['svc:Action-${aws:username}', 'svc:Other-${aws:PrincipalTag/team}'],
      notActions: [],
    };
    setWorkLimit(1000000);
    let threw = false;
    let result = null;
    try {
      result = denyActionApplies(denyStmt, 's3:GetObject');
    } catch (e) {
      threw = isGlobBudgetError(e);
    }
    assert.equal(threw, false, 'a tiny variable Deny action list must NOT trip a generous budget');
    // All-variable, non-matching -> applies (might match at runtime), uncertain.
    assert.deepEqual(result, { applies: true, certain: false });
  } finally {
    setWorkLimit(prev);
  }
});

// A deny-HEAVY end-to-end analogue: a broad iam:* Allow across many statements plus
// Deny statements whose Action lists are large all-${...} variable sets. The
// escalation engine folds these denies into every matched action of every finding
// (applyDenyToActions -> denyEffectOnAction -> denyActionApplies), so the now-charged
// inner loop makes the whole deny fold participate in the budget rather than running
// free. At scale this fails closed; a small analogue completes.
function buildDenyHeavyPolicy(nAllow, nDeny, varsPerDeny) {
  const statements = [];
  for (let i = 0; i < nAllow; i++) {
    statements.push({
      Sid: `Allow${i}`, Effect: 'Allow', Action: ['iam:*'], Resource: ['*'],
    });
  }
  for (let j = 0; j < nDeny; j++) {
    const acts = [];
    for (let k = 0; k < varsPerDeny; k++) acts.push(`iam:Deny-\${aws:PrincipalTag/t-${j}-${k}}`);
    statements.push({
      Sid: `Deny${j}`, Effect: 'Deny', Action: acts, Resource: ['*'],
    });
  }
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}

// A tight per-run work ceiling used to witness that the (previously uncharged)
// all-${...} Deny action fold now PARTICIPATES in the deterministic budget. The
// bounded caps (<= 1000 statements, <= 10000 actions) mean a deny-heavy policy cannot
// on its own exceed the generous DEFAULT_WORK_LIMIT - the confirmed unbounded blow-up
// is the O(N^3) role-takeover loop above - so the deny-fold participation is shown at
// a tight ceiling that the large all-variable fold exceeds and a small one does not.
const TIGHT_WORK_LIMIT = 5000000;

test('(2) deny-heavy variable-action policy completes BOUNDED at the default budget (never a hang)', () => {
  // 200 broad iam:* Allows x 4 denies x 2400 all-variable actions = a large
  // denyActionApplies traversal, WITHIN caps. Pre-fix the variable-action inner loop
  // charged nothing; the fold must now be bounded and finish well under the ms budget.
  const text = buildDenyHeavyPolicy(200, 4, 2400);
  assert.equal(validate(text).ok, true, 'the deny-heavy policy is within every limit');
  const a = analyze(text);
  assert.equal(a.ok, true);
  // Boundedness asserted via the DETERMINISTIC op-count work budget, NOT a wall-clock
  // ceiling. The deny fold IS charged (the paired tight-ceiling test below trips it), so a
  // run that does NOT hit the work-budget abort proves the charged fold work stayed under
  // the fixed DEFAULT_WORK_LIMIT - an unbounded/hang fold would exceed it and fail closed.
  // This bound is load-independent; an absolute ms ceiling flaked here (deny-heavy took
  // 4149ms) purely from CPU contention under the runner's default file parallelism, not
  // any logic regression. (analysisAborted, not incomplete: this policy is legitimately
  // coverage-incomplete for unrelated reasons - codes:[], no RESOURCE_BUDGET_EXCEEDED.)
  assert.equal(a.coverage.summary.analysisAborted, false, 'the charged deny fold completes within the fixed DEFAULT work budget (bounded op-count, no clock)');
});

test('(2) the all-${...} Deny action fold PARTICIPATES in the work budget -> fails CLOSED at a tight ceiling, never clean', () => {
  const text = buildDenyHeavyPolicy(200, 4, 2400);
  const a = analyze(text, { workLimit: TIGHT_WORK_LIMIT });
  assert.equal(a.ok, true, 'well-formed in-band result');
  assert.equal(a.coverage.summary.analysisAborted, true, 'the charged deny fold trips the tight budget (proof it participates)');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'));
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('(2) NO over-correction: a SMALL deny-heavy variable-action policy stays COMPLETE at the same tight ceiling', () => {
  const text = buildDenyHeavyPolicy(1, 1, 3);
  assert.equal(validate(text).ok, true);
  const a = analyze(text, { workLimit: TIGHT_WORK_LIMIT });
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small variable-Deny policy does NOT trip even the tight budget');
});

// ---------------------------------------------------------------------------
// (3) Action `paths` glob: LINEAR, ReDoS-immune matcher replaces the anchored RegExp.
// ---------------------------------------------------------------------------

test('(3) globMatchPath agrees with globToRegExp on representative path patterns', () => {
  const cases = [
    ['policies/**/*.json', 'policies/a.json', true],
    ['policies/**/*.json', 'policies/x/y/a.json', true],
    ['policies/**/*.json', 'policies/a.txt', false],
    ['src/*.json', 'src/a.json', true],
    ['src/*.json', 'src/nested/a.json', false],
    ['**/*.json', 'a.json', true],
    ['a?c.json', 'abc.json', true],
    ['a?c.json', 'a/c.json', false],
    ['file[0-9].json', 'file7.json', true],
    ['file[0-9].json', 'filex.json', false],
    ['file[!0-9].json', 'filex.json', true],
    ['logs/**', 'logs/a/b/c.txt', true],
    ['readme.md', 'readme.md', true],
  ];
  for (const [pattern, path, expected] of cases) {
    const re = globToRegExp(pattern);
    assert.equal(re.test(path), expected, `regex oracle: ${pattern} vs ${path}`);
    assert.equal(globMatchPath(pattern, path), expected, `linear matcher: ${pattern} vs ${path}`);
  }
});

test('(3) a pathological ReDoS `paths` pattern resolves in LINEAR time (never exponential)', () => {
  // '*a*a*...*b' vs a long all-'a' path with no 'b': the classic catastrophic-
  // backtracking ReDoS for an anchored RegExp of many '[^/]*' quantifiers. The linear
  // matcher decides it in O(tokens x length). It never matches (no 'b'), the maximal-
  // work case. Absolute ceiling: the old anchored RegExp would blow past it by many
  // orders of magnitude at 60 stars.
  const stars = 60;
  const pattern = `${'*a'.repeat(stars)}*b`;
  const longFile = `${'a'.repeat(4000)}.log`;
  const list = [longFile, 'other.json'];

  const t0 = performance.now();
  const { files, error } = resolveFiles([pattern], list);
  const elapsed = performance.now() - t0;

  assert.equal(error && error.reason, 'NO_FILES_MATCHED', 'the pathological pattern matches nothing (no clean pass either)');
  assert.deepEqual(files, []);
  assert.ok(elapsed < BUDGET_MS, `pathological glob resolved in ${elapsed.toFixed(1)}ms (linear); budget ${BUDGET_MS}ms`);
});

test('(3) an over-complex glob (too many wildcards) fails CLOSED to a usage error, never a clean scan', () => {
  const pattern = `${'*a'.repeat(300)}*b`; // > MAX_GLOB_WILDCARDS
  const { files, error } = resolveFiles([pattern], ['a.json']);
  assert.equal(error && error.reason, 'INVALID_GLOB', 'an over-complex pattern is a usage error');
  assert.deepEqual(files, []);
  // globToRegExp is hard-capped too, so the exported RegExp path can never build a
  // catastrophic RegExp from such a pattern.
  assert.throws(() => globToRegExp(pattern), /complexity/i, 'globToRegExp refuses an over-complex pattern');
});

test('(3) runAction on a pathological `paths` input completes bounded and fails CLOSED (never a green pass)', () => {
  const stars = 80;
  const pattern = `${'*a'.repeat(stars)}*b`;
  const longFile = `${'a'.repeat(6000)}.json`;
  const env = { 'INPUT_PATHS': pattern, 'INPUT_FAMILY': 'identity' };
  const io = {
    listFiles: () => [longFile, 'policy.json'],
    readFile: () => '{}',
  };
  const t0 = performance.now();
  const r = runAction({ env, io });
  const elapsed = performance.now() - t0;
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a pathological paths input must NEVER report a clean exit 0');
  assert.ok(elapsed < BUDGET_MS, `runAction on pathological paths returned in ${elapsed.toFixed(1)}ms (bounded); budget ${BUDGET_MS}ms`);
});
