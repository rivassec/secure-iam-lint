// IAM Blast Radius - shared wildcard (glob) matcher (S3-dos-budget).
//
// ONE canonical IAM-wildcard matcher, imported by every engine module that
// compares a policy pattern against a concrete action/resource/service string
// (escalation.js, rules.js, and the family-aware analyzers). Previously several of
// those files kept their OWN byte-identical copy of a greedy two-pointer matcher; copies are a
// maintenance and (worse) a SECURITY hazard - a DoS fix or semantic correction
// has to land in all three or the surfaces drift. This module is the single
// source of truth so a fix lands once.
//
// SEMANTICS (unchanged from the copies it replaces - an IAM wildcard glob):
//   '*'  matches any run of characters, including the empty run.
//   '?'  matches exactly one character.
//   any other character matches itself, literally. There is NO escape character:
//        '$', '{', '}' are ordinary literals here (IAM policy VARIABLES such as
//        ${aws:username} are handled by callers via hasPolicyVariable(), never
//        by this matcher).
//
// COMPLEXITY (the DoS fix, threat-model T5). The problem is a genuine quadratic:
// a pattern with a long literal/'?' run BETWEEN two stars ('*' + run + '*', or the
// suffix form '*' + run) matched against a long text re-scans that run from every
// text offset -> O(n*m). Iteration-1 anchored only the FIRST and LAST '*'-delimited
// segments, which fixed the pure suffix form but left the INTERIOR case ('*' + run +
// '*') exactly as quadratic (findSegFrom re-scanning from every offset). This
// matcher removes the class entirely:
//   - no '*'            -> one length-checked windowed compare (O(m));
//   - prefix + suffix   -> anchor the first segment at the start and the last at
//                          the end, each a single windowed compare (O(m));
//   - interior segments -> found left-to-right at their EARLIEST occurrence using a
//                          bit-parallel Shift-And automaton (Baeza-Yates/Gonnet)
//                          that consumes each text position EXACTLY ONCE and never
//                          re-scans an offset. Cost is O((run + window) * ceil(run/w))
//                          which, with the per-string cap (validate.js
//                          MAX_STRING_LENGTH), is effectively linear - the interior
//                          quadratic is gone.
// Greedy leftmost placement of the interior segments is a correct recognizer for
// this glob language (each '*' absorbs an arbitrary gap, so the earliest placement
// of an interior segment never precludes a later segment's match), so the result is
// byte-identical to the greedy two-pointer matcher it replaces for every input.
//
// DEFENSE IN DEPTH: this is paired with a per-string length cap in validate.js
// (LIMITS.MAX_STRING_LENGTH) so a single Action/Resource token can never be more
// than a few KB, and with cooperative BUDGETS (below):
//   - a DETERMINISTIC WORK budget (an op-count ceiling) that BOTH the browser and
//     the Node adapters arm. Because it counts WORK, not wall-clock, it is
//     deterministic (architecture invariant 8: same input -> same result) yet it
//     still bounds a pathological call-count explosion (the nested deny-coverage
//     loops can call the matcher a huge number of times even when each call is
//     cheap). analyze() arms it by default so the browser/worker path can NEVER
//     return a COMPLETE verdict after an unbounded run - it fails CLOSED to an
//     "analysis aborted (resource budget)" incomplete state instead.
//   - an OPTIONAL WALL-CLOCK deadline the Node CLI/Action arm (armGlobBudget) for a
//     real time ceiling. It is sampled on a cadence tied to WORK DONE (not to raw
//     matcher-call count), so a run whose cost concentrates in a few expensive calls
//     is still bounded to ~one check-interval of extra work past the deadline. When
//     disarmed, no clock is ever read, so the browser path stays deterministic.
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. Deterministic
// under the work budget (which is an op count, not a clock); the wall-clock
// deadline is opt-in and only the Node adapters ever arm it.

// --- Cooperative budgets (opt-in; OFF by default) ----------------------------
// The engine analysis is synchronous and CPU-bound, so a caller cannot preempt it
// from the outside in single-threaded JS. Two independent ceilings can be armed:
//
//   budgetDeadline  absolute Date.now()-style timestamp (wall-clock). Set by the
//                   Node adapters (cli/scan.mjs) via armGlobBudget(). NON-
//                   deterministic by nature, so the browser NEVER sets it.
//   workLimit       a deterministic ceiling on accumulated WORK UNITS (char
//                   compares / automaton word-steps). Set by analyze() (browser +
//                   Node) so a runaway is bounded even with no clock.
//
// Both default to Infinity (disarmed). While disarmed, the matcher never touches
// the clock or the counter, so it is exactly the deterministic default.
let budgetDeadline = Infinity;
let workLimit = Infinity;

// Accumulated work since the budget was (re)armed, and the next work checkpoint.
// The clock + limit are only tested when accumulated work crosses a checkpoint,
// so both ceilings are sampled on a cadence tied to WORK DONE rather than to the
// number of matcher calls. This is the fix for the coarse "once per 1024 calls"
// sampling: cost that concentrates in a few expensive calls is now still checked
// frequently (every WORK_CHECK_INTERVAL units of actual work), so a wall-clock
// budget of B ms actually bounds runtime to ~B ms plus one interval of work.
let workDone = 0;
let nextWorkCheck = 0;
const WORK_CHECK_INTERVAL = 1 << 15; // 32768 work units between clock/limit checks

// The error thrown when an armed budget is exceeded. A distinct, tagged shape so
// analyze()/scan() can tell it apart from a genuine internal fault and map it to the
// specific fail-closed "aborted (resource budget)" verdict. `kind` distinguishes the
// deterministic WORK ceiling ('work' -> analyze() converts it to a graceful in-band
// incomplete result) from the wall-clock deadline ('clock' -> analyze() re-throws so
// the Node adapter reports its timing-dependent RESOURCE_BUDGET_EXCEEDED verdict).
export class GlobBudgetError extends Error {
  constructor(kind, message) {
    super(message || 'analysis aborted (resource budget)');
    this.name = 'GlobBudgetError';
    this.code = 'RESOURCE_BUDGET_EXCEEDED';
    this.kind = kind === 'clock' ? 'clock' : 'work';
  }
}

export function isGlobBudgetError(e) {
  return !!(e && (e instanceof GlobBudgetError || e.code === 'RESOURCE_BUDGET_EXCEEDED'));
}

/**
 * Arm the cooperative WALL-CLOCK budget. `deadlineEpochMs` is an absolute
 * Date.now()-style timestamp; once accumulated work crosses a checkpoint at or past
 * it, the matcher throws a GlobBudgetError({kind:'clock'}). A deadline already at or
 * before "now" aborts on the very first checkpoint DETERMINISTICALLY (chargeWork
 * compares with `>=`), so arming Date.now()+budgetMs for budgetMs<=0 always fails
 * closed rather than racing on whether a millisecond elapses first (used by tests to
 * force the path). Resets the work counter but does NOT touch a work limit an
 * enclosing analyze() may have armed. Caller MUST pair with disarmGlobBudget() in a
 * finally block.
 */
export function armGlobBudget(deadlineEpochMs) {
  budgetDeadline = typeof deadlineEpochMs === 'number' ? deadlineEpochMs : Infinity;
  workDone = 0;
  nextWorkCheck = 0;
}

// Disarm the WALL-CLOCK budget (back to clock-free). Leaves any armed work limit in
// place (analyze() owns that via setWorkLimit and restores it itself).
export function disarmGlobBudget() {
  budgetDeadline = Infinity;
  workDone = 0;
  nextWorkCheck = 0;
}

/**
 * Set the deterministic WORK ceiling (an op-count, not a clock). Returns nothing;
 * pair with the value returned by getWorkLimit() to restore. `limit` <= 0 forces an
 * abort on the first charge (test hook); Infinity disables it. Resets the work
 * counter so the ceiling measures work done from this point.
 */
export function setWorkLimit(limit) {
  workLimit = (typeof limit === 'number') ? limit : Infinity;
  workDone = 0;
  nextWorkCheck = 0;
}

export function getWorkLimit() {
  return workLimit;
}

/**
 * Run `fn` with BOTH cooperative budgets temporarily disarmed, then restore the
 * exact prior budget state (deadline, work limit, and the running counters) in a
 * finally. Returns fn()'s result.
 *
 * This is for BOUNDED, post-analysis bookkeeping that legitimately calls the shared
 * matcher a fixed, tiny number of times (e.g. masked-grant.js testing a Resource
 * value against the fixed probe battery during coverage enrichment) and must be
 * INERT with respect to the enclosing analyze() budget: it must neither (a) charge
 * work that could push a borderline-but-completing analysis over its work ceiling
 * (a spurious abort / over-correction), nor (b) re-throw the budget sentinel when it
 * runs AFTER an analysis has ALREADY aborted (the deadline/limit is in the past, so
 * even one tiny match would throw). Disarming for the duration makes chargeWork a
 * no-op, so the call is deterministic and side-effect-free on the budget.
 */
export function withoutBudget(fn) {
  const savedDeadline = budgetDeadline;
  const savedLimit = workLimit;
  const savedDone = workDone;
  const savedNext = nextWorkCheck;
  budgetDeadline = Infinity;
  workLimit = Infinity;
  try {
    return fn();
  } finally {
    budgetDeadline = savedDeadline;
    workLimit = savedLimit;
    workDone = savedDone;
    nextWorkCheck = savedNext;
  }
}

// Charge `n` units of work and, when accumulated work crosses the next checkpoint,
// test both ceilings. Cheap in the common (disarmed) case: a single comparison and
// early return. When armed, an integer add plus an occasional checkpoint test.
//
// EXPORTED (S3-dos-budget iter-3) so engine modules can charge the budget for a
// traversal step that does NOT reach the matcher. The DoS class was: a nested
// deny-coverage loop (escalation.js) short-circuits globMatch when a Deny resource
// is an IAM policy variable (${...}), so the whole O(findings x actions x denies x
// resources) scan accrued ZERO work and analyze()'s work budget - sampled only
// inside chargeWork - never tripped; a runaway returned a COMPLETE verdict. Callers
// charge one unit per real comparison they perform (matcher-reached or not) so the
// deterministic budget bounds the traversal itself, not just the matcher calls.
export function chargeWork(n) {
  if (workLimit === Infinity && budgetDeadline === Infinity) return; // disarmed
  workDone += n;
  if (workDone >= nextWorkCheck) {
    nextWorkCheck = workDone + WORK_CHECK_INTERVAL;
    // Deterministic work ceiling first (browser + Node backstop).
    if (workDone > workLimit) throw new GlobBudgetError('work');
    // Wall-clock deadline second (Node adapters only; never armed on the browser).
    // Uses `>=` (deadline REACHED, not strictly exceeded) so a deadline set at or
    // before the sampled instant aborts DETERMINISTICALLY on the first checkpoint,
    // instead of hinging on whether >=1ms happens to elapse between arming and the
    // first charge. That race made a zero-budget arm (armGlobBudget(Date.now()+0),
    // as scan()/the Action pass for budgetMs<=0) a coin flip under load: a small
    // policy would intermittently fail CLOSED (exit 3) when the checkpoint sampled a
    // millisecond later, and complete otherwise. A budget's deadline is a wall it may
    // not cross, so reaching it is exhaustion -> abort. Positive budgets are unaffected
    // except at the exact-equal instant (a measure-zero boundary that is already
    // "budget exhausted"), keeping fast policies well within a generous budget.
    if (budgetDeadline !== Infinity && Date.now() >= budgetDeadline) {
      throw new GlobBudgetError('clock');
    }
  }
}

// --- Matcher internals -------------------------------------------------------

// Does literal/`?` segment `seg` match text `t` at offset `at`? Caller guarantees
// at + seg.length <= t.length. '?' matches any single char; every other char is
// literal. Charges its (bounded) comparison work up front so an armed budget is
// sampled even inside a single large anchored compare.
function segMatchesAt(t, seg, at) {
  const L = seg.length;
  chargeWork(L);
  for (let k = 0; k < L; k++) {
    const c = seg[k];
    if (c !== '?' && c !== t[at + k]) return false;
  }
  return true;
}

// Find the EARLIEST index i in [from, maxStart] where `seg` (literals + '?') occurs
// in `t`, or -1. Linear, offset-once via a bit-parallel Shift-And automaton
// (Baeza-Yates/Gonnet), so no text offset is ever re-scanned - this is what kills
// the interior quadratic. '?' is handled natively (a position that matches every
// character). BigInt state keeps the automaton correct for any segment length
// without manual multi-word bookkeeping.
//
// An empty segment matches at `from` (length 0), preserving the old findSegFrom
// contract for consecutive '*' in a pattern.
function findSegEarliest(t, seg, from, maxStart) {
  const L = seg.length;
  if (L === 0) return from <= maxStart ? from : -1;
  if (from > maxStart) return -1;

  // Build the per-character position masks once (bit j set = seg[j] is this char),
  // plus a shared "matches any char" mask for '?'. O(L) BigInt work, charged.
  chargeWork(L);
  const charMask = new Map(); // charCode -> BigInt of positions
  let qMask = 0n;
  for (let j = 0; j < L; j++) {
    const ch = seg[j];
    const bit = 1n << BigInt(j);
    if (ch === '?') {
      qMask |= bit;
    } else {
      const cc = seg.charCodeAt(j);
      charMask.set(cc, (charMask.get(cc) || 0n) | bit);
    }
  }
  const matchBit = 1n << BigInt(L - 1);

  // Scan text positions [from .. min(t.length-1, maxStart+L-1)]. D holds the set of
  // active partial-match end positions; injecting bit 0 (| 1n) each step lets a new
  // match begin at any position, so the first time matchBit sets is the EARLIEST
  // occurrence with start >= from and start <= maxStart. Each step is O(ceil(L/64))
  // BigInt work, charged so an armed budget is sampled proportionally to real cost.
  const upper = Math.min(t.length - 1, maxStart + L - 1);
  const step = 1 + (L >> 6);
  let D = 0n;
  for (let i = from; i <= upper; i++) {
    chargeWork(step);
    const cc = t.charCodeAt(i);
    const B = (charMask.get(cc) || 0n) | qMask;
    D = (((D << 1n) | 1n) & B);
    if ((D & matchBit) !== 0n) {
      return i - L + 1;
    }
  }
  return -1;
}

/**
 * Match an IAM wildcard pattern against a literal string.
 *
 * @param {string} pattern  wildcard pattern ('*' any run, '?' one char, else literal)
 * @param {string} text     concrete string to test
 * @returns {boolean}
 */
export function globMatch(pattern, text) {
  const p = String(pattern);
  const t = String(text);
  const tn = t.length;
  // Charge the up-front cost (the split allocation + a base amount) so even a
  // trivial call advances the budget counter - this is what makes a deadline that
  // is already in the past (or a work limit <= 0) abort on the first matcher call.
  chargeWork(p.length + tn + 1);

  // Decompose on '*' into anchored segments.
  const segs = p.split('*');

  // No wildcard: an exact, length-matched windowed compare.
  if (segs.length === 1) {
    return segs[0].length === tn && segMatchesAt(t, segs[0], 0);
  }

  const first = segs[0];
  const last = segs[segs.length - 1];

  // Prefix and suffix must both fit without overlapping.
  if (first.length + last.length > tn) return false;
  // Anchor the first segment at the start...
  if (!segMatchesAt(t, first, 0)) return false;
  // ...and the last segment at the end.
  if (!segMatchesAt(t, last, tn - last.length)) return false;

  // Interior segments (if any) are placed left-to-right at their earliest match,
  // each within the window between the consumed prefix and the reserved suffix. The
  // '*' between segments absorbs any gap, so earliest placement never precludes a
  // later match (correct greedy recognizer for this glob language).
  let cursor = first.length;
  const maxEnd = tn - last.length;
  for (let s = 1; s < segs.length - 1; s++) {
    const seg = segs[s];
    const pos = findSegEarliest(t, seg, cursor, maxEnd - seg.length);
    if (pos < 0) return false;
    cursor = pos + seg.length;
  }
  return true;
}

export default globMatch;
