// IAM Blast Radius - headless scan adapter (Phase 15, story P15-scan).
//
// A CALLABLE, deterministic, Node-only ADAPTER around the shipped browser engine.
// It imports the engine READ-ONLY (never mutates it, never changes analysis
// behavior) and translates the engine's EXISTING fail-closed signals into a
// single structured result plus the load-bearing exit-code contract.
//
// This module is NOT part of the browser-served engine graph: nothing here is
// imported by content/tools/iam-blast-radius/{engine,app.js,worker.js}. It may
// therefore be Node-oriented, but it deliberately uses NO Node built-ins, no
// network, no eval, and no dynamic import - it is a pure function over its input
// so it can be unit-tested under `node --test` and reused by the CLI + the
// GitHub Action wrapper without a process boundary.
//
// FAIL CLOSED is the whole point: "unknown / unsupported / malformed / could-not-
// analyze" are EXPLICIT states that map to analysisStatus 'partial'|'failed' and
// exit code 3 - they NEVER collapse to 'complete' + exit 0. There is no
// --ignore-unknown escape hatch and no family auto-detection: a missing/auto
// family is a usage error (exit 2), and every other engine fail-closed signal is
// exit 3.
//
// Exit-code contract (mirrors docs/sarif-cli-design.md):
//   0  analyzed, no findings at/above threshold        (analysisStatus complete)
//   1  analyzed, findings at/above threshold           (analysisStatus complete)
//   2  usage/config error (missing/empty input, missing/auto family)
//   3  fail-closed could-not-analyze                   (analysisStatus partial|failed)
//   4  internal invariant error
// A CI gate treats 1,2,3,4 as FAILED. Code 3 is DISTINCT from 0 and from 1.

// READ-ONLY import of the shipped browser engine. The engine is the single source
// of analysis truth (architecture invariant: one engine, two adapters); this
// module derives its verdict from what the engine already reports.
import { analyze } from '../content/tools/iam-blast-radius/engine/analyze.js';
// The cooperative wall-clock budget (S3-dos-budget). analyze() is synchronous and
// CPU-bound, so it cannot be preempted from outside in single-threaded JS. Instead
// this adapter ARMS an absolute deadline that the engine's hot wildcard matcher
// (engine/glob.js) checks cheaply; on overrun it throws a tagged sentinel that we
// catch here and turn into a graceful fail-closed "analysis aborted" verdict - never
// a clean pass. The browser/worker path never arms this (it has its own T5 worker
// watchdog), so browser analysis stays deterministic.
import { armGlobBudget, disarmGlobBudget, isGlobBudgetError } from '../content/tools/iam-blast-radius/engine/glob.js';

// Stable exit codes. Frozen so a caller can reference them by name without risk of
// mutation.
export const EXIT = Object.freeze({
  CLEAN: 0,
  FINDINGS: 1,
  USAGE: 2,
  FAIL_CLOSED: 3,
  INTERNAL: 4,
});

// analysisStatus is a THREE-STATE machine-readable verdict. `complete` is the
// only value that may map to a passing exit code (0/1); everything else fails
// closed (exit 3, or 4 for an internal invariant error).
export const ANALYSIS_STATUS = Object.freeze({
  COMPLETE: 'complete',
  PARTIAL: 'partial',
  FAILED: 'failed',
});

// Analyzer-state categories for the individual fail-closed reasons carried in
// `analysisStates`. Kept coarse + stable so the SARIF adapter (P15-sarif) can map
// them to analysis-state results without re-deriving them.
export const ANALYSIS_STATE = Object.freeze({
  MALFORMED: 'malformed',     // input rejected before/at model build (parse/schema/limits)
  UNSUPPORTED: 'unsupported', // recognized shape the engine will not evaluate (family gate)
  INCOMPLETE: 'incomplete',   // analyzed a subset; unsupported elements/actions/conditions
  UNKNOWN: 'unknown',         // a finding whose viability could not be established
  INTERNAL: 'internal',       // an internal invariant error (should never happen)
});

// Severity order, most-severe first. Local copy (not imported) so the threshold
// contract is owned by the adapter and cannot drift if the engine's presentation
// order ever changes. Mirrors engine SEVERITY_ORDER.
const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

// Threshold tokens accepted by the exit-code gate. 'none' is a sentinel meaning
// "no finding is ever blocking" - it can only ever suppress the 1-vs-0 decision
// for an already-COMPLETE analysis; it can NEVER downgrade a fail-closed 3.
const THRESHOLDS = Object.freeze(['critical', 'high', 'medium', 'low', 'info', 'none']);

const DEFAULT_THRESHOLD = 'high';

// Default wall-clock budget (ms) for one policy's analysis when a caller does not
// specify one. Real analyses finish in single-digit milliseconds even on a
// cap-sized policy (MAX_STATEMENTS x MAX_ACTIONS, per-string-capped, linear
// matcher), so a multi-second ceiling never trips a legitimate run yet bounds a
// pathological one. The CLI/Action pass this (or a caller override) through
// input.budgetMs; a run that exceeds it fails CLOSED with RESOURCE_BUDGET_EXCEEDED
// (exit 3), never a clean pass. budgetMs<=0 forces immediate abort on the first
// matcher call (used by tests to exercise the path deterministically). Omit
// budgetMs entirely (undefined) to disable the budget and keep scan() clock-free.
export const DEFAULT_BUDGET_MS = 10000;

// Family selection tokens this adapter accepts. Deliberately DOES NOT include
// 'auto' / 'auto-detect': the CI contract forbids family auto-detection, so an
// auto selection is a usage error here even though the engine itself supports it.
// Canonical families + the recognized synonyms the engine canonicalizes. A token
// outside this set is a usage error (exit 2) - the caller named a family that does
// not exist - rejected before the engine runs, distinct from a valid family whose
// document the engine cannot analyze (exit 3).
export const SELECTABLE_FAMILIES = Object.freeze(new Set([
  'identity', 'resource', 'role-trust', 'permissions-boundary', 'scp-rcp', 'session',
  // engine-recognized synonyms (family.js FAMILY_ALIASES)
  'scp', 'rcp', 'trust',
]));

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

// The recognized AWS partition set. Load-bearing for the fail-closed
// unconfirmed-partition guard: account ids do NOT encode partition, so a
// cross-partition PassRole demotion is only trustworthy when the caller supplied a
// REAL partition. An unrecognized token ("zzz", "banana", "AWS", "a", ".") must
// NEVER be trusted as a confident partition assertion - it is treated as NOT
// provided (see the partition handling in scan), so the demoted finding fails
// closed exactly like the unconfirmed-account path instead of slipping under the
// threshold. Matched case-sensitively against the canonical lowercase ARN tokens;
// a case variant is conservatively treated as unrecognized (fails closed, never
// opens). Mirrors the engine's ARN partition tokens.
const KNOWN_PARTITIONS = Object.freeze(new Set([
  'aws', 'aws-us-gov', 'aws-cn',
  'aws-iso', 'aws-iso-b', 'aws-iso-e', 'aws-iso-f',
]));

// NOTE (IAM-1508, S2-guard-parity): the empty-NotAction / empty-NotResource
// complement, malformed-condition-value, and suppressed ForAnyValue never-match
// guards NO LONGER live here. They were adapter-only re-parses of the raw text -
// a drift hazard, since the browser path (analyze()) never saw them. Detection now
// lives in the SHARED engine (engine/masked-grant.js -> coverage.summary.maskedGrants),
// so BOTH surfaces observe the same masked-grant states from one source. This adapter
// reads that coverage below (step 4b) and translates it into the fail-closed verdict;
// it never re-parses the policy text, so the two surfaces cannot diverge.
// Does a finding severity sit at or above the configured threshold? 'none' never
// matches. An unknown severity token is conservatively treated as NOT below the
// floor only when threshold is a real severity - but since the engine only emits
// the five known severities, an unrecognized token simply does not count.
function meetsThreshold(severity, threshold) {
  if (threshold === 'none') return false;
  const ti = SEVERITIES.indexOf(threshold);
  const si = SEVERITIES.indexOf(String(severity));
  if (ti === -1 || si === -1) return false;
  return si <= ti; // lower index = more severe
}

// Does a finding carry a PassRole PARTITION_MISMATCH demotion? The engine records
// this warning code when a concrete cross-partition role is judged not-viable
// against the subject's partition. That verdict is only trustworthy when the
// caller actually supplied the partition: account ids do NOT encode partition, so
// a subject that is really in aws-us-gov/aws-cn (same account id) would make the
// path fully viable. When partition was NOT explicitly provided the engine
// defaults it to 'aws' and renders a confident "not viable" that is really
// UNKNOWN - exactly the fail-open where a demoted (critical->medium) finding
// slips under a 'high' threshold and reports a clean pass.
function hasPartitionMismatch(f) {
  const esc = f && f.escalation;
  return !!(esc && Array.isArray(esc.warningCodes) && esc.warningCodes.includes('PARTITION_MISMATCH'));
}

// The required-unknowns a finding depends on, given whether the caller explicitly
// supplied a partition. Extends the engine's own escalation.requiredUnknowns with
// 'subjectPartition' when a PARTITION_MISMATCH was derived against a DEFAULTED
// partition (the engine assumed 'aws' and never recorded the unknown).
function unknownViabilityReasons(f, partitionProvided) {
  const esc = f && f.escalation;
  const reqs = (esc && Array.isArray(esc.requiredUnknowns)) ? esc.requiredUnknowns.slice() : [];
  if (!partitionProvided && hasPartitionMismatch(f) && !reqs.includes('subjectPartition')) {
    reqs.push('subjectPartition');
  }
  return reqs;
}

// A finding whose exploitability/viability the engine could not establish. The
// canonical signal is escalation.requiredUnknowns (e.g. ['subjectAccount'] when a
// PassRole path pins a concrete account but the subject account was not supplied,
// which CAPS exploitability to low and would otherwise slip under a 'high'
// threshold and report a clean pass - the exact fail-open this guards). Also
// honors any explicit 'unknown' certainty/viability marker defensively, AND an
// unconfirmed-partition PARTITION_MISMATCH (see hasPartitionMismatch): a
// not-viable verdict computed against a DEFAULTED partition is genuinely unknown,
// so it fails closed exactly like the unconfirmed-account path rather than
// collapsing to a clean pass.
function findingHasUnknownViability(f, partitionProvided) {
  if (!f || typeof f !== 'object') return false;
  const esc = f.escalation;
  if (esc && Array.isArray(esc.requiredUnknowns) && esc.requiredUnknowns.length > 0) return true;
  if (esc && esc.viability === 'unknown') return true;
  if (f.viability === 'unknown') return true;
  if (f.certainty === 'unknown') return true;
  if (!partitionProvided && hasPartitionMismatch(f)) return true;
  return false;
}

// Human-readable message for a masked-grant analyzer-state code (IAM-1508). The
// engine detects the shape and carries its code + JSON path on coverage; the
// message is presentation only and lives with the adapter that renders it.
const MASKED_GRANT_MESSAGES = Object.freeze({
  EMPTY_NOTACTION_COMPLEMENT:
    'An Allow statement uses NotAction with an empty complement ([]), which under ' +
    'AWS semantics excludes nothing and therefore grants EVERY action (a full-admin ' +
    'grant). The analyzer cannot faithfully model this shape, so the policy fails ' +
    'closed rather than reporting a clean pass.',
  EMPTY_NOTRESOURCE_COMPLEMENT:
    'An Allow statement uses NotResource with an empty complement ([]), which under ' +
    'AWS semantics excludes nothing and therefore applies to EVERY resource (the same ' +
    'broad scope as Resource "*"). The analyzer models this as no resource scope and ' +
    'does not fire its wildcard-resource finding, so the policy fails closed rather ' +
    'than reporting a clean pass.',
  MALFORMED_CONDITION_VALUE:
    'A Condition value array carries a non-string element (an object, array, or null). ' +
    'AWS rejects this as MalformedPolicyDocument, and the analyzer silently drops the ' +
    'element - so it cannot faithfully model the statement. The policy fails closed ' +
    'rather than reporting a clean pass.',
  SUPPRESSED_NEVER_MATCH_ALLOW:
    'An Allow statement is suppressed as a never-match by an empty ForAnyValue ' +
    'condition value ([]), which under AWS semantics can never match and so grants ' +
    'nothing. A full grant neutralized this way is reported as an analyzer-state ' +
    'rather than a silent clean pass (suppressed does NOT mean the grant was safe).',
  MALFORMED_CONDITION_BLOCK:
    'A Condition operator block (e.g. StringEquals) is not an object mapping a ' +
    'condition key to value(s) - it is a string, number, null, or array. AWS rejects ' +
    'this as MalformedPolicyDocument, and the analyzer drops the block and evaluates ' +
    'the statement as UNCONDITIONAL, silently discarding the restriction. The policy ' +
    'fails closed rather than reporting a clean pass.',
  UNSPECIFIED_RESOURCE_SCOPE:
    'An identity Allow statement names an Action but omits both Resource and ' +
    'NotResource, so its resource scope is UNSPECIFIED. AWS requires a Resource ' +
    'element here; with neither key the analyzer reads the scope as narrow and ' +
    'suppresses its wildcard-resource / data-exfil findings. The policy fails closed ' +
    'rather than reporting a clean pass.',
  MALFORMED_RESOURCE_ARN:
    'An Allow statement carries a Resource (or NotResource) value that is neither ' +
    '"*" nor an ARN. The AWS IAM grammar requires a Resource element to be "*" or an ' +
    'ARN, so AWS rejects this as MalformedPolicyDocument and the analyzer cannot ' +
    'decide what the value scopes - a suffix/infix glob (e.g. "*.pem") or a bare ' +
    'literal would otherwise read as a narrow scope and let a bulk read pass clean. ' +
    'The policy fails closed rather than reporting a clean pass.',
});

function maskedGrantMessage(code) {
  return MASKED_GRANT_MESSAGES[code]
    || 'A masked grant was detected; the policy fails closed rather than reporting a clean pass.';
}

function state(analysisState, code, message, extra) {
  return Object.freeze({
    analysisState,
    code: code || null,
    message: message || null,
    path: (extra && extra.path != null) ? String(extra.path) : null,
    ...(extra && extra.details ? { details: extra.details } : {}),
  });
}

// Build the analyzer-state list from an enriched coverage object's `summary`
// (present on every ok:true engine result). Each unsupported semantic input the
// engine already surfaced becomes one INCOMPLETE analyzer-state. Deterministic.
function incompleteStatesFromCoverage(coverage) {
  const out = [];
  const s = coverage && coverage.summary;
  if (!s) return out;

  for (const el of (s.unsupportedElements || [])) {
    out.push(state(
      ANALYSIS_STATE.INCOMPLETE,
      el.code || 'UNSUPPORTED_ELEMENT',
      el.hazardMessage || `Recognized-but-unmodeled element: ${el.element}.`,
      { path: el.path },
    ));
  }
  if ((s.unrecognizedActions || []).length > 0) {
    out.push(state(
      ANALYSIS_STATE.INCOMPLETE,
      'UNKNOWN_ACTION',
      'One or more actions are not recognized by the action-catalog snapshot, so ' +
        'the analysis could not fully vouch for those grants (unsupported does NOT ' +
        'mean safe).',
      { details: { actions: s.unrecognizedActions.slice() } },
    ));
  }
  if ((s.unsupportedConditions || []).length > 0) {
    out.push(state(
      ANALYSIS_STATE.INCOMPLETE,
      'UNSUPPORTED_CONDITION',
      'One or more condition keys are not modeled by the analyzer, so it could not ' +
        'reason about part of the request-context gating.',
      { details: { conditions: s.unsupportedConditions.slice() } },
    ));
  }
  for (const m of (s.actionResourceMismatches || [])) {
    out.push(state(
      ANALYSIS_STATE.INCOMPLETE,
      m.code || 'ACTION_RESOURCE_TYPE_MISMATCH',
      m.note || 'An action operates on a resource type the supplied ARN cannot identify.',
      { details: { statementIndex: m.statementIndex, actions: (m.actions || []).slice() } },
    ));
  }
  if (s.trustDeny && s.trustDeny.unmodeled) {
    out.push(state(
      ANALYSIS_STATE.INCOMPLETE,
      'TRUST_DENY_UNMODELED',
      s.trustDeny.note || 'A same-policy trust Deny could not be fully modeled.',
    ));
  }
  if (s.resourceContext && s.resourceContext.incomplete) {
    out.push(state(
      ANALYSIS_STATE.INCOMPLETE,
      'RESOURCE_ANALYSIS_INCOMPLETE',
      s.resourceContext.note ||
        'Resource policy accepted, but service-specific resource rules are not yet ' +
        'implemented (zero findings does NOT mean safe).',
    ));
  }
  return out;
}

// Analyzer-state list for a family-gate BLOCK (engine ok:true, coverage.blocked).
// Every blocking code becomes one UNSUPPORTED analyzer-state carrying the exact
// JSON path the engine reported.
function blockedStates(coverage) {
  const codes = (coverage && Array.isArray(coverage.blockingCodes)) ? coverage.blockingCodes : [];
  return codes.map((b) => state(
    ANALYSIS_STATE.UNSUPPORTED,
    b && b.code,
    b && b.message,
    { path: b && b.path, ...(b && b.hazard ? { details: { hazard: true } } : {}) },
  ));
}

// Analyzer-state list for an engine ok:false result. An INTERNAL invariant error
// is separated (exit 4); every other error is a MALFORMED/rejected input (exit 3).
function errorStates(errors) {
  const list = Array.isArray(errors) ? errors : [];
  const internal = list.some((e) => e && e.code === 'INTERNAL');
  const kind = internal ? ANALYSIS_STATE.INTERNAL : ANALYSIS_STATE.MALFORMED;
  const states = list.map((e) => state(kind, e && e.code, e && e.message, { path: e && e.path }));
  return { internal, states };
}

/**
 * Build a usage/config-error result (exit 2). Never analyzes.
 */
function usageError(reason, message) {
  return Object.freeze({
    analysisStatus: ANALYSIS_STATUS.FAILED,
    analysisStates: Object.freeze([state(ANALYSIS_STATE.MALFORMED, reason, message)]),
    findings: Object.freeze([]),
    blockingCount: 0,
    findingsCount: 0,
    exitCode: EXIT.USAGE,
    reason,
    message,
    family: null,
    coverage: null,
    engineOk: false,
  });
}

/**
 * Run a headless, fail-closed scan of one policy document.
 *
 * Pure and deterministic: same input -> same result, every call. Never throws
 * (an unexpected throw is caught and mapped to an INTERNAL exit 4, never 0).
 *
 * @param {object} input
 * @param {string} input.text       raw policy JSON text (required, non-empty)
 * @param {string} input.family     REQUIRED explicit family (no auto-detection)
 * @param {string} [input.subjectAccount] AWS account id for PassRole viability
 * @param {string} [input.partition]      AWS partition (default 'aws')
 * @param {string} [input.threshold]      min blocking severity (default 'high')
 * @param {number} [input.budgetMs]        wall-clock budget for analysis in ms. When
 *   a finite number, the analysis fails CLOSED (exit 3, RESOURCE_BUDGET_EXCEEDED) if
 *   it overruns; <=0 aborts immediately (test hook). Omit to disable (clock-free).
 * @returns {Readonly<{analysisStatus:string, analysisStates:ReadonlyArray<object>,
 *   findings:ReadonlyArray<object>, blockingCount:number, exitCode:number,
 *   reason:string, family:(string|null), coverage:(object|null)}>}
 */
export function scan(input) {
  const inp = input || {};

  // --- 1. Adapter-owned usage/config validation (exit 2). ---------------------
  // These are config errors the adapter can reject WITHOUT running analysis; they
  // must never reach the engine as an implicit "analyze anyway".
  if (!isNonEmptyString(inp.text)) {
    return usageError('MISSING_INPUT', 'No policy text supplied (input is missing or empty).');
  }

  // Whether the caller EXPLICITLY supplied a RECOGNIZED partition. Load-bearing for
  // the fail-closed gate: an unconfirmed (or bogus) partition cannot be used to
  // demote a finding to a confident "not viable" (see findingHasUnknownViability).
  // A non-empty but UNRECOGNIZED token ("zzz", "banana", "AWS", ...) is treated as
  // NOT provided - the engine defaults to 'aws' and the unconfirmed-partition guard
  // fires - so a garbage partition can never be trusted as a confident assertion
  // that slips a demoted finding under the threshold. This mirrors how the engine
  // treats an invalid subjectAccount (CONCRETE_ACCOUNT_ID_RE) as absent, and how
  // this adapter validates threshold/family against allow-lists.
  const partitionToken = isNonEmptyString(inp.partition) ? inp.partition.trim() : null;
  const validPartition = (partitionToken && KNOWN_PARTITIONS.has(partitionToken)) ? partitionToken : null;
  const partitionProvided = validPartition !== null;

  const threshold = isNonEmptyString(inp.threshold) ? inp.threshold.trim().toLowerCase() : DEFAULT_THRESHOLD;
  if (!THRESHOLDS.includes(threshold)) {
    return usageError(
      'INVALID_THRESHOLD',
      `Unknown threshold "${inp.threshold}". Use one of: ${THRESHOLDS.join(', ')}.`,
    );
  }

  if (!isNonEmptyString(inp.family)) {
    // MISSING family is a usage error - the family is NEVER auto-detected.
    return usageError(
      'MISSING_FAMILY',
      'A policy family is required (identity, resource, role-trust, ' +
        'permissions-boundary, scp-rcp, or session). This tool does not auto-detect ' +
        'the family.',
    );
  }
  const familyToken = inp.family.trim();
  const familyLower = familyToken.toLowerCase();
  if (familyLower === 'auto' || familyLower === 'auto-detect') {
    // Auto-detection is explicitly refused by the CI contract, even though the
    // engine itself supports it. Treat it as a usage error, not a silent detect.
    return usageError(
      'AUTO_FAMILY_REFUSED',
      'Family auto-detection is not permitted. Select an explicit policy family.',
    );
  }
  if (!SELECTABLE_FAMILIES.has(familyLower)) {
    // An unrecognized family VALUE is a usage error (exit 2): the caller named a
    // family that does not exist. This is distinct from a valid family whose
    // document the engine cannot analyze (exit 3), and is consistent with a
    // missing family also being a usage error.
    return usageError(
      'UNKNOWN_FAMILY',
      `Unknown policy family '${familyToken}' (expected one of: identity, ` +
        'resource, role-trust, permissions-boundary, scp-rcp, session).',
    );
  }

  // --- 2. Run the engine READ-ONLY. ------------------------------------------
  // requireExplicitFamily is set so the engine also refuses to guess. The family
  // token is already validated against SELECTABLE_FAMILIES above, so the engine's
  // own INVALID_FAMILY path is now a defense-in-depth backstop rather than the
  // CLI's primary rejection. subjectAccount/partition feed the engine's existing
  // PassRole viability reasoning.
  // Arm the cooperative wall-clock budget (S3-dos-budget) when the caller supplied a
  // finite budgetMs. budgetMs<=0 sets a deadline at or before "now"; chargeWork's `>=`
  // deadline check makes the first checkpoint abort DETERMINISTICALLY (no race on
  // whether a millisecond elapses first), so a zero/negative budget always fails
  // closed. An undefined/NaN budgetMs leaves the budget disarmed so scan() stays
  // clock-free (existing programmatic callers).
  const budgetMs = Number.isFinite(inp.budgetMs) ? inp.budgetMs : null;
  const budgetArmed = budgetMs !== null;
  let result;
  try {
    if (budgetArmed) armGlobBudget(Date.now() + budgetMs);
    result = analyze(inp.text, {
      family: familyToken,
      requireExplicitFamily: true,
      subjectAccount: isNonEmptyString(inp.subjectAccount) ? inp.subjectAccount.trim() : undefined,
      // Pass only a VALIDATED partition; an unrecognized token is dropped (engine
      // defaults to 'aws') so it cannot masquerade as a confident assertion.
      partition: validPartition || undefined,
    });
  } catch (e) {
    // The armed wall-clock budget was exceeded: report a graceful, fail-closed
    // "analysis aborted (resource budget)" verdict (analysisStatus failed, exit 3).
    // This is the whole point of the budget - a pathological policy must NEVER
    // collapse to a clean pass; it stops with an explicit incomplete state instead.
    if (isGlobBudgetError(e)) {
      return Object.freeze({
        analysisStatus: ANALYSIS_STATUS.FAILED,
        analysisStates: Object.freeze([state(
          ANALYSIS_STATE.INCOMPLETE,
          'RESOURCE_BUDGET_EXCEEDED',
          'analysis aborted (resource budget): the analysis exceeded its wall-clock ' +
            'budget and was stopped before completing. Zero findings here does NOT ' +
            'mean the policy is safe - it means the policy could not be fully analyzed.',
        )]),
        findings: Object.freeze([]),
        blockingCount: 0,
        findingsCount: 0,
        exitCode: EXIT.FAIL_CLOSED,
        reason: 'RESOURCE_BUDGET_EXCEEDED',
        family: familyToken,
        coverage: null,
        engineOk: false,
      });
    }
    // The engine is otherwise designed never to throw; if it somehow does, fail
    // closed to an INTERNAL invariant error (exit 4) - NEVER a clean pass.
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: Object.freeze([state(
        ANALYSIS_STATE.INTERNAL,
        'INTERNAL',
        'Analysis threw unexpectedly.',
      )]),
      findings: Object.freeze([]),
      blockingCount: 0,
      findingsCount: 0,
      exitCode: EXIT.INTERNAL,
      reason: 'INTERNAL',
      family: familyToken,
      coverage: null,
      engineOk: false,
    });
  } finally {
    if (budgetArmed) disarmGlobBudget();
  }

  // --- 3. Engine ok:false -> rejected/malformed input, or internal error. -----
  if (!result || result.ok !== true) {
    const { internal, states } = errorStates(result && result.errors);
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: Object.freeze(states.length ? states : [state(
        ANALYSIS_STATE.MALFORMED, 'REJECTED', 'The policy could not be analyzed.',
      )]),
      findings: Object.freeze([]),
      blockingCount: 0,
      findingsCount: 0,
      exitCode: internal ? EXIT.INTERNAL : EXIT.FAIL_CLOSED,
      reason: internal ? 'INTERNAL' : 'MALFORMED_INPUT',
      family: familyToken,
      coverage: null,
      engineOk: false,
    });
  }

  const coverage = result.coverage || null;
  const effectiveFamily = (coverage && coverage.summary && coverage.summary.effectiveFamily)
    || result.family || familyToken;
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const findingsCount = findings.length;
  const blockingCount = findings.filter((f) => meetsThreshold(f && f.severity, threshold)).length;

  // --- 3b. RESOURCE-BUDGET ABORT (S3-dos-budget). ----------------------------
  // The engine's DETERMINISTIC work budget tripped mid-analysis: analyze() returned a
  // well-formed result (ok:true) but marked coverage ABORTED because a within-caps
  // policy's CPU cost exploded. This is a hard fail-closed state (the analysis never
  // ran to a conclusion) and takes precedence over every other verdict below - a
  // budget-aborted run must NEVER map to a clean pass or a normal findings gate. This
  // mirrors the wall-clock catch above (both report RESOURCE_BUDGET_EXCEEDED, exit 3);
  // the difference is only the trigger (deterministic op-count vs. wall-clock).
  if (coverage && coverage.summary && coverage.summary.analysisAborted === true) {
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: Object.freeze([state(
        ANALYSIS_STATE.INCOMPLETE,
        'RESOURCE_BUDGET_EXCEEDED',
        'analysis aborted (resource budget): the analysis exceeded its resource ' +
          'budget and was stopped before completing. Zero findings here does NOT ' +
          'mean the policy is safe - it means the policy could not be fully analyzed.',
      )]),
      findings: Object.freeze(findings.slice()),
      blockingCount,
      findingsCount,
      exitCode: EXIT.FAIL_CLOSED,
      reason: 'RESOURCE_BUDGET_EXCEEDED',
      family: effectiveFamily,
      coverage,
      engineOk: true,
    });
  }

  // --- 4. Family gate FAIL-CLOSED (blocked shape) -> failed (exit 3). ---------
  // The engine ran to a well-formed conclusion (ok:true) but refused to evaluate
  // the document's shape/family. This is the strongest fail-closed signal and
  // takes precedence over any incomplete/unknown reasoning.
  if (coverage && coverage.blocked) {
    const states = blockedStates(coverage);
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: Object.freeze(states.length ? states : [state(
        ANALYSIS_STATE.UNSUPPORTED, 'UNSUPPORTED', 'The policy family/shape is not analyzable.',
      )]),
      findings: Object.freeze(findings.slice()),
      blockingCount,
      findingsCount,
      exitCode: EXIT.FAIL_CLOSED,
      reason: 'FAMILY_BLOCKED',
      family: effectiveFamily,
      coverage,
      engineOk: true,
    });
  }

  // --- 4b. FAIL-CLOSED masked-grant shapes (engine-detected). -----------------
  // The shared engine now surfaces every masked-grant shape as a structured
  // analyzer-state on coverage.summary.maskedGrants (empty NotAction/NotResource
  // complement, malformed condition value, suppressed ForAnyValue never-match) and
  // flips coverage.summary.incomplete. This adapter reads THAT - it no longer
  // re-parses the raw policy text - so the browser (analyze()) and CLI surfaces
  // observe the identical masked-grant set and cannot drift.
  //
  // Runs BEFORE the generic incomplete step (step 5) so a masked grant reports its
  // SPECIFIC reason/code (EMPTY_NOTACTION_COMPLEMENT, ...) rather than collapsing to
  // COVERAGE_INCOMPLETE. A 'malformed' masked grant (empty complement / non-primitive
  // condition value) is a hard fail-closed (FAILED, exit 3); a lone 'incomplete'
  // masked grant (suppressed ForAnyValue never-match) leaves a trace (PARTIAL, exit
  // 3). Neither can be downgraded by any threshold.
  const maskedGrants = (coverage && coverage.summary && Array.isArray(coverage.summary.maskedGrants))
    ? coverage.summary.maskedGrants
    : [];
  if (maskedGrants.length > 0) {
    // Reason precedence mirrors the historical guard order: an empty NotAction
    // complement outranks an empty NotResource complement, which outranks a malformed
    // condition value. A lone suppressed never-match is the weakest (PARTIAL).
    const MALFORMED_REASON_RANK = [
      'EMPTY_NOTACTION_COMPLEMENT',
      'EMPTY_NOTRESOURCE_COMPLEMENT',
      'UNSPECIFIED_RESOURCE_SCOPE',
      'MALFORMED_RESOURCE_ARN',
      'MALFORMED_CONDITION_BLOCK',
      'MALFORMED_CONDITION_VALUE',
    ];
    const rankOf = (code) => {
      const i = MALFORMED_REASON_RANK.indexOf(code);
      return i === -1 ? MALFORMED_REASON_RANK.length : i;
    };
    const malformed = maskedGrants
      .filter((g) => g && g.kind === 'malformed')
      .slice()
      .sort((a, b) => rankOf(a.code) - rankOf(b.code));
    const suppressed = maskedGrants.filter((g) => g && g.kind === 'incomplete');
    if (malformed.length > 0) {
      const states = malformed.map((g) => state(
        ANALYSIS_STATE.MALFORMED, g.code, maskedGrantMessage(g.code), { path: g.path },
      ));
      // Co-occurring suppressed never-match paths ride along so the full trace survives.
      for (const g of suppressed) {
        states.push(state(
          ANALYSIS_STATE.INCOMPLETE, g.code, maskedGrantMessage(g.code), { path: g.path },
        ));
      }
      return Object.freeze({
        analysisStatus: ANALYSIS_STATUS.FAILED,
        analysisStates: Object.freeze(states),
        findings: Object.freeze(findings.slice()),
        blockingCount,
        findingsCount,
        exitCode: EXIT.FAIL_CLOSED,
        reason: malformed[0].code,
        family: effectiveFamily,
        coverage,
        engineOk: true,
      });
    }
    // Only suppressed never-match(es): a would-be grant neutralized by an empty
    // ForAnyValue set. Valid AWS, but it must leave a trace, not a silent clean.
    const states = suppressed.map((g) => state(
      ANALYSIS_STATE.INCOMPLETE, g.code, maskedGrantMessage(g.code), { path: g.path },
    ));
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.PARTIAL,
      analysisStates: Object.freeze(states.length ? states : [state(
        ANALYSIS_STATE.INCOMPLETE, 'SUPPRESSED_NEVER_MATCH_ALLOW',
        maskedGrantMessage('SUPPRESSED_NEVER_MATCH_ALLOW'),
      )]),
      findings: Object.freeze(findings.slice()),
      blockingCount,
      findingsCount,
      exitCode: EXIT.FAIL_CLOSED,
      reason: 'SUPPRESSED_NEVER_MATCH_ALLOW',
      family: effectiveFamily,
      coverage,
      engineOk: true,
    });
  }

  // --- 5. Analyzed a subset, or a finding of unknown viability -> partial. ----
  // "incomplete" coverage (unsupported elements/actions/conditions) and any
  // unknown-viability finding both prevent an honest "complete" verdict. Either
  // yields analysisStatus 'partial' and exit 3 - a clean pass is impossible while
  // part of the analysis could not be established. This is what stops a
  // capped-to-low unknown-viability finding from slipping under a 'high' threshold
  // and reporting exit 0.
  const coverageIncomplete = !!(coverage && coverage.summary && coverage.summary.incomplete);
  const unknownFindings = findings.filter((f) => findingHasUnknownViability(f, partitionProvided));
  if (coverageIncomplete || unknownFindings.length > 0) {
    const states = incompleteStatesFromCoverage(coverage);
    for (const f of unknownFindings) {
      const reqs = unknownViabilityReasons(f, partitionProvided);
      states.push(state(
        ANALYSIS_STATE.UNKNOWN,
        'UNKNOWN_VIABILITY',
        'A finding\'s exploitability could not be established from the supplied ' +
          'context; its viability is unknown (unknown does NOT mean not exploitable).',
        {
          details: {
            findingId: f && f.id ? String(f.id) : null,
            statementIndex: typeof (f && f.statementIndex) === 'number' ? f.statementIndex : null,
            requiredUnknowns: reqs,
          },
        },
      ));
    }
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.PARTIAL,
      // Guarantee at least one analyzer-state accompanies a partial verdict.
      analysisStates: Object.freeze(states.length ? states : [state(
        ANALYSIS_STATE.INCOMPLETE, 'COVERAGE_INCOMPLETE',
        'The analysis covered only a subset of the document; unsupported elements ' +
          'prevent a complete conclusion.',
      )]),
      findings: Object.freeze(findings.slice()),
      blockingCount,
      findingsCount,
      exitCode: EXIT.FAIL_CLOSED,
      reason: unknownFindings.length > 0 && !coverageIncomplete ? 'UNKNOWN_VIABILITY' : 'COVERAGE_INCOMPLETE',
      family: effectiveFamily,
      coverage,
      engineOk: true,
    });
  }

  // --- 6. Complete analysis. Findings gate on the threshold (exit 1 vs 0). -----
  return Object.freeze({
    analysisStatus: ANALYSIS_STATUS.COMPLETE,
    analysisStates: Object.freeze([]),
    findings: Object.freeze(findings.slice()),
    blockingCount,
    findingsCount,
    exitCode: blockingCount > 0 ? EXIT.FINDINGS : EXIT.CLEAN,
    reason: blockingCount > 0 ? 'FINDINGS_AT_OR_ABOVE_THRESHOLD' : 'CLEAN',
    family: effectiveFamily,
    coverage,
    engineOk: true,
  });
}

export default scan;
