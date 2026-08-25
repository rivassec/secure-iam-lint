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

// Strip EXACTLY ONE leading U+FEFF (UTF-8 BOM), byte-for-byte identical to the
// engine's own normalization (validate.js: "if text.charCodeAt(0) === 0xfeff then
// text.slice(1)"). A file saved as "UTF-8 with BOM" - the DEFAULT for many Windows
// editors and PowerShell Set-Content/Out-File - begins with a single U+FEFF that
// JSON.parse rejects. The engine strips it before parsing; any adapter guard that
// re-parses the raw text MUST strip it the same way, or it diverges from the engine
// (a BOM-prefixed policy the engine analyzes fine would throw in the guard, and a
// catch that swallowed the throw would default the guard OPEN). Only the FIRST code
// unit is removed; an embedded U+FEFF elsewhere is preserved verbatim.
function stripLeadingBom(text) {
  return (typeof text === 'string' && text.charCodeAt(0) === 0xfeff) ? text.slice(1) : text;
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

// FAIL-CLOSED: an Allow statement whose ONLY action element is a present-but-empty
// NotAction complement (`"NotAction": []`). Under AWS semantics an empty NotAction
// excludes NOTHING, so this Allow grants EVERY action on its resource(s) - a
// full-admin grant. The shipped engine's model gates MISSING_ACTION on
// `NotAction !== undefined` (true for `[]`) and ruleNotActionAllow early-returns on
// an empty notActions list, so the engine faithfully evaluates neither: it models
// the statement as granting nothing and reports 'complete' + 0 findings. That is
// the one empty-complement shape that slips the engine's own validation (an empty
// STRING NotAction, a null/object NotAction, or Action+NotAction together are all
// already rejected). Since the engine is imported READ-ONLY and its analysis
// behavior must not change, the adapter detects this un-analyzable shape from the
// raw text and fails closed (MALFORMED, exit 3) rather than letting a masked
// full-admin grant pass a CI gate CLEAN. Deterministic; no engine mutation.
//
// Deliberately NARROW so it never re-flags a benign shape the engine correctly
// treats as granting nothing: `Action: []` (empty POSITIVE set = no actions),
// an empty `Statement: []`, and `Deny` + `NotAction: []` (deny everything) all
// stay exactly as the engine reports them. Only Effect === 'Allow' with a
// present, well-typed, empty-array NotAction is intercepted.
// Returns { paths, parseError }. `paths` lists the JSON paths of masked full-admin
// statements; `parseError` is true only on an adapter/engine PARSE DIVERGENCE that
// must fail closed (never default the guard open).
function emptyNotActionComplementPaths(text) {
  // Normalize identically to the engine (strip one leading BOM) BEFORE re-parsing,
  // so a UTF-8-with-BOM policy the engine analyzed to ok:true is parsed the same
  // way here rather than throwing and being waved through.
  const normalized = stripLeadingBom(text);
  let parsed;
  try {
    parsed = JSON.parse(normalized);
  } catch {
    // Reaching this guard means the engine ALREADY parsed these same bytes to
    // ok:true (step 3 fails every rejected/unparseable input closed before here).
    // If our own parse of the BOM-normalized text now fails, the adapter and the
    // engine have diverged on the input - an internal invariant violation. Fail
    // CLOSED (exit 4) rather than returning [] and defaulting the guard OPEN, which
    // is exactly the fail-open a BOM-prefixed masked-admin policy exploited.
    return { paths: [], parseError: true };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { paths: [], parseError: false };
  const stmtRaw = parsed.Statement;
  // Mirror the engine: Statement may be a single object (normalized to index 0)
  // or an array. Anything else carries no analyzable statement here.
  let statements;
  if (Array.isArray(stmtRaw)) {
    statements = stmtRaw;
  } else if (stmtRaw !== null && typeof stmtRaw === 'object') {
    statements = [stmtRaw];
  } else {
    return { paths: [], parseError: false };
  }
  const out = [];
  for (let i = 0; i < statements.length; i++) {
    const s = statements[i];
    if (!s || typeof s !== 'object' || Array.isArray(s)) continue;
    if (s.Effect !== 'Allow') continue; // Deny + NotAction:[] denies everything (benign).
    if (!Object.prototype.hasOwnProperty.call(s, 'NotAction')) continue;
    const na = s.NotAction;
    if (Array.isArray(na) && na.length === 0) {
      out.push(`Statement[${i}].NotAction`);
    }
  }
  return { paths: out, parseError: false };
}

// FAIL-CLOSED: the RESOURCE-axis symmetric twin of emptyNotActionComplementPaths.
// An Allow statement whose ONLY resource element is a present-but-empty NotResource
// complement (`"NotResource": []`). Under AWS semantics an empty NotResource excludes
// NOTHING, so this Allow applies to EVERY resource - byte-for-byte the same broad
// scope as `"Resource": "*"`. The shipped engine models resource breadth as
// `resources.includes('*') || notResources.length > 0` (rules.js resourceIsBroad);
// an empty NotResource has notResources.length === 0 and no Resource, so the engine
// reads it as "no resource scope" and ruleWildcardResource never fires. The
// byte-equivalent `"Resource": "*"` policy flags WILDCARD-RESOURCE and blocks at
// exit 1, so a single-action broad-resource grant written as `NotResource: []` would
// otherwise collapse to 'complete' + exit 0 (CLEAN) - a CI gate bypass. The engine
// is imported READ-ONLY and its analysis behavior must not change, so the adapter
// detects this un-faithfully-modeled shape from the raw text and fails closed
// (MALFORMED, exit 3), exactly like the empty-NotAction complement. Deterministic;
// no engine mutation.
//
// Deliberately NARROW, mirroring the NotAction guard so it never re-flags a shape
// the engine DOES model faithfully: a NON-empty NotResource (`NotResource: ["arn"]`)
// already flags WILDCARD-RESOURCE (rules.test.js) and is left untouched; `Resource: []`
// (empty positive set) and `Deny` + `NotResource: []` (deny across all resources) stay
// exactly as the engine reports them. Only Effect === 'Allow' with a present,
// well-typed, empty-array NotResource is intercepted. Returns { paths, parseError }
// with identical fail-closed parse-divergence semantics to emptyNotActionComplementPaths.
function emptyNotResourceComplementPaths(text) {
  // Normalize identically to the engine (strip one leading BOM) BEFORE re-parsing,
  // so a UTF-8-with-BOM policy the engine analyzed to ok:true is parsed the same way
  // here rather than throwing and being waved through.
  const normalized = stripLeadingBom(text);
  let parsed;
  try {
    parsed = JSON.parse(normalized);
  } catch {
    // The engine already parsed these bytes to ok:true before this guard runs; if our
    // BOM-normalized re-parse now fails, adapter and engine have diverged on the input
    // - an internal invariant violation. Fail CLOSED (exit 4) rather than returning []
    // and defaulting the guard OPEN, exactly as the empty-NotAction guard does.
    return { paths: [], parseError: true };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { paths: [], parseError: false };
  const stmtRaw = parsed.Statement;
  let statements;
  if (Array.isArray(stmtRaw)) {
    statements = stmtRaw;
  } else if (stmtRaw !== null && typeof stmtRaw === 'object') {
    statements = [stmtRaw];
  } else {
    return { paths: [], parseError: false };
  }
  const out = [];
  for (let i = 0; i < statements.length; i++) {
    const s = statements[i];
    if (!s || typeof s !== 'object' || Array.isArray(s)) continue;
    if (s.Effect !== 'Allow') continue; // Deny + NotResource:[] denies across all resources (benign).
    if (!Object.prototype.hasOwnProperty.call(s, 'NotResource')) continue;
    const nr = s.NotResource;
    if (Array.isArray(nr) && nr.length === 0) {
      out.push(`Statement[${i}].NotResource`);
    }
  }
  return { paths: out, parseError: false };
}

// FAIL-CLOSED: an Allow statement whose Condition silently DROPS or SUPPRESSES a
// full grant through the engine's condition-VALUE handling. Two disjoint shapes,
// both only meaningful on Effect:'Allow' (a never-match Deny denies nothing, so it
// is benign - scoped identically to emptyNotActionComplementPaths):
//
//   (a) MALFORMED condition value - a condition value ARRAY carrying a member that
//       is NOT a string/number/boolean (null, an object, or a nested array). AWS
//       rejects such an element with MalformedPolicyDocument, so the policy cannot
//       even deploy - yet engine/conditions.js toValueArray (the member filter)
//       silently DROPS the non-primitive member, so [{}] and [null] collapse to [].
//       When the operator is ForAnyValue that emptied set makes statementNeverMatches
//       treat the WHOLE Allow as a structural never-match; rules.js / escalation.js
//       then skip the grant and the analysis reports 'complete' + 0 findings. Even
//       when the operator is not ForAnyValue, the engine evaluated a value set the
//       author did not write (a member was dropped), so it did NOT faithfully analyze
//       the policy. Either way this un-analyzable, undeployable grant must fail closed
//       (MALFORMED, exit 3) rather than pass a CI gate CLEAN.
//
//   (b) SUPPRESSED never-match - a ForAnyValue operator whose value is a LITERALLY
//       empty array ([]). This is VALID AWS (ForAnyValue over no values can never
//       match, so the statement grants nothing), but the engine SUPPRESSES the whole
//       Allow as a never-match and emits no finding. On a full-admin-looking Allow
//       (Action:*/Resource:*) that leaves a silent CLEAN with zero trace of the
//       suppressed grant. Surface it as an analyzer-state so a suppressed would-be
//       grant fails closed (INCOMPLETE, exit 3) instead of collapsing to 0/clean.
//
// Detected from the RAW text (the engine is imported READ-ONLY), BOM-normalized
// exactly like the engine so a UTF-8-with-BOM policy cannot slip the guard.
// Deterministic; no engine mutation.
//
// Returns { malformedPaths, suppressedPaths, parseError }. `parseError` is true
// only on an adapter/engine PARSE DIVERGENCE that must fail closed (never default
// the guard open) - identical semantics to emptyNotActionComplementPaths.
function maskedConditionGrantPaths(text) {
  const normalized = stripLeadingBom(text);
  let parsed;
  try {
    parsed = JSON.parse(normalized);
  } catch {
    // The engine already parsed these bytes to ok:true before this guard runs; if
    // our BOM-normalized re-parse now fails, adapter and engine have diverged on the
    // input. Fail CLOSED (exit 4) rather than defaulting the guard OPEN.
    return { malformedPaths: [], suppressedPaths: [], parseError: true };
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { malformedPaths: [], suppressedPaths: [], parseError: false };
  }
  const stmtRaw = parsed.Statement;
  let statements;
  if (Array.isArray(stmtRaw)) {
    statements = stmtRaw;
  } else if (stmtRaw !== null && typeof stmtRaw === 'object') {
    statements = [stmtRaw];
  } else {
    return { malformedPaths: [], suppressedPaths: [], parseError: false };
  }
  const malformedPaths = [];
  const suppressedPaths = [];
  for (let i = 0; i < statements.length; i++) {
    const s = statements[i];
    if (!s || typeof s !== 'object' || Array.isArray(s)) continue;
    if (s.Effect !== 'Allow') continue; // a never-match Deny is benign.
    const cond = s.Condition;
    if (!cond || typeof cond !== 'object' || Array.isArray(cond)) continue;
    for (const op of Object.keys(cond)) {
      const block = cond[op];
      if (!block || typeof block !== 'object' || Array.isArray(block)) continue;
      // Mirror engine parseOperator: ForAnyValue is a lowercased operator prefix.
      const forAnyValue = String(op).toLowerCase().startsWith('foranyvalue:');
      for (const key of Object.keys(block)) {
        const raw = block[key];
        if (!Array.isArray(raw)) continue;
        // Mirror engine toValueArray's member filter (keep only primitives).
        const hasNonPrimitive = raw.some(
          (v) => !(typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'),
        );
        const path = `Statement[${i}].Condition.${op}.${key}`;
        if (hasNonPrimitive) {
          malformedPaths.push(path);
        } else if (forAnyValue && raw.length === 0) {
          suppressedPaths.push(path);
        }
      }
    }
  }
  return { malformedPaths, suppressedPaths, parseError: false };
}

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
  let result;
  try {
    result = analyze(inp.text, {
      family: familyToken,
      requireExplicitFamily: true,
      subjectAccount: isNonEmptyString(inp.subjectAccount) ? inp.subjectAccount.trim() : undefined,
      // Pass only a VALIDATED partition; an unrecognized token is dropped (engine
      // defaults to 'aws') so it cannot masquerade as a confident assertion.
      partition: validPartition || undefined,
    });
  } catch (e) {
    // The engine is designed never to throw; if it somehow does, fail closed to an
    // INTERNAL invariant error (exit 4) - NEVER a clean pass.
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

  // --- 5b. FAIL-CLOSED empty-complement guard (must precede any 'complete'). ---
  // An Allow statement with a present-but-empty NotAction ([]) is a masked
  // full-admin grant the engine models as granting nothing (see
  // emptyNotActionComplementPaths). It is the one empty-complement shape that
  // reaches this point as ok:true + 0 findings; every other malformed NotAction is
  // already rejected upstream. Intercept it here - the only place that can return
  // 'complete' + exit 0 - so a could-not-faithfully-analyze full-admin policy can
  // NEVER pass a gate CLEAN.
  const { paths: emptyComplementPaths, parseError: complementParseError } =
    emptyNotActionComplementPaths(inp.text);
  if (complementParseError) {
    // The engine parsed the input (ok:true) but the adapter's own guard could not
    // re-parse the BOM-normalized text: a divergence that must NEVER pass a gate
    // clean. Fail closed to an INTERNAL invariant error (exit 4).
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: Object.freeze([state(
        ANALYSIS_STATE.INTERNAL,
        'INTERNAL',
        'The adapter could not re-parse an input the engine accepted; refusing to ' +
          'report a clean pass on a divergent parse.',
      )]),
      findings: Object.freeze(findings.slice()),
      blockingCount,
      findingsCount,
      exitCode: EXIT.INTERNAL,
      reason: 'INTERNAL',
      family: effectiveFamily,
      coverage,
      engineOk: true,
    });
  }
  if (emptyComplementPaths.length > 0) {
    const states = emptyComplementPaths.map((p) => state(
      ANALYSIS_STATE.MALFORMED,
      'EMPTY_NOTACTION_COMPLEMENT',
      'An Allow statement uses NotAction with an empty complement ([]), which under ' +
        'AWS semantics excludes nothing and therefore grants EVERY action (a ' +
        'full-admin grant). The analyzer cannot faithfully model this shape, so the ' +
        'policy fails closed rather than reporting a clean pass.',
      { path: p },
    ));
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: Object.freeze(states),
      findings: Object.freeze(findings.slice()),
      blockingCount,
      findingsCount,
      exitCode: EXIT.FAIL_CLOSED,
      reason: 'EMPTY_NOTACTION_COMPLEMENT',
      family: effectiveFamily,
      coverage,
      engineOk: true,
    });
  }

  // --- 5b-2. FAIL-CLOSED empty NotRESOURCE complement guard (symmetric twin). ---
  // An Allow statement with a present-but-empty NotResource ([]) applies to EVERY
  // resource (an empty complement excludes nothing) - the byte-equivalent of
  // Resource:"*" - but the engine models it as "no resource scope" and never fires
  // WILDCARD-RESOURCE (see emptyNotResourceComplementPaths / rules.js resourceIsBroad).
  // It reaches this point as ok:true + 0 broad-resource findings, so it must be
  // intercepted here, exactly like the empty-NotAction complement, or a broad-resource
  // single-action grant collapses to 'complete' + exit 0 CLEAN while the identical
  // Resource:"*" policy blocks at exit 1. Fail closed (exit 3), never CLEAN.
  const { paths: emptyNotResourcePaths, parseError: notResourceParseError } =
    emptyNotResourceComplementPaths(inp.text);
  if (notResourceParseError) {
    // Engine parsed the input (ok:true) but the adapter's BOM-normalized re-parse could
    // not: a divergence that must NEVER pass a gate clean. Fail closed (exit 4).
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: Object.freeze([state(
        ANALYSIS_STATE.INTERNAL,
        'INTERNAL',
        'The adapter could not re-parse an input the engine accepted; refusing to ' +
          'report a clean pass on a divergent parse.',
      )]),
      findings: Object.freeze(findings.slice()),
      blockingCount,
      findingsCount,
      exitCode: EXIT.INTERNAL,
      reason: 'INTERNAL',
      family: effectiveFamily,
      coverage,
      engineOk: true,
    });
  }
  if (emptyNotResourcePaths.length > 0) {
    const states = emptyNotResourcePaths.map((p) => state(
      ANALYSIS_STATE.MALFORMED,
      'EMPTY_NOTRESOURCE_COMPLEMENT',
      'An Allow statement uses NotResource with an empty complement ([]), which under ' +
        'AWS semantics excludes nothing and therefore applies to EVERY resource (the ' +
        'same broad scope as Resource "*"). The analyzer models this as no resource ' +
        'scope and does not fire its wildcard-resource finding, so the policy fails ' +
        'closed rather than reporting a clean pass.',
      { path: p },
    ));
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: Object.freeze(states),
      findings: Object.freeze(findings.slice()),
      blockingCount,
      findingsCount,
      exitCode: EXIT.FAIL_CLOSED,
      reason: 'EMPTY_NOTRESOURCE_COMPLEMENT',
      family: effectiveFamily,
      coverage,
      engineOk: true,
    });
  }

  // --- 5c. FAIL-CLOSED masked-grant condition guard (must precede any 'complete').
  // A full grant can be silently dropped or suppressed by the engine's condition-
  // VALUE handling: a non-string/non-primitive array member (e.g. [{}]/[null]) that
  // toValueArray drops, or a ForAnyValue [] that statementNeverMatches suppresses.
  // Both let a full-admin or escalation Allow reach here as ok:true + 0 findings
  // with a MODELED condition key (so coverage.summary.incomplete stays false and
  // steps 5/5b never fire). Intercept them - the last gate before 'complete' - so a
  // could-not-faithfully-analyze / undeployable masked grant NEVER passes CLEAN.
  const {
    malformedPaths: malformedCondPaths,
    suppressedPaths: suppressedCondPaths,
    parseError: condParseError,
  } = maskedConditionGrantPaths(inp.text);
  if (condParseError) {
    // Engine parsed the input (ok:true) but the adapter's BOM-normalized re-parse
    // could not: a divergence that must NEVER pass a gate clean (exit 4).
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: Object.freeze([state(
        ANALYSIS_STATE.INTERNAL,
        'INTERNAL',
        'The adapter could not re-parse an input the engine accepted; refusing to ' +
          'report a clean pass on a divergent parse.',
      )]),
      findings: Object.freeze(findings.slice()),
      blockingCount,
      findingsCount,
      exitCode: EXIT.INTERNAL,
      reason: 'INTERNAL',
      family: effectiveFamily,
      coverage,
      engineOk: true,
    });
  }
  if (malformedCondPaths.length > 0) {
    // A non-primitive condition array member is an undeployable (MalformedPolicyDocument)
    // policy the engine silently rewrote by dropping the member. FAILED, exit 3. Any
    // co-occurring suppressed-never-match paths ride along so the full trace survives.
    const states = malformedCondPaths.map((p) => state(
      ANALYSIS_STATE.MALFORMED,
      'MALFORMED_CONDITION_VALUE',
      'A Condition value array carries a non-string element (an object, array, or ' +
        'null). AWS rejects this as MalformedPolicyDocument, and the analyzer silently ' +
        'drops the element - so it cannot faithfully model the statement. The policy ' +
        'fails closed rather than reporting a clean pass.',
      { path: p },
    ));
    for (const p of suppressedCondPaths) {
      states.push(state(
        ANALYSIS_STATE.INCOMPLETE,
        'SUPPRESSED_NEVER_MATCH_ALLOW',
        'An Allow statement is suppressed as a never-match by an empty ForAnyValue ' +
          'condition value ([]); a would-be grant leaves no finding.',
        { path: p },
      ));
    }
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: Object.freeze(states),
      findings: Object.freeze(findings.slice()),
      blockingCount,
      findingsCount,
      exitCode: EXIT.FAIL_CLOSED,
      reason: 'MALFORMED_CONDITION_VALUE',
      family: effectiveFamily,
      coverage,
      engineOk: true,
    });
  }
  if (suppressedCondPaths.length > 0) {
    // A ForAnyValue [] is valid AWS but SUPPRESSES the whole Allow as a never-match,
    // so a full-admin-looking grant leaves a silent CLEAN. Surface it as an analyzer-
    // state and fail closed (PARTIAL, exit 3) so the suppressed grant leaves a trace.
    const states = suppressedCondPaths.map((p) => state(
      ANALYSIS_STATE.INCOMPLETE,
      'SUPPRESSED_NEVER_MATCH_ALLOW',
      'An Allow statement is suppressed as a never-match by an empty ForAnyValue ' +
        'condition value ([]), which under AWS semantics can never match and so grants ' +
        'nothing. A full grant neutralized this way is reported as an analyzer-state ' +
        'rather than a silent clean pass (suppressed does NOT mean the grant was safe).',
      { path: p },
    ));
    return Object.freeze({
      analysisStatus: ANALYSIS_STATUS.PARTIAL,
      analysisStates: Object.freeze(states),
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
