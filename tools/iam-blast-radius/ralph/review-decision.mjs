// review-decision.mjs — fail-closed critic-review decision model (IAM-1101 / Phase 11A).
//
// This module is workflow infrastructure, NOT part of the shipped IAM Blast
// Radius tool. It exists because the IAM-1005 "529 storm" incident let an
// UNREVIEWED story auto-accept: the old arbiter treated a missing/errored
// critic result as "no blocking findings" and therefore as approval. That is a
// fail-OPEN control. This module implements the fail-CLOSED model from
// docs/phases-11-13-execution-plan.md §1 and is the empirical fix gated by the
// 15 fault-injection cases in docs/record-tests/cases/workflow-cases.json.
//
// Core principle (record-test bundle): unknown, unavailable, malformed, timed
// out, and failed are EXPLICIT non-pass states. An empty array, a missing
// result, or a rejected promise is NEVER equivalent to critic approval.
//
// A story is ACCEPTED iff: the critic panel is non-empty (configured), EVERY
// required critic returned an explicit PASS, and the durable ledger row was
// committed. Anything else -> not accepted (blocked | review_error), always
// with a ledger row recording why.
//
// Emitted objects conform to:
//   docs/record-tests/schemas/critic-result.schema.json      (critic attempts)
//   docs/record-tests/schemas/review-ledger-entry.schema.json (ledger rows)
//
// Deterministic: no Date.now()/Math.random(); an injectable monotonic clock
// yields stable ISO timestamps so the same scenario yields byte-identical
// output on re-run (mirrors the engine's determinism invariant for infra).

export const TERMINAL_STATES = Object.freeze([
  'PASS',
  'BLOCKER',
  'ERROR',
  'TIMEOUT',
  'INVALID_RESPONSE',
]);

// A control failure (never an approval, never a legitimate "blocked" verdict):
// the critic could not be trusted to have actually reviewed the artifact.
export const CONTROL_FAILURE_STATES = Object.freeze(['ERROR', 'TIMEOUT', 'INVALID_RESPONSE']);

export const DECISIONS = Object.freeze({
  APPROVED: 'approved',
  BLOCKED: 'blocked',
  REVIEW_ERROR: 'review_error',
});

export const DEFAULT_REQUIRED_CRITICS = Object.freeze(['security', 'correctness', 'evidence']);

// Number of ADDITIONAL attempts after the first for a non-PASS critic.
// Default 2 -> up to 3 total attempts per critic.
export const DEFAULT_CRITIC_MAX_RETRY = 2;

const LEDGER_SCHEMA_VERSION = 1;

// ---------------------------------------------------------------------------
// Deterministic clock
// ---------------------------------------------------------------------------

// A monotonic clock that returns RFC3339/ISO-8601 date-time strings. Injectable
// so tests are deterministic and never depend on wall-clock time.
export function makeClock(startISO = '2026-08-24T00:00:00.000Z', stepMs = 1000) {
  let t = Date.parse(startISO);
  if (Number.isNaN(t)) throw new Error('makeClock: invalid startISO');
  return function now() {
    const iso = new Date(t).toISOString();
    t += stepMs;
    return iso;
  };
}

// ---------------------------------------------------------------------------
// Classification: raw critic response -> critic-result (schema-valid)
// ---------------------------------------------------------------------------

function errObj(code, message, httpStatus) {
  const e = { code, message: message || code };
  if (typeof httpStatus === 'number') e.httpStatus = httpStatus;
  return e;
}

// Classify one raw critic response into a critic-result object conforming to
// critic-result.schema.json. `raw` may be:
//   - a number         -> an HTTP status with no usable body -> ERROR
//   - the string
//     'TIMEOUT'        -> TIMEOUT
//   - any other string -> attempt JSON.parse; unparseable -> INVALID_RESPONSE
//   - an object with
//     `error`          -> provider error envelope (any httpStatus) -> ERROR
//   - an object with a
//     valid `status`   -> that terminal state (with consistency checks)
//   - an object without
//     an explicit status-> INVALID_RESPONSE (missing verdict is not approval)
//   - null/undefined    -> INVALID_RESPONSE (a missing result is never a pass)
//
// The returned object always carries criticId, status, attempt, completedAt.
// Non-PASS/BLOCKER results always carry an `error`. PASS always carries an
// empty `findings` array. BLOCKER carries the (non-empty) findings.
export function classifyResponse(raw, { criticId, attempt, now }) {
  const base = { criticId, attempt, completedAt: now() };

  const result = classifyRawStatus(raw);
  return finalize(base, result);
}

function finalize(base, result) {
  const out = { criticId: base.criticId, status: result.status, attempt: base.attempt, completedAt: base.completedAt };
  if (result.status === 'PASS') {
    out.findings = [];
  } else if (result.status === 'BLOCKER') {
    out.findings = result.findings;
  } else {
    out.error = result.error;
  }
  return out;
}

function classifyRawStatus(raw) {
  // Missing result — never approval.
  if (raw === null || raw === undefined) {
    return { status: 'INVALID_RESPONSE', error: errObj('MISSING_RESULT', 'No critic result was received') };
  }

  // Bare number = an HTTP status line with no usable critic body. Cannot be a
  // verdict -> control failure.
  if (typeof raw === 'number') {
    return { status: 'ERROR', error: errObj(`HTTP_${raw}`, `Critic transport returned HTTP ${raw}`, raw) };
  }

  if (typeof raw === 'string') {
    if (raw === 'TIMEOUT') {
      return { status: 'TIMEOUT', error: errObj('TIMEOUT', 'Critic exceeded its wall-clock budget') };
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { status: 'INVALID_RESPONSE', error: errObj('MALFORMED_JSON', 'Critic response was not valid JSON') };
    }
    // A parseable JSON string that is itself a scalar (e.g. "PASS", 3) is not a
    // structured critic result.
    if (parsed === null || typeof parsed !== 'object') {
      return { status: 'INVALID_RESPONSE', error: errObj('MALFORMED_JSON', 'Critic response did not decode to an object') };
    }
    return classifyObject(parsed);
  }

  if (typeof raw === 'object') return classifyObject(raw);

  return { status: 'INVALID_RESPONSE', error: errObj('MALFORMED_JSON', 'Unrecognized critic response type') };
}

function classifyObject(obj) {
  // Provider error envelope wins regardless of HTTP status (CRT-08: a 200 with
  // an error body is still an ERROR, never parsed as approval).
  if (obj.error && typeof obj.error === 'object') {
    const code = typeof obj.error.code === 'string' && obj.error.code ? obj.error.code : 'PROVIDER_ERROR';
    const httpStatus = typeof obj.httpStatus === 'number' ? obj.httpStatus
      : (typeof obj.error.httpStatus === 'number' ? obj.error.httpStatus : undefined);
    return { status: 'ERROR', error: errObj(code, obj.error.message || `Provider error: ${code}`, httpStatus) };
  }

  const status = obj.status;
  if (typeof status !== 'string') {
    // No explicit verdict. Empty/null findings ALONE are never sufficient
    // (CRT-03: {findings:null}; CRT-04 principle: findings:[] needs a status).
    return { status: 'INVALID_RESPONSE', error: errObj('MISSING_STATUS', 'Critic result had no explicit status') };
  }

  switch (status) {
    case 'PASS': {
      const f = obj.findings;
      if (f === undefined || (Array.isArray(f) && f.length === 0)) {
        return { status: 'PASS' };
      }
      // A "PASS" carrying findings contradicts itself.
      return { status: 'INVALID_RESPONSE', error: errObj('INCONSISTENT_PASS', 'PASS status carried non-empty findings') };
    }
    case 'BLOCKER': {
      const f = obj.findings;
      if (Array.isArray(f) && f.length > 0 && f.every(isValidFinding)) {
        return { status: 'BLOCKER', findings: f.map(normalizeFinding) };
      }
      return { status: 'INVALID_RESPONSE', error: errObj('INCONSISTENT_BLOCKER', 'BLOCKER status without valid findings') };
    }
    case 'ERROR':
      return { status: 'ERROR', error: obj.error && typeof obj.error === 'object'
        ? errObj(obj.error.code || 'ERROR', obj.error.message, obj.error.httpStatus)
        : errObj('ERROR', 'Critic reported ERROR') };
    case 'TIMEOUT':
      return { status: 'TIMEOUT', error: errObj('TIMEOUT', 'Critic reported TIMEOUT') };
    case 'INVALID_RESPONSE':
      return { status: 'INVALID_RESPONSE', error: errObj('INVALID_RESPONSE', 'Critic reported INVALID_RESPONSE') };
    default:
      return { status: 'INVALID_RESPONSE', error: errObj('UNKNOWN_STATUS', `Unrecognized critic status: ${String(status)}`) };
  }
}

function isValidFinding(f) {
  return f && typeof f === 'object'
    && typeof f.message === 'string' && f.message.length > 0
    && ['blocker', 'high', 'medium', 'low', 'info'].includes(f.severity);
}

function normalizeFinding(f) {
  return { severity: f.severity, message: f.message };
}

// ---------------------------------------------------------------------------
// Pure decision over a set of final critic results
// ---------------------------------------------------------------------------

// A required critic id is valid iff it is a non-empty string (matches the
// schema constraint on criticId / requiredCriticIds.items: string, minLength 1).
function isValidCriticId(id) {
  return typeof id === 'string' && id.length > 0;
}

// Given the required critic ids and a Map<criticId, criticResult> of FINAL
// results, decide the review outcome. Pure; no I/O.
//
// Precedence (fail-closed):
//   1. empty/invalid panel        -> configurationError, review_error
//   2. any malformed critic id    -> configurationError, review_error
//   3. any required critic missing -> review_error (control failure)
//   4. any control-failure state   -> review_error (control failure)
//   5. any BLOCKER                 -> blocked (a legitimate non-pass verdict)
//   6. every critic PASS           -> approved
export function decide(requiredCriticIds, resultsByCritic) {
  if (!Array.isArray(requiredCriticIds) || requiredCriticIds.length === 0) {
    return {
      decision: DECISIONS.REVIEW_ERROR,
      accepted: false,
      configurationError: true,
      missingCritics: [],
      errorCodes: ['EMPTY_CRITIC_PANEL'],
    };
  }

  // F4 (fail-closed): every required critic id MUST be a non-empty string. Both
  // bundle schemas require criticId / requiredCriticIds.items to be a string with
  // minLength 1, so a numeric/empty/non-string id (e.g. 123, '', {}, null) would
  // produce a schema-INVALID ledger row AND, worse, let acceptance proceed on a
  // malformed panel (the positional `?? \`critic-${i}\`` remap only catches
  // null/undefined, so 123 or '' flow straight through as a "present" critic).
  // Reject the panel as a configuration error - fail closed, never accept, never
  // commit a schema-violating row - exactly like EMPTY/DUPLICATE panels.
  if (!requiredCriticIds.every(isValidCriticId)) {
    return {
      decision: DECISIONS.REVIEW_ERROR,
      accepted: false,
      configurationError: true,
      missingCritics: [],
      errorCodes: ['INVALID_CRITIC_ID'],
    };
  }

  // F3 (fail-closed): a duplicate-id panel cannot be decided honestly - two slots
  // collapse to one keyed result. Reject it as a configuration error rather than
  // let a later PASS mask an earlier BLOCKER for the same critic id.
  if (new Set(requiredCriticIds).size !== requiredCriticIds.length) {
    return {
      decision: DECISIONS.REVIEW_ERROR,
      accepted: false,
      configurationError: true,
      missingCritics: [],
      errorCodes: ['DUPLICATE_CRITIC_IDS'],
    };
  }

  const missingCritics = requiredCriticIds.filter((id) => !resultsByCritic.has(id));
  const present = requiredCriticIds
    .filter((id) => resultsByCritic.has(id))
    .map((id) => resultsByCritic.get(id));

  const errorCodes = [];
  if (missingCritics.length) errorCodes.push('MISSING_CRITIC');

  // A null/undefined result slot is never a verdict - treat it as a control
  // failure (never dereference it as if it were a real result). Defense against a
  // caller that seeds the map with a missing result (F2).
  const controlFailures = present.filter((r) => !r || CONTROL_FAILURE_STATES.includes(r.status));
  for (const r of controlFailures) {
    const code = r && r.error && r.error.code ? r.error.code : (r ? r.status : 'MISSING_RESULT');
    if (!errorCodes.includes(code)) errorCodes.push(code);
  }

  const hasBlocker = present.some((r) => r && r.status === 'BLOCKER');
  const allPass = missingCritics.length === 0
    && present.length === requiredCriticIds.length
    && present.every((r) => r && r.status === 'PASS');

  let decision;
  let accepted = false;
  if (allPass) {
    decision = DECISIONS.APPROVED;
    accepted = true;
  } else if (missingCritics.length || controlFailures.length) {
    // A control failure or a missing critic can never be a trustworthy verdict:
    // fail closed to review_error, never "blocked" (which implies a real review).
    decision = DECISIONS.REVIEW_ERROR;
  } else if (hasBlocker) {
    decision = DECISIONS.BLOCKED;
  } else {
    decision = DECISIONS.REVIEW_ERROR;
  }

  return { decision, accepted, configurationError: false, missingCritics, errorCodes };
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

function ledgerIdempotencyKey({ workItemId, workflowRunId, artifactId }) {
  return `${workItemId}::${workflowRunId}::${artifactId}`;
}

function buildLedgerEntry({
  workItemId, workflowRunId, artifactId, requiredCriticIds,
  criticAttempts, decision, errorCodes, startedAt, completedAt,
}) {
  const entry = {
    schemaVersion: LEDGER_SCHEMA_VERSION,
    workItemId,
    workflowRunId,
    artifactId,
    requiredCriticIds: [...requiredCriticIds],
    criticAttempts,
    decision,
    startedAt,
    completedAt,
    idempotencyKey: ledgerIdempotencyKey({ workItemId, workflowRunId, artifactId }),
  };
  if (errorCodes && errorCodes.length) entry.errorCodes = [...new Set(errorCodes)];
  return entry;
}

// A durable, idempotent ledger. writeLedger throws to simulate a durable-store
// failure (CRT-11). Dedups by idempotencyKey (CRT-12 crash-recovery, CRT-13
// duplicate delivery) so exactly one row is committed.
export class InMemoryLedger {
  constructor({ failWrite = false } = {}) {
    this.rows = [];
    this._keys = new Set();
    this._failWrite = failWrite;
  }

  write(entry) {
    if (this._failWrite) {
      const err = new Error('Ledger write failed (durable store unavailable)');
      err.code = 'LEDGER_WRITE_FAILED';
      throw err;
    }
    const key = entry.idempotencyKey;
    if (key && this._keys.has(key)) {
      return { committed: true, deduplicated: true };
    }
    if (key) this._keys.add(key);
    this.rows.push(entry);
    return { committed: true, deduplicated: false };
  }
}

// ---------------------------------------------------------------------------
// Orchestrator: runReview
// ---------------------------------------------------------------------------

const DEFAULT_IDS = {
  workItemId: 'IAM-XXXX',
  workflowRunId: 'run-1',
  artifactId: 'artifact-1',
};

// runReview drives one review to a terminal, ledgered outcome. It accepts the
// record-test scenario shapes directly (so the fault-injection cases can be
// replayed verbatim) AND is the reference the phase workflow arbiters mirror.
//
// Scenario fields (from docs/record-tests/cases/workflow-cases.json):
//   requiredCritics      override the required critic panel
//   responses            one raw response per required critic (positional)
//   responsesByCritic    { criticId: rawResponse }
//   attempts             a single critic's sequential attempts (retry testing)
//   retryLimit           max total attempts for the retried critic
//   ledgerWrite:'FAIL'   simulate a durable ledger write failure
//   crashPoint           'after-review-before-ledger' (crash-recovery test)
//   duplicateDelivery    replay the same critic result / ledger commit twice
//   terminalStates       assert a ledger row is written for every terminal state
//
// Returns a rich object (superset used by the fault-injection assertions):
//   { accepted, decision, criticResults, criticStatus, ledgerRows, ledgerEntry,
//     configurationError, missingCritics, errorCode, errorCodes,
//     acceptedOnlyAfterAttempt, ledgerAttempts, deduplicated, recovery,
//     finalLedgerRows, ledgerRowForEveryState }
export function runReview(scenario = {}, options = {}) {
  const now = options.now || makeClock();
  const criticMaxRetry = options.criticMaxRetry ?? DEFAULT_CRITIC_MAX_RETRY;
  const ids = { ...DEFAULT_IDS, ...(options.ids || {}) };
  const startedAt = now();

  if (scenario.terminalStates) {
    return runTerminalStateCoverage(scenario, { now, ids, startedAt });
  }

  const requiredCriticIds = scenario.requiredCritics ?? DEFAULT_REQUIRED_CRITICS;

  // Configuration error: an empty panel must never pass vacuously (CRT-14:
  // never `[].every(...) === true`). No schema-valid ledger row can name zero
  // critics, so we return without one.
  if (!Array.isArray(requiredCriticIds) || requiredCriticIds.length === 0) {
    const d = decide(requiredCriticIds, new Map());
    return finalizeResult({
      decision: d.decision,
      accepted: false,
      configurationError: true,
      criticResults: [],
      criticStatus: undefined,
      ledgerRows: [],
      missingCritics: [],
      errorCodes: d.errorCodes,
    });
  }

  // F4 (fail-closed): a required-critic panel carrying a malformed id (numeric,
  // empty, non-string) must never be analyzed. The positional bind below only
  // remaps null/undefined via `?? \`critic-${i}\``, so 123 or '' would otherwise
  // flow through as a present critic and both accept a malformed panel and commit
  // a schema-INVALID ledger row (criticId / requiredCriticIds.items require a
  // non-empty string). Reject it as a configurationError - fail closed, no ledger.
  if (!requiredCriticIds.every(isValidCriticId)) {
    return finalizeResult({
      decision: DECISIONS.REVIEW_ERROR,
      accepted: false,
      configurationError: true,
      criticResults: [],
      criticStatus: undefined,
      ledgerRows: [],
      missingCritics: [],
      errorCodes: ['INVALID_CRITIC_ID'],
    });
  }

  // F3 (fail-closed): a required-critic panel with DUPLICATE ids is a degenerate
  // configuration. Results are keyed by criticId, so a duplicate would let a later
  // PASS silently overwrite an earlier BLOCKER / control failure for the SAME
  // critic and accept a story a blocker should have blocked. Reject the panel as a
  // configurationError rather than key-collapse it - fail closed, never accept.
  if (new Set(requiredCriticIds).size !== requiredCriticIds.length) {
    return finalizeResult({
      decision: DECISIONS.REVIEW_ERROR,
      accepted: false,
      configurationError: true,
      criticResults: [],
      criticStatus: undefined,
      ledgerRows: [],
      missingCritics: [],
      errorCodes: ['DUPLICATE_CRITIC_IDS'],
    });
  }

  if (scenario.attempts) {
    return runRetryScenario(scenario, { now, ids, startedAt, criticMaxRetry, requiredCriticIds });
  }

  // Build a Map<criticId, finalResult> and an ordered list of ALL attempts.
  const resultsByCritic = new Map();
  const criticAttempts = [];
  let criticStatus;

  if (scenario.responsesByCritic) {
    const entries = Object.entries(scenario.responsesByCritic);
    for (const [criticId, raw] of entries) {
      const r = classifyResponse(raw, { criticId, attempt: 1, now });
      resultsByCritic.set(criticId, r);
      criticAttempts.push(r);
      if (criticStatus === undefined) criticStatus = r.status;
    }
  } else {
    const responses = Array.isArray(scenario.responses) ? scenario.responses : [];
    // Positional: responses[i] belongs to requiredCriticIds[i]. Any required
    // critic without a response is simply absent -> missing -> fail closed.
    responses.forEach((raw, i) => {
      const criticId = requiredCriticIds[i] ?? `critic-${i}`;
      const r = classifyResponse(raw, { criticId, attempt: 1, now });
      resultsByCritic.set(criticId, r);
      criticAttempts.push(r);
    });
    criticStatus = criticAttempts.length ? criticAttempts[0].status : undefined;
  }

  const dedup = scenario.duplicateDelivery === true;
  if (dedup) {
    // A duplicate delivery of an already-recorded critic result must not add a
    // second attempt (CRT-13). We already deduped by keying on criticId in the
    // Map; simulate the second delivery being ignored.
  }

  const d = decide(requiredCriticIds, resultsByCritic);
  const errorCodes = [...d.errorCodes];

  // Ensure the ledger always has >=1 attempt row (schema minItems:1). If no
  // responses were supplied at all, synthesize a MISSING_RESULT attempt for the
  // first required critic so the failure is still recorded.
  let attemptsForLedger = criticAttempts;
  if (attemptsForLedger.length === 0) {
    attemptsForLedger = [classifyResponse(null, { criticId: requiredCriticIds[0], attempt: 1, now })];
  }

  return commitAndFinalize({
    decision: d.decision,
    accepted: d.accepted,
    configurationError: false,
    criticResults: [...resultsByCritic.values()],
    criticStatus,
    criticAttempts: attemptsForLedger,
    missingCritics: d.missingCritics,
    errorCodes,
    requiredCriticIds,
    ids,
    startedAt,
    now,
    ledgerWriteFail: scenario.ledgerWrite === 'FAIL',
    crashPoint: scenario.crashPoint,
    duplicateDelivery: dedup,
  });
}

// A single critic exercised across a retry budget (CRT-05: 529 then PASS;
// CRT-06: retries exhausted -> CRITIC_RETRY_EXHAUSTED).
//
// F1 (fail-closed): the retry loop exercises exactly ONE critic (the one being
// re-invoked). Its final result updates only THAT critic's slot; the decision is
// still taken over the FULL required-critic panel, so any OTHER required critic
// that produced no result is MISSING -> review_error, never a vacuous single-
// critic accept. A retried critic PASSing can never accept a story on its own.
//
// F2 (fail-closed): a degenerate/empty attempts list (or retryLimit:0) yields no
// critic result at all. That is a control failure, NOT a throw and NOT a pass:
// synthesize a MISSING_RESULT for the retried critic, fail closed to review_error
// with CRITIC_RETRY_EXHAUSTED, and still write a durable ledger row.
function runRetryScenario(scenario, { now, ids, startedAt, criticMaxRetry, requiredCriticIds }) {
  const criticId = (Array.isArray(scenario.requiredCritics) && scenario.requiredCritics[0])
    || requiredCriticIds[0]
    || 'security';
  const maxAttempts = typeof scenario.retryLimit === 'number'
    ? scenario.retryLimit
    : 1 + criticMaxRetry;

  const attempts = [];
  let finalResult = null;
  let acceptedOnlyAfterAttempt;

  for (let i = 0; i < scenario.attempts.length && attempts.length < maxAttempts; i++) {
    const attemptNo = i + 1;
    const r = classifyResponse(scenario.attempts[i], { criticId, attempt: attemptNo, now });
    attempts.push(r);
    finalResult = r;
    if (r.status === 'PASS') {
      acceptedOnlyAfterAttempt = attemptNo;
      break;
    }
  }

  // F2: no attempt produced a result (empty attempts / retryLimit:0). Never let
  // finalResult stay null (which would throw in decide). Record it as a missing
  // critic result so the fault is ledgered, not swallowed.
  if (finalResult === null) {
    finalResult = classifyResponse(null, { criticId, attempt: 1, now });
    attempts.push(finalResult);
  }

  const exhausted = finalResult.status !== 'PASS';

  // F1: the retried critic updates ONLY its own slot; decide over the FULL panel
  // so the un-run required critics are MISSING and block acceptance. A single
  // retried PASS on a multi-critic panel is therefore review_error, not accepted.
  const resultsByCritic = new Map([[criticId, finalResult]]);
  const d = decide(requiredCriticIds, resultsByCritic);

  const errorCodes = [...d.errorCodes];
  let decision = d.decision;
  let accepted = d.accepted;
  if (exhausted) {
    decision = DECISIONS.REVIEW_ERROR;
    accepted = false;
    if (!errorCodes.includes('CRITIC_RETRY_EXHAUSTED')) errorCodes.push('CRITIC_RETRY_EXHAUSTED');
  }

  const out = commitAndFinalize({
    decision,
    accepted,
    configurationError: false,
    criticResults: [finalResult],
    criticStatus: finalResult.status,
    criticAttempts: attempts,
    missingCritics: d.missingCritics,
    errorCodes,
    requiredCriticIds,
    ids,
    startedAt,
    now,
    ledgerWriteFail: scenario.ledgerWrite === 'FAIL',
    crashPoint: scenario.crashPoint,
    duplicateDelivery: scenario.duplicateDelivery === true,
  });
  out.acceptedOnlyAfterAttempt = acceptedOnlyAfterAttempt;
  out.ledgerAttempts = attempts.length;
  return out;
}

// CRT-15: exercise every terminal state and assert a durable ledger row exists
// for each. Also exercises RETRY_EXHAUSTED as a terminal outcome.
function runTerminalStateCoverage(scenario, { now, ids }) {
  const ledger = new InMemoryLedger();
  const perState = {};
  const criticId = 'security';

  for (const state of scenario.terminalStates) {
    const startedAt = now();
    let result;
    let decision;
    let errorCodes = [];
    if (state === 'RETRY_EXHAUSTED') {
      result = classifyResponse(529, { criticId, attempt: 3, now });
      decision = DECISIONS.REVIEW_ERROR;
      errorCodes = ['CRITIC_RETRY_EXHAUSTED'];
    } else if (state === 'PASS') {
      result = classifyResponse({ status: 'PASS', findings: [] }, { criticId, attempt: 1, now });
      decision = DECISIONS.APPROVED;
    } else if (state === 'BLOCKER') {
      result = classifyResponse({ status: 'BLOCKER', findings: [{ severity: 'blocker', message: 'blocking finding' }] }, { criticId, attempt: 1, now });
      decision = DECISIONS.BLOCKED;
    } else if (state === 'ERROR') {
      result = classifyResponse(529, { criticId, attempt: 1, now });
      decision = DECISIONS.REVIEW_ERROR;
      errorCodes = [result.error.code];
    } else if (state === 'TIMEOUT') {
      result = classifyResponse('TIMEOUT', { criticId, attempt: 1, now });
      decision = DECISIONS.REVIEW_ERROR;
      errorCodes = ['TIMEOUT'];
    } else if (state === 'INVALID_RESPONSE') {
      result = classifyResponse({ findings: null }, { criticId, attempt: 1, now });
      decision = DECISIONS.REVIEW_ERROR;
      errorCodes = ['MISSING_STATUS'];
    } else {
      result = classifyResponse(null, { criticId, attempt: 1, now });
      decision = DECISIONS.REVIEW_ERROR;
      errorCodes = ['MISSING_RESULT'];
    }
    const entry = buildLedgerEntry({
      ...ids,
      // Distinct artifactId per state so each writes its own idempotent row.
      artifactId: `${ids.artifactId}::${state}`,
      requiredCriticIds: [criticId],
      criticAttempts: [result],
      decision,
      errorCodes,
      startedAt,
      completedAt: now(),
    });
    ledger.write(entry);
    perState[state] = entry;
  }

  const ledgerRowForEveryState = scenario.terminalStates.every((s) => !!perState[s])
    && ledger.rows.length === scenario.terminalStates.length;

  return finalizeResult({
    decision: DECISIONS.REVIEW_ERROR,
    accepted: false,
    configurationError: false,
    criticResults: [],
    criticStatus: undefined,
    ledgerRows: ledger.rows,
    missingCritics: [],
    errorCodes: [],
    extra: { ledgerRowForEveryState, finalLedgerRows: ledger.rows.length },
  });
}

// Build the ledger entry, commit it durably (before acceptance is final), and
// assemble the result. Acceptance NEVER survives a ledger-write failure.
function commitAndFinalize({
  decision, accepted, configurationError, criticResults, criticStatus,
  criticAttempts, missingCritics, errorCodes, requiredCriticIds, ids,
  startedAt, now, ledgerWriteFail, crashPoint, duplicateDelivery,
}) {
  const ledger = new InMemoryLedger({ failWrite: ledgerWriteFail });
  const completedAt = now();
  const entry = buildLedgerEntry({
    ...ids,
    requiredCriticIds,
    criticAttempts,
    decision: ledgerWriteFail ? DECISIONS.REVIEW_ERROR : decision,
    errorCodes: ledgerWriteFail ? [...new Set([...errorCodes, 'LEDGER_WRITE_FAILED'])] : errorCodes,
    startedAt,
    completedAt,
  });

  let finalDecision = decision;
  let finalAccepted = accepted;
  let deduplicated = false;
  let recovery;

  try {
    // Crash-after-review-before-ledger: the first commit attempt is lost; the
    // idempotent retry re-commits exactly one row (CRT-12).
    if (crashPoint === 'after-review-before-ledger') {
      recovery = 'idempotent';
      ledger.write(entry); // recovery re-commit
      // A second (duplicate) recovery delivery must not add a row.
      const r2 = ledger.write(entry);
      if (r2.deduplicated) deduplicated = true;
    } else {
      const r1 = ledger.write(entry);
      if (duplicateDelivery) {
        const r2 = ledger.write(entry); // idempotent replay (CRT-13)
        deduplicated = r2.deduplicated || r1.deduplicated;
      }
    }
  } catch (e) {
    // Durable ledger commit failed -> the review CANNOT be accepted (CRT-11).
    finalDecision = DECISIONS.REVIEW_ERROR;
    finalAccepted = false;
    if (!errorCodes.includes('LEDGER_WRITE_FAILED')) errorCodes = [...errorCodes, 'LEDGER_WRITE_FAILED'];
    return finalizeResult({
      decision: finalDecision,
      accepted: finalAccepted,
      configurationError,
      criticResults,
      criticStatus,
      ledgerRows: [], // nothing durably committed
      missingCritics,
      errorCodes,
      extra: { ledgerWriteError: e.code || 'LEDGER_WRITE_FAILED', deduplicated, recovery },
    });
  }

  return finalizeResult({
    decision: finalDecision,
    accepted: finalAccepted,
    configurationError,
    criticResults,
    criticStatus,
    ledgerRows: ledger.rows,
    missingCritics,
    errorCodes,
    extra: { deduplicated, recovery },
  });
}

function finalizeResult({
  decision, accepted, configurationError, criticResults, criticStatus,
  ledgerRows, missingCritics, errorCodes, extra = {},
}) {
  const out = {
    decision,
    accepted: !!accepted,
    configurationError: !!configurationError,
    criticResults: criticResults || [],
    criticStatus,
    ledgerRows: ledgerRows || [],
    ledgerEntry: (ledgerRows && ledgerRows.length) ? ledgerRows[0] : undefined,
    missingCritics: missingCritics || [],
    errorCodes: errorCodes ? [...new Set(errorCodes)] : [],
    finalLedgerRows: (ledgerRows || []).length,
    ...extra,
  };
  out.errorCode = out.errorCodes.length ? out.errorCodes[out.errorCodes.length - 1] : undefined;
  return out;
}
