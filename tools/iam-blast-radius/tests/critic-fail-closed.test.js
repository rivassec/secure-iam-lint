// IAM-1101 / Phase 11A — critic fail-closed review-decision gate.
//
// Drives ALL 15 fault-injection cases in
// docs/record-tests/cases/workflow-cases.json through the repo's
// ralph/review-decision.mjs module and asserts each case's recorded `expect`.
// Also asserts that every critic attempt and every ledger row the module emits
// conforms to the two bundle schemas
// (docs/record-tests/schemas/critic-result.schema.json and
// review-ledger-entry.schema.json).
//
// This is the empirical fix for the IAM-1005 "529 storm" that let an unreviewed
// story auto-accept: ERROR / TIMEOUT / INVALID_RESPONSE / null / missing critic
// results must NEVER yield accepted=true, and every fault must leave a durable,
// schema-valid ledger record. Absence of a result is never approval.
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  runReview,
  classifyResponse,
  decide,
  makeClock,
  DECISIONS,
  TERMINAL_STATES,
  DEFAULT_REQUIRED_CRITICS,
} from '../ralph/review-decision.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const bundleDir = join(here, '..', 'docs', 'record-tests');

const workflowCases = JSON.parse(
  readFileSync(join(bundleDir, 'cases', 'workflow-cases.json'), 'utf8'),
);
const criticResultSchema = JSON.parse(
  readFileSync(join(bundleDir, 'schemas', 'critic-result.schema.json'), 'utf8'),
);
const ledgerSchema = JSON.parse(
  readFileSync(join(bundleDir, 'schemas', 'review-ledger-entry.schema.json'), 'utf8'),
);

// ---------------------------------------------------------------------------
// Minimal JSON-Schema validator (draft-2020-12 subset used by the two bundle
// schemas). Deliberately tiny + self-contained: no network, no dependency. It
// covers exactly the keywords the two schema files use so that "conforms to the
// schema" is checked against the literal committed schema, not a paraphrase.
// ---------------------------------------------------------------------------

const DATE_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

function schemaErrors(schema, value, refs, path = '$') {
  const errs = [];

  if (schema.$ref) {
    const target = refs[schema.$ref];
    if (!target) { errs.push(`${path}: unresolved $ref ${schema.$ref}`); return errs; }
    return errs.concat(schemaErrors(target, value, refs, path));
  }

  if (schema.const !== undefined && value !== schema.const) {
    errs.push(`${path}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
  }
  if (schema.enum && !schema.enum.includes(value)) {
    errs.push(`${path}: ${JSON.stringify(value)} not in enum ${JSON.stringify(schema.enum)}`);
  }

  if (schema.type) {
    const t = schema.type;
    const ok =
      (t === 'object' && value && typeof value === 'object' && !Array.isArray(value)) ||
      (t === 'array' && Array.isArray(value)) ||
      (t === 'string' && typeof value === 'string') ||
      (t === 'integer' && Number.isInteger(value)) ||
      (t === 'number' && typeof value === 'number');
    if (!ok) { errs.push(`${path}: expected type ${t}, got ${Array.isArray(value) ? 'array' : typeof value}`); return errs; }
  }

  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) errs.push(`${path}: shorter than minLength ${schema.minLength}`);
    if (schema.format === 'date-time' && !DATE_TIME_RE.test(value)) errs.push(`${path}: not a date-time: ${value}`);
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) errs.push(`${path}: below minimum ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errs.push(`${path}: above maximum ${schema.maximum}`);
  }

  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errs.push(`${path}: fewer than minItems ${schema.minItems}`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errs.push(`${path}: more than maxItems ${schema.maxItems}`);
    if (schema.uniqueItems) {
      const seen = new Set(value.map((v) => JSON.stringify(v)));
      if (seen.size !== value.length) errs.push(`${path}: items not unique`);
    }
    if (schema.items) value.forEach((v, i) => errs.push(...schemaErrors(schema.items, v, refs, `${path}[${i}]`)));
  }

  if (value && typeof value === 'object' && !Array.isArray(value)) {
    if (schema.required) {
      for (const key of schema.required) {
        if (!(key in value)) errs.push(`${path}: missing required property ${key}`);
      }
    }
    if (schema.properties) {
      for (const [key, sub] of Object.entries(schema.properties)) {
        if (key in value) errs.push(...schemaErrors(sub, value[key], refs, `${path}.${key}`));
      }
    }
    if (schema.additionalProperties === false && schema.properties) {
      for (const key of Object.keys(value)) {
        if (!(key in schema.properties)) errs.push(`${path}: additional property ${key} not allowed`);
      }
    }
  }

  if (schema.allOf) {
    for (const sub of schema.allOf) {
      if (sub.if) {
        // if/then: apply `then` only when `if` matches (no violations).
        const ifErrs = schemaErrors(sub.if, value, refs, path);
        if (ifErrs.length === 0 && sub.then) errs.push(...schemaErrors(sub.then, value, refs, path));
      } else {
        errs.push(...schemaErrors(sub, value, refs, path));
      }
    }
  }

  return errs;
}

const REFS = { 'critic-result.schema.json': criticResultSchema };

function assertValidCriticResult(obj, ctx) {
  const errs = schemaErrors(criticResultSchema, obj, REFS);
  assert.equal(errs.length, 0, `critic-result schema violation (${ctx}): ${errs.join('; ')}`);
}
function assertValidLedgerEntry(obj, ctx) {
  const errs = schemaErrors(ledgerSchema, obj, REFS);
  assert.equal(errs.length, 0, `ledger schema violation (${ctx}): ${errs.join('; ')}`);
}

// Sanity-check the validator itself: it must reject a known-bad shape, so a
// green schema assertion means something (the BND-02 "narrow assertion must
// still fail" principle applied to the schema checker).
test('schema validator rejects an invalid critic result', () => {
  const bad = { criticId: 'x', status: 'PASS', attempt: 1, completedAt: 'not-a-date', findings: [{ severity: 'blocker', message: 'm' }] };
  const errs = schemaErrors(criticResultSchema, bad, REFS);
  assert.ok(errs.length >= 2, `expected date-time + PASS-maxItems violations, got: ${errs.join('; ')}`);
});

test('schema validator rejects an invalid ledger entry', () => {
  const bad = { schemaVersion: 2, workItemId: '', requiredCriticIds: [], criticAttempts: [], decision: 'yes' };
  const errs = schemaErrors(ledgerSchema, bad, REFS);
  assert.ok(errs.length >= 3, `expected several violations, got: ${errs.join('; ')}`);
});

// ---------------------------------------------------------------------------
// The 15 fault-injection cases — every case runs with a deterministic clock.
// ---------------------------------------------------------------------------

// Compare only the keys the recorded case pins in `expect`. `ledgerRows` in the
// bundle is a COUNT; the module returns an array, so it is compared by length.
function assertExpect(caseId, result, expect) {
  for (const [key, want] of Object.entries(expect)) {
    if (key === 'ledgerRows') {
      assert.equal(result.ledgerRows.length, want, `${caseId}: ledgerRows count`);
    } else if (key === 'missingCritics') {
      assert.deepEqual(result.missingCritics, want, `${caseId}: missingCritics`);
    } else {
      assert.deepEqual(result[key], want, `${caseId}: ${key} (got ${JSON.stringify(result[key])}, want ${JSON.stringify(want)})`);
    }
  }
}

for (const testCase of workflowCases.cases) {
  test(`workflow-case ${testCase.id} fails closed as recorded`, () => {
    const result = runReview(testCase, { now: makeClock() });

    // Recorded expectations.
    assertExpect(testCase.id, result, testCase.expect);

    // Universal fail-closed invariants for every case.
    assert.equal(typeof result.accepted, 'boolean');
    if (result.accepted) {
      // Acceptance is only ever legal when every required critic PASSed AND a
      // durable ledger row exists. No fault case may reach here.
      assert.equal(result.decision, DECISIONS.APPROVED, `${testCase.id}: accepted implies approved`);
      assert.ok(result.ledgerRows.length >= 1, `${testCase.id}: accepted implies a ledger row`);
    }

    // Every emitted critic attempt + ledger row must conform to the schemas.
    for (const row of result.ledgerRows) {
      assertValidLedgerEntry(row, `${testCase.id} ledger`);
      for (const a of row.criticAttempts) assertValidCriticResult(a, `${testCase.id} attempt`);
    }
    for (const r of result.criticResults) assertValidCriticResult(r, `${testCase.id} criticResult`);
  });
}

// Explicit named coverage of the fail-closed acceptance criterion:
// ERROR/TIMEOUT/INVALID_RESPONSE/null never yield accepted=true.
test('no ERROR/TIMEOUT/INVALID/null critic scenario is ever accepted', () => {
  const hostile = [
    { responses: [529, 529, 529] },
    { responses: [{ status: 'PASS' }, 529, { status: 'PASS' }] },
    { responses: ['TIMEOUT', 'TIMEOUT', 'TIMEOUT'] },
    { responses: [{ findings: null }, { findings: null }, { findings: null }] },
    { responses: ['{not-json', '{bad', '}'] },
    { responses: [null, null, null] },
    { responses: [{ httpStatus: 200, error: { code: 'provider_overloaded' } }] },
  ];
  for (const scenario of hostile) {
    const r = runReview(scenario, { now: makeClock() });
    assert.equal(r.accepted, false, `hostile scenario accepted: ${JSON.stringify(scenario)}`);
    assert.equal(r.decision, DECISIONS.REVIEW_ERROR);
    assert.ok(r.ledgerRows.length >= 1, 'a fault still writes a ledger row');
  }
});

// ---------------------------------------------------------------------------
// Adapted from docs/record-tests/templates/critic-fail-closed.test.template.mjs
// (the repository's real workflow adapter is runReview).
// ---------------------------------------------------------------------------

async function runReviewWithMocks(scenario) {
  return runReview(scenario, { now: makeClock() });
}

test('all critic 529 responses block acceptance and write a ledger row', async () => {
  const result = await runReviewWithMocks({
    requiredCritics: ['security', 'correctness', 'evidence'],
    responses: [529, 529, 529],
  });
  assert.equal(result.accepted, false);
  assert.equal(result.decision, 'review_error');
  assert.equal(result.ledgerRows.length, 1);
  assert.equal(result.ledgerRows[0].criticAttempts.length >= 3, true);
});

test('null findings without explicit PASS is invalid, not approval', async () => {
  const result = await runReviewWithMocks({ responses: [{ findings: null }] });
  assert.equal(result.accepted, false);
  assert.equal(result.criticResults[0].status, 'INVALID_RESPONSE');
});

test('empty required critic set cannot pass vacuously', async () => {
  const result = await runReviewWithMocks({ requiredCritics: [], responses: [] });
  assert.equal(result.accepted, false);
  assert.equal(result.configurationError, true);
});

test('ledger failure occurs before acceptance (isolated: single passing critic)', async () => {
  // requiredCritics is a single PASS so the ONLY thing that can block is the
  // ledger write — proving acceptance never survives a failed durable commit.
  const result = await runReviewWithMocks({
    requiredCritics: ['security'],
    responses: [{ status: 'PASS', findings: [] }],
    ledgerWrite: 'FAIL',
  });
  assert.equal(result.accepted, false);
  assert.equal(result.decision, 'review_error');
  assert.equal(result.ledgerRows.length, 0, 'nothing durably committed on a ledger-write failure');
  assert.ok(result.errorCodes.includes('LEDGER_WRITE_FAILED'));
});

// ---------------------------------------------------------------------------
// Unit tests for the classification + pure decision surface.
// ---------------------------------------------------------------------------

test('classifyResponse maps every raw shape to the right terminal state', () => {
  const now = makeClock();
  const c = (raw) => classifyResponse(raw, { criticId: 's', attempt: 1, now }).status;
  assert.equal(c(529), 'ERROR');
  assert.equal(c('TIMEOUT'), 'TIMEOUT');
  assert.equal(c('{not-json'), 'INVALID_RESPONSE');
  assert.equal(c(null), 'INVALID_RESPONSE');
  assert.equal(c(undefined), 'INVALID_RESPONSE');
  assert.equal(c({ findings: null }), 'INVALID_RESPONSE');
  assert.equal(c({ findings: [] }), 'INVALID_RESPONSE'); // empty findings, no status
  assert.equal(c({ status: 'PASS', findings: [] }), 'PASS');
  assert.equal(c({ status: 'PASS' }), 'PASS');
  assert.equal(c({ status: 'PASS', findings: [{ severity: 'high', message: 'm' }] }), 'INVALID_RESPONSE');
  assert.equal(c({ status: 'BLOCKER', findings: [{ severity: 'blocker', message: 'm' }] }), 'BLOCKER');
  assert.equal(c({ status: 'BLOCKER' }), 'INVALID_RESPONSE');
  assert.equal(c({ httpStatus: 200, error: { code: 'provider_overloaded', message: 'x' } }), 'ERROR');
});

test('classifyResponse output is schema-valid for every terminal state', () => {
  const now = makeClock();
  const inputs = [
    { status: 'PASS', findings: [] },
    { status: 'BLOCKER', findings: [{ severity: 'blocker', message: 'boom' }] },
    529,
    'TIMEOUT',
    '{bad',
  ];
  for (const raw of inputs) {
    assertValidCriticResult(classifyResponse(raw, { criticId: 's', attempt: 1, now }), JSON.stringify(raw));
  }
});

test('decide requires ALL critics PASS to accept', () => {
  const pass = { criticId: 's', status: 'PASS', attempt: 1, completedAt: 't', findings: [] };
  const blocker = { criticId: 'c', status: 'BLOCKER', attempt: 1, completedAt: 't', findings: [{ severity: 'blocker', message: 'x' }] };
  const err = { criticId: 'e', status: 'ERROR', attempt: 1, completedAt: 't', error: { code: 'HTTP_529', message: 'x' } };

  const allPass = decide(['s', 'c', 'e'], new Map([['s', pass], ['c', { ...pass, criticId: 'c' }], ['e', { ...pass, criticId: 'e' }]]));
  assert.equal(allPass.accepted, true);
  assert.equal(allPass.decision, DECISIONS.APPROVED);

  const withBlocker = decide(['s', 'c'], new Map([['s', pass], ['c', blocker]]));
  assert.equal(withBlocker.accepted, false);
  assert.equal(withBlocker.decision, DECISIONS.BLOCKED);

  const withError = decide(['s', 'e'], new Map([['s', pass], ['e', err]]));
  assert.equal(withError.accepted, false);
  assert.equal(withError.decision, DECISIONS.REVIEW_ERROR);

  const missing = decide(['s', 'x'], new Map([['s', pass]]));
  assert.equal(missing.accepted, false);
  assert.equal(missing.decision, DECISIONS.REVIEW_ERROR);
  assert.deepEqual(missing.missingCritics, ['x']);

  const emptyPanel = decide([], new Map());
  assert.equal(emptyPanel.accepted, false);
  assert.equal(emptyPanel.configurationError, true);
});

test('a control failure outranks a blocker (review_error, never blocked)', () => {
  const pass = { criticId: 's', status: 'PASS', attempt: 1, completedAt: 't', findings: [] };
  const blocker = { criticId: 'c', status: 'BLOCKER', attempt: 1, completedAt: 't', findings: [{ severity: 'blocker', message: 'x' }] };
  const err = { criticId: 'e', status: 'ERROR', attempt: 1, completedAt: 't', error: { code: 'HTTP_529', message: 'x' } };
  const d = decide(['s', 'c', 'e'], new Map([['s', pass], ['c', blocker], ['e', err]]));
  assert.equal(d.decision, DECISIONS.REVIEW_ERROR);
  assert.equal(d.accepted, false);
});

test('runReview is deterministic (byte-identical output on re-run)', () => {
  const scenario = { responses: [{ status: 'PASS', findings: [] }, 529, 'TIMEOUT'] };
  const a = runReview(scenario, { now: makeClock() });
  const b = runReview(scenario, { now: makeClock() });
  assert.deepEqual(a, b);
});

test('a fully-passing panel with a durable ledger is accepted + approved', () => {
  const result = runReview({
    requiredCritics: ['security', 'correctness', 'evidence'],
    responses: [
      { status: 'PASS', findings: [] },
      { status: 'PASS', findings: [] },
      { status: 'PASS', findings: [] },
    ],
  }, { now: makeClock() });
  assert.equal(result.accepted, true);
  assert.equal(result.decision, DECISIONS.APPROVED);
  assert.equal(result.ledgerRows.length, 1);
  assertValidLedgerEntry(result.ledgerRows[0], 'happy-path');
});

// ---------------------------------------------------------------------------
// Fail-open regressions in the retry / multi-critic path (F1/F2/F3).
// The retry loop exercises ONE critic; it must never accept a multi-critic story
// on that one critic alone, never throw on a degenerate attempts list, and never
// let a duplicate-id panel mask a blocker. These reproduce the IAM-1005
// unreviewed-auto-accept class of defect.
// ---------------------------------------------------------------------------

test('F1: a retried critic PASS does NOT accept a multi-critic story (others still missing)', () => {
  const result = runReview({
    requiredCritics: ['security', 'correctness', 'evidence'],
    attempts: [{ status: 'PASS', findings: [] }],
  }, { now: makeClock() });
  assert.equal(result.accepted, false, 'one retried PASS cannot accept a 3-critic panel');
  assert.equal(result.decision, DECISIONS.REVIEW_ERROR);
  assert.deepEqual(result.missingCritics, ['correctness', 'evidence'],
    'the critics that never ran are reported missing, not silently empty');
  // The ledger names the FULL required panel, so the fault is auditable.
  assert.deepEqual(result.ledgerRows[0].requiredCriticIds, ['security', 'correctness', 'evidence']);
});

test('F1: the DEFAULT panel does not collapse to a single critic on the retry path', () => {
  const result = runReview({ attempts: [{ status: 'PASS', findings: [] }] }, { now: makeClock() });
  assert.equal(result.accepted, false, 'default 3-critic panel must not accept on security alone');
  assert.equal(result.decision, DECISIONS.REVIEW_ERROR);
  assert.deepEqual(result.missingCritics, ['correctness', 'evidence']);
});

test('F2: an empty attempts list fails closed with a ledger row (never throws)', () => {
  let result;
  assert.doesNotThrow(() => {
    result = runReview({
      requiredCritics: ['security', 'correctness', 'evidence'],
      attempts: [],
    }, { now: makeClock() });
  }, 'a degenerate empty attempts list must not throw out of runReview');
  assert.equal(result.accepted, false);
  assert.equal(result.decision, DECISIONS.REVIEW_ERROR);
  assert.ok(result.ledgerRows.length >= 1, 'a control failure still writes a durable ledger row');
  assert.ok(
    result.errorCodes.includes('CRITIC_RETRY_EXHAUSTED') || result.errorCodes.includes('MISSING_RESULT'),
    `expected a control-failure code, got ${JSON.stringify(result.errorCodes)}`,
  );
  for (const row of result.ledgerRows) assertValidLedgerEntry(row, 'F2 empty attempts');
});

test('F2: retryLimit:0 fails closed (never throws)', () => {
  let result;
  assert.doesNotThrow(() => {
    result = runReview({ attempts: [{ status: 'PASS' }], retryLimit: 0 }, { now: makeClock() });
  });
  assert.equal(result.accepted, false);
  assert.equal(result.decision, DECISIONS.REVIEW_ERROR);
  assert.ok(result.ledgerRows.length >= 1);
});

test('F3: a duplicate required-critic id panel is a configurationError, never accepted', () => {
  // A BLOCKER on the first "security" slot must not be overwritten by a later
  // PASS keyed to the same id and accepted.
  const result = runReview({
    requiredCritics: ['security', 'security', 'evidence'],
    responses: [
      { status: 'BLOCKER', findings: [{ severity: 'blocker', message: 'boom' }] },
      { status: 'PASS', findings: [] },
      { status: 'PASS', findings: [] },
    ],
  }, { now: makeClock() });
  assert.equal(result.accepted, false, 'a blocker on a duplicate-id panel must never accept');
  assert.equal(result.configurationError, true);
  assert.notEqual(result.decision, DECISIONS.APPROVED);
  assert.ok(result.errorCodes.includes('DUPLICATE_CRITIC_IDS'));
});

test('F3: decide() rejects a duplicate-id panel as a configurationError', () => {
  const pass = { criticId: 'security', status: 'PASS', attempt: 1, completedAt: 't', findings: [] };
  const d = decide(['security', 'security'], new Map([['security', pass]]));
  assert.equal(d.accepted, false);
  assert.equal(d.configurationError, true);
  assert.equal(d.decision, DECISIONS.REVIEW_ERROR);
});

// ---------------------------------------------------------------------------
// F4: a malformed critic id (non-string / empty string) in the required panel
// must fail closed as a configurationError, never accept, and never commit a
// schema-INVALID ledger row. The positional `?? \`critic-${i}\`` remap only
// catches null/undefined, so a numeric or empty id would otherwise flow through
// as a "present" critic and produce accepted=true on a malformed panel — the
// exact fail-open class IAM-1101 exists to prevent. The green 15 workflow-cases
// don't exercise this surface, so it is pinned here explicitly.
// ---------------------------------------------------------------------------

test('F4: a numeric critic id fails closed (accepted=false, INVALID_CRITIC_ID)', () => {
  const result = runReview({
    requiredCritics: [123, 'security'],
    responses: [{ status: 'PASS' }, { status: 'PASS' }],
  }, { now: makeClock() });
  assert.equal(result.accepted, false, 'a numeric critic id must never accept');
  assert.equal(result.configurationError, true);
  assert.notEqual(result.decision, DECISIONS.APPROVED);
  assert.equal(result.decision, DECISIONS.REVIEW_ERROR);
  assert.ok(result.errorCodes.includes('INVALID_CRITIC_ID'),
    `expected INVALID_CRITIC_ID, got ${JSON.stringify(result.errorCodes)}`);
  // No schema-violating ledger row is committed for a malformed panel.
  assert.equal(result.ledgerRows.length, 0, 'a malformed panel commits no ledger row');
});

test('F4: an empty-string critic id fails closed', () => {
  const result = runReview({
    requiredCritics: ['', 'security'],
    responses: [{ status: 'PASS' }, { status: 'PASS' }],
  }, { now: makeClock() });
  assert.equal(result.accepted, false);
  assert.equal(result.configurationError, true);
  assert.ok(result.errorCodes.includes('INVALID_CRITIC_ID'));
  assert.equal(result.ledgerRows.length, 0);
});

test('F4: an object critic id fails closed', () => {
  const result = runReview({
    requiredCritics: [{}, 'security'],
    responses: [{ status: 'PASS' }, { status: 'PASS' }],
  }, { now: makeClock() });
  assert.equal(result.accepted, false);
  assert.equal(result.configurationError, true);
  assert.ok(result.errorCodes.includes('INVALID_CRITIC_ID'));
  assert.equal(result.ledgerRows.length, 0);
});

test('F4: a null critic id fails closed (not by accident of the ?? remap)', () => {
  const result = runReview({
    requiredCritics: [null, 'security'],
    responses: [{ status: 'PASS' }, { status: 'PASS' }],
  }, { now: makeClock() });
  assert.equal(result.accepted, false);
  assert.equal(result.configurationError, true);
  assert.ok(result.errorCodes.includes('INVALID_CRITIC_ID'));
  assert.equal(result.ledgerRows.length, 0);
});

test('F4: decide() rejects a malformed critic id as a configurationError', () => {
  const pass = { criticId: 'security', status: 'PASS', attempt: 1, completedAt: 't', findings: [] };
  for (const badId of [123, '', {}, null, undefined, true]) {
    const d = decide([badId, 'security'], new Map([['security', pass]]));
    assert.equal(d.accepted, false, `id ${JSON.stringify(badId)} must not accept`);
    assert.equal(d.configurationError, true);
    assert.equal(d.decision, DECISIONS.REVIEW_ERROR);
    assert.ok(d.errorCodes.includes('INVALID_CRITIC_ID'),
      `id ${JSON.stringify(badId)}: expected INVALID_CRITIC_ID, got ${JSON.stringify(d.errorCodes)}`);
  }
});

test('F4: a malformed critic id on the RETRY path also fails closed', () => {
  const result = runReview({
    requiredCritics: [123, 'correctness', 'evidence'],
    attempts: [{ status: 'PASS', findings: [] }],
  }, { now: makeClock() });
  assert.equal(result.accepted, false, 'a retried PASS must not accept a malformed panel');
  assert.equal(result.configurationError, true);
  assert.ok(result.errorCodes.includes('INVALID_CRITIC_ID'));
  assert.equal(result.ledgerRows.length, 0);
});

test('TERMINAL_STATES and DEFAULT_REQUIRED_CRITICS are the documented sets', () => {
  assert.deepEqual([...TERMINAL_STATES], ['PASS', 'BLOCKER', 'ERROR', 'TIMEOUT', 'INVALID_RESPONSE']);
  assert.deepEqual([...DEFAULT_REQUIRED_CRITICS], ['security', 'correctness', 'evidence']);
});
