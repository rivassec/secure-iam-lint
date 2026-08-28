// A-condition-budget (round-4, mechanical, defense-in-depth): the condition classifier
// charges the cooperative work budget PROPORTIONAL to the per-VALUE work it does, and a
// value-array flood on one statement's Condition routes to coverage.summary.incomplete
// (never a bare clean pass, never by silently dropping values).
//
// TWO independent defenses, both fail-CLOSED, neither a verdict-semantics change:
//   (1) conditions.js classifyConditions now charges chargeWork(Math.max(1, values))
//       per KEY instead of a flat one-unit-per-key. A single key carrying a huge value
//       array used to do O(values) work charged as ONE unit, so a tight/exceeded budget
//       never sampled it - the exact uncharged-loop shape a future superlinear
//       regression could ride to a multi-second COMPLETE verdict. The per-value charge
//       makes that loop PARTICIPATE: a tight ceiling now trips it -> analysisAborted.
//   (2) validate.js LIMITS.MAX_CONDITION_VALUES + masked-grant.js: a statement whose
//       Condition carries more than the (GENEROUS) cap routes to
//       coverage.summary.incomplete via TOO_MANY_CONDITION_VALUES - fail closed, values
//       never dropped, the whole document never discarded.
//
// chargeWork is a no-op while no budget is armed and the cap is far above any legit
// policy, so NO existing verdict changes (the full suite proves that). This file
// witnesses: the flood fails closed (budget OR cap), a normal large-but-legit allowlist
// still COMPLETES, and browser analyze() is never more permissive than CLI scan().
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate, LIMITS } from '../../../content/tools/iam-blast-radius/engine/validate.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';

// An identity policy: one benign read on a NARROW resource (no finding, complete
// coverage by itself) plus a StringEquals aws:SourceVpc condition carrying V values.
// The narrow resource keeps the baseline CLEAN so any incomplete comes from the
// condition, not a broad-resource flip.
function policyWithConditionValues(V) {
  const values = new Array(V);
  for (let n = 0; n < V; n++) values[n] = 1; // numeric primitives: tiny + not malformed
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Action: ['s3:GetObject'],
      Resource: ['arn:aws:s3:::my-bucket/prefix/*'],
      Condition: { StringEquals: { 'aws:SourceVpc': values } },
    }],
  });
}

// --- (1) per-value budget participation --------------------------------------

// A value count UNDER the cap but above the budget's work-check interval (1<<15), so the
// single per-key value charge crosses a checkpoint and a tight ceiling samples it. Under
// the OLD flat chargeWork(keys.length) this one-key statement charged ONE unit - far below
// any checkpoint - so a tight budget never sampled the O(values) work it hid.
const HEAVY_VALUES = 40000;

test('per-value charge PARTICIPATES: a huge value array on ONE key trips a tight budget -> aborted+incomplete', () => {
  const text = policyWithConditionValues(HEAVY_VALUES);
  assert.equal(validate(text).ok, true, 'the flood is within every hard limit (not rejected)');
  // Under the OLD chargeWork(keys.length) this one-key statement charged ONE unit and a
  // tight ceiling never tripped; the per-value charge samples the real O(values) work.
  const a = analyze(text, { workLimit: 5000 });
  assert.equal(a.ok, true, 'well-formed in-band result');
  assert.equal(a.coverage.summary.analysisAborted, true, 'the now-charged per-value scan trips a tight budget');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'), 'carries the budget-abort code');
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis');
});

test('NO over-correction: the same heavy value array COMPLETES under the default budget', () => {
  const text = policyWithConditionValues(HEAVY_VALUES);
  const a = analyze(text); // default budget
  assert.equal(a.ok, true);
  assert.equal(a.coverage.summary.analysisAborted, false, 'a legit large value array does not false-close under the default budget');
  // The known key on a narrow resource yields no finding and (under the cap) no
  // TOO_MANY_CONDITION_VALUES, so the policy is a clean COMPLETE pass.
  assert.equal(a.coverage.summary.incomplete, false, 'a large-but-legit value array completes cleanly');
  assert.ok(!a.coverage.summary.codes.includes('TOO_MANY_CONDITION_VALUES'), 'under the cap: no flood code');
});

test('NO over-correction: a tiny-condition policy stays COMPLETE at the same tight ceiling', () => {
  const a = analyze(policyWithConditionValues(2), { workLimit: 5000 });
  assert.equal(a.coverage.summary.analysisAborted, false, 'proportional charge: a tiny condition does not trip the tight budget');
});

// --- (2) MAX_CONDITION_VALUES cap -> coverage.summary.incomplete --------------

test('cap: a value-array flood over MAX_CONDITION_VALUES routes to incomplete (values NOT dropped, doc NOT discarded)', () => {
  const text = policyWithConditionValues(LIMITS.MAX_CONDITION_VALUES + 1);
  // NOT a hard reject: validate accepts it (the whole document is not discarded) and
  // never truncates the value array.
  const v = validate(text);
  assert.equal(v.ok, true, 'the flood is NOT hard-rejected by validate (fail-closed happens in the engine, not by discarding the doc)');
  const a = analyze(text);
  assert.equal(a.ok, true, 'well-formed in-band result');
  assert.equal(a.coverage.summary.incomplete, true, 'an over-cap condition flood is INCOMPLETE, never a bare clean pass');
  assert.ok(a.coverage.summary.codes.includes('TOO_MANY_CONDITION_VALUES'), 'carries the flood code');
  // It is the CAP, not the deterministic budget: the default budget is far above the
  // (bounded) work this flood costs, so it is not an abort - it is a coverage caveat.
  assert.equal(a.coverage.summary.analysisAborted, false, 'the cap flip is a coverage caveat, not a budget abort');
  const flood = a.coverage.summary.maskedGrants.find((g) => g.code === 'TOO_MANY_CONDITION_VALUES');
  assert.ok(flood, 'the masked-grant list carries a structured flood entry');
  assert.equal(flood.kind, 'incomplete', 'kind incomplete: the document is deployable, this is a coverage caveat');
  assert.equal(flood.path, 'Statement[0].Condition', 'the entry locates the offending statement Condition');
});

test('cap is effect-agnostic: a flood on a Deny statement is also incomplete (a flood is a work concern, not a grant)', () => {
  const values = new Array(LIMITS.MAX_CONDITION_VALUES + 1).fill(1);
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Deny',
      Action: ['s3:GetObject'],
      Resource: ['arn:aws:s3:::my-bucket/prefix/*'],
      Condition: { StringEquals: { 'aws:SourceVpc': values } },
    }],
  });
  const a = analyze(text);
  assert.equal(a.coverage.summary.incomplete, true, 'a Deny-side flood is equally fail-closed');
  assert.ok(a.coverage.summary.codes.includes('TOO_MANY_CONDITION_VALUES'));
});

test('normal large-but-legit allowlist (under the cap) still COMPLETES', () => {
  const text = policyWithConditionValues(5000); // an allowlist far larger than any real policy, still legit
  assert.equal(validate(text).ok, true);
  const a = analyze(text);
  assert.equal(a.ok, true);
  assert.equal(a.coverage.summary.incomplete, false, 'a legit allowlist under the cap is a clean COMPLETE pass');
  assert.equal(a.coverage.summary.analysisAborted, false);
  assert.ok(!a.coverage.summary.codes.includes('TOO_MANY_CONDITION_VALUES'));
});

// --- browser <-> CLI parity ---------------------------------------------------

test('parity: the CLI fails CLOSED (exit 3) on the flood the browser marks incomplete - browser is never more permissive', () => {
  const text = policyWithConditionValues(LIMITS.MAX_CONDITION_VALUES + 1);
  const a = analyze(text);
  assert.equal(a.coverage.summary.incomplete, true, 'browser: not a clean pass');

  const r = scan({ text, family: 'identity' });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'CLI never exits 0 on a flood the browser marked incomplete');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'CLI fails closed (exit 3)');
  assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'CLI status is never complete');
  const codes = r.analysisStates.map((st) => st.code);
  assert.ok(codes.includes('TOO_MANY_CONDITION_VALUES'), 'the CLI surfaces the flood code');
});

test('parity: a legit under-cap allowlist is CLEAN on both surfaces (no over-correction)', () => {
  const text = policyWithConditionValues(5000);
  const a = analyze(text);
  assert.equal(a.coverage.summary.incomplete, false);
  const r = scan({ text, family: 'identity' });
  assert.equal(r.exitCode, EXIT.CLEAN, 'CLI exits 0 on the legit allowlist');
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'CLI status complete on the legit allowlist');
});
