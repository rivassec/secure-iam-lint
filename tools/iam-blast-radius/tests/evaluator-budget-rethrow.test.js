// S3-dos-budget-all (round-2 residual F3): evaluator.js decide()/evaluate() catch
// blocks SWALLOWED the cooperative budget sentinel, a latent fail-OPEN.
//
// ROOT CAUSE. decide() reaches the shared wildcard matcher (actionApplies/resourceApplies
// -> actionMatches/resourceMatches -> globMatch), which charges the deterministic work
// budget and, on a runaway, throws GlobBudgetError. Both decide() and evaluate() wrapped
// their bodies in `try { ... } catch (e) { errors.push({code:'INTERNAL'...}); return
// <benign> }`, so a tripped budget was DEMOTED to a benign "evaluation failed / not
// granted" result instead of propagating. Any caller that routed a policy through these
// exported functions could therefore observe a COMPLETE-looking result after an unbounded
// run - the exact fail-open glob.js forbids (threat-model T5/T8). The sibling modules
// (rules.js / escalation.js / trust.js) all re-throw with `if (isGlobBudgetError(e))
// throw e;`; evaluator.js was the one surface missing it.
//
// FIX. Add `if (isGlobBudgetError(e)) throw e;` at the TOP of both catch blocks so a
// budget trip propagates to analyze()/scan() (which map it to the fail-closed
// aborted+incomplete verdict), while a genuine internal fault is still swallowed to the
// benign result exactly as before.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import { evaluate, decide } from '../../../content/tools/iam-blast-radius/engine/evaluator.js';
import {
  setWorkLimit,
  getWorkLimit,
  isGlobBudgetError,
  GlobBudgetError,
} from '../../../content/tools/iam-blast-radius/engine/glob.js';

// A minimal well-formed identity model whose wildcard Action forces decide() through the
// shared matcher (globMatch), the real path that can throw GlobBudgetError.
const MODEL = modelFromText(JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: ['s3:*'], Resource: ['*'] }],
})).model;

test('F3: decide() RE-THROWS a tripped work budget instead of swallowing it into a benign decision', () => {
  const prev = getWorkLimit();
  setWorkLimit(1); // any real matcher call charges > 1 and trips on the first checkpoint
  let threw = false;
  let wasBudget = false;
  try {
    decide(MODEL, { action: 's3:GetObject', resource: 'arn:aws:s3:::bucket/object' });
  } catch (e) {
    threw = true;
    wasBudget = isGlobBudgetError(e);
  } finally {
    setWorkLimit(prev);
  }
  assert.equal(threw, true, 'a tripped budget must propagate out of decide(), not be caught into a NOT_GRANTED result');
  assert.equal(wasBudget, true, 're-thrown error is the GlobBudgetError sentinel (isGlobBudgetError)');
});

test('F3: decide() still SWALLOWS a genuine internal fault to a benign ok:false result (fix did not widen)', () => {
  // A booby-trapped statement whose property access throws a PLAIN Error simulates an
  // internal fault deep in the try body. It must be caught and demoted (ok:false), NOT
  // re-thrown - only the budget sentinel re-throws.
  const boobyStmt = {
    get effect() { throw new Error('internal boom'); },
    index: 0, sid: 'x', actions: ['s3:*'], notActions: [], resources: ['*'], notResources: [], condition: null,
  };
  let threw = false;
  let result = null;
  try {
    result = decide({ statements: [boobyStmt] }, { action: 's3:GetObject' });
  } catch (e) {
    threw = true;
  }
  assert.equal(threw, false, 'a plain internal fault is still swallowed, never re-thrown');
  assert.equal(result && result.ok, false, 'and demoted to a benign ok:false decision');
});

test('F3: evaluate() RE-THROWS a propagating GlobBudgetError instead of swallowing it', () => {
  // evaluate() does not itself reach the matcher today, so the budget error is injected
  // via a throwing getter to prove the catch block re-throws the sentinel - a defensive
  // mirror of the decide() fix that closes the surface should a future change route a
  // matcher call through the statement walk.
  const boobyStmt = {
    get effect() { throw new GlobBudgetError('work'); },
    index: 0, sid: 'x', actions: ['s3:*'], notActions: [], resources: ['*'], notResources: [], condition: null,
  };
  let threw = false;
  let wasBudget = false;
  try {
    evaluate({ statements: [boobyStmt] });
  } catch (e) {
    threw = true;
    wasBudget = isGlobBudgetError(e);
  }
  assert.equal(threw, true, 'a propagating budget error must not be swallowed by evaluate()');
  assert.equal(wasBudget, true, 're-thrown error is the GlobBudgetError sentinel');
});

test('F3: evaluate() still SWALLOWS a genuine internal fault to a benign ok:false result', () => {
  const boobyStmt = {
    get effect() { throw new Error('internal boom'); },
    index: 0, sid: 'x', actions: ['s3:*'], notActions: [], resources: ['*'], notResources: [], condition: null,
  };
  let threw = false;
  let result = null;
  try {
    result = evaluate({ statements: [boobyStmt] });
  } catch (e) {
    threw = true;
  }
  assert.equal(threw, false, 'a plain internal fault is still swallowed, never re-thrown');
  assert.equal(result && result.ok, false, 'and demoted to a benign ok:false result');
});
