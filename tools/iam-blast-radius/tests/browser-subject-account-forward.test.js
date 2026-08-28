// S2-crossaccount-scoped-surface (iteration-2, finding #1): the BROWSER adapter must
// forward the analyzed-principal account id to the engine, so the flagship browser
// tool surfaces the SAME cross-account findings the CLI/action already can.
//
// Before the fix, worker.js called analyze(text, { family, requireExplicitFamily,
// resourceContext }) with NO subjectAccount, and app.js built none - so every
// CROSS-ACCOUNT-* finding was UNREACHABLE in the browser: a scoped cross-account
// sts:AssumeRole (or whole-container data read) read affirmatively CLEAN there while
// the CLI (given --subject-account) reported it. That is a browser fail-OPEN on the
// exact scoped-but-real capabilities this story targets (threat-model T8).
//
// This gate drives the REAL shipped worker.js message handler (not analyze() directly)
// under a minimal `self` shim - the same message shape app.js posts - and asserts the
// subject-account rides through to the engine. A regression that drops the forward
// (worker.js stops reading data.subjectAccount, or app.js stops posting it) makes the
// WITH-subject case go clean again and fails here.
//
// Runs under `node --test`. The shim only provides the two Worker globals worker.js
// touches (addEventListener + postMessage); the engine import is the real shipped code.

import { test } from 'node:test';
import assert from 'node:assert/strict';

const SUBJECT = '123456789012';
const OTHER = '999999999999';

function policy(statements) {
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}

// Load the shipped worker.js ONCE under a controllable `self` shim. worker.js registers
// its 'message' listener at import time and posts results back via self.postMessage; we
// capture both so a synthetic message drives the real adapter end to end.
let messageHandler = null;
let lastPosted = null;

test('setup: import the shipped worker.js under a self shim', async () => {
  globalThis.self = {
    addEventListener: (type, fn) => { if (type === 'message') messageHandler = fn; },
    postMessage: (m) => { lastPosted = m; },
  };
  await import('../../../content/tools/iam-blast-radius/worker.js');
  assert.equal(typeof messageHandler, 'function', 'worker.js registered a message handler');
});

// Drive the worker adapter exactly as app.js does (a structured-clone-shaped message)
// and return the engine result the worker posted back.
function runWorker(message) {
  lastPosted = null;
  messageHandler({ data: message });
  assert.ok(lastPosted && lastPosted.result, 'worker posted a result back');
  return lastPosted.result;
}

function findingIds(result) {
  return result.ok && Array.isArray(result.findings) ? result.findings.map((f) => f.id) : [];
}

function isClean(result) {
  return !!(result && result.ok === true
    && Array.isArray(result.findings) && result.findings.length === 0
    && !(result.coverage && result.coverage.summary && result.coverage.summary.incomplete));
}

test('finding #1: the worker forwards subjectAccount -> cross-account assume-role surfaces in the browser', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${OTHER}:role/X` },
  ]);
  const result = runWorker({
    id: 1, text, family: 'identity', requireExplicitFamily: true, subjectAccount: SUBJECT,
  });
  assert.ok(findingIds(result).includes('CROSS-ACCOUNT-ASSUME-ROLE'),
    `the browser worker must surface the cross-account finding; got [${findingIds(result)}]`);
  assert.equal(isClean(result), false, 'the browser must NOT read CLEAN on a cross-account scoped assume');
});

test('finding #1: the worker forwards subjectAccount -> cross-account whole-container read surfaces', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: `arn:aws:dynamodb:us-east-1:${OTHER}:table/app-data` },
  ]);
  const result = runWorker({
    id: 2, text, family: 'identity', requireExplicitFamily: true, subjectAccount: SUBJECT,
  });
  assert.ok(findingIds(result).includes('CROSS-ACCOUNT-DATA-READ'),
    `the browser worker must surface the cross-account data read; got [${findingIds(result)}]`);
});

test('conservative: NO subjectAccount (the pre-field browser default) stays quiet, not a false positive', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${OTHER}:role/X` },
  ]);
  const result = runWorker({ id: 3, text, family: 'identity', requireExplicitFamily: true });
  assert.deepEqual(findingIds(result), [],
    'without a subject account the browser stays conservatively quiet (cannot tell same- from cross-account)');
});

test('MUST-STAY-QUIET: same-account scoped assume stays quiet even with the subject forwarded', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${SUBJECT}:role/X` },
  ]);
  const result = runWorker({
    id: 4, text, family: 'identity', requireExplicitFamily: true, subjectAccount: SUBJECT,
  });
  assert.deepEqual(findingIds(result), [], 'same-account scoped assume is routine use and stays quiet');
  assert.equal(isClean(result), true);
});

test('a non-string subjectAccount is dropped by the worker (fails closed to quiet, never throws)', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${OTHER}:role/X` },
  ]);
  // A malformed field (object) must not be forwarded as a usable subject; the worker
  // drops it and the engine stays conservatively quiet.
  const result = runWorker({
    id: 5, text, family: 'identity', requireExplicitFamily: true, subjectAccount: { evil: true },
  });
  assert.deepEqual(findingIds(result), [], 'a non-string subject account is ignored, not trusted');
});
