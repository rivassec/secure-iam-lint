// Regression tests for story S4-sarif-sid.
//
// THREAT: the statement Sid is attacker-controlled free-form policy text (it rides
// through the engine verbatim - engine/rules.js statementSid() returns stmt.sid). The
// SARIF adapter used to (a) inject it verbatim into result.message.text, which GitHub
// renders as MARKDOWN in the Security tab - so `[x](javascript:...)`, newlines, or a
// 10KB blob could inject a link/line-break/bloat - and (b) fold the RAW Sid into the
// partialFingerprints identity, so a fork PR could craft a Sid whose fingerprint
// COLLIDES with a dismissed base-branch alert and auto-suppress a real finding
// (a fail-OPEN).
//
// FIX (cli/sarif.mjs): sanitize the Sid (strip control chars/newlines/backticks, cap
// length + ellipsize) and render it as a DISTINCT backtick-quoted inline-code token,
// never as free prose; apply the same to properties.statementSid and evidence Sids;
// and EXCLUDE the raw Sid from the fingerprint identity (fingerprint on type + family
// + statement POSITION + normalized action/resource/principal/condition), so a hostile
// Sid can neither inject markdown nor force a fingerprint collision.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import {
  buildSarifLog, formatSarif, findingIdentity, FINGERPRINT_KEY,
} from '../../../cli/sarif.mjs';

const MANIFEST = { ruleVersion: '1' };

// A run of every char the sanitizer must strip: C0 controls, DEL, C1 controls, backtick.
const CONTROL_AND_BACKTICK = /[\u0000-\u001F\u007F-\u009F`]/;

// An admin-identity policy (iam:* on *) fires DIRECT-IAM-ADMIN, whose finding carries
// the statement Sid verbatim - the exact injection channel under test.
function adminPolicy(sid) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: sid, Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
  });
}

function securityResult(text) {
  const result = scan({ text, family: 'identity' });
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const sec = log.runs[0].results.filter((r) => r.properties.category === 'security');
  assert.ok(sec.length >= 1, 'a security finding is present');
  return sec[0];
}

// --- message.text: hostile Sid is neutralized -------------------------------------

test('S4: a markdown-link payload Sid is wrapped in an inline-code token, never free prose', () => {
  const sid = '[x](javascript:alert(document.domain))';
  const res = securityResult(adminPolicy(sid));
  const msg = res.message.text;
  // The Sid appears exactly once, bracketed by backticks (an inline-code span), so
  // GitHub markdown cannot render the `[label](url)` as a live link.
  const idx = msg.indexOf(sid);
  assert.ok(idx > 0, 'sanitized Sid is present in the message');
  assert.equal(msg.indexOf(sid, idx + 1), -1, 'Sid appears exactly once');
  assert.equal(msg[idx - 1], '`', 'Sid is immediately preceded by a backtick');
  assert.equal(msg[idx + sid.length], '`', 'Sid is immediately followed by a backtick');
});

test('S4: newlines in a Sid cannot break the rendered message across lines', () => {
  const sid = 'FirstLine\nSecondLine [evil](javascript:1)\r\nThird';
  const res = securityResult(adminPolicy(sid));
  assert.ok(!/[\r\n]/.test(res.message.text), 'no newline leaks into message.text');
  assert.ok(!/[\r\n]/.test(res.properties.statementSid), 'no newline leaks into properties.statementSid');
  // whitespace runs collapse to single spaces
  assert.ok(res.properties.statementSid.startsWith('FirstLine SecondLine'));
});

test('S4: a 10KB Sid is length-capped + ellipsized in message and properties', () => {
  const big = 'A'.repeat(10 * 1024);
  const res = securityResult(adminPolicy(big));
  const ps = res.properties.statementSid;
  assert.ok(ps.length <= 128 + 3, `statementSid capped (${ps.length})`);
  assert.ok(ps.endsWith('...'), 'ellipsized');
  // The message stays bounded - the 10KB blob never lands verbatim.
  assert.ok(res.message.text.length < 512, `message stays bounded (${res.message.text.length})`);
  assert.ok(!res.message.text.includes(big), 'raw 10KB blob is not embedded');
});

test('S4: control characters and backticks never survive into a rendered field', () => {
  // ESC (0x1B) + ANSI, a C1 control (0x9F), and a backtick breakout attempt.
  const sid = 'Ok\u001B[31mred' + '`breakout`' + '\u0007\u009FEnd';
  const res = securityResult(adminPolicy(sid));
  assert.ok(!CONTROL_AND_BACKTICK.test(res.properties.statementSid),
    'no control chars or backticks in properties.statementSid');
  assert.ok(!CONTROL_AND_BACKTICK.test(res.message.text.replace(/`/g, '')),
    'no control chars in message.text (backticks are only the two wrapper delimiters)');
  // A backtick pair inside the Sid cannot close the wrapper and open a new span.
  assert.ok(!res.message.text.includes('`breakout`'), 'a backtick pair cannot escape the code span');
});

// --- message.text: hostile ACTION list is neutralized too (same class as the Sid) ---
//
// An Action is as attacker-controlled as a Sid (a fork PR owns the whole policy JSON),
// and it is embedded in the SAME markdown-rendered message.text. It must get the SAME
// neutralization + distinct-token quoting as the Sid, never free prose.

// A policy whose Action carries a markdown/newline payload. A single-statement wildcard
// resource on the identity family fires a broad-resource finding that carries the
// actions verbatim into message.text.
function actionPolicy(action) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'S', Effect: 'Allow', Action: action, Resource: '*' }],
  });
}

test('S4: a markdown-link payload in an Action is wrapped in an inline-code token, never free prose', () => {
  const action = '[pwn](javascript:alert(document.domain))';
  const res = securityResult(actionPolicy(action));
  const msg = res.message.text;
  const idx = msg.indexOf(action);
  assert.ok(idx > 0, 'sanitized action is present in the message');
  assert.equal(msg[idx - 1], '`', 'action is immediately preceded by a backtick');
  assert.equal(msg[idx + action.length], '`', 'action is immediately followed by a backtick');
  // The markdown link never lands outside a code span (as free prose).
  assert.ok(!/actions: \[pwn\]\(javascript:/.test(msg), 'action link is not emitted as free prose');
});

test('S4: newlines/control chars in an Action cannot break the rendered message across lines', () => {
  const action = '[pwn](javascript:alert(1))\nInjected-2nd-line\r\nThird[31m';
  const res = securityResult(actionPolicy(action));
  assert.ok(!/[\r\n]/.test(res.message.text), 'no newline leaks into message.text via an Action');
  assert.ok(!CONTROL_AND_BACKTICK.test(res.message.text.replace(/`/g, '')),
    'no control chars in message.text via an Action (backticks are only wrapper delimiters)');
});

test('S4: a backtick breakout in an Action cannot escape its code span', () => {
  const action = 'ok`breakout`[x](javascript:1)';
  const res = securityResult(actionPolicy(action));
  assert.ok(!res.message.text.includes('`breakout`'), 'a backtick pair in an Action cannot escape the code span');
});

// The cap-under-hostile-oversize cases exercise the SARIF adapter directly with a
// synthetic finding (mirroring the findingIdentity tests below): a 10KB Action arriving
// through scan() would trip the input-size fail-closed guard (owned by S3-dos-budget)
// before any finding is produced, so the adapter's own bound is proven at buildSarifLog.
function syntheticMessage(finding) {
  const log = buildSarifLog({ findings: [finding], family: 'identity' }, { file: 'p.json' }, MANIFEST);
  const sec = log.runs[0].results.filter((r) => r.properties.category === 'security');
  assert.ok(sec.length >= 1, 'a security finding is present');
  return sec[0].message.text;
}

test('S4: a 10KB Action is length-capped in message.text and never lands verbatim', () => {
  const big = 'a'.repeat(10 * 1024);
  const msg = syntheticMessage({
    id: 'T', severity: 'high', title: 't', statementIndex: 0, statementSid: 'S',
    actions: [big], resources: ['*'], conditions: null,
  });
  assert.ok(!msg.includes(big), 'raw 10KB Action blob is not embedded');
  assert.ok(msg.length < 512, `message stays bounded (${msg.length})`);
  assert.ok(!CONTROL_AND_BACKTICK.test(msg.replace(/`/g, '')), 'no control chars survive');
});

test('S4: a huge Action array is token-capped with a (+N more) count, not bloated', () => {
  const actions = [];
  for (let i = 0; i < 50; i++) actions.push(`svc:Op${String(i).padStart(3, '0')}`);
  const msg = syntheticMessage({
    id: 'T', severity: 'high', title: 't', statementIndex: 0, statementSid: 'S',
    actions, resources: ['*'], conditions: null,
  });
  assert.ok(/\(\+\d+ more\)/.test(msg), 'elided remainder is reported as a count');
  assert.ok(msg.length < 1024, `message stays bounded (${msg.length})`);
});

test('S4: a benign Action rides through message.text as a quoted token (no false mangling)', () => {
  const res = securityResult(actionPolicy('s3:GetObject'));
  assert.ok(res.message.text.includes('`s3:GetObject`'), 'benign action is a quoted inline-code token');
});

// --- partialFingerprints: hostile Sid cannot force a collision / churn -------------

test('S4: a hostile Sid does NOT change the fingerprint of an otherwise-identical finding', () => {
  const benign = scan({ text: adminPolicy('CleanSid'), family: 'identity' });
  const hostile = scan({
    text: adminPolicy(`[x](javascript:alert(1))\n${'B'.repeat(10000)}`),
    family: 'identity',
  });
  const fpBenign = buildSarifLog(benign, {}, MANIFEST)
    .runs[0].results.find((r) => r.properties.category === 'security')
    .partialFingerprints[FINGERPRINT_KEY];
  const fpHostile = buildSarifLog(hostile, {}, MANIFEST)
    .runs[0].results.find((r) => r.properties.category === 'security')
    .partialFingerprints[FINGERPRINT_KEY];
  assert.equal(fpHostile, fpBenign,
    'the raw Sid is excluded from fingerprint identity, so it cannot force a collision or churn');
});

test('S4: findingIdentity ignores the Sid entirely (type/family/position/action/resource only)', () => {
  const base = {
    id: 'T', severity: 'high', title: 't',
    statementIndex: 0, statementSid: 'Benign',
    actions: ['iam:*'], resources: ['*'], conditions: null,
  };
  const hostile = { ...base, statementSid: `[x](javascript:alert(1))\n${'B'.repeat(10000)}` };
  assert.equal(findingIdentity(hostile, 'identity'), findingIdentity(base, 'identity'),
    'the Sid is not part of the semantic identity');
  assert.ok(!findingIdentity(base, 'identity').includes('Benign'),
    'the identity string carries no Sid at all');
  // A different STATEMENT POSITION still separates findings (position is structural,
  // not attacker-forgeable against a semantically different finding).
  const movedStmt = { ...base, statementIndex: 1 };
  assert.notEqual(findingIdentity(movedStmt, 'identity'), findingIdentity(base, 'identity'));
});

// --- no over-correction: a benign Sid rides through intact -------------------------

test('S4: a benign Sid is passed through unchanged (no false mangling)', () => {
  const res = securityResult(adminPolicy('AllowLambdaDeployment'));
  assert.equal(res.properties.statementSid, 'AllowLambdaDeployment');
  assert.ok(res.message.text.includes('`AllowLambdaDeployment`'),
    'benign Sid is still rendered as a quoted token');
});

// --- determinism holds under hostile input ----------------------------------------

test('S4: SARIF is byte-identical across builds even with a hostile Sid', () => {
  const text = adminPolicy(`[x](javascript:alert(1))\n${'Z'.repeat(9000)}`);
  const result = scan({ text, family: 'identity' });
  assert.equal(
    formatSarif(result, { file: 'p.json' }, MANIFEST),
    formatSarif(result, { file: 'p.json' }, MANIFEST),
  );
});
