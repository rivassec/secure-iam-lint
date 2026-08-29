// Stage-14 CRITICAL (FAILOPEN-PASSEDTOSERVICE-CASEFOLD): operatorPermitsService()
// case-folded the condition VALUE for EVERY operator, including the case-SENSITIVE
// negated denylist operators (StringNotEquals/StringNotLike/ArnNotEquals/ArnNotLike).
// AWS StringNotEquals is case-sensitive: an UPPERCASE iam:PassedToService denylist
// value ("LAMBDA.AMAZONAWS.COM") does NOT equal the request's canonical lowercase
// principal ("lambda.amazonaws.com"), so the NotEquals is TRUE, the Allow applies, and
// iam:PassRole->lambda is genuinely permitted. The folded matcher over-matched, misread
// the entry as a real deny, and SUPPRESSED PASSROLE-LAMBDA -> a real critical capability
// read CLEAN (active suppression). Fix: fold the value ONLY for the *IgnoreCase base
// operators. This suite pins both directions.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const A = (policy) => analyze(JSON.stringify(policy), { family: 'identity', requireExplicitFamily: true });
const ids = (r) => (r.findings || []).map((f) => f.id);
const passLambda = (cond) => ({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow', Action: ['iam:PassRole', 'lambda:CreateFunction'],
    Resource: 'arn:aws:iam::111122223333:role/app',
    ...(cond ? { Condition: cond } : {}),
  }],
});

test('CRITICAL: an UPPERCASE StringNotEquals PassedToService denylist must NOT suppress the escalation', () => {
  const p = passLambda({ StringNotEquals: { 'iam:PassedToService': 'LAMBDA.AMAZONAWS.COM' } });
  const r = A(p);
  assert.ok(ids(r).includes('PASSROLE-LAMBDA'),
    'AWS StringNotEquals is case-sensitive: "LAMBDA..." != "lambda..." so the Deny is TRUE, the Allow applies, and PassRole->lambda is permitted -> the escalation must fire');
  const s = scan({ text: JSON.stringify(p), family: 'identity' });
  assert.notEqual(s.exitCode, 0, 'CLI must not read CLEAN on the suppressed escalation');
});

test('control: the same policy with NO condition fires PASSROLE-LAMBDA:critical', () => {
  const r = A(passLambda(null));
  const f = r.findings.find((x) => x.id === 'PASSROLE-LAMBDA');
  assert.ok(f && f.severity === 'critical');
});

test('StringNotEqualsIgnoreCase UPPERCASE correctly stays clean (AWS folds -> a real deny)', () => {
  // IgnoreCase DOES fold at AWS: "LAMBDA..." == "lambda..." -> NotEquals FALSE -> the
  // Deny condition holds -> PassRole->lambda is genuinely blocked -> clean is correct.
  const r = A(passLambda({ StringNotEqualsIgnoreCase: { 'iam:PassedToService': 'LAMBDA.AMAZONAWS.COM' } }));
  assert.ok(!ids(r).includes('PASSROLE-LAMBDA'), 'IgnoreCase folds -> genuine deny -> no escalation');
});

test('lowercase StringNotEquals denylist for lambda correctly suppresses (true deny)', () => {
  // "lambda.amazonaws.com" == request value -> NotEquals FALSE -> deny -> blocked -> clean.
  const r = A(passLambda({ StringNotEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } }));
  assert.ok(!ids(r).includes('PASSROLE-LAMBDA'), 'an exact-case denylist genuinely blocks lambda');
});

test('lowercase StringEquals allowlist for lambda permits -> PASSROLE-LAMBDA fires', () => {
  const r = A(passLambda({ StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } }));
  assert.ok(ids(r).includes('PASSROLE-LAMBDA'), 'an exact-case allowlist for lambda permits the pass');
});
