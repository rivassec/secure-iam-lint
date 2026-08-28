// S2-passrole-allstmts (iter-4, axis 1) — an {other}-shaped SAME-account PassRole role
// glob co-located with a concrete FOREIGN role must keep the compound path CRITICAL.
//
// Regression for a CRITICAL fail-open of the same CLASS as the statement-ORDER and
// ARN-SPELLING demotions (threat-model T8). ROLE_ARN_PARTS_RE only pins a concrete
// arn:...:role/<name>; a same-account token WITHOUT the literal ':role/' (arn:<acct>:role*,
// :r*, :role?*, :*, a leading wildcard) parsed as {other}, and resourceReachesSubject
// returned a flat false for {other}. A co-located concrete FOREIGN role then drove a
// confident critical->medium PASSROLE_CROSS_ACCOUNT_INCOMPATIBLE demotion; because
// 'role*' also evades the WILDCARD-RESOURCE backstop, no HIGH finding survived and
// scan() reported exit 0 CLEAN on a fully-viable, wildcard-scoped, SAME-account PassRole
// grant. In AWS IAM these globs match every same-account role ARN, so the path is viable.
//
// The fix credits an {other} token as REACHING the subject when, read as an IAM wildcard
// glob, it COULD name a role ARN in the subject's own account+partition (a bounded,
// non-fixed-probe glob-produces-prefix decision), so a viable same-account glob keeps the
// path CRITICAL and never lets a co-located foreign role demote it. This drives every
// spelling through the real engine (analyze()) AND the fail-closed CLI adapter (scan())
// and asserts the finding stays critical (no confident demotion code) and scan() never
// reports exit 0 CLEAN — independent of resource order and statement order. A canonical
// control (arn:...:role/*) confirms the fix did not over-correct.
//
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(
  join(here, '..', 'fixtures', 'order-invariance',
    'passrole-other-shaped-same-account-reaches.json'),
  'utf8',
));

const ctx = fixture.context;
const want = fixture.expect;
const findingId = want.findingId;
const foreign = fixture.foreignConcreteRole;

const analyzeOpts = { subjectAccount: ctx.subjectAccount, partition: ctx.partition };
const scanBase = { family: 'identity', subjectAccount: ctx.subjectAccount, partition: ctx.partition };

function policyFor(passResourceArray) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [fixture.runStatement, {
      Sid: 'Pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: passResourceArray,
    }],
  });
}

function passStatementFor(token, order) {
  // order: 'passOtherThenForeign' or 'passForeignThenOther'
  const other = fixture.variants[token];
  const resources = order === 'passForeignThenOther' ? [foreign, other] : [other, foreign];
  return { Sid: 'Pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: resources };
}

function findPassrole(res) {
  return (res.findings || []).find((x) => x.id === findingId);
}

// --- Each {other} same-account glob co-located with a foreign role stays CRITICAL. ---
for (const [name, other] of Object.entries(fixture.variants)) {
  // Resource-order A: [other, foreign].  Resource-order B: [foreign, other].
  for (const [orderLabel, resources] of [
    ['other-then-foreign', [other, foreign]],
    ['foreign-then-other', [foreign, other]],
  ]) {
    const text = policyFor(resources);

    test(`analyze(): {other} same-account glob stays critical, no confident demotion [${name}/${orderLabel}]`, () => {
      const res = analyze(text, analyzeOpts);
      assert.equal(res.ok, true, 'analyze() ok');
      const f = findPassrole(res);
      assert.ok(f, `${findingId} must be present (never demoted-then-dropped) [${name}/${orderLabel}]`);
      assert.equal(f.severity, want.everyVariant.analyzeSeverity,
        `must stay ${want.everyVariant.analyzeSeverity}: a same-account role glob is a viable pass [${name}/${orderLabel}]`);
      const esc = f.escalation || {};
      for (const code of want.everyVariant.mustNotHaveWarningCode) {
        assert.ok(
          !(esc.warningCodes || []).includes(code),
          `must NOT assert a confident ${code} demotion when a same-account glob reaches the subject [${name}/${orderLabel}]`,
        );
      }
    });

    test(`scan(): {other} same-account glob NEVER reports exit 0 CLEAN [${name}/${orderLabel}]`, () => {
      const r = scan({ ...scanBase, text });
      assert.notEqual(r.exitCode, 0, `must not be exit 0 [${name}/${orderLabel}]`);
      assert.notEqual(r.exitCode, EXIT.CLEAN, `must not be CLEAN exit [${name}/${orderLabel}]`);
      assert.notEqual(r.reason, 'CLEAN', `reason must not be CLEAN [${name}/${orderLabel}]`);
      assert.equal(r.exitCode, EXIT.FINDINGS,
        `a viable same-account critical path must gate at exit 1 [${name}/${orderLabel}]`);
    });
  }
}

// --- Non-canonical {other} scaffold: UNKNOWN viability, fail CLOSED (never a --------
// confident demotion caught only by a coincidental backstop). An {other}-shaped token
// whose IAM-ARN scaffold/partition/account is non-canonical (uppercase, whitespace,
// short account) cannot be confidently compared to the subject, so it must stay
// critical + record requiredUnknowns and scan() must fail CLOSED (exit 3), NOT be
// confidently demoted cross-account.
for (const [name, other] of Object.entries(fixture.unmodelableVariants)) {
  const uw = want.unmodelableVariant;
  for (const [orderLabel, resources] of [
    ['other-then-foreign', [other, foreign]],
    ['foreign-then-other', [foreign, other]],
  ]) {
    const text = policyFor(resources);

    test(`analyze(): non-canonical {other} scaffold stays critical + unknown-viability [${name}/${orderLabel}]`, () => {
      const res = analyze(text, analyzeOpts);
      const f = findPassrole(res);
      assert.ok(f, `${findingId} present [${name}/${orderLabel}]`);
      assert.equal(f.severity, uw.analyzeSeverity,
        `must stay critical: a non-canonical token is UNKNOWN, not a confident cross-account medium [${name}/${orderLabel}]`);
      const esc = f.escalation || {};
      for (const code of uw.mustNotHaveWarningCode) {
        assert.ok(!(esc.warningCodes || []).includes(code),
          `must NOT assert a confident ${code} demotion on an unmodelable token [${name}/${orderLabel}]`);
      }
      assert.ok(Array.isArray(esc.requiredUnknowns) && esc.requiredUnknowns.length > 0,
        `must record requiredUnknowns so the fail-closed guard fires [${name}/${orderLabel}]`);
    });

    test(`scan(): non-canonical {other} scaffold fails CLOSED (exit 3), never CLEAN [${name}/${orderLabel}]`, () => {
      const r = scan({ ...scanBase, text });
      assert.notEqual(r.exitCode, 0, `must not be exit 0 [${name}/${orderLabel}]`);
      assert.notEqual(r.reason, 'CLEAN', `reason must not be CLEAN [${name}/${orderLabel}]`);
      assert.equal(r.exitCode, EXIT.FAIL_CLOSED,
        `an unmodelable token is unknown viability -> exit 3 [${name}/${orderLabel}]`);
    });
  }
}

// --- Statement-order independence: Pass before/after the exec statement. ---------
for (const ordering of fixture.orderings) {
  const label = ordering.join(' -> ');
  const token = 'rolePrefixNoSlash';
  const statements = ordering.map((tok) => {
    if (tok === 'run') return fixture.runStatement;
    return passStatementFor(token, tok);
  });
  const text = JSON.stringify({ Version: '2012-10-17', Statement: statements });

  test(`scan(): gates at exit 1 regardless of statement/resource order [${label}]`, () => {
    const r = scan({ ...scanBase, text });
    assert.notEqual(r.exitCode, EXIT.CLEAN, 'must never report CLEAN');
    assert.equal(r.exitCode, EXIT.FINDINGS,
      'a viable same-account glob keeps the path critical in every permutation');
  });

  test(`analyze(): finding stays critical regardless of statement/resource order [${label}]`, () => {
    const res = analyze(text, analyzeOpts);
    const f = findPassrole(res);
    assert.ok(f, `${findingId} present [${label}]`);
    assert.equal(f.severity, 'critical', `severity for ordering [${label}]`);
  });
}

// --- Canonical control: the fix did NOT over-correct into a false positive. -------
test('scan(): canonical same-account role/* co-located with a foreign role gates at exit 1', () => {
  const r = scan({ ...scanBase, text: policyFor([fixture.canonicalControl, foreign]) });
  assert.equal(r.exitCode, want.canonicalControl.scanExitCode);
  assert.equal(r.exitCode, EXIT.FINDINGS);
});

test('analyze(): canonical same-account role/* is a plain critical finding', () => {
  const res = analyze(policyFor([fixture.canonicalControl, foreign]), analyzeOpts);
  const f = findPassrole(res);
  assert.ok(f);
  assert.equal(f.severity, want.canonicalControl.analyzeSeverity);
});

// --- Determinism (architecture invariant #8). ----------------------------------
test('analyze(): deterministic findings for a fixed {other} same-account glob', () => {
  const text = policyFor([fixture.variants.rolePrefixNoSlash, foreign]);
  const a = JSON.stringify(analyze(text, analyzeOpts).findings);
  const b = JSON.stringify(analyze(text, analyzeOpts).findings);
  assert.equal(a, b);
});
