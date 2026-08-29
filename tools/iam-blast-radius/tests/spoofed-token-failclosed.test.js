// Stage-11 re-review, RC-A (finding #1, critical fail-open + #7).
//
// stripModelSpoof de-spoofs a token VALUE at the model boundary and the engine
// then TRUSTS the cleaned token. That is safe for an Allow ACTION (de-spoofing
// only makes more rules fire) but it is a T8 FAIL-OPEN in the suppression
// direction: a Deny action carrying an invisible code point (e.g. a zero-width
// space) is AWS-INERT - AWS matches the literal requested action against the
// Deny pattern that still carries the code point and does NOT match, so the
// Allow is live - yet the linter de-spoofs the Deny into `iam:PutUserPolicy`,
// credits it as covering the Allow, and returns exit 0 / CLEAN / findings=[].
//
// The homograph control (Cyrillic 'p', NOT in the strip class) already fails
// CLOSED (exit 3, incomplete) because its token stays non-canonical. This suite
// pins the fix: any SECURITY-RELEVANT token that CHANGES under stripModelSpoof
// must flip coverage.summary.incomplete (fail closed), never a bare CLEAN, while
// the model still stores the cleaned value (S4 display invariant is untouched).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';

const ZWSP = '​';
const SHY = '­'; // soft hyphen
const WJ = '⁠'; // word joiner
const VS16 = '️'; // variation selector-16

const policy = (denyAction) => JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'iam:PutUserPolicy', Resource: '*' },
    ...(denyAction ? [{ Effect: 'Deny', Action: denyAction, Resource: '*' }] : []),
  ],
});

const run = (denyAction) => scan({ text: policy(denyAction), family: 'identity' });

test('RC-A #1: an Allow-only policy fires PUT-INLINE-POLICY (baseline)', () => {
  const r = run(null);
  assert.notEqual(r.exitCode, 0, 'a live admin grant is never a clean pass');
  assert.ok((r.findings || []).some((f) => /PUT-INLINE-POLICY/.test(f.id)),
    'the real capability surfaces');
});

test('RC-A #1: a genuine clean Deny legitimately reads clean (no over-correction)', () => {
  const r = run('iam:PutUserPolicy');
  assert.equal(r.exitCode, 0, 'an explicit Deny that AWS honors wins -> clean');
  assert.equal((r.findings || []).length, 0);
});

for (const [name, cp] of [['ZWSP U+200B', ZWSP], ['soft-hyphen U+00AD', SHY],
  ['word-joiner U+2060', WJ], ['VS16 U+FE0F', VS16]]) {
  test(`RC-A #1: a spoofed Deny action (${name}) MUST NOT read clean (fail closed)`, () => {
    const r = run(`iam:PutUser${cp}Policy`);
    // The core T8 assertion: never exit 0 / CLEAN on a policy carrying a live
    // capability behind an AWS-inert (spoofed) Deny.
    assert.notEqual(r.exitCode, 0,
      `spoofed Deny (${name}) suppressed the finding -> FAIL-OPEN`);
    assert.equal(r.reason, 'COVERAGE_INCOMPLETE',
      'a de-spoofed (tampered) token flips coverage.summary.incomplete, like the homograph control');
    assert.equal(r.coverage.summary.incomplete, true, 'coverage marks the analysis incomplete');
    // The de-spoofed Deny still suppresses the finding IN-MODEL (findings may be
    // empty), but the tampered token flips the verdict to INCOMPLETE so it is never
    // a clean pass - that is the fail-closed property. The stable code names why.
    assert.ok((r.coverage.summary.codes || []).includes('SPOOFED_TOKEN_NORMALIZED'),
      'the incomplete verdict names the spoofed-token reason');
  });
}

test('RC-A #7: a spoofed Condition KEY must not credit an unmodeled guardrail into a clean pass', () => {
  // sts:ExternalId spelled with an embedded ZWSP: de-spoofing it onto a modeled
  // guardrail key must not flip a fail-closed (exit 3) into a clean exit 0.
  const p = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Action: 'sts:AssumeRole',
      Resource: '*',
      Condition: { StringEquals: { [`sts:External${ZWSP}Id`]: 'abc' } },
    }],
  });
  const r = scan({ text: p, family: 'identity' });
  assert.notEqual(r.exitCode, 0, 'a spoofed condition key must never yield a clean pass');
  assert.equal(r.coverage.summary.incomplete, true, 'spoofed condition key -> incomplete (fail closed)');
});

test('RC-A: a legitimate ASCII policy is unaffected (no false fail-closed)', () => {
  // No invisible code points anywhere -> stripModelSpoof is a no-op -> the
  // spoofed-token signal never fires, so a genuinely clean policy stays clean.
  const p = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }],
  });
  const r = scan({ text: p, family: 'identity' });
  assert.equal(r.reason, 'CLEAN', 'a pure-ASCII clean policy stays clean');
  assert.equal(r.exitCode, 0, 'no false fail-closed on legitimate input');
});
