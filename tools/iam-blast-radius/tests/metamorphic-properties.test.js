// B1: metamorphic security-property oracle + a proof that the OLD coarse parity
// predicate was blind to content substitution (the class the A1 fail-open belonged to).

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import {
  isClean, findingKeySet, setsEqual, runAllProperties, spoofTwinKey, maxSevRank,
  addSpoofedDeny, checkSpoofedDenyInert,
} from './lib/metamorphic.mjs';

const A = (policy, family) => analyze(JSON.stringify(policy), { family, requireExplicitFamily: true });

// Representative corpus across families + severities.
const CORPUS = [
  { family: 'identity', policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] } },
  { family: 'identity', policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['iam:PassRole', 'lambda:CreateFunction'], Resource: '*' }] } },
  { family: 'identity', policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::bkt/key' }] } },
  { family: 'identity', policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*', Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-x' } } }] } },
  { family: 'identity', policy: { Version: '2012-10-17', Statement: [{ Sid: 'a', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' }, { Sid: 'b', Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' }] } },
  { family: 'role-trust', policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole' }] } },
  { family: 'role-trust', policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole' }] } },
];

test('metamorphic security properties hold across the corpus (broaden/order/spoof monotonicity)', () => {
  const allFails = [];
  for (const { family, policy } of CORPUS) {
    const fails = runAllProperties((t, o) => analyze(t, o), policy, { family, requireExplicitFamily: true });
    if (fails.length) allFails.push(`[${family}] ${JSON.stringify(policy.Statement)}\n   - ${fails.join('\n   - ')}`);
  }
  assert.equal(allFails.length, 0, `metamorphic property violations:\n${allFails.join('\n')}`);
});

test('spoof-twin monotonicity specifically holds on the A1 trust PoC', () => {
  const poc = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole' }] };
  const base = A(poc, 'role-trust');
  const twin = A(spoofTwinKey(poc), 'role-trust');
  // base fires TRUST-PUBLIC:critical; the spoof-twin must NOT read cleaner (post-fix it
  // fails closed). Never clean, never lower severity.
  assert.equal(isClean(base), false);
  assert.ok(!isClean(twin), 'spoof-twin must not be clean');
  assert.ok(maxSevRank(twin) >= maxSevRank(base) || maxSevRank(twin) === Infinity,
    'spoof-twin must not lower severity below the original');
});

// --- Proof the OLD oracle was blind to content substitution (B1 justification) ---
test('content-level oracle catches a substitution the clean-bool oracle cannot', () => {
  const poc = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] };
  const real = A(poc, 'identity');
  assert.ok((real.findings || []).some((f) => f.severity === 'critical'), 'sanity: admin policy fires a critical');

  // Simulate an A1-style content-substitution regression: a hypothetical buggy engine
  // that SWAPS the critical finding for a benign LOW one (findings.length stays > 0).
  const buggy = { ...real, findings: [{ id: 'BENIGN', severity: 'low' }] };

  // OLD oracle (the coarse predicate that let A1 through): only asks "is it clean?".
  // Both real and buggy are non-clean (findings.length !== 0), so it sees NO difference.
  assert.equal(isClean(real), isClean(buggy), 'clean-bool oracle is BLIND: real and buggy both non-clean');

  // NEW content-level oracle: compares the {id:severity} set -> catches the swap, and
  // sees the max severity was silently lowered from critical to low.
  assert.ok(!setsEqual(findingKeySet(real), findingKeySet(buggy)), 'content oracle CATCHES the substitution');
  assert.ok(maxSevRank(buggy) < maxSevRank(real), 'content oracle sees the severity was lowered critical->low');
});

// --- Stage-11 RC-B: the oracle must SEE the #1 class (spoofed-Deny suppression) ---

// ABSOLUTE reference probe: a fixed set of known-risky policies that must NEVER read
// clean, independent of any metamorphic gating. This catches the T8 false-clean class
// directly - a base that is wrongly clean is invisible to every property that gates on
// hasConcreteFinding(base), so we also assert the ground truth head-on.
const NEVER_CLEAN = [
  { family: 'identity', why: 'admin *:*', policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] } },
  { family: 'identity', why: 'inline-policy self-escalation', policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'iam:PutUserPolicy', Resource: '*' }] } },
  { family: 'identity', why: '#1 spoofed-Deny fail-open', policy: { Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Action: 'iam:PutUserPolicy', Resource: '*' },
    { Effect: 'Deny', Action: 'iam:PutUser​Policy', Resource: '*' },
  ] } },
  { family: 'role-trust', why: 'public assume-role', policy: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole' }] } },
];

test('absolute probe: known-risky policies never read clean (T8 ground truth)', () => {
  for (const { family, why, policy } of NEVER_CLEAN) {
    const r = A(policy, family);
    assert.equal(isClean(r), false, `MUST NOT read clean: ${why}`);
  }
});

test('new property holds on the real engine and would CATCH a spoofed-Deny suppressor', () => {
  const poc = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'iam:PutUserPolicy', Resource: '*' }] };
  const opts = { family: 'identity', requireExplicitFamily: true };

  // On the fixed engine the property holds: adding an AWS-inert spoofed Deny does not
  // lower risk (it flips the verdict to incomplete -> maxSevRank Infinity).
  const real = (t, o) => analyze(t, o);
  assert.deepEqual(checkSpoofedDenyInert(real, poc, opts), { ok: true, msg: 'spoofed-deny-inert ok' });

  // Proof the property is NOT vacuous: a stub engine that de-spoofs the Deny and lets it
  // SUPPRESS the finding (the pre-fix #1 behavior) is caught. The stub returns the base
  // finding for the Allow-only policy but a CLEAN result once the spoofed Deny is present.
  const vulnerable = (t) => {
    const p = JSON.parse(t);
    const hasSpoofedDeny = (p.Statement || []).some((s) => s.Effect === 'Deny' && String(s.Action).includes('​'));
    if (hasSpoofedDeny) return { ok: true, findings: [], coverage: { summary: { incomplete: false } } };
    return { ok: true, findings: [{ id: 'PUT-INLINE-POLICY', severity: 'high' }], coverage: { summary: { incomplete: false } } };
  };
  const verdict = checkSpoofedDenyInert(vulnerable, poc, opts);
  assert.equal(verdict.ok, false, 'the property MUST catch a spoofed-Deny suppressor (else it is vacuous)');
  assert.match(verdict.msg, /T8 #1 fail-open/);
});

test('spoofTwinKey overwrites with a DISTINCT decoy (a copy would not guard the A1 fix)', () => {
  // #5: the twin value must differ from the original, so removing the A1 collision guard
  // would actually change the model (last-key-wins installs the decoy) and be caught.
  const poc = { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999999999999:root' }, Action: 'sts:AssumeRole' }] };
  const twinned = spoofTwinKey(poc);
  const principal = twinned.Statement[0].Principal;
  const twinKey = Object.keys(principal).find((k) => k.includes('​'));
  assert.ok(twinKey, 'a zero-width twin key was added');
  assert.notEqual(principal[twinKey], principal.AWS, 'the decoy value must DIFFER from the real value');
});
