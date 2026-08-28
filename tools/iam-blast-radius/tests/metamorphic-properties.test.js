// B1: metamorphic security-property oracle + a proof that the OLD coarse parity
// predicate was blind to content substitution (the class the A1 fail-open belonged to).

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import {
  isClean, findingKeySet, setsEqual, runAllProperties, spoofTwinKey, maxSevRank,
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
