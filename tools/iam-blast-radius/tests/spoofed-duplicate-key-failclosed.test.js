// Regression for the CRITICAL fail-open found in the multi-team review (A1):
// a spoofed DUPLICATE object key that differs only by an invisible control
// character (e.g. "AWS" vs "AWS​") survives validate.js's raw duplicate-key
// gate (raw strings differ), then stripModelSpoof collapses BOTH to the same
// normalized key, and the second silently OVERWRITES the first in
// normalizePrincipal / copyGuarded - erasing a real grant/condition while the tool
// reports ok:true, coverage.summary.incomplete:false.
//
// The engine MUST fail CLOSED on any post-normalization key collision, never
// silently drop the losing entry.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const ZWSP = '​';

function codes(r) {
  return (r.errors || []).map((e) => e.code);
}

test('Principal: a zero-width-twin AWS key must NOT silently erase Principal:"*"', () => {
  const attack = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Principal: { AWS: '*', [`AWS${ZWSP}`]: 'arn:aws:iam::111111111111:root' },
      Action: 'sts:AssumeRole',
    }],
  });
  const r = analyze(attack, { family: 'role-trust', requireExplicitFamily: true });
  // Fail closed: the collision is rejected (ok:false). It must NEVER read ok:true
  // with the public "*" quietly gone.
  assert.equal(r.ok, false, 'spoofed duplicate Principal key must fail closed, not analyze clean');
  assert.ok(codes(r).includes('SPOOFED_DUPLICATE_KEY'),
    `expected SPOOFED_DUPLICATE_KEY, got ${JSON.stringify(codes(r))}`);
});

test('Condition: a zero-width-twin condition key must NOT silently erase a restriction', () => {
  const attack = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow', Action: 's3:GetObject', Resource: '*',
      Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-real', [`aws:PrincipalOrgID${ZWSP}`]: 'o-decoy' } },
    }],
  });
  const r = analyze(attack, { family: 'identity', requireExplicitFamily: true });
  assert.equal(r.ok, false, 'spoofed duplicate Condition key must fail closed');
  assert.ok(codes(r).includes('SPOOFED_DUPLICATE_KEY'),
    `expected SPOOFED_DUPLICATE_KEY, got ${JSON.stringify(codes(r))}`);
});

test('Condition operator block: a zero-width-twin operator key must fail closed', () => {
  const attack = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow', Action: 's3:GetObject', Resource: '*',
      Condition: { StringEquals: { 'aws:x': '1' }, [`StringEquals${ZWSP}`]: { 'aws:y': '2' } },
    }],
  });
  const r = analyze(attack, { family: 'identity', requireExplicitFamily: true });
  assert.equal(r.ok, false, 'spoofed duplicate condition-operator key must fail closed');
});

// --- No over-correction: legitimate inputs must STILL work -------------------

test('a SINGLE spoofed key (no twin) still de-spoofs and analyzes cleanly', () => {
  const ok = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Principal: { [`AWS${ZWSP}`]: '*' }, // stripped to AWS, no collision
      Action: 'sts:AssumeRole',
    }],
  });
  const r = analyze(ok, { family: 'role-trust', requireExplicitFamily: true });
  assert.equal(r.ok, true, 'a lone spoofed key must de-spoof and analyze, not fail closed');
  // and it must still surface the public trust it now correctly represents
  assert.ok((r.findings || []).some((f) => f.severity === 'critical' || /PUBLIC/.test(f.id)),
    'the de-spoofed Principal:"*" must fire the public-trust finding');
});

test('distinct legitimate principal types (AWS + Service) do NOT false-collide', () => {
  const ok = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::111111111111:root', Service: 'lambda.amazonaws.com' },
      Action: 'sts:AssumeRole',
    }],
  });
  const r = analyze(ok, { family: 'role-trust', requireExplicitFamily: true });
  assert.equal(r.ok, true, 'two distinct principal types must not be treated as a collision');
});
