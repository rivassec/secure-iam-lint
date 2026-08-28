// Regression suite for STORY S3-trust-calibration (Phase 20, Round 4).
//
// Three trust/principal verdict fail-opens the verdict-core audit reproduced in
// engine/trust.js + engine/model.js. Each MUST-CLOSE case previously read CLEAN
// (ok:true, no blocking finding, exit 0) on a policy carrying real risk; each
// control MUST stay as designed so the fix does not over-fire into false
// positives. Runs on node's built-in runner: `node --test`.
//
//   (1) empty Principal {} / empty principal value array on sts:AssumeRole.
//   (2) a confused-deputy-relevant SERVICE trust with no source binding.
//   (3) a cross-account EXTERNAL principal pinned via a FOREIGN-account
//       aws:PrincipalArn scored one band below the direct-external baseline.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

function pol(statement) {
  return JSON.stringify({ Version: '2012-10-17', Statement: statement });
}
function trust(statement) {
  return analyze(pol(statement));
}
function ids(r) {
  return r.findings.map((f) => f.id);
}
function find(r, id) {
  return r.findings.find((f) => f.id === id);
}

// ---------------------------------------------------------------------------
// (1) Empty / member-less Principal must fail CLOSED, never read clean.
// ---------------------------------------------------------------------------

test('(1) empty Principal {} on sts:AssumeRole fails CLOSED (INVALID_PRINCIPAL, not a clean pass)', () => {
  const r = trust([{ Effect: 'Allow', Principal: {}, Action: 'sts:AssumeRole' }]);
  // The whole model is rejected -> analyze() is not ok. It must NOT be the clean
  // triple (ok:true && findings.length===0 && !incomplete) the audit flagged.
  assert.equal(r.ok, false, 'empty Principal {} must be rejected, not analyzed clean');
  assert.ok(
    r.errors.some((e) => e.code === 'INVALID_PRINCIPAL'),
    `expected INVALID_PRINCIPAL, got ${JSON.stringify(r.errors.map((e) => e.code))}`,
  );
});

test('(1) empty principal VALUE ARRAY {AWS:[]} fails CLOSED (INVALID_PRINCIPAL)', () => {
  const r = trust([{ Effect: 'Allow', Principal: { AWS: [] }, Action: 'sts:AssumeRole' }]);
  assert.equal(r.ok, false, 'empty value array must be rejected');
  assert.ok(r.errors.some((e) => e.code === 'INVALID_PRINCIPAL'));
});

test('(1) a partly-empty principal {AWS:[], Service:["lambda..."]} still fails CLOSED (empty value array)', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { AWS: [], Service: ['lambda.amazonaws.com'] },
    Action: 'sts:AssumeRole',
  }]);
  assert.equal(r.ok, false, 'an empty value array anywhere is invalid');
  assert.ok(r.errors.some((e) => e.code === 'INVALID_PRINCIPAL'));
});

test('(1) CONTROL: Principal "*" still analyzes and stays TRUST-PUBLIC critical', () => {
  const r = trust([{ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }]);
  assert.equal(r.ok, true, 'Principal "*" is valid (anyPrincipal, empty byType) - not rejected');
  const f = find(r, 'TRUST-PUBLIC');
  assert.ok(f, 'expected TRUST-PUBLIC');
  assert.equal(f.severity, 'critical', 'wildcard principal stays critical public trust');
});

test('(1) CONTROL: a concrete single-principal trust still analyzes cleanly', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::123456789012:role/App' },
    Action: 'sts:AssumeRole',
  }]);
  assert.equal(r.ok, true, 'a non-empty principal is valid');
});

// ---------------------------------------------------------------------------
// (2) Confused-deputy service trust without a source binding must not be
//     flattened to TRUST-SERVICE:info (non-blocking).
// ---------------------------------------------------------------------------

for (const svc of [
  'events.amazonaws.com', 'scheduler.amazonaws.com', 'cloudtrail.amazonaws.com',
  's3.amazonaws.com', 'sns.amazonaws.com',
]) {
  test(`(2) ${svc} trust with NO source binding raises out of info (BLOCKING high)`, () => {
    const r = trust([{ Effect: 'Allow', Principal: { Service: svc }, Action: 'sts:AssumeRole' }]);
    const f = find(r, 'TRUST-SERVICE');
    assert.ok(f, 'expected a TRUST-SERVICE finding');
    assert.equal(f.severity, 'high', `unbound confused-deputy service must be high, got ${f.severity}`);
    // It must NOT read clean and must NOT become an external/public/escalation over-claim.
    for (const bad of ['TRUST-PUBLIC', 'TRUST-CROSS-ACCOUNT', 'TRUST-ORG-EXPANSION']) {
      assert.ok(!ids(r).includes(bad), `must not fire ${bad}`);
    }
    // Blocking under the default 'high' threshold -> not the clean triple.
    assert.ok(!(r.ok && r.findings.length === 0), 'must not be a no-findings clean pass');
  });
}

test('(2) CONTROL: cloudtrail + aws:SourceAccount stays informational (source-bound)', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { Service: 'cloudtrail.amazonaws.com' },
    Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'aws:SourceAccount': '123456789012' } },
  }]);
  const f = find(r, 'TRUST-SERVICE');
  assert.ok(f);
  assert.equal(f.severity, 'info', 'a source-bound confused-deputy service stays info');
});

test('(2) CONTROL: s3 + aws:SourceArn stays informational (source-bound)', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { Service: 's3.amazonaws.com' },
    Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:s3:::example-source-bucket' } },
  }]);
  assert.equal(find(r, 'TRUST-SERVICE').severity, 'info');
});

test('(2) CONTROL: a VACUOUS source condition (match-all SourceArn) still fails closed (high)', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { Service: 'events.amazonaws.com' },
    Action: 'sts:AssumeRole',
    Condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:*:*:*:*' } },
  }]);
  assert.equal(find(r, 'TRUST-SERVICE').severity, 'high',
    'a match-all SourceArn does not bind the source -> stays a confused-deputy exposure');
});

test('(2) CONTROL: lambda/ec2/ecs EXECUTION-role trusts stay informational (no over-fire)', () => {
  for (const svc of ['lambda.amazonaws.com', 'ec2.amazonaws.com', 'ecs-tasks.amazonaws.com']) {
    const r = trust([{ Effect: 'Allow', Principal: { Service: svc }, Action: 'sts:AssumeRole' }]);
    const f = find(r, 'TRUST-SERVICE');
    assert.ok(f, `expected TRUST-SERVICE for ${svc}`);
    assert.equal(f.severity, 'info', `${svc} is an execution-role trust and must stay info`);
  }
});

test('(2) mixed lambda + events(unbound): lambda stays info, events raises high (two findings)', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { Service: ['lambda.amazonaws.com', 'events.amazonaws.com'] },
    Action: 'sts:AssumeRole',
  }]);
  const svc = r.findings.filter((f) => f.id === 'TRUST-SERVICE');
  const high = svc.find((f) => f.severity === 'high');
  const info = svc.find((f) => f.severity === 'info');
  assert.ok(high, 'events raises a high confused-deputy finding');
  assert.match(high.why, /events\.amazonaws\.com/);
  assert.ok(info, 'lambda stays an info finding');
  assert.match(info.why, /lambda\.amazonaws\.com/);
});

// ---------------------------------------------------------------------------
// (3) A cross-account external principal pinned via a FOREIGN-account
//     aws:PrincipalArn must stay HIGH, not drop one band to medium.
// ---------------------------------------------------------------------------

test('(3) root:1111 + ArnEquals aws:PrincipalArn = role in a DIFFERENT account stays HIGH', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::111122223333:root' },
    Action: 'sts:AssumeRole',
    Condition: { ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::999988887777:role/ext' } },
  }]);
  const f = find(r, 'TRUST-CROSS-ACCOUNT');
  assert.ok(f);
  assert.equal(f.severity, 'high',
    'a foreign-account aws:PrincipalArn is itself cross-account; it must not narrow to medium');
  assert.match(f.why, /different account|cross-account ARN/i,
    'explains the PrincipalArn is foreign-account, not a sub-account narrowing');
});

test('(3) parity: the SAME external role as Principal.AWS is also high', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::999988887777:role/ext' },
    Action: 'sts:AssumeRole',
  }]);
  assert.equal(find(r, 'TRUST-CROSS-ACCOUNT').severity, 'high');
});

test('(3) CONTROL: root:9999 + exact aws:PrincipalArn in the SAME account stays medium (designed narrowing)', () => {
  const r = trust([{
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::999999999999:root' },
    Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::999999999999:role/OnlyThisRole' } },
  }]);
  const f = find(r, 'TRUST-CROSS-ACCOUNT');
  assert.equal(f.severity, 'medium', 'a same-account single-principal narrowing stays medium');
  assert.match(f.why, /pins WHICH principal/i);
});

test('(3) CONTROL: root:9999 + account-pinned wildcard aws:PrincipalArn (role/deploy across *) stays medium', () => {
  // arn:aws:iam::*:role/deploy under Principal root:9999 intersects to the single
  // role in account 9999 (the account is fixed by the Principal, not the condition):
  // a same-account narrowing, NOT a foreign-account ARN.
  const r = trust([{
    Effect: 'Allow',
    Principal: { AWS: 'arn:aws:iam::999999999999:root' },
    Action: 'sts:AssumeRole',
    Condition: { StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy' } },
  }]);
  assert.equal(find(r, 'TRUST-CROSS-ACCOUNT').severity, 'medium',
    'a wildcard-account PrincipalArn fixed by the Principal is same-account -> medium, not foreign');
});

test('(3) CONTROL: Principal "*" + exact aws:PrincipalArn (one role) stays a scoped TRUST-PUBLIC, not critical', () => {
  // publicScopeConstraint path: no named reference account, so the single-principal
  // narrowing of "*" is unaffected by the foreign-account check.
  const r = trust([{
    Effect: 'Allow',
    Principal: '*',
    Action: 'sts:AssumeRole',
    Condition: { StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::111122223333:role/App' } },
  }]);
  const f = find(r, 'TRUST-PUBLIC');
  assert.ok(f);
  assert.notEqual(f.severity, 'critical');
});
