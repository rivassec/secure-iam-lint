// Unit tests for IAM-105: compound-finding correlation (engine/correlate.js).
// Runs on node's built-in runner: `node --test`.
//
// correlateFindings() folds a subordinate wildcard/broad-resource finding into
// the compound escalation path whose statement it sits on, so the findings
// table shows one primary path row (with a risk-factor checklist + `subsumed`
// sub-property) instead of duplicate rows. A wildcard finding on a statement no
// compound path consumes is genuinely independent and must never be dropped.
//
// These tests exercise the pure function directly with synthetic findings so
// the subsumption logic is verified in isolation from the rest of the pipeline
// (end-to-end coverage lives in analyze.test.js against real fixtures).

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { correlateFindings } from '../../../content/tools/iam-blast-radius/engine/correlate.js';

// A minimal compound PassRole->service escalation finding: grants drawn from
// two statements (pass @0, exec @1).
function compound(overrides = {}) {
  return Object.assign({
    id: 'PASSROLE-LAMBDA',
    severity: 'critical',
    title: 'PassRole + Lambda',
    statementSid: 'PassStmt',
    statementIndex: 0,
    actions: ['iam:PassRole', 'lambda:CreateFunction'],
    resources: ['*'],
    escalation: { technique: 'passrole-service-execution', service: 'lambda' },
    riskFactors: [{ key: 'pass-role', label: 'iam:PassRole granted', present: true }],
    evidence: [
      { statementIndex: 0, role: 'pass', action: 'iam:PassRole' },
      { statementIndex: 1, role: 'execute', action: 'lambda:CreateFunction' },
    ],
  }, overrides);
}

function wildcard(statementIndex, id = 'WILDCARD-RESOURCE') {
  return {
    id,
    severity: 'high',
    title: id === 'WILDCARD-RESOURCE' ? 'Wildcard resource' : 'Wildcard action',
    statementSid: `Stmt${statementIndex}`,
    statementIndex,
    actions: ['lambda:CreateFunction'],
    resources: ['*'],
    why: 'why', limit: 'limit', remediation: 'fix',
  };
}

test('folds a wildcard finding on the exec statement into the compound primary', () => {
  const wc = wildcard(1);
  const out = correlateFindings([compound(), wc]);
  // The wildcard row is gone from the top level.
  assert.equal(out.length, 1, 'one top-level row remains');
  const primary = out[0];
  assert.equal(primary.id, 'PASSROLE-LAMBDA');
  assert.ok(Array.isArray(primary.subsumed) && primary.subsumed.length === 1,
    'the wildcard finding is attached as subsumed');
  assert.equal(primary.subsumed[0].id, 'WILDCARD-RESOURCE');
  assert.equal(primary.subsumed[0].statementIndex, 1);
  // Prose preserved in the subsumed view (nothing lost).
  assert.equal(primary.subsumed[0].why, 'why');
  assert.equal(primary.subsumed[0].remediation, 'fix');
});

test('folds a wildcard finding on the PASS statement too', () => {
  const out = correlateFindings([compound(), wildcard(0)]);
  assert.equal(out.length, 1);
  assert.equal(out[0].subsumed[0].statementIndex, 0);
});

test('a wildcard finding on an unrelated statement stays independent', () => {
  const wc = wildcard(5); // statement 5 is not part of the path (evidence @0,@1)
  const out = correlateFindings([compound(), wc]);
  assert.equal(out.length, 2, 'both rows survive');
  const primary = out.find((f) => f.id === 'PASSROLE-LAMBDA');
  const indep = out.find((f) => f.id === 'WILDCARD-RESOURCE');
  assert.ok(indep, 'independent wildcard finding is NOT dropped');
  assert.ok(!primary.subsumed, 'primary subsumes nothing');
});

test('a mix: subsume the on-path wildcard, keep the off-path one', () => {
  const onPath = wildcard(1);
  const offPath = wildcard(9);
  const out = correlateFindings([compound(), onPath, offPath]);
  assert.equal(out.length, 2, 'primary + one independent');
  const primary = out.find((f) => f.id === 'PASSROLE-LAMBDA');
  assert.equal(primary.subsumed.length, 1);
  assert.equal(primary.subsumed[0].statementIndex, 1);
  const survivors = out.filter((f) => f.id === 'WILDCARD-RESOURCE');
  assert.equal(survivors.length, 1, 'the off-path wildcard survives');
  assert.equal(survivors[0].statementIndex, 9);
});

test('WILDCARD-ACTION is also subordinate when on a path statement', () => {
  const wa = wildcard(1, 'WILDCARD-ACTION');
  const out = correlateFindings([compound(), wa]);
  assert.equal(out.length, 1);
  assert.equal(out[0].subsumed[0].id, 'WILDCARD-ACTION');
});

// Service-relatedness gate (adversarial-iam-semantics): sitting on a path
// statement is necessary but not sufficient. A wildcard finding that covers a
// service the path does NOT use is an independent capability, never a scope
// factor of the path.
test('an unrelated-service WILDCARD-ACTION on a path statement stays independent', () => {
  // Compound path uses iam (pass) + lambda (exec). s3:* is unrelated.
  const s3wild = {
    id: 'WILDCARD-ACTION', severity: 'high', title: 'Wildcard action',
    statementSid: 'Stmt0', statementIndex: 0, actions: ['s3:*'], resources: ['*'],
    why: 'why', limit: 'limit', remediation: 'fix',
  };
  const out = correlateFindings([compound(), s3wild]);
  assert.equal(out.length, 2, 's3:* is a genuinely independent broad grant, not dropped');
  const primary = out.find((f) => f.id === 'PASSROLE-LAMBDA');
  assert.ok(!primary.subsumed, 'primary does not claim s3:* as a risk factor');
  const indep = out.find((f) => f.id === 'WILDCARD-ACTION');
  assert.ok(indep, 'the unrelated WILDCARD-ACTION remains a top-level row');
});

test('a WILDCARD-RESOURCE that also covers an unrelated service stays independent', () => {
  // Bundled statement: pass + exec + an unrelated s3:*, all on statement 0, so
  // the WILDCARD-RESOURCE action list covers iam + lambda + s3.
  const single = compound({
    evidence: [
      { statementIndex: 0, role: 'pass', action: 'iam:PassRole' },
      { statementIndex: 0, role: 'execute', action: 'lambda:CreateFunction' },
    ],
  });
  const wr = {
    id: 'WILDCARD-RESOURCE', severity: 'high', title: 'Wildcard resource',
    statementSid: 'Stmt0', statementIndex: 0,
    actions: ['iam:PassRole', 'lambda:CreateFunction', 's3:*'], resources: ['*'],
    why: 'why', limit: 'limit', remediation: 'fix',
  };
  const out = correlateFindings([single, wr]);
  assert.equal(out.length, 2, 'the broad-resource grant covers s3 too, so it is not subsumed');
  assert.ok(out.some((f) => f.id === 'WILDCARD-RESOURCE'), 'WILDCARD-RESOURCE stays top-level');
  const primary = out.find((f) => f.id === 'PASSROLE-LAMBDA');
  assert.ok(!primary.subsumed, 'primary subsumes nothing unrelated');
});

test('a same-service WILDCARD-RESOURCE (only path services) is still subsumed', () => {
  // Same bundled shape but WITHOUT the unrelated service: purely pass + exec.
  const single = compound({
    evidence: [
      { statementIndex: 0, role: 'pass', action: 'iam:PassRole' },
      { statementIndex: 0, role: 'execute', action: 'lambda:CreateFunction' },
    ],
  });
  const wr = {
    id: 'WILDCARD-RESOURCE', severity: 'high', title: 'Wildcard resource',
    statementSid: 'Stmt0', statementIndex: 0,
    actions: ['iam:PassRole', 'lambda:CreateFunction'], resources: ['*'],
    why: 'why', limit: 'limit', remediation: 'fix',
  };
  const out = correlateFindings([single, wr]);
  assert.equal(out.length, 1, 'a pure scope factor of the path is folded in');
  assert.equal(out[0].subsumed[0].id, 'WILDCARD-RESOURCE');
});

test('non-wildcard rule findings are never subsumed', () => {
  const other = {
    id: 'DIRECT-IAM-ADMIN', severity: 'high', title: 'Direct IAM admin',
    statementSid: 'Stmt1', statementIndex: 1, actions: ['iam:PutUserPolicy'],
    resources: ['*'], why: 'w', limit: 'l', remediation: 'r',
  };
  const out = correlateFindings([compound(), other]);
  assert.equal(out.length, 2, 'DIRECT-IAM-ADMIN is not a scope-breadth finding; untouched');
  const primary = out.find((f) => f.id === 'PASSROLE-LAMBDA');
  assert.ok(!primary.subsumed);
});

test('no compound primary present -> passthrough (order preserved)', () => {
  const a = wildcard(0);
  const b = wildcard(1, 'WILDCARD-ACTION');
  const out = correlateFindings([a, b]);
  assert.deepEqual(out.map((f) => [f.id, f.statementIndex]), [
    ['WILDCARD-RESOURCE', 0],
    ['WILDCARD-ACTION', 1],
  ]);
});

test('deterministic + pure: inputs not mutated, repeat call equal', () => {
  const input = [compound(), wildcard(1), wildcard(7)];
  const a = correlateFindings(input);
  const b = correlateFindings(input);
  assert.deepEqual(
    JSON.parse(JSON.stringify(a)),
    JSON.parse(JSON.stringify(b)),
    'same input -> deep-equal output',
  );
  // Original primary object was not given a subsumed property in place.
  assert.ok(!('subsumed' in input[0]), 'input primary not mutated');
});

test('a subsumed finding matched by two primaries is removed once, attached to each', () => {
  // Two compound paths (EC2 + Lambda) both consuming exec statement @1.
  const ec2 = compound({
    id: 'PASSROLE-EC2', escalation: { technique: 'passrole-service-execution', service: 'ec2' },
    evidence: [
      { statementIndex: 0, role: 'pass', action: 'iam:PassRole' },
      { statementIndex: 1, role: 'execute', action: 'ec2:RunInstances' },
    ],
  });
  const lambda = compound(); // evidence @0,@1
  const wc = wildcard(1);
  const out = correlateFindings([ec2, lambda, wc]);
  // wc removed from top level; both primaries survive.
  assert.equal(out.filter((f) => f.id === 'WILDCARD-RESOURCE').length, 0);
  assert.equal(out.length, 2);
  for (const p of out) {
    assert.ok(Array.isArray(p.subsumed) && p.subsumed.length === 1,
      `${p.id} attaches the shared subordinate`);
  }
});

test('output primaries with subsumed are frozen (immutable result)', () => {
  const out = correlateFindings([compound(), wildcard(1)]);
  assert.ok(Object.isFrozen(out[0]), 'enriched primary is frozen');
  assert.ok(Object.isFrozen(out[0].subsumed), 'subsumed array is frozen');
  assert.ok(Object.isFrozen(out[0].subsumed[0]), 'subsumed view is frozen');
});
