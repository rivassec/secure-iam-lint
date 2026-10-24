// v1.3.0 round 8 Lane B: org condition keys (F-3).
// Shapes mirror the trial bundle probes (probes/conditions/*, batch-2 f1*).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { classifyConditionEntry } from '../../../content/tools/iam-blast-radius/engine/conditions.js';

const ORG = 'o-exampleorg';
const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const run = (text, o = {}) => scan({ text, family: 'identity', partition: 'aws', subjectAccount: '111111111111', ...o });
const codes = (r) => (r.analysisStates || []).map((s) => s.code);
const ids = (r) => r.findings.map((f) => `${f.id}:${f.severity}`).sort();
const allow = (Action, Condition, Resource = '*') => ({ Effect: 'Allow', Action, Resource, Condition });

// Trial probes (aws:SourceVpce is the supported control, already modeled).
const PROBES = [
  ['s3:GetObject', { 'ForAnyValue:StringLike': { 'aws:PrincipalOrgPaths': `${ORG}/r-ab12/ou-ab12-11111111/*` } }],
];

test('E-2/F-3: every trial probe key is modeled (no UNSUPPORTED_CONDITION)', () => {
  for (const [action, cond] of PROBES) {
    const r = run(P(allow(action, cond)));
    assert.ok(!codes(r).includes('UNSUPPORTED_CONDITION'), `${action} ${JSON.stringify(cond)}: ${codes(r)}`);
  }
});

test('E-2/F-3: a modeled key never turns a finding into a clean pass', () => {
  // Same verdict as the ungated grant: the condition only narrows an Allow.
  for (const [action, cond] of PROBES) {
    const gated = run(P(allow(action, cond)));
    const bare = run(P(allow(action, undefined)));
    assert.equal(gated.exitCode === EXIT.CLEAN, bare.exitCode === EXIT.CLEAN, `${action}: ${gated.exitCode} vs ${bare.exitCode}`);
    assert.deepEqual(ids(gated), ids(bare), action);
  }
});

const NEW_KEYS = [
  ['aws:ResourceOrgID', ORG], ['aws:ResourceOrgPaths', `${ORG}/*`], ['aws:PrincipalOrgPaths', `${ORG}/*`],
];
const OPS = ['StringEquals', 'StringLike', 'StringNotEquals', 'StringEqualsIfExists', 'ForAnyValue:StringLike',
  'ForAllValues:StringEquals', 'ForAnyValue:StringNotLike', 'ArnLike', 'Null', 'Bool'];

test('E-2/F-3: no operator on a new key reads an exfil grant clean, Allow or beside a Deny', () => {
  for (const [key, value] of NEW_KEYS) {
    for (const op of OPS) {
      const v = op === 'Null' ? 'true' : op === 'Bool' ? 'true' : value;
      const cond = { [op]: { [key]: v } };
      const r = run(P(allow('s3:GetObject', cond)));
      assert.notEqual(r.exitCode, EXIT.CLEAN, `${op} ${key}`);
      // A conditional Deny never blocks, so the Allow keeps its finding.
      const d = run(P(allow('s3:GetObject', undefined), { Effect: 'Deny', Action: 's3:GetObject', Resource: '*', Condition: cond }));
      assert.ok(ids(d).includes('DATA-EXFIL:high'), `Deny ${op} ${key}: ${ids(d)}`);
    }
  }
});

test('E-2/F-3: undecidable shapes stay UNSUPPORTED_CONDITION (exit 3)', () => {
  for (const cond of [
    // Multivalued keys need ForAnyValue/ForAllValues.
    { StringLike: { 'aws:PrincipalOrgPaths': `${ORG}/*` } },
    { StringEquals: { 'aws:ResourceOrgPaths': `${ORG}/r-ab12/` } },
    { StringEquals: { 'aws:ResourceOrgIDs': ORG } },
  ]) {
    const r = run(P(allow('s3:GetObject', cond)));
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, JSON.stringify(cond));
    assert.ok(codes(r).includes('UNSUPPORTED_CONDITION'), JSON.stringify(cond));
  }
});

test('F-3: credit follows the PrincipalOrgID rules', () => {
  const c = (op, key, v) => classifyConditionEntry(op, key, v).credited;
  assert.equal(c('StringEquals', 'aws:ResourceOrgID', ORG), true);
  assert.equal(c('StringLike', 'aws:ResourceOrgID', 'o-*'), false);
  assert.equal(c('StringEquals', 'aws:ResourceOrgID', '${aws:PrincipalOrgID}'), false);
  assert.equal(c('StringEqualsIfExists', 'aws:ResourceOrgID', ORG), false);
  assert.equal(c('StringNotEquals', 'aws:ResourceOrgID', ORG), false);
  assert.equal(c('DateGreaterThan', 'aws:ResourceOrgID', ORG), false);
  assert.equal(c('ForAnyValue:StringLike', 'aws:ResourceOrgPaths', `${ORG}/r-ab12/*`), true);
  assert.equal(c('ForAnyValue:StringLike', 'aws:ResourceOrgPaths', 'o-*/r-ab12/*'), false);
  assert.equal(c('ForAnyValue:StringLike', 'aws:ResourceOrgPaths', '*/r-ab12/*'), false);
  assert.equal(c('ForAllValues:StringLike', 'aws:ResourceOrgPaths', `${ORG}/*`), false);
  assert.equal(c('ForAnyValue:StringLike', 'aws:ResourceOrgPaths', [`${ORG}/*`, '*']), false);
  // Never credited: principal org paths (trust.js does not credit them).
  assert.equal(c('ForAnyValue:StringLike', 'aws:PrincipalOrgPaths', `${ORG}/*`), false);
  assert.equal(c('Bool', 'aws:ResourceOrgID', 'true'), false);
  assert.equal(classifyConditionEntry('StringNotEquals', 'aws:ResourceOrgID', ORG).class, 'expansion');
});

test('F-3 f1/f1b/f1c/f1d: org gate keeps the findings and names the org bound', () => {
  const roles = ['arn:aws:iam::*:role/deployer', 'arn:aws:iam::*:role/pulumi'];
  const gate = { StringEquals: { 'aws:ResourceOrgID': ORG } };
  const f1 = run(P(allow('sts:AssumeRole', gate, roles)));
  const f1b = run(P(allow('sts:AssumeRole', undefined, roles)));
  assert.equal(f1.exitCode, EXIT.FINDINGS);
  assert.deepEqual(ids(f1), ids(f1b));
  const why = (r) => r.findings.find((f) => f.id === 'ASSUME-ROLE-EXPANSION').why;
  assert.match(why(f1), /aws:ResourceOrgID condition bounds the target roles to accounts in the named organization/);
  assert.doesNotMatch(why(f1b), /organization/);
  // An undependable gate names no bound.
  for (const weak of [{ StringEqualsIfExists: { 'aws:ResourceOrgID': ORG } }, { StringLike: { 'aws:ResourceOrgID': 'o-*' } },
    { StringNotEquals: { 'aws:ResourceOrgID': ORG } }]) {
    const r = run(P(allow('sts:AssumeRole', weak, roles)));
    assert.equal(r.exitCode, EXIT.FINDINGS, JSON.stringify(weak));
    assert.doesNotMatch(why(r), /bounds the target roles/, JSON.stringify(weak));
  }
  const paths = run(P(allow('sts:AssumeRole', { 'ForAnyValue:StringLike': { 'aws:ResourceOrgPaths': `${ORG}/r-ab12/*` } }, roles)));
  assert.match(why(paths), /aws:ResourceOrgPaths condition bounds/);
  // The why text never echoes the condition value.
  assert.ok(!why(f1).includes(ORG));
  const f1c = run(P(allow('iam:PassRole', gate, 'arn:aws:iam::*:role/cfn-deployer')));
  assert.equal(f1c.exitCode, EXIT.FINDINGS);
  assert.deepEqual(ids(f1c), ids(run(P(allow('iam:PassRole', undefined, 'arn:aws:iam::*:role/cfn-deployer')))));
  const f1d = run(P(allow('sts:AssumeRole', undefined, 'arn:aws:iam::222222222222:role/deployer')));
  assert.equal(f1d.exitCode, EXIT.CLEAN);
});

test('F-3: resource family credits a principal org path only with a literal org id', () => {
  const B = 'arn:aws:s3:::bkt';
  const res = (cond) => scan({
    text: P({ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: `${B}/*`, Condition: cond }),
    family: 'resource', partition: 'aws', resourceContext: { arn: B },
  });
  const bare = ids(res(undefined));
  assert.ok(bare.some((x) => x.endsWith(':critical')), bare.join(','));
  // A globbed org segment matches every org: still the anonymous public grant.
  for (const v of ['o-*/*', '*/*', '?*']) {
    const r = res({ 'ForAnyValue:StringLike': { 'aws:PrincipalOrgPaths': v } });
    assert.ok(ids(r).some((x) => x.endsWith(':critical')), `${v}: ${ids(r)}`);
  }
  const lit = res({ 'ForAnyValue:StringLike': { 'aws:PrincipalOrgPaths': `${ORG}/r-ab12/*` } });
  assert.equal(lit.exitCode, EXIT.FINDINGS);
  assert.ok(!codes(lit).includes('UNSUPPORTED_CONDITION'));
  assert.ok(!ids(lit).some((x) => x.endsWith(':critical')), ids(lit).join(','));
  // ForAllValues passes when the key is absent (anonymous): not narrowed.
  const fav = res({ 'ForAllValues:StringLike': { 'aws:PrincipalOrgPaths': `${ORG}/*` } });
  assert.ok(ids(fav).some((x) => x.endsWith(':critical')), ids(fav).join(','));
});

test('F-3: a role trust gated by a principal org path keeps its ungated severity', () => {
  const trust = (cond) => scan({
    text: P({ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole', Condition: cond }),
    family: 'role-trust', partition: 'aws',
  });
  const bare = trust(undefined);
  const gated = trust({ 'ForAnyValue:StringLike': { 'aws:PrincipalOrgPaths': `${ORG}/*` } });
  assert.notEqual(gated.exitCode, EXIT.CLEAN);
  assert.ok(!codes(gated).includes('UNSUPPORTED_CONDITION'));
  assert.deepEqual(ids(gated), ids(bare));
});
