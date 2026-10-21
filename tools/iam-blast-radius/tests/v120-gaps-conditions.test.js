// G2 (s3:/aws:ResourceAccount) and G3 (cognito amr) condition modeling.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { classifyConditionEntry } from '../../../content/tools/iam-blast-radius/engine/conditions.js';

const ACCT = '111122223333';
const idScan = (cond) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['s3:GetObject*', 's3:PutObject*', 's3:DeleteObject*'], Resource: 'arn:aws:s3:::*', Condition: cond }] }),
  family: 'identity', partition: 'aws', threshold: 'high', subjectAccount: ACCT,
});
const trustScan = (cond) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { Federated: 'cognito-identity.amazonaws.com' }, Action: 'sts:AssumeRoleWithWebIdentity', Condition: cond }] }),
  family: 'role-trust', partition: 'aws', threshold: 'high', subjectAccount: ACCT,
});
const notes = (r) => r.findings.flatMap((f) => (f.conditionClassification ? f.conditionClassification.entries.map((e) => e.note) : []));

test('G2: a StringNotEquals ResourceAccount guard is modeled and names the same-account scope', () => {
  for (const key of ['s3:ResourceAccount', 'aws:ResourceAccount']) {
    const r = idScan({ StringNotEquals: { [key]: '555566667777' } });
    assert.equal(r.exitCode, EXIT.FINDINGS, key);
    assert.ok(notes(r).some((n) => n.includes('INCLUDING same-account') && n.includes('555566667777')), key);
  }
});

test('G2: a positive literal ResourceAccount pin is a credited constraint; globs are not', () => {
  const e = classifyConditionEntry('StringEquals', 's3:ResourceAccount', '555566667777');
  assert.equal(e.class, 'constraint');
  assert.equal(e.credited, true);
  const g = classifyConditionEntry('StringEquals', 's3:ResourceAccount', '5555*');
  assert.equal(g.credited, false);
  // A non-string operator never credits the pin.
  const n = classifyConditionEntry('NumericEquals', 's3:ResourceAccount', '555566667777');
  assert.equal(n.credited, false);
  // Modeled either way: no key reaches context-required.
  for (const x of [e, g, n]) assert.notEqual(x.class, 'context-required');
});

test('G2 control: an unmodeled condition key still fails closed', () => {
  assert.equal(idScan({ StringNotEquals: { 's3:ResourceAccountTypo': '555566667777' } }).exitCode, EXIT.FAIL_CLOSED);
});

test('G3: cognito amr authenticated/unauthenticated is modeled, never credited', () => {
  for (const v of ['authenticated', 'unauthenticated']) {
    const r = trustScan({ 'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': v } });
    assert.equal(r.exitCode, EXIT.FINDINGS, v);
    assert.ok(r.findings.some((f) => f.id === 'TRUST-FEDERATED'), v);
    const e = r.findings[0].conditionClassification.entries.find((x) => x.key.endsWith(':amr'));
    assert.equal(e.credited, false, v);
  }
});

test('G3: unmodeled amr shapes stay fail-closed', () => {
  // A provider-name amr value, a foreign host, and a non-string operator.
  assert.equal(trustScan({ 'ForAnyValue:StringLike': { 'cognito-identity.amazonaws.com:amr': 'graph.facebook.com' } }).exitCode, EXIT.FAIL_CLOSED);
  assert.equal(trustScan({ StringEquals: { 'token.actions.githubusercontent.com:amr': 'authenticated' } }).exitCode, EXIT.FAIL_CLOSED);
  assert.equal(trustScan({ NumericEquals: { 'cognito-identity.amazonaws.com:amr': 'authenticated' } }).exitCode, EXIT.FAIL_CLOSED);
});
