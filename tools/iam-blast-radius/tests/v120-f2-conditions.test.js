// F2-08 (aws-cn allow arm takes both spellings), F2-09 (amr guest audience,
// ResourceAccount 12-digit crediting) from the Mac's 8854f5c review.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { classifyConditionEntry } from '../../../content/tools/iam-blast-radius/engine/conditions.js';
import { operatorPermitsService } from '../../../content/tools/iam-blast-radius/engine/escalation-conditions.js';

const ACCT = '111122223333';

test('F2-08: under aws-cn the allow arm accepts either spelling for every service', () => {
  for (const svc of ['datapipeline.amazonaws.com', 'ec2.amazonaws.com', 'lambda.amazonaws.com']) {
    assert.equal(operatorPermitsService('StringEquals', [svc], svc, 'aws-cn'), 'permit', svc);
    assert.equal(operatorPermitsService('StringEquals', [`${svc}.cn`], svc, 'aws-cn'), 'permit', `${svc}.cn`);
  }
  // Deny arm: covering one spelling is uncertain; covering both is a real deny.
  assert.equal(operatorPermitsService('StringNotEquals', ['datapipeline.amazonaws.com'], 'datapipeline.amazonaws.com', 'aws-cn'), 'uncertain');
  assert.equal(operatorPermitsService('StringNotEquals', ['datapipeline.amazonaws.com', 'datapipeline.amazonaws.com.cn'], 'datapipeline.amazonaws.com', 'aws-cn'), 'deny');
});

test('F2-08: the Mac regress shape - a canonical datapipeline pin in aws-cn keeps the PassRole path', () => {
  const r = scan({
    text: JSON.stringify({ Version: '2012-10-17', Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws-cn:iam::${ACCT}:role/admin`, Condition: { StringEquals: { 'iam:PassedToService': 'datapipeline.amazonaws.com' } } },
      { Effect: 'Allow', Action: 'datapipeline:CreatePipeline', Resource: '*' },
    ] }),
    family: 'identity', partition: 'aws-cn', threshold: 'high', subjectAccount: ACCT,
  });
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.ok(r.findings.some((f) => f.id.startsWith('PASSROLE-')), r.findings.map((f) => f.id).join(','));
});

test('F2-09: amr "unauthenticated" is a guest-population expansion, never a credited narrowing', () => {
  const u = classifyConditionEntry('ForAnyValue:StringLike', 'cognito-identity.amazonaws.com:amr', 'unauthenticated');
  assert.equal(u.class, 'expansion');
  assert.equal(u.credited, false);
  assert.ok(u.note.includes('GUEST'), u.note);
  const a = classifyConditionEntry('StringEquals', 'cognito-identity.amazonaws.com:amr', 'authenticated');
  assert.equal(a.class, 'constraint');
  assert.equal(a.credited, false);
});

test('F2-09: ResourceAccount credits only a full-literal 12-digit account id', () => {
  assert.equal(classifyConditionEntry('StringEquals', 's3:ResourceAccount', '11112222333').credited, false); // 11 digits
  assert.equal(classifyConditionEntry('StringEquals', 's3:ResourceAccount', '111122223333').credited, true);
  assert.equal(classifyConditionEntry('StringEquals', 'aws:ResourceAccount', '1111222233334').credited, false); // 13
});
