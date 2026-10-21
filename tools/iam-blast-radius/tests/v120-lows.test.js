// The five parked lows pulled into v1.2.0 (R1-04, R1-05, R2-03, R2-04, R2-05).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { applyBaseline, parseBaseline, buildBaseline } from '../../../cli/baseline.mjs';
import { operatorPermitsService } from '../../../content/tools/iam-blast-radius/engine/escalation-conditions.js';

const ACCT = '111122223333';
const run = (statements, { family = 'identity', partition = 'aws' } = {}) => scan({
  text: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
  family, partition, threshold: 'high', subjectAccount: ACCT,
});
const ids = (r) => r.findings.map((f) => f.id);

test('R1-04: ${*} ${?} ${$} are literal escapes, not variables', () => {
  // Escaped literals never match a service principal: no over-fire on the allow arm.
  for (const v of ['${*}', '${?}', '${$}', 'lambda.${$}amazonaws.com']) {
    assert.equal(operatorPermitsService('StringEquals', [v], 'lambda.amazonaws.com'), 'deny', v);
    assert.equal(operatorPermitsService('StringLike', [v], 'lambda.amazonaws.com'), 'deny', v);
  }
  // A denylist of an escaped literal denies nothing real: the path stays.
  assert.equal(operatorPermitsService('StringNotEquals', ['${*}'], 'lambda.amazonaws.com'), 'permit');
  assert.equal(operatorPermitsService('StringNotLike', ['${*}'], 'lambda.amazonaws.com'), 'permit');
  // A real variable (even next to an escape) is still caller-controlled.
  assert.equal(operatorPermitsService('StringEquals', ['${aws:username}'], 'lambda.amazonaws.com'), 'permit');
  assert.equal(operatorPermitsService('StringEquals', ['${*}${aws:username}'], 'lambda.amazonaws.com'), 'permit');
  // End to end: StringEquals "${*}" no longer produces a PASSROLE critical.
  const pol = (pts) => [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/admin`, Condition: { StringEquals: { 'iam:PassedToService': pts } } },
    { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: `arn:aws:lambda:us-east-2:${ACCT}:function:example` },
  ];
  assert.ok(!ids(run(pol('${*}'))).some((i) => i.startsWith('PASSROLE-')), ids(run(pol('${*}'))).join(','));
  assert.ok(ids(run(pol('${aws:username}'))).some((i) => i.startsWith('PASSROLE-')));
});

test('R1-05: a baseline survives AWS-equivalent condition rewrites, dies on real edits', () => {
  const rcp = (org) => JSON.stringify({ Version: '2012-10-17', Statement: [{
    Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*',
    Condition: { StringNotEqualsIfExists: { 'aws:PrincipalOrgID': org }, 'aws:unmodeled-key': { k: 'v' } },
  }] });
  const scanRcp = (text) => scan({ text, family: 'rcp', partition: 'aws', threshold: 'high' });
  const good = applyBaseline(scanRcp(rcp('o-abc123def4')), 'pol/rcp.json', null, 'high');
  const keys = parseBaseline(JSON.stringify(buildBaseline([{ file: 'pol/rcp.json', result: good }]))).keys;
  const rescan = (org) => applyBaseline(scanRcp(rcp(org)), 'pol/rcp.json', keys, 'high').exitCode;
  // Scalar vs one-element array, and value order, are the same condition.
  assert.equal(rescan(['o-abc123def4']), EXIT.CLEAN);
  assert.equal(rescan(['o-abc123def4', 'o-abc123def4']), EXIT.CLEAN);
  // A real value change still dies.
  assert.equal(rescan('o-attacker999'), EXIT.FAIL_CLOSED);
  assert.equal(rescan(['o-abc123def4', 'o-attacker999']), EXIT.FAIL_CLOSED);
});

test('R2-03: anonymous=* appears once in principals, whatever the spelling', () => {
  const trust = (principal) => scan({
    text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: principal, Action: 'sts:AssumeRole' }] }),
    family: 'role-trust', partition: 'aws', threshold: 'high', subjectAccount: ACCT,
  });
  for (const principal of ['*', { AWS: '*' }, { AWS: ['*', '*'] }]) {
    const f = trust(principal).findings.find((x) => x.principals && x.principals.includes('anonymous=*'));
    assert.ok(f, JSON.stringify(principal));
    assert.equal(f.principals.filter((t) => t === 'anonymous=*').length, 1, JSON.stringify(principal));
  }
  // No finding carries duplicate principal tokens.
  for (const f of trust({ AWS: '*', Service: 'lambda.amazonaws.com' }).findings) {
    const p = f.principals || [];
    assert.equal(new Set(p).size, p.length, p.join(','));
  }
});

test('R2-04: a bare account and its root ARN build the same trust baseline id', () => {
  const t = (principal) => scan({
    text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: principal }, Action: 'sts:AssumeRole' }] }),
    family: 'role-trust', partition: 'aws', threshold: 'high', subjectAccount: ACCT,
  });
  const good = applyBaseline(t('arn:aws:iam::444455556666:root'), 't/p.json', null, 'high');
  const keys = parseBaseline(JSON.stringify(buildBaseline([{ file: 't/p.json', result: good }]))).keys;
  // The equivalent bare spelling matches the accepted baseline.
  assert.equal(applyBaseline(t('444455556666'), 't/p.json', keys, 'high').exitCode, EXIT.CLEAN);
  // A different account still re-fires (R1-06 intact).
  assert.equal(applyBaseline(t('777788889999'), 't/p.json', keys, 'high').exitCode, EXIT.FINDINGS);
});

test('R2-05: a cross-partition pin keeps the demoted finding instead of reading CLEAN', () => {
  const pol = [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws-cn:iam::${ACCT}:role/admin`, Condition: { StringEquals: { 'iam:PassedToService': 'ec2.amazonaws.com.cn' } } },
    { Effect: 'Allow', Action: 'ec2:AssociateIamInstanceProfile', Resource: `arn:aws-cn:ec2:cn-north-1:${ACCT}:instance/i-0abc` },
  ];
  const r = run(pol, { partition: 'aws' });
  // Demoted below threshold (exit 0) but LISTED, never silently dropped.
  assert.equal(r.exitCode, EXIT.CLEAN);
  const f = r.findings.find((x) => x.id === 'PASSROLE-EC2');
  assert.ok(f, ids(r).join(','));
  assert.notEqual(f.severity, 'critical');
});
