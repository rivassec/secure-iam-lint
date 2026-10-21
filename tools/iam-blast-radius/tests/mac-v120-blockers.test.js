// The three v1.2.0 blockers from the Mac's targeted round (T2-1, T2-2, F3).

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

const passRole = (pts, arn = `arn:aws:iam::${ACCT}:role/admin`) => ({
  Effect: 'Allow', Action: 'iam:PassRole', Resource: arn,
  ...(pts ? { Condition: { StringEquals: { 'iam:PassedToService': pts } } } : {}),
});

test('T2-1: a ${...} PassedToService value never erases the PassRole escalation', () => {
  const lambdaExec = { Effect: 'Allow', Action: ['lambda:CreateFunction', 'lambda:InvokeFunction'], Resource: `arn:aws:lambda:us-east-2:${ACCT}:function:example` };
  for (const pts of [
    "${aws:PrincipalTag/svc, 'lambda.amazonaws.com'}",
    '${aws:PrincipalTag/svc}',
    '${aws:username}',
  ]) {
    const r = run([passRole(pts), lambdaExec]);
    assert.equal(r.exitCode, EXIT.FINDINGS, pts);
    assert.ok(ids(r).some((i) => i.startsWith('PASSROLE-')), `${pts}: ${ids(r)}`);
  }
  // StringLike with an embedded variable.
  const like = run([{ ...passRole(null), Condition: { StringLike: { 'iam:PassedToService': 'lambda.${aws:PrincipalTag/dom}' } } }, lambdaExec]);
  assert.ok(ids(like).some((i) => i.startsWith('PASSROLE-')), ids(like).join(','));
  // A literal non-matching pin still blocks (no over-fire).
  const pinned = run([passRole('ecs-tasks.amazonaws.com'), lambdaExec]);
  assert.ok(!ids(pinned).includes('PASSROLE-LAMBDA'), ids(pinned).join(','));
});

test('T2-1: the EC2 instance-profile form (the v1.1.0 regression) flags again', () => {
  const r = run([
    { ...passRole('${aws:PrincipalTag/svc}') },
    { Effect: 'Allow', Action: 'ec2:AssociateIamInstanceProfile', Resource: `arn:aws:ec2:us-east-1:${ACCT}:instance/i-0abc` },
  ]);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(ids(r).includes('PASSROLE-EC2'), ids(r).join(','));
});

test('T2-2: aws-cn ec2.amazonaws.com.cn pin is recognized as an EC2 pass', () => {
  const r = run([
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws-cn:iam::${ACCT}:role/admin`, Condition: { StringEquals: { 'iam:PassedToService': 'ec2.amazonaws.com.cn' } } },
    { Effect: 'Allow', Action: 'ec2:AssociateIamInstanceProfile', Resource: `arn:aws-cn:ec2:cn-north-1:${ACCT}:instance/i-0123456789abcdef0` },
  ], { partition: 'aws-cn' });
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.ok(ids(r).includes('PASSROLE-EC2'), ids(r).join(','));
});

test('operatorPermitsService: variables, partitions and literal operators', () => {
  assert.equal(operatorPermitsService('StringEquals', ['${aws:PrincipalTag/svc}'], 'lambda.amazonaws.com'), 'permit');
  // The .cn spelling counts only where the partition sends it (R1-02/R1-03).
  assert.equal(operatorPermitsService('StringEquals', ['ec2.amazonaws.com.cn'], 'ec2.amazonaws.com', 'aws-cn'), 'permit');
  assert.equal(operatorPermitsService('StringEquals', ['ec2.amazonaws.com.cn'], 'ec2.amazonaws.com', 'aws'), 'deny');
  assert.equal(operatorPermitsService('StringEquals', ['ecs-tasks.amazonaws.com'], 'lambda.amazonaws.com'), 'deny');
  assert.equal(operatorPermitsService('StringNotEquals', ['ec2.amazonaws.com.cn'], 'ec2.amazonaws.com', 'aws'), 'permit');
  // F2-08: a canonical-only deny in aws-cn covers one of two plausible spellings
  // ("instead of or in addition to"), so it is uncertain, not a confident permit.
  assert.equal(operatorPermitsService('StringNotEquals', ['ec2.amazonaws.com'], 'ec2.amazonaws.com', 'aws-cn'), 'uncertain');
  assert.equal(operatorPermitsService('StringNotEquals', ['lambda.amazonaws.com'], 'lambda.amazonaws.com'), 'deny');
  // R1-01: (Not)Equals is literal; only Like/Arn* expand wildcards.
  assert.equal(operatorPermitsService('StringNotEquals', ['*'], 'lambda.amazonaws.com'), 'permit');
  assert.equal(operatorPermitsService('StringNotEqualsIgnoreCase', ['LAMBDA.*'], 'lambda.amazonaws.com'), 'permit');
  assert.equal(operatorPermitsService('StringNotLike', ['*'], 'lambda.amazonaws.com'), 'deny');
  assert.equal(operatorPermitsService('ArnNotEquals', ['*'], 'lambda.amazonaws.com'), 'deny');
  assert.equal(operatorPermitsService('StringEquals', ['*'], 'lambda.amazonaws.com'), 'deny');
});

test('F3: a baseline acceptance dies when any condition value in the statement changes', () => {
  const rcp = (org, svc) => JSON.stringify({ Version: '2012-10-17', Statement: [{
    Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*',
    Condition: { StringNotEqualsIfExists: { 'aws:PrincipalOrgID': org }, BoolIfExists: { 'aws:PrincipalIsAWSService': svc } },
  }] });
  const scanRcp = (text) => scan({ text, family: 'rcp', partition: 'aws', threshold: 'high' });
  const good = applyBaseline(scanRcp(rcp('o-abc123def4', 'false')), 'pol/rcp.json', null, 'high');
  const keys = parseBaseline(JSON.stringify(buildBaseline([{ file: 'pol/rcp.json', result: good }]))).keys;
  assert.equal(applyBaseline(scanRcp(rcp('o-abc123def4', 'false')), 'pol/rcp.json', keys, 'high').exitCode, EXIT.CLEAN);
  // Edit A: service-principal flag flipped. Edit B: a MODELED sibling key's value changed.
  assert.equal(applyBaseline(scanRcp(rcp('o-abc123def4', 'true')), 'pol/rcp.json', keys, 'high').exitCode, EXIT.FAIL_CLOSED);
  assert.equal(applyBaseline(scanRcp(rcp('o-attacker999', 'false')), 'pol/rcp.json', keys, 'high').exitCode, EXIT.FAIL_CLOSED);
});

test('R1-01: StringNotEquals "*" (and glob spellings) never erases the PassRole escalation', () => {
  const lambdaExec = { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: `arn:aws:lambda:us-east-2:${ACCT}:function:example` };
  const pr = (op, v) => ({ Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/admin`, Condition: { [op]: { 'iam:PassedToService': v } } });
  for (const [op, v] of [['StringNotEquals', '*'], ['StringNotEquals', 'lambda.amazonaws.co*'], ['StringNotEquals', 'lambda.amazonaws.co?'], ['StringNotEqualsIgnoreCase', 'LAMBDA.*']]) {
    const r = run([pr(op, v), lambdaExec]);
    assert.equal(r.exitCode, EXIT.FINDINGS, `${op} ${v}`);
    assert.ok(ids(r).includes('PASSROLE-LAMBDA'), `${op} ${v}: ${ids(r)}`);
  }
  // Real denies stay denies.
  for (const [op, v] of [['StringNotEquals', 'lambda.amazonaws.com'], ['StringNotLike', '*']]) {
    assert.ok(!ids(run([pr(op, v), lambdaExec])).includes('PASSROLE-LAMBDA'), `${op} ${v}`);
  }
});

test('R1-02/R1-03: the .cn spelling is partition-aware in both arms', () => {
  const assoc = (part) => ({ Effect: 'Allow', Action: 'ec2:AssociateIamInstanceProfile', Resource: `arn:${part}:ec2:cn-north-1:${ACCT}:instance/i-0abc` });
  const pr = (part, op, v) => ({ Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:${part}:iam::${ACCT}:role/admin`, Condition: { [op]: { 'iam:PassedToService': v } } });
  // cn: a canonical-only denylist denies nothing EC2 actually sends -> the finding fires.
  for (const op of ['StringNotEquals', 'StringNotLike']) {
    const r = run([pr('aws-cn', op, 'ec2.amazonaws.com'), assoc('aws-cn')], { partition: 'aws-cn' });
    assert.equal(r.exitCode, EXIT.FINDINGS, op);
    assert.ok(ids(r).includes('PASSROLE-EC2'), `${op}: ${ids(r)}`);
  }
  // aws / aws-us-gov: a .cn pin is unpassable there, never a critical.
  for (const part of ['aws', 'aws-us-gov']) {
    const r = run([pr(part, 'StringEquals', 'ec2.amazonaws.com.cn'), assoc(part)], { partition: part });
    assert.notEqual(r.exitCode, EXIT.FINDINGS, part);
  }
});

test('R1-06: a trust baseline never survives swapping the trusted account', () => {
  const t = (acct) => scan({ text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${acct}:root` }, Action: 'sts:AssumeRole' }] }), family: 'role-trust', partition: 'aws', threshold: 'high', subjectAccount: ACCT });
  const good = applyBaseline(t('444455556666'), 't/policy.json', null, 'high');
  const keys = parseBaseline(JSON.stringify(buildBaseline([{ file: 't/policy.json', result: good }]))).keys;
  assert.equal(applyBaseline(t('444455556666'), 't/policy.json', keys, 'high').exitCode, EXIT.CLEAN);
  for (const swapped of ['777788889999']) {
    assert.equal(applyBaseline(t(swapped), 't/policy.json', keys, 'high').exitCode, EXIT.FINDINGS, swapped);
  }
});

test('R2-01: an omitted or unrecognized partition never fails open on a .cn pin', () => {
  const pol = [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws-cn:iam::${ACCT}:role/admin`, Condition: { StringEquals: { 'iam:PassedToService': 'ec2.amazonaws.com.cn' } } },
    { Effect: 'Allow', Action: 'ec2:AssociateIamInstanceProfile', Resource: `arn:aws-cn:ec2:cn-north-1:${ACCT}:instance/i-0abc` },
  ];
  // null bypasses the helper default: scan() sees no asserted partition.
  for (const partition of [null, 'AWS-CN', 'zzz']) {
    const r = run(pol, { partition });
    assert.notEqual(r.exitCode, EXIT.CLEAN, String(partition));
    assert.ok(ids(r).includes('PASSROLE-EC2'), `${partition}: ${ids(r)}`);
  }
  assert.equal(run(pol, { partition: 'aws-cn' }).exitCode, EXIT.FINDINGS);
});

test('D1: cn ARNs + canonical-only denylist never read CLEAN without an asserted partition', () => {
  // The divergence-1 residual: the statement's own ARNs say aws-cn, where a deny of
  // the canonical spelling covers nothing EC2 sends. v1.2.0 pre-fix exited 0 here.
  const pol = [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws-cn:iam::${ACCT}:role/admin`, Condition: { StringNotEquals: { 'iam:PassedToService': 'ec2.amazonaws.com' } } },
    { Effect: 'Allow', Action: 'ec2:AssociateIamInstanceProfile', Resource: `arn:aws-cn:ec2:cn-north-1:${ACCT}:instance/i-0abc` },
  ];
  for (const partition of [null, 'aws-cn']) {
    const r = run(pol, { partition });
    assert.notEqual(r.exitCode, EXIT.CLEAN, String(partition));
    assert.ok(ids(r).includes('PASSROLE-EC2'), `${partition}: ${ids(r)}`);
  }
  // Asserted canonical partition: the cn ARNs are unreachable there, the deny is real.
  assert.equal(run(pol, { partition: 'aws' }).exitCode, EXIT.CLEAN);
  // Mixed-partition ARN evidence resolves nothing: fail closed, never CLEAN.
  const mixed = run([pol[0], { ...pol[1], Resource: `arn:aws:ec2:us-east-1:${ACCT}:instance/i-0abc` }], { partition: null });
  assert.notEqual(mixed.exitCode, EXIT.CLEAN);
});

test('R3-03/R3-01/R3-02: path-level ARN evidence decides the matching world', () => {
  const NE = { StringNotEquals: { 'iam:PassedToService': 'ec2.amazonaws.com' } };
  const cnAssoc = { Effect: 'Allow', Action: 'ec2:AssociateIamInstanceProfile', Resource: `arn:aws-cn:ec2:cn-north-1:${ACCT}:instance/i-0abc` };
  // Evidence the old per-statement derivation missed: companion Resource, a wildcarded
  // or variable or wrong-case partition segment (poison -> wide), NotResource (never
  // evidence), and ARN-valued condition entries.
  const passStmts = [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: NE }, // star_comp
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws-c?:iam::${ACCT}:role/admin`, Condition: NE }, // qpart (R3-03)
    { Effect: 'Allow', Action: 'iam:PassRole', NotResource: `arn:aws:iam::${ACCT}:role/other`, Condition: NE }, // notres_aws
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { ...NE, ArnLike: { 'iam:AssociatedResourceArn': cnAssoc.Resource } } }, // cond_assoc
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:\${aws:PrincipalTag/partition}:iam::${ACCT}:role/admin`, Condition: NE }, // R3-01
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:AWS-CN:iam::${ACCT}:role/admin`, Condition: NE }, // R3-02
  ];
  for (const [i, pr] of passStmts.entries()) {
    const r = run([pr, cnAssoc], { partition: null });
    assert.notEqual(r.exitCode, EXIT.CLEAN, `case ${i}`);
    assert.ok(ids(r).includes('PASSROLE-EC2'), `case ${i}: ${ids(r)}`);
  }
  // Asserted canonical partition still credits the deny.
  const ctl = run([passStmts[0], cnAssoc], { partition: 'aws' });
  assert.ok(!ids(ctl).includes('PASSROLE-EC2'), ids(ctl).join(','));
});

test('R2-02: unpinned services under aws-cn may send either spelling', () => {
  const lambdaStmts = (cond) => [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws-cn:iam::${ACCT}:role/admin`, Condition: cond },
    { Effect: 'Allow', Action: ['lambda:CreateFunction', 'lambda:InvokeFunction'], Resource: `arn:aws-cn:lambda:cn-north-1:${ACCT}:function:example` },
  ];
  // A canonical pin may be what China Lambda sends: the finding fires.
  const eq = run(lambdaStmts({ StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } }), { partition: 'aws-cn' });
  assert.ok(ids(eq).includes('PASSROLE-LAMBDA'), ids(eq).join(','));
  // A .cn-only denylist covers only one of the two possible spellings: uncertain, not clean.
  const ne = run(lambdaStmts({ StringNotEquals: { 'iam:PassedToService': 'lambda.amazonaws.com.cn' } }), { partition: 'aws-cn' });
  assert.notEqual(ne.exitCode, EXIT.CLEAN);
  assert.ok(ids(ne).includes('PASSROLE-LAMBDA'), ids(ne).join(','));
});
