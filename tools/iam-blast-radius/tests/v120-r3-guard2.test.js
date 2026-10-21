// v1.2.0 confirmation round (fe9e1c2): guardrail Deny gaps B-01..B-08.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const ORG = 'o-abcdefghij';
const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const run = (text, o = {}) => scan({ text, family: 'scp-rcp', partition: 'aws', subjectAccount: ACCT, ...o });
const sev = (r) => r.findings.map((f) => f.severity);
const RA = ['s3:*', 'kms:*', 'secretsmanager:*', 'sts:*'];
const rcp = (Condition, extra = {}) => ({ Effect: 'Deny', Principal: '*', Action: RA, Resource: '*', Condition, ...extra });
const REGION = { StringNotEquals: { 'aws:RequestedRegion': ['us-east-1'] } };
const scp = (Condition, extra = {}) => ({ Effect: 'Deny', Action: '*', Resource: '*', Condition, ...extra });

const high = (name, text, o) => {
  const r = run(text, o);
  assert.equal(r.exitCode, EXIT.FINDINGS, `${name}: rc ${r.exitCode}`);
  assert.ok(sev(r).includes('high'), `${name}: ${sev(r)}`);
  return r;
};
const clean = (name, text, o) => assert.equal(run(text, o).exitCode, EXIT.CLEAN, name);
const failClosed = (name, text, o) => assert.equal(run(text, o).exitCode, EXIT.FAIL_CLOSED, name);

test('B-01: a positive PrincipalOrgPaths comparator is an inverted perimeter', () => {
  high('p01', P(rcp({ StringLike: { 'aws:PrincipalOrgPaths': `${ORG}/*` }, BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } })));
  high('p07', P(rcp({ StringNotEqualsIfExists: { 'aws:PrincipalOrgID': ORG }, BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' },
    StringEquals: { 'aws:PrincipalOrgPaths': 'o-zzzzzzzzzz/r-zz99/' } })));
  // Unchanged: a globbed org path is not a modeled shape (exit 3).
  failClosed('negated org paths perimeter', P(rcp({ StringNotLikeIfExists: { 'aws:PrincipalOrgPaths': `${ORG}/*` },
    BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } })));
});

test('B-02: a positive SourceAccount limits the confused-deputy Deny to that account', () => {
  const base = { StringNotEqualsIfExists: { 'aws:SourceOrgID': ORG }, Bool: { 'aws:PrincipalIsAWSService': 'true' } };
  for (const [name, extra] of [
    ['q18', { StringEquals: { 'aws:SourceAccount': ACCT } }],
    ['p04', { StringEqualsIfExists: { 'aws:SourceAccount': ACCT } }],
    ['p05', { StringLike: { 'aws:SourceAccount': '1111*' }, Null: { 'aws:SourceAccount': 'false' } }],
  ]) {
    const r = high(name, P(rcp({ ...base, ...extra })));
    assert.ok(!r.findings.some((f) => /implementing confused-deputy protection/.test(f.why || '')), name);
  }
  clean('template', P(rcp({ ...base, Null: { 'aws:SourceAccount': 'false' } })));
});

test('B-04: principal checks use the subject account', () => {
  high('own-account ARN carve-out', P(scp({ ...REGION, ArnNotLike: { 'aws:PrincipalArn': `arn:aws:iam::${ACCT}:*` } })));
  high('foreign-account-only Deny', P(scp({ ...REGION, StringEquals: { 'aws:PrincipalAccount': '444455556666' } })));
  high('foreign-account ARN pin', P(scp({ ...REGION, ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::444455556666:role/x' } })));
  clean('own-account role pin', P(scp({ ...REGION, ArnLike: { 'aws:PrincipalArn': `arn:aws:iam::${ACCT}:role/x` } })));
  clean('one-role break-glass', P(scp({ ...REGION, ArnNotLike: { 'aws:PrincipalArn': `arn:aws:iam::${ACCT}:role/BreakGlass` } })));
});

test('B-07: a partial account carve-out is not "every account"', () => {
  const t05 = P(scp({ StringNotLike: { 'aws:PrincipalAccount': ['1*', '4*'] } }));
  clean('no subject', t05, { subjectAccount: null });
  high('subject inside the carve-out', t05);
  high('all-glob', P(scp({ StringNotLike: { 'aws:PrincipalAccount': '*' } })), { subjectAccount: null });
});

test('B-03: a Resource that can never match is a no-op', () => {
  // D-03: ec2:* includes cross-region copies, so it may fire (exit 3).
  failClosed('ec2:* in the allowed region', P(scp(REGION, { Action: 'ec2:*', Resource: 'arn:aws:ec2:us-east-1:*:*' })));
  high('ec2 action in the allowed region', P(scp(REGION, { Action: 'ec2:TerminateInstances', Resource: 'arn:aws:ec2:us-east-1:*:*' })));
  high('s3 ARN with a region', P(scp(REGION, { Action: 's3:*', Resource: 'arn:aws:s3:us-east-1::*' })));
  high('rcp s3 ARN with a region', P(rcp({ StringNotEqualsIfExists: { 'aws:PrincipalOrgID': ORG },
    BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } }, { Action: ['s3:*'], Resource: 'arn:aws:s3:us-east-1::*' })));
  high('wrong partition', P(scp(REGION, { Action: 's3:*', Resource: 'arn:aws-cn:s3:::*' })));
  clean('partition omitted', P(scp(REGION, { Action: 's3:*', Resource: 'arn:aws-cn:s3:::*' })), { partition: null });
  failClosed('unknown partition', P(scp(REGION, { Action: 's3:*', Resource: 'arn:aws-xx:s3:::*' })), { partition: null });
  clean('ec2 outside the allowed region', P(scp(REGION, { Action: 'ec2:*', Resource: 'arn:aws:ec2:eu-west-1:*:*' })));
  clean('s3 access point', P(scp(REGION, { Action: 's3:*', Resource: `arn:aws:s3:eu-west-1:${ACCT}:accesspoint/*` })));
});

test('B-05: contradictory string conditions on one key never fire', () => {
  high('s07', P(scp({ StringNotEquals: { 'aws:RequestedRegion': ['us-east-1'], 'aws:PrincipalArn': `arn:aws:iam::${ACCT}:role/x` },
    StringEquals: { 'aws:PrincipalArn': `arn:aws:iam::${ACCT}:role/x` } })));
});

test('B-08: an RCP on services RCPs do not govern fails closed', () => {
  failClosed('ec2+lambda', P(rcp({ StringNotEqualsIfExists: { 'aws:PrincipalOrgID': ORG },
    BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } }, { Action: ['ec2:*', 'lambda:*'] })));
});
