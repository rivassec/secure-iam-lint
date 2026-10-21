// v1.2.0 final confirmation (e63f602): principal-pin no-ops D-01/D-02 and lows D-03..D-05.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const run = (text, o = {}) => scan({ text, family: 'scp-rcp', partition: 'aws', subjectAccount: ACCT, ...o });
const sev = (r) => r.findings.map((f) => f.severity);
const scp = (Condition, extra = {}) => ({ Effect: 'Deny', Action: '*', Resource: '*', Condition, ...extra });

const high = (name, text, o) => {
  const r = run(text, o);
  assert.equal(r.exitCode, EXIT.FINDINGS, `${name}: rc ${r.exitCode}`);
  assert.ok(sev(r).includes('high'), `${name}: ${sev(r)}`);
};
const notHigh = (name, text, o) => {
  const r = run(text, o);
  assert.ok(!sev(r).includes('high') && !sev(r).includes('critical'), `${name}: ${sev(r)}`);
  return r;
};
const clean = (name, text, o) => assert.equal(run(text, o).exitCode, EXIT.CLEAN, name);

test('D-01: StringEquals with a literal * on a principal key never matches', () => {
  const c = { StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::*:root' } };
  high('with subject', P(scp(c)));
  high('no subject', P(scp(c)), { subjectAccount: undefined });
  high('account ?', P(scp({ StringEquals: { 'aws:PrincipalAccount': '11112222333?' } })), { subjectAccount: undefined });
  // Controls: ArnEquals and StringLike expand *, so the root deny is live.
  clean('ArnEquals *', P(scp({ ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::*:root' } })));
  clean('StringLike *', P(scp({ StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:root' } })));
});

test('D-01: a literal * value does not count as a subject-account hit', () => {
  high('mixed foreign', P(scp({ StringEquals: { 'aws:PrincipalArn':
    ['arn:aws:iam::*:root', 'arn:aws:iam::444455556666:role/x'] } })));
});

test('D-02: aws:PrincipalArn is never an sts assumed-role ARN', () => {
  high('assumed-role pin', P(scp({ StringLike: { 'aws:PrincipalArn': `arn:aws:sts::${ACCT}:assumed-role/Dev/*` } })));
  clean('role pin', P(scp({ StringLike: { 'aws:PrincipalArn': `arn:aws:iam::${ACCT}:role/Dev` } })));
  clean('federated-user pin', P(scp({ StringLike: { 'aws:PrincipalArn': `arn:aws:sts::${ACCT}:federated-user/*` } })));
});

test('D-05: a NotLike union missing one leading digit is a partial carve-out', () => {
  const d = '0123456890'.split('').map((x) => `${x}*`);
  clean('no 7', P(scp({ StringNotLike: { 'aws:PrincipalAccount': d } })), { subjectAccount: undefined });
});

test('D-04: case-sensitive negation vs IgnoreCase / other-case pins is no contradiction', () => {
  const role = `arn:aws:iam::${ACCT}:role/Admin`;
  notHigh('c05', P(scp({ StringEqualsIgnoreCase: { 'aws:PrincipalArn': role }, StringNotEquals: { 'aws:PrincipalArn': role } })));
  notHigh('c07', P(scp({ StringEquals: { 'aws:PrincipalArn': role },
    StringNotLike: { 'aws:PrincipalArn': `arn:aws:iam::${ACCT}:role/admin*` } })));
  high('same-case contradiction', P(scp({ StringEquals: { 'aws:PrincipalArn': role }, StringNotEquals: { 'aws:PrincipalArn': role } })));
});

test('D-03: a cross-region copy Deny on source-region ARNs is not a high no-op', () => {
  const r = notHigh('copy', P({ Effect: 'Deny', Action: ['ec2:CopySnapshot', 'ec2:CopyImage'],
    Resource: ['arn:aws:ec2:us-east-1::snapshot/*', 'arn:aws:ec2:us-east-1::image/*'],
    Condition: { StringNotEquals: { 'aws:RequestedRegion': ['us-east-1'] } } }));
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  high('single-region action', P({ Effect: 'Deny', Action: 'ec2:TerminateInstances',
    Resource: 'arn:aws:ec2:us-east-1:*:instance/*', Condition: { StringNotEquals: { 'aws:RequestedRegion': ['us-east-1'] } } }));
});
