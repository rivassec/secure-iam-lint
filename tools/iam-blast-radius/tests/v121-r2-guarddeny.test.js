// v1.2.0 review root cause B: SCP/RCP Deny paths use their own allow-list of modeled
// (key, operator) shapes, plus the no-op / inverted / bypass checks (V1-*, V3-*, M1, M2).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const ORG = 'o-exampleorgid';
const P = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st });
const run = (text) => scan({ text, family: 'scp-rcp', partition: 'aws', subjectAccount: ACCT });
const sev = (r) => r.findings.map((f) => f.severity);
const rcp = (Condition, extra = {}) => ({ Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*', Condition, ...extra });
const T = { StringNotEqualsIfExists: { 'aws:PrincipalOrgID': ORG }, BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } };
const SRC = { StringNotEqualsIfExists: { 'aws:SourceOrgID': ORG }, Bool: { 'aws:PrincipalIsAWSService': 'true' }, Null: { 'aws:SourceAccount': 'false' } };
const G = ['organizations:LeaveOrganization', 'cloudtrail:StopLogging', 'cloudtrail:DeleteTrail', 'guardduty:DeleteDetector'];
const scp = (Condition, extra = {}) => ({ Effect: 'Deny', Action: G, Resource: '*', ...(Condition ? { Condition } : {}), ...extra });

const clean = (name, text) => {
  const r = run(text);
  assert.equal(r.exitCode, EXIT.CLEAN, `${name}: rc ${r.exitCode}`);
};
const high = (name, text) => {
  const r = run(text);
  assert.equal(r.exitCode, EXIT.FINDINGS, `${name}: rc ${r.exitCode}`);
  assert.ok(sev(r).includes('high'), `${name}: ${sev(r)}`);
};
const unsupported = (name, text) => {
  const r = run(text);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `${name}: rc ${r.exitCode}`);
  assert.ok(r.analysisStates.some((s) => s.code === 'UNSUPPORTED_CONDITION'), name);
};
const notClean = (name, text) => assert.notEqual(run(text).exitCode, EXIT.CLEAN, name);

test('controls: the AWS templates and real SCP guardrails stay clean', () => {
  clean('F12 template', P(rcp(T)));
  clean('template, no IfExists', P(rcp({ StringNotEquals: { 'aws:PrincipalOrgID': ORG }, Bool: { 'aws:PrincipalIsAWSService': 'false' } })));
  clean('org-only perimeter', P(rcp({ StringNotEqualsIfExists: { 'aws:PrincipalOrgID': ORG } })));
  clean('confused-deputy template', P(rcp(SRC)));
  clean('IgnoreCase perimeter', P(rcp({ StringNotEqualsIgnoreCaseIfExists: { 'aws:PrincipalOrgID': ORG }, BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } })));
  clean('narrow-action perimeter', P(rcp(T, { Action: 's3:GetObject' })));
  clean('plain guardrail', P(scp()));
  const fa = run(P({ Effect: 'Allow', Action: '*', Resource: '*' }, scp()));
  assert.equal(fa.analysisStatus, 'complete');
  assert.equal(fa.findings.find((f) => f.id === 'SCP-GUARDRAIL').severity, 'info');
  clean('region lock', P({ Effect: 'Deny', NotAction: ['iam:*', 'organizations:*', 'sts:*', 'support:*'], Resource: '*', Condition: { StringNotEquals: { 'aws:RequestedRegion': ['us-east-2'] } } }));
  clean('region NotLike legit', P({ Effect: 'Deny', NotAction: ['iam:*'], Resource: '*', Condition: { StringNotLike: { 'aws:RequestedRegion': ['us-*', 'eu-*'] } } }));
  clean('break-glass carve-out', P(scp({ ArnNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/BreakGlass' } })));
  clean('MFA BoolIfExists false', P(scp({ BoolIfExists: { 'aws:MultiFactorAuthPresent': 'false' } })));
  clean('trail-scoped Deny', P(scp(null, { Action: ['cloudtrail:StopLogging'], Resource: 'arn:aws:cloudtrail:us-east-1:111122223333:trail/x' })));
  clean('foreign-account carve-out', P(scp({ StringNotEquals: { 'aws:PrincipalAccount': '444455556666' } })));
});

test('FullAWSAccess alone stays SCP-CEILING high', () => {
  high('FullAWSAccess', P({ Effect: 'Allow', Action: '*', Resource: '*' }));
});

test('M1/M2: unknown operators are unsupported in RCP and SCP Denies', () => {
  unsupported('M1', P(rcp({ StringNotEqualsBogusIfExists: { 'aws:PrincipalOrgID': ORG }, BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } })));
  unsupported('M2', P(scp({ StringNotEqualsBogus: { 'aws:RequestedRegion': 'us-east-2' } })));
  for (const op of ['ArnNotLikeIfExists', 'NumericNotEqualsIfExists', 'BinaryNotEquals', 'ForAllValues:StringNotEquals', 'ForAnyValue:StringNotEqualsIfExists']) {
    unsupported(op, P(rcp({ [op]: { 'aws:PrincipalOrgID': ORG }, BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } })));
  }
});

test('V1-1/V3-02: AND-ed keys outside the RCP allow-list are unsupported', () => {
  const extras = {
    B9: { StringEquals: { 'aws:RequestedRegion': 'xx-none-1' } },
    E2: { ArnNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:*' } },
    E3: { Null: { 'aws:PrincipalArn': 'true' } },
    E4: { StringEquals: { 'aws:PrincipalAccount': '000000000000' } },
    E7: { Null: { 'aws:SourceAccount': 'false' } },
    srcip: { IpAddress: { 'aws:SourceIp': '203.0.113.10/32' } },
    mfa: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } },
    nullip: { Null: { 'aws:SourceIp': 'false' } },
    vpce: { StringNotEqualsIfExists: { 'aws:PrincipalOrgID': ORG, 'aws:SourceVpce': 'vpce-1a2b3c4d' } },
  };
  for (const [k, extra] of Object.entries(extras)) unsupported(k, P(rcp({ ...T, ...extra })));
  const pa = run(P(rcp({ ...T, StringNotLike: { 'aws:PrincipalArn': '*' } })));
  assert.equal(pa.exitCode, EXIT.FAIL_CLOSED);
  assert.ok(sev(pa).includes('high'), 'pa NotLike * never fires');
  unsupported('literal o-* id', P(rcp({ StringNotEqualsIfExists: { 'aws:PrincipalOrgID': [ORG, 'o-*'] }, BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } })));
  unsupported('literal o-* source org', P(rcp({ ...SRC, StringNotEqualsIfExists: { 'aws:SourceOrgID': 'o-*' } })));
});

test('V1-1: never-firing RCP perimeters report high', () => {
  high('B7 contradictory flag', P(rcp({ StringNotEqualsIfExists: { 'aws:PrincipalOrgID': ORG }, Bool: { 'aws:PrincipalIsAWSService': 'true' }, BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } })));
  high('B10 Null org true', P(rcp({ ...T, Null: { 'aws:PrincipalOrgID': 'true' } })));
  high('B19 NotResource s3', P({ Effect: 'Deny', Principal: '*', Action: 's3:*', NotResource: 'arn:aws:s3:::*', Condition: T }));
  high('E5 NotResource *', P({ Effect: 'Deny', Principal: '*', Action: 's3:*', NotResource: '*', Condition: T }));
  high('E6 wrong-service Resource', P(rcp(T, { Resource: 'arn:aws:sqs:*:*:*' })));
});

test('V1-2: a ${...} org value admits every org', () => {
  for (const op of ['StringNotEqualsIfExists', 'StringNotLikeIfExists']) {
    high(op, P(rcp({ [op]: { 'aws:PrincipalOrgID': '${aws:PrincipalOrgID}' }, BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } })));
  }
  high('org-only self-ref', P(rcp({ StringNotEqualsIfExists: { 'aws:PrincipalOrgID': '${aws:PrincipalOrgID}' } })));
  high('source self-ref', P(rcp({ ...SRC, StringNotEqualsIfExists: { 'aws:SourceOrgID': '${aws:SourceOrgID}' } })));
});

test('V1-3: inverted confused-deputy template reports high', () => {
  high('B14d IsAWSService false', P(rcp({ ...SRC, Bool: { 'aws:PrincipalIsAWSService': 'false' } })));
  high('B14f Null SourceAccount true', P(rcp({ ...SRC, Null: { 'aws:SourceAccount': 'true' } })));
});

test('V3-05: Null PrincipalOrgID false inverts the perimeter', () => {
  high('null false', P(rcp({ Null: { 'aws:PrincipalOrgID': 'false' } })));
});

test('V3-06/V3-07: no org key, or a non-* Principal, is unsupported', () => {
  unsupported('svc true only', P(rcp({ BoolIfExists: { 'aws:PrincipalIsAWSService': 'true' } })));
  unsupported('svc false only', P(rcp({ BoolIfExists: { 'aws:PrincipalIsAWSService': 'false' } })));
  unsupported('Principal account', P(rcp(T, { Principal: { AWS: 'arn:aws:iam::444455556666:root' } })));
});

test('V1-4/V3-01: SCP carve-outs that exempt every principal report high', () => {
  const cs = [
    { StringNotLike: { 'aws:PrincipalArn': '*' } },
    { ArnNotLike: { 'aws:PrincipalArn': 'arn:*' } },
    { ArnNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:*' } },
    { ArnNotEquals: { 'aws:PrincipalArn': '*' } },
    { StringNotLikeIfExists: { 'aws:PrincipalArn': '*' } },
    { ArnNotLike: { 'aws:PrincipalArn': ['arn:aws:iam::*:role/*', 'arn:aws:iam::*:user/*'] } },
    { ArnNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/*' } },
    { StringNotLike: { 'aws:PrincipalAccount': '*' } },
    { StringNotEquals: { 'aws:PrincipalAccount': ACCT } },
    { ArnNotLike: { 'aws:PrincipalArn': '${aws:PrincipalArn}' } },
  ];
  for (const c of cs) high(JSON.stringify(c), P(scp(c)));
  high('cloudtrail-only F8 shape', P({ Effect: 'Deny', Action: 'cloudtrail:StopLogging', Resource: '*', Condition: { StringNotLike: { 'aws:PrincipalArn': '*' } } }));
});

test('V1-5/V3-01/V1-6: SCP Denies that never fire report high', () => {
  high('Null PrincipalArn true', P(scp({ Null: { 'aws:PrincipalArn': 'true' } })));
  high('Null RequestedRegion true', P(scp({ Null: { 'aws:RequestedRegion': 'true' } })));
  for (const nr of ['*', 'arn:*', 'arn:aws:*', ['arn:aws:s3:::x', '*']]) {
    high(`NotResource ${nr}`, P({ Effect: 'Deny', Action: G, NotResource: nr }));
  }
  high('FullAWSAccess + NotResource *', P({ Effect: 'Allow', Action: '*', Resource: '*' }, { Effect: 'Deny', Action: G, NotResource: '*' }));
  high('wrong-service Resource', P(scp(null, { Action: ['cloudtrail:StopLogging'], Resource: 'arn:aws:s3:::x' })));
  unsupported('empty Resource', P(scp(null, { Action: ['cloudtrail:StopLogging'], Resource: [] })));
  unsupported('other NotResource', P({ Effect: 'Deny', Action: G, NotResource: 'arn:aws:cloudtrail:us-east-1:111122223333:trail/x' }));
});

test('V3-03: a region / NotAction list whose union covers everything is a no-op', () => {
  const regions = [['us-*', 'eu-*', 'ap-*', 'ca-*', 'sa-*', 'me-*', 'af-*', 'il-*', 'mx-*', 'cn-*'],
    ['*1', '*2', '*3', '*4', '*5', '*6', '*7', '*8', '*9']];
  for (const v of regions) {
    for (const op of ['StringNotLike', 'StringNotLikeIfExists']) {
      high(`${op} ${v[0]}`, P({ Effect: 'Deny', NotAction: ['iam:*', 'sts:*'], Resource: '*', Condition: { [op]: { 'aws:RequestedRegion': v } } }));
    }
  }
  const az = [...'abcdefghijklmnopqrstuvwxyz'].map((c) => `${c}*`);
  notClean('NotAction a*..z*', P({ Effect: 'Deny', NotAction: az, Resource: '*' }));
  high('NotAction a*..z* region deny', P({ Effect: 'Deny', NotAction: az, Resource: '*', Condition: { StringNotEquals: { 'aws:RequestedRegion': 'us-east-2' } } }));
  notClean('ForAllValues region *', P({ Effect: 'Deny', NotAction: ['iam:*'], Resource: '*', Condition: { 'ForAllValues:StringNotLike': { 'aws:RequestedRegion': '*' } } }));
  clean('literal * under NotEqualsIgnoreCase', P(scp({ StringNotEqualsIgnoreCase: { 'aws:RequestedRegion': '*' } })));
});

test('V3-04: presence gates a caller can bypass', () => {
  high('MFA Bool false', P(scp({ Bool: { 'aws:MultiFactorAuthPresent': 'false' } })));
  unsupported('Null SourceIp false', P(scp({ Null: { 'aws:SourceIp': 'false' } })));
  unsupported('SourceVpc', P(scp({ StringEqualsIfExists: { 'aws:SourceVpc': 'vpc-1a2b3c4d' } })));
});

test('SCP: keys outside the allow-list are unsupported', () => {
  unsupported('PrincipalOrgID in an SCP', P(scp({ StringNotEquals: { 'aws:PrincipalOrgID': ORG } })));
  unsupported('CurrentTime', P(scp({ DateLessThan: { 'aws:CurrentTime': '2000-01-01T00:00:00Z' } })));
  unsupported('PrincipalType', P(scp({ StringEquals: { 'aws:PrincipalType': 'Root' } })));
});
