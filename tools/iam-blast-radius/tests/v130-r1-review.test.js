// v1.3.0 round-1 review: E-1 (role ARN evidence), E-2 (only valid principals), E-3 (read wildcards fail closed).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { toJsonReport } from '../../../cli/iam-br.mjs';

const A = '111122223333';
const V = '444455556666';
const trust = (p) => JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: p }, Action: 'sts:AssumeRole' }] });
const own = (acct, part = 'aws') => ({ type: 'iam-role', arn: `arn:${part}:iam::${acct}:role/prod` });
const run = (p, o = {}) => scan({ text: trust(p), family: 'role-trust', partition: 'aws', ...o });
const ids = (r) => r.findings.map((f) => `${f.id}:${f.severity}`);

test('E-1: a subject account alone never proves same-account', () => {
  const r = run(`arn:aws:iam::${V}:role/vendor`, { subjectAccount: V });
  assert.deepEqual(ids(r), ['TRUST-CROSS-ACCOUNT:high']);
  assert.match(r.findings[0].why, /supply the role ARN/);
  assert.equal(run(`arn:aws:iam::${V}:root`, { subjectAccount: V }).exitCode, EXIT.FINDINGS);
});

test('E-1: the role ARN proves it; a contradicting subject or partition does not', () => {
  const ok = run(`arn:aws:iam::${A}:role/x`, { subjectAccount: A, resourceContext: own(A) });
  assert.deepEqual(ids(ok), ['TRUST-SAME-ACCOUNT:low']);
  assert.match(ok.findings[0].why, new RegExp(`arn:aws:iam::${A}:role/prod`));
  assert.deepEqual(ids(run(`arn:aws:iam::${A}:role/x`, { subjectAccount: V, resourceContext: own(A) })), ['TRUST-CROSS-ACCOUNT:high']);
  assert.deepEqual(ids(run(`arn:aws:iam::${A}:role/x`, { resourceContext: own(A, 'aws-cn') })), ['TRUST-CROSS-ACCOUNT:high']);
  assert.deepEqual(ids(run(`arn:aws:iam::${A}:role/x`, { resourceContext: { type: 'iam-role', arn: `arn:aws:iam::${A}:role/*` } })), ['TRUST-CROSS-ACCOUNT:high']);
});

test('E-1: the JSON report echoes the asserted subject account', () => {
  const r = run(`arn:aws:iam::${A}:role/x`, { subjectAccount: A });
  assert.equal(toJsonReport(r, { subjectAccount: A }).subjectAccountAsserted, A);
  assert.equal(toJsonReport(r, { subjectAccount: 'nope' }).subjectAccountAsserted, null);
  assert.equal(toJsonReport(r, {}).subjectAccountAsserted, null);
});

test('E-2: principals AWS would reject never read same-account', () => {
  const ev = { resourceContext: own(A) };
  for (const [name, p, o] of [
    ['E-2a bogus partition', `arn:evil:iam::${A}:root`, { partition: undefined }],
    ['E-2b other partition', `arn:aws-cn:iam::${A}:role/x`, { partition: undefined }],
    ['E-2c upper case', `arn:AWS:IAM::${A}:role/x`, {}],
    ['E-2d trailing space', `arn:aws:iam::${A}:role/x `, {}],
    ['E-2e assumed-role under iam', `arn:aws:iam::${A}:assumed-role/x/s`, {}],
  ]) {
    assert.ok(!ids(run(p, { ...ev, ...o })).some((x) => x.startsWith('TRUST-SAME-ACCOUNT')), name);
  }
  assert.deepEqual(ids(run(`arn:aws:sts::${A}:assumed-role/x/s`, ev)), ['TRUST-SAME-ACCOUNT:low']);
});

test('E-3: read wildcards in deny-only services fail closed (v1.3.0 behavior change)', () => {
  for (const a of ['lambda:Get*', 'lambda:List*', 'cloudformation:Describe*', 'config:Describe*']) {
    const text = JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: a, Resource: '*' }] });
    assert.equal(scan({ text, family: 'identity', partition: 'aws' }).exitCode, EXIT.FAIL_CLOSED, a);
  }
});
