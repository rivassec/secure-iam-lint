// v1.3.0 P6: a trust whose AWS principals are all in the subject account is same-account.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '111122223333';
const doc = (...st) => JSON.stringify({ Version: '2012-10-17', Statement: st.map((s) => ({ Effect: 'Allow', Action: 'sts:AssumeRole', ...s })) });
// E-1: same-account needs the role's own ARN as evidence.
const OWN = { type: 'iam-role', arn: `arn:aws:iam::${ACCT}:role/prod` };
const run = (text, o = {}) => scan({ text, family: 'role-trust', partition: 'aws', subjectAccount: ACCT, resourceContext: OWN, ...o });
const ids = (r) => r.findings.map((f) => `${f.id}:${f.severity}`).sort();
const role = (a) => `arn:aws:iam::${a}:role/helperbot-task`;

test('P6: same-account role ARN (the Mac chk.mjs shape) is TRUST-SAME-ACCOUNT low', () => {
  const r = run(doc({ Principal: { AWS: role(ACCT) } }));
  assert.deepEqual(ids(r), ['TRUST-SAME-ACCOUNT:low']);
  assert.equal(r.exitCode, EXIT.CLEAN);
  for (const p of [`arn:aws:iam::${ACCT}:user/ci`, `arn:aws:sts::${ACCT}:assumed-role/x/s`]) {
    assert.deepEqual(ids(run(doc({ Principal: { AWS: p } }))), ['TRUST-SAME-ACCOUNT:low'], p);
  }
});

test('P6: same-account root (ARN or bare id) is TRUST-SAME-ACCOUNT medium', () => {
  for (const p of [`arn:aws:iam::${ACCT}:root`, ACCT]) {
    const r = run(doc({ Principal: { AWS: p } }));
    assert.deepEqual(ids(r), ['TRUST-SAME-ACCOUNT:medium'], p);
    assert.match(r.findings[0].why, /every IAM principal in the account/);
  }
  assert.deepEqual(ids(run(doc({ Principal: { AWS: [role(ACCT), ACCT] } }))), ['TRUST-SAME-ACCOUNT:medium'], 'root wins');
});

test('P6 guards: anything not proven same-account stays cross-account high', () => {
  const high = (name, text, o) => assert.deepEqual(ids(run(text, o)), ['TRUST-CROSS-ACCOUNT:high'], name);
  high('no subject, no role ARN', doc({ Principal: { AWS: role(ACCT) } }), { subjectAccount: undefined, resourceContext: undefined });
  high('subject only, no role ARN (E-1)', doc({ Principal: { AWS: role(ACCT) } }), { resourceContext: undefined });
  high('bad subject', doc({ Principal: { AWS: role(ACCT) } }), { subjectAccount: '1111' });
  high('other account', doc({ Principal: { AWS: role('444455556666') } }));
  high('mixed accounts', doc({ Principal: { AWS: [role(ACCT), role('444455556666')] } }));
  high('mixed root', doc({ Principal: { AWS: [role(ACCT), 'arn:aws:iam::444455556666:root'] } }));
  high('not iam/sts', doc({ Principal: { AWS: `arn:aws:s3:::${ACCT}` } }));
  high('variable', doc({ Principal: { AWS: `arn:aws:iam::${ACCT}:role/\${aws:username}` } }));
});

test('P6 guards: canonical users and wildcards are never same-account', () => {
  const r = run(doc({ Principal: { AWS: role(ACCT), CanonicalUser: 'a'.repeat(64) } }));
  assert.ok(!ids(r).some((x) => x.startsWith('TRUST-SAME-ACCOUNT')), ids(r).join());
  const w = run(doc({ Principal: { AWS: `arn:aws:iam::${ACCT}:role/app-*` } }));
  assert.ok(ids(w).includes('TRUST-INVALID-PRINCIPAL:high') || w.exitCode === EXIT.FAIL_CLOSED, ids(w).join());
  assert.ok(!ids(w).some((x) => x.startsWith('TRUST-SAME-ACCOUNT')));
  assert.notEqual(run(doc({ Principal: '*' })).exitCode, EXIT.CLEAN, 'public');
});

test('P6: per-statement - a cross-account statement next to a same-account one stays high', () => {
  const r = run(doc({ Principal: { AWS: role(ACCT) } }, { Principal: { AWS: role('444455556666') } }));
  assert.deepEqual(ids(r), ['TRUST-CROSS-ACCOUNT:high', 'TRUST-SAME-ACCOUNT:low']);
  assert.equal(r.exitCode, EXIT.FINDINGS);
});

test('P6: service principals in the same statement keep their own finding', () => {
  const r = run(doc({ Principal: { AWS: role(ACCT), Service: 'lambda.amazonaws.com' } }));
  assert.deepEqual(ids(r), ['TRUST-SAME-ACCOUNT:low', 'TRUST-SERVICE:info']);
});

test('P6: conditions do not change the same-account verdict', () => {
  for (const Condition of [{ Bool: { 'aws:MultiFactorAuthPresent': 'true' } },
    { StringEqualsIfExists: { 'sts:ExternalId': 'x1' } }]) {
    assert.deepEqual(ids(run(doc({ Principal: { AWS: role(ACCT) }, Condition }))), ['TRUST-SAME-ACCOUNT:low'], JSON.stringify(Condition));
  }
  // A cross-account trust's conditions still behave as before.
  assert.deepEqual(ids(run(doc({ Principal: { AWS: 'arn:aws:iam::444455556666:root' }, Condition: { StringEquals: { 'sts:ExternalId': 'x1' } } }))),
    ['TRUST-CROSS-ACCOUNT:low']);
});

test('P6: an asserted partition must match; another partition is another account', () => {
  const cn = `arn:aws-cn:iam::${ACCT}:role/helperbot-task`;
  assert.ok(!ids(run(doc({ Principal: { AWS: cn } }))).includes('TRUST-SAME-ACCOUNT:low'));
  assert.ok(!ids(run(doc({ Principal: { AWS: `arn:aws-cn:iam::${ACCT}:root` } }))).some((x) => x.startsWith('TRUST-SAME-ACCOUNT')));
  assert.deepEqual(ids(run(doc({ Principal: { AWS: cn } }), { partition: 'aws-cn',
    resourceContext: { type: 'iam-role', arn: `arn:aws-cn:iam::${ACCT}:role/prod` } })), ['TRUST-SAME-ACCOUNT:low']);
});
