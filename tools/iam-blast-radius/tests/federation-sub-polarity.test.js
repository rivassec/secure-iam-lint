// Federated sub/aud operator polarity: only a non-bypassable positive string match on a
// literal value pins the subject, independent of the order the Condition operators appear in.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import { conditionSignals } from '../../../content/tools/iam-blast-radius/engine/trust-conditions.js';
import { classifyConditionEntry } from '../../../content/tools/iam-blast-radius/engine/conditions.js';

const ACCT = '111122223333';
const ISSUERS = {
  github: ['token.actions.githubusercontent.com', 'sts.amazonaws.com', 'repo:acme/app:ref:refs/heads/main'],
  okta: ['acme.okta.com/oauth2/default', 'api://default', '00u1abcdEFGH'],
  gitlab: ['gitlab.com', 'https://gitlab.com', 'project_path:acme/app:ref_type:branch:ref:main'],
  tfc: ['app.terraform.io', 'aws.workload.identity', 'organization:acme:project:p:workspace:w:run_phase:apply'],
};
const NON_STRING = [
  ['Null', 'false'],
  ['Null', 'true'],
  ['DateGreaterThan', '2020-01-01T00:00:00Z'],
  ['NumericGreaterThan', '0'],
  ['Bool', 'true'],
];

function policy(host, condition) {
  return {
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow',
      Principal: { Federated: `arn:aws:iam::${ACCT}:oidc-provider/${host}` },
      Action: 'sts:AssumeRoleWithWebIdentity',
      Condition: condition,
    }],
  };
}

function run(p) {
  const r = scan({ text: JSON.stringify(p), family: 'role-trust', partition: 'aws', threshold: 'high', subjectAccount: ACCT });
  return { exit: r.exitCode, ids: (r.findings || []).map((f) => `${f.id}:${f.severity}`) };
}

// Builds a Condition whose operator keys appear in exactly the given order.
function ordered(entries) {
  const c = {};
  for (const [op, key, val] of entries) c[op] = { ...(c[op] || {}), [key]: val };
  return c;
}

for (const [name, [host, aud, sub]] of Object.entries(ISSUERS)) {
  const audEq = ['StringEquals', `${host}:aud`, aud];
  const subKey = `${host}:sub`;
  // F5 (v1.2.0): GitHub is multi-tenant, so an unpinned subject is internet-open.
  const broadSev = name === 'github' ? 'critical' : 'high';

  for (const [op, val] of NON_STRING) {
    test(`${name}: ${op}:${val} on sub alone is a broad subject (${broadSev}, exit 1)`, () => {
      assert.deepEqual(run(policy(host, ordered([audEq, [op, subKey, val]]))), { exit: 1, ids: [`TRUST-FEDERATED:${broadSev}`] });
    });

    for (const broadPos of [['StringLike', subKey, '*'], ['StringLike', subKey, 'repo:*'], ['StringNotEquals', subKey, sub]]) {
      test(`${name}: ${broadPos[0]} "${broadPos[2]}" with ${op}:${val} is ${broadSev} in both orders`, () => {
        const a = run(policy(host, ordered([audEq, broadPos, [op, subKey, val]])));
        const b = run(policy(host, ordered([audEq, [op, subKey, val], broadPos])));
        assert.deepEqual(a, { exit: 1, ids: [`TRUST-FEDERATED:${broadSev}`] });
        assert.deepEqual(b, a);
      });
    }

    test(`${name}: exact StringEquals sub ANDed with ${op}:${val} stays tight in both orders`, () => {
      const a = run(policy(host, ordered([audEq, ['StringEquals', subKey, sub], [op, subKey, val]])));
      const b = run(policy(host, ordered([[op, subKey, val], audEq, ['StringEquals', subKey, sub]])));
      assert.deepEqual(a, { exit: 0, ids: ['TRUST-FEDERATED:low'] });
      assert.deepEqual(b, a);
    });

    test(`${name}: ${op} on sub is not a credited guardrail`, () => {
      assert.equal(classifyConditionEntry(op, subKey, val, null, new Set([host])).credited, false);
    });

    test(`${name}: ${op} on aud is not an audience constraint`, () => {
      assert.equal(conditionSignals({ [op]: { [`${host}:aud`]: val } }, null).audConstraint, false);
    });
  }

  test(`${name}: exact StringEquals sub stays tight (low, exit 0)`, () => {
    assert.deepEqual(run(policy(host, ordered([audEq, ['StringEquals', subKey, sub]]))), { exit: 0, ids: ['TRUST-FEDERATED:low'] });
  });

  test(`${name}: IfExists exact sub is broad in both orders next to a glob`, () => {
    const ie = ['StringEqualsIfExists', subKey, sub];
    const glob = ['StringLike', subKey, '*'];
    assert.deepEqual(run(policy(host, ordered([audEq, ie, glob]))), { exit: 1, ids: ['TRUST-FEDERATED:high'] });
    assert.deepEqual(run(policy(host, ordered([audEq, glob, ie]))), { exit: 1, ids: ['TRUST-FEDERATED:high'] });
  });

  test(`${name}: positive StringEquals aud is an audience constraint`, () => {
    assert.equal(conditionSignals({ StringEquals: { [`${host}:aud`]: aud } }, null).audConstraint, true);
    assert.equal(conditionSignals({ StringLike: { [`${host}:aud`]: '*' } }, null).audConstraint, false);
    assert.equal(conditionSignals({ StringEqualsIfExists: { [`${host}:aud`]: aud } }, null).audConstraint, false);
  });
}
