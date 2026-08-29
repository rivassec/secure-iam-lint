// Stage-13 EFO-3 / Stage-14: overwriting the code (or code-selecting configuration) of
// an EXISTING compute resource runs attacker code under that resource's already-bound
// execution/service role - a standalone code-exec / lateral-movement primitive that
// needs NO iam:PassRole. EFO-3 first closed only lambda:UpdateFunctionCode; Stage-14
// generalized it (COMPUTE-CODE-OVERWRITE) to the whole "update existing compute" class:
// lambda:UpdateFunctionCode / UpdateFunctionConfiguration, codebuild:UpdateProject,
// glue:UpdateJob, cloudformation:UpdateStack. The paired-with-PassRole case still fires
// the compound critical PASSROLE-* path (deduped away here).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const A = (policy) => analyze(JSON.stringify(policy), { family: 'identity', requireExplicitFamily: true });
const ids = (r) => (r.findings || []).map((f) => f.id);
const one = (action, resource) => ({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: action, Resource: resource }],
});

const CLASS = [
  ['lambda:UpdateFunctionCode', 'arn:aws:lambda:us-east-1:111111111111:function:prod-fn'],
  ['lambda:UpdateFunctionConfiguration', 'arn:aws:lambda:us-east-1:111111111111:function:prod-fn'],
  ['codebuild:UpdateProject', 'arn:aws:codebuild:us-east-1:111111111111:project/prod'],
  ['glue:UpdateJob', 'arn:aws:glue:us-east-1:111111111111:job/prod'],
  ['cloudformation:UpdateStack', 'arn:aws:cloudformation:us-east-1:111111111111:stack/prod/*'],
];

for (const [action, resource] of CLASS) {
  test(`EFO-3/Stage-14: standalone ${action} (no PassRole) fires COMPUTE-CODE-OVERWRITE:high, not CLEAN`, () => {
    const p = one(action, resource);
    const s = scan({ text: JSON.stringify(p), family: 'identity' });
    assert.notEqual(s.exitCode, 0, `${action} standalone must not be a clean pass`);
    const r = A(p);
    assert.ok(ids(r).includes('COMPUTE-CODE-OVERWRITE'), `${action} must fire COMPUTE-CODE-OVERWRITE`);
    const f = r.findings.find((x) => x.id === 'COMPUTE-CODE-OVERWRITE');
    assert.equal(f.severity, 'high');
    assert.equal(f.escalation.service, action.split(':')[0], 'service is derived from the matched action');
  });
}

test('Stage-14: the paired PassRole+lambda case stays critical-only (dedup, no COMPUTE-CODE-OVERWRITE)', () => {
  const p = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'lambda:UpdateFunctionCode', Resource: 'arn:aws:lambda:us-east-1:111111111111:function:prod-fn' },
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
    ],
  };
  const r = A(p);
  assert.ok(ids(r).includes('PASSROLE-LAMBDA'), 'paired lambda path stays critical');
  assert.ok(!ids(r).includes('COMPUTE-CODE-OVERWRITE'), 'not double-flagged (deduped vs PASSROLE-LAMBDA)');
});

test('Stage-14: paired PassRole+codebuild stays critical-only (dedup vs PASSROLE-SERVICE)', () => {
  const p = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'codebuild:UpdateProject', Resource: 'arn:aws:codebuild:us-east-1:111111111111:project/prod' },
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { StringEquals: { 'iam:PassedToService': 'codebuild.amazonaws.com' } } },
    ],
  };
  const r = A(p);
  assert.ok(ids(r).includes('PASSROLE-SERVICE'), 'paired codebuild path fires the compound critical');
  assert.ok(!ids(r).includes('COMPUTE-CODE-OVERWRITE'), 'not double-flagged (deduped vs PASSROLE-SERVICE)');
});

test('EFO-3: a same-policy Deny covering the overwrite action removes the path (clean)', () => {
  const p = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'lambda:UpdateFunctionCode', Resource: 'arn:aws:lambda:us-east-1:111111111111:function:prod-fn' },
      { Effect: 'Deny', Action: 'lambda:UpdateFunctionCode', Resource: '*' },
    ],
  };
  const s = scan({ text: JSON.stringify(p), family: 'identity' });
  assert.equal(s.exitCode, 0, 'an explicit same-policy Deny removes the standalone path');
});

test('EFO-3: an unrelated read-only action does not fire COMPUTE-CODE-OVERWRITE', () => {
  const r = A(one('lambda:GetFunction', '*'));
  assert.ok(!ids(r).includes('COMPUTE-CODE-OVERWRITE'), 'only overwrite-existing-compute actions fire the finding');
});
