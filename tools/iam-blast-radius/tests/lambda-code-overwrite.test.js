// Stage-13 EFO-3: standalone lambda:UpdateFunctionCode is a privilege-escalation /
// lateral-movement primitive that needs NO iam:PassRole - overwriting an existing
// function's code runs attacker code under that function's ALREADY-BOUND execution
// role (Rhino "UpdateExistingLambdaFunctionCode"). The engine already MODELS this
// technique (escalation.js: LAMBDA_CODE_ONLY_ACTIONS, 'replace-existing-function-code',
// requiresPassRole:false) but only CREDITED it inside detectPassRolePaths, which
// returns early when no iam:PassRole grant is present - so a standalone grant read
// fully CLEAN (T8 fail-open). This suite pins the standalone LAMBDA-CODE-OVERWRITE
// finding (high), and that the PassRole-PAIRED case stays critical-only (no dup).

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const A = (policy) => analyze(JSON.stringify(policy), { family: 'identity', requireExplicitFamily: true });
const ids = (r) => (r.findings || []).map((f) => f.id);

test('EFO-3: standalone lambda:UpdateFunctionCode (narrow ARN, no PassRole) is NOT clean', () => {
  const p = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 'lambda:UpdateFunctionCode', Resource: 'arn:aws:lambda:us-east-1:111111111111:function:prod-fn' }],
  };
  const s = scan({ text: JSON.stringify(p), family: 'identity' });
  assert.notEqual(s.exitCode, 0, 'a standalone code-overwrite primitive is never a clean pass');
  const r = A(p);
  assert.ok(ids(r).includes('LAMBDA-CODE-OVERWRITE'), 'the standalone finding surfaces');
  const f = r.findings.find((x) => x.id === 'LAMBDA-CODE-OVERWRITE');
  assert.equal(f.severity, 'high', 'standalone code-overwrite is high (elevation depends on the existing role)');
});

test('EFO-3: the paired PassRole+lambda case stays critical-only (no duplicate LAMBDA-CODE-OVERWRITE)', () => {
  const p = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'lambda:UpdateFunctionCode', Resource: 'arn:aws:lambda:us-east-1:111111111111:function:prod-fn' },
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
    ],
  };
  const r = A(p);
  assert.ok(ids(r).includes('PASSROLE-LAMBDA'), 'the paired path fires critical PASSROLE-LAMBDA');
  assert.ok(!ids(r).includes('LAMBDA-CODE-OVERWRITE'),
    'the paired case is not ALSO tagged with the standalone finding (deduped)');
});

test('EFO-3: a same-policy Deny covering lambda:UpdateFunctionCode removes the path (clean)', () => {
  const p = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'lambda:UpdateFunctionCode', Resource: 'arn:aws:lambda:us-east-1:111111111111:function:prod-fn' },
      { Effect: 'Deny', Action: 'lambda:UpdateFunctionCode', Resource: '*' },
    ],
  };
  const s = scan({ text: JSON.stringify(p), family: 'identity' });
  assert.equal(s.exitCode, 0, 'an explicit same-policy Deny that AWS honors removes the standalone path');
});

test('EFO-3: an unrelated read-only lambda action does not fire LAMBDA-CODE-OVERWRITE', () => {
  const r = A({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'lambda:GetFunction', Resource: '*' }] });
  assert.ok(!ids(r).includes('LAMBDA-CODE-OVERWRITE'), 'only code-overwrite actions fire the finding');
});
