// COMPUTE-SESSION-TAKEOVER (v1.1.0): gaining interactive code-execution on an
// EXISTING compute resource that already carries an IAM role, and thereby using that
// role - no iam:PassRole, no code overwrite. Same outcome as COMPUTE-CODE-OVERWRITE
// (exec as an existing resource's role) but by ACCESSING the resource rather than
// mutating its code:
//   - ssm:SendCommand / ssm:StartSession  -> commands/shell on an EC2 instance as the
//     instance role;
//   - ec2-instance-connect:SendSSHPublicKey / SendSerialConsoleSSHPublicKey -> push a key,
//     connect (SSH or serial console), read the role from IMDS;
//   - sagemaker:CreatePresignedNotebookInstanceUrl -> open an existing notebook and run
//     code as its execution role (Rhino repo method 28).
// High severity (mirrors COMPUTE-CODE-OVERWRITE): a standalone code-exec primitive;
// elevation depends on the target role's power, which is out of scope here.
//
// Runs under `node --test`.

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
  ['ssm:SendCommand', 'arn:aws:ec2:us-east-1:111111111111:instance/*'],
  ['ssm:StartSession', 'arn:aws:ec2:us-east-1:111111111111:instance/*'],
  ['ec2-instance-connect:SendSSHPublicKey', 'arn:aws:ec2:us-east-1:111111111111:instance/*'],
  ['ec2-instance-connect:SendSerialConsoleSSHPublicKey', 'arn:aws:ec2:us-east-1:111111111111:instance/*'],
  ['sagemaker:CreatePresignedNotebookInstanceUrl', 'arn:aws:sagemaker:us-east-1:111111111111:notebook-instance/n'],
];

for (const [action, resource] of CLASS) {
  test(`standalone ${action} (no PassRole) fires COMPUTE-SESSION-TAKEOVER:high, not CLEAN`, () => {
    const p = one(action, resource);
    const s = scan({ text: JSON.stringify(p), family: 'identity' });
    assert.notEqual(s.exitCode, 0, `${action} standalone must not be a clean pass`);
    const r = A(p);
    assert.ok(ids(r).includes('COMPUTE-SESSION-TAKEOVER'), `${action} must fire COMPUTE-SESSION-TAKEOVER`);
    const f = r.findings.find((x) => x.id === 'COMPUTE-SESSION-TAKEOVER');
    assert.equal(f.severity, 'high');
    assert.equal(f.escalation.service, action.split(':')[0], 'service is derived from the matched action');
  });
}

test('a read-only session action does not fire COMPUTE-SESSION-TAKEOVER', () => {
  const r = A(one('ssm:GetCommandInvocation', '*'));
  assert.ok(!ids(r).includes('COMPUTE-SESSION-TAKEOVER'), 'only interactive/exec session actions fire the finding');
});

test('a same-policy Deny removes the COMPUTE-SESSION-TAKEOVER finding', () => {
  // The detector's Deny handling drops the named path. These session actions are not
  // yet in the coverage action-catalog (catalog.js), so a fully-denied session action
  // stays incomplete-coverage (fail-closed) rather than CLEAN - correct conservatism,
  // and a tracked follow-up to model them for a clean verdict.
  const p = {
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'ssm:SendCommand', Resource: 'arn:aws:ec2:us-east-1:111111111111:instance/i-0abc' },
      { Effect: 'Deny', Action: 'ssm:SendCommand', Resource: '*' },
    ],
  };
  const r = A(p);
  assert.ok(!ids(r).includes('COMPUTE-SESSION-TAKEOVER'), 'the same-policy Deny removes the named path');
  const s = scan({ text: JSON.stringify(p), family: 'identity' });
  // Fails CLOSED, not CLEAN. The covering Deny drops the NAMED finding, but because these
  // session actions are not yet in ACTION_CATALOG the verdict must be incomplete-coverage
  // (exit 3), never a clean pass (0) or a findings pass (1). Assert the exact code so all
  // three are pinned: a regression to CLEAN - the T8 fail-open - is caught here, which the
  // old notEqual(exitCode, 1) let through (it also passed on a clean 0).
  assert.equal(s.exitCode, 3, 'denied session action must fail closed via incomplete coverage (exit 3), never CLEAN (0) or findings (1)');
  assert.equal(s.reason, 'COVERAGE_INCOMPLETE', 'the fail-closed verdict is incomplete coverage, not a clean pass');
});
