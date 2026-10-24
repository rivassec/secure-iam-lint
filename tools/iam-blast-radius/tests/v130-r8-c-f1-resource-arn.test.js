// v1.3.0 r8 F-1: CodeArtifact (and other plain type/id services from the trial) are
// modeled ARN grammars, so a confined wildcard reads NARROW instead of MALFORMED.
// Policies f3a..f3h are the 2026-10-23 Mac bundle probes, inlined.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { classifyResource, RESOURCE_CLASS } from '../../../content/tools/iam-blast-radius/engine/resource-arn.js';

const { BROAD, NARROW, MALFORMED } = RESOURCE_CLASS;
const A = 'arn:aws:codeartifact:us-east-2:111111111111';
const CA_READ = ['codeartifact:GetRepositoryEndpoint', 'codeartifact:ReadFromRepository'];

const PROBES = {
  f3a: { Action: CA_READ, Resource: `${A}:domain/example` },
  f3b: { Action: CA_READ, Resource: `${A}:repository/example/*` },
  f3c: { Action: CA_READ, Resource: `${A}:repository/example/python` },
  f3d: { Action: CA_READ, Resource: [`${A}:domain/example`, `${A}:repository/example/*`] },
  f3e: { Action: ['ecr:BatchGetImage'], Resource: 'arn:aws:ecr:us-east-2:111111111111:repository/team/*' },
  f3f: { Action: ['codeartifact:ReadFromRepository'], Resource: `${A}:package/example/python/*` },
  f3g: { Action: ['ssm:GetParameter'], Resource: 'arn:aws:ssm:us-east-2:111111111111:parameter/app/config/*' },
  f3h: { Action: ['logs:PutLogEvents'], Resource: 'arn:aws:logs:us-east-2:111111111111:log-group:/app/*:*' },
};

function run(stmt) {
  return scan({
    text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', ...stmt }] }),
    family: 'identity', partition: 'aws', subjectAccount: '111111111111',
  });
}
const codes = (r) => r.analysisStates.map((s) => s.code);

test('F-1: confined wildcards on the added services are NARROW', () => {
  for (const v of [
    `${A}:repository/example/*`,
    `${A}:package/example/python/*`,
    `${A}:package-group/example/npm/*`,
    `${A}:repository/example/py-*`,
    'arn:aws:scheduler:us-east-1:111111111111:schedule/ci/*',
    'arn:aws:ecr-public::111111111111:repository/team-*',
    'arn:aws:acm-pca:us-east-1:111111111111:certificate-authority/ca-*',
    'arn:aws:amplify:us-east-1:111111111111:apps/d123/branches/*',
    'arn:aws:cognito-idp:us-east-1:111111111111:userpool/us-east-1_ab*',
    'arn:aws:ses:us-east-1:111111111111:identity/app-*',
    'arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/rt-*',
  ]) assert.equal(classifyResource(v), NARROW, v);
});

test('F-1: whole-collection wildcards on the added services stay BROAD', () => {
  for (const v of [
    `${A}:repository/*`, `${A}:repository/*/python`, `${A}:package/*/python/*`, `${A}:domain/*`,
    'arn:aws:scheduler:us-east-1:111111111111:schedule/*',
    'arn:aws:ecr-public::111111111111:repository/*',
    'arn:aws:amplify:us-east-1:111111111111:apps/*/branches/*',
    'arn:aws:cognito-idp:us-east-1:111111111111:userpool/*',
    'arn:aws:codeartifact:us-east-2:*:repository/example/*',
  ]) assert.equal(classifyResource(v), BROAD, v);
});

test('F-1 control: an unmodeled service keeps the HYBRID downgrade', () => {
  assert.equal(classifyResource('arn:aws:madeupsvc:us-east-1:111111111111:widget/my-*'), MALFORMED);
  assert.equal(classifyResource('arn:aws:codeartifacts:us-east-2:111111111111:repository/example/*'), MALFORMED);
});

// Lane A made the two codeartifact reads known, so in-account scoped reads are clean.
test('F-1 probes f3a-f3d/f3f: parsed, and scoped codeartifact reads are clean', () => {
  for (const id of ['f3a', 'f3b', 'f3c', 'f3d', 'f3f']) {
    const r = run(PROBES[id]);
    assert.ok(!codes(r).includes('MALFORMED_RESOURCE_ARN'), `${id}: ${codes(r)}`);
    assert.equal(r.exitCode, EXIT.CLEAN, `${id}: ${codes(r)}`);
  }
});

test('F-1 control: the same codeartifact read on a broad scope still fails closed', () => {
  for (const res of ['*', 'arn:aws:codeartifact:us-east-2:111111111111:repository/*',
    'arn:aws:codeartifact:us-east-2:*:repository/example/*']) {
    const r = run({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'codeartifact:ReadFromRepository', Resource: res }] });
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, res);
  }
});

test('F-1 probes f3e/f3g/f3h: unchanged verdicts', () => {
  assert.equal(run(PROBES.f3e).exitCode, EXIT.CLEAN);
  assert.equal(run(PROBES.f3h).exitCode, EXIT.CLEAN);
  const g = run(PROBES.f3g);
  assert.equal(g.exitCode, EXIT.FINDINGS);
  assert.ok(g.findings.some((f) => f.id === 'DATA-EXFIL'));
});
