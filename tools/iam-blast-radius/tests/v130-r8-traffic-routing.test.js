// r8: TRAFFIC-ROUTING (ENI / ELB / EventBridge / security-group writes) and the exact
// matchPatterns prefilter that keeps the detector catalogs off the DoS budget.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import { matchPatterns } from '../../../content/tools/iam-blast-radius/engine/rules-detectors.js';
import { actionGrants, TRAFFIC_ROUTING_ACTIONS, TRAFFIC_REDIRECT_ACTIONS, DATA_READ_ACTIONS } from '../../../content/tools/iam-blast-radius/engine/rules-classify.js';

const ACCT = '123456789012';
const P = (...s) => JSON.stringify({ Version: '2012-10-17', Statement: s });
const allow = (a, r) => P({ Effect: 'Allow', Action: a, Resource: r });
const run = (text) => scan({ text, family: 'identity', threshold: 'high', subjectAccount: ACCT, partition: 'aws' });
const tr = (r) => (r.findings || []).filter((f) => f.id === 'TRAFFIC-ROUTING');
const arn = (svc, id) => `arn:aws:${svc}:us-east-2:${ACCT}:${id}`;

test('redirect actions are high (exit 1) on one named resource', () => {
  for (const a of TRAFFIC_REDIRECT_ACTIONS) {
    const r = run(allow(a, arn(a.split(':')[0], 'x/y')));
    assert.equal(r.exitCode, EXIT.FINDINGS, a);
    assert.deepEqual(tr(r).map((f) => f.severity), ['high'], a);
  }
});

test('every other routing write is a medium finding: known, reported, exit 0 at fail-on high', () => {
  for (const a of TRAFFIC_ROUTING_ACTIONS.filter((x) => !TRAFFIC_REDIRECT_ACTIONS.includes(x))) {
    const r = run(allow(a, arn(a.split(':')[0], 'x/y')));
    assert.equal(r.exitCode, EXIT.CLEAN, `${a}: ${r.reason}`);
    assert.deepEqual(tr(r).map((f) => f.severity), ['medium'], a);
    const strict = scan({ text: allow(a, arn(a.split(':')[0], 'x/y')), family: 'identity', threshold: 'medium', subjectAccount: ACCT, partition: 'aws' });
    assert.equal(strict.exitCode, EXIT.FINDINGS, `${a} at fail-on medium`);
  }
});

test('a family wildcard reaching a still-withheld member stays exit 3', () => {
  // ModifyTrustStore (mTLS trust) and CreateConnection (credentials) are not modeled.
  for (const a of ['elasticloadbalancing:Modify*', 'events:Create*']) {
    const r = run(allow(a, arn(a.split(':')[0], 'x/y')));
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, a);
    assert.ok(tr(r).length > 0, a);
  }
});

test('reads, deletes and a covering Deny do not produce TRAFFIC-ROUTING', () => {
  assert.equal(tr(run(allow(['elasticloadbalancing:DescribeListeners', 'ec2:DescribeNetworkInterfaces'], '*'))).length, 0);
  assert.equal(tr(run(allow('events:DeleteRule', arn('events', 'rule/r')))).length, 0);
  const denied = run(P({ Effect: 'Allow', Action: 'events:PutTargets', Resource: arn('events', 'rule/r') },
    { Effect: 'Deny', Action: 'events:PutTargets', Resource: '*' }));
  assert.equal(tr(denied).length, 0);
  assert.equal(denied.exitCode, EXIT.CLEAN);
});

// The prefilter must never change which patterns match: compare against the naive scan.
test('matchPatterns prefilter is exact (randomized + edge patterns)', () => {
  const catalogs = [TRAFFIC_ROUTING_ACTIONS, DATA_READ_ACTIONS];
  const naive = (acts, cat) => acts.filter((p) => cat.some((c) => actionGrants(p, c)));
  const seeds = [...TRAFFIC_ROUTING_ACTIONS, ...DATA_READ_ACTIONS, 's3:GetObject', 'dynamodb:Scan'];
  let x = 12345;
  const rnd = (n) => { x = (x * 1103515245 + 12345) % 2147483648; return x % n; };
  const pats = ['e*', '*:PutTargets', 'ec2?CreateNetworkInterface', '?????:PutRule', 'EVENTS:PUTTARGETS',
    'elasticloadbalancing:*Listener', '*', 'ec2', ':', '', 'events:Put*s', 'e*s:P?tR?le', 'İevents:PutRule'];
  for (let k = 0; k < 4000; k++) {
    const chars = seeds[rnd(seeds.length)].split('');
    const edits = 1 + rnd(4);
    for (let e = 0; e < edits; e++) {
      const i = rnd(chars.length);
      const op = rnd(4);
      if (op === 0) chars[i] = '?';
      else if (op === 1) chars.splice(i, 1, '*');
      else if (op === 2) chars.splice(i, 1);
      else chars[i] = chars[i].toUpperCase();
    }
    pats.push(chars.join(''));
  }
  for (const cat of catalogs) {
    assert.deepEqual(matchPatterns({ actions: pats }, cat, true), naive(pats.filter((p) => p !== '*'), cat));
  }
});
