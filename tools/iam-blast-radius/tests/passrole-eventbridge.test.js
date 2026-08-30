// EventBridge (CloudWatch Events) is a PassRole target: events:PutTargets takes a
// RoleArn that EventBridge assumes to invoke the target. iam:PassRole + events:PutTargets
// therefore lets an attacker pass a privileged role to EventBridge and drive it. This is a
// PASSROLE-SERVICE path; before the events catalog entry it was caught only by the
// incomplete-coverage backstop (never CLEAN, but not named). Surfaced by the privesc
// benchmark second tier.
//
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const ACCT = '123456789012';

test('iam:PassRole + events:PutTargets fires PASSROLE-SERVICE (critical), never CLEAN', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: `arn:aws:iam::${ACCT}:role/eb` },
      { Effect: 'Allow', Action: 'events:PutRule', Resource: '*' },
      { Effect: 'Allow', Action: 'events:PutTargets', Resource: '*' },
    ],
  });
  const s = scan({ text, family: 'identity', subjectAccount: ACCT, partition: 'aws' });
  assert.notEqual(s.exitCode, EXIT.CLEAN, 'PassRole to EventBridge must never read CLEAN');
  const r = analyze(text, { subjectAccount: ACCT, partition: 'aws' });
  const ids = (r.findings || []).map((f) => f.id);
  assert.ok(ids.includes('PASSROLE-SERVICE'), `expected PASSROLE-SERVICE, got [${ids.join(', ')}]`);
});
