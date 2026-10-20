// UNKNOWN_ACTION / UNSUPPORTED_CONDITION analyzer-state rows name the offending
// tokens in SARIF message.text. Before, only the JSON output carried them
// (details.actions / details.conditions), so a SARIF-only consumer had to bisect the
// policy to find which action or key failed the run.
//
// The tokens are attacker-controlled policy text, so each is rendered markdown-inert
// (every ASCII punctuation char backslash-escaped), and the fingerprint must not move
// (stateIdentity never reads details) so existing alerts do not churn.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import { buildSarifLog, FINGERPRINT_KEY } from '../../../cli/sarif.mjs';

const MANIFEST = { ruleVersion: '1' };

function stateRows(policy, family = 'identity') {
  const result = scan({
    text: JSON.stringify(policy),
    family,
    threshold: 'high',
    subjectAccount: '123456789012',
    partition: 'aws',
  });
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  return log.runs[0].results.filter((r) => r.ruleId.startsWith('analysis.'));
}

test('UNKNOWN_ACTION message names each unknown action', () => {
  const rows = stateRows({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 'sqs:SendMessage', 'fakesvc:DoThing'], Resource: 'arn:aws:s3:::b/*' }],
  });
  const row = rows.find((r) => r.ruleId === 'analysis.UNKNOWN_ACTION');
  assert.ok(row, 'UNKNOWN_ACTION row present');
  assert.ok(row.message.text.endsWith(' Offending actions: fakesvc\\:DoThing, sqs\\:SendMessage.'), row.message.text);
  assert.doesNotMatch(row.message.text, /s3:GetObject/);
});

test('UNSUPPORTED_CONDITION message names each unmodeled condition key', () => {
  const rows = stateRows({
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::b',
      Condition: { StringLike: { 'zzz:madeupkey': ['home/*'] } },
    }],
  });
  const row = rows.find((r) => r.ruleId === 'analysis.UNSUPPORTED_CONDITION');
  assert.ok(row, 'UNSUPPORTED_CONDITION row present');
  assert.ok(row.message.text.endsWith(' Offending condition keys: zzz\\:madeupkey.'), row.message.text);
});

test('a hostile unknown action renders inert (no newline, no live link, no raw backtick)', () => {
  const rows = stateRows({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: ['fakesvc:Do[x](javascript:alert(1))`bt`\nInjected'], Resource: '*' }],
  });
  const row = rows.find((r) => r.ruleId === 'analysis.UNKNOWN_ACTION');
  assert.ok(row);
  const text = row.message.text;
  assert.doesNotMatch(text, /\n/);
  assert.ok(!text.includes(']('), text);
  assert.ok(!/(^|[^\\])`/.test(text), `no unescaped backtick: ${text}`);
});

test('a long unknown-action list is count-capped with a truthful remainder', () => {
  const actions = Array.from({ length: 20 }, (_, i) => `fakesvc:Action${String(i).padStart(2, '0')}`);
  const rows = stateRows({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: actions, Resource: '*' }] });
  const text = rows.find((r) => r.ruleId === 'analysis.UNKNOWN_ACTION').message.text;
  assert.match(text, /\(\+8 more\)\.$/);
  assert.ok(text.includes('fakesvc\\:Action11'));
  assert.ok(!text.includes('fakesvc\\:Action12'));
});

test('the state fingerprint does not depend on which actions are unknown', () => {
  const fp = (action) => stateRows({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: action, Resource: '*' }],
  }).find((r) => r.ruleId === 'analysis.UNKNOWN_ACTION').partialFingerprints[FINGERPRINT_KEY];
  assert.equal(fp('fakesvc:One'), fp('fakesvc:Two'));
});

test('the offending tokens also ride in a machine-readable, inert property', () => {
  const unknown = stateRows({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: ['sqs:SendMessage', 'fakesvc:DoThing'], Resource: '*' }],
  }).find((r) => r.ruleId === 'analysis.UNKNOWN_ACTION');
  assert.deepEqual(unknown.properties.unknownActions, ['fakesvc\\:DoThing', 'sqs\\:SendMessage']);
  const cond = stateRows({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: 's3:ListBucket', Resource: 'arn:aws:s3:::b', Condition: { StringEquals: { 'zzz:madeup': 'x' } } }],
  }).find((r) => r.ruleId === 'analysis.UNSUPPORTED_CONDITION');
  assert.deepEqual(cond.properties.unsupportedConditions, ['zzz\\:madeup']);
});
