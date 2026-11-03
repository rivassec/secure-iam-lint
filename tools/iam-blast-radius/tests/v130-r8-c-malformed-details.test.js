// v1.3.0 r8 Lane C: MALFORMED_RESOURCE_ARN names the offending value (neutralized,
// capped) and why, in JSON details and SARIF properties. The fingerprint does not move.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import { buildSarifLog, FINGERPRINT_KEY } from '../../../cli/sarif.mjs';
import {
  classifyResource, classifyResourceDetailed, RESOURCE_CLASS, MALFORMED_REASON,
} from '../../../content/tools/iam-blast-radius/engine/resource-arn.js';
import { MAX_DETAIL_VALUE_LEN } from '../../../content/tools/iam-blast-radius/engine/masked-grant.js';

const doc = (resource, action = 's3:GetObject') => JSON.stringify({
  Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: action, Resource: resource }],
});
const run = (resource) => scan({ text: doc(resource), family: 'identity', partition: 'aws' });
const mstate = (r) => r.analysisStates.find((s) => s.code === 'MALFORMED_RESOURCE_ARN');
const srow = (r) => buildSarifLog(r, { file: 'p.json' }, { ruleVersion: '1' })
  .runs[0].results.find((x) => x.ruleId === 'analysis.MALFORMED_RESOURCE_ARN');

test('reason: one per MALFORMED path; null exactly when not MALFORMED', () => {
  const cases = [
    ['', MALFORMED_REASON.EMPTY],
    [' ', MALFORMED_REASON.EMPTY],
    [' arn:aws:s3:::bucket/*', MALFORMED_REASON.WHITESPACE],
    ['*.pem', MALFORMED_REASON.NOT_AN_ARN],
    ['arn:aws', MALFORMED_REASON.NOT_AN_ARN],
    ['arn:aws:iam::123456789012:/role/*', MALFORMED_REASON.EMPTY_LEADING_SEGMENT],
    ['arn:aws:madeupsvc:us-east-1:123456789012:widget/my-*', MALFORMED_REASON.UNMODELED_SERVICE_GLOB],
  ];
  for (const [v, reason] of cases) {
    assert.deepEqual(classifyResourceDetailed(v), { cls: RESOURCE_CLASS.MALFORMED, reason }, JSON.stringify(v));
  }
  for (const v of ['*', 'arn:aws:iam::123456789012:role/*', 'arn:aws:s3:::b/*', ' arn:aws:s3:::*', '?*']) {
    const d = classifyResourceDetailed(v);
    assert.equal(d.cls, classifyResource(v));
    assert.equal(d.reason, null, v);
  }
});

test('JSON details: first offending value, reason and count', () => {
  const st = mstate(run(['arn:aws:s3:::ok/*', 'arn:aws:madeupsvc:us-east-1:123456789012:widget/my-*', '*.pem']));
  assert.ok(st);
  assert.equal(st.path, 'Statement[0].Resource');
  assert.deepEqual(st.details, {
    value: 'arn:aws:madeupsvc:us-east-1:123456789012:widget/my-*',
    reason: 'UNMODELED_SERVICE_GLOB',
    count: 2,
  });
});

test('details value is display-neutralized and capped', () => {
  const long = `*${'a'.repeat(500)}.pem`;
  const st = mstate(run(long));
  assert.equal(st.details.value.length, MAX_DETAIL_VALUE_LEN + 3);
  assert.ok(st.details.value.endsWith('...'));
  const hostile = mstate(run('*‮.pem​[x](javascript:alert(1))א'));
  assert.doesNotMatch(hostile.details.value, /[‮​א]/);
});

test('SARIF: reason prose + properties, markdown-inert, fingerprint unchanged', () => {
  const r = run('*.pem[x](https://evil.example/t.png)`bt`');
  const row = srow(r);
  assert.ok(row.message.text.endsWith(' Reason: the value is neither the bare wildcard nor a well-formed ARN.'), row.message.text);
  assert.equal(row.properties.malformedReason, 'NOT_AN_ARN');
  assert.equal(row.properties.malformedCount, 1);
  assert.ok(row.properties.offendingValue.length > 0);
  const text = JSON.stringify(row);
  assert.ok(!text.includes(']('), text);
  assert.ok(!/(^|[^\\])`/.test(row.properties.offendingValue));
  // Identity is code + path only: a different malformed value keeps the fingerprint.
  assert.equal(row.partialFingerprints[FINGERPRINT_KEY], srow(run('*-prod')).partialFingerprints[FINGERPRINT_KEY]);
  const bare = { ...mstate(r) };
  delete bare.details;
  const noDetails = buildSarifLog({ ...r, analysisStates: [bare] }, { file: 'p.json' }, { ruleVersion: '1' }).runs[0].results[0];
  assert.equal(noDetails.partialFingerprints[FINGERPRINT_KEY], row.partialFingerprints[FINGERPRINT_KEY]);
});

test('NotResource axis carries its own details', () => {
  const r = scan({
    text: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 's3:GetObject', NotResource: ['arn:aws:iam::123456789012::role/x'] }] }),
    family: 'identity', partition: 'aws',
  });
  const st = mstate(r);
  assert.equal(st.path, 'Statement[0].NotResource');
  assert.equal(st.details.reason, 'EMPTY_LEADING_SEGMENT');
});
