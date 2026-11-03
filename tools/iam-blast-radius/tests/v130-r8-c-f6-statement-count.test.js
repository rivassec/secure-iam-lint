// v1.3.0 r8 F-6: a per-document count of statements left without a verdict, in the
// engine coverage, the CLI JSON (`statementCoverage`) and the SARIF run properties.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan } from '../../../cli/scan.mjs';
import { buildSarifLog, statementVerdictCoverage } from '../../../cli/sarif.mjs';
import { toJsonReport, toPulumiJsonReport } from '../../../cli/iam-br.mjs';
import { scanPulumi } from '../../../cli/pulumi.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const pol = (...Statement) => JSON.stringify({ Version: '2012-10-17', Statement });
const OK = { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' };
const run = (text, family = 'identity') => scan({ text, family, partition: 'aws' });
const sarifProps = (r) => buildSarifLog(r, { file: 'p.json' }, { ruleVersion: '1' }).runs[0].properties;

test('clean document: zero of N', () => {
  const r = run(pol(OK, { ...OK, Sid: 'two' }));
  assert.deepEqual(statementVerdictCoverage(r), { total: 2, withoutVerdict: 0, indexes: [] });
  const p = sarifProps(r);
  assert.equal(p.statementsTotal, 2);
  assert.equal(p.statementsWithoutVerdict, 0);
});

test('each gap kind names its own statement', () => {
  const text = pol(
    OK,
    { Effect: 'Allow', Action: 'fakesvc:Do', Resource: '*' },
    { ...OK, Condition: { StringEquals: { 'zzz:MadeUp': 'x' } } },
    { Effect: 'Allow', Action: 's3:GetObject', Resource: '*.pem' },
    { Effect: 'Allow', Action: 'dynamodb:GetItem', Resource: '?*' },
    { ...OK, Sid: 'last' },
  );
  const a = analyze(text, { family: 'identity' });
  assert.deepEqual(a.coverage.summary.statementsWithoutVerdict, { count: 4, indexes: [1, 2, 3, 4] });
  const r = run(text);
  assert.deepEqual(toJsonReport(r, {}).statementCoverage, { total: 6, withoutVerdict: 4, indexes: [1, 2, 3, 4] });
  assert.equal(sarifProps(r).statementsWithoutVerdict, 4);
});

test('an unknown action counted once per statement, on every statement that carries it', () => {
  const r = run(pol(
    { Effect: 'Allow', Action: ['fakesvc:Do', 'fakesvc:Other'], Resource: '*' },
    { Effect: 'Allow', Action: 'fakesvc:Do', Resource: '*' },
    OK,
  ));
  assert.deepEqual(statementVerdictCoverage(r), { total: 3, withoutVerdict: 2, indexes: [0, 1] });
});

test('document-wide gaps count every statement (blocked family)', () => {
  const r = run(pol(OK, { Effect: 'Allow', NotPrincipal: { AWS: 'arn:aws:iam::123456789012:root' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }), 'resource');
  const c = statementVerdictCoverage(r);
  assert.ok(c, 'coverage present');
  assert.equal(c.withoutVerdict, c.total);
  assert.ok(c.total >= 1);
});

test('rejected input: null, never a fabricated zero', () => {
  const r = run('{"Version":"2012-10-17","Statement":[');
  assert.equal(statementVerdictCoverage(r), null);
  assert.equal(toJsonReport(r, {}).statementCoverage, null);
  const p = sarifProps(r);
  assert.equal(p.statementsTotal, null);
  assert.equal(p.statementsWithoutVerdict, null);
});

test('incomplete implies a non-zero count (no "incomplete, 0 statements")', () => {
  for (const text of [
    pol({ Effect: 'Allow', Action: 'fakesvc:Do', Resource: '*' }),
    pol({ ...OK, Condition: { StringEquals: { 'zzz:k': 'x' } } }),
    pol({ Effect: 'Allow', Action: 's3:GetObject', Resource: ' arn:aws:s3:::b/*' }),
    pol({ Effect: 'Allow', NotAction: [], Resource: '*' }),
  ]) {
    const a = analyze(text, { family: 'identity' });
    assert.equal(a.coverage.summary.incomplete, true, text);
    assert.ok(a.coverage.summary.statementsWithoutVerdict.count > 0, text);
  }
});

test('Pulumi: each document carries its own statementCoverage', () => {
  const text = readFileSync(join(here, 'pulumi-fixtures', 'preview-update.json'), 'utf8');
  const res = scanPulumi({ text, subjectAccount: '111122223333', partition: 'aws' });
  const rep = toPulumiJsonReport(res, {});
  assert.ok(rep.documents.length > 0);
  for (const d of rep.documents) {
    assert.ok(Object.hasOwn(d, 'statementCoverage'));
    if (d.statementCoverage) assert.ok(d.statementCoverage.withoutVerdict <= d.statementCoverage.total);
  }
});
