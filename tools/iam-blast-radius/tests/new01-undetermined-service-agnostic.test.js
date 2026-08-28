// NEW-01 (service-agnostic undetermined-account whole-container read). Sibling of R1.
//
// classifyContainerReads' account-UNRESOLVABLE branch collected the surviving read
// ONLY when `arn.service === 's3'`. A dynamodb / kinesis / rds-data ARN with an EMPTY
// or WILDCARD account segment (e.g. arn:aws:dynamodb:us-east-1::table/orders) makes
// concreteResourceAccount() return null - reaching the SAME branch - for ANY service,
// but the S3-only gate DROPPED it, so an unscoped dynamodb:Scan on an account-less
// table read CLEAN (exit 0, findings []) with a KNOWN subject account. That is a
// fail-OPEN: an account-undeterminable whole-container read must never read CLEAN.
//
// The fix makes the undetermined surfacing SERVICE-AGNOSTIC: any whole-container read
// (isWholeContainerRead) with NO concrete account AND NO aws:ResourceAccount pin is
// surfaced as CROSS-ACCOUNT-DATA-READ-UNDETERMINED at info, whatever the service. The
// S3 behaviour, same-account quiet, and single-object quiet are all preserved.
//
// Runs under `node --test`. Real-boundary: the SHIPPED analyze() and the CLI scan().

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan } from '../../../cli/scan.mjs';

const SUBJECT = '123456789012';
const OTHER = '999999999999';
const CERTAINTY = new Set(['high', 'medium', 'low']);

function policy(statements) {
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}
function ids(r) { return r.ok ? r.findings.map((f) => f.id) : []; }
function isClean(r) {
  return !!(r && r.ok === true
    && Array.isArray(r.findings) && r.findings.length === 0
    && !(r.coverage && r.coverage.summary && r.coverage.summary.incomplete));
}
function findingById(r, id) { return r.findings.find((f) => f.id === id); }

// The account-less whole-container reads, one per non-S3 datastore primitive. dynamodb
// is the SHARP case: dynamodb:Scan is a CATALOGUED read, so an account-less table read
// does NOT trip coverage.incomplete - before the fix it was a fully-CLEAN pass, the
// exact reproduced fail-open. kinesis/rds-data are uncatalogued (coverage.incomplete
// already), so they additionally prove the new finding COEXISTS with incomplete coverage
// (no duplicate, no double-drop).
const ACCOUNTLESS = Object.freeze([
  { svc: 'dynamodb', action: 'dynamodb:Scan', resource: 'arn:aws:dynamodb:us-east-1::table/orders', catalogued: true },
  { svc: 'dynamodb (Query)', action: 'dynamodb:Query', resource: 'arn:aws:dynamodb:us-east-1::table/orders', catalogued: true },
  { svc: 'kinesis', action: 'kinesis:GetRecords', resource: 'arn:aws:kinesis:us-east-1::stream/events', catalogued: false },
  { svc: 'rds-data', action: 'rds-data:ExecuteStatement', resource: 'arn:aws:rds-data:us-east-1::cluster:mydb', catalogued: false },
  { svc: 'rds-data (batch)', action: 'rds-data:BatchExecuteStatement', resource: 'arn:aws:rds-data:us-east-1::cluster:mydb', catalogued: false },
]);

for (const c of ACCOUNTLESS) {
  test(`MUST-CLOSE (NEW-01): account-less ${c.svc} whole-container read must NOT read CLEAN`, () => {
    const r = analyze(policy([{ Effect: 'Allow', Action: c.action, Resource: c.resource }]), { subjectAccount: SUBJECT });
    assert.equal(isClean(r), false, `${c.svc} account-less whole-container read is not an affirmative CLEAN`);
    const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
    assert.ok(f, `the account-undeterminable ${c.svc} read must surface; got [${ids(r)}]`);
    assert.equal(f.severity, 'info', 'the crossing is unproven -> info');
    // T8: never a fabricated CONFIRMED cross-account claim (the owner is unknown, not known-to-differ).
    assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ'), 'no confirmed cross-account claim on an account-less ARN');
    assert.match(f.why, /cannot be determined|undetermined/i, 'why states the account is undetermined');
    assert.match(f.why, /not.*safety claim|complete/i, 'why states CLEAN is not a safety claim here');
    // The finding names the actual (non-S3) resource, and its wording must NOT mislabel a
    // non-S3 resource as an "S3 read".
    assert.deepEqual(f.resources, [c.resource], 'the finding names the exact account-less resource');
    assert.doesNotMatch(f.title, /\bS3\b/, 'a non-S3 finding must not mislabel itself as an S3 read');
    // The service-agnostic why must describe the non-S3 datastore shape, not present the
    // resource as S3-only (it may still reference the S3-bucket case as one example).
    assert.match(f.why, /table \/ stream \/ database/,
      'the non-S3 why describes the datastore (table/stream/database) shape');
    assert.ok(CERTAINTY.has(f.policyEvidence) && CERTAINTY.has(f.pathExploitability));
    assert.ok(/^https:\/\//.test(f.docRef));
    assert.ok(Array.isArray(f.actions) && f.actions.length > 0);
  });

  test(`no-duplicate (NEW-01): account-less ${c.svc} read surfaces EXACTLY ONE undetermined row`, () => {
    const r = analyze(policy([{ Effect: 'Allow', Action: c.action, Resource: c.resource }]), { subjectAccount: SUBJECT });
    const rows = r.findings.filter((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
    assert.equal(rows.length, 1, `exactly one undetermined row for one account-less resource; got ${rows.length}`);
    if (!c.catalogued) {
      // The uncatalogued primitives ALSO flag coverage.incomplete - the finding and the
      // coverage signal COEXIST cleanly (the caution's non-double-report requirement).
      assert.ok(r.coverage && r.coverage.summary && r.coverage.summary.incomplete,
        `${c.svc} is uncatalogued so coverage stays incomplete alongside the finding`);
    }
  });

  test(`parity (NEW-01): scan() surfaces the account-less ${c.svc} read (never a silent drop)`, () => {
    const text = policy([{ Effect: 'Allow', Action: c.action, Resource: c.resource }]);
    assert.equal(isClean(analyze(text, { subjectAccount: SUBJECT })), false, 'analyze() is not clean');
    const s = scan({ text, family: 'identity', subjectAccount: SUBJECT });
    assert.ok(s.findingsCount > 0, 'the CLI surfaces the undetermined read (never a silent drop)');
    assert.ok(s.findings.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
      'the CLI report carries the undetermined finding');
  });
}

// A WILDCARD account segment is just as unresolvable as an empty one - it must not clear.
test('MUST-CLOSE (NEW-01): a WILDCARD account segment is also undetermined, not CLEAN', () => {
  const r = analyze(policy([
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: 'arn:aws:dynamodb:us-east-1:*:table/orders' },
  ]), { subjectAccount: SUBJECT });
  assert.equal(isClean(r), false, 'a wildcard-account whole-container read must not read CLEAN');
  assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'), 'wildcard account -> undetermined');
});

// -----------------------------------------------------------------------------
// MUST-STAY-QUIET (no over-correction into false positives / noise).
// -----------------------------------------------------------------------------

test('MUST-STAY-QUIET (NEW-01): a same-account resolvable dynamodb read stays CLEAN', () => {
  const r = analyze(policy([
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: `arn:aws:dynamodb:us-east-1:${SUBJECT}:table/orders` },
  ]), { subjectAccount: SUBJECT });
  assert.equal(isClean(r), true, 'a resolvable same-account table read is routine least privilege -> quiet');
});

test('MUST-STAY-QUIET (NEW-01): a single-item dynamodb:GetItem read stays CLEAN (the single-object analog)', () => {
  // dynamodb:GetItem is the table analog of an s3 bucket/key single-object read: it is
  // deliberately EXCLUDED from DATA_READ_ACTIONS, so an account-less GetItem never reaches
  // the whole-container classifier and stays quiet (it is catalogued, so no incomplete).
  const r = analyze(policy([
    { Effect: 'Allow', Action: 'dynamodb:GetItem', Resource: 'arn:aws:dynamodb:us-east-1::table/orders' },
  ]), { subjectAccount: SUBJECT });
  assert.equal(isClean(r), true, 'a single-item read is not a whole-container read -> quiet');
});

test('conservative (NEW-01): an account-less dynamodb read with UNKNOWN subject stays QUIET', () => {
  // dynamodb:Scan is catalogued (no incomplete). Without a subject there is nothing to
  // compare against, so - exactly like the S3 unknown-subject case - it stays clean.
  const r = analyze(policy([
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: 'arn:aws:dynamodb:us-east-1::table/orders' },
  ])); // no subjectAccount
  assert.equal(isClean(r), true, 'without a subject there is nothing to compare against');
  assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'), 'undetermined needs a known subject');
});

test('control (NEW-01): a CONCRETE foreign-account dynamodb read is a CONFIRMED cross read', () => {
  const r = analyze(policy([
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: `arn:aws:dynamodb:us-east-1:${OTHER}:table/orders` },
  ]), { subjectAccount: SUBJECT });
  assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ'), 'a resolvable foreign owner -> confirmed cross read');
  assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'), 'a resolved owner is not undetermined');
});

// -----------------------------------------------------------------------------
// S3 behaviour unchanged (the sibling control): the canonical S3 bucket path keeps its
// exact id/severity/wording, and its title still reads "S3".
// -----------------------------------------------------------------------------

test('KEEP-GREEN (NEW-01): the canonical S3 bare-bucket read is byte-unchanged', () => {
  const r = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::other-acct-bucket/*' },
  ]), { subjectAccount: SUBJECT });
  const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.ok(f, 'the S3 bare-bucket read still surfaces');
  assert.equal(f.severity, 'info');
  assert.equal(f.title, 'Whole-container S3 read with an undeterminable owning account',
    'the S3-only finding keeps its exact S3-specific title (byte-unchanged)');
  assert.match(f.why, /canonical S3 bucket ARN/, 'the S3-only why keeps its canonical-S3-bucket wording');
});

// A statement mixing an account-less S3 bucket AND an account-less non-S3 table surfaces
// ONE undetermined finding covering BOTH; its wording must be service-agnostic (not "S3").
test('mixed (NEW-01): an S3 + dynamodb account-less statement surfaces both, service-agnostic wording', () => {
  const r = analyze(policy([
    {
      Effect: 'Allow',
      Action: ['s3:GetObject', 'dynamodb:Scan'],
      Resource: ['arn:aws:s3:::orders/*', 'arn:aws:dynamodb:us-east-1::table/orders'],
    },
  ]), { subjectAccount: SUBJECT });
  const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.ok(f, 'the mixed account-less statement surfaces an undetermined read');
  assert.ok(f.resources.includes('arn:aws:s3:::orders/*')
    && f.resources.includes('arn:aws:dynamodb:us-east-1::table/orders'),
  'the mixed finding names BOTH account-less resources (neither silently dropped)');
  assert.doesNotMatch(f.title, /\bS3\b/, 'a mixed finding must not mislabel itself as an S3-only read');
});

// -----------------------------------------------------------------------------
// Determinism.
// -----------------------------------------------------------------------------

test('determinism (NEW-01): account-less non-S3 findings are byte-identical across two runs', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: 'arn:aws:dynamodb:us-east-1::table/orders' },
  ]);
  const opts = { subjectAccount: SUBJECT };
  assert.equal(
    JSON.stringify(analyze(text, opts).findings),
    JSON.stringify(analyze(text, opts).findings),
  );
});
