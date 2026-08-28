// S1-breadth-classify: the ONE semantic Resource-ARN classifier
// (engine/resource-arn.js) that REPLACES the accreted isBroadArnResource + the
// shallow startsWith('arn:') gate masked-grant.js used to decide undecidability.
//
// This suite locks the CLASS the classifier closes, at three levels:
//   1. the classifier itself: classifyResource(value) -> BROAD | NARROW | MALFORMED,
//      and the shared parseArn() both rules.js and masked-grant.js read;
//   2. the two SURFACES that read it: rules.js isBroadArnResource (BROAD firing) and
//      masked-grant.js MALFORMED_RESOURCE_ARN (undecidable -> incomplete) - they must
//      agree because they share the one classifier ("two gates agree wrongly" killed);
//   3. end-to-end through the shipped analyze() AND the CLI scan(): every MUST-CLOSE
//      value is fail-CLOSED (a finding OR incomplete, never a bare CLEAN / exit 0) and
//      every MUST-STAY-NARROW value is genuinely clean (no over-correction).
//
// The fail-open CLASS: a value that is neither "*" nor a well-formed 6-segment ARN
// (a suffix/infix glob "*.pem", a bare literal, a truncated "arn:"/"arn:aws", a
// leading-whitespace ARN, an empty element) used to read as a narrow scope (or slip
// masked-grant's startsWith('arn:') gate) and returned a bare CLEAN on a real bulk
// read - a DATA-EXFIL fail-OPEN (threat-model T8). Plus two structural fail-opens the
// old enumerative predicate missed: a no-delimiter typed-resource glob (function*,
// role*) that swallows the type/id boundary, and a broad-but-undecidable glob ("?*")
// on a statement the rule catalog leaves finding-free (dynamodb:GetItem).
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  classifyResource, parseArn, RESOURCE_CLASS,
} from '../../../content/tools/iam-blast-radius/engine/resource-arn.js';
import { isBroadArnResource } from '../../../content/tools/iam-blast-radius/engine/rules.js';
import {
  detectMaskedGrants, MASKED_GRANT_CODES,
} from '../../../content/tools/iam-blast-radius/engine/masked-grant.js';
import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';
import { defaultCatalog, ACCESS_LEVELS } from '../../../content/tools/iam-blast-radius/engine/catalog.js';

const { BROAD, NARROW, MALFORMED } = RESOURCE_CLASS;
const BROAD_IDS = new Set(['DATA-EXFIL', 'WILDCARD-RESOURCE']);

function policy(action, resource) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'S', Effect: 'Allow', Action: action, Resource: resource }],
  });
}
function isClean(r) {
  return !!(r && r.ok === true
    && Array.isArray(r.findings) && r.findings.length === 0
    && !(r.coverage && r.coverage.summary && r.coverage.summary.incomplete));
}
function incomplete(r) {
  return !!(r.coverage && r.coverage.summary && r.coverage.summary.incomplete);
}
function ids(r) { return r.ok ? r.findings.map((f) => f.id) : []; }

// --- 1. The classifier verdicts ----------------------------------------------

const BROAD_CASES = [
  '*',
  // wildcard high in the ARN (partition / service / account)
  'arn:*:s3:::my-bucket/*', 'arn:aws:*', 'arn:aws:?*', 'arn:aws:iam::*:role/*',
  'arn:*:*:*:*:*', 'arn:?:?:?:?:?',
  // whole-collection identifier wildcard
  'arn:aws:iam::123456789012:role/*', 'arn:aws:s3:us-east-1:123456789012:accesspoint/*/object/*',
  // no-delimiter typed-resource glob (swallows the type/id boundary)
  'arn:aws:lambda:us-east-1:123456789012:function*', 'arn:aws:iam::123456789012:role*',
  // S3 bucket-name-segment wildcard (leading, interior, suffix; decorated region/acct)
  'arn:aws:s3:::*/*', 'arn:aws:s3:::*-prod/*.pem', 'arn:aws:s3:::my-bucket-*/*.pem',
  'arn:aws:s3:::pre*fix/key', 'arn:aws:s3:us-east-1::my-bucket-*/key.pem',
  // s3-outposts whole-collection leaf
  'arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-abc/bucket/*',
  // boundary-crossing NON-ARN globs (semantic probe battery)
  '*/*', '?*', '**', '*:*', 'arn*',
  // sns/sqs leading-wildcard name
  'arn:aws:sns:us-east-1:123456789012:*',
];

const NARROW_CASES = [
  'arn:aws:s3:::my-bucket/prefix/*', 'arn:aws:s3:::my-bucket/*', 'arn:aws:s3:::example-bucket',
  'arn:aws:iam::123456789012:role/app-*', 'arn:aws:iam::123456789012:role/deployment/*',
  'arn:aws:lambda:us-east-1:123456789012:function:my-fn',
  'arn:aws:kms:us-east-1:123456789012:key/abcd',
  'arn:aws:s3:us-east-1:123456789012:accesspoint/my-ap/object/*',
  'arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-abc/bucket/my-bucket/object/*',
  'arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-abc/bucket/prod-*',
  'arn:aws:sns:us-east-1:123456789012:my-topic-*', 'arn:aws:sqs:us-east-1:123456789012:app-events',
  // unknown service, CONCRETE resource: one resource regardless of grammar
  'arn:aws:x:::y', 'arn:aws:madeupsvc:us-east-1:123456789012:widget/myitem',
];

const MALFORMED_CASES = [
  // not "*" and not a well-formed ARN, and NOT a boundary-crossing glob
  '*/*.pem', '*.pem', '*.key', '*.env', '*.txt', '*log', '*-prod',
  'my-plain-resource', 'https://evil.example.com/leak',
  // truncated / empty-segment ARNs the old startsWith('arn:') gate read as narrow
  'arn:', 'arn:aws', 'arn:aws:s3', 'arn:aws:s3:::',
  // whitespace: an empty element, or leading/trailing space that must not rescue a
  // would-be-narrow value into clean
  '', ' ', '\t', ' arn:aws:s3:::bucket/*', 'arn:aws:s3:::my-bucket/*  ',
  // HYBRID: a would-be-narrow ARN on a service the engine does not model, where the
  // narrowness relies on the unverified typed grammar (a confined wildcard)
  'arn:aws:madeupsvc:us-east-1:123456789012:widget/my-*',
  // EMPTY LEADING SEGMENT in the resource-id (iter-5 fail-open closure): a leading '/'
  // or ':' makes the resource-TYPE / bucket-NAME head token empty, so the real
  // whole-collection keyword used to be mis-read as a concrete name -> NARROW -> bare
  // CLEAN. Every one of these re-spells a MUST-FIRE whole-collection wildcard
  // (role/*, all-buckets) or a HIGH-severity bulk read; they are undeployable and must
  // fail closed to MALFORMED, never NARROW. High-order partition/service/account
  // wildcards are UNAFFECTED (still BROAD) - see the dedicated iter-5 test below.
  'arn:aws:iam::123456789012:/role/*', 'arn:aws:iam::123456789012::role/*',
  'arn:aws:s3:::/*', 'arn:aws:s3:::/', 'arn:aws:s3:::/key', 'arn:aws:s3:::/prefix/*',
  'arn:aws:kms:us-east-1:123456789012:/key/*',
  'arn:aws:dynamodb:us-east-1:123456789012:/table/*',
  'arn:aws:lambda:us-east-1:123456789012:/function/*',
];

test('classifyResource: BROAD verdicts', () => {
  for (const v of BROAD_CASES) {
    assert.equal(classifyResource(v), BROAD, `${JSON.stringify(v)} must be BROAD`);
  }
});
test('classifyResource: NARROW verdicts', () => {
  for (const v of NARROW_CASES) {
    assert.equal(classifyResource(v), NARROW, `${JSON.stringify(v)} must be NARROW`);
  }
});
test('classifyResource: MALFORMED verdicts', () => {
  for (const v of MALFORMED_CASES) {
    assert.equal(classifyResource(v), MALFORMED, `${JSON.stringify(v)} must be MALFORMED`);
  }
});

test('parseArn: well-formed 6-segment ARN parses; truncated/empty-segment does not', () => {
  const a = parseArn('arn:aws:s3:::my-bucket/key');
  assert.deepEqual(a, {
    partition: 'aws', service: 's3', region: '', account: '', resourceId: 'my-bucket/key',
  });
  for (const bad of ['arn:', 'arn:aws', 'arn:aws:s3', 'arn:aws:s3:::', 'not-an-arn', '*', '', '  arn:aws:s3:::b/k']) {
    assert.equal(parseArn(bad), null, `${JSON.stringify(bad)} is not a well-formed ARN`);
  }
});

// --- 2. The two surfaces agree (ONE classifier, no drift) --------------------

test('rules.isBroadArnResource === (classifyResource === BROAD) for every case', () => {
  for (const v of [...BROAD_CASES, ...NARROW_CASES, ...MALFORMED_CASES]) {
    assert.equal(isBroadArnResource(v), classifyResource(v) === BROAD,
      `${JSON.stringify(v)}: rules breadth predicate must mirror the shared classifier`);
  }
});

test('masked-grant flags MALFORMED_RESOURCE_ARN exactly for MALFORMED values (Allow)', () => {
  for (const v of MALFORMED_CASES) {
    if (v.trim() === '') continue; // an empty/whitespace element may not survive into resources[]
    const m = modelFromText(policy('s3:GetObject', v));
    assert.equal(m.ok, true, `${JSON.stringify(v)}: model builds`);
    const flagged = detectMaskedGrants(m.model)
      .some((g) => g.code === MASKED_GRANT_CODES.MALFORMED_RESOURCE_ARN);
    assert.ok(flagged, `${JSON.stringify(v)}: MUST be flagged MALFORMED_RESOURCE_ARN`);
  }
  for (const v of [...BROAD_CASES, ...NARROW_CASES]) {
    const m = modelFromText(policy('s3:GetObject', v));
    if (!m.ok) continue;
    const flagged = detectMaskedGrants(m.model)
      .some((g) => g.code === MASKED_GRANT_CODES.MALFORMED_RESOURCE_ARN);
    assert.ok(!flagged, `${JSON.stringify(v)}: BROAD/NARROW must NOT be flagged MALFORMED_RESOURCE_ARN`);
  }
});

// --- 3. End-to-end: MUST-CLOSE is fail-closed (finding OR incomplete) ---------

// Structural fail-opens the old predicate missed: a no-delimiter typed glob fires a
// broad finding (function*/role* match every function/role in the account).
const MUST_CLOSE_FIRES = [
  ['lambda:UpdateFunctionCode', 'arn:aws:lambda:us-east-1:123456789012:function*'],
  ['iam:PassRole', 'arn:aws:iam::123456789012:role*'],
  ['s3:GetObject', 'arn:aws:s3:::my-bucket-*/*.pem'],
  ['s3:GetObject', 'arn:aws:s3:::probe-*/*.pem'],
];
test('MUST-CLOSE (fires): a broad finding fires and the CLI blocks (exit 1)', () => {
  for (const [action, resource] of MUST_CLOSE_FIRES) {
    const r = analyze(policy(action, resource));
    assert.equal(isClean(r), false, `${resource}: MUST NOT be a bare CLEAN (T8)`);
    assert.ok(ids(r).some((id) => BROAD_IDS.has(id)), `${resource}: MUST fire a broad-scope finding; got [${ids(r)}]`);
    const s = scan({ text: policy(action, resource), family: 'identity' });
    assert.notEqual(s.exitCode, EXIT.CLEAN, `${resource}: scan must not exit 0`);
    assert.ok(s.blockingCount >= 1, `${resource}: expected a blocking finding`);
  }
});

// Undecidable values route to incomplete (MALFORMED_RESOURCE_ARN), never a finding,
// never a bare CLEAN. The CLI fails closed (exit 3).
const MUST_CLOSE_INCOMPLETE = [
  '*/*.pem', '*.pem', '*.key', '*.env', '*.txt', '*log', '*-prod',
  'arn:', 'arn:aws', ' arn:aws:s3:::bucket/*', '', ' ', '\t',
];
test('MUST-CLOSE (undecidable): incomplete via MALFORMED_RESOURCE_ARN, CLI fails closed', () => {
  for (const resource of MUST_CLOSE_INCOMPLETE) {
    const r = analyze(policy('s3:GetObject', resource));
    assert.equal(r.ok, true, `${JSON.stringify(resource)}: well-formed analysis`);
    assert.equal(isClean(r), false, `${JSON.stringify(resource)}: MUST NOT be a bare CLEAN (T8)`);
    assert.equal(incomplete(r), true, `${JSON.stringify(resource)}: undecidable -> incomplete`);
    assert.ok(r.coverage.summary.codes.includes('MALFORMED_RESOURCE_ARN'),
      `${JSON.stringify(resource)}: carries MALFORMED_RESOURCE_ARN; got [${r.coverage.summary.codes.join(', ')}]`);
    const s = scan({ text: policy('s3:GetObject', resource), family: 'identity' });
    assert.equal(s.exitCode, EXIT.FAIL_CLOSED, `${JSON.stringify(resource)}: expected fail-closed exit 3; got ${s.exitCode}`);
    assert.equal(s.reason, 'MALFORMED_RESOURCE_ARN', `${JSON.stringify(resource)}: reason MALFORMED_RESOURCE_ARN; got ${s.reason}`);
  }
});

// The action-aware fail-open: a broad-but-undecidable glob ("?*") on a statement the
// rule catalog leaves finding-free (a non-exfil read). "broad implies a rule fired"
// is the assumption that fails open; the tool must mark it incomplete instead.
test('MUST-CLOSE (broad-but-uncovered): dynamodb:GetItem on "?*" is incomplete, not CLEAN', () => {
  const r = analyze(policy('dynamodb:GetItem', '?*'));
  assert.equal(r.ok, true);
  assert.equal(ids(r).length, 0, 'no rule covers a dynamodb read on a broad glob');
  assert.equal(isClean(r), false, '"?*" must NOT be a bare CLEAN (T8)');
  assert.equal(incomplete(r), true, 'broad-but-undecidable uncovered glob -> incomplete');
  assert.ok(r.coverage.summary.codes.includes('BROAD_RESOURCE_UNDECIDABLE'),
    `carries BROAD_RESOURCE_UNDECIDABLE; got [${r.coverage.summary.codes.join(', ')}]`);
  assert.deepEqual(
    r.coverage.summary.broadUndecidableUncovered.map((u) => u.value), ['?*'],
    'the exact uncovered value is recorded',
  );
  const s = scan({ text: policy('dynamodb:GetItem', '?*'), family: 'identity' });
  assert.notEqual(s.exitCode, EXIT.CLEAN, 'scan must not exit 0');
  assert.equal(s.exitCode, EXIT.FAIL_CLOSED, 'a broad-but-uncovered grant fails closed (exit 3)');
  assert.ok(s.analysisStates.some((st) => st.code === 'BROAD_RESOURCE_UNDECIDABLE'),
    'the CLI names the broad-undecidable analyzer-state');
});

// A concrete covered read on "?*"'s covered twin: s3:GetObject on "?*" DOES fire
// DATA-EXFIL (the boundary-crossing glob is broad), so it stays a COMPLETE finding -
// the action-aware signal must NOT fire when a finding already covered the statement.
test('a broad glob the rules DID cover ("?*" + s3:GetObject) stays a COMPLETE finding', () => {
  const s = scan({ text: policy('s3:GetObject', '?*'), family: 'identity' });
  assert.equal(s.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'covered broad glob is a complete analysis');
  assert.equal(s.exitCode, EXIT.FINDINGS, 'covered broad glob blocks at exit 1');
  assert.ok(!(s.coverage.summary.codes || []).includes('BROAD_RESOURCE_UNDECIDABLE'),
    'a covered statement must not raise the broad-undecidable signal');
});

// S1-breadth-classify (iter 2): the well-formed-ARN HALF of the same fail-open class.
// The action-aware net above ("?*") originally EXCLUDED every well-formed ARN
// (`parseArn(v) !== null` short-circuit), re-instating the exact forbidden assumption
// ("broad implies a rule fired") for the whole well-formed-ARN input space. A non-exfil
// READ on a BROAD well-formed ARN fires NEITHER rule (WILDCARD-RESOURCE needs a non-read
// action; DATA-EXFIL needs the s3-bulk/secret catalog), so it slipped through as a bare
// CLEAN. These are the read-action twins of the '?*' must-close case: an attacker
// re-spells the fail-closed glob '?*' as the equally-broad well-formed ARN
// 'arn:aws:dynamodb::*:table/foo' (wildcard ACCOUNT - a cross-account read) and the tool
// must NOT clear it. classifyResource() reports BROAD on all of them, the rule catalog
// leaves them finding-free, and they must route to incomplete symmetric with '?*'.
const MUST_CLOSE_BROAD_ARN_READ = [
  ['dynamodb:GetItem', 'arn:aws:dynamodb::*:table/foo'],            // wildcard ACCOUNT (cross-account)
  ['dynamodb:GetItem', 'arn:aws:dynamodb:us-east-1:123456789012:table/*'], // whole-collection wildcard
  ['iam:GetRole', 'arn:aws:iam::*:role/*'],                        // wildcard account + collection
  ['kms:DescribeKey', 'arn:aws:kms:us-east-1:*:key/*'],            // wildcard account + collection
  ['s3:GetBucketPolicy', 'arn:aws:s3:::*'],                        // whole-bucket-namespace wildcard
];
test('MUST-CLOSE (broad well-formed ARN + read): incomplete, not CLEAN, symmetric with "?*"', () => {
  for (const [action, resource] of MUST_CLOSE_BROAD_ARN_READ) {
    // The one shared classifier reports BROAD - the twin's broadness equals the glob's.
    assert.equal(classifyResource(resource), BROAD, `${resource}: classifier must report BROAD`);
    const r = analyze(policy(action, resource));
    assert.equal(r.ok, true, `${resource}: well-formed analysis`);
    assert.equal(ids(r).length, 0, `${resource}: no rule covers a non-exfil read on a broad ARN; got [${ids(r)}]`);
    assert.equal(isClean(r), false, `${resource}: MUST NOT be a bare CLEAN (T8 fail-open)`);
    assert.equal(incomplete(r), true, `${resource}: broad-but-uncovered well-formed ARN -> incomplete`);
    assert.ok(r.coverage.summary.codes.includes('BROAD_RESOURCE_UNDECIDABLE'),
      `${resource}: carries BROAD_RESOURCE_UNDECIDABLE; got [${r.coverage.summary.codes.join(', ')}]`);
    assert.deepEqual(
      r.coverage.summary.broadUndecidableUncovered.map((u) => u.value), [resource],
      `${resource}: the exact uncovered value is recorded`,
    );
    // Browser-CLI parity: the CLI fails closed at exit 3, matching the '?*' twin.
    const s = scan({ text: policy(action, resource), family: 'identity' });
    assert.notEqual(s.exitCode, EXIT.CLEAN, `${resource}: scan must not exit 0`);
    assert.equal(s.exitCode, EXIT.FAIL_CLOSED, `${resource}: a broad-but-uncovered ARN fails closed (exit 3)`);
    assert.ok(s.analysisStates.some((st) => st.code === 'BROAD_RESOURCE_UNDECIDABLE'),
      `${resource}: the CLI names the broad-undecidable analyzer-state`);
  }
});

// The mutating-action twins of the SAME broad well-formed ARNs stay COMPLETE findings:
// a rule fires, the statement is covered, and the broad-undecidable net must NOT also
// mark it incomplete (the coveredStatementIndexes guard). Guards against a regression
// where removing the parseArn short-circuit double-flags a statement a rule already owns.
const BROAD_ARN_WRITE_STAYS_FINDING = [
  ['dynamodb:PutItem', 'arn:aws:dynamodb::*:table/foo'],
  ['iam:PassRole', 'arn:aws:iam::*:role/*'],
  ['s3:DeleteObject', 'arn:aws:s3:::*'],
];
test('broad well-formed ARN + mutating action stays a COMPLETE finding (not double-flagged)', () => {
  for (const [action, resource] of BROAD_ARN_WRITE_STAYS_FINDING) {
    const r = analyze(policy(action, resource));
    assert.equal(isClean(r), false, `${resource}: MUST NOT be a bare CLEAN`);
    assert.ok(ids(r).length >= 1, `${resource}: a rule must fire on a broad-resource mutating action; got [${ids(r)}]`);
    assert.ok(!(r.coverage.summary.codes || []).includes('BROAD_RESOURCE_UNDECIDABLE'),
      `${resource}: a covered statement must NOT raise the broad-undecidable signal`);
    const s = scan({ text: policy(action, resource), family: 'identity' });
    assert.notEqual(s.exitCode, EXIT.CLEAN, `${resource}: scan must not exit 0`);
  }
});

// --- 3a-iter5. Empty-leading-segment resource-id: a leading '/' or ':' fail-open -----
// A resource-id that STARTS with a delimiter ('/role/*', ':role/*', '/*') makes the
// resource-TYPE / bucket-NAME head token the empty string, so the classifier used to
// read the REAL whole-collection keyword as a concrete top-level name and returned
// NARROW -> bare CLEAN. This re-spells every whole-collection wildcard the story locks
// as MUST-FIRE (role/*, all-buckets) and downgrades even a HIGH-severity bulk read
// (s3:GetObject @ 'arn:aws:s3:::/*') to clean. Both analyze() and scan() failed open
// identically (shared classifier hole, not a parity gap). They must now reach a finding
// OR incomplete, never a bare CLEAN, on both surfaces.
const EMPTY_LEADING_SEGMENT_READS = [
  ['s3:GetObject', 'arn:aws:s3:::/*'],       // was NARROW; twin of DATA-EXFIL 'arn:aws:s3:::*'
  ['s3:GetObject', 'arn:aws:s3:::/'],
  ['s3:GetObject', 'arn:aws:s3:::/key'],
  ['s3:GetObject', 'arn:aws:s3:::/prefix/*'],
  ['dynamodb:PutItem', 'arn:aws:iam::123456789012:/role/*'],
  ['dynamodb:PutItem', 'arn:aws:iam::123456789012::role/*'],
  ['kms:Decrypt', 'arn:aws:kms:us-east-1:123456789012:/key/*'],
  ['dynamodb:GetItem', 'arn:aws:dynamodb:us-east-1:123456789012:/table/*'],
  ['lambda:InvokeFunction', 'arn:aws:lambda:us-east-1:123456789012:/function/*'],
];
test('MUST-CLOSE (empty leading segment): a leading-delimiter resource-id is MALFORMED -> incomplete, never CLEAN, parity', () => {
  for (const [action, resource] of EMPTY_LEADING_SEGMENT_READS) {
    // The one shared classifier must NOT read a leading-delimiter id as NARROW.
    assert.equal(classifyResource(resource), MALFORMED,
      `${resource}: an empty leading resource-id segment must be MALFORMED, not NARROW`);
    const text = policy(action, resource);
    const r = analyze(text);
    assert.equal(r.ok, true, `${resource}: well-formed analysis`);
    assert.equal(isClean(r), false, `${resource}: MUST NOT be a bare CLEAN (T8 fail-open)`);
    assert.equal(incomplete(r), true, `${resource}: undecidable -> incomplete`);
    assert.ok(r.coverage.summary.codes.includes('MALFORMED_RESOURCE_ARN'),
      `${resource}: carries MALFORMED_RESOURCE_ARN; got [${r.coverage.summary.codes.join(', ')}]`);
    // Browser-CLI parity: scan() fails closed identically (exit 3), never exit 0.
    const s = scan({ text, family: 'identity' });
    assert.notEqual(s.exitCode, EXIT.CLEAN, `${resource}: scan must not exit 0`);
    assert.equal(s.exitCode, EXIT.FAIL_CLOSED, `${resource}: expected fail-closed exit 3; got ${s.exitCode}`);
    assert.equal(s.reason, 'MALFORMED_RESOURCE_ARN', `${resource}: reason MALFORMED_RESOURCE_ARN; got ${s.reason}`);
  }
});

// The high-order wildcard checks (partition/service/account) are NOT evaded by a
// leading delimiter: a genuinely broad account-wildcard ARN that ALSO carries a
// leading-delimiter resource-id must still fire BROAD (the MALFORMED guard is placed
// AFTER the high-order wildcard check, so fail-closed BROAD is never traded for
// MALFORMED). The canonical no-leading-delimiter twin already classifies BROAD.
test('empty-leading-segment guard does not evade the high-order partition/service/account wildcard (still BROAD)', () => {
  for (const v of [
    'arn:aws:iam::*:/role/*', 'arn:aws:s3:us-east-1:*:/accesspoint/*',
    'arn:*:s3:::/bucket/*', 'arn:aws:*:us-east-1:123456789012:/table/*',
  ]) {
    assert.equal(classifyResource(v), BROAD,
      `${v}: a high-order (partition/service/account) wildcard is BROAD regardless of a leading-delimiter resource-id`);
    assert.equal(isBroadArnResource(v), true, `${v}: rules breadth predicate must still fire`);
  }
});

// --- 3b. NotResource axis: the broad-uncovered net must be axis-symmetric --------
// Iteration-3 fail-open closure. broadUndecidableUncovered originally inspected only
// s.resources, never s.notResources, so a routine-read Allow scoped by a NON-EMPTY
// NotResource complement (grant on everything EXCEPT a narrow set - account-wide broad
// per rules.js resourceIsBroad()) fired no rule and read as a bare CLEAN. This is the
// internal asymmetry vs masked-grant.js, which already covers BOTH axes for MALFORMED.
function notResourcePolicy(action, notResource) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'S', Effect: 'Allow', Action: action, NotResource: notResource }],
  });
}

// A broad complement on a routine read fires NO rule (dynamodb:GetItem / iam:GetRole
// are not in the exfil catalog and NotResource emits no WILDCARD-RESOURCE for a read),
// so without the NotResource-axis net these were bare CLEAN fail-opens.
const BROAD_NOTRESOURCE_READ = [
  ['dynamodb:GetItem', 'arn:aws:s3:::my-bucket/*'],
  ['iam:GetRole', 'arn:aws:iam::123456789012:role/keep'],
  ['kms:DescribeKey', 'arn:aws:kms:us-east-1:123456789012:key/abc'],
  ['ec2:DescribeInstances', 'arn:aws:ec2:us-east-1:123456789012:instance/i-0'],
  ['s3:GetBucketPolicy', 'arn:aws:s3:::my-bucket'],
];
test('MUST-CLOSE (NotResource axis): a broad NotResource complement on an uncovered read is incomplete, not CLEAN', () => {
  for (const [action, notResource] of BROAD_NOTRESOURCE_READ) {
    const text = notResourcePolicy(action, notResource);
    const r = analyze(text);
    assert.equal(r.ok, true, `${action}: analyzes`);
    assert.equal(isClean(r), false, `${action} NotResource ${notResource}: must NOT be a bare CLEAN (T8)`);
    assert.equal(incomplete(r), true, `${action} NotResource ${notResource}: broad complement -> incomplete`);
    assert.ok(r.coverage.summary.codes.includes('BROAD_RESOURCE_UNDECIDABLE'),
      `${action}: carries BROAD_RESOURCE_UNDECIDABLE; got [${r.coverage.summary.codes.join(', ')}]`);
    const entry = r.coverage.summary.broadUndecidableUncovered.find((u) => u.axis === 'NotResource');
    assert.ok(entry, `${action}: an entry is recorded on the NotResource axis`);
    assert.equal(entry.value, notResource, `${action}: the complement value travels as evidence`);
    // Browser-CLI parity: the CLI fails closed at exit 3 with the same code + axis.
    const s = scan({ text, family: 'identity' });
    assert.equal(s.exitCode, EXIT.FAIL_CLOSED, `${action}: scan must fail closed (exit 3)`);
    assert.notEqual(s.analysisStatus, ANALYSIS_STATUS.COMPLETE, `${action}: scan status must not be complete`);
    const st = s.analysisStates.find((x) => x.code === 'BROAD_RESOURCE_UNDECIDABLE');
    assert.ok(st, `${action}: scan surfaces BROAD_RESOURCE_UNDECIDABLE`);
    assert.equal(st.path, `Statement[0].NotResource`, `${action}: the analyzer-state path points at the NotResource axis`);
  }
});

// The covered twin: a WRITE action + NotResource fires WILDCARD-RESOURCE (resourceIsBroad
// true + a non-read action), so the statement is COVERED and the broad-uncovered net must
// NOT also flag it. Guards the "keep WILDCARD-RESOURCE-fires-on-write NotResource case green"
// requirement against a double-flag regression.
test('WILDCARD-RESOURCE fires on a write + NotResource; the broad-uncovered net does not double-flag it', () => {
  const text = notResourcePolicy('s3:PutObject', 'arn:aws:s3:::my-bucket/*');
  const r = analyze(text);
  assert.equal(isClean(r), false, 'a broad write must NOT be a bare CLEAN');
  assert.ok(ids(r).includes('WILDCARD-RESOURCE'), `WILDCARD-RESOURCE must fire; got [${ids(r)}]`);
  assert.ok(!(r.coverage.summary.codes || []).includes('BROAD_RESOURCE_UNDECIDABLE'),
    'a covered write statement must NOT also raise the broad-undecidable signal');
  assert.ok(!(r.coverage.summary.broadUndecidableUncovered || []).some((u) => u.axis === 'NotResource'),
    'no NotResource-axis broad-uncovered entry for a covered statement');
  // A covered statement was analyzed to a conclusion: the CLI reports COMPLETE and
  // raises no broad-undecidable analyzer-state (my net must not flip a covered write
  // to incomplete). Its exit code follows the ordinary severity threshold, not this net.
  const s = scan({ text, family: 'identity' });
  assert.equal(s.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'a covered write analyzes COMPLETE, not incomplete');
  assert.ok(!s.analysisStates.some((x) => x.code === 'BROAD_RESOURCE_UNDECIDABLE'),
    'the CLI raises no broad-undecidable state for a covered write');
});

// A malformed member on the NotResource axis still routes via masked-grant (unchanged);
// a broad WELL-FORMED complement now routes via the broad-uncovered net. Either way the
// read is incomplete - the axis is fail-closed for BOTH shapes, symmetric with Resource.
test('a malformed NotResource member on an uncovered read stays incomplete (masked-grant, unchanged)', () => {
  const r = analyze(notResourcePolicy('dynamodb:GetItem', '*.pem'));
  assert.equal(incomplete(r), true, 'a malformed NotResource complement -> incomplete');
});

// --- 3c. Deny-interaction: the broad-uncovered net keys off DENY-SURVIVING findings --
// Iteration-4 fail-open closure. broadUndecidableUncovered originally built its
// "covered" set from the PRE-Deny-suppression `combined` finding set, while the
// authoritative table later DROPS Deny-suppressed rule findings (ruleFindingDenySuppressed:
// a same-policy full action-Deny OR a NotResource fence). So when a statement's ONLY rule
// finding was Deny-suppressed, the statement stayed marked "covered", the net SKIPPED it,
// and a DIFFERENT surviving broad READ on that same statement was never flagged -> a bare
// CLEAN (T8). This re-instated the exact forbidden assumption ("a rule fired implies a risk
// was surfaced") that the design warns against, except the fired rule is later removed by
// Deny precedence. The fix keys "covered" off tableFindings (the Deny-SURVIVING set), so a
// statement whose only finding is Deny-suppressed re-enters the net and its surviving broad
// read flips incomplete. General across BOTH Deny mechanisms (full action-Deny AND
// NotResource fence) and BOTH covering rules (DATA-EXFIL bulk-read AND secret-read).
function twoStatementText(allow, deny) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [Object.assign({ Sid: 'A', Effect: 'Allow' }, allow),
      Object.assign({ Sid: 'D', Effect: 'Deny' }, deny)],
  });
}

// [description, allow-stmt, deny-stmt, the surviving-broad-read resource value]
const DENY_SUPPRESSED_SURVIVING_BROAD_READ = [
  // 1. Full action-Deny suppresses DATA-EXFIL (s3:GetObject); the surviving
  //    dynamodb:GetItem reads EVERY table in the account/region (whole-collection wildcard).
  ['full action-Deny, surviving dynamodb read on table/*',
    { Action: ['s3:GetObject', 'dynamodb:GetItem'], Resource: 'arn:aws:dynamodb:us-east-1:123456789012:table/*' },
    { Action: 's3:GetObject', Resource: '*' },
    'arn:aws:dynamodb:us-east-1:123456789012:table/*'],
  // 2. Secret twin: secretsmanager:GetSecretValue suppressed; the surviving iam:GetRole
  //    is a cross-account (wildcard-account) role read.
  ['full action-Deny, surviving cross-account iam:GetRole on role/*',
    { Action: ['secretsmanager:GetSecretValue', 'iam:GetRole'], Resource: 'arn:aws:iam::*:role/*' },
    { Action: 'secretsmanager:GetSecretValue', Resource: '*' },
    'arn:aws:iam::*:role/*'],
  // 3. NotResource-fence twin: denyFencesToNarrow removes DATA-EXFIL; the surviving
  //    dynamodb:GetItem on "arn:aws:s3:::*/*" (BROAD) is uncovered.
  ['NotResource fence, surviving dynamodb read on s3:::*/*',
    { Action: ['s3:GetObject', 'dynamodb:GetItem'], Resource: 'arn:aws:s3:::*/*' },
    { Action: 's3:GetObject', NotResource: 'arn:aws:s3:::keep/only' },
    'arn:aws:s3:::*/*'],
];
test('MUST-CLOSE (Deny-suppressed twin): a surviving broad read on a Deny-suppressed statement is incomplete, not CLEAN', () => {
  for (const [desc, allow, deny, survivingValue] of DENY_SUPPRESSED_SURVIVING_BROAD_READ) {
    // The surviving read's resource is genuinely BROAD per the one shared classifier.
    assert.equal(classifyResource(survivingValue), BROAD, `${desc}: surviving value must classify BROAD`);
    const text = twoStatementText(allow, deny);
    const r = analyze(text);
    assert.equal(r.ok, true, `${desc}: analyzes`);
    // The one finding that fired is fully Deny-suppressed, so the table is empty...
    assert.equal(ids(r).length, 0, `${desc}: the sole finding is Deny-suppressed; got [${ids(r)}]`);
    // ...but the surviving broad read must NOT let the tool clear the policy.
    assert.equal(isClean(r), false, `${desc}: MUST NOT be a bare CLEAN (T8 fail-open)`);
    assert.equal(incomplete(r), true, `${desc}: the surviving broad read -> incomplete`);
    assert.ok(r.coverage.summary.codes.includes('BROAD_RESOURCE_UNDECIDABLE'),
      `${desc}: carries BROAD_RESOURCE_UNDECIDABLE; got [${r.coverage.summary.codes.join(', ')}]`);
    const entry = (r.coverage.summary.broadUndecidableUncovered || []).find((u) => u.value === survivingValue);
    assert.ok(entry, `${desc}: the surviving broad value is recorded as uncovered`);
    // Browser-CLI parity: the CLI fails closed at exit 3, not a clean exit 0.
    const s = scan({ text, family: 'identity' });
    assert.notEqual(s.exitCode, EXIT.CLEAN, `${desc}: scan must not exit 0`);
    assert.equal(s.exitCode, EXIT.FAIL_CLOSED, `${desc}: a surviving broad read fails closed (exit 3)`);
    assert.notEqual(s.analysisStatus, ANALYSIS_STATUS.COMPLETE, `${desc}: scan status must not be complete`);
    assert.ok(s.analysisStates.some((st) => st.code === 'BROAD_RESOURCE_UNDECIDABLE'),
      `${desc}: the CLI names the broad-undecidable analyzer-state`);
  }
});

// Control A (no over-correction): the SAME statements WITHOUT the Deny keep the covering
// finding, so the net must NOT also flip incomplete - the covered statement stays a
// COMPLETE finding. Proves the interaction, not the classifier, drove the closure.
test('control: without the Deny the covering finding stays and the net does not double-flag', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'A', Effect: 'Allow', Action: ['s3:GetObject', 'dynamodb:GetItem'],
      Resource: 'arn:aws:dynamodb:us-east-1:123456789012:table/*',
    }],
  });
  const r = analyze(text);
  assert.ok(ids(r).includes('DATA-EXFIL'), `DATA-EXFIL must fire without the Deny; got [${ids(r)}]`);
  assert.equal(isClean(r), false, 'a real exfil finding is not clean');
  assert.ok(!(r.coverage.summary.codes || []).includes('BROAD_RESOURCE_UNDECIDABLE'),
    'a covered statement must NOT also raise the broad-undecidable signal');
});

// Control B (no over-correction): a Deny-suppressed statement whose SHARED resource is
// NARROW must STAY CLEAN - the surviving read is narrow, so the net must not fire. Guards
// against over-correcting every Deny-suppressed statement into incomplete.
test('control: a Deny-suppressed statement with a NARROW resource stays CLEAN (no over-correction)', () => {
  const text = twoStatementText(
    { Action: ['s3:GetObject', 'dynamodb:GetItem'], Resource: 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table' },
    { Action: 's3:GetObject', Resource: '*' },
  );
  const r = analyze(text);
  assert.equal(ids(r).length, 0, `no surviving finding on a narrow resource; got [${ids(r)}]`);
  assert.equal(isClean(r), true, 'a Deny-suppressed statement scoped to a narrow resource must analyze CLEAN');
  const s = scan({ text, family: 'identity' });
  assert.equal(s.exitCode, EXIT.CLEAN, 'a narrow surviving read is genuinely clean (exit 0)');
});

// --- 4. MUST-STAY-NARROW: no over-correction (clean, no finding, not incomplete) --

const MUST_STAY_NARROW = [
  ['s3:GetObject', 'arn:aws:s3:::my-bucket/prefix/*'],
  ['s3:PutObject', 'arn:aws:s3:::my-bucket/*'],
  ['iam:GetRole', 'arn:aws:iam::123456789012:role/app-*'],
  ['iam:PassRole', 'arn:aws:iam::123456789012:role/deployment/*'],
  ['lambda:InvokeFunction', 'arn:aws:lambda:us-east-1:123456789012:function:my-fn'],
  // unknown-service CONCRETE resource (recognized action): the resource is a decided
  // single resource, so it must NOT mark incomplete (the HYBRID downgrades only a
  // would-be-narrow WILDCARD on an unmodeled service, never a fully-concrete id).
  ['s3:GetObject', 'arn:aws:x:::y'],
];
test('MUST-STAY-NARROW: a scoped, decided resource analyzes CLEAN (no over-correction)', () => {
  for (const [action, resource] of MUST_STAY_NARROW) {
    const r = analyze(policy(action, resource));
    assert.equal(r.ok, true, `${resource}: well-formed`);
    for (const id of ids(r)) {
      assert.ok(!BROAD_IDS.has(id), `${resource}: must NOT fire broad-scope ${id}`);
    }
    assert.equal(incomplete(r), false, `${resource}: a decided narrow resource must NOT mark incomplete`);
    assert.equal(isClean(r), true, `${resource}: a scoped, decided resource must analyze CLEAN`);
  }
});

// A malformed Resource on a DENY statement cannot mask an Allow finding (Allow-only).
test('a MALFORMED Resource on a Deny statement is not flagged (Allow-only)', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'A', Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::my-bucket/*' },
      { Sid: 'D', Effect: 'Deny', Action: 's3:GetObject', Resource: '*.pem' },
    ],
  });
  const m = modelFromText(text);
  assert.equal(m.ok, true);
  assert.ok(!detectMaskedGrants(m.model).some((g) => g.code === MASKED_GRANT_CODES.MALFORMED_RESOURCE_ARN),
    'a malformed Deny resource must not be flagged');
  assert.equal(isClean(analyze(text)), true, 'a scoped Allow fenced by a malformed Deny stays clean');
});

// --- 3d-iter6. The bare "*" on a resource-scopable READ is a fail-open too --------
// The broad-uncovered net EXCLUDED the bare "*" ("its scope is fully decided"), but
// that assumption is FALSE for a resource-scopable READ. dynamodb:GetItem (and
// iam:GetRole / kms:DescribeKey / s3:GetBucketPolicy / secretsmanager:DescribeSecret)
// on Resource "*" fires NO rule (WILDCARD-RESOURCE needs a non-read action; DATA-EXFIL
// needs the s3-bulk/secret catalog), so "*" returned a bare CLEAN / exit 0 - while the
// STRICTLY NARROWER "?*" was correctly flipped incomplete. "*" superset-of "?*", so the
// broadest possible wildcard fell open while the sneakier spelling was caught (risk
// ordering inverted). It must now flip incomplete + BROAD_RESOURCE_UNDECIDABLE exactly
// as "?*" does, symmetric across analyze() and scan().
const MUST_CLOSE_READ_ON_STAR = [
  'dynamodb:GetItem',
  'iam:GetRole',
  'kms:DescribeKey',
  's3:GetBucketPolicy',
  'secretsmanager:DescribeSecret',
];
test('MUST-CLOSE (read @ "*"): a resource-scopable read on the bare "*" is incomplete, not CLEAN, parity with "?*"', () => {
  for (const action of MUST_CLOSE_READ_ON_STAR) {
    const text = policy(action, '*');
    const r = analyze(text);
    assert.equal(r.ok, true, `${action}: well-formed analysis`);
    assert.equal(ids(r).length, 0, `${action}: no rule covers a resource-scopable read on "*"; got [${ids(r)}]`);
    assert.equal(isClean(r), false, `${action} @ "*": MUST NOT be a bare CLEAN (T8 fail-open)`);
    assert.equal(incomplete(r), true, `${action} @ "*": broad-but-uncovered read -> incomplete`);
    assert.ok(r.coverage.summary.codes.includes('BROAD_RESOURCE_UNDECIDABLE'),
      `${action}: carries BROAD_RESOURCE_UNDECIDABLE; got [${r.coverage.summary.codes.join(', ')}]`);
    assert.deepEqual(
      r.coverage.summary.broadUndecidableUncovered.map((u) => u.value), ['*'],
      `${action}: the bare "*" is recorded as the uncovered value`,
    );
    // Browser-CLI parity: scan() fails closed at exit 3, identical to the "?*" twin.
    const s = scan({ text, family: 'identity' });
    assert.notEqual(s.exitCode, EXIT.CLEAN, `${action}: scan must not exit 0`);
    assert.equal(s.exitCode, EXIT.FAIL_CLOSED, `${action}: a broad-but-uncovered read fails closed (exit 3); got ${s.exitCode}`);
    assert.ok(s.analysisStates.some((st) => st.code === 'BROAD_RESOURCE_UNDECIDABLE'),
      `${action}: the CLI names the broad-undecidable analyzer-state`);
  }
});

// "*" superset-of "?*": the broader wildcard is now at least as fail-closed as the
// narrower one. Locks the inverted-risk-ordering regression the iter-6 blocker named.
test('read @ "*" is no less fail-closed than the strictly narrower read @ "?*"', () => {
  for (const action of MUST_CLOSE_READ_ON_STAR) {
    assert.equal(incomplete(analyze(policy(action, '*'))), true, `${action} @ "*" must be incomplete`);
    assert.equal(incomplete(analyze(policy(action, '?*'))), true, `${action} @ "?*" must be incomplete`);
  }
});

// ANTI-OVER-CORRECTION for the read-@-"*" fix: an ENUMERATION / LIST read genuinely
// REQUIRES Resource "*" (no resource-level scoping), so its mandatory wildcard must
// stay CLEAN - flipping it would re-break the aws-required-wildcard-resource-not-
// penalized negative fixture. A wildcard action PATTERN (ec2:Describe*, iam:Get*) spans
// both Read and List members, so it is never treated as a decidably-scopable read and
// stays clean too. And the must-keep-firing "*" + a MUTATING action still fires (covered
// by WILDCARD-RESOURCE, never re-routed through the uncovered net).
// Iteration 7: the catalog "Read" level is NECESSARY but NOT SUFFICIENT for
// resource-scopability. A subset of READ-level actions have NO resource-level
// permission support and AWS REQUIRES Resource "*" (ec2:DescribeTags,
// cloudtrail:LookupEvents / DescribeTrails, sts:GetCallerIdentity /
// GetSessionToken / GetFederationToken). The iter-6 gate keyed on accessLevel===READ
// alone flipped THESE to incomplete too - a false positive that re-broke the
// read-only-wildcard-resource + aws-required-wildcard-resource-not-penalized negative
// fixtures (a minimal, correct least-privilege policy failed CLOSED at exit 3). They
// must stay CLEAN, discriminated by the catalog `requiresWildcardResource` bit, NOT the
// READ level. Included below alongside the List enumerations and wildcard patterns.
const REQUIRED_WILDCARD_READS_STAY_CLEAN = [
  'ec2:DescribeInstances',      // catalog List - requires "*"
  'ec2:DescribeSecurityGroups', // catalog List
  's3:ListAllMyBuckets',        // catalog List
  'iam:ListRoles',              // catalog List
  'ec2:Describe*',              // wildcard pattern (spans List + Read) - not a concrete scopable read
  'iam:Get*',                   // wildcard pattern
  'ec2:DescribeTags',           // catalog READ, but requires "*" (no resource-level support)
  'cloudtrail:LookupEvents',    // catalog READ, requires "*"
  'cloudtrail:DescribeTrails',  // catalog READ, requires "*"
  'sts:GetCallerIdentity',      // catalog READ, requires "*"
  'sts:GetSessionToken',        // catalog READ, requires "*"
  'sts:GetFederationToken',     // catalog READ, requires "*"
];
test('anti-over-correction (read @ "*"): required-wildcard enumeration reads stay CLEAN / exit 0', () => {
  for (const action of REQUIRED_WILDCARD_READS_STAY_CLEAN) {
    const text = policy(action, '*');
    const r = analyze(text);
    assert.equal(r.ok, true, `${action}: well-formed`);
    assert.equal(incomplete(r), false, `${action} @ "*": a required-wildcard read must NOT mark incomplete`);
    assert.equal(isClean(r), true, `${action} @ "*": a required-wildcard read must analyze CLEAN`);
    assert.ok(!(r.coverage.summary.codes || []).includes('BROAD_RESOURCE_UNDECIDABLE'),
      `${action}: no broad-undecidable signal on a required-wildcard read`);
    assert.equal(scan({ text, family: 'identity' }).exitCode, EXIT.CLEAN, `${action}: scan must exit 0`);
  }
});

test('anti-over-correction (read @ "*"): a MUTATING action on "*" still fires WILDCARD-RESOURCE (not this net)', () => {
  for (const action of ['s3:PutObject', 'dynamodb:PutItem', 'iam:CreateRole']) {
    const r = analyze(policy(action, '*'));
    assert.equal(isClean(r), false, `${action} @ "*": a broad write must never read CLEAN`);
    assert.ok(ids(r).length >= 1, `${action} @ "*": a rule must fire; got [${ids(r)}]`);
    assert.ok(!(r.coverage.summary.codes || []).includes('BROAD_RESOURCE_UNDECIDABLE'),
      `${action}: a covered write must NOT raise the broad-undecidable signal`);
  }
});

// A statement MIXING a required-wildcard List read with a resource-scopable Read on "*"
// flips incomplete: the scopable read is a real account-wide broad read regardless of
// the List sibling that also (legitimately) needs "*".
test('read @ "*": a scopable read mixed with a required-wildcard List read still flips incomplete', () => {
  const r = analyze(policy(['iam:ListRoles', 'iam:GetRole'], '*'));
  assert.equal(incomplete(r), true, 'the scopable iam:GetRole read on "*" flips incomplete');
  assert.ok(r.coverage.summary.codes.includes('BROAD_RESOURCE_UNDECIDABLE'));
});

// --- 3d-iter7. READ level is necessary-but-NOT-sufficient for scopable-on-"*" ------
// The iter-6 gate treated EVERY catalog-READ action on "*" as a decidably-scopable
// account-wide read and flipped it incomplete. But a subset of READ-level actions have
// NO resource-level permission support and AWS REQUIRES Resource "*" (ec2:DescribeTags,
// cloudtrail:LookupEvents / DescribeTrails, sts:GetCallerIdentity / GetSessionToken /
// GetFederationToken). Their "*" is service-mandated least privilege, not an avoidable
// over-scope, so flipping them incomplete was a FALSE POSITIVE that failed a correct
// policy CLOSED at exit 3 and re-broke the read-only-wildcard-resource negative fixture.
// The discriminator is the catalog `requiresWildcardResource` bit, NOT the READ level.
const REQUIRED_WILDCARD_LEVEL_READS = [
  'ec2:DescribeTags',
  'cloudtrail:LookupEvents',
  'cloudtrail:DescribeTrails',
  'sts:GetCallerIdentity',
  'sts:GetSessionToken',
  'sts:GetFederationToken',
];
test('iter7 FP: a REQUIRED-WILDCARD READ on "*" stays CLEAN (READ is not sufficient for scopable)', () => {
  for (const action of REQUIRED_WILDCARD_LEVEL_READS) {
    // Preconditions: it IS catalog READ level (so it slipped the iter-6 accessLevel gate)
    // yet is flagged required-wildcard - the discriminator that keeps it clean.
    const rec = defaultCatalog.lookup(action);
    assert.equal(rec.known, true, `${action}: known action`);
    assert.equal(rec.accessLevel, ACCESS_LEVELS.READ, `${action}: catalog READ level`);
    assert.equal(rec.requiresWildcardResource, true, `${action}: requires Resource "*"`);

    const text = policy(action, '*');
    const r = analyze(text);
    assert.equal(r.ok, true, `${action}: well-formed`);
    assert.equal(incomplete(r), false, `${action} @ "*": required-wildcard READ must NOT mark incomplete`);
    assert.equal(isClean(r), true, `${action} @ "*": required-wildcard READ must analyze CLEAN`);
    assert.ok(!(r.coverage.summary.codes || []).includes('BROAD_RESOURCE_UNDECIDABLE'),
      `${action}: no broad-undecidable signal on a required-wildcard READ`);
    // Browser-CLI parity: scan() exits 0, NOT the exit-3 fail-closed the iter-6 gate produced.
    assert.equal(scan({ text, family: 'identity' }).exitCode, EXIT.CLEAN,
      `${action}: a required-wildcard READ must exit 0 (was wrongly exit 3)`);
  }
});

// The genuinely-scopable twin at the SAME "*" MUST still flip incomplete: the fix
// narrows the gate, it does not disable it. Locks that the discriminator - not a blanket
// exemption - drove the closure (guards a re-introduced fail-open).
test('iter7: a genuinely-scopable READ on "*" still flips incomplete (fix does not disable the net)', () => {
  for (const action of ['dynamodb:GetItem', 'iam:GetRole', 'kms:DescribeKey',
    's3:GetBucketPolicy', 'secretsmanager:DescribeSecret']) {
    assert.equal(defaultCatalog.lookup(action).requiresWildcardResource, false,
      `${action}: is genuinely resource-scopable`);
    const r = analyze(policy(action, '*'));
    assert.equal(incomplete(r), true, `${action} @ "*": scopable read still flips incomplete`);
    assert.ok(r.coverage.summary.codes.includes('BROAD_RESOURCE_UNDECIDABLE'),
      `${action}: carries BROAD_RESOURCE_UNDECIDABLE`);
  }
});

// The two named negative fixtures, run end-to-end through analyze() AND scan(), asserting
// NOT-INCOMPLETE / exit 0 - the assertion the fixtures' own findingIds-only checks miss,
// which is precisely how the iter-6 over-correction slipped the deterministic gate.
test('iter7: the required-wildcard-read negative fixtures analyze CLEAN end-to-end (not just finding-free)', () => {
  const fixtures = [
    '../fixtures/wildcard/read-only-wildcard-resource-negative.json',
    '../fixtures/negative/aws-required-wildcard-resource-not-penalized.json',
  ];
  for (const rel of fixtures) {
    const url = new URL(rel, import.meta.url);
    const fx = JSON.parse(readFileSync(url, 'utf8'));
    const text = JSON.stringify(fx.policy);
    const r = analyze(text);
    assert.equal(r.ok, true, `${rel}: valid`);
    assert.equal(r.findings.length, 0, `${rel}: no findings (fixture intent)`);
    assert.equal(incomplete(r), false, `${rel}: a required-wildcard-read policy must NOT be marked incomplete`);
    assert.equal(isClean(r), true, `${rel}: must analyze CLEAN, not fail closed`);
    assert.equal(scan({ text, family: 'identity' }).exitCode, EXIT.CLEAN, `${rel}: scan must exit 0`);
  }
});

// --- 3e-iter6. API Gateway leading-slash ARNs are legit, not MALFORMED ------------
// resource-arn.js's empty-leading-segment guard blanket-rejected any resource-id
// starting with "/". But API Gateway management ARNs legitimately begin with "/":
// arn:aws:apigateway:<region>::/restapis/<id>/stages/<name> (empty account, leading
// "/restapis/..."). A fully-concrete, properly-scoped apigateway resource was
// classified MALFORMED and marked incomplete on both surfaces - a real false positive
// on a common, deployable ARN format. The leading "/" is part of the grammar: strip it
// and classify under the typed grammar, so a concrete API is NARROW while a
// whole-collection wildcard (/restapis/*, /*) is still BROAD (fail-closed preserved).
const APIGW_CONCRETE_NARROW = [
  'arn:aws:apigateway:us-east-1::/restapis/a1b2c3/stages/prod',
  'arn:aws:apigateway:us-east-1::/restapis/a1b2c3/stages/*', // wildcard only in sub-path of one concrete API
  'arn:aws:apigateway:eu-west-1::/restapis/xyz789',
];
const APIGW_COLLECTION_BROAD = [
  'arn:aws:apigateway:us-east-1::/restapis/*', // every rest API
  'arn:aws:apigateway:us-east-1::/*',          // everything
];
test('apigateway FP: a concrete leading-slash apigateway ARN is NARROW, not MALFORMED', () => {
  for (const resource of APIGW_CONCRETE_NARROW) {
    assert.equal(classifyResource(resource), NARROW,
      `${resource}: a concrete apigateway resource must be NARROW, not MALFORMED`);
    assert.equal(isBroadArnResource(resource), false, `${resource}: rules breadth predicate must stay quiet`);
    // The classifier is the single MALFORMED oracle both surfaces read: masked-grant
    // must NOT route a decided narrow apigateway ARN to incomplete. (The analyze()-level
    // "clean" behavior is confounded here only by apigateway actions being outside the
    // curated action catalog - an unrelated unrecognized-action coverage note - so the
    // resource classification is asserted at the classifier + masked-grant layer.)
    const m = modelFromText(policy('s3:GetObject', resource));
    assert.equal(m.ok, true, `${resource}: parses`);
    assert.ok(!detectMaskedGrants(m.model).some((g) => g.code === MASKED_GRANT_CODES.MALFORMED_RESOURCE_ARN),
      `${resource}: a decided apigateway ARN must NOT be flagged MALFORMED_RESOURCE_ARN`);
  }
});
test('apigateway: a whole-collection wildcard leading-slash ARN stays BROAD (fail-closed preserved)', () => {
  for (const resource of APIGW_COLLECTION_BROAD) {
    assert.equal(classifyResource(resource), BROAD,
      `${resource}: a whole-collection apigateway wildcard must be BROAD`);
    assert.equal(isBroadArnResource(resource), true, `${resource}: rules breadth predicate must fire`);
  }
  // The leading-slash exemption is apigateway-only: other services keep the guard.
  assert.equal(classifyResource('arn:aws:s3:::/*'), MALFORMED, 's3 leading-slash stays MALFORMED');
  assert.equal(classifyResource('arn:aws:iam::123456789012:/role/*'), MALFORMED, 'iam leading-slash stays MALFORMED');
});

// --- 5. Determinism (architecture invariant #8) ------------------------------
test('classifier and analyze() are deterministic', () => {
  for (const v of [...BROAD_CASES, ...NARROW_CASES, ...MALFORMED_CASES]) {
    assert.equal(classifyResource(v), classifyResource(v), `${JSON.stringify(v)}: classifier deterministic`);
    const t = policy('s3:GetObject', v);
    assert.deepEqual(analyze(t), analyze(t), `${JSON.stringify(v)}: analyze() deterministic`);
  }
});
