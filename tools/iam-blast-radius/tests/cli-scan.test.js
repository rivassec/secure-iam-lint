// Tests for the headless scan adapter (Phase 15, story P15-scan).
//
// The scan module is a Node-only ADAPTER over the shipped browser engine. These
// tests pin the fail-closed contract: unknown / unsupported / malformed /
// could-not-analyze inputs MUST yield analysisStatus 'partial' or 'failed' and
// exit code 3 (or 2 for a usage error) - NEVER 'complete' + exit 0. They also pin
// the analysisStatus/exitCode derivation, threshold gating, and determinism.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT, ANALYSIS_STATUS, ANALYSIS_STATE } from '../../../cli/scan.mjs';

// --- Fixtures (inline so the suite is self-contained + deterministic). --------

// A benign identity policy: one recognized read action on a specific resource ->
// no findings, complete coverage.
const CLEAN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow',
    Action: 'ec2:DescribeInstances',
    Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc',
  }],
});

// Full IAM admin -> a real (high) finding, complete coverage.
const ADMIN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
});

// A PassRole path whose passable role pins a CONCRETE account, with NO subject
// account supplied -> the engine caps exploitability and records
// escalation.requiredUnknowns:['subjectAccount'] (unknown viability).
const PASSROLE_UNKNOWN_VIABILITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::999988887777:role/app' },
    { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
  ],
});

// A resource-based policy shape (every statement names a Principal).
const RESOURCE_SHAPE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow',
    Principal: { AWS: '*' },
    Action: 's3:GetObject',
    Resource: 'arn:aws:s3:::bucket/*',
  }],
});

// A concrete action the curated catalog snapshot does not recognize -> incomplete
// coverage (no findings, but "unsupported does not mean safe").
const UNKNOWN_ACTION = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'faketool:DoThing', Resource: 'arn:aws:x:::y' }],
});

// A PassRole -> EC2 escalation whose passable role is pinned to a CONCRETE account
// in a NON-'aws' partition. Account ids do not encode partition, so whether the
// subject principal is in the same partition (viable) or a different one (not
// viable) is UNKNOWN unless the caller supplies the partition. Without it the
// engine defaults to 'aws', renders a confident PARTITION_MISMATCH "not viable",
// and demotes the critical path to a non-blocking medium -> the exact fail-open.
const PASSROLE_GOVCLOUD_ROLE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws-us-gov:iam::111122223333:role/app' },
    { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
  ],
});
const PASSROLE_CN_ROLE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws-cn:iam::111122223333:role/app' },
    { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
  ],
});

// A full-admin grant expressed as an empty-array NotAction complement. Under AWS
// semantics an empty NotAction excludes NOTHING, so this Allow grants EVERY action
// on every resource. The shipped engine models it as granting nothing (the
// MISSING_ACTION gate keys off `NotAction !== undefined`, true for `[]`, and
// ruleNotActionAllow early-returns on an empty list) -> it would otherwise report
// 'complete' + 0 findings. The adapter MUST fail closed on this masked admin grant.
const EMPTY_NOTACTION_ADMIN = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', NotAction: [], Resource: '*' }],
});
// Same masked grant with NO Resource and in the single-object Statement form.
const EMPTY_NOTACTION_NO_RESOURCE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', NotAction: [] }],
});
const EMPTY_NOTACTION_SINGLE_OBJECT = JSON.stringify({
  Version: '2012-10-17',
  Statement: { Effect: 'Allow', NotAction: [], Resource: '*' },
});
// A benign second statement plus the masked-admin statement second: the fail-open
// must be caught even when it is not the first statement.
const EMPTY_NOTACTION_MIXED = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc' },
    { Effect: 'Allow', NotAction: [], Resource: '*' },
  ],
});
// Benign siblings that share the empty-array shape but grant nothing under AWS
// semantics: an empty POSITIVE Action set, an empty Statement block, and a Deny
// with an empty NotAction complement (deny everything). None of these is a
// fail-open, so the guard must NOT touch them.
const EMPTY_ACTION_BENIGN = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: [], Resource: '*' }],
});
const EMPTY_STATEMENT_BENIGN = JSON.stringify({ Version: '2012-10-17', Statement: [] });
const DENY_EMPTY_NOTACTION_BENIGN = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Deny', NotAction: [], Resource: '*' }],
});

// The RESOURCE-axis symmetric twin of the empty-NotAction complement (iter 3
// BLOCKER). An Allow with an empty-array NotResource ([]) applies to EVERY resource
// (an empty complement excludes nothing) - byte-for-byte the same broad scope as
// Resource:"*" - but the engine models it as "no resource scope" and never fires
// WILDCARD-RESOURCE (rules.js resourceIsBroad reads notResources.length === 0 as no
// scope). It would otherwise report 'complete' + 0 findings + exit 0 CLEAN while the
// identical Resource:"*" policy blocks at exit 1. The adapter MUST fail closed.
const EMPTY_NOTRESOURCE_PASSROLE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:PassRole', NotResource: [] }],
});
const EMPTY_NOTRESOURCE_S3GET = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 's3:GetObject', NotResource: [] }],
});
const EMPTY_NOTRESOURCE_SINGLE_OBJECT = JSON.stringify({
  Version: '2012-10-17',
  Statement: { Effect: 'Allow', Action: 'iam:PassRole', NotResource: [] },
});
// The byte-equivalent broad-resource control expressed as Resource:"*": it flags
// WILDCARD-RESOURCE and blocks at exit 1. The NotResource:[] twin must also fail the
// gate (exit 3), never collapse to a clean exit 0.
const RESOURCE_STAR_PASSROLE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' }],
});
// A benign second statement plus the masked broad-resource statement second: caught
// even when not the first statement.
const EMPTY_NOTRESOURCE_MIXED = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc' },
    { Effect: 'Allow', Action: 'iam:PassRole', NotResource: [] },
  ],
});
// Benign siblings that share the empty-array shape but do NOT mask a broad-resource
// grant the engine suppresses: a NON-empty NotResource (already flagged as broad by
// the engine) and a Deny + empty NotResource (deny across all resources). Neither is
// a fail-open, so the guard must NOT touch them.
const NONEMPTY_NOTRESOURCE_BENIGN = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Allow', Action: 's3:PutObject', NotResource: 'arn:aws:s3:::keep/*' }],
});
const DENY_EMPTY_NOTRESOURCE_BENIGN = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Effect: 'Deny', Action: 's3:*', NotResource: [] }],
});

// --- analysisStatus 'complete' -> exit 0 / 1 ---------------------------------

test('clean identity policy -> complete, exit 0, no analyzer-states', () => {
  const r = scan({ text: CLEAN_IDENTITY, family: 'identity' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.equal(r.exitCode, 0);
  assert.equal(r.blockingCount, 0);
  assert.deepEqual([...r.analysisStates], []);
});

test('policy with a finding at/above threshold -> complete, exit 1', () => {
  const r = scan({ text: ADMIN_IDENTITY, family: 'identity' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.equal(r.exitCode, 1);
  assert.ok(r.blockingCount >= 1);
  assert.ok(r.findingsCount >= 1);
});

test('threshold gates the 0-vs-1 decision for a complete analysis', () => {
  // The admin finding is `high`; raising the threshold above it yields exit 0.
  const belowHigh = scan({ text: ADMIN_IDENTITY, family: 'identity', threshold: 'critical' });
  assert.equal(belowHigh.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(belowHigh.exitCode, EXIT.CLEAN);
  const atHigh = scan({ text: ADMIN_IDENTITY, family: 'identity', threshold: 'high' });
  assert.equal(atHigh.exitCode, EXIT.FINDINGS);
});

// --- analysisStatus 'failed' -> exit 3 (fail-closed) -------------------------

test('malformed JSON -> failed, exit 3, malformed analyzer-state', () => {
  const r = scan({ text: '{ not valid json', family: 'identity' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(r.exitCode, 3);
  assert.ok(r.analysisStates.length >= 1);
  assert.equal(r.analysisStates[0].analysisState, ANALYSIS_STATE.MALFORMED);
});

test('unsupported family (resource without context) -> failed, exit 3', () => {
  const r = scan({ text: RESOURCE_SHAPE, family: 'resource' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.ok(r.analysisStates.some((s) => s.analysisState === ANALYSIS_STATE.UNSUPPORTED));
});

test('resource selected on an identity shape -> failed, exit 3', () => {
  const r = scan({ text: CLEAN_IDENTITY, family: 'resource' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('an unrecognized family token is a usage error (exit 2), never analyzed', () => {
  const r = scan({ text: ADMIN_IDENTITY, family: 'banana' });
  // A family that does not exist is a caller mistake (usage error, exit 2),
  // distinct from a valid family whose document cannot be analyzed (exit 3).
  assert.equal(r.exitCode, EXIT.USAGE);
  assert.equal(r.reason, 'UNKNOWN_FAMILY');
  // It must NOT have been analyzed as an identity admin grant.
  assert.equal(r.blockingCount, 0);
});

// --- analysisStatus 'partial' -> exit 3 (fail-closed) ------------------------

test('unknown-viability finding -> partial, exit 3, unknown analyzer-state (THE fail-open guard)', () => {
  const r = scan({ text: PASSROLE_UNKNOWN_VIABILITY, family: 'identity' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(r.exitCode, 3);
  assert.ok(r.analysisStates.some((s) => s.analysisState === ANALYSIS_STATE.UNKNOWN));
  // Crucially: it must NEVER be reported as complete + clean.
  assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
});

test('supplying the subject account resolves viability -> complete', () => {
  const r = scan({ text: PASSROLE_UNKNOWN_VIABILITY, family: 'identity', subjectAccount: '999988887777' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  // A real path was confirmed same-account, so it gates as a finding.
  assert.equal(r.exitCode, EXIT.FINDINGS);
});

// --- unconfirmed-partition fail-open (P15-scan iteration 2 BLOCKER) -----------
// A concrete cross-partition PassRole role, subject account supplied but partition
// NOT supplied, must fail closed exactly like the unconfirmed-ACCOUNT path. The
// engine defaults partition to 'aws' and demotes the finding to a non-blocking
// 'medium'; the adapter must recognize that the "not viable" verdict rests on an
// UNCONFIRMED partition and refuse to collapse it to a clean pass.

test('cross-partition PassRole, subject account but NO partition -> partial, exit 3 (fail-open guard)', () => {
  const r = scan({ text: PASSROLE_GOVCLOUD_ROLE, family: 'identity', subjectAccount: '111122223333' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(r.exitCode, 3);
  assert.equal(r.reason, 'UNKNOWN_VIABILITY');
  // It must NEVER be reported as complete + clean (the demoted medium under 'high').
  assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  const st = r.analysisStates.find((s) => s.code === 'UNKNOWN_VIABILITY');
  assert.ok(st, 'an UNKNOWN_VIABILITY analyzer-state is present');
  assert.ok(
    st.details.requiredUnknowns.includes('subjectPartition'),
    'the unconfirmed partition is recorded as a required-unknown',
  );
});

test('aws-cn variant of the unconfirmed-partition path also fails closed -> exit 3', () => {
  const r = scan({ text: PASSROLE_CN_ROLE, family: 'identity', subjectAccount: '111122223333' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('supplying the TRUE partition resolves the cross-partition path as viable -> exit 1', () => {
  const r = scan({
    text: PASSROLE_GOVCLOUD_ROLE, family: 'identity',
    subjectAccount: '111122223333', partition: 'aws-us-gov',
  });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.exitCode, EXIT.FINDINGS);
  assert.equal(r.exitCode, 1);
  assert.ok(r.blockingCount >= 1);
});

test('EXPLICITLY asserting a different partition is a confirmed mismatch -> complete, exit 0', () => {
  // The caller asserts the subject is in commercial 'aws' while the role is in
  // aws-us-gov: viability is now KNOWN (not viable), a legitimate complete verdict,
  // not a fail-open. Supplying the partition is what resolves the unknown.
  const r = scan({
    text: PASSROLE_GOVCLOUD_ROLE, family: 'identity',
    subjectAccount: '111122223333', partition: 'aws',
  });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.deepEqual([...r.analysisStates], []);
});

test('threshold none does NOT turn the unconfirmed-partition partial into exit 0', () => {
  const r = scan({
    text: PASSROLE_GOVCLOUD_ROLE, family: 'identity',
    subjectAccount: '111122223333', threshold: 'none',
  });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('unrecognized action -> partial, exit 3, incomplete analyzer-state', () => {
  const r = scan({ text: UNKNOWN_ACTION, family: 'identity' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.ok(r.analysisStates.some((s) => s.code === 'UNKNOWN_ACTION'));
});

// --- usage/config errors -> exit 2 -------------------------------------------

test('missing input text -> usage error, exit 2', () => {
  assert.equal(scan({ family: 'identity' }).exitCode, EXIT.USAGE);
  assert.equal(scan({ text: '', family: 'identity' }).exitCode, EXIT.USAGE);
  assert.equal(scan({ text: '   ', family: 'identity' }).exitCode, EXIT.USAGE);
});

test('missing family -> usage error, exit 2 (never auto-detected)', () => {
  const r = scan({ text: CLEAN_IDENTITY });
  assert.equal(r.exitCode, EXIT.USAGE);
  assert.equal(r.reason, 'MISSING_FAMILY');
  assert.equal(scan({ text: CLEAN_IDENTITY, family: '' }).exitCode, EXIT.USAGE);
});

test('auto family selection is refused as a usage error, exit 2 (no auto-detection)', () => {
  assert.equal(scan({ text: CLEAN_IDENTITY, family: 'auto' }).reason, 'AUTO_FAMILY_REFUSED');
  assert.equal(scan({ text: CLEAN_IDENTITY, family: 'auto' }).exitCode, EXIT.USAGE);
  assert.equal(scan({ text: CLEAN_IDENTITY, family: 'auto-detect' }).exitCode, EXIT.USAGE);
});

test('unknown threshold token -> usage error, exit 2', () => {
  assert.equal(scan({ text: CLEAN_IDENTITY, family: 'identity', threshold: 'nope' }).exitCode, EXIT.USAGE);
});

// --- adversarial: --threshold none must NEVER downgrade a fail-closed 3 ------

test('threshold none does not turn a malformed fail-closed into exit 0', () => {
  const r = scan({ text: '{ not json', family: 'identity', threshold: 'none' });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.notEqual(r.exitCode, EXIT.CLEAN);
});

test('threshold none does not turn an unknown-viability partial into exit 0', () => {
  const r = scan({ text: PASSROLE_UNKNOWN_VIABILITY, family: 'identity', threshold: 'none' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('threshold none does not turn an incomplete-coverage partial into exit 0', () => {
  const r = scan({ text: UNKNOWN_ACTION, family: 'identity', threshold: 'none' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
});

test('threshold none DOES yield exit 0 for a genuinely complete analysis with findings', () => {
  const r = scan({ text: ADMIN_IDENTITY, family: 'identity', threshold: 'none' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.exitCode, EXIT.CLEAN);
});

// --- structural + determinism guarantees -------------------------------------

test('every fail-closed result carries at least one analyzer-state', () => {
  for (const input of [
    { text: '{ bad', family: 'identity' },
    { text: RESOURCE_SHAPE, family: 'resource' },
    { text: PASSROLE_UNKNOWN_VIABILITY, family: 'identity' },
    { text: UNKNOWN_ACTION, family: 'identity' },
  ]) {
    const r = scan(input);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `expected exit 3 for ${JSON.stringify(input.family)}`);
    assert.ok(r.analysisStates.length >= 1);
  }
});

test('analysisStatus is never complete when the exit code is 3', () => {
  for (const input of [
    { text: '{ bad', family: 'identity' },
    { text: RESOURCE_SHAPE, family: 'resource' },
    { text: PASSROLE_UNKNOWN_VIABILITY, family: 'identity' },
    { text: UNKNOWN_ACTION, family: 'identity' },
    { text: CLEAN_IDENTITY, family: 'scp-rcp' },
  ]) {
    const r = scan(input);
    if (r.exitCode === EXIT.FAIL_CLOSED) {
      assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
    }
  }
});

test('scan is deterministic (same input -> byte-identical structured result)', () => {
  const once = JSON.stringify(scan({ text: PASSROLE_UNKNOWN_VIABILITY, family: 'identity' }));
  const twice = JSON.stringify(scan({ text: PASSROLE_UNKNOWN_VIABILITY, family: 'identity' }));
  assert.equal(once, twice);
});

test('scan never throws on hostile / weird inputs', () => {
  for (const bad of [undefined, null, {}, { text: 42, family: 'identity' }, { text: '{}', family: 7 }]) {
    assert.doesNotThrow(() => scan(bad));
  }
});

test('the result shape matches the P15-scan contract', () => {
  const r = scan({ text: ADMIN_IDENTITY, family: 'identity' });
  for (const key of ['analysisStatus', 'analysisStates', 'findings', 'blockingCount', 'exitCode']) {
    assert.ok(Object.prototype.hasOwnProperty.call(r, key), `missing key ${key}`);
  }
  assert.ok(['complete', 'partial', 'failed'].includes(r.analysisStatus));
  assert.ok(Array.isArray([...r.analysisStates]));
  assert.ok(Array.isArray([...r.findings]));
  assert.equal(typeof r.blockingCount, 'number');
  assert.ok([0, 1, 2, 3, 4].includes(r.exitCode));
});

// --- empty NotAction complement (masked full-admin) MUST fail closed ---------

test('empty-array NotAction complement (masked admin) -> failed, exit 3, never clean', () => {
  for (const text of [EMPTY_NOTACTION_ADMIN, EMPTY_NOTACTION_NO_RESOURCE, EMPTY_NOTACTION_SINGLE_OBJECT]) {
    const r = scan({ text, family: 'identity' });
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED, 'must not be complete');
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
    assert.equal(r.exitCode, 3);
    assert.equal(r.reason, 'EMPTY_NOTACTION_COMPLEMENT');
    assert.ok(r.analysisStates.length >= 1);
    assert.equal(r.analysisStates[0].analysisState, ANALYSIS_STATE.MALFORMED);
    assert.equal(r.analysisStates[0].code, 'EMPTY_NOTACTION_COMPLEMENT');
  }
});

test('empty NotAction complement fails closed regardless of threshold (none/critical cannot downgrade)', () => {
  for (const threshold of ['none', 'critical', 'high', 'info']) {
    const r = scan({ text: EMPTY_NOTACTION_ADMIN, family: 'identity', threshold });
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `threshold ${threshold}`);
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  }
});

test('empty NotAction complement is caught even when not the first statement', () => {
  const r = scan({ text: EMPTY_NOTACTION_MIXED, family: 'identity' });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.analysisStates[0].path, 'Statement[1].NotAction');
});

test('benign empty-array siblings are NOT flagged as fail-closed (no over-fire)', () => {
  // Empty POSITIVE Action set, empty Statement block, and Deny + empty NotAction
  // all grant nothing under AWS semantics -> they must remain a clean complete pass.
  for (const text of [EMPTY_ACTION_BENIGN, EMPTY_STATEMENT_BENIGN, DENY_EMPTY_NOTACTION_BENIGN]) {
    const r = scan({ text, family: 'identity' });
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, `should stay complete: ${text}`);
    assert.equal(r.exitCode, EXIT.CLEAN);
    assert.notEqual(r.reason, 'EMPTY_NOTACTION_COMPLEMENT');
  }
});

test('empty NotAction complement scan is deterministic', () => {
  const a = JSON.stringify(scan({ text: EMPTY_NOTACTION_ADMIN, family: 'identity' }));
  const b = JSON.stringify(scan({ text: EMPTY_NOTACTION_ADMIN, family: 'identity' }));
  assert.equal(a, b);
});

// --- BOM must NOT bypass the empty-NotAction-complement guard (iter 4 BLOCKER) --
// A UTF-8 BOM (U+FEFF) is the DEFAULT prefix emitted by many Windows editors and
// PowerShell Set-Content/Out-File. The engine strips exactly one leading BOM before
// parsing (validate.js), so a BOM-prefixed masked-admin policy analyzes to ok:true
// + 0 findings + complete. The adapter's own text guard must strip the BOM the SAME
// way before re-parsing; otherwise its raw JSON.parse throws, the catch defaults the
// guard OPEN, and the masked full-admin grant passes CLEAN (exit 0) - a fail-open.
const BOM = '﻿';

test('BOM-prefixed empty-NotAction admin STILL fails closed (exit 3), not clean', () => {
  for (const text of [EMPTY_NOTACTION_ADMIN, EMPTY_NOTACTION_NO_RESOURCE, EMPTY_NOTACTION_SINGLE_OBJECT, EMPTY_NOTACTION_MIXED]) {
    const r = scan({ text: BOM + text, family: 'identity' });
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED, `BOM must not open the guard: ${text}`);
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
    assert.equal(r.exitCode, 3);
    assert.equal(r.reason, 'EMPTY_NOTACTION_COMPLEMENT');
    assert.equal(r.analysisStates[0].code, 'EMPTY_NOTACTION_COMPLEMENT');
  }
});

test('BOM-prefixed masked admin matches the same result as without the BOM', () => {
  const withBom = scan({ text: BOM + EMPTY_NOTACTION_ADMIN, family: 'identity' });
  const without = scan({ text: EMPTY_NOTACTION_ADMIN, family: 'identity' });
  assert.equal(withBom.exitCode, without.exitCode);
  assert.equal(withBom.reason, without.reason);
  assert.equal(withBom.analysisStatus, without.analysisStatus);
});

test('BOM-prefixed benign policy still analyzes clean (BOM strip does not over-fire)', () => {
  const r = scan({ text: BOM + CLEAN_IDENTITY, family: 'identity' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.exitCode, EXIT.CLEAN);
  assert.deepEqual([...r.analysisStates], []);
});

test('BOM does not open the guard at any threshold', () => {
  for (const threshold of ['none', 'critical', 'high', 'info']) {
    const r = scan({ text: BOM + EMPTY_NOTACTION_ADMIN, family: 'identity', threshold });
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `threshold ${threshold}`);
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  }
});

// --- empty NotRESOURCE complement (masked broad-resource grant) MUST fail closed -
// The RESOURCE-axis twin of the empty-NotAction guard (iter 3 BLOCKER). A broad-
// resource single-action grant written as NotResource:[] must NEVER collapse to
// 'complete' + exit 0 CLEAN while the byte-equivalent Resource:"*" blocks at exit 1.

test('empty-array NotResource complement -> failed, exit 3, never clean', () => {
  for (const text of [EMPTY_NOTRESOURCE_PASSROLE, EMPTY_NOTRESOURCE_S3GET, EMPTY_NOTRESOURCE_SINGLE_OBJECT]) {
    const r = scan({ text, family: 'identity' });
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED, 'must not be complete');
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
    assert.equal(r.exitCode, 3);
    assert.notEqual(r.exitCode, EXIT.CLEAN);
    assert.equal(r.reason, 'EMPTY_NOTRESOURCE_COMPLEMENT');
    assert.ok(r.analysisStates.length >= 1);
    assert.equal(r.analysisStates[0].analysisState, ANALYSIS_STATE.MALFORMED);
    assert.equal(r.analysisStates[0].code, 'EMPTY_NOTRESOURCE_COMPLEMENT');
  }
});

test('NotResource:[] and its Resource:"*" twin both FAIL the gate (never one clean)', () => {
  // The core bug: byte-equivalent broad-resource grants must produce equivalent gate
  // verdicts. Resource:"*" blocks (exit 1); NotResource:[] must also fail (exit 3).
  const control = scan({ text: RESOURCE_STAR_PASSROLE, family: 'identity', threshold: 'high' });
  const twin = scan({ text: EMPTY_NOTRESOURCE_PASSROLE, family: 'identity', threshold: 'high' });
  assert.equal(control.exitCode, EXIT.FINDINGS, 'Resource:"*" control blocks at exit 1');
  assert.notEqual(twin.exitCode, EXIT.CLEAN, 'NotResource:[] twin must NEVER be clean exit 0');
  assert.notEqual(twin.analysisStatus, ANALYSIS_STATUS.COMPLETE, 'twin must not report complete/CLEAN');
  // A CI gate treats both 1 and 3 as FAILED - the twins are equivalent at the gate.
  for (const code of [control.exitCode, twin.exitCode]) {
    assert.ok([EXIT.FINDINGS, EXIT.FAIL_CLOSED].includes(code));
  }
});

test('empty NotResource complement fails closed regardless of threshold (none cannot downgrade)', () => {
  for (const threshold of ['none', 'critical', 'high', 'info']) {
    const r = scan({ text: EMPTY_NOTRESOURCE_PASSROLE, family: 'identity', threshold });
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `threshold ${threshold}`);
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  }
});

test('empty NotResource complement is caught even when not the first statement', () => {
  const r = scan({ text: EMPTY_NOTRESOURCE_MIXED, family: 'identity' });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
  assert.equal(r.analysisStates[0].path, 'Statement[1].NotResource');
});

test('empty NotResource guard does NOT over-fire on benign siblings', () => {
  // A NON-empty NotResource is already modeled as broad by the engine (its own
  // WILDCARD-RESOURCE finding governs the verdict); a Deny + empty NotResource denies
  // across all resources. Neither is the suppressed-grant fail-open, so neither may be
  // re-flagged as EMPTY_NOTRESOURCE_COMPLEMENT.
  for (const text of [NONEMPTY_NOTRESOURCE_BENIGN, DENY_EMPTY_NOTRESOURCE_BENIGN]) {
    const r = scan({ text, family: 'identity' });
    assert.notEqual(r.reason, 'EMPTY_NOTRESOURCE_COMPLEMENT', `must not fire on: ${text}`);
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.FAILED, `must not fail-close: ${text}`);
  }
});

test('empty NotResource complement scan is deterministic', () => {
  const a = JSON.stringify(scan({ text: EMPTY_NOTRESOURCE_PASSROLE, family: 'identity' }));
  const b = JSON.stringify(scan({ text: EMPTY_NOTRESOURCE_PASSROLE, family: 'identity' }));
  assert.equal(a, b);
});

test('BOM-prefixed empty-NotResource complement STILL fails closed (exit 3), not clean', () => {
  for (const text of [EMPTY_NOTRESOURCE_PASSROLE, EMPTY_NOTRESOURCE_S3GET, EMPTY_NOTRESOURCE_SINGLE_OBJECT, EMPTY_NOTRESOURCE_MIXED]) {
    const r = scan({ text: BOM + text, family: 'identity' });
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED, `BOM must not open the guard: ${text}`);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
    assert.equal(r.reason, 'EMPTY_NOTRESOURCE_COMPLEMENT');
    assert.equal(r.analysisStates[0].code, 'EMPTY_NOTRESOURCE_COMPLEMENT');
  }
});

// --- an UNRECOGNIZED partition must not downgrade a fail-closed (iter 4 BLOCKER) -
// A bogus partition string ("zzz", "banana", "AWS", "a", ".") is non-empty but is
// NOT a real AWS partition. It must be treated as NOT provided so the
// cross-partition PassRole demotion stays UNKNOWN and fails closed (exit 3), never
// trusted as a confident assertion that slips the demoted medium under 'high'.
const BOGUS_PARTITIONS = ['zzz', 'banana', 'AWS', 'a', '.', 'aws-fake', 'AWS-CN', ' '];

test('bogus partition does NOT downgrade the cross-partition fail-closed (exit 3, not 0)', () => {
  for (const partition of BOGUS_PARTITIONS) {
    const r = scan({ text: PASSROLE_GOVCLOUD_ROLE, family: 'identity', subjectAccount: '111122223333', partition });
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL, `partition ${JSON.stringify(partition)} must stay partial`);
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `partition ${JSON.stringify(partition)} must fail closed`);
    assert.equal(r.exitCode, 3);
    assert.equal(r.reason, 'UNKNOWN_VIABILITY');
    const st = r.analysisStates.find((s) => s.code === 'UNKNOWN_VIABILITY');
    assert.ok(st && st.details.requiredUnknowns.includes('subjectPartition'));
  }
});

test('aws-cn role + subject match + partition "zzz" yields exit 3 (finding verify)', () => {
  const r = scan({ text: PASSROLE_CN_ROLE, family: 'identity', subjectAccount: '111122223333', partition: 'zzz' });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(r.exitCode, 3);
  assert.notEqual(r.exitCode, EXIT.CLEAN);
});

test('a RECOGNIZED partition is still honored (aws-us-gov -> viable finding, exit 1)', () => {
  const r = scan({ text: PASSROLE_GOVCLOUD_ROLE, family: 'identity', subjectAccount: '111122223333', partition: 'aws-us-gov' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.exitCode, EXIT.FINDINGS);
});

test('a RECOGNIZED mismatching partition is a confident complete verdict (aws -> exit 0)', () => {
  const r = scan({ text: PASSROLE_GOVCLOUD_ROLE, family: 'identity', subjectAccount: '111122223333', partition: 'aws' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.exitCode, EXIT.CLEAN);
});

test('exit-code constants are stable', () => {
  assert.deepEqual(
    { ...EXIT },
    { CLEAN: 0, FINDINGS: 1, USAGE: 2, FAIL_CLOSED: 3, INTERNAL: 4 },
  );
});

// --- adversarial-failopen critic re-run: newly-probed vectors (iter 5) --------
// The empty-array NotAction guard is exact (na.length === 0). A NotAction whose
// only entries are VACUOUS action tokens - an empty string or whitespace - is
// semantically the same masked full-admin grant (it excludes no REAL action, so
// the Allow grants everything), yet it is a non-empty array the exact guard does
// not intercept. It must still fail closed: the unrecognized-action coverage
// signal catches it (exit 3), never a clean complete pass. Pin it so a future
// change to that coverage path cannot silently open this into a fail-open.
const VACUOUS_NOTACTION = [
  JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', NotAction: [''], Resource: '*' }] }),
  JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', NotAction: [' '], Resource: '*' }] }),
  JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', NotAction: '', Resource: '*' }] }),
];

test('vacuous NotAction complement (empty/whitespace action tokens) fails closed, never clean', () => {
  for (const text of VACUOUS_NOTACTION) {
    const r = scan({ text, family: 'identity' });
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, `must not be complete: ${text}`);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `must fail closed: ${text}`);
    assert.equal(r.exitCode, 3);
    assert.ok(r.analysisStates.length >= 1);
  }
});

test('vacuous NotAction complement stays fail-closed at every threshold', () => {
  for (const threshold of ['none', 'critical', 'high', 'info']) {
    const r = scan({ text: VACUOUS_NOTACTION[0], family: 'identity', threshold });
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `threshold ${threshold}`);
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  }
});

// An INVALID subjectAccount (not a 12-digit account id) must be treated as ABSENT,
// exactly like an unrecognized partition. Otherwise a garbage account could be read
// as a confident assertion that resolves a PassRole path's viability and slips the
// unknown-viability finding under the threshold as a clean pass. All malformed
// account tokens must leave the finding UNKNOWN and fail closed (exit 3).
const BOGUS_ACCOUNTS = ['not-an-account', '12345', '999988887777xxx', '0x12', '99998888777', '9999888877770'];

test('bogus subjectAccount does NOT resolve viability - stays unknown, exit 3 (fail-open guard)', () => {
  for (const subjectAccount of BOGUS_ACCOUNTS) {
    const r = scan({ text: PASSROLE_UNKNOWN_VIABILITY, family: 'identity', subjectAccount });
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL, `account ${JSON.stringify(subjectAccount)} must stay partial`);
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `account ${JSON.stringify(subjectAccount)} must fail closed`);
    assert.equal(r.exitCode, 3);
  }
});

test('only a VALID 12-digit subjectAccount resolves the unknown-viability path (exit 1)', () => {
  const r = scan({ text: PASSROLE_UNKNOWN_VIABILITY, family: 'identity', subjectAccount: '999988887777' });
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.exitCode, EXIT.FINDINGS);
});

// The empty-NotAction guard re-parses the raw text and trusts that its parse
// AGREES with the engine's. That safety rests on JSON with duplicate keys (which
// could let the two parsers disagree on which value wins) being REJECTED outright,
// and on a "__proto__" key never polluting the guard's object walk. Pin both: a
// duplicate-key or __proto__-carrying document must fail closed (exit 3), never
// reach a divergent clean pass, and must never mutate Object.prototype.
test('duplicate-key JSON is rejected (fail closed, exit 3) - no parse divergence fail-open', () => {
  const dupNotAction = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["s3:x"],"NotAction":[],"Resource":"*"}]}';
  const dupStatement = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"arn:aws:ec2:us-east-1:111122223333:instance/i-0abc"}],"Statement":[{"Effect":"Allow","NotAction":[],"Resource":"*"}]}';
  for (const text of [dupNotAction, dupStatement]) {
    const r = scan({ text, family: 'identity' });
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, `dup-key must not be complete: ${text}`);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `dup-key must fail closed: ${text}`);
  }
});

test('a __proto__ key neither pollutes the prototype nor opens a masked-admin fail-open', () => {
  const text = '{"Version":"2012-10-17","__proto__":{"polluted":1},"Statement":[{"Effect":"Allow","NotAction":[],"Resource":"*"}]}';
  const r = scan({ text, family: 'identity' });
  assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.notEqual(r.exitCode, EXIT.CLEAN);
  assert.equal({}.polluted, undefined, 'Object.prototype must not be polluted');
});

// --- masked-grant CONDITION-VALUE fail-open (P15-cli iteration 2 BLOCKER) ------
// A full-admin or escalation Allow can be silently neutralized by the engine's
// condition-VALUE handling when the condition KEY is MODELED (so coverage stays
// "complete" and the unsupported-condition path never fires):
//   - a non-string array member ([{}], [null]) is DROPPED by toValueArray, and
//     under ForAnyValue the emptied set makes statementNeverMatches suppress the
//     whole grant -> rules/escalation skip it -> 'complete' + 0 findings. AWS
//     rejects a non-string condition element as MalformedPolicyDocument, so the
//     policy is also undeployable. It MUST fail closed (MALFORMED, exit 3).
//   - a LITERALLY empty ForAnyValue array ([]) is valid AWS but the engine
//     suppresses the Allow as a never-match, leaving a full grant with no finding.
//     It MUST leave a trace (INCOMPLETE analyzer-state, exit 3), not a silent CLEAN.
// The MODELED keys are the exploit surface (aws:SourceVpc / aws:SourceIp /
// aws:PrincipalOrgID / sts:ExternalId); an UNMODELED key would already fail closed
// via unsupportedConditions.
const COND_KEY = 'aws:SourceVpc';
function maskedCondAdmin(value, op = 'ForAnyValue:StringEquals', action = '*') {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Action: action, Resource: '*', Condition: { [op]: { [COND_KEY]: value } } }],
  });
}

test('non-string condition array member ([{}]/[null]) -> failed, exit 3, MALFORMED, never clean', () => {
  for (const value of [[{}], [null], [[]], ['ok', {}]]) {
    const r = scan({ text: maskedCondAdmin(value), family: 'identity' });
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, `must not be complete: ${JSON.stringify(value)}`);
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.FAILED);
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
    assert.equal(r.exitCode, 3);
    assert.equal(r.reason, 'MALFORMED_CONDITION_VALUE');
    assert.ok(r.analysisStates.length >= 1);
    assert.equal(r.analysisStates[0].analysisState, ANALYSIS_STATE.MALFORMED);
    assert.equal(r.analysisStates[0].code, 'MALFORMED_CONDITION_VALUE');
  }
});

test('empty ForAnyValue array ([]) on an Allow -> partial, exit 3, INCOMPLETE trace, never clean', () => {
  const r = scan({ text: maskedCondAdmin([]), family: 'identity' });
  assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(r.analysisStatus, ANALYSIS_STATUS.PARTIAL);
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(r.exitCode, 3);
  assert.equal(r.reason, 'SUPPRESSED_NEVER_MATCH_ALLOW');
  assert.ok(r.analysisStates.some((s) => s.code === 'SUPPRESSED_NEVER_MATCH_ALLOW'));
  assert.equal(r.analysisStates[0].analysisState, ANALYSIS_STATE.INCOMPLETE);
});

test('masked-condition fail-open holds across MODELED keys and ForAnyValue operators', () => {
  for (const key of ['aws:SourceVpc', 'aws:SourceIp', 'aws:PrincipalOrgID', 'sts:ExternalId']) {
    for (const op of ['ForAnyValue:StringEquals', 'ForAnyValue:IpAddress']) {
      for (const value of [[{}], [null], []]) {
        const text = JSON.stringify({
          Version: '2012-10-17',
          Statement: [{ Effect: 'Allow', Action: '*', Resource: '*', Condition: { [op]: { [key]: value } } }],
        });
        const r = scan({ text, family: 'identity' });
        assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `${key} ${op} ${JSON.stringify(value)} must fail closed`);
        assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
      }
    }
  }
});

test('masked-condition fail-open holds for escalation/exfil shapes (not just Action:*)', () => {
  const shapes = [
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'iam:*', Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'aws:SourceVpc': [{}] } } }] }),
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 's3:ListBucket'], Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'aws:SourceVpc': [null] } } }] }),
    JSON.stringify({ Version: '2012-10-17', Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'aws:SourceVpc': [{}] } } },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'aws:SourceVpc': [{}] } } },
    ] }),
  ];
  for (const text of shapes) {
    const r = scan({ text, family: 'identity' });
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  }
});

test('masked-condition fail-open cannot be downgraded by any threshold (incl. none)', () => {
  for (const threshold of ['none', 'critical', 'high', 'info']) {
    for (const value of [[{}], [null], []]) {
      const r = scan({ text: maskedCondAdmin(value), family: 'identity', threshold });
      assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `threshold ${threshold} value ${JSON.stringify(value)}`);
      assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
      assert.notEqual(r.exitCode, EXIT.CLEAN);
    }
  }
});

test('masked-condition fail-open is caught when it is NOT the first statement', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc' },
      { Effect: 'Allow', Action: '*', Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'aws:SourceVpc': [{}] } } },
    ],
  });
  const r = scan({ text, family: 'identity' });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  assert.equal(r.reason, 'MALFORMED_CONDITION_VALUE');
  assert.equal(r.analysisStates[0].path, 'Statement[1].Condition.ForAnyValue:StringEquals.aws:SourceVpc');
});

test('a BOM-prefixed masked-condition policy STILL fails closed (exit 3), not clean', () => {
  for (const value of [[{}], [null], []]) {
    const r = scan({ text: BOM + maskedCondAdmin(value), family: 'identity' });
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `BOM must not open the guard: ${JSON.stringify(value)}`);
    assert.notEqual(r.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  }
});

test('benign condition-value siblings are NOT flagged (no over-fire)', () => {
  // A valid value array, boolean/number primitives (kept by toValueArray), an empty
  // NON-ForAnyValue array (grant still emits -> exit 1, not a suppressed never-match),
  // and a Deny + empty ForAnyValue (never-match Deny is benign) must NOT become exit 3.
  const stayFindings = [
    maskedCondAdmin(['vpc-123']),
    maskedCondAdmin([true]),
    maskedCondAdmin([123]),
    maskedCondAdmin([], 'StringEquals'), // non-ForAnyValue empty [] -> grant still evaluated
  ];
  for (const text of stayFindings) {
    const r = scan({ text, family: 'identity' });
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE, `should stay complete: ${text}`);
    assert.notEqual(r.reason, 'MALFORMED_CONDITION_VALUE');
    assert.notEqual(r.reason, 'SUPPRESSED_NEVER_MATCH_ALLOW');
    assert.equal(r.exitCode, EXIT.FINDINGS);
  }
  // A never-match Deny grants/denies nothing -> benign clean pass.
  const denyText = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: 'Deny', Action: '*', Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'aws:SourceVpc': [] } } }],
  });
  const rDeny = scan({ text: denyText, family: 'identity' });
  assert.equal(rDeny.analysisStatus, ANALYSIS_STATUS.COMPLETE);
  assert.equal(rDeny.exitCode, EXIT.CLEAN);
});

test('masked-condition scan is deterministic', () => {
  const a = JSON.stringify(scan({ text: maskedCondAdmin([{}]), family: 'identity' }));
  const b = JSON.stringify(scan({ text: maskedCondAdmin([{}]), family: 'identity' }));
  assert.equal(a, b);
});
