// S1-R1-deny-fence-surviving: a WHOLE-CONTAINER read that SURVIVES a NotResource-Deny
// fence on a broad Allow must NOT read CLEAN/exit-0.
//
// THE BUG (R1, HIGH). A broad exfil Allow ({Allow s3:GetObject Resource:*}) fenced by a
// same-policy Deny ({Deny s3:GetObject NotResource:[arn:aws:s3:::acme-competitor-bucket/*]})
// used to read exit0 / complete / findings:[]. denyFencesToNarrow proves the spared set
// NARROW (correct), ruleFindingDenySuppressed drops DATA-EXFIL and survivingBroadReadActions
// keeps the coverage net quiet (correct) - but NOTHING then inspected the PROVEN SURVIVING
// spared resource (arn:aws:s3:::acme-competitor-bucket/*) for its OWN risk: a live whole-
// bucket read (the archetypal exfil primitive) read CLEAN (threat-model T8). The SAME spared
// scope granted DIRECTLY surfaced CROSS-ACCOUNT-DATA-READ-UNDETERMINED, so widening the ARN
// behind a fence was a silent evasion.
//
// THE FIX. An analyze.js post-pass (survivingSparedContainerReads, which HAS the denies in
// scope) reuses rules.js's shared whole-container classifier on the PROVEN SURVIVING spared
// set and surfaces the surviving read as CROSS-ACCOUNT-DATA-READ[-UNDETERMINED] - NEVER
// DATA-EXFIL (whose bulk-fence exemption would re-suppress it). The undetermined S3-bucket
// case is subject-account-INDEPENDENT (like DATA-EXFIL, it never needed a subject).
//
// These exercise the REAL boundaries: the shipped analyze() engine, the CLI scan() core,
// real SARIF bytes (partialFingerprints), a real CLI subprocess, and browser==CLI parity.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import { survivingSparedContainerReads } from '../../../content/tools/iam-blast-radius/engine/rules.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';
import { buildSarifLog, FINGERPRINT_KEY } from '../../../cli/sarif.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = join(here, '..', '..', '..', 'cli', 'iam-br.mjs');
const MANIFEST = { ruleVersion: '1' };

const SUBJECT = '123456789012';
const OTHER = '999999999999';

function policy(statements) {
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}
function ids(r) { return r.ok ? r.findings.map((f) => f.id) : []; }
function findingById(r, id) { return r.findings.find((f) => f.id === id); }

// The browser "clean" predicate (identical to browser-cli-parity.test.js + the story
// definition): ok, zero findings, coverage not incomplete.
function analyzeClean(r) {
  return !!(r && r.ok === true
    && Array.isArray(r.findings) && r.findings.length === 0
    && !(r.coverage && r.coverage.summary && r.coverage.summary.incomplete));
}
function scanClean(sr) {
  return sr.exitCode === EXIT.CLEAN && sr.analysisStatus === ANALYSIS_STATUS.COMPLETE;
}

// The reproduced-bug policy: broad exfil Allow fenced to ONE WHOLE BUCKET whose owning
// account is unresolvable (canonical S3 bucket ARN).
const FENCED_WHOLE_BUCKET = policy([
  { Sid: 'AllowReadBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
  { Sid: 'DenyButCompetitor', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
]);

// ---------------------------------------------------------------------------
// MUST-CLOSE: the fenced whole-bucket read surfaces (never CLEAN) - on a DEFAULT scan
// (no --subject-account) AND with --subject-account.
// ---------------------------------------------------------------------------

test('MUST-CLOSE: fenced whole-bucket read surfaces UNDETERMINED on a DEFAULT scan (no subject)', () => {
  const r = analyze(FENCED_WHOLE_BUCKET);
  assert.equal(r.ok, true);
  assert.equal(analyzeClean(r), false, 'the surviving whole-bucket read must NOT read CLEAN (R1 fail-open)');
  assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
    `expected the derived undetermined read; got [${ids(r)}]`);
  // The fence removed the broad exfil reach, so DATA-EXFIL must NOT be re-reported.
  assert.ok(!ids(r).includes('DATA-EXFIL'), 'DATA-EXFIL is fenced away and must not fire');
  const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.equal(f.severity, 'info', 'an UNPROVEN crossing surfaces at INFO (never overstated)');
  assert.deepEqual(f.resources, ['arn:aws:s3:::acme-competitor-bucket/*'],
    'the finding reports the PROVEN SURVIVING spared resource, not the Allow "*"');
  assert.ok(Array.isArray(f.actions) && f.actions.includes('s3:GetObject'));
  assert.ok(/^https:\/\//.test(f.docRef));
});

test('MUST-CLOSE: fenced whole-bucket read surfaces UNDETERMINED WITH a subject account too', () => {
  const r = analyze(FENCED_WHOLE_BUCKET, { subjectAccount: SUBJECT });
  assert.equal(analyzeClean(r), false);
  assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
    `S3 bucket ARNs are account-blind: undetermined even WITH a subject; got [${ids(r)}]`);
});

test('MUST-CLOSE: the derived finding id is NEVER DATA-EXFIL (would be instantly re-suppressed)', () => {
  // ruleFindingDenySuppressed exempts a NotResource-fenced bulk read only when
  // id===DATA-EXFIL. A derived DATA-EXFIL would be dropped again -> silent CLEAN.
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(FENCED_WHOLE_BUCKET, opt);
    for (const f of r.findings) {
      assert.notEqual(f.id, 'DATA-EXFIL',
        'the surviving-spared finding must use a CROSS-ACCOUNT-DATA-READ* id, never DATA-EXFIL');
    }
  }
});

test('MUST-CLOSE: the CLI (scan) fails the gate on the fenced whole-bucket read at its INFO threshold', () => {
  // The finding gates at INFO (like the directly-granted whole-bucket read, corpus 08).
  const sr = scan({ text: FENCED_WHOLE_BUCKET, family: 'identity', threshold: 'info' });
  assert.equal(scanClean(sr), false, 'a live exfil primitive must never be a clean CLI pass');
  assert.equal(sr.exitCode, 1, 'a finding at/above the info threshold exits 1');
  assert.ok(sr.findings.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
    'the CLI surfaces the same derived finding the browser does');
});

test('MUST-CLOSE: the SAME spared scope granted DIRECTLY also surfaces UNDETERMINED (parity of paths)', () => {
  // The fence must not be a silent evasion: fenced-to-X and directly-granted-X agree.
  const direct = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  ]), { subjectAccount: SUBJECT });
  assert.ok(ids(direct).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
    'the directly-granted whole-bucket read surfaces the same id the fenced remnant does');
});

test('MUST-CLOSE: a cross-account resolvable spared read surfaces CROSS-ACCOUNT-DATA-READ (subject known)', () => {
  // A Deny sparing an account-BEARING S3 access-point ARN in ANOTHER account.
  const text = policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: `arn:aws:s3:us-east-1:${OTHER}:accesspoint/foreign-ap/object/*` },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  assert.equal(analyzeClean(r), false);
  const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ');
  assert.ok(f, `expected a confirmed cross-account read; got [${ids(r)}]`);
  assert.deepEqual(f.resources, [`arn:aws:s3:us-east-1:${OTHER}:accesspoint/foreign-ap/object/*`]);
  assert.ok(/DIFFERENT AWS account/.test(f.why));
});

// ---------------------------------------------------------------------------
// MUST-CLOSE (iteration 2): the SENSITIVELY-NAMED and VARIABLE-SCOPED spared whole
// buckets - the highest-value exfil targets - must surface too. The iteration-1 fix
// closed R1 only for NEUTRALLY-named spared buckets: classifyContainerReads dropped any
// account-less S3 spared bucket matching a sensitivity token or carrying a ${...} variable
// on the premise it "already surfaces via the DATA-READ path". That premise holds ONLY for
// ruleDataReadScoped (NARROW Allow, DATA-READ fall-through runs); for the survivingSpared*
// caller the Allow is BROAD so ruleDataReadScoped early-returns at `if (broad) return;` and
// no DATA-READ ever fires -> the sensitive/variable spared bucket read CLEAN. A strict
// inversion: the more sensitive the spared bucket, the LESS likely the tool warned.
// ---------------------------------------------------------------------------

const SENSITIVE_BUCKETS = ['production-secrets', 'customer-exports', 'payroll-backup'];

for (const bucket of SENSITIVE_BUCKETS) {
  const arn = `arn:aws:s3:::${bucket}/*`;
  const fenced = policy([
    { Sid: 'AllowReadBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Sid: 'FenceSensitive', Effect: 'Deny', Action: 's3:GetObject', NotResource: arn },
  ]);

  test(`MUST-CLOSE: sensitively-named spared bucket '${bucket}' surfaces on a DEFAULT scan (no subject)`, () => {
    const r = analyze(fenced);
    assert.equal(analyzeClean(r), false,
      `a fenced whole-bucket read of '${bucket}' must NOT read CLEAN (R1 iter-2 fail-open)`);
    assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
      `expected the derived undetermined read for '${bucket}'; got [${ids(r)}]`);
    assert.ok(!ids(r).includes('DATA-EXFIL'), 'the fence removed the broad exfil reach');
    const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
    assert.deepEqual(f.resources, [arn], 'reports the PROVEN SURVIVING spared bucket, not the Allow "*"');
  });

  test(`MUST-CLOSE: sensitively-named spared bucket '${bucket}' surfaces WITH a subject account too`, () => {
    const r = analyze(fenced, { subjectAccount: SUBJECT });
    assert.equal(analyzeClean(r), false,
      `S3 bucket ARNs are account-blind: '${bucket}' must surface even WITH a subject`);
    assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'), `got [${ids(r)}]`);
  });

  test(`MUST-CLOSE: the CLI fails the gate on sensitively-named spared bucket '${bucket}' (--threshold info)`, () => {
    const sr = scan({ text: fenced, family: 'identity', threshold: 'info' });
    assert.equal(scanClean(sr), false, `a live exfil primitive ('${bucket}') must never be a clean CLI pass`);
    assert.equal(sr.exitCode, 1);
    assert.ok(sr.findings.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'));
  });
}

test('MUST-CLOSE: a VARIABLE-scoped spared whole bucket surfaces (default + subject)', () => {
  // A ${...}-scoped bare bucket cannot be resolved to a concrete ARN, so it is account-
  // blind AND its objects are uncertain: the highest-uncertainty spared shape must not
  // read CLEAN. Preserved verbatim in the finding's resources.
  const arn = 'arn:aws:s3:::data-${aws:PrincipalTag/x}/*';
  const fenced = policy([
    { Sid: 'AllowReadBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Sid: 'FenceVariable', Effect: 'Deny', Action: 's3:GetObject', NotResource: arn },
  ]);
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(fenced, opt);
    assert.equal(analyzeClean(r), false, 'a variable-scoped spared whole-bucket read must NOT read CLEAN');
    const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
    assert.ok(f, `expected the derived undetermined read; got [${ids(r)}]`);
    assert.deepEqual(f.resources, [arn], 'the policy variable is preserved verbatim in the finding');
  }
});

test('parity-of-paths: sensitively-named DIRECT narrow grant surfaces DATA-READ; the FENCED remnant is never CLEAN', () => {
  // The bug was a strict inversion vs a direct grant. The direct narrow grant of the SAME
  // sensitive bucket surfaces (DATA-READ/medium); the fenced remnant must likewise surface
  // (not silently clear) - the fence must not become an evasion for sensitive names.
  const direct = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::production-secrets/*' },
  ]));
  assert.ok(ids(direct).includes('DATA-READ'), `direct sensitive grant surfaces DATA-READ; got [${ids(direct)}]`);
  const fencedR = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::production-secrets/*' },
  ]));
  assert.equal(analyzeClean(fencedR), false, 'the fenced sensitive remnant must not be CLEAN while a direct grant fires');
});

// ---------------------------------------------------------------------------
// MUST-STAY-QUIET (no false positives / no noise) - the HYBRID boundary.
// ---------------------------------------------------------------------------

test('MUST-STAY-QUIET: a SINGLE-OBJECT spared read is routine least privilege -> CLEAN', () => {
  const text = policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/report.csv' },
  ]);
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(text, opt);
    assert.equal(analyzeClean(r), true, 'a single concrete object read stays quiet (whole-container excludes it)');
    assert.deepEqual(ids(r), []);
  }
});

test('MUST-STAY-QUIET: a same-account condition/ARN-resolvable whole-bucket spared read -> CLEAN', () => {
  // Account-bearing access-point ARN in the SUBJECT's own account.
  const sameAcctAp = policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: `arn:aws:s3:us-east-1:${SUBJECT}:accesspoint/own-ap/object/*` },
  ]);
  const r1 = analyze(sameAcctAp, { subjectAccount: SUBJECT });
  assert.equal(analyzeClean(r1), true, 'a resolved SAME-account whole-bucket spared read is quiet');
  assert.deepEqual(ids(r1), []);

  // A canonical bare bucket whose owner is PINNED to the subject account by an
  // aws:ResourceAccount condition: the surviving-spared post-pass RECOVERS the owner and
  // classifies it SAME-account, so it derives NO finding. (The analysis is separately
  // marked incomplete only because aws:ResourceAccount is an unmodeled condition key -
  // a pre-existing, orthogonal signal - so we assert QUIETNESS of the R1 post-pass here,
  // not full cleanliness.)
  const pinnedSame = policy([
    {
      Effect: 'Allow', Action: 's3:GetObject', Resource: '*',
      Condition: { StringEquals: { 'aws:ResourceAccount': SUBJECT } },
    },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  ]);
  const r2 = analyze(pinnedSame, { subjectAccount: SUBJECT });
  assert.ok(!ids(r2).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED')
    && !ids(r2).includes('CROSS-ACCOUNT-DATA-READ'),
  'a condition-pinned same-account whole-bucket spared read derives no cross-account finding');
  assert.ok(!ids(r2).includes('DATA-EXFIL'), 'the fence still removes the broad exfil reach');
});

test('MUST-STAY-QUIET: an UNRELATED-service Deny spawns no bogus S3 finding (DATA-EXFIL still loud)', () => {
  // Deny ec2:* NotResource:s3bucket does not fence s3:GetObject, so the broad Allow is
  // still broad exfil - DATA-EXFIL fires and NO surviving-spared S3 finding is invented.
  const text = policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Effect: 'Deny', Action: 'ec2:*', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  assert.ok(ids(r).includes('DATA-EXFIL'), 'an unrelated Deny does not fence the broad read; DATA-EXFIL fires');
  assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED')
    && !ids(r).includes('CROSS-ACCOUNT-DATA-READ'),
  'the unrelated Deny\'s spared S3 ARN must NOT spawn a bogus cross-account finding');
});

test('MUST-STAY-QUIET: a CONDITIONAL (not-definitive) Deny is not a fence -> DATA-EXFIL loud, no derived finding', () => {
  const text = policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    {
      Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*',
      Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } },
    },
  ]);
  const r = analyze(text);
  assert.ok(ids(r).includes('DATA-EXFIL'), 'a conditional Deny may not apply -> broad read survives -> DATA-EXFIL');
  assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
    'a conditional Deny is not credited as a fence, so no surviving-spared finding is derived');
});

test('MUST-STAY-QUIET (iter-3 over-correction): ARN-WILDCARD Allow + Deny sparing an UNCOVERED bucket -> CLEAN', () => {
  // R1 iteration-3 BLOCKER: the broad Allow is an ARN-WILDCARD (arn:aws:s3:::prod-*/*), NOT
  // the bare "*" every other R1 fixture uses. resourceIsBroad() is true so the post-pass runs,
  // but the spared acme-competitor bucket falls ENTIRELY OUTSIDE the Allow's grant: prod-*
  // objects are DENIED (not spared) and the spared bucket is NOT granted -> AWS net = ZERO
  // readable. The surviving-spared classifier must intersect the spared set with the Allow's
  // OWN resource scope, so this valid-but-effectively-SAFE policy reports CLEAN, never a
  // fabricated finding on a bucket the policy grants no access to (threat-model T8).
  const text = policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::prod-*/*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  ]);
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(text, opt);
    assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED')
      && !ids(r).includes('CROSS-ACCOUNT-DATA-READ'),
    `a spared bucket the Allow never grants must not fabricate a finding; got [${ids(r)}]`);
    assert.equal(analyzeClean(r), true,
      'an ARN-wildcard Allow that grants nothing after the fence is effectively SAFE -> CLEAN');
  }
  // Real CLI subprocess: the fabricated-finding path drove exit 1 at --threshold info; the
  // fixed path must exit 0 CLEAN on this effectively-safe input.
  const sr = scan({ text, family: 'identity', threshold: 'info', subjectAccount: SUBJECT });
  assert.equal(scanClean(sr), true, 'effectively-safe ARN-wildcard-Allow input is a clean CLI pass');
});

test('MUST-CLOSE (iter-3 true-positive twin): ARN-WILDCARD Allow + Deny sparing a COVERED bucket -> fires', () => {
  // The twin of the above: the Deny spares prod-secrets/*, which the Allow arn:aws:s3:::prod-*/*
  // DOES cover (prod-* matches prod-secrets). The intersection is non-empty, so the surviving
  // whole-bucket read is a real capability and MUST surface - the intersection fix must not
  // over-suppress a genuinely-granted spared read.
  const text = policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::prod-*/*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::prod-secrets/*' },
  ]);
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(text, opt);
    assert.equal(analyzeClean(r), false,
      'a spared bucket the Allow DOES grant is a live surviving read -> must not be CLEAN');
    const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
    assert.ok(f, `expected the derived undetermined read for the covered spare; got [${ids(r)}]`);
    assert.deepEqual(f.resources, ['arn:aws:s3:::prod-secrets/*'],
      'reports the PROVEN SURVIVING (Allow-covered) spared bucket');
    assert.ok(!ids(r).includes('DATA-EXFIL'), 'the fence still removes the broad exfil reach');
  }
});

// ---------------------------------------------------------------------------
// MUST-STAY-QUIET (iteration 4 over-correction): a spared resource that ANOTHER
// same-policy Deny ALSO removes is NOT a surviving capability. The surviving-spared
// set must be the resources the fence spares MINUS everything the rest of the Deny
// set removes - not the raw union of NotResource carve-outs. Reporting a bucket that
// is net-UNREADABLE (AWS explicit-Deny precedence) is a fabricated finding (T8 noise)
// that would train reviewers to ignore the derived id. Each case below is net-ZERO
// readable and MUST read CLEAN on the DEFAULT scan AND with --subject-account.
// ---------------------------------------------------------------------------

// C1: two NotResource fences on the SAME action, sparing DIFFERENT buckets. Reading
// bucket-a is denied by the bucket-b fence (a is not-b, so its NotResource matches);
// reading bucket-b is denied by the bucket-a fence. Net readable = ZERO. The raw
// UNION {a,b} is a double false positive; the correct surviving set is the
// INTERSECTION of the fences' spared sets = empty.
const C1_MUTUAL_FENCES = policy([
  { Sid: 'AllowBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
  { Sid: 'FenceA', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::bucket-a/*' },
  { Sid: 'FenceB', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::bucket-b/*' },
]);

// C2: fence spares acme-competitor, but an explicit Resource-Deny removes it. Net ZERO.
const C2_FENCE_PLUS_EXPLICIT = policy([
  { Sid: 'AllowBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
  { Sid: 'Fence', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  { Sid: 'AlsoDenyAcme', Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::acme-competitor-bucket/*' },
]);

// C3: fence + a BLANKET Deny s3:GetObject on Resource "*" -> denies everything incl. the spare.
const C3_FENCE_PLUS_BLANKET = policy([
  { Sid: 'AllowBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
  { Sid: 'Fence', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  { Sid: 'DenyAll', Effect: 'Deny', Action: 's3:GetObject', Resource: '*' },
]);

// C4: fence + a WHOLE-SERVICE blanket Deny s3:* on Resource "*" -> everything denied.
const C4_FENCE_PLUS_SERVICE_BLANKET = policy([
  { Sid: 'AllowBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
  { Sid: 'Fence', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  { Sid: 'DenyService', Effect: 'Deny', Action: 's3:*', Resource: '*' },
]);

for (const [label, text] of [
  ['C1 two mutually-exclusive NotResource fences', C1_MUTUAL_FENCES],
  ['C2 fence + explicit Resource-Deny on the spared bucket', C2_FENCE_PLUS_EXPLICIT],
  ['C3 fence + blanket Deny s3:GetObject Resource:*', C3_FENCE_PLUS_BLANKET],
  ['C4 fence + whole-service blanket Deny s3:* Resource:*', C4_FENCE_PLUS_SERVICE_BLANKET],
]) {
  test(`MUST-STAY-QUIET: net-unreadable spared bucket reads CLEAN (${label})`, () => {
    for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
      const r = analyze(text, opt);
      assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED')
        && !ids(r).includes('CROSS-ACCOUNT-DATA-READ'),
      `a net-unreadable spared bucket must not fabricate a derived finding; got [${ids(r)}]`);
      assert.equal(analyzeClean(r), true,
        `explicit-Deny precedence makes this net-ZERO readable -> CLEAN; got [${ids(r)}]`);
    }
  });

  test(`MUST-STAY-QUIET: the CLI is a clean exit-0 pass on the net-unreadable spare (${label})`, () => {
    const sr = scan({ text, family: 'identity', threshold: 'info', subjectAccount: SUBJECT });
    assert.equal(scanClean(sr), true, `net-unreadable input must be a clean CLI pass; got exit ${sr.exitCode}`);
    assert.equal(sr.exitCode, 0);
  });
}

test('MUST-STAY-QUIET (real subprocess): the C1 mutual-fence policy exits 0 CLEAN', () => {
  const res = spawnSync('node',
    [CLI_PATH, '--family', 'identity', '--threshold', 'info', '--format', 'json'],
    { input: C1_MUTUAL_FENCES, encoding: 'utf8' });
  assert.notEqual(res.status, null, 'the CLI ran to completion');
  assert.equal(res.status, 0, 'a net-unreadable mutual-fence policy is a clean exit 0');
  const report = JSON.parse(res.stdout);
  assert.deepEqual(report.findings.map((f) => f.id).filter((id) => /CROSS-ACCOUNT-DATA-READ/.test(id)), [],
    'no derived cross-account finding on a net-unreadable input');
});

// TRUE-POSITIVE GUARD: the deny-subtraction must NOT over-suppress. Here a SECOND
// Deny removes an UNRELATED bucket (bucket-x), leaving the fence's spared
// acme-competitor bucket genuinely readable -> the derived finding MUST still fire.
test('MUST-CLOSE (iter-4 twin): an unrelated extra Deny does not suppress a still-readable spare', () => {
  const text = policy([
    { Sid: 'AllowBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Sid: 'Fence', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
    { Sid: 'DenyUnrelated', Effect: 'Deny', Action: 's3:GetObject', Resource: 'arn:aws:s3:::some-other-bucket/*' },
  ]);
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(text, opt);
    assert.equal(analyzeClean(r), false,
      'the spared acme-competitor bucket is still readable -> must not be CLEAN');
    const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
    assert.ok(f, `expected the derived undetermined read; got [${ids(r)}]`);
    assert.deepEqual(f.resources, ['arn:aws:s3:::acme-competitor-bucket/*'],
      'reports the still-readable spared bucket, not the unrelated denied one');
  }
});

// TRUE-POSITIVE GUARD: two fences that BOTH spare the SAME bucket -> the intersection
// is non-empty -> the surviving read is real and MUST fire (the subtraction must not
// collapse a genuine surviving spare to empty).
test('MUST-CLOSE (iter-4 twin): two fences both sparing the same bucket still fire', () => {
  const text = policy([
    { Sid: 'AllowBroad', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Sid: 'FenceOne', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
    { Sid: 'FenceTwo', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  ]);
  const r = analyze(text);
  assert.equal(analyzeClean(r), false, 'both fences spare the same bucket -> it is readable -> not CLEAN');
  const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.ok(f, `expected the derived undetermined read; got [${ids(r)}]`);
  assert.deepEqual(f.resources, ['arn:aws:s3:::acme-competitor-bucket/*']);
});

// ---------------------------------------------------------------------------
// Mixed-resource Allow: derived finding + a normal ruleDataReadScoped finding COEXIST,
// no duplicate report, no fingerprint collision (real SARIF bytes).
// ---------------------------------------------------------------------------

test('mixed-resource Allow: derived (spared) + normal (own-resource) findings coexist, distinct fingerprints', () => {
  // Allow reads on ["*", a cross-account dynamodb table]; a Deny fences the s3 leg to one
  // bucket. ruleDataReadScoped surfaces the dynamodb table (own resource, cross-account);
  // the post-pass surfaces the s3 spared bucket (undetermined). Both on statement 0.
  const text = policy([
    {
      Sid: 'MixedRead', Effect: 'Allow',
      Action: ['s3:GetObject', 'dynamodb:Scan'],
      Resource: ['*', `arn:aws:dynamodb:us-east-1:${OTHER}:table/customers`],
    },
    { Sid: 'FenceS3', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  assert.equal(r.ok, true);

  const undet = r.findings.filter((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  const cross = r.findings.filter((f) => f.id === 'CROSS-ACCOUNT-DATA-READ');
  assert.equal(undet.length, 1, `exactly one derived undetermined finding; got [${ids(r)}]`);
  assert.equal(cross.length, 1, `exactly one normal cross-account finding; got [${ids(r)}]`);
  // The derived finding reports the SPARED bucket; the normal one reports the OWN table.
  assert.deepEqual(undet[0].resources, ['arn:aws:s3:::acme-competitor-bucket/*']);
  assert.deepEqual(cross[0].resources, [`arn:aws:dynamodb:us-east-1:${OTHER}:table/customers`]);

  // No duplicate: no two findings share (id, statementIndex, actions, resources).
  const keys = r.findings.map((f) => [f.id, f.statementIndex,
    (f.actions || []).slice().sort().join(','), (f.resources || []).slice().sort().join(',')].join('|'));
  assert.equal(new Set(keys).size, keys.length, 'no duplicate-report row');

  // Real SARIF bytes: the two data-read findings hash to DISTINCT partialFingerprints
  // (so dismissing one code-scanning alert never suppresses the other).
  const sr = scan({ text, family: 'identity', threshold: 'info', subjectAccount: SUBJECT });
  const log = buildSarifLog(sr, {}, MANIFEST);
  const results = log.runs[0].results;
  const fpUndet = results.find((x) => x.ruleId === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED')
    .partialFingerprints[FINGERPRINT_KEY];
  const fpCross = results.find((x) => x.ruleId === 'CROSS-ACCOUNT-DATA-READ')
    .partialFingerprints[FINGERPRINT_KEY];
  assert.ok(fpUndet && fpCross && fpUndet !== fpCross,
    `the coexisting findings must have distinct fingerprints; got ${fpUndet} vs ${fpCross}`);
});

// ---------------------------------------------------------------------------
// Iteration-5 over-correction BLOCKER: duplicate-report when the spared bucket is
// ALSO an explicit Allow resource AND the fence covers only a strict ACTION-SUBSET
// of the Allow's read actions. ruleDataReadScoped reports the Allow's OWN leg with the
// FULL read action set on the spared bucket; the derived helper re-reports the SAME
// bucket with only the FENCED action subset. The two rows describe ONE surviving
// capability but the exact-action-set dedup key treated the subset as distinct -> two
// SARIF alerts / two table rows for one bucket (dismissing one leaves the other). The
// dedup must be SUBSET-aware: a derived finding sharing (id, statementIndex) with a
// table finding whose resources cover it and whose actions are a SUPERSET is dropped as
// already-covered, leaving exactly ONE (broader) row per surviving bucket.
// ---------------------------------------------------------------------------

// The exact iteration-5 repro: the spared bucket is BOTH an explicit Allow resource and
// the fence's NotResource carve-out; the Deny fences only s3:GetObject (a strict subset
// of the Allow's [s3:GetObject, s3:ListBucket] reads).
const SUBSET_FENCE_ON_EXPLICIT_ALLOW = policy([
  {
    Sid: 'BroadAndExplicit', Effect: 'Allow',
    Action: ['s3:GetObject', 's3:ListBucket'],
    Resource: ['*', 'arn:aws:s3:::acme-competitor-bucket/*'],
  },
  { Sid: 'FenceGetOnly', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
]);

test('iter-5 no-duplicate: subset-action fence on an explicit-Allow spared bucket yields exactly ONE row', () => {
  const r = analyze(SUBSET_FENCE_ON_EXPLICIT_ALLOW, { subjectAccount: SUBJECT });
  assert.equal(r.ok, true);
  // Still surfaces (the surviving capability is reported, never CLEAN).
  assert.equal(analyzeClean(r), false);
  const undet = r.findings.filter((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.equal(undet.length, 1,
    `one surviving bucket must yield exactly one row, not one-per-action-subset; got [${ids(r)}]`);
  // The surviving row is the BROADER one (the derived strict-subset row was dropped as
  // already-covered, the fuller-capability table row is kept).
  assert.deepEqual(undet[0].resources, ['arn:aws:s3:::acme-competitor-bucket/*']);
  assert.deepEqual(undet[0].actions.slice().sort(), ['s3:GetObject', 's3:ListBucket'],
    'the kept row reports the FULL surviving read capability, not the fenced action subset');
});

test('iter-5 no-duplicate: the derived helper itself still returns the redundant subset row (dedup collapses it, not the helper)', () => {
  // The fix lives in analyze.js dedup, NOT by weakening survivingSparedContainerReads:
  // the helper still legitimately derives the [s3:GetObject] surviving read; analyze()
  // drops it because a broader table finding already covers it.
  const built = modelFromText(SUBSET_FENCE_ON_EXPLICIT_ALLOW);
  assert.equal(built.ok, true);
  const raw = survivingSparedContainerReads(built.model, { subjectAccount: SUBJECT });
  assert.ok(raw.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'
    && f.actions.length === 1 && f.actions[0] === 's3:GetObject'),
  'the helper still derives the fenced-subset surviving read (the collapse is dedup, not suppression)');
});

test('iter-5 no-duplicate: real SARIF bytes carry exactly ONE result for the surviving bucket', () => {
  const sr = scan({ text: SUBSET_FENCE_ON_EXPLICIT_ALLOW, family: 'identity', threshold: 'info', subjectAccount: SUBJECT });
  assert.equal(scanClean(sr), false, 'the surviving read must still fail the gate');
  const log = buildSarifLog(sr, {}, MANIFEST);
  const results = log.runs[0].results.filter((x) => x.ruleId === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.equal(results.length, 1,
    `one bucket -> one code-scanning alert, not two with distinct fingerprints; got ${results.length}`);
});

test('iter-5 no-duplicate: PARITY holds on the subset-fence policy (default + subject)', () => {
  for (const opts of [{}, { subjectAccount: SUBJECT }]) {
    const sr = scan({ text: SUBSET_FENCE_ON_EXPLICIT_ALLOW, family: 'identity', threshold: 'info', ...opts });
    const ar = analyze(SUBSET_FENCE_ON_EXPLICIT_ALLOW, opts);
    assert.ok(scanClean(sr) || !analyzeClean(ar),
      'browser must not read clean while the CLI surfaces/fails closed');
  }
});

// ---------------------------------------------------------------------------
// Iteration-6 BLOCKER (fail-open): R1 reached via a NotResource-COMPLEMENT Allow.
// The broad read need not be Resource:"*"; it can be a broad NotResource complement
// ({Allow s3:GetObject NotResource:[excluded/*]}) that grants the action on EVERY
// resource EXCEPT its own carve-out. A same-policy NotResource Deny then fences it down
// to exactly the spared bucket (granted by the Allow, spared by the Deny) - a live whole-
// bucket read. survivingSparedContainerReads bailed on stmt.resources.length===0 and the
// broad-uncovered net skipped the fence-narrowed action (survivingBroadReadActions empty),
// so the surviving read read CLEAN/exit-0 at every threshold - while the semantically-
// identical Resource:"*" form surfaced CROSS-ACCOUNT-DATA-READ-UNDETERMINED. The complement
// form must surface the surviving read EXACTLY as the Resource:"*" form does.
// ---------------------------------------------------------------------------

// The complement-Allow repro: the broad grant is a NotResource complement, not Resource:"*".
const COMPLEMENT_FENCED_WHOLE_BUCKET = policy([
  { Sid: 'AllowReadComplement', Effect: 'Allow', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::excluded/*' },
  { Sid: 'DenyButCompetitor', Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
]);

test('iter-6 MUST-CLOSE: complement-Allow fenced whole-bucket read surfaces UNDETERMINED on a DEFAULT scan', () => {
  const r = analyze(COMPLEMENT_FENCED_WHOLE_BUCKET);
  assert.equal(r.ok, true);
  assert.equal(analyzeClean(r), false,
    'a broad NotResource-complement Allow fenced to one spared bucket is a live read; must NOT read CLEAN');
  assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
    `expected the derived undetermined read for the complement form; got [${ids(r)}]`);
  assert.ok(!ids(r).includes('DATA-EXFIL'), 'the fence removed the broad exfil reach');
  const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.equal(f.severity, 'info');
  assert.deepEqual(f.resources, ['arn:aws:s3:::acme-competitor-bucket/*'],
    'the finding reports the PROVEN SURVIVING spared bucket, not the Allow complement or its carve-out');
  assert.ok(Array.isArray(f.actions) && f.actions.includes('s3:GetObject'));
});

test('iter-6 MUST-CLOSE: complement-Allow fenced whole-bucket read surfaces WITH a subject too (S3 account-blind)', () => {
  const r = analyze(COMPLEMENT_FENCED_WHOLE_BUCKET, { subjectAccount: SUBJECT });
  assert.equal(analyzeClean(r), false);
  assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'), `got [${ids(r)}]`);
});

test('iter-6 MUST-CLOSE: the complement form agrees with the Resource:"*" form (fence not a silent evasion)', () => {
  // The two spellings of "broad" must not disagree: fenced-via-complement and
  // fenced-via-star yield the same derived id + surviving resource.
  const starForm = findingById(analyze(FENCED_WHOLE_BUCKET), 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  const complementForm = findingById(analyze(COMPLEMENT_FENCED_WHOLE_BUCKET), 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.ok(starForm && complementForm, 'both broad spellings surface the derived read');
  assert.deepEqual(complementForm.resources, starForm.resources,
    'the complement form reports the SAME surviving spared bucket the Resource:"*" form does');
  assert.deepEqual(complementForm.actions, starForm.actions);
});

test('iter-6 MUST-CLOSE: the CLI (scan) fails the gate on the complement-Allow fenced read at INFO', () => {
  const sr = scan({ text: COMPLEMENT_FENCED_WHOLE_BUCKET, family: 'identity', threshold: 'info' });
  assert.equal(scanClean(sr), false, 'a live exfil primitive expressed via a complement Allow must never be a clean CLI pass');
  assert.equal(sr.exitCode, 1);
  assert.ok(sr.findings.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'));
});

test('iter-6 MUST-CLOSE: real subprocess - complement-Allow form never exits 0 clean', () => {
  const res = spawnSync('node',
    [CLI_PATH, '--family', 'identity', '--threshold', 'info', '--format', 'json'],
    { input: COMPLEMENT_FENCED_WHOLE_BUCKET, encoding: 'utf8' });
  assert.notEqual(res.status, null, 'the CLI ran to completion');
  assert.equal(res.status, 1, 'a finding at/above info -> exit 1 (never a clean exit 0)');
  const report = JSON.parse(res.stdout);
  assert.ok(report.findings.map((f) => f.id).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
    `the emitted JSON bytes carry the derived finding; got [${report.findings.map((f) => f.id)}]`);
});

test('iter-6 MUST-CLOSE: default threshold (high) is ALSO not clean on the complement form (never findings=0 exit=0)', () => {
  // The blocker measured `status=complete exit=0 reason=CLEAN findings=0` at BOTH the
  // default (high) and info thresholds. At default the INFO finding does not gate (exit 0
  // is correct), but the analysis must still SURFACE the finding, never findings=0/CLEAN.
  const sr = scan({ text: COMPLEMENT_FENCED_WHOLE_BUCKET, family: 'identity' });
  assert.ok(sr.findings.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
    'the surviving read must be SURFACED even below the gate, never a findings=0 clean run');
});

test('iter-6 MUST-CLOSE: ListBucket-COMPLEMENT fenced whole-bucket surfaces (generalizes past GetObject)', () => {
  const text = policy([
    { Effect: 'Allow', Action: 's3:ListBucket', NotResource: 'arn:aws:s3:::excluded' },
    { Effect: 'Deny', Action: 's3:ListBucket', NotResource: 'arn:aws:s3:::acme-competitor-bucket' },
  ]);
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(text, opt);
    assert.equal(analyzeClean(r), false, 'a ListBucket-complement fenced to one bucket is a live container list; not CLEAN');
    const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
    assert.ok(f, `expected the derived undetermined read; got [${ids(r)}]`);
    assert.deepEqual(f.resources, ['arn:aws:s3:::acme-competitor-bucket']);
  }
});

test('iter-6 MUST-CLOSE: complement-Allow fenced to a CROSS-ACCOUNT access point surfaces CROSS-ACCOUNT-DATA-READ (subject known)', () => {
  const text = policy([
    { Effect: 'Allow', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::excluded/*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: `arn:aws:s3:us-east-1:${OTHER}:accesspoint/foreign-ap/object/*` },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  assert.equal(analyzeClean(r), false);
  const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ');
  assert.ok(f, `expected a confirmed cross-account read for the complement form; got [${ids(r)}]`);
  assert.deepEqual(f.resources, [`arn:aws:s3:us-east-1:${OTHER}:accesspoint/foreign-ap/object/*`]);
});

test('iter-6 MUST-STAY-QUIET: a complement Allow that ENTIRELY EXCLUDES the spared bucket is net-ZERO -> CLEAN', () => {
  // The Allow grants everything EXCEPT acme-competitor-bucket/*; the Deny spares ONLY
  // acme-competitor-bucket/*. The one resource the Deny leaves readable is the one the
  // Allow refuses to grant -> net ZERO readable. Must not fabricate a finding.
  const text = policy([
    { Effect: 'Allow', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/*' },
  ]);
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(text, opt);
    assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED')
      && !ids(r).includes('CROSS-ACCOUNT-DATA-READ'),
    `a spared bucket the complement Allow excludes must not fabricate a finding; got [${ids(r)}]`);
    assert.equal(analyzeClean(r), true, 'net-ZERO readable complement policy is a genuine CLEAN pass');
  }
  const sr = scan({ text, family: 'identity', threshold: 'info', subjectAccount: SUBJECT });
  assert.equal(scanClean(sr), true, 'the CLI is a clean exit-0 on the net-unreadable complement policy');
});

test('iter-6 MUST-STAY-QUIET: a SINGLE-OBJECT spared read via a complement Allow stays CLEAN', () => {
  const text = policy([
    { Effect: 'Allow', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::excluded/*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::acme-competitor-bucket/report.csv' },
  ]);
  for (const opt of [undefined, { subjectAccount: SUBJECT }]) {
    const r = analyze(text, opt);
    assert.equal(analyzeClean(r), true, 'a single concrete object spared read stays quiet (whole-container excludes it)');
    assert.deepEqual(ids(r), []);
  }
});

test('iter-6 MUST-STAY-QUIET: a same-account access-point spared via a complement Allow stays quiet', () => {
  const text = policy([
    { Effect: 'Allow', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::excluded/*' },
    { Effect: 'Deny', Action: 's3:GetObject', NotResource: `arn:aws:s3:us-east-1:${SUBJECT}:accesspoint/own-ap/object/*` },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED')
    && !ids(r).includes('CROSS-ACCOUNT-DATA-READ'),
  'a resolved SAME-account spared read via a complement Allow is quiet');
});

test('iter-6: PARITY holds on the complement-Allow fenced read (default + subject)', () => {
  for (const opts of [{}, { subjectAccount: SUBJECT }]) {
    const sr = scan({ text: COMPLEMENT_FENCED_WHOLE_BUCKET, family: 'identity', threshold: 'info', ...opts });
    const ar = analyze(COMPLEMENT_FENCED_WHOLE_BUCKET, opts);
    assert.ok(scanClean(sr) || !analyzeClean(ar),
      'browser must not read clean while the CLI surfaces/fails closed on the complement form');
    assert.ok(sr.findings.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'));
    assert.ok(ar.findings.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'));
  }
});

// ---------------------------------------------------------------------------
// browser==CLI parity + determinism + real-subprocess byte-faithfulness.
// ---------------------------------------------------------------------------

test('PARITY: analyze() is never more permissive than scan() on the fenced whole-bucket read', () => {
  for (const opts of [{}, { subjectAccount: SUBJECT }]) {
    const sr = scan({ text: FENCED_WHOLE_BUCKET, family: 'identity', threshold: 'info', ...opts });
    const ar = analyze(FENCED_WHOLE_BUCKET, opts);
    assert.ok(scanClean(sr) || !analyzeClean(ar),
      'browser must not read clean while the CLI surfaces/fails closed');
    // Both surfaces carry the same derived finding id.
    assert.ok(sr.findings.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'));
    assert.ok(ar.findings.some((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED'));
  }
});

test('deterministic: analyze() over the fenced policy is deep-equal twice', () => {
  assert.deepEqual(analyze(FENCED_WHOLE_BUCKET, { subjectAccount: SUBJECT }),
    analyze(FENCED_WHOLE_BUCKET, { subjectAccount: SUBJECT }));
});

test('real subprocess: cli/iam-br.mjs --format json surfaces the derived finding in its bytes (never exit 0 clean)', () => {
  const res = spawnSync('node',
    [CLI_PATH, '--family', 'identity', '--threshold', 'info', '--format', 'json'],
    { input: FENCED_WHOLE_BUCKET, encoding: 'utf8' });
  assert.notEqual(res.status, null, 'the CLI ran to completion');
  assert.equal(res.status, 1, 'a finding at/above info -> exit 1 (never a clean exit 0)');
  const report = JSON.parse(res.stdout);
  const idsOut = report.findings.map((f) => f.id);
  assert.ok(idsOut.includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'),
    `the emitted JSON bytes carry the derived finding; got [${idsOut}]`);
});
