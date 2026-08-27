// S2-crossaccount-scoped-surface: the tool used to emit an affirmative CLEAN
// (analyze() ok + zero findings + not-incomplete) on scoped-but-real dangerous
// cross-account capabilities:
//   (A) a scoped sts:AssumeRole into ANOTHER account read CLEAN (only broad/wildcard
//       scopes fired ASSUME-ROLE-EXPANSION), and
//   (B) a whole-container read on a cross-account resource read CLEAN, with severity
//       gated by a resource-NAME wordlist an adversary trivially evades.
//
// Per Oliver's HYBRID decision this story surfaces the CROSS-ACCOUNT cases at
// LOW/INFO (only when the subject account is KNOWN, via context), keeps SAME-account
// scoped reads/assume-role QUIET, and makes the wordlist RAISE severity rather than
// GATE reporting. Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const SUBJECT = '123456789012';
const OTHER = '999999999999';
const CERTAINTY = new Set(['high', 'medium', 'low']);
const SEVERITY = ['critical', 'high', 'medium', 'low', 'info'];

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

// ---------------------------------------------------------------------------
// (A) Cross-account scoped sts:AssumeRole.
// ---------------------------------------------------------------------------

test('MUST-CLOSE (A): scoped sts:AssumeRole into another account is a finding, not CLEAN', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${OTHER}:role/X` },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  assert.equal(r.ok, true);
  assert.ok(ids(r).includes('CROSS-ACCOUNT-ASSUME-ROLE'), `expected a cross-account finding; got [${ids(r)}]`);
  assert.equal(isClean(r), false, 'a cross-account scoped assume must NOT read CLEAN');
  const f = findingById(r, 'CROSS-ACCOUNT-ASSUME-ROLE');
  assert.equal(f.severity, 'low', 'surfaced at LOW');
  // The finding must state exploitability depends on the target role's trust policy.
  assert.match(f.why, /trust policy/i);
  assert.match(f.why, /permissions/i);
  // Evidence contract (mirrors evidence.test): certainty tokens + provenance.
  assert.ok(CERTAINTY.has(f.policyEvidence) && CERTAINTY.has(f.pathExploitability));
  assert.ok(/^https:\/\//.test(f.docRef));
  assert.ok(Array.isArray(f.actions) && f.actions.length > 0);
});

test('MUST-STAY-QUIET (A): same-account scoped sts:AssumeRole stays CLEAN', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${SUBJECT}:role/X` },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  assert.deepEqual(ids(r), [], 'same-account scoped assume must be quiet');
  assert.equal(isClean(r), true);
});

test('conservative (A): cross-account scoped assume with UNKNOWN subject stays CLEAN', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${OTHER}:role/X` },
  ]);
  const r = analyze(text); // no subjectAccount
  assert.deepEqual(ids(r), [], 'no subject account -> conservative quiet');
  assert.equal(isClean(r), true);
});

test('KEEP-GREEN (A): a broad/wildcard assume still fires ASSUME-ROLE-EXPANSION (not the low cross-account rule)', () => {
  const text = policy([{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: '*' }]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  assert.ok(ids(r).includes('ASSUME-ROLE-EXPANSION'), 'broad scope still fires the expansion rule');
  assert.ok(!ids(r).includes('CROSS-ACCOUNT-ASSUME-ROLE'), 'a broad scope is not the scoped cross-account shape');
});

test('graph (A): cross-account assume draws a can-assume edge to the cross-account role', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${OTHER}:role/X` },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  const edge = r.graph.edges.find(
    (e) => e.type === 'can-assume' && String(e.to).includes(`${OTHER}:role/X`),
  );
  assert.ok(edge, 'a can-assume edge to the cross-account role must exist');
});

// Iteration-4 regression: a multi-resource sts:AssumeRole statement that lists a
// SAME-account role BEFORE the cross-account role must scope the finding's
// `resources` to the cross-account role ONLY, so the graph builder (which keys the
// can-assume edge off firstResource) draws the edge to the cross-account role and
// draws NO can-assume edge to the same-account role (HYBRID: same-account assume
// stays quiet at the graph layer). Previously `resources` carried the full
// statement scope, so a same-account-first ordering silently dropped the required
// cross-account edge and manufactured a spurious same-account edge.
test('regression (A): mixed same+cross assume (same role listed first) targets the cross-account role edge', () => {
  const text = policy([
    {
      Effect: 'Allow', Action: 'sts:AssumeRole',
      Resource: [`arn:aws:iam::${SUBJECT}:role/Same`, `arn:aws:iam::${OTHER}:role/Cross`],
    },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  const f = findingById(r, 'CROSS-ACCOUNT-ASSUME-ROLE');
  assert.ok(f, 'the cross-account finding still fires');
  // The finding's resources are the cross-account subset only, in policy order.
  assert.deepEqual(f.resources, [`arn:aws:iam::${OTHER}:role/Cross`],
    'resources is scoped to the cross-account role, not the full statement scope');

  const assumeEdges = r.graph.edges.filter((e) => e.type === 'can-assume');
  const toCross = assumeEdges.find((e) => String(e.to).includes(`${OTHER}:role/Cross`));
  assert.ok(toCross, 'a can-assume edge to the cross-account role must exist');
  const toSame = assumeEdges.find((e) => String(e.to).includes(`${SUBJECT}:role/Same`));
  assert.ok(!toSame, 'NO can-assume edge to the same-account role (stays quiet at the graph layer)');
});

test('regression (A): cross-account assume edge target is order-independent', () => {
  const crossFirst = analyze(policy([
    {
      Effect: 'Allow', Action: 'sts:AssumeRole',
      Resource: [`arn:aws:iam::${OTHER}:role/Cross`, `arn:aws:iam::${SUBJECT}:role/Same`],
    },
  ]), { subjectAccount: SUBJECT });
  const sameFirst = analyze(policy([
    {
      Effect: 'Allow', Action: 'sts:AssumeRole',
      Resource: [`arn:aws:iam::${SUBJECT}:role/Same`, `arn:aws:iam::${OTHER}:role/Cross`],
    },
  ]), { subjectAccount: SUBJECT });
  const cf = findingById(crossFirst, 'CROSS-ACCOUNT-ASSUME-ROLE');
  const sf = findingById(sameFirst, 'CROSS-ACCOUNT-ASSUME-ROLE');
  assert.deepEqual(cf.resources, [`arn:aws:iam::${OTHER}:role/Cross`]);
  assert.deepEqual(sf.resources, cf.resources,
    'the cross-account subset is identical regardless of Resource-list ordering');
});

test('regression (A): a statement of TWO cross-account roles lists both, none same-account', () => {
  const THIRD = '111122223333';
  const text = policy([
    {
      Effect: 'Allow', Action: 'sts:AssumeRole',
      Resource: [
        `arn:aws:iam::${SUBJECT}:role/Same`,
        `arn:aws:iam::${OTHER}:role/A`,
        `arn:aws:iam::${THIRD}:role/B`,
      ],
    },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  const f = findingById(r, 'CROSS-ACCOUNT-ASSUME-ROLE');
  assert.deepEqual(f.resources, [`arn:aws:iam::${OTHER}:role/A`, `arn:aws:iam::${THIRD}:role/B`],
    'both cross-account roles are scoped in, the same-account role is excluded');
  const assumeEdges = r.graph.edges.filter((e) => e.type === 'can-assume');
  assert.ok(!assumeEdges.some((e) => String(e.to).includes(`${SUBJECT}:role/Same`)),
    'no can-assume edge to the same-account role');
});

// ---------------------------------------------------------------------------
// (B) Cross-account whole-container reads.
// ---------------------------------------------------------------------------

test('MUST-CLOSE (B): cross-account whole-bucket read + cross-account dynamodb:Scan are findings, not CLEAN', () => {
  const text = policy([
    {
      Effect: 'Allow', Action: 's3:GetObject',
      Resource: `arn:aws:s3:us-east-1:${OTHER}:accesspoint/my-ap/object/*`,
    },
    {
      Effect: 'Allow', Action: 'dynamodb:Scan',
      Resource: `arn:aws:dynamodb:us-east-1:${OTHER}:table/orders`,
    },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  assert.equal(r.ok, true);
  const cross = r.findings.filter((f) => f.id === 'CROSS-ACCOUNT-DATA-READ');
  assert.equal(cross.length, 2, `both cross-account reads surface; got [${ids(r)}]`);
  assert.equal(isClean(r), false, 'cross-account whole-container reads must NOT read CLEAN');
  for (const f of cross) {
    assert.ok(SEVERITY.indexOf(f.severity) >= SEVERITY.indexOf('low'), 'LOW/INFO band');
    assert.ok(/resource policy/i.test(f.why), 'why names the out-of-scope target resource policy');
    assert.ok(CERTAINTY.has(f.policyEvidence) && CERTAINTY.has(f.pathExploitability));
    assert.ok(/^https:\/\//.test(f.docRef));
  }
});

test('MUST-CLOSE (B): a NEUTRALLY-named cross-account whole-bucket read is surfaced (raise, not gate)', () => {
  // A neutral name that matches NO sensitivity token still surfaces cross-account.
  const text = policy([
    {
      Effect: 'Allow', Action: 'dynamodb:Scan',
      Resource: `arn:aws:dynamodb:us-east-1:${OTHER}:table/app-data`,
    },
  ]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ');
  assert.ok(f, 'a neutral name must NOT gate the cross-account read out of the report');
  assert.equal(f.severity, 'info', 'neutral name -> the info floor');
});

test('raise-not-gate (B): a sensitivity-token name RAISES severity above the neutral floor', () => {
  const neutral = analyze(policy([
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: `arn:aws:dynamodb:us-east-1:${OTHER}:table/app-data` },
  ]), { subjectAccount: SUBJECT });
  const sensitive = analyze(policy([
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: `arn:aws:dynamodb:us-east-1:${OTHER}:table/production-backups` },
  ]), { subjectAccount: SUBJECT });
  const nf = findingById(neutral, 'CROSS-ACCOUNT-DATA-READ');
  const sf = findingById(sensitive, 'CROSS-ACCOUNT-DATA-READ');
  assert.ok(nf && sf, 'both fire regardless of name');
  assert.equal(nf.severity, 'info');
  assert.equal(sf.severity, 'low');
  assert.ok(SEVERITY.indexOf(sf.severity) < SEVERITY.indexOf(nf.severity), 'the wordlist RAISES severity');
});

test('MUST-STAY-QUIET (B): same-account whole-container reads stay CLEAN', () => {
  const table = analyze(policy([
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: `arn:aws:dynamodb:us-east-1:${SUBJECT}:table/orders` },
  ]), { subjectAccount: SUBJECT });
  assert.equal(isClean(table), true, 'same-account whole-table read is quiet');

  const ap = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: `arn:aws:s3:us-east-1:${SUBJECT}:accesspoint/my-ap/object/*` },
  ]), { subjectAccount: SUBJECT });
  assert.equal(isClean(ap), true, 'same-account whole-bucket read is quiet');
});

// ---------------------------------------------------------------------------
// (B'') iteration-5 fail-open close: a CANONICAL S3 bucket ARN (arn:aws:s3:::bucket/*)
// carries NO account field, so the owning account was unresolvable and a whole-bucket
// read of another account's bucket read affirmatively CLEAN (findings=[], not-
// incomplete, exit-0 reason=CLEAN) - the archetypal exfil primitive was the one that
// silently cleared. The fix surfaces an account-UNDETERMINED read (info, not-clean)
// so 'complete'/'CLEAN' is never a safety claim on a bare-bucket whole-container read,
// while a single concrete object read and an unknown-subject read stay QUIET, and an
// explicit aws:ResourceAccount / s3:ResourceAccount condition recovers the owner and
// upgrades to a CONFIRMED same/cross classification.
// ---------------------------------------------------------------------------

test('MUST-CLOSE (B\'\'): a neutral accountless bucket/* read must NOT read CLEAN', () => {
  const r = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::other-acct-bucket/*' },
  ]), { subjectAccount: SUBJECT });
  assert.equal(isClean(r), false, 'a bare-bucket whole-container read is not an affirmative CLEAN');
  const f = findingById(r, 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
  assert.ok(f, `the undeterminable-owner read must surface; got [${ids(r)}]`);
  assert.equal(f.severity, 'info', 'the crossing is unproven -> info');
  // It must NOT fabricate a CONFIRMED cross-account claim (T8: no overstated certainty).
  assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ'), 'no confirmed cross-account claim on a bare bucket');
  assert.match(f.why, /cannot be determined|undetermined/i, 'why states the account is undetermined');
  assert.match(f.why, /not.*safety claim|complete/i, 'why states CLEAN is not a safety claim here');
  assert.ok(CERTAINTY.has(f.policyEvidence) && CERTAINTY.has(f.pathExploitability));
  assert.ok(/^https:\/\//.test(f.docRef));
  assert.ok(Array.isArray(f.actions) && f.actions.length > 0);
});

test('MUST-CLOSE (B\'\'): s3:ListBucket and s3:GetObjectVersion on a bare bucket also surface undetermined', () => {
  for (const [action, resource] of [
    ['s3:ListBucket', 'arn:aws:s3:::other-acct-bucket'],
    ['s3:GetObjectVersion', 'arn:aws:s3:::other-acct-bucket/*'],
  ]) {
    const r = analyze(policy([{ Effect: 'Allow', Action: action, Resource: resource }]), { subjectAccount: SUBJECT });
    assert.equal(isClean(r), false, `${action} on a bare bucket must not read CLEAN`);
    assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'), `${action} surfaces undetermined`);
  }
});

test('MUST-STAY-QUIET (B\'\'): a single concrete accountless OBJECT read stays CLEAN', () => {
  const r = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::my-bucket/report.csv' },
  ]), { subjectAccount: SUBJECT });
  assert.equal(isClean(r), true, 'a single concrete object read is not a whole-container read');
});

test('conservative (B\'\'): an accountless bucket/* read with UNKNOWN subject stays CLEAN', () => {
  const r = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::other-acct-bucket/*' },
  ])); // no subjectAccount
  assert.equal(isClean(r), true, 'without a subject account there is nothing to compare against');
  assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'), 'undetermined needs a known subject');
});

test('condition-recovery (B\'\'): aws:ResourceAccount pinning ANOTHER account -> CONFIRMED cross-account read', () => {
  for (const key of ['aws:ResourceAccount', 's3:ResourceAccount']) {
    const r = analyze(policy([
      {
        Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::partner-bucket/*',
        Condition: { StringEquals: { [key]: OTHER } },
      },
    ]), { subjectAccount: SUBJECT });
    assert.equal(isClean(r), false, `${key}=OTHER is not CLEAN`);
    assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ'), `${key} recovers the owner -> a CONFIRMED cross-account read`);
    // Once the owner is recovered it is no longer undetermined.
    assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'), `${key} resolves the account (not undetermined)`);
  }
});

test('condition-recovery (B\'\'): aws:ResourceAccount pinning the SUBJECT account resolves same-account (no cross/undetermined finding)', () => {
  const r = analyze(policy([
    {
      Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::my-bucket/*',
      Condition: { StringEquals: { 'aws:ResourceAccount': SUBJECT } },
    },
  ]), { subjectAccount: SUBJECT });
  // The condition recovers the owner as the SUBJECT account, so the bare-bucket read is
  // resolved to same-account: neither a confirmed cross-account read NOR an account-
  // undetermined read is emitted (the fail-open close does not manufacture a finding
  // once the owner is derivably the subject's own account).
  assert.deepEqual(ids(r), [], 'a resolved same-account read emits no cross-account / undetermined finding');
  // NB: aws:ResourceAccount is not (yet) a modeled condition key, so coverage is
  // independently 'incomplete' - an honest can't-fully-clear state from the unknown
  // key, unrelated to this fix. The invariant here is the ABSENCE of a data-read
  // finding, not a full CLEAN verdict.
});

test('no-masking (B\'\'): a bare bucket read + a dynamodb cross read BOTH surface (neither masked)', () => {
  const r = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::other-acct-bucket/*' },
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: `arn:aws:dynamodb:us-east-1:${OTHER}:table/orders` },
  ]), { subjectAccount: SUBJECT });
  assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ-UNDETERMINED'), 'the S3 bare-bucket read is not masked by the dynamodb finding');
  assert.ok(ids(r).includes('CROSS-ACCOUNT-DATA-READ'), 'the dynamodb confirmed cross read still fires');
});

test('graph (B\'\'): an undetermined bare-bucket read draws a can-read edge naming the undetermined owner', () => {
  const r = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::other-acct-bucket/*' },
  ]), { subjectAccount: SUBJECT });
  const edge = r.graph.edges.find(
    (e) => e.type === 'can-read' && String(e.to).includes('cross-account-undetermined-read'),
  );
  assert.ok(edge, 'a can-read edge for the account-undetermined read must exist (never silently edgeless)');
});

test('parity (B\'\'): scan() never reads clean/exit-0-with-no-finding on a bare-bucket cross read', () => {
  const text = policy([{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::other-acct-bucket/*' }]);
  const a = analyze(text, { subjectAccount: SUBJECT });
  assert.equal(isClean(a), false, 'analyze() is not clean');
  const s = scan({ text, family: 'identity', subjectAccount: SUBJECT });
  assert.ok(s.findingsCount > 0, 'the CLI surfaces the undetermined read (never a silent drop)');
});

test('MUST-STAY-QUIET (B): a single concrete cross-account OBJECT read stays CLEAN', () => {
  const r = analyze(policy([
    {
      Effect: 'Allow', Action: 's3:GetObject',
      Resource: `arn:aws:s3:us-east-1:${OTHER}:accesspoint/my-ap/object/report.csv`,
    },
  ]), { subjectAccount: SUBJECT });
  assert.equal(isClean(r), true, 'a single concrete object read is not a whole-container read');
});

test('KEEP-GREEN (B): a broad bulk read still fires DATA-EXFIL', () => {
  const r = analyze(policy([{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }]), { subjectAccount: SUBJECT });
  assert.ok(ids(r).includes('DATA-EXFIL'), 'broad bulk read still fires DATA-EXFIL');
});

// ---------------------------------------------------------------------------
// (B') iteration-2 fail-open close: a BROAD whole-container read (wildcard resource
// id) in a KNOWN foreign account must surface AT LEAST as loudly as the concrete
// case. Before the fix, widening arn:...:OTHER:stream/events to :OTHER:stream/*
// routed through the resourceIsBroad early-return and read CLEAN - evadable by
// simply broadening the ARN. kinesis:GetRecords is the sharp case: its verb is
// read-classified, so a broad scope does NOT trip WILDCARD-RESOURCE and the policy
// was fully clean.
// ---------------------------------------------------------------------------

test('MUST-CLOSE (B\'): a BROAD cross-account kinesis whole-container read is NOT CLEAN', () => {
  const broad = analyze(policy([
    { Effect: 'Allow', Action: 'kinesis:GetRecords', Resource: `arn:aws:kinesis:us-east-1:${OTHER}:stream/*` },
  ]), { subjectAccount: SUBJECT });
  assert.ok(ids(broad).includes('CROSS-ACCOUNT-DATA-READ'),
    `broad cross-account stream read must surface; got [${ids(broad)}]`);
  assert.equal(isClean(broad), false, 'a broad cross-account whole-container read must NOT read CLEAN');
});

test('MUST-CLOSE (B\'): widening a cross-account read never REMOVES the finding (no evasion)', () => {
  const narrow = analyze(policy([
    { Effect: 'Allow', Action: 'kinesis:GetRecords', Resource: `arn:aws:kinesis:us-east-1:${OTHER}:stream/events` },
  ]), { subjectAccount: SUBJECT });
  const broad = analyze(policy([
    { Effect: 'Allow', Action: 'kinesis:GetRecords', Resource: `arn:aws:kinesis:us-east-1:${OTHER}:stream/*` },
  ]), { subjectAccount: SUBJECT });
  const nf = findingById(narrow, 'CROSS-ACCOUNT-DATA-READ');
  const bf = findingById(broad, 'CROSS-ACCOUNT-DATA-READ');
  assert.ok(nf, 'the narrow read fires');
  assert.ok(bf, 'the strictly-broader read must also fire (never CLEAN while the narrower fires)');
  // The broader read is at least as severe as the narrower one.
  assert.ok(SEVERITY.indexOf(bf.severity) <= SEVERITY.indexOf(nf.severity),
    'the broader read is surfaced at least as loudly as the narrower one');
});

test('raise-not-gate (B\'): a broad cross-account read with a sensitive name RAISES severity, still not gated', () => {
  const neutral = analyze(policy([
    { Effect: 'Allow', Action: 'kinesis:GetRecords', Resource: `arn:aws:kinesis:us-east-1:${OTHER}:stream/*` },
  ]), { subjectAccount: SUBJECT });
  const sensitive = analyze(policy([
    { Effect: 'Allow', Action: 'kinesis:GetRecords', Resource: `arn:aws:kinesis:us-east-1:${OTHER}:stream/production-*` },
  ]), { subjectAccount: SUBJECT });
  const nf = findingById(neutral, 'CROSS-ACCOUNT-DATA-READ');
  const sf = findingById(sensitive, 'CROSS-ACCOUNT-DATA-READ');
  assert.ok(nf && sf, 'both fire regardless of name');
  assert.equal(nf.severity, 'info', 'neutral broad name -> info floor');
  assert.equal(sf.severity, 'low', 'a sensitivity token raises info -> low');
});

test('MUST-STAY-QUIET (B\'): a BROAD SAME-account whole-container read gets NO cross-account finding', () => {
  // Widening a SAME-account read to stream/* must NOT manufacture a cross-account
  // finding (HYBRID: same-account stays quiet). (kinesis:GetRecords is an
  // unrecognized catalog action, so coverage is independently 'incomplete' - an
  // honest can't-fully-clear state unrelated to this fix; the invariant here is the
  // absence of a spurious CROSS-ACCOUNT-DATA-READ.)
  const same = analyze(policy([
    { Effect: 'Allow', Action: 'kinesis:GetRecords', Resource: `arn:aws:kinesis:us-east-1:${SUBJECT}:stream/*` },
  ]), { subjectAccount: SUBJECT });
  assert.ok(!ids(same).includes('CROSS-ACCOUNT-DATA-READ'),
    'a broad SAME-account read must not manufacture a cross-account finding');
});

test('KEEP-GREEN (B\'): a broad accountless S3 bulk read is not a fabricated cross-account read', () => {
  // arn:aws:s3:::my-bucket/* carries no account, so no cross-account claim is
  // fabricated even with a subject present; CROSS-ACCOUNT-DATA-READ must NOT fire.
  const r = analyze(policy([
    { Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::my-bucket/*' },
  ]), { subjectAccount: SUBJECT });
  assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ'),
    'an accountless bucket/* read is not a fabricated cross-account read');
});

test('deny (B): a same-policy Deny removes the cross-account read from the authoritative table', () => {
  const r = analyze(policy([
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: `arn:aws:dynamodb:us-east-1:${OTHER}:table/orders` },
    { Effect: 'Deny', Action: 'dynamodb:Scan', Resource: '*' },
  ]), { subjectAccount: SUBJECT });
  assert.ok(!ids(r).includes('CROSS-ACCOUNT-DATA-READ'), 'a denied read is not a surviving capability');
});

// ---------------------------------------------------------------------------
// Browser <-> CLI parity + determinism.
// ---------------------------------------------------------------------------

test('parity: scan() never reads clean/exit-0-with-no-finding on the cross-account cases', () => {
  const cases = [
    policy([{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${OTHER}:role/X` }]),
    policy([{ Effect: 'Allow', Action: 'dynamodb:Scan', Resource: `arn:aws:dynamodb:us-east-1:${OTHER}:table/orders` }]),
  ];
  for (const text of cases) {
    const a = analyze(text, { subjectAccount: SUBJECT });
    assert.equal(isClean(a), false, 'analyze() is not clean');
    const s = scan({ text, family: 'identity', subjectAccount: SUBJECT });
    // The finding is present in the CLI report (findingsCount > 0), so the CLI never
    // silently drops the candidate policy even though a LOW/INFO finding sits under
    // the default 'high' gate.
    assert.ok(s.findingsCount > 0, 'the CLI surfaces the cross-account finding');
    assert.notEqual(s.exitCode, undefined);
  }
});

test('determinism: cross-account findings are byte-identical across two runs', () => {
  const text = policy([
    { Effect: 'Allow', Action: 'sts:AssumeRole', Resource: `arn:aws:iam::${OTHER}:role/X` },
    { Effect: 'Allow', Action: 'dynamodb:Scan', Resource: `arn:aws:dynamodb:us-east-1:${OTHER}:table/production-backups` },
  ]);
  const opts = { subjectAccount: SUBJECT };
  assert.equal(
    JSON.stringify(analyze(text, opts).findings),
    JSON.stringify(analyze(text, opts).findings),
  );
});
