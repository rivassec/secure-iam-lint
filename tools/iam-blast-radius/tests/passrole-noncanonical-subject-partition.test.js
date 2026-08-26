// S2-passrole-allstmts (SUBJECT axis) — PassRole viability must fail CLOSED on a
// non-canonical SUBJECT partition token.
//
// Regression for a HIGH fail-open of the SAME class as the ARN-spelling / statement-ORDER
// demotions, reached through the OTHER side of the exact-equality partition compare: the
// SUBJECT partition (ctx.partition). The role-ARN partition/account tokens are validated
// against KNOWN_PARTITIONS / 12-digit, but the subject partition was trusted VERBATIM
// (only .trim()). A non-canonical spelling of the subject's OWN partition ('AWS', 'Aws',
// '*', 'aws-gov', 'AWS-US-GOV', ...) therefore made a viable same-account, same-real-
// partition critical PassRole->service path read as cross-partition and get CONFIDENTLY
// demoted critical->medium (PARTITION_MISMATCH): analyze() rated the path MEDIUM while
// scan() - which sanitizes the partition against KNOWN_PARTITIONS - kept it CRITICAL /
// exit 1, so analyze() was MORE permissive than scan() for byte-identical input (the
// browser==CLI parity invariant), and the sole medium finding slips under a high-threshold
// gate as CLEAN (threat-model T8).
//
// The fix lives in the shared engine (the single source of truth): ctx.partition is
// validated with the SAME KNOWN_PARTITIONS rigor as role-ARN partitions, and an
// unrecognized/non-canonical subject partition token NEVER drives a confident cross-
// partition demotion. Two shapes are driven through the real engine (analyze()) AND the
// CLI fail-closed adapter (scan()):
//   (A) a genuinely VIABLE aws same-account path stays CRITICAL / scan exit 1 under every
//       non-canonical partition (account reasoning defaults to 'aws'; no demotion needed);
//   (B) an aws-us-gov same-account role under a non-canonical subject partition fails
//       CLOSED as UNKNOWN viability (critical + requiredUnknowns:['subjectPartition'] /
//       scan exit 3), never a confident PARTITION_MISMATCH medium.
// Canonical controls confirm the fix did not over-correct: the real 'aws' / 'aws-us-gov'
// partition still yields the correct viable/critical/exit-1 verdict.
//
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(readFileSync(
  join(here, '..', 'fixtures', 'order-invariance',
    'passrole-noncanonical-subject-partition-same-account.json'),
  'utf8',
));

const findingId = fixture.expect.findingId;
const subjectAccount = fixture.subjectAccount;

function policyFor(shape) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [shape.passStatement, shape.runStatement],
  });
}
function passroleFinding(res) {
  return (res.findings || []).find((f) => f.id === findingId);
}

// --- (A) Viable aws same-account path: CRITICAL under every non-canonical partition. --
{
  const shape = fixture.viableSameAccount;
  const text = policyFor(shape);
  const want = fixture.expect.viableSameAccount;

  for (const partition of fixture.nonCanonicalPartitions) {
    test(`viable aws path stays critical, no confident demotion [partition=${JSON.stringify(partition)}]`, () => {
      const res = analyze(text, { subjectAccount, partition });
      assert.equal(res.ok, true, 'analyze() ok');
      const f = passroleFinding(res);
      assert.ok(f, `${findingId} must be present (never demoted-then-dropped)`);
      assert.equal(f.severity, want.everyNonCanonicalPartition.analyzeSeverity,
        'a viable same-account pass must stay critical; a non-canonical subject partition '
        + 'must NOT confidently demote it critical->medium');
      const esc = f.escalation || {};
      for (const code of want.everyNonCanonicalPartition.mustNotHaveWarningCode) {
        assert.ok(
          !(esc.warningCodes || []).includes(code),
          `must NOT assert a confident ${code} demotion against a non-canonical subject partition`,
        );
      }
    });

    test(`viable aws path: analyze() is NOT more permissive than scan() [partition=${JSON.stringify(partition)}]`, () => {
      // The exact parity invariant: byte-identical input must not read cleaner via analyze()
      // than via the partition-sanitizing scan() adapter. scan() gates it at exit 1.
      const r = scan({ family: 'identity', subjectAccount, partition, text });
      assert.equal(r.exitCode, want.everyNonCanonicalPartition.scanExitCode,
        'scan() gates the viable path at exit 1');
      assert.equal(r.exitCode, EXIT.FINDINGS);
      // analyze() must be at least as strict: a critical finding fires the same gate.
      const f = passroleFinding(analyze(text, { subjectAccount, partition }));
      assert.equal(f.severity, 'critical',
        'analyze() must not be more permissive (medium-only) than scan() for byte-identical input');
    });
  }

  test('viable aws path: canonical control (partition=aws) is a plain critical finding', () => {
    const res = analyze(text, { subjectAccount, partition: want.canonicalPartition });
    const f = passroleFinding(res);
    assert.ok(f);
    assert.equal(f.severity, want.canonicalControl.analyzeSeverity);
    const esc = f.escalation || {};
    assert.ok(!(esc.requiredUnknowns && esc.requiredUnknowns.length),
      'a confidently viable same-account pass must NOT be marked unknown-viability');
    const r = scan({ family: 'identity', subjectAccount, partition: want.canonicalPartition, text });
    assert.equal(r.exitCode, want.canonicalControl.scanExitCode);
    assert.equal(r.exitCode, EXIT.FINDINGS);
  });
}

// --- (B) Cross-partition same-account role: fail CLOSED (unknown), never confident medium.
{
  const shape = fixture.crossPartitionSameAccount;
  const text = policyFor(shape);
  const want = fixture.expect.crossPartitionSameAccount;

  for (const partition of fixture.nonCanonicalPartitions) {
    test(`cross-partition role + non-canonical subject partition fails CLOSED as unknown [partition=${JSON.stringify(partition)}]`, () => {
      const res = analyze(text, { subjectAccount, partition });
      const f = passroleFinding(res);
      assert.ok(f, `${findingId} present`);
      assert.equal(f.severity, want.everyNonCanonicalPartition.analyzeSeverity,
        'severity is KEPT (unknown viability), never a below-threshold medium');
      const esc = f.escalation || {};
      for (const code of want.everyNonCanonicalPartition.mustNotHaveWarningCode) {
        assert.ok(
          !(esc.warningCodes || []).includes(code),
          `must NOT assert a confident ${code} demotion against a non-canonical subject partition`,
        );
      }
      assert.ok(
        Array.isArray(esc.requiredUnknowns)
          && esc.requiredUnknowns.includes(want.everyNonCanonicalPartition.requiredUnknown),
        `must record requiredUnknowns:['${want.everyNonCanonicalPartition.requiredUnknown}'] so the fail-closed guard fires`,
      );
    });

    test(`cross-partition role: scan() NEVER reports exit 0 CLEAN [partition=${JSON.stringify(partition)}]`, () => {
      const r = scan({ family: 'identity', subjectAccount, partition, text });
      assert.notEqual(r.exitCode, want.everyNonCanonicalPartition.scanExitCodeNot, 'must not be exit 0');
      assert.notEqual(r.exitCode, EXIT.CLEAN, 'must not be CLEAN exit');
      assert.notEqual(r.reason, 'CLEAN', 'reason must not be CLEAN');
      assert.equal(r.exitCode, want.everyNonCanonicalPartition.scanExitCode,
        'fails closed as UNKNOWN_VIABILITY (exit 3)');
      assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
    });
  }

  test('cross-partition role: canonical control (subject really aws-us-gov) is viable critical / exit 1', () => {
    const res = analyze(text, { subjectAccount, partition: want.realPartition });
    const f = passroleFinding(res);
    assert.ok(f);
    assert.equal(f.severity, want.realPartitionControl.analyzeSeverity);
    const esc = f.escalation || {};
    assert.ok(!(esc.requiredUnknowns && esc.requiredUnknowns.length),
      'a confidently viable same-partition pass must NOT be marked unknown-viability');
    const r = scan({ family: 'identity', subjectAccount, partition: want.realPartition, text });
    assert.equal(r.exitCode, want.realPartitionControl.scanExitCode);
    assert.equal(r.exitCode, EXIT.FINDINGS);
  });

  test('cross-partition role: real cross-partition subject (aws) still confidently demotes (no over-correction)', () => {
    // The fix must NOT suppress a GENUINE partition mismatch: a subject confidently in
    // 'aws' passing an aws-us-gov role is a real cross-partition non-viability -> medium
    // + PARTITION_MISMATCH, scan clean (this is T91-06's contract, preserved).
    const res = analyze(text, { subjectAccount, partition: 'aws' });
    const f = passroleFinding(res);
    assert.ok(f);
    assert.equal(f.severity, 'medium', 'a confidently-known cross-partition subject still demotes');
    assert.ok((f.escalation.warningCodes || []).includes('PARTITION_MISMATCH'));
  });
}

// --- Determinism (architecture invariant #8). ----------------------------------------
test('deterministic findings for a fixed non-canonical subject partition', () => {
  const text = policyFor(fixture.crossPartitionSameAccount);
  const a = JSON.stringify(analyze(text, { subjectAccount, partition: 'AWS' }).findings);
  const b = JSON.stringify(analyze(text, { subjectAccount, partition: 'AWS' }).findings);
  assert.equal(a, b);
});
