// S5-partition-parity — PassRole viability must fail CLOSED on a DEFAULTED (absent)
// SUBJECT partition, so the browser is never MORE permissive than the CLI.
//
// Regression for a HIGH browser>CLI parity break of the SAME class as the non-canonical
// SUBJECT partition axis (passrole-noncanonical-subject-partition.test.js), reached
// through the ABSENT case. The browser (primary UI) forwards subjectAccount but NO
// partition (app.js/worker.js -> analyze({ subjectAccount })). The engine defaulted
// ctx.partition to 'aws' AND treated that DEFAULT as a confidently-known partition
// (partitionKnown was true when the raw token was ''), so a same-account aws-us-gov role
// was read as cross-partition and CONFIDENTLY demoted critical->medium (PARTITION_MISMATCH)
// with a false "principal is in partition aws ... NOT a viable path" why and coverage
// complete/confident. The CLI scan() adapter, by contrast, sanitized the (absent)
// partition and correctly reported analysisStatus=partial / exit 3 /
// requiredUnknowns:['subjectPartition']. analyze() was therefore MORE permissive than
// scan() for byte-identical no-partition input (threat-model T8, browser==CLI parity).
//
// The fix lives in the shared engine (the single source of truth): an ABSENT partition
// is a DEFAULTED partition, NOT a confidently-supplied one - it fails CLOSED as
// unknown-viability EXACTLY like a non-canonical token, and never drives a confident
// cross-partition demotion. An EXPLICITLY-supplied canonical partition still demotes /
// clears confidently. Every shape is driven through the REAL boundary on BOTH surfaces:
// the shipped engine analyze() (the browser path) AND the CLI fail-closed adapter scan().
//   (A) a genuinely VIABLE aws same-account path with NO partition stays CRITICAL /
//       scan exit 1 (account reasoning defaults to 'aws'; the path is genuinely viable);
//   (B) an aws-us-gov same-account role with NO partition fails CLOSED as UNKNOWN
//       viability (critical + requiredUnknowns:['subjectPartition'] / scan exit 3),
//       never a confident PARTITION_MISMATCH medium.
// Explicit-partition controls prove no over-correction: an EXPLICIT 'aws' subject still
// confidently demotes the aws-us-gov role to medium (PARTITION_MISMATCH, scan clean), and
// an EXPLICIT 'aws-us-gov' subject is viable/critical/exit 1.
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
    'passrole-defaulted-subject-partition-same-account.json'),
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
function warningCodes(f) {
  return (f && f.escalation && f.escalation.warningCodes) || [];
}

// --- (A) Viable aws same-account path with NO partition: CRITICAL, never demoted. ------
{
  const text = policyFor(fixture.viableSameAccount);
  const want = fixture.expect.viableSameAccount;

  test('viable aws path with DEFAULTED (absent) partition stays critical, no confident demotion', () => {
    // The browser path: NO partition option supplied at all.
    const res = analyze(text, { subjectAccount });
    assert.equal(res.ok, true, 'analyze() ok');
    const f = passroleFinding(res);
    assert.ok(f, 'the PassRole path fires');
    assert.equal(f.severity, want.defaultedPartition.analyzeSeverity,
      'a viable same-account aws pass with no partition must stay critical (account reasoning defaults to aws)');
    for (const code of want.defaultedPartition.mustNotHaveWarningCode) {
      assert.ok(!warningCodes(f).includes(code),
        `must NOT assert a confident ${code} demotion on a viable same-account aws path`);
    }
  });

  test('viable aws path: analyze() (browser) is NOT more permissive than scan() (CLI) with NO partition', () => {
    // The exact parity invariant: byte-identical no-partition input must not read cleaner
    // via analyze() (the browser path) than via the CLI scan() adapter.
    const r = scan({ family: 'identity', subjectAccount, text });
    assert.equal(r.exitCode, want.defaultedPartition.scanExitCode, 'scan() gates the viable path at exit 1');
    const f = passroleFinding(analyze(text, { subjectAccount }));
    assert.equal(f.severity, 'critical',
      'analyze() must not be more permissive (medium-only) than scan() for byte-identical no-partition input');
  });
}

// --- (B) Cross-partition same-account role with NO partition: fail CLOSED (unknown). ---
{
  const text = policyFor(fixture.crossPartitionSameAccount);
  const want = fixture.expect.crossPartitionSameAccount;

  test('aws-us-gov role + DEFAULTED (absent) partition fails CLOSED as unknown, never confident medium', () => {
    // The reproduced parity break: browser confidently demoted this to medium; it must
    // instead stay critical and be marked unknown-viability, exactly as the CLI reports.
    const res = analyze(text, { subjectAccount });
    assert.equal(res.ok, true, 'analyze() ok');
    const f = passroleFinding(res);
    assert.ok(f, 'the PassRole path fires');
    assert.equal(f.severity, want.defaultedPartition.analyzeSeverity,
      'a same-account cross-partition role under a DEFAULTED partition must NOT be confidently demoted');
    for (const code of want.defaultedPartition.mustNotHaveWarningCode) {
      assert.ok(!warningCodes(f).includes(code),
        `must NOT assert a confident ${code} demotion against a DEFAULTED subject partition`);
    }
    const esc = f.escalation || {};
    assert.ok(
      Array.isArray(esc.requiredUnknowns)
        && esc.requiredUnknowns.includes(want.defaultedPartition.requiredUnknown),
      `must record requiredUnknowns:['${want.defaultedPartition.requiredUnknown}'] so the fail-closed guard fires on both paths`,
    );
  });

  test('aws-us-gov role + DEFAULTED (absent) partition: scan() NEVER reports exit 0 CLEAN', () => {
    const r = scan({ family: 'identity', subjectAccount, text });
    assert.notEqual(r.exitCode, want.defaultedPartition.scanExitCodeNot, 'must not be exit 0');
    assert.equal(r.exitCode, want.defaultedPartition.scanExitCode, 'fails closed as UNKNOWN_VIABILITY (exit 3)');
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED);
  });

  test('parity: analyze() (browser) not more permissive than scan() (CLI) on the no-partition PassRole input', () => {
    // The headline S5 assertion: the reproduced input {aws-us-gov PassRole ; ec2:RunInstances}
    // with NO partition. scan() fails closed (exit 3); analyze() must reflect the same
    // unknown viability (critical, not a confident medium demotion, requiredUnknowns set).
    const r = scan({ family: 'identity', subjectAccount, text });
    const f = passroleFinding(analyze(text, { subjectAccount }));
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'CLI fails closed (exit 3)');
    assert.notEqual(f.severity, 'medium',
      'browser must not confidently demote to medium while the CLI fails closed');
    assert.ok((f.escalation.requiredUnknowns || []).includes('subjectPartition'),
      'browser surfaces the SAME unknown viability (subjectPartition) the CLI does');
  });

  // --- Explicit-partition controls: no over-correction. -------------------------------
  test('explicit aws subject still confidently demotes the aws-us-gov role (no over-correction)', () => {
    const p = want.explicitAwsControl;
    const res = analyze(text, { subjectAccount, partition: p.partition });
    const f = passroleFinding(res);
    assert.ok(f);
    assert.equal(f.severity, p.analyzeSeverity, 'an EXPLICITLY-known cross-partition subject still demotes to medium');
    for (const code of p.mustHaveWarningCode) {
      assert.ok(warningCodes(f).includes(code), `explicit-aws control must carry ${code}`);
    }
    const esc = f.escalation || {};
    assert.ok(!(esc.requiredUnknowns && esc.requiredUnknowns.length),
      'an EXPLICIT partition is a confident demotion, not unknown-viability');
    const r = scan({ family: 'identity', subjectAccount, partition: p.partition, text });
    assert.equal(r.exitCode, p.scanExitCode, 'explicit-aws demoted medium is below the high threshold (scan clean)');
  });

  test('explicit aws-us-gov subject is viable critical (no over-correction)', () => {
    const p = want.explicitRealPartitionControl;
    const res = analyze(text, { subjectAccount, partition: p.partition });
    const f = passroleFinding(res);
    assert.ok(f);
    assert.equal(f.severity, p.analyzeSeverity);
    const esc = f.escalation || {};
    assert.ok(!(esc.requiredUnknowns && esc.requiredUnknowns.length),
      'a confidently viable same-partition pass must NOT be marked unknown-viability');
    const r = scan({ family: 'identity', subjectAccount, partition: p.partition, text });
    assert.equal(r.exitCode, p.scanExitCode);
    assert.equal(r.exitCode, EXIT.FINDINGS);
  });
}

// --- Determinism (architecture invariant #8). ----------------------------------------
test('deterministic findings for the DEFAULTED-partition cross-partition input', () => {
  const text = policyFor(fixture.crossPartitionSameAccount);
  const a = JSON.stringify(analyze(text, { subjectAccount }).findings);
  const b = JSON.stringify(analyze(text, { subjectAccount }).findings);
  assert.equal(a, b);
});
