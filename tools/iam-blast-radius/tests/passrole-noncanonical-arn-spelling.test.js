// S2-passrole-allstmts (ARN-spelling axis) — PassRole viability must fail CLOSED on
// a non-canonical SAME-account role ARN spelling.
//
// Regression for a HIGH fail-open of the SAME class as the statement-ORDER demotion,
// reached through ARN SPELLING instead of ordering (threat-model T8). A PassRole
// target ARN's partition/account tokens are extracted with a lenient, case-insensitive
// regex, but same-vs-cross-account viability was decided with EXACT string equality.
// So a role in the subject's OWN account written non-canonically (uppercase/mixed-case
// partition, embedded whitespace/tab, a space after a colon, or a non-12-digit account
// token) failed the exact match, was judged cross-account/cross-partition NOT-viable,
// demoted critical->medium (PASSROLE_CROSS_ACCOUNT_INCOMPATIBLE / PARTITION_MISMATCH)
// and slipped under the default 'high' exit gate to exit 0 CLEAN — order-independent,
// no decoy required.
//
// The fix treats an UNMODELABLE partition/account token (partition not a recognized
// AWS partition, account not a bare 12-digit id, once wildcards are excluded) as
// UNKNOWN viability: the engine keeps the finding at critical (never a below-threshold
// medium) and records requiredUnknowns so scan() fails CLOSED (exit 3 UNKNOWN_VIABILITY)
// instead of reporting CLEAN. This test drives every non-canonical spelling through the
// real engine (analyze()) AND the CLI fail-closed adapter (scan()) and asserts scan()
// NEVER returns exit 0 CLEAN, with analyze() never emitting a confident cross-account /
// partition demotion. A canonical control confirms the fix did not over-correct into a
// false positive, and an order block confirms the fix is statement-order-independent.
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
    'passrole-noncanonical-arn-spelling-same-account.json'),
  'utf8',
));

const ctx = fixture.context;
const want = fixture.expect;
const findingId = want.findingId;

function policyFor(passResource) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [fixture.runStatement, {
      Sid: 'Pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: passResource,
    }],
  });
}

function statementFor(token) {
  if (token === 'run') return fixture.runStatement;
  const s = fixture[token];
  assert.ok(s, `fixture ordering references unknown token "${token}"`);
  return s;
}

const analyzeOpts = { subjectAccount: ctx.subjectAccount, partition: ctx.partition };
const scanBase = { family: 'identity', subjectAccount: ctx.subjectAccount, partition: ctx.partition };

// --- Each non-canonical same-account spelling must fail CLOSED, never CLEAN. ----
for (const [name, resource] of Object.entries(fixture.variants)) {
  const text = policyFor(resource);

  test(`analyze(): non-canonical same-account ARN stays critical, no confident demotion [${name}]`, () => {
    const res = analyze(text, analyzeOpts);
    assert.equal(res.ok, true, 'analyze() ok');
    const f = (res.findings || []).find((x) => x.id === findingId);
    assert.ok(f, `${findingId} must be present (never demoted-then-dropped) [${name}]`);
    assert.equal(f.severity, want.everyVariant.analyzeSeverity,
      `must stay ${want.everyVariant.analyzeSeverity} — an unmodelable token is UNKNOWN, not a confident cross-account medium [${name}]`);
    const esc = f.escalation || {};
    for (const code of want.everyVariant.mustNotHaveWarningCode) {
      assert.ok(
        !(esc.warningCodes || []).includes(code),
        `must NOT assert a confident ${code} demotion on an unmodelable same-account ARN [${name}]`,
      );
    }
    // The unknown-viability signal that makes scan() fail closed must be present.
    assert.ok(
      Array.isArray(esc.requiredUnknowns) && esc.requiredUnknowns.length > 0,
      `must record requiredUnknowns so the fail-closed guard fires [${name}]`,
    );
  });

  test(`scan(): non-canonical same-account ARN NEVER reports exit 0 CLEAN [${name}]`, () => {
    const r = scan({ ...scanBase, text });
    assert.notEqual(r.exitCode, 0, `must not be exit 0 [${name}]`);
    assert.notEqual(r.exitCode, EXIT.CLEAN, `must not be CLEAN exit [${name}]`);
    assert.notEqual(r.reason, 'CLEAN', `reason must not be CLEAN [${name}]`);
    // Fails closed as UNKNOWN_VIABILITY (exit 3), the honest verdict for a token we
    // cannot model — never a below-threshold medium slipping under the 'high' gate.
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED, `must fail closed (exit 3) [${name}]`);
  });

  // The variant must reproduce the ORIGINAL fail-open under the OLD contract, i.e. the
  // exact string mismatch is what would have demoted it — proving the test bites.
  test(`sanity: variant is genuinely same-account and non-canonical [${name}]`, () => {
    assert.notEqual(resource, fixture.canonicalControl.Resource, `${name} must differ from canonical`);
    assert.ok(resource.includes(ctx.subjectAccount) || /iam::\s*\d/i.test(resource),
      `${name} must reference the subject account (possibly non-canonically)`);
  });
}

// --- Canonical control: the fix did NOT over-correct into a false positive. ------
test('scan(): canonical same-account ARN still gates at exit 1 (no over-correction)', () => {
  const r = scan({ ...scanBase, text: policyFor(fixture.canonicalControl.Resource) });
  assert.equal(r.exitCode, want.canonicalControl.scanExitCode);
  assert.equal(r.exitCode, EXIT.FINDINGS);
});

test('analyze(): canonical same-account ARN is a plain critical finding, no requiredUnknowns', () => {
  const res = analyze(policyFor(fixture.canonicalControl.Resource), analyzeOpts);
  const f = (res.findings || []).find((x) => x.id === findingId);
  assert.ok(f);
  assert.equal(f.severity, want.canonicalControl.analyzeSeverity);
  const esc = f.escalation || {};
  assert.ok(!(esc.requiredUnknowns && esc.requiredUnknowns.length),
    'a confidently viable same-account pass must NOT be marked unknown-viability');
});

// --- Order independence: canonical cross-account decoy vs unmodelable same-account.
for (const ordering of fixture.orderings) {
  const label = ordering.join(' -> ');
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: ordering.map(statementFor),
  });

  test(`scan(): fails closed (never CLEAN) regardless of statement order [${label}]`, () => {
    const r = scan({ ...scanBase, text });
    assert.notEqual(r.exitCode, EXIT.CLEAN, 'must never report CLEAN');
    assert.equal(r.exitCode, EXIT.FAIL_CLOSED,
      'unmodelable same-account grant outranks a canonical cross-account decoy in every order');
  });

  test(`analyze(): finding stays critical regardless of statement order [${label}]`, () => {
    const res = analyze(text, analyzeOpts);
    const f = (res.findings || []).find((x) => x.id === findingId);
    assert.ok(f, `${findingId} present [${label}]`);
    assert.equal(f.severity, 'critical', `severity for ordering [${label}]`);
  });
}

// --- Determinism (architecture invariant #8). ----------------------------------
test('analyze(): deterministic findings for a fixed non-canonical spelling', () => {
  const text = policyFor(fixture.variants.uppercasePartition);
  const a = JSON.stringify(analyze(text, analyzeOpts).findings);
  const b = JSON.stringify(analyze(text, analyzeOpts).findings);
  assert.equal(a, b);
});
