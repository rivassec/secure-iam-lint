// S1-dataexfil-arn (iteration 4 BLOCKER): the account-wildcard fail-open.
//
// A broad ARN-wildcard resource "reaches across the account/service boundary".
// The account-WILDCARD case was closed only when the resource IDENTIFIER was
// empty or itself leading-wildcard: pairing a wildcard ACCOUNT segment ('*'/'?')
// with a CONCRETE-prefixed identifier ('role/deployment/*', 'role/app-*',
// 'function:svc-*', 'secret:app/*') escaped every broadness branch -
// isBroadArnResource's account-wildcard branch demanded resourceId==='' ||
// leading-wildcard, the type-prefix branch only inspected the (concrete) first
// identifier segment, and the finite semantic probe battery (single IAM-role
// probe pinned to path /platform/) matched 0 probes. Result: analyze() ok:true
// findings=[] and scan() exit 0 CLEAN on a grant that reaches EVERY account in
// the partition - a fail-OPEN (threat-model T8), internally inconsistent with the
// must-warn corpus that locks arn:aws:iam::*:role/* as WILDCARD-RESOURCE/high.
//
// The fix: isBroadArnResource treats a leading-wildcard ACCOUNT segment ('*'/'?')
// as account-crossing/broad INDEPENDENT of how the resource identifier is scoped.
// A concrete-prefixed identifier does not re-narrow a wildcard account back to one
// account. A CONCRETE account keeps the grant single-account, so a trailing
// name/path wildcard behind a concrete account stays quiet (no over-firing).
//
// This suite double-locks the class through the SHIPPED engine analyze() AND the
// CLI scan(), and asserts the parity invariant (analyze() is never more permissive
// than scan()). Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../cli/scan.mjs';

const BROAD_IDS = new Set(['DATA-EXFIL', 'WILDCARD-RESOURCE']);

function policyText(action, resource) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'S', Effect: 'Allow', Action: action, Resource: resource }],
  });
}

function findingIds(result) {
  return result.ok ? result.findings.map((f) => f.id) : [];
}

// Wildcard ACCOUNT ('*' or '?') + a CONCRETE-prefixed resource identifier. Each is
// account-crossing and must fire a broad-resource finding on BOTH paths. The exact
// blocker input is the first entry.
const ACCOUNT_WILDCARD_FAILOPENS = [
  ['iam:PassRole', 'arn:aws:iam::*:role/deployment/*'],
  ['iam:PassRole', 'arn:aws:iam::*:role/app-*'],
  ['iam:PassRole', 'arn:aws:iam::*:role/a*'],
  ['iam:PassRole', 'arn:aws:iam::?:role/deployment/*'],
  ['lambda:UpdateFunctionCode', 'arn:aws:lambda:*:*:function:svc-*'],
  ['secretsmanager:PutSecretValue', 'arn:aws:secretsmanager:*:*:secret:app/*'],
  // Unknown-to-the-catalog service (ecr) still surfaces the broad resource on
  // analyze(); scan() fails CLOSED (non-zero) rather than reporting clean.
  ['ecr:PutImage', 'arn:aws:ecr:*:*:repository/team-*'],
];

test('account-wildcard + concrete identifier fires a broad-resource finding on analyze() (fail-CLOSED)', () => {
  for (const [action, resource] of ACCOUNT_WILDCARD_FAILOPENS) {
    const result = analyze(policyText(action, resource));
    assert.equal(result.ok, true, `analyze(${resource}) should analyze; errors ${JSON.stringify(result.errors)}`);
    const ids = findingIds(result);
    const broad = ids.filter((id) => BROAD_IDS.has(id));
    assert.ok(
      broad.length >= 1,
      `${resource}: expected a broad-resource finding (fail-open, T8); got [${ids.join(', ')}]`,
    );
    for (const f of result.findings.filter((x) => BROAD_IDS.has(x.id))) {
      assert.equal(f.severity, 'high', `${resource}: ${f.id} must be high; got ${f.severity}`);
    }
  }
});

test('account-wildcard + concrete identifier drives a NON-ZERO CLI exit (never clean)', () => {
  for (const [action, resource] of ACCOUNT_WILDCARD_FAILOPENS) {
    const r = scan({ text: policyText(action, resource), family: 'identity' });
    assert.notEqual(
      r.exitCode,
      EXIT.CLEAN,
      `${resource}: scan() must NOT exit 0/clean on a broad account-crossing grant (fail-open, T8); got exit ${r.exitCode}`,
    );
  }
});

test('PARITY: analyze() is never more permissive than scan() on the account-wildcard class', () => {
  for (const [action, resource] of ACCOUNT_WILDCARD_FAILOPENS) {
    const a = analyze(policyText(action, resource));
    const s = scan({ text: policyText(action, resource), family: 'identity' });
    const analyzeFlags = findingIds(a).some((id) => BROAD_IDS.has(id));
    const scanClean = s.exitCode === EXIT.CLEAN;
    // If analyze flags the grant broad, scan must not read it clean.
    assert.ok(
      !(analyzeFlags && scanClean),
      `${resource}: analyze() flagged broad but scan() exited clean - parity violation / browser-more-permissive`,
    );
  }
});

// A CONCRETE account keeps the grant single-account: a trailing name/path wildcard
// behind it is scoped and must stay QUIET (no over-firing). Mirrors the wildcard
// cases above with the account pinned to 123456789012.
const CONCRETE_ACCOUNT_NEGATIVES = [
  ['iam:PassRole', 'arn:aws:iam::123456789012:role/deployment/*'],
  ['iam:PassRole', 'arn:aws:iam::123456789012:role/app-*'],
  ['lambda:UpdateFunctionCode', 'arn:aws:lambda:us-east-1:123456789012:function:svc-*'],
  ['secretsmanager:PutSecretValue', 'arn:aws:secretsmanager:us-east-1:123456789012:secret:app/*'],
];

test('concrete-account name/path prefixes stay QUIET (no WILDCARD-RESOURCE over-firing)', () => {
  for (const [action, resource] of CONCRETE_ACCOUNT_NEGATIVES) {
    const result = analyze(policyText(action, resource));
    assert.equal(result.ok, true, `analyze(${resource}) should analyze cleanly`);
    const ids = findingIds(result);
    assert.ok(
      !ids.includes('WILDCARD-RESOURCE'),
      `${resource}: single-account prefix must NOT fire WILDCARD-RESOURCE (over-firing); got [${ids.join(', ')}]`,
    );
  }
});

test('account-wildcard analysis is deterministic (same input -> deep-equal twice)', () => {
  for (const [action, resource] of ACCOUNT_WILDCARD_FAILOPENS) {
    const text = policyText(action, resource);
    assert.deepEqual(analyze(text), analyze(text), `${resource}: analyze() must be deterministic`);
  }
});
