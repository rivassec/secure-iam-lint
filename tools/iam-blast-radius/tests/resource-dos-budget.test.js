// S3-dos-budget-all (iteration 5): close the DoS class in the RESOURCE-family
// evaluator (engine/resource.js), the 3042-line surface the earlier iterations left
// with only two chargeWork sites. Two confirmed within-caps, validate-passing resource
// policies drove analyze() into UNCHARGED O(V^2) loops (T5/T8 fail-open DoS - a
// multi-second grind that the deterministic work budget could not sample because the
// loops never reached the shared matcher, the only prior charge point):
//
//   (HIGH)   sourceBindingAnalysis over aws:SourceArn / aws:SourceAccount condition
//            value arrays: sourceAccountSet()'s Array.includes() dedup (resource.js),
//            the per-operator account-set merge, and the SourceArn-vs-SourceAccount
//            disjoint-set scan were each O(V^2) and charged zero. A within-caps
//            resource policy (V=22000, 968 KB, validate.ok) took ~2741 ms.
//   (MEDIUM) the KMS/named-principal dedup filters
//            (namedEntries.filter(e => !acctEntries.includes(e)) and the same-account
//            partition) were O(V^2) over an attacker-sized Principal.AWS list and
//            charged zero; workLimit far above any real budget did NOT abort them.
//
// The fix (mirroring the trust.js / escalation.js approach, NOT a validate.js count cap
// - Principal / Condition counts stay deliberately UNCAPPED per the established
// trustdeny-principal-scan-budget contract): replace every O(V^2) Array.includes()
// dedup with Set membership (-> O(V)) AND charge the deterministic work budget for the
// traversal so it PARTICIPATES (a tight workLimit now aborts; the default budget keeps
// legitimate policies complete). Each pathological-but-within-caps input MUST now
// complete under a fixed ms budget or fail CLOSED, and the small/legit cases MUST NOT
// over-correct into a false fail-closed or lose their finding.
//
// Runs on node's built-in runner: `node --test`.

import test from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';

// Boundedness ("the O(V^2) grind is gone") is asserted via the DETERMINISTIC op-count
// work budget (coverage.summary.analysisAborted === false: a run that completes stayed
// under the fixed DEFAULT_WORK_LIMIT, and an O(V^2) regression at these V would exceed it
// and abort), NOT an absolute wall-clock ceiling. The pre-fix HIGH repro took ~2741 ms
// single-threaded; a fixed ms ceiling on such an input flakes under the runner's default
// file-level parallelism (CPU contention). The op-count budget is load-independent.

const SQS_CTX = { type: 'sqs', arn: 'arn:aws:sqs:us-east-1:999988887777:q' };
const KMS_CTX = { type: 'kms-key', arn: 'arn:aws:kms:us-east-1:999988887777:key/1234abcd-12ab-34cd-56ef-1234567890ab' };
const RESOURCE_OPTS = (ctx, extra) => ({
  family: 'resource', requireExplicitFamily: true, resourceContext: ctx, ...extra,
});

// ---------------------------------------------------------------------------
// (HIGH) source-binding condition arrays: sourceAccountSet / account-set merge /
// SourceArn-vs-SourceAccount disjoint scan.
// ---------------------------------------------------------------------------

// A single Allow granting a service principal, gated by aws:SourceArn (V distinct
// account-bearing ARNs) AND aws:SourceAccount (V distinct bare account ids). Every
// value is short (bare 12-digit accounts, minimal ARNs) so V=22000 stays under
// MAX_BYTES (~968 KB) and validate() passes - yet it feeds V-sized arrays into the
// source-binding dedup + disjoint-set scan that used to be O(V^2) and uncharged.
function buildSourceBindingHeavyPolicy(V) {
  const arns = [];
  const accts = [];
  for (let i = 0; i < V; i++) {
    const acct = String(100000000000 + i);
    arns.push(`arn:aws:sns:::${acct}`);
    accts.push(acct);
  }
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'S',
      Effect: 'Allow',
      Principal: { Service: 'sns.amazonaws.com' },
      Action: ['sqs:SendMessage'],
      Resource: '*',
      Condition: {
        ArnLike: { 'aws:SourceArn': arns },
        StringEquals: { 'aws:SourceAccount': accts },
      },
    }],
  });
}

test('(HIGH) source-binding-heavy resource policy is WITHIN caps yet analyzes BOUNDED (the O(V^2) condition-array grind is gone)', () => {
  const text = buildSourceBindingHeavyPolicy(22000);
  assert.equal(validate(text).ok, true, 'the source-binding-heavy policy is within every validate limit (Condition arrays are deliberately uncapped)');

  const a = analyze(text, RESOURCE_OPTS(SQS_CTX)); // browser style: default work budget, no wall clock

  assert.equal(a.ok, true, 'well-formed in-band result, never an uncaught throw');
  // "Analyzes BOUNDED / O(V^2) grind is gone" is asserted via the DETERMINISTIC op-count
  // work budget, not a wall-clock ceiling: the O(V^2) regression this guards against
  // (V=22000 -> ~4.8e8 units) would exceed the fixed DEFAULT_WORK_LIMIT (6e7) and abort,
  // so a run that COMPLETES proves the scan stayed linear - independent of CPU load. (An
  // absolute ms ceiling on this ~2.7s-pre-fix input flakes under the runner's default
  // file-level parallelism.)
  assert.equal(a.coverage.summary.analysisAborted, false, 'under the DEFAULT budget the now-linear scan completes within the fixed op-count budget (an O(V^2) grind would exceed it and abort)');
});

test('(HIGH) the source-binding condition-array scan PARTICIPATES in the work budget -> a tight workLimit aborts, never a COMPLETE pass', () => {
  const text = buildSourceBindingHeavyPolicy(22000);
  // Pre-fix, even workLimit far above any real budget did NOT abort (the loops charged
  // zero). A tight ceiling must now trip the deterministic budget.
  const a = analyze(text, RESOURCE_OPTS(SQS_CTX, { workLimit: 5000 }));
  assert.equal(a.ok, true, 'a budget abort is a graceful in-band result, not a throw');
  assert.equal(a.coverage.summary.analysisAborted, true, 'the condition-array traversal now charges the work budget, so a tight ceiling aborts it');
  assert.equal(a.coverage.summary.incomplete, true, 'an aborted analysis is INCOMPLETE, never a clean COMPLETE');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'), 'aborted coverage carries RESOURCE_BUDGET_EXCEEDED');
  assert.equal(a.findings.length, 0, 'no findings asserted from an aborted analysis (fail closed, never a false clean)');
});

test('(HIGH) source-binding-heavy analysis is DETERMINISTIC (op-count budget, no clock in the verdict)', () => {
  const text = buildSourceBindingHeavyPolicy(22000);
  const a1 = analyze(text, RESOURCE_OPTS(SQS_CTX, { workLimit: 5000 }));
  const a2 = analyze(text, RESOURCE_OPTS(SQS_CTX, { workLimit: 5000 }));
  assert.deepEqual(a1.findings, a2.findings, 'same input + same budget -> same (empty) findings twice');
  assert.equal(
    a1.coverage.summary.analysisAborted && a2.coverage.summary.analysisAborted,
    true,
    'both runs abort at the same deterministic trip point',
  );
});

test('(HIGH) NO over-correction: a small source-binding MISMATCH still analyzes COMPLETE and fires its finding', () => {
  // aws:SourceArn pins account 111111111111 while aws:SourceAccount pins 222222222222:
  // an internally inconsistent (disjoint) source binding. The proportional charge must
  // NOT trip on this tiny legitimate path, and the mismatch finding must still fire.
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'Mismatch',
      Effect: 'Allow',
      Principal: { Service: 'sns.amazonaws.com' },
      Action: ['sqs:SendMessage'],
      Resource: '*',
      Condition: {
        ArnLike: { 'aws:SourceArn': 'arn:aws:sns:us-east-1:111111111111:topic' },
        StringEquals: { 'aws:SourceAccount': '222222222222' },
      },
    }],
  });
  assert.equal(validate(text).ok, true);
  const a = analyze(text, RESOURCE_OPTS(SQS_CTX));
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small legit source-binding policy does NOT trip the budget');
  assert.ok(a.findings.length > 0, 'the small policy still surfaces a resource finding (no false negative from the DoS fix)');
});

// ---------------------------------------------------------------------------
// (MEDIUM) KMS / named-principal dedup filters over an attacker-sized Principal.AWS
// list.
// ---------------------------------------------------------------------------

// A KMS key policy naming V distinct bare 12-digit account principals with kms:*. Bare
// ids (~15 bytes each) keep V=65000 under MAX_BYTES while feeding a V-sized entry list
// into the account-peel and same-account-partition filters that used to be O(V^2).
function buildKmsPrincipalHeavyPolicy(V) {
  const ids = [];
  for (let i = 0; i < V; i++) ids.push(String(100000000000 + i));
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'S', Effect: 'Allow', Principal: { AWS: ids }, Action: ['kms:*'], Resource: '*' }],
  });
}

test('(MEDIUM) KMS principal-heavy resource policy is WITHIN caps yet analyzes BOUNDED (the O(V^2) principal-dedup grind is gone)', () => {
  const text = buildKmsPrincipalHeavyPolicy(65000);
  assert.equal(validate(text).ok, true, 'the principal-heavy KMS policy is within every validate limit (Principal count is deliberately uncapped)');

  const a = analyze(text, RESOURCE_OPTS(KMS_CTX));

  assert.equal(a.ok, true, 'well-formed in-band result');
  // Deterministic op-count bound (not a wall-clock ceiling): an O(V^2) dedup regression at
  // V=65000 would exceed the fixed DEFAULT_WORK_LIMIT and abort, so a COMPLETE run proves
  // the dedup stayed linear - load-independent, unlike a flaky absolute ms ceiling.
  assert.equal(a.coverage.summary.analysisAborted, false, 'the now-linear dedup completes within the fixed op-count budget (an O(V^2) grind would exceed it and abort)');
});

test('(MEDIUM) the KMS principal-dedup filters PARTICIPATE in the work budget -> a tight workLimit aborts (was non-participating at workLimit=10,000,000)', () => {
  const text = buildKmsPrincipalHeavyPolicy(65000);
  const a = analyze(text, RESOURCE_OPTS(KMS_CTX, { workLimit: 5000 }));
  assert.equal(a.ok, true);
  assert.equal(a.coverage.summary.analysisAborted, true, 'the principal-dedup traversal now charges the budget, so a tight ceiling aborts it');
  assert.equal(a.coverage.summary.incomplete, true, 'aborted -> incomplete, never a clean COMPLETE');
  assert.ok(a.coverage.summary.codes.includes('RESOURCE_BUDGET_EXCEEDED'));
  assert.equal(a.findings.length, 0, 'no findings from an aborted analysis (fail closed)');
});

test('(MEDIUM) NO over-correction: a small KMS account-delegation policy still analyzes COMPLETE and fires RESOURCE-KMS-ACCOUNT-DELEGATION', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'EnableIAMUserPermissions',
      Effect: 'Allow',
      Principal: { AWS: 'arn:aws:iam::111122223333:root' },
      Action: 'kms:*',
      Resource: '*',
    }],
  });
  assert.equal(validate(text).ok, true);
  const a = analyze(text, RESOURCE_OPTS({ type: 'kms-key', arn: 'arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab' }));
  assert.equal(a.coverage.summary.analysisAborted, false, 'a small legit KMS delegation does NOT trip the budget');
  assert.ok(
    a.findings.some((f) => f.id === 'RESOURCE-KMS-ACCOUNT-DELEGATION'),
    'the legitimate KMS account-delegation finding still fires (no false negative from the DoS fix)',
  );
});
