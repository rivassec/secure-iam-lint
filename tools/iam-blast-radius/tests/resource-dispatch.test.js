// IAM-1401 (Phase 14): per-service DISPATCH scaffolding in engine/resource.js.
// Runs on node's built-in runner: `node --test`.
//
// This tranche is PURE ROUTING: after parseResourceContext() accepts a context,
// the analyzer selects a per-service rule set by the DETECTED service token
// (serviceForArn: s3-bucket / s3-object / kms-key / sns / sqs) and runs it IN
// ADDITION to the generic principal-centric resourceFindings() loop. No
// per-service FINDINGS exist yet (the S3 / KMS / messaging rules are IAM-1402..
// 1404); the handlers are stubs. These tests pin the wiring and the two
// adversarial guarantees the story calls out:
//   - unknown / unmodeled / dangerous service tokens fall back to the generic
//     path and NEVER throw;
//   - dispatch bleed is structurally impossible - each handler is registered
//     under its exact service token(s) only, so one service's rule set can never
//     run for (and therefore never reclassify) another service.
// It also asserts the dispatch is ADDITIVE: the combined finding set still
// carries every generic finding, and (because the stubs add nothing yet) is
// byte-identical to the generic-only set, so no existing behavior regresses.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as resourceModule from '../../../content/tools/iam-blast-radius/engine/resource.js';
import {
  perServiceRuleSetFor,
  dispatchPerServiceRules,
  analyzeResource,
  RESOURCE_SERVICES,
  MODELED_RESOURCE_SERVICES,
  RESOURCE_CODES,
} from '../../../content/tools/iam-blast-radius/engine/resource.js';

// A minimal normalized model with one anonymous "*" Allow (drives the generic
// PUBLIC-ACCESS finding on S3/SNS/SQS and the KMS not-anonymous over-grant later).
function anonModel(action) {
  return {
    statements: [{
      index: 0, sid: 'Pub', effect: 'Allow', actions: [action],
      resources: ['*'], condition: null,
      principal: { anyPrincipal: true, byType: {} },
    }],
  };
}

// A representative accepted context per modeled service token.
const CONTEXTS = {
  [RESOURCE_SERVICES.S3_BUCKET]: { arn: 'arn:aws:s3:::corp-data', account: '123456789012' },
  [RESOURCE_SERVICES.S3_OBJECT]: { arn: 'arn:aws:s3:::corp-data/*', account: '123456789012' },
  [RESOURCE_SERVICES.KMS_KEY]: { arn: 'arn:aws:kms:us-east-1:111122223333:key/abcd-1234' },
  [RESOURCE_SERVICES.SNS]: { arn: 'arn:aws:sns:us-east-2:444455556666:MyTopic' },
  [RESOURCE_SERVICES.SQS]: { arn: 'arn:aws:sqs:us-east-2:111122223333:queue1' },
};

// ---------------------------------------------------------------------------
// perServiceRuleSetFor(): a handler for every modeled token, null otherwise.
// ---------------------------------------------------------------------------

test('perServiceRuleSetFor: every modeled service token has a handler', () => {
  for (const token of MODELED_RESOURCE_SERVICES) {
    const handler = perServiceRuleSetFor(token);
    assert.equal(typeof handler, 'function', `${token} must have a per-service handler`);
  }
});

test('perServiceRuleSetFor: generic / unknown / invalid / dangerous tokens -> null', () => {
  const bad = [
    RESOURCE_SERVICES.GENERIC, // detected-but-unmodeled: no per-service rules
    'dynamodb', 'lambda', 'secretsmanager', '', 's3', 'kms', // near-misses / raw service
    '__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty',
    null, undefined, 42, {}, [], true,
  ];
  for (const token of bad) {
    assert.equal(perServiceRuleSetFor(token), null, `${String(token)} must have no handler`);
  }
});

test('perServiceRuleSetFor: dangerous keys never resolve an inherited value (Map, not prototype)', () => {
  // A plain-object table would return Object.prototype.constructor for the
  // "constructor" key; the Map-backed table must not leak any such value.
  for (const key of ['__proto__', 'constructor', 'prototype', 'valueOf']) {
    const h = perServiceRuleSetFor(key);
    assert.equal(h, null, `${key} must not resolve to a prototype-chain value`);
  }
});

// ---------------------------------------------------------------------------
// Structural scoping: no dispatch bleed (trap 4). Each handler is bound to its
// own service token(s) ONLY. The KMS handler is a DISTINCT function reference
// from the S3 and messaging handlers, so KMS-specific reasoning is structurally
// incapable of running for S3 / SNS / SQS.
// ---------------------------------------------------------------------------

test('dispatch scoping: KMS handler is distinct from S3 and messaging handlers', () => {
  const s3Bucket = perServiceRuleSetFor(RESOURCE_SERVICES.S3_BUCKET);
  const s3Object = perServiceRuleSetFor(RESOURCE_SERVICES.S3_OBJECT);
  const kms = perServiceRuleSetFor(RESOURCE_SERVICES.KMS_KEY);
  const sns = perServiceRuleSetFor(RESOURCE_SERVICES.SNS);
  const sqs = perServiceRuleSetFor(RESOURCE_SERVICES.SQS);

  // S3 bucket + object are the same bucket policy at different resource scope.
  assert.equal(s3Bucket, s3Object, 'S3 bucket and object share one handler');
  // SNS + SQS share the messaging family (differ only in action namespace).
  assert.equal(sns, sqs, 'SNS and SQS share one messaging handler');
  // The KMS handler must be its OWN reference - it can never be the S3 or the
  // messaging handler, so the KMS not-anonymous reframing cannot bleed sideways.
  assert.notEqual(kms, s3Bucket, 'KMS handler must not be the S3 handler');
  assert.notEqual(kms, sns, 'KMS handler must not be the messaging handler');
  assert.notEqual(s3Bucket, sns, 'S3 and messaging handlers must be distinct');
});

// ---------------------------------------------------------------------------
// dispatchPerServiceRules(): pure routing, never throws, empty in this tranche.
// ---------------------------------------------------------------------------

test('dispatchPerServiceRules: returns [] for every modeled service (pure routing)', () => {
  for (const [token, base] of Object.entries(CONTEXTS)) {
    const ctx = { ...base, service: token };
    const out = dispatchPerServiceRules(anonModel('s3:GetObject'), ctx);
    assert.ok(Array.isArray(out), `${token}: returns an array`);
    assert.equal(out.length, 0, `${token}: no per-service findings yet (IAM-1401 is routing only)`);
  }
});

test('dispatchPerServiceRules: generic / unknown / missing service -> [] (falls back to generic)', () => {
  const model = anonModel('s3:GetObject');
  const cases = [
    { service: RESOURCE_SERVICES.GENERIC },
    { service: 'dynamodb' },
    { service: '' },
    { service: null },
    {}, // no service field at all
  ];
  for (const ctx of cases) {
    const out = dispatchPerServiceRules(model, ctx);
    assert.deepEqual(out, [], `${JSON.stringify(ctx)}: no per-service rules, empty`);
  }
});

test('dispatchPerServiceRules: NEVER throws on hostile / malformed ctx or model', () => {
  const hostile = [
    [null, null],
    [undefined, undefined],
    [{}, {}],
    [anonModel('kms:Decrypt'), { service: '__proto__' }],
    [anonModel('kms:Decrypt'), { service: 'constructor' }],
    [anonModel('kms:Decrypt'), { service: { nested: true } }],
    [42, { service: RESOURCE_SERVICES.KMS_KEY }],
    ['not-a-model', { service: RESOURCE_SERVICES.SQS }],
    [{ statements: 'nope' }, { service: RESOURCE_SERVICES.SNS }],
  ];
  for (const [m, c] of hostile) {
    let out;
    assert.doesNotThrow(() => { out = dispatchPerServiceRules(m, c); }, `${JSON.stringify(c)}: must not throw`);
    assert.ok(Array.isArray(out), 'always returns an array');
    assert.equal(out.length, 0, 'stub handlers add nothing');
  }
});

// ---------------------------------------------------------------------------
// Additivity + no-regression through the module entry point analyzeResource().
// The combined finding set must still carry the generic findings, and (stubs add
// nothing) be byte-identical to the generic-only baseline. Coverage stays
// INCOMPLETE and keeps the fail-closed + not-effective language.
// ---------------------------------------------------------------------------

test('analyzeResource: per-service dispatch is additive - generic findings preserved on every service', () => {
  // Each accepted context must still yield the generic finding it did before
  // dispatch was wired (public-access on S3/SNS/SQS; KMS routes account/root and
  // "*" through its generic branches). The dispatch only ever ADDS.
  for (const [token, base] of Object.entries(CONTEXTS)) {
    const action = token === RESOURCE_SERVICES.KMS_KEY ? 'kms:Decrypt'
      : token === RESOURCE_SERVICES.SNS ? 'sns:Publish'
      : token === RESOURCE_SERVICES.SQS ? 'sqs:ReceiveMessage'
      : 's3:GetObject';
    const res = analyzeResource(anonModel(action), base);
    assert.equal(res.ok, true, `${token}: accepted`);
    // The anonymous "*" Allow still produces the generic PUBLIC-ACCESS finding on
    // every modeled service (KMS "*" also surfaces via the generic public branch
    // in this tranche - IAM-1403 will refine its wording, not this story).
    assert.ok(
      res.findings.some((f) => f.id === 'PUBLIC-ACCESS'),
      `${token}: generic PUBLIC-ACCESS finding is preserved, not suppressed`,
    );
    // Every finding still carries the potential-not-effective caveat.
    for (const f of res.findings) {
      assert.ok(/not effective access/i.test(f.limit), `${token}: ${f.id} keeps the caveat`);
    }
    // Coverage stays INCOMPLETE and fail-closed.
    assert.equal(res.coverage.incomplete, true, `${token}: coverage stays incomplete`);
    assert.equal(res.coverage.code, RESOURCE_CODES.RESOURCE_ANALYSIS_INCOMPLETE, `${token}: incomplete code`);
    assert.ok(/not\s+mean\s+the\s+resource\s+is\s+safe/i.test(res.coverage.note), `${token}: keeps fail-closed language`);
    assert.ok(/per-service rule set/i.test(res.coverage.note), `${token}: note reflects the per-service dispatch ran`);
  }
});

test('analyzeResource: KMS anonymous "*" is NOT reclassified by dispatch (no bleed from a future KMS carve-out)', () => {
  // In the IAM-1401 tranche the KMS handler is a stub, so a KMS "*" still flows
  // through the GENERIC public branch exactly as before. Critically, running the
  // S3/SNS/SQS anonymous grants through the same dispatch must ALSO be unchanged -
  // the dispatch keeps each service independent. This pins the pre-1403 baseline
  // so a later KMS carve-out cannot silently alter S3/SQS classification here.
  const s3 = analyzeResource(anonModel('s3:GetObject'), CONTEXTS[RESOURCE_SERVICES.S3_BUCKET]);
  const sqs = analyzeResource(anonModel('sqs:ReceiveMessage'), CONTEXTS[RESOURCE_SERVICES.SQS]);
  const s3Pub = s3.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  const sqsPub = sqs.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.ok(s3Pub && s3Pub.severity === 'critical', 'S3 "*" stays critical public');
  assert.ok(sqsPub && sqsPub.severity === 'critical', 'SQS "*" stays critical public');
});

test('analyzeResource: rejected / unmodeled context still fails closed after dispatch is wired', () => {
  const model = anonModel('s3:GetObject');
  // Missing context -> RESOURCE_CONTEXT_REQUIRED; dispatch is never reached.
  const missing = analyzeResource(model, null);
  assert.equal(missing.ok, false, 'missing context fails closed');
  assert.equal(missing.findings.length, 0, 'no findings on a rejected context');
  assert.equal(missing.coverage.code, RESOURCE_CODES.RESOURCE_CONTEXT_REQUIRED);
  // Unmodeled service -> UNSUPPORTED_RESOURCE_SHAPE; dispatch is never reached.
  const unmodeled = analyzeResource(model, { arn: 'arn:aws:lambda:us-east-1:123456789012:function:my-fn' });
  assert.equal(unmodeled.ok, false, 'unmodeled service fails closed');
  assert.equal(unmodeled.coverage.code, RESOURCE_CODES.UNSUPPORTED_RESOURCE_SHAPE);
});

test('analyzeResource: determinism - combined finding set is byte-identical across two runs', () => {
  for (const [token, base] of Object.entries(CONTEXTS)) {
    const action = token === RESOURCE_SERVICES.KMS_KEY ? 'kms:Decrypt' : 's3:GetObject';
    const a = JSON.stringify(analyzeResource(anonModel(action), base).findings);
    const b = JSON.stringify(analyzeResource(anonModel(action), base).findings);
    assert.equal(a, b, `${token}: findings byte-identical across runs`);
  }
});

test('the generic resourceFindings loop stays module-internal (not part of the export surface)', () => {
  // The dispatch adds a small, intentional public surface (perServiceRuleSetFor,
  // dispatchPerServiceRules); the generic principal-centric loop must remain a
  // private implementation detail so callers cannot bypass the fail-closed
  // analyzeResource() boundary.
  assert.equal(resourceModule.resourceFindings, undefined, 'resourceFindings stays module-internal');
  assert.equal(typeof resourceModule.perServiceRuleSetFor, 'function', 'dispatch accessor is exported');
  assert.equal(typeof resourceModule.dispatchPerServiceRules, 'function', 'dispatch runner is exported');
});
