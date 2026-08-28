// Regression suite for STORY S2-airtight-incomplete (Round 4 / Phase 20).
//
// The fail-closed BACKSTOP (coverage.summary.incomplete) must be airtight: several
// unknown/partial inputs reached CLEAN (analyze() ok:true && findings.length===0 &&
// !coverage.summary.incomplete, and CLI exit 0) when they must reach INCOMPLETE.
// This suite pins the three closed leaks and their must-stay-green controls.
//
//   (a) catalog.js  - an uncatalogued WILDCARD action on a concrete-but-unknown
//                     service (sqs:Send*, bedrock:Invoke*), or a known-service
//                     pattern that expands to NO catalogued action, now routes to
//                     coverage incomplete (unsupported != safe). Known-service
//                     wildcards that DO expand (s3:Get*) stay clean.
//   (b) coverage.js - a TRUNCATED attack-path graph now folds into
//                     summary.incomplete + a stable GRAPH_TRUNCATED code, and the
//                     CLI surfaces it as a non-clean exit 3.
//   (c) conditions.js - federationMeta now validates the provider HOST; an
//                     attacker-named key (acme:customkey:sub, totally.made.up:aud)
//                     falls through to context-required -> incomplete. Real
//                     federation keys (token.actions.githubusercontent.com:aud,
//                     cognito-identity.amazonaws.com:aud, saml:aud) stay understood.
//
// Pure node:test; imports the SHIPPED engine + the CLI adapter by relative path so
// the browser-cli-parity invariant is exercised on both surfaces.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../cli/scan.mjs';
import {
  defaultCatalog, unrecognizedActions, isWildcardAction,
} from '../../../content/tools/iam-blast-radius/engine/catalog.js';
import {
  classifyConditionEntry, unsupportedConditionKeys, classifyConditions,
} from '../../../content/tools/iam-blast-radius/engine/conditions.js';
import { enrichCoverage } from '../../../content/tools/iam-blast-radius/engine/coverage.js';

// analyze() "clean" per the browser-cli-parity invariant.
function isClean(r) {
  return r.ok && r.findings.length === 0
    && !(r.coverage && r.coverage.summary && r.coverage.summary.incomplete);
}
function analyzeClean(policy) {
  return isClean(analyze(JSON.stringify(policy)));
}
function coverage(policy) {
  return analyze(JSON.stringify(policy)).coverage.summary;
}
// A single-Allow identity policy carrying `action` on a concrete resource.
function allowAction(action, resource = 'arn:aws:sqs:us-east-1:123456789012:q') {
  return { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: action, Resource: resource }] };
}
// A single-Allow identity policy whose only condition is `{Op:{key:val}}`.
function allowWithCondition(key, op = 'StringEquals', val = 'v') {
  return {
    Version: '2012-10-17',
    Statement: [{
      Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::bucket/obj',
      Condition: { [op]: { [key]: val } },
    }],
  };
}

// ---------------------------------------------------------------------------
// (a) Uncatalogued WILDCARD action on a concrete-but-unknown service.
// ---------------------------------------------------------------------------

test('(a) MUST-CLOSE: sqs:Send* on a concrete queue reaches INCOMPLETE (parity with concrete sqs:SendMessage)', () => {
  const wildcard = coverage(allowAction('sqs:Send*'));
  const concrete = coverage(allowAction('sqs:SendMessage'));
  assert.equal(concrete.incomplete, true, 'the concrete unknown action is incomplete today');
  assert.equal(wildcard.incomplete, true, 'the wildcard on the SAME unknown service must be incomplete too (no fail-open)');
  assert.ok(wildcard.unrecognizedActions.includes('sqs:Send*'), 'the wildcard is named in unrecognizedActions');
  assert.equal(analyzeClean(allowAction('sqs:Send*')), false, 'sqs:Send* is NOT clean');
});

test('(a) MUST-CLOSE: bedrock:Invoke* on an unknown service reaches INCOMPLETE', () => {
  const s = coverage(allowAction('bedrock:Invoke*', 'arn:aws:bedrock:us-east-1:123456789012:model/m'));
  assert.equal(s.incomplete, true);
  assert.ok(s.unrecognizedActions.includes('bedrock:Invoke*'));
});

test('(a) CONTROL: s3:Get* (known service, pattern expands to catalogued actions) stays CLEAN', () => {
  assert.equal(analyzeClean(allowAction('s3:Get*', 'arn:aws:s3:::bucket/obj')), true);
  const s = coverage(allowAction('s3:Get*', 'arn:aws:s3:::bucket/obj'));
  assert.deepEqual([...s.unrecognizedActions], [], 's3:Get* is analyzable and not reported');
});

test('(a) CONTROL: a known-service whole-service wildcard s3:* is analyzable (not an UNKNOWN_ACTION)', () => {
  // s3:* fires a real finding (so it is non-clean on its own merits) but must NOT be
  // added to unrecognizedActions - it expands to catalogued actions.
  const s = coverage(allowAction('s3:*', 'arn:aws:s3:::bucket/*'));
  assert.deepEqual([...s.unrecognizedActions], [], 's3:* expands to known actions; not an unknown action');
});

test('(a) a known-service wildcard that expands to NO catalogued action is INCOMPLETE (fail closed)', () => {
  // s3 has no "Zzz*" action in the snapshot -> the pattern vouches for nothing.
  const s = coverage(allowAction('s3:Zzz*', 'arn:aws:s3:::bucket/obj'));
  assert.equal(s.incomplete, true);
  assert.ok(s.unrecognizedActions.includes('s3:Zzz*'));
});

test('(a) the bare all-actions "*" is NOT reported as an unknown action (owned by the rule catalog)', () => {
  // A Deny "*" guardrail must not be flipped incomplete by the wildcard net.
  const s = coverage({ Version: '2012-10-17', Statement: [{ Effect: 'Deny', Action: '*', Resource: '*' }] });
  assert.deepEqual([...s.unrecognizedActions], [], 'bare "*" is not a concrete-but-unknown service');
});

test('(a) catalog.classifyWildcard classifies the wildcard classes correctly', () => {
  assert.equal(defaultCatalog.classifyWildcard('s3:Get*').supported, true, 'known service + matching pattern');
  assert.equal(defaultCatalog.classifyWildcard('s3:*').supported, true, 'known service whole-service wildcard');
  assert.equal(defaultCatalog.classifyWildcard('sqs:Send*').supported, false, 'unknown service');
  assert.equal(defaultCatalog.classifyWildcard('bedrock:Invoke*').supported, false, 'unknown service');
  assert.equal(defaultCatalog.classifyWildcard('s3:Zzz*').supported, false, 'known service, expands to nothing');
  assert.equal(defaultCatalog.classifyWildcard('*').allServices, true, 'bare "*" is the all-actions wildcard');
  assert.equal(defaultCatalog.classifyWildcard('*').supported, true, 'bare "*" is not flagged here');
});

test('(a) unrecognizedActions scans NotAction and dedups/sorts wildcard + concrete unknowns', () => {
  const model = {
    statements: [
      { actions: ['sqs:Send*', 's3:GetObject'], notActions: [] },
      { actions: [], notActions: ['bedrock:Invoke*', 'sqs:Send*'] },
    ],
  };
  assert.deepEqual(unrecognizedActions(model, defaultCatalog), ['bedrock:Invoke*', 'sqs:Send*']);
});

test('(a) PARITY: analyze() and CLI scan() agree that sqs:Send* is non-clean (exit 3)', () => {
  const text = JSON.stringify(allowAction('sqs:Send*'));
  assert.equal(isClean(analyze(text)), false);
  const r = scan({ text, family: 'identity' });
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'the unknown-service wildcard fails closed to exit 3');
  assert.ok(r.analysisStates.some((s) => s.code === 'UNKNOWN_ACTION'), 'surfaced as UNKNOWN_ACTION');
});

test('(a) DETERMINISM: sqs:Send* analyzes to a deep-equal result twice', () => {
  const text = JSON.stringify(allowAction('sqs:Send*'));
  assert.deepEqual(analyze(text).coverage.summary.unrecognizedActions, analyze(text).coverage.summary.unrecognizedActions);
});

test('(a) isWildcardAction treats "?" as a wildcard metacharacter too', () => {
  assert.equal(isWildcardAction('s3:GetObjec?'), true);
  assert.equal(isWildcardAction('s3:GetObject'), false);
});

// ---------------------------------------------------------------------------
// (b) Truncated attack-path graph -> incomplete + GRAPH_TRUNCATED + exit 3.
// ---------------------------------------------------------------------------

// A policy whose findings exceed the graph node bound (GRAPH_LIMITS.MAX_NODES=500):
// 700 distinct destructive grants -> 700 findings -> the graph truncates.
function truncatingPolicy() {
  const st = [];
  for (let i = 0; i < 700; i++) {
    st.push({ Effect: 'Allow', Action: 's3:DeleteObject', Resource: `arn:aws:s3:::bucket-${i}/*` });
  }
  return { Version: '2012-10-17', Statement: st };
}

test('(b) MUST-CLOSE: a truncated graph flips summary.incomplete and carries GRAPH_TRUNCATED', () => {
  const r = analyze(JSON.stringify(truncatingPolicy()));
  assert.equal(r.graph.truncated, true, 'the graph truncated (precondition)');
  assert.equal(r.coverage.summary.graph.truncated, true);
  assert.equal(r.coverage.summary.graph.complete, false);
  assert.equal(r.coverage.summary.incomplete, true, 'a truncated graph is INCOMPLETE (never a bare CLEAN)');
  assert.ok(r.coverage.summary.codes.includes('GRAPH_TRUNCATED'), 'stable code present');
});

test('(b) enrichCoverage folds graph.truncated into incomplete on any family (unit)', () => {
  const cov = { detected: 'identity', family: 'identity', supported: true, blocked: false, blockingCodes: [] };
  const complete = enrichCoverage(cov, { graph: { truncated: false } });
  const truncated = enrichCoverage(cov, { graph: { truncated: true } });
  assert.equal(complete.summary.incomplete, false, 'a complete graph does not flip incomplete on its own');
  assert.equal(truncated.summary.incomplete, true, 'a truncated graph flips incomplete');
  assert.ok(truncated.summary.codes.includes('GRAPH_TRUNCATED'));
  assert.ok(!complete.summary.codes.includes('GRAPH_TRUNCATED'));
});

test('(b) CLI scan() surfaces a truncated graph as a non-clean exit 3 with a GRAPH_TRUNCATED state', () => {
  const text = JSON.stringify(truncatingPolicy());
  const r = scan({ text, family: 'identity' });
  assert.notEqual(r.exitCode, EXIT.CLEAN, 'a truncated-graph analysis must never report clean');
  assert.equal(r.exitCode, EXIT.FAIL_CLOSED, 'it fails closed to exit 3');
  assert.ok(r.analysisStates.some((s) => s.code === 'GRAPH_TRUNCATED'), 'the CLI names the truncation');
});

test('(b) CONTROL: a small policy keeps a complete graph and does NOT carry GRAPH_TRUNCATED', () => {
  const r = analyze(JSON.stringify(allowAction('s3:DeleteObject', 'arn:aws:s3:::bucket/obj')));
  assert.equal(r.graph.truncated, false);
  assert.equal(r.coverage.summary.graph.complete, true);
  assert.ok(!r.coverage.summary.codes.includes('GRAPH_TRUNCATED'));
});

// ---------------------------------------------------------------------------
// (c) federationMeta must validate the provider host.
// ---------------------------------------------------------------------------

test('(c) MUST-CLOSE: acme:customkey:sub reaches INCOMPLETE (parity with acme:customkey)', () => {
  const attacker = coverage(allowWithCondition('acme:customkey:sub'));
  const bare = coverage(allowWithCondition('acme:customkey'));
  assert.equal(bare.incomplete, true, 'the bare unknown key is incomplete today');
  assert.equal(attacker.incomplete, true, 'the :sub-suffixed attacker key must be incomplete too (no short-circuit)');
  assert.ok(attacker.unsupportedConditions.includes('acme:customkey:sub'));
});

test('(c) MUST-CLOSE: totally.made.up:aud reaches INCOMPLETE (a domain-shaped host is not enough)', () => {
  const s = coverage(allowWithCondition('totally.made.up:aud'));
  assert.equal(s.incomplete, true);
  assert.ok(s.unsupportedConditions.includes('totally.made.up:aud'));
});

test('(c) CONTROLS: real federation provider keys stay UNDERSTOOD (clean, credited constraint)', () => {
  for (const key of [
    'token.actions.githubusercontent.com:aud',
    'cognito-identity.amazonaws.com:aud',
    'accounts.google.com:aud',
    'saml:aud',
  ]) {
    assert.equal(analyzeClean(allowWithCondition(key)), true, `${key} stays clean`);
    const entry = classifyConditionEntry('StringEquals', key, 'sts.amazonaws.com');
    assert.equal(entry.known, true, `${key} is a known federation key`);
    assert.equal(entry.credited, true, `${key} is credited as a federation-audience constraint`);
  }
});

test('(c) an unrecognized provider :sub/:aud is context-required and NOT credited', () => {
  for (const key of ['acme:customkey:sub', 'totally.made.up:aud', 'evil.example.com:sub']) {
    const entry = classifyConditionEntry('StringEquals', key, 'v');
    assert.equal(entry.known, false, `${key} is not a modeled key`);
    assert.equal(entry.credited, false, `${key} is never credited as a guardrail`);
    assert.equal(entry.class, 'context-required', `${key} classifies as context-required`);
  }
});

test('(c) unsupportedConditionKeys reports the attacker federation key across a model', () => {
  const model = {
    statements: [
      { condition: { StringEquals: { 'totally.made.up:aud': 'x' } } },
      { condition: { StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' } } },
    ],
  };
  const keys = unsupportedConditionKeys(model);
  assert.ok(keys.includes('totally.made.up:aud'), 'the fabricated provider host is unsupported');
  assert.ok(!keys.includes('token.actions.githubusercontent.com:aud'), 'the real provider host is NOT unsupported');
});

test('(c) a real federated trust policy stays understood while a fabricated-provider one is incomplete', () => {
  // classifyConditions summary agrees with the per-entry classification.
  const real = classifyConditions({ StringEquals: { 'saml:aud': 'https://signin.aws.amazon.com/saml' } });
  const fake = classifyConditions({ StringEquals: { 'made.up.idp:aud': 'x' } });
  assert.equal(real.contextRequiredKeys.length, 0, 'saml:aud is modeled');
  assert.deepEqual([...fake.contextRequiredKeys], ['made.up.idp:aud'], 'the fabricated provider is context-required');
});
