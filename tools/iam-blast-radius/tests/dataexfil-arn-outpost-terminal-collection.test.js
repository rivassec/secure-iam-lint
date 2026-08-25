// S1-dataexfil-arn iteration 5: lock the residual fail-OPEN in isBroadArnResource()'s
// S3-on-Outposts loop. The loop's leaf-exclusion bound (`i < idParts.length - 1`)
// skipped an ARN that TERMINATES at a wildcarded COLLECTION identifier -
//   arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-abc/bucket/*
//   arn:aws:s3-outposts:us-east-1:123456789012:outpost/op-abc/accesspoint/*
// each of which names EVERY bucket / access point on the outpost (the whole
// collection). Because the terminal wildcard was skipped, resourceIsBroad returned
// false and a MUTATING grant on it (s3:PutBucketAcl / s3:PutObject /
// s3:GetBucketPolicy / s3:PutAccessPointPolicy - "make every outpost bucket public")
// reported findings=[] status complete exit 0 CLEAN on BOTH analyze() and scan():
// a WILDCARD-RESOURCE fail-OPEN (threat-model T8).
//
// Fix: a leading wildcard on a TERMINAL collection identifier is broad too; only a
// content-leaf key wildcard within a concretely-named parent
// (outpost/<id>/bucket/<name>/object/*) stays scoped. These tests assert:
//   1. every terminal-collection form + mutating action fires WILDCARD-RESOURCE:high
//      on analyze() and drives a NON-ZERO scan() exit (no fail-open),
//   2. the genuinely-scoped one-named-parent object form stays quiet (no over-fire),
//   3. analyze()/scan() PARITY: scan never cleaner than analyze.
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';

const OUTPOST = 'arn:aws:s3-outposts:us-east-1:123456789012';

function policy(action, resource) {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'S', Effect: 'Allow', Action: action, Resource: resource }],
  });
}

// Catalog-known non-read (mutating) actions for which a broad resource is a
// meaningful, remediable WILDCARD-RESOURCE. (The finding also named
// s3:GetBucketPolicy - a READ verb, correctly NOT WILDCARD-RESOURCE, so its
// quiet result is by-design action classification, not the broadness fail-open -
// and s3:PutAccessPointPolicy, absent from the action-catalog snapshot, which
// makes the analysis fail-closed "partial" rather than complete; both are
// excluded here so the assertion isolates the broadness verdict.)
const MUTATING_ACTIONS = ['s3:PutBucketAcl', 's3:PutObject', 's3:PutBucketPolicy'];

// Terminal-collection ARNs: a leading wildcard on the LAST collection identifier -
// every bucket / access point on the outpost.
const TERMINAL_COLLECTION_RESOURCES = [
  `${OUTPOST}:outpost/op-abc/bucket/*`,
  `${OUTPOST}:outpost/op-abc/accesspoint/*`,
];

test('mutating action on a terminal-collection outpost ARN fires WILDCARD-RESOURCE:high (no fail-open)', () => {
  for (const resource of TERMINAL_COLLECTION_RESOURCES) {
    for (const action of MUTATING_ACTIONS) {
      const text = policy(action, resource);
      const result = analyze(text);
      assert.equal(result.ok, true, `${action} on ${resource}: expected clean analysis; got ${JSON.stringify(result.errors)}`);
      const ids = result.findings.map((f) => f.id);
      assert.ok(ids.includes('WILDCARD-RESOURCE'),
        `${action} on ${resource}: MUST fire WILDCARD-RESOURCE (fail-open, T8); got [${ids.join(', ')}]`);
      const wr = result.findings.find((f) => f.id === 'WILDCARD-RESOURCE');
      assert.equal(wr.severity, 'high', `${action} on ${resource}: WILDCARD-RESOURCE must be high; got ${wr.severity}`);
    }
  }
});

test('CLI scan() exits NON-ZERO (analyzed clean, blocking) on terminal-collection outpost ARNs', () => {
  for (const resource of TERMINAL_COLLECTION_RESOURCES) {
    for (const action of MUTATING_ACTIONS) {
      const r = scan({ text: policy(action, resource), family: 'identity' });
      assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE,
        `${action} on ${resource}: expected COMPLETE analysis; got ${r.analysisStatus}`);
      assert.equal(r.exitCode, EXIT.FINDINGS,
        `${action} on ${resource}: expected non-zero findings exit; got ${r.exitCode}`);
      assert.notEqual(r.exitCode, EXIT.CLEAN,
        `${action} on ${resource}: must NOT exit 0/clean on all-outpost-buckets grant (fail-open, T8)`);
      assert.ok(r.blockingCount >= 1, `${action} on ${resource}: expected blockingCount>=1; got ${r.blockingCount}`);
    }
  }
});

test('scoped one-named-parent object form stays quiet (no over-fire) - both bucket and access-point', () => {
  const scoped = [
    `${OUTPOST}:outpost/op-abc/bucket/my-bucket/object/*`,
    `${OUTPOST}:outpost/op-abc/accesspoint/my-ap/object/*`,
  ];
  for (const resource of scoped) {
    for (const action of MUTATING_ACTIONS) {
      const result = analyze(policy(action, resource));
      assert.equal(result.ok, true, `${action} on ${resource}: expected clean analysis`);
      const ids = result.findings.map((f) => f.id);
      assert.ok(!ids.includes('WILDCARD-RESOURCE'),
        `${action} on ${resource}: scoped one-named-parent grant must NOT fire WILDCARD-RESOURCE; got [${ids.join(', ')}]`);
      assert.ok(!ids.includes('DATA-EXFIL'),
        `${action} on ${resource}: scoped grant must NOT fire DATA-EXFIL; got [${ids.join(', ')}]`);
    }
  }
});

test('PARITY: scan() is never more permissive than analyze() on any crafted input', () => {
  const inputs = [
    ...TERMINAL_COLLECTION_RESOURCES,
    `${OUTPOST}:outpost/op-abc/bucket/my-bucket/object/*`,
    `${OUTPOST}:outpost/op-abc/accesspoint/my-ap/object/*`,
    `${OUTPOST}:outpost/op-abc/bucket/*/object/*`,
    '*',
  ];
  for (const resource of inputs) {
    const text = policy('s3:PutBucketAcl', resource);
    const analyzed = analyze(text);
    const scanned = scan({ text, family: 'identity' });
    const analyzeHasBlocking = analyzed.ok && analyzed.findings.some((f) => f.severity === 'critical' || f.severity === 'high');
    if (analyzeHasBlocking) {
      assert.notEqual(scanned.exitCode, EXIT.CLEAN,
        `${resource}: analyze() has a blocking finding but scan() exited CLEAN - a parity fail-open`);
    }
  }
});
