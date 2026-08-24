// IAM-1207 (Phase 12): the resource-family FLIP scoreboard.
//
// This is the single authoritative gate that ties the resource-based acceptance
// tests to their committed fixtures and proves they FLIPPED from fail-closed to
// real resource analysis once the Phase-12 resource evaluator shipped
// (IAM-1201..1206). Before Phase 12 these were blocked-by-design deferred
// fixtures (fixtures/acceptance-2-deferred/) asserting
// UNSUPPORTED_POLICY_FAMILY. They are now committed acceptance fixtures under
// fixtures/resource/, each driven through the REAL engine (analyze() with the
// explicit attached-resource context) and asserted to produce a genuine,
// non-blocked resource analysis with the expected resource finding.
//
// Required flip set (docs/acceptance-suite-2.md + suite-3, per IAM-1207):
//   suite-2: 26, 27, 28, 32, 33, 49, 51, 53
//   suite-3: 69, 85
//
// The fixtures are discovered by their suite2Test / suite3Test tag, so this gate
// fails LOUDLY if a required test loses its committed fixture, regresses to
// fail-closed, or drops its expected finding - it can never silently skip.
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { RESOURCE_IDS } from '../../../content/tools/iam-blast-radius/engine/resource.js';

const here = dirname(fileURLToPath(import.meta.url));
const resourceDir = join(here, '..', 'fixtures', 'resource');

// The required flip set and the resource finding each analyzed fixture must now
// produce (the semantic proof that the flip is real, not just "not blocked").
const REQUIRED = {
  suite2: {
    26: 'RESOURCE-CONFUSED-DEPUTY',
    27: 'RESOURCE-CONFUSED-DEPUTY',
    28: 'PUBLIC-ACCESS',
    32: 'RESOURCE-SAME-ACCOUNT-GRANT',
    33: 'RESOURCE-SAME-ACCOUNT-GRANT',
    49: 'PUBLIC-ACCESS',
    51: 'RESOURCE-KMS-ACCOUNT-DELEGATION',
    53: 'RESOURCE-CONFUSED-DEPUTY',
  },
  suite3: {
    69: 'PUBLIC-ACCESS',
    85: 'PUBLIC-ACCESS',
  },
};

// Codes that would mean the shape was NOT actually analyzed (still fail-closed).
const FAIL_CLOSED_CODES = ['UNSUPPORTED_POLICY_FAMILY', 'RESOURCE_CONTEXT_REQUIRED', 'UNSUPPORTED_RESOURCE_SHAPE'];

function fixtureText(data) {
  return typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
}

// Build a { suite2Test|suite3Test : {file,data} } index over fixtures/resource/.
function indexFixtures() {
  const bySuite2 = new Map();
  const bySuite3 = new Map();
  for (const f of readdirSync(resourceDir).filter((x) => x.endsWith('.json'))) {
    const data = JSON.parse(readFileSync(join(resourceDir, f), 'utf8'));
    if (typeof data.suite2Test === 'number') bySuite2.set(data.suite2Test, { file: f, data });
    if (typeof data.suite3Test === 'number') bySuite3.set(data.suite3Test, { file: f, data });
  }
  return { bySuite2, bySuite3 };
}

const INDEX = indexFixtures();

function checkFlip(kind, num, expectedFinding, entry) {
  assert.ok(entry, `${kind} test ${num}: no committed resource fixture carries this suite tag (flip lost)`);
  const { file, data } = entry;

  // The resource-policy context is explicit and required.
  assert.ok(data.options && data.options.family === 'resource', `${file}: must explicitly select the resource family`);
  assert.ok(
    data.options.resourceContext && typeof data.options.resourceContext.arn === 'string',
    `${file}: must carry the explicit attached-resource context`,
  );

  const res = analyze(fixtureText(data), data.options);

  // FLIPPED to real analysis: accepted, routed to the resource family, NOT blocked.
  assert.equal(res.ok, true, `${file}: ${kind} test ${num} must analyze cleanly (flip), got ${JSON.stringify(res.errors)}`);
  assert.equal(res.family, 'resource', `${file}: ${kind} test ${num} routed to the resource family`);
  assert.equal(res.coverage.blocked, false, `${file}: ${kind} test ${num} must NOT be fail-closed anymore`);

  const codes = (res.coverage.summary && res.coverage.summary.codes) || [];
  for (const bad of FAIL_CLOSED_CODES) {
    assert.ok(!codes.includes(bad), `${file}: ${kind} test ${num} must not carry the fail-closed code ${bad}`);
  }
  // Accepted resource analysis is still INCOMPLETE (unsupported != safe).
  assert.ok(codes.includes('RESOURCE_ANALYSIS_INCOMPLETE'), `${file}: accepted resource analysis stays incomplete`);

  // The expected resource finding is present, and EVERY finding is a resource id
  // (never an identity-rule finding on a resource policy).
  assert.ok(res.findings.some((f) => f.id === expectedFinding), `${file}: ${kind} test ${num} must produce ${expectedFinding}`);
  for (const f of res.findings) {
    assert.ok(RESOURCE_IDS.includes(f.id), `${file}: ${kind} test ${num} produced non-resource finding ${f.id}`);
    assert.match(String(f.limit), /not effective access/i, `${file}: ${f.id} must carry the potential-blast-radius caveat`);
  }
}

test('suite-2 resource tests 26/27/28/32/33/49/51/53 flipped from fail-closed to real resource analysis', () => {
  for (const [num, finding] of Object.entries(REQUIRED.suite2)) {
    checkFlip('suite-2', Number(num), finding, INDEX.bySuite2.get(Number(num)));
  }
});

test('suite-3 resource tests 69/85 flipped from fail-closed to real resource analysis', () => {
  for (const [num, finding] of Object.entries(REQUIRED.suite3)) {
    checkFlip('suite-3', Number(num), finding, INDEX.bySuite3.get(Number(num)));
  }
});

test('the flipped tests are no longer carried as blocked-by-design deferred fixtures', () => {
  // The only shapes that remain in the deferred set are genuinely-unmodeled
  // families (permissions-boundary 30, session 31, SCP-shape 43, RCP 52). None of
  // the flipped resource tests may still be represented there.
  const deferredDir = join(here, '..', 'fixtures', 'acceptance-2-deferred');
  const stillDeferred = new Set(
    readdirSync(deferredDir)
      .filter((x) => x.endsWith('.json'))
      .map((x) => JSON.parse(readFileSync(join(deferredDir, x), 'utf8')).suite2Test),
  );
  for (const num of Object.keys(REQUIRED.suite2).map(Number)) {
    assert.ok(!stillDeferred.has(num), `suite-2 test ${num} flipped but is still a blocked-by-design deferred fixture`);
  }
  // The remaining deferred set is exactly the genuinely-unmodeled families.
  assert.deepEqual([...stillDeferred].sort((a, b) => a - b), [30, 31, 43, 52], 'remaining deferred set is boundary/session/SCP/RCP only');
});
