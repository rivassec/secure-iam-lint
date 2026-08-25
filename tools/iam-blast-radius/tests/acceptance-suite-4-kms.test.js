// IAM-1403 (Phase 14): per-service KMS key-policy finding rules.
// Runs on node's built-in runner: `node --test`.
//
// Drives the real analyze() pipeline through the fixtures/acceptance-4-kms/ corpus
// (acceptance-suite-4 tests 109-116 + 127, the KMS campaign) and asserts the
// KMS per-service refinements layered ON TOP of the generic resource evaluator:
//   - a KMS Principal "*" grant is a critical over-grant but is NOT anonymous: the
//     PUBLIC-ACCESS finding is reframed to "every AWS identity in every account"
//     with NO anonymous / unauthenticated / anyone-on-the-internet wording, and
//     Resource:"*" = the attached key only (109, trap 1); resource.anonymous is
//     cleared so metadata never contradicts the text;
//   - account-root delegation stays RESOURCE-KMS-ACCOUNT-DELEGATION (not public, not
//     root-only) medium same-account / high cross-account (110, 113);
//   - a "*" narrowed only by kms:ViaService is STILL account-open (KMS-VIASERVICE-
//     NOT-SCOPING, principalScopedBy empty) (111, trap 2), whereas kms:CallerAccount
//     narrows WHO to the named account (PUBLIC-ACCESS high, scopedBy=[kms:CallerAccount],
//     no ViaService note) (112);
//   - kms:CreateGrant to a "*"/cross-account principal is onward-DELEGATION ranked
//     above key use, never over-claimed as decrypt/effective (114, trap 5);
//   - the KMS silent-key-policy inversion: a key policy that omits the account-
//     delegation statement (and grants no "*") is fail-closed UNKNOWN, never "safe"
//     (115, 127);
//   - a transport-only Deny never neutralizes a KMS grant (116, trap 3).
//
// Every finding must carry the potential-blast-radius-not-effective caveat and be a
// resource-family id. The `forbidWhy` guards are the engine-level proof that the KMS
// finding never asserts the false-classification phrase (anonymous / scoped-to-
// account / proven-decrypt) the adversarial critic targets.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { RESOURCE_IDS } from '../../../content/tools/iam-blast-radius/engine/resource.js';

const here = dirname(fileURLToPath(import.meta.url));
const fxDir = join(here, '..', 'fixtures', 'acceptance-4-kms');

const FIXTURES = readdirSync(fxDir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(fxDir, f), 'utf8')) }));

function findingText(f) {
  // limit is deliberately excluded: RESOURCE_LIMIT contains the phrase "not
  // effective access", so a forbidWhy on "effective access" must not match the
  // universal caveat, only the finding's own why/title/remediation.
  return `${f.why || ''}\n${f.title || ''}\n${f.remediation || ''}`;
}

test('fixtures/acceptance-4-kms corpus is present and well-formed', () => {
  // Tests 109-116 (8) + 127 (1) = 9 KMS per-service fixtures.
  assert.equal(FIXTURES.length, 9, `expected 9 KMS suite-4 fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy`);
    assert.ok(data.options && typeof data.options === 'object', `${file}: has analyze options`);
    // Per-service assertions live under expectKms (the top-level `expect` stays
    // limited to identity-safe keys - {valid} - because the shared analyze.test.js
    // globber runs every fixture through analyze() with NO options).
    assert.ok(data.expectKms && typeof data.expectKms === 'object', `${file}: has expectKms`);
  }
});

for (const { file, data } of FIXTURES) {
  test(`suite-4 KMS fixture ${file}: analyze() matches the per-service contract`, () => {
    const e = data.expectKms;
    let res;
    assert.doesNotThrow(() => { res = analyze(JSON.stringify(data.policy), data.options); }, `${file}: analyze threw`);

    // Accepted resource analysis (never blocked, routed to the resource evaluator).
    assert.equal(res.ok, true, `${file}: ok`);
    assert.equal(res.family, 'resource', `${file}: resource family`);
    assert.ok(res.coverage && res.coverage.blocked === false, `${file}: not blocked`);
    if (e.coverageIncomplete) {
      assert.equal(
        res.coverage.summary && res.coverage.summary.incomplete, true,
        `${file}: coverage stays INCOMPLETE (never "safe")`,
      );
    }

    const byId = (id) => res.findings.find((f) => f.id === id);

    // Expected findings present.
    for (const want of e.findingIds || []) {
      assert.ok(byId(want), `${file}: expected finding ${want}; got [${res.findings.map((f) => f.id).join(', ')}]`);
    }
    // Forbidden findings absent (dispatch-bleed + over/under-fire guards).
    for (const bad of e.notFindingIds || []) {
      assert.ok(!byId(bad), `${file}: finding ${bad} must be absent`);
    }
    // Severities exact (never over/understate the evidence).
    for (const [id, sev] of Object.entries(e.findingSeverities || {})) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for severity check`);
      assert.equal(f.severity, sev, `${file}: ${id} severity`);
    }
    // A "*" that is NOT anonymous-critical (narrowed by a principal-account key).
    for (const id of e.notCritical || []) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for notCritical check`);
      assert.notEqual(f.severity, 'critical', `${file}: ${id} must not be unconditioned-critical`);
    }
    // principalScopedBy is the engine-level proof of narrowing (or its absence).
    // kms:ViaService / a network selector must leave it EMPTY; kms:CallerAccount
    // records the exact key(s).
    for (const [id, keys] of Object.entries(e.scopedBy || {})) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for scopedBy check`);
      assert.deepEqual(
        (f.resource && f.resource.principalScopedBy) || [],
        keys,
        `${file}: ${id} principalScopedBy`,
      );
    }
    for (const id of e.scopedByEmpty || []) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for scopedByEmpty check`);
      assert.deepEqual(
        (f.resource && f.resource.principalScopedBy) || [],
        [],
        `${file}: ${id} must not be credited as narrowed (channel key is not principal scoping)`,
      );
    }
    // A KMS "*" grant reaches every AWS identity in every account but NOT an
    // anonymous/unauthenticated caller - resource.anonymous must be FALSE so the
    // metadata does not contradict the not-anonymous finding text (trap 1).
    for (const id of e.anonymousFalse || []) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for anonymousFalse check`);
      assert.equal(
        f.resource && f.resource.anonymous, false,
        `${file}: ${id} resource.anonymous must be false on a KMS "*" grant`,
      );
    }
    // Positive rationale substrings (the KMS-specific observation is stated).
    for (const [id, needles] of Object.entries(e.whyIncludes || {})) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for whyIncludes check`);
      for (const needle of needles) {
        assert.ok(String(f.why).includes(needle), `${file}: ${id} why must mention "${needle}"`);
      }
    }
    // Forbidden CLAIMS: the finding must NOT assert the false-classification phrase
    // (targeted per finding id so a negated mention elsewhere never false-positives).
    for (const [id, phrases] of Object.entries(e.forbidWhy || {})) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for forbidWhy check`);
      const hay = findingText(f).toLowerCase();
      for (const phrase of phrases) {
        assert.ok(!hay.includes(phrase.toLowerCase()), `${file}: ${id} must NOT claim "${phrase}"`);
      }
    }

    // Universal resource-family invariants: every finding is a resource id and
    // carries the potential-blast-radius-not-effective caveat (threat-model T8).
    for (const f of res.findings) {
      assert.ok(RESOURCE_IDS.includes(f.id), `${file}: ${f.id} is not a resource-family finding id`);
      assert.ok(
        typeof f.limit === 'string' && /not effective access/i.test(f.limit),
        `${file}: ${f.id} lacks the capability-not-effective caveat`,
      );
    }
  });
}

test('suite-4 KMS analysis is deterministic (byte-identical findings across runs)', () => {
  for (const { file, data } of FIXTURES) {
    const a = JSON.stringify(analyze(JSON.stringify(data.policy), data.options).findings);
    const b = JSON.stringify(analyze(JSON.stringify(data.policy), data.options).findings);
    assert.equal(a, b, `${file}: deterministic`);
  }
});

// The KMS not-anonymous carve-out (IAM-1403) MUST NOT leak to S3 or SQS
// (dispatch bleed, trap 4). A genuinely-anonymous S3 / SQS Principal "*" grant stays
// critical PUBLIC-ACCESS WITH the anonymous wording; only the kms-key token is
// softened. This is the load-bearing cross-service independence guarantee.
test('dispatch bleed guard: S3 / SQS "*" stay anonymous-critical while KMS "*" is reframed', () => {
  const s3 = analyze(
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }] }),
    { family: 'resource', requireExplicitFamily: true, resourceContext: { type: 's3-bucket', arn: 'arn:aws:s3:::b', account: '123456789012' } },
  );
  const sqs = analyze(
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: '*', Action: 'sqs:ReceiveMessage', Resource: 'arn:aws:sqs:us-east-2:111122223333:queue1' }] }),
    { family: 'resource', requireExplicitFamily: true, resourceContext: { type: 'sqs', arn: 'arn:aws:sqs:us-east-2:111122223333:queue1' } },
  );
  const kms = analyze(
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'kms:Decrypt', Resource: '*' }] }),
    { family: 'resource', requireExplicitFamily: true, resourceContext: { type: 'kms-key', arn: 'arn:aws:kms:us-east-1:111122223333:key/abcd-1234' } },
  );
  const s3Pub = s3.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  const sqsPub = sqs.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  const kmsPub = kms.findings.find((f) => f.id === 'PUBLIC-ACCESS');

  // S3 / SQS: still genuinely anonymous public.
  assert.equal(s3Pub.severity, 'critical', 'S3 "*" stays critical');
  assert.ok(/anonymous/i.test(s3Pub.why), 'S3 "*" keeps anonymous wording');
  assert.equal(s3Pub.resource.anonymous, true, 'S3 "*" resource.anonymous true');
  assert.equal(sqsPub.severity, 'critical', 'SQS "*" stays critical');
  assert.ok(/anonymous/i.test(sqsPub.why), 'SQS "*" keeps anonymous wording');
  assert.equal(sqsPub.resource.anonymous, true, 'SQS "*" resource.anonymous true');

  // KMS: reframed - no "including anonymous / unauthenticated callers", not flagged
  // anonymous in metadata, but still a critical over-grant.
  assert.equal(kmsPub.severity, 'critical', 'KMS "*" stays a critical over-grant');
  assert.ok(!/including anonymous|unauthenticated callers|anyone on the internet/i.test(kmsPub.why),
    'KMS "*" drops the anonymous/unauthenticated wording');
  assert.ok(/every AWS identity in every account/.test(kmsPub.why), 'KMS "*" uses the all-accounts framing');
  assert.equal(kmsPub.resource.anonymous, false, 'KMS "*" resource.anonymous false');
});

// KMS-KEY-POLICY-TAKEOVER code path (no acceptance-suite-4 fixture exercises a
// PutKeyPolicy grant to "*" / an external principal - 115 is a confirmed same-account
// grant that must NOT fire it - so cover both directions directly here).
test('kms:PutKeyPolicy to "*" is critical takeover; to an external principal is high; to a confirmed same-account principal it does NOT fire', () => {
  const KEY = { type: 'kms-key', arn: 'arn:aws:kms:us-east-1:111122223333:key/abcd-1234' };
  const opts = { family: 'resource', requireExplicitFamily: true, resourceContext: KEY };

  const star = analyze(
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'kms:PutKeyPolicy', Resource: '*' }] }),
    opts,
  );
  const starTakeover = star.findings.find((f) => f.id === 'KMS-KEY-POLICY-TAKEOVER');
  assert.ok(starTakeover, '"*" PutKeyPolicy fires takeover');
  assert.equal(starTakeover.severity, 'critical', '"*" takeover is critical');
  assert.ok(!/proves|is in effect(?! )/i.test(starTakeover.why) || /does NOT prove/i.test(starTakeover.why),
    'takeover never over-claims effectiveness');

  const external = analyze(
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::999900001111:role/Partner' }, Action: 'kms:PutKeyPolicy', Resource: '*' }] }),
    opts,
  );
  const extTakeover = external.findings.find((f) => f.id === 'KMS-KEY-POLICY-TAKEOVER');
  assert.ok(extTakeover, 'external PutKeyPolicy fires takeover');
  assert.equal(extTakeover.severity, 'high', 'external takeover is high');

  const sameAccount = analyze(
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: 'arn:aws:iam::111122223333:role/KeyAdmin' }, Action: 'kms:PutKeyPolicy', Resource: '*' }] }),
    opts,
  );
  assert.ok(
    !sameAccount.findings.some((f) => f.id === 'KMS-KEY-POLICY-TAKEOVER'),
    'a confirmed same-account admin grant is not a takeover exposure',
  );
});
