// IAM-1404 (Phase 14): shared SNS topic + SQS queue messaging per-service rules.
// Runs on node's built-in runner: `node --test`.
//
// Drives the real analyze() pipeline through the fixtures/acceptance-4-messaging/
// corpus (acceptance-suite-4 tests 117-126, the SNS + SQS campaigns) and asserts the
// messaging per-service refinements layered ON TOP of the generic resource evaluator:
//   - a public "*" sns:Subscribe / sqs:ReceiveMessage stays critical PUBLIC-ACCESS
//     (SQS "*" IS anonymous per AWS docs; SNS "*" is a public wildcard grant) and the
//     messaging rule ADDS MESSAGING-PUBLIC-EXPOSURE (high) naming the exfiltrate /
//     drain vector (117, 122). resource.anonymous stays TRUE - the KMS not-anonymous
//     carve-out (IAM-1403) never leaks here (trap 4);
//   - a "*" narrowed by aws:PrincipalOrgID is high/narrowed, never anonymous, and
//     MESSAGING-PUBLIC-EXPOSURE does NOT fire (120);
//   - a service-principal publish/send without a source binding is a medium
//     confused-deputy exposure, never public write (118, 124); source-bound is an
//     info negative control (119, 123); a match-all aws:SourceArn is bypassed while
//     aws:SourceAccount still binds (125);
//   - the deprecated aws:SourceOwner is recognized as a present (legacy) binding, not
//     a missing one, and surfaces a migration note (121);
//   - cross-account sqs:* is high RESOURCE-CROSS-ACCOUNT plus a MESSAGING-POLICY-
//     TAKEOVER (the wildcard includes the queue-policy control actions), never
//     over-claimed as effective (126).
//
// The `forbidWhy` guards are the engine-level proof that a messaging finding never
// asserts a false-classification phrase (not-anonymous / authenticated-only / public
// write / effective takeover) the adversarial critic targets. Every finding must
// carry the potential-blast-radius-not-effective caveat and be a resource-family id.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { RESOURCE_IDS } from '../../../content/tools/iam-blast-radius/engine/resource.js';

const here = dirname(fileURLToPath(import.meta.url));
const fxDir = join(here, '..', 'fixtures', 'acceptance-4-messaging');

const FIXTURES = readdirSync(fxDir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(fxDir, f), 'utf8')) }));

function findingText(f) {
  // limit is deliberately excluded: RESOURCE_LIMIT contains "not effective access",
  // so a forbidWhy phrase must only ever match the finding's own why/title/remediation.
  return `${f.why || ''}\n${f.title || ''}\n${f.remediation || ''}`;
}

test('fixtures/acceptance-4-messaging corpus is present and well-formed', () => {
  // Tests 117-126 = 10 SNS/SQS per-service fixtures.
  assert.equal(FIXTURES.length, 10, `expected 10 messaging suite-4 fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy`);
    assert.ok(data.options && typeof data.options === 'object', `${file}: has analyze options`);
    // Per-service assertions live under expectMessaging (the top-level `expect` stays
    // limited to {valid} because the shared analyze.test.js globber runs every fixture
    // through analyze() with NO options and reads its top-level expect).
    assert.ok(data.expectMessaging && typeof data.expectMessaging === 'object', `${file}: has expectMessaging`);
  }
});

for (const { file, data } of FIXTURES) {
  test(`suite-4 messaging fixture ${file}: analyze() matches the per-service contract`, () => {
    const e = data.expectMessaging;
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

    for (const want of e.findingIds || []) {
      assert.ok(byId(want), `${file}: expected finding ${want}; got [${res.findings.map((f) => f.id).join(', ')}]`);
    }
    for (const bad of e.notFindingIds || []) {
      assert.ok(!byId(bad), `${file}: finding ${bad} must be absent`);
    }
    for (const [id, sev] of Object.entries(e.findingSeverities || {})) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for severity check`);
      assert.equal(f.severity, sev, `${file}: ${id} severity`);
    }
    // A "*" that is NOT anonymous-critical (narrowed by a principal-identity key).
    for (const id of e.notCritical || []) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for notCritical check`);
      assert.notEqual(f.severity, 'critical', `${file}: ${id} must not be unconditioned-critical`);
    }
    // principalScopedBy proves narrowing (or its absence).
    for (const [id, keys] of Object.entries(e.scopedBy || {})) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for scopedBy check`);
      assert.deepEqual((f.resource && f.resource.principalScopedBy) || [], keys, `${file}: ${id} principalScopedBy`);
    }
    for (const id of e.scopedByEmpty || []) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for scopedByEmpty check`);
      assert.deepEqual(
        (f.resource && f.resource.principalScopedBy) || [], [],
        `${file}: ${id} must not be credited as narrowed (a genuinely-anonymous "*" is not scoped)`,
      );
    }
    // A genuinely-anonymous SNS/SQS "*" grant keeps resource.anonymous TRUE - the KMS
    // not-anonymous carve-out (test 109) must NOT leak into the messaging family.
    for (const id of e.anonymousTrue || []) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for anonymousTrue check`);
      assert.equal(
        f.resource && f.resource.anonymous, true,
        `${file}: ${id} resource.anonymous must be TRUE on a genuinely-anonymous SNS/SQS "*" grant`,
      );
    }
    // Confused-deputy source-binding state / bound keys / bypassed keys (engine-level
    // proof of source-bound vs unbound vs bypassed, never a prose match).
    for (const [id, state] of Object.entries(e.sourceBindingState || {})) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for sourceBindingState check`);
      assert.equal(f.resource && f.resource.sourceBinding && f.resource.sourceBinding.state, state, `${file}: ${id} sourceBinding.state`);
    }
    for (const [id, keys] of Object.entries(e.sourceBindingBound || {})) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for sourceBindingBound check`);
      assert.deepEqual((f.resource && f.resource.sourceBinding && f.resource.sourceBinding.boundKeys) || [], keys, `${file}: ${id} sourceBinding.boundKeys`);
    }
    for (const [id, keys] of Object.entries(e.sourceBindingBypassed || {})) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for sourceBindingBypassed check`);
      assert.deepEqual((f.resource && f.resource.sourceBinding && f.resource.sourceBinding.bypassedKeys) || [], keys, `${file}: ${id} sourceBinding.bypassedKeys`);
    }
    // Positive rationale substrings (the messaging-specific observation is stated).
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

    // Universal resource-family invariants.
    for (const f of res.findings) {
      assert.ok(RESOURCE_IDS.includes(f.id), `${file}: ${f.id} is not a resource-family finding id`);
      assert.ok(
        typeof f.limit === 'string' && /not effective access/i.test(f.limit),
        `${file}: ${f.id} lacks the capability-not-effective caveat`,
      );
    }
  });
}

test('suite-4 messaging analysis is deterministic (byte-identical findings across runs)', () => {
  for (const { file, data } of FIXTURES) {
    const a = JSON.stringify(analyze(JSON.stringify(data.policy), data.options).findings);
    const b = JSON.stringify(analyze(JSON.stringify(data.policy), data.options).findings);
    assert.equal(a, b, `${file}: deterministic`);
  }
});

// Dispatch-bleed guard (trap 4): the KMS "not anonymous" carve-out (IAM-1403) must
// NEVER downgrade or reword a genuinely-anonymous SNS/SQS "*" public grant. A KMS "*"
// is reframed ("every AWS identity in every account", no anonymous wording); the SNS
// and SQS "*" stay critical PUBLIC-ACCESS WITH the anonymous wording and
// resource.anonymous TRUE. This is the load-bearing cross-service independence check.
test('dispatch bleed guard: SNS / SQS "*" stay anonymous-critical while a KMS "*" is reframed', () => {
  const opt = (type, arn) => ({ family: 'resource', requireExplicitFamily: true, resourceContext: { type, arn } });
  const sns = analyze(
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: '*', Action: 'sns:Publish', Resource: 'arn:aws:sns:us-east-2:444455556666:MyTopic' }] }),
    opt('sns', 'arn:aws:sns:us-east-2:444455556666:MyTopic'),
  );
  const sqs = analyze(
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: '*', Action: 'sqs:ReceiveMessage', Resource: 'arn:aws:sqs:us-east-2:111122223333:queue1' }] }),
    opt('sqs', 'arn:aws:sqs:us-east-2:111122223333:queue1'),
  );
  const kms = analyze(
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'kms:Decrypt', Resource: '*' }] }),
    opt('kms-key', 'arn:aws:kms:us-east-1:111122223333:key/abcd-1234'),
  );
  const snsPub = sns.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  const sqsPub = sqs.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  const kmsPub = kms.findings.find((f) => f.id === 'PUBLIC-ACCESS');

  assert.equal(snsPub.severity, 'critical', 'SNS "*" stays critical');
  assert.ok(/anonymous/i.test(snsPub.why), 'SNS "*" keeps anonymous wording');
  assert.equal(snsPub.resource.anonymous, true, 'SNS "*" resource.anonymous true');
  assert.ok(!/every AWS identity in every account/.test(snsPub.why), 'SNS "*" never uses the KMS all-accounts framing');

  assert.equal(sqsPub.severity, 'critical', 'SQS "*" stays critical');
  assert.ok(/anonymous/i.test(sqsPub.why), 'SQS "*" keeps anonymous wording');
  assert.equal(sqsPub.resource.anonymous, true, 'SQS "*" resource.anonymous true');
  assert.ok(!/every AWS identity in every account/.test(sqsPub.why), 'SQS "*" never uses the KMS all-accounts framing');

  // KMS: reframed - never anonymous, resource.anonymous false. Proves the softening is
  // KMS-scoped and did not leak sideways to the messaging family.
  assert.equal(kmsPub.resource.anonymous, false, 'KMS "*" resource.anonymous false');
  assert.ok(!/including anonymous|unauthenticated callers|anyone on the internet/i.test(kmsPub.why), 'KMS "*" drops anonymous wording');
});

// A messaging service-principal grant is NEVER "public write" (a service is not "*").
// Both an unbound exposure (medium) and a source-bound negative control (info) must
// keep this distinction - the mirror of the S3/SNS/SQS "service is not public" trap.
test('a messaging service principal is never classified public write (unbound or bound)', () => {
  const opt = { family: 'resource', requireExplicitFamily: true, resourceContext: { type: 'sqs', arn: 'arn:aws:sqs:us-east-2:444455556666:MyQueue' } };
  const unbound = analyze(
    JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { Service: 's3.amazonaws.com' }, Action: 'sqs:SendMessage', Resource: 'arn:aws:sqs:us-east-2:444455556666:MyQueue' }] }),
    opt,
  );
  const cd = unbound.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.ok(cd && cd.severity === 'medium', 'unbound service send is a medium confused-deputy exposure');
  assert.ok(!unbound.findings.some((f) => f.id === 'PUBLIC-ACCESS' || f.id === 'MESSAGING-PUBLIC-EXPOSURE'), 'a service principal never triggers a public-access finding');
});
