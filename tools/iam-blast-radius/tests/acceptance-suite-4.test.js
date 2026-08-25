// IAM-1402 (Phase 14): per-service S3 bucket-policy finding rules.
// Runs on node's built-in runner: `node --test`.
//
// Drives the real analyze() pipeline through the fixtures/acceptance-4/ corpus
// (acceptance-suite-4 tests 101-108 + 128, the S3 campaign) and asserts the
// per-service S3 refinements layered ON TOP of the generic resource evaluator:
//   - a genuine public "*" s3:GetObject stays critical PUBLIC-ACCESS with the
//     Block-Public-Access fail-closed caveat (101);
//   - a "*" narrowed by aws:PrincipalOrgID is high/narrowed, never anonymous (102);
//   - a "*" scoped only by a network selector (aws:SourceIp) is STILL anonymous
//     within the network - never credited as narrowed to authenticated principals
//     (103), and s3:ResourceAccount pins the bucket-owner, not the caller (108);
//   - an SSE-enforcing / TLS request-property Deny does NOT privatize a public read
//     (104, trap 3) - it is classified request-property, exactly like test 28;
//   - s3:PutBucketPolicy to an external principal is ranked as bucket-policy
//     TAKEOVER above a data-plane action, never over-claimed as effective (105);
//   - cross-account read (106) and same-account direct grant (107) keep their
//     generic classification and severity;
//   - a CanonicalUser grant surfaces fail-closed, never zero findings (128).
//
// The near-miss guards (103/104/108) assert principalScopedBy stays EMPTY - the
// engine-level proof that a network / resource-account / request-property key was
// NOT mis-credited as narrowing the "*" to authenticated principals (the false
// negative the adversarial critic targets). Every finding must carry the
// potential-blast-radius-not-effective caveat and be a resource-family id.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { RESOURCE_IDS } from '../../../content/tools/iam-blast-radius/engine/resource.js';

const here = dirname(fileURLToPath(import.meta.url));
const fxDir = join(here, '..', 'fixtures', 'acceptance-4');

const FIXTURES = readdirSync(fxDir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(fxDir, f), 'utf8')) }));

function findingText(f) {
  return `${f.why || ''}\n${f.title || ''}\n${f.remediation || ''}`;
}

test('fixtures/acceptance-4 corpus is present and well-formed', () => {
  // Tests 101-108 (8) + 128 (1) = 9 S3 per-service fixtures.
  assert.equal(FIXTURES.length, 9, `expected 9 S3 suite-4 fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy`);
    assert.ok(data.options && typeof data.options === 'object', `${file}: has analyze options`);
    // Per-service assertions live under expectS3 (a resource fixture keeps its
    // top-level `expect` limited to identity-safe keys - {valid, notFindingIds} -
    // because the shared analyze.test.js globber runs every fixture through
    // analyze() with NO options and reads its top-level expect).
    assert.ok(data.expectS3 && typeof data.expectS3 === 'object', `${file}: has expectS3`);
  }
});

for (const { file, data } of FIXTURES) {
  test(`suite-4 S3 fixture ${file}: analyze() matches the per-service contract`, () => {
    const e = data.expectS3;
    let res;
    assert.doesNotThrow(() => { res = analyze(JSON.stringify(data.policy), data.options); }, `${file}: analyze threw`);

    // Accepted resource analysis (never blocked, routed to the resource evaluator).
    assert.equal(res.ok, true, `${file}: ok`);
    assert.equal(res.family, 'resource', `${file}: resource family`);
    assert.ok(res.coverage && res.coverage.blocked === false, `${file}: not blocked`);

    const byId = (id) => res.findings.find((f) => f.id === id);

    // Expected findings present.
    for (const want of e.findingIds || []) {
      assert.ok(byId(want), `${file}: expected finding ${want}; got [${res.findings.map((f) => f.id).join(', ')}]`);
    }
    // Forbidden findings absent (identity ids + per-service ids that must not fire).
    for (const bad of e.notFindingIds || []) {
      assert.ok(!byId(bad), `${file}: finding ${bad} must be absent`);
    }
    // Severities exact (never over/understate the evidence).
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
    // principalScopedBy is the engine-level proof of narrowing (or its absence). A
    // near-miss condition (network / resource-account / request-property) must leave
    // it EMPTY; a genuine principal-identity condition records the exact key(s).
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
        `${file}: ${id} must not be credited as narrowed to authenticated principals`,
      );
    }
    // Positive rationale substrings (the S3-specific observation is stated).
    for (const [id, needles] of Object.entries(e.whyIncludes || {})) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for whyIncludes check`);
      for (const needle of needles) {
        assert.ok(String(f.why).includes(needle), `${file}: ${id} why must mention "${needle}"`);
      }
    }
    // Block Public Access fail-closed caveat present on every S3 public/broad finding.
    for (const id of e.pabCaveatOn || []) {
      const f = byId(id);
      assert.ok(f, `${file}: ${id} present for PAB caveat check`);
      assert.ok(/Block Public Access/.test(String(f.why)), `${file}: ${id} must carry the Block Public Access caveat`);
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

test('suite-4 S3 analysis is deterministic (byte-identical findings across runs)', () => {
  for (const { file, data } of FIXTURES) {
    const a = JSON.stringify(analyze(JSON.stringify(data.policy), data.options).findings);
    const b = JSON.stringify(analyze(JSON.stringify(data.policy), data.options).findings);
    assert.equal(a, b, `${file}: deterministic`);
  }
});
