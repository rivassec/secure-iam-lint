// IAM-904 (Phase 9): deferred-family suite-2 tests, driven and asserted so there
// are NO silent skips.
//
// docs/acceptance-suite-2.md tests 25-54 include cases that depend on policy
// families this analyzer does not yet model. Phase 9 was fenced to the three
// in-scope engine bugs (901/902/903) and did not build those families.
//
// IAM-1207 (Phase 12) UPDATE: the resource-based policy family shipped
// (IAM-1201..1206), so tests 26/27/28/32/33/49/51/53 FLIPPED from
// blocked-by-design to real resource analysis and now live as committed
// acceptance fixtures under fixtures/resource/ (driven from analyze() with the
// explicit attached-resource context by tests/resource.test.js), scoreboarded by
// tests/acceptance-resource-flip.test.js. Test 29 (Deny + NotPrincipal hazard)
// is driven by tests/acceptance-suite-2.test.js. The ONLY shapes that remain
// genuinely deferred here are the permissions-boundary (30), session (31),
// SCP-shape (43), and RCP (52) families - each still a design-blocked fixture
// below.
//
// Rather than skip these tests, each is encoded as a FIXTURE under
// fixtures/acceptance-2-deferred/ carrying:
//   - the exact policy from the suite,
//   - the CURRENT honest engine state (fail-closed with a machine-readable
//     blocking code, or the documented "analyzed as identity" family-gap), and
//   - a `designBlocked` string naming the family tranche that will flip it.
//
// This test drives every fixture through the REAL analyze() and asserts that
// honest state. If a future tranche ships a real evaluator for one of these
// families, family detection (or the blocking code) changes and the matching
// assertion fails LOUDLY - forcing whoever builds the family to update the
// expectation deliberately, exactly the "no silent skips" contract from IAM-904.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const deferredDir = join(here, '..', 'fixtures', 'acceptance-2-deferred');

function loadDir(dir) {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
}

const fixtures = loadDir(deferredDir);

test('every deferred fixture names a design-blocked family tranche', () => {
  for (const { file, data } of fixtures) {
    assert.equal(typeof data.suite2Test, 'number', `${file}: missing suite2Test number`);
    assert.ok(
      typeof data.designBlocked === 'string' && data.designBlocked.length > 20,
      `${file}: must carry a descriptive designBlocked follow-up tag (no silent skips)`,
    );
    assert.ok(
      ['blocked-by-design', 'family-gap'].includes(data.expect.deferred),
      `${file}: expect.deferred must be blocked-by-design or family-gap`,
    );
  }
});

for (const { file, data } of fixtures) {
  test(`deferred suite-2 ${file}: engine honestly ${data.expect.deferred}`, () => {
    const text = JSON.stringify(data.policy);
    let res;
    assert.doesNotThrow(() => { res = analyze(text); }, `${file}: analyze() threw`);

    const exp = data.expect;

    if (exp.familyBlocked === true) {
      // Fail-closed: analyze() ran to a well-formed BLOCKING coverage state
      // (ok:true, zero findings, empty graph, a machine-readable blocking code).
      assert.equal(res.ok, exp.ok, `${file}: ok mismatch`);
      assert.ok(res.coverage && res.coverage.blocked === true, `${file}: coverage must be blocked`);
      assert.equal(res.findings.length, 0, `${file}: blocked shape must have zero findings`);
      assert.equal(res.graph.nodes.length, 0, `${file}: blocked shape must have zero graph nodes`);
      assert.equal(res.graph.edges.length, 0, `${file}: blocked shape must have zero graph edges`);
      const codes = res.coverage.blockingCodes.map((c) => c.code);
      assert.ok(
        codes.includes(exp.blockingCode),
        `${file}: expected blocking code ${exp.blockingCode}, got ${codes.join(',')}`,
      );
    } else {
      // family-gap: no family selector exists yet, so the shape is analyzed under
      // the identity lens. Assert that documented current state precisely; a real
      // boundary/session evaluator would change res.family and trip this.
      assert.equal(res.ok, true, `${file}: family-gap shape still analyzes ok`);
      assert.equal(
        res.family,
        exp.detectedFamily,
        `${file}: family-gap detected family changed - a family evaluator may have shipped; flip the expectation deliberately`,
      );
      assert.deepEqual(
        res.findings.map((f) => f.id).sort(),
        exp.currentFindingIds,
        `${file}: family-gap finding set changed - re-baseline the deferred expectation deliberately`,
      );
    }
  });
}
