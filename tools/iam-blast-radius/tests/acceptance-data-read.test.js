// IAM-706: resource-scoped and variable-scoped data-read coverage with inferred
// sensitivity (acceptance suite tests 7 and 21). Runs under `node --test`.
//
// The battle test (docs/acceptance-suite.md; verdicts in
// ~/knowledge/personal/iam-blast-radius-battle-test-2026-08-22.md) found that a
// read scoped to a NAMED bucket (test 7: production-exports) or a policy-VARIABLE
// resource (test 21: ${aws:username}) produced NO finding, because DATA-EXFIL
// only fires a bulk object read on a BROAD resource. This story adds a lower-
// certainty, neutrally-framed DATA-READ capability for exactly that gap, WITHOUT:
//   - regressing the constrained KMS finding (test 7 - the two must coexist),
//   - over-firing on routine neutrally-named scoped reads (safe/scoped fixtures),
//   - resolving or reclassifying the policy variable (test 21 - preserved verbatim),
//   - escalating to critical or claiming every object is readable.
//
// Fixtures under fixtures/acceptance/ carry a `dataReadExpect` block:
//   findingId              the data-read finding id that must be produced
//   statementIndex         the statement it must be anchored on
//   maxSeverity            severity ceiling (must be medium-or-lower)
//   maxPathExploitability  path-exploitability ceiling
//   sensitivityInferred    the `why` states sensitivity is inferred, not proven
//   resourcesInclude[]     resource ARNs that must appear verbatim in the finding
//   variableScoped         the resource carries a policy variable, preserved verbatim
//   preserveVerbatim       the exact ${...} ARN that must survive unresolved
//   coexistsWith           a second finding that must remain (e.g. constrained KMS)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const acceptanceDir = join(here, '..', 'fixtures', 'acceptance');

// Certainty / severity ladders (higher index == weaker). A ceiling passes when
// the actual value is AT or BELOW (weaker-or-equal to) the ceiling.
const SEVERITY = ['critical', 'high', 'medium', 'low', 'info'];
const CERTAINTY = ['high', 'medium', 'low'];

function atOrBelow(ladder, actual, ceiling) {
  const ai = ladder.indexOf(actual);
  const ci = ladder.indexOf(ceiling);
  return ai >= 0 && ci >= 0 && ai >= ci;
}

function loadFixturesWith(key) {
  return readdirSync(acceptanceDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `acceptance/${f}`, data: JSON.parse(readFileSync(join(acceptanceDir, f), 'utf8')) }))
    .filter(({ data }) => data && data[key]);
}

function findingById(result, id, statementIndex) {
  return result.findings.find(
    (f) => f.id === id && (statementIndex === undefined || f.statementIndex === statementIndex),
  );
}

const fixtures = loadFixturesWith('dataReadExpect');

// Coverage guard: the story's two acceptance cases must always be exercised. If
// the fixtures vanish or lose their block, fail rather than silently pass.
test('IAM-706: acceptance tests 7 and 21 both have a dataReadExpect fixture', () => {
  const tests = new Set(fixtures.map(({ data }) => data.acceptanceTest));
  assert.ok(tests.has(7), 'missing dataReadExpect fixture for acceptance test 7');
  assert.ok(tests.has(21), 'missing dataReadExpect fixture for acceptance test 21');
});

for (const { file, data } of fixtures) {
  const dre = data.dataReadExpect;
  test(`${file}: resource/variable-scoped data-read coverage (IAM-706)`, () => {
    const text = typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
    const result = analyze(text);
    assert.equal(result.ok, true, `${file}: analyze() must succeed`);
    assert.ok(!(result.coverage && result.coverage.blocked), `${file}: must not be blocked`);

    // Declared findingIds present / notFindingIds absent.
    const ids = new Set(result.findings.map((f) => f.id));
    for (const want of (data.expect && data.expect.findingIds) || []) {
      assert.ok(ids.has(want), `${file}: expected finding ${want}; got ${JSON.stringify([...ids])}`);
    }
    for (const forbid of (data.expect && data.expect.notFindingIds) || []) {
      assert.ok(!ids.has(forbid), `${file}: finding ${forbid} must NOT be produced`);
    }

    // The data-read finding: present, anchored, medium-or-lower, capped confidence.
    const f = findingById(result, dre.findingId, dre.statementIndex);
    assert.ok(f, `${file}: expected ${dre.findingId} on statement ${dre.statementIndex}`);
    assert.ok(atOrBelow(SEVERITY, f.severity, dre.maxSeverity),
      `${file}: ${dre.findingId} severity ${f.severity} exceeds ceiling ${dre.maxSeverity} (a scoped read must never be critical/high)`);
    assert.notEqual(f.severity, 'critical', `${file}: a resource-scoped read must never be critical`);
    if (dre.maxPathExploitability) {
      assert.ok(atOrBelow(CERTAINTY, f.pathExploitability, dre.maxPathExploitability),
        `${file}: ${dre.findingId} pathExploitability ${f.pathExploitability} exceeds ceiling ${dre.maxPathExploitability}`);
    }

    // Sensitivity must be presented as INFERRED, never proven.
    if (dre.sensitivityInferred) {
      assert.match(f.why, /infer/i, `${file}: ${dre.findingId} must state sensitivity is inferred`);
      assert.match(f.why, /not proven|not prove/i, `${file}: ${dre.findingId} must say the inference is not proof`);
    }

    // Resource ARNs preserved verbatim in the finding evidence.
    for (const r of dre.resourcesInclude || []) {
      assert.ok(f.resources.includes(r), `${file}: ${dre.findingId} resources must include ${r} verbatim`);
    }

    // Variable-scoped: the ${...} ARN survives unresolved and unreclassified.
    if (dre.variableScoped) {
      assert.ok(f.resources.some((r) => r.includes('${')),
        `${file}: ${dre.findingId} must preserve the policy variable (\${...}) in its resources`);
      if (dre.preserveVerbatim) {
        assert.ok(f.resources.includes(dre.preserveVerbatim),
          `${file}: ${dre.findingId} must preserve ${dre.preserveVerbatim} verbatim`);
        // The variable must not have been resolved to a concrete principal name.
        assert.ok(!f.resources.some((r) => /company-home\/[a-z0-9._-]+\/\*/i.test(r) && !r.includes('${')),
          `${file}: the \${aws:username} variable must not be resolved to a concrete user`);
      }
    }

    // Coexisting finding (test 7: constrained KMS is not regressed / not merged).
    if (dre.coexistsWith) {
      const co = dre.coexistsWith;
      const cf = findingById(result, co.findingId, co.statementIndex);
      assert.ok(cf, `${file}: expected coexisting finding ${co.findingId}`);
      assert.notEqual(cf.statementIndex, f.statementIndex,
        `${file}: ${co.findingId} and ${dre.findingId} must come from different statements`);
      if (co.maxSeverity) {
        assert.ok(atOrBelow(SEVERITY, cf.severity, co.maxSeverity),
          `${file}: ${co.findingId} severity ${cf.severity} exceeds ceiling ${co.maxSeverity} (constrained KMS must not be broad/high)`);
      }
      for (const r of co.resourcesInclude || []) {
        assert.ok(cf.resources.includes(r), `${file}: ${co.findingId} resources must include ${r}`);
      }
      if (co.constrainedNotBroad) {
        assert.ok(!cf.resources.includes('*'),
          `${file}: ${co.findingId} must stay scoped to its key ARN, not wildcard/broad`);
        assert.ok(cf.conditions && Object.keys(cf.conditions).length > 0,
          `${file}: ${co.findingId} must retain its constraining Condition (kms:ViaService)`);
      }
    }
  });
}
