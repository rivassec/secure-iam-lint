// IAM-1102 / Phase 11B — T91 subject-account + partition + deny-residual
// PassRole viability.
//
// Drives ALL 9 T91-* fault-injection cases from the external record-test bundle
// (docs/record-tests/cases/analyzer-cases.json) through the REAL engine
// (analyze()) and asserts each case's recorded `expect`. These are the frozen
// truth for the cross-account / cross-partition / deny-residual PassRole
// downgrade: iam:PassRole passes a role only to a service in the SAME account AND
// partition as the role, so the compound PassRole -> service-execution path is
// viable only when a role in the subject's OWN account+partition can be passed.
//
// Principle (record-test bundle): unknown / incompatible / residual-foreign is an
// EXPLICIT non-viable state, never silently treated as a viable critical path and
// never silently suppressed. A KNOWN differing account or partition demotes the
// path (not critical) with a machine-readable warning code; an UNKNOWN subject
// account caps path exploitability and records the required-unknown rather than
// over-claiming. Same-account / wildcard-broad viable cases stay critical.
//
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const bundleCases = JSON.parse(
  readFileSync(join(here, '..', 'docs', 'record-tests', 'cases', 'analyzer-cases.json'), 'utf8'),
).cases;

const T91_CASES = bundleCases.filter((c) => /^T91-/.test(c.id));

// Sanity: the bundle really carries all 9 T91 cases (a silent drop must fail).
test('the record bundle carries all 9 T91-* cases', () => {
  assert.equal(T91_CASES.length, 9, `expected 9 T91 cases, got ${T91_CASES.length}`);
});

const EXPLOIT_RANK = { low: 1, medium: 2, high: 3 };

function severityMatches(actual, want) {
  return Array.isArray(want) ? want.includes(actual) : actual === want;
}

// The PASSROLE-EC2 finding is the subject of every T91 case.
function passroleEc2(res) {
  return (res.findings || []).find((f) => f.id === 'PASSROLE-EC2');
}

function analyzeCase(testCase) {
  const opts = testCase.context
    ? { subjectAccount: testCase.context.subjectAccount, partition: testCase.context.partition }
    : {};
  const res = analyze(JSON.stringify(testCase.input), opts);
  assert.equal(res.ok, true, `${testCase.id}: analyze() ok`);
  return res;
}

for (const testCase of T91_CASES) {
  test(`T91 viability: ${testCase.id} matches its recorded expect`, () => {
    const res = analyzeCase(testCase);
    const expect = testCase.expect || {};
    const f = passroleEc2(res);
    const esc = (f && f.escalation) || {};

    // requiredFindings: the finding must exist; severity + targetResources pinned
    // where recorded.
    for (const rf of expect.requiredFindings || []) {
      const hit = (res.findings || []).find((x) => x.id === rf.ruleId);
      assert.ok(hit, `${testCase.id}: required finding ${rf.ruleId} present`);
      if (rf.severity !== undefined) {
        assert.ok(
          severityMatches(hit.severity, rf.severity),
          `${testCase.id}: ${rf.ruleId} severity ${hit.severity} not in ${JSON.stringify(rf.severity)}`,
        );
      }
      if (rf.targetResources !== undefined) {
        assert.deepEqual(
          (hit.escalation && hit.escalation.targetResources) || [],
          rf.targetResources,
          `${testCase.id}: ${rf.ruleId} targetResources`,
        );
      }
    }

    // forbiddenFindings: the finding must NOT be present at the forbidden severity
    // (it may still exist at a lower, honest severity - that is the downgrade).
    for (const ff of expect.forbiddenFindings || []) {
      const bad = (res.findings || []).some(
        (x) => x.id === ff.ruleId && severityMatches(x.severity, ff.severity),
      );
      assert.ok(
        !bad,
        `${testCase.id}: ${ff.ruleId} must NOT be present at severity ${JSON.stringify(ff.severity)} `
          + `(got ${f && f.severity})`,
      );
    }

    // requiredWarningCodes: the machine-readable non-viability code(s).
    for (const code of expect.requiredWarningCodes || []) {
      assert.ok(f, `${testCase.id}: PASSROLE-EC2 finding present for warning ${code}`);
      assert.ok(
        (esc.warningCodes || []).includes(code),
        `${testCase.id}: warningCodes ${JSON.stringify(esc.warningCodes)} must include ${code}`,
      );
    }

    // excludedTargets: foreign-account roles removed from the viable target set,
    // and NEVER also listed as a reachable target.
    for (const ex of expect.excludedTargets || []) {
      assert.ok(
        (esc.excludedTargets || []).includes(ex),
        `${testCase.id}: excludedTargets ${JSON.stringify(esc.excludedTargets)} must include ${ex}`,
      );
      assert.ok(
        !(esc.targetResources || []).includes(ex),
        `${testCase.id}: ${ex} must not appear as a reachable target`,
      );
    }

    // maxPathExploitability: exploitability must be at or below the cap.
    if (expect.maxPathExploitability !== undefined) {
      assert.ok(f, `${testCase.id}: PASSROLE-EC2 finding present for exploitability cap`);
      assert.ok(
        EXPLOIT_RANK[f.pathExploitability] <= EXPLOIT_RANK[expect.maxPathExploitability],
        `${testCase.id}: pathExploitability ${f.pathExploitability} exceeds cap ${expect.maxPathExploitability}`,
      );
    }

    // requiredUnknowns: the explicit context the analyzer needs to resolve
    // viability (never invented, never assumed away).
    for (const unk of expect.requiredUnknowns || []) {
      assert.ok(f, `${testCase.id}: PASSROLE-EC2 finding present for required-unknown ${unk}`);
      assert.ok(
        (esc.requiredUnknowns || []).includes(unk),
        `${testCase.id}: requiredUnknowns ${JSON.stringify(esc.requiredUnknowns)} must include ${unk}`,
      );
    }

    // forbiddenTargetCorrelations: a role from a DIFFERENT statement (e.g. a
    // separate sts:AssumeRole target) must never be correlated as a PassRole
    // target of this finding.
    for (const bad of expect.forbiddenTargetCorrelations || []) {
      assert.ok(
        !(esc.targetResources || []).includes(bad),
        `${testCase.id}: ${bad} must not be a PassRole target correlation`,
      );
      assert.ok(
        !(f.resources || []).includes(bad),
        `${testCase.id}: ${bad} must not appear in the finding resources`,
      );
    }
  });
}

// Cross-cutting invariant: for the KNOWN-incompatible cases the path is reported
// (not dropped) but never asserted critical; for the UNKNOWN case exploitability
// is capped but severity is NOT silently suppressed (the subject could be the
// pinned account) - the false-negative threat-model T8 forbids silent suppression.
test('T91: an incompatible/unknown path is reported, never dropped', () => {
  for (const testCase of T91_CASES) {
    const res = analyzeCase(testCase);
    const f = passroleEc2(res);
    assert.ok(f, `${testCase.id}: the PASSROLE-EC2 path is still reported (never silently dropped)`);
  }
});
