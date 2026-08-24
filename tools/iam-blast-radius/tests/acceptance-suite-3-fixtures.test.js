// IAM-1003 (Phase 10): fixture-driven acceptance harness for docs/acceptance-
// suite-3.md Campaign C (IAM role-takeover correlation, tests 72-80).
//
// Each fixture under fixtures/acceptance-3/ is driven through the REAL pipeline
// (validate() + analyze()), never from its declared numbers alone, so the
// correlation contract is enforced on every `node --test` run:
//
//   72 exact same-role takeover -> one critical, primitives subsumed
//   73 different target roles -> no correlation
//   74 wildcard modifier overlaps an exact assumable role -> takeover anchored
//      on the concrete intersecting role, NOT generalized to the wildcard
//   75 simultaneously-unsatisfiable conditions -> NO compound takeover, both
//      condition expressions preserved
//   76 explicit Deny removes a prerequisite -> no full path, remainder kept
//   77 AttachRolePolicy alternative to PutRolePolicy -> critical takeover
//   78 modify-without-assume -> no self-assumption path
//   80 duplicate modify statements -> one path, no duplicate graph edges
//
// The generic assertions (valid/status/findingIds/etc.) mirror the suite-2
// harness; the ROLE-TAKEOVER-specific `expect.takeover` block adds the
// anchoring / subsumption / per-statement-evidence checks this campaign needs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { validate } from '../../../content/tools/iam-blast-radius/engine/validate.js';

const here = dirname(fileURLToPath(import.meta.url));
const suite3Dir = join(here, '..', 'fixtures', 'acceptance-3');

function fixtureText(data) {
  return typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
}

function loadDir(dir) {
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
}

// A finding id present anywhere: as a top-level row OR folded into a primary's
// subsumed[] risk factors.
function presentAnywhere(findings, id) {
  return findings.some(
    (f) => f.id === id || (Array.isArray(f.subsumed) && f.subsumed.some((s) => s.id === id)),
  );
}

for (const { file, data } of loadDir(suite3Dir)) {
  test(`suite-3 ${file}: engine matches expectation`, () => {
    const text = fixtureText(data);

    let vres;
    assert.doesNotThrow(() => { vres = validate(text); }, `validate() threw on ${file}`);
    let res;
    // IAM-1005: a fixture may declare an analysis context (e.g. subjectAccount for
    // the cross-account PassRole case, test 91). Absent -> default {} (unchanged).
    assert.doesNotThrow(() => { res = analyze(text, data.options || {}); }, `analyze() threw on ${file}`);

    const exp = data.expect || {};

    if (typeof exp.valid === 'boolean') {
      assert.equal(vres.ok, exp.valid, `${file}: validate ok mismatch`);
      assert.equal(res.ok, exp.valid, `${file}: analyze ok mismatch`);
    }

    if (exp.status === 'blocked') {
      assert.equal(res.ok, false, `${file}: blocked status requires ok:false`);
      assert.equal(res.findings.length, 0, `${file}: blocked result must have zero findings`);
    }

    // IAM-1008 (Campaign A parser hardening): validation-failure fixtures declare
    // the exact error code(s), JSON path(s), and message fragment(s) the guard must
    // report. Both validate() and analyze() must surface the code (analyze fails
    // closed at validate); paths/messages are checked on the validate() errors.
    const errExp = data.errorExpect || {};
    const vcodes = vres.errors.map((e) => e.code);
    const acodes = res.errors.map((e) => e.code);
    for (const code of (errExp.errorCodes || [])) {
      assert.ok(vcodes.includes(code), `${file}: validate missing error code ${code} (got ${vcodes.join(',')})`);
      assert.ok(acodes.includes(code), `${file}: analyze missing error code ${code} (got ${acodes.join(',')})`);
    }
    for (const p of (errExp.pathIncludes || [])) {
      assert.ok(vres.errors.some((e) => e.path === p), `${file}: no validation error at path ${p} (got ${vres.errors.map((e) => e.path).join(',')})`);
    }
    for (const m of (errExp.messageIncludes || [])) {
      assert.ok(vres.errors.some((e) => (e.message || '').includes(m)), `${file}: no validation error message including ${JSON.stringify(m)}`);
    }

    const topIds = new Set(res.findings.map((f) => f.id));

    for (const id of (exp.findingIds || [])) {
      assert.ok(topIds.has(id), `${file}: expected top-level finding ${id} (got ${[...topIds].join(',')})`);
    }
    // Absent at the TOP level, but MAY be subsumed into a primary (folded risk
    // factor). Used for the standalone primitives a takeover subsumes.
    for (const id of (exp.absentTopLevel || [])) {
      assert.ok(!topIds.has(id), `${file}: ${id} must not be a top-level row (folded into the primary)`);
    }
    // Absent everywhere: not a top-level row and not subsumed anywhere.
    for (const id of (exp.notFindingIdsAnywhere || [])) {
      assert.ok(!presentAnywhere(res.findings, id), `${file}: ${id} must not be present anywhere`);
    }

    // IAM-1006 (F2, test 95): per-action precision on a finding's action list. A
    // finding may be required to INCLUDE certain actions and EXCLUDE others - e.g.
    // WILDCARD-RESOURCE must list iam:PassRole (remediable) but NOT iam:ListRoles
    // (a required-wildcard enumeration action with no resource-level scoping).
    for (const [id, want] of Object.entries(exp.findingActions || {})) {
      const f = res.findings.find((x) => x.id === id);
      assert.ok(f, `${file}: expected a ${id} finding to check its actions`);
      const acts = Array.isArray(f.actions) ? f.actions : [];
      for (const a of (want.include || [])) {
        assert.ok(acts.includes(a), `${file}: ${id}.actions must include ${a} (got ${acts.join(',')})`);
      }
      for (const a of (want.exclude || [])) {
        assert.ok(!acts.includes(a), `${file}: ${id}.actions must NOT include ${a} (got ${acts.join(',')})`);
      }
    }

    // Strings that must survive somewhere in the analysis result (e.g. both
    // condition expressions of test 75, the iam:PolicyARN evidence of test 77).
    if (Array.isArray(exp.preservesStrings)) {
      const blob = JSON.stringify(res);
      for (const s of exp.preservesStrings) {
        assert.ok(blob.includes(s), `${file}: expected the string ${JSON.stringify(s)} to be preserved in the result`);
      }
    }

    // No two graph edges share the same {from,to,type} triple.
    if (exp.graphNoDuplicateEdges) {
      const seen = new Set();
      for (const e of res.graph.edges) {
        const key = `${e.from}|${e.to}|${e.type}`;
        assert.ok(!seen.has(key), `${file}: duplicate graph edge ${key}`);
        seen.add(key);
      }
    }

    // ROLE-TAKEOVER-specific contract.
    if (exp.takeover) {
      const t = exp.takeover;
      const takeovers = res.findings.filter((f) => f.id === 'ROLE-TAKEOVER');
      if (typeof t.count === 'number') {
        assert.equal(takeovers.length, t.count, `${file}: expected ${t.count} ROLE-TAKEOVER row(s), got ${takeovers.length}`);
      } else {
        assert.ok(takeovers.length >= 1, `${file}: expected at least one ROLE-TAKEOVER`);
      }
      const f = takeovers[0];
      assert.ok(f, `${file}: no ROLE-TAKEOVER finding to inspect`);

      if (Array.isArray(t.severityOneOf)) {
        assert.ok(t.severityOneOf.includes(f.severity), `${file}: takeover severity ${f.severity} not in ${t.severityOneOf.join('/')}`);
      }
      if (Array.isArray(t.resources)) {
        // Anchored on the concrete intersecting role, never generalized.
        assert.deepEqual(f.resources.slice().sort(), t.resources.slice().sort(), `${file}: takeover resources mismatch`);
      }
      if (Array.isArray(t.subsumes)) {
        const subIds = new Set((f.subsumed || []).map((s) => s.id));
        for (const id of t.subsumes) {
          assert.ok(subIds.has(id), `${file}: takeover must subsume ${id} (got ${[...subIds].join(',')})`);
        }
      }
      if (typeof t.requiresPassRole === 'boolean') {
        assert.ok(!f.actions.includes('iam:PassRole'), `${file}: takeover header must not name iam:PassRole`);
        const anyOf = f.escalation.prerequisites.anyOf;
        assert.equal(anyOf[0].requiresPassRole, t.requiresPassRole, `${file}: requiresPassRole mismatch`);
      }
      // Per-statement evidence provenance (test 79): each leg's evidence record
      // carries ONLY the actions its own statement grants, at the right index.
      if (t.evidence) {
        const legs = new Map((f.evidence || []).map((e) => [e.role, e]));
        for (const [role, want] of Object.entries(t.evidence)) {
          const got = legs.get(role);
          assert.ok(got, `${file}: missing evidence leg ${role}`);
          if (typeof want.statementIndex === 'number') {
            assert.equal(got.statementIndex, want.statementIndex, `${file}: leg ${role} statementIndex`);
          }
          if (Array.isArray(want.actions)) {
            assert.deepEqual(got.actions.slice().sort(), want.actions.slice().sort(), `${file}: leg ${role} actions`);
          }
        }
      }
      if (Array.isArray(t.whyIncludes)) {
        for (const s of t.whyIncludes) assert.ok(f.why.includes(s), `${file}: why must name ${s}`);
      }
      if (Array.isArray(t.whyExcludes)) {
        for (const s of t.whyExcludes) assert.ok(!f.why.includes(s), `${file}: why must NOT generalize to ${s}`);
      }
    }

    // IAM-1004 (Campaign D): analysis-coverage contract. A resource-family fail-
    // closed result is ok:true with coverage.blocked (family.test.js convention),
    // NOT ok:false - so coverage is asserted separately from exp.status.
    if (exp.coverage) {
      const c = res.coverage;
      const s = c.summary;
      if (typeof exp.coverage.blocked === 'boolean') {
        assert.equal(c.blocked, exp.coverage.blocked, `${file}: coverage.blocked mismatch`);
      }
      if (typeof exp.coverage.supported === 'boolean') {
        assert.equal(s.supported, exp.coverage.supported, `${file}: coverage supported mismatch`);
      }
      if (typeof exp.coverage.incomplete === 'boolean') {
        assert.equal(s.incomplete, exp.coverage.incomplete, `${file}: coverage incomplete mismatch`);
      }
      for (const code of (exp.coverage.codesInclude || [])) {
        assert.ok(s.codes.includes(code), `${file}: coverage codes must include ${code} (got ${s.codes.join(',')})`);
      }
      for (const code of (exp.coverage.codesExclude || [])) {
        assert.ok(!s.codes.includes(code), `${file}: coverage codes must NOT include ${code}`);
      }
      for (const code of (exp.coverage.blockingCodesInclude || [])) {
        assert.ok(
          (c.blockingCodes || []).some((b) => b.code === code),
          `${file}: blockingCodes must include ${code}`,
        );
      }
    }

    // IAM-1004: an invalid partial-wildcard Principal member must be located by its
    // exact JSON path (e.g. a poisoned array member at Statement[0].Principal.AWS[1]),
    // never silently dropped so only the valid member(s) read as a complete result.
    if (exp.invalidPrincipal) {
      const inv = res.findings.find((f) => f.id === 'TRUST-INVALID-PRINCIPAL');
      assert.ok(inv, `${file}: expected a TRUST-INVALID-PRINCIPAL finding`);
      const paths = (inv.invalidPrincipalPaths || []).map((p) => p.path);
      for (const p of (exp.invalidPrincipal.pathsInclude || [])) {
        assert.ok(paths.includes(p), `${file}: invalidPrincipalPaths must include ${p} (got ${paths.join(',')})`);
      }
      if (typeof exp.invalidPrincipal.whyIncludes === 'string') {
        assert.ok(inv.why.includes(exp.invalidPrincipal.whyIncludes), `${file}: invalid-principal why must name ${exp.invalidPrincipal.whyIncludes}`);
      }
    }

    // IAM-1004 (test 85): a wildcard in an aws:PrincipalArn CONDITION value must
    // never be mis-flagged as an invalid partial Principal-element wildcard.
    if (exp.notMisflaggedAsInvalidPrincipal) {
      assert.ok(
        !res.findings.some((f) => f.id === 'TRUST-INVALID-PRINCIPAL'),
        `${file}: a condition-value wildcard must NOT produce TRUST-INVALID-PRINCIPAL`,
      );
      assert.ok(
        !res.coverage.summary.codes.includes('INVALID_PRINCIPAL_WILDCARD_ARN'),
        `${file}: a condition-value wildcard must NOT raise INVALID_PRINCIPAL_WILDCARD_ARN`,
      );
    }
  });
}
