// IAM-704: complement (NotAction/NotResource) + version gate + SCP fail-closed.
// Acceptance-suite tests 13, 14, 19, 22C. Runs on `node --test`.
//
// These assertions are VERIFIED AGAINST analyze() OUTPUT (not just the fixtures'
// declared expectations). Two fixture expectation blocks are honored:
//
//   complementExpect  (tests 13, 14) - the policy is MODELED (not blocked) but a
//     complement grant must NEVER present its EXCLUDED set as an allowed
//     action/resource. Excluded items ride in excludedActions/excludedResources;
//     confidence is reduced (complement-derived).
//
//   coverageExpect    (tests 19, 22C) - the policy FAILS CLOSED with a blocking
//     coverage code (SCP shape / unsupported version), producing no findings and
//     no positive capability edges, and never silently rewriting the version.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';

const here = dirname(fileURLToPath(import.meta.url));
const acceptanceDir = join(here, '..', 'fixtures', 'acceptance');

// Certainty ladder, most -> least certain, so "no stronger than the cap" is a
// simple index comparison.
const CONFIDENCE_RANK = Object.freeze({ high: 0, medium: 1, low: 2 });

// Graph edge types that assert a positive CAPABILITY (as opposed to the
// informational `denies` / `allows` bookkeeping edges). A blocked analysis must
// emit none of these.
const CAPABILITY_EDGE_TYPES = new Set([
  'can-assume', 'can-pass', 'can-modify', 'can-read', 'can-write',
  'can-destroy', 'can-decrypt', 'can-execute-as', 'trusts', 'delegation',
]);

function loadFixturesWith(key) {
  return readdirSync(acceptanceDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `acceptance/${f}`, data: JSON.parse(readFileSync(join(acceptanceDir, f), 'utf8')) }))
    .filter((x) => x.data && x.data[key]);
}

function fixtureText(data) {
  return typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
}

function lower(arr) {
  return new Set((Array.isArray(arr) ? arr : []).map((s) => String(s).toLowerCase()));
}

function findingById(findings, id) {
  return (findings || []).filter((f) => f.id === id);
}

// Assert basic expect.findingIds / notFindingIds so the fixture's declared
// finding set is actually exercised (the provenance/compound harnesses do not
// check `expect`).
function assertBasicExpect(result, data, file) {
  const expect = data.expect || {};
  assert.equal(result.ok, !!expect.valid, `${file}: expect.valid ${expect.valid}, got ok ${result.ok}`);
  const ids = new Set(result.findings.map((f) => f.id));
  for (const want of expect.findingIds || []) {
    assert.ok(ids.has(want), `${file}: MUST find ${want}; got [${[...ids].join(', ')}]`);
  }
  for (const notWant of expect.notFindingIds || []) {
    assert.ok(!ids.has(notWant), `${file}: MUST NOT find ${notWant}; got [${[...ids].join(', ')}]`);
  }
}

// ---------------------------------------------------------------------------
// Tests 13 & 14: complement grants are modeled without presenting the excluded
// set as allowed.
// ---------------------------------------------------------------------------

for (const { file, data } of loadFixturesWith('complementExpect')) {
  test(`${file}: complement grant never presents the excluded set as allowed (IAM-704)`, () => {
    const result = analyze(fixtureText(data));
    assertBasicExpect(result, data, file);

    const ce = data.complementExpect;
    assert.equal(result.coverage.blocked, !!ce.blocked, `${file}: coverage.blocked`);
    if (ce.detectedFamily) {
      assert.equal(result.coverage.detected, ce.detectedFamily, `${file}: detected family`);
    }

    // Global invariant: NO finding anywhere presents an excluded ACTION as an
    // allowed action (test 13).
    for (const excluded of ce.excludedNeverAllowed || []) {
      const ex = String(excluded).toLowerCase();
      for (const f of result.findings) {
        assert.ok(!lower(f.actions).has(ex),
          `${file}: excluded action "${excluded}" must not appear in ${f.id}.actions [${f.actions.join(', ')}]`);
      }
    }
    // Global invariant: NO finding presents an excluded RESOURCE as a granted
    // resource (test 14).
    for (const excluded of ce.excludedResourcesNeverGranted || []) {
      const ex = String(excluded).toLowerCase();
      for (const f of result.findings) {
        assert.ok(!lower(f.resources).has(ex),
          `${file}: excluded resource "${excluded}" must not appear in ${f.id}.resources [${f.resources.join(', ')}]`);
      }
    }

    for (const wf of ce.findings || []) {
      const matches = findingById(result.findings, wf.id);
      assert.ok(matches.length > 0, `${file}: expected a ${wf.id} finding`);
      for (const f of matches) {
        const fctx = `${file}/${f.id}`;
        if (Array.isArray(wf.complement)) {
          assert.ok(Array.isArray(f.complement) && lowerSetEquals(f.complement, wf.complement),
            `${fctx}: complement expected [${wf.complement.join(', ')}]; got ${JSON.stringify(f.complement)}`);
        }
        if (Array.isArray(wf.excludedActions)) {
          assert.ok(Array.isArray(f.excludedActions) && lowerSetEquals(f.excludedActions, wf.excludedActions),
            `${fctx}: excludedActions expected [${wf.excludedActions.join(', ')}]; got ${JSON.stringify(f.excludedActions)}`);
        }
        if (Array.isArray(wf.excludedResources)) {
          assert.ok(Array.isArray(f.excludedResources) && lowerSetEquals(f.excludedResources, wf.excludedResources),
            `${fctx}: excludedResources expected [${wf.excludedResources.join(', ')}]; got ${JSON.stringify(f.excludedResources)}`);
        }
        for (const bad of wf.actionsExclude || []) {
          assert.ok(!lower(f.actions).has(String(bad).toLowerCase()),
            `${fctx}: actions must not contain excluded "${bad}"`);
        }
        for (const bad of wf.resourcesExclude || []) {
          assert.ok(!lower(f.resources).has(String(bad).toLowerCase()),
            `${fctx}: resources must not contain excluded "${bad}"`);
        }
        if (wf.resourcesEmpty === true) {
          assert.equal(f.resources.length, 0, `${fctx}: resources must be empty (complement carve-out, not a granted ARN)`);
        }
        if (wf.maxPolicyEvidence) {
          assert.ok(CONFIDENCE_RANK[f.policyEvidence] >= CONFIDENCE_RANK[wf.maxPolicyEvidence],
            `${fctx}: policyEvidence "${f.policyEvidence}" is stronger than the reduced cap "${wf.maxPolicyEvidence}"`);
        }
        // The complement caveat must be present in the limitation text.
        assert.ok(/complement/i.test(f.limit),
          `${fctx}: limit must carry the complement caveat`);
      }
    }
  });
}

function lowerSetEquals(a, b) {
  const sa = lower(a);
  const sb = lower(b);
  if (sa.size !== sb.size) return false;
  for (const v of sa) if (!sb.has(v)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Tests 19 & 22C: fail-closed coverage blocks (SCP shape / unsupported version).
// ---------------------------------------------------------------------------

for (const { file, data } of loadFixturesWith('coverageExpect')) {
  test(`${file}: fails closed with the expected coverage block (IAM-704)`, () => {
    const result = analyze(fixtureText(data));
    assertBasicExpect(result, data, file);

    const cov = data.coverageExpect;
    assert.equal(result.coverage.blocked, !!cov.blocked, `${file}: coverage.blocked`);
    if (cov.detectedFamily) {
      assert.equal(result.coverage.detected, cov.detectedFamily, `${file}: detected family`);
    }
    const gotCodes = new Set((result.coverage.blockingCodes || []).map((b) => b.code));
    for (const want of cov.blockingCodes || []) {
      assert.ok(gotCodes.has(want), `${file}: expected blocking code ${want}; got [${[...gotCodes].join(', ')}]`);
    }
    if (cov.noFindings) {
      assert.equal(result.findings.length, 0, `${file}: a blocked analysis must produce no findings`);
    }
    if (cov.noCapabilityEdges) {
      for (const e of result.graph.edges) {
        assert.ok(!CAPABILITY_EDGE_TYPES.has(e.type),
          `${file}: a blocked analysis must emit no positive capability edge (got ${e.type})`);
      }
    }
    if (cov.preservedVersion !== undefined) {
      assert.ok(result.model, `${file}: a blocked-but-parsed policy still exposes its model`);
      assert.equal(result.model.version, cov.preservedVersion,
        `${file}: the policy Version must be preserved verbatim, never silently rewritten`);
    }

    // The blocking coverage code travels into every export (JSON + Markdown).
    const jsonCodes = new Set((JSON.parse(toJSON(result)).coverage.blockingCodes || []).map((b) => b.code));
    for (const want of cov.blockingCodes || []) {
      assert.ok(jsonCodes.has(want), `${file}: JSON export must carry blocking code ${want}`);
    }
    const md = toMarkdown(result);
    for (const want of cov.blockingCodes || []) {
      assert.ok(md.includes(want), `${file}: Markdown export must carry blocking code ${want}`);
    }
  });
}
