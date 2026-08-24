// IAM-1103 (Phase 11C): commit the record-test bundle's BND-*/DEF-* analyzer
// cases as a BLOCKING regression suite driven from analyze().
//
// The external record-test bundle (docs/record-tests/, 2026-08-24) enumerates 8
// BND-* (boundary / family-switch semantics) and 10 DEF-* (deferred-family
// fail-closed) analyzer cases. This suite is the durable engine-side gate for
// them: every BND-*/DEF-* case in the bundle is accounted for here - the
// ENGINE-DRIVABLE cases (those carrying an `input` policy + an `expect` block)
// are driven through the real analyze() pipeline and asserted; the UI-only cases
// (family-switch / browser-matrix / export / stale-state procedures, which need a
// real DOM + Worker) are each mapped to a NAMED Playwright assertion in
// tests/e2e/record-cases.spec.js. A meta-test proves NOTHING is silently skipped:
// a future bundle case with no engine assertion and no named e2e marker fails.
//
// Phase-11C principle: unknown / unavailable / malformed / unsupported are
// EXPLICIT non-pass states. A blocked shape yields ZERO findings and an EMPTY
// graph - never an empty-because-safe conclusion. The core fix this suite guards
// is DEF-05: an unrecognized/aliased control-policy family ('scp'/'rcp') must
// FAIL CLOSED, never fall through to identity analysis and emit capability
// findings on a document that grants nothing (the bundle's fail-OPEN bug).
//
// ADAPTER NAME-MAP (behavior is authoritative, not the literal label; the
// engine's shipped ids/codes are covered by the 1200+ existing tests, so the map
// lives at THIS fixture layer only):
//   BOUNDARY-ENVELOPE                    -> PERMISSIONS-BOUNDARY-ENVELOPE
//   UNSUPPORTED_OR_INVALID_NOTPRINCIPAL  -> UNSUPPORTED_NOTPRINCIPAL
//   MIXED_OR_INVALID_POLICY_FAMILY       -> AMBIGUOUS_POLICY_SHAPE
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const bundlePath = join(here, '..', 'docs', 'record-tests', 'cases', 'analyzer-cases.json');
const e2eSpecPath = join(here, 'e2e', 'record-cases.spec.js');

const bundle = JSON.parse(readFileSync(bundlePath, 'utf8'));
const e2eSpecText = readFileSync(e2eSpecPath, 'utf8');

// Adapter name-map: bundle label -> engine canonical id/code. Applied to every
// rule id and coverage code the bundle names before it is compared to engine
// output.
const NAME_MAP = Object.freeze({
  'BOUNDARY-ENVELOPE': 'PERMISSIONS-BOUNDARY-ENVELOPE',
  UNSUPPORTED_OR_INVALID_NOTPRINCIPAL: 'UNSUPPORTED_NOTPRINCIPAL',
  MIXED_OR_INVALID_POLICY_FAMILY: 'AMBIGUOUS_POLICY_SHAPE',
});
const mapName = (n) => (Object.prototype.hasOwnProperty.call(NAME_MAP, n) ? NAME_MAP[n] : n);

// The BND-*/DEF-* subset this suite owns. (T91-* cross-account cases are the
// 11B gate, driven by tests/t91-passrole-viability.test.js.)
const isRecordCase = (id) => /^(BND|DEF)-\d+$/.test(String(id || ''));

// An engine-drivable case carries the policy `input` + an `expect` contract; a
// UI-only case is a `kind`-based procedure with no `input`.
const isEngineDrivable = (c) => c && Object.prototype.hasOwnProperty.call(c, 'input');

// Capability (positive-grant) edge types per the architecture edge ontology. A
// blocked shape or a ceiling/envelope family emits NONE of these - the record
// cases assert exactly zero. `denies`/`trusts` are relationship edges, not
// capability grants, so they are excluded from the count.
const CAPABILITY_EDGE_TYPES = new Set([
  'allows', 'can-assume', 'can-pass', 'can-modify', 'can-execute-as',
  'can-read', 'can-decrypt', 'can-write', 'can-destroy',
]);
function capabilityEdgeCount(graph) {
  const edges = (graph && Array.isArray(graph.edges)) ? graph.edges : [];
  return edges.filter((e) => e && CAPABILITY_EDGE_TYPES.has(e.type)).length;
}

const recordCases = bundle.cases.filter((c) => isRecordCase(c.id));

// Assert the bundle still carries the expected shape (8 BND + 10 DEF). If the
// bundle grows, the meta-test below forces the new case to be handled.
test('IAM-1103: the record bundle exposes the 8 BND-* + 10 DEF-* analyzer cases', () => {
  const bnd = recordCases.filter((c) => c.id.startsWith('BND-'));
  const def = recordCases.filter((c) => c.id.startsWith('DEF-'));
  assert.equal(bnd.length, 8, 'eight BND-* cases');
  assert.equal(def.length, 10, 'ten DEF-* cases');
});

// --- Engine-drivable cases: driven through the real analyze() pipeline --------

for (const c of recordCases.filter(isEngineDrivable)) {
  test(`IAM-1103 record case ${c.id}: analyze() matches the bundle expectation (name-mapped)`, () => {
    const res = analyze(JSON.stringify(c.input), c.family ? { family: c.family } : {});

    // analyze() NEVER throws: even a fail-closed shape returns ok:true with a
    // well-formed blocking coverage state the UI can render.
    assert.equal(res.ok, true, `${c.id}: pipeline runs to a structured conclusion`);
    const exp = c.expect || {};
    const cov = res.coverage;

    if (exp.status === 'BLOCKED') {
      // Fail-closed: blocked coverage, ZERO findings, and (graph:null) an empty
      // graph. An empty result here means "not understood", never "safe".
      assert.ok(cov && cov.blocked === true, `${c.id}: coverage is blocked (fail-closed)`);
      assert.equal(res.findings.length, 0, `${c.id}: a blocked shape emits no findings`);
      const codes = (cov.blockingCodes || []).map((b) => b.code);
      if (exp.errorCode) {
        const want = mapName(exp.errorCode);
        assert.ok(codes.includes(want),
          `${c.id}: blocking code ${want} present (got [${codes.join(', ')}])`);
      } else {
        assert.ok(codes.length > 0, `${c.id}: at least one machine-readable blocking code`);
      }
      if (exp.graph === null) {
        assert.equal(res.graph.nodes.length, 0, `${c.id}: no graph nodes on a blocked shape`);
        assert.equal(res.graph.edges.length, 0, `${c.id}: no graph edges on a blocked shape`);
      }
      if (typeof exp.capabilityEdges === 'number') {
        assert.equal(capabilityEdgeCount(res.graph), exp.capabilityEdges,
          `${c.id}: capability-edge count`);
      }
    } else if (exp.status === 'COMPLETE') {
      // A supported family analyzed to completion. Assert the required rule fired,
      // the forbidden one did not, the legitimate prose is present, and the
      // capability-edge budget holds.
      assert.ok(cov && cov.blocked === false, `${c.id}: coverage completed (not blocked)`);
      const ids = res.findings.map((f) => f.id);
      for (const r of exp.requiredRuleIds || []) {
        assert.ok(ids.includes(mapName(r)),
          `${c.id}: required rule ${mapName(r)} present (got [${ids.join(', ')}])`);
      }
      for (const f of exp.forbiddenRuleIds || []) {
        assert.ok(!ids.includes(mapName(f)),
          `${c.id}: forbidden rule ${mapName(f)} absent`);
      }
      if (exp.requiredText && exp.requiredText.length) {
        const hay = JSON.stringify(res.findings).toLowerCase();
        for (const t of exp.requiredText) {
          assert.ok(hay.includes(String(t).toLowerCase()),
            `${c.id}: legitimate prose present: "${t}"`);
        }
      }
      if (typeof exp.capabilityEdges === 'number') {
        assert.equal(capabilityEdgeCount(res.graph), exp.capabilityEdges,
          `${c.id}: capability-edge count`);
      }
    } else {
      assert.fail(`${c.id}: unhandled expect.status "${exp.status}"`);
    }
  });
}

// --- UI-only cases: each maps to a NAMED Playwright assertion ------------------
//
// The UI-only record cases (family-switch state isolation, three-browser
// parity, export-after-switch, stale-state, unsupported->supported switch, the
// blocked-export contract) need a real DOM + Worker, so they live in
// tests/e2e/record-cases.spec.js. This node-suite gate does NOT run the browser
// - it asserts each case has a named assertion in that spec (the title carries a
// `[CASE-ID]` marker), so a UI-only case can never be silently dropped even
// though the browser run is CI's job.
test('IAM-1103: every UI-only record case has a named e2e assertion (no silent skips)', () => {
  const uiOnly = recordCases.filter((c) => !isEngineDrivable(c));
  // Sanity: the UI-only set is exactly the kind-based procedures we expect.
  assert.ok(uiOnly.length > 0, 'there are UI-only record cases to map');
  for (const c of uiOnly) {
    assert.ok(e2eSpecText.includes(`[${c.id}]`),
      `${c.id} (kind: ${c.kind}) must have a named e2e assertion "[${c.id}]" in ` +
        'tests/e2e/record-cases.spec.js');
  }
});

// Every BND-*/DEF-* record case is accounted for: it is either engine-drivable
// (asserted above) or has a named e2e marker. A new bundle case that is neither
// fails this meta-test rather than passing unnoticed.
test('IAM-1103: no record case is silently skipped', () => {
  for (const c of recordCases) {
    const handled = isEngineDrivable(c) || e2eSpecText.includes(`[${c.id}]`);
    assert.ok(handled,
      `${c.id} is neither engine-drivable nor covered by a named e2e assertion`);
  }
});
