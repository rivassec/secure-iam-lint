// IAM-1303 (Phase 13): the SCP / RCP org-control-family FLIP scoreboard.
//
// This is the single authoritative gate that ties the SCP/RCP acceptance-suite
// tests to their committed fixtures and proves they FLIPPED from fail-closed to
// real ceiling / guardrail analysis once the Phase-13 org-control evaluators
// shipped (IAM-1301 engine/scp.js + IAM-1302 engine/rcp.js). Before Phase 13
// these were blocked-by-design deferred fixtures asserting UNSUPPORTED_SCP_SHAPE
// (suite-1 test 19, suite-2 test 43) or UNSUPPORTED_POLICY_FAMILY (suite-2 test
// 52). They are now committed acceptance fixtures under fixtures/family-scp/ and
// fixtures/family-rcp/, each driven through the REAL engine (analyze() with the
// explicit SCP / RCP family selection) and asserted to produce a genuine,
// non-blocked ceiling / guardrail analysis with the expected org-control finding.
//
// This mirrors the IAM-1207 resource-family flip gate (acceptance-resource-flip
// .test.js) exactly. It is the org-control analogue.
//
// PHASE-13 IMMUTABLE GUARDRAIL: an SCP / RCP is a permission CEILING / GUARDRAIL,
// NEVER a grant. The flip is only "real" if the flipped analysis emits ZERO
// positive capability edges/nodes, only SCP/RCP ceiling/guardrail finding ids
// (never an identity / escalation / resource-capability id), and carries the
// ceiling-not-grant + intersection caveat on every finding. Auto-detect is NOT
// part of this flip: an SCP/RCP shape under auto-detect still fails closed with a
// machine-readable UNSUPPORTED_* code (asserted by phase13-scp/phase13-rcp), so
// the org-control family is "analyzed-or-explicitly-fail-closed", never mis-read.
//
// Required flip set (docs/acceptance-suite.md test 19 + docs/acceptance-suite-2.md
// tests 43/52):
//   suite-1: 19 -> SCP-GUARDRAIL (deny-guardrail SCP)
//   suite-2: 43 -> SCP-GUARDRAIL (negated-IfExists over-broad region deny)
//   suite-2: 52 -> RCP-GUARDRAIL (org confused-deputy resource guardrail)
//
// The fixtures are discovered by their suiteTest / suite2Test tag, so this gate
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
import { SCP_IDS } from '../../../content/tools/iam-blast-radius/engine/scp.js';
import { RCP_IDS } from '../../../content/tools/iam-blast-radius/engine/rcp.js';
import { ESCALATION_IDS } from '../../../content/tools/iam-blast-radius/engine/escalation.js';
import { RESOURCE_IDS } from '../../../content/tools/iam-blast-radius/engine/resource.js';

const here = dirname(fileURLToPath(import.meta.url));
const scpDir = join(here, '..', 'fixtures', 'family-scp');
const rcpDir = join(here, '..', 'fixtures', 'family-rcp');

// The set of finding ids that are a legitimate org-control ceiling / guardrail.
const ORG_CONTROL_IDS = new Set([...SCP_IDS, ...RCP_IDS]);
const ESC = new Set(ESCALATION_IDS);
const RESOURCE = new Set(RESOURCE_IDS);

// Codes that would mean the shape was NOT actually analyzed (still fail-closed).
const FAIL_CLOSED_CODES = [
  'UNSUPPORTED_SCP_SHAPE',
  'UNSUPPORTED_POLICY_FAMILY',
  'UNSUPPORTED_NOTPRINCIPAL',
  'AMBIGUOUS_POLICY_SHAPE',
];

// The required flip set and the org-control finding each analyzed fixture must
// now produce (the semantic proof that the flip is real, not just "not blocked").
const REQUIRED = {
  suite1: { 19: 'SCP-GUARDRAIL' },
  suite2: { 43: 'SCP-GUARDRAIL', 52: 'RCP-GUARDRAIL' },
};

function fixtureText(data) {
  return typeof data.policyRaw === 'string' ? data.policyRaw : JSON.stringify(data.policy);
}

// Build a { suiteTest|suite2Test : {file,data} } index over the family-scp/ and
// family-rcp/ committed fixtures.
function indexFixtures() {
  const bySuite1 = new Map();
  const bySuite2 = new Map();
  for (const dir of [scpDir, rcpDir]) {
    for (const f of readdirSync(dir).filter((x) => x.endsWith('.json'))) {
      const data = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      const rel = `${dir === scpDir ? 'family-scp' : 'family-rcp'}/${f}`;
      if (typeof data.suiteTest === 'number') bySuite1.set(data.suiteTest, { file: rel, data });
      if (typeof data.suite2Test === 'number') bySuite2.set(data.suite2Test, { file: rel, data });
    }
  }
  return { bySuite1, bySuite2 };
}

const INDEX = indexFixtures();

function checkFlip(kind, num, expectedFinding, entry) {
  assert.ok(entry, `${kind} test ${num}: no committed family-scp/family-rcp fixture carries this suite tag (flip lost)`);
  const { file, data } = entry;

  // The org-control family is explicitly selected (SCP or RCP), like the resource
  // flip explicitly selects the resource family.
  assert.ok(
    data.options && (data.options.family === 'scp' || data.options.family === 'rcp'),
    `${file}: must explicitly select the scp or rcp family`,
  );

  const res = analyze(fixtureText(data), data.options);

  // FLIPPED to real analysis: accepted, routed to the org-control family, NOT blocked.
  assert.equal(res.ok, true, `${file}: ${kind} test ${num} must analyze cleanly (flip), got ${JSON.stringify(res.errors)}`);
  assert.equal(res.family, 'scp-rcp', `${file}: ${kind} test ${num} routed to the scp-rcp family`);
  assert.equal(res.coverage.blocked, false, `${file}: ${kind} test ${num} must NOT be fail-closed anymore`);
  assert.equal(res.coverage.supported, true, `${file}: ${kind} test ${num} is a supported ceiling-family shape`);

  const codes = (res.coverage.summary && res.coverage.summary.codes) || [];
  const blockingCodes = (res.coverage.blockingCodes || []).map((b) => b.code);
  for (const bad of FAIL_CLOSED_CODES) {
    assert.ok(!codes.includes(bad), `${file}: ${kind} test ${num} must not carry the fail-closed code ${bad}`);
    assert.ok(!blockingCodes.includes(bad), `${file}: ${kind} test ${num} must not carry the fail-closed blocking code ${bad}`);
  }

  // The expected org-control finding is present, and EVERY finding is an SCP/RCP
  // ceiling/guardrail id (never an identity / escalation / resource-capability id).
  assert.ok(res.findings.some((f) => f.id === expectedFinding), `${file}: ${kind} test ${num} must produce ${expectedFinding}`);
  for (const f of res.findings) {
    assert.ok(ORG_CONTROL_IDS.has(f.id), `${file}: ${kind} test ${num} produced non-org-control finding ${f.id}`);
    assert.ok(!ESC.has(f.id), `${file}: ${kind} test ${num} produced an escalation finding ${f.id}`);
    assert.ok(!RESOURCE.has(f.id), `${file}: ${kind} test ${num} produced a resource-capability finding ${f.id}`);
    assert.equal(f.escalation, undefined, `${file}: ${f.id} carries escalation enrichment (a ceiling grants nothing)`);
    // A ceiling / guardrail is never a compound escalation path.
    assert.notEqual(f.severity, 'critical', `${file}: ${f.id} must never be critical (a ceiling grants nothing)`);
    // The ceiling-not-grant + intersection caveat (Phase-13 immutable guardrail).
    assert.match(String(f.limit), /ceiling/i, `${file}: ${f.id} must frame the finding as a ceiling`);
    assert.match(String(f.limit), /INTERSECTION/, `${file}: ${f.id} must state the intersection semantics`);
    assert.match(String(f.limit), /not\s+grant/i, `${file}: ${f.id} must state SCPs/RCPs do not grant`);
    assert.match(String(f.limit), /not effective access/i, `${file}: ${f.id} must carry the capability-not-effective caveat`);
  }

  // The flip is only real if it manufactured ZERO positive capability edges/nodes.
  assert.equal(res.graph.edges.length, 0, `${file}: ${kind} test ${num} must emit ZERO capability edges (ceiling, not grant)`);
  assert.equal(res.graph.nodes.length, 0, `${file}: ${kind} test ${num} must emit ZERO graph nodes (ceiling, not grant)`);

  return { res };
}

test('suite-1 test 19 (SCP deny guardrail) flipped from fail-closed to real ceiling/guardrail analysis', () => {
  for (const [num, finding] of Object.entries(REQUIRED.suite1)) {
    const { res } = checkFlip('suite-1', Number(num), finding, INDEX.bySuite1.get(Number(num)));
    // Test 19 is a two-Deny SCP: an organization-departure guardrail + a region
    // guardrail whose NotAction global-service list is a carve-out, never allowed.
    const region = res.findings.find((f) => f.guardrailKind === 'region');
    assert.ok(region, 'suite-1 test 19: a region guardrail is present');
    assert.deepEqual(region.excludedActions, ['iam:*', 'route53:*', 'support:*'], 'the NotAction carve-out is surfaced as excludedActions');
    for (const ex of region.excludedActions) {
      assert.ok(!region.actions.includes(ex), `carve-out ${ex} must never be reported as an allowed action`);
    }
    assert.ok(res.findings.some((f) => f.guardrailKind === 'organization'), 'suite-1 test 19: an organization-departure guardrail is present');
  }
});

test('suite-2 tests 43/52 (negated-IfExists SCP deny + RCP confused-deputy) flipped from fail-closed to real analysis', () => {
  // 43: over-broad region deny hazard (negated ...IfExists still denies when the key is absent).
  const r43 = checkFlip('suite-2', 43, REQUIRED.suite2[43], INDEX.bySuite2.get(43)).res;
  const g43 = r43.findings.find((f) => f.hazard === true);
  assert.ok(g43, 'suite-2 test 43: the over-broad regional-deny hazard is flagged');
  assert.equal(g43.guardrailKind, 'region', 'suite-2 test 43: hazard is a region guardrail');
  assert.equal(g43.negatedIfExists, true, 'suite-2 test 43: the negated ...IfExists polarity is recorded');

  // 52: org confused-deputy resource guardrail - deny-only, no S3/public-access grant,
  // and the three conditions preserved TOGETHER (interaction intact).
  const r52 = checkFlip('suite-2', 52, REQUIRED.suite2[52], INDEX.bySuite2.get(52)).res;
  const g52 = r52.findings.find((f) => f.id === 'RCP-GUARDRAIL');
  assert.equal(g52.denyOnly, true, 'suite-2 test 52: RCP is deny-only');
  assert.equal(g52.guardrailKind, 'confused-deputy', 'suite-2 test 52: confused-deputy guardrail');
  assert.ok(!r52.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'suite-2 test 52: no public-access finding manufactured from a deny-only RCP');
  assert.deepEqual(
    Object.getOwnPropertyNames(g52.conditions).sort(),
    ['Bool', 'Null', 'StringNotEqualsIfExists'],
    'suite-2 test 52: all three confused-deputy operators preserved on one finding (not three independent denies)',
  );
});

test('the flipped SCP/RCP tests are no longer carried as blocked-by-design deferred fixtures', () => {
  // Once the Phase-13 evaluators shipped, suite-2 tests 43/52 must leave the
  // deferred set (fixtures/acceptance-2-deferred/). The only shapes that remain
  // deferred there are the genuinely-unmodeled permissions-boundary (30) and
  // session (31) families.
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
  assert.deepEqual([...stillDeferred].sort((a, b) => a - b), [30, 31], 'remaining deferred set is permissions-boundary/session only');
});

test('SCP/RCP flip is deterministic over the committed org-control fixtures', () => {
  for (const [, entry] of [...INDEX.bySuite1, ...INDEX.bySuite2]) {
    const text = fixtureText(entry.data);
    assert.deepEqual(
      analyze(text, entry.data.options),
      analyze(text, entry.data.options),
      `${entry.file}: analyze() must be deterministic`,
    );
  }
});
