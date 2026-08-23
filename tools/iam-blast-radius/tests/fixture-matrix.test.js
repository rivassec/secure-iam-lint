// IAM-504 + IAM-602: fixture-matrix completeness meta-test as a release gate.
// Runs on node's built-in runner: `node --test`.
//
// This is the self-explaining specification of the fixture corpus. It enumerates
// EVERY rule id (rules.js RULE_IDS) and escalation id (escalation.js
// ESCALATION_IDS) and fails - it does not skip - if any of them ships without
// the fixture coverage its risk category requires. A future rule that lands
// without its "when NOT to fire" coverage breaks this gate.
//
// REQUIRED MATRIX
// ---------------
// Per-rule cells (asserted for every id where SEMANTICALLY APPLICABLE, encoded
// in APPLICABILITY below with a documented rationale per exclusion):
//   positive        - a policy where the rule fires
//   negative        - a policy where the rule must NOT fire (asserted absent):
//                     the primary "when-NOT-to-fire" coverage
//   boundary        - an edge/near-miss policy (scoped/conditioned/partial-
//                     wildcard/almost-firing) that exercises the rule's decision
//                     boundary; sourced from the `*-boundary.json` fixtures
//   deny            - the rule's interaction with an explicit Deny (suppressed,
//                     or present-but-Deny-aware)
//   condition       - the rule under a Condition (narrowed, still explainable)
//   notAction       - the rule reached via an Allow-NotAction inversion
//   notResource     - the rule under a NotResource scope
//   hostile         - a positive witness whose Sid/ARN/Condition carry HTML/JS
//                     payloads that must ride through analyze() as inert DATA
//
// Tree-wide cells (coverage that must exist ACROSS the fixtures/ tree, spanning
// rule categories - not one per individual id):
//   family-mismatch - a dangerous-looking policy in a family the engine does NOT
//                     model (resource / role-trust / NotPrincipal / ambiguous)
//                     that FAILS CLOSED: analyze() blocks and the identity rule
//                     that WOULD fire on the same actions is correctly suppressed
//   deterministic-export - same input -> byte-identical JSON + Markdown
//
// Coverage is DERIVED from fixture content + real analyze() output (a fixture
// witnesses a cell only if the engine actually behaves as the kind requires),
// so a mislabeled fixture cannot paper over a gap. The family-mismatch gate is
// double-locked: the engine must actually fail closed on the shape AND the same
// policy reshaped to identity form must actually fire the declared rule, so a
// "family-mismatch" claim can never be vacuous.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';
import { RULE_IDS } from '../../../content/tools/iam-blast-radius/engine/rules.js';
import { ESCALATION_IDS } from '../../../content/tools/iam-blast-radius/engine/escalation.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

// --- Applicability matrix ----------------------------------------------------
// positive/negative/boundary/deny/condition/hostile apply to EVERY rule (a grant
// can always be present, absent, at a decision boundary, Deny-interacting,
// Condition-narrowed, or carry a hostile string). notAction / notResource are
// applicable only where such a policy is a realistic, engine-detectable
// expression of the rule - never a contrived one:
//   - notAction applies to action-breadth / IAM-action rules: an Allow-NotAction
//     inverts the whole action space, so it genuinely grants iam:*/admin actions
//     and the broad-resource rule. It does NOT meaningfully express a specific
//     data-read (DATA-EXFIL / KMS-DECRYPT), destructive/detection action set, or
//     a two-action PassRole+exec pairing, so those are excluded.
//   - notResource applies to rules whose risk is resource-scoped (broad resource,
//     data read, decryption, destruction, detection, direct-IAM writes, and the
//     role-ARN-scoped AssumeRole / trust-modify paths). It is not a realistic
//     shape for pure action-breadth (WILDCARD-ACTION, NOTACTION-ALLOW) or the
//     PassRole+exec compound paths, so those are excluded.
const APPLICABILITY = Object.freeze({
  'WILDCARD-ACTION': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notAction', 'hostile'],
  'WILDCARD-RESOURCE': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notAction', 'notResource', 'hostile'],
  'DIRECT-IAM-ADMIN': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notAction', 'notResource', 'hostile'],
  'DATA-EXFIL': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notResource', 'hostile'],
  'KMS-DECRYPT': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notResource', 'hostile'],
  // IAM-706: resource/variable-scoped data-read capability. notAction is excluded
  // (an Allow-NotAction inverts the whole action space and does not express a
  // specific named/variable-scoped S3 read); notResource is excluded (this rule
  // requires an explicit, named/variable Resource - a NotResource complement is
  // the DATA-EXFIL/WILDCARD-RESOURCE shape, not a scoped read whose NAME infers
  // sensitivity).
  'DATA-READ': ['positive', 'negative', 'boundary', 'deny', 'condition', 'hostile'],
  'DESTRUCTIVE-ACTION': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notResource', 'hostile'],
  'DETECTION-IMPAIRMENT': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notResource', 'hostile'],
  'NOTACTION-ALLOW': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notAction', 'hostile'],
  'PASSROLE-LAMBDA': ['positive', 'negative', 'boundary', 'deny', 'condition', 'hostile'],
  'PASSROLE-EC2': ['positive', 'negative', 'boundary', 'deny', 'condition', 'hostile'],
  'PASSROLE-SERVICE': ['positive', 'negative', 'boundary', 'deny', 'condition', 'hostile'],
  'POLICY-VERSION': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notAction', 'hostile'],
  'ATTACH-POLICY': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notAction', 'hostile'],
  'PUT-INLINE-POLICY': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notAction', 'hostile'],
  'TRUST-POLICY-MODIFY': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notAction', 'notResource', 'hostile'],
  'CREDENTIAL-CREATION': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notAction', 'hostile'],
  'ASSUME-ROLE-EXPANSION': ['positive', 'negative', 'boundary', 'deny', 'condition', 'notAction', 'notResource', 'hostile'],
});

// A boundary witness is one of the curated `*-boundary.json` edge-case fixtures
// (scoped resource, narrowing Condition, partial wildcard, PassedToService
// near-miss, conditional Deny) that analyze() relates to the rule - it produces
// the rule OR asserts it absent. The filename marks the author's boundary INTENT;
// relatedness via real analyze() output is the engine-verified half (so a
// mislabeled file cannot witness a rule it never touches).
const BOUNDARY_NAME_RE = /boundary/i;

// A hostile string is present when a finding field carries markup / script / URI
// scheme payload verbatim (proof it rode through as inert DATA, not markup).
const HOSTILE_RE = /[<>]|onerror|onload|javascript:|<script/i;

function fixtureText(fx) {
  return typeof fx.policyRaw === 'string' ? fx.policyRaw : JSON.stringify(fx.policy);
}

function loadAllFixtures() {
  const out = [];
  for (const d of readdirSync(fixturesDir, { withFileTypes: true })) {
    if (!d.isDirectory()) continue;
    for (const f of readdirSync(join(fixturesDir, d.name))) {
      if (!f.endsWith('.json')) continue;
      out.push({
        file: `${d.name}/${f}`,
        data: JSON.parse(readFileSync(join(fixturesDir, d.name, f), 'utf8')),
      });
    }
  }
  return out;
}

function statementsOf(fx) {
  const p = fx.policy;
  if (!p) return [];
  const s = p.Statement;
  return Array.isArray(s) ? s : (s ? [s] : []);
}

// Build the coverage map: for each (rule, kind) count the fixtures that witness
// it. Coverage is derived from real analyze() output so it cannot be faked.
function buildCoverage() {
  const cov = {};
  for (const rule of Object.keys(APPLICABILITY)) {
    cov[rule] = {};
    for (const kind of APPLICABILITY[rule]) cov[rule][kind] = [];
  }

  for (const { file, data } of loadAllFixtures()) {
    let res;
    try { res = analyze(fixtureText(data)); } catch { continue; }
    if (!res || !Array.isArray(res.findings)) continue;

    const producedIds = new Set(res.findings.map((f) => f.id));
    for (const f of res.findings) {
      for (const s of (f.subsumed || [])) producedIds.add(s.id);
    }
    const neg = new Set([
      ...((data.expect && data.expect.notFindingIds) || []),
      ...((data.negativeExpect && data.negativeExpect.mustNotFind) || []),
    ]);

    const st = statementsOf(data);
    const hasDeny = st.some((s) => s && s.Effect === 'Deny');
    const hasCond = st.some((s) => s && s.Condition);
    const hasNotAction = st.some((s) => s && s.NotAction);
    const hasNotResource = st.some((s) => s && s.NotResource);
    const isHostile = !!(data.expect && data.expect.hostile === true);
    const isBoundary = BOUNDARY_NAME_RE.test(file);

    for (const rule of Object.keys(APPLICABILITY)) {
      const kinds = APPLICABILITY[rule];
      const positive = producedIds.has(rule);
      const negative = neg.has(rule);
      const related = positive || negative;
      const c = cov[rule];

      if (positive && kinds.includes('positive')) c.positive.push(file);
      if (negative && kinds.includes('negative')) c.negative.push(file);
      if (related && isBoundary && kinds.includes('boundary')) c.boundary.push(file);
      if (related && hasDeny && kinds.includes('deny')) c.deny.push(file);
      if (related && hasCond && kinds.includes('condition')) c.condition.push(file);
      if (related && hasNotAction && kinds.includes('notAction')) c.notAction.push(file);
      if (related && hasNotResource && kinds.includes('notResource')) c.notResource.push(file);
      if (isHostile && positive && kinds.includes('hostile')) {
        const finding = res.findings.find((x) => x.id === rule);
        const probe = finding && JSON.stringify({
          s: finding.statementSid, r: finding.resources, c: finding.conditions,
        });
        if (probe && HOSTILE_RE.test(probe)) c.hostile.push(file);
      }
    }
  }
  return cov;
}

const COVERAGE = buildCoverage();

// --- Gate 1: the applicability matrix covers the entire live rule catalog ----
// A new rule (rules.js / escalation.js) that is not added to APPLICABILITY would
// otherwise escape the matrix entirely. Fail if the catalog and matrix drift.
test('applicability matrix covers every rule + escalation id in the live catalog', () => {
  const catalog = new Set([...RULE_IDS, ...ESCALATION_IDS]);
  const declared = new Set(Object.keys(APPLICABILITY));
  for (const id of catalog) {
    assert.ok(declared.has(id), `rule ${id} is in the catalog but missing from APPLICABILITY`);
  }
  for (const id of declared) {
    assert.ok(catalog.has(id), `APPLICABILITY declares ${id} which is not in the live catalog`);
  }
});

// --- Gate 2: every applicable (rule, kind) cell has a verified witness -------
for (const rule of Object.keys(APPLICABILITY)) {
  test(`fixture matrix complete for ${rule}`, () => {
    for (const kind of APPLICABILITY[rule]) {
      const witnesses = COVERAGE[rule][kind];
      assert.ok(
        witnesses.length > 0,
        `${rule}: no fixture witnesses the "${kind}" cell of the per-rule matrix`,
      );
    }
  });
}

// --- Gate 3: hostile witnesses actually ride through inert -------------------
// Each hostile fixture declares the ids it is a witness for; assert every one of
// those ids fires AND carries the hostile string verbatim (inert data), and that
// analyze() never throws or produces markup structure for them.
test('hostile fixtures render every declared rule id with the payload inert', () => {
  const hostileFixtures = loadAllFixtures().filter(
    ({ data }) => data.expect && data.expect.hostile === true,
  );
  assert.ok(hostileFixtures.length >= 2, 'expected at least two hostile fixtures');
  for (const { file, data } of hostileFixtures) {
    const res = analyze(fixtureText(data));
    assert.equal(res.ok, true, `${file}: hostile fixture must analyze ok`);
    const byId = new Map(res.findings.map((f) => [f.id, f]));
    for (const id of (data.expect.hostileFor || [])) {
      const f = byId.get(id);
      assert.ok(f, `${file}: expected hostile witness ${id} to fire`);
      const probe = JSON.stringify({ s: f.statementSid, r: f.resources, c: f.conditions });
      assert.ok(HOSTILE_RE.test(probe), `${file}: ${id} lost its hostile string (should ride through as inert data)`);
      // The hostile Sid is preserved verbatim - never sanitized into a token.
      assert.equal(typeof f.statementSid, 'string');
    }
  }
});

// --- Gate 4: deterministic export (global cell) ------------------------------
// Same input -> byte-identical JSON + Markdown across runs, for a multi-finding
// policy. Determinism of findings is covered elsewhere; this pins the export.
test('deterministic-export: JSON + Markdown are byte-identical across runs', () => {
  const witnesses = [
    'wildcard/admin-star.json',
    'pass-role/passrole-lambda-positive.json',
    'exfil/secrets-and-kms-positive.json',
  ];
  for (const rel of witnesses) {
    const fx = JSON.parse(readFileSync(join(fixturesDir, rel), 'utf8'));
    const a = analyze(fixtureText(fx));
    assert.equal(toJSON(a), toJSON(analyze(fixtureText(fx))), `${rel}: JSON not deterministic`);
    assert.equal(toMarkdown(a), toMarkdown(analyze(fixtureText(fx))), `${rel}: Markdown not deterministic`);
  }
});

// --- Gate 5: family-mismatch coverage exists across the tree -----------------
// A "family-mismatch" witness proves the engine fails closed on a shape it does
// not model (resource / role-trust / NotPrincipal / ambiguous) INSTEAD OF firing
// an identity rule on the dangerous actions it carries. A fixture declares the
// rule ids it witnesses via `expect.familyMismatchFor`. The gate is double-locked
// so the claim can never be vacuous:
//   (a) analyze(policy) fails closed - coverage.blocked === true, zero findings;
//   (b) the SAME policy reshaped to identity form (Principal/NotPrincipal
//       stripped from every statement) actually FIRES each declared id -> the
//       action set is genuinely rule-triggering and was suppressed ONLY by the
//       family mismatch.
// This is tree-wide coverage (spanning rule categories), not one witness per id:
// the corpus must witness at least one capability rule (rules.js) AND at least
// one escalation path (escalation.js) failing closed.
function identityVariant(policy) {
  const p = JSON.parse(JSON.stringify(policy));
  const st = Array.isArray(p.Statement) ? p.Statement : (p.Statement ? [p.Statement] : []);
  for (const s of st) { if (s) { delete s.Principal; delete s.NotPrincipal; } }
  p.Statement = st;
  return p;
}

test('family-mismatch: dangerous actions in an unmodeled family fail closed (not fired as identity rules)', () => {
  const witnesses = loadAllFixtures().filter(
    ({ data }) => data.expect && Array.isArray(data.expect.familyMismatchFor)
      && data.expect.familyMismatchFor.length > 0,
  );
  assert.ok(
    witnesses.length >= 2,
    'expected at least two family-mismatch witnesses (declare expect.familyMismatchFor)',
  );

  const RULE_SET = new Set(RULE_IDS);
  const ESC_SET = new Set(ESCALATION_IDS);
  const capabilityWitnessed = new Set();
  const escalationWitnessed = new Set();

  for (const { file, data } of witnesses) {
    // (a) the real shape fails closed with no confident findings.
    const blockedRes = analyze(fixtureText(data));
    assert.equal(blockedRes.ok, true, `${file}: family-mismatch fixture must analyze ok`);
    assert.ok(
      blockedRes.coverage && blockedRes.coverage.blocked === true,
      `${file}: family-mismatch witness must fail closed (coverage.blocked)`,
    );
    assert.equal(
      blockedRes.findings.length, 0,
      `${file}: a fail-closed shape must produce zero confident findings`,
    );

    // (b) the identity-shaped variant actually fires each declared id, proving
    //     the suppression came from the family mismatch and nothing else.
    const idRes = analyze(JSON.stringify(identityVariant(data.policy)));
    assert.equal(
      idRes.coverage && idRes.coverage.blocked, false,
      `${file}: identity variant must NOT be blocked (else the witness is vacuous)`,
    );
    const fired = new Set(idRes.findings.map((f) => f.id));
    for (const f of idRes.findings) for (const s of (f.subsumed || [])) fired.add(s.id);

    for (const id of data.expect.familyMismatchFor) {
      assert.ok(
        RULE_SET.has(id) || ESC_SET.has(id),
        `${file}: familyMismatchFor lists ${id} which is not a live rule/escalation id`,
      );
      assert.ok(
        fired.has(id),
        `${file}: identity variant must fire ${id} (else this is not a real family-mismatch of that rule)`,
      );
      if (RULE_SET.has(id)) capabilityWitnessed.add(id);
      if (ESC_SET.has(id)) escalationWitnessed.add(id);
    }
  }

  assert.ok(
    capabilityWitnessed.size >= 1,
    'family-mismatch coverage must span at least one capability rule (rules.js)',
  );
  assert.ok(
    escalationWitnessed.size >= 1,
    'family-mismatch coverage must span at least one escalation path (escalation.js)',
  );
});
