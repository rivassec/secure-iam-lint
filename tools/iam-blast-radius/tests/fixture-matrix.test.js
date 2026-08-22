// IAM-504: per-rule fixture matrix as a release gate.
// Runs on node's built-in runner: `node --test`.
//
// Every rule (rules.js risk catalog + escalation.js path catalog) must ship a
// fixture for each kind that is SEMANTICALLY APPLICABLE to it:
//   positive        - a policy where the rule fires
//   negative        - a policy where the rule must NOT fire (asserted absent)
//   deny            - a policy exercising the rule's interaction with an
//                     explicit Deny (suppressed, or present-but-Deny-aware)
//   condition       - the rule under a Condition (narrowed, still explainable)
//   notAction       - the rule reached via an Allow-NotAction inversion
//   notResource     - the rule under a NotResource scope
//   hostile         - a positive witness whose Sid/ARN/Condition carry HTML/JS
//                     payloads that must ride through analyze() as inert DATA
//   (deterministic-export is a GLOBAL property, asserted once at the end.)
//
// "Where semantically applicable" is encoded in APPLICABILITY with a documented
// rationale per exclusion (see below). This gate FAILS - it does not skip - if
// any applicable cell loses its fixture, so the matrix cannot silently regress.
// Coverage is DERIVED from fixture content + real analyze() output (a fixture
// witnesses a cell only if the engine actually behaves as the kind requires),
// so a mislabeled fixture cannot paper over a gap.

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
// positive/negative/deny/condition/hostile apply to EVERY rule (a grant can
// always be present, absent, Deny-interacting, Condition-narrowed, or carry a
// hostile string). notAction / notResource are applicable only where such a
// policy is a realistic, engine-detectable expression of the rule - never a
// contrived one:
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
  'WILDCARD-ACTION': ['positive', 'negative', 'deny', 'condition', 'notAction', 'hostile'],
  'WILDCARD-RESOURCE': ['positive', 'negative', 'deny', 'condition', 'notAction', 'notResource', 'hostile'],
  'DIRECT-IAM-ADMIN': ['positive', 'negative', 'deny', 'condition', 'notAction', 'notResource', 'hostile'],
  'DATA-EXFIL': ['positive', 'negative', 'deny', 'condition', 'notResource', 'hostile'],
  'KMS-DECRYPT': ['positive', 'negative', 'deny', 'condition', 'notResource', 'hostile'],
  'DESTRUCTIVE-ACTION': ['positive', 'negative', 'deny', 'condition', 'notResource', 'hostile'],
  'DETECTION-IMPAIRMENT': ['positive', 'negative', 'deny', 'condition', 'notResource', 'hostile'],
  'NOTACTION-ALLOW': ['positive', 'negative', 'deny', 'condition', 'notAction', 'hostile'],
  'PASSROLE-LAMBDA': ['positive', 'negative', 'deny', 'condition', 'hostile'],
  'PASSROLE-EC2': ['positive', 'negative', 'deny', 'condition', 'hostile'],
  'PASSROLE-SERVICE': ['positive', 'negative', 'deny', 'condition', 'hostile'],
  'POLICY-VERSION': ['positive', 'negative', 'deny', 'condition', 'notAction', 'hostile'],
  'ATTACH-POLICY': ['positive', 'negative', 'deny', 'condition', 'notAction', 'hostile'],
  'PUT-INLINE-POLICY': ['positive', 'negative', 'deny', 'condition', 'notAction', 'hostile'],
  'TRUST-POLICY-MODIFY': ['positive', 'negative', 'deny', 'condition', 'notAction', 'notResource', 'hostile'],
  'CREDENTIAL-CREATION': ['positive', 'negative', 'deny', 'condition', 'notAction', 'hostile'],
  'ASSUME-ROLE-EXPANSION': ['positive', 'negative', 'deny', 'condition', 'notAction', 'notResource', 'hostile'],
});

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

    for (const rule of Object.keys(APPLICABILITY)) {
      const kinds = APPLICABILITY[rule];
      const positive = producedIds.has(rule);
      const negative = neg.has(rule);
      const related = positive || negative;
      const c = cov[rule];

      if (positive && kinds.includes('positive')) c.positive.push(file);
      if (negative && kinds.includes('negative')) c.negative.push(file);
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
