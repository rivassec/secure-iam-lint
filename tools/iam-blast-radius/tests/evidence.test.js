// IAM-504: explainable-evidence completeness as a release gate.
// Runs on node's built-in runner: `node --test`.
//
// Every finding analyze() produces - across every fixture - must expose the
// full human- + machine-readable evidence set the story requires:
//   policy family, statement index + Sid (Sid is DISPLAY evidence, not stable
//   identity), normalized action(s), normalized resource(s), relevant condition,
//   rule id, certainty (policyEvidence + pathExploitability), and the limitation.
// The JSON export must carry the same per-finding evidence verbatim (machine
// readable), and subsumed sub-findings (IAM-105/201) must be equally explainable.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { toJSON } from '../../../content/tools/iam-blast-radius/engine/report.js';
import { RULE_IDS } from '../../../content/tools/iam-blast-radius/engine/rules.js';
import { ESCALATION_IDS } from '../../../content/tools/iam-blast-radius/engine/escalation.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

const CATALOG = new Set([...RULE_IDS, ...ESCALATION_IDS]);
const CERTAINTY = new Set(['high', 'medium', 'low']);

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

// Assert the full explainable-evidence contract on a single finding.
function assertEvidenceComplete(f, ctx) {
  // Rule id (machine-readable identity of the rule that fired).
  assert.ok(CATALOG.has(f.id), `${ctx}: finding id ${f.id} not in the live catalog`);
  // Policy family the finding was evaluated under (IAM-504 addition).
  assert.ok(
    typeof f.policyFamily === 'string' && f.policyFamily.length > 0,
    `${ctx}: finding ${f.id} missing policyFamily evidence`,
  );
  // Statement evidence: index (stable) + Sid (display evidence, may be an
  // "(index N)" placeholder but is always a non-empty string).
  assert.equal(typeof f.statementIndex, 'number', `${ctx}: ${f.id} missing statementIndex`);
  assert.ok(
    typeof f.statementSid === 'string' && f.statementSid.length > 0,
    `${ctx}: ${f.id} missing statementSid display evidence`,
  );
  // Normalized action(s) + resource(s).
  assert.ok(Array.isArray(f.actions) && f.actions.length > 0, `${ctx}: ${f.id} actions must be a non-empty array`);
  assert.ok(f.actions.every((a) => typeof a === 'string'), `${ctx}: ${f.id} actions must be strings`);
  assert.ok(Array.isArray(f.resources), `${ctx}: ${f.id} resources must be an array`);
  assert.ok(f.resources.every((r) => typeof r === 'string'), `${ctx}: ${f.id} resources must be strings`);
  // Relevant condition: the KEY must be present (null when the statement has no
  // Condition); when present it is an object carried as inert data.
  assert.ok('conditions' in f, `${ctx}: ${f.id} must expose a conditions field (null allowed)`);
  assert.ok(
    f.conditions === null || typeof f.conditions === 'object',
    `${ctx}: ${f.id} conditions must be null or an object`,
  );
  // Certainty: two orthogonal signals, each from the fixed vocabulary.
  assert.ok(CERTAINTY.has(f.policyEvidence), `${ctx}: ${f.id} bad policyEvidence ${f.policyEvidence}`);
  assert.ok(CERTAINTY.has(f.pathExploitability), `${ctx}: ${f.id} bad pathExploitability ${f.pathExploitability}`);
  // Limitation: present, and carries the capability-not-effective caveat so the
  // finding can never be read as effective permissions.
  assert.ok(
    typeof f.limit === 'string' && /not effective access/i.test(f.limit),
    `${ctx}: ${f.id} limitation missing / lacks the capability-not-effective caveat`,
  );
  // Provenance so a downloaded finding is traceable to a rule revision + doc.
  assert.ok(typeof f.ruleVersion === 'string' && f.ruleVersion.length > 0, `${ctx}: ${f.id} missing ruleVersion`);
  assert.ok(/^https:\/\//.test(f.docRef || ''), `${ctx}: ${f.id} docRef must be an https URL`);
}

test('every finding across every fixture exposes the complete evidence set', () => {
  let sawFinding = false;
  for (const { file, data } of loadAllFixtures()) {
    let res;
    assert.doesNotThrow(() => { res = analyze(fixtureText(data)); }, `${file}: analyze threw`);
    if (!res.ok) continue;
    for (const f of res.findings) {
      sawFinding = true;
      assertEvidenceComplete(f, file);
      // Subsumed sub-findings (folded risk factors) are findings too and must be
      // equally explainable - the family stamp reaches them.
      for (const s of (f.subsumed || [])) {
        assert.ok(
          typeof s.policyFamily === 'string' && s.policyFamily.length > 0,
          `${file}: subsumed ${s.id} under ${f.id} missing policyFamily evidence`,
        );
      }
    }
  }
  assert.ok(sawFinding, 'expected at least one finding across the fixture corpus');
});

test('policy family stamped on findings matches the analysis coverage family', () => {
  // A supported identity policy: every finding carries the effective family and
  // it agrees with the coverage summary the exports advertise.
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'wildcard', 'admin-star.json'), 'utf8'));
  const res = analyze(fixtureText(fx));
  assert.equal(res.family, 'identity');
  for (const f of res.findings) assert.equal(f.policyFamily, 'identity', `${f.id} family mismatch`);
});

test('JSON export carries the per-finding evidence set verbatim (machine-readable)', () => {
  const fx = JSON.parse(readFileSync(join(fixturesDir, 'pass-role', 'passrole-lambda-positive.json'), 'utf8'));
  const parsed = JSON.parse(toJSON(analyze(fixtureText(fx))));
  assert.ok(Array.isArray(parsed.findings) && parsed.findings.length > 0);
  for (const f of parsed.findings) {
    for (const key of [
      'id', 'policyFamily', 'statementIndex', 'statementSid', 'actions',
      'resources', 'conditions', 'policyEvidence', 'pathExploitability',
      'limit', 'ruleVersion', 'docRef',
    ]) {
      assert.ok(Object.prototype.hasOwnProperty.call(f, key), `export finding ${f.id} missing ${key}`);
    }
    assert.equal(f.policyFamily, 'identity');
  }
});
