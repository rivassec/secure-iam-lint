// IAM-505: built-in abuse-case sample policies.
//
// The shipped UI (samples.js) offers a small set of loadable sample policies.
// A UI sample is NOT a substitute for a regression fixture, so this suite pins
// the samples down as engine behavior:
//
//   1. SAMPLES is well-formed: unique ids, required display fields, at least one
//      obvious escalation and at least one "scary-but-neutralized" sample.
//   2. Samples are fictional + deterministic: every account id is the AWS
//      documentation example account 111122223333, and analyze() is stable.
//   3. Each sample has a matching engine fixture under fixtures/samples/ whose
//      policy is byte-identical to the shipped sample - the loadable sample and
//      the tested behavior can never silently drift apart.
//   4. analyze() on each sample satisfies the fixture's sampleExpect contract
//      (findings present/absent, severity not overstated, and - for the
//      neutralized fail-closed case - a blocking coverage state with the exact
//      code + JSON path).
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze, SEVERITY_ORDER } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { SAMPLES } from '../../../content/tools/iam-blast-radius/samples.js';

const here = dirname(fileURLToPath(import.meta.url));
const samplesDir = join(here, '..', 'fixtures', 'samples');

function loadFixture(id) {
  const file = join(samplesDir, `${id}.json`);
  assert.ok(existsSync(file), `sample "${id}" must have a matching fixture at fixtures/samples/${id}.json`);
  return JSON.parse(readFileSync(file, 'utf8'));
}

test('SAMPLES is a well-formed, non-empty, unique-id set with the required display fields', () => {
  assert.ok(Array.isArray(SAMPLES), 'SAMPLES is an array');
  assert.ok(SAMPLES.length >= 2, `expected a small set (>=2), found ${SAMPLES.length}`);

  const ids = new Set();
  for (const s of SAMPLES) {
    assert.equal(typeof s.id, 'string', 'sample has a string id');
    assert.ok(s.id.length > 0, 'sample id is non-empty');
    assert.ok(!ids.has(s.id), `sample id "${s.id}" is unique`);
    ids.add(s.id);
    assert.equal(typeof s.label, 'string', `${s.id}: has a string label`);
    assert.ok(s.label.length > 0, `${s.id}: label is non-empty`);
    assert.equal(typeof s.description, 'string', `${s.id}: has a string description`);
    assert.ok(s.description.length > 0, `${s.id}: description is non-empty`);
    assert.ok(['escalation', 'neutralized'].includes(s.kind), `${s.id}: kind is escalation|neutralized`);
    assert.ok(s.policy && typeof s.policy === 'object', `${s.id}: has a policy object`);
  }
});

test('sample set includes at least one obvious escalation and at least one scary-but-neutralized sample', () => {
  const kinds = SAMPLES.map((s) => s.kind);
  assert.ok(kinds.includes('escalation'), 'at least one escalation sample');
  assert.ok(kinds.includes('neutralized'), 'at least one neutralized sample');
});

test('samples are fictional: every account id is the AWS example account 111122223333', () => {
  for (const s of SAMPLES) {
    const text = JSON.stringify(s.policy);
    // Any 12-digit run that is not the documentation example account is a real
    // (or real-looking) account id and must not ship in a built-in sample.
    const accountIds = text.match(/\b\d{12}\b/g) || [];
    for (const acct of accountIds) {
      assert.equal(acct, '111122223333', `${s.id}: account id "${acct}" is not the example account 111122223333`);
    }
  }
});

test('every fixtures/samples/ fixture corresponds to a shipped SAMPLE (no orphan fixtures)', () => {
  const sampleIds = new Set(SAMPLES.map((s) => s.id));
  const files = existsSync(samplesDir)
    ? readdirSync(samplesDir).filter((f) => f.endsWith('.json'))
    : [];
  for (const f of files) {
    const data = JSON.parse(readFileSync(join(samplesDir, f), 'utf8'));
    assert.equal(typeof data.sampleId, 'string', `${f}: carries a sampleId`);
    assert.ok(sampleIds.has(data.sampleId), `${f}: sampleId "${data.sampleId}" matches a shipped SAMPLE`);
  }
  assert.equal(files.length, SAMPLES.length, 'one fixture per sample (no extras, none missing)');
});

test('each SAMPLE has a matching engine fixture with a byte-identical policy', () => {
  for (const s of SAMPLES) {
    const fx = loadFixture(s.id);
    assert.equal(fx.sampleId, s.id, `${s.id}: fixture sampleId matches`);
    // Deep-equal the policy so the loadable sample and the tested fixture can
    // never silently drift apart.
    assert.deepEqual(s.policy, fx.policy, `${s.id}: shipped sample policy matches its fixture policy`);
  }
});

test('analyze() on each sample is deterministic (same input -> deep-equal twice)', () => {
  for (const s of SAMPLES) {
    const text = JSON.stringify(s.policy);
    assert.deepEqual(analyze(text), analyze(text), `${s.id}: analyze() must be deterministic`);
  }
});

test('analyze() on each sample satisfies its fixture sampleExpect contract', () => {
  for (const s of SAMPLES) {
    const fx = loadFixture(s.id);
    const expect = fx.sampleExpect || {};
    const result = analyze(JSON.stringify(s.policy));

    assert.equal(result.ok, true, `${s.id}: sample analyzes cleanly`);

    const blocked = !!(result.coverage && result.coverage.blocked);
    if (typeof expect.blocked === 'boolean') {
      assert.equal(blocked, expect.blocked, `${s.id}: coverage.blocked === ${expect.blocked}`);
    }

    const ids = result.findings.map((f) => f.id);
    const idSet = new Set(ids);

    for (const want of expect.mustFind || []) {
      assert.ok(idSet.has(want), `${s.id}: MUST find ${want}; got [${ids.join(', ')}]`);
    }
    for (const notWant of expect.mustNotFind || []) {
      assert.ok(!idSet.has(notWant), `${s.id}: MUST NOT find ${notWant}; got [${ids.join(', ')}]`);
    }

    // Exact severity, where the fixture pins it (the obvious-escalation sample).
    for (const [id, sev] of Object.entries(expect.severity || {})) {
      for (const f of result.findings.filter((x) => x.id === id)) {
        assert.equal(f.severity, sev, `${s.id}: ${id} severity is "${sev}"`);
      }
    }

    // Severity must not be overstated above the fixture cap (the neutralized
    // broad-services sample: wildcards high, never critical).
    for (const [id, maxSev] of Object.entries(expect.maxSeverity || {})) {
      const cap = SEVERITY_ORDER[maxSev];
      assert.ok(cap !== undefined, `${s.id}: unknown maxSeverity level "${maxSev}"`);
      for (const f of result.findings.filter((x) => x.id === id)) {
        assert.ok(
          SEVERITY_ORDER[f.severity] >= cap,
          `${s.id}: ${id} severity "${f.severity}" overstates the cap "${maxSev}"`,
        );
      }
    }

    // Fail-closed neutralization: the exact blocking code + JSON path.
    if (Array.isArray(expect.blockingCodes)) {
      const got = (result.coverage && result.coverage.blockingCodes) || [];
      for (const want of expect.blockingCodes) {
        assert.ok(
          got.some((b) => b.code === want.code && b.path === want.path),
          `${s.id}: expected blocking code ${want.code} @ ${want.path}; got ${JSON.stringify(got)}`,
        );
      }
    }
  }
});

test('at least one neutralized sample demonstrates a fail-closed/coverage or Deny-suppression outcome', () => {
  let demonstrated = false;
  for (const s of SAMPLES.filter((x) => x.kind === 'neutralized')) {
    const result = analyze(JSON.stringify(s.policy));
    const blocked = !!(result.coverage && result.coverage.blocked);
    const ids = new Set(result.findings.map((f) => f.id));
    // Fail-closed (blocked coverage) OR a dangerous capability that a Deny /
    // boundary shape suppressed (no DATA-EXFIL / no escalation finding).
    if (blocked || (!ids.has('DATA-EXFIL') && !ids.has('PASSROLE-LAMBDA'))) {
      demonstrated = true;
      break;
    }
  }
  assert.ok(demonstrated, 'a neutralized sample must show fail-closed/coverage or Deny suppression');
});
