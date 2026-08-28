// S1-dataexfil-arn: the "must-warn" corpus - the fail-CLOSED counterpart to the
// negative corpus. Each fixture is a policy that carries REAL risk (a broad-scope
// bulk object read) which the engine MUST surface: it must fire the declared
// finding AND drive a NON-ZERO CLI exit. These lock the HIGH fail-open where
// DATA-EXFIL bulk-read detection was blind to ARN-wildcard resources - a bulk read
// on arn:aws:s3:::*/* (also arn:aws:s3:::* , arn:aws:s3:::*/prefix* , arn:aws:* ,
// arn:*:*:*:*:* , a leading-wildcard bucket name) formerly returned findings=[]
// status complete exit 0 CLEAN on BOTH the browser engine and the CLI/Action
// (threat-model T8: a clean report on a risky policy is a security harm).
//
// This suite double-locks each fixture:
//   1. the SHIPPED browser engine analyze() reports the finding (mustFind present,
//      mustNotFind absent, severity not understated), and
//   2. the CLI/Action adapter scan() analyzes cleanly (analysisStatus complete -
//      NOT a fail-closed error) yet returns a NON-ZERO exit with blockingCount>=1,
//      so a CI gate actually fails on the policy.
//
//   mustWarnExpect.mustFind[]            ids that MUST be present
//   mustWarnExpect.mustNotFind[]         ids that MUST be absent (no over-firing)
//   mustWarnExpect.minSeverity{id:sev}   a present finding's severity must be at
//                                        least this severe (so it blocks at the
//                                        default 'high' threshold)
//   mustWarnExpect.nonZeroExit           the CLI must exit non-zero on this policy
//
// Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze, SEVERITY_ORDER } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../cli/scan.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const mustWarnDir = join(here, '..', 'fixtures', 'must-warn');

function loadMustWarnFixtures() {
  if (!existsSync(mustWarnDir)) return [];
  return readdirSync(mustWarnDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `must-warn/${f}`, data: JSON.parse(readFileSync(join(mustWarnDir, f), 'utf8')) }));
}

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

const FIXTURES = loadMustWarnFixtures();

test('must-warn corpus is present and well-formed (>=5 fixtures, each policy + mustWarnExpect + note)', () => {
  assert.ok(FIXTURES.length >= 5, `expected >=5 must-warn fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy object`);
    assert.ok(data.mustWarnExpect && typeof data.mustWarnExpect === 'object', `${file}: has a mustWarnExpect`);
    assert.ok(Array.isArray(data.mustWarnExpect.mustFind) && data.mustWarnExpect.mustFind.length > 0,
      `${file}: mustWarnExpect.mustFind is a non-empty array`);
    assert.equal(typeof data.note, 'string', `${file}: has a note string`);
    assert.ok(data.note.length > 0, `${file}: note is non-empty`);
  }
});

test('shipped engine analyze() fires the required finding for every must-warn fixture (no fail-open, no over-firing)', () => {
  for (const { file, data } of FIXTURES) {
    const expect = data.mustWarnExpect || {};
    const result = analyze(fixtureText(data));

    // A must-warn policy is valid input that MUST analyze cleanly and surface risk;
    // it must never vacuously "pass" by failing to analyze.
    assert.equal(result.ok, true, `${file}: expected a clean analysis; got errors ${JSON.stringify(result.errors)}`);
    assert.ok(result.findings.length > 0, `${file}: a risky policy must not report findings=[] (fail-open, T8)`);

    const ids = result.findings.map((f) => f.id);
    const idSet = new Set(ids);

    for (const want of expect.mustFind || []) {
      assert.ok(idSet.has(want), `${file}: MUST find ${want}; got [${ids.join(', ')}]`);
    }
    for (const notWant of expect.mustNotFind || []) {
      assert.ok(!idSet.has(notWant), `${file}: MUST NOT find ${notWant} (over-firing); got [${ids.join(', ')}]`);
    }

    // Severity must be at least as severe as the floor, so the finding actually
    // blocks at the default 'high' threshold rather than slipping under it.
    for (const [id, minSev] of Object.entries(expect.minSeverity || {})) {
      const floor = SEVERITY_ORDER[minSev];
      assert.ok(floor !== undefined, `${file}: unknown minSeverity level "${minSev}"`);
      for (const f of result.findings.filter((x) => x.id === id)) {
        assert.ok(
          SEVERITY_ORDER[f.severity] <= floor,
          `${file}: ${id} severity "${f.severity}" is below the required floor "${minSev}"`,
        );
      }
    }
  }
});

test('CLI scan() exits NON-ZERO on every must-warn fixture (analyzed clean, but blocking)', () => {
  for (const { file, data } of FIXTURES) {
    const expect = data.mustWarnExpect || {};
    if (!expect.nonZeroExit) continue;
    const r = scan({ text: fixtureText(data), family: 'identity' });

    // The policy is analyzable: it must reach a COMPLETE analysis (not a
    // fail-closed error path) and then BLOCK on its findings - proving the exit
    // is non-zero because of a real finding, not because the input was rejected.
    assert.equal(r.analysisStatus, ANALYSIS_STATUS.COMPLETE,
      `${file}: expected a complete analysis; got ${r.analysisStatus} (${JSON.stringify(r.analysisStates || [])})`);
    assert.equal(r.exitCode, EXIT.FINDINGS, `${file}: expected exit ${EXIT.FINDINGS} (findings); got ${r.exitCode}`);
    assert.notEqual(r.exitCode, EXIT.CLEAN, `${file}: must NOT exit 0/clean on a risky policy (fail-open, T8)`);
    assert.ok(r.blockingCount >= 1, `${file}: expected blockingCount>=1; got ${r.blockingCount}`);
  }
});

test('must-warn analysis is deterministic (same input -> deep-equal twice)', () => {
  for (const { file, data } of FIXTURES) {
    const text = fixtureText(data);
    assert.deepEqual(analyze(text), analyze(text), `${file}: analyze() must be deterministic`);
  }
});
