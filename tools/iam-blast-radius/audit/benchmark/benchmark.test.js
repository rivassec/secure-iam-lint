// Ground-truth benchmark: the engine must catch every published IAM privesc method.
//
// Drives analyze() AND the CLI scan() over the Rhino Security Labs privesc catalog
// (corpus.mjs) and asserts, for each method:
//   1. scan() never reads CLEAN  (fail-closed invariant, threat-model T8), and
//   2. the specific named detector fires (a named escalation, not just the
//      incomplete-coverage backstop).
//
// A failure here means a published, real-world privesc primitive slipped the
// engine -- either a regression or a newly-out-of-model method to handle
// explicitly. Prints a scorecard line for the README/badge evidence.
//
// Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT } from '../../../../cli/scan.mjs';
import { CORPUS, SECOND_TIER, PART2, SUBJECT_ACCOUNT } from './corpus.mjs';

const CTX = { subjectAccount: SUBJECT_ACCOUNT, partition: 'aws' };

let caught = 0;
let tierNamed = 0;
let tierBackstop = 0;
let p2Named = 0;
let p2Backstop = 0;
for (const c of CORPUS) {
  test(`privesc catalog: ${c.id} is caught (not CLEAN, fires ${c.finding})`, () => {
    const text = JSON.stringify({ Version: '2012-10-17', Statement: c.statements });

    // Boundary: the CLI must never read CLEAN for a real privesc primitive.
    const s = scan({ text, family: 'identity', subjectAccount: SUBJECT_ACCOUNT, partition: 'aws' });
    assert.notEqual(s.exitCode, EXIT.CLEAN, `${c.id}: scan() reported CLEAN on a real privesc method`);

    // Finding-level: the specific named detector must fire.
    const res = analyze(text, CTX);
    assert.equal(res.ok, true, `${c.id}: analyze() did not complete ok`);
    const ids = (res.findings || []).map((f) => f.id);
    assert.ok(ids.includes(c.finding),
      `${c.id}: expected detector ${c.finding}, got [${ids.join(', ') || 'none'}]`);
    caught++;
  });
}

// Second tier: every method must still fail closed (never CLEAN). Where `finding`
// is set the specific detector must fire; where it is null the method is caught by
// the incomplete-coverage backstop (recorded honestly, a named-detector candidate).
for (const c of SECOND_TIER) {
  test(`second tier: ${c.id} never CLEAN${c.finding ? ` (fires ${c.finding})` : ' (backstop)'}`, () => {
    const text = JSON.stringify({ Version: '2012-10-17', Statement: c.statements });
    const s = scan({ text, family: 'identity', subjectAccount: SUBJECT_ACCOUNT, partition: 'aws' });
    assert.notEqual(s.exitCode, EXIT.CLEAN, `${c.id}: scan() reported CLEAN on a real privesc method`);

    const res = analyze(text, CTX);
    assert.equal(res.ok, true, `${c.id}: analyze() did not complete ok`);
    if (c.finding) {
      const ids = (res.findings || []).map((f) => f.id);
      assert.ok(ids.includes(c.finding), `${c.id}: expected ${c.finding}, got [${ids.join(', ') || 'none'}]`);
      tierNamed++;
    } else {
      // Backstop: no named finding required, but coverage must be flagged incomplete
      // so the non-CLEAN verdict is a deliberate "cannot fully decide", not an accident.
      assert.equal(res.coverage?.summary?.incomplete, true,
        `${c.id}: backstop case must mark coverage incomplete`);
      tierBackstop++;
    }
  });
}

// Rhino Part 2 (repo methods 22-28): completes the full 28. Same fail-closed
// invariant; named where a detector exists, backstop otherwise (CodeStar 23-25 is a
// deprecated/removed AWS service, left as a documented backstop).
for (const c of PART2) {
  test(`rhino 22-28: ${c.id} never CLEAN${c.finding ? ` (fires ${c.finding})` : c.deprecated ? ' (backstop, deprecated service)' : ' (backstop)'}`, () => {
    const text = JSON.stringify({ Version: '2012-10-17', Statement: c.statements });
    const s = scan({ text, family: 'identity', subjectAccount: SUBJECT_ACCOUNT, partition: 'aws' });
    assert.notEqual(s.exitCode, EXIT.CLEAN, `${c.id}: scan() reported CLEAN on a real privesc method`);
    const res = analyze(text, CTX);
    assert.equal(res.ok, true, `${c.id}: analyze() did not complete ok`);
    if (c.finding) {
      const ids = (res.findings || []).map((f) => f.id);
      assert.ok(ids.includes(c.finding), `${c.id}: expected ${c.finding}, got [${ids.join(', ') || 'none'}]`);
      p2Named++;
    } else {
      assert.equal(res.coverage?.summary?.incomplete, true, `${c.id}: backstop case must mark coverage incomplete`);
      p2Backstop++;
    }
  });
}

test('SCORECARD: full published privesc catalog is caught', () => {
  assert.equal(caught, CORPUS.length,
    `caught ${caught}/${CORPUS.length} methods`);
  assert.equal(tierNamed + tierBackstop, SECOND_TIER.length,
    `second tier: ${tierNamed + tierBackstop}/${SECOND_TIER.length} accounted for`);
  assert.equal(p2Named + p2Backstop, PART2.length,
    `rhino part 2: ${p2Named + p2Backstop}/${PART2.length} accounted for`);
  // Emitted to test output so CI logs / evidence capture show the numbers.
  console.log(`# privesc-benchmark: Rhino Part1 ${caught}/${CORPUS.length} named, 0 CLEAN; ` +
    `Part2(22-28) ${p2Named} named + ${p2Backstop} backstop, 0 CLEAN; ` +
    `second-tier ${tierNamed} named + ${tierBackstop} backstop, 0 CLEAN`);
});
