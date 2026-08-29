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
import { CORPUS, SUBJECT_ACCOUNT } from './corpus.mjs';

const CTX = { subjectAccount: SUBJECT_ACCOUNT, partition: 'aws' };

let caught = 0;
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

test('SCORECARD: full published privesc catalog is caught', () => {
  assert.equal(caught, CORPUS.length,
    `caught ${caught}/${CORPUS.length} methods`);
  // Emitted to test output so CI logs / evidence capture show the number.
  console.log(`# privesc-benchmark: ${caught}/${CORPUS.length} named-detector catches, 0 CLEAN`);
});
