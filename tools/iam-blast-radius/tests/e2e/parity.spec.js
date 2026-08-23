// IAM-603: node/browser parity gate.
//
// The engine is authored and unit-tested as a Node module (analyze.js), but it
// SHIPS to users inside a browser module Worker (worker.js -> engine/analyze.js).
// A divergence between the two - a browser-only global, a structured-clone
// surprise, an engine file that behaves differently under a real browser's JS
// engine - would mean the tested behavior is not the shipped behavior. This gate
// closes that hole: for the WHOLE fixture corpus it compares the browser worker's
// output to the Node analyze() baseline and asserts they are identical.
//
// It runs across chromium / firefox / webkit (playwright.config.js projects), so
// parity is proven on all three shipped engines, not just one. CI-only (needs a
// real browser + real module Worker); NOT part of the node --test authoring loop.
//
// Baseline: computed in Node here, from the SAME engine source the browser loads
// over HTTP (content/tools/iam-blast-radius/engine/analyze.js served verbatim).
// Browser: the REAL worker.js + engine run; we post each fixture's raw text and
// read back the result the same way app.js does (structured clone via postMessage).
//
// Comparison is byte-for-byte on JSON.stringify(result). structured clone
// preserves own-property insertion order per spec, and both sides run identical
// deterministic engine code, so an identical result serializes identically; any
// difference is a real node/browser divergence and fails the gate.

import { test, expect } from '@playwright/test';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', '..', 'fixtures');
const PAGE = '/tools/iam-blast-radius/index.html';
const WORKER_URL = '/tools/iam-blast-radius/worker.js';

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

// Enumerate the full fixture corpus (every category), sorted for determinism -
// the same corpus the node determinism gate walks.
function loadCorpus() {
  const categories = readdirSync(fixturesDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
  const out = [];
  for (const category of categories) {
    const dir = join(fixturesDir, category);
    if (!existsSync(dir)) continue;
    for (const f of readdirSync(dir).filter((n) => n.endsWith('.json')).sort()) {
      const data = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      out.push({ file: `${category}/${f}`, text: fixtureText(data) });
    }
  }
  return out;
}

const CORPUS = loadCorpus();

// Node baseline: the serialized analyze() result per fixture. Keyed by file so a
// mismatch names the offending fixture.
const BASELINE = new Map(
  CORPUS.map(({ file, text }) => [file, JSON.stringify(analyze(text))]),
);

test.beforeEach(async ({ page }) => {
  // A dialog during analysis would mean injected content executed.
  page.on('dialog', async (d) => {
    throw new Error(`Unexpected dialog (possible XSS): ${d.message()}`);
  });
  await page.goto(PAGE);
});

test('the browser worker produces byte-identical results to the Node engine for the whole corpus', async ({ page }) => {
  expect(CORPUS.length, 'fixture corpus must be non-empty').toBeGreaterThan(0);

  // Drive the REAL module worker inside the page: post every fixture's text and
  // collect the JSON.stringify of each result. One worker, sequential jobs (the
  // engine is deterministic and stateless, so ordering does not matter; this just
  // keeps responses unambiguous). Returns [{ file, json }].
  const browserResults = await page.evaluate(async ({ workerUrl, payloads }) => {
    const worker = new Worker(workerUrl, { type: 'module' });
    const out = [];
    try {
      for (let i = 0; i < payloads.length; i++) {
        const { file, text } = payloads[i];
        const id = i + 1;
        // eslint-disable-next-line no-await-in-loop
        const result = await new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            worker.removeEventListener('message', onMsg);
            reject(new Error(`worker did not respond for ${file}`));
          }, 10000);
          function onMsg(e) {
            if (e.data && e.data.id === id) {
              clearTimeout(timer);
              worker.removeEventListener('message', onMsg);
              resolve(e.data.result);
            }
          }
          worker.addEventListener('message', onMsg);
          worker.postMessage({ id, text });
        });
        out.push({ file, json: JSON.stringify(result) });
      }
    } finally {
      worker.terminate();
    }
    return out;
  }, { workerUrl: WORKER_URL, payloads: CORPUS });

  expect(browserResults.length, 'browser processed every fixture').toBe(CORPUS.length);

  const mismatches = [];
  for (const { file, json } of browserResults) {
    const baseline = BASELINE.get(file);
    if (json !== baseline) mismatches.push(file);
  }
  expect(mismatches, `node/browser divergence on: ${mismatches.join(', ')}`).toEqual([]);

  // Spot-assert the first fixture explicitly so a failure shows the diff, not
  // just a name list.
  const first = browserResults[0];
  expect(first.json, `${first.file}: browser worker result must equal the Node baseline`)
    .toBe(BASELINE.get(first.file));
});

test('parity holds on a representative escalation fixture (explicit single-fixture check)', async ({ page }) => {
  // A focused check that also exercises the exact path app.js uses, on a fixture
  // that produces a rich result (findings + graph edges + coverage), so a
  // divergence in any of those subtrees is caught with a clear single-fixture diff.
  const target = 'pass-role/passrole-lambda-positive.json';
  const baseline = BASELINE.get(target);
  expect(baseline, `${target} must exist in the corpus`).toBeTruthy();

  const browserJson = await page.evaluate(async ({ workerUrl, text }) => {
    const worker = new Worker(workerUrl, { type: 'module' });
    try {
      const result = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('worker timeout')), 10000);
        worker.addEventListener('message', (e) => {
          if (e.data && e.data.id === 1) { clearTimeout(timer); resolve(e.data.result); }
        });
        worker.postMessage({ id: 1, text });
      });
      return JSON.stringify(result);
    } finally {
      worker.terminate();
    }
  }, { workerUrl: WORKER_URL, text: CORPUS.find((c) => c.file === target).text });

  expect(browserJson).toBe(baseline);
});
