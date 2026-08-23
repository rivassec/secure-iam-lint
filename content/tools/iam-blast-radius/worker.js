// Analysis Web Worker (IAM-007).
//
// Runs the engine off the main thread so a hostile multi-MB / deeply-nested
// policy cannot freeze the UI (threat-model T5). The worker receives ONLY raw
// policy text, runs the pure analyze() pipeline, and posts back the result.
// It performs no network access (there is nothing to send anywhere) and never
// touches the DOM. app.js arms a wall-clock watchdog and terminates this
// worker on overrun.
//
// Loaded as a module worker: new Worker('worker.js', { type: 'module' }).

import { analyze, CATALOG_VERSION } from './engine/analyze.js';

self.addEventListener('message', (event) => {
  const data = event && event.data;
  const id = data && typeof data.id !== 'undefined' ? data.id : null;
  const text = data && typeof data.text === 'string' ? data.text : '';
  // IAM-501: optional manual family override forwarded from the UI. Only a
  // string family token is honored; anything else falls back to auto-detect.
  const family = data && typeof data.family === 'string' ? data.family : undefined;

  let result;
  try {
    result = analyze(text, family ? { family } : undefined);
  } catch (e) {
    // analyze() already backstops, but never let the worker die silently.
    result = {
      ok: false,
      errors: [{ code: 'INTERNAL', message: 'Worker analysis failed unexpectedly.', path: null }],
      findings: [],
      model: null,
      graph: { nodes: [], edges: [], truncated: false, limits: {} },
      // IAM-604: derive the fallback catalog version from the same constant the
      // success path uses, so the worker cannot drift from the engine manifest.
      catalogVersion: CATALOG_VERSION,
      counts: { findings: 0, edges: 0, nodes: 0 },
      family: null,
      coverage: null,
    };
  }

  self.postMessage({ id, result });
});
