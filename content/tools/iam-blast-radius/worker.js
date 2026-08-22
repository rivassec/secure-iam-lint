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

import { analyze } from './engine/analyze.js';

self.addEventListener('message', (event) => {
  const data = event && event.data;
  const id = data && typeof data.id !== 'undefined' ? data.id : null;
  const text = data && typeof data.text === 'string' ? data.text : '';

  let result;
  try {
    result = analyze(text);
  } catch (e) {
    // analyze() already backstops, but never let the worker die silently.
    result = {
      ok: false,
      errors: [{ code: 'INTERNAL', message: 'Worker analysis failed unexpectedly.', path: null }],
      findings: [],
      model: null,
      graph: { nodes: [], edges: [], truncated: false, limits: {} },
      catalogVersion: '1',
      counts: { findings: 0, edges: 0, nodes: 0 },
    };
  }

  self.postMessage({ id, result });
});
