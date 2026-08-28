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
  // A dedicated module Worker is same-origin by construction (its MessageEvent
  // origin is the empty string / falsy); reject only a present, foreign origin.
  // The truthiness short-circuit keeps this inert for the empty-origin worker case
  // (and for harnesses that post an origin-less event).
  if (event.origin && event.origin !== self.location.origin) return;
  const data = event && event.data;
  const id = data && typeof data.id !== 'undefined' ? data.id : null;
  const text = data && typeof data.text === 'string' ? data.text : '';
  // IAM-501: optional manual family override forwarded from the UI. Only a
  // string family token is honored; anything else falls back to auto-detect.
  const family = data && typeof data.family === 'string' ? data.family : undefined;
  // IAM-1001: the mandatory-selection flag. When the UI sets it and no family was
  // chosen, analyze() fails closed with POLICY_FAMILY_REQUIRED rather than
  // auto-detecting - the same contract the synchronous path enforces.
  const requireExplicitFamily = !!(data && data.requireExplicitFamily);
  // IAM-1201: the attached-resource context ({ type, arn }) for the resource
  // family. Only a plain object is honored; anything else is dropped so the
  // engine's context gate (RESOURCE_CONTEXT_REQUIRED) fails closed.
  const resourceContext = data && data.resourceContext && typeof data.resourceContext === 'object'
    ? data.resourceContext
    : undefined;
  // S2-crossaccount-scoped-surface (iteration-2, finding #1): the optional analyzed-
  // principal account id. Only a string is honored; anything else is dropped so the
  // engine's own validation (CONCRETE_ACCOUNT_ID_RE) decides whether it is a usable
  // subject. Without it the engine cannot tell same- from cross-account and stays
  // conservatively quiet - so forwarding it is what lets the BROWSER surface the same
  // cross-account findings the CLI/action already can (parity, no browser fail-open).
  const subjectAccount = data && typeof data.subjectAccount === 'string'
    ? data.subjectAccount
    : undefined;

  let result;
  try {
    result = analyze(text, { family, requireExplicitFamily, resourceContext, subjectAccount });
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
