// UI controller (IAM-007): input -> Web Worker analysis -> accessible findings
// table, with a synchronous fallback for no-Worker environments.
//
// Security posture (architecture + threat-model, immutable):
//   - Zero network egress: this file contains NO network APIs. Policy text is
//     analyzed in-browser and never sent anywhere.
//   - Safe DOM only: every node is built with createElement + textContent.
//     Hostile SIDs/ARNs/conditions render as inert text (threat-model T1).
//   - No storage of policy content: state is in-memory only and cleared on the
//     Clear button and on pagehide (threat-model T4).
//   - CSP-clean: no inline styles/scripts; all events via addEventListener.

import { analyze, findingToRow, FINDING_COLUMNS, FINDING_DETAIL_FIELDS, CATALOG_VERSION, summarize } from './engine/analyze.js';
import { LIMITS } from './engine/validate.js';
import { toJSON, toMarkdown } from './engine/report.js';
import { createGraphRenderer } from './engine/render-graph.js';

// Wall-clock budget for a single worker run before we terminate it (T5).
const WATCHDOG_MS = 8000;

// In-memory only. Never persisted to localStorage/IndexedDB/cookies.
const state = {
  lastAnalysis: null,
};

let els = null;
let graphRenderer = null;

function byId(id) {
  return document.getElementById(id);
}

function collectElements() {
  return {
    input: byId('policy-input'),
    file: byId('policy-file'),
    analyzeBtn: byId('analyze-btn'),
    clearBtn: byId('clear-btn'),
    status: byId('status'),
    findings: byId('findings'),
    graph: byId('graph'),
    evidence: byId('evidence'),
    exportJson: byId('export-json'),
    exportMd: byId('export-md'),
    ruleVersion: byId('rule-version'),
  };
}

// Honor the user's reduced-motion preference (IAM-008): the SVG renderer skips
// its entrance animation when this is true. Guarded for environments without
// matchMedia.
function prefersReducedMotion() {
  try {
    return typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch (e) {
    return false;
  }
}

function setStatus(message) {
  if (els.status) els.status.textContent = message;
}

function clearChildren(node) {
  if (node) node.replaceChildren();
}

function setExportEnabled(enabled) {
  const ok = !!enabled;
  if (els.exportJson) els.exportJson.disabled = !ok;
  if (els.exportMd) els.exportMd.disabled = !ok;
}

// --- Rendering ---------------------------------------------------------------

function renderErrors(errors) {
  clearChildren(els.findings);
  const list = Array.isArray(errors) ? errors : [];
  const wrap = document.createElement('div');
  wrap.className = 'errors';
  wrap.setAttribute('role', 'alert');

  const heading = document.createElement('p');
  heading.textContent = 'The policy could not be analyzed:';
  wrap.appendChild(heading);

  const ul = document.createElement('ul');
  for (const e of list) {
    const li = document.createElement('li');
    const code = (e && e.code) ? `${e.code}: ` : '';
    li.textContent = code + ((e && e.message) || 'Unknown error.');
    ul.appendChild(li);
  }
  if (list.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'Unknown validation error.';
    ul.appendChild(li);
  }
  wrap.appendChild(ul);
  els.findings.appendChild(wrap);
}

function renderNoFindings() {
  clearChildren(els.findings);
  const p = document.createElement('p');
  p.textContent =
    'No blast-radius findings were produced from the supplied policy. ' +
    'This is not proof the policy is safe - it means none of the current ' +
    'rules matched the supplied context.';
  els.findings.appendChild(p);
}

// IAM-106: a scannable risk-summary header rendered above the findings table.
// Counts of the four highlighted capability families plus the single
// highest-risk escalation path in one line. Safe DOM only (createElement +
// textContent); the path line's service label rides through as inert text.
// Accessible: labelled region with its own heading, counts as a definition list
// so each label/value pair is programmatically associated.
function renderRiskSummary(findings) {
  const summary = summarize(findings);

  const section = document.createElement('section');
  section.className = 'risk-summary';
  section.setAttribute('aria-labelledby', 'risk-summary-h');

  const heading = document.createElement('h3');
  heading.id = 'risk-summary-h';
  heading.textContent = 'Risk summary';
  section.appendChild(heading);

  const dl = document.createElement('dl');
  dl.className = 'risk-summary-counts';
  for (const cat of summary.categories) {
    const dt = document.createElement('dt');
    dt.textContent = cat.label;
    const dd = document.createElement('dd');
    dd.textContent = String(cat.count);
    if (cat.count > 0) dd.className = 'rs-count-nonzero';
    dl.appendChild(dt);
    dl.appendChild(dd);
  }
  section.appendChild(dl);

  const top = document.createElement('p');
  top.className = 'risk-summary-top';
  if (summary.highestRisk) {
    const label = document.createElement('span');
    label.className = 'rs-top-label';
    label.textContent = 'Highest-risk path: ';
    const value = document.createElement('span');
    value.textContent = summary.highestRisk.path;
    top.appendChild(label);
    top.appendChild(value);
  } else {
    top.textContent =
      'Highest-risk path: none - no privilege-escalation path was detected in the supplied context.';
  }
  section.appendChild(top);

  return section;
}

function renderFindings(findings) {
  clearChildren(els.findings);

  if (!Array.isArray(findings) || findings.length === 0) {
    renderNoFindings();
    return;
  }

  els.findings.appendChild(renderRiskSummary(findings));

  const table = document.createElement('table');

  const caption = document.createElement('caption');
  caption.textContent =
    `${findings.length} potential blast-radius finding` +
    (findings.length === 1 ? '' : 's') +
    ', most severe first. Capability view, not effective permissions.';
  table.appendChild(caption);

  const thead = document.createElement('thead');
  const headRow = document.createElement('tr');
  for (const col of FINDING_COLUMNS) {
    const th = document.createElement('th');
    th.setAttribute('scope', 'col');
    th.textContent = col.label;
    headRow.appendChild(th);
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  let detailSeq = 0;
  for (const finding of findings) {
    const detailId = `finding-detail-${detailSeq++}`;
    const cells = findingToRow(finding);

    const row = document.createElement('tr');
    row.className = 'finding-row';

    // IAM-101: the Finding cell carries the disclosure toggle. Activating it
    // (mouse or keyboard) expands the per-row detail that now holds the
    // why/limit/remediation prose (plus any risk-factor checklist / subsumed
    // rows). A textual [+]/[-] marker means the state is legible without color.
    let toggleBtn = null;
    let toggleMarker = null;
    for (const cell of cells) {
      const td = document.createElement('td');
      if (cell.key === 'severity') {
        td.className = `sev-${String(finding.severity || 'info')}`;
        td.textContent = cell.text;
      } else if (cell.key === 'title') {
        toggleBtn = document.createElement('button');
        toggleBtn.type = 'button';
        toggleBtn.className = 'row-toggle';
        toggleBtn.setAttribute('aria-expanded', 'false');
        toggleBtn.setAttribute('aria-controls', detailId);
        toggleMarker = document.createElement('span');
        toggleMarker.className = 'row-toggle-marker';
        toggleMarker.setAttribute('aria-hidden', 'true');
        toggleMarker.textContent = '[+] ';
        const label = document.createElement('span');
        label.textContent = cell.text;
        toggleBtn.appendChild(toggleMarker);
        toggleBtn.appendChild(label);
        td.appendChild(toggleBtn);
      } else {
        td.textContent = cell.text;
      }
      row.appendChild(td);
    }
    tbody.appendChild(row);

    // Every finding now has a detail row (its prose lives there). IAM-105's
    // compound risk-factor checklist + subsumed findings are appended to the
    // same detail when present. Safe DOM only; hostile labels ride through as
    // inert textContent.
    const detail = renderDetailRow(finding, cells.length, detailId);
    tbody.appendChild(detail);
    if (toggleBtn) wireDisclosure(toggleBtn, toggleMarker, detail);
  }
  table.appendChild(tbody);

  els.findings.appendChild(table);
}

// Wire a finding row's disclosure toggle to its detail row. Collapsed by
// default so rows stay compact (IAM-101); toggling flips aria-expanded, the
// row's hidden state, and the textual marker together.
function wireDisclosure(button, marker, detailRow) {
  button.addEventListener('click', () => {
    const expanded = button.getAttribute('aria-expanded') === 'true';
    const next = !expanded;
    button.setAttribute('aria-expanded', String(next));
    detailRow.hidden = !next;
    if (marker) marker.textContent = next ? '[-] ' : '[+] ';
  });
}

// Append one labelled prose block (dt/dd) to a definition list. Empty values
// are still rendered (as an empty dd) so the label set is stable and no field
// silently disappears. textContent only - hostile strings stay inert.
function appendProse(dl, label, value) {
  const dt = document.createElement('dt');
  dt.textContent = label;
  const dd = document.createElement('dd');
  dd.textContent = value === null || value === undefined ? '' : String(value);
  dl.appendChild(dt);
  dl.appendChild(dd);
}

// Build the per-finding detail row (IAM-101). Always present: it carries the
// why / limit / remediation prose that used to sprawl across three table
// columns. For compound escalation paths (IAM-105) it also carries the
// present/absent risk-factor checklist and any subsumed subordinate findings.
// Collapsed (hidden) by default. createElement + textContent only; no markup is
// ever built from policy-derived strings.
function renderDetailRow(finding, columnCount, detailId) {
  const factors = Array.isArray(finding.riskFactors) ? finding.riskFactors : [];
  const subsumed = Array.isArray(finding.subsumed) ? finding.subsumed : [];

  const tr = document.createElement('tr');
  tr.className = 'finding-detail';
  tr.id = detailId;
  tr.hidden = true;
  const td = document.createElement('td');
  td.colSpan = columnCount;

  // Prose (moved out of the table columns): why / limit / remediation.
  const dl = document.createElement('dl');
  dl.className = 'finding-detail-prose';
  for (const field of FINDING_DETAIL_FIELDS) {
    appendProse(dl, field.label, finding[field.key]);
  }
  td.appendChild(dl);

  if (factors.length > 0) {
    const heading = document.createElement('p');
    heading.className = 'risk-factors-heading';
    heading.textContent = 'Risk factors for this escalation path:';
    td.appendChild(heading);

    const ul = document.createElement('ul');
    ul.className = 'risk-factors';
    for (const rf of factors) {
      const li = document.createElement('li');
      li.className = rf.present ? 'rf-present' : 'rf-absent';
      // Textual [x]/[ ] marker so the checklist is meaningful without color.
      const box = document.createElement('span');
      box.className = 'rf-box';
      box.textContent = rf.present ? '[x] ' : '[ ] ';
      const label = document.createElement('span');
      label.textContent = String(rf.label || rf.key || '');
      li.appendChild(box);
      li.appendChild(label);
      ul.appendChild(li);
    }
    td.appendChild(ul);
  }

  if (subsumed.length > 0) {
    const heading = document.createElement('p');
    heading.className = 'subsumed-heading';
    heading.textContent =
      'Subordinate findings folded into this path (not shown as separate rows):';
    td.appendChild(heading);

    const ul = document.createElement('ul');
    ul.className = 'subsumed-findings';
    for (const s of subsumed) {
      const li = document.createElement('li');
      const actions = Array.isArray(s.actions) ? s.actions.join(', ') : '';
      const resources = Array.isArray(s.resources) ? s.resources.join(', ') : '';
      li.textContent =
        `${String(s.id || '')} on ${String(s.statementSid || '')} ` +
        `(${actions} -> ${resources})`;
      ul.appendChild(li);
    }
    td.appendChild(ul);
  }

  tr.appendChild(td);
  return tr;
}

// Reset the evidence panel to its idle prompt.
function resetEvidence() {
  if (!els.evidence) return;
  clearChildren(els.evidence);
  const p = document.createElement('p');
  p.className = 'evidence-empty';
  p.textContent = 'Select an edge in the graph to inspect the statement, actions, ' +
    'resources and condition behind it. Every edge also appears in the findings table.';
  els.evidence.appendChild(p);
}

// Render the attack-path SVG (IAM-008), a progressive enhancement over the
// authoritative findings table. Clicking/activating an edge fills the evidence
// panel. A short textual summary is always present above the SVG so the section
// is meaningful with assistive tech and never a dead box.
function renderGraph(graph, counts, findings) {
  clearChildren(els.graph);
  resetEvidence();

  const edges = counts && typeof counts.edges === 'number' ? counts.edges : 0;
  const nodes = counts && typeof counts.nodes === 'number' ? counts.nodes : 0;
  const summary = document.createElement('p');
  summary.className = 'graph-summary';
  summary.textContent =
    `Attack-path model: ${nodes} node` + (nodes === 1 ? '' : 's') +
    `, ${edges} edge` + (edges === 1 ? '' : 's') +
    '. Every edge is also in the findings table above.';
  els.graph.appendChild(summary);

  if (!graphRenderer) return;
  graphRenderer.render(graph || { nodes: [], edges: [] }, els.graph, {
    reducedMotion: prefersReducedMotion(),
    onEdgeSelect: (edge) => {
      graphRenderer.renderEvidence(edge, els.evidence, { findings });
      setStatus('Showing evidence for the selected edge below the graph.');
    },
  });
}

// --- Result handling ---------------------------------------------------------

function handleResult(result) {
  state.lastAnalysis = result;

  if (!result || !result.ok) {
    renderErrors(result ? result.errors : []);
    clearChildren(els.graph);
    resetEvidence();
    setExportEnabled(false);
    setStatus('Analysis failed - see the messages below the input.');
    return;
  }

  renderFindings(result.findings);
  renderGraph(result.graph, result.counts, result.findings);
  setExportEnabled(true);

  const n = result.counts ? result.counts.findings : result.findings.length;
  setStatus(
    `Analysis complete: ${n} finding` + (n === 1 ? '' : 's') +
    '. This is potential blast radius, not effective permissions.',
  );
}

// --- Analysis dispatch (worker + sync fallback) ------------------------------

function workerSupported() {
  return typeof Worker !== 'undefined';
}

function runSync(text) {
  // No-Worker fallback (architecture invariant 5). Same pure pipeline.
  const result = analyze(text);
  handleResult(result);
}

function runInWorker(text) {
  let worker;
  try {
    worker = new Worker('worker.js', { type: 'module' });
  } catch (e) {
    runSync(text);
    return;
  }

  let settled = false;
  const watchdog = setTimeout(() => {
    if (settled) return;
    settled = true;
    try { worker.terminate(); } catch (e) { /* ignore */ }
    setExportEnabled(false);
    clearChildren(els.findings);
    clearChildren(els.graph);
    resetEvidence();
    setStatus(
      'Analysis exceeded the time budget and was stopped. Try a smaller policy.',
    );
  }, WATCHDOG_MS);

  worker.addEventListener('message', (event) => {
    if (settled) return;
    settled = true;
    clearTimeout(watchdog);
    try { worker.terminate(); } catch (e) { /* ignore */ }
    const payload = event && event.data;
    handleResult(payload ? payload.result : null);
  });

  worker.addEventListener('error', () => {
    if (settled) return;
    settled = true;
    clearTimeout(watchdog);
    try { worker.terminate(); } catch (e) { /* ignore */ }
    // Fall back to the synchronous path rather than failing outright.
    runSync(text);
  });

  worker.postMessage({ id: 1, text });
}

function analyzeText(text) {
  if (typeof text !== 'string' || text.trim().length === 0) {
    setExportEnabled(false);
    clearChildren(els.graph);
    renderErrors([{ code: 'EMPTY_INPUT', message: 'Paste or import a policy first.' }]);
    setStatus('Nothing to analyze.');
    return;
  }
  setStatus('Analyzing locally in your browser...');
  if (workerSupported()) runInWorker(text);
  else runSync(text);
}

// --- File import -------------------------------------------------------------

function importFile(file) {
  if (!file) return;
  if (typeof file.size === 'number' && file.size > LIMITS.MAX_BYTES) {
    renderErrors([{
      code: 'TOO_LARGE',
      message: `File is ${file.size} bytes; limit is ${LIMITS.MAX_BYTES} bytes.`,
    }]);
    setStatus('File is too large to analyze.');
    return;
  }
  const reader = new FileReader();
  reader.addEventListener('load', () => {
    const text = typeof reader.result === 'string' ? reader.result : '';
    if (els.input) els.input.value = text;
    analyzeText(text);
  });
  reader.addEventListener('error', () => {
    setStatus('Could not read the selected file.');
  });
  reader.readAsText(file);
}

// --- Export ------------------------------------------------------------------

function download(filename, mime, text) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Release the object URL on the next tick (after the click is processed).
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function exportJson() {
  if (!state.lastAnalysis || !state.lastAnalysis.ok) {
    setStatus('Run an analysis before exporting.');
    return;
  }
  download('iam-blast-radius.json', 'application/json', toJSON(state.lastAnalysis));
  setStatus('Downloaded JSON report.');
}

function exportMd() {
  if (!state.lastAnalysis || !state.lastAnalysis.ok) {
    setStatus('Run an analysis before exporting.');
    return;
  }
  download('iam-blast-radius.md', 'text/markdown', toMarkdown(state.lastAnalysis));
  setStatus('Downloaded Markdown report.');
}

// --- Clear / lifecycle -------------------------------------------------------

function clearAnalysis(announce) {
  state.lastAnalysis = null;
  if (els.input) els.input.value = '';
  if (els.file) els.file.value = '';
  clearChildren(els.findings);
  clearChildren(els.graph);
  resetEvidence();
  setExportEnabled(false);
  if (announce) {
    setStatus('Analysis cleared. No policy content is retained.');
    if (els.input) els.input.focus();
  }
}

// Wipe in-memory state when the page is being hidden/unloaded (T4). No policy
// content survives navigation; nothing was ever written to storage.
function onPageHide() {
  state.lastAnalysis = null;
  if (els && els.input) els.input.value = '';
}

// --- Bootstrap ---------------------------------------------------------------

function init() {
  els = collectElements();

  try {
    graphRenderer = createGraphRenderer(document);
  } catch (e) {
    graphRenderer = null; // graph is a progressive enhancement; table still works
  }

  if (els.ruleVersion) els.ruleVersion.textContent = CATALOG_VERSION;
  setExportEnabled(false);
  resetEvidence();

  if (els.analyzeBtn) {
    els.analyzeBtn.addEventListener('click', () => {
      analyzeText(els.input ? els.input.value : '');
    });
  }
  if (els.clearBtn) {
    els.clearBtn.addEventListener('click', () => clearAnalysis(true));
  }
  if (els.file) {
    els.file.addEventListener('change', () => {
      const file = els.file.files && els.file.files[0];
      importFile(file);
    });
  }
  if (els.exportJson) els.exportJson.addEventListener('click', exportJson);
  if (els.exportMd) els.exportMd.addEventListener('click', exportMd);

  window.addEventListener('pagehide', onPageHide);
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
}

export { init };
