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
import { toJSON, toMarkdown, analysisStatus } from './engine/report.js';
import { createGraphRenderer } from './engine/render-graph.js';
import { noFindingsMessage } from './engine/coverage.js';
import { checkVersionCoherence } from './engine/version.js';
import { SAMPLES } from './samples.js';

// Wall-clock budget for a single worker run before we terminate it (T5).
const WATCHDOG_MS = 8000;

// In-memory only. Never persisted to localStorage/IndexedDB/cookies.
const state = {
  lastAnalysis: null,
};

let els = null;
let graphRenderer = null;

// IAM-604: set at startup when the shipped version identifiers are internally
// inconsistent (a partial / torn deploy). While set, analysis is blocked - the
// tool fails closed rather than report findings from an engine whose modules
// disagree about their own versions (threat-model T8: mislabeled certainty).
let versionBlock = null;

// IAM-503: single-flight analysis boundary. At most one analysis job may be in
// flight. A monotonic id identifies the current job; starting a new job
// terminates and invalidates the previous worker so a stale (older) response
// can never overwrite a newer result. A message whose id is not the current
// job's id - or that arrives after the job was superseded - is ignored.
let jobSeq = 0;
let currentJob = null; // { id, worker, watchdog }

function byId(id) {
  return document.getElementById(id);
}

function collectElements() {
  return {
    input: byId('policy-input'),
    file: byId('policy-file'),
    family: byId('policy-family'),
    analyzeBtn: byId('analyze-btn'),
    clearBtn: byId('clear-btn'),
    samples: byId('samples'),
    status: byId('status'),
    coverage: byId('coverage'),
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

// IAM-503: expose the in-flight state as aria-busy on the findings region (the
// primary output) so assistive tech announces that analysis is running, and set
// the analyze button's aria-busy for the same reason. Called with true at
// dispatch and false the moment a job settles (success, failure, crash, or
// timeout).
function setBusy(busy) {
  const value = busy ? 'true' : 'false';
  if (els.findings) els.findings.setAttribute('aria-busy', value);
  if (els.analyzeBtn) els.analyzeBtn.setAttribute('aria-busy', value);
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

// IAM-604: render the fail-closed notice when the shipped version identifiers do
// not agree with the engine manifest. Safe DOM only (createElement +
// textContent); the mismatched values ride through as inert text. This replaces
// the findings region with an alert and analysis stays disabled.
function renderVersionBlock(coherence) {
  clearChildren(els.findings);
  const wrap = document.createElement('div');
  wrap.className = 'errors version-mismatch';
  wrap.setAttribute('role', 'alert');

  const heading = document.createElement('p');
  heading.textContent =
    "Analysis is disabled: this tool's version identifiers are inconsistent.";
  wrap.appendChild(heading);

  const explain = document.createElement('p');
  explain.textContent =
    'The shipped files disagree about their own version, which usually means a ' +
    'partial or cached deploy. To avoid reporting findings from a torn engine, ' +
    'analysis is blocked. Reload after the deploy completes; if it persists, the ' +
    'assets need a cache purge.';
  wrap.appendChild(explain);

  const mismatches = coherence && Array.isArray(coherence.mismatches)
    ? coherence.mismatches
    : [];
  if (mismatches.length > 0) {
    const ul = document.createElement('ul');
    for (const m of mismatches) {
      const li = document.createElement('li');
      li.textContent =
        `${String(m.id)}: expected ${String(m.expected)}, found ${String(m.actual)}`;
      ul.appendChild(li);
    }
    wrap.appendChild(ul);
  }
  els.findings.appendChild(wrap);
}

// IAM-1001: the raw family selector value. '' means NO selection (mandatory
// selection not yet made); 'auto' is the explicit Auto-detect choice; anything
// else is an explicit family. Never coerces '' to auto-detect - that silent
// default is exactly what the mandatory-selection contract removes.
function familySelectionValue() {
  return els.family && typeof els.family.value === 'string' ? els.family.value : '';
}

// IAM-1001: is an explicit family (including Auto-detect) currently selected?
function hasFamilySelection() {
  return familySelectionValue().length > 0;
}

// IAM-1001: the analyze() options for the current selection. requireExplicitFamily
// is ALWAYS set from the UI, so a run with no selection fails closed at the engine
// with POLICY_FAMILY_REQUIRED (defense in depth behind the disabled button). A
// concrete/auto selection is forwarded as `family`.
function analyzeOptions() {
  const v = familySelectionValue();
  return { family: v.length > 0 ? v : undefined, requireExplicitFamily: true };
}

// IAM-1001: the Analyze control is enabled only when a policy family is selected
// (and the version-coherence gate has not blocked). This is the primary
// mandatory-selection mechanism; the engine POLICY_FAMILY_REQUIRED block backs it.
function updateAnalyzeEnabled() {
  if (!els.analyzeBtn) return;
  els.analyzeBtn.disabled = !!versionBlock || !hasFamilySelection();
}

// IAM-1001: set the machine-readable analysis status on the status element as a
// data attribute, so the browser surface reports the SAME status token the JSON
// and Markdown exports do (test 71). Kept separate from the human status text.
function setResultStatus(result) {
  if (els.status) els.status.setAttribute('data-status', analysisStatus(result));
}

// IAM-501: a compact blocking-coverage notice. When the policy shape is one the
// engine does not model (NotPrincipal, a resource/role-trust/other family, an
// ambiguous mixed shape, or an unmodeled manual override), analysis fails closed
// BEFORE rule evaluation and returns no findings. Rendering this notice makes the
// blocking state visible and explicit ("unsupported does NOT mean safe") rather
// than showing a misleading empty result. Safe DOM only; the blocking codes /
// JSON paths / messages ride through as inert textContent. The full coverage
// panel is IAM-502; this is the minimum so a blocked shape is never silent.
function renderCoverageNotice(coverage) {
  const codesList = Array.isArray(coverage.blockingCodes) ? coverage.blockingCodes : [];
  // IAM-1001: the mandatory-selection block is a DIFFERENT state from an
  // unsupported shape - it means the user has not picked a family yet, not that
  // the analyzer failed closed on a shape it understood. Word it accordingly.
  const familyRequired = codesList.some((b) => b && b.code === 'POLICY_FAMILY_REQUIRED');

  const section = document.createElement('section');
  section.className = 'coverage-blocked';
  section.setAttribute('role', 'alert');
  section.setAttribute('aria-labelledby', 'coverage-blocked-h');

  const heading = document.createElement('h3');
  heading.id = 'coverage-blocked-h';
  heading.textContent = familyRequired
    ? 'Select a policy family to analyze'
    : 'Analysis stopped - policy shape not supported';
  section.appendChild(heading);

  const dl = document.createElement('dl');
  dl.className = 'coverage-meta';
  appendProse(dl, 'Detected family', coverage.detected);
  if (coverage.override) appendProse(dl, 'Manual override', coverage.override);
  section.appendChild(dl);

  const intro = document.createElement('p');
  intro.textContent = familyRequired
    ? 'Choose the policy family (or Auto-detect) before analyzing. The tool does ' +
      'not guess the family from the document shape, because analyzing one family ' +
      'as another would produce confident but wrong findings.'
    : 'This analyzer models identity-policy semantics only. It stopped before ' +
      'evaluating rules rather than present findings on a shape it does not ' +
      'understand. Unsupported does NOT mean safe - it means no conclusion.';
  section.appendChild(intro);

  const codes = Array.isArray(coverage.blockingCodes) ? coverage.blockingCodes : [];
  if (codes.length > 0) {
    const ul = document.createElement('ul');
    ul.className = 'coverage-codes';
    for (const b of codes) {
      const li = document.createElement('li');
      const code = document.createElement('span');
      code.className = 'coverage-code';
      code.textContent = String(b.code || '');
      li.appendChild(code);
      if (b.path) {
        const path = document.createElement('span');
        path.className = 'coverage-path';
        path.textContent = ` at ${String(b.path)}`;
        li.appendChild(path);
      }
      if (b.message) {
        const msg = document.createElement('span');
        msg.className = 'coverage-message';
        msg.textContent = ` - ${String(b.message)}`;
        li.appendChild(msg);
      }
      ul.appendChild(li);
    }
    section.appendChild(ul);
  }

  return section;
}

// IAM-502: the zero-findings wording flips automatically when coverage is
// incomplete. With unsupported semantic input present it reads "No findings in
// the supported subset - unsupported elements prevent a complete conclusion",
// so an empty result is never mistaken for a clean bill of health.
function renderNoFindings(coverage) {
  clearChildren(els.findings);
  const p = document.createElement('p');
  p.textContent = noFindingsMessage(coverage);
  els.findings.appendChild(p);
}

// IAM-502: the COMPACT "Analysis coverage" panel, rendered above the findings in
// visual + DOM order (its own <section> precedes the findings section in
// index.html). It names the detected family, statements accepted/rejected,
// unrecognized actions, unsupported conditions/elements, the AWS evaluation
// layers this single document did NOT cover, graph complete/truncated, and the
// build SHA + rule version + catalog version. When any unsupported semantic
// input exists it takes a visually prominent warning state ("unsupported does
// NOT mean safe"). Safe DOM only (createElement + textContent); every
// policy-derived string (family tokens, JSON paths, action names) rides through
// as inert text.
function renderCoveragePanel(coverage) {
  clearChildren(els.coverage);
  const s = coverage && coverage.summary;
  if (!s) return;

  const section = document.createElement('section');
  section.className = s.incomplete ? 'coverage-summary coverage-incomplete' : 'coverage-summary';
  section.setAttribute('aria-labelledby', 'coverage-summary-h');

  const heading = document.createElement('h3');
  heading.id = 'coverage-summary-h';
  heading.textContent = 'Coverage summary';
  section.appendChild(heading);

  const dl = document.createElement('dl');
  dl.className = 'coverage-summary-meta';
  const familyText = s.override
    ? `${s.detectedFamilyLabel} (manual override: ${s.override})`
    : s.detectedFamilyLabel;
  appendProse(dl, 'Detected family', familyText);
  appendProse(dl, 'Supported for rule evaluation', s.supported ? 'yes' : 'no');
  appendProse(
    dl,
    'Statements',
    `${s.statements.accepted} accepted, ${s.statements.rejected} rejected (of ${s.statements.total})`,
  );
  appendProse(dl, 'Unrecognized actions', coverageList(s.unrecognizedActions));
  appendProse(dl, 'Unsupported conditions', coverageList(s.unsupportedConditions));
  // IAM-806: same-policy trust Deny caveat (a neutralizing Deny is never silently
  // discarded from a "complete" analysis). Rendered as inert textContent.
  if (s.trustDeny && s.trustDeny.present && s.trustDeny.note) {
    appendProse(dl, 'Same-policy trust Deny', s.trustDeny.note);
  }
  appendProse(dl, 'Attack-path graph', s.graph.truncated ? 'truncated (bounded)' : 'complete');
  section.appendChild(dl);

  // Evaluation layers this single document did not cover - the concrete form of
  // "not effective permissions".
  if (Array.isArray(s.missingLayers) && s.missingLayers.length > 0) {
    const layers = document.createElement('p');
    layers.className = 'coverage-layers';
    const label = document.createElement('span');
    label.className = 'coverage-layers-label';
    label.textContent = 'Layers not supplied (each could further constrain, or grant cross-account): ';
    const value = document.createElement('span');
    value.textContent = s.missingLayers.map((l) => l.label).join(', ') + '.';
    layers.appendChild(label);
    layers.appendChild(value);
    section.appendChild(layers);
  }

  // Prominent warning state whenever unsupported semantic input exists.
  if (s.incomplete) {
    const warn = document.createElement('p');
    warn.className = 'coverage-warn';
    warn.setAttribute('role', 'note');
    warn.textContent =
      'Unsupported input is present - this is not a complete conclusion. ' +
      'Unsupported does NOT mean safe.';
    section.appendChild(warn);

    if (Array.isArray(s.unsupportedElements) && s.unsupportedElements.length > 0) {
      const ul = document.createElement('ul');
      ul.className = 'coverage-unsupported';
      for (const e of s.unsupportedElements) {
        const li = document.createElement('li');
        const el = document.createElement('span');
        el.className = 'coverage-code';
        el.textContent = String(e.element || '');
        li.appendChild(el);
        if (e.path) {
          const path = document.createElement('span');
          path.className = 'coverage-path';
          path.textContent = ` at ${String(e.path)}`;
          li.appendChild(path);
        }
        ul.appendChild(li);
      }
      section.appendChild(ul);
    }

    // IAM-1006 (test 50): action/resource-type mismatches (e.g. an S3 object
    // action scoped to a bucket-only ARN). Rendered as inert textContent so the
    // bucket-vs-object remediation is visible in the UI, never a silent
    // complete/empty result. Safe DOM only (createElement + textContent).
    if (Array.isArray(s.actionResourceMismatches) && s.actionResourceMismatches.length > 0) {
      const ul = document.createElement('ul');
      ul.className = 'coverage-mismatches';
      for (const m of s.actionResourceMismatches) {
        const li = document.createElement('li');
        const note = document.createElement('span');
        note.className = 'coverage-mismatch-note';
        note.textContent = String(m.note || '');
        li.appendChild(note);
        if (m.remediation) {
          const rem = document.createElement('span');
          rem.className = 'coverage-mismatch-remediation';
          rem.textContent = ` Remediation: ${String(m.remediation)}`;
          li.appendChild(rem);
        }
        ul.appendChild(li);
      }
      section.appendChild(ul);
    }
  }

  // Version footer: build SHA + rule + catalog version, so a screenshot or copy
  // is tied to a shipped revision.
  const versions = document.createElement('p');
  versions.className = 'coverage-versions';
  versions.textContent =
    `Build ${s.versions.buildSha} - rule catalog v${s.versions.ruleVersion} - ` +
    `action catalog v${s.versions.catalogVersion}`;
  section.appendChild(versions);

  els.coverage.appendChild(section);
}

// Join a coverage string list for display, or the explicit "(none)" so an empty
// slot is legible rather than a blank cell.
function coverageList(values) {
  if (Array.isArray(values) && values.length > 0) return values.join(', ');
  return '(none)';
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

function renderFindings(findings, coverage) {
  clearChildren(els.findings);

  if (!Array.isArray(findings) || findings.length === 0) {
    renderNoFindings(coverage);
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

  // IAM-506: condition classification. Describes how each Condition entry READS
  // (appears to narrow / select / broaden, or context-required) - never a
  // runtime allow/deny claim. Hostile condition keys/values ride through as
  // inert text (createElement + textContent only).
  const cc = finding.conditionClassification;
  if (cc && cc.present && Array.isArray(cc.entries) && cc.entries.length > 0) {
    const heading = document.createElement('p');
    heading.className = 'condition-class-heading';
    heading.textContent = 'Condition classification (how the text reads, not a runtime verdict):';
    td.appendChild(heading);

    const ul = document.createElement('ul');
    ul.className = 'condition-classes';
    for (const e of cc.entries) {
      const li = document.createElement('li');
      li.className = `cc-${String(e.appears)}`;
      const tag = document.createElement('span');
      tag.className = 'cc-tag';
      tag.textContent = `[${String(e.appears)}] `;
      const body = document.createElement('span');
      body.textContent = `${String(e.operator)} ${String(e.key)} - ${String(e.note)}`;
      li.appendChild(tag);
      li.appendChild(body);
      ul.appendChild(li);
    }
    td.appendChild(ul);
  }

  if (factors.length > 0) {
    const heading = document.createElement('p');
    heading.className = 'risk-factors-heading';
    // Only a compound escalation-path finding may call its checklist "for this
    // escalation path". IAM-201 capability findings (KMS-DECRYPT, DATA-EXFIL, ...)
    // also expose a risk-factor checklist but are NOT paths - no escalation
    // enrichment - so their heading stays capability-neutral to avoid asserting a
    // path the analysis never detected.
    heading.textContent = finding.escalation
      ? 'Risk factors for this escalation path:'
      : 'Risk factors for this finding:';
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
      'Subordinate findings folded into this finding (not shown as separate rows):';
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
  // IAM-1001: publish the machine-readable status on the browser surface so it
  // agrees with the JSON/Markdown exports (test 71).
  setResultStatus(result);

  if (!result || !result.ok) {
    clearChildren(els.coverage);
    renderErrors(result ? result.errors : []);
    clearChildren(els.graph);
    resetEvidence();
    setExportEnabled(false);
    setStatus('Analysis failed - see the messages below the input.');
    return;
  }

  // IAM-502: the compact coverage summary panel precedes the findings in DOM +
  // visual order (its own section is above the findings section). It renders for
  // every successful analysis, blocked or not.
  renderCoveragePanel(result.coverage);

  // IAM-501: fail-closed coverage state. The pipeline ran (ok:true) but the
  // shape is unmodeled, so there are no findings and no graph - show the
  // blocking notice instead. Export stays enabled: the JSON/MD report records
  // the detected family + the blocking coverage codes.
  if (result.coverage && result.coverage.blocked) {
    clearChildren(els.findings);
    els.findings.appendChild(renderCoverageNotice(result.coverage));
    clearChildren(els.graph);
    resetEvidence();
    setExportEnabled(true);
    setStatus(
      'Analysis stopped: the policy shape (' +
      String(result.coverage.detected || 'unknown') +
      ') is not supported for rule evaluation. No findings were produced.',
    );
    return;
  }

  renderFindings(result.findings, result.coverage);
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

function runSync(text, options) {
  // No-Worker fallback (architecture invariant 5). This path is reached ONLY
  // when a Web Worker cannot be constructed BEFORE analysis starts (Worker
  // undefined, or `new Worker(...)` throws). It is NEVER used to recover from a
  // worker that failed AFTER dispatch - that would re-run the engine on hostile
  // input on the main thread, which IAM-503 forbids (see failClosed).
  const result = analyze(text, options);
  handleResult(result);
}

// IAM-503: terminate + invalidate whatever job is currently in flight (if any).
// Used when a newer submission supersedes an older one, and by Clear / pagehide.
// After this, any late message from the old worker is ignored because its id no
// longer matches the current job.
function invalidateCurrentJob() {
  if (!currentJob) return;
  if (currentJob.watchdog) clearTimeout(currentJob.watchdog);
  if (currentJob.worker) {
    try { currentJob.worker.terminate(); } catch (e) { /* ignore */ }
  }
  currentJob = null;
}

// IAM-503 fail-closed boundary. A worker crash / runtime error / malformed
// message / watchdog expiry AFTER dispatch renders a bounded error and sets a
// status message WITHOUT re-running analyze() (and the hostile policy text) on
// the main thread. This is the whole point of the execution boundary: a broken
// worker must degrade to a clear error, never to main-thread reprocessing.
function failClosed(detailMessage, statusMessage) {
  clearChildren(els.coverage);
  clearChildren(els.graph);
  resetEvidence();
  setExportEnabled(false);
  state.lastAnalysis = null;
  renderErrors([{ code: 'WORKER_FAILED', message: detailMessage }]);
  setStatus(statusMessage);
}

// IAM-503: clear all prior output (findings, coverage, graph, evidence, export)
// and drop the retained analysis at the start of every new job, so a superseded
// or failed run never leaves stale results on screen.
function resetOutputForNewJob() {
  state.lastAnalysis = null;
  setExportEnabled(false);
  clearChildren(els.coverage);
  clearChildren(els.findings);
  clearChildren(els.graph);
  resetEvidence();
}

function runInWorker(text, options) {
  const opts = options || {};
  // Newer submission wins: supersede any in-flight job first (terminates the
  // prior worker so its result can never land after this one).
  invalidateCurrentJob();

  const id = ++jobSeq;

  let worker;
  try {
    worker = new Worker('worker.js', { type: 'module' });
  } catch (e) {
    // Worker construction unavailable BEFORE analysis started -> the ONLY
    // permitted synchronous fallback (architecture invariant 5).
    runSync(text, opts);
    return;
  }

  const job = { id, worker, watchdog: null };
  currentJob = job;

  // A job is stale if it has been superseded (currentJob moved on) or is no
  // longer the newest job id. Stale callbacks return without touching the UI.
  const isStale = () => currentJob !== job || jobSeq !== id;

  // Settle this job: stop the watchdog, terminate the worker, drop the busy
  // state, and release it as the current job. Idempotent via the stale check in
  // each caller.
  const settle = () => {
    if (job.watchdog) { clearTimeout(job.watchdog); job.watchdog = null; }
    try { worker.terminate(); } catch (e) { /* ignore */ }
    if (currentJob === job) currentJob = null;
    setBusy(false);
  };

  job.watchdog = setTimeout(() => {
    if (isStale()) return;
    settle();
    // Fail closed on timeout: bounded error, NOT a main-thread re-run.
    failClosed(
      'Analysis exceeded the time budget and was stopped before it finished. ' +
      'To protect the page it was not re-run on the main thread. Try a smaller policy.',
      'Analysis exceeded the time budget and was stopped. Try a smaller policy.',
    );
  }, WATCHDOG_MS);

  worker.addEventListener('message', (event) => {
    if (isStale()) return; // a newer job supersedes this one; ignore stale result
    const payload = event && event.data;
    // Accept only a well-formed message that carries THIS job's id and a result
    // object with a boolean ok. Anything else is a malformed message -> fail
    // closed rather than reprocessing on the main thread.
    if (!payload || payload.id !== job.id || !payload.result ||
        typeof payload.result.ok !== 'boolean') {
      settle();
      failClosed(
        'The analysis worker returned an unexpected message and was stopped. ' +
        'The policy was not re-analyzed on the main thread.',
        'Analysis failed: the worker returned an unexpected result.',
      );
      return;
    }
    settle();
    handleResult(payload.result);
  });

  worker.addEventListener('error', () => {
    if (isStale()) return;
    settle();
    // A worker runtime crash after dispatch. Fail closed - never re-run the
    // engine on the hostile input on the main thread.
    failClosed(
      'The analysis worker stopped unexpectedly. To protect the page, the ' +
      'policy was not re-analyzed on the main thread. Try again, or use a ' +
      'smaller policy.',
      'Analysis failed: the worker stopped unexpectedly.',
    );
  });

  worker.addEventListener('messageerror', () => {
    if (isStale()) return;
    settle();
    failClosed(
      'The analysis worker sent a message that could not be read and was ' +
      'stopped. The policy was not re-analyzed on the main thread.',
      'Analysis failed: the worker returned an unreadable result.',
    );
  });

  setBusy(true);
  // IAM-1001: forward the family selection AND the requireExplicitFamily flag so
  // the worker's analyze() enforces the mandatory-selection contract identically
  // to the sync path.
  worker.postMessage({ id, text, family: opts.family, requireExplicitFamily: !!opts.requireExplicitFamily });
}

function analyzeText(text) {
  // IAM-604: fail closed on an incoherent shipped version set. The startup check
  // already disabled the button and rendered the notice; this guard also stops a
  // programmatic caller (e.g. loadSample) from analyzing against a torn engine.
  if (versionBlock) {
    setStatus('Analysis is disabled until the version mismatch is resolved.');
    return;
  }
  if (typeof text !== 'string' || text.trim().length === 0) {
    invalidateCurrentJob();
    setBusy(false);
    resetOutputForNewJob();
    renderErrors([{ code: 'EMPTY_INPUT', message: 'Paste or import a policy first.' }]);
    setStatus('Nothing to analyze.');
    return;
  }
  // Clear prior output at job start (single-flight): a new run never shows the
  // previous run's findings while it is in flight.
  resetOutputForNewJob();
  setStatus('Analyzing locally in your browser...');
  // IAM-1001: always carry requireExplicitFamily; a run with no selection fails
  // closed at the engine (POLICY_FAMILY_REQUIRED) rather than defaulting to a
  // shape-based family.
  const options = analyzeOptions();
  if (workerSupported()) runInWorker(text, options);
  else runSync(text, options);
}

// IAM-1001: changing the policy family INVALIDATES any prior analysis
// immediately (test 70): no identity result may remain visible under a boundary
// label. We tear down the retained result + rendered findings/coverage/graph/
// evidence/export, then either auto-reanalyze under the new family (when input is
// present and a family is selected) or prompt for the next step. This keeps the
// displayed conclusion and the selected family in lockstep.
function onFamilyChange() {
  updateAnalyzeEnabled();

  if (versionBlock) return; // analysis is disabled entirely; nothing to invalidate

  const text = els.input ? els.input.value : '';
  if (!hasFamilySelection()) {
    // Back to no selection: drop any prior result and require a selection again.
    invalidateCurrentJob();
    setBusy(false);
    resetOutputForNewJob();
    if (els.status) els.status.removeAttribute('data-status');
    setStatus('Select a policy family to analyze.');
    return;
  }

  if (typeof text === 'string' && text.trim().length > 0) {
    // Re-run under the newly selected family. analyzeText clears prior output
    // first, so the previous family's findings never linger under a new label.
    analyzeText(text);
  } else {
    invalidateCurrentJob();
    setBusy(false);
    resetOutputForNewJob();
    if (els.status) els.status.removeAttribute('data-status');
    setStatus('Policy family selected. Paste or import a policy, then analyze.');
  }
}

// --- Built-in samples (IAM-505) ----------------------------------------------

// Load a built-in sample: fill the input with the (pretty-printed) sample policy
// and run the normal analysis flow (worker + coverage panel + findings + graph),
// exactly as if the user had pasted it. The manual family override is reset to
// Auto-detect so a sample always demonstrates its intended auto-detected
// behavior (e.g. the NotPrincipal sample must auto-detect the resource family
// and fail closed). File input is cleared so the two input sources never
// disagree. The sample policy is our own static, fictional data, but it still
// flows through the same safe path as any pasted text.
function loadSample(sample) {
  if (!sample || !sample.policy) return;
  const text = JSON.stringify(sample.policy, null, 2);
  if (els.input) els.input.value = text;
  if (els.file) els.file.value = '';
  // IAM-1001: a sample must satisfy the mandatory-selection contract. Load it
  // under explicit Auto-detect so it reproduces its intended auto-detected
  // behavior (e.g. the NotPrincipal sample must auto-detect the resource family
  // and fail closed), which is exactly what the engine sample fixtures assert.
  if (els.family) els.family.value = 'auto';
  updateAnalyzeEnabled();
  analyzeText(text);
}

// Render the sample loader controls (IAM-505). Each sample is a keyboard- and
// pointer-operable <button> with a visible description associated via
// aria-describedby, so the loaders are meaningful with assistive tech. Safe DOM
// only (createElement + textContent); the sample labels/descriptions are static
// strings from samples.js.
function renderSamples() {
  if (!els.samples) return;
  clearChildren(els.samples);
  let i = 0;
  for (const sample of SAMPLES) {
    const descId = `sample-desc-${i++}`;

    const li = document.createElement('li');
    li.className = 'sample-item';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = sample.kind === 'escalation'
      ? 'sample-btn sample-escalation'
      : 'sample-btn sample-neutralized';
    btn.setAttribute('aria-describedby', descId);
    btn.textContent = sample.label;
    btn.addEventListener('click', () => loadSample(sample));
    li.appendChild(btn);

    const desc = document.createElement('span');
    desc.className = 'sample-desc';
    desc.id = descId;
    desc.textContent = sample.description;
    li.appendChild(desc);

    els.samples.appendChild(li);
  }
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
  // IAM-503: cancel any in-flight job so a late worker result cannot repaint the
  // UI after a Clear, and drop the busy state.
  invalidateCurrentJob();
  setBusy(false);
  state.lastAnalysis = null;
  if (els.input) els.input.value = '';
  if (els.file) els.file.value = '';
  // IAM-1001: Clear resets the selector to no selection (mandatory again) and
  // disables Analyze until the user re-selects a family.
  if (els.family) els.family.value = '';
  updateAnalyzeEnabled();
  if (els.status) els.status.removeAttribute('data-status');
  clearChildren(els.coverage);
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
  // IAM-503: terminate any in-flight worker on navigation so no analysis of the
  // (now-cleared) policy text survives the page.
  // IAM-504 (privacy gate): fully wipe the rendered analysis too, not just the
  // in-memory state, so nothing policy-derived lingers in the DOM if the page is
  // restored from the bfcache. Reuse the same teardown the Clear button runs
  // (without the "cleared" announcement, since the page is going away).
  clearAnalysis(false);
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
  setBusy(false); // stable initial aria-busy state on the findings region
  resetEvidence();
  renderSamples(); // IAM-505: build the built-in sample loader buttons

  // IAM-604: version-coherence startup gate. If the shipped identifiers do not
  // agree with the engine manifest, fail closed: disable the Analyze/import
  // controls, show the mismatch notice, and refuse to analyze (analyzeText also
  // guards on `versionBlock`). Event handlers are still wired below so the
  // controls exist and stay inert; the guard - not just the disabled attribute -
  // is the real block.
  const coherence = checkVersionCoherence();
  if (!coherence.ok) {
    versionBlock = coherence;
    if (els.analyzeBtn) els.analyzeBtn.disabled = true;
    if (els.file) els.file.disabled = true;
    setExportEnabled(false);
    renderVersionBlock(coherence);
    setStatus('Analysis is disabled: version identifiers are inconsistent (possible partial deploy).');
  }

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

  // IAM-1001: mandatory family selection. React to selector changes (invalidate
  // prior analysis; auto-reanalyze under the new family) and set the initial
  // Analyze enabled-state from the current selection (disabled with none).
  if (els.family) els.family.addEventListener('change', onFamilyChange);
  updateAnalyzeEnabled();

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
