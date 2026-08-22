// Export serialization: analysis result -> JSON / Markdown text (IAM-007).
//
// Pure and deterministic. Produces the text payloads that app.js hands to a
// Blob for download; it performs NO network access and NO DOM work, so it is
// unit-testable under `node --test`. HTML export is intentionally NOT offered
// here (threat-model T6 prefers JSON/MD; any future HTML export must escape
// every interpolated policy value). Hostile SIDs/ARNs/conditions are carried
// as inert text: JSON via JSON.stringify, Markdown as plain body text (a
// downloaded .md file does not execute markup).

import { noFindingsMessage } from './coverage.js';

const REPORT_TITLE = 'IAM Blast Radius - analysis report';

// Fixed, prominent caveat mirrored from the UI disclaimer so an exported file
// cannot be mistaken for an "effective permissions" statement.
const CAVEAT =
  'This report shows the POTENTIAL blast radius based on the supplied policy ' +
  'context. It does NOT compute effective permissions: AWS evaluates identity, ' +
  'resource, and trust policies, permission boundaries, SCPs, and session ' +
  'policies together, and a single policy cannot show that.';

/**
 * Serialize an analysis result to a stable JSON string.
 *
 * @param {object} analysis result from analyze()
 * @returns {string} pretty-printed JSON
 */
export function toJSON(analysis) {
  const a = analysis || {};
  const payload = {
    tool: 'iam-blast-radius',
    report: REPORT_TITLE,
    caveat: CAVEAT,
    catalogVersion: a.catalogVersion || '1',
    // IAM-501: record the detected/selected policy family and any blocking
    // coverage state (with machine-readable codes + JSON paths). A clean parse
    // is NOT proof of complete coverage - unsupported shapes are surfaced here,
    // never silently dropped.
    family: a.family || null,
    coverage: a.coverage || null,
    counts: a.counts || { findings: 0, edges: 0, nodes: 0 },
    findings: Array.isArray(a.findings) ? a.findings : [],
    model: a.model || null,
    graph: a.graph || { nodes: [], edges: [] },
  };
  return JSON.stringify(payload, null, 2);
}

function line(parts) {
  return parts.join('');
}

// IAM-504 (hostile MD inertness): a policy-derived value (Sid, ARN, action,
// condition token) can carry embedded newlines / control characters. The JSON
// export keeps them verbatim (JSON.stringify escapes them - inert, round-trips),
// but Markdown has no in-line escape: a raw newline inside a "- Statement: ..."
// bullet would start a NEW line that could pose as a heading ("## x") or list
// item and forge document structure in a downloaded report. Collapse CR/LF, the
// Unicode line/paragraph separators, and C0/C1 control chars to a single space
// so every interpolated value stays on its own line as inert text. Used ONLY by
// the Markdown serializer; JSON stays byte-verbatim.
function mdSafe(value) {
  // eslint-disable-next-line no-control-regex
  return String(value).replace(/[\u0000-\u001F\u007F-\u009F\u2028\u2029]+/g, ' ');
}

function list(values) {
  if (!Array.isArray(values) || values.length === 0) return '(none)';
  return values.map((v) => mdSafe(v)).join(', ');
}

/**
 * Serialize an analysis result to a Markdown document.
 *
 * Uses headings + bullet lists (no Markdown tables) so hostile pipe/newline
 * characters in policy fields cannot distort layout. Deterministic: findings
 * are emitted in the order analyze() sorted them.
 *
 * @param {object} analysis result from analyze()
 * @returns {string} Markdown text
 */
export function toMarkdown(analysis) {
  const a = analysis || {};
  const findings = Array.isArray(a.findings) ? a.findings : [];
  const counts = a.counts || { findings: findings.length, edges: 0, nodes: 0 };

  const out = [];
  out.push(`# ${REPORT_TITLE}`);
  out.push('');
  out.push(`> ${CAVEAT}`);
  out.push('');
  out.push(`- Rule catalog version: ${a.catalogVersion || '1'}`);
  out.push(`- Policy family: ${a.family || 'unknown'}`);
  out.push(`- Findings: ${counts.findings}`);
  out.push(`- Graph nodes: ${counts.nodes}`);
  out.push(`- Graph edges: ${counts.edges}`);
  out.push('');

  // IAM-501: record the coverage state so a downloaded report can never be
  // mistaken for a complete conclusion. Unsupported / ambiguous shapes fail
  // closed: their blocking codes + JSON paths are written out verbatim.
  const coverage = a.coverage || null;
  if (coverage) {
    const s = coverage.summary || null;
    out.push('## Analysis coverage');
    out.push('');
    out.push('A clean parse is NOT the same as complete coverage. Unsupported ' +
      'does NOT mean safe.');
    out.push('');
    out.push(`- Detected family: ${coverage.detected || 'unknown'}`);
    if (coverage.override) out.push(`- Manual family override: ${coverage.override}`);
    out.push(`- Supported for rule evaluation: ${coverage.supported ? 'yes' : 'no'}`);
    if (s) {
      out.push(`- Statements: ${s.statements.accepted} accepted, ` +
        `${s.statements.rejected} rejected (of ${s.statements.total}).`);
      out.push(`- Unrecognized actions: ${list(s.unrecognizedActions)}`);
      out.push(`- Unsupported conditions: ${list(s.unsupportedConditions)}`);
      out.push('- Unsupported elements: ' +
        (Array.isArray(s.unsupportedElements) && s.unsupportedElements.length > 0
          ? s.unsupportedElements
            .map((e) => `${String(e.element)}${e.path ? ` at ${String(e.path)}` : ''}`)
            .join(', ')
          : '(none)'));
      out.push('- Evaluation layers NOT covered by this document: ' +
        (Array.isArray(s.missingLayers) && s.missingLayers.length > 0
          ? s.missingLayers.map((l) => String(l.label)).join(', ')
          : '(none)'));
      out.push(`- Attack-path graph: ${s.graph.truncated ? 'truncated (bounded; findings table stays authoritative)' : 'complete'}.`);
      out.push(`- Build SHA: ${s.versions.buildSha}`);
      out.push(`- Rule version: ${s.versions.ruleVersion}`);
      out.push(`- Action-catalog version: ${s.versions.catalogVersion}`);
    }
    if (coverage.blocked) {
      out.push('- Coverage: BLOCKED - analysis stopped before rule evaluation ' +
        '(unsupported does NOT mean safe).');
      const codes = Array.isArray(coverage.blockingCodes) ? coverage.blockingCodes : [];
      for (const b of codes) {
        out.push(line([
          '  - ', String(b.code || ''),
          b.path ? ` at ${String(b.path)}` : '',
          b.message ? `: ${String(b.message)}` : '',
        ]));
      }
    } else if (s && s.incomplete) {
      out.push('- Coverage: INCOMPLETE - unsupported semantic input prevents a ' +
        'complete conclusion (unsupported does NOT mean safe).');
    } else {
      out.push('- Coverage: complete for the supported subset.');
    }
    out.push('');
  }

  if (findings.length === 0) {
    out.push('## Findings');
    out.push('');
    // IAM-502: the zero-findings wording flips to the supported-subset variant
    // whenever coverage is incomplete (unsupported does NOT mean safe).
    out.push(noFindingsMessage(coverage));
    out.push('');
    return out.join('\n');
  }

  out.push('## Findings');
  out.push('');
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i] || {};
    out.push(`### ${i + 1}. [${String(f.severity || 'info').toUpperCase()}] ${String(f.title || f.id || 'Finding')}`);
    out.push('');
    out.push(line(['- Rule: ', String(f.id || '')]));
    // IAM-504: explainable evidence - name the policy family each finding was
    // evaluated under (Sid is display evidence, not stable identity).
    if (f.policyFamily) out.push(line(['- Policy family: ', String(f.policyFamily)]));
    out.push(line(['- Statement: ', mdSafe(f.statementSid || '')]));
    out.push(line(['- Policy evidence: ', String(f.policyEvidence || '')]));
    out.push(line(['- Path exploitability: ', String(f.pathExploitability || '')]));
    out.push(line(['- Actions: ', list(f.actions)]));
    out.push(line(['- Resources: ', list(f.resources)]));
    if (f.why) out.push(line(['- Why it matters: ', String(f.why)]));
    if (f.limit) out.push(line(['- What this does NOT prove: ', String(f.limit)]));
    if (f.remediation) out.push(line(['- Remediation: ', String(f.remediation)]));
    if (f.docRef) out.push(line(['- Reference: ', String(f.docRef)]));
    // IAM-506: condition classification - how each Condition entry READS (appears
    // to narrow / select / broaden, or context-required). NEVER a runtime
    // allow/deny claim. Values are mdSafe()'d so a newline-laden key/operator
    // cannot forge document structure in a downloaded .md.
    const cc = f.conditionClassification;
    if (cc && cc.present && Array.isArray(cc.entries) && cc.entries.length > 0) {
      out.push('- Condition classification (how the text reads, not a runtime verdict):');
      for (const e of cc.entries) {
        out.push(line([
          '  - [', mdSafe(e.appears), '] ', mdSafe(e.operator), ' ', mdSafe(e.key),
          ' - ', mdSafe(e.note),
        ]));
      }
    }
    // A finding's present/absent risk-factor checklist (IAM-105 compound paths
    // and IAM-201 capability findings both expose one), plus any subordinate
    // wildcard/broad-resource findings folded into it. The heading is
    // capability-neutral ("this finding") because subsumption also happens on a
    // standalone capability finding that is NOT an escalation path - asserting a
    // "path" here would claim one the analysis never detected.
    if (Array.isArray(f.riskFactors) && f.riskFactors.length > 0) {
      out.push('- Risk factors:');
      for (const rf of f.riskFactors) {
        out.push(line(['  - [', rf.present ? 'x' : ' ', '] ', String(rf.label || rf.key || '')]));
      }
    }
    if (Array.isArray(f.subsumed) && f.subsumed.length > 0) {
      out.push('- Subsumed findings (risk factors folded into this finding, not separate rows):');
      for (const s of f.subsumed) {
        out.push(line([
          '  - ', mdSafe(s.id || ''), ' on ', mdSafe(s.statementSid || ''),
          ' (', list(s.actions), ' -> ', list(s.resources), ')',
        ]));
      }
    }
    out.push('');
  }
  return out.join('\n');
}

export default { toJSON, toMarkdown };
