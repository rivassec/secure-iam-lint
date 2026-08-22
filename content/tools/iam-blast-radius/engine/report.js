// Export serialization: analysis result -> JSON / Markdown text (IAM-007).
//
// Pure and deterministic. Produces the text payloads that app.js hands to a
// Blob for download; it performs NO network access and NO DOM work, so it is
// unit-testable under `node --test`. HTML export is intentionally NOT offered
// here (threat-model T6 prefers JSON/MD; any future HTML export must escape
// every interpolated policy value). Hostile SIDs/ARNs/conditions are carried
// as inert text: JSON via JSON.stringify, Markdown as plain body text (a
// downloaded .md file does not execute markup).

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

function list(values) {
  if (!Array.isArray(values) || values.length === 0) return '(none)';
  return values.map((v) => String(v)).join(', ');
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
  out.push(`- Findings: ${counts.findings}`);
  out.push(`- Graph nodes: ${counts.nodes}`);
  out.push(`- Graph edges: ${counts.edges}`);
  out.push('');

  if (findings.length === 0) {
    out.push('## Findings');
    out.push('');
    out.push('No blast-radius findings were produced from the supplied policy.');
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
    out.push(line(['- Statement: ', String(f.statementSid || '')]));
    out.push(line(['- Policy evidence: ', String(f.policyEvidence || '')]));
    out.push(line(['- Path exploitability: ', String(f.pathExploitability || '')]));
    out.push(line(['- Actions: ', list(f.actions)]));
    out.push(line(['- Resources: ', list(f.resources)]));
    if (f.why) out.push(line(['- Why it matters: ', String(f.why)]));
    if (f.limit) out.push(line(['- What this does NOT prove: ', String(f.limit)]));
    if (f.remediation) out.push(line(['- Remediation: ', String(f.remediation)]));
    if (f.docRef) out.push(line(['- Reference: ', String(f.docRef)]));
    // IAM-105: a compound path's present/absent risk-factor checklist, and any
    // subordinate wildcard/broad-resource findings folded into it.
    if (Array.isArray(f.riskFactors) && f.riskFactors.length > 0) {
      out.push('- Risk factors:');
      for (const rf of f.riskFactors) {
        out.push(line(['  - [', rf.present ? 'x' : ' ', '] ', String(rf.label || rf.key || '')]));
      }
    }
    if (Array.isArray(f.subsumed) && f.subsumed.length > 0) {
      out.push('- Subsumed findings (risk factors of this path, not separate rows):');
      for (const s of f.subsumed) {
        out.push(line([
          '  - ', String(s.id || ''), ' on ', String(s.statementSid || ''),
          ' (', list(s.actions), ' -> ', list(s.resources), ')',
        ]));
      }
    }
    out.push('');
  }
  return out.join('\n');
}

export default { toJSON, toMarkdown };
