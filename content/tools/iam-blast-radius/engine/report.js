// Export serialization: analysis result -> JSON / Markdown text (IAM-007).
//
// Pure and deterministic. Produces the text payloads that app.js hands to a
// Blob for download; it performs NO network access and NO DOM work, so it is
// unit-testable under `node --test`. HTML export is intentionally NOT offered
// here (threat-model T6 prefers JSON/MD; any future HTML export must escape
// every interpolated policy value). Hostile SIDs/ARNs/conditions are carried
// as inert text: JSON via JSON.stringify (escaped string values that
// round-trip), Markdown via mdEscape() which backslash-escapes every
// Markdown/HTML metacharacter so an attacker-controlled policy value cannot
// forge an active link or executable HTML in a downloaded .md (threat-model
// T1/T6, suite-3 test 99).

import { noFindingsMessage } from './coverage.js';

const REPORT_TITLE = 'IAM Blast Radius - analysis report';

// IAM-1001: a single, machine-readable analysis STATUS derived from the result,
// so the browser, the JSON export, and the Markdown export report the SAME status
// token (test 71: statuses must agree across surfaces). A blocked export is never
// labeled authoritative - its status is "blocked", not "ok".
//   error   - the pipeline failed before producing a conclusion (ok:false), e.g.
//             a validation/parse failure or an over-limit (TOO_LARGE) input.
//   blocked - the pipeline reached a fail-closed coverage state (family gate:
//             unsupported/ambiguous shape, NotPrincipal, POLICY_FAMILY_REQUIRED).
//   warned  - a supported analysis whose coverage is incomplete (unsupported
//             conditions/actions/elements present - "unsupported != safe").
//   ok      - a supported analysis with complete coverage for its subset.
export function analysisStatus(analysis) {
  const a = analysis || {};
  if (!a.ok) return 'error';
  const cov = a.coverage || null;
  if (cov && cov.blocked) return 'blocked';
  const s = cov && cov.summary;
  if (s && s.incomplete) return 'warned';
  return 'ok';
}

// IAM-1001: the family the user explicitly SELECTED (the override), distinct from
// the detected/effective family. 'auto-detect' when the user opted into shape
// auto-detect; null when no selection was recorded (e.g. a hard failure, or a
// back-compat auto-detect caller).
function selectedFamilyOf(analysis) {
  const cov = analysis && analysis.coverage;
  if (cov && typeof cov.override === 'string' && cov.override.length > 0) return cov.override;
  // A supported non-override result that ran under explicit auto-detect records
  // it in notes; keep the export honest but simple: no override -> 'auto-detect'
  // when coverage exists, null when it does not.
  if (cov) return 'auto-detect';
  return null;
}

// IAM-1001: the stable, machine-readable warning codes for an export. For a
// successful/blocked analysis these are the coverage summary codes (blocking +
// non-blocking); for a hard failure they are the error codes.
function warningsOf(analysis) {
  const a = analysis || {};
  if (!a.ok) {
    return (Array.isArray(a.errors) ? a.errors : [])
      .map((e) => String(e && e.code ? e.code : ''))
      .filter((c) => c.length > 0);
  }
  const s = a.coverage && a.coverage.summary;
  if (s && Array.isArray(s.codes)) return s.codes.map(String);
  const bc = a.coverage && Array.isArray(a.coverage.blockingCodes) ? a.coverage.blockingCodes : [];
  return bc.map((b) => String(b && b.code ? b.code : '')).filter((c) => c.length > 0);
}

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
    // IAM-1001: a single machine-readable analysis status (ok/warned/blocked/
    // error), the explicitly SELECTED family, and the stable warning codes -
    // present on every export so the browser/JSON/Markdown surfaces agree and a
    // blocked report is never read as authoritative (test 71).
    status: analysisStatus(a),
    selectedFamily: selectedFamilyOf(a),
    warnings: warningsOf(a),
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

// IAM-1002 / suite-3 test 99 (threat-model T1/T6): a policy-derived value can be
// a BARE URL ("https://evil.example.com/x") or a "www."-prefixed host. Backslash-
// escaping Markdown/HTML metacharacters (below) does NOT touch ':' or '/', so a
// bare URL survives verbatim - and GFM (GitHub), CommonMark-with-autolink, and
// pandoc --autolink_bare_uris turn a bare "http://"/"https://"/"ftp://"/"www."
// token into an ACTIVE (clickable) link in a downloaded/shared report, giving an
// attacker a phishing/tracking link out of a hostile Sid/ARN/condition value.
// Neutralize the autolink TRIGGER tokens so no scheme is ever recognized.
//
// The break must SURVIVE inline parsing to defeat cmark-gfm's autolink post-pass
// (it scans text AFTER inline parsing): a backslash before ASCII punctuation
// (e.g. '\/' or '\:') is a Markdown escape the parser CONSUMES, re-exposing the
// URL - so we insert a backslash before a LETTER instead, which CommonMark/GFM/
// pandoc all leave as a literal backslash. "https://" -> "h\ttps://": the alnum
// run before "://" is now "ttps", not a valid scheme, so the recognizer never
// fires; "www." -> "w\ww.". The host stays fully readable as inert text. The
// fixed catalog docRef URL is never routed through here, so it stays clickable.
//
// PERFORMANCE (iteration-3 fix): the "<scheme>://" break was previously a regex
// `/([A-Za-z])([A-Za-z0-9+.-]*:\/\/)/g`. Its greedy `[A-Za-z0-9+.-]*` re-scans to
// the end of the run and backtracks at EVERY letter start, so a long scheme-char
// string that never contains "://" (e.g. a hostile Resource value with no colon)
// costs O(n^2): a 50KB value took ~33s. A hand-written single left-to-right scan
// makes it O(n) with output byte-identical to the old regex - it finds each
// maximal scheme-char run, and only when that run is immediately followed by
// "://" inserts a backslash after the run's FIRST letter (matching the leftmost
// greedy semantics of the old regex, including runs whose first char is a digit).
const SCHEME_CHAR = (code) =>
  (code >= 0x41 && code <= 0x5a) || // A-Z
  (code >= 0x61 && code <= 0x7a) || // a-z
  (code >= 0x30 && code <= 0x39) || // 0-9
  code === 0x2b || code === 0x2e || code === 0x2d; // + . -
const SCHEME_LETTER = (code) =>
  (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);

function breakAutolinks(value) {
  const str = String(value);
  const n = str.length;
  const parts = [];
  let i = 0;
  while (i < n) {
    if (SCHEME_CHAR(str.charCodeAt(i))) {
      // Extend over the maximal run of scheme chars [i..e].
      let e = i;
      while (e + 1 < n && SCHEME_CHAR(str.charCodeAt(e + 1))) e++;
      // Break only if the run is immediately followed by "://" (charCodeAt past
      // the end returns NaN, so the comparisons are safely false at EOF).
      if (str.charCodeAt(e + 1) === 0x3a && // :
          str.charCodeAt(e + 2) === 0x2f && // /
          str.charCodeAt(e + 3) === 0x2f) { // /
        // Leftmost greedy match starts at the run's first LETTER (a scheme must
        // begin with a letter); a run with no letter yields no match.
        let f = i;
        while (f <= e && !SCHEME_LETTER(str.charCodeAt(f))) f++;
        if (f <= e) {
          parts.push(str.slice(i, f + 1), '\\', str.slice(f + 1, e + 1), '://');
          i = e + 4; // past the run and the consumed "://"
          continue;
        }
      }
      parts.push(str.slice(i, e + 1));
      i = e + 1;
    } else {
      // Batch the non-scheme run so a long inert string is one slice, not n+= .
      let j = i + 1;
      while (j < n && !SCHEME_CHAR(str.charCodeAt(j))) j++;
      parts.push(str.slice(i, j));
      i = j;
    }
  }
  // "www." host prefix - break the leading "www" so the www autolink cannot fire.
  // Linear (no unbounded quantifier), so it stays cheap; kept as a regex.
  return parts.join('').replace(/(w)(ww\.)/gi, '$1\\$2');
}

// IAM-1001 / suite-3 test 99 (threat-model T1/T6): mdSafe() only collapses
// control chars; it does NOT stop a policy value from forging an ACTIVE link
// ([text](url) / [text][ref] / <autolink> / bare-URL autolink) or RAW HTML
// (<img onerror=...>, <script>) in a downloaded .md. mdEscape() runs mdSafe()
// first, then backslash-escapes every Markdown/HTML metacharacter an attacker
// could use to build link or HTML syntax: backslash, backtick, [ ] ( ) < > and |
// (table cell). CommonMark/GFM/pandoc all render a backslash-escaped punctuation
// char as inert literal text, so `[click](javascript:alert(1))` and
// `<img src=x onerror=alert(1)>` render as visible text, never an active link or
// executable HTML. Finally breakAutolinks() neutralizes the bare-URL/"www."
// autolink vector that punctuation-escaping alone cannot reach (':' and '/' carry
// no escape). It runs LAST so its literal backslashes are not themselves escaped.
// Non-trigger ':' '/' '*' '_' still render unchanged, so ARNs, actions, and
// wildcards read normally. Applied to EVERY policy-derived interpolation in the
// Markdown serializer; JSON stays byte-verbatim via JSON.stringify.
function mdEscape(value) {
  const escaped = mdSafe(value).replace(/[\\`[\]()<>|]/g, (ch) => `\\${ch}`);
  return breakAutolinks(escaped);
}

function list(values) {
  if (!Array.isArray(values) || values.length === 0) return '(none)';
  return values.map((v) => mdEscape(v)).join(', ');
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
  // IAM-1001: the analysis status + explicitly selected family + warning codes,
  // mirrored from the same helpers the JSON export uses, so the two surfaces (and
  // the browser) agree (test 71). A blocked report reads "blocked", never a
  // complete/authoritative status.
  out.push(`- Analysis status: ${analysisStatus(a)}`);
  out.push(`- Selected family: ${selectedFamilyOf(a) || 'none'}`);
  out.push(`- Rule catalog version: ${a.catalogVersion || '1'}`);
  out.push(`- Policy family: ${a.family || 'unknown'}`);
  const warnings = warningsOf(a);
  out.push(`- Warnings: ${warnings.length > 0 ? warnings.join(', ') : '(none)'}`);
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
      if (s.trustDeny && s.trustDeny.present) {
        out.push(`- Same-policy trust Deny: ${s.trustDeny.note}`);
      }
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
    out.push(`### ${i + 1}. [${String(f.severity || 'info').toUpperCase()}] ${mdEscape(f.title || f.id || 'Finding')}`);
    out.push('');
    out.push(line(['- Rule: ', String(f.id || '')]));
    // IAM-504: explainable evidence - name the policy family each finding was
    // evaluated under (Sid is display evidence, not stable identity).
    if (f.policyFamily) out.push(line(['- Policy family: ', String(f.policyFamily)]));
    out.push(line(['- Statement: ', mdEscape(f.statementSid || '')]));
    out.push(line(['- Policy evidence: ', String(f.policyEvidence || '')]));
    out.push(line(['- Path exploitability: ', String(f.pathExploitability || '')]));
    out.push(line(['- Actions: ', list(f.actions)]));
    // IAM-701: when a finding's actions are distributed across MORE THAN ONE
    // statement (a compound cross-statement path), spell out the per-statement
    // provenance so the single "- Statement:" anchor above is never read as
    // granting the whole combined action list. Each line attributes only the
    // actions the named statement actually grants.
    const cs = Array.isArray(f.contributingStatements) ? f.contributingStatements : [];
    if (cs.length > 1) {
      out.push('- Contributing statements (which statement grants which action):');
      for (const s of cs) {
        out.push(line([
          '  - ', mdEscape(s.statementSid || `(index ${s.statementIndex})`),
          ': ', list(s.actions),
        ]));
      }
    }
    out.push(line(['- Resources: ', list(f.resources)]));
    // IAM-704: a complement (NotAction/NotResource) grant. The excluded set is
    // reported EXPLICITLY as excluded (never as an allowed action/resource) so a
    // downloaded report cannot be misread as granting the listed items.
    if (Array.isArray(f.excludedActions) && f.excludedActions.length > 0) {
      out.push(line(['- Excluded actions (NOT granted; complement carve-out): ', list(f.excludedActions)]));
    }
    if (Array.isArray(f.excludedResources) && f.excludedResources.length > 0) {
      out.push(line(['- Excluded resources (NOT granted; complement carve-out): ', list(f.excludedResources)]));
    }
    // why/limit/remediation are tool-authored prose but interpolate policy-derived
    // strings (role ARNs, action names - see escalation.js role-takeover why),
    // so they run through mdEscape too: a hostile ARN embedded in the prose can
    // no more forge a link/HTML than one in the Resources list (test 99).
    if (f.why) out.push(line(['- Why it matters: ', mdEscape(f.why)]));
    if (f.limit) out.push(line(['- What this does NOT prove: ', mdEscape(f.limit)]));
    if (f.remediation) out.push(line(['- Remediation: ', mdEscape(f.remediation)]));
    // docRef is a fixed catalog AWS-docs URL (never policy-derived); leave it
    // unescaped so the link stays clickable in the report.
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
          '  - [', mdEscape(e.appears), '] ', mdEscape(e.operator), ' ', mdEscape(e.key),
          ' - ', mdEscape(e.note),
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
        out.push(line(['  - [', rf.present ? 'x' : ' ', '] ', mdEscape(rf.label || rf.key || '')]));
      }
    }
    if (Array.isArray(f.subsumed) && f.subsumed.length > 0) {
      out.push('- Subsumed findings (risk factors folded into this finding, not separate rows):');
      for (const s of f.subsumed) {
        out.push(line([
          '  - ', mdEscape(s.id || ''), ' on ', mdEscape(s.statementSid || ''),
          ' (', list(s.actions), ' -> ', list(s.resources), ')',
        ]));
      }
    }
    out.push('');
  }
  return out.join('\n');
}

export default { toJSON, toMarkdown };
