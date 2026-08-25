// IAM Blast Radius - SARIF 2.1.0 adapter (Phase 15, story P15-sarif).
//
// A PURE, deterministic adapter that turns a scan() result (see cli/scan.mjs) into
// a SARIF 2.1.0 log. It consumes engine/scan output ONLY: no I/O, no Node APIs, no
// network, no eval, no dynamic import, no clock, no randomness. That keeps it unit-
// testable, reusable by the CLI and the GitHub Action wrapper without a process
// boundary, and byte-for-byte reproducible (same result -> same SARIF, every run).
//
// It changes NO analysis behavior: it never re-derives a verdict, a severity, or a
// certainty. Everything it emits is a faithful projection of what scan() already
// decided. In particular:
//
//   - SARIF is an INTERCHANGE format, never the source of truth for whether a build
//     should fail. The CLI exit code owns the CI gate. This module never computes or
//     influences an exit code.
//   - Security findings and analyzer-state (fail-closed) findings are emitted as two
//     DISJOINT result groups. An analyzer-state result carries kind:'fail',
//     level:'error', properties.category:'analysis-state', properties.failClosed:true,
//     and NEVER a security-severity - so a code-scanning consumer can never misread a
//     "could not analyze" as a vulnerability. This is the load-bearing separation.
//
// SARIF mapping (docs/sarif-cli-design.md):
//   runs[0].tool.driver.name       = 'IAM Blast Radius'
//   runs[0].tool.driver.rules[]    = one reportingDescriptor per finding TYPE
//   result.ruleId                  = finding TYPE (finding.id), not instance
//   result.message.text            = deterministic per-instance summary
//   result.level + security-severity from severity (critical/high error; medium
//                                    warning; low/info note; info omits severity)
//   result.properties              = certainty / evidence / policyFamily / jsonPointer
//   result.partialFingerprints     = normalized SEMANTIC identity (never message
//                                    text, line, timestamp, or object key order)

// Severity -> SARIF level + GitHub `security-severity`. Mirrors the design doc.
// `info` maps to `note` and OMITS security-severity (it is not a vulnerability
// score). This is the ONLY severity->level authority in the SARIF path.
export const SARIF_SEVERITY = Object.freeze({
  critical: Object.freeze({ level: 'error', securitySeverity: '9.0' }),
  high: Object.freeze({ level: 'error', securitySeverity: '7.0' }),
  medium: Object.freeze({ level: 'warning', securitySeverity: '5.0' }),
  low: Object.freeze({ level: 'note', securitySeverity: '2.0' }),
  info: Object.freeze({ level: 'note', securitySeverity: null }),
});

// Most-severe first, so a finding TYPE that appears with more than one severity
// takes its rule-level defaultConfiguration from the most severe instance.
const SEVERITY_RANK = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

// The partialFingerprints KEY. Versioned so a future fingerprinting change can be
// introduced under a new key without silently merging/splitting existing alerts.
export const FINGERPRINT_KEY = 'iamBlastRadius/semanticIdentity/v1';

function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

function sevMap(severity) {
  const key = String(severity == null ? 'info' : severity).toLowerCase();
  return SARIF_SEVERITY[key] || SARIF_SEVERITY.info;
}

// The artifact URI recorded for every result's location: an explicit --artifact-uri
// wins; else the input file path; else 'stdin' (a pasted / piped policy has no real
// file). Mirrors docs/sarif-cli-design.md's location model.
export function artifactUri(opts) {
  const o = opts || {};
  if (isNonEmptyString(o.artifactUri)) return o.artifactUri.trim();
  if (isNonEmptyString(o.file)) return o.file;
  return 'stdin';
}

// --- Deterministic normalization + fingerprinting ----------------------------

// Stable JSON: object keys sorted recursively, so key ORDER can never change a
// fingerprint. Arrays keep their order (order is semantically meaningful and is the
// engine's deterministic output). Used only for the Condition block.
function stableStringify(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

// Normalize an action/resource/principal list to a stable, de-duplicated, sorted
// token list. Actions are case-insensitive in AWS, so they are lowercased; resource
// ARNs and principals are kept case-exact (only de-duplicated + sorted) because the
// resource segment of an ARN is case-sensitive. A non-array collapses to a single
// token; null/undefined collapses to [].
function normList(value, { lowercase = false } = {}) {
  let arr;
  if (Array.isArray(value)) arr = value;
  else if (value == null) arr = [];
  else arr = [value];
  const seen = new Set();
  const out = [];
  for (const v of arr) {
    let s = String(v);
    if (lowercase) s = s.toLowerCase();
    if (!seen.has(s)) { seen.add(s); out.push(s); }
  }
  return out.sort();
}

// Pull the principal token(s) off a finding, if any (resource / trust findings).
// Identity findings have none; the fingerprint simply omits an empty principal.
function findingPrincipals(f) {
  if (!f || typeof f !== 'object') return [];
  const raw = f.principal != null ? f.principal
    : (f.principals != null ? f.principals : null);
  if (raw == null) return [];
  if (Array.isArray(raw) || typeof raw !== 'object') return normList(raw);
  // A Principal object ({ AWS: [...], Service: [...] }) -> flatten to "type=value".
  const out = [];
  for (const k of Object.keys(raw).sort()) {
    for (const v of normList(raw[k])) out.push(`${k}=${v}`);
  }
  return out;
}

// cyrb53 - a small, fast, well-distributed NON-cryptographic hash (public domain).
// Pure JS (Math.imul only): no Node APIs, deterministic. A partialFingerprint needs
// stable dedup, not cryptographic strength. Two seeds are concatenated to widen the
// output and cut collision odds. Returns a fixed-length lowercase hex string.
function cyrb53(str, seed) {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
  h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
  h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const n = 4294967296 * (2097151 & h2) + (h1 >>> 0);
  return n.toString(16).padStart(14, '0');
}

function hashIdentity(canonical) {
  return `${cyrb53(canonical, 0)}${cyrb53(canonical, 0x9e3779b9)}`;
}

// The canonical SEMANTIC identity string for a security finding. Load-bearing: this
// is what partialFingerprints hashes, so it MUST be stable across whitespace,
// object key order, and absolute-vs-repo-relative artifact paths, and MUST NOT
// include message text, line numbers, timestamps, or the artifact URI. It captures:
// finding type + policy family + statement POSITION + normalized action / resource /
// principal / condition, plus the sorted names (never values) of any unresolved
// viability inputs - so supplying a subject account resolves the finding without
// churning a different account VALUE into the fingerprint.
//
// SECURITY (S4-sarif-sid): the raw statement Sid is DELIBERATELY EXCLUDED. The Sid is
// attacker-controlled free-form policy text; folding it into the identity would let a
// fork PR craft a Sid whose fingerprint COLLIDES with a dismissed base-branch alert,
// auto-suppressing a real finding. Statement identity is carried by the structural
// POSITION (statementIndex) - which the attacker cannot use to forge a collision
// against a semantically different finding - never by the free-form label.
export function findingIdentity(finding, family) {
  const f = finding || {};
  const esc = f.escalation && typeof f.escalation === 'object' ? f.escalation : null;
  const requiredUnknowns = (esc && Array.isArray(esc.requiredUnknowns))
    ? esc.requiredUnknowns.map(String).sort()
    : [];
  const parts = [
    'kind=finding',
    `type=${f.id != null ? String(f.id) : ''}`,
    `family=${family != null ? String(family) : ''}`,
    `stmtIndex=${typeof f.statementIndex === 'number' ? f.statementIndex : ''}`,
    `actions=${normList(f.actions, { lowercase: true }).join('|')}`,
    `resources=${normList(f.resources).join('|')}`,
    `principals=${findingPrincipals(f).join('|')}`,
    `condition=${f.conditions == null ? '' : stableStringify(f.conditions)}`,
    `viability=${requiredUnknowns.join('|')}`,
  ];
  return parts.join('\n');
}

// The canonical identity string for an analyzer-state (fail-closed) result. Keyed on
// the state's SEMANTIC identity (category + analysisState + code + normalized path),
// never on the human message text - so wording changes do not churn alerts and a
// path-anchored state stays stable.
export function stateIdentity(st) {
  const s = st || {};
  return [
    'kind=analysis-state',
    `state=${s.analysisState != null ? String(s.analysisState) : ''}`,
    `code=${s.code != null ? String(s.code) : ''}`,
    `path=${s.path != null ? String(s.path) : ''}`,
  ].join('\n');
}

// --- Certainty + evidence projection (preserved exactly, never re-derived) ----

// The certainty the finding already carries, copied EXACTLY (no re-derivation). The
// engine expresses certainty as separate, orthogonal signals - policyEvidence (how
// firmly the policy text supports the capability) and pathExploitability (how
// reachable/viable the path is) - plus, for an escalation path, the target role's
// permissions (always 'unknown' from a single policy). Only present signals are
// attached; an empty object is omitted by the caller.
function certaintyOf(finding) {
  const f = finding || {};
  const out = {};
  if (f.policyEvidence != null) out.policyEvidence = f.policyEvidence;
  if (f.pathExploitability != null) out.pathExploitability = f.pathExploitability;
  const esc = f.escalation && typeof f.escalation === 'object' ? f.escalation : null;
  if (esc && esc.targetPermissions != null) out.targetPermissions = esc.targetPermissions;
  return out;
}

// A compact, deterministic copy of the finding's supporting evidence rows (present
// on escalation findings). Passed through as plain data; the engine already produced
// it deterministically. Returns null when there is no evidence to attach.
function evidenceOf(finding) {
  const f = finding || {};
  if (!Array.isArray(f.evidence) || f.evidence.length === 0) return null;
  return f.evidence.map((e) => {
    const row = {};
    if (e && e.statementIndex != null) row.statementIndex = e.statementIndex;
    // SECURITY (S4-sarif-sid): evidence Sids are attacker-controlled too; sanitize
    // before surfacing in properties.evidence. Omit when nothing printable survives.
    if (e && e.statementSid != null) {
      const safeSid = sanitizeSid(e.statementSid);
      if (safeSid) row.statementSid = safeSid;
    }
    if (e && e.role != null) row.role = e.role;
    if (e && Array.isArray(e.actions)) row.actions = e.actions.slice();
    if (e && Array.isArray(e.resources)) row.resources = e.resources.slice();
    if (e && e.condition != null) row.condition = e.condition;
    if (e && e.note != null) row.note = e.note;
    return row;
  });
}

// Max characters kept from a hostile Sid before ellipsizing. A 10KB Sid must never
// land verbatim in message.text or properties.
const MAX_SID_LEN = 128;

// Neutralize an attacker-controlled statement Sid before it is embedded anywhere a
// consumer might render it (SARIF message.text is rendered as MARKDOWN by GitHub's
// Security tab; properties are shown in alert detail). It:
//   - strips ASCII/C1 control chars and newlines (they break out of a line / an
//     inline-code span and let a payload span multiple rendered lines),
//   - strips backticks (so the value cannot escape the inline-code span it is wrapped
//     in, which is what defuses markdown-link / image injection like [x](javascript:...)),
//   - collapses remaining runs of whitespace to a single space, and
//   - caps length + ellipsizes (a multi-KB Sid cannot bloat or dominate the output).
// Returns '' when nothing printable survives (caller then falls back to the index).
// Pure + deterministic: same Sid -> same token, every run.
function sanitizeSid(sid) {
  let s = String(sid);
  // Control chars (C0 0x00-0x1F incl. newlines/tabs, DEL, C1 0x80-0x9F) + backticks
  // -> space. Backtick removal keeps the value inside its inline-code wrapper so a
  // markdown payload cannot escape it.
  // eslint-disable-next-line no-control-regex
  s = s.replace(/[\u0000-\u001F\u007F-\u009F`]/g, ' ');
  s = s.replace(/\s+/g, ' ').trim();
  if (s.length > MAX_SID_LEN) s = `${s.slice(0, MAX_SID_LEN)}...`;
  return s;
}

// Max distinct action tokens rendered inline before the list is elided. Bounds the
// message so a policy carrying a huge Action array cannot dominate message.text; the
// full normalized action list still rides in partialFingerprints identity + properties.
const MAX_MSG_ACTIONS = 12;

// Render an attacker-controlled action list for message.text. Each Action is just as
// attacker-controlled as a Sid (a fork PR owns the whole policy JSON), and GitHub
// renders message.text as MARKDOWN. So every action is neutralized with the SAME
// treatment the Sid gets - control chars / newlines / backticks stripped, length capped
// - and wrapped in its OWN backtick-quoted inline-code token, NEVER emitted as free
// prose. That defuses an Action like `[x](javascript:...)` (the markdown link cannot
// render inside a code span) and an embedded newline (it is stripped, so it cannot break
// the message across lines). The token COUNT is capped so a large Action array cannot
// bloat the message; the elided remainder is reported as a plain "(+N more)" count.
// Returns '' (no `; actions:` clause) when nothing printable survives.
function renderActionClause(actions) {
  const norm = normList(actions);
  if (norm.length === 0) return '';
  const shown = norm.slice(0, MAX_MSG_ACTIONS);
  const tokens = [];
  for (const a of shown) {
    const safe = sanitizeSid(a);
    if (safe) tokens.push(`\`${safe}\``);
  }
  if (tokens.length === 0) return '';
  const more = norm.length - shown.length;
  const suffix = more > 0 ? `, (+${more} more)` : '';
  return `; actions: ${tokens.join(', ')}${suffix}`;
}

// A deterministic, one-line per-instance message. Deliberately carries the finding
// TITLE + statement identity + action list, but NOT the resource ARNs (those live in
// properties/evidence): keeps the human-facing message stable and low-leakage while
// the full semantic identity is preserved in partialFingerprints + properties.
//
// SECURITY (S4-sarif-sid): every attacker-controlled policy field surfaced here - the
// statement Sid AND the Action list - is sanitized (control chars/newlines/backticks
// stripped, length capped) and rendered as DISTINCT backtick-quoted inline-code tokens,
// NEVER as free prose, because GitHub renders this text as markdown in the Security tab.
// The finding title and policy family are tool-controlled (fixed rule metadata), so they
// are the only free prose. A hostile Sid or Action such as `[x](javascript:...)` or one
// carrying a newline therefore cannot inject a link, image, or line break into the
// rendered message.
function findingMessage(finding, family) {
  const f = finding || {};
  const title = isNonEmptyString(f.title) ? f.title.trim() : String(f.id != null ? f.id : 'finding');
  const safeSid = f.statementSid != null ? sanitizeSid(f.statementSid) : '';
  const sidToken = safeSid
    ? `\`${safeSid}\``
    : (typeof f.statementIndex === 'number' ? `(index ${f.statementIndex})` : '(unknown statement)');
  const fam = family != null ? String(family) : 'unknown';
  const actionPart = renderActionClause(f.actions);
  return `${title} [${fam} policy] at statement ${sidToken}${actionPart}. Potential blast radius from the supplied policy context only; not effective permissions.`;
}

// A stable JSON Pointer to the statement the finding is anchored on, when the engine
// reported a numeric statement index. Point at the whole document otherwise.
function jsonPointerFor(finding) {
  const f = finding || {};
  if (typeof f.statementIndex === 'number' && f.statementIndex >= 0) {
    return `/Statement/${f.statementIndex}`;
  }
  return null;
}

// --- reportingDescriptor (rule) catalog ---------------------------------------

// Build the tool.driver.rules[] catalog: one reportingDescriptor per finding TYPE
// and per analyzer-state code, in first-appearance order (deterministic). Returns
// the rules array plus an index map so each result can carry a resolving ruleIndex.
function buildRules(result) {
  const rules = [];
  const index = new Map();

  // Security-finding TYPES. defaultConfiguration.level + the rule-level
  // security-severity are taken from the MOST SEVERE instance of the type.
  const typeMax = new Map(); // ruleId -> {severity, title, docRef}
  for (const f of (result.findings || [])) {
    const id = f && f.id != null ? String(f.id) : 'finding';
    const sev = String(f && f.severity != null ? f.severity : 'info').toLowerCase();
    const rank = SEVERITY_RANK.indexOf(sev);
    const prev = typeMax.get(id);
    const prevRank = prev ? SEVERITY_RANK.indexOf(prev.severity) : Infinity;
    if (!prev || (rank !== -1 && rank < prevRank)) {
      typeMax.set(id, {
        severity: rank === -1 ? (prev ? prev.severity : 'info') : sev,
        title: isNonEmptyString(f && f.title) ? f.title.trim() : id,
        docRef: isNonEmptyString(f && f.docRef) ? f.docRef.trim() : null,
      });
    }
  }
  for (const [id, meta] of typeMax) {
    if (index.has(id)) continue;
    const map = sevMap(meta.severity);
    const descriptor = {
      id,
      name: id,
      shortDescription: { text: meta.title },
      fullDescription: {
        text: `IAM blast-radius finding type ${id}. Reports POTENTIAL blast radius `
          + 'from the supplied policy context; it does not assert effective permissions.',
      },
      defaultConfiguration: { level: map.level },
      properties: { category: 'security' },
    };
    if (map.securitySeverity != null) descriptor.properties['security-severity'] = map.securitySeverity;
    if (meta.docRef) descriptor.helpUri = meta.docRef;
    index.set(id, rules.length);
    rules.push(descriptor);
  }

  // Analyzer-state CODES. NEVER carry a security-severity (they are not vuln scores);
  // fixed error-level, category analysis-state - the separation an adversary must not
  // be able to collapse.
  for (const s of (result.analysisStates || [])) {
    const code = s && s.code != null ? String(s.code) : 'FAIL_CLOSED';
    const ruleId = `analysis.${code}`;
    if (index.has(ruleId)) continue;
    const stateName = s && s.analysisState != null ? String(s.analysisState) : 'unknown';
    const descriptor = {
      id: ruleId,
      name: ruleId,
      shortDescription: {
        text: `Analyzer state (${stateName}): ${code}. Fail-closed "could not analyze"; `
          + 'this is NOT a vulnerability score.',
      },
      defaultConfiguration: { level: 'error' },
      // No security-severity, by contract.
      properties: { category: 'analysis-state', failClosed: true, analysisState: stateName },
    };
    index.set(ruleId, rules.length);
    rules.push(descriptor);
  }

  return { rules, index };
}

// --- Result rows --------------------------------------------------------------

function locationFor(uri) {
  return { physicalLocation: { artifactLocation: { uri } } };
}

// Build the two DISJOINT result groups. Security findings first (in engine order),
// then analyzer-state results (in scan order). The separation is the whole point of
// the fail-closed design and must survive any refactor.
function buildResults(result, uri, ruleIndex) {
  const out = [];

  for (const f of (result.findings || [])) {
    const id = f && f.id != null ? String(f.id) : 'finding';
    const sev = String(f && f.severity != null ? f.severity : 'info').toLowerCase();
    const map = sevMap(sev);
    const properties = {
      category: 'security',
      severity: sev,
      policyFamily: result.family != null ? result.family : null,
    };
    if (map.securitySeverity != null) properties['security-severity'] = map.securitySeverity;
    const certainty = certaintyOf(f);
    if (Object.keys(certainty).length > 0) properties.certainty = certainty;
    const evidence = evidenceOf(f);
    if (evidence) properties.evidence = evidence;
    const pointer = jsonPointerFor(f);
    if (pointer) properties.jsonPointer = pointer;
    // SECURITY (S4-sarif-sid): the Sid is attacker-controlled; sanitize (strip control
    // chars/newlines/backticks, cap length) before embedding in a rendered property.
    // Omit when nothing printable survives rather than emit an empty token.
    if (f && f.statementSid != null) {
      const safeSid = sanitizeSid(f.statementSid);
      if (safeSid) properties.statementSid = safeSid;
    }

    const row = {
      ruleId: id,
      level: map.level,
      message: { text: findingMessage(f, result.family) },
      locations: [locationFor(uri)],
      partialFingerprints: { [FINGERPRINT_KEY]: hashIdentity(findingIdentity(f, result.family)) },
      properties,
    };
    if (ruleIndex.has(id)) row.ruleIndex = ruleIndex.get(id);
    out.push(row);
  }

  for (const s of (result.analysisStates || [])) {
    const code = s && s.code != null ? String(s.code) : 'FAIL_CLOSED';
    const ruleId = `analysis.${code}`;
    const properties = {
      // NO security-severity here, by contract: an analyzer-state result is NOT a
      // vulnerability and must never be mistakable for one.
      category: 'analysis-state',
      failClosed: true,
      analysisState: s && s.analysisState != null ? String(s.analysisState) : 'unknown',
    };
    if (s && s.path != null) properties.path = String(s.path);
    const row = {
      ruleId,
      kind: 'fail',
      level: 'error',
      message: {
        text: isNonEmptyString(s && s.message)
          ? s.message
          : 'Analysis could not be completed for this policy (fail-closed).',
      },
      locations: [locationFor(uri)],
      partialFingerprints: { [FINGERPRINT_KEY]: hashIdentity(stateIdentity(s)) },
      properties,
    };
    if (ruleIndex.has(ruleId)) row.ruleIndex = ruleIndex.get(ruleId);
    out.push(row);
  }

  return out;
}

// The tool's SARIF semanticVersion: the rule-catalog version (the finding contract),
// distinct from the dated action-catalog snapshot. Read from the canonical manifest.
function semanticVersion(manifest) {
  return (manifest && manifest.ruleVersion) || '0';
}

/**
 * Build the SARIF 2.1.0 log object for a scan() result. Pure + deterministic.
 *
 * @param {object} result   a scan() result (findings + analysisStates + verdict)
 * @param {object} [opts]    { artifactUri?, file? } - location model inputs
 * @param {object} [manifest] the version manifest ({ ruleVersion, ... })
 * @returns {object} a SARIF 2.1.0 log
 */
export function buildSarifLog(result, opts, manifest) {
  const res = result || {};
  const uri = artifactUri(opts);
  const { rules, index } = buildRules(res);
  const results = buildResults(res, uri, index);

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'IAM Blast Radius',
          informationUri: 'https://rivassec.com/tools/iam-blast-radius/',
          semanticVersion: semanticVersion(manifest),
          rules,
        },
      },
      // Machine-readable verdict alongside the results, so a consumer that (wrongly)
      // ignores the exit code can still see partial/failed. NOT authoritative for the
      // CI gate - the CLI exit code is.
      properties: {
        analysisStatus: res.analysisStatus != null ? res.analysisStatus : null,
        exitCode: typeof res.exitCode === 'number' ? res.exitCode : null,
        blockingCount: typeof res.blockingCount === 'number' ? res.blockingCount : 0,
        findingsCount: typeof res.findingsCount === 'number'
          ? res.findingsCount
          : (Array.isArray(res.findings) ? res.findings.length : 0),
      },
      results,
    }],
  };
}

/**
 * Serialize the SARIF 2.1.0 log to a deterministic, pretty-printed string with a
 * trailing newline.
 */
export function formatSarif(result, opts, manifest) {
  return `${JSON.stringify(buildSarifLog(result, opts, manifest), null, 2)}\n`;
}

export default formatSarif;
