// IAM Blast Radius - accepted-results baseline (CLI + Action).
//
// Adoption gap from a real-world trial: with no way to accept a known result, a repo
// whose existing policies carry ANY finding or fail-closed state can only run the check
// with `continue-on-error` - which also hides every NEW risky grant. A baseline is a
// committed file of keys for results the maintainer has reviewed and accepted; a run
// then fails only on results NOT in it.
//
// Fail-closed contract (what a baseline can and cannot do):
//   - It is OPT-IN: no baseline input -> the verdict is byte-for-byte unchanged.
//   - It never touches exit 2 (usage) or exit 4 (internal), nor a FAILED analysis
//     (malformed / blocked / budget / family-gate), nor any partial state other than
//     UNKNOWN_ACTION and UNSUPPORTED_CONDITION. Those still exit 3.
//   - Each accepted item is keyed INDIVIDUALLY. An analyzer-state key folds in the exact
//     sorted action / condition-key list, so accepting today's unknown action can never
//     accept a different one tomorrow; a finding key is its full semantic identity
//     (findingIdentity - the same input as the SARIF fingerprint) PLUS its severity and
//     rule version, so an engine upgrade that raises a finding's severity or changes its
//     rule invalidates the acceptance instead of silently carrying it over.
//   - Each entry's review metadata (file, ruleId, and a finding's severity) is
//     LOAD-BEARING: an entry whose id matches a result but whose metadata does not is
//     never accepted and is reported as a mismatch (the CLI / Action turn it into exit 2).
//     A reviewer reading a baseline diff therefore sees what is really being accepted.
//   - The baseline is repo content, so a PR can edit it like any other file (as it can
//     the workflow). Protect it with CODEOWNERS / required review; see ACTION.md.
//   - Every key is bound to the artifact URI (the repo-relative file), so accepting a
//     result in one file never accepts it in another.
//   - Keys are SHA-256 (not the SARIF fingerprint's fast cyrb53): a PR author controls
//     the policy text, so a forgeable hash would let a crafted new grant collide with an
//     accepted key and pass. They are serialized as "id" / "baselineId", never under a
//     "key"-like name: a 64-hex value next to the word "key" trips generic secret
//     scanners (gitleaks generic-api-key) in every repo that commits a baseline.
//   - analysisStatus stays truthful ('partial' remains 'partial'); only the exit code and
//     reason reflect the acceptance, and the SARIF marks accepted rows with the standard
//     baselineState / suppressions fields.
//
// Pure over its inputs apart from node:crypto (hashing). No I/O.

import { createHash } from 'node:crypto';

import { EXIT, ANALYSIS_STATUS, meetsThreshold } from './scan.mjs';
import { findingIdentity, stateIdentity } from './sarif.mjs';

export const BASELINE_VERSION = 1;
// Bounds on a committed baseline file (it is repo content; keep it from becoming a
// resource-exhaustion input).
export const MAX_BASELINE_BYTES = 1024 * 1024;
export const MAX_BASELINE_ENTRIES = 20000;

// Analyzer-state codes a baseline may accept, each mapped to the details list that
// identifies WHAT was unsupported.
const BASELINABLE_STATES = Object.freeze({
  UNKNOWN_ACTION: 'actions',
  UNSUPPORTED_CONDITION: 'conditions',
});

const KEY_RE = /^[0-9a-f]{64}$/;

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

// JSON.stringify of a fixed-shape tuple is injective (string quoting makes every
// delimiter inside a token inert), so distinct (kind, uri, identity) never share input.
function keyOf(kind, uri, canonical) {
  return sha256(`iam-blast-radius-baseline-v${BASELINE_VERSION}\n${JSON.stringify([kind, String(uri), canonical])}`);
}

export function findingBaselineKey(finding, family, uri) {
  const f = finding || {};
  const extra = `\nseverity=${f.severity != null ? String(f.severity) : ''}\nruleVersion=${f.ruleVersion != null ? String(f.ruleVersion) : ''}`;
  return keyOf('finding', uri, `${findingIdentity(f, family)}${extra}`);
}

// The review metadata a baseline entry must carry for a row (also what buildBaseline
// writes): the file, the SARIF ruleId, and - for a finding - its severity.
function rowMeta(row, uri) {
  const isState = typeof row.code === 'string' && !Object.hasOwn(row, 'severity');
  return isState
    ? { file: String(uri), ruleId: `analysis.${row.code}` }
    : { file: String(uri), ruleId: String(row.id), severity: String(row.severity) };
}

// null for a state a baseline may never accept.
export function stateBaselineKey(st, uri) {
  const s = st || {};
  const field = Object.hasOwn(BASELINABLE_STATES, s.code) ? BASELINABLE_STATES[s.code] : null;
  if (!field) return null;
  const raw = s.details && Array.isArray(s.details[field]) ? s.details[field] : [];
  const tokens = [...new Set(raw.map(String))].sort();
  if (tokens.length === 0) return null;
  return keyOf('analysis-state', uri, `${stateIdentity(s)}\ntokens=${JSON.stringify(tokens)}`);
}

/**
 * Parse a committed baseline file. Never throws. Returns the accepted ids plus each id's
 * review metadata (applyBaseline checks it against the matched result).
 * @param {string} text
 * @returns {{ok:true, keys:Map<string,object>} | {ok:false, reason:string, message:string}}
 */
export function parseBaseline(text) {
  const bad = (message) => ({ ok: false, reason: 'INVALID_BASELINE', message });
  if (typeof text !== 'string') return bad('The baseline file could not be read as text.');
  if (Buffer.byteLength(text, 'utf8') > MAX_BASELINE_BYTES) {
    return bad(`The baseline file exceeds ${MAX_BASELINE_BYTES} bytes.`);
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    return bad('The baseline file is not valid JSON.');
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return bad('The baseline file must be a JSON object.');
  if (doc.version !== BASELINE_VERSION) return bad(`Unsupported baseline version (expected ${BASELINE_VERSION}).`);
  if (!Array.isArray(doc.entries)) return bad('The baseline file has no "entries" array.');
  if (doc.entries.length > MAX_BASELINE_ENTRIES) return bad(`The baseline file has more than ${MAX_BASELINE_ENTRIES} entries.`);
  const keys = new Map();
  for (const e of doc.entries) {
    const k = e && typeof e === 'object' ? e.id : undefined;
    if (typeof k !== 'string' || !KEY_RE.test(k)) {
      return bad('Every baseline entry needs an "id" of 64 lowercase hex characters.');
    }
    if (keys.has(k)) return bad('The baseline file lists the same "id" twice.');
    if (typeof e.file !== 'string' || typeof e.ruleId !== 'string' || e.file === '' || e.ruleId === '') {
      return bad('Every baseline entry needs its "file" and "ruleId" (they are checked against the result).');
    }
    const isState = e.ruleId.startsWith('analysis.');
    if (!isState && (typeof e.severity !== 'string' || e.severity === '')) {
      return bad('Every finding entry in the baseline needs its "severity" (it is checked against the result).');
    }
    keys.set(k, isState
      ? { file: e.file, ruleId: e.ruleId }
      : { file: e.file, ruleId: e.ruleId, severity: e.severity });
  }
  return { ok: true, keys };
}

/**
 * Attach baseline keys to a scan() result and, when `accepted` is a key Set, apply it.
 * Returns a new frozen result; the input is not mutated. With no `accepted` set the
 * verdict fields are returned UNCHANGED (keys are still attached so the SARIF can
 * publish them for a later baseline).
 *
 * @param {object} result   a scan() (or synthetic unit) result
 * @param {string} uri      the artifact URI the SARIF will carry for this result
 * @param {Map<string,object>|null} accepted ids -> review metadata from parseBaseline, or null
 * @param {string} threshold the run's fail-on threshold
 * @returns {object}
 */
export function applyBaseline(result, uri, accepted, threshold) {
  if (!result || typeof result !== 'object') return result;
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const states = Array.isArray(result.analysisStates) ? result.analysisStates : [];
  const keyOfRow = new Map();
  for (const f of findings) keyOfRow.set(f, findingBaselineKey(f, result.family, uri));
  for (const s of states) {
    const k = stateBaselineKey(s, uri);
    if (k) keyOfRow.set(s, k);
  }
  const applied = accepted instanceof Map;
  const used = new Set();
  const mismatched = new Set();
  const isAccepted = (row) => {
    const k = keyOfRow.get(row);
    if (!applied || !k || !accepted.has(k)) return false;
    const want = accepted.get(k);
    const have = rowMeta(row, uri);
    const same = want.file === have.file && want.ruleId === have.ruleId
      && (have.severity === undefined || want.severity === have.severity);
    if (!same) { mismatched.add(k); return false; }
    used.add(k);
    return true;
  };

  let verdict = {};
  const eligible = applied
    && (result.exitCode === EXIT.CLEAN || result.exitCode === EXIT.FINDINGS
      || (result.exitCode === EXIT.FAIL_CLOSED && result.analysisStatus === ANALYSIS_STATUS.PARTIAL));
  if (eligible) {
    const openStates = states.filter((s) => !isAccepted(s));
    const open = findings.filter((f) => !isAccepted(f));
    const blockingCount = open.filter((f) => meetsThreshold(f && f.severity, threshold)).length;
    const acceptedCount = used.size;
    let exitCode;
    let reason;
    if (result.exitCode === EXIT.FAIL_CLOSED && (openStates.length > 0 || states.length === 0)) {
      exitCode = EXIT.FAIL_CLOSED;
      reason = result.reason;
    } else if (blockingCount > 0) {
      exitCode = EXIT.FINDINGS;
      reason = 'FINDINGS_AT_OR_ABOVE_THRESHOLD';
    } else {
      exitCode = EXIT.CLEAN;
      reason = acceptedCount > 0 ? 'CLEAN_WITH_BASELINE' : 'CLEAN';
    }
    verdict = { exitCode, reason, blockingCount };
  }

  return Object.freeze({
    ...result,
    ...verdict,
    // `used` is the set of rows this verdict ACTUALLY accepted (empty for an ineligible
    // result): the SARIF suppresses only those, never a merely-listed id.
    baseline: Object.freeze({
      uri: String(uri),
      applied,
      keyOf: keyOfRow,
      used: Object.freeze([...used].sort()),
      mismatched: Object.freeze([...mismatched].sort()),
    }),
  });
}

/**
 * Build a baseline document accepting every keyed result of the given units.
 * @param {Array<{file:(string|null), result:object}>} units results already passed through applyBaseline
 * @returns {object} baseline document (deterministic: entries sorted by key)
 */
export function buildBaseline(units) {
  const byKey = new Map();
  for (const u of Array.isArray(units) ? units : []) {
    const r = u && u.result;
    const b = r && r.baseline;
    if (!b || !(b.keyOf instanceof Map)) continue;
    for (const [row, key] of b.keyOf) {
      if (byKey.has(key)) continue;
      byKey.set(key, { id: key, ...rowMeta(row, b.uri) });
    }
  }
  return {
    version: BASELINE_VERSION,
    tool: 'iam-blast-radius',
    note: 'Accepted IAM Blast Radius results. "file", "ruleId" and "severity" are checked against each matched result; review every entry before committing.',
    entries: [...byKey.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)),
  };
}

export function formatBaseline(doc) {
  return `${JSON.stringify(doc, null, 2)}\n`;
}
