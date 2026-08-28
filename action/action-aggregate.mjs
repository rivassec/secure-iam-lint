// action-aggregate.mjs - multi-file SARIF aggregation for the GitHub Action: merge per-file runs into one SARIF log, rank + truncate to the result/byte ceilings (fail-closed truncation notice). Extracted from index.mjs (behavior-preserving).
import { isNonEmptyString, utf8ByteLength } from './action-utils.mjs';
import { DEFAULT_MAX_SARIF_RESULTS, DEFAULT_MAX_SARIF_BYTES, SARIF_OUTPUT_TRUNCATED_REASON } from './action-consts.mjs';
import { buildSarifLog } from '../cli/sarif.mjs';
import { EXIT } from '../cli/scan.mjs';
import { VERSION_MANIFEST } from '../content/tools/iam-blast-radius/engine/version.js';

export const SARIF_KEEP_RANK = Object.freeze({
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
});
export function resultKeepPriority(res) {
  if (res && res.kind === 'fail' && res.properties && res.properties.category === 'analysis-state') {
    return 100; // fail-closed analyzer-state: never dropped before any security finding
  }
  const sev = res && res.properties ? String(res.properties.severity) : '';
  return SARIF_KEEP_RANK[sev] || 1;
}

// CONSERVATIVE over-estimate (UTF-8 bytes) of a value's contribution to the final pretty-
// printed aggregate SARIF. Mirrors cli/sarif.mjs estimateRowBytes: measure the real UTF-8
// bytes of JSON.stringify(x, null, 2), then add a generous per-line margin for the DEEPER
// nesting (runs[i].results[j] sits several levels down, so each line carries extra leading
// spaces) plus separators. Over-counting only makes truncation slightly more aggressive, so
// the REAL serialized document is GUARANTEED <= the budget, never merely likely.
export function aggEstBytes(value, perLine, flat) {
  const s = JSON.stringify(value, null, 2);
  let lines = 1;
  for (let i = 0; i < s.length; i += 1) if (s.charCodeAt(i) === 10) lines += 1;
  return utf8ByteLength(s) + lines * perLine + flat;
}
export function aggEstResultBytes(res) { return aggEstBytes(res, 16, 16); }
export function aggEstRunBytes(run) { return aggEstBytes(run, 16, 64); } // full run, incl. its results
export function aggEstRunScaffoldBytes(run) { return aggEstBytes({ ...run, results: [] }, 16, 72); }

// The family to attribute the aggregate truncation notification to: the first unit that
// carries one. Purely cosmetic (it never affects the exit code); leaks no policy content.
export function aggregateFamily(units) {
  for (const u of units) {
    const fam = u && u.result && u.result.family;
    if (fam != null) return fam;
  }
  return null;
}

// The synthetic scan()-compatible result for the aggregate DOCUMENT-level truncation
// notification (S2-NEW-SARIF-AGGREGATE). Shaped so buildSarifLog projects it into a
// kind:'fail' / category:'analysis-state' result carrying NO security-severity - the SAME
// load-bearing fail-closed shape as every other analyzer-state, so a consumer can never
// misread it as a vulnerability. Its exitCode is NEVER aggregated (finalize computes the
// exit code from the REAL units BEFORE this notification is built), so the truncation can
// never downgrade - or inflate - the Action's exit code. The message carries ONLY counts +
// the configured ceilings, never a filename or policy content, so it stays deterministic.
export function aggregateSarifTruncatedResult(message, family) {
  return Object.freeze({
    analysisStatus: 'partial',
    analysisStates: Object.freeze([Object.freeze({
      analysisState: 'output-truncated', code: SARIF_OUTPUT_TRUNCATED_REASON, message, path: null,
    })]),
    findings: Object.freeze([]),
    findingsCount: 0,
    blockingCount: 0,
    exitCode: EXIT.FAIL_CLOSED,
    reason: SARIF_OUTPUT_TRUNCATED_REASON,
    family: family != null ? family : null,
  });
}

// The deterministic aggregate-truncation message. Carries ONLY counts + the configured
// ceilings (no filename, no policy content) so it stays deterministic and leaks nothing.
export function truncationMessage(maxResults, maxBytes, totalResults, elided) {
  return 'Aggregate SARIF output reached the safe document budget and was truncated to stay '
    + `below the code-scanning upload limits (max ${maxResults} results / ${maxBytes} bytes; `
    + 'GitHub silently drops results past ~5000 per upload and rejects uploads past ~10 MB gzip): '
    + `${elided} of ${totalResults} result${totalResults === 1 ? '' : 's'} `
    + `${elided === 1 ? 'was' : 'were'} elided, keeping the highest-severity/blocking findings and `
    + 'every fail-closed analyzer-state first. Results were TRUNCATED, not cleared, and the exit '
    + 'code is UNAFFECTED (it is driven only by finding severity). Raise max-sarif-results / '
    + 'max-sarif-bytes, or split the scan, to retrieve every result.';
}

// Build one multi-run SARIF 2.1.0 log: one run per scanned unit (each carrying its
// own file URI, rules, and results, including analyzer-state results for a
// fail-closed file). Reuses the pure per-result SARIF adapter unchanged. For a
// config error with no scanned files, a single run describes the usage error so
// the SARIF is never a silent empty/clean document.
//
// S2-NEW-SARIF-AGGREGATE: the concatenation is then bounded by a DOCUMENT-LEVEL budget
// mirroring the per-run one in cli/sarif.mjs. The per-run budget bounds ONE run; NOTHING
// bounded the SUM across one run per file, so a within-caps fan-out could push the aggregate
// past GitHub's ~5000-results / ~10 MB-gzip upload caps - at which point GitHub SILENTLY
// DROPS the excess results and Security-tab findings vanish with no error. When the aggregate
// exceeds EITHER the result-count cap or the (uncompressed-proxy) byte cap, results are
// TRUNCATED DETERMINISTICALLY - highest-severity / blocking findings and every fail-closed
// analyzer-state kept FIRST - and ONE truthful SARIF_OUTPUT_TRUNCATED analyzer-state result is
// appended so the truncation is VISIBLE in the SARIF, never silent. `caps` = { maxResults,
// maxBytes, family }; omitted/invalid fields fall back to the DEFAULT_MAX_SARIF_* ceilings.
// The Action exit code is UNAFFECTED: finalize() computes it from the real units before this
// runs, and this function only shapes the SARIF document.
export function buildAggregateSarif(units, manifest = VERSION_MANIFEST, caps = {}) {
  const list = Array.isArray(units) ? units : [];
  const maxResults = Number.isInteger(caps.maxResults) && caps.maxResults > 0
    ? caps.maxResults : DEFAULT_MAX_SARIF_RESULTS;
  const maxBytes = Number.isInteger(caps.maxBytes) && caps.maxBytes > 0
    ? caps.maxBytes : DEFAULT_MAX_SARIF_BYTES;

  const runs = list.map((u) => {
    const opts = isNonEmptyString(u && u.file) ? { file: u.file } : { artifactUri: 'action-inputs' };
    return buildSarifLog(u.result, opts, manifest).runs[0];
  });
  const SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
  const fullLog = { $schema: SCHEMA, version: '2.1.0', runs };

  // Under BOTH caps -> emit the document UNCHANGED (byte-for-byte as before this budget
  // existed). The byte total is the EXACT serialized size emitArtifacts will write (pretty-
  // printed + a trailing newline), so a document that genuinely fits is never disturbed.
  const totalResults = runs.reduce((n, r) => n + ((r.results && r.results.length) || 0), 0);
  const totalBytes = utf8ByteLength(`${JSON.stringify(fullLog, null, 2)}\n`);
  if (totalResults <= maxResults && totalBytes <= maxBytes) return fullLog;

  // --- Truncate. Flatten every result with its keep-priority + a conservative byte cost. --
  const flat = [];
  runs.forEach((run, ri) => {
    (run.results || []).forEach((res, rj) => {
      flat.push({ ri, rj, prio: resultKeepPriority(res), cost: aggEstResultBytes(res) });
    });
  });
  // Highest priority first; ties keep the ORIGINAL (run, in-run) order for determinism.
  const order = flat.slice().sort((a, b) => b.prio - a.prio || a.ri - b.ri || a.rj - b.rj);

  // Reserve the truncation notification's bytes + its ONE result slot out of the budget up
  // front, so the fail-closed signal always survives even in the extreme where every real
  // result is elided. The final notification message is a few digits longer (the exact elided
  // count), so estimate the reserve from a full-length sizing message that is >= the real one.
  const family = caps.family != null ? caps.family : aggregateFamily(list);
  const buildNotifRun = (msg) => buildSarifLog(
    aggregateSarifTruncatedResult(msg, family), { artifactUri: 'action-aggregate' }, manifest,
  ).runs[0];
  const notifReserveBytes = aggEstRunBytes(buildNotifRun(truncationMessage(maxResults, maxBytes, totalResults, totalResults)));
  const runScaffold = runs.map((r) => aggEstRunScaffoldBytes(r));
  const docScaffoldBytes = aggEstBytes({ $schema: SCHEMA, version: '2.1.0', runs: [] }, 8, 256);

  const resultCap = Math.max(0, maxResults - 1); // reserve ONE result slot for the notification
  let usedResults = 0;
  let usedBytes = docScaffoldBytes + notifReserveBytes;
  const chargedRuns = new Set();
  const keptByRun = new Map(); // ri -> Set<rj>
  for (const item of order) {
    if (usedResults >= resultCap) break;
    const runCost = chargedRuns.has(item.ri) ? 0 : runScaffold[item.ri];
    // Keep highest-priority-FIRST: if the next (most important remaining) result does not fit,
    // STOP - never skip it to backfill a less-important, cheaper one.
    if (usedBytes + runCost + item.cost > maxBytes) break;
    usedBytes += runCost + item.cost;
    usedResults += 1;
    chargedRuns.add(item.ri);
    let set = keptByRun.get(item.ri);
    if (!set) { set = new Set(); keptByRun.set(item.ri, set); }
    set.add(item.rj);
  }

  const elided = totalResults - usedResults;
  const notification = buildNotifRun(truncationMessage(maxResults, maxBytes, totalResults, elided));

  // Rebuild the surviving runs (drop those whose results were all elided; ruleIndex stays
  // valid because each run keeps its own tool.driver.rules intact), then append the visible
  // truncation notification LAST.
  const truncatedRuns = [];
  runs.forEach((run, ri) => {
    const kept = keptByRun.get(ri);
    if (!kept || kept.size === 0) return;
    truncatedRuns.push({ ...run, results: (run.results || []).filter((_, rj) => kept.has(rj)) });
  });
  truncatedRuns.push(notification);
  return { $schema: SCHEMA, version: '2.1.0', runs: truncatedRuns };
}

// --- Output + summary rendering ----------------------------------------------

// Render the GITHUB_OUTPUT file body for a { name: value } map. Single-line values
// use `name=value`; a value containing a newline uses the heredoc delimiter form
// (GitHub's multi-line output syntax). Our values are all single-line scalars.
//
// S4-action-hardening: two hardenings against GITHUB_OUTPUT injection.
//   1. A value containing any C0 control char OTHER than the newline that legitimately
//      triggers the heredoc form (NUL, CR, vertical tab, ...) is REJECTED (throw ->
//      caught by emitArtifacts as a writeError -> fail closed): such a char never
//      belongs in these scalar outputs and could split/forge `key=value` lines. The
//      key is likewise validated.
//   2. The heredoc delimiter is UNPREDICTABLE (a per-value random token), not the old
//      guessable `ghadelim_<key>_EOF`. With a random delimiter a crafted multi-line
//      value cannot close the heredoc early to inject forged/suppressed output lines;
//      as a further guard a value that still contains the chosen delimiter line is
//      rejected outright.
// Every C0 control char EXCEPT the newline (0x0a) that legitimately triggers the
// heredoc form: 0x00-0x09 and 0x0b-0x1f. A value carrying any of these is rejected.
export const VALUE_CONTROL_CHAR_RE = /[\u0000-\u0009\u000b-\u001f]/;
// An output KEY is a bare identifier: any C0 control char (incl. newline) is unsafe.
export const KEY_CONTROL_CHAR_RE = /[\u0000-\u001f]/;
