// SECONDARY snapshot channel (a CHANGE-DETECTOR, not a safety proof).
//
// The oracle (golden-oracle.test.js) proves fail-closed PROPERTIES. This module is the
// secondary signal: it captures a NORMALIZED snapshot of each corpus case across the
// three surfaces and stores it under ./baselines. `diff.mjs` re-derives and compares,
// so an UNINTENDED behaviour change is caught even when no property flips. It proves
// STABILITY only - it can just as easily freeze a KNOWN-OPEN bug's wrong output, which
// is exactly why it is NOT the primary mechanism. NEITHER channel proves the policy or
// the engine is "safe".
//
// Surfaces per case:
//   cli-json  - a real `node cli/iam-br.mjs --format json` SPAWN (child_process, NOT an
//               in-process import), reading the policy on STDIN so no filesystem path
//               leaks into the artifact; captures {exit, json, stderrClean}.
//   cli-sarif - the same spawn with --format sarif; captures {exit, sarif}.
//   analyze   - the in-process browser engine analyze(), reduced to a stable projection.
//
// Volatile fields (version/semanticVersion identifiers, absolute paths) are stripped so
// a deliberate version bump or a machine-specific path does not read as a behaviour drift.
//
// Usage:
//   node capture.mjs            # dry-run: print the snapshot for every case to stdout
//   node capture.mjs --update   # rewrite ./baselines/<id>.json deliberately

import { spawnSync } from 'node:child_process';
import { writeFileSync, mkdirSync, readdirSync, rmSync, realpathSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

import { analyze } from '../../../../content/tools/iam-blast-radius/engine/analyze.js';
import { CASES, corpusText, analyzeOptionsFor } from './manifest.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = join(here, '..', '..', '..', '..', 'cli', 'iam-br.mjs');
export const BASELINES_DIR = join(here, 'baselines');

// Keys whose values are legitimately volatile across intended releases; dropped so the
// snapshot tracks BEHAVIOUR, not release identifiers.
const VOLATILE_KEYS = new Set(['version', 'semanticVersion']);

// Collapse machine/run-specific absolute paths to a stable placeholder.
function scrubString(s) {
  return s
    .replace(/\/private\/var\/folders\/[^"\s]+/g, '<TMP>')
    .replace(/\/var\/folders\/[^"\s]+/g, '<TMP>')
    .replace(/\/tmp\/[^"\s]+/g, '<TMP>')
    .replace(new RegExp(join(here, '..', '..', '..', '..').replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '<REPO>');
}

// Recursively drop volatile keys and scrub path-like strings. Deterministic key order
// via JSON round-trip at write time (JSON.stringify preserves insertion order, which
// the engine builds deterministically).
function normalize(value) {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return scrubString(value);
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value)) {
      if (VOLATILE_KEYS.has(k)) continue;
      out[k] = normalize(value[k]);
    }
    return out;
  }
  return value;
}

function spawnCli(args, input) {
  const res = spawnSync('node', [CLI_PATH, ...args], { input, encoding: 'utf8' });
  return res;
}

// Parse a surface that MUST be machine-parseable (--format json / --format sarif). An
// unparseable result is a HARD capture failure, never a blessable baseline: baselining a
// `{__unparsed: ...}` blob would freeze a broken/garbage emission as "expected" and let a
// later regression that emits valid-but-wrong JSON slip by. Fail loud instead.
function parseMachineOutput(stdout, kind, ctx) {
  try {
    return JSON.parse(stdout);
  } catch (e) {
    throw new Error(
      `capture: ${ctx} produced UNPARSEABLE ${kind} - a machine-parseable format MUST parse; `
      + `this is a hard capture failure, not a baseline. ${e.message}. `
      + `head=${JSON.stringify(scrubString(String(stdout).slice(0, 200)))}`,
    );
  }
}

// Short stable hash of a value's deterministic JSON serialization.
function stableHash(value) {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 16);
}

// Coverage projection: the incomplete flag plus the counts that carry verdict meaning
// (statement accounting + how much the analysis could NOT decide). A shift here is a real
// behaviour change even if no finding id flips.
function coverageProjection(cov) {
  if (!cov) return { incomplete: false, codes: [], statements: null, counts: {} };
  const len = (a) => (Array.isArray(a) ? a.length : 0);
  const st = cov.statements;
  return {
    incomplete: !!cov.incomplete,
    analysisAborted: !!cov.analysisAborted,
    codes: Array.isArray(cov.codes) ? cov.codes.slice().sort() : [],
    statements: st
      ? { total: st.total ?? null, accepted: st.accepted ?? null, rejected: st.rejected ?? null }
      : null,
    counts: {
      unrecognizedActions: len(cov.unrecognizedActions),
      unsupportedConditions: len(cov.unsupportedConditions),
      unsupportedElements: len(cov.unsupportedElements),
      actionResourceMismatches: len(cov.actionResourceMismatches),
      maskedGrants: len(cov.maskedGrants),
      broadUndecidableUncovered: len(cov.broadUndecidableUncovered),
    },
  };
}

// A richer normalized finding: the fields that carry the VERDICT (actions, resource
// scope, condition presence) plus a stable hash of the evidence/why rationale, so the
// snapshot diff catches a changed scope / evidence / message - not only a changed id or
// severity. Volatile prose (the full why/limit/remediation text) is folded into the hash
// rather than stored verbatim; nothing time-dependent is captured.
function normalizeFinding(f) {
  const arr = (a) => (Array.isArray(a) ? a.slice().sort() : []);
  const evidenceWhy = {
    why: String(f.why || ''),
    remediation: String(f.remediation || ''),
    evidence: Array.isArray(f.evidence) ? f.evidence : [],
    escalationTechnique: (f.escalation && f.escalation.technique) || null,
  };
  return {
    id: String(f.id || ''),
    severity: String(f.severity || ''),
    title: String(f.title || ''),
    statementIndex: typeof f.statementIndex === 'number' ? f.statementIndex : null,
    actions: arr(f.actions),
    resources: arr(f.resources),
    conditionsPresent: !!(f.conditionClassification && f.conditionClassification.present),
    evidenceWhyHash: stableHash(evidenceWhy),
  };
}

// A stable, reduced projection of an analyze() result (the full object carries a large
// graph; the snapshot keeps the decision-relevant surface).
function analyzeProjection(ar) {
  const cov = ar && ar.coverage && ar.coverage.summary;
  const key = (f) => `${f.id}|${f.severity}|${f.statementIndex}|${f.evidenceWhyHash}`;
  return {
    ok: !!(ar && ar.ok),
    coverage: coverageProjection(cov),
    findings: (ar && Array.isArray(ar.findings) ? ar.findings : [])
      .map(normalizeFinding)
      .sort((a, b) => key(a).localeCompare(key(b))),
  };
}

// The full normalized snapshot for one corpus case.
export function snapshotFor(c) {
  const text = corpusText(c.file);
  const baseArgs = ['--family', c.family];
  if (c.threshold) baseArgs.push('--threshold', c.threshold);
  if (c.subjectAccount) baseArgs.push('--subject-account', c.subjectAccount);

  const jsonRun = spawnCli([...baseArgs, '--format', 'json'], text);
  const sarifRun = spawnCli([...baseArgs, '--format', 'sarif'], text);
  const ar = analyze(text, analyzeOptionsFor(c));

  return {
    id: c.id,
    klass: c.klass,
    knownOpen: c.knownOpen ? c.knownOpen.bug : null,
    cliJson: {
      exit: jsonRun.status,
      stderrClean: String(jsonRun.stderr || '').trim() === '',
      report: normalize(parseMachineOutput(jsonRun.stdout, 'JSON', `${c.id} cli --format json`)),
    },
    cliSarif: {
      exit: sarifRun.status,
      sarif: normalize(parseMachineOutput(sarifRun.stdout, 'SARIF', `${c.id} cli --format sarif`)),
    },
    analyze: analyzeProjection(ar),
  };
}

export function baselinePath(id) {
  return join(BASELINES_DIR, `${id}.json`);
}

export function writeBaselines() {
  mkdirSync(BASELINES_DIR, { recursive: true });
  // Remove stale baselines for ids no longer in the corpus.
  const live = new Set(CASES.map((c) => `${c.id}.json`));
  for (const f of readdirSync(BASELINES_DIR)) {
    if (f.endsWith('.json') && !live.has(f)) rmSync(join(BASELINES_DIR, f));
  }
  for (const c of CASES) {
    const snap = snapshotFor(c);
    writeFileSync(baselinePath(c.id), JSON.stringify(snap, null, 2) + '\n');
  }
  return CASES.length;
}

function main() {
  const update = process.argv.includes('--update');
  if (update) {
    const n = writeBaselines();
    process.stdout.write(`capture: wrote ${n} baseline(s) to ${BASELINES_DIR}\n`);
    return;
  }
  for (const c of CASES) {
    process.stdout.write(JSON.stringify(snapshotFor(c), null, 2) + '\n');
  }
  process.stderr.write('capture: dry-run only. Re-run with --update to (re)write baselines.\n');
}

// Run only when invoked directly. Compare a REALPATH-resolved argv[1] to this module's
// URL - deliberately NOT the buggy `import.meta.url === pathToFileURL(argv[1])` this
// harness audits, so a symlinked invocation of the harness still runs correctly.
const invokedDirectly = (() => {
  try {
    const entry = process.argv[1];
    if (!entry) return false;
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch { return false; }
})();

if (invokedDirectly) main();
