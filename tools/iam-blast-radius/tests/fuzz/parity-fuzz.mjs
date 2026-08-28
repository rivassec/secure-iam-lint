#!/usr/bin/env node
// IAM Blast Radius - differential parity fuzzer (S6-cigate-doc).
//
// THE INVARIANT under test (the immutable safety contract, same one
// browser-cli-parity.test.js pins): the BROWSER engine (analyze(), the code
// app.js/worker.js run) may NEVER be MORE PERMISSIVE than the CLI (scan()).
// For every policy:
//
//     scanClean(scan(p))  ||  !analyzeClean(analyze(p))      MUST hold
//
//   analyze clean := ok === true && findings.length === 0
//                    && !coverage.summary.incomplete           (browser-cli-parity)
//   scan clean    := exitCode === 0 && analysisStatus === 'complete'
//
// The forbidden state is scan NON-clean while analyze reports a clean pass - a
// silent browser fail-OPEN on a policy the CLI correctly fails closed (T8).
//
// This fuzzer drives that comparison over MANY deterministically-generated,
// mutation-heavy policies biased toward the known fail-open surface (empty
// NotAction/NotResource complements, suppressed never-match conditions,
// malformed condition blocks, dangerous __proto__/constructor keys, deep
// nesting, over-limit sizes, BOM/Unicode noise, truncated JSON, ...). It ALSO
// fails on two further ways the tool could betray the contract on hostile input:
//   - either surface THROWS instead of failing closed gracefully, or
//   - either surface exceeds a hard wall-clock ceiling on a single input (DoS).
//
// DETERMINISTIC: a given --seed yields exactly the same policy sequence and the
// same verdict on every machine and every run (no Date.now()/Math.random()).
// A violation prints a self-contained reproducer (seed, index, family, exact
// text) that drops straight into a regression fixture.
//
// Usage:  node tests/fuzz/parity-fuzz.mjs [--seed N] [--count N] [--budget-ms N]
//                                         [--ceiling-ms N] [--quiet]
// Env fallbacks: FUZZ_SEED, FUZZ_COUNT, FUZZ_BUDGET_MS, FUZZ_CEILING_MS.
// Exit 0 = invariant held over the whole run; exit 1 = at least one violation.

import { analyze } from '../../../../content/tools/iam-blast-radius/engine/analyze.js';
import { scan, EXIT, ANALYSIS_STATUS } from '../../../../cli/scan.mjs';

// --- Deterministic PRNG (mulberry32): pure, seedable, no global state --------
export function makeRng(seed) {
  // Coerce to a 32-bit unsigned integer; a string seed hashes deterministically.
  let s;
  if (typeof seed === 'number' && Number.isFinite(seed)) {
    s = seed >>> 0;
  } else {
    const str = String(seed);
    let h = 2166136261 >>> 0;
    for (let i = 0; i < str.length; i += 1) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    s = h >>> 0;
  }
  const rng = () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  rng.int = (n) => Math.floor(rng() * n);           // [0, n)
  rng.pick = (arr) => arr[rng.int(arr.length)];
  rng.chance = (p) => rng() < p;
  return rng;
}

// --- Clean predicates (identical to browser-cli-parity.test.js) --------------
export function analyzeClean(ar) {
  return !!(ar && ar.ok === true
    && Array.isArray(ar.findings) && ar.findings.length === 0
    && !(ar.coverage && ar.coverage.summary && ar.coverage.summary.incomplete));
}
export function scanClean(sr) {
  return !!(sr && sr.exitCode === EXIT.CLEAN && sr.analysisStatus === ANALYSIS_STATUS.COMPLETE);
}

// The forbidden state: CLI fails closed / non-clean while the browser reports a
// clean pass (browser strictly MORE permissive). Exported so the regression
// suite can prove the detector fires on a synthetic fail-open.
export function isParityViolation(ar, sr) {
  return !scanClean(sr) && analyzeClean(ar);
}

const FAMILIES = [
  'identity', 'resource', 'role-trust', 'permissions-boundary', 'scp-rcp', 'session',
];

// --- Building blocks ---------------------------------------------------------
const ACTIONS = [
  '*', 's3:*', 's3:GetObject', 's3:DeleteObject', 'iam:PassRole', 'iam:*',
  'iam:CreateAccessKey', 'sts:AssumeRole', 'kms:Decrypt', 'ec2:RunInstances',
  'lambda:InvokeFunction', 'dynamodb:*', 'secretsmanager:GetSecretValue',
];
const RESOURCES = [
  '*', 'arn:aws:s3:::my-bucket/*', 'arn:aws:iam::123456789012:role/app-*',
  'arn:aws:kms:us-east-1:123456789012:key/*', 'arn:aws:lambda:*:*:function:*',
];
const PRINCIPALS = [
  '*', { AWS: '*' }, { AWS: 'arn:aws:iam::123456789012:root' },
  { Service: 'lambda.amazonaws.com' }, { AWS: ['*', 'arn:aws:iam::999:root'] },
  { Federated: 'cognito-identity.amazonaws.com' },
];

// A condition operator/value pair, weighted toward the suppressed/malformed
// shapes that historically produced browser fail-opens.
function makeCondition(rng) {
  const kind = rng.int(8);
  switch (kind) {
    case 0: return { 'ForAnyValue:StringEquals': { 'aws:PrincipalOrgID': [] } };      // never-match suppression
    case 1: return { 'ForAllValues:StringEquals': { 'aws:SourceVpc': [] } };
    case 2: return { 'ForAnyValue:StringEquals': { 'aws:SourceVpc': [{}] } };          // malformed value
    case 3: return { StringEquals: { 'aws:SourceIp': [null] } };                       // malformed value
    case 4: return { StringEquals: 'not-an-object' };                                  // malformed block
    case 5: return { StringLike: { 's3:prefix': ['home/*'] } };                        // benign
    case 6: return { Bool: { 'aws:MultiFactorAuthPresent': 'true' } };                 // benign
    default: return {};
  }
}

function oneOrArray(rng, v) {
  return rng.chance(0.5) ? v : [v];
}

// Build a single statement object. `hostile` steers toward fail-open shapes.
function makeStatement(rng, family) {
  const st = {};
  if (rng.chance(0.85)) st.Sid = rng.pick(['S', 'Allow', 'x', `s${rng.int(1000)}`]);
  st.Effect = rng.chance(0.75) ? 'Allow' : 'Deny';

  // Action vs NotAction (empty NotAction is a known full-admin fail-open).
  const actionMode = rng.int(5);
  if (actionMode === 0) st.NotAction = [];                                  // empty complement -> everything
  else if (actionMode === 1) st.NotAction = oneOrArray(rng, rng.pick(ACTIONS));
  else if (actionMode === 2) { /* omit Action entirely */ }
  else st.Action = rng.chance(0.5) ? rng.pick(ACTIONS) : Array.from({ length: 1 + rng.int(4) }, () => rng.pick(ACTIONS));

  // Resource vs NotResource (empty NotResource is a known every-resource fail-open).
  // Trust/SCP-shaped families legitimately omit Resource; let the mutator decide.
  const resMode = rng.int(5);
  if (resMode === 0) st.NotResource = [];                                   // empty complement -> every resource
  else if (resMode === 1) st.NotResource = oneOrArray(rng, rng.pick(RESOURCES));
  else if (resMode === 2) { /* omit Resource entirely */ }
  else st.Resource = rng.chance(0.5) ? rng.pick(RESOURCES) : Array.from({ length: 1 + rng.int(3) }, () => rng.pick(RESOURCES));

  if (family === 'role-trust' || rng.chance(0.15)) st.Principal = rng.pick(PRINCIPALS);
  if (rng.chance(0.45)) st.Condition = makeCondition(rng);
  return st;
}

// Assemble a whole policy document object.
function makePolicyObject(rng, family) {
  const n = 1 + rng.int(4);
  const statements = Array.from({ length: n }, () => makeStatement(rng, family));
  const doc = {};
  if (rng.chance(0.9)) doc.Version = rng.pick(['2012-10-17', '2008-10-17', 'bogus']);
  // Statement as array, or as a bare object (single-statement shorthand).
  doc.Statement = (n === 1 && rng.chance(0.3)) ? statements[0] : statements;
  return doc;
}

// Raw hostile JSON text that cannot be produced by JSON.stringify of a plain
// object (dangerous keys, truncation) - injected verbatim as policy text.
function rawHostile(rng) {
  const bank = [
    '{"Version":"2012-10-17","Statement":[{"__proto__":{"polluted":true},"Effect":"Allow","Action":"*","Resource":"*"}]}',
    '{"Version":"2012-10-17","Statement":[{"constructor":{"x":1},"Effect":"Allow","Action":"*","Resource":"*"}]}',
    '{"Version":"2012-10-17","Statement":[{"prototype":1,"Effect":"Allow","NotAction":[],"Resource":"*"}]}',
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"',   // truncated
    '{"Statement":',                                                                          // truncated
    'not json at all',
    '[]',
    'null',
    '{}',
    '{"Version":"2012-10-17","Statement":{"Effect":"Allow","NotAction":[],"NotResource":[]}}', // double empty complement
  ];
  return rng.pick(bank);
}

// Optional structural mutators applied to a generated JSON string.
function mutateText(rng, text) {
  if (rng.chance(0.12)) text = '﻿' + text;                       // BOM prefix
  if (rng.chance(0.08)) text = '  \n\t' + text + '\n';                // surrounding whitespace
  if (rng.chance(0.06)) text = text.replace('Allow', 'A‮llow'); // BiDi override noise in a value
  return text;
}

// Produce one fuzz case: { text, family, label }.
export function generateCase(rng) {
  const family = rng.pick(FAMILIES);
  // ~15% of cases are raw hostile strings; the rest are structured + mutated.
  if (rng.chance(0.15)) {
    return { text: rawHostile(rng), family, label: 'raw-hostile' };
  }
  // Rarely, blow a size/depth limit to exercise the fail-closed limit paths.
  if (rng.chance(0.04)) {
    const many = Array.from({ length: 1100 }, () => ({ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }));
    return { text: JSON.stringify({ Version: '2012-10-17', Statement: many }), family, label: 'over-limit-statements' };
  }
  if (rng.chance(0.04)) {
    // Deep nesting inside a condition value, past MAX_DEPTH (64).
    let deep = 0;
    let s = '';
    for (let i = 0; i < 80; i += 1) { s += '['; deep += 1; }
    for (let i = 0; i < deep; i += 1) { s += ']'; }
    return { text: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":${s}}]}`, family, label: 'over-depth' };
  }
  const obj = makePolicyObject(rng, family);
  return { text: mutateText(rng, JSON.stringify(obj)), family, label: 'structured' };
}

// --- The differential check for a single case --------------------------------
// Returns null if the invariant held; otherwise a violation descriptor.
export function checkParity(text, family, opts) {
  const budgetMs = (opts && opts.budgetMs) || 5000;
  const ceilingMs = (opts && opts.ceilingMs) || 8000;

  // Both surfaces must FAIL CLOSED, never throw, on hostile input.
  let ar; let sr; let arMs; let srMs;
  let t0 = process.hrtime.bigint();
  try {
    ar = analyze(text, { family, requireExplicitFamily: true });
  } catch (e) {
    return { kind: 'throw', surface: 'analyze', detail: (e && e.message) || String(e) };
  }
  arMs = Number(process.hrtime.bigint() - t0) / 1e6;

  t0 = process.hrtime.bigint();
  try {
    sr = scan({ text, family, budgetMs });
  } catch (e) {
    return { kind: 'throw', surface: 'scan', detail: (e && e.message) || String(e) };
  }
  srMs = Number(process.hrtime.bigint() - t0) / 1e6;

  // DoS: a single hostile input must never blow the wall-clock ceiling.
  if (arMs > ceilingMs) return { kind: 'budget', surface: 'analyze', detail: `analyze took ${arMs.toFixed(1)}ms > ${ceilingMs}ms` };
  if (srMs > ceilingMs) return { kind: 'budget', surface: 'scan', detail: `scan took ${srMs.toFixed(1)}ms > ${ceilingMs}ms` };

  // THE INVARIANT: browser never more permissive than CLI.
  if (isParityViolation(ar, sr)) {
    return {
      kind: 'parity',
      detail: `scan{exit:${sr.exitCode},status:${sr.analysisStatus},reason:${sr.reason}} `
        + `analyze{ok:${ar.ok},findings:${ar.findings && ar.findings.length},`
        + `incomplete:${!!(ar.coverage && ar.coverage.summary && ar.coverage.summary.incomplete)}}`,
    };
  }
  return null;
}

// --- Run a whole deterministic sweep -----------------------------------------
export function runFuzz(config) {
  const cfg = config || {};
  const seed = cfg.seed != null ? cfg.seed : 1;
  const count = cfg.count != null ? cfg.count : 2000;
  const budgetMs = cfg.budgetMs != null ? cfg.budgetMs : 5000;
  const ceilingMs = cfg.ceilingMs != null ? cfg.ceilingMs : 8000;
  const rng = makeRng(seed);
  const violations = [];
  let maxCallMs = 0;

  for (let i = 0; i < count; i += 1) {
    const c = generateCase(rng);
    const v = checkParity(c.text, c.family, { budgetMs, ceilingMs });
    if (v) {
      violations.push({ index: i, seed, family: c.family, label: c.label, text: c.text, ...v });
      // Cap stored reproducers so a systemic break does not exhaust memory.
      if (violations.length >= 25) break;
    }
  }
  return { seed, count, checked: count, violations, maxCallMs };
}

// --- CLI ---------------------------------------------------------------------
function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--seed') out.seed = Number(argv[++i]);
    else if (a === '--count') out.count = Number(argv[++i]);
    else if (a === '--budget-ms') out.budgetMs = Number(argv[++i]);
    else if (a === '--ceiling-ms') out.ceilingMs = Number(argv[++i]);
    else if (a === '--quiet') out.quiet = true;
  }
  return out;
}

function main(argv) {
  const args = parseArgs(argv);
  const seed = args.seed != null && Number.isFinite(args.seed) ? args.seed
    : (process.env.FUZZ_SEED != null ? Number(process.env.FUZZ_SEED) : 1);
  const count = args.count != null && Number.isFinite(args.count) ? args.count
    : (process.env.FUZZ_COUNT != null ? Number(process.env.FUZZ_COUNT) : 2000);
  const budgetMs = args.budgetMs != null && Number.isFinite(args.budgetMs) ? args.budgetMs
    : (process.env.FUZZ_BUDGET_MS != null ? Number(process.env.FUZZ_BUDGET_MS) : 5000);
  const ceilingMs = args.ceilingMs != null && Number.isFinite(args.ceilingMs) ? args.ceilingMs
    : (process.env.FUZZ_CEILING_MS != null ? Number(process.env.FUZZ_CEILING_MS) : 8000);

  const res = runFuzz({ seed, count, budgetMs, ceilingMs });
  if (!args.quiet) {
    process.stdout.write(`parity-fuzz: seed=${seed} count=${count} checked=${res.checked} `
      + `violations=${res.violations.length}\n`);
  }
  if (res.violations.length > 0) {
    process.stderr.write('PARITY FUZZ VIOLATION(S) - reproducers follow:\n');
    for (const v of res.violations) {
      process.stderr.write(
        `  [${v.kind}] seed=${v.seed} index=${v.index} family=${v.family} label=${v.label}\n`
        + `    ${v.detail}\n`
        + `    text=${JSON.stringify(v.text)}\n`,
      );
    }
    process.exitCode = 1;
    return 1;
  }
  return 0;
}

// Run only when invoked directly (never when imported by the test harness).
const invokedDirectly = (() => {
  try {
    const entry = process.argv && process.argv[1];
    return entry && import.meta.url === new URL(`file://${entry}`).href;
  } catch { return false; }
})();
if (invokedDirectly) {
  main(process.argv.slice(2));
}
