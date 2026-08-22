// Unit tests for IAM-502: analysis coverage summary + export + wording flip.
// Runs on node's built-in runner: `node --test`.
//
// Acceptance (prd.json IAM-502):
//   - a COMPACT coverage summary carries: detected family, statements
//     accepted/rejected, unrecognized actions, unsupported conditions/elements,
//     missing evaluation layers, graph complete/truncated, build SHA + rule +
//     catalog version
//   - the zero-findings wording flips automatically when coverage is incomplete
//   - coverage (with the summary + stable codes) is part of JSON + MD exports;
//     a clean parse is NOT equivalent to complete coverage
//   - "unsupported does NOT mean safe" wording travels with exports
//
// The coverage panel's DOM order + a11y (coverage precedes findings) is a
// browser assertion (tests/e2e/ui-shell.spec.js); this suite covers the pure
// data + serialization off-browser.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';
import {
  enrichCoverage,
  noFindingsMessage,
  NO_FINDINGS_COMPLETE,
  NO_FINDINGS_INCOMPLETE,
  BUILD_SHA,
  RULE_VERSION,
  EVALUATION_LAYERS,
} from '../../../content/tools/iam-blast-radius/engine/coverage.js';
import { detectFamily, COVERAGE_CODES } from '../../../content/tools/iam-blast-radius/engine/family.js';
import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';

const IDENTITY = JSON.stringify({ Statement: [{ Effect: 'Allow', Action: 's3:*', Resource: '*' }] });
const RESOURCE = JSON.stringify({
  Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }],
});
const NOTPRINCIPAL = JSON.stringify({
  Statement: [
    { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    { Effect: 'Deny', NotPrincipal: { AWS: 'x' }, Action: 's3:*', Resource: '*' },
  ],
});

// ---------------------------------------------------------------------------
// enrichCoverage(): the pure summary projection.
// ---------------------------------------------------------------------------

function coverageFor(text, options) {
  const m = modelFromText(text);
  assert.equal(m.ok, true, 'model built');
  const cov = detectFamily(m.model, options || {});
  const graph = { nodes: [], edges: [], truncated: false };
  return { cov: enrichCoverage(cov, { model: m.model, graph, catalogVersion: '1' }), model: m.model };
}

test('enrichCoverage preserves every IAM-501 field and adds a summary (superset)', () => {
  const { cov } = coverageFor(IDENTITY);
  for (const k of ['detected', 'override', 'family', 'supported', 'blocked', 'blockingCodes', 'notes']) {
    assert.ok(k in cov, `coverage keeps IAM-501 field ${k}`);
  }
  assert.ok(cov.summary && typeof cov.summary === 'object', 'summary added');
  assert.ok(Object.isFrozen(cov), 'enriched coverage is frozen');
  assert.ok(Object.isFrozen(cov.summary), 'summary is frozen');
});

test('supported identity: all statements accepted, coverage complete, identity layer excluded', () => {
  const { cov } = coverageFor(IDENTITY);
  const s = cov.summary;
  assert.equal(s.detectedFamily, 'identity');
  assert.equal(s.detectedFamilyLabel, 'Identity policy');
  assert.equal(s.effectiveFamily, 'identity');
  assert.equal(s.supported, true);
  assert.equal(s.blocked, false);
  assert.equal(s.incomplete, false, 'a supported identity policy is complete coverage');
  assert.deepEqual(s.statements, { total: 1, accepted: 1, rejected: 0 });
  assert.deepEqual(s.unsupportedElements, []);
  assert.deepEqual(s.unrecognizedActions, []);
  assert.deepEqual(s.unsupportedConditions, []);
  // Missing layers = everything except the identity layer this document is.
  const keys = s.missingLayers.map((l) => l.key);
  assert.ok(!keys.includes('identity'), 'the analyzed layer is not "missing"');
  assert.ok(keys.includes('resource') && keys.includes('permissions-boundary') &&
    keys.includes('scp') && keys.includes('rcp') && keys.includes('session'),
    'the other five AWS layers are named as not covered');
  assert.equal(s.missingLayers.length, EVALUATION_LAYERS.length - 1);
  assert.deepEqual(s.graph, { complete: true, truncated: false });
  assert.deepEqual(s.versions, { buildSha: BUILD_SHA, ruleVersion: RULE_VERSION, catalogVersion: '1' });
});

test('blocked resource policy: zero accepted, incomplete, all rejected', () => {
  const { cov } = coverageFor(RESOURCE);
  const s = cov.summary;
  assert.equal(s.blocked, true);
  assert.equal(s.supported, false);
  assert.equal(s.incomplete, true, 'a blocked shape is incomplete coverage');
  assert.deepEqual(s.statements, { total: 1, accepted: 0, rejected: 1 });
  assert.ok(s.codes.includes(COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY), 'stable code carried in summary');
});

test('NotPrincipal surfaces as an unsupported element with its exact JSON path', () => {
  const { cov } = coverageFor(NOTPRINCIPAL);
  const s = cov.summary;
  assert.equal(s.incomplete, true);
  assert.equal(s.unsupportedElements.length, 1);
  assert.equal(s.unsupportedElements[0].element, 'NotPrincipal');
  assert.equal(s.unsupportedElements[0].code, COVERAGE_CODES.UNSUPPORTED_NOTPRINCIPAL);
  assert.equal(s.unsupportedElements[0].path, 'Statement[1].NotPrincipal');
});

test('missing layers reflect the effective (overridden) family', () => {
  // Overriding to permissions-boundary blocks, but the layer bookkeeping should
  // treat permissions-boundary as the represented layer.
  const { cov } = coverageFor(IDENTITY, { family: 'permissions-boundary' });
  const keys = cov.summary.missingLayers.map((l) => l.key);
  assert.ok(!keys.includes('permissions-boundary'), 'the overridden layer is represented, not missing');
  assert.ok(keys.includes('identity'), 'identity is now a not-covered layer');
});

test('graph truncation is reflected in the summary', () => {
  const m = modelFromText(IDENTITY);
  const cov = detectFamily(m.model, {});
  const enriched = enrichCoverage(cov, {
    model: m.model,
    graph: { nodes: [], edges: [], truncated: true },
    catalogVersion: '1',
  });
  assert.deepEqual(enriched.summary.graph, { complete: false, truncated: true });
});

test('enrichCoverage is deterministic and never throws on missing context', () => {
  const m = modelFromText(IDENTITY);
  const cov = detectFamily(m.model, {});
  assert.deepEqual(
    enrichCoverage(cov, { model: m.model, graph: { truncated: false }, catalogVersion: '1' }),
    enrichCoverage(cov, { model: m.model, graph: { truncated: false }, catalogVersion: '1' }),
  );
  assert.doesNotThrow(() => enrichCoverage(cov, undefined));
  assert.doesNotThrow(() => enrichCoverage(undefined, undefined));
  const bare = enrichCoverage(undefined, undefined);
  assert.deepEqual(bare.summary.statements, { total: 0, accepted: 0, rejected: 0 });
});

// ---------------------------------------------------------------------------
// noFindingsMessage(): the zero-findings wording flip.
// ---------------------------------------------------------------------------

test('noFindingsMessage flips to the supported-subset wording when incomplete', () => {
  const complete = coverageFor(IDENTITY).cov;
  const incomplete = coverageFor(RESOURCE).cov;
  assert.equal(noFindingsMessage(complete), NO_FINDINGS_COMPLETE);
  assert.equal(noFindingsMessage(incomplete), NO_FINDINGS_INCOMPLETE);
  assert.match(NO_FINDINGS_INCOMPLETE, /No findings in the supported subset/);
  assert.match(NO_FINDINGS_INCOMPLETE, /does NOT mean safe/);
  // Tolerates a failed analysis (null coverage) -> the complete message.
  assert.equal(noFindingsMessage(null), NO_FINDINGS_COMPLETE);
});

// ---------------------------------------------------------------------------
// analyze() attaches the enriched summary; exports carry it (JSON + MD).
// ---------------------------------------------------------------------------

test('analyze() attaches the coverage summary on supported and blocked results', () => {
  const ok = analyze(IDENTITY);
  assert.ok(ok.coverage && ok.coverage.summary, 'summary present on supported result');
  assert.equal(ok.coverage.summary.blocked, false);
  assert.equal(ok.coverage.summary.statements.accepted, 1);

  const blocked = analyze(RESOURCE);
  assert.ok(blocked.coverage && blocked.coverage.summary, 'summary present on blocked result');
  assert.equal(blocked.coverage.summary.blocked, true);
  assert.equal(blocked.coverage.summary.incomplete, true);
});

test('JSON export carries the coverage summary with stable machine-readable codes', () => {
  const parsed = JSON.parse(toJSON(analyze(RESOURCE)));
  assert.ok(parsed.coverage && parsed.coverage.summary, 'JSON records the coverage summary');
  const s = parsed.coverage.summary;
  assert.deepEqual(s.statements, { total: 1, accepted: 0, rejected: 1 });
  assert.ok(Array.isArray(s.missingLayers) && s.missingLayers.length > 0);
  assert.equal(s.versions.buildSha, BUILD_SHA);
  assert.ok(s.codes.includes(COVERAGE_CODES.UNSUPPORTED_POLICY_FAMILY), 'stable code in JSON');

  // A clean identity parse still records a summary - a clean parse is NOT proof
  // of complete coverage.
  const okParsed = JSON.parse(toJSON(analyze(IDENTITY)));
  assert.ok(okParsed.coverage.summary, 'supported result still records coverage');
  assert.equal(okParsed.coverage.summary.incomplete, false);
});

test('Markdown export includes the coverage summary fields + unsupported!=safe wording', () => {
  const md = toMarkdown(analyze(RESOURCE));
  assert.match(md, /## Analysis coverage/);
  assert.match(md, /Statements: 0 accepted, 1 rejected \(of 1\)/);
  assert.match(md, /Unrecognized actions: \(none\)/);
  assert.match(md, /Unsupported conditions: \(none\)/);
  assert.match(md, /Evaluation layers NOT covered/);
  assert.match(md, new RegExp(`Build SHA: ${BUILD_SHA}`));
  assert.match(md, /Rule version: 1/);
  // IAM-507: the ACTION-catalog version is now a dated snapshot, distinct from
  // the rule-catalog version (still 1).
  assert.match(md, /Action-catalog version: 2026\.08\.22/);
  assert.match(md, /Unsupported does NOT mean safe/);
  // Blocked shape yields zero findings -> the flipped wording, not "No blast-radius".
  assert.match(md, /No findings in the supported subset/);
});

test('Markdown zero-findings wording: complete for a clean identity policy', () => {
  // A safe identity policy with no findings uses the COMPLETE wording.
  const md = toMarkdown(analyze(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/key' }],
  })));
  assert.match(md, /No blast-radius findings were produced/);
  assert.doesNotMatch(md, /No findings in the supported subset/);
});

test('NotPrincipal markdown names the unsupported element + its path', () => {
  const md = toMarkdown(analyze(NOTPRINCIPAL));
  assert.match(md, /Unsupported elements: NotPrincipal at Statement\[1\]\.NotPrincipal/);
  assert.match(md, /No findings in the supported subset/);
});
