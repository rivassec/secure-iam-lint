// S4-unicode-spoof regression suite (threat-model T1/T6/T8).
//
// Closes the Unicode bidi / zero-width visual-spoofing CLASS. A policy-derived
// value (Sid, ARN, action, Condition key/value, Principal) is HOSTILE input and
// can carry INVISIBLE / REORDERING format-control code points. Wherever such a
// value reaches a HUMAN-FACING TRUST SURFACE - the rendered findings table + SVG
// graph (the reviewer's PR-approval trust signal on fork-PR content), or a
// downloaded .md/.json/SARIF report - it could display a benign-looking grant
// that differs from the real policy (Trojan-Source). textContent gives NO bidi
// protection.
//
// The fix neutralizes the format-control class at the policy-string NORMALIZATION
// boundary (engine/model.js) AND at each sink (report.js Markdown/JSON, cli/sarif,
// app.js DOM, engine/render-graph.js SVG) - defense in depth, defined in
// engine/format-control.js as TWO classes: the DISPLAY class (INVISIBLE_SPOOF, broad:
// \p{Cc}+\p{Cf}+default-ignorable+U+2028/U+2029+Braille) applied at every human-facing
// sink, and the narrower MODEL_NORMALIZE_SPOOF applied at the model boundary, which
// PRESERVES \p{Cc}/U+2028/U+2029 so a malformed ARN stays non-canonical and viability
// fails CLOSED (see the passrole-noncanonical-arn-spelling regression) instead of being
// silently canonicalized. Section 5 pins that boundary from both sides.
//
// These tests assert EXACT codepoint removal (not merely visual output), and the
// DOM/SVG half exercises ACTUAL rendered nodes (the graph renderer's text nodes +
// evidence panel), not just strings.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  INVISIBLE_SPOOF,
  NON_ASCII_SPOOF,
  REPLACEMENT,
  stripFormatControls,
  neutralizeForDisplay,
  sanitizeTree,
} from '../../../content/tools/iam-blast-radius/engine/format-control.js';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';
import { createGraphRenderer } from '../../../content/tools/iam-blast-radius/engine/render-graph.js';
import { formatSarif, CONTROL_AND_FORMAT, inertLeaf } from '../../../cli/sarif.mjs';

// --- format-control code points under test -----------------------------------
// A representative from every enumerated range in the story, PLUS a default-
// ignorable (variation selector) and the Braille blank (category So).
const CP = {
  ALM: '؜', // Arabic letter mark
  ZWSP: '​', // zero-width space
  ZWNJ: '‌', // zero-width non-joiner
  ZWJ: '‍', // zero-width joiner
  LRM: '‎', // left-to-right mark
  RLM: '‏', // right-to-left mark
  LRE: '‪', // left-to-right embedding
  RLE: '‫', // right-to-left embedding
  PDF: '‬', // pop directional formatting
  LRO: '‭', // left-to-right override
  RLO: '‮', // right-to-left override
  WJ: '⁠', // word joiner
  LRI: '⁦', // left-to-right isolate
  RLI: '⁧', // right-to-left isolate
  FSI: '⁨', // first strong isolate
  PDI: '⁩', // pop directional isolate
  BOM: '﻿', // byte-order mark / ZW no-break space
  SHY: '­', // soft hyphen (\p{Cf})
  VS1: '︀', // variation selector (default-ignorable)
  BRAILLE: '⠀', // braille pattern blank (category So)
};
const ALL_SPOOF = Object.values(CP).join('');

// Fresh non-global detector so lastIndex state never leaks between .test() calls.
function hasFormatControl(s) {
  return /[\p{Cf}\p{Default_Ignorable_Code_Point}⠀]/u.test(String(s));
}

// Recursively assert no string anywhere in a value carries a format-control cp.
function assertTreeClean(value, where) {
  if (typeof value === 'string') {
    assert.ok(!hasFormatControl(value), `${where}: format control survived in ${JSON.stringify(value)}`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertTreeClean(v, `${where}[${i}]`));
    return;
  }
  if (value && typeof value === 'object') {
    for (const k of Object.keys(value)) {
      assert.ok(!hasFormatControl(k), `${where}: format control survived in KEY ${JSON.stringify(k)}`);
      assertTreeClean(value[k], `${where}.${k}`);
    }
  }
}

// --- Minimal Document / Element stub (mirrors render-graph.test.js) ----------
// Records tag + textContent + children so a test can inspect the ACTUAL rendered
// text nodes the renderer built.
class FakeElement {
  constructor(tag, ns) {
    this.tag = String(tag);
    this.ns = ns || null;
    this.attributes = Object.create(null);
    this.children = [];
    this._text = '';
    this.listeners = Object.create(null);
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren() { this.children = []; this._text = ''; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() {
    if (this.children.length === 0) return this._text;
    return this._text + this.children.map((c) => c.textContent).join('');
  }
  addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
  *walk() { yield this; for (const c of this.children) yield* c.walk(); }
  // Own textContent only (not descendants) - so a per-node assertion is exact.
  ownText() { return this._text; }
}
function fakeDocument() {
  return {
    created: [],
    createElementNS(ns, tag) { const el = new FakeElement(tag, ns); this.created.push(el); return el; },
    createElement(tag) { const el = new FakeElement(tag, null); this.created.push(el); return el; },
  };
}

// =============================================================================
// 1. Shared class definition (engine/format-control.js)
// =============================================================================

test('S4: stripFormatControls removes EXACTLY the invisible/reordering class, nothing legible', () => {
  // Every enumerated code point is removed - assert the whole payload collapses.
  assert.equal(stripFormatControls(ALL_SPOOF), '', 'all format controls removed');
  for (const [name, cp] of Object.entries(CP)) {
    assert.equal(stripFormatControls(`a${cp}b`), 'ab', `${name} (U+${cp.codePointAt(0).toString(16)}) stripped`);
  }
});

test('S4: stripFormatControls PRESERVES legitimate content (RTL letters, alnum, punctuation)', () => {
  // Real bidi TEXT renders correctly without explicit override controls, so the
  // letters themselves must be preserved - only the controls go.
  const hebrew = 'שלום'; // shalom
  const arabic = 'مرحبا'; // marhaba
  for (const s of [hebrew, arabic, 'iam:PassRole', 'arn:aws:s3:::my-bucket/*', 'Sid_123', 'a-b.c+d']) {
    assert.equal(stripFormatControls(s), s, `legitimate content preserved: ${s}`);
    assert.ok(!hasFormatControl(s), 'sanity: sample carries no format control');
  }
  // A control BETWEEN two RTL letters is removed but both letters stay.
  assert.equal(stripFormatControls(`${hebrew[0]}${CP.RLO}${hebrew[1]}`), `${hebrew[0]}${hebrew[1]}`);
});

test('S4: the shared regex has the u flag and is global (safe reuse across replace calls)', () => {
  assert.ok(INVISIBLE_SPOOF.flags.includes('u'), 'u flag required for \\p{...}');
  assert.ok(INVISIBLE_SPOOF.global, 'global so replace() removes every occurrence');
});

test('S4: sanitizeTree strips KEYS and VALUES deeply, preserves structure + non-strings', () => {
  const input = {
    [`k${CP.ZWSP}ey`]: `v${CP.RLO}al`,
    nested: { [`op${CP.BOM}`]: [`x${CP.ZWJ}`, 2, true, null] },
    num: 5,
    bool: false,
  };
  const out = sanitizeTree(input);
  assertTreeClean(out, 'sanitizeTree');
  assert.deepEqual(out, { key: 'val', nested: { op: ['x', 2, true, null] }, num: 5, bool: false });
  assert.equal(sanitizeTree(null), null);
  assert.equal(sanitizeTree(undefined), undefined);
});

// =============================================================================
// 2. Normalization boundary (engine/model.js)
// =============================================================================

test('S4: the model de-spoofs Sid / Action / Resource at the normalization boundary (exact cp removal)', () => {
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: `Grant${CP.RLO}Admin${CP.ZWSP}`,
      Effect: 'Allow',
      Action: [`iam:${CP.ZWNJ}PassRole`, `s3:Get${CP.BOM}Object`],
      Resource: `arn:aws:s3:::${CP.LRO}reports/*`,
    }],
  });
  const m = modelFromText(policy);
  assert.equal(m.ok, true, 'analysis still succeeds on hostile unicode input');
  const st = m.model.statements[0];
  assert.equal(st.sid, 'GrantAdmin');
  assert.deepEqual(st.actions, ['iam:PassRole', 's3:GetObject']);
  assert.deepEqual(st.resources, ['arn:aws:s3:::reports/*']);
  assertTreeClean(m.model, 'model');
});

test('S4: the model de-spoofs Condition keys AND values', () => {
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'S',
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: '*',
      Condition: { [`String${CP.ZWSP}Equals`]: { [`aws:${CP.BOM}username`]: `al${CP.RLO}ice` } },
    }],
  });
  const m = modelFromText(policy);
  assert.equal(m.ok, true);
  const cond = m.model.statements[0].condition;
  assert.deepEqual(Object.keys(cond), ['StringEquals']);
  assert.deepEqual(Object.keys(cond.StringEquals), ['aws:username']);
  assert.equal(cond.StringEquals['aws:username'], 'alice');
  assertTreeClean(m.model, 'model');
});

test('S4: the model de-spoofs Principal type keys and values', () => {
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'Trust',
      Effect: 'Allow',
      Principal: { [`AW${CP.ZWSP}S`]: `arn:aws:iam::${CP.RLO}123456789012:root` },
      Action: 'sts:AssumeRole',
    }],
  });
  const m = modelFromText(policy);
  assert.equal(m.ok, true);
  const p = m.model.statements[0].principal;
  assert.deepEqual(Object.keys(p.byType), ['AWS']);
  assert.deepEqual(p.byType.AWS, ['arn:aws:iam::123456789012:root']);
  assertTreeClean(m.model, 'model');
});

test('S4 (bonus fail-closed): an OBFUSCATED dangerous key is de-spoofed then REJECTED', () => {
  // "__pro<ZWSP>to__" is not literally "__proto__", so it slips validate()'s
  // dangerous-key check; the model strips the ZWSP FIRST, then the guard fires.
  // Stripping before the check is what closes this prototype-pollution fail-open.
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'S',
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: '*',
      Condition: { StringEquals: { [`__pro${CP.ZWSP}to__`]: 'x' } },
    }],
  });
  const m = modelFromText(policy);
  assert.equal(m.ok, false, 'the de-spoofed __proto__ key must be rejected, not silently kept');
  assert.ok(m.errors.some((e) => e.code === 'DANGEROUS_KEY'), 'DANGEROUS_KEY error raised');
});

test('S4: analyze() output (findings + graph) is fully de-spoofed for BOTH surfaces (parity)', () => {
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: `Pass${CP.RLO}All${CP.ZWSP}`,
      Effect: 'Allow',
      Action: ['iam:PassRole', 'lambda:CreateFunction'],
      Resource: `arn:aws:iam::111122223333:role/${CP.BOM}app-role`,
    }],
  });
  const r = analyze(policy, { family: 'identity' });
  assert.equal(r.ok, true);
  assertTreeClean(r.findings, 'findings');
  assertTreeClean(r.graph, 'graph');
  assertTreeClean(r.model, 'model');
  assertTreeClean(r.coverage, 'coverage');
});

// =============================================================================
// 3. Report sinks (Markdown / JSON / SARIF)
// =============================================================================

function spoofedAnalysis() {
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: `benign${CP.RLO}${CP.ZWSP}Admin`,
      Effect: 'Allow',
      Action: ['iam:*', `s3:${CP.BOM}DeleteBucket`],
      Resource: `arn:aws:s3:::${CP.LRO}prod-data/*`,
      Condition: { [`String${CP.ZWNJ}Equals`]: { 'aws:username': `ro${CP.RLM}ot` } },
    }],
  });
  return analyze(policy, { family: 'identity' });
}

test('S4: the Markdown export carries NO format-control code point (exact removal)', () => {
  const md = toMarkdown(spoofedAnalysis());
  assert.ok(!hasFormatControl(md), 'no invisible/reordering control survives in the .md');
  assert.match(md, /benignAdmin/, 'legible Sid text is preserved');
});

test('S4: the JSON export carries NO format-control code point anywhere (keys + values)', () => {
  const json = toJSON(spoofedAnalysis());
  assert.ok(!hasFormatControl(json), 'no control survives in the raw .json text');
  assertTreeClean(JSON.parse(json), 'json');
});

test('S4: the SARIF export carries NO format-control code point anywhere', () => {
  const sarif = formatSarif(spoofedAnalysis(), { toolVersion: '1.0.0' });
  assert.ok(!hasFormatControl(sarif), 'no control survives in the SARIF text');
  assertTreeClean(JSON.parse(sarif), 'sarif');
});

// =============================================================================
// 4. DOM / SVG sinks - ACTUAL rendered nodes (engine/render-graph.js)
// =============================================================================

test('S4 (rendered SVG): a spoofed policy renders with NO format control in any text node', () => {
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: `Pass${CP.RLO}${CP.ZWSP}`,
      Effect: 'Allow',
      Action: ['iam:PassRole', 'lambda:CreateFunction'],
      Resource: `arn:aws:iam::111122223333:role/${CP.BOM}app-role`,
    }],
  });
  const r = analyze(policy, { family: 'identity' });
  const doc = fakeDocument();
  const svg = createGraphRenderer(doc).render(r.graph, new FakeElement('div'), { reducedMotion: true });
  // Walk every ACTUAL rendered node and assert its own text is clean.
  for (const el of svg.walk()) {
    assert.ok(!hasFormatControl(el.ownText()), `rendered <${el.tag}> text carried a format control: ${JSON.stringify(el.ownText())}`);
  }
});

test('S4 (rendered SVG - SINK ISOLATION): render-graph strips even when fed un-normalized labels', () => {
  // Bypass the model boundary entirely: hand the renderer a graph whose labels
  // carry format controls directly. This proves render-graph's OWN sink strip
  // (setSvgText) closes the class, so a future path that skips normalization is
  // still safe (defense in depth; sink-only enumeration is what we refuse to trust).
  const base = analyze(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'S', Effect: 'Allow', Action: ['iam:PassRole', 'lambda:CreateFunction'], Resource: 'arn:aws:iam::111122223333:role/app-role' }],
  }), { family: 'identity' });
  const graph = JSON.parse(JSON.stringify(base.graph)); // deep, unfrozen clone
  for (const n of graph.nodes) n.label = `${n.label}${CP.RLO}${CP.ZWSP}${CP.BOM}`;
  for (const e of graph.edges || []) e.label = `${e.label}${CP.LRO}${CP.ZWNJ}`;
  const doc = fakeDocument();
  const svg = createGraphRenderer(doc).render(graph, new FakeElement('div'), { reducedMotion: true });
  let sawText = false;
  for (const el of svg.walk()) {
    if (el.tag === 'text' || el.tag === 'title') sawText = true;
    assert.ok(!hasFormatControl(el.ownText()), `rendered <${el.tag}> text carried a format control (sink strip failed)`);
  }
  assert.ok(sawText, 'sanity: the render produced <text>/<title> label nodes');
});

test('S4 (rendered DOM - evidence panel): renderEvidence strips hostile evidence values', () => {
  // The evidence panel is the click-through trust surface: it must not carry a
  // bidi/zero-width spoof from a hostile Sid / ARN / condition. Feed un-normalized
  // evidence directly (sink isolation) and inspect the ACTUAL rendered nodes.
  const doc = fakeDocument();
  const renderer = createGraphRenderer(doc);
  const panel = new FakeElement('div');
  const edge = {
    label: `can pass${CP.RLO}`,
    type: 'can-pass',
    from: 'principal',
    to: `role:${CP.ZWSP}x`,
    certainty: 'policy-supported',
    evidence: [{
      statementSid: `Pass${CP.BOM}Role`,
      statementIndex: 0,
      actions: [`iam:${CP.ZWNJ}PassRole`],
      resources: [`arn:aws:iam::111122223333:role/${CP.LRO}app-role`],
      condition: { [`String${CP.ZWSP}Equals`]: { 'aws:username': `ro${CP.RLM}ot` } },
      findingId: 'PASSROLE-LAMBDA',
    }],
  };
  const finding = {
    id: 'PASSROLE-LAMBDA',
    policyEvidence: `direct${CP.RLO} grant`,
    pathExploitability: `needs${CP.ZWSP} target perms`,
    limit: `not${CP.BOM} effective permissions`,
  };
  renderer.renderEvidence(edge, panel, { findings: [finding] });
  let sawDd = false;
  for (const el of panel.walk()) {
    if (el.tag === 'dd') sawDd = true;
    assert.ok(!hasFormatControl(el.ownText()), `rendered <${el.tag}> evidence text carried a format control: ${JSON.stringify(el.ownText())}`);
  }
  assert.ok(sawDd, 'sanity: the evidence panel rendered field values');
  // Legible text still present somewhere in the panel.
  assert.match(panel.textContent, /PassRole/);
});

// =============================================================================
// 5. CLASS-COMPLETENESS BOUNDARY - the invisible/reordering code points that a
//    \p{Cf}-only class left open (S4 residual). The story defines the class as
//    "no visible width OR reorder text", so line/paragraph separators (Zl/Zp)
//    and the \p{Cc} control block are IN-CLASS. Enumerating \p{Cf}/DI instances
//    (section 1) never probes this boundary, so it is asserted explicitly here.
// =============================================================================

// The residual code points, by category (none is \p{Cf} nor default-ignorable):
//   U+2028 Zl / U+2029 Zp  - invisible, force a line-break text REORDER
//   U+000B VT / U+000C FF / U+001B ESC - \p{Cc} controls (line break / ANSI /
//                                        raw bytes in a downloaded .json)
const RESIDUAL = {
  LS: '\u2028', // line separator (Zl)
  PS: '\u2029', // paragraph separator (Zp)
  VT: '\u000b', // vertical tab (Cc)
  FF: '\u000c', // form feed (Cc)
  ESC: '\u001b', // escape (Cc)
};

// A detector for JUST the residual class, so a whole-document scan does not trip
// on the STRUCTURAL newlines/tabs that legitimately format JSON/Markdown output
// (those are \p{Cc} too, but they are report scaffolding, not policy-derived).
function hasResidual(s) {
  return /[\u2028\u2029]/u.test(String(s));
}

test('S4 (class boundary): stripFormatControls removes Zl/Zp separators and Cc controls', () => {
  for (const [name, cp] of Object.entries(RESIDUAL)) {
    assert.equal(
      stripFormatControls(`a${cp}b`),
      'ab',
      `${name} (U+${cp.codePointAt(0).toString(16).padStart(4, '0')}) stripped by the shared class`,
    );
  }
  // The exact Trojan-Source payload from the finding: a forced line break splitting
  // a benign-looking grant from a dangerous one must collapse to a single token.
  assert.equal(
    stripFormatControls(`ReadOnlyAudit${RESIDUAL.LS}${RESIDUAL.PS}iamFullAdmin`),
    'ReadOnlyAuditiamFullAdmin',
  );
});

test('S4 (class boundary): PRESERVES legitimate structural whitespace inside a value', () => {
  // Space and ordinary intra-token characters are NOT in the class; only the
  // invisible/reordering set is removed. (IAM values are alphanumeric, but this
  // pins that the class is not over-broad against printable text.)
  assert.equal(stripFormatControls('Read Only Audit'), 'Read Only Audit');
});

test('S4 (class boundary): DISPLAY sinks (JSON export + DOM sanitizeTree) carry NO Zl/Zp/Cc residual', () => {
  // The finding's end-to-end vector: a Sid whose forced line break splits the
  // visible grant. The residual lives in the Sid (a display LABEL) so a real finding
  // still fires; actions/resources are clean so detection is unaffected. Before the
  // fix, the separators appeared literally in toJSON() bytes (JSON.stringify does not
  // escape U+2028/29) and survived the app.js sanitizeTree chokepoint into every
  // findings-cell. The DISPLAY class (broad) now neutralizes them at both sinks.
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: `ReadOnlyAudit${RESIDUAL.LS}${RESIDUAL.PS}iam${RESIDUAL.VT}Full${RESIDUAL.FF}Admin${RESIDUAL.ESC}`,
      Effect: 'Allow',
      Action: ['iam:PassRole', 'lambda:CreateFunction'],
      Resource: 'arn:aws:iam::111122223333:role/app-role',
    }],
  });
  const r = analyze(policy, { family: 'identity' });
  assert.equal(r.ok, true, 'analysis still succeeds on the residual payload');
  assert.ok((r.findings || []).length > 0, 'a real finding still fires (clean actions/resources)');

  // The model deliberately PRESERVES Zl/Zp/Cc (narrow normalization class) so a
  // malformed value stays non-canonical for the analysis (fail-closed) - assert that
  // is exactly what happens, so a future edit that silently widens the MODEL class
  // (re-introducing the passrole fail-open) is caught here too.
  assert.ok(hasResidual(r.model.statements[0].sid), 'model retains the separators (narrow normalization, fail-closed)');

  // DISPLAY sink 1 - JSON export bytes: no residual anywhere (keys or values).
  const json = toJSON(r);
  assert.ok(!hasResidual(json), 'no Zl/Zp/Cc residual survives in the .json bytes');
  assert.ok(!/[\u000b\u000c\u001b]/u.test(json), 'no VT/FF/ESC control survives in the .json bytes');

  // DISPLAY sink 2 - app.js:847 DOM chokepoint: sanitizeTree feeds every findings-cell.
  const displayed = sanitizeTree(r);
  const flat = JSON.stringify(displayed);
  assert.ok(!hasResidual(flat), 'no Zl/Zp/Cc residual survives the sanitizeTree DOM chokepoint');
  assert.ok(!/[\u000b\u000c\u001b]/u.test(flat), 'no VT/FF/ESC control survives the sanitizeTree DOM chokepoint');

  // Legible grant text is intact (the halves joined, not split across a line).
  assert.match(json, /ReadOnlyAuditiamFullAdmin/);
});

test('S4 (superset invariant): engine INVISIBLE_SPOOF is a superset of the CLI SARIF class', () => {
  // A future edit that narrows the engine class below the SARIF sink's class would
  // make the browser JSON/DOM surface MORE permissive than the CLI SARIF surface
  // (display-parity regression). Assert the containment directly against the REAL
  // SARIF source regex. Fresh non-global copies so .test() lastIndex never leaks.
  const engine = new RegExp(INVISIBLE_SPOOF.source, 'u');
  const sarif = new RegExp(CONTROL_AND_FORMAT.source, 'u');
  // Sweep the BMP plus targeted astral samples (variation-selector supplement, the
  // reserved tag-block base and end) - every code point the SARIF class strips must
  // also be stripped by the engine class.
  const astral = [0xE0000, 0xE0001, 0xE0020, 0xE007F, 0xE0100, 0xE01EF];
  const points = [];
  for (let cp = 0; cp <= 0xFFFF; cp++) points.push(cp);
  for (const cp of astral) points.push(cp);
  for (const cp of points) {
    const ch = String.fromCodePoint(cp);
    if (sarif.test(ch)) {
      assert.ok(
        engine.test(ch),
        `SARIF strips U+${cp.toString(16).toUpperCase().padStart(4, '0')} but the engine class does not - superset broken`,
      );
    }
  }
});


// =============================================================================
// 6. S4-unicode-spoof ITERATION 3 - the CODE-POINT-FREE bidi mechanism + the Zs
//    homograph-space class. INVISIBLE_SPOOF (sections 1-5) closes the FORMAT-
//    CONTROL mechanism of the spoof. These tests close the SECOND Trojan-Source
//    mechanism: a STRONG-RTL letter reorders its neutral/numeric neighbours in the
//    DISPLAY with NO format-control code point at all (CVE-2021-42574), plus the
//    \p{Zs} homograph-space class (which the CLI collapsed via \s+ but the browser
//    left verbatim - a browser-more-permissive-than-CLI parity break) and homograph
//    LETTERS. IAM tokens are ASCII per the AWS grammar, so every display/export sink
//    clamps non-ASCII to U+FFFD - an ALLOWLIST that cannot fail open on the next
//    un-enumerated RTL script / Zs space, unlike a blocklist.
// =============================================================================

const RTL = {
  HEB: 'א',       // HEBREW LETTER ALEF (Bidi_Class R)
  ARAB: 'ب',      // ARABIC LETTER BEH (Bidi_Class AL)
  NKO: '߁',       // NKO DIGIT ONE (RTL script)
  THAANA: 'ހ',    // THAANA LETTER HAA (RTL script)
  ADLAM: '\u{1E900}',  // ADLAM CAPITAL LETTER ALIF (astral RTL script)
};
const ZS = {
  NBSP: ' ', ENQUAD: ' ', NNBSP: ' ',
  MMSP: ' ', IDEOSPACE: '　', OGHAM: ' ',
};
const HOMOGLYPH = { CYR_A: 'а' }; // CYRILLIC SMALL LETTER A (looks like Latin 'a')
const SPOOF_NON_ASCII = [
  ...Object.values(RTL), ...Object.values(ZS), ...Object.values(HOMOGLYPH),
];

// CLASS-level assertion: after the display/export charset clamp, the ONLY non-ASCII code
// point that may survive on a policy-derived surface is U+FFFD (the neutralization marker).
// This catches ANY non-ASCII - including an un-enumerated RTL script or Zs space a blocklist
// would miss - not merely the specific payload chars, which is the point of the allowlist.
function assertOnlyAsciiOrReplacement(text, where) {
  const bad = [];
  for (const ch of String(text)) {
    const cp = ch.codePointAt(0);
    if (cp >= 0x80 && ch !== REPLACEMENT) bad.push(`U+${cp.toString(16).toUpperCase()}`);
  }
  assert.deepEqual(bad, [], `${where}: only ASCII (+ U+FFFD) may survive; leaked: ${bad.join(' ')}`);
}
function assertNoSpoofChars(text, where) {
  for (const ch of SPOOF_NON_ASCII) {
    assert.ok(!String(text).includes(ch),
      `${where}: spoof char U+${ch.codePointAt(0).toString(16).toUpperCase()} survived verbatim`);
  }
}

function rtlZsSpoofAnalysis() {
  // Action carries iam:* so a REAL finding fires and the hostile values ride the finding +
  // graph + evidence paths (not only the coverage path).
  const policy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: `Read${RTL.HEB}${ZS.NBSP}Only`,
      Effect: 'Allow',
      Action: ['iam:*', `s3:${HOMOGLYPH.CYR_A}DeleteBucket`],
      Resource: `arn:aws:s3:::${RTL.ARAB}prod${ZS.IDEOSPACE}data/*`,
      Condition: { [`String${ZS.NNBSP}Equals`]: { 'aws:username': `ro${RTL.NKO}ot${RTL.ADLAM}` } },
    }],
  });
  return analyze(policy, { family: 'identity' });
}

test('S4 iter-3 (Markdown): strong-RTL + Zs + homograph are charset-clamped (class-level)', () => {
  const r = rtlZsSpoofAnalysis();
  assert.equal(r.ok, true);
  assert.ok((r.findings || []).length > 0, 'a real finding fired so the values ride the finding path');
  const md = toMarkdown(r);
  assertNoSpoofChars(md, 'markdown');
  assertOnlyAsciiOrReplacement(md, 'markdown');
  assert.match(md, /Read/, 'legible ASCII survives as inert text');
});

test('S4 iter-3 (JSON): strong-RTL + Zs + homograph are charset-clamped (keys + values)', () => {
  const json = toJSON(rtlZsSpoofAnalysis());
  assertNoSpoofChars(json, 'json');
  assertOnlyAsciiOrReplacement(json, 'json');
  const parsed = JSON.parse(json);
  assert.ok(parsed && typeof parsed === 'object', 'valid JSON after the clamp');
});

test('S4 iter-3 (SARIF): strong-RTL + Zs + homograph are charset-clamped (CLI parity)', () => {
  const sarif = formatSarif(rtlZsSpoofAnalysis(), { toolVersion: '1.0.0' });
  assertNoSpoofChars(sarif, 'sarif');
  assertOnlyAsciiOrReplacement(sarif, 'sarif');
});

test('S4 iter-3 (rendered SVG - SINK ISOLATION): render-graph clamps strong-RTL/Zs on un-normalized labels', () => {
  const base = analyze(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Sid: 'S', Effect: 'Allow', Action: ['iam:PassRole', 'lambda:CreateFunction'], Resource: 'arn:aws:iam::111122223333:role/app-role' }],
  }), { family: 'identity' });
  const graph = JSON.parse(JSON.stringify(base.graph));
  for (const n of graph.nodes) n.label = `${n.label}${RTL.HEB}${ZS.IDEOSPACE}${HOMOGLYPH.CYR_A}`;
  for (const e of graph.edges || []) e.label = `${e.label}${RTL.ARAB}${ZS.NBSP}`;
  const doc = fakeDocument();
  const svg = createGraphRenderer(doc).render(graph, new FakeElement('div'), { reducedMotion: true });
  let sawText = false;
  for (const el of svg.walk()) {
    if (el.tag === 'text' || el.tag === 'title') sawText = true;
    assertNoSpoofChars(el.ownText(), `rendered <${el.tag}>`);
    assertOnlyAsciiOrReplacement(el.ownText(), `rendered <${el.tag}>`);
  }
  assert.ok(sawText, 'sanity: render produced <text>/<title> nodes');
});

test('S4 iter-3 (rendered DOM - evidence panel): renderEvidence clamps strong-RTL/Zs values', () => {
  const doc = fakeDocument();
  const renderer = createGraphRenderer(doc);
  const panel = new FakeElement('div');
  const edge = {
    label: `can pass${RTL.HEB}`,
    type: 'can-pass', from: 'principal', to: `role:${ZS.NBSP}x`,
    certainty: 'policy-supported',
    evidence: [{
      statementSid: `Pass${RTL.ARAB}Role`,
      statementIndex: 0,
      actions: [`iam:${HOMOGLYPH.CYR_A}PassRole`],
      resources: [`arn:aws:iam::111122223333:role/${ZS.IDEOSPACE}app-role`],
      condition: { [`String${ZS.NNBSP}Equals`]: { 'aws:username': `ro${RTL.NKO}ot` } },
      findingId: 'PASSROLE-LAMBDA',
    }],
  };
  const finding = { id: 'PASSROLE-LAMBDA', policyEvidence: `direct${RTL.HEB} grant`, limit: `not${ZS.NBSP} effective` };
  renderer.renderEvidence(edge, panel, { findings: [finding] });
  let sawDd = false;
  for (const el of panel.walk()) {
    if (el.tag === 'dd') sawDd = true;
    assertNoSpoofChars(el.ownText(), `rendered <${el.tag}>`);
    assertOnlyAsciiOrReplacement(el.ownText(), `rendered <${el.tag}>`);
  }
  assert.ok(sawDd, 'sanity: the evidence panel rendered field values');
  assert.match(panel.textContent, /PassRole/);
});

test('S4 iter-3 (BLOCKER 2 parity): the Zs homograph-space class is neutralized on BOTH surfaces', () => {
  // The residual: the CLI leaf sanitizer collapsed the Zs run via \s+ while the browser
  // display strip left it verbatim, so the browser JSON was MORE permissive than CLI SARIF.
  // Now BOTH clamp non-ASCII (incl. the whole \p{Zs} class) to U+FFFD. Assert neither the
  // browser DISPLAY neutralizer nor the CLI leaf sanitizer leaves any Zs char verbatim.
  for (const ch of Object.values(ZS)) {
    const probe = `a${ch}b`;
    const hex = ch.codePointAt(0).toString(16).toUpperCase();
    assert.ok(!neutralizeForDisplay(probe).includes(ch), `browser display leaves Zs U+${hex} verbatim`);
    assert.ok(!inertLeaf(probe, 128).includes(ch), `CLI leaf leaves Zs U+${hex} verbatim`);
  }
});

test('S4 iter-3 (superset invariant, EFFECTIVE): browser display is >= as strict as the CLI leaf sanitizer', () => {
  // Compare EFFECTIVE per-sink OUTPUT, not just the regexes (which miss the CLI whitespace
  // collapse of the Zs class and the shared non-ASCII clamp). For every codepoint: if the
  // CLI leaf sanitizer NEUTRALIZES it (absent from the CLI output of a benign probe), the
  // browser display neutralizer MUST also neutralize it - else the browser JSON/DOM surface
  // is MORE permissive than CLI SARIF (the documented parity regression).
  const astral = [0xE0000, 0xE0001, 0xE0020, 0xE007F, 0xE0100, 0xE01EF, 0x1E900, 0x1D400];
  const points = [];
  for (let cp = 0; cp <= 0xFFFF; cp++) {
    if (cp >= 0xD800 && cp <= 0xDFFF) continue; // skip lone surrogates
    points.push(cp);
  }
  for (const cp of astral) points.push(cp);
  for (const cp of points) {
    const ch = String.fromCodePoint(cp);
    const probe = `a${ch}b`;
    const cli = inertLeaf(probe, 128);
    if (!cli.includes(ch)) {
      const browser = neutralizeForDisplay(probe);
      assert.ok(!browser.includes(ch),
        `CLI neutralizes U+${cp.toString(16).toUpperCase().padStart(4, '0')} but browser display leaves it verbatim - superset broken`);
    }
  }
});
