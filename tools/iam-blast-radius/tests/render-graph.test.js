// Unit tests for IAM-008 SVG graph renderer (engine/render-graph.js).
// Runs on node's built-in runner: `node --test`.
//
// The renderer is the only module that touches SVG/DOM, so it is exercised here
// against a MINIMAL Document stub (the rendering interface is injected). That
// keeps the whole SVG backend testable without a browser and asserts the
// security-critical invariants directly:
//   - hostile policy strings (SVG/HTML/JS payloads) are placed via textContent
//     only; NO element is ever created from input markup (threat-model T1)
//   - geometry attributes are finite numbers from our deterministic layout
//   - distinct css class PER certainty class (never blended)
//   - reduced-motion honored (no entrance-animation class when requested)
//   - click AND keyboard activation open the evidence panel
//   - the layout is deterministic (same graph -> identical geometry)
//
// Browser-level acceptance (real SVG paint, real events, zero egress) lives in
// tests/e2e/graph.spec.js and is CI's job.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import {
  computeLayout,
  createGraphRenderer,
  CERTAINTY_CLASSES,
  EDGE_STYLE_ORDER,
  SVG_NS,
} from '../../../content/tools/iam-blast-radius/engine/render-graph.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

function analyzeFixture(rel) {
  const fx = JSON.parse(readFileSync(join(fixturesDir, rel), 'utf8'));
  const text = typeof fx.policyRaw === 'string' ? fx.policyRaw : JSON.stringify(fx.policy);
  return analyze(text);
}

// --- Minimal Document / Element stub ----------------------------------------
// Records tag + namespace + attributes + children + textContent + listeners so
// tests can inspect exactly what the renderer built and dispatch events.

class FakeElement {
  constructor(tag, ns) {
    this.tag = String(tag);
    this.ns = ns || null;
    this.attributes = Object.create(null);
    this.children = [];
    this._text = '';
    this.listeners = Object.create(null);
  }

  setAttribute(name, value) {
    this.attributes[name] = String(value);
  }

  getAttribute(name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  replaceChildren() {
    this.children = [];
    this._text = '';
  }

  set textContent(value) {
    this._text = String(value);
    this.children = [];
  }

  get textContent() {
    if (this.children.length === 0) return this._text;
    return this._text + this.children.map((c) => c.textContent).join('');
  }

  addEventListener(type, fn) {
    (this.listeners[type] = this.listeners[type] || []).push(fn);
  }

  dispatch(type, event) {
    for (const fn of this.listeners[type] || []) fn(event || {});
  }

  // Depth-first walk over this subtree (inclusive).
  *walk() {
    yield this;
    for (const c of this.children) yield* c.walk();
  }

  find(pred) {
    for (const el of this.walk()) if (pred(el)) return el;
    return null;
  }

  findAll(pred) {
    const out = [];
    for (const el of this.walk()) if (pred(el)) out.push(el);
    return out;
  }
}

function fakeDocument() {
  return {
    created: [],
    createElementNS(ns, tag) {
      const el = new FakeElement(tag, ns);
      this.created.push(el);
      return el;
    },
    createElement(tag) {
      const el = new FakeElement(tag, null);
      this.created.push(el);
      return el;
    },
  };
}

function mount(doc) {
  const el = new FakeElement('div', null);
  return el;
}

// Every element tag the renderer is allowed to create. If input markup ever
// leaked into a createElement(NS) call, an unexpected tag (script/img/svg-in-svg)
// would appear here and fail the inertness assertion.
const ALLOWED_TAGS = new Set([
  // SVG vocabulary
  'svg', 'defs', 'marker', 'path', 'g', 'rect', 'text', 'title',
  // HTML evidence panel
  'p', 'h3', 'dl', 'dt', 'dd', 'ol', 'li',
]);

// --- computeLayout (pure) ----------------------------------------------------

test('computeLayout is deterministic and produces finite integer geometry', () => {
  const result = analyzeFixture('pass-role/passrole-lambda-positive.json');
  const a = computeLayout(result.graph);
  const b = computeLayout(result.graph);
  assert.equal(JSON.stringify(a), JSON.stringify(b), 'same graph -> identical layout');

  assert.ok(Number.isInteger(a.width) && a.width > 0);
  assert.ok(Number.isInteger(a.height) && a.height > 0);
  for (const n of a.nodes) {
    for (const k of ['x', 'y', 'w', 'h', 'cx', 'cy']) {
      assert.ok(Number.isFinite(n[k]), `node ${n.id}.${k} finite`);
    }
  }
  for (const e of a.edges) {
    for (const k of ['x1', 'y1', 'x2', 'y2', 'labelX', 'labelY']) {
      assert.ok(Number.isFinite(e[k]), `edge ${e.id}.${k} finite`);
    }
    assert.match(e.path, /^M[-\d., C]+$/, 'path is a numeric SVG path');
  }
});

test('computeLayout tolerates empty / malformed graph input without throwing', () => {
  assert.doesNotThrow(() => computeLayout(undefined));
  assert.doesNotThrow(() => computeLayout({}));
  assert.doesNotThrow(() => computeLayout({ nodes: null, edges: 'nope' }));
  const empty = computeLayout({ nodes: [], edges: [] });
  assert.equal(empty.edges.length, 0);
  // The synthetic principal is always laid out even with no target nodes.
  assert.ok(empty.nodes.length >= 1);
});

test('an edge to an absent node is dropped from the layout', () => {
  const graph = {
    nodes: [{ id: 'principal', type: 'Principal', label: 'P' }],
    edges: [{ id: 'e1', from: 'principal', to: 'ghost', type: 'allows', certainty: 'confirmed-by-context', label: 'x', evidence: [] }],
  };
  const layout = computeLayout(graph);
  assert.equal(layout.edges.length, 0, 'edge to missing target is not laid out');
});

// --- createGraphRenderer contract -------------------------------------------

test('createGraphRenderer requires a document with createElementNS', () => {
  assert.throws(() => createGraphRenderer(null));
  assert.throws(() => createGraphRenderer({}));
});

test('render builds an <svg> with only whitelisted element tags', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  const el = mount(doc);
  const result = analyzeFixture('wildcard/admin-star.json');
  const svg = r.render(result.graph, el, { reducedMotion: true });

  assert.equal(svg.tag, 'svg');
  assert.equal(svg.ns, SVG_NS);
  assert.equal(el.children.length, 1, 'svg mounted');

  for (const created of doc.created) {
    assert.ok(ALLOWED_TAGS.has(created.tag), `unexpected element tag created: ${created.tag}`);
  }
  // Geometry attributes on the svg are numeric.
  assert.match(svg.getAttribute('viewBox'), /^0 0 \d+ \d+$/);
});

test('each edge group carries the distinct css class for its certainty', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  const el = mount(doc);
  const result = analyzeFixture('pass-role/passrole-lambda-positive.json');
  const svg = r.render(result.graph, el, { reducedMotion: true });

  const edgeGroups = svg.findAll(
    (n) => n.tag === 'g' && (n.getAttribute('class') || '').includes('graph-edge'),
  );
  assert.ok(edgeGroups.length >= 1, 'at least one edge rendered');
  for (const g of edgeGroups) {
    const cls = g.getAttribute('class');
    const hasCert = Object.values(CERTAINTY_CLASSES).some((c) => cls.includes(c.cssClass));
    assert.ok(hasCert, `edge group missing a certainty class: ${cls}`);
    // Focusable + activatable.
    assert.equal(g.getAttribute('tabindex'), '0');
    assert.equal(g.getAttribute('role'), 'button');
  }
});

test('IAM-107: the passable-role pivot renders as a distinguished unknown-privileges node', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  const el = mount(doc);
  const result = analyzeFixture('pass-role/passrole-lambda-positive.json');
  const svg = r.render(result.graph, el, { reducedMotion: true });

  // The pivot node group carries the fixed unknown-privileges marker class so
  // the renderer visually separates KNOWN grants from the UNKNOWN target-role
  // privileges (IAM-107 req 2). Its text spells the distinction out too, so the
  // signal is not color-only (a11y).
  const pivot = svg.find(
    (n) => n.tag === 'g' && (n.getAttribute('class') || '').includes('node-unknown-priv'),
  );
  assert.ok(pivot, 'expected a node group flagged node-unknown-priv');
  assert.match(pivot.textContent, /unknown/i, 'pivot node text names the unknown privileges');

  // The service-execution node is flagged as the potential privilege-boundary
  // crossing.
  const boundary = svg.find(
    (n) => n.tag === 'g' && (n.getAttribute('class') || '').includes('node-boundary'),
  );
  assert.ok(boundary, 'expected a node group flagged node-boundary (service execution)');

  // Still no non-whitelisted tags were synthesized building these nodes.
  for (const created of doc.created) {
    assert.ok(ALLOWED_TAGS.has(created.tag), `unexpected element tag created: ${created.tag}`);
  }
});

test('IAM-107: the transition lays out left-to-right across columns (pivot between principal and service)', () => {
  const result = analyzeFixture('pass-role/passrole-lambda-positive.json');
  const layout = computeLayout(result.graph);
  const principal = layout.nodes.find((n) => n.id === 'principal');
  const pivot = layout.nodes.find((n) => n.id === 'role:passable:lambda');
  const service = layout.nodes.find((n) => n.id === 'service:lambda');
  assert.ok(principal && pivot && service, 'principal, pivot, and service all laid out');
  // The pivot sits in a column strictly between the principal and the service,
  // so the privilege transition reads as a path rather than parallel spokes.
  assert.ok(principal.x < pivot.x, 'pivot is right of the principal');
  assert.ok(pivot.x < service.x, 'service is right of the pivot');
});

test('EDGE_STYLE_ORDER lists every certainty class exactly once', () => {
  const keys = Object.keys(CERTAINTY_CLASSES).sort();
  assert.deepEqual([...EDGE_STYLE_ORDER].sort(), keys);
});

test('reduced-motion is honored: entrance-animation class is omitted', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  const result = analyzeFixture('wildcard/admin-star.json');

  const reduced = r.render(result.graph, mount(doc), { reducedMotion: true });
  assert.ok(!reduced.getAttribute('class').includes('iam-graph-animate'), 'no animation class when reduced');

  const motion = r.render(result.graph, mount(doc), { reducedMotion: false });
  assert.ok(motion.getAttribute('class').includes('iam-graph-animate'), 'animation class when motion allowed');
});

test('an empty graph renders an explanatory note instead of a dead box', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  const result = analyzeFixture('safe/read-only-scoped.json');
  assert.equal(result.graph.edges.length, 0, 'safe fixture has no edges');
  const svg = r.render(result.graph, mount(doc), { reducedMotion: true });
  const note = svg.find((n) => n.tag === 'text' && (n.getAttribute('class') || '') === 'edge-empty-note');
  assert.ok(note, 'empty-note present');
  assert.match(note.textContent, /No attack-path edges/);
});

// --- Interaction: click + keyboard open the evidence panel ------------------

test('clicking an edge invokes onEdgeSelect with the original edge', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  const result = analyzeFixture('pass-role/passrole-lambda-positive.json');
  let selected = null;
  const svg = r.render(result.graph, mount(doc), {
    reducedMotion: true,
    onEdgeSelect: (edge) => { selected = edge; },
  });
  const edgeGroup = svg.find(
    (n) => n.tag === 'g' && (n.getAttribute('class') || '').includes('graph-edge'),
  );
  edgeGroup.dispatch('click');
  assert.ok(selected && Array.isArray(selected.evidence), 'onEdgeSelect got the edge with evidence');
});

test('Enter and Space activate an edge from the keyboard', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  const result = analyzeFixture('pass-role/passrole-lambda-positive.json');
  let count = 0;
  let prevented = 0;
  const svg = r.render(result.graph, mount(doc), {
    reducedMotion: true,
    onEdgeSelect: () => { count += 1; },
  });
  const edgeGroup = svg.find(
    (n) => n.tag === 'g' && (n.getAttribute('class') || '').includes('graph-edge'),
  );
  edgeGroup.dispatch('keydown', { key: 'Enter', preventDefault() { prevented += 1; } });
  edgeGroup.dispatch('keydown', { key: ' ', preventDefault() { prevented += 1; } });
  edgeGroup.dispatch('keydown', { key: 'Tab', preventDefault() { prevented += 1; } });
  assert.equal(count, 2, 'Enter + Space activate; Tab does not');
  assert.equal(prevented, 2, 'default scrolling/submit prevented only on activation keys');
});

// --- Evidence panel ----------------------------------------------------------

test('renderEvidence shows statement/actions/resources/condition + evidence/exploitability/limit', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  const result = analyzeFixture('pass-role/passrole-lambda-positive.json');
  const layout = computeLayout(result.graph);
  const edge = layout.edges[0].edge;
  const panel = mount(doc);
  r.renderEvidence(edge, panel, { findings: result.findings });

  const text = panel.textContent;
  assert.match(text, /Statement/);
  assert.match(text, /Actions/);
  assert.match(text, /Resources/);
  assert.match(text, /Condition/);
  assert.match(text, /Certainty/);
  // IAM-104: both split certainty signals + limit are enriched from the finding.
  assert.match(text, /Policy evidence/);
  assert.match(text, /Path exploitability/);
  assert.match(text, /NOT prove/);
  // Truthfulness caveat present (threat-model T8).
  assert.match(text, /not effective permissions/);
});

test('renderEvidence handles a null/edge with no evidence without throwing', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  assert.doesNotThrow(() => r.renderEvidence(null, mount(doc), {}));
  assert.doesNotThrow(() => r.renderEvidence({ label: 'x', type: 'allows', certainty: 'unknown-incomplete-context', evidence: [] }, mount(doc), {}));
});

// --- Security: hostile SVG/HTML injection renders inert (threat-model T1) ----

test('SVG/HTML/JS payloads in policy fields render as inert text, never as markup', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  const result = analyzeFixture('graph/svg-injection-inert.json');
  assert.ok(result.ok, 'fixture analyzes');
  assert.ok(result.graph.edges.length >= 1, 'destructive edge present');

  const el = mount(doc);
  const svg = r.render(result.graph, el, { reducedMotion: true });

  // 1. No element was EVER created from the payload markup: the only tags in the
  //    whole document are our fixed vocabulary. In particular, zero script/img
  //    and no nested <svg> beyond the single root.
  for (const created of doc.created) {
    assert.ok(ALLOWED_TAGS.has(created.tag), `unexpected element created from input: ${created.tag}`);
  }
  assert.equal(doc.created.filter((n) => n.tag === 'script').length, 0);
  assert.equal(doc.created.filter((n) => n.tag === 'img').length, 0);
  assert.equal(doc.created.filter((n) => n.tag === 'svg').length, 1, 'only the root svg');

  // 2. The hostile ARN payload IS present, but only as inert text content.
  const payload = 'script>alert(document.domain)';
  assert.ok(svg.textContent.includes(payload), 'payload carried as text somewhere in the SVG');

  // 3. No attribute anywhere carries an on* event handler or a javascript: url
  //    derived from input.
  for (const created of doc.created) {
    for (const name of Object.keys(created.attributes)) {
      assert.ok(!/^on/i.test(name), `event-handler attribute set: ${name}`);
      assert.ok(!/^\s*javascript:/i.test(created.attributes[name]), 'no javascript: url');
    }
  }

  // 4. Evidence panel for the same edge is equally inert.
  const edge = computeLayout(result.graph).edges[0].edge;
  const panel = mount(doc);
  r.renderEvidence(edge, panel, { findings: result.findings });
  assert.ok(panel.textContent.includes('script>alert') || panel.textContent.includes('onerror'),
    'panel carries payload as text');
  for (const created of doc.created) {
    assert.ok(ALLOWED_TAGS.has(created.tag), `evidence created unexpected tag: ${created.tag}`);
  }
});

test('renderEvidence serializes a hostile condition object as inert JSON text', () => {
  const doc = fakeDocument();
  const r = createGraphRenderer(doc);
  const edge = {
    label: 'x',
    type: 'allows',
    certainty: 'conditionally-reachable',
    from: 'principal',
    to: 'resource:x',
    evidence: [{
      statementSid: '<img src=x onerror=alert(1)>',
      statementIndex: 0,
      actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::b/*'],
      condition: { StringEquals: { 'aws:username': '<script>alert(1)</script>' } },
      findingId: 'X',
    }],
  };
  const panel = mount(doc);
  r.renderEvidence(edge, panel, {});
  const text = panel.textContent;
  assert.match(text, /StringEquals/, 'condition serialized as text');
  assert.ok(text.includes('<script>alert(1)</script>'), 'hostile condition value present as text');
  for (const created of doc.created) {
    assert.ok(ALLOWED_TAGS.has(created.tag), `unexpected tag: ${created.tag}`);
  }
});
