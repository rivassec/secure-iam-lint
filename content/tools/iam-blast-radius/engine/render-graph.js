// IAM Blast Radius - SVG graph renderer behind a rendering interface (IAM-008).
//
// Final stage of the pipeline (docs/architecture.md data-flow): consumes the
// pure graph DATA produced by graph.js (IAM-006) and paints it as an SVG. It is
// the ONLY module that touches SVG/DOM; the data model stays rendering-agnostic
// and replaceable (architecture invariant 7: any graph lib lives behind this
// interface). The findings table remains the authoritative representation - the
// graph is a progressive enhancement and is never the only view.
//
// SECURITY POSTURE (docs/threat-model.md, immutable):
//   T1 DOM XSS: node/edge labels embed HOSTILE policy strings (Sids, ARNs,
//      condition values). They are written ONLY via `textContent` on SVG <text>
//      / HTML text nodes. Geometry attributes are NUMBERS produced by our own
//      deterministic layout, never values from input. No markup is ever built
//      from policy text. `class` attributes come from a FIXED internal
//      vocabulary (the certainty classes below), never from input.
//   T2 Code injection: no eval/Function/inline handlers; events bound via
//      addEventListener only.
//   No network APIs. No storage. Deterministic: same graph -> same SVG geometry
//      and order, every run (no Date.now()/Math.random()).
//
// PUBLIC API:
//   SVG_NS, CERTAINTY_CLASSES, EDGE_STYLE_ORDER   -> frozen vocab
//   computeLayout(graph, opts)                    -> pure geometry (no DOM)
//   createGraphRenderer(doc)                      -> rendering interface:
//        { render(graph, mountEl, opts) -> svg,
//          renderEvidence(edge, panelEl, opts),
//          clear(mountEl, panelEl) }

export const SVG_NS = 'http://www.w3.org/2000/svg';

// Certainty class -> the FIXED css class + human label used on edges and in the
// evidence panel. Distinct visual styles per class (NOT blended into one score),
// per docs/architecture.md "Graph model". These strings are our own constants;
// none of them ever derive from analyzed input.
// IAM-202 certainty vocabulary. `confirmed-by-policy` (was confirmed-by-context)
// and `context-required` (was conditionally-reachable) are renamed for accuracy;
// `policy-supported` is new (the grants are present but the transition needs an
// out-of-scope precondition this policy cannot prove).
export const CERTAINTY_CLASSES = Object.freeze({
  'confirmed-by-policy': Object.freeze({
    cssClass: 'cert-confirmed',
    label: 'Confirmed by this policy text',
  }),
  'policy-supported': Object.freeze({
    cssClass: 'cert-policy-supported',
    label: 'Policy-supported (grants present; the transition needs an out-of-scope precondition)',
  }),
  'context-required': Object.freeze({
    cssClass: 'cert-context-required',
    label: 'Context required (a Condition may gate it)',
  }),
  'potentially-reachable': Object.freeze({
    cssClass: 'cert-potential',
    label: 'Potentially reachable (multiple unknowns)',
  }),
  'blocked-by-deny': Object.freeze({
    cssClass: 'cert-blocked',
    label: 'Blocked by an explicit Deny in this policy',
  }),
  'unknown-incomplete-context': Object.freeze({
    cssClass: 'cert-unknown',
    label: 'Unknown - incomplete context',
  }),
});

// Deterministic legend order (most-decisive first, matching the graph builder's
// intent that a Deny is the single most important fact to surface).
export const EDGE_STYLE_ORDER = Object.freeze([
  'blocked-by-deny',
  'confirmed-by-policy',
  'policy-supported',
  'context-required',
  'potentially-reachable',
  'unknown-incomplete-context',
]);

// Edge-TYPE -> the FIXED css class + human label used to visually separate the
// relationship kinds (IAM-202 introduces `can-decrypt` for kms:Decrypt, distinct
// from a plain `can-read` data read). These strings are our own vocabulary; none
// derive from analyzed input. The certainty class still drives the primary edge
// stroke; the edge-type class rides alongside so decrypt never looks like a read.
export const EDGE_TYPE_CLASSES = Object.freeze({
  'can-read': 'edge-type-can-read',
  'can-decrypt': 'edge-type-can-decrypt',
});

function edgeTypeClass(type) {
  return Object.prototype.hasOwnProperty.call(EDGE_TYPE_CLASSES, type)
    ? EDGE_TYPE_CLASSES[type]
    : null;
}

// Semantic lane vocabulary (IAM-401). The graph model (graph.js) assigns every
// edge a `lane`; the renderer groups edges/nodes into labeled lane sections so
// escalation paths read within their own band and do not visually compete with
// data-access or scope nodes. Labels are our own FIXED display strings (never
// derived from analyzed input) and mirror graph.js LANES; the local copy keeps
// the renderer free of a data-module dependency (same pattern as
// CERTAINTY_CLASSES). LANE_ORDER is the deterministic top-to-bottom draw order;
// empty lanes are omitted (no empty headings).
export const LANE_LABELS = Object.freeze({
  'privilege-escalation': 'PRIVILEGE ESCALATION',
  'identity-expansion': 'IDENTITY EXPANSION',
  'data-access': 'DATA ACCESS',
  scope: 'SCOPE',
  'explicit-deny': 'EXPLICIT DENY',
});

export const LANE_ORDER = Object.freeze([
  'privilege-escalation',
  'identity-expansion',
  'data-access',
  'scope',
  'explicit-deny',
]);

const LANE_INDEX = new Map(LANE_ORDER.map((id, i) => [id, i]));

function laneLabel(id) {
  return Object.prototype.hasOwnProperty.call(LANE_LABELS, id) ? LANE_LABELS[id] : String(id);
}

// Fallback lane for any edge whose lane is missing/unknown, so the layout always
// has a valid band to place it in (mirrors graph.js's SCOPE fallback).
const DEFAULT_LANE = 'scope';

function laneOf(id) {
  return LANE_INDEX.has(id) ? id : DEFAULT_LANE;
}

function certaintyClass(certainty) {
  const entry = CERTAINTY_CLASSES[certainty];
  return entry ? entry.cssClass : 'cert-unknown';
}

function certaintyLabel(certainty) {
  const entry = CERTAINTY_CLASSES[certainty];
  return entry ? entry.label : CERTAINTY_CLASSES['unknown-incomplete-context'].label;
}

// --- Layout constants --------------------------------------------------------
// Small, fixed grid. Real policies yield a handful of nodes; a two-column layered
// layout (principal on the left, target nodes stacked on the right) keeps the
// geometry deterministic and dependency-free.
const LAYOUT = Object.freeze({
  NODE_W: 240,
  NODE_H: 46,
  COL_GAP: 200,
  ROW_GAP: 26,
  PAD: 24,
  PARALLEL_SPREAD: 26, // vertical separation for parallel edges to one target
  // IAM-401 lane bands: vertical space reserved above each lane's nodes for its
  // heading, and the gap between consecutive lane bands.
  LANE_HEADING_H: 30,
  LANE_GAP: 34,
});

const PRINCIPAL_ID = 'principal';

function round(n) {
  // Integer coordinates keep the emitted SVG byte-stable across runs.
  return Math.round(n);
}

/**
 * Compute a deterministic lane-grouped layout for a graph data structure
 * (IAM-401). Pure: no DOM, no measurement, no randomness. Safe on hostile/empty
 * input.
 *
 * The principal sits on the left; the rest of the graph is split into labeled
 * semantic lanes (PRIVILEGE ESCALATION / IDENTITY EXPANSION / DATA ACCESS /
 * SCOPE / EXPLICIT DENY) stacked top-to-bottom. Within a lane, nodes are placed
 * in columns by hop-distance from the principal (so an escalation path reads
 * left-to-right: principal -> passable role -> service), and rows stack parallel
 * nodes. Empty lanes are omitted (no empty band, no heading). The layout stays
 * deterministic: lane order is fixed and nodes keep the graph's own order.
 *
 * @param {{nodes:Array,edges:Array}} graph graph.js output (or export payload)
 * @returns {{width:number,height:number,
 *            nodes:Array<{id,type,label,lane,x,y,w,h,cx,cy}>,
 *            edges:Array<object>,
 *            lanes:Array<{id,label,x,y,width,height,headingX,headingY}>}}
 */
export function computeLayout(graph) {
  const g = graph && typeof graph === 'object' ? graph : {};
  const rawNodes = Array.isArray(g.nodes) ? g.nodes : [];
  const rawEdges = Array.isArray(g.edges) ? g.edges : [];

  const principal = rawNodes.find((n) => n && n.id === PRINCIPAL_ID) || {
    id: PRINCIPAL_ID,
    type: 'Principal',
    label: 'Principal (subject of this policy)',
  };
  const targets = rawNodes.filter((n) => n && n.id !== PRINCIPAL_ID);

  const { NODE_W, NODE_H, COL_GAP, ROW_GAP, PAD, LANE_HEADING_H, LANE_GAP } = LAYOUT;

  const nodeById = new Map();
  for (const n of rawNodes) if (n && typeof n.id === 'string') nodeById.set(n.id, n);

  // --- Layered columns by hop-distance from the principal (IAM-107) ----------
  // Escalation-path transitions chain THROUGH an intermediate node (principal ->
  // passable role -> service), so deeper nodes belong in later columns and the
  // path reads left to right. Depth = shortest hop count from the principal;
  // an unreachable node defaults to column 1. Pure BFS, deterministic.
  const adjacency = new Map();
  for (const e of rawEdges) {
    if (!e || typeof e !== 'object') continue;
    if (!adjacency.has(e.from)) adjacency.set(e.from, []);
    adjacency.get(e.from).push(e.to);
  }
  const depth = new Map([[PRINCIPAL_ID, 0]]);
  const queue = [PRINCIPAL_ID];
  while (queue.length > 0) {
    const cur = queue.shift();
    const d = depth.get(cur);
    for (const next of adjacency.get(cur) || []) {
      if (!nodeById.has(next) && next !== PRINCIPAL_ID) continue; // absent target
      if (!depth.has(next)) {
        depth.set(next, d + 1);
        queue.push(next);
      }
    }
  }
  const depthOf = (id) => (depth.has(id) ? depth.get(id) : 1);

  // --- Assign every non-principal node to a lane (IAM-401) -------------------
  // A node's lane is the lane of the edge(s) touching it (as target, or as the
  // source of a transition hop like the passable-role pivot). The principal is
  // lane-less (a shared root). If a node is touched by edges of several lanes,
  // the earliest lane in LANE_ORDER wins - deterministic, and it keeps the crux
  // of a path (e.g. the passable-role pivot) in the escalation lane.
  const nodeLane = new Map();
  const considerLane = (id, lane) => {
    if (id === PRINCIPAL_ID) return;
    const laneId = laneOf(lane);
    const prev = nodeLane.get(id);
    if (prev === undefined || LANE_INDEX.get(laneId) < LANE_INDEX.get(prev)) {
      nodeLane.set(id, laneId);
    }
  };
  for (const e of rawEdges) {
    if (!e || typeof e !== 'object') continue;
    considerLane(e.to, e.lane);
    considerLane(e.from, e.lane);
  }
  const laneForNode = (id) => nodeLane.get(id) || DEFAULT_LANE;

  const colX = (col) => PAD + col * (NODE_W + COL_GAP);

  // --- Bucket target nodes into lane -> column -> node[] ----------------------
  const laneBuckets = new Map(); // laneId -> Map(col -> node[])
  let maxCol = 1;
  for (const n of targets) {
    const laneId = laneForNode(n.id);
    const col = Math.max(1, depthOf(n.id));
    if (col > maxCol) maxCol = col;
    if (!laneBuckets.has(laneId)) laneBuckets.set(laneId, new Map());
    const cols = laneBuckets.get(laneId);
    if (!cols.has(col)) cols.set(col, []);
    cols.get(col).push(n);
  }

  // Non-empty lanes in the fixed deterministic order.
  const activeLanes = LANE_ORDER.filter((id) => laneBuckets.has(id));

  const positioned = new Map();
  const layoutNodes = [];
  const lanes = [];

  const width = round(colX(maxCol) + NODE_W + PAD);
  const laneContentX = colX(1);
  const laneWidth = round(width - laneContentX - PAD);

  // --- Stack lane bands top-to-bottom ----------------------------------------
  let laneTop = PAD;
  for (const laneId of activeLanes) {
    const cols = laneBuckets.get(laneId);
    let tallest = 1;
    for (const arr of cols.values()) if (arr.length > tallest) tallest = arr.length;
    const contentH = tallest * NODE_H + (tallest - 1) * ROW_GAP;
    const contentTop = laneTop + LANE_HEADING_H;

    for (const [col, arr] of cols) {
      const x = colX(col);
      for (let i = 0; i < arr.length; i++) {
        const n = arr[i];
        const y = round(contentTop + i * (NODE_H + ROW_GAP));
        const node = {
          id: n.id,
          type: n.type || 'Resource',
          label: typeof n.label === 'string' ? n.label : String(n.id),
          lane: laneId,
          // Fixed internal markers (IAM-107) carried through for the renderer to
          // distinguish KNOWN grants from UNKNOWN target-role privileges. Never
          // sourced from analyzed input.
          unknownPrivileges: !!n.unknownPrivileges,
          boundaryCrossing: !!n.boundaryCrossing,
          x,
          y,
          w: NODE_W,
          h: NODE_H,
          cx: round(x + NODE_W / 2),
          cy: round(y + NODE_H / 2),
        };
        positioned.set(n.id, node);
        layoutNodes.push(node);
      }
    }

    const bandH = LANE_HEADING_H + contentH;
    lanes.push({
      id: laneId,
      label: laneLabel(laneId),
      x: laneContentX,
      y: laneTop,
      width: laneWidth,
      height: round(bandH),
      headingX: laneContentX,
      headingY: round(laneTop + LANE_HEADING_H - 12),
    });
    laneTop = round(laneTop + bandH + LANE_GAP);
  }

  // Total height: the stacked lanes, or a single principal row when there are no
  // target nodes.
  const stackBottom = activeLanes.length > 0 ? laneTop - LANE_GAP : PAD + NODE_H;
  const height = round(Math.max(stackBottom + PAD, 2 * PAD + NODE_H));

  // Principal on the left, vertically centered across the whole band stack.
  const principalY = round((height - NODE_H) / 2);
  const principalNode = {
    id: principal.id,
    type: principal.type || 'Principal',
    label: typeof principal.label === 'string' ? principal.label : String(principal.id),
    lane: null,
    x: PAD,
    y: principalY,
    w: NODE_W,
    h: NODE_H,
    cx: round(PAD + NODE_W / 2),
    cy: round(principalY + NODE_H / 2),
  };
  positioned.set(principal.id, principalNode);
  layoutNodes.unshift(principalNode);

  // Group parallel edges (same source/target pair) so they can be fanned apart.
  const groupCount = new Map();
  for (const e of rawEdges) {
    if (!e) continue;
    const key = `${e.from} ${e.to}`;
    groupCount.set(key, (groupCount.get(key) || 0) + 1);
  }
  const groupSeen = new Map();

  const layoutEdges = [];
  for (const e of rawEdges) {
    if (!e || typeof e !== 'object') continue;
    const from = positioned.get(e.from);
    const to = positioned.get(e.to);
    if (!from || !to) continue; // an edge to a capped/absent node is dropped

    const key = `${e.from} ${e.to}`;
    const total = groupCount.get(key) || 1;
    const idx = groupSeen.get(key) || 0;
    groupSeen.set(key, idx + 1);
    // Symmetric fan offset: -k..0..+k across the group.
    const offset = round((idx - (total - 1) / 2) * LAYOUT.PARALLEL_SPREAD);

    // Endpoints leave the source's right edge and arrive at the target's left
    // edge, so layered columns connect left-to-right. A same-column edge (rare)
    // still yields finite geometry.
    const x1 = round(from.x + from.w);
    const y1 = from.cy;
    const x2 = to.x;
    const y2 = to.cy + offset;
    const midX = round((x1 + x2) / 2);
    // Cubic bezier control points bowed toward the fan offset.
    const c1x = midX;
    const c1y = y1;
    const c2x = midX;
    const c2y = y2;
    const path = `M${x1},${y1} C${c1x},${c1y} ${c2x},${c2y} ${x2},${y2}`;

    layoutEdges.push({
      id: e.id,
      type: e.type,
      certainty: e.certainty,
      lane: laneOf(e.lane),
      label: typeof e.label === 'string' ? e.label : String(e.type || 'edge'),
      from: e.from,
      to: e.to,
      x1,
      y1,
      x2,
      y2,
      path,
      labelX: midX,
      labelY: round((y1 + y2) / 2) - 4,
      edge: e, // carry the original edge (with evidence) for the inspect panel
    });
  }

  return { width, height, nodes: layoutNodes, edges: layoutEdges, lanes };
}

// --- Rendering interface -----------------------------------------------------
// createGraphRenderer(doc) returns the interface app.js drives. `doc` is any
// Document-like object exposing createElementNS/createElement; injecting it keeps
// the renderer unit-testable under `node --test` with a minimal DOM stub and
// makes the whole SVG backend swappable (architecture invariant 7).

function shorten(text, max) {
  const s = String(text == null ? '' : text);
  if (s.length <= max) return s;
  // Ellipsis is a fixed ASCII literal, not from input; truncation keeps labels legible.
  return s.slice(0, max - 3) + '...';
}

/**
 * @param {Document} doc a Document-like object (createElementNS/createElement)
 */
export function createGraphRenderer(doc) {
  if (!doc || typeof doc.createElementNS !== 'function') {
    throw new Error('createGraphRenderer requires a document with createElementNS');
  }

  function svgEl(tag, attrs) {
    const el = doc.createElementNS(SVG_NS, tag);
    if (attrs) {
      for (const k of Object.keys(attrs)) {
        // Values are our own numbers / fixed class strings, never input markup.
        el.setAttribute(k, String(attrs[k]));
      }
    }
    return el;
  }

  function htmlEl(tag, text, className) {
    const el = doc.createElement(tag);
    if (className) el.setAttribute('class', className);
    if (text !== undefined && text !== null) el.textContent = String(text);
    return el;
  }

  function buildDefs() {
    const defs = svgEl('defs');
    // A single neutral arrowhead marker; its geometry is fixed, not from input.
    const marker = svgEl('marker', {
      id: 'iam-arrow',
      viewBox: '0 0 10 10',
      refX: 9,
      refY: 5,
      markerWidth: 7,
      markerHeight: 7,
      orient: 'auto-start-reverse',
      markerUnits: 'userSpaceOnUse',
    });
    const arrowPath = svgEl('path', { d: 'M0,0 L10,5 L0,10 z', class: 'iam-arrowhead' });
    marker.appendChild(arrowPath);
    defs.appendChild(marker);
    return defs;
  }

  function buildNode(node) {
    // Fixed marker classes (IAM-107) let styles.css visually separate what the
    // analysis KNOWS from what it does NOT: the passable-role pivot
    // (`node-unknown-priv`) whose real privileges are unknown, and the
    // service-execution node (`node-boundary`) that is the potential
    // privilege-boundary crossing. Class strings are our own vocabulary, never
    // derived from analyzed input.
    let cls = 'graph-node';
    if (node.unknownPrivileges) cls += ' node-unknown-priv';
    if (node.boundaryCrossing) cls += ' node-boundary';
    const g = svgEl('g', { class: cls });
    const rect = svgEl('rect', {
      x: node.x,
      y: node.y,
      width: node.w,
      height: node.h,
      rx: 6,
      ry: 6,
      class: 'node-box',
    });
    g.appendChild(rect);

    const typeText = svgEl('text', {
      x: node.x + 10,
      y: node.y + 18,
      class: 'node-type',
    });
    // Node type is our vocabulary; annotate the unknown-privileges pivot so the
    // KNOWN/UNKNOWN split is legible in text (not only by color/border).
    typeText.textContent = node.unknownPrivileges
      ? `${String(node.type)} - privileges unknown`
      : String(node.type);
    g.appendChild(typeText);

    const labelText = svgEl('text', {
      x: node.x + 10,
      y: node.y + 36,
      class: 'node-label',
    });
    // HOSTILE policy string (ARN/Sid) -> textContent only. Inert.
    labelText.textContent = shorten(node.label, 40);
    g.appendChild(labelText);

    // Full label available to assistive tech / tooltip without markup.
    const title = svgEl('title');
    title.textContent = String(node.label);
    g.appendChild(title);
    return g;
  }

  function buildEdge(le, onSelect) {
    const cls = certaintyClass(le.certainty);
    // Edge-type class (IAM-202) is appended when the type has a distinct visual
    // treatment (e.g. can-decrypt vs can-read); it comes from our fixed
    // vocabulary, never from analyzed input.
    const typeCls = edgeTypeClass(le.type);
    const g = svgEl('g', {
      class: typeCls ? `graph-edge ${cls} ${typeCls}` : `graph-edge ${cls}`,
      tabindex: 0,
      role: 'button',
    });
    // Accessible name names the lane, the relationship, and the certainty, as
    // inert text (IAM-401: the lane grouping is exposed to assistive tech, not
    // only visually). The lane label is our own fixed vocabulary.
    g.setAttribute(
      'aria-label',
      `${laneLabel(laneOf(le.lane))}. ${le.label}. ${certaintyLabel(le.certainty)}. ` +
        'Activate to inspect evidence.',
    );

    // Wide transparent hit path for easy click/focus targeting.
    const hit = svgEl('path', { d: le.path, class: 'edge-hit' });
    g.appendChild(hit);

    // Visible styled path; the certainty class drives dash/color in CSS.
    const path = svgEl('path', {
      d: le.path,
      class: 'edge-path',
      'marker-end': 'url(#iam-arrow)',
    });
    g.appendChild(path);

    const label = svgEl('text', {
      x: le.labelX,
      y: le.labelY,
      class: 'edge-label',
      'text-anchor': 'middle',
    });
    label.textContent = shorten(le.label, 42); // edge label may embed policy text
    g.appendChild(label);

    const title = svgEl('title');
    title.textContent = `${le.label} - ${certaintyLabel(le.certainty)}`;
    g.appendChild(title);

    if (typeof onSelect === 'function' && typeof g.addEventListener === 'function') {
      g.addEventListener('click', () => onSelect(le.edge, le));
      g.addEventListener('keydown', (ev) => {
        const key = ev && ev.key;
        if (key === 'Enter' || key === ' ' || key === 'Spacebar') {
          if (typeof ev.preventDefault === 'function') ev.preventDefault();
          onSelect(le.edge, le);
        }
      });
    }
    return g;
  }

  // Build one lane section: a labeled band grouping the paths inside it
  // (IAM-401). The heading text and aria-label are our own FIXED lane
  // vocabulary, never derived from analyzed input. `role="group"` + aria-label
  // expose the lane grouping to assistive tech; the authoritative equivalent
  // stays the findings table.
  function buildLane(lane) {
    const g = svgEl('g', {
      class: `graph-lane lane-${lane.id}`,
      role: 'group',
      'aria-label': `${lane.label} lane`,
    });
    // A subtle band rect behind the lane's nodes (geometry is our own numbers).
    const band = svgEl('rect', {
      x: lane.x - 12,
      y: lane.y,
      width: lane.width + 24,
      height: lane.height,
      rx: 6,
      ry: 6,
      class: 'lane-band',
    });
    g.appendChild(band);
    const heading = svgEl('text', {
      x: lane.headingX,
      y: lane.headingY,
      class: 'lane-heading',
    });
    heading.textContent = lane.label; // fixed vocabulary, inert
    g.appendChild(heading);
    return g;
  }

  /**
   * Render the graph as an SVG into mountEl.
   *
   * @param {object} graph graph.js data ({nodes, edges, truncated})
   * @param {Element} mountEl container to render into (replaced)
   * @param {{onEdgeSelect?:Function, reducedMotion?:boolean}} [opts]
   * @returns {Element} the created <svg>
   */
  function render(graph, mountEl, opts) {
    const options = opts || {};
    const layout = computeLayout(graph);

    if (mountEl && typeof mountEl.replaceChildren === 'function') {
      mountEl.replaceChildren();
    }

    const cls = options.reducedMotion ? 'iam-graph' : 'iam-graph iam-graph-animate';
    const svg = svgEl('svg', {
      class: cls,
      viewBox: `0 0 ${layout.width} ${layout.height}`,
      width: layout.width,
      height: layout.height,
      role: 'group',
      'aria-label': 'Attack-path graph. The same edges appear in the findings table.',
    });

    svg.appendChild(buildDefs());

    // Lane bands + headings first, behind everything (IAM-401): the semantic
    // sections a viewer reads before the paths inside them. Omitted entirely
    // when there are no lanes (empty graph), so no empty heading is drawn.
    const laneList = Array.isArray(layout.lanes) ? layout.lanes : [];
    if (laneList.length > 0) {
      const laneLayer = svgEl('g', { class: 'lane-layer' });
      for (const lane of laneList) laneLayer.appendChild(buildLane(lane));
      svg.appendChild(laneLayer);
    }

    // Edges next so nodes paint on top of the lines.
    const edgeLayer = svgEl('g', { class: 'edge-layer' });
    for (const le of layout.edges) edgeLayer.appendChild(buildEdge(le, options.onEdgeSelect));
    svg.appendChild(edgeLayer);

    const nodeLayer = svgEl('g', { class: 'node-layer' });
    for (const n of layout.nodes) nodeLayer.appendChild(buildNode(n));
    svg.appendChild(nodeLayer);

    if (layout.edges.length === 0) {
      const note = svgEl('text', {
        x: round(layout.width / 2),
        y: round(layout.height / 2),
        class: 'edge-empty-note',
        'text-anchor': 'middle',
      });
      note.textContent = 'No attack-path edges were derived from this policy.';
      svg.appendChild(note);
    }

    if (graph && graph.truncated) {
      const warn = svgEl('text', {
        x: LAYOUT.PAD,
        y: round(layout.height - 6),
        class: 'graph-truncated',
      });
      warn.textContent = 'Graph truncated: size cap reached (see findings table for all findings).';
      svg.appendChild(warn);
    }

    if (mountEl && typeof mountEl.appendChild === 'function') mountEl.appendChild(svg);
    return svg;
  }

  // --- Evidence panel --------------------------------------------------------
  // Built entirely with createElement + textContent. Every value (Sid, ARN,
  // action, condition JSON) is inert text. HTML export is NOT produced here.

  function appendField(dl, term, value) {
    const dt = htmlEl('dt', term);
    const dd = htmlEl('dd', value);
    dl.appendChild(dt);
    dl.appendChild(dd);
  }

  function conditionText(condition) {
    if (condition === null || condition === undefined) return '(none)';
    if (typeof condition === 'string') return condition;
    try {
      // JSON.stringify cannot emit executable markup; the result is inert text
      // placed via textContent only (never an HTML-assigning sink).
      return JSON.stringify(condition);
    } catch (e) {
      return '(unserializable condition)';
    }
  }

  function listText(values) {
    if (!Array.isArray(values) || values.length === 0) return '(none)';
    return values.map((v) => String(v)).join(', ');
  }

  /**
   * Render the click/inspect evidence panel for one edge.
   *
   * @param {object} edge original graph edge (with evidence[])
   * @param {Element} panelEl container to render into (replaced)
   * @param {{findings?:Array<object>}} [opts] findings, to enrich each evidence
   *        row with its policyEvidence + pathExploitability + limit by matching
   *        findingId
   */
  function renderEvidence(edge, panelEl, opts) {
    if (!panelEl) return;
    if (typeof panelEl.replaceChildren === 'function') panelEl.replaceChildren();

    const options = opts || {};
    const findingsById = new Map();
    if (Array.isArray(options.findings)) {
      for (const f of options.findings) {
        if (f && typeof f.id === 'string') findingsById.set(f.id, f);
      }
    }

    if (!edge || typeof edge !== 'object') {
      panelEl.appendChild(htmlEl('p', 'Select an edge to inspect its evidence.', 'evidence-empty'));
      return;
    }

    const heading = htmlEl('h3', String(edge.label || edge.type || 'Edge'), 'evidence-title');
    panelEl.appendChild(heading);

    const summary = htmlEl('dl', undefined, 'evidence-summary');
    appendField(summary, 'Relationship', `${edge.from} -> ${edge.to}`);
    appendField(summary, 'Edge type', String(edge.type || ''));
    appendField(summary, 'Certainty', certaintyLabel(edge.certainty));
    panelEl.appendChild(summary);

    const evidence = Array.isArray(edge.evidence) ? edge.evidence : [];
    if (evidence.length === 0) {
      panelEl.appendChild(htmlEl('p', 'This edge carries no per-statement evidence.', 'evidence-empty'));
      return;
    }

    const list = htmlEl('ol', undefined, 'evidence-list');
    for (const ev of evidence) {
      const li = doc.createElement('li');
      const dl = htmlEl('dl', undefined, 'evidence-item');
      appendField(dl, 'Statement', String(ev.statementSid != null ? ev.statementSid : `(index ${ev.statementIndex})`));
      appendField(dl, 'Actions', listText(ev.actions));
      appendField(dl, 'Resources', listText(ev.resources));
      appendField(dl, 'Condition', conditionText(ev.condition));
      const finding = ev.findingId ? findingsById.get(ev.findingId) : null;
      if (finding) {
        // IAM-104: split certainty - render both signals, never a single blended
        // "confidence". Policy evidence = how strongly this policy text shows the
        // grant; path exploitability = how likely it actually elevates given
        // unknowns (target-role permissions, other controls).
        if (finding.policyEvidence) {
          appendField(dl, 'Policy evidence', String(finding.policyEvidence));
        }
        if (finding.pathExploitability) {
          appendField(dl, 'Path exploitability', String(finding.pathExploitability));
        }
        if (finding.limit) appendField(dl, 'What this does NOT prove', String(finding.limit));
      }
      li.appendChild(dl);
      list.appendChild(li);
    }
    panelEl.appendChild(list);

    // Truthfulness caveat (threat-model T8): the panel never implies effective
    // permissions.
    panelEl.appendChild(
      htmlEl(
        'p',
        'Potential blast radius within this policy context - not effective permissions.',
        'evidence-caveat',
      ),
    );
  }

  function clear(mountEl, panelEl) {
    if (mountEl && typeof mountEl.replaceChildren === 'function') mountEl.replaceChildren();
    if (panelEl && typeof panelEl.replaceChildren === 'function') panelEl.replaceChildren();
  }

  return { render, renderEvidence, clear };
}

export default createGraphRenderer;
