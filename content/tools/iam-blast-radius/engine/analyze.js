// Analysis orchestration for the UI shell (IAM-007).
//
// Pure, deterministic, and dependency-free: runs the full engine pipeline
// text -> validate -> model -> (rules + escalations) -> graph and returns a
// single frozen result object. Both worker.js (Web Worker path) and app.js
// (synchronous no-Worker fallback) call analyze(); keeping the orchestration
// here guarantees the two paths produce byte-identical output and lets the
// pipeline be unit-tested under `node --test` with no DOM/Worker present.
//
// Determinism (architecture invariant 8): no Date.now()/Math.random() anywhere.
// Never throws: every failure mode from the underlying engine is surfaced as a
// structured { ok:false, errors[] } result.

import { modelFromText } from './model.js';
import {
  emptyGraph, fail, blockedResult, abortedResult, trustResult, envelopeResult, scpResult, rcpResult, resourceResult,
} from './analyze-results.js';
export * from './analyze-results.js';
import {
  SEVERITY_ORDER, severityRank, sortFindings, FINDING_COLUMNS, FINDING_DETAIL_FIELDS, textList, findingToRow, SUMMARY_CATEGORIES, SUMMARY_CATEGORY_BY_ID, SERVICE_LABELS, serviceLabel, pathLineFor, summarize, stampFamily,
  CATALOG_VERSION,
} from './analyze-format.js';
export * from './analyze-format.js';
import { analyzeRules, ruleFindingDenySuppressed, actionResourceTypeMismatches, survivingBroadReadActions, survivingSparedContainerReads } from './rules.js';
import { analyzeEscalations } from './escalation.js';
import { analyzeTrust, trustFindingDenyState, summarizeTrustDeny } from './trust.js';
import { analyzeEnvelope } from './envelope.js';
import { analyzeScp } from './scp.js';
import { analyzeRcp } from './rcp.js';
import { analyzeResource } from './resource.js';
import { correlateFindings } from './correlate.js';
import { buildGraph, buildTrustGraph, buildResourceGraph, GRAPH_LIMITS } from './graph.js';
import { detectFamily, FAMILIES, isRcpShape } from './family.js';
import { enrichCoverage, duplicateSids } from './coverage.js';
import { classifyConditions, unsupportedConditionKeys } from './conditions.js';
// S1-breadth-classify: the shared Resource-ARN classifier. Used here (post-rules) to
// close the last breadth fail-open the rule engine cannot: ANY value classifyResource()
// reports BROAD - a non-ARN glob ("?*", "*/*") OR a broad WELL-FORMED ARN
// ("arn:aws:dynamodb::*:table/foo", wildcard ACCOUNT) - riding on an Allow statement the
// rule engine covered with NO finding (a non-exfil read like dynamodb:GetItem, which
// fires neither DATA-EXFIL nor WILDCARD-RESOURCE). "broad implies a rule fired" is
// exactly the assumption that fails open (and it fails open identically for a glob and a
// well-formed ARN); this checks the fired findings instead, symmetric across spellings.
import { classifyResource, RESOURCE_CLASS } from './resource-arn.js';
import { defaultCatalog, unrecognizedActions, ACCESS_LEVELS } from './catalog.js';
// Cooperative resource budgets (S3-dos-budget). analyze() arms a DETERMINISTIC
// WORK budget (an op-count ceiling, not a clock - so architecture invariant 8 holds)
// on EVERY run, including the browser/worker path, so a pathological within-caps
// policy whose CPU cost explodes can never return a COMPLETE verdict: it fails CLOSED
// to a graceful in-band "analysis aborted (resource budget)" incomplete result. The
// separate WALL-CLOCK sentinel (armed only by the Node adapter, cli/scan.mjs) is
// RE-THROWN so scan() maps it to its timing-dependent RESOURCE_BUDGET_EXCEEDED verdict.
import { isGlobBudgetError, setWorkLimit, getWorkLimit } from './glob.js';

// Default deterministic WORK ceiling for one analyze() run. Units are ~char-compares
// / automaton word-steps charged inside the shared matcher. Sized FAR above any
// legitimate policy (a within-all-caps policy analyzes in a few million work units)
// yet far below an unbounded runaway, so it never trips a real analysis but bounds a
// pathological one (whose cost comes from the deny-coverage nested loops calling the
// matcher an enormous number of times, not from any single quadratic call). It is an
// op count, not milliseconds, so the trip point is DETERMINISTIC across machines;
// with the now-linear matcher this budget is a backstop, not the primary control.
// Callers may override via options.workLimit (a finite number; <=0 forces an
// immediate abort for tests; Infinity disables it).
export const DEFAULT_WORK_LIMIT = 60000000;

// The RULE/finding catalog version reported at the top level of the result (UI
// footer + export "Rule catalog version"). Rule + escalation findings all carry
// ruleVersion '1' in this phase. This is DISTINCT from the ACTION-catalog version
// (catalog.js ACTION_CATALOG_VERSION), a dated snapshot surfaced separately in the
// coverage summary (versions.catalogVersion) - the two version on their own cadence.

// Severity display order (highest blast radius first). Used to sort the
// findings table deterministically and by the Markdown/JSON export.
function statementScopableReadActions(stmt) {
  if (!stmt || !Array.isArray(stmt.actions)) return [];
  return stmt.actions.filter((a) => {
    const res = defaultCatalog.lookup(a);
    return res.known
      && res.accessLevel === ACCESS_LEVELS.READ
      && !res.requiresWildcardResource;
  });
}

// S3-SWEEP-01 (class-sweep sibling of cli/sarif.mjs S1-NEW02): the INJECTIVE suppression
// identity for a surviving-spared derived finding. The dedup that drops an already-reported
// derived read (the survivingSparedContainerReads post-pass) keys on (id, statementIndex,
// sorted actions, sorted resources). actions + resources are ATTACKER-CONTROLLED policy text
// with no charset restriction, so a plain `.join(',')`/`.join('|')` was NON-injective: a
// single token literally containing the inner ',' (or the outer '|', or a newline) forged the
// sorted-join of a DISTINCT multi-element list, so a semantically different SURVIVING cross-
// account / whole-container read collided with an existing key and was silently dropped from
// the authoritative table - a live exfil primitive reading CLEAN (threat-model R1 / T8).
//
// JSON.stringify of the [id, statementIndex, sortedActions, sortedResources] tuple is
// INJECTIVE: JSON string quoting/escaping makes every ',' / '|' / newline inside a token
// INERT (it can never span an element or a field boundary), so two distinct lists always
// map to distinct keys. It is also DETERMINISTIC (array order is fixed; elements are a
// string, a number-or-null, and two arrays of strings) and pure - no delimiter can be forged.
// Benign findings (real ARNs / action names carry no delimiter) keep their exact pre-fix
// equivalence classes, so the dedup behavior is unchanged (no over-suppression, no churn):
// the fix only SEPARATES the delimiter-forged collisions the plain join used to conflate.
// id is a fixed rule enum and statementIndex a structural number (neither attacker-forgeable),
// but they ride the same injective encoding so the whole key is closed as a class.
export function findingIdentityKey(f) {
  const id = f && f.id != null ? String(f.id) : '';
  const statementIndex = f && typeof f.statementIndex === 'number' ? f.statementIndex : null;
  const actions = (Array.isArray(f && f.actions) ? f.actions : [])
    .map((a) => String(a).toLowerCase()).slice().sort();
  const resources = (Array.isArray(f && f.resources) ? f.resources : [])
    .map(String).slice().sort();
  return JSON.stringify([id, statementIndex, actions, resources]);
}

/**
 * Run the full analysis pipeline on raw policy text.
 *
 * Never throws. On any validation/model failure returns { ok:false, errors[] }
 * with empty findings/graph. On success returns findings sorted for display,
 * the normalized model, and the graph data structure.
 *
 * @param {string} text raw pasted/imported policy text
 * @returns {{ok:boolean, errors:Array, findings:Array<object>, model:(object|null),
 *            graph:object, catalogVersion:string, counts:object}}
 */
export function analyze(text, options) {
  const opts = options || {};
  // S3-dos-budget: arm the DETERMINISTIC work budget for this run (browser + Node).
  // A finite options.workLimit overrides the default (<=0 forces an immediate abort
  // for tests); options.workLimit === Infinity disables it. Save/restore the prior
  // limit so a caller that already armed one (or a wall-clock deadline set by scan())
  // is left exactly as it was. The wall-clock deadline is independent and untouched.
  const prevWorkLimit = getWorkLimit();
  let workLimit = DEFAULT_WORK_LIMIT;
  if (opts.workLimit === Infinity) workLimit = Infinity;
  else if (Number.isFinite(opts.workLimit)) workLimit = opts.workLimit;
  setWorkLimit(workLimit);
  // Refs hoisted so the budget-abort catch can build a coverage-bearing fail-closed
  // result from whatever context the pipeline reached before the trip.
  let model = null;
  let coverageRef = null;
  try {
    const m = modelFromText(text);
    if (!m.ok) return fail(m.errors);
    model = m.model;

    // IAM-501: classify the policy family from shape (auto-detect by default;
    // an optional manual override is honored). Fail closed BEFORE any rule
    // evaluation on a shape the engine does not model - never present confident
    // identity findings on a resource/trust/ambiguous/NotPrincipal document.
    const coverage = detectFamily(m.model, opts);
    coverageRef = coverage;
    if (coverage.blocked) return blockedResult(m.model, coverage);

    const effectiveFamily = coverage.family || coverage.detected || 'unknown';

    // IAM-801 (Phase 8): a role-trust policy is routed to the family-aware TRUST
    // evaluator, NEVER to the identity rules/escalation engine. A trust policy
    // conveys WHO MAY ASSUME the role, not the role's permissions; running
    // identity rules on it would emit spurious identity-style findings (e.g. a
    // broad-Resource finding for the Resource a trust policy legitimately omits).
    // Every trust finding carries the limitation that the assumed role's
    // permissions are out of scope / unknown.
    if (effectiveFamily === FAMILIES.ROLE_TRUST) {
      return trustResult(m.model, coverage, effectiveFamily);
    }

    // IAM-1002 (Phase 10): an explicit permissions-boundary / session selection
    // is a CEILING/RESTRICTION, not a grant. Route it to the envelope evaluator
    // (no positive capability edges, no escalation) rather than the identity
    // engine. Auto-detect never reaches here (it cannot distinguish these from
    // identity); only an explicit override selects them.
    if (effectiveFamily === FAMILIES.PERMISSIONS_BOUNDARY
      || effectiveFamily === FAMILIES.SESSION) {
      return envelopeResult(m.model, coverage, effectiveFamily);
    }

    // IAM-1301 / IAM-1302 (Phase 13): an accepted SCP/RCP family (explicit selection
    // on a guardrail-shaped document - the family gate has already failed closed on
    // any non-guardrail shape) is a CEILING/GUARDRAIL. Route it to the family-aware
    // ceiling evaluator (no positive capability edges, no escalation) rather than
    // the identity/resource engine. The two org-control shapes are disjoint: an SCP
    // is no-Principal (isScpShape rejects Principals) and an RCP is Principal-bearing
    // (isRcpShape requires a Principal on every statement), so a Principal-bearing
    // accepted document is the RCP guardrail and everything else is the SCP ceiling.
    if (effectiveFamily === FAMILIES.SCP_RCP) {
      if (isRcpShape(m.model.statements)) {
        return rcpResult(m.model, coverage, effectiveFamily);
      }
      return scpResult(m.model, coverage, effectiveFamily);
    }

    // IAM-1201 (Phase 12): an accepted resource family (explicit selection + a
    // valid attached-resource context - the family gate has already failed closed
    // otherwise) is routed to the resource evaluator, never the identity engine.
    // Only a NON-blocked accepted resource reaches here (blocked shapes returned
    // via blockedResult above), so this is the accept-and-route path.
    if (effectiveFamily === FAMILIES.RESOURCE) {
      return resourceResult(m.model, coverage, effectiveFamily, options || {});
    }

    const rules = analyzeRules(m.model, options || {});
    const esc = analyzeEscalations(m.model, options || {});
    const errors = [
      ...(rules.ok ? [] : rules.errors),
      ...(esc.ok ? [] : esc.errors),
    ];
    if (errors.length) return fail(errors);

    const combined = [...rules.findings, ...esc.findings];

    // IAM-302: same-policy explicit-Deny precedence for the AUTHORITATIVE TABLE.
    // rules.js is deliberately Deny-UNAWARE when it emits findings so the graph
    // can still draw the `blocked-by-deny` edge for a granted-but-denied
    // capability (a Phase-2 invariant). Here we drop from the TABLE only those
    // rule findings whose capability a same-policy Deny fully removes (fully
    // blocked, or a broad bulk-read fenced to a narrow set). Escalation findings
    // already have Deny folded in by escalation.js. The graph below still
    // receives the FULL `combined` set, so blocked-by-deny edges are preserved.
    // Computed HERE (before the broad-uncovered net) because that net keys its
    // "covered" decision off the DENY-SURVIVING findings, not the pre-suppression
    // set - see the coveredStatementIndexes note below.
    const tableFindings = combined.filter(
      (f) => !ruleFindingDenySuppressed(f, m.model),
    );

    // S1-breadth-classify (iter 2): close the residual breadth fail-open the rule
    // catalog is structurally blind to. A resource value classifyResource() reports
    // BROAD - the bare "*", a wildcard high in the ARN (partition/service/ACCOUNT), a
    // whole-collection identifier wildcard (role/*), a bucket-name-segment wildcard, or
    // a boundary-crossing non-ARN glob ("?*"/"*/*") - matches essentially every resource
    // of a service or spans the account boundary. When a finding fired on its Allow
    // statement (s3:GetObject on "?*" -> DATA-EXFIL; iam:PassRole on "arn:aws:iam::*:role/*"
    // -> WILDCARD-RESOURCE) the risk is already surfaced. When NO finding fired the grant
    // would otherwise read as a bare CLEAN: a fail-OPEN (threat-model T8). This is the
    // exact shape of a broad-resource READ: the rule catalog DELIBERATELY treats a
    // read-only wildcard as routine (grantsNonReadAction gates WILDCARD-RESOURCE;
    // DATA-EXFIL needs the s3-bulk/secret catalog), so dynamodb:GetItem / iam:GetRole /
    // kms:DescribeKey / s3:GetBucketPolicy on a BROAD resource fires NEITHER rule.
    //
    // The control MUST hold SYMMETRICALLY across spellings of "read broadly": the glob
    // "?*" and the equally-broad WELL-FORMED ARN "arn:aws:dynamodb::*:table/foo" (wildcard
    // ACCOUNT - a cross-account read) are the SAME broadness from the one shared classifier
    // and must BOTH route to incomplete. So this nets on ONLY two facts: (a) the shared
    // classifier's BROAD verdict, and (b) whether a rule finding actually COVERED the
    // statement - NEVER on "a well-formed ARN implies a rule fired", which is precisely the
    // assumption that fails open (iter-1 excluded well-formed ARNs here via parseArn, which
    // re-instated that assumption and left every broad-well-formed-ARN read a bare CLEAN).
    // Allow-only; the bare "*" is excluded (its scope is fully decided and it is the single
    // most-recognized wildcard the rule catalog owns).
    //
    // Iteration 4: the covered set is built from the DENY-SURVIVING findings
    // (`tableFindings`), NOT the pre-suppression `combined` set. Keying it off
    // `combined` re-instated the forbidden assumption this design warns against:
    // a rule DID fire on a statement, so the statement was marked "covered" and
    // the net SKIPPED it - but the authoritative table later DROPS that finding
    // via ruleFindingDenySuppressed (same-policy Deny precedence / NotResource
    // fence). "A rule fired" then no longer implies "a risk was surfaced": a
    // DIFFERENT surviving broad read on that same statement (dynamodb:GetItem next
    // to a Deny-suppressed s3:GetObject on "arn:aws:...:table/*") was never
    // flagged and the tool returned a bare CLEAN. Keying "covered" off findings
    // that ACTUALLY SURVIVE into the table means a statement whose only finding is
    // Deny-suppressed re-enters this net and its surviving broad read flips
    // incomplete - never a bare CLEAN. Symmetric across both Deny mechanisms
    // (full action-Deny AND NotResource fence) and both covering rules
    // (DATA-EXFIL bulk-read AND secret-read), since both are folded out of
    // tableFindings by the same ruleFindingDenySuppressed filter.
    const coveredStatementIndexes = new Set(
      tableFindings
        .map((f) => (typeof f.statementIndex === 'number' ? f.statementIndex : null))
        .filter((i) => i !== null),
    );
    //
    // Iteration 3: this net must cover the NotResource axis too, symmetric with
    // masked-grant.js's both-axis MALFORMED handling (which already covers Resource
    // AND NotResource). rules.js resourceIsBroad() treats a NON-EMPTY NotResource as
    // broad (Allow-everything-EXCEPT-a-narrow-set spans essentially every ARN), so a
    // routine-read Allow scoped by NotResource (dynamodb:GetItem NotResource
    // arn:aws:s3:::my-bucket/*) fires NO rule yet is account-wide broad. Inspecting
    // only s.resources left that grant a bare CLEAN on the NotResource axis - an
    // internal asymmetry (a malformed NotResource was already caught, a broad-but-
    // well-formed one was not). Both axes now flip incomplete.
    const broadUndecidableUncovered = [];
    for (const s of m.model.statements) {
      if (!s || s.effect !== 'Allow') continue;
      if (coveredStatementIndexes.has(s.index)) continue;
      const sid = (typeof s.sid === 'string' && s.sid.length > 0) ? s.sid : `(index ${s.index})`;
      // Iteration 6: the bare "*" is NOT unconditionally a decided/covered scope. For a
      // RESOURCE-SCOPABLE READ (catalog "Read" level: dynamodb:GetItem, iam:GetRole,
      // kms:DescribeKey, s3:GetBucketPolicy, secretsmanager:DescribeSecret) that no rule
      // covered, Resource "*" is an account-wide broad read the rule catalog is blind to
      // ("*" >= "?*", yet only "?*" was flipping) - it must flip incomplete exactly as
      // "?*" does. An ENUMERATION/LIST read (ec2:DescribeInstances, s3:ListAllMyBuckets,
      // iam:ListRoles) genuinely REQUIRES "*" (no resource-level scoping), so its "*" is
      // still waved through - flagging it would be a false positive. A mutating "*"
      // already fired WILDCARD-RESOURCE, so it never reaches this uncovered net.
      // Iteration 8: EXCLUDE the scope a same-policy explicit Deny covers before
      // treating this statement's broad resource as a surviving broad read. A
      // Deny-suppressed rule finding drops out of tableFindings, so its statement
      // re-enters this net (see the coveredStatementIndexes note) - but if the SAME
      // same-policy Deny fully removes the scopable read (explicit-deny-suppresses-
      // exfil: Deny s3:GetObject "*") or fences its broad scope down to a narrow set
      // (notresource-deny-fences-exfil: Deny NotResource approved-data/*), there is
      // NO surviving broad read and the correct verdict is CLEAN. Keying off the
      // literal "*" resource instead of the fenced effective scope re-flagged those
      // as BROAD_RESOURCE_UNDECIDABLE - a false positive that contradicts Control B
      // (a Deny-suppressed statement with a NARROW surviving resource stays CLEAN).
      // survivingBroadReadActions() applies the identical Deny semantics
      // ruleFindingDenySuppressed() uses (no drift). When the statement HAD scopable
      // reads but a Deny covered them ALL, the broad resource is Deny-decided: skip
      // it (a statement with no scopable reads is unaffected; a partially-surviving
      // read still flips incomplete).
      const scopableReads = statementScopableReadActions(s);
      const survivingReads = survivingBroadReadActions(scopableReads, s, m.model);
      if (scopableReads.length > 0 && survivingReads.length === 0) continue;
      const starIsScopableRead = survivingReads.length > 0;
      // Resource axis: a broad Resource value the rule catalog left uncovered.
      let flagged = false;
      if (Array.isArray(s.resources)) {
        for (const v of s.resources) {
          // The bare "*" is a decided scope EXCEPT when a resource-scopable read rides
          // it uncovered (then it is the broadest possible undecidable-for-coverage read).
          if (String(v).trim() === '*' && !starIsScopableRead) continue;
          if (classifyResource(v) !== RESOURCE_CLASS.BROAD) continue; // narrow/malformed handled elsewhere
          broadUndecidableUncovered.push(Object.freeze({
            statementIndex: s.index,
            statementSid: sid,
            axis: 'Resource',
            value: String(v),
          }));
          flagged = true;
          break; // one entry per statement is enough to mark it incomplete
        }
      }
      if (flagged) continue; // a statement carries either Resource or NotResource, never both
      // NotResource axis: a NON-EMPTY NotResource complement is inherently broad
      // (resourceIsBroad() true). An empty complement is handled by masked-grant
      // (EMPTY_NOTRESOURCE_COMPLEMENT); a malformed member is handled by masked-grant
      // (MALFORMED_RESOURCE_ARN). A broad well-formed complement on an uncovered read
      // fell through both - close it here.
      if (Array.isArray(s.notResources) && s.notResources.length > 0) {
        broadUndecidableUncovered.push(Object.freeze({
          statementIndex: s.index,
          statementSid: sid,
          axis: 'NotResource',
          value: s.notResources.map((v) => String(v)).join(', '),
        }));
      }
    }

    // S1-R1-deny-fence-surviving: DERIVE the whole-container read that SURVIVES a
    // NotResource-Deny fence on a broad Allow. rules.js is Deny-UNAWARE when it emits
    // findings, so a broad exfil Allow fenced down to one spared bucket is handled only
    // by SUPPRESSION (DATA-EXFIL dropped, coverage net quiet) and the PROVEN SURVIVING
    // spared resource is never examined for its own risk - a live whole-bucket read read
    // CLEAN (R1 fail-open, T8). This post-pass HAS the denies in scope (like
    // survivingBroadReadActions above), reuses rules.js's shared classifier (no drift),
    // and surfaces the surviving read as CROSS-ACCOUNT-DATA-READ[-UNDETERMINED] - NEVER
    // DATA-EXFIL (whose bulk-fence exemption would instantly re-suppress it). It is
    // subject-account-INDEPENDENT for the account-blind S3 bucket case (like DATA-EXFIL,
    // it never needed a subject); a resolvable cross-account read still needs a KNOWN
    // subject. These findings enter the AUTHORITATIVE TABLE only (the graph, built from
    // `combined`, still shows the underlying grant + blocked-by-deny edge unchanged).
    const derivedSpared = survivingSparedContainerReads(m.model, {
      subjectAccount: (options && options.subjectAccount) || null,
    });
    // Dedup defensively against the table: a derived finding whose (id, statement,
    // actions, resources) identity already appears is not re-reported (no duplicate row,
    // no fingerprint collision). The exact-identity key handles the belt-and-braces cases
    // (derived-vs-derived, exact table match). The key is built by the INJECTIVE
    // module-level findingIdentityKey() (see its definition) so an attacker-controlled
    // action/resource token that contains the join delimiter cannot forge a collision
    // that drops a distinct surviving-spared read (S3-SWEEP-01).
    // SUBSET-aware table coverage (iteration-5 over-correction close). Exact-key equality
    // alone MISSES the mixed case where the spared bucket is ALSO an explicit Allow
    // resource AND the fence covers only a strict ACTION-SUBSET of the Allow's reads:
    // ruleDataReadScoped reports the Allow's own leg with the FULL read action set on the
    // spared bucket (e.g. [s3:GetObject, s3:ListBucket]), while the derived helper reports
    // the SAME bucket with only the FENCED subset (e.g. [s3:GetObject]). Same id, same
    // statement, same resource, subset actions - ONE surviving capability, but the exact
    // key treated the subset as a distinct row -> two SARIF alerts / two table rows for one
    // bucket (dismissing one leaves the other). A derived finding is DROPPED as
    // already-covered when a table finding shares its (id, statementIndex), covers ALL its
    // resources, and covers ALL its actions (i.e. the derived row is a resource+action
    // SUBSET of a broader table row). The broader table row is kept, so the fuller surviving
    // capability is still reported. A derived finding on a DIFFERENT resource (the mixed
    // Resource:["*","other/*"] coexistence case) or a DIFFERENT id is NOT a subset and is
    // preserved - so genuinely-distinct surviving reads still each surface.
    const actionSetOf = (f) => new Set(
      (Array.isArray(f && f.actions) ? f.actions : []).map((a) => String(a).toLowerCase()),
    );
    const resourceSetOf = (f) => new Set(
      (Array.isArray(f && f.resources) ? f.resources : []).map(String),
    );
    const isSubsetOf = (small, big) => {
      for (const x of small) if (!big.has(x)) return false;
      return true;
    };
    const coveredByTable = (f) => tableFindings.some((t) => (
      t && t.id === f.id
      && typeof t.statementIndex === 'number' && t.statementIndex === f.statementIndex
      && isSubsetOf(resourceSetOf(f), resourceSetOf(t))
      && isSubsetOf(actionSetOf(f), actionSetOf(t))
    ));
    const tableIdentities = new Set(tableFindings.map(findingIdentityKey));
    const derivedUnique = [];
    const derivedSeen = new Set(tableIdentities);
    for (const f of derivedSpared) {
      if (coveredByTable(f)) continue;
      const key = findingIdentityKey(f);
      if (derivedSeen.has(key)) continue;
      derivedSeen.add(key);
      derivedUnique.push(f);
    }

    // IAM-105: fold subordinate wildcard/broad-resource rows into the compound
    // escalation path that already accounts for them, so the table shows one
    // primary path finding with a risk-factor checklist instead of duplicate
    // subordinate rows. Independent wildcard findings are untouched.
    // The derived surviving-spared findings are NEW capabilities (not subordinate to any
    // compound path), so they are appended AFTER correlation, never folded away.
    const correlated = [...correlateFindings(tableFindings), ...derivedUnique];
    // IAM-504: stamp the effective policy family onto every finding so each row
    // carries the full explainable-evidence set (family + statement + action +
    // resource + condition + rule id + certainty + limitation). effectiveFamily
    // is computed once above (used by the trust-family branch too).
    const stamped = correlated.map((f) => stampFamily(f, effectiveFamily));
    const findings = Object.freeze(sortFindings(stamped));

    // The graph is built from the full (pre-correlation, pre-Deny-suppression)
    // finding set: a subsumed wildcard grant is still a real edge, and a
    // Deny-blocked capability is still shown as a blocked-by-deny edge. The
    // findings table stays the authoritative, de-duplicated, live-capability view.
    const g = buildGraph(m.model, combined);
    const graph = g.ok ? g.graph : emptyGraph();

    // IAM-502: enrich the family-gate coverage into the full analysis-coverage
    // summary now that the model + graph exist (statement counts, graph
    // complete/truncated, missing evaluation layers, versions). Exports and the
    // coverage panel read this single object.
    // IAM-506: report condition keys the classifier does not model as
    // unsupported conditions. A single such key marks coverage incomplete
    // (unsupported does NOT mean safe) - the honest signal that the analysis
    // could not reason about part of the request-context gating.
    // IAM-507: the ACTION-catalog reports concrete actions it does not recognize
    // as "unknown action" in coverage (not an error, not silently dropped), and
    // its dated version travels in the summary. Unknown actions mark coverage
    // incomplete - the snapshot could not vouch for that grant (unsupported does
    // NOT mean safe). The catalog sits behind an interface (defaultCatalog) so a
    // generated/sharded snapshot can replace it without touching this pipeline.
    const enriched = enrichCoverage(coverage, {
      model: m.model,
      graph,
      catalogVersion: defaultCatalog.version,
      unsupportedConditions: unsupportedConditionKeys(m.model),
      unrecognizedActions: unrecognizedActions(m.model, defaultCatalog),
      // IAM-1006 (test 50): object-action vs bucket-only-ARN mismatches - a
      // non-blocking coverage warning so an ineffective grant is never reported
      // as a complete, empty analysis.
      actionResourceMismatches: actionResourceTypeMismatches(m.model),
      // IAM-1007 (test 60): non-unique Sids across statements - a non-blocking
      // evidence-identity advisory (statements stay keyed on their distinct
      // index; the collision is named, never allowed to overwrite a record).
      duplicateSids: duplicateSids(m.model),
      // S1-breadth-classify: broad-but-undecidable resource globs on statements the
      // rule catalog left finding-free (dynamodb:GetItem on "?*"). Flips incomplete so
      // an under-covered broad grant is never a bare CLEAN.
      broadUndecidableUncovered,
    });

    return Object.freeze({
      ok: true,
      errors: Object.freeze([]),
      findings,
      model: m.model,
      graph,
      catalogVersion: CATALOG_VERSION,
      counts: Object.freeze({
        findings: findings.length,
        edges: graph.edges.length,
        nodes: graph.nodes.length,
      }),
      // IAM-501/502: the detected/selected family + enriched coverage summary
      // travel with every successful result so exports and the coverage panel
      // can name the family they analyzed and what they did / did not cover.
      family: enriched.family,
      coverage: enriched,
    });
  } catch (e) {
    // S3-dos-budget: a tripped resource budget is not an internal fault.
    if (isGlobBudgetError(e)) {
      // WALL-CLOCK deadline ('clock', armed only by the Node adapter): re-throw so
      // scan() maps it to its timing-dependent RESOURCE_BUDGET_EXCEEDED verdict. This
      // path is never taken on the browser (it never arms a clock).
      if (e.kind === 'clock') throw e;
      // DETERMINISTIC work ceiling ('work', armed on every run incl. the browser):
      // convert to a graceful, well-formed fail-closed result - ok:true, zero
      // findings, coverage marked aborted/incomplete - so a runaway can NEVER return
      // a COMPLETE verdict and NEVER surfaces as an uncaught throw or a clean pass.
      return abortedResult(model, coverageRef);
    }
    // Absolute backstop: the UI must never see an uncaught exception.
    return fail([{ code: 'INTERNAL', message: 'Analysis failed unexpectedly.', path: null }]);
  } finally {
    // Restore the work limit the caller had (Infinity by default), leaving any
    // wall-clock deadline scan() armed untouched.
    setWorkLimit(prevWorkLimit);
  }
}

export default analyze;
