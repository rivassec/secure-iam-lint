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

// Depth bound for the recursive condition neutralizer. REUSED from the engine's input
// validator (do NOT invent a second, unbounded recursive walker): the same MAX_DEPTH
// that gates parse also gates how deep an evidence Condition may be walked for output.
// validate.js is a pure engine module (no Node APIs); importing it here keeps this
// adapter pure and Node-free. This module is never in the browser graph (it is only
// imported by cli/ + action/), so no `node:` dependency can leak through it.
import { LIMITS } from '../content/tools/iam-blast-radius/engine/validate.js';
// S4-unicode-spoof iteration 3: the strong-RTL / homograph-space / homograph-letter class,
// shared with the browser display sinks so BOTH surfaces neutralize the SAME charset (the
// superset/parity invariant is structural, not just regex-compared). CONTROL_AND_FORMAT
// below closes the invisible/format-control mechanism; NON_ASCII_SPOOF closes the second,
// code-point-free bidi Trojan-Source mechanism - a strong-RTL LETTER reorders its neighbours
// with no format-control char, and a \p{Zs} space / Cyrillic homograph masquerades as ASCII.
// IAM tokens are ASCII per the AWS grammar, so any non-ASCII in a value bound for the
// (markdown-rendered) Security tab is a spoof vector, clamped to U+FFFD. format-control.js is
// a pure engine module (no node: APIs), so importing it keeps this adapter Node-free; it is
// never in the browser graph (cli/ + action/ only), so no node: dependency can leak through.
import { NON_ASCII_SPOOF, REPLACEMENT } from '../content/tools/iam-blast-radius/engine/format-control.js';

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

// Join a normalized attacker-controlled token list into ONE identity-string field with an
// UNFORGEABLE element boundary (S2-R2-sarif-identity iteration 2; generalized to EVERY
// identity list by S1-NEW02-sarif-identity-injective).
//
// The token lists folded into findingIdentity are ATTACKER-CONTROLLED policy text (a fork PR
// owns the whole policy JSON) with NO charset restriction (an S3 key permits ~any byte). A
// plain `list.join('|')` let a SINGLE token that literally contains the '|' delimiter forge
// the same joined string as a MULTI-element list split on that '|' - so two semantically
// DISTINCT lists (e.g. resources:[a,b] vs resources:['a|b'], or NotResource:[a,b] vs
// NotResource:['a|b']) hashed to ONE partialFingerprint, and dismissing one code-scanning
// alert AUTO-SUPPRESSED the other (a fail-OPEN on re-detection). A raw newline in a token was
// worse still: it could inject a fresh `key=value` line into the multi-line identity string
// and forge a DIFFERENT part (e.g. escService / escTechnique). So each token is
// backslash-escaped - '\\' FIRST (so the escapes we add are unambiguous), then the '|'
// delimiter and any newline - making the encoding INJECTIVE: the only UNESCAPED '|' are the
// real element separators and no token can span an identity line. A benign token (no '\\',
// '|', or newline - every real ARN / action / principal) is emitted byte-for-byte as a plain
// "|"-join would, so this NEVER churns an existing non-injection fingerprint.
//
// R2 first applied this to the EXCLUDED (NotAction / NotResource) lists. NEW-02 (its HIGH
// sibling) closes the SAME class on the POSITIVE lists - actions, resources, principals -
// which findingIdentity still joined with a plain '|'. This helper is now the SINGLE injective
// joiner every attacker-controlled identity list flows through, so the two paths cannot drift.
// Pure + deterministic; reused for the positive lists AND both complement sides.
function joinInjective(list) {
  return list
    .map((s) => String(s).replace(/\\/g, '\\\\').replace(/\|/g, '\\|').replace(/\n/g, '\\n'))
    .join('|');
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
    // S1-NEW02: the POSITIVE identity lists are attacker-controlled policy text with no
    // charset restriction, so each is joined through the INJECTIVE joinInjective() (escape
    // '\', '|', newline) - a plain `.join('|')` let a single '|'- or newline-bearing token
    // forge the sorted-join identity of a DISTINCT multi-element list (a fingerprint-collision
    // fail-open, sibling of R2). Benign tokens (every real ARN / action / principal) emit
    // byte-for-byte as the plain join did, so ordinary fingerprints never churn.
    `actions=${joinInjective(normList(f.actions, { lowercase: true }))}`,
    `resources=${joinInjective(normList(f.resources))}`,
    `principals=${joinInjective(findingPrincipals(f))}`,
    `condition=${f.conditions == null ? '' : stableStringify(f.conditions)}`,
    `viability=${requiredUnknowns.join('|')}`,
    // S5-sarif-symmetric: an escalation path's TARGET SERVICE and TECHNIQUE are part of
    // its semantic identity, not decoration. Several distinct PassRole routes share one
    // finding TYPE (id=PASSROLE-SERVICE covers ecs/glue/cloudformation/sagemaker/
    // codebuild/datapipeline) and, when the exec statement grants a wildcard action, the
    // SAME anchor position + normalized action list ("*") + resource. Without the service
    // + technique folded in, those routes hash to ONE partialFingerprint, so a maintainer
    // dismissing one code-scanning alert SUPPRESSES every other route (a fail-OPEN). These
    // are tool-controlled enum values (never attacker free-text), so they cannot be used
    // to forge a collision; they can only SPLIT genuinely-distinct routes apart.
    `escService=${esc && esc.service != null ? String(esc.service) : ''}`,
    `escTechnique=${esc && esc.technique != null ? String(esc.technique) : ''}`,
  ];
  // S2-R2-sarif-identity: the EXCLUDED (NotAction / NotResource) scope is part of the
  // finding's SEMANTIC identity, not decoration. makeFinding (engine/rules.js) EMPTIES the
  // positive scope for a complement grant - a NotResource DATA-EXFIL reports actions:[...],
  // resources:[], and a NotAction NOTACTION-ALLOW / WILDCARD-RESOURCE reports actions:["*"],
  // resources:["*"] - and stows the REAL discriminating scope in excludedActions /
  // excludedResources. Without folding those in, two carve-outs differing ONLY in their
  // NotResource/NotAction target (e.g. `NotResource: bucket-a/*` vs `bucket-b/*`) share the
  // anchor position, the (identical) positive action/resource lists, and every other part -
  // so they hash to ONE partialFingerprint. A maintainer dismissing carve-out A's
  // code-scanning alert then AUTO-SUPPRESSES the still-live, semantically distinct carve-out
  // B (a fail-OPEN on re-detection). The excluded set is canonicalized through the SAME
  // normList used for actions/resources (sort + de-dup; actions case-folded, ARNs case-exact;
  // scalar-vs-list collapsed), so order / case / equivalent-spelling do NOT churn the
  // fingerprint - only a genuinely different carve-out target splits them apart. Appended
  // CONDITIONALLY (only when the finding actually carries an excluded set): a non-complement
  // finding's identity string is byte-identical to before, so its fingerprint never churns.
  // BOTH complement sides are covered. These lists ride the hash ONLY (never rendered here);
  // the human-facing projection is neutralized separately in buildResults.
  const excludedActions = normList(f.excludedActions, { lowercase: true });
  if (excludedActions.length > 0) parts.push(`excludedActions=${joinInjective(excludedActions)}`);
  const excludedResources = normList(f.excludedResources);
  if (excludedResources.length > 0) parts.push(`excludedResources=${joinInjective(excludedResources)}`);
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
    // SECURITY (S2/S4/S5-sarif): EVERY attacker-controlled string in an evidence row is
    // neutralized before it reaches properties.evidence - symmetrically, never verbatim.
    // A fork PR owns the whole policy JSON, so the Sid, role label, action tokens,
    // resource ARNs, the free-prose note, AND the raw Condition block are all hostile.
    // These fields are emitted BARE (un-wrapped) in the properties bag, so - like the
    // note and the condition - EVERY one is rendered MARKDOWN-INERT (inertLeaf: strip
    // control + bidi/zero-width, cap length, then backslash-escape EVERY ASCII-punctuation
    // char). A backtick-only strip would be INERT here (a live `[x](url)` / `![x](url)` /
    // `<url>` only defuses inside a code span, and these values are NOT code-span-wrapped),
    // so the token-like fields go through inertLeaf / inertTokenList, NOT sanitizeSid.
    // The NOTE is engine-authored FREE PROSE that interpolates raw actions + ARNs
    // (engine/rules.js ACTION_RESOURCE_TYPE_MISMATCH), so it gets sanitizeStateMessage
    // (same escape). The CONDITION is a NESTED object whose operator + key names AND leaf
    // values are ALL attacker-controlled: neutralized RECURSIVELY (keys and values alike
    // markdown-inert) and bounded three ways PER ROW (per-leaf length, aggregate node/char
    // budget, recursion depth) so it cannot carry a live link/image/autolink into a consumer
    // (see neutralizeCondition). The action / resource token lists are likewise COUNT- and
    // aggregate-char-capped (inertTokenList). Nothing in this row is emitted raw. NOTE: these
    // caps are PER ROW and cannot bound the SUM across a document; the cross-row amplification
    // (thousands of findings summing past GitHub's ~10 MB upload cap) is closed SEPARATELY by
    // the DOCUMENT-level budget in buildResults - not here.
    if (e && e.statementSid != null) {
      const safeSid = inertLeaf(e.statementSid, MAX_SID_LEN);
      if (safeSid) row.statementSid = safeSid;
    }
    if (e && e.role != null) {
      const safeRole = inertLeaf(e.role, MAX_SID_LEN);
      if (safeRole) row.role = safeRole;
    }
    if (e && Array.isArray(e.actions)) row.actions = inertTokenList(e.actions);
    if (e && Array.isArray(e.resources)) row.resources = inertTokenList(e.resources);
    if (e && e.condition != null) {
      const { value, truncated } = neutralizeCondition(e.condition);
      if (truncated) {
        // A bound was hit (depth / aggregate node / aggregate char). Emit a bounded,
        // markdown-inert SUMMARY of the sanitized partial + an explicit flag, NEVER the
        // raw object: this is the amplification/injection fail-closed for the Condition.
        let summaryRaw = '';
        try { summaryRaw = JSON.stringify(value); } catch { summaryRaw = ''; }
        row.conditionSummary = inertSummary(summaryRaw, MAX_CONDITION_SUMMARY_LEN)
          || '(condition omitted)';
        row.conditionTruncated = true;
      } else if (value != null) {
        row.condition = value;
      }
    }
    if (e && e.note != null) row.note = sanitizeStateMessage(e.note);
    return row;
  });
}

// The invisible / reordering code points that EVERY attacker string must be stripped of
// before it reaches a SARIF sink. Left in, these are not markdown punctuation and are not
// caught by the ASCII-punctuation escape (nor, for most, by `\s`), so a fork PR could
// bidi-REORDER or zero-width-HIDE/SPLIT an ARN / Sid / condition token so a hostile value
// renders as a benign one in a consumer's Security-tab alert detail (an RTL / homograph /
// hidden-text spoof) - a fail-OPEN distinct from, and not covered by, the markdown-link
// class.
//
// The CLASS is "code points that occupy no visible width or reorder their neighbours." A
// hand-enumerated range can only ever cover the SUBSET the author happened to list. Two
// earlier drafts proved it: a "codepoint-exhaustive" BMP range missed the astral tag
// block, the Hangul fillers, the variation selectors and U+180E; a follow-up that added
// \p{Cc}\p{Cf} plus a hand-list of the non-Cc/Cf invisibles STILL missed the combining
// grapheme joiner U+034F, the Khmer inherent vowels U+17B4/U+17B5, and the reserved tag-
// block base U+E0000 - all zero-width, none caught. Each patch closed one spelling; the
// hunter found the next. So the class is matched by Unicode PROPERTY, not enumeration:
//   \p{Cc}  - every C0 (0x00-0x1F) + DEL + C1 (0x7F-0x9F) control.
//   \p{Cf}  - every format char: SOFT HYPHEN U+00AD, ARABIC LETTER MARK U+061C, the ZW /
//             bidi-mark + embedding + isolate + deprecated-format set (U+200B-200F,
//             U+202A-202E, U+2060-206F), BOM U+FEFF, interlinear annotation U+FFF9-FFFB,
//             MONGOLIAN VOWEL SEPARATOR U+180E, and the ASTRAL tag block U+E0001/E0020-
//             E007F.
//   \p{Default_Ignorable_Code_Point}  - the property Unicode itself defines for "code
//             points that should render as nothing when unsupported": it SUBSUMES the CGJ
//             U+034F, the Khmer inherent vowels, EVERY Hangul filler (U+115F U+1160 U+3164
//             U+FFA0), EVERY variation selector (U+FE00-FE0F + the U+E0100-E01EF
//             supplement), the whole U+2060-206F block INCLUDING the currently-unassigned-
//             but-reserved U+2065 and the reserved tag-block base U+E0000 - and, crucially,
//             any FUTURE default-ignorable assignment. This is what closes the "next
//             spelling" regress at the property level instead of one code point at a time.
// Plus the ONE spoofing invisible Unicode files under none of those properties:
//   U+2800  BRAILLE PATTERN BLANK (category So, NOT Default_Ignorable) - renders as blank
//           width, so it can pad/hide a token, yet no property above matches it. It is the
//           sole code point that still needs to be named explicitly.
// This is the SINGLE definition every leaf sanitizer below strips against, so the class is
// closed once, not per-field. The `u` flag is REQUIRED: it enables the \p{...} property
// escapes and makes the astral code points match as whole code points. Reusing one global
// regex across .replace() calls is safe (String.prototype.replace resets a global regex's
// lastIndex at the start of every call).
// Exported so tests/s4-unicode-spoof.test.js can assert the engine's canonical
// INVISIBLE_SPOOF class is a SUPERSET of this one - if a future edit ever narrows
// the engine class below this SARIF class, the browser JSON/DOM output surface
// would become MORE permissive toward invisible/control code points than the CLI
// SARIF surface (a display-parity regression), and that test must fail.
export const CONTROL_AND_FORMAT =
  /[\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}\u2800]/gu;

// Max characters kept from a hostile Sid before ellipsizing. A 10KB Sid must never
// land verbatim in message.text or properties.
const MAX_SID_LEN = 128;

// Bounds on an evidence token list (actions / resources) emitted BARE into the properties
// bag. Like message.text's MAX_MSG_ACTIONS, this stops a policy carrying a huge Action /
// Resource array from amplifying the SARIF: the entry COUNT is capped and the AGGREGATE
// sanitized-char budget across the list is capped (many small tokens cannot sum past it).
// The full normalized lists still ride in partialFingerprints identity, unaffected.
const MAX_EVIDENCE_TOKENS = 32;
const MAX_EVIDENCE_TOKEN_CHARS = 4096;
// Tool-authored, markdown-inert marker appended when a token list is capped, so the
// truncation is TRUTHFUL (fail-closed ethos) rather than a silent drop.
const EVIDENCE_TRUNCATED_MARKER = '(list truncated)';

// Neutralize an attacker-controlled Sid/Action token for embedding INSIDE A BACKTICK
// INLINE-CODE SPAN (message.text via findingMessage / renderActionClause - the ONLY
// remaining callers). GitHub renders message.text as MARKDOWN; a code span makes its
// contents inert, so the neutralization here only has to (a) keep the value from escaping
// its span and (b) bound its size:
//   - strips C0/C1 control chars, DEL, and the bidi/zero-width/format set (CONTROL_AND_
//     FORMAT) so a payload cannot break the line, inject ANSI, or bidi/zero-width-spoof
//     the rendered token,
//   - strips backticks (so the value cannot close its inline-code wrapper and open a
//     markdown construct outside it - the defense that makes the code span inert),
//   - collapses remaining runs of whitespace to a single space, and
//   - caps length + ellipsizes (a multi-KB Sid cannot bloat or dominate the output).
// Returns '' when nothing printable survives (caller then falls back to the index).
//
// SECURITY: this backtick-strip defense is INERT for a value emitted BARE (not code-span-
// wrapped) - there `[x](url)` / `![x](url)` / `<url>` still render live. Every BARE
// properties-bag field (evidence statementSid/role/actions/resources, top-level
// properties.statementSid, condition, note, path) therefore goes through the markdown-
// inert `inertLeaf` (ASCII-punctuation backslash-escape), NOT this function. Do not route
// a bare field here. Pure + deterministic: same Sid -> same token, every run.
function sanitizeSid(sid) {
  let s = String(sid);
  // Control + bidi/zero-width (CONTROL_AND_FORMAT) + backticks -> space. Backtick removal
  // keeps the value inside its inline-code wrapper so a markdown payload cannot escape it.
  // S4 iteration 3: after the control/format strip, clamp remaining non-ASCII to U+FFFD
  // (strong-RTL letter / Zs homograph space / homograph letter) so the code-span token
  // cannot bidi-reorder or homograph-spoof in the rendered Security tab.
  s = s.replace(CONTROL_AND_FORMAT, ' ').replace(NON_ASCII_SPOOF, REPLACEMENT).replace(/`/g, ' ');
  s = s.replace(/\s+/g, ' ').trim();
  if (s.length > MAX_SID_LEN) s = `${s.slice(0, MAX_SID_LEN)}...`;
  return s;
}

// Neutralize an attacker-controlled token list (evidence actions / resources) for the
// BARE properties bag. These entries are emitted un-wrapped (never inside a code span),
// so each is rendered MARKDOWN-INERT via inertLeaf (ASCII-punctuation backslash-escape) -
// the same treatment condition/note get - NOT merely backtick-stripped, which would leave
// a live `[x](url)` / `![x](url)` / `<url>` in a resource or action. Empty tokens are
// dropped; both the entry COUNT and the AGGREGATE sanitized-char budget across the list
// are capped, with a truthful marker appended on truncation, so a huge Action/Resource
// array cannot amplify the SARIF. Order is preserved. Benign ARNs ride through with their
// punctuation backslash-escaped (readable, inert), exactly like a benign condition value.
// Pure + deterministic.
function inertTokenList(list) {
  const out = [];
  let chars = 0;
  let truncated = false;
  for (const v of list) {
    if (out.length >= MAX_EVIDENCE_TOKENS) { truncated = true; break; }
    const safe = inertLeaf(v, MAX_SID_LEN);
    if (!safe) continue;
    if (chars + safe.length > MAX_EVIDENCE_TOKEN_CHARS) { truncated = true; break; }
    chars += safe.length;
    out.push(safe);
  }
  if (truncated) out.push(EVIDENCE_TRUNCATED_MARKER);
  return out;
}

// Max characters kept from an analyzer-state message before ellipsizing. Some engine
// error messages interpolate attacker-controlled policy text (e.g. a duplicate
// condition-key spelling), so this bounds a hostile blow-up.
const MAX_STATE_MSG_LEN = 480;

// The fixed, tool-authored fallback when an analyzer-state carries no printable message.
const STATE_MSG_FALLBACK = 'Analysis could not be completed for this policy (fail-closed).';

// ASCII-punctuation code points (CommonMark's backslash-escapable set): 0x21-0x2F,
// 0x3A-0x40, 0x5B-0x60 (backslash 0x5C included), 0x7B-0x7E. Escaping EVERY one of
// these is what makes an analyzer-state message render inert.
// eslint-disable-next-line no-useless-escape
const ASCII_PUNCT = /[!-/:-@[-`{-~]/g;

// Neutralize an analyzer-state (fail-closed) message before it becomes SARIF
// message.text. This is the SINGLE CHOKEPOINT every analyzer-state message passes
// through (buildResults below), and it is deliberately NOT the finding-message path:
//
//   - A security FINDING's message is assembled HERE from tool prose plus individually
//     code-span-wrapped, pre-sanitized tokens (see findingMessage), so it is safe by
//     construction.
//   - An analyzer-state message is authored by the ENGINE (validate.js / model.js /
//     scan.mjs) as FREE PROSE that may interpolate attacker-controlled policy text
//     verbatim - a duplicate condition-key spelling, a rejected key name, a JSON path,
//     or any message a FUTURE engine change adds. GitHub renders message.text as
//     MARKDOWN in its Security tab, so a fork PR (which owns the whole policy JSON)
//     could otherwise inject a clickable link/image into a maintainer's alert view.
//
// Rather than trust each engine call site to pre-sanitize (a CLASS the fail-open hunter
// reopens with the next new message), we neutralize at the sink so ANY analyzer-state
// message - named or not-yet-written - renders inert. It:
//   - strips C0/C1 control chars + newlines AND the bidi/zero-width/format set
//     (CONTROL_AND_FORMAT) - the former break the rendered line / inject ANSI, the latter
//     reorder or hide/split a token to spoof it (neither is caught by the punctuation
//     escape below),
//   - collapses whitespace, caps length + ellipsizes (bounds a hostile blow-up), and
//   - backslash-escapes EVERY ASCII-punctuation char, so NO markdown construct can form:
//     not an inline or reference link, image, autolink `<url>`, bare-URL / www / email
//     autolink, code span, HTML tag, or emphasis. This is complete WITHOUT enumerating
//     markdown's link grammar (which the next spelling would evade). CommonMark renders
//     `\<punct>` as the literal punctuation, so the human text reads identically while
//     every `[label](url)`, `<url>`, or bare `https://...` is inert.
// Pure + deterministic: same message -> same text, every run.
function sanitizeStateMessage(msg) {
  let s = isNonEmptyString(msg) ? String(msg) : '';
  // S4 iteration 3: control/format strip THEN non-ASCII charset clamp (strong-RTL /
  // Zs homograph / homograph letter -> U+FFFD), before whitespace collapse + escape.
  s = s.replace(CONTROL_AND_FORMAT, " ").replace(NON_ASCII_SPOOF, REPLACEMENT);
  s = s.replace(/\s+/g, ' ').trim();
  if (!s) return STATE_MSG_FALLBACK;
  if (s.length > MAX_STATE_MSG_LEN) s = `${s.slice(0, MAX_STATE_MSG_LEN)}...`;
  // One pass over the ORIGINAL chars, so a literal `\` becomes `\\` and a `[` becomes
  // `\[` with no double-escaping.
  return s.replace(ASCII_PUNCT, '\\$&');
}

// --- Condition neutralization (S2-sarif-sanitize-all) -------------------------
//
// An evidence row's `condition` is the raw IAM Condition block copied off the statement
// (engine escalation/resource/trust/graph). It is a NESTED object whose OPERATOR + key
// names AND leaf VALUES are ALL attacker-controlled (a fork PR owns the whole policy
// JSON). The old `row.condition = e.condition` emitted it VERBATIM - the one evidence
// field the sibling code sanitized, that this one did not - so:
//   (1) a markdown/control payload in a condition key OR value reached a SARIF property
//       un-neutralized (GitHub renders alert detail; a live link/image could form), and
//   (2) it was uncapped PER-FIELD: bounded only by validate.js MAX_BYTES (1 MiB whole
//       document) across up to MAX_STATEMENTS statements, a large Condition per statement
//       could amplify a ~200 KB policy into a multi-hundred-KB SARIF and breach GitHub's
//       ~10 MB SARIF upload limit, SILENTLY DROPPING findings from the Security tab.
// So the block is neutralized RECURSIVELY (keys AND values markdown-inert) and bounded
// THREE ways: a per-leaf length cap, an AGGREGATE node/char budget (so many small
// entries cannot sum to hundreds of KB), and recursion DEPTH reusing validate.js
// MAX_DEPTH. Cycles are handled defensively (a JSON policy cannot contain one, but a
// synthetic caller could). On ANY breach the caller emits a bounded conditionSummary +
// conditionTruncated:true instead of the object - fail CLOSED on the Condition.
//
// NOTE: findingIdentity() hashes f.conditions via stableStringify for the
// partialFingerprint and is DELIBERATELY untouched by this path - that input is
// hash-only, never rendered, and changing it would auto-un-suppress every previously
// dismissed alert on every consumer repo.

// Per-leaf (value or key) length cap. Real condition keys/values are short; a rendered
// evidence leaf need not carry a multi-KB blob.
const MAX_CONDITION_LEAF_LEN = 256;
// Aggregate caps across the WHOLE condition block: max sanitized leaves+keys visited and
// max total sanitized characters. This is the amplification bound - many small entries
// cannot sum past it.
const MAX_CONDITION_NODES = 256;
const MAX_CONDITION_CHARS = 4096;
// Cap on the EMITTED conditionSummary fallback string (breach path). This bounds the
// string AS RENDERED, not merely its pre-escape length: inertLeaf caps the RAW length,
// but ASCII-punctuation backslash-escaping can up to ~double the output (a JSON summary
// is punctuation-dense), so inertLeaf(raw, N) alone could emit ~2N. inertSummary below
// hard-clamps the escaped output to this cap (+ a clean ellipsis) so the emitted summary
// honours the documented bound for ANY partial shape - flat-root or nested.
const MAX_CONDITION_SUMMARY_LEN = 480;

// Markdown-inert rendering of a SINGLE BARE leaf: a condition leaf/key, an evidence
// statementSid/role, a token in an action/resource list, or a top-level statementSid.
// The shared neutralizer for EVERY properties-bag string that is emitted un-wrapped (not
// inside a code span). Same treatment the analyzer-state message/note gets: strip C0/C1
// control chars + newlines AND the bidi/zero-width/format set (CONTROL_AND_FORMAT - so a
// token cannot be reordered or zero-width-hidden/split into a spoof), collapse whitespace,
// cap length, then backslash-escape EVERY ASCII-punctuation char so NO markdown construct
// (link/image/autolink/code span/HTML/emphasis) can form - and, incidentally, so a literal
// `__proto__`/`constructor` key can never survive as such (the underscores/letters are
// escaped, and the sanitized tree uses null-prototype objects regardless). Pure +
// deterministic.
// Exported for tests/s4-unicode-spoof.test.js: the strengthened superset invariant compares
// this leaf sanitizer's EFFECTIVE per-codepoint neutralization against the browser display
// neutralizer (neutralizeForDisplay), not merely the underlying regexes - so the CLI's
// whitespace-run collapse of the Zs class and the shared non-ASCII clamp are both in scope.
export function inertLeaf(value, maxLen) {
  let s = String(value);
  // S4 iteration 3: control/format strip THEN non-ASCII charset clamp (strong-RTL /
  // Zs homograph / homograph letter -> U+FFFD), before whitespace collapse + escape.
  s = s.replace(CONTROL_AND_FORMAT, ' ').replace(NON_ASCII_SPOOF, REPLACEMENT);
  s = s.replace(/\s+/g, ' ').trim();
  let truncated = false;
  if (s.length > maxLen) { s = s.slice(0, maxLen); truncated = true; }
  // Escape the (already length-bounded) content, THEN append a CLEAN ellipsis. Escaping
  // first keeps the cap bounded on the RAW length and avoids splitting a `\x` escape pair
  // mid-sequence; the appended `...` is left unescaped because a period forms no markdown
  // construct, so a truncated value still reads with a normal trailing ellipsis.
  s = s.replace(ASCII_PUNCT, '\\$&');
  return truncated ? `${s}...` : s;
}

// Markdown-inert summary of the sanitized-partial condition emitted on a breach, bounded
// AS RENDERED. inertLeaf(raw, N) caps the RAW pre-escape length; escaping can up to ~double
// it (a JSON summary is punctuation-dense), so inertLeaf alone can emit ~2N - contradicting
// the documented MAX_CONDITION_SUMMARY_LEN and the suite's `<= cap + ellipsis` invariant for
// a flat-root partial (a nested partial happens to collapse to "{}"). This hard-clamps the
// ESCAPED output to `cap` (+ a clean "..."), trimming a dangling trailing backslash first so
// a `\x` escape pair is never split. Bounded output for ANY partial shape. Pure + deterministic.
function inertSummary(raw, cap) {
  const inert = inertLeaf(raw, cap);
  if (inert.length <= cap) return inert;
  // Drop a lone (odd-count) trailing backslash so the slice never ends mid escape-pair, then
  // mark the elision. `\\` pairs (escaped backslashes) are complete and kept.
  const clipped = inert.slice(0, cap).replace(/\\+$/, (m) => (m.length % 2 ? m.slice(0, -1) : m));
  return `${clipped}...`;
}

// Recursively neutralize an evidence Condition. Returns { value, truncated }:
//   - value:     a sanitized copy (nested null-prototype objects / arrays / inert
//                strings) with EVERY key and leaf rendered markdown-inert, or a partial
//                copy when a bound was hit, or null when nothing survived;
//   - truncated: true iff any bound (depth / aggregate nodes / aggregate chars / cycle)
//                was hit, signalling the caller to emit a bounded summary instead.
// A single shared budget threads through the whole walk so the caps are AGGREGATE, not
// per-branch. Cycle-safe via a visited Set. Never throws.
function neutralizeCondition(root) {
  const budget = { nodes: 0, chars: 0, truncated: false, seen: new Set() };

  function walk(value, depth) {
    if (budget.truncated) return null;
    if (depth > LIMITS.MAX_DEPTH) { budget.truncated = true; return null; }
    if (value === null || value === undefined) return null;
    if (typeof value !== 'object') {
      const s = inertLeaf(value, MAX_CONDITION_LEAF_LEN);
      budget.nodes += 1;
      budget.chars += s.length;
      if (budget.nodes > MAX_CONDITION_NODES || budget.chars > MAX_CONDITION_CHARS) {
        budget.truncated = true;
        return null;
      }
      return s;
    }
    if (budget.seen.has(value)) { budget.truncated = true; return null; }
    budget.seen.add(value);
    // Charge the CONTAINER itself, not only its keys/leaves. An empty (or all-empty-child)
    // container serializes to "{}"/"[]" and costs bytes, yet an earlier walker charged only
    // the keys + scalar leaves - so an array/object of thousands of EMPTY containers summed
    // to ZERO against the node/char budget and slipped past the aggregate cap (an
    // amplification hole in the same class). Every container now costs one node + its two
    // bracket bytes, so N empty containers cost N nodes and trip the cap like any other
    // fan-out. Checked BEFORE recursing so the breach is caught at this level.
    budget.nodes += 1;
    budget.chars += 2;
    if (budget.nodes > MAX_CONDITION_NODES || budget.chars > MAX_CONDITION_CHARS) {
      budget.truncated = true;
      budget.seen.delete(value);
      return null;
    }
    let out;
    if (Array.isArray(value)) {
      out = [];
      for (const el of value) {
        const child = walk(el, depth + 1);
        if (budget.truncated) break;
        out.push(child);
      }
    } else {
      // Null-prototype output: a sanitized key that happens to spell a dangerous key
      // becomes a plain own property, never a prototype mutation. (validate.js already
      // rejects such keys upstream; this keeps the adapter safe for synthetic callers.)
      out = Object.create(null);
      for (const k of Object.keys(value)) {
        const safeKey = inertLeaf(k, MAX_CONDITION_LEAF_LEN);
        budget.nodes += 1;
        budget.chars += safeKey.length;
        if (budget.nodes > MAX_CONDITION_NODES || budget.chars > MAX_CONDITION_CHARS) {
          budget.truncated = true;
          break;
        }
        const child = walk(value[k], depth + 1);
        if (budget.truncated) break;
        out[safeKey] = child;
      }
    }
    budget.seen.delete(value);
    return out;
  }

  const value = walk(root, 0);
  return { value, truncated: budget.truncated };
}

// Max chars kept from an artifact URI. A URI is a location, NOT markdown-rendered prose
// (GitHub shows it as a file path, not markdown), so it is neutralized DIFFERENTLY from a
// message: C0/C1 control chars + newlines AND the bidi/zero-width/format set
// (CONTROL_AND_FORMAT) are STRIPPED - the controls can never legitimately appear in a
// path/URI, and the bidi/zero-width set would otherwise RTL-reorder or zero-width-hide a
// path segment so a hostile scanned-file name spoofs a benign one in the alert location -
// and the length is capped. Path punctuation (`/`, `.`) is PRESERVED (not escaped) so a
// legitimate repo-relative path is not mangled; markdown escaping is unnecessary here
// because the uri is not rendered as markdown.
const MAX_URI_LEN = 2048;
// Returns { uri, truncated }. When the sanitized URI exceeds MAX_URI_LEN it is sliced, but
// the location string is NEVER marked in place: appending an ellipsis/marker would corrupt
// the artifact-location path (breaking GitHub's file deep-link and possibly pointing at a
// nonexistent path). The `truncated` flag is surfaced SEPARATELY as properties.uriTruncated
// by the caller (locationFor), so the slice is visibly recorded without mutating the URI.
// The URI is deliberately excluded from findingIdentity, so this cannot churn a fingerprint.
function sanitizeUri(uri) {
  let s = String(uri);
  // S4 iteration 3: strip control/format, then clamp non-ASCII to U+FFFD so a strong-RTL /
  // homograph path segment cannot reorder or homograph-spoof the alert location.
  s = s.replace(CONTROL_AND_FORMAT, '').replace(NON_ASCII_SPOOF, REPLACEMENT);
  let truncated = false;
  // Measured AFTER neutralization: a URI long only because of now-stripped control chars is
  // not flagged; the flag tracks whether the actually-emitted path was cut.
  if (s.length > MAX_URI_LEN) { s = s.slice(0, MAX_URI_LEN); truncated = true; }
  return { uri: s, truncated };
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
    const ruleId = `analysis.${s && s.code != null ? String(s.code) : 'FAIL_CLOSED'}`;
    if (index.has(ruleId)) continue;
    index.set(ruleId, rules.length);
    rules.push(stateDescriptor(s));
  }

  return { rules, index };
}

// The reportingDescriptor for one analyzer-state CODE. Extracted so the security-critical
// contract (fixed error level, category analysis-state, NEVER a security-severity) is
// defined ONCE and reused by both the normal states and the synthetic truncation state -
// they can never drift apart into a shape a consumer could misread as a vulnerability.
function stateDescriptor(s) {
  const code = s && s.code != null ? String(s.code) : 'FAIL_CLOSED';
  const ruleId = `analysis.${code}`;
  const stateName = s && s.analysisState != null ? String(s.analysisState) : 'unknown';
  return {
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
}

// One analyzer-state RESULT row. Extracted (mirrors stateDescriptor) so the normal states
// and the synthetic truncation state share ONE definition: kind:'fail', level:'error',
// category analysis-state, NO security-severity, message through the sanitizeStateMessage
// sink, and a path rendered markdown-inert. The caller assigns ruleIndex.
function stateResultRow(s, uri) {
  const code = s && s.code != null ? String(s.code) : 'FAIL_CLOSED';
  const properties = {
    // NO security-severity here, by contract: an analyzer-state result is NOT a
    // vulnerability and must never be mistakable for one.
    category: 'analysis-state',
    failClosed: true,
    analysisState: s && s.analysisState != null ? String(s.analysisState) : 'unknown',
  };
  // SECURITY (S2-sarif-sanitize-all): an analyzer-state path can embed attacker-controlled
  // policy KEY NAMES, so it is rendered markdown-inert before it lands in a property a
  // consumer may display - never raw. (stateIdentity() hashes the RAW s.path separately for
  // the fingerprint; that hash-only input is untouched.)
  if (s && s.path != null) {
    const safePath = inertLeaf(s.path, MAX_STATE_MSG_LEN);
    if (safePath) properties.path = safePath;
  }
  // R5-uri-trunc: a sliced (over-length) artifact URI is recorded via a SEPARATE flag, never
  // by mutating the location string. Same treatment as the finding rows below.
  const { location, uriTruncated } = locationFor(uri);
  if (uriTruncated) properties.uriTruncated = true;
  return {
    ruleId: `analysis.${code}`,
    kind: 'fail',
    level: 'error',
    // SECURITY (S4-sarif-sid): the engine authors this message as free prose that can
    // interpolate attacker-controlled policy text. GitHub renders message.text as MARKDOWN,
    // so it MUST be neutralized here - the single chokepoint every analyzer-state message
    // flows through - not at each engine call site. See sanitizeStateMessage.
    message: { text: sanitizeStateMessage(s && s.message) },
    locations: [location],
    partialFingerprints: { [FINGERPRINT_KEY]: hashIdentity(stateIdentity(s)) },
    properties,
  };
}

// --- Document-level output budget (S2-sarif-sanitize-all, iteration 4) ---------
//
// The per-condition-block budget (MAX_CONDITION_NODES/CHARS in neutralizeCondition) and
// the per-field caps (inertTokenList, inertLeaf) each bound ONE evidence row. They are
// re-created FRESH for every row, so they never bound the SUM across a whole document. A
// within-limits policy (< validate.js MAX_BYTES, <= MAX_STATEMENTS) can still fan out to
// THOUSANDS of findings whose small-but-nonzero evidence rows sum past GitHub's ~10 MB
// SARIF upload cap - at which point GitHub SILENTLY DROPS every finding from the Security
// tab, a total fail-OPEN of the security signal (the story's stated document-level harm).
//
// So the builder threads ONE budget across ALL result rows and fails CLOSED when it is hit:
//   1. it stops attaching per-finding evidence (the amplifier), degrading to a bare-but-
//      PRESENT finding row - the finding, its severity, message and fingerprint survive;
//   2. if even bare rows would still breach, it stops emitting further finding rows and
//      records how many were elided; and
//   3. buildSarifLog then appends ONE truthful SARIF_OUTPUT_TRUNCATED analyzer-state result
//      (kind:fail, level:error, category analysis-state, NO security-severity) announcing
//      the truncation - so findings are TRUNCATED, never SILENTLY dropped.
// The ceiling is kept comfortably below GitHub's ~10 MB cap. This bounds the SARIF
// regardless of how many findings a within-limits policy produces.
const MAX_SARIF_BYTES = 8 * 1024 * 1024;
// Headroom reserved for the fixed document scaffold (schema, tool.driver + rules[], run
// properties) and the appended analyzer-state rows (including the truncation state), so the
// per-row budget alone can never consume the whole ceiling.
const SARIF_OVERHEAD_RESERVE = 512 * 1024;

// UTF-8 byte length of a string. The whole SARIF size budget is denominated in BYTES
// (MAX_SARIF_BYTES, GitHub's upload cap) - NOT UTF-16 code units. String.prototype.length
// UNDER-counts any multibyte content (a BMP CJK char is 1 code unit but 3 UTF-8 bytes; an
// accented Latin char 1 code unit but 2 bytes), so a within-limits multibyte fan-out could
// serialize PAST the byte ceiling while a .length-based estimate still read as fitting -
// the tool would then believe it fit and emit no truncation state. TextEncoder is a Web +
// Node global (no import, pure, deterministic); one shared instance avoids per-row churn.
const UTF8 = new TextEncoder();
function utf8Bytes(s) { return UTF8.encode(s).length; }

// A CONSERVATIVE over-estimate of a result row's contribution to the FINAL pretty-printed
// SARIF, in UTF-8 BYTES (the unit the budget names). buildSarifLog serializes with 2-space
// indentation and every result object lives at nesting depth 4 (runs[0].results[i]), so
// each line of a row carries >= 8 leading spaces beyond what JSON.stringify(row, null, 2)
// emits at depth 0. The row content is measured in real UTF-8 bytes (utf8Bytes, not
// .length, so multibyte fields are not under-counted); the indentation (ASCII spaces, 1
// byte each) and trailing separator are added as bytes too. Adding 8 bytes per line (an
// over-count) makes the SUMMED estimate always >= the real serialized byte size, so
// staying under the byte budget is GUARANTEED, not merely likely. Line count is taken over
// code units by scanning for '\n' (an ASCII code point, so the count is exact). Pure +
// deterministic (no clock, no randomness).
function estimateRowBytes(row) {
  const s = JSON.stringify(row, null, 2);
  let lines = 1;
  for (let i = 0; i < s.length; i += 1) if (s.charCodeAt(i) === 10) lines += 1;
  return utf8Bytes(s) + lines * 8 + 2;
}

// The synthetic analyzer-state describing a document-level truncation. Tool-authored (no
// attacker content); the count is deterministic. Routed through the SAME analyzer-state
// descriptor + row builders + sanitizeStateMessage sink as every other state, so it carries
// the load-bearing fail-closed shape by construction.
function truncationState(budget) {
  const elided = budget.elidedFindings;
  const findingNote = elided > 0
    ? `${elided} finding result${elided === 1 ? ' was' : 's were'} elided entirely; `
    : '';
  const evidenceNote = budget.evidenceElided
    ? 'per-finding evidence was omitted from some results; '
    : '';
  const stateNote = budget.elidedStates > 0
    ? `${budget.elidedStates} analyzer-state result${budget.elidedStates === 1 ? ' was' : 's were'} `
      + 'elided entirely; '
    : '';
  return {
    code: 'SARIF_OUTPUT_TRUNCATED',
    analysisState: 'output-truncated',
    message: 'SARIF output reached the safe size budget and was truncated to stay below the '
      + `code-scanning upload limit: ${findingNote}${evidenceNote}${stateNote}`
      + 'results were TRUNCATED, not cleared. Re-run the analyzer (the CLI JSON output has '
      + 'no such cap) to retrieve every result. This is an analyzer-state signal, not a '
      + 'vulnerability score.',
    path: null,
  };
}

// --- Result rows --------------------------------------------------------------

// Returns { location, uriTruncated }. The location's artifact-location URI is the sanitized-
// but-UNMODIFIED (never marker-appended) path; uriTruncated tells the caller to record a
// SEPARATE properties.uriTruncated flag so a slice is visible without corrupting the URI.
function locationFor(uri) {
  // SECURITY (S2-sarif-sanitize-all): the artifact URI can be attacker-influenced - in
  // the Action a fork PR names the scanned file, and a hostile name could carry control
  // chars / newlines into a SARIF location. Strip them (path punctuation is preserved so
  // a legitimate repo-relative path is not mangled). See sanitizeUri.
  const { uri: safeUri, truncated } = sanitizeUri(uri);
  return {
    location: { physicalLocation: { artifactLocation: { uri: safeUri } } },
    uriTruncated: truncated,
  };
}

// Build the two DISJOINT result groups. Security findings first (in engine order),
// then analyzer-state results (in scan order). The separation is the whole point of
// the fail-closed design and must survive any refactor.
//
// Returns { results, budget }. `budget` reports whether the DOCUMENT-level output cap was
// hit (see MAX_SARIF_BYTES): buildSarifLog reads it to append the truthful truncation
// state. Security findings are charged against the budget FIRST; the analyzer-state rows
// (the load-bearing fail-closed signal) are charged against the SAME budget AFTER findings,
// so they are preserved as far as the budget allows but can be TRUNCATED (with an announced
// SARIF_OUTPUT_TRUNCATED state) when their attacker-controlled, unbounded count would breach
// the cap - the class is bounded document-level and TYPE-AGNOSTICALLY, not per row type. The
// SARIF_OVERHEAD_RESERVE keeps room for the fixed scaffold, the bounded rules[] catalog, and
// the appended truncation state, so the fail-closed analysis-state category always survives.
function buildResults(result, uri, ruleIndex) {
  const out = [];
  const budget = {
    bytes: 0,
    // Ceiling for finding-row content; the reserve protects the fixed scaffold + the always-
    // emitted analyzer-state rows (including the appended truncation state).
    max: MAX_SARIF_BYTES - SARIF_OVERHEAD_RESERVE,
    evidenceStopped: false, // sticky: once tripped, no later finding carries evidence
    evidenceElided: false, // >=1 finding had its evidence dropped to fit
    elidedFindings: 0, // findings dropped ENTIRELY (even bare rows would breach)
    elidedStates: 0, // analyzer-state rows dropped ENTIRELY (would breach the budget)
    truncated: false,
  };

  const findings = result.findings || [];

  // DOCUMENT-level output cap (S2-sarif-sanitize-all, iteration 4). The per-block +
  // per-field caps bound ONE row; NONE of them bound the SUM across ALL rows, so a within-
  // limits policy fanning out to thousands of findings can still breach GitHub's ~10 MB
  // upload cap and get the WHOLE Security-tab signal silently dropped. Two ordered passes
  // fail CLOSED while preserving the MOST signal:
  //   Pass A builds every finding's BARE row (no evidence) and its evidence aside.
  //   Then evidence - the amplifier - is shed GLOBALLY FIRST (it is detail, not the finding)
  //   before any finding is dropped, so a finding is elided ENTIRELY only if even the bare
  //   rows overflow the budget. buildSarifLog then appends ONE truthful
  //   SARIF_OUTPUT_TRUNCATED analyzer-state result so anything trimmed is ANNOUNCED, never
  //   silently dropped (the exit code, owned by scan(), is unaffected either way).
  const built = [];
  for (const f of findings) {
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
    // SECURITY (S2/S4-sarif): the Sid is attacker-controlled and this property is emitted
    // BARE (not code-span-wrapped), so it is rendered MARKDOWN-INERT (inertLeaf: strip
    // control + bidi/zero-width, cap length, backslash-escape ASCII punctuation) - a
    // backtick-only strip would leave a live `[x](url)` / `<url>` here. Omit when nothing
    // printable survives rather than emit an empty token.
    if (f && f.statementSid != null) {
      const safeSid = inertLeaf(f.statementSid, MAX_SID_LEN);
      if (safeSid) properties.statementSid = safeSid;
    }
    // SECURITY + SURFACING (S2-R2-sarif-identity): a complement grant EMPTIES its positive
    // scope (see makeFinding) and stows the discriminating NotAction / NotResource carve-out
    // in excludedActions / excludedResources. That scope is now folded into the
    // partialFingerprint (findingIdentity) so distinct carve-outs no longer collide - but the
    // DISTINGUISHING evidence must also reach the human-facing SARIF, or a reviewer sees two
    // identical-looking DATA-EXFIL rows that differ only by an invisible hash. So the excluded
    // set is SURFACED in the properties bag. It is ATTACKER-CONTROLLED policy text (a fork PR
    // owns the whole policy JSON), same class as the Sid / action tokens the file was hardened
    // against, and it is emitted BARE (not code-span-wrapped), so it is routed through the SAME
    // inertTokenList as evidence actions/resources: EACH entry rendered markdown-inert
    // (control/bidi/zero-width stripped, non-ASCII clamped, ASCII-punctuation backslash-escaped
    // so no live `[x](url)` / `<url>` / image can form), the entry COUNT and AGGREGATE char
    // budget capped (a huge NotAction/NotResource array cannot amplify the SARIF), with a
    // truthful marker on truncation - NEVER a raw append. The FULL canonical set still rides
    // the fingerprint unaffected. Omitted when empty so non-complement rows are unchanged.
    if (f && Array.isArray(f.excludedActions) && f.excludedActions.length > 0) {
      properties.excludedActions = inertTokenList(f.excludedActions);
    }
    if (f && Array.isArray(f.excludedResources) && f.excludedResources.length > 0) {
      properties.excludedResources = inertTokenList(f.excludedResources);
    }

    // R5-uri-trunc: an over-length artifact URI is sliced but NOT marker-mutated (that would
    // corrupt GitHub's file deep-link); the slice is recorded via a SEPARATE properties flag.
    const { location, uriTruncated } = locationFor(uri);
    if (uriTruncated) properties.uriTruncated = true;
    const row = {
      ruleId: id,
      level: map.level,
      message: { text: findingMessage(f, result.family) },
      locations: [location],
      partialFingerprints: { [FINGERPRINT_KEY]: hashIdentity(findingIdentity(f, result.family)) },
      properties,
    };
    if (ruleIndex.has(id)) row.ruleIndex = ruleIndex.get(id);

    // fullCost includes evidence (natural key position preserved); bareCost is measured on a
    // shallow clone with evidence removed, so the REAL row is never reordered in the common
    // (no-truncation) case - existing byte-for-byte SARIF output is unchanged.
    const fullCost = estimateRowBytes(row);
    let bareCost = fullCost;
    if (evidence) {
      const bareClone = { ...row, properties: { ...properties } };
      delete bareClone.properties.evidence;
      bareCost = estimateRowBytes(bareClone);
    }
    built.push({ row, properties, hasEvidence: Boolean(evidence), fullCost, bareCost });
  }

  // How many findings fit at their BARE cost (in engine order). Findings are dropped only
  // when even bare rows overflow - the genuine extreme.
  let bareUsed = 0;
  let emitCount = built.length;
  for (let i = 0; i < built.length; i += 1) {
    if (bareUsed + built[i].bareCost > budget.max) { emitCount = i; break; }
    bareUsed += built[i].bareCost;
  }
  if (emitCount < built.length) {
    budget.elidedFindings = built.length - emitCount;
    budget.truncated = true;
  }

  // Spend the REMAINING budget on evidence, in order, until it is exhausted; thereafter
  // evidence is shed (sticky) and the row carries an explicit evidenceElided marker.
  let used = bareUsed;
  for (let i = 0; i < emitCount; i += 1) {
    const b = built[i];
    if (!b.hasEvidence) { out.push(b.row); continue; }
    if (!budget.evidenceStopped) {
      const evMarginal = b.fullCost - b.bareCost;
      if (used + evMarginal <= budget.max) {
        used += evMarginal; // keep this row's evidence (already attached)
      } else {
        budget.evidenceStopped = true;
      }
    }
    if (budget.evidenceStopped) {
      delete b.properties.evidence;
      b.properties.evidenceElided = true;
      budget.evidenceElided = true;
      budget.truncated = true;
    }
    out.push(b.row);
  }
  // Analyzer-state rows (S2-sarif-sanitize-all, iteration 5). These carry the load-bearing
  // fail-closed signal, but their COUNT is attacker-controlled and UNBOUNDED within validate()
  // limits: e.g. validate.findDuplicateKeys emits one DUPLICATE_JSON_KEY error PER duplicate
  // condition key (uncapped), and scan()->errorStates maps each 1:1 to a state; likewise the
  // per-statement fan-out in incompleteStatesFromCoverage (which rides on ok:TRUE results and
  // COEXISTS with real security findings). An earlier version emitted every state row here
  // WITHOUT charging the budget - so a within-limits policy (< MAX_BYTES, <= MAX_STATEMENTS)
  // could still sum thousands of state rows PAST GitHub's ~10 MB upload cap, at which point the
  // WHOLE SARIF is silently dropped and even the fail-closed block never reaches the Security
  // tab (a total fail-OPEN, strictly worse than a finding overflow because it announced nothing).
  //
  // So the state rows are charged against the SAME document byte budget as findings, at the
  // DOCUMENT level, TYPE-AGNOSTICALLY - the class is closed once, not per row type. Findings were
  // charged FIRST (above), so genuine security findings are preserved over voluminous states.
  // When a state row would breach the budget we STOP, count the elided states, and set
  // budget.truncated so buildSarifLog appends the truthful SARIF_OUTPUT_TRUNCATED analyzer-state
  // result. That truncation row is itself protected by SARIF_OVERHEAD_RESERVE (kept for the fixed
  // scaffold + rules[] catalog + the appended truncation state, all bounded), so the fail-closed
  // analysis-state CATEGORY always survives in the SARIF even in the extreme where every real
  // state row is elided - and the serialized SARIF can never exceed the cap regardless of how many
  // states a within-limits policy produces.
  const states = result.analysisStates || [];
  let stateEmit = 0;
  for (const s of states) {
    const row = stateResultRow(s, uri);
    const ruleId = row.ruleId;
    if (ruleIndex.has(ruleId)) row.ruleIndex = ruleIndex.get(ruleId);
    const cost = estimateRowBytes(row);
    if (used + cost > budget.max) break;
    used += cost;
    out.push(row);
    stateEmit += 1;
  }
  if (stateEmit < states.length) {
    budget.elidedStates = states.length - stateEmit;
    budget.truncated = true;
  }
  budget.bytes = used;

  return { results: out, budget };
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
  const { results, budget } = buildResults(res, uri, index);

  // DOCUMENT-level fail-closed (S2-sarif-sanitize-all, iteration 4): if buildResults hit the
  // output cap, append ONE truthful analyzer-state result announcing the truncation. It
  // reuses the same descriptor + row builders as every other state (kind:fail, level:error,
  // category analysis-state, NO security-severity), so it can never be misread as a
  // vulnerability. Emitted here - not in buildResults - because it must be ordered LAST
  // (after all real results) and needs a rule descriptor + index that may not yet exist.
  if (budget.truncated) {
    const st = truncationState(budget);
    const ruleId = `analysis.${st.code}`;
    if (!index.has(ruleId)) {
      index.set(ruleId, rules.length);
      rules.push(stateDescriptor(st));
    }
    const row = stateResultRow(st, uri);
    row.ruleIndex = index.get(ruleId);
    results.push(row);
  }

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
