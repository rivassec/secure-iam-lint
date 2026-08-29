// IAM Blast Radius - the invisible / reordering format-control spoof class
// (S4-unicode-spoof, threat-model T1/T6/T8), defined ONCE for the whole engine.
//
// A policy-derived value (Sid, ARN, action, condition key/value, Principal) is
// HOSTILE input. It can carry INVISIBLE or REORDERING format-control code points:
//   - bidi embeddings / overrides / isolates  U+202A-202E, U+2066-2069
//   - the zero-width set + bidi marks          U+200B-200F
//   - the Arabic letter mark                   U+061C
//   - the word-joiner / invisible-operator /   U+2060-206F
//     deprecated-format block
//   - the byte-order mark / ZW no-break space  U+FEFF
//   - SOFT HYPHEN and every other format char  (the rest of \p{Cf})
//   - variation selectors, Hangul fillers, CGJ (\p{Default_Ignorable_Code_Point})
//   - the C0/C1 control block                  (\p{Cc}: VT/FF/ESC/DEL/...)
//   - LINE / PARAGRAPH SEPARATOR               U+2028 / U+2029
// These occupy no width or reorder their neighbours, so wherever a policy value
// reaches a HUMAN-FACING TRUST SURFACE - the rendered findings table / SVG graph
// (the reviewer's PR-approval trust signal on fork-PR content), a downloaded .md/
// .json/SARIF report - it can display a benign-looking grant that differs from
// the real policy (a Trojan-Source visual spoof). textContent gives NO protection:
// the browser still applies the Unicode bidi algorithm to a text node.
//
// TWO classes, because the spoof class is neutralized at TWO kinds of boundary with
// DIFFERENT correctness requirements:
//
// 1. INVISIBLE_SPOOF - the DISPLAY class (broad). Everything invisible / reordering /
//    control that must NEVER reach a human trust surface or a downloaded artifact.
//    Applied at every DISPLAY / EXPORT sink (report.js JSON + Markdown, app.js DOM
//    sanitizeTree, engine/render-graph.js SVG labels). Matched by Unicode PROPERTY,
//    never a hand-enumerated range (a range fails open on the next spelling - the
//    exact regress the CLI SARIF sink hit repeatedly):
//      \p{Cc}                            - every C0 (0x00-0x1F) + DEL + C1 (0x7F-0x9F)
//                                          control (VT/FF/ESC break a line, inject
//                                          ANSI, or land raw in a downloaded .json).
//      \p{Cf}                            - every format char (bidi/zw/mark/BOM/ALM/...)
//      \p{Default_Ignorable_Code_Point}  - the Unicode property for "renders as nothing
//                                          when unsupported"; subsumes variation
//                                          selectors, Hangul fillers, CGJ, the U+2060-
//                                          206F block, and any FUTURE assignment.
//      U+2028 LINE SEP (Zl) / U+2029 PARA SEP (Zp) - invisible but FORCE a line-break
//                                          text reorder (a hostile Sid `ReadOnlyAudit
//                                          <U+2028>iamFullAdmin` wraps the dangerous
//                                          half to a new line in an HTML findings cell -
//                                          Trojan-Source). Neither is Cc/Cf/default-
//                                          ignorable, so both MUST be named.
//      U+2800  BRAILLE PATTERN BLANK      - blank width, category So, matched by none of
//                                          the properties above; named explicitly.
//    This MUST be a SUPERSET of every leaf sink's own class (cli/sarif.mjs
//    CONTROL_AND_FORMAT), enforced by tests/s4-unicode-spoof.test.js - so the browser
//    JSON/DOM output surface can never be MORE permissive than the CLI SARIF surface.
//
// 2. MODEL_NORMALIZE_SPOOF - the NORMALIZATION class (narrow). The subset removed from
//    a policy value BEFORE analysis. It strips ONLY \p{Cf} + \p{Default_Ignorable_Code_
//    Point} + the Braille blank: code points with NO legitimate meaning in a policy
//    value AND no CANONICALIZATION effect - removing a zero-width space from
//    `arn:aws<ZWSP>:...` or de-obfuscating a `__pro<ZWSP>to__` key is pure de-spoofing
//    that only ever makes a value MORE recognizable as its true self.
//    It deliberately does NOT strip \p{Cc} controls or the U+2028/U+2029 separators,
//    because those are how a MALFORMED / NON-CANONICAL policy value announces itself to
//    the analysis. A TAB or line separator embedded in an ARN partition/account token
//    must ride into the model INTACT so the engine judges the ARN UNMODELABLE and fails
//    CLOSED (PassRole viability -> UNKNOWN -> scan exit 3) - NOT get silently "cleaned"
//    into a canonical ARN and then confidently (mis)resolved, which for a cross-account
//    spelling could demote critical->medium and slip under the exit gate to a fail-OPEN
//    CLEAN (regression: passrole-noncanonical-arn-spelling). The DISPLAY class re-strips
//    the broad set, so these controls are still neutralized before any value reaches a
//    human trust surface or a downloaded report - defense in depth, no leak.
//
// Neither INVISIBLE_SPOOF nor MODEL_NORMALIZE_SPOOF touches strong-directional LETTERS
// (Hebrew \p{Lo}, Arabic letters) - by design, because those two classes close ONLY the
// FORMAT-CONTROL mechanism of the visual spoof. That is NOT the whole class: see the
// NON_ASCII_SPOOF section below (S4-unicode-spoof iteration 3) for the OTHER bidi
// Trojan-Source mechanism - strong-RTL letters + homograph SPACES + homograph LETTERS -
// closed at the DISPLAY / EXPORT sinks by an ASCII allowlist, NOT here. The `u` flag is
// REQUIRED for the \p{...} escapes. A leading BOM is a DECODE concern (validate.js strips
// exactly one leading U+FEFF before JSON.parse); these classes strip U+FEFF only as a
// spoof code point EMBEDDED inside a parsed string value, where it has no legitimate
// meaning.
//
// WHICH SURFACES NEUTRALIZE (the display-safe contract). The DISPLAY / EXPORT sinks that
// run values through neutralizeForDisplay / sanitizeTree are: the browser DOM findings
// table (app.js), the SVG graph labels (render-graph.js), the Markdown export and the SARIF
// export (report.js + cli/sarif.mjs). The CLI `--format json` plain-JSON output is the
// DELIBERATE exception and is NOT in that list: it is a BYTE-FAITHFUL machine artifact, not
// a human display surface, so it emits engine strings verbatim (neutralizing them would
// corrupt the fingerprint/ARN/action bytes downstream tooling consumes). Hostile Unicode
// rides through that JSON INERT (data in a JSON string - never executed, never interpolated
// into a page); the residual risk is purely visual and only if a human treats raw
// `cat report.json` as a display surface, which is why the docs route humans to
// `--format sarif`. See docs/threat-model.md (T6 output-surface neutralization contract).
//
// Pure, deterministic, browser-safe (no node: imports, no DOM, no network).

export const INVISIBLE_SPOOF =
  /[\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}\u2028\u2029\u2800]/gu;

export const MODEL_NORMALIZE_SPOOF =
  /[\p{Cf}\p{Default_Ignorable_Code_Point}⠀]/gu;

// 3. NON_ASCII_SPOOF - the CHARSET class for DISPLAY / EXPORT sinks (S4-unicode-spoof,
//    iteration 3). The format-control classes above close the INVISIBLE / control
//    mechanism of the spoof, but Trojan-Source has a SECOND, code-point-free mechanism: a
//    STRONG-RTL letter (Hebrew, Arabic, N'Ko, Adlam, Thaana, ... - the Unicode Bidi_Class
//    R / AL letters) makes the Unicode Bidi Algorithm REORDER the neutral / numeric
//    characters next to it, so `Read<heb>Only` can DISPLAY in a different order than it is
//    stored - a visible grant differing from the real policy - with NO format-control code
//    point at all (CVE-2021-42574). The same surface also admits homograph SPACES (the
//    \p{Zs} class - U+00A0, U+2000-200A, U+202F, U+205F, U+3000, U+1680, none of them
//    Cc/Cf) and homograph LETTERS (a Cyrillic 'a' U+0430 for Latin 'a').
//
//    Enumerating "the RTL scripts" or "the Zs spaces" is the exact enumeration trap the
//    fail-open hunter reopens on the NEXT script / space / homograph (JS regex has no
//    \p{Bidi_Class=R}, and Unicode keeps adding RTL scripts). So the class is closed
//    POSITIVELY by the AWS grammar's charset, not negatively by a blocklist: every policy-
//    derived TOKEN (Sid, Action, ARN, Principal, Condition key/value) is ASCII per the AWS
//    grammar, so ANY code point outside 7-bit ASCII in a value bound for a HUMAN trust
//    surface is a spoof vector and is neutralized. An allowlist cannot fail open on a
//    "next spelling" - there is no un-enumerated RTL script or Zs space it misses.
//
//    Neutralized by REPLACEMENT with U+FFFD (not deletion): the tampering shows as a
//    visible replacement glyph on the trust surface (honest - a reviewer sees a value was
//    not clean ASCII) rather than being silently removed, and U+FFFD is itself bidi-
//    neutral (Bidi_Class ON), so it triggers no reordering and is not Cc/Cf/Zs/default-
//    ignorable. INVISIBLE_SPOOF is applied FIRST (removing the invisible/control set,
//    including its non-ASCII members), so only VISIBLE non-ASCII survives to be replaced.
//
//    Applied ONLY at the DISPLAY / EXPORT sinks (report.js MD+JSON, app.js DOM, render-
//    graph.js SVG, and - via this same shared class imported there - cli/sarif.mjs),
//    NEVER at the model boundary: the analysis still sees the raw token (so findings +
//    fail-closed viability + S2 partialFingerprints are byte-for-byte unchanged), and only
//    the human-facing PROJECTION is charset-clamped. The CLI leaf sanitizers strip the
//    same class, so the browser JSON/DOM surface is never MORE permissive than CLI SARIF
//    (the superset/parity invariant, pinned EFFECTIVELY - not just at the regex level - by
//    tests/s4-unicode-spoof.test.js).
export const REPLACEMENT = '�';
export const NON_ASCII_SPOOF = /[^\x00-\x7F]/gu;

// DISPLAY sink neutralizer (broad, format-control only). Remove (not space-replace) the
// invisible/reordering spoof class from a string bound for a human trust surface or a
// downloaded artifact. Removal is correct: these code points have no legitimate rendering
// in a policy-derived value, and a replacement space would only make the spoof noisier.
// NOTE: this is the FORMAT-CONTROL half of the display neutralization ONLY. The full
// display sinks call neutralizeForDisplay (below), which layers the NON_ASCII_SPOOF
// charset clamp on top to also close the strong-RTL / homograph mechanism.
export function stripFormatControls(value) {
  return String(value).replace(INVISIBLE_SPOOF, '');
}

// The FULL DISPLAY / EXPORT sink neutralizer (S4-unicode-spoof). Closes BOTH visual-spoof
// mechanisms for a policy-derived value bound for a human trust surface / downloaded
// artifact: (1) removes the invisible/reordering FORMAT-CONTROL class (INVISIBLE_SPOOF),
// then (2) replaces every remaining VISIBLE non-ASCII code point with U+FFFD (NON_ASCII_
// SPOOF) so a strong-RTL letter cannot bidi-reorder its neighbours, a \p{Zs} homograph
// space cannot masquerade as ASCII whitespace, and a homograph letter cannot masquerade as
// ASCII. Order matters: strip the invisible set first, so its non-ASCII members (bidi
// controls, BOM, ...) are REMOVED, not turned into a visible U+FFFD. Pure + deterministic.
// This is the single chokepoint every browser display/export sink uses; cli/sarif.mjs's
// leaf sanitizers apply the SAME two classes so the two surfaces stay in parity.
export function neutralizeForDisplay(value) {
  return String(value)
    .replace(INVISIBLE_SPOOF, '')
    .replace(NON_ASCII_SPOOF, REPLACEMENT);
}

// MODEL-normalization neutralizer (narrow). De-spoofs a policy value as it ENTERS the
// model - strips only the zero-width / bidi / default-ignorable set, and PRESERVES
// \p{Cc} controls + U+2028/U+2029 so a malformed value stays malformed for the analysis
// (fail closed). See the class comment above.
export function stripModelSpoof(value) {
  return String(value).replace(MODEL_NORMALIZE_SPOOF, '');
}

// Deep-copy a JSON-serializable value for DISPLAY / EXPORT, neutralizing the FULL spoof
// class (format-control removal + non-ASCII charset clamp, via neutralizeForDisplay) on
// every string VALUE and every object KEY. Keys must be neutralized too: a hostile
// Condition operator/key rides through the normalized model as an OBJECT KEY, and the
// model rides into exports and the display sanitizer - a value-only pass would leave that
// spelling of the class open. Fresh objects only (never mutates a frozen input); non-
// string primitives pass through untouched. O(n) over an already size-capped tree
// (validate.js input limits). Deterministic.
const SANITIZE_DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export function sanitizeTree(value) {
  if (typeof value === 'string') return neutralizeForDisplay(value);
  if (Array.isArray(value)) return value.map(sanitizeTree);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value)) {
      // Defense in depth (review finding E2): the analyzed-policy pipeline rejects
      // __proto__/constructor/prototype long before this display sanitizer, but a future
      // caller could hand sanitizeTree() a raw JSON.parse'd object that skipped validate.js.
      // Never reparent the output via a dangerous key.
      //
      // Stage-11 #8: neutralize the key BEFORE the blocklist check. Checking the RAW
      // key let a format-control-spoofed twin (`__pro<U+200B>to__`) pass - it is not
      // literally "__proto__" - and neutralizeForDisplay() then collapsed it back to
      // "__proto__", reparenting the output (or dropping the value). Test the CLEANED
      // key, the same strip-before-check ordering the model boundary uses.
      const cleanKey = neutralizeForDisplay(key);
      if (SANITIZE_DANGEROUS_KEYS.has(cleanKey)) continue;
      out[cleanKey] = sanitizeTree(value[key]);
    }
    return out;
  }
  return value;
}

export default {
  INVISIBLE_SPOOF,
  MODEL_NORMALIZE_SPOOF,
  NON_ASCII_SPOOF,
  REPLACEMENT,
  stripFormatControls,
  neutralizeForDisplay,
  stripModelSpoof,
  sanitizeTree,
};
