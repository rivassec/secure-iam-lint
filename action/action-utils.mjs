// action-utils.mjs - tiny shared primitives for the GitHub Action (string/number guards,
// positive-int input coercion, UTF-8 byte length). Extracted from index.mjs
// (behavior-preserving; self-contained, no imports).

export function isNonEmptyString(v) {
  return typeof v === 'string' && v.trim().length > 0;
}

export function toCount(n) {
  return Number.isFinite(n) ? n : 0;
}

// Coerce a positive-integer input, defaulting when absent / non-numeric / non-integer /
// <= 0. A zero or negative ceiling is nonsensical (it would fail-closed on the very first
// file); such a value falls back to the sane default rather than bricking the Action.
export function positiveIntInput(raw, dflt) {
  if (!isNonEmptyString(raw)) return dflt;
  const n = Number(String(raw).trim());
  return Number.isInteger(n) && n > 0 ? n : dflt;
}

// UTF-8 byte length of a string, for the aggregate BYTE ceiling. TextEncoder is a Node +
// Web global (no import, pure, deterministic); String.prototype.length UNDER-counts
// multibyte content, so bytes - not UTF-16 code units - are what the ceiling measures. One
// shared instance avoids per-file churn.
const AGG_UTF8 = new TextEncoder();
export function utf8ByteLength(s) { return AGG_UTF8.encode(String(s)).length; }
