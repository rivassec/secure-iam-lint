// IAM Blast Radius - input validation + hostile-input guards (IAM-001).
//
// Analyzed policies are HOSTILE input (see docs/threat-model.md). This module
// is the first gate: it enforces resource limits BEFORE parse, rejects
// prototype-pollution keys, parses into null-prototype maps, and never throws
// an uncaught exception on any input.
//
// Public API:
//   validate(text) -> { ok: boolean, errors: Error[], raw: object|null }
// where each error is { code, message, path } and `raw` is the sanitized,
// null-prototype representation of the policy (only when ok === true).
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. Deterministic.

// --- Limits (exported so tests and callers can reference the exact values) ---

export const LIMITS = Object.freeze({
  // Max UTF-8 byte length of the raw input. 1 MiB is far larger than any real
  // IAM policy (AWS managed-policy hard cap is ~6 KB) yet cheap to reject.
  MAX_BYTES: 1024 * 1024,
  // Max JSON nesting depth. Real policies nest ~5-6 deep; 64 is generous.
  // Enforced BEFORE parse to avoid deep-recursion / stack-overflow DoS.
  MAX_DEPTH: 64,
  // Structural counts, enforced after a safe parse.
  MAX_STATEMENTS: 1000,
  MAX_ACTIONS: 10000,
  MAX_RESOURCES: 10000,
});

// Keys that enable prototype pollution. Rejected at ANY depth, as object keys.
const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

// --- Error helper ------------------------------------------------------------

function err(code, message, path) {
  return { code, message, path: path === undefined ? null : path };
}

// --- Depth pre-scan ----------------------------------------------------------
// Scan the raw text counting structural {/[ depth while respecting string
// literals and escapes. Returns the maximum depth seen, or throws a sentinel
// object if depth exceeds the cap (so we bail early, before JSON.parse).

function maxJsonDepth(text) {
  let depth = 0;
  let max = 0;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (ch === '\\') {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
    } else if (ch === '{' || ch === '[') {
      depth++;
      if (depth > max) max = depth;
      // Fail fast: no legitimate policy nests this deep.
      if (depth > LIMITS.MAX_DEPTH) return depth;
    } else if (ch === '}' || ch === ']') {
      if (depth > 0) depth--;
    }
  }
  return max;
}

// --- Sanitize walk -----------------------------------------------------------
// Rebuild the parsed value into a structure that uses null-prototype maps for
// every object, rejecting dangerous keys along the way. A visited set guards
// against pathological / circular structures (JSON text cannot produce cycles,
// but this keeps the walk total even if a non-JSON object is ever passed in).

function sanitize(value, path, errors, visited) {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (visited.has(value)) {
    errors.push(err('CIRCULAR', 'Circular reference detected in input.', path));
    return null;
  }
  visited.add(value);

  if (Array.isArray(value)) {
    const out = [];
    for (let i = 0; i < value.length; i++) {
      out.push(sanitize(value[i], `${path}[${i}]`, errors, visited));
      if (errors.length) return null;
    }
    visited.delete(value);
    return out;
  }

  const clean = Object.create(null);
  // getOwnPropertyNames surfaces a "__proto__" key when JSON.parse created it
  // as an own data property (which it does, via CreateDataProperty).
  const keys = Object.getOwnPropertyNames(value);
  for (const key of keys) {
    if (DANGEROUS_KEYS.has(key)) {
      errors.push(
        err(
          'DANGEROUS_KEY',
          `Rejected dangerous key "${key}" (prototype-pollution guard).`,
          path ? `${path}.${key}` : key,
        ),
      );
      return null;
    }
    clean[key] = sanitize(value[key], path ? `${path}.${key}` : key, errors, visited);
    if (errors.length) return null;
  }
  visited.delete(value);
  return clean;
}

// --- Structural count guards -------------------------------------------------

function countArrayOrString(v) {
  if (typeof v === 'string') return 1;
  if (Array.isArray(v)) return v.length;
  return 0;
}

function enforceCounts(raw, errors) {
  // raw is null-prototype; access via bracket notation is safe.
  const stmtRaw = raw['Statement'];
  let statements;
  if (Array.isArray(stmtRaw)) {
    statements = stmtRaw;
  } else if (stmtRaw && typeof stmtRaw === 'object') {
    statements = [stmtRaw];
  } else {
    // No countable Statement block; schema validation is the parser's job.
    return;
  }

  if (statements.length > LIMITS.MAX_STATEMENTS) {
    errors.push(
      err(
        'TOO_MANY_STATEMENTS',
        `Policy has ${statements.length} statements; limit is ${LIMITS.MAX_STATEMENTS}.`,
        'Statement',
      ),
    );
    return;
  }

  let actions = 0;
  let resources = 0;
  for (const s of statements) {
    if (!s || typeof s !== 'object' || Array.isArray(s)) continue;
    actions += countArrayOrString(s['Action']) + countArrayOrString(s['NotAction']);
    resources += countArrayOrString(s['Resource']) + countArrayOrString(s['NotResource']);
  }
  if (actions > LIMITS.MAX_ACTIONS) {
    errors.push(
      err('TOO_MANY_ACTIONS', `Policy has ${actions} actions; limit is ${LIMITS.MAX_ACTIONS}.`),
    );
  }
  if (resources > LIMITS.MAX_RESOURCES) {
    errors.push(
      err(
        'TOO_MANY_RESOURCES',
        `Policy has ${resources} resources; limit is ${LIMITS.MAX_RESOURCES}.`,
      ),
    );
  }
}

// --- Byte length -------------------------------------------------------------

function byteLength(text) {
  if (typeof TextEncoder === 'function') {
    return new TextEncoder().encode(text).length;
  }
  // Fallback (should not happen in Node >=11 or any modern browser): estimate
  // UTF-8 length from code points.
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      bytes += 4;
      i++; // surrogate pair
    } else bytes += 3;
  }
  return bytes;
}

// --- Public entry point ------------------------------------------------------

/**
 * Validate hostile IAM policy text before any downstream parsing/analysis.
 * Never throws: all failure modes are reported as structured errors.
 *
 * @param {string} text raw pasted/imported policy text
 * @returns {{ok: boolean, errors: Array<{code:string,message:string,path:?string}>, raw: (object|null)}}
 */
export function validate(text) {
  const errors = [];
  try {
    if (typeof text !== 'string') {
      errors.push(err('NOT_A_STRING', 'Input must be a string of policy text.'));
      return { ok: false, errors, raw: null };
    }

    if (text.trim().length === 0) {
      errors.push(err('EMPTY_INPUT', 'Input is empty.'));
      return { ok: false, errors, raw: null };
    }

    const bytes = byteLength(text);
    if (bytes > LIMITS.MAX_BYTES) {
      errors.push(
        err('TOO_LARGE', `Input is ${bytes} bytes; limit is ${LIMITS.MAX_BYTES} bytes.`),
      );
      return { ok: false, errors, raw: null };
    }

    // Depth guard BEFORE parse (threat-model T5).
    const depth = maxJsonDepth(text);
    if (depth > LIMITS.MAX_DEPTH) {
      errors.push(
        err('TOO_DEEP', `JSON nesting depth exceeds limit of ${LIMITS.MAX_DEPTH}.`),
      );
      return { ok: false, errors, raw: null };
    }

    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      errors.push(err('INVALID_JSON', 'Input is not valid JSON.'));
      return { ok: false, errors, raw: null };
    }

    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      errors.push(
        err('NOT_AN_OBJECT', 'Top-level policy must be a JSON object.'),
      );
      return { ok: false, errors, raw: null };
    }

    const raw = sanitize(parsed, '', errors, new WeakSet());
    if (errors.length) {
      return { ok: false, errors, raw: null };
    }

    enforceCounts(raw, errors);
    if (errors.length) {
      return { ok: false, errors, raw: null };
    }

    return { ok: true, errors, raw };
  } catch (e) {
    // Absolute backstop: no input may produce an uncaught exception.
    errors.push(err('INTERNAL', 'Validation failed unexpectedly.'));
    return { ok: false, errors, raw: null };
  }
}

export default validate;
