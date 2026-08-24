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

// --- Duplicate object-key scan (IAM-901) -------------------------------------
// JSON.parse silently applies last-key-wins for a repeated object key, so a
// statement like { "Action": "s3:GetObject", "Action": "iam:*" } parses to just
// { Action: "iam:*" } - the first grant vanishes and the analyzer would report on
// a policy that is NOT the one the author wrote (a security-relevant surprise,
// suite-2 test 44). JSON.parse cannot see the collision, so we detect it in the
// RAW TEXT with a minimal, non-recursive-into-strings JSON walk that tracks the
// set of keys seen WITHIN EACH object and records any repeat, with the object's
// JSON path so the UI can point at the duplicate.
//
// Only a repeat WITHIN THE SAME object is a collision; the same key name in two
// different objects/statements is legal and must not be flagged. Keys are
// compared AFTER decoding JSON string escapes, matching how JSON.parse would
// collide them (e.g. "Action" and "Action").
//
// The scan runs only after JSON.parse has already accepted the text and after
// the depth guard, so the input is known well-formed and shallower than
// MAX_DEPTH; the walk therefore cannot over-recurse or hit malformed tokens.
// Defensive all the same: it never throws (any surprise ends the scan and
// returns whatever was found so far).

function decodeJsonString(text, start) {
  // text[start] === '"'. Return { value, end } where end is the index just past
  // the closing quote. Decodes standard JSON escapes so key comparison matches
  // JSON.parse semantics.
  let out = '';
  let i = start + 1;
  const n = text.length;
  while (i < n) {
    const ch = text[i];
    if (ch === '"') {
      return { value: out, end: i + 1 };
    }
    if (ch === '\\') {
      const esc = text[i + 1];
      switch (esc) {
        case '"': out += '"'; i += 2; break;
        case '\\': out += '\\'; i += 2; break;
        case '/': out += '/'; i += 2; break;
        case 'b': out += '\b'; i += 2; break;
        case 'f': out += '\f'; i += 2; break;
        case 'n': out += '\n'; i += 2; break;
        case 'r': out += '\r'; i += 2; break;
        case 't': out += '\t'; i += 2; break;
        case 'u': {
          const hex = text.slice(i + 2, i + 6);
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
          break;
        }
        default:
          // Unknown escape (should not occur post-JSON.parse); copy literally.
          out += esc;
          i += 2;
      }
      continue;
    }
    out += ch;
    i++;
  }
  return { value: out, end: n };
}

function isWs(ch) {
  return ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r';
}

function findDuplicateKeys(text) {
  const dups = [];
  const n = text.length;
  let i = 0;

  function skipWs() {
    while (i < n && isWs(text[i])) i++;
  }

  // Advance past a primitive token (number / true / false / null) up to the next
  // structural character. Strings/objects/arrays are handled by parseValue.
  function skipPrimitive() {
    while (i < n) {
      const ch = text[i];
      if (ch === ',' || ch === '}' || ch === ']' || isWs(ch)) break;
      i++;
    }
  }

  function parseString() {
    const r = decodeJsonString(text, i);
    i = r.end;
    return r.value;
  }

  function parseValue(path) {
    skipWs();
    if (i >= n) return;
    const ch = text[i];
    if (ch === '{') {
      parseObject(path);
    } else if (ch === '[') {
      parseArray(path);
    } else if (ch === '"') {
      parseString();
    } else {
      skipPrimitive();
    }
  }

  function parseArray(path) {
    i++; // consume '['
    skipWs();
    if (text[i] === ']') { i++; return; }
    let idx = 0;
    while (i < n) {
      parseValue(`${path}[${idx}]`);
      idx++;
      skipWs();
      if (text[i] === ',') { i++; skipWs(); continue; }
      if (text[i] === ']') { i++; return; }
      return; // unexpected; bail (post-JSON.parse this cannot happen)
    }
  }

  function parseObject(path) {
    i++; // consume '{'
    skipWs();
    if (text[i] === '}') { i++; return; }
    const seen = new Set();
    while (i < n) {
      skipWs();
      if (text[i] !== '"') return; // unexpected
      const key = parseString();
      if (seen.has(key)) {
        dups.push({ key, path });
      } else {
        seen.add(key);
      }
      skipWs();
      if (text[i] !== ':') return; // unexpected
      i++; // consume ':'
      parseValue(path ? `${path}.${key}` : key);
      skipWs();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === '}') { i++; return; }
      return; // unexpected
    }
  }

  try {
    skipWs();
    parseValue('');
  } catch (e) {
    // Should be unreachable post-JSON.parse; fail safe by returning what we have.
  }
  return dups;
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

    // IAM-901: JSON.parse cannot see a duplicate object key (last-key-wins would
    // silently drop the first grant), so scan the RAW TEXT and BLOCK if any
    // object repeats a key. This fails closed - no findings/graph downstream -
    // because the parsed document is not the policy that was written. The
    // original text is left untouched (the caller still holds it) so the UI can
    // highlight the duplicate. Same key in DIFFERENT objects is legal and is not
    // flagged. Runs before schema/count guards so the block takes precedence.
    const duplicateKeys = findDuplicateKeys(text);
    if (duplicateKeys.length > 0) {
      for (const d of duplicateKeys) {
        const location = d.path ? d.path : '(top-level object)';
        errors.push(
          err(
            'DUPLICATE_JSON_KEY',
            `Duplicate key "${d.key}" in object at ${location}; ` +
              'JSON parsers keep only the last value, so a grant would be silently ' +
              'dropped. Remove the duplicate before analysis.',
            d.path ? `${d.path}.${d.key}` : d.key,
          ),
        );
      }
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
