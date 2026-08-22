// IAM Blast Radius - normalized IAM model (IAM-002).
//
// Third stage of the pipeline (see docs/architecture.md data-flow):
//   text -> validate() -> raw -> parse() -> model()
//
// buildModel() turns the tolerant raw statements from parse() into a strict,
// normalized, deeply-FROZEN model that the rest of the engine (evaluator,
// rules, escalation, graph) can rely on without re-checking shapes:
//
//   - Action / NotAction / Resource / NotResource are always string arrays.
//   - A scalar string is promoted to a one-element array.
//   - Effect is exactly "Allow" or "Deny".
//   - Sid, Condition, Principal are normalized to stable shapes (null when
//     absent).
//   - Statement order and 0-based index are preserved.
//
// Analyzed policies are HOSTILE input (docs/threat-model.md). This module:
//   - never throws (all failure modes are structured errors);
//   - rejects prototype-pollution keys in Condition/Principal maps even though
//     validate() already strips them (defense in depth if called standalone);
//   - builds only fresh objects with keys it controls or has re-checked.
//
// Public API:
//   buildModel(raw)      -> { ok, errors[], model|null }   (raw from validate)
//   modelFromText(text)  -> { ok, errors[], model|null }   (full pipeline)
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. Deterministic.

import { validate } from './validate.js';
import { parse } from './parse.js';

// Prototype-pollution guard, mirrored from validate.js so this module is safe
// even if a caller hands it raw that did not pass through validate().
const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

// AWS effect values are case-sensitive.
const VALID_EFFECTS = new Set(['Allow', 'Deny']);

function err(code, message, path) {
  return { code, message, path: path === undefined ? null : path };
}

// --- Deep freeze -------------------------------------------------------------
// Freeze the finished model so downstream stages cannot mutate it (invariant:
// deterministic engine; same input -> same model, stable across consumers).

function deepFreeze(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Object.isFrozen(value)) return value;
  Object.freeze(value);
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

// --- Scalar/array normalization ----------------------------------------------
// Action/NotAction/Resource/NotResource accept a string or an array of
// strings. Normalize to a fresh string array. Returns { ok, values, error }.

function toStringArray(value, field, path) {
  if (value === undefined) {
    return { ok: true, values: [] };
  }
  if (typeof value === 'string') {
    return { ok: true, values: [value] };
  }
  if (Array.isArray(value)) {
    const values = [];
    for (let i = 0; i < value.length; i++) {
      if (typeof value[i] !== 'string') {
        return {
          ok: false,
          error: err(
            'INVALID_ELEMENT_TYPE',
            `${field} array element ${i} must be a string.`,
            `${path}.${field}[${i}]`,
          ),
        };
      }
      values.push(value[i]);
    }
    return { ok: true, values };
  }
  return {
    ok: false,
    error: err(
      'INVALID_FIELD_TYPE',
      `${field} must be a string or an array of strings.`,
      `${path}.${field}`,
    ),
  };
}

// --- Condition normalization -------------------------------------------------
// Condition is an object of { operator: { key: value | [values] } }. We keep it
// structurally intact (fresh copy, dangerous keys re-rejected) without trying
// to interpret operator semantics here (that is the evaluator's job).

function normalizeCondition(value, errors, path) {
  if (value === undefined) return null;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    errors.push(
      err('INVALID_CONDITION', 'Condition must be an object.', `${path}.Condition`),
    );
    return null;
  }
  return copyGuarded(value, errors, `${path}.Condition`);
}

// Recursively copy a plain data value into fresh objects/arrays, rejecting
// prototype-pollution keys. Strings/numbers/booleans/null pass through.
function copyGuarded(value, errors, path) {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    const out = [];
    for (let i = 0; i < value.length; i++) {
      out.push(copyGuarded(value[i], errors, `${path}[${i}]`));
    }
    return out;
  }
  const out = {};
  for (const key of Object.getOwnPropertyNames(value)) {
    if (DANGEROUS_KEYS.has(key)) {
      errors.push(
        err(
          'DANGEROUS_KEY',
          `Rejected dangerous key "${key}" (prototype-pollution guard).`,
          `${path}.${key}`,
        ),
      );
      continue;
    }
    out[key] = copyGuarded(value[key], errors, `${path}.${key}`);
  }
  return out;
}

// --- Principal normalization -------------------------------------------------
// Principal may be the wildcard string "*" or an object keyed by type
// (AWS/Service/Federated/CanonicalUser), each value a string or string array.
// Normalized shape:
//   null                                        (absent)
//   { anyPrincipal: true,  byType: {} }         ("*")
//   { anyPrincipal: false, byType: { AWS: [...], Service: [...] } }

function normalizePrincipal(value, errors, path) {
  if (value === undefined) return null;
  if (value === '*') {
    return { anyPrincipal: true, byType: {} };
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    errors.push(
      err(
        'INVALID_PRINCIPAL',
        'Principal must be "*" or an object keyed by principal type.',
        `${path}.Principal`,
      ),
    );
    return null;
  }
  const byType = {};
  for (const key of Object.getOwnPropertyNames(value)) {
    if (DANGEROUS_KEYS.has(key)) {
      errors.push(
        err(
          'DANGEROUS_KEY',
          `Rejected dangerous key "${key}" (prototype-pollution guard).`,
          `${path}.Principal.${key}`,
        ),
      );
      continue;
    }
    const arr = toStringArray(value[key], key, `${path}.Principal`);
    if (!arr.ok) {
      errors.push(arr.error);
      continue;
    }
    byType[key] = arr.values;
  }
  return { anyPrincipal: false, byType };
}

// --- Single statement normalization ------------------------------------------

function normalizeStatement(stmt, index, errors) {
  const path = `Statement[${index}]`;

  if (stmt === null || typeof stmt !== 'object' || Array.isArray(stmt)) {
    errors.push(err('INVALID_STATEMENT', 'Statement must be an object.', path));
    return null;
  }

  const before = errors.length;

  // Effect (required, exactly Allow/Deny).
  const effect = stmt['Effect'];
  if (typeof effect !== 'string' || !VALID_EFFECTS.has(effect)) {
    errors.push(
      err('INVALID_EFFECT', 'Effect must be exactly "Allow" or "Deny".', `${path}.Effect`),
    );
  }

  // Sid (optional string).
  let sid = null;
  if (stmt['Sid'] !== undefined) {
    if (typeof stmt['Sid'] === 'string') {
      sid = stmt['Sid'];
    } else {
      errors.push(err('INVALID_SID', 'Sid must be a string.', `${path}.Sid`));
    }
  }

  // Action / NotAction: exactly one family must be present.
  const hasAction = stmt['Action'] !== undefined;
  const hasNotAction = stmt['NotAction'] !== undefined;
  if (hasAction && hasNotAction) {
    errors.push(
      err(
        'ACTION_AND_NOTACTION',
        'A statement may not contain both Action and NotAction.',
        path,
      ),
    );
  } else if (!hasAction && !hasNotAction) {
    errors.push(
      err('MISSING_ACTION', 'Statement must contain Action or NotAction.', path),
    );
  }
  const actions = collect(toStringArray(stmt['Action'], 'Action', path), errors);
  const notActions = collect(toStringArray(stmt['NotAction'], 'NotAction', path), errors);

  // Resource / NotResource: at most one family. Absence is tolerated (some
  // contexts imply the resource); default to empty arrays.
  const hasResource = stmt['Resource'] !== undefined;
  const hasNotResource = stmt['NotResource'] !== undefined;
  if (hasResource && hasNotResource) {
    errors.push(
      err(
        'RESOURCE_AND_NOTRESOURCE',
        'A statement may not contain both Resource and NotResource.',
        path,
      ),
    );
  }
  const resources = collect(toStringArray(stmt['Resource'], 'Resource', path), errors);
  const notResources = collect(
    toStringArray(stmt['NotResource'], 'NotResource', path),
    errors,
  );

  const condition = normalizeCondition(stmt['Condition'], errors, path);
  const principal = normalizePrincipal(stmt['Principal'], errors, path);

  if (errors.length !== before) {
    // This statement had at least one schema error; do not emit a half-built
    // normalized statement that downstream code might trust.
    return null;
  }

  return {
    index,
    sid,
    effect,
    actions,
    notActions,
    resources,
    notResources,
    condition,
    principal,
  };
}

// Push a toStringArray error (if any) and return the values array.
function collect(result, errors) {
  if (!result.ok) {
    errors.push(result.error);
    return [];
  }
  return result.values;
}

// --- Public entry points -----------------------------------------------------

/**
 * Build a normalized, frozen model from a validated policy object.
 * Never throws.
 *
 * @param {object} raw sanitized null-prototype policy object (from validate())
 * @returns {{ok:boolean, errors:Array<{code:string,message:string,path:?string}>,
 *            model:(object|null)}}
 */
export function buildModel(raw) {
  const errors = [];
  try {
    const parsed = parse(raw);
    if (!parsed.ok) {
      return { ok: false, errors: parsed.errors, model: null };
    }

    const statements = [];
    for (let i = 0; i < parsed.statements.length; i++) {
      const normalized = normalizeStatement(parsed.statements[i], i, errors);
      if (normalized !== null) statements.push(normalized);
    }

    if (errors.length) {
      return { ok: false, errors, model: null };
    }

    const model = deepFreeze({
      version: parsed.version,
      id: parsed.id,
      statements,
    });

    return { ok: true, errors, model };
  } catch (e) {
    // Absolute backstop: no input may produce an uncaught exception.
    errors.push(err('INTERNAL', 'Model construction failed unexpectedly.'));
    return { ok: false, errors, model: null };
  }
}

/**
 * Convenience: run the full text -> validate -> parse -> model pipeline.
 * Never throws.
 *
 * @param {string} text raw pasted/imported policy text
 * @returns {{ok:boolean, errors:Array<{code:string,message:string,path:?string}>,
 *            model:(object|null)}}
 */
export function modelFromText(text) {
  const v = validate(text);
  if (!v.ok) {
    return { ok: false, errors: v.errors, model: null };
  }
  return buildModel(v.raw);
}

export default buildModel;
