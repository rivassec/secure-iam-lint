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
import { stripModelSpoof } from './format-control.js';

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

// S4-unicode-spoof + Stage-11 RC-A: strip the narrow spoof class and RECORD when
// doing so CHANGED the token. `stripModelSpoof` is a no-op on valid (alphanumeric)
// AWS tokens, so a change means the source carried an invisible/reordering code
// point - i.e. the token was tampered. We still return the CLEANED value (display
// stays legible, S4 intact), but the caller's `spoof` accumulator flips so the
// verdict layer refuses to TRUST the canonicalized token. This closes the fail-OPEN
// where a de-spoofed Deny/NotAction/condition-key is AWS-inert (AWS matches the
// literal requested token against the pattern that still carries the code point and
// does NOT match) yet the linter credits it as coverage and reads CLEAN.
function despoof(value, spoof) {
  const stripped = stripModelSpoof(value);
  if (spoof && stripped !== value) spoof.hit = true;
  return stripped;
}

// Stage-13 EFO-1: an AWS action namespace is strictly ASCII (`service:Action`, where
// both halves are drawn from [A-Za-z0-9] plus `:_*?-` and policy variables `${...}`).
// A code point > U+007F therefore cannot belong to a real AWS action. It matters
// because the case-insensitive action matcher lowercases via JS .toLowerCase(), which
// Unicode-case-FOLDS some non-ASCII LETTERS onto ASCII (U+212A KELVIN SIGN -> 'k',
// among others) - a channel the stripModelSpoof accumulator does not see (those code
// points are letters, not the invisible/reordering class it strips). At real AWS the
// token is inert (ASCII-only case-insensitive matching never folds U+212A onto 'K'),
// so a non-ASCII Deny/NotAction is AWS-inert yet the folded matcher would credit it as
// a guardrail (fail OPEN), and a non-ASCII Allow action would silently match no
// detector (fail OPEN mirror). Treat any non-ASCII action token as a canonicalization
// event that flips the spoof accumulator, exactly like a de-spoofed token - fail
// closed (incomplete), never a bare CLEAN.
const NON_ASCII_RE = /[^\x00-\x7F]/;
function actionsHaveNonAscii(values) {
  for (const v of values) {
    if (NON_ASCII_RE.test(String(v))) return true;
  }
  return false;
}

function toStringArray(value, field, path, spoof) {
  if (value === undefined) {
    return { ok: true, values: [] };
  }
  if (typeof value === 'string') {
    // S4-unicode-spoof: normalization boundary. Strip the NARROW model class
    // (stripModelSpoof: zero-width / bidi / default-ignorable) as the string enters
    // the model. The narrow class PRESERVES \p{Cc} controls + U+2028/U+2029 on
    // purpose: a control/separator in an ARN keeps the value non-canonical so
    // viability fails CLOSED (UNKNOWN), rather than being "cleaned" into a canonical
    // ARN and mis-resolved. Display sinks re-strip the broad class, so nothing
    // invisible reaches a human trust surface (format-control.js). Stage-11 RC-A: a
    // canonicalization is recorded via `spoof` so the verdict never TRUSTS a token
    // that only exists after de-spoofing (fail closed, not a bare CLEAN).
    return { ok: true, values: [despoof(value, spoof)] };
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
      values.push(despoof(value[i], spoof));
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

function normalizeCondition(value, errors, path, spoof) {
  if (value === undefined) return null;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    errors.push(
      err('INVALID_CONDITION', 'Condition must be an object.', `${path}.Condition`),
    );
    return null;
  }
  return copyGuarded(value, errors, `${path}.Condition`, spoof);
}

// Recursively copy a plain data value into fresh objects/arrays, rejecting
// prototype-pollution keys. Strings/numbers/booleans/null pass through.
function copyGuarded(value, errors, path, spoof) {
  // S4-unicode-spoof: normalization boundary. A Condition carries attacker-
  // controlled OBJECT KEYS (operators, condition keys) and string VALUES. Strip the
  // invisible/reordering spoof class from both. The key is stripped BEFORE the
  // dangerous-key check so an obfuscated `__pro<ZWSP>to__` collapses to `__proto__`
  // and is still rejected (closes a would-be prototype-pollution fail-open); it is
  // stripped BEFORE recursion so nested keys are de-spoofed too. Stage-11 RC-A: a
  // stripped key/value that CHANGED sets `spoof.hit` so a de-spoofed condition KEY
  // can never be credited as a modeled guardrail that flips exit 3 -> clean pass.
  if (value === null) return value;
  if (typeof value === 'string') return despoof(value, spoof);
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    const out = [];
    for (let i = 0; i < value.length; i++) {
      out.push(copyGuarded(value[i], errors, `${path}[${i}]`, spoof));
    }
    return out;
  }
  const out = {};
  for (const rawKey of Object.getOwnPropertyNames(value)) {
    const key = despoof(rawKey, spoof);
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
    // S4-unicode-spoof (collision): two DISTINCT raw keys that differ only by an
    // invisible control character collapse to the SAME normalized key here. Without
    // this guard the second silently OVERWRITES the first - erasing a real Condition
    // operator/key (e.g. a restriction) while analysis reports CLEAN/complete. A
    // spoofed duplicate is malformed; fail CLOSED (the pushed error -> ok:false) and
    // keep the FIRST value rather than silently dropping either one.
    if (Object.prototype.hasOwnProperty.call(out, key)) {
      errors.push(
        err(
          'SPOOFED_DUPLICATE_KEY',
          `Object key "${key}" appears more than once after control-character `
            + `normalization (a distinct raw key collapsed onto it).`,
          `${path}.${key}`,
        ),
      );
      continue;
    }
    out[key] = copyGuarded(value[rawKey], errors, `${path}.${key}`, spoof);
  }
  return out;
}

// --- Principal / NotPrincipal normalization ----------------------------------
// Principal (and its mutually-exclusive twin NotPrincipal) may be the wildcard
// string "*" or an object keyed by type (AWS/Service/Federated/CanonicalUser),
// each value a string or string array. Both share this normalizer; `element`
// selects which one for error paths/messages so the two stay DISTINCT elements
// (IAM-501: Principal and NotPrincipal are modeled separately, never merged).
// Normalized shape:
//   null                                        (absent)
//   { anyPrincipal: true,  byType: {} }         ("*")
//   { anyPrincipal: false, byType: { AWS: [...], Service: [...] } }

function normalizePrincipal(value, errors, path, element, spoof) {
  const name = element || 'Principal';
  if (value === undefined) return null;
  if (value === '*') {
    return { anyPrincipal: true, byType: {} };
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    errors.push(
      err(
        element === 'NotPrincipal' ? 'INVALID_NOTPRINCIPAL' : 'INVALID_PRINCIPAL',
        `${name} must be "*" or an object keyed by principal type.`,
        `${path}.${name}`,
      ),
    );
    return null;
  }
  const byType = {};
  for (const rawKey of Object.getOwnPropertyNames(value)) {
    // S4-unicode-spoof: strip the spoof class from the principal-type key BEFORE
    // the dangerous-key check (same rationale as copyGuarded); values are stripped
    // inside toStringArray. Stage-11 RC-A: record a canonicalized key via `spoof`.
    const key = despoof(rawKey, spoof);
    if (DANGEROUS_KEYS.has(key)) {
      errors.push(
        err(
          'DANGEROUS_KEY',
          `Rejected dangerous key "${key}" (prototype-pollution guard).`,
          `${path}.${name}.${key}`,
        ),
      );
      continue;
    }
    // S4-unicode-spoof (collision): a zero-width/format-control twin of a principal
    // TYPE key (e.g. "AWS" + "AWS​") collapses to one key here; without this
    // guard the second silently OVERWRITES the first, erasing a real principal (the
    // reported CRITICAL public/cross-account grant vanishes under a benign decoy while
    // analysis reads CLEAN). Fail CLOSED on the collision, keep the FIRST value.
    if (Object.prototype.hasOwnProperty.call(byType, key)) {
      errors.push(
        err(
          'SPOOFED_DUPLICATE_KEY',
          `${name} type "${key}" appears more than once after control-character `
            + `normalization (a distinct raw key collapsed onto it).`,
          `${path}.${name}.${key}`,
        ),
      );
      continue;
    }
    const arr = toStringArray(value[rawKey], key, `${path}.${name}`, spoof);
    if (!arr.ok) {
      errors.push(arr.error);
      continue;
    }
    byType[key] = arr.values;
  }
  // S3-trust-calibration (1): fail CLOSED on a principal that names NO actual
  // principal member. Two shapes collapse to a member-less byType and would
  // otherwise read as a benign, non-firing trust/resource grant (a fail-OPEN that
  // reports CLEAN on `Principal: {}` + sts:AssumeRole):
  //   - an empty principal object `{}`               -> byType has ZERO keys;
  //   - a principal whose value array is empty `{"AWS": []}` (or any key mapping
  //     to `[]`)                                      -> an empty VALUE ARRAY.
  // AWS requires at least one principal value; both are malformed. Reject them as
  // INVALID_PRINCIPAL / INVALID_NOTPRINCIPAL so buildModel fails (ok:false ->
  // analyze() is not-ok, CLI exit 3) rather than emitting a member-less principal
  // the trust family flattens to no finding. Principal "*" is handled ABOVE
  // (anyPrincipal:true, byType:{}) and returns before this guard, so a wildcard
  // principal - which legitimately has an empty byType - is never rejected here.
  const presentKeys = Object.keys(byType);
  const hasEmptyValueArray = presentKeys.some((k) => byType[k].length === 0);
  if (presentKeys.length === 0 || hasEmptyValueArray) {
    errors.push(
      err(
        element === 'NotPrincipal' ? 'INVALID_NOTPRINCIPAL' : 'INVALID_PRINCIPAL',
        `${name} must name at least one principal value; an empty principal ` +
          'object or an empty principal value array is not a valid principal.',
        `${path}.${name}`,
      ),
    );
    return null;
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

  // Stage-11 RC-A: per-statement accumulator. Set true when stripModelSpoof
  // canonicalized any SECURITY-RELEVANT token (Action/NotAction/Resource/
  // NotResource/Condition key or value/Principal type). Sid/Version/Id are
  // deliberately EXCLUDED - they are cosmetic and cannot hide a grant.
  const spoof = { hit: false };

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
      sid = stripModelSpoof(stmt['Sid']); // S4-unicode-spoof: normalization boundary
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
  const actions = collect(toStringArray(stmt['Action'], 'Action', path, spoof), errors);
  const notActions = collect(toStringArray(stmt['NotAction'], 'NotAction', path, spoof), errors);
  // Stage-13 EFO-1: a non-ASCII code point in an Action/NotAction token cannot be a
  // real AWS action; it is either inert at AWS or a case-fold spoof of one. Flip the
  // spoof accumulator so the verdict fails closed (incomplete) rather than trusting a
  // folded match - the same fail-closed posture as a de-spoofed token above.
  if (actionsHaveNonAscii(actions) || actionsHaveNonAscii(notActions)) spoof.hit = true;

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
  const resources = collect(toStringArray(stmt['Resource'], 'Resource', path, spoof), errors);
  const notResources = collect(
    toStringArray(stmt['NotResource'], 'NotResource', path, spoof),
    errors,
  );

  const condition = normalizeCondition(stmt['Condition'], errors, path, spoof);

  // Principal / NotPrincipal: distinct, mutually-exclusive elements (IAM-501).
  // AWS forbids both in one statement; that is a schema error here. Each is
  // normalized on its own field so a family-aware evaluator can tell them apart
  // (NotPrincipal is not "the absence of Principal" - it is an explicit,
  // separately-modeled element). NotPrincipal is only ever a resource-policy
  // element; the fail-closed coverage gate (family.js) rejects it until a
  // family-aware evaluator exists, but the MODEL still records it faithfully.
  const hasPrincipal = stmt['Principal'] !== undefined;
  const hasNotPrincipal = stmt['NotPrincipal'] !== undefined;
  if (hasPrincipal && hasNotPrincipal) {
    errors.push(
      err(
        'PRINCIPAL_AND_NOTPRINCIPAL',
        'A statement may not contain both Principal and NotPrincipal.',
        path,
      ),
    );
  }
  const principal = normalizePrincipal(stmt['Principal'], errors, path, 'Principal', spoof);
  const notPrincipal = normalizePrincipal(stmt['NotPrincipal'], errors, path, 'NotPrincipal', spoof);

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
    notPrincipal,
    // IAM-1508 (S2-guard-parity): record which action/resource COMPLEMENT element
    // was actually present in the source statement. The normalized model collapses
    // `Action: []` and `NotAction: []` to the identical `actions:[] notActions:[]`
    // shape, so a downstream masked-grant detector (engine/masked-grant.js) cannot
    // otherwise distinguish a benign empty POSITIVE set from an empty COMPLEMENT
    // (`NotAction: []` excludes nothing -> grants EVERY action). These booleans keep
    // that distinction so the shared engine - not just the CLI adapter - can fail
    // closed on the empty-complement full-admin/broad-resource shapes.
    notActionPresent: hasNotAction,
    notResourcePresent: hasNotResource,
    // S1-shape-failclosed: presence of the POSITIVE Resource key, symmetric to
    // notResourcePresent. The model collapses "Resource key absent" and
    // "Resource: []" to the identical `resources:[]` shape, but the two are NOT
    // equivalent: `Resource: []` is an explicit empty POSITIVE set (matches no
    // resource -> grants nothing, benign) whereas OMITTING Resource entirely on an
    // identity statement leaves the resource scope UNSPECIFIED (AWS requires a
    // Resource element; the rules engine reads the empty array as "narrow" and
    // suppresses WILDCARD-RESOURCE / DATA-EXFIL - a fail-OPEN). The masked-grant
    // detector uses this flag (with resourcePresent === false AND notResourcePresent
    // === false, and no Principal) to fail closed on the unspecified-scope shape.
    resourcePresent: hasResource,
    // Stage-11 RC-A: a security-relevant token in this statement was canonicalized
    // by stripModelSpoof (the source carried an invisible/reordering code point).
    // The verdict layer must NOT trust a de-spoofed token as coverage/guardrail;
    // coverage.summary.incomplete is flipped so a spoofed Deny/NotAction/condition
    // -key can never suppress a finding into a clean pass (fail closed).
    spoofedToken: spoof.hit,
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
      // S4-unicode-spoof: the policy Version/Id are policy-derived display strings
      // that ride into the model + exports, so they are de-spoofed at the boundary
      // too (no-op on a valid "2012-10-17"; a non-string passes through untouched).
      version: typeof parsed.version === 'string' ? stripModelSpoof(parsed.version) : parsed.version,
      id: typeof parsed.id === 'string' ? stripModelSpoof(parsed.id) : parsed.id,
      statements,
      // Stage-11 RC-A: how many statements carried a canonicalized (tampered)
      // security-relevant token. Non-zero flips coverage.summary.incomplete in
      // enrichCoverage so a de-spoofed token can never read as a complete CLEAN
      // pass. Zero on every legitimate (pure-ASCII) policy - no false fail-closed.
      spoofedTokenCount: statements.reduce((n, s) => n + (s && s.spoofedToken ? 1 : 0), 0),
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
