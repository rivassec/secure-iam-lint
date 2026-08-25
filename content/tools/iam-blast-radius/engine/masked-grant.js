// IAM Blast Radius - masked-grant fail-closed detection (IAM-1508, S2-guard-parity).
//
// A "masked grant" is a statement the NORMALIZED model faithfully represents but
// the rules/escalation/graph engines then evaluate as granting NOTHING (or as a
// faithfully-analyzed grant when they did not actually analyze it faithfully).
// Left unflagged, such a statement makes analyze() report ok:true + 0 findings +
// coverage.complete on a policy that carries real risk - a silent fail-OPEN
// (threat-model T8: a user could wrongly clear a real risk).
//
// These four shapes were previously caught ONLY by the CLI adapter (cli/scan.mjs),
// which re-parsed the raw text independently of the engine. That is a drift hazard:
// the browser path (app.js/worker.js -> analyze()) never saw them. This module MOVES
// the detection into the shared engine so BOTH surfaces observe it from one source.
// analyze() now marks coverage INCOMPLETE (via coverage.js) and carries a structured
// analyzer-state for each; the CLI adapter reads that coverage instead of re-parsing,
// so the two surfaces cannot diverge.
//
// The four shapes (all only meaningful on Effect:'Allow' - a never-match / empty
// complement on a Deny denies nothing and is benign):
//
//   EMPTY_NOTACTION_COMPLEMENT   NotAction present-and-empty ([]). Under AWS
//     semantics an empty NotAction excludes NOTHING, so the Allow grants EVERY
//     action - a full-admin grant. The model gates MISSING_ACTION on presence
//     (NotAction:[] is "present"), and the rule engine early-returns on an empty
//     NotAction, so the engine models it as granting nothing. -> kind 'malformed'.
//
//   EMPTY_NOTRESOURCE_COMPLEMENT NotResource present-and-empty ([]). An empty
//     NotResource excludes NOTHING, so the Allow applies to EVERY resource - the
//     byte-equivalent of Resource:"*" - but the engine reads it as "no resource
//     scope" and never fires WILDCARD-RESOURCE. -> kind 'malformed'.
//
//   MALFORMED_CONDITION_VALUE    A Condition value ARRAY carrying a member that is
//     not a string/number/boolean (an object, nested array, or null). AWS rejects
//     such an element with MalformedPolicyDocument (the policy is undeployable), yet
//     conditions.js toValueArray silently DROPS the non-primitive member, so the
//     engine evaluated a value set the author did not write. -> kind 'malformed'.
//
//   SUPPRESSED_NEVER_MATCH_ALLOW A ForAnyValue operator over a LITERALLY empty array
//     ([]). Valid AWS (ForAnyValue over no values can never match, so the statement
//     grants nothing), but the engine SUPPRESSES the whole Allow as a never-match and
//     emits no finding - a full-admin-looking grant leaves a silent CLEAN. Surfaced
//     as a trace, not a hard reject. -> kind 'incomplete'.
//
// Operates on the NORMALIZED, FROZEN model ONLY - never on raw text, never re-parsed.
// The model preserves the 0-based statement index and the original Condition operator
// and key spellings, so the JSON paths this emits match what the old raw-text guards
// produced (e.g. "Statement[1].Condition.ForAnyValue:StringEquals.aws:SourceVpc").
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. No 'node:' imports.
// Deterministic: same model -> same masked-grant list, same order, every run.

// Stable, machine-readable codes. Frozen so callers can reference them by name and
// the SARIF/CLI adapters can map them without re-deriving.
export const MASKED_GRANT_CODES = Object.freeze({
  EMPTY_NOTACTION_COMPLEMENT: 'EMPTY_NOTACTION_COMPLEMENT',
  EMPTY_NOTRESOURCE_COMPLEMENT: 'EMPTY_NOTRESOURCE_COMPLEMENT',
  MALFORMED_CONDITION_VALUE: 'MALFORMED_CONDITION_VALUE',
  SUPPRESSED_NEVER_MATCH_ALLOW: 'SUPPRESSED_NEVER_MATCH_ALLOW',
});

// Detection kinds:
//   'malformed'  -> the analyzer could not faithfully model the statement (or AWS
//                   would reject the document); the strongest masked-grant signal.
//   'incomplete' -> a suppressed would-be grant left no finding; surfaced as a trace.
export const MASKED_GRANT_KINDS = Object.freeze({
  MALFORMED: 'malformed',
  INCOMPLETE: 'incomplete',
});

// Is a condition value-array member a primitive the engine keeps? MIRRORS
// conditions.js toValueArray's filter EXACTLY (string | number | boolean survive;
// object / array / null are dropped). A member the filter drops is the malformed
// element AWS would reject.
function isPrimitiveMember(v) {
  return typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean';
}

// MIRRORS conditions.js parseOperator: a ForAnyValue set-qualifier is a case-
// insensitive operator PREFIX. Kept local so this module stays dependency-free
// (same rationale as the duplicated helper sets elsewhere in the engine).
function isForAnyValueOperator(operator) {
  return String(operator).toLowerCase().startsWith('foranyvalue:');
}

function entry(element, code, path, kind) {
  return Object.freeze({ element, code, path: path == null ? null : String(path), kind });
}

/**
 * Detect every masked-grant shape in a normalized model.
 *
 * Pure and deterministic; never throws (a malformed/partial model yields []).
 * Operates on the frozen model only - no raw text, no re-parse.
 *
 * @param {object|null} model normalized model (from buildModel/modelFromText)
 * @returns {Array<{element:string, code:string, path:(string|null), kind:string}>}
 *   masked-grant analyzer-states, in stable statement-then-element order.
 */
export function detectMaskedGrants(model) {
  const out = [];
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  for (const s of statements) {
    if (!s || typeof s !== 'object') continue;
    // Only an Allow can MASK a grant. A Deny + empty complement denies nothing, and
    // a never-match Deny grants/denies nothing - both benign (matches the CLI guards
    // and the negative "must-not-fire" corpus).
    if (s.effect !== 'Allow') continue;
    const i = typeof s.index === 'number' ? s.index : statements.indexOf(s);

    // EMPTY_NOTACTION_COMPLEMENT: NotAction was PRESENT and is the empty array. The
    // presence flag distinguishes this from a benign empty POSITIVE `Action: []`
    // (both collapse to actions:[] notActions:[] in the model).
    if (s.notActionPresent === true
      && Array.isArray(s.notActions) && s.notActions.length === 0) {
      out.push(entry(
        'NotAction',
        MASKED_GRANT_CODES.EMPTY_NOTACTION_COMPLEMENT,
        `Statement[${i}].NotAction`,
        MASKED_GRANT_KINDS.MALFORMED,
      ));
    }

    // EMPTY_NOTRESOURCE_COMPLEMENT: NotResource present-and-empty (resource-axis twin).
    if (s.notResourcePresent === true
      && Array.isArray(s.notResources) && s.notResources.length === 0) {
      out.push(entry(
        'NotResource',
        MASKED_GRANT_CODES.EMPTY_NOTRESOURCE_COMPLEMENT,
        `Statement[${i}].NotResource`,
        MASKED_GRANT_KINDS.MALFORMED,
      ));
    }

    // Condition-value masked grants. The normalized condition is a fresh copy that
    // preserves the original operator/key spellings and the raw value structure
    // (objects/arrays/null survive copyGuarded), so both the malformed non-primitive
    // member and the suppressed empty ForAnyValue array are visible here.
    const cond = s.condition;
    if (cond && typeof cond === 'object' && !Array.isArray(cond)) {
      for (const op of Object.keys(cond)) {
        const block = cond[op];
        if (!block || typeof block !== 'object' || Array.isArray(block)) continue;
        const forAnyValue = isForAnyValueOperator(op);
        for (const key of Object.keys(block)) {
          const value = block[key];
          if (!Array.isArray(value)) continue;
          const path = `Statement[${i}].Condition.${op}.${key}`;
          if (value.some((v) => !isPrimitiveMember(v))) {
            // MALFORMED_CONDITION_VALUE takes precedence over a co-located empty-set
            // check: a non-primitive member is the undeployable/dropped-member shape.
            out.push(entry(
              'Condition',
              MASKED_GRANT_CODES.MALFORMED_CONDITION_VALUE,
              path,
              MASKED_GRANT_KINDS.MALFORMED,
            ));
          } else if (forAnyValue && value.length === 0) {
            out.push(entry(
              'Condition',
              MASKED_GRANT_CODES.SUPPRESSED_NEVER_MATCH_ALLOW,
              path,
              MASKED_GRANT_KINDS.INCOMPLETE,
            ));
          }
        }
      }
    }
  }
  return out;
}

export default detectMaskedGrants;
