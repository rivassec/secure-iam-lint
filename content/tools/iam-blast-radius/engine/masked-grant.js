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
// Most shapes are only meaningful on Effect:'Allow' - a never-match / empty complement
// on a Deny denies nothing and is benign. The EXCEPTION is a malformed CONDITION
// (block or value): a Deny whose condition the engine cannot model is dropped and read
// as UNCONDITIONAL, which can SUPPRESS a real Allow finding - a fail-open on the Deny
// side too. So condition-shape detection runs for BOTH effects; the complement /
// never-match / unspecified-resource shapes stay Allow-only.
//
// The Allow-only shapes:
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
// S1-shape-failclosed extends the same fail-closed net to three more MODEL-SHAPE
// classes that the engine previously read as clean (all confirmed silent CLEANs):
//
//   MALFORMED_CONDITION_VALUE (extended) The original code caught only a non-primitive
//     member inside a value ARRAY. A Condition value that is DIRECTLY a non-scalar -
//     a bare object ({}), null, or a nested structure where a scalar or array-of-
//     scalars belongs (e.g. Condition:{StringEquals:{aws:PrincipalOrgID:{}}}) - was
//     skipped (the detector only looked at arrays), so the malformed statement read
//     CLEAN. A condition value must be a primitive scalar or an array of primitive
//     scalars; anything else is undeployable (AWS MalformedPolicyDocument) and the
//     engine cannot faithfully model it. -> kind 'malformed'.
//
//   MALFORMED_CONDITION_BLOCK   A Condition OPERATOR block (the value of an operator
//     like StringEquals) that is not an object mapping condition-key -> value(s) - a
//     string, number, null, or array. The engine drops the unrecognized block and
//     evaluates the Allow as UNCONDITIONAL, silently discarding a restriction the
//     author wrote. -> kind 'malformed'.
//
//   UNSPECIFIED_RESOURCE_SCOPE  An identity-style Allow (no Principal / NotPrincipal)
//     that names an Action/NotAction but omits BOTH Resource and NotResource. AWS
//     requires a Resource element on identity statements; with neither key the
//     resource scope is UNSPECIFIED, yet the rules engine reads the empty resources[]
//     as "narrow" and suppresses WILDCARD-RESOURCE / DATA-EXFIL. `resourcePresent`
//     (model.js) distinguishes this from the benign explicit empty set `Resource: []`
//     (matches nothing -> grants nothing). A resource-based statement (Principal
//     present) legitimately implies its resource and is exempt. -> kind 'malformed'.
//
// Operates on the NORMALIZED, FROZEN model ONLY - never on raw text, never re-parsed.
// The model preserves the 0-based statement index and the original Condition operator
// and key spellings, so the JSON paths this emits match what the old raw-text guards
// produced (e.g. "Statement[1].Condition.ForAnyValue:StringEquals.aws:SourceVpc").
//
// S1-breadth-classify decides the RESOURCE-VALUE SHAPE from the ONE shared
// classifier (engine/resource-arn.js), replacing this module's old shallow
// startsWith('arn:') gate (which "agreed wrongly" with the rules predicate and let
// "arn:" / "arn:aws" / a leading-whitespace ARN slip through as narrow):
//
//   MALFORMED_RESOURCE_ARN  A Resource / NotResource element value classifyResource()
//     reports as MALFORMED: neither the bare "*" nor a well-formed 6-segment ARN
//     (partition+service+resourceId non-empty), OR carrying leading/trailing
//     whitespace, OR a would-be-narrow ARN on a service the engine does not model
//     (the HYBRID default). Per the AWS IAM grammar such a value is undeployable
//     (MalformedPolicyDocument) and its concrete scope cannot be established - a
//     suffix/infix glob ("*.pem"/"*-prod"), a bare literal, a URL, or a truncated
//     "arn:"/"arn:aws" used to read as a NARROW scope and returned a bare CLEAN on a
//     bulk read: a DATA-EXFIL fail-OPEN (threat-model T8). Per the never-silent-clean
//     north star an UNDECIDABLE value routes to coverage.summary.incomplete, NOT a
//     fabricated confident DATA-EXFIL finding (firing would overstate certainty and
//     over-broaden adversarial edges). A value classifyResource() reports as BROAD
//     (the bare "*", a wildcard high in the ARN, a whole-collection identifier
//     wildcard, or a boundary-crossing non-ARN glob "*/*"/"?*") is NOT masked HERE:
//     when a mutating action rides on it the rules engine surfaces it directly
//     (DATA-EXFIL / WILDCARD-RESOURCE). But a broad value is NOT guaranteed to fire a
//     rule - the catalog deliberately treats a broad-resource READ as routine
//     (WILDCARD-RESOURCE needs grantsNonReadAction; DATA-EXFIL needs the s3-bulk/secret
//     catalog), so a non-exfil read (dynamodb:GetItem, iam:GetRole) on a BROAD value -
//     whether a glob "?*" or a broad WELL-FORMED ARN "arn:aws:dynamodb::*:table/foo" -
//     fires NEITHER rule. That broad-but-uncovered case is closed one level up in
//     analyze.js, which can see the fired findings and marks the statement incomplete
//     (BROAD_RESOURCE_UNDECIDABLE) for ANY BROAD value on an uncovered Allow, symmetric
//     across glob and well-formed-ARN spellings; see coverage.js broadUndecidableUncovered.
//     Every non-"*"/non-well-formed-ARN value is therefore fail-CLOSED either way -
//     broad-and-firing, broad-and-uncovered-incomplete, or undecidable-and-incomplete -
//     never a bare clean. -> kind 'malformed'.
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. No 'node:' imports.
// Deterministic: same model -> same masked-grant list, same order, every run.

// S1-breadth-classify: the SAME shared semantic classifier the rules breadth
// predicate uses. Reading undecidability from classifyResource() (not a shallow
// startsWith('arn:') gate) kills the "two gates agree wrongly" fail-open: a value
// like "arn:" / "arn:aws" / " arn:aws:s3:::bucket/*" / a suffix-glob "*.pem" is now
// decided by ONE grammar shared with rules.js, so the two surfaces cannot disagree.
import { classifyResource, RESOURCE_CLASS } from './resource-arn.js';
// A-condition-budget: the canonical Condition-value cap. validate.js is a leaf module
// (no engine imports), so importing LIMITS introduces no cycle and keeps the shipped
// browser engine graph free of any 'node:' import. The cap lives with the other input
// limits; the routing-to-incomplete decision (not a hard reject) is enforced here.
import { LIMITS } from './validate.js';

// Stable, machine-readable codes. Frozen so callers can reference them by name and
// the SARIF/CLI adapters can map them without re-deriving.
export const MASKED_GRANT_CODES = Object.freeze({
  EMPTY_NOTACTION_COMPLEMENT: 'EMPTY_NOTACTION_COMPLEMENT',
  EMPTY_NOTRESOURCE_COMPLEMENT: 'EMPTY_NOTRESOURCE_COMPLEMENT',
  MALFORMED_CONDITION_VALUE: 'MALFORMED_CONDITION_VALUE',
  SUPPRESSED_NEVER_MATCH_ALLOW: 'SUPPRESSED_NEVER_MATCH_ALLOW',
  // S1-shape-failclosed additions.
  MALFORMED_CONDITION_BLOCK: 'MALFORMED_CONDITION_BLOCK',
  UNSPECIFIED_RESOURCE_SCOPE: 'UNSPECIFIED_RESOURCE_SCOPE',
  // S1-breadth-failclosed addition.
  MALFORMED_RESOURCE_ARN: 'MALFORMED_RESOURCE_ARN',
  // A-condition-budget addition: a value-array flood on one statement's Condition.
  TOO_MANY_CONDITION_VALUES: 'TOO_MANY_CONDITION_VALUES',
});

// A Resource / NotResource element value the engine cannot decide the scope of.
// Decided by the ONE shared classifier (engine/resource-arn.js): a value is
// undecidable exactly when classifyResource returns MALFORMED - it is neither the
// bare "*" nor a well-formed 6-segment ARN (partition+service+resourceId non-empty),
// OR it carries leading/trailing whitespace, OR it is a would-be-narrow ARN on a
// service the engine does not model. Per the AWS IAM grammar such a value is
// undeployable (MalformedPolicyDocument) and its scope cannot be established, so it
// routes to coverage.incomplete, never a bare clean pass.
//
// This deliberately does NOT special-case "provably broad" values the way the old
// probe-battery gate did: under the shared grammar a boundary-crossing non-ARN glob
// ("*/*", "?*") is now uniformly MALFORMED (undecidable) rather than a fabricated
// confident DATA-EXFIL, and a broad WELL-FORMED ARN classifies BROAD (not MALFORMED),
// so it is not masked HERE. A BROAD value is NOT guaranteed to fire a rule, though: a
// broad-resource READ fires neither WILDCARD-RESOURCE (needs grantsNonReadAction) nor
// DATA-EXFIL (needs the s3-bulk/secret catalog). That broad-but-uncovered case - for a
// glob "?*" OR a broad well-formed ARN "arn:aws:dynamodb::*:table/foo" alike - is closed
// one level up in analyze.js (broadUndecidableUncovered), which can see the fired
// findings and marks the statement incomplete for ANY BROAD value no rule covered. The
// result: a broad value can no longer fire NEITHER a finding NOR an incomplete (the
// dynamodb:GetItem-on-broad fail-open, where the resource was broad yet no rule fired) -
// every non-"*" value reaches a finding or incomplete, never a bare clean.
function isUndecidableResourceValue(value) {
  return classifyResource(value) === RESOURCE_CLASS.MALFORMED;
}

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

// A-condition-budget: total number of Condition VALUES on one statement, summed across
// every operator block and key. Mirrors conditions.js toValueArray's arity (an array
// contributes its length; a present scalar contributes 1; an absent/null value or a
// malformed non-object operator block contributes 0 - the latter is caught separately as
// MALFORMED_CONDITION_BLOCK), so the count matches the per-value work the classifier
// actually does. Bounded work: it walks the already-size-capped (MAX_BYTES) condition.
function countConditionValues(cond) {
  if (!cond || typeof cond !== 'object' || Array.isArray(cond)) return 0;
  let total = 0;
  for (const op of Object.keys(cond)) {
    const block = cond[op];
    if (!block || typeof block !== 'object' || Array.isArray(block)) continue;
    for (const key of Object.keys(block)) {
      const v = block[key];
      if (Array.isArray(v)) total += v.length;
      else if (v !== null && v !== undefined) total += 1;
    }
  }
  return total;
}

// Detect malformed Condition SHAPES on one statement. Unlike the empty-complement /
// never-match / unspecified-resource shapes (which only MASK a grant on an Allow), a
// malformed condition is a fail-open on EITHER effect: a Deny whose condition the
// engine cannot model is silently dropped and treated as UNCONDITIONAL, which can
// SUPPRESS a real Allow finding (an Allow-only detector would miss that). So this runs
// for every statement; only the empty-ForAnyValue never-match (a suppressed would-be
// grant) is Allow-specific and gated by `isAllow`.
//   MALFORMED_CONDITION_BLOCK   operator value is not an object of key -> value(s).
//   MALFORMED_CONDITION_VALUE   a value that is not a scalar nor an array of scalars.
//   SUPPRESSED_NEVER_MATCH_ALLOW empty ForAnyValue value array (Allow only).
function detectConditionShapes(cond, i, isAllow, out) {
  if (!cond || typeof cond !== 'object' || Array.isArray(cond)) return;
  for (const op of Object.keys(cond)) {
    const block = cond[op];
    // MALFORMED_CONDITION_BLOCK: an operator's value must be an OBJECT mapping
    // condition-key -> scalar | [scalars]. A string / number / boolean / null / array
    // block is malformed (AWS MalformedPolicyDocument); the engine drops it and
    // evaluates the statement as UNCONDITIONAL, silently discarding the author's
    // restriction. Fail closed instead of skipping. null is typeof 'object', so guard
    // it explicitly.
    if (block === null || typeof block !== 'object' || Array.isArray(block)) {
      out.push(entry(
        'Condition',
        MASKED_GRANT_CODES.MALFORMED_CONDITION_BLOCK,
        `Statement[${i}].Condition.${op}`,
        MASKED_GRANT_KINDS.MALFORMED,
      ));
      continue;
    }
    const forAnyValue = isForAnyValueOperator(op);
    for (const key of Object.keys(block)) {
      const value = block[key];
      const path = `Statement[${i}].Condition.${op}.${key}`;
      if (Array.isArray(value)) {
        if (value.some((v) => !isPrimitiveMember(v))) {
          // MALFORMED_CONDITION_VALUE takes precedence over a co-located empty-set
          // check: a non-primitive member is the undeployable/dropped-member shape.
          out.push(entry(
            'Condition',
            MASKED_GRANT_CODES.MALFORMED_CONDITION_VALUE,
            path,
            MASKED_GRANT_KINDS.MALFORMED,
          ));
        } else if (isAllow && forAnyValue && value.length === 0) {
          out.push(entry(
            'Condition',
            MASKED_GRANT_CODES.SUPPRESSED_NEVER_MATCH_ALLOW,
            path,
            MASKED_GRANT_KINDS.INCOMPLETE,
          ));
        }
      } else if (!isPrimitiveMember(value)) {
        // A condition value that is DIRECTLY a non-scalar - a bare object ({}), null,
        // or a nested structure - where a scalar or array-of-scalars belongs. The
        // engine's value normalizer keeps only scalars, so it silently models a value
        // set the author did not write. Fail closed.
        out.push(entry(
          'Condition',
          MASKED_GRANT_CODES.MALFORMED_CONDITION_VALUE,
          path,
          MASKED_GRANT_KINDS.MALFORMED,
        ));
      }
    }
  }
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
    const i = typeof s.index === 'number' ? s.index : statements.indexOf(s);
    const isAllow = s.effect === 'Allow';

    // Condition-shape malformation (block/value) is a fail-open on EITHER effect: a
    // malformed Deny condition the engine drops is treated as unconditional and can
    // SUPPRESS a real Allow finding. Detect it for every statement (the never-match
    // suppressed-grant sub-case is Allow-only and gated inside the helper).
    detectConditionShapes(s.condition, i, isAllow, out);

    // A-condition-budget: a statement whose Condition carries more than
    // LIMITS.MAX_CONDITION_VALUES values (summed across operators/keys) is a value-array
    // flood - a DoS work concern (the classifier does O(values) work per key). Route it
    // to coverage.summary.incomplete instead of silently analyzing (or dropping) an
    // adversarial flood: fail CLOSED, never a bare clean pass. Effect-agnostic (the work
    // cost is independent of Allow/Deny, and a flood on a Deny is equally a work concern).
    // kind 'incomplete' - the document is deployable; this is a resource/coverage caveat,
    // not a malformed shape.
    if (countConditionValues(s.condition) > LIMITS.MAX_CONDITION_VALUES) {
      out.push(entry(
        'Condition',
        MASKED_GRANT_CODES.TOO_MANY_CONDITION_VALUES,
        `Statement[${i}].Condition`,
        MASKED_GRANT_KINDS.INCOMPLETE,
      ));
    }

    // The remaining shapes only MASK a grant on an Allow. A Deny + empty complement
    // denies nothing/everything, a never-match Deny grants/denies nothing, and a
    // no-resource Deny denies nothing - all benign (matches the CLI guards and the
    // negative "must-not-fire" corpus).
    if (!isAllow) continue;

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

    // UNSPECIFIED_RESOURCE_SCOPE: identity-style Allow (no Principal/NotPrincipal)
    // that names a real action grant but carries NEITHER a Resource NOR a NotResource
    // key. AWS requires a Resource element on an identity statement; omitting both
    // leaves the resource scope UNSPECIFIED, and resourceIsBroad(rules.js) reads the
    // resulting empty resources[] as "narrow", suppressing WILDCARD-RESOURCE and the
    // bulk-read DATA-EXFIL finding - a silent fail-OPEN. The presence flag distinguishes
    // this from the benign explicit empty POSITIVE set `Resource: []` (matches nothing
    // -> grants nothing). A resource-based statement (Principal present) implies its
    // resource and is exempt. A real action grant is required (a positive Action, or a
    // NotAction complement); an empty positive `Action: []` grants nothing and an empty
    // `NotAction: []` is already caught above, so neither reaches here.
    const hasResourceKey = s.resourcePresent === true || s.notResourcePresent === true;
    const identityStyle = s.principal == null && s.notPrincipal == null;
    const grantsSomething = (Array.isArray(s.actions) && s.actions.length > 0)
      || (Array.isArray(s.notActions) && s.notActions.length > 0);
    if (identityStyle && !hasResourceKey && grantsSomething) {
      out.push(entry(
        'Resource',
        MASKED_GRANT_CODES.UNSPECIFIED_RESOURCE_SCOPE,
        `Statement[${i}]`,
        MASKED_GRANT_KINDS.MALFORMED,
      ));
    }

    // MALFORMED_RESOURCE_ARN (S1-breadth-failclosed): a Resource / NotResource value
    // that is neither "*" nor arn:-shaped is malformed per the AWS IAM grammar and
    // the engine cannot decide what it scopes. Routed to coverage.incomplete so a
    // bulk read on such a value (s3:GetObject on "*.pem", "*-prod", a bare literal,
    // a URL) can never return a silent CLEAN (threat-model T8). Emitted at most once
    // per axis per statement (element granularity), pointing at the axis; a value
    // that is already provably broad is excluded (it fires DATA-EXFIL instead - see
    // isUndecidableResourceValue). Allow-only, symmetric to the empty-complement
    // shapes: a malformed Resource on a Deny cannot mask an Allow finding.
    for (const [axis, list] of [['Resource', s.resources], ['NotResource', s.notResources]]) {
      if (Array.isArray(list) && list.some(isUndecidableResourceValue)) {
        out.push(entry(
          axis,
          MASKED_GRANT_CODES.MALFORMED_RESOURCE_ARN,
          `Statement[${i}].${axis}`,
          MASKED_GRANT_KINDS.MALFORMED,
        ));
      }
    }
  }
  return out;
}

export default detectMaskedGrants;
