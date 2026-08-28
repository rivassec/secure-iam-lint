// trust-findings.js - trust finding factory + principal-summary/breadth helpers (makeFinding, principalSummary, principalIsBroad, makeInvalidPrincipalFinding). Extracted (behavior-preserving).
import { arnAccountPinned, hasGlob, statementSid } from './trust-principal-helpers.js';
import { RULE_VERSION, TRUST_LIMIT, DOC_PRINCIPAL } from './trust-catalogs.js';

export function makeFinding(stmt, principals, { id, severity, title, why, remediation, docRef, pathExploitability }) {
  const actions = stmt.actions.slice();
  const evidence = [Object.freeze({
    statementIndex: stmt.index,
    statementSid: statementSid(stmt),
    role: 'trust',
    actions: actions.slice(),
    resources: [],
    condition: stmt.condition === undefined ? null : stmt.condition,
    // The typed principals this statement trusts (inert data; display evidence).
    // IAM-1004: carry the member's principal key + array index so a consumer
    // (coverage/export) can reconstruct the exact location Principal.<key>[<i>].
    principals: principals.entries.map((e) => Object.freeze(
      e.key !== undefined
        ? { type: e.type, value: e.value, key: e.key, index: e.index }
        : { type: e.type, value: e.value },
    )),
    note: null,
  })];
  return {
    id,
    severity,
    title,
    statementSid: statementSid(stmt),
    statementIndex: stmt.index,
    actions,
    resources: [], // a trust policy has no Resource; its absence is normal.
    conditions: stmt.condition === undefined ? null : stmt.condition,
    // Split confidence (IAM-104): the trust grant is literally in the policy
    // (policyEvidence high); reaching/using the role's power needs the assumer to
    // act AND the (unknown) target-role privileges (pathExploitability capped
    // below policyEvidence).
    policyEvidence: 'high',
    pathExploitability: pathExploitability || 'medium',
    why,
    limit: TRUST_LIMIT,
    remediation,
    ruleVersion: RULE_VERSION,
    docRef,
    // Trust enrichment (analogous to the escalation enrichment on identity
    // findings, but for the trust direction). targetPermissions is ALWAYS
    // 'unknown' and is never inferred.
    trust: {
      principalTypes: [...principals.categories].sort(),
      anonymous: principals.anonymous,
      targetPermissions: 'unknown',
    },
    evidence,
    contributingStatements: [Object.freeze({
      statementIndex: stmt.index,
      statementSid: statementSid(stmt),
      actions: actions.slice(),
    })],
  };
}

export function principalSummary(principals) {
  return principals.entries.map((e) => e.value).join(', ') || '(none)';
}

// Whether a single Principal VALUE is ORG-WIDE / PUBLIC in breadth: the anonymous
// "*" (any principal in any account), or a wildcarded ARN that is NOT pinned to a
// single account (e.g. "arn:aws:iam::*:role/*" spans every account). An
// account-pinned wildcard ARN (e.g. "arn:aws:iam::123456789012:role/app-*") names
// many principals but is BOUNDED to one account, so it is NOT org-wide; a concrete
// account id / :root ARN / specific user-or-role ARN carries no wildcard and is
// likewise bounded. Reuses arnAccountPinned() so this test and the condition-value
// narrowing test agree on "bounded to one account".
export function principalValueIsBroad(value) {
  const s = String(value);
  if (s === '*') return true; // anonymous / public
  if (!hasGlob(s)) return false; // a bounded, fully-literal principal
  // A wildcarded value is org-wide UNLESS it is pinned to a single account.
  return !arnAccountPinned(s);
}

// The NAMED Principal is BROAD when it is anonymous/public ("*") or names an
// org-wide / all-accounts wildcard (a wildcard ARN not pinned to one account).
// Breadth of the named principal (independent of any Condition) is what decides
// whether a negated aws:PrincipalOrgID reads as an org-WIDE external expansion
// (critical) or merely scopes an already-bounded principal. AWS evaluates
// Principal AND Condition, so a negated org condition can never widen trust beyond
// the named Principal (adversarial defect IAM-802-C: a StringNotEquals org on ONE
// specific role ARN is not org-wide). IAM-803 iteration 4 extends this: an
// ACCOUNT-PINNED wildcard ARN (arn:aws:iam::<acct>:role/app-*) is bounded to a
// single account, so it too is NOT broad - it must fall through to the
// cross-account branch (high, carrying the expansion-polarity note) rather than
// fire the org-wide critical headline, which would over-claim an "organization-
// wide set of outside principals" the single-account evidence contradicts AND
// score the bounded subset ABOVE the strictly broader whole-account trust.
export function principalIsBroad(principals) {
  if (principals.anonymous) return true;
  return principals.entries.some((e) => principalValueIsBroad(e.value));
}

// A filtered VIEW of a classified principal restricted to a set of category
// types, so a finding names ONLY the principals it is actually about in its
// summary / evidence.principals / trust.principalTypes. Without this, a statement
// naming a Federated provider AND an AWS account would attribute the account to
// the federated finding (and vice versa) - the attribution overclaim behind
// adversarial defect IAM-802-A, where the co-present cross-account trust was
// dropped from the findings table while the graph still drew its can-assume edge.
export function subsetPrincipals(principals, types) {
  const keep = new Set(types);
  const entries = principals.entries.filter((e) => keep.has(e.type));
  const categories = new Set(entries.map((e) => e.type));
  const anonymous = entries.some((e) => e.type === 'anonymous');
  return { anonymous, categories, entries, unknownTypes: [] };
}

// Build a classified-principals object from an explicit LIST of entries (a
// value-level subset, unlike subsetPrincipals which selects by principal TYPE).
// Used to split service principals into the source-binding-requiring subset and
// the ordinary subset (S3-trust-calibration 2) so each gets its own finding.
export function principalsFromEntries(entries) {
  const categories = new Set(entries.map((e) => e.type));
  const anonymous = entries.some((e) => e.type === 'anonymous');
  return { anonymous, categories, entries, unknownTypes: [] };
}

// IAM-903 / IAM-1006: build the fail-closed TRUST-INVALID-PRINCIPAL finding for a
// SUBSET of invalid partial-wildcard principal members (an AWS Principal ARN
// wildcard, or a Service/Federated member carrying a '*'/'?'). Computes the exact
// per-member JSON path (Statement[N].Principal.<key>[<i>]) and attaches
// invalidPrincipalPaths so analyze() raises the INVALID_PRINCIPAL_WILDCARD_ARN
// coverage warning and the trusted set is reported UNDETERMINED, never as a
// complete, valid trust. `buildWhy(invalidWho, invalidPaths)` lets each key emit
// its own accurate prose while sharing one deterministic finding shape.
export function makeInvalidPrincipalFinding(stmt, invalid, { title, buildWhy, remediation }) {
  const invalidPaths = invalid.entries.map((e) => (
    e.key !== undefined && e.index !== undefined
      ? `Statement[${stmt.index}].Principal.${e.key}[${e.index}]`
      : `Statement[${stmt.index}].Principal`
  ));
  const invalidWho = invalid.entries.map((e) => (
    e.key !== undefined && e.index !== undefined
      ? `${e.value} (at Principal.${e.key}[${e.index}])`
      : e.value
  )).join(', ') || '(none)';
  const finding = makeFinding(stmt, invalid, {
    id: 'TRUST-INVALID-PRINCIPAL',
    severity: 'high',
    title,
    why: buildWhy(invalidWho, invalidPaths),
    remediation,
    docRef: DOC_PRINCIPAL,
    pathExploitability: 'low',
  });
  // IAM-1004: expose the precise machine-readable location(s) of the invalid
  // member(s) so the error path names the array index (not just a dropped value).
  finding.invalidPrincipalPaths = Object.freeze(
    invalid.entries.map((e, i) => Object.freeze({
      path: invalidPaths[i],
      value: e.value,
      key: e.key !== undefined ? e.key : null,
      index: e.index !== undefined ? e.index : null,
    })),
  );
  return finding;
}

// Emit the trust finding(s) for a single trust statement, following the
// documented severity model (trust-policy-semantics.md section 5). Returns an
// array (usually one finding; a statement mixing e.g. an external account AND a
// service principal can yield more than one).
