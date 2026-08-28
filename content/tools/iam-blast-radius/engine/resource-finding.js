// resource-finding.js - resource-policy finding factory (makeResourceFinding) + S3-object action helpers + entry summarizer. Shared leaf imported by resource.js and the per-service rule modules. Extracted (behavior-preserving).
import { RESOURCE_LIMIT, RESOURCE_RULE_VERSION } from './resource-catalogs.js';
import { parseArn } from './arn-util.js';

// --- S3 bucket-vs-object action/resource typing (IAM-1204; test 50 in the
// resource context) -----------------------------------------------------------
//
// S3 object-level actions (s3:GetObject, s3:PutObject, ...) require an OBJECT-scoped
// resource (arn:aws:s3:::bucket/key or .../*); a bucket-only ARN does not identify
// objects (resource-policy-semantics.md section 2.1). A resource policy granting an
// object action on a bucket-only ARN is an action/resource-type mismatch, NOT
// confirmed object access. Curated set of common object actions (lowercased action
// name after the s3: prefix). A wildcarded action (s3:*, s3:Get*) is intentionally
// NOT classified - the analyzer never guesses a mismatch from a wildcard.
export const S3_OBJECT_ACTIONS = Object.freeze(new Set([
  'getobject', 'putobject', 'deleteobject', 'getobjectacl', 'putobjectacl',
  'getobjectversion', 'getobjectversionacl', 'putobjectversionacl',
  'deleteobjectversion', 'getobjecttagging', 'putobjecttagging',
  'deleteobjecttagging', 'getobjectversiontagging', 'putobjectversiontagging',
  'deleteobjectversiontagging', 'restoreobject', 'getobjecttorrent',
  'getobjectretention', 'putobjectretention', 'getobjectlegalhold',
  'putobjectlegalhold', 'bypassgovernanceretention', 'getobjectattributes',
  'getobjectversionattributes', 'abortmultipartupload', 'listmultipartuploadparts',
  'replicateobject',
]));

export function isS3ObjectAction(action) {
  const m = /^s3:(.+)$/.exec(String(action).toLowerCase());
  return m ? S3_OBJECT_ACTIONS.has(m[1]) : false;
}

// Scope of an S3 resource ARN string: 'object' (a key or /* follows the bucket),
// 'bucket' (bucket-only, no '/'), or null for a non-S3 / non-ARN string.
export function s3ResourceScope(resourceStr) {
  const arn = parseArn(resourceStr);
  if (!arn || String(arn.service).toLowerCase() !== 's3') return null;
  return String(arn.resource).includes('/') ? 'object' : 'bucket';
}

// Human summary of a set of principal entries (inert; ARNs/ids embedded verbatim
// as data, only ever rendered via textContent downstream - never markup, T1).
export function summarizeEntries(entries) {
  const vals = entries.map((e) => String(e.value)).filter((v) => v.length > 0);
  if (vals.length === 0) return 'the named principal(s)';
  if (vals.length <= 3) return vals.join(', ');
  return `${vals.slice(0, 3).join(', ')} (+${vals.length - 3} more)`;
}

// Build one resource finding in the canonical finding shape (architecture.md). The
// resource evaluator emits findings from the RESOURCE's perspective, so `resources`
// is the attached-resource scope this statement grants on, and every finding
// carries RESOURCE_LIMIT (potential blast radius, not effective access).
export function makeResourceFinding(stmt, entries, opts) {
  const actions = Array.isArray(stmt.actions) ? stmt.actions.slice() : [];
  const resources = Array.isArray(stmt.resources) && stmt.resources.length > 0
    ? stmt.resources.slice()
    : (opts.attachedArn ? [opts.attachedArn] : ['(attached resource)']);
  const sid = (typeof stmt.sid === 'string' && stmt.sid.length > 0)
    ? stmt.sid
    : `(index ${stmt.index})`;
  const principalEvidence = entries.map((e) => Object.freeze(
    e.key !== undefined
      ? { type: e.type, value: String(e.value), key: e.key, index: e.index }
      : { type: e.type, value: String(e.value) },
  ));
  const evidence = [Object.freeze({
    statementIndex: stmt.index,
    statementSid: sid,
    role: 'resource',
    actions: actions.slice(),
    resources: resources.slice(),
    condition: stmt.condition === undefined ? null : stmt.condition,
    // The typed principals this statement grants access to (WHO can act on the
    // resource), each identified distinctly and never collapsed (section 3).
    principals: principalEvidence,
    note: null,
  })];
  return {
    id: opts.id,
    severity: opts.severity,
    title: opts.title,
    statementSid: sid,
    statementIndex: stmt.index,
    actions,
    resources,
    conditions: stmt.condition === undefined ? null : stmt.condition,
    // A resource-policy grant is literally in the policy (policyEvidence high);
    // reaching/using it depends on the caller + other layers not supplied here
    // (pathExploitability capped below - IAM-104 split confidence). An
    // action/resource-type mismatch is the exception: the object action does NOT
    // confirm object access, so its policyEvidence is explicitly lowered (test 50).
    policyEvidence: opts.policyEvidence || 'high',
    pathExploitability: opts.pathExploitability || 'medium',
    why: opts.why,
    limit: RESOURCE_LIMIT,
    remediation: opts.remediation,
    ruleVersion: RESOURCE_RULE_VERSION,
    docRef: opts.docRef,
    // Resource enrichment (analogous to the trust block on trust findings): the
    // attached resource + the principals this grant reaches. targetAccess is
    // ALWAYS the direct grant only; effective access is never inferred.
    resource: Object.freeze({
      service: opts.service || null,
      attachedArn: opts.attachedArn || null,
      principalTypes: [...new Set(entries.map((e) => e.type))].sort(),
      // Whether this grant reaches an anonymous/unauthenticated caller. Defaults to
      // "an anonymous "*" principal is present", but a per-service reframe may clear
      // it: a KMS "*" uses the wildcard-principal FORM yet reaches only authenticated
      // AWS identities (KMS has no unauthenticated path), so its reach is not
      // anonymous even though the principal element is "*" (IAM-1403).
      anonymous: opts.anonymousReach !== undefined
        ? !!opts.anonymousReach
        : entries.some((e) => e.type === 'anonymous'),
      // Principal-scoping condition keys narrowing an anonymous "*" grant to
      // authenticated principals; empty for a genuinely-public/unconditioned grant
      // and for non-anonymous findings. A non-empty value means the "*" is NARROWED
      // (test 85) and no anonymous/"anyone" reach may be asserted downstream.
      principalScopedBy: Object.freeze(Array.isArray(opts.principalScopedBy) ? opts.principalScopedBy.slice() : []),
      transportOnlyDeny: !!opts.transportOnlyDeny,
      // IAM-1203: for a service-principal confused-deputy finding, the source-binding
      // state read from the statement (which keys bind the calling service, which
      // were present but ineffective, and whether SourceArn/SourceAccount disagree).
      // null on every non-confused-deputy finding.
      sourceBinding: opts.sourceBinding
        ? Object.freeze({
            state: opts.sourceBinding.state,
            boundKeys: Object.freeze(opts.sourceBinding.boundKeys.slice()),
            bypassedKeys: Object.freeze(opts.sourceBinding.bypassedKeys.slice()),
            sourceArnAccount: opts.sourceBinding.sourceArnAccount,
            sourceAccount: opts.sourceBinding.sourceAccount,
          })
        : null,
    }),
    evidence,
    contributingStatements: [Object.freeze({
      statementIndex: stmt.index,
      statementSid: sid,
      actions: actions.slice(),
    })],
  };
}

// Principal-centric resource findings (IAM-1202 + IAM-1203): enumerate WHO can act
// on the attached resource and emit
//   - PUBLIC-ACCESS            for an anonymous ("*" / {AWS:"*"}) Allow principal,
//   - RESOURCE-CROSS-ACCOUNT   for an external AWS account/root/principal-ARN whose
//     account differs from (or cannot be pinned to) the resource's own account, and
//   - RESOURCE-CONFUSED-DEPUTY for a SERVICE principal (IAM-1203): a confused-deputy
//     exposure when unbound, a negative control when properly source-bound, or an
//     internally-inconsistent warning when SourceArn/SourceAccount disagree,
//   - RESOURCE-SAME-ACCOUNT-GRANT for a named principal in the resource's OWN account
//     (IAM-1204): the direct same-account resource-vs-identity grant, and
//   - RESOURCE-ACTION-RESOURCE-MISMATCH for an S3 object action scoped to a
//     bucket-only ARN (IAM-1204).
// Deterministic: statement order, then principal-entry order.
