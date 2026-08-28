// resource-principal-classification.js - principalSubKind + fail-closed principal-type catalog (SUBKIND_LABELS, FAIL_CLOSED_PRINCIPAL_TYPES/META). Extracted (behavior-preserving).
import { parseArn } from './arn-util.js';

// Sub-kind of a named AWS principal entry, for wording that never conflates an IAM
// user, an IAM role, an assumed-role session, a federated-user session, a bare
// account, or an account-root principal (advanced invariant 5; tests 32/33). Reads
// the ARN's service + resource segment; partition-agnostic (test 47). An
// assumed-role-session ARN is identified as exactly one session and is NEVER
// rewritten to the role ARN.
export function principalSubKind(entry) {
  const type = entry && typeof entry === 'object' ? String(entry.type) : '';
  if (type === 'aws-account') return 'account';
  if (type === 'aws-root') return 'account-root';
  const arn = parseArn(entry && entry.value != null ? String(entry.value) : '');
  const svc = arn ? String(arn.service).toLowerCase() : '';
  const res = arn ? String(arn.resource) : '';
  if (svc === 'sts' && /^assumed-role\//i.test(res)) return 'role-session';
  if (svc === 'sts' && /^federated-user\//i.test(res)) return 'federated-user-session';
  if (svc === 'iam' && /^user\//i.test(res)) return 'user';
  if (svc === 'iam' && /^role\//i.test(res)) return 'role';
  return 'principal';
}

// Human labels for each principal sub-kind (inert display evidence).
export const SUBKIND_LABELS = Object.freeze({
  user: 'IAM user',
  role: 'IAM role',
  'role-session': 'assumed-role session (one exact session, not the underlying role)',
  'federated-user-session': 'federated-user session (one exact session)',
  account: 'AWS account (the account and its administrators, not the root user only)',
  'account-root': 'AWS account principal (the account and its administrators, not the root user only)',
  principal: 'AWS principal',
});

// --- Fail-closed unmodeled / invalid resource principals (IAM-1208 fix 4) ------
//
// A resource-policy Principal type that the resource evaluator does not model a
// finding for must never be SILENTLY DROPPED - zero findings would read as
// "nothing here is risky / the resource is safe", exactly the fail-open mistake
// the threat model forbids (T8; resource-policy-semantics.md 3.10 "the analyzer
// does not guess", 10.8 "unsupported != safe"). Two kinds fall here, both surfaced
// fail-closed, mirroring the trust family's "fail closed toward surfacing"
// (trust.js TRUST-INVALID-PRINCIPAL):
//   - canonical-user: a recognized S3 CanonicalUser principal (section 3.8). It
//     is a real principal type, but this analyzer does not model canonical-user
//     grants, so its reach is UNKNOWN - recognized-but-unmodeled, surfaced (not
//     dropped) so the reader knows a grant exists the analysis did not resolve.
//   - aws-principal-arn-wildcard / service-wildcard / federated-wildcard: an
//     INVALID Principal element - a partial "*"/"?" wildcard the Principal element
//     cannot use to match multiple principals/services/providers (section 3.3-3.7;
//     suite-2 test 48 / suite-3 tests 81-83). AWS rejects such a policy at save
//     time; the granted set is UNDETERMINED and it must be read as neither a
//     specific grant nor a broad one.
// Deterministic order (sorted) so a statement naming several of these emits its
// findings in a stable sequence.
export const FAIL_CLOSED_PRINCIPAL_TYPES = Object.freeze([
  'aws-principal-arn-wildcard',
  'canonical-user',
  'federated-oidc',
  'federated-saml',
  'federated-wildcard',
  'service-wildcard',
]);

export const FAIL_CLOSED_PRINCIPAL_META = Object.freeze({
  'canonical-user': {
    severity: 'medium',
    title: 'Resource grant to a CanonicalUser principal (recognized but unmodeled - fail closed)',
    why: (who, serviceLabel, acts) =>
      `The resource policy grants a CanonicalUser principal (${who}) permission to ` +
      `${acts} on this ${serviceLabel}. A CanonicalUser id is a recognized Amazon ` +
      'S3 account-principal form, but this analyzer does NOT model canonical-user ' +
      'grants, so WHO the id resolves to and how far the grant reaches are UNKNOWN ' +
      'from this document. It is surfaced fail-closed rather than dropped: the ' +
      'absence of a modeled finding does NOT mean the grant is safe (unsupported ' +
      '!= safe), and the CanonicalUser grant is never silently ignored.',
    remediation:
      'Prefer an explicit AWS account or IAM principal (e.g. Principal { "AWS": ' +
      '"arn:aws:iam::<account-id>:root" }) over a raw CanonicalUser id so the grant ' +
      'is auditable and this analyzer (and your reviewers) can resolve who it ' +
      'reaches. If the CanonicalUser form is required, confirm out-of-band exactly ' +
      'which account/identity the canonical id belongs to and that it is intended ' +
      'to have this access.',
  },
  'aws-principal-arn-wildcard': {
    severity: 'high',
    title: 'Invalid wildcard Principal ARN on a resource policy (fail closed)',
    why: (who, serviceLabel, acts) =>
      `The resource policy names an AWS Principal ARN that uses a partial "*"/"?" ` +
      `wildcard to denote multiple principals (${who}) while granting ${acts} on ` +
      `this ${serviceLabel}. This is NOT a valid IAM Principal element: a principal ` +
      'ARN cannot use a partial wildcard to match multiple user/role principals ' +
      '(AWS rejects such a policy at save time), and the standalone Principal "*" is ' +
      'the ONLY wildcard the element accepts. The granted set is therefore ' +
      'UNDETERMINED from this document - it is neither a single specific principal ' +
      'nor trust/access for "every principal the pattern appears to match" - so the ' +
      'statement is surfaced fail-closed rather than expanded or dropped.',
    remediation:
      'A principal-ARN wildcard is invalid in the Principal element. Name the exact ' +
      'account/role/user ARN that should have this access. To scope a SET of ' +
      'principals matching a pattern, use Principal "*" together with an ' +
      'aws:PrincipalArn condition (e.g. ArnLike aws:PrincipalArn ' +
      'arn:aws:iam::<account-id>:role/app/*) - the wildcard is valid in that ' +
      'condition value, not in the Principal element itself.',
  },
  'service-wildcard': {
    severity: 'high',
    title: 'Invalid wildcard Service principal on a resource policy (fail closed)',
    why: (who, serviceLabel, acts) =>
      `The resource policy names a Service principal that contains a partial ` +
      `"*"/"?" wildcard (${who}) while granting ${acts} on this ${serviceLabel}. ` +
      'This is NOT a valid Principal element: an AWS Service principal is an EXACT ' +
      'service identifier (e.g. events.amazonaws.com) and the Principal element does ' +
      'not wildcard-match service names, so a member carrying a wildcard matches NO ' +
      'service and grants no service relationship. The granted set is UNDETERMINED, ' +
      'so the statement is surfaced fail-closed rather than read as a normal, ' +
      'complete service grant.',
    remediation:
      'A wildcard is invalid in a Service principal. Name each exact service ' +
      'identifier you intend to grant (e.g. events.amazonaws.com, ' +
      's3.amazonaws.com), one per member; the Service principal element does not ' +
      'support "*"/"?" matching. Add a confused-deputy source binding ' +
      '(aws:SourceArn / aws:SourceAccount) for each service that needs access.',
  },
  'federated-oidc': {
    severity: 'medium',
    title: 'Resource grant to a Federated (OIDC) principal (recognized but unmodeled - fail closed)',
    why: (who, serviceLabel, acts) =>
      `The resource policy names a Federated OIDC identity-provider principal (${who}) ` +
      `while granting ${acts} on this ${serviceLabel}. A Federated principal is a ` +
      'recognized IAM principal form, but AWS treats OIDC/SAML Federated principals as ' +
      'valid ONLY in role-trust policies (sts:AssumeRoleWithWebIdentity), not on other ' +
      'resource-based policies, and this analyzer does NOT model what a Federated grant ' +
      'reaches on a resource policy. WHO it resolves to and how far it reaches are ' +
      'UNDETERMINED from this document. It is surfaced fail-closed rather than dropped: ' +
      'the absence of a modeled finding does NOT mean the grant is safe (unsupported != ' +
      'safe), and the Federated grant is never silently ignored.',
    remediation:
      'Do not place an OIDC Federated principal on a non-trust resource policy - it ' +
      'belongs in a role-trust policy consumed via sts:AssumeRoleWithWebIdentity. If ' +
      'you intend cross-account or external access to this resource, name the specific ' +
      'AWS account, role, or service principal that must reach it, and grant the ' +
      'federated identity access to a ROLE (via that role\'s trust policy) instead.',
  },
  'federated-saml': {
    severity: 'medium',
    title: 'Resource grant to a Federated (SAML) principal (recognized but unmodeled - fail closed)',
    why: (who, serviceLabel, acts) =>
      `The resource policy names a Federated SAML identity-provider principal (${who}) ` +
      `while granting ${acts} on this ${serviceLabel}. A Federated principal is a ` +
      'recognized IAM principal form, but AWS treats OIDC/SAML Federated principals as ' +
      'valid ONLY in role-trust policies (sts:AssumeRoleWithSAML), not on other ' +
      'resource-based policies, and this analyzer does NOT model what a Federated grant ' +
      'reaches on a resource policy. WHO it resolves to and how far it reaches are ' +
      'UNDETERMINED from this document. It is surfaced fail-closed rather than dropped: ' +
      'the absence of a modeled finding does NOT mean the grant is safe (unsupported != ' +
      'safe), and the Federated grant is never silently ignored.',
    remediation:
      'Do not place a SAML Federated principal on a non-trust resource policy - it ' +
      'belongs in a role-trust policy consumed via sts:AssumeRoleWithSAML. If you ' +
      'intend cross-account or external access to this resource, name the specific AWS ' +
      'account, role, or service principal that must reach it, and grant the federated ' +
      'identity access to a ROLE (via that role\'s trust policy) instead.',
  },
  'federated-wildcard': {
    severity: 'high',
    title: 'Invalid wildcard Federated principal on a resource policy (fail closed)',
    why: (who, serviceLabel, acts) =>
      `The resource policy names a Federated principal that contains a partial ` +
      `"*"/"?" wildcard (${who}) while granting ${acts} on this ${serviceLabel}. ` +
      'This is NOT a valid Principal element: a Federated principal is a SPECIFIC ' +
      'identity-provider ARN (an IAM OIDC/SAML provider) or a built-in OIDC ' +
      'hostname, and the Principal element does not wildcard-match provider ARNs, so ' +
      'a member carrying a wildcard matches NO provider and establishes no ' +
      'relationship. The granted set is UNDETERMINED, so the statement is surfaced ' +
      'fail-closed rather than read as a complete federated grant. (AWS also treats ' +
      'OIDC/SAML Federated principals as valid only in role-trust policies, not on ' +
      'other resource-based policy types.)',
    remediation:
      'A wildcard is invalid in a Federated principal. Name the exact identity-' +
      'provider ARN you intend to grant (e.g. arn:aws:iam::<account-id>:oidc-' +
      'provider/<provider-host>); the Federated principal element does not support ' +
      '"*"/"?" matching. Note that OIDC/SAML federated principals belong in a role ' +
      'trust policy, not most resource policies.',
  },
});
