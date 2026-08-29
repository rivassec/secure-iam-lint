// rules-catalog.js - RULES rule-definition catalog + RULE_IDS. Extracted (behavior-preserving; self-contained frozen data).

export const RULES = Object.freeze({
  'WILDCARD-ACTION': Object.freeze({
    id: 'WILDCARD-ACTION',
    order: 0,
    title: 'Wildcard action grant',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
  }),
  'WILDCARD-RESOURCE': Object.freeze({
    id: 'WILDCARD-RESOURCE',
    order: 1,
    title: 'Wildcard / overly broad resource scope',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html',
  }),
  'DIRECT-IAM-ADMIN': Object.freeze({
    id: 'DIRECT-IAM-ADMIN',
    order: 2,
    title: 'Direct IAM administration',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagement.html',
  }),
  'DATA-EXFIL': Object.freeze({
    id: 'DATA-EXFIL',
    order: 3,
    title: 'Sensitive data read / exfiltration',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
  }),
  'KMS-DECRYPT': Object.freeze({
    id: 'KMS-DECRYPT',
    order: 4,
    title: 'KMS decryption capability',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html',
  }),
  'DESTRUCTIVE-ACTION': Object.freeze({
    id: 'DESTRUCTIVE-ACTION',
    order: 5,
    title: 'Destructive action grant',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
  }),
  'DETECTION-IMPAIRMENT': Object.freeze({
    id: 'DETECTION-IMPAIRMENT',
    order: 6,
    title: 'Detection / logging impairment',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html',
  }),
  'NOTACTION-ALLOW': Object.freeze({
    id: 'NOTACTION-ALLOW',
    order: 7,
    title: 'Allow with NotAction (broad inverse grant)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html',
  }),
  // IAM-706: a lower-certainty, resource-scoped data-read capability. Neutral
  // framing on purpose ("data-read", NOT "exfiltration"): it covers a read scoped
  // to a NAMED bucket whose name only INFERS sensitivity, or to a policy-VARIABLE
  // resource whose ARN cannot be resolved. Distinct from DATA-EXFIL (broad-scope
  // bulk read / secret retrieval, high). Ordered last so it never displaces the
  // established rules within a statement.
  'DATA-READ': Object.freeze({
    id: 'DATA-READ',
    order: 8,
    title: 'Data-read capability (resource-scoped, inferred sensitivity)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html',
  }),
  // IAM-1005: indirect privilege assignment via group membership. Distinct from
  // DIRECT-IAM-ADMIN (a direct self-policy edit): iam:AddUserToGroup grants only
  // whatever the target group already carries, which this single policy cannot
  // establish. Ordered last so it never displaces the established rules.
  'GROUP-MEMBERSHIP': Object.freeze({
    id: 'GROUP-MEMBERSHIP',
    order: 9,
    title: 'Group-membership privilege assignment (iam:AddUserToGroup)',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_manage_add-remove-users.html',
  }),
  // S2-crossaccount-scoped-surface (B): a whole-container read (bucket / table /
  // stream / database bulk read) whose concrete resource account differs from the
  // analyzed/subject account. Surfaced REGARDLESS of resource name (the sensitivity
  // wordlist only RAISES severity, it never gates reporting). LOW/INFO band: it
  // crosses the account boundary, but whether the objects are actually reachable
  // depends on the target account's resource policy (bucket/table policy), which is
  // not in scope here. Ordered last so it never displaces the established rules.
  'CROSS-ACCOUNT-DATA-READ': Object.freeze({
    id: 'CROSS-ACCOUNT-DATA-READ',
    order: 10,
    title: 'Cross-account whole-container data read',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html',
  }),
  // S2-crossaccount-scoped-surface (iteration-5, S3 fail-open close): a whole-
  // container read (bucket/* or bucket list) on a CANONICAL S3 bucket ARN
  // (arn:aws:s3:::bucket/*), which carries NO account field and no aws:ResourceAccount
  // / s3:ResourceAccount condition pinning its owner. Its owning account is genuinely
  // not recoverable from the policy text, so the tool CANNOT clear it as same-account
  // - it must not read CLEAN (fail closed). Surfaced at INFO as an UNDETERMINED
  // (account-blind) cross-account read: the sibling CROSS-ACCOUNT-DATA-READ makes a
  // CONFIRMED cross-account claim (a resolvable, differing account), whereas this one
  // is explicit that the account is unknown and MUST NOT be read as a proven crossing
  // (threat-model T8). Ordered last so it never displaces the established rules.
  'CROSS-ACCOUNT-DATA-READ-UNDETERMINED': Object.freeze({
    id: 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED',
    order: 11,
    title: 'Whole-container S3 read with an undeterminable owning account',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html',
  }),
  // Stage-13 EFO-2: rewrite a resource's own policy to grant an external/arbitrary
  // principal access (cross-account exfil / key-control / backdoor). Distinct from
  // DIRECT-IAM-ADMIN (identity-policy edits).
  'RESOURCE-POLICY-WRITE': Object.freeze({
    id: 'RESOURCE-POLICY-WRITE',
    order: 12,
    title: 'Resource-policy write / cross-account grant',
    ruleVersion: '1',
    docRef:
      'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies-cross-account-resource-access.html',
  }),
});

export const RULE_IDS = Object.freeze(Object.keys(RULES));
