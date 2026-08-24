# IAM Blast Radius - Resource-Policy Semantics (AWS-verified reference)

Grounding spec for the resource-policy feature (Phase 12). Stories
IAM-1200..1207 build against this document. It changes no shipped code; it is
the source of truth for how the resource evaluator must classify a
resource-based policy (S3 bucket/object, SNS topic, SQS queue, KMS key, and the
generic shape).

Every claim below is verified against current AWS documentation. Sources are
cited inline by number and listed at the end. ASCII only. No secrets.

---

## 0. The load-bearing invariant (read this first)

**A resource-based policy is analyzed from the RESOURCE's perspective: who may
act on THIS attached resource, under what conditions.** It is NOT an identity
policy and must never be run through identity rules.

A resource-based policy is attached to a resource (an S3 bucket, an SNS topic,
an SQS queue, a KMS key, an IAM role's trust policy, etc.) and specifies the
`Principal` that is allowed or denied access to that resource [1][2]. The
`Principal` element is required in a resource-based policy and cannot appear in
an identity-based policy [2].

Therefore, for every resource finding this analyzer emits:

- **The resource-policy context (attached resource type + ARN) is EXPLICIT and
  required.** "Who can act on this resource" is only meaningful relative to a
  known attached resource. A resource policy supplied with no resource context
  fails closed (`RESOURCE_CONTEXT_REQUIRED`); the analyzer never guesses the
  resource type or ARN.
- The finding describes the direct resource-policy grant (which principals may
  perform which actions on this resource). **Effective access still depends on
  the principal's identity policies, permissions boundaries, session policies,
  SCPs/RCPs, and service-specific controls that are NOT supplied.** Every
  resource finding must carry that limitation. This is potential blast radius,
  NOT effective permissions (threat-model T8).
- The analyzer classifies policy TEXT. It never asserts that a specific runtime
  AWS request would be allowed or denied.

Corollary: a resource policy is NOT an identity policy. Do not emit an
identity-style "broad IAM capability" finding on it. `Resource` in a resource
policy is contextual to the attached resource (see section 6), not an
identity-policy wildcard-blast surface.

---

## 1. Resource-vs-identity evaluation (the difference that matters)

This is the single most important semantic difference between a resource policy
and an identity policy, and the analyzer must state it plainly.

### 1.1 Same account: identity OR resource is enough

Within a single account, AWS evaluates the union of identity-based and
resource-based permissions: "If an action is allowed by an identity-based
policy, a resource-based policy, or both, then AWS allows the action. An
explicit deny in either of these policies overrides the allow." [3]

Consequence for the analyzer: a resource-policy `Allow` to a same-account
principal can grant access **even when that principal's identity policy is
silent** (implicit deny in the identity policy does not, on its own, defeat a
direct same-account resource-policy grant). This is why a same-account
resource-policy grant is materially different from an identity grant
(acceptance-suite-2 test 32). But an **applicable explicit `Deny`** - in the
identity policy, a permissions boundary, an SCP/RCP, or the resource policy
itself - still blocks [3]. State both halves; do not over-claim the grant.

Do not generalize the same-account behavior to cross-account principals or
silently treat a role principal and a role-session principal as the same thing
(section 5.4; test 32, test 33).

### 1.2 Cross account: BOTH sides must allow

For a cross-account request, "AWS performs two evaluations... The request is
allowed only if both evaluations return a decision of `Allow`." [4] The
resource-based policy in the trusting (resource-owning) account must name the
external principal, AND that principal's identity-based policy in its own
account must allow the action against the resource ARN [4]. An explicit deny in
either account is decisive [4].

Consequence: a cross-account `Allow` in the resource policy is a NECESSARY but
not SUFFICIENT condition for access. The analyzer reports the resource side it
can see and states that the caller's account must also grant the action - it is
unknown here.

### 1.3 The universal rule

An applicable explicit `Deny` always overrides an `Allow`, in every layer
[3][4]. A resource `Allow` is potential reach; a matching explicit `Deny` is a
hard block; the absence of an `Allow` elsewhere may still stop a cross-account
request. The analyzer never collapses "the resource policy allows X" into "X is
effective."

---

## 2. Per-service resource shapes

All of these are resource-based policies with the same JSON grammar (`Effect`,
`Principal`/`NotPrincipal`, `Action`, `Resource`, `Condition`) [2]. The service
context changes the resource ARN grammar, the action namespace, and some
evaluation nuances. The analyzer detects the service from the supplied resource
type/ARN and routes to the resource evaluator - never to identity rules.

### 2.1 Amazon S3 - bucket policy and object scope

- Bucket ARN: `arn:aws:s3:::bucket-name`.
- Object ARN: `arn:aws:s3:::bucket-name/key` or `arn:aws:s3:::bucket-name/*`.
- **Bucket-vs-object typing matters.** Object actions (for example
  `s3:GetObject`, `s3:PutObject`) require an object-scoped resource
  (`.../*` or a specific key); a bucket-only ARN does not identify objects.
  Bucket actions (for example `s3:GetBucketPolicy`, `s3:ListBucket`) require the
  bucket ARN. A resource policy that grants `s3:GetObject` on a bucket-only ARN
  is an action/resource-type mismatch, not confirmed object read
  (acceptance-suite-2 test 50; the same warning applies in the resource
  context). Remediation must distinguish bucket actions from object actions.
- S3 also has an external control (Block Public Access) that can override a
  public bucket policy - see section 4.

### 2.2 Amazon SNS - topic access policy

- Topic ARN: `arn:aws:sns:region:account-id:topic-name`.
- A resource-based access policy on the topic; commonly grants `sns:Publish` or
  `sns:Subscribe` to a service principal (for example S3 event notifications,
  EventBridge) or another account [2]. Service-principal grants need
  confused-deputy binding (section 3; test 26/27).

### 2.3 Amazon SQS - queue access policy

- Queue ARN: `arn:aws:sqs:region:account-id:queue-name`.
- A resource-based access policy on the queue; commonly grants `sqs:SendMessage`
  to a service principal or another account [2]. Same confused-deputy
  considerations as SNS.

### 2.4 AWS KMS - key policy

- Key ARN: `arn:aws:kms:region:account-id:key/key-id`.
- A KMS key policy is the primary access control for the key and has
  service-specific semantics (section 7). Two facts the analyzer must never get
  wrong: the account-root delegation statement is neither public nor
  root-user-only (section 7.1), and `Resource: "*"` in a key policy means the
  ATTACHED key, not every key in the account (section 6; test 51).

### 2.5 Generic / other resource-based policies

Many services support resource-based policies (Lambda, Secrets Manager, ECR,
API Gateway, OpenSearch, EventBridge buses, etc.) [2]. For a recognized-but-
unmodeled resource shape, the analyzer FAILS CLOSED (surfaces it in coverage as
unsupported) rather than applying S3/KMS-specific reasoning to a service whose
nuances are not modeled. "Unsupported != safe."

---

## 3. Principal types in a resource policy

The `Principal` element names who is allowed or denied. All syntax below is from
the AWS `Principal` reference [2]. Multiple values under one principal type form
a logical OR (you authenticate as one principal at a time) [2]. You cannot use a
wildcard to match part of a principal name or ARN [2].

### 3.1 Anonymous / public (`*`)

```
"Principal": "*"
"Principal": { "AWS": "*" }
```

These are equivalent and mean **all principals, including anonymous (public)
access** [2]. AWS: "using a wildcard (*) with an `Allow` effect grants access to
all users, including anonymous users (public access)" and "strongly recommend
that you do not use a wildcard (*) in the `Principal` element of a resource-based
policy with an `Allow` effect unless you intend to grant public or anonymous
access" [2].

- Analyzer classification: **anonymous** -> PUBLIC-ACCESS, severity
  **critical/high** (test 28 PublicRead; suite-3 test 69). A `*` principal
  narrowed by an `aws:PrincipalArn` condition is NOT unconditioned public -
  account for the condition (suite-3 test 85; do not reject the wildcard in the
  condition VALUE as a partial-ARN principal wildcard).

### 3.2 AWS account and root

```
"Principal": { "AWS": "arn:aws:iam::123456789012:root" }
"Principal": { "AWS": "123456789012" }
```

The account ARN (`...:root`) and the bare 12-digit account ID behave
identically: "Both delegate permissions to the account. Using the account ARN in
the `Principal` element does not limit permissions to only the root user of the
account." [2] An administrator in the trusted account must then grant one of its
identities permission to use the access [2].

- Analyzer classification: **aws-account** (bare id) or **aws-root** (`:root`
  ARN) -> ACCOUNT-DELEGATION. **Not public. Not root-user-only** (test 25 for
  the trust family; the same rule holds on any resource policy, and for the KMS
  account-root statement in test 51). Cross-account when the account differs
  from the resource's own account.

### 3.3 IAM user ARN

```
"Principal": { "AWS": "arn:aws:iam::123456789012:user/user-name" }
```

Names a specific IAM user; a wildcard cannot mean "all users" [2]. In a role
trust policy a user ARN transforms to the user's unique principal ID on save (to
resist delete-and-recreate escalation) [2].

- Analyzer classification: **aws-principal-arn** (user).

### 3.4 IAM role ARN

```
"Principal": { "AWS": "arn:aws:iam::123456789012:role/role-name" }
```

An IAM role principal. "When you specify a role principal in a resource-based
policy, the effective permissions for the principal are limited by any policy
types that limit permissions for the role" - session policies and permissions
boundaries [2]. AWS recommends using the role ARN rather than a role-session ARN
wherever possible [2].

- Analyzer classification: **aws-principal-arn** (role).

### 3.5 Role-session and federated-user-session ARN

```
"Principal": { "AWS": "arn:aws:sts::123456789012:assumed-role/role-name/session-name" }
"Principal": { "AWS": "arn:aws:sts::123456789012:federated-user/user-name" }
```

A role-session principal identifies ONE exact assumed-role session (role +
session name) [2]; a federated-user session ARN identifies one
`GetFederationToken` session [2]. **The analyzer must NOT collapse an
assumed-role-session ARN to the underlying role ARN** (test 33): they are
distinct principals with distinct boundary/session behavior.

- Analyzer classification: **aws-principal-arn** (role-session / federated-user
  session), identified as exactly one session.

### 3.6 Service principal

```
"Principal": { "Service": "events.amazonaws.com" }
"Principal": { "Service": [ "ecs.amazonaws.com", "elasticloadbalancing.amazonaws.com" ] }
```

An AWS service identifier, usually `service-name.amazonaws.com` [2]. Multiple
services go in an array under a single `Service` key [2]. `"Service": "*"` is not
valid [2]. Note the opt-in-Region regionalized form
(`service-name.region.amazonaws.com`) for cross-Region service calls [2].

- Analyzer classification: **service**. **A service principal is NOT a public
  principal.** Do not describe a resource granting a service principal as
  "publicly writable" (test 26). A service grant without source binding is a
  confused-deputy exposure (section 3, next), not public access.

### 3.7 Federated - OIDC and SAML

```
"Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/<provider-url>" }
"Principal": { "Federated": "arn:aws:iam::123456789012:saml-provider/provider-name" }
```

Federated principals (an OIDC provider, one of the four built-in OIDC IdPs, or a
SAML provider in the account) are used with
`sts:AssumeRoleWithWebIdentity` / `sts:AssumeRoleWithSAML` [2]. AWS states OIDC
and SAML federated principals are only valid in ROLE TRUST policies, not other
resource-based policy types [2]. If a `Federated` principal appears on a
non-trust resource policy, treat the shape as unusual and surface it in
coverage.

- Analyzer classification: **federated-oidc** / **federated-saml** (see
  trust-policy-semantics.md for subject-scope severity in the trust family).

### 3.8 CanonicalUser (S3)

```
"Principal": { "CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be" }
```

An S3 canonical user ID - an Amazon S3-specific account-principal form [2]. It is
a recognized resource-policy principal type (mainly S3), not a role-trust
principal.

- Analyzer classification: **canonical-user** (recognized).

### 3.9 NotPrincipal (fail closed + hazard warning)

`NotPrincipal` is a distinct element (everyone EXCEPT the listed principals) and
is a known trap - see section 8. On a resource/trust policy it must surface the
specific Deny+NotPrincipal hazard, never render as an ordinary exclusion. It is
never silently treated as `Principal`. In an IDENTITY policy it stays rejected
(`UNSUPPORTED_NOTPRINCIPAL`) as before [5].

### 3.10 Unknown / unmodeled principal types (fail closed)

Any `Principal` shape not in 3.1-3.8 keeps the shape unsupported and is surfaced
in coverage ("unsupported != safe"). The analyzer does not guess.

---

## 4. Confused deputy for service principals (source binding)

When an AWS service principal (a calling service such as CloudTrail,
EventBridge, S3 notifications) is granted access to your resource, "the resource
policy from the called service is only authorizing the AWS service principal, and
not the actor who configured the calling service" [6]. An S3 bucket that trusts
`cloudtrail.amazonaws.com` with no conditions could receive logs from an
unauthorized actor's account if they know the bucket name [6]. That is the
cross-service confused deputy.

AWS mitigation - use these condition keys in the resource policy "wherever an AWS
service principal is granted permission to access one of your resources" [6]:

- **`aws:SourceArn`** - allow the service principal to act only on behalf of a
  specific source resource (a specific trail, fleet, rule, etc.); compare with
  `ArnEquals`/`ArnLike` [6].
- **`aws:SourceAccount`** - allow the service principal to act only on behalf of
  a specific account; compare with `StringEquals` [6].
- **`aws:SourceOrgID`** / **`aws:SourceOrgPaths`** - on behalf of a specific
  organization or org path [6].

These keys are populated only when the request is made by an AWS service
principal on your behalf [6]. Analyzer polarity:

- Service principal **without** `aws:SourceArn`/`aws:SourceAccount` (or
  SourceOrgID) -> **confused-deputy exposure** finding (high/medium), naming the
  missing source binding, subject to service support. **Do not call the resource
  publicly writable** - the principal is a service, not `*` (test 26).
- Service principal **properly source-bound** (for example `ArnEquals
  aws:SourceArn` AND `StringEquals aws:SourceAccount`, ANDed) -> **negative
  control**, informational/low, no "missing source binding" warning. Do not
  infer whether the referenced source resource exists (test 27).
- **Mismatched** `aws:SourceAccount` vs the account component of
  `aws:SourceArn` -> warn the constraint is internally inconsistent / likely
  ineffective; do not praise it as source-bound, and do not turn the mismatch
  into a public-write finding (test 53).

This reuses the trust-family confused-deputy logic; the same reasoning as
`sts:ExternalId` for cross-account role trust, applied to service principals on a
resource policy.

---

## 5. Transport constraints vs identity constraints (do not confuse them)

**A transport constraint is NOT an identity constraint. A transport `Deny` does
not make public access private.** This is the crux of acceptance-suite-2 test 28.

`aws:SecureTransport` is a global condition key that checks whether the request
was sent over SSL/TLS: true if the request used HTTPS, false if HTTP [7][10]. A
common S3 pattern denies all actions when `aws:SecureTransport` is `false`, i.e.
it forces HTTPS [7]. That is a good hygiene control - but it constrains the
TRANSPORT (HTTP vs HTTPS), not WHO may act.

Given a policy with (a) `Allow Principal:* s3:GetObject` (public read) and (b)
`Deny Principal:* s3:* Condition Bool aws:SecureTransport=false`:

- The public read Allow remains fully effective over HTTPS. The Deny only
  removes the plaintext-HTTP path. The object is still publicly readable to
  anyone, over TLS.
- The analyzer must classify the Deny as **transport-only** and must NOT claim
  it suppresses the `PublicRead` Allow (test 28).

Confirmation from S3's own "meaning of public" logic: when S3 decides whether a
bucket policy is public, it "begins by assuming that the policy is public" and
considers it non-public only if access is restricted to fixed values of a
specific set of keys - an AWS principal, `aws:SourceIp`, `aws:SourceArn`,
`aws:SourceVpc`, `aws:SourceVpce`, `aws:SourceOwner`, `aws:SourceAccount`,
`aws:userid`, or the access-point keys [8]. **`aws:SecureTransport` is not in
that list**, so adding a `SecureTransport` condition does not make a
`Principal:*` policy non-public [8].

### 5.1 Block Public Access is a separate external control

Whether the public read is actually reachable also depends on **S3 Block Public
Access (BPA)**, which is a distinct account/bucket/access-point/org-level control
that "override[s] these policies and permissions" and is "enforced regardless of
how the resources are created" [8]. BPA is NOT part of the bucket policy; if BPA
is not supplied to the analyzer, actual exposure depends on that external control
and the analyzer must say so (test 28). The analyzer never assumes BPA is on or
off.

---

## 6. `Resource` in a resource policy is contextual

`Resource` in a resource-based policy scopes the statement to (part of) the
ATTACHED resource - it is not an identity-policy blast surface.

- **KMS key policy:** "In a key policy, the value of the Resource element is
  `"*"`, which means 'this KMS key.' The asterisk (`"*"`) identifies the KMS key
  to which the key policy is attached." [9] The analyzer must NEVER expand
  `Resource:*` in a key policy into "every KMS key in the account," and must
  never create a graph node per KMS key (test 51). `Resource:*` here is the one
  attached key.
- **S3 bucket policy:** `Resource` names the bucket and/or its objects; object
  actions need `.../*` or a key, bucket actions need the bucket ARN (section 2.1;
  test 50).
- General rule: interpret `Resource` relative to the supplied resource context.
  A resource-policy `Resource:*` is contextual to the attached resource, not an
  identity-style "all resources" wildcard, and must not be scored as an
  identity broad-resource finding.

---

## 7. Account-delegation semantics (not public, not root-only)

### 7.1 KMS "Enable IAM User Permissions"

The default KMS key-policy statement:

```
{
  "Sid": "Enable IAM User Permissions",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
  "Action": "kms:*",
  "Resource": "*"
}
```

AWS: this statement "gives the AWS account that owns the KMS key full access to
the KMS key" and "allows the account to use IAM policies to allow access to the
KMS key, in addition to the key policy." [11] Critically: "When the principal in
a key policy statement is the account principal, the policy statement doesn't
give any IAM principal permission to use the KMS key. Instead, it allows the
account to use IAM policies to delegate the permissions specified in the policy
statement." [11] And: "A principal in `arn:aws:iam::111122223333:root` format
does not represent the AWS account root user, despite the use of 'root'... the
account principal represents the account and its administrators, including the
account root user." [9]

Analyzer rules for this statement (test 51):

- Report **broad KMS authority delegated to the OWNING ACCOUNT**
  (ACCOUNT-DELEGATION), high-level breadth.
- **Do NOT call the key public** (the principal is one account root ARN, not
  `*`).
- **Do NOT say only the root user can administer the key** (the account
  principal is the account + its IAM-empowered admins, not solely root).
- Explain that KMS key-policy + IAM interaction needs service-specific semantics,
  and which individual principals are actually reachable is UNKNOWN without the
  account's identity policies.
- `Resource:*` = the attached key only (section 6).

Note the KMS-specific twist: unlike other resource policies, a KMS key policy
does NOT automatically let the owning account's IAM policies govern the key -
that authority exists only because this explicit statement grants it [11]. So its
absence is meaningful for KMS; do not treat a KMS key policy like an S3 bucket
policy.

### 7.2 S3 same-account grants

A same-account resource-policy grant to a specific user/role/session principal is
a direct grant whose evaluation differs from an identity grant (section 1.1;
tests 32, 33). Report the direct grant with the resource-vs-identity caveat; an
applicable explicit deny still applies; do not generalize to cross-account or
conflate role vs session.

---

## 8. The Deny + NotPrincipal hazard (semantic warning, not ordinary exclusion)

`NotPrincipal` must be used with `"Effect":"Deny"`; using it with `Allow` is not
supported [5]. Semantically it denies access to all principals EXCEPT those
listed. It is a trap and must never be modeled as a plain "deny everyone except
these" exclusion.

The documented hazard [5]: "Don't use resource-based policy statements that
include a `NotPrincipal` policy element with a `Deny` effect for IAM users or
roles that have a permissions boundary policy attached. The `NotPrincipal`
element with a `Deny` effect will always deny any IAM principal that has a
permissions boundary policy attached, regardless of the values specified in the
`NotPrincipal` element." So principals you intended to EXEMPT can still be denied
if they carry a permissions boundary [5].

AWS also warns that `NotPrincipal` makes troubleshooting hard and recommends the
`aws:PrincipalArn` condition key with `ArnNotEquals` instead - a `Deny` on
`Principal:*` with `ArnNotEquals aws:PrincipalArn <allowed-arn>` [2][5]. And when
`NotPrincipal` is used you must also list the account ARN of the not-denied
principal, or you may deny the whole account [5].

Analyzer rules (test 29):

- On a resource (or trust) policy, `Deny + NotPrincipal` -> a **high-confidence
  semantic hazard warning**: state the permissions-boundary caveat and recommend
  `ArnNotEquals` with `aws:PrincipalArn`.
- This may remain a blocking / fail-closed coverage state
  (`UNSUPPORTED_NOTPRINCIPAL`) - but it MUST surface the specific hazard, never
  silently render an ordinary deny graph.
- `NotPrincipal` in an identity policy stays rejected as before [5]. It is also
  not supported in SCPs/RCPs [5].

---

## 9. Condition composition (AND across keys, OR within values)

A single `Condition` block combines multiple distinct condition keys with
logical **AND**; multiple values for the SAME key combine with logical **OR**
(for a single-valued context key). The analyzer must preserve this structure and
not simplify it (test 49).

Example: `StringEquals` with `aws:SourceVpce: [vpce-A, vpce-B]` AND
`aws:PrincipalTag/environment: "production"` means (source VPCe is A OR B) AND
(principal tag environment == production). Report broad `Principal:*` syntax as
CONSTRAINED by a network selector AND a principal-tag selector - do not reduce it
to "VPCe OR tag" (test 49). Multivalued context keys additionally require the
`ForAllValues`/`ForAnyValue` set operators to be reasoned about correctly [8];
missing set operators / `Null` / `...IfExists` / negated operators must not be
turned into wrong "key is missing / protective" conclusions.

Unknown or unmodeled conditions remain **context-required** and are NEVER
credited as protective ("unsupported != safe"); they feed path-exploitability
and coverage, and the analyzer must not claim a runtime request will match.

---

## 10. Load-bearing invariants (the fail-closed contract)

Every one of these is a hard rule for the resource evaluator:

1. **Resource-policy context is explicit.** The attached resource type + ARN are
   required inputs. Missing required context -> fail closed
   (`RESOURCE_CONTEXT_REQUIRED`); never guess.
2. **Potential blast radius, not effective permissions.** Every resource finding
   states that effective access depends on identity policies, permissions
   boundaries, session policies, SCPs/RCPs, and service controls not supplied
   [3][4].
3. **A service principal is NOT a public principal.** A service grant without
   source binding is a confused-deputy exposure, not public write (test 26) [6].
4. **An account principal is NOT root-user-only.** The `:root` ARN and bare
   account id both delegate to the whole account and its admins, not solely the
   root user (test 25, test 51) [2][9][11].
5. **A transport constraint is NOT an identity constraint.** An
   `aws:SecureTransport` Deny does not make public access private; BPA is a
   separate external control (test 28) [7][8].
6. **`Resource:*` in a KMS key policy is the ATTACHED key, not every key.** No
   per-key node explosion (test 51) [9].
7. **Route resource statements to the resource evaluator, never identity
   rules.** No identity-style broad-`Resource` finding on a resource policy.
8. **Fail closed on genuinely-unmodeled resource shapes** and on
   `NotPrincipal`/other recognized-but-unmodeled elements; surface them in
   coverage. "Unsupported != safe."
9. **Never assert a runtime AWS allow/deny.** The analyzer classifies policy
   text; it does not simulate the authorization engine. An applicable explicit
   `Deny` still blocks [3][4].
10. **SCP/RCP families stay DEFERRED (Phase 13).** They are not resource-based
    grants in this family and are not built here.

---

## Sources

All URLs are current AWS documentation, verified for this reference.

1. Identity-based policies and resource-based policies (definitions):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html
2. AWS JSON policy elements: Principal (all Principal types and syntax, account
   root delegates to the whole account, `*` public-access warning, service
   principal array form, CanonicalUser, role-session principals):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
3. Policy evaluation logic - Evaluating identity-based policies with
   resource-based policies (same-account union; explicit deny overrides):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
4. Cross-account policy evaluation logic (both account evaluations must allow;
   explicit deny in either is decisive):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html
5. AWS JSON policy elements: NotPrincipal (Deny+NotPrincipal permissions-boundary
   hazard; `aws:PrincipalArn` + `ArnNotEquals` recommendation; not in identity
   policies / SCP / RCP):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html
6. The confused deputy problem (cross-service; `aws:SourceArn`,
   `aws:SourceAccount`, `aws:SourceOrgID`, `aws:SourceOrgPaths` on resource
   policies granting service principals):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
7. Protecting data in transit with encryption (`aws:SecureTransport` HTTPS-only
   S3 bucket-policy pattern):
   https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingEncryptionInTransit.html
8. Blocking public access to your Amazon S3 storage (BPA overrides bucket
   policies; the "meaning of public" fixed-value key list, which excludes
   `aws:SecureTransport`; multivalued set operators):
   https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
9. Creating a key policy - key policy elements (`Resource:"*"` means "this KMS
   key"; account principal is the account + admins, not the root user):
   https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html
10. AWS global condition context keys (`aws:SecureTransport`):
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
11. Default key policy - Allows access to the AWS account and enables IAM
    policies (account gets full access via IAM delegation; not root-only; without
    it IAM allow policies are ineffective but IAM deny still applies):
    https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html
