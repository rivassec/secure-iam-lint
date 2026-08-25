# IAM Blast Radius - Per-Service Resource-Policy Semantics (AWS-verified reference)

Grounding spec for Phase 14 ("per-service resource-policy finding rules"). This
document EXTENDS `docs/resource-policy-semantics.md` (the generic resource
grounding, Phase 12); it does not repeat it. Where the generic evaluator treats
every resource policy alike, this reference names the per-service authorization
nuances that make the SAME syntax mean DIFFERENT things on S3 vs KMS vs SNS vs
SQS. Stories IAM-1400..1404 build against this document; it changes no shipped
code.

Every service-specific claim below is verified against current AWS documentation.
Sources are cited inline by number and listed at the end. ASCII only. No secrets.

The load-bearing contract is unchanged from the generic doc and is repeated here
because every per-service rule inherits it:

- **Potential blast radius, NOT effective access.** Every per-service finding
  carries `RESOURCE_LIMIT`: it reports the direct resource-policy grant read from
  the resource's perspective, never effective/granted access. Effective access
  also depends on the caller's identity policies, permissions boundaries, session
  policies, SCPs/RCPs, and service controls that are not supplied here; for
  cross-account access the caller's own account must ALSO allow it; an applicable
  explicit Deny in any layer still blocks [g3][g4].
- **Fail closed.** On unmodeled, ambiguous, or invalid input a per-service rule
  must SURFACE (>=1 finding or a coverage warning), never silently drop and never
  return `ok:true` on a rejected context. "Unsupported != safe."
- **A `*` narrowed by a genuine identity/org condition is NOT anonymous-critical**
  (section 6), and **a service principal is not a public principal** [g4].

`[g#]` citations refer to the sources in `resource-policy-semantics.md`; `[#]`
citations are this document's own sources (at the end).

---

## 0. What "per-service" adds over the generic evaluator

The generic evaluator (`engine/resource.js`, hardened by IAM-1208) already emits
PUBLIC-ACCESS, RESOURCE-CROSS-ACCOUNT, RESOURCE-CONFUSED-DEPUTY,
RESOURCE-SAME-ACCOUNT-GRANT, RESOURCE-KMS-ACCOUNT-DELEGATION,
RESOURCE-ACTION-RESOURCE-MISMATCH, and RESOURCE-UNSUPPORTED-PRINCIPAL, and it
already credits the principal-identity scoping keys (`aws:PrincipalArn`,
`aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`,
`aws:PrincipalType`, `aws:userid`, `aws:PrincipalTag/*`, `aws:SourceArn`,
`aws:SourceAccount`) as narrowing an anonymous `*`.

Per-service rules add the deltas the generic path CANNOT get right because they
depend on the service:

1. **The meaning of `Principal:"*"` is service-specific.** On S3 and SQS a
   wildcard-principal Allow is genuinely ANONYMOUS / unauthenticated public
   access (section 1, 4). On KMS the SAME `*` is "all AWS identities in all
   accounts" with NO unauthenticated path at all - not anonymous (section 3).
   The generic PUBLIC-ACCESS wording ("including anonymous, unauthenticated
   callers") is correct for S3/SQS and WRONG for KMS.
2. **Service-specific narrowing keys.** `kms:ViaService` and `kms:CallerAccount`
   (section 3.3), and the S3 "meaning of public" fixed-value key set
   (section 1.2), are keys the generic scoping set does not model, and two of
   them (`kms:ViaService`, the S3 network keys) narrow the CHANNEL, not the
   principal - crediting them as identity scoping is a false-negative trap.
3. **Service-specific request-property Deny keys.** `s3:x-amz-server-side-encryption`
   and `s3:TlsVersion` are transport/content constraints, exactly like
   `aws:SecureTransport` (test 28): a Deny on them does NOT make a public grant
   private (section 1.3).
4. **Service-specific dangerous / control-plane actions.** `s3:PutBucketPolicy`,
   `kms:PutKeyPolicy`, `kms:CreateGrant`, `sns:Subscribe`, `sqs:ReceiveMessage`
   etc. carry a blast radius the generic "who can act" enumeration does not rank
   (sections 1.4, 3.4, 4.2).
5. **Service-specific fail-closed caveats.** S3 Block Public Access (out of policy
   scope), and the KMS silent-key-policy inversion (sections 1.5, 3.5).

---

## 1. Amazon S3 bucket policy

Resource: `s3-bucket` / `s3-object` (`arn:aws:s3:::bucket[/key]`). The S3 bucket
policy is the canonical anonymous-public-exposure surface: unlike KMS/SNS/SQS
control-plane calls, S3 object reads can be made by unauthenticated HTTP clients,
so `Principal:"*"` on S3 is public in the strongest sense [1].

### 1.1 Public `*` vs narrowed `*`

- **Bare `Principal:"*"` (or `{"AWS":"*"}`) on an Allow = anonymous public
  access** [1]. Severity **critical**. AWS: a wildcard principal on an Allow
  "grants access to all users, including anonymous users (public access)" [1].
- A `*` **narrowed by a principal-IDENTITY condition** (`aws:PrincipalOrgID`,
  `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalTag/*`, `aws:userid`,
  `aws:PrincipalOrgPaths`, `aws:PrincipalType`) is NOT unconditioned public - it
  is scoped to AUTHENTICATED principals matching the constraint (high, "broad
  syntax narrowed by a principal condition"; suite-3 test 85). `aws:PrincipalOrgID`
  under a POSITIVE operator is the recommended org-scoping control for a
  cross-account bucket [3][10].

### 1.2 The S3 "meaning of public" key set (a per-service near-miss)

When S3 itself decides whether a bucket policy is "public" (for Block Public
Access), it "begins by assuming that the policy is public" and treats it as
non-public only if access is restricted to fixed values of a SPECIFIC key set:
an AWS principal, `aws:SourceAccount`, `aws:SourceArn`, `aws:SourceVpc`,
`aws:SourceVpce`, `aws:SourceOwner`, `aws:SourceIp`, `aws:userid`, or the
S3 access-point keys [2].

Analyzer nuance - **do NOT conflate "S3 considers it non-public" with "scoped to
authenticated principals":**

- `aws:SourceVpc`, `aws:SourceVpce`, `aws:SourceIp` are NETWORK selectors. A `*`
  Allow narrowed only by `aws:SourceIp`/`aws:SourceVpce` still allows ANONYMOUS,
  UNAUTHENTICATED callers that happen to originate from that network - S3's
  "not public" classification only means "not open to the whole internet," not
  "authenticated only." The generic evaluator deliberately does NOT credit
  network selectors as principal narrowing (`resource-policy-semantics.md`
  section 5), and the S3 rule must keep that distinction: report a `*` narrowed
  by a network-only selector as **network-scoped but still anonymous within that
  network**, never as "authenticated principals only."
- Only the principal-IDENTITY subset (`aws:PrincipalOrgID`/`Arn`/`Account`/...,
  and `aws:SourceArn`/`aws:SourceAccount` when they pin an owner) excludes the
  anonymous caller.

### 1.3 Request-property Deny keys are NOT identity constraints

A Deny gated ONLY on a request-property key constrains the request, not WHO may
act, so it never neutralizes a public Allow (this generalizes test 28's
`aws:SecureTransport`):

- `aws:SecureTransport` (HTTP vs HTTPS) [11].
- `s3:TlsVersion` (minimum TLS version) [3].
- `s3:x-amz-server-side-encryption` - a `StringNotEquals
  s3:x-amz-server-side-encryption` Deny FORCES server-side encryption on
  `PutObject`; it constrains the object's encryption header, not the caller [3].

A public-read bucket that ALSO carries an SSE-enforcing or TLS-enforcing Deny is
STILL publicly readable (over TLS, with SSE) - the Deny must be recorded as a
request-property constraint and must NOT downgrade the PUBLIC-ACCESS finding.

Caveat (service-to-service redaction): `aws:SecureTransport`, `s3:TlsVersion`,
`aws:SourceIp`, `aws:VpcSourceIp` are REDACTED for AWS service-to-service calls,
so a Deny using them can unintentionally block AWS service principals unless
`aws:PrincipalIsAWSService:false` is added [3]. Note it; do not credit the Deny
as identity scoping.

### 1.4 `s3:ResourceAccount` / `aws:ResourceAccount`

`s3:ResourceAccount` / `aws:ResourceAccount` pin the BUCKET-OWNER account [3].
They are used in IAM / VPC-endpoint policies to stop clients reaching buckets in
other accounts. In a bucket policy they constrain the RESOURCE account, not the
principal identity, so they do NOT narrow a `*` principal to authenticated
callers - never credit them as principal scoping.

### 1.5 Dangerous S3 actions and the PAB fail-closed caveat

- **Bucket-control actions**: `s3:PutBucketPolicy`, `s3:PutBucketAcl`,
  `s3:PutBucketPublicAccessBlock`, `s3:DeleteBucketPolicy` let the grantee
  REWRITE the bucket's own resource policy or ACLs (resource-policy takeover /
  self-expansion). To an external or `*` principal these are far more dangerous
  than a data-plane action and must be ranked accordingly.
- **Data-plane breadth**: `s3:GetObject` to `*` (public read / exfil),
  `s3:PutObject`/`s3:DeleteObject` to `*` (public write / destruction), `s3:*`
  to `*` (full bucket control including the bucket-control actions above).
- **Block Public Access (out of policy scope, fail closed):** BPA is a separate
  account/bucket/access-point/org control that OVERRIDES a public bucket policy
  and is "enforced regardless of how the resources are created" [2]. It is NOT in
  the policy document. Every S3 public/broad finding must carry the "cannot see
  PAB" caveat: whether the public grant is actually reachable also depends on BPA,
  which is not supplied; the analyzer never assumes BPA is on or off.

---

## 2. Object-vs-bucket typing (shared with the generic doc)

Object actions (`s3:GetObject`, `s3:PutObject`, ...) require an object-scoped
resource (`.../*` or a key); bucket actions (`s3:ListBucket`,
`s3:GetBucketPolicy`, `s3:PutBucketPolicy`) require the bucket ARN. An object
action on a bucket-only ARN is an action/resource-type mismatch, not confirmed
object access (test 50; already emitted as RESOURCE-ACTION-RESOURCE-MISMATCH).
The per-service S3 rule reuses this; it does not re-implement it.

---

## 3. AWS KMS key policy

Resource: `kms-key` (`arn:aws:kms:region:account:key/key-id`). The key policy is
the primary access control for a KMS key and has semantics that differ sharply
from S3 [5][6].

### 3.1 `Principal:"*"` on a KMS key is NOT anonymous (the sharpest trap)

AWS: `"AWS": "*"` in a key policy "represents all AWS identities in all accounts"
and "An asterisk gives every identity in every AWS account permission to use the
KMS key, unless another policy statement explicitly denies it. Users in other AWS
accounts can use your KMS key whenever they have corresponding permissions in
their own account." [5]

- KMS has NO unauthenticated path - every KMS API call is SigV4-signed. So a KMS
  key policy `*` is NOT "anonymous / public to the internet"; it is
  **every AWS principal in every account, subject to cross-account
  double-authorization** (the caller's own account must also allow it) [5][g4].
- The per-service KMS PUBLIC-ACCESS-class finding MUST DROP the "including
  anonymous / unauthenticated / anyone on the internet" wording and reframe as
  above. It is still a serious over-grant (high/critical), but the reason is
  "every AWS account," not "anonymous."

### 3.2 Account-root delegation (already modeled; do not regress)

`Principal {"AWS":"arn:aws:iam::acct:root"}` (or the bare account id) with
`kms:*` `Resource:"*"` is the "Enable IAM User Permissions" delegation: it gives
the OWNING ACCOUNT (the account and its administrators, NOT the root user only,
NOT public) authority to use IAM policies to reach the key [5][6]. `Resource:"*"`
= THIS attached key only, never every key in the account [5]. This is
RESOURCE-KMS-ACCOUNT-DELEGATION (test 51); the per-service rule keeps it and does
not classify it as public or root-only.

### 3.3 KMS narrowing keys: `kms:CallerAccount` vs `kms:ViaService`

The AWS-managed-key pattern is `Principal {"AWS":"*"}` narrowed by BOTH keys [7]:

- **`kms:CallerAccount`** pins the caller's ACCOUNT: it lets a policy "allow or
  deny access to all identities (users and roles) in an AWS account," and
  combining it with `Principal:"*"` gives "all identities in that account" [7].
  It is a PRINCIPAL-ACCOUNT scoping key (the KMS analog of `aws:PrincipalAccount`)
  and DOES narrow a `*` to authenticated principals in the named account.
- **`kms:ViaService`** pins the SERVICE CHANNEL: it "allows requests that come
  through" a specific service, e.g. `ec2.us-west-2.amazonaws.com` [7]. It
  constrains HOW the request is made, not WHO the caller is. A `*` key policy
  narrowed ONLY by `kms:ViaService` is STILL account-open: any account's
  principals whose requests flow through that service in that Region can use the
  key. Treat `kms:ViaService` like a network/channel selector (analogous to the
  S3 network keys, section 1.2): it narrows the vector, NOT the principal, and
  must not by itself downgrade a `*` grant to "scoped to my account / authenticated
  only." The key that pins WHO is `kms:CallerAccount` (or
  `aws:PrincipalAccount`/`aws:PrincipalOrgID`).

### 3.4 Dangerous KMS actions

- **`kms:Decrypt` / `kms:GenerateDataKey*` / `kms:ReEncrypt*`** to `*` or
  cross-account = the data-plane exposure: a principal that can Decrypt with the
  key can turn ciphertext it holds into plaintext. High; higher when the grant is
  external.
- **`kms:*`** = full key control including the control-plane actions below.
- **`kms:PutKeyPolicy`** rewrites the key's own policy (key-policy takeover /
  self-expansion) - "much like" grant permission in its blast radius [8].
- **`kms:CreateGrant`** is a DELEGATION primitive, not mere use. AWS: "Permission
  to create grants has security implications, much like allowing the
  kms:PutKeyPolicy permission." A principal with `kms:CreateGrant` "can use a
  grant to allow users and roles, including AWS services, to use the KMS key.
  The principals can be identities in your own AWS account or identities in a
  different account or organization," and "These principals are not required to
  have the permission that they are granting on the key." [8] So a `*` or
  cross-account `kms:CreateGrant` grant lets the grantee ONWARD-DELEGATE key use
  cross-account/org - the per-service rule must name it as delegation, not as
  direct key use, and must not over-claim that it itself decrypts data.
  `kms:GrantIsForAWSResource:true` limits CreateGrant to AWS-service-created
  grants (a narrowing control) [5][8].

### 3.5 The KMS silent-key-policy inversion (fail-closed caveat)

For KMS, an absent/silent policy has the OPPOSITE meaning from S3. `PutKeyPolicy`
REQUIRES a key policy; `CreateKey` without one applies the default (which
includes the account-delegation statement) [5]. But UNLIKE other resource
policies, a KMS key policy does NOT automatically let the owning account's IAM
policies govern the key - that authority exists ONLY because the explicit
account-delegation statement grants it; "without it IAM allow policies are
ineffective" (an IAM Deny still applies) [6]. Therefore:

- A key policy that OMITS the account-delegation statement means IAM identity
  policies CANNOT reach the key - only the key-policy-named principals can. A key
  policy that is "silent" about a principal is fail-closed UNKNOWN for that
  principal's effective access; do not read S3's "absent policy = private but IAM
  can still grant" onto KMS.
- The analyzer sees only the key policy; whether any IAM policy grants use of the
  key is unknown here. State it; never infer per-principal reachability from the
  key policy alone.

---

## 4. Amazon SNS topic policy and Amazon SQS queue policy

Resource: `sns` (`arn:aws:sns:region:account:topic`) / `sqs`
(`arn:aws:sqs:region:account:queue`). Both are messaging resource policies with
near-identical semantics, so Phase 14 models them with ONE shared rule family
(the confused-deputy / cross-account / public messaging rule); the two services
differ only in action namespace.

### 4.1 Public and cross-account messaging

- **SQS `Principal:"*"` IS anonymous/public.** AWS SQS docs label a
  `Principal:"*"` statement as granting "all users (anonymous users)" the named
  permission (e.g. `sqs:ReceiveMessage`) [9]. So an unconditioned `*` SQS queue
  policy is genuinely public and MUST be **critical**, exactly like S3 - the KMS
  "not anonymous" softening (section 3.1) must NOT leak to SQS.
- **SNS `Principal:"*"`** is likewise treated as a public/wildcard-principal
  grant [1]; the documented cross-account and org patterns always pair `*` with a
  narrowing condition (`aws:PrincipalOrgID`, `aws:SourceArn`, `aws:SourceAccount`)
  [10]. A bare, unconditioned `*` topic policy is a public grant (critical); a `*`
  narrowed by `aws:PrincipalOrgID` (POSITIVE) is the org-scoped publish pattern
  and is NOT unconditioned public [10].
- **Cross-account**: a named external account/role principal is a cross-account
  grant (the caller's account must also allow it) [9][10]; enumerate it distinctly
  (RESOURCE-CROSS-ACCOUNT).

### 4.2 Dangerous messaging actions

- **SNS**: `sns:Publish` to `*` = anyone can inject messages to the topic (and to
  every subscriber); `sns:Subscribe` to `*` = anyone can attach an endpoint and
  EXFILTRATE every message published to the topic; `sns:SetTopicAttributes` /
  `sns:AddPermission` = policy takeover.
- **SQS**: `sqs:SendMessage` to `*` = anyone can inject/poison the queue;
  `sqs:ReceiveMessage` (+ `sqs:DeleteMessage`) to `*` = anyone can DRAIN/read the
  queue's messages [9]; `sqs:SetQueueAttributes` / `sqs:AddPermission` = policy
  takeover.

### 4.3 Confused deputy for the classic notification pattern

The classic S3-notifications / EventBridge / CloudWatch -> SNS/SQS pattern grants
an AWS SERVICE principal (`s3.amazonaws.com`, `events.amazonaws.com`,
`sns.amazonaws.com`, ...) `sns:Publish` / `sqs:SendMessage`. A service principal
is NOT public [g4], but without a source binding it is a confused-deputy exposure:
AWS authorizes the SERVICE, not the actor who configured it [4].

- The mitigation keys are `aws:SourceArn` (ArnEquals/ArnLike, the specific source
  topic/bucket/rule) and `aws:SourceAccount` (StringEquals, the source account),
  ANDed [4][10]. A properly source-bound service grant is a NEGATIVE control
  (info/low); a missing binding is an exposure (medium); a `SourceArn`-account vs
  `SourceAccount` mismatch is internally inconsistent (medium; test 53). This is
  RESOURCE-CONFUSED-DEPUTY, reused per service.
- **`aws:SourceOwner` is DEPRECATED**: "new services can integrate with Amazon
  SNS only through `aws:SourceArn` and `aws:SourceAccount`," though SNS keeps
  backward compatibility for services already using it [10]. Recognize
  `aws:SourceOwner` as a legacy source-binding key on SNS but recommend
  `aws:SourceArn`/`aws:SourceAccount`.

### 4.4 Fail-closed on unknown principals

An unmodeled/invalid principal type on an SNS/SQS policy (CanonicalUser, a
partial-wildcard AWS/Service/Federated principal) is surfaced fail-closed
(RESOURCE-UNSUPPORTED-PRINCIPAL), never silently dropped and never zero-findings.
Reused from IAM-1208; the per-service rule must not regress it.

---

## 5. Per-service dispatch (how the rules attach)

The per-service rules attach to the EXISTING generic path in `engine/resource.js`
without regressing it:

- `serviceForArn()` already classifies `s3-bucket` / `s3-object` / `sns` / `sqs`
  / `kms-key`. The dispatch selects a per-service rule set by that service token
  and runs it IN ADDITION to (not instead of) the generic principal-centric loop.
- Every per-service finding uses the canonical resource-finding shape
  (`makeResourceFinding`), carries `RESOURCE_LIMIT`, and sets `resource.service`.
  New finding ids extend `RESOURCE_IDS`; they never re-route to identity rules.
- The generic loop remains the SAFETY NET: if a per-service rule declines to fire
  (an unmodeled sub-shape), the generic PUBLIC-ACCESS / CROSS-ACCOUNT /
  CONFUSED-DEPUTY / UNSUPPORTED-PRINCIPAL findings and the INCOMPLETE coverage
  flag still apply. A per-service rule may REFINE severity/wording for its
  service but must not SUPPRESS a generic fail-closed finding.
- The KMS "not anonymous" reframing (section 3.1) is SCOPED to `kms-key` only.
  The dispatch must guarantee it cannot change the S3/SQS/SNS anonymous-public
  classification (section 8, trap 4).

---

## 6. What narrows a `*`, per service (summary table)

`Y` = narrows an anonymous `*` to authenticated principals; `N` = does not
(channel/transport/resource-owner only, `*` stays as-broad).

```
key                                  S3    SQS   SNS   KMS   role
-----------------------------------  ----  ----  ----  ----  --------------------------------
aws:PrincipalOrgID (positive)        Y     Y     Y     Y     principal-identity (org)
aws:PrincipalArn / Account / Tag     Y     Y     Y     Y     principal-identity
aws:userid / PrincipalType/OrgPaths  Y     Y     Y     Y     principal-identity
aws:SourceArn / aws:SourceAccount    Y*    Y*    Y*    Y*    source binding (confused-deputy)
kms:CallerAccount                    -     -     -     Y     principal-account (KMS-only)
kms:ViaService                       -     -     -     N     service channel (KMS-only)
aws:SourceIp/SourceVpc/SourceVpce    N     N     N     N     network selector
aws:SecureTransport / s3:TlsVersion  N     N     N     N     transport (request property)
s3:x-amz-server-side-encryption      N     -     -     -     object content (request property)
s3:ResourceAccount/aws:ResourceAcct  N     -     -     -     resource-owner account, not caller
negated operator on any of the above N     N     N     N     EXCLUSION, broadens (never credit)
```

`Y*` = source-binding keys narrow WHO for the confused-deputy vector on a service
principal; on a `*` principal they scope to the named account/source (identity
subset). A NEGATED operator on any key is an exclusion that broadens, never a
narrowing (`resource-policy-semantics.md` section 9); it keeps the grant at least
as broad as public.

---

## 7. Load-bearing per-service invariants (fail-closed contract)

1. **Anonymous is service-specific.** S3 and SQS `*` = anonymous public
   (critical) [1][9]; KMS `*` = every AWS principal in every account, no
   unauthenticated path (drop the "anonymous" wording) [5]; SNS `*` = public
   wildcard principal [1].
2. **Channel keys are not identity keys.** `kms:ViaService` and the S3 network
   keys narrow the vector, not the principal; they never by themselves make a `*`
   "authenticated / scoped to my account."
3. **Request-property Deny keys are not identity constraints.**
   `s3:x-amz-server-side-encryption`, `s3:TlsVersion`, `aws:SecureTransport`
   Denies do not make a public grant private (test 28 generalized) [3][11].
4. **Control-plane actions outrank data-plane actions.** `s3:PutBucketPolicy`,
   `kms:PutKeyPolicy`, `kms:CreateGrant`, `sns:AddPermission`,
   `sqs:AddPermission` are policy/grant takeover or onward-delegation; rank them
   above ordinary access [3][8].
5. **KMS silent policy is fail-closed UNKNOWN, and inverted vs S3.** No
   account-delegation statement => IAM cannot govern the key [6]; never infer
   per-principal reachability from a key policy alone.
6. **S3 Block Public Access is out of scope and fail-closed.** Every S3
   public/broad finding carries the "cannot see PAB" caveat [2].
7. **A service principal is not public**; source-bind it (confused deputy) [4].
   `aws:SourceOwner` is a deprecated legacy binding on SNS [10].
8. **Per-service refines, never suppresses.** A per-service rule adds/refines
   refines findings; the generic fail-closed findings and INCOMPLETE coverage still stand
   if a sub-shape is unmodeled. "Unsupported != safe."

---

## 8. The five hardest correctness traps (what the adversarial critic must target)

1. **KMS `*` mislabeled anonymous.** The per-service KMS finding must NOT say
   "including anonymous / unauthenticated / anyone on the internet." KMS has no
   unauthenticated path; `*` = all AWS identities in all accounts, cross-account
   still double-authorized [5]. Near-miss: an S3-style PUBLIC-ACCESS message
   reused verbatim on a KMS key.
2. **`kms:ViaService` credited as principal scoping.** A `*` key policy narrowed
   ONLY by `kms:ViaService` is still account-open; only `kms:CallerAccount` /
   `aws:PrincipalAccount` / `aws:PrincipalOrgID` pin WHO [7]. Near-miss: crediting
   `Principal:"*"` + `kms:ViaService` as "scoped to my account / authenticated."
3. **SSE/TLS Deny read as making S3 public access private.** A
   `s3:x-amz-server-side-encryption` or `s3:TlsVersion` Deny is a request-property
   constraint like `aws:SecureTransport` (test 28); it does NOT suppress a public
   `s3:GetObject` Allow [3][11]. Near-miss: a public bucket with an SSE-enforcing
   Deny scored as private.
4. **The KMS "not anonymous" carve-out leaking to S3/SQS/SNS (dispatch bleed).**
   SQS docs explicitly call `Principal:"*"` "anonymous users" [9]; S3 is public
   [1]. A per-service refactor must keep the genuinely-anonymous S3/SQS public
   grant CRITICAL while softening ONLY KMS. Near-miss (both directions): the KMS
   softening downgrades an SQS `*`, or the S3 anonymous wording is applied to a
   KMS key.
5. **Control-plane / delegation actions under-ranked or over-claimed.**
   `kms:CreateGrant` lets the grantee ONWARD-DELEGATE key use cross-account/org
   without holding the permission itself [8]; `s3:PutBucketPolicy` /
   `kms:PutKeyPolicy` rewrite the resource policy. A `*` or cross-account grant of
   these must be ranked as takeover/delegation - but NOT over-claimed as directly
   decrypting data or as effective access (same fail-closed cross-account caveat).
   Near-miss: `kms:CreateGrant` to `*` scored as an ordinary key-use grant, or as
   a proven decrypt.

---

## Sources

All URLs are current AWS documentation, verified for this reference on
2026-08-24. `[g#]` sources are those in `resource-policy-semantics.md`.

1. AWS JSON policy elements: Principal (wildcard `*` = all users including
   anonymous public; account-root delegation; service-principal form):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
2. Blocking public access to your Amazon S3 storage (BPA overrides bucket
   policies, enforced regardless of creation; the "meaning of public" fixed-value
   key set that excludes aws:SecureTransport):
   https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
3. Bucket policy examples using condition keys (s3:x-amz-server-side-encryption
   SSE enforcement; s3:TlsVersion; s3:ResourceAccount / aws:ResourceAccount;
   aws:PrincipalIsAWSService service-to-service redaction note;
   aws:PrincipalAccount deny-except-account):
   https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazon-s3-policy-keys.html
4. The confused deputy problem (aws:SourceArn / aws:SourceAccount /
   aws:SourceOrgID on resource policies granting service principals):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
5. Creating a key policy (KMS `"AWS":"*"` = all AWS identities in all accounts;
   account-root delegation not root-only; Resource:"*" = this key; PutKeyPolicy
   requires a policy):
   https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html
6. Default key policy - allows access to the account and enables IAM policies
   (account gets full access via IAM delegation; without the statement IAM allow
   policies are ineffective, IAM deny still applies):
   https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html
7. AWS KMS condition keys (kms:ViaService = request-through-a-service channel;
   kms:CallerAccount = all identities in an account, combines with Principal:"*"):
   https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html
8. Grants in AWS KMS (kms:CreateGrant delegates key use cross-account/org; grantee
   need not hold the permission; "much like kms:PutKeyPolicy";
   kms:GrantIsForAWSResource narrowing):
   https://docs.aws.amazon.com/kms/latest/developerguide/grants.html
9. Basic examples of Amazon SQS policies (Principal:"*" = "all users (anonymous
   users)"; SendMessage / ReceiveMessage; cross-account exclusions):
   https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-sqs-policies.html
10. Example cases for Amazon SNS access control (Publish/Subscribe; S3->SNS
    aws:SourceAccount; aws:PrincipalOrgID org publish; aws:SourceOwner deprecated
    in favor of aws:SourceArn/aws:SourceAccount):
    https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html
11. Protecting data in transit with encryption (aws:SecureTransport HTTPS-only S3
    pattern):
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingEncryptionInTransit.html
