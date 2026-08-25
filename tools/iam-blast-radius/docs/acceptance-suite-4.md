# IAM Blast Radius - Per-Service Resource-Policy Acceptance Suite IV

## Purpose

Non-duplicative extension covering **Phase 14: per-service resource-policy
finding rules** (S3 bucket policy, KMS key policy, SNS topic policy, SQS queue
policy). It builds on the resource family shipped in Phase 12 (suite-2 tests
26/27/28/32/33/49/51/53, suite-3 69/85) and on the grounding doc
`docs/resource-per-service-semantics.md`. Every case adds a nuance the GENERIC
resource evaluator cannot get right because it is service-specific.

The expected results describe **potential blast radius from the selected policy
family and supplied resource context** - NOT effective/granted access. Every
finding must carry the potential-not-effective caveat.

## Result vocabulary (same as suite-2/3)

- **Finding:** a supported per-service capability or risk was established.
- **Constraint:** a supported condition/deny measurably narrows a capability.
- **Coverage warning:** analysis continues, but an element cannot be interpreted
  precisely (non-blocking; flips `incomplete`).
- **Fail-closed / blocked:** input, family, or unsupported semantics can
  materially change the conclusion; no normal result is presented as complete.

## Fixture schema

Every case is `family: "resource"` with an explicit `resourceContext`:

```json
{ "id": "...", "family": "resource",
  "resourceContext": { "type": "<s3-bucket|s3-object|kms-key|sns|sqs>",
                       "arn": "arn:...", "account": "<optional 12-digit>" },
  "expect": { "status": "complete|complete_with_warnings|blocked",
              "findings": [ { "ruleId": "...", "severity": [...] } ],
              "forbidClaims": [ ... ] } }
```

Rule ids shown are suggestions; the deterministic mapping is what matters. The
generic resource ids (PUBLIC-ACCESS, RESOURCE-CROSS-ACCOUNT,
RESOURCE-CONFUSED-DEPUTY, RESOURCE-SAME-ACCOUNT-GRANT,
RESOURCE-KMS-ACCOUNT-DELEGATION, RESOURCE-UNSUPPORTED-PRINCIPAL) remain valid; a
per-service rule may REFINE severity/wording but must never SUPPRESS a generic
fail-closed finding.

---

# Campaign A - Amazon S3 bucket policy

## Test 101 - Public object read is genuinely anonymous (MUST be critical)

**Family:** Resource. **Resource context:** `s3-bucket`
`arn:aws:s3:::public-downloads`, account `123456789012`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
  "Action": "s3:GetObject", "Resource": "arn:aws:s3:::public-downloads/*" }] }
```

### Expected result

- **Critical** PUBLIC-ACCESS: anonymous / public read of objects.
- State the grant reaches ANONYMOUS, unauthenticated callers (S3 supports it).
- Carry the "cannot see Block Public Access" caveat: actual exposure also depends
  on BPA, not supplied.
- forbidClaims: "effective access proven"; "BPA is off"; "safe".

## Test 102 - `*` narrowed by aws:PrincipalOrgID is NOT anonymous public

**Family:** Resource. **Resource context:** `s3-bucket`
`arn:aws:s3:::org-shared`, account `123456789012`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::org-shared/*",
  "Condition": { "StringEquals": { "aws:PrincipalOrgID": "o-example" } } }] }
```

### Expected result

- **High** "broad principal syntax narrowed by a principal condition" - NOT
  critical PUBLIC-ACCESS.
- Record `principalScopedBy: [aws:PrincipalOrgID]`; state access is scoped to
  authenticated principals in the organization.
- forbidClaims: "anonymous"; "unauthenticated"; "anyone"; "public".

## Test 103 - `*` narrowed only by aws:SourceIp is still anonymous within the network (near-miss)

**Family:** Resource. **Resource context:** `s3-bucket`
`arn:aws:s3:::ip-scoped`, account `123456789012`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::ip-scoped/*",
  "Condition": { "IpAddress": { "aws:SourceIp": "203.0.113.0/24" } } }] }
```

### Expected result

- Report the `*` as scoped to a NETWORK range but STILL reaching anonymous,
  unauthenticated callers from that network - a network selector is not a
  principal-identity constraint (grounding 1.2).
- Do NOT credit `aws:SourceIp` as narrowing to authenticated principals; do NOT
  downgrade to "authenticated only".
- Severity high/critical (still public within the CIDR). PAB caveat present.
- forbidClaims: "authenticated principals only"; "not public".

## Test 104 - SSE-enforcing Deny does not make public access private (near-miss)

**Family:** Resource. **Resource context:** `s3-bucket`
`arn:aws:s3:::sse-enforced`, account `123456789012`.

```json
{ "Version": "2012-10-17", "Statement": [
  { "Sid": "PublicRead", "Effect": "Allow", "Principal": "*",
    "Action": "s3:GetObject", "Resource": "arn:aws:s3:::sse-enforced/*" },
  { "Sid": "RequireSSE", "Effect": "Deny", "Principal": "*",
    "Action": "s3:PutObject", "Resource": "arn:aws:s3:::sse-enforced/*",
    "Condition": { "StringNotEquals": {
      "s3:x-amz-server-side-encryption": "AES256" } } }] }
```

### Expected result

- **Critical** PUBLIC-ACCESS on the read Allow stands.
- Classify the Deny as a REQUEST-PROPERTY (object-encryption) constraint, like
  `aws:SecureTransport` (test 28) - it constrains the write's encryption header,
  not WHO may act, and does NOT suppress the public read.
- forbidClaims: "deny makes the bucket private"; "SSE requirement neutralizes
  public read".

## Test 105 - s3:PutBucketPolicy to an external account is policy takeover

**Family:** Resource. **Resource context:** `s3-bucket`
`arn:aws:s3:::corp-data`, account `123456789012`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::999900001111:role/Partner" },
  "Action": "s3:PutBucketPolicy", "Resource": "arn:aws:s3:::corp-data" }] }
```

### Expected result

- **High** RESOURCE-CROSS-ACCOUNT, refined to name `s3:PutBucketPolicy` as a
  bucket-policy TAKEOVER / self-expansion primitive (the grantee can rewrite the
  bucket's own access policy), ranked above a data-plane action.
- Cross-account: the caller's own account must also allow it (necessary, not
  sufficient).
- forbidClaims: "effective takeover proven"; "same-account".

## Test 106 - Cross-account object read

**Family:** Resource. **Resource context:** `s3-bucket`
`arn:aws:s3:::corp-data`, account `123456789012`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "AWS": "999900001111" },
  "Action": "s3:GetObject", "Resource": "arn:aws:s3:::corp-data/*" }] }
```

### Expected result

- **High** RESOURCE-CROSS-ACCOUNT to external account `999900001111`.
- State the caller's account must also allow the action against this ARN.
- forbidClaims: "same-account"; "effective access".

## Test 107 - Same-account direct user grant (resource-vs-identity)

**Family:** Resource. **Resource context:** `s3-bucket`
`arn:aws:s3:::finance-reports`, account `123456789012`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::123456789012:user/Alice" },
  "Action": "s3:GetObject", "Resource": "arn:aws:s3:::finance-reports/*" }] }
```

### Expected result

- **Medium** RESOURCE-SAME-ACCOUNT-GRANT (suite-2 test 32 semantics): a direct
  resource-policy grant can be effective even when Alice's identity policy is
  silent; an applicable explicit Deny still blocks.
- Do NOT generalize to role/cross-account. Requires the explicit `account`
  context (S3 ARN carries none).
- forbidClaims: "cross-account"; "identity policy must also allow".

## Test 108 - s3:ResourceAccount does not narrow the principal (near-miss)

**Family:** Resource. **Resource context:** `s3-bucket`
`arn:aws:s3:::owner-scoped`, account `123456789012`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::owner-scoped/*",
  "Condition": { "StringEquals": { "s3:ResourceAccount": "123456789012" } } }] }
```

### Expected result

- Still **critical** PUBLIC-ACCESS: `s3:ResourceAccount` pins the BUCKET-OWNER
  account, not the caller identity, so it does NOT exclude anonymous callers
  (grounding 1.4).
- Do NOT credit `s3:ResourceAccount` as principal scoping.
- forbidClaims: "scoped to account 123456789012 principals"; "not public".

---

# Campaign B - AWS KMS key policy

## Test 109 - KMS `*` is NOT anonymous (the sharpest trap)

**Family:** Resource. **Resource context:** `kms-key`
`arn:aws:kms:us-east-1:111122223333:key/abcd-1234`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "AWS": "*" },
  "Action": ["kms:Decrypt", "kms:GenerateDataKey"], "Resource": "*" }] }
```

### Expected result

- A high/critical over-grant: the key is usable by EVERY AWS identity in EVERY
  account (cross-account still double-authorized). `Resource:"*"` = this attached
  key only.
- The finding MUST NOT say "anonymous", "unauthenticated", or "anyone on the
  internet" - KMS has no unauthenticated path (grounding 3.1).
- forbidClaims: "anonymous"; "unauthenticated"; "public to the internet";
  "Resource:* means every KMS key".

## Test 110 - KMS account-root delegation (not public, not root-only)

**Family:** Resource. **Resource context:** `kms-key`
`arn:aws:kms:us-east-1:111122223333:key/abcd-1234`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Sid": "EnableIAMUserPermissions", "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
  "Action": "kms:*", "Resource": "*" }] }
```

### Expected result

- RESOURCE-KMS-ACCOUNT-DELEGATION (suite-2 test 51): broad KMS authority
  delegated to the OWNING account (medium).
- Do NOT call the key public; do NOT say only the root user can administer it;
  `Resource:"*"` = the attached key; individual reachable principals unknown
  without the account's IAM policies.
- forbidClaims: "public"; "root user only"; "every KMS key in the account".

## Test 111 - KMS `*` + kms:ViaService only is still account-open (near-miss)

**Family:** Resource. **Resource context:** `kms-key`
`arn:aws:kms:us-west-2:111122223333:key/abcd-1234`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "AWS": "*" },
  "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"],
  "Resource": "*",
  "Condition": { "StringEquals": {
    "kms:ViaService": "ec2.us-west-2.amazonaws.com" } } }] }
```

### Expected result

- Report `kms:ViaService` as a SERVICE-CHANNEL constraint (requests made through
  EC2 in this Region), NOT a principal-identity scope: the grant is still open to
  any account's principals whose requests flow through that service (grounding
  3.3).
- Do NOT downgrade to "scoped to my account" / "authenticated only"; only
  `kms:CallerAccount` / `aws:PrincipalAccount` / `aws:PrincipalOrgID` would do
  that.
- forbidClaims: "scoped to account 111122223333"; "authenticated only";
  "not broad".

## Test 112 - KMS `*` + kms:CallerAccount narrows to the account (contrast to 111)

**Family:** Resource. **Resource context:** `kms-key`
`arn:aws:kms:us-west-2:111122223333:key/abcd-1234`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "AWS": "*" },
  "Action": ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"],
  "Resource": "*",
  "Condition": { "StringEquals": {
    "kms:CallerAccount": "111122223333",
    "kms:ViaService": "ec2.us-west-2.amazonaws.com" } } }] }
```

### Expected result

- The `*` is NARROWED: `kms:CallerAccount` pins WHO (all identities in account
  `111122223333`), and `kms:ViaService` additionally pins the channel. Report as
  scoped to that account's principals via EC2 (not a broad/public grant).
- Preserve the AND composition of the two keys (do not collapse to OR).
- forbidClaims: "public"; "any account".

## Test 113 - Cross-account KMS delegation to an external root

**Family:** Resource. **Resource context:** `kms-key`
`arn:aws:kms:us-east-1:111122223333:key/abcd-1234`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::999900001111:root" },
  "Action": ["kms:Decrypt", "kms:DescribeKey"], "Resource": "*" }] }
```

### Expected result

- **High** cross-account KMS delegation: authority over the key delegated to
  EXTERNAL account `999900001111`; the external account must also allow it via
  its IAM policies.
- Not public; not root-only.
- forbidClaims: "same-account"; "public".

## Test 114 - kms:CreateGrant is onward-delegation, not mere use

**Family:** Resource. **Resource context:** `kms-key`
`arn:aws:kms:us-east-1:111122223333:key/abcd-1234`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::999900001111:role/Integrator" },
  "Action": "kms:CreateGrant", "Resource": "*" }] }
```

### Expected result

- **High** cross-account, refined: `kms:CreateGrant` is a DELEGATION primitive -
  the grantee can create grants allowing OTHER principals (in any account/org,
  including AWS services) to use the key, and need not hold the permission itself
  (grounding 3.4). Rank above ordinary key use.
- Do NOT over-claim it directly decrypts data or proves effective access.
- forbidClaims: "proves decrypt"; "effective access"; "only uses the key".

## Test 115 - KMS silent key policy is fail-closed UNKNOWN (inverted vs S3)

**Family:** Resource. **Resource context:** `kms-key`
`arn:aws:kms:us-east-1:111122223333:key/abcd-1234`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Sid": "SingleAdminOnly", "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::111122223333:role/KeyAdmin" },
  "Action": ["kms:Describe*", "kms:PutKeyPolicy"], "Resource": "*" }] }
```

### Expected result

- Report the direct grant to `KeyAdmin`, AND a **coverage warning**: this key
  policy OMITS the account-delegation ("Enable IAM User Permissions") statement,
  so unlike S3, IAM identity policies CANNOT govern this key - only key-policy
  named principals can use it; per-principal effective access is UNKNOWN from
  this document (grounding 3.5). Note `kms:PutKeyPolicy` = key-policy takeover.
- forbidClaims: "IAM policies can still grant access to this key"; "absent policy
  means private-but-IAM-reachable" (that is the S3 rule, not KMS).

## Test 116 - KMS transport-only Deny does not neutralize the grant

**Family:** Resource. **Resource context:** `kms-key`
`arn:aws:kms:us-east-1:111122223333:key/abcd-1234`.

```json
{ "Version": "2012-10-17", "Statement": [
  { "Effect": "Allow", "Principal": { "AWS": "*" },
    "Action": "kms:Decrypt", "Resource": "*" },
  { "Effect": "Deny", "Principal": { "AWS": "*" }, "Action": "kms:*",
    "Resource": "*",
    "Condition": { "Bool": { "aws:SecureTransport": "false" } } }] }
```

### Expected result

- The `*` Decrypt Allow stands (every AWS identity in every account - NOT
  anonymous, per 109). The `aws:SecureTransport` Deny is TRANSPORT-only and does
  not narrow WHO may act.
- forbidClaims: "anonymous"; "the deny makes the key private".

---

# Campaign C - Amazon SNS topic policy

## Test 117 - Public subscribe is an exfiltration vector (critical)

**Family:** Resource. **Resource context:** `sns`
`arn:aws:sns:us-east-2:444455556666:MyTopic`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": "*", "Action": "sns:Subscribe",
  "Resource": "arn:aws:sns:us-east-2:444455556666:MyTopic" }] }
```

### Expected result

- **Critical** PUBLIC-ACCESS refined for SNS: a public `sns:Subscribe` lets any
  principal attach an endpoint and EXFILTRATE every message published to the
  topic.
- forbidClaims: "safe"; "effective access".

## Test 118 - Service principal publish without source binding (confused deputy)

**Family:** Resource. **Resource context:** `sns`
`arn:aws:sns:us-west-2:123456789012:security-events`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "Service": "events.amazonaws.com" },
  "Action": "sns:Publish",
  "Resource": "arn:aws:sns:us-west-2:123456789012:security-events" }] }
```

### Expected result

- **Medium** RESOURCE-CONFUSED-DEPUTY (suite-2 test 26 semantics): missing
  `aws:SourceArn`/`aws:SourceAccount`, subject to service support.
- Do NOT describe the topic as publicly writable - the principal is an AWS
  service, not `*`.
- forbidClaims: "public write"; "anonymous".

## Test 119 - Properly source-bound service publish (negative control)

**Family:** Resource. **Resource context:** `sns`
`arn:aws:sns:us-west-2:123456789012:security-events`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "Service": "events.amazonaws.com" },
  "Action": "sns:Publish",
  "Resource": "arn:aws:sns:us-west-2:123456789012:security-events",
  "Condition": {
    "ArnEquals": { "aws:SourceArn":
      "arn:aws:events:us-west-2:123456789012:rule/alerts" },
    "StringEquals": { "aws:SourceAccount": "123456789012" } } }] }
```

### Expected result

- **Info/low** source-bound negative control; no missing-binding warning.
- Preserve the AND of the two operators. Do NOT infer whether the rule exists.
- forbidClaims: "missing source binding"; "exposure".

## Test 120 - `*` narrowed by aws:PrincipalOrgID publish (near-miss)

**Family:** Resource. **Resource context:** `sns`
`arn:aws:sns:us-east-2:444455556666:MyTopic`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "AWS": "*" }, "Action": "sns:Publish",
  "Resource": "arn:aws:sns:us-east-2:444455556666:MyTopic",
  "Condition": { "StringEquals": { "aws:PrincipalOrgID": "o-myorg" } } }] }
```

### Expected result

- **High** "broad principal syntax narrowed by a principal condition" - the
  org-scoped publish pattern; NOT critical public.
- forbidClaims: "anonymous"; "public"; "anyone".

## Test 121 - Deprecated aws:SourceOwner legacy binding

**Family:** Resource. **Resource context:** `sns`
`arn:aws:sns:us-east-2:444455556666:MyTopic`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "Service": "ses.amazonaws.com" },
  "Action": "sns:Publish",
  "Resource": "arn:aws:sns:us-east-2:444455556666:MyTopic",
  "Condition": { "StringEquals": { "aws:SourceOwner": "111122223333" } } }] }
```

### Expected result

- Recognize `aws:SourceOwner` as a LEGACY (deprecated) source-binding key on SNS:
  treat as a present source binding for confused-deputy purposes, but recommend
  migrating to `aws:SourceArn`/`aws:SourceAccount` (grounding 4.3).
- Do NOT report it as a missing binding; do NOT treat the service principal as
  public.
- forbidClaims: "no source binding"; "public write".

---

# Campaign D - Amazon SQS queue policy

## Test 122 - SQS `*` receive is anonymous public and MUST stay critical (dispatch-bleed near-miss)

**Family:** Resource. **Resource context:** `sqs`
`arn:aws:sqs:us-east-2:111122223333:queue1`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Sid": "AnonymousReceive", "Effect": "Allow", "Principal": "*",
  "Action": "sqs:ReceiveMessage",
  "Resource": "arn:aws:sqs:us-east-2:111122223333:queue1" }] }
```

### Expected result

- **Critical** PUBLIC-ACCESS: AWS SQS docs label a `Principal:"*"` grant as "all
  users (anonymous users)"; `sqs:ReceiveMessage` to `*` lets anyone DRAIN/read
  the queue.
- The KMS "not anonymous" softening (test 109) MUST NOT leak here - SQS `*` IS
  anonymous. Verify the per-service dispatch keeps S3/SQS/SNS anonymous framing
  independent of the KMS carve-out.
- forbidClaims: "not anonymous"; "all AWS identities in all accounts" (that is
  the KMS wording, wrong for SQS); "authenticated only".

## Test 123 - SNS-to-SQS source-bound service send (negative control)

**Family:** Resource. **Resource context:** `sqs`
`arn:aws:sqs:us-east-2:444455556666:MyQueue`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Sid": "Allow-SNS-SendMessage", "Effect": "Allow",
  "Principal": { "Service": "sns.amazonaws.com" }, "Action": "sqs:SendMessage",
  "Resource": "arn:aws:sqs:us-east-2:444455556666:MyQueue",
  "Condition": { "ArnEquals": { "aws:SourceArn":
    "arn:aws:sns:us-east-2:444455556666:MyTopic" } } }] }
```

### Expected result

- **Info/low** source-bound negative control (the documented S3/SNS -> SQS
  pattern with `aws:SourceArn`).
- forbidClaims: "missing source binding"; "public write".

## Test 124 - SQS service send without source binding (confused deputy)

**Family:** Resource. **Resource context:** `sqs`
`arn:aws:sqs:us-east-2:444455556666:MyQueue`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "Service": "s3.amazonaws.com" },
  "Action": "sqs:SendMessage",
  "Resource": "arn:aws:sqs:us-east-2:444455556666:MyQueue" }] }
```

### Expected result

- **Medium** RESOURCE-CONFUSED-DEPUTY: missing `aws:SourceArn`/`aws:SourceAccount`
  for the S3-notifications -> SQS pattern.
- A service principal is not public write.
- forbidClaims: "public write"; "anonymous".

## Test 125 - SQS SourceArn/SourceAccount account mismatch

**Family:** Resource. **Resource context:** `sqs`
`arn:aws:sqs:us-east-2:111122223333:cloudtrail-queue`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "Service": "s3.amazonaws.com" },
  "Action": "sqs:SendMessage",
  "Resource": "arn:aws:sqs:us-east-2:111122223333:cloudtrail-queue",
  "Condition": {
    "StringEquals": { "aws:SourceAccount": "111122223333" },
    "ArnLike": { "aws:SourceArn": "arn:aws:s3:::*" } } }] }
```

### Expected result

- Note: `aws:SourceArn` `arn:aws:s3:::*` pins no account (S3 ARNs carry none), so
  this variant is a BYPASSED binding, not a clean mismatch: `aws:SourceAccount`
  binds account `111122223333` while `aws:SourceArn` resolves no account. Report
  the effective source-account binding on `aws:SourceAccount` and flag the
  match-all `aws:SourceArn` as a bypassed key (grounding 4.3; IAM-1208 set logic).
- If the fixture instead uses two disjoint 12-digit accounts (e.g.
  `aws:SourceAccount:111122223333` + `aws:SourceArn` in `444455556666`), expect
  **medium** state=`mismatched` (suite-2 test 53 semantics).
- forbidClaims: "correctly source-bound" (for the disjoint variant);
  "public write".

## Test 126 - Cross-account full queue control

**Family:** Resource. **Resource context:** `sqs`
`arn:aws:sqs:us-east-2:123456789012:queue1`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "AWS": "999900001111" },
  "Action": "sqs:*", "Resource": "arn:aws:sqs:us-east-2:123456789012:queue1" }] }
```

### Expected result

- **High** RESOURCE-CROSS-ACCOUNT to external account `999900001111`; refine that
  `sqs:*` includes queue-policy control (`sqs:SetQueueAttributes`,
  `sqs:AddPermission`) = takeover, plus send/receive.
- forbidClaims: "same-account"; "effective access".

---

# Campaign E - Fail-closed and adversarial controls

## Test 127 - Silent / no-grant policy is UNKNOWN, not safe

**Family:** Resource. **Resource context:** `kms-key`
`arn:aws:kms:us-east-1:111122223333:key/abcd-1234`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Deny", "Principal": { "AWS": "*" }, "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": { "Bool": { "aws:SecureTransport": "false" } } }] }
```

### Expected result

- No positive grant is present (Deny-only). Coverage stays **INCOMPLETE**: the
  absence of a finding does NOT mean the key is safe or unreachable - a KMS key
  with no account-delegation Allow is UNKNOWN for effective access (grounding
  3.5). Do not present a clean, empty analysis as "safe".
- forbidClaims: "safe"; "no access"; "analysis complete / nothing here".

## Test 128 - CanonicalUser principal surfaces fail-closed (never zero findings)

**Family:** Resource. **Resource context:** `s3-bucket`
`arn:aws:s3:::legacy-acl-bucket`, account `123456789012`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow",
  "Principal": { "CanonicalUser":
    "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be" },
  "Action": "s3:GetObject", "Resource": "arn:aws:s3:::legacy-acl-bucket/*" }] }
```

### Expected result

- **Medium** RESOURCE-UNSUPPORTED-PRINCIPAL (IAM-1208 fix 4): a CanonicalUser
  grant is recognized-but-unmodeled - surfaced fail-closed, never silently
  dropped, never zero-findings. WHO it resolves to is UNKNOWN.
- forbidClaims: "no grant"; "safe"; "zero findings".

## Test 129 - Unsupported resource shape fails closed

**Family:** Resource. **Resource context:** `type: null`,
`arn: arn:aws:lambda:us-east-1:123456789012:function:my-fn`.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": { "Service": "s3.amazonaws.com" },
  "Action": "lambda:InvokeFunction",
  "Resource": "arn:aws:lambda:us-east-1:123456789012:function:my-fn" }] }
```

### Expected result

- **Blocked / fail-closed** `UNSUPPORTED_RESOURCE_SHAPE`: Lambda resource policies
  are not modeled in this release. Analysis stops rather than apply S3/KMS/SNS/SQS
  reasoning to an unmodeled service. "Unsupported != safe."
- forbidClaims: "no findings means safe"; a public/confused-deputy finding
  presented as a supported result.

## Test 130 - Rejected / null resource context fails closed

**Family:** Resource. **Resource context:** absent (`null`) or an unparseable ARN.

```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::orphan/*" }] }
```

### Expected result

- **Fail-closed** `RESOURCE_CONTEXT_REQUIRED` (IAM-1208 fix 3):
  `analyzeResource(model, null)` returns `ok:false` (or a coverage object carrying
  the parser's actual code) with a note that the context was REJECTED - NEVER
  `ok:true` claiming the policy was "accepted and routed" or the context
  "recorded". Zero findings; the absence of a finding does not mean safe.
- forbidClaims: "accepted and routed"; "context recorded"; a PUBLIC-ACCESS
  finding emitted without a known attached resource.

---

## Coverage summary

| Service | Tests | Includes adversarial near-miss |
| --- | --- | --- |
| S3 bucket policy | 101-108 (8) | 103 network-only `*`, 104 SSE Deny, 108 s3:ResourceAccount |
| KMS key policy | 109-116 (8) | 109 `*`-not-anonymous, 111 ViaService-not-scoping, 114 CreateGrant, 115 silent-policy |
| SNS topic policy | 117-121 (5) | 120 org-narrowed `*`, 121 deprecated SourceOwner |
| SQS queue policy | 122-126 (5) | 122 KMS-carve-out dispatch bleed, 125 bypassed vs mismatched |
| Fail-closed / adversarial | 127-130 (4) | 127 silent=UNKNOWN, 129/130 fail-closed contexts |

Required adversarial guarantees exercised:

- A `*` that is actually NARROWED and must NOT be critical: 102, 112, 120.
- A silent policy that must be UNKNOWN (not safe): 115, 127.
- A service principal that must NOT be public: 118, 121, 124.
- A genuinely public grant that MUST be critical: 101, 117, 122.
- Service-specific `*` divergence (KMS not-anonymous vs S3/SQS anonymous): 109 vs
  101/122 (the dispatch must keep them independent).

## Acceptance threshold

This suite passes when tests 101-130 produce the expected complete / warning /
fail-closed state; no per-service rule suppresses a generic fail-closed finding;
the KMS "not anonymous" reframing is scoped to `kms-key` and never changes the
S3/SNS/SQS anonymous-public classification; request-property Deny keys
(`s3:x-amz-server-side-encryption`, `s3:TlsVersion`, `aws:SecureTransport`) and
channel keys (`kms:ViaService`, network selectors) never make a public/`*` grant
read as private/scoped; and every finding carries the potential-not-effective
caveat. Browser, JSON, and Markdown exports must agree on status, evidence,
conditions, and uncertainty.

## AWS reference basis

Grounded in `docs/resource-per-service-semantics.md` and its verified sources:
S3 Principal/BPA/condition-keys, KMS key-policy/ViaService/grants, SNS/SQS access
policy examples, and the confused-deputy reference.
