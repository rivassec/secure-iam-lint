# IAM Blast Radius - SCP / RCP Semantics (AWS-verified reference)

Grounding spec for the AWS Organizations guardrail families (Phase 13). Story
IAM-1300 builds against this document. It changes no shipped code; it is the
source of truth for how the analyzer must classify a Service Control Policy
(SCP) and a Resource Control Policy (RCP).

Every claim below is verified against current AWS documentation. Sources are
cited inline by number and listed at the end. ASCII only. No secrets.

---

## 0. The load-bearing invariant (read this first)

**An SCP or an RCP is a permission CEILING / GUARDRAIL. It NEVER grants
permission.**

This is the same invariant the permissions-boundary and session families
already enforce in `engine/envelope.js`: an Allow in a ceiling policy is a
MAXIMUM-PERMISSIONS ENVELOPE, not a grant, and effective access is the
INTERSECTION of the ceiling and an independently-supplied identity/resource
policy. The SCP/RCP families reuse that ceiling semantics verbatim.

AWS states it plainly for SCPs: "SCPs do not grant permissions to the IAM users
and IAM roles in your organization. No permissions are granted by an SCP. An SCP
defines a permission guardrail, or sets limits, on the actions that the IAM
users and IAM roles in your organization can perform." [1] And: "an SCP never
grants permissions. Instead, SCPs are access controls that specify the maximum
available permissions" [1].

AWS states it identically for RCPs: "RCPs alone are not sufficient in granting
permissions to the resources in your organization. No permissions are granted by
an RCP. An RCP defines a permissions guardrail, or sets limits" [3]. And: "an RCP
never grants permissions. Instead, RCPs are access controls that specify the
maximum available permissions for resources in your organization." [3]

**Effective access is an INTERSECTION.** AWS: "The effective permissions are the
logical intersection between what is allowed by the SCP and resource control
policies (RCPs) and what is allowed by the identity-based and resource-based
policies." [1][3] An action is effective only if it is allowed by an identity
(or resource) policy AND permitted (not denied, and within any SCP Allow) by
every applicable SCP, AND not denied by any applicable RCP.

Therefore, for every SCP/RCP observation this analyzer emits:

- The finding describes a CEILING (an SCP Allow-list envelope) or a GUARDRAIL (a
  Deny). It is potential blast-radius framing ("this is the widest the ceiling
  permits"), NEVER a positive capability.
- The analyzer must NEVER manufacture a positive capability finding or a
  capability graph edge (can-read / can-write / can-pass / data-exfil /
  escalation) from an SCP or RCP. A ceiling can never establish a grant. Doing
  so is the overstated-certainty harm the threat model forbids (T8).
- A `NotAction` list is NEVER reported as "allowed." See section 4.
- On a genuinely-unmodeled SCP/RCP sub-shape, the analyzer fails closed
  (reports "unknown / not modeled"), never guesses a grant.

The identity, trust, resource, permissions-boundary, and session families stay
UNCHANGED. This document only adds the org-guardrail semantics.

---

## 1. SCP fundamentals

An SCP is an AWS Organizations policy that offers "central control over the
maximum available permissions for the IAM users and IAM roles in your
organization" [1]. Structurally an SCP looks almost like an identity policy and
"use[s] almost the same syntax" [1], but its semantics are a ceiling, not a
grant (section 0).

Scope facts the analyzer may state, all from [1]:

- **Member accounts only.** "SCPs don't affect users or roles in the management
  account. They affect only the member accounts in your organization." [1]
- **Every level must permit.** "An SCP restricts permissions for IAM users and
  roles in member accounts, including the member account's root user. Any account
  has only those permissions permitted by every parent above it." [1]
- **An SCP is not a substitute for a grant.** "Users and roles must still be
  granted permissions with appropriate IAM permission policies. A user without
  any IAM permission policies has no access, even if the applicable SCPs allow
  all services and all actions." [1]
- **Non-restrictable entities.** SCPs "do not affect any service-linked role" and
  cannot restrict actions performed by the management account [1]. The analyzer
  should not claim an SCP constrains those.

Because an SCP is a ceiling, its severity model mirrors `envelope.js`: a wildcard
SCP Allow is a WIDE ceiling (little protection) and a scoped SCP Allow is a TIGHT
ceiling. Neither is ever a "critical grant" -- a ceiling grants nothing.

---

## 2. SCP Allow-list ceilings

SCPs support two styles, and AWS distinguishes them explicitly: an allow-list
SCP and a deny-list SCP.

**Allow-list mechanics (deny-by-default).** "For a permission to be allowed for
a specific account, there must be an explicit Allow statement at every level from
the root through each OU in the direct path to the account (including the target
account itself)." [2] "SCP evaluation follows a deny-by-default model, meaning
that any permissions not explicitly allowed in the SCPs are denied." [2]

**The FullAWSAccess default.** "when you enable SCPs, AWS Organizations attaches
an AWS managed SCP policy named FullAWSAccess which allows all services and
actions. If this policy is removed and not replaced at any level of the
organization, all OUs and accounts under that level would be blocked from taking
any actions." [2] AWS warns: "You should not remove the FullAWSAccess policy
unless you modify or replace it with a separate policy with allowed actions,
otherwise all AWS actions from member accounts will fail." [1]

**Intersection across levels (the ceiling narrows going down).** AWS scenario 7:
two root-level allow-list SCPs plus a default FullAWSAccess at the OU "due to
intersection behavior, accounts A and B under these OUs can only access the
services explicitly permitted by the root-level SCP. The more restrictive root
policy takes precedence." [2]

**How the analyzer must talk about an SCP Allow:** it is the ceiling breadth, not
a grant. An `"Effect": "Allow"` statement in an SCP describes the widest set of
actions the ceiling will let through at that level; the identity policy must
still independently allow the action, and every other level's SCP must also
permit it. The analyzer reuses the `envelope.js` breadth logic (wildcard action
or `Resource: "*"` -> broad/high-breadth ceiling; scoped -> narrow) and states
the intersection in each finding's `limit`. It emits NO capability edge.

---

## 3. SCP Deny guardrails

A Deny in an SCP is the classic guardrail: it removes actions from the ceiling.

**Deny at any level wins.** "For a permission to be denied for a specific
account, any SCP from the root through each OU in the direct path to the account
(including the target account itself) can deny that permission." [2] AWS scenario
6: a root-level `Deny S3` beats a lower `Allow S3` -- "the root-level S3 deny
takes precedence." [2]

**Deny is a subtraction, not an assertion of access.** An SCP Deny tells you an
action is blocked at/below that node. It says NOTHING about whether the action
would otherwise be allowed -- that still depends on identity policies and the
allow-list ceiling. The analyzer reports an SCP Deny as a GUARDRAIL observation
(what the ceiling forbids), never inverting it into "everything else is
therefore allowed."

Deny guardrails commonly carry `Condition` blocks (region, MFA, org-id, source);
those conditions narrow WHEN the guardrail applies and are evidence, not grants.
See sections 5 and 6.

---

## 4. NotAction in SCPs (the polarity trap)

`NotAction` "explicitly matches everything except the specified list of actions."
[5] Its effect depends on the statement `Effect`:

- With `"Effect": "Deny"`, a `NotAction` list means: **deny every action EXCEPT
  the listed ones.** AWS: "You can use the NotAction element in a statement with
  'Effect': 'Deny' to deny access to all of the listed resources except for the
  actions specified in the NotAction element. This combination does not allow the
  listed items, but instead explicitly denies the actions not listed. You must
  still allow actions that you want to allow." [5]

**The load-bearing rule for the analyzer:** a `Deny` + `NotAction` list is a
DENY of everything-except-the-list. The listed actions are the CARVE-OUT
(exempted from the deny), NOT a grant. AWS is explicit that even the exempted
actions are not thereby allowed: "this would not grant the user access to any
actions; it would only explicitly deny all other actions except IAM actions." [5]

So the analyzer must:

- Report the guardrail as "denies all actions except {list}" -- the wide,
  everything-else deny is the finding.
- Surface the `NotAction` list as `excludedActions` / a carve-out (exactly as
  `envelope.js` already does), NEVER as the "allowed actions."
- Never read a `NotAction` complement as a positive capability. The excluded set
  is not a grant; it is merely outside this deny's reach and still subject to
  every other policy.

(For completeness: `NotAction` with `Allow` "provide[s] access to all of the
actions in an AWS service, except for the actions specified" [5]. SCPs can use
this shape too, but even then the SCP only widens the ceiling -- it still grants
nothing, per section 0. AWS warns this shape "could result in granting users more
permissions than you intended" [5], which for a ceiling means an over-wide
envelope, not an actual grant.)

---

## 5. Region guardrails: aws:RequestedRegion + global-service exceptions

A very common SCP guardrail restricts which AWS Regions may be used, via the
`aws:RequestedRegion` global condition key in a `Deny`.

**The canonical AWS pattern** denies all actions whose `aws:RequestedRegion` is
not in an allowed set, while exempting global services with `NotAction` [6]:

```
{
    "Version":"2012-10-17",
    "Statement": [
        {
            "Sid": "DenyAllOutsideRequestedRegions",
            "Effect": "Deny",
            "NotAction": [
                "cloudfront:*",
                "iam:*",
                "organizations:*",
                "route53:*",
                "support:*"
            ],
            "Resource": "*",
            "Condition": {
                "StringNotEquals": {
                    "aws:RequestedRegion": [
                        "eu-central-1",
                        "eu-west-1",
                        "eu-west-2",
                        "eu-west-3"
                    ]
                }
            }
        }
    ]
}
```

**Why the global-service NotAction carve-out exists.** AWS: "Actions in the
CloudFront, IAM, Route 53, and Support services should not be denied because
these are popular AWS global services with a single endpoint that is physically
located in the us-east-1 Region. Because all requests to these services are made
to the us-east-1 Region, the requests would be denied without the NotAction
element." [6] Other global services (for example `budgets`, `globalaccelerator`,
`organizations`, `waf`) may need adding [6].

**How the analyzer must classify this shape:**

- It is a REGION GUARDRAIL: the ceiling forbids actions outside the allowed
  Regions. Report it as a guardrail with the allowed-Region set and the
  global-service carve-out as evidence.
- The `NotAction` global-service list is a CARVE-OUT (exempt from the region
  deny), not "allowed in every region" -- section 4 applies. Do not report the
  carve-out services as granted.
- AWS explicitly warns the pattern grants nothing: "This policy does not allow
  any actions. Use this policy in combination with other policies that allow
  specific actions." [6] The analyzer must carry that same limit.
- `StringNotEquals` on `aws:RequestedRegion` is a negated match: the deny fires
  when the requested Region is not one of the listed values. State the region
  set the ceiling allows, not a fabricated capability.

---

## 6. StringNotEqualsIfExists in a Deny (negated-IfExists)

Guardrails frequently use the `...IfExists` operator suffix, especially the
negated form `StringNotEqualsIfExists`, so the analyzer must model its polarity
correctly.

**Base `...IfExists` semantics.** AWS: "If the condition key is present in the
context of the request, process the key as specified in the policy. If the key
is not present, evaluate the condition element as true." [7]

**The Deny-specific consequence (the important part).** AWS: "If you are using an
'Effect': 'Deny' element with a negated condition operator like
StringNotEqualsIfExists, the request is still denied even if the condition key is
not present." [7]

So in a Deny guardrail, `StringNotEqualsIfExists` on a key is a FAIL-CLOSED
guardrail: the deny fires both when the key is present-and-not-matching AND when
the key is absent. This is deliberate -- an attacker cannot dodge the guardrail
by omitting the context key. The analyzer must:

- Read `StringNotEqualsIfExists` in a Deny as "denies unless the key is present
  AND equals an allowed value" -- absence still denies.
- Never treat the absent-key case as a grant or an escape hatch. The IfExists on
  a Deny is a strengthening of the guardrail, not a hole in it.

(Contrast: `...IfExists` on an `Allow` evaluates true when the key is absent,
which can WIDEN a ceiling. Even then the SCP grants nothing -- it only widens the
envelope.)

The `Null` operator is the companion existence check: "Use a Null condition
operator to check if a condition key is absent at the time of authorization. In
the policy statement, use either true (the key doesn't exist -- it is null) or
false (the key exists and its value is not null)." [7] It appears in the RCP
confused-deputy pattern below.

---

## 7. RCP fundamentals (org resource guardrails, deny-only)

An RCP is the resource-side sibling of an SCP: "RCPs offer central control over
the maximum available permissions for resources in your organization." [3] RCPs
"are most closely related to resource-based policies" [3] but, like SCPs, are a
ceiling, not a grant (section 0).

Key facts the analyzer may state, all from [3][4]:

- **Deny-only in practice.** The default RCP, `RCPFullAWSAccess`, "is
  automatically attached to the organization root, every OU, and every account
  ... This default RCP allows all principals and actions access to pass through
  RCP evaluation. You can make use of Deny statements to restrict access to
  resources in your organization." [4] An RCP does its work through `Deny`; its
  Allow is only the pass-through default. AWS also frames RCPs as "coarse-grained
  preventative controls, and they don't grant access." [4]
- **Resources, not principals, are the subject.** "RCPs affect only resources
  that are managed by accounts that are part of the organization." [3] They set
  the ceiling on "who may access org resources," including callers outside the
  organization: an RCP "applies to the S3 bucket in Account A even when accessed
  by users from Account B" outside the org [3].
- **Effective access is still an intersection.** "The effective permissions are
  the logical intersection between what is allowed by the RCPs and service
  control policies (SCPs) and what is allowed by the identity-based and
  resource-based policies." [3] "A user or role without any IAM permission
  policies has no access, even if an applicable RCP allows all services, all
  actions, and all resources." [3]
- **Supported-service subset.** RCPs apply only to a documented subset of
  services (S3, SQS, KMS, STS, Secrets Manager, CloudWatch Logs, ECR, DynamoDB,
  and others) [3]. If a policy targets a service outside that list, the RCP does
  not apply there -- the analyzer should not claim a ceiling it does not have,
  and should fail closed / note "service may be out of RCP scope."
- **Non-restrictable.** RCPs do not affect resources in the management account,
  do not apply to service-linked roles, and do not apply to AWS managed KMS keys
  [3]. (KMS adds that `kms:RetireGrant` "is not effective in an RCP, even if the
  Action element specifies an asterisk" [8].)

Because an RCP grants nothing, the analyzer treats an RCP the same way as any
ceiling: report the guardrail breadth, state the intersection limit, emit NO
positive capability edge.

---

## 8. RCP confused-deputy protection at org scope

The confused deputy is a privilege-escalation pattern where a less-privileged
actor coerces a more-privileged deputy (often an AWS service principal) into
acting on its behalf [9]. RCPs let an org centrally close this at the resource
side. The canonical AWS RCP example (KMS) is [8]:

```
{
    "Version":"2012-10-17",
    "Statement": [
        {
            "Sid": "RCPEnforceConfusedDeputyProtection",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "kms:*",
            "Resource": "*",
            "Condition": {
                "StringNotEqualsIfExists": {
                    "aws:SourceOrgID": "my-org-id"
                },
                "Bool": {
                    "aws:PrincipalIsAWSService": "true"
                },
                "Null": {
                    "aws:SourceAccount": "false"
                }
            }
        }
    ]
}
```

How AWS describes the mechanism [8]: the RCP "requires that AWS service
principals can only access your customer managed KMS keys when the request
originates from your organization. This policy applies the control only on
requests that have aws:SourceAccount present ... If aws:SourceAccount is present
in the request context, the Null condition evaluates to true, causing the
aws:SourceOrgID key to be enforced."

Decode of the three conditions the analyzer must model:

- `"Bool": {"aws:PrincipalIsAWSService": "true"}` -- the guardrail applies only
  when the caller is an AWS service principal (the potential confused deputy).
- `"Null": {"aws:SourceAccount": "false"}` -- only when `aws:SourceAccount` is
  present in the request context (so service integrations that never set it are
  not broken). See the `Null` semantics in section 6 [7].
- `"StringNotEqualsIfExists": {"aws:SourceOrgID": "my-org-id"}` -- deny unless the
  source org is your org; because it is negated-IfExists in a Deny, absence of
  `aws:SourceOrgID` still denies (section 6) [7]. That fail-closed behavior is
  exactly what makes it a guardrail.

A related identity-perimeter RCP uses `aws:PrincipalOrgID` with
`"Bool": {"aws:PrincipalIsAWSService": "false"}` to deny non-service principals
outside the org [8].

**How the analyzer must classify these:** a confused-deputy RCP is a DENY
GUARDRAIL scoped by org identity. Report it as "org resource guardrail: denies
access to these resources unless the caller is within the org / a trusted
source." The presence of `aws:SourceOrgID` + `aws:PrincipalIsAWSService` +
`Null` on `aws:SourceAccount` is confused-deputy protection and should raise
CONFIDENCE that the guardrail is present, never generate a capability edge.
Absence of these keys where you would expect them is a coverage gap the analyzer
may note -- but it must not invent an exposure it cannot see, and it must not
report the guardrail as a grant.

---

## 9. What the analyzer must do (summary of obligations)

1. **Route to a ceiling evaluator, not the identity engine.** SCP and RCP inputs
   are analyzed as ceilings/guardrails, reusing `engine/envelope.js` ceiling
   semantics (Allow = maximum-permissions envelope; Deny = guardrail). Never run
   identity rules or the escalation catalog on an SCP/RCP.

2. **Never emit a positive capability.** No can-read / can-write / can-pass /
   data-exfil / escalation finding or edge may originate from an SCP or RCP. The
   graph draws no capability edge for these families. Every finding is framed as
   a CEILING or GUARDRAIL, and every finding's `limit` states "this is a ceiling,
   not a grant; effective access is the intersection with identity/resource
   policies that are not supplied here."

3. **NotAction lists are carve-outs, never grants** (section 4). Surface them as
   an excluded set, never as allowed actions.

4. **Model condition polarity honestly** (sections 5, 6): `StringNotEquals` on
   `aws:RequestedRegion`, negated-IfExists in Deny (fail-closed), and `Null`
   existence checks are guardrail evidence, not grants.

5. **RCPs are deny-only org resource guardrails** (sections 7, 8). Respect the
   supported-service subset and the non-restrictable exceptions; do not claim a
   ceiling where RCPs do not apply.

6. **Fail closed on unmodeled sub-shapes.** If an SCP/RCP construct is not
   modeled, report "unknown / not modeled," never a guessed grant. Overstating a
   ceiling as access is threat-model harm T8.

7. **Do not touch the other families.** Identity, trust, resource,
   permissions-boundary, and session behavior is unchanged by this document.

---

## Sources

All URLs are current AWS documentation, verified for this reference.

1. Service control policies (SCPs) -- AWS Organizations User Guide (SCPs never
   grant; permission guardrail; member-accounts-only; effective permissions are
   the intersection; FullAWSAccess must not be removed unmodified):
   https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html
2. SCP evaluation -- How SCPs work with Allow and Deny (explicit Allow at every
   level; deny-by-default; FullAWSAccess default; Deny at any level wins;
   intersection scenario 7):
   https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html
3. Resource control policies (RCPs) -- AWS Organizations User Guide (RCPs never
   grant; resource guardrail; supported-service list; intersection with
   SCP/identity/resource policies; non-restrictable exceptions):
   https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
4. Resource control policy examples -- AWS Organizations User Guide
   (RCPFullAWSAccess default pass-through; RCPs are coarse-grained preventative
   controls that do not grant access; use Deny statements):
   https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_examples.html
5. IAM JSON policy elements: NotAction (NotAction matches everything except the
   list; Deny+NotAction denies all actions not listed and grants nothing):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html
6. AWS: Denies access to AWS based on the requested Region (aws:RequestedRegion
   with NotAction global-service carve-out; StringNotEquals; "does not allow any
   actions"):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples_aws_deny-requested-region.html
7. IAM JSON policy elements: Condition operators (...IfExists semantics; negated
   IfExists in Deny still denies when key absent; Null existence check):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html
8. Resource control policies in AWS KMS (RCPs never grant; confused-deputy RCP
   example with aws:SourceOrgID + aws:PrincipalIsAWSService + Null on
   aws:SourceAccount; kms:RetireGrant not effective in an RCP):
   https://docs.aws.amazon.com/kms/latest/developerguide/resource-control-policies.html
9. The confused deputy problem -- IAM User Guide:
   https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
10. AWS global condition context keys (aws:RequestedRegion, aws:SourceOrgID,
    aws:PrincipalIsAWSService, aws:SourceAccount, aws:PrincipalOrgID):
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
