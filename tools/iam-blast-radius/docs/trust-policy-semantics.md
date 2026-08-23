# IAM Blast Radius - Trust-Policy Semantics (AWS-verified reference)

Grounding spec for the role-trust feature (Phase 8). Stories IAM-801..806
build against this document. It changes no shipped code; it is the source of
truth for how the trust analyzer must classify a role trust policy.

Every claim below is verified against current AWS documentation. Sources are
cited inline by number and listed at the end. ASCII only. No secrets.

---

## 0. The load-bearing invariant (read this first)

**A role trust policy conveys WHO MAY ASSUME the role. It never conveys the
assumed role's permissions.**

AWS defines a trust policy as a resource-based policy attached to a role that
"defines which principals can assume the role" [1][2]. The role's own
permissions come from a separate identity-based (permissions) policy plus any
permissions boundary and session policy [1]. None of that is present in a
trust policy.

Therefore, for every trust finding this analyzer emits:

- The finding describes only the trust relationship (who is allowed to call
  `sts:AssumeRole*` against this role, and under what conditions).
- The assumed role's actual privileges are **out of scope / unknown**. The
  analyzer must say so on every trust finding.
- The analyzer must NEVER state or imply that an assumer "inherits the role's
  power," gains admin, or reaches any specific resource. That is a
  truthfulness harm (threat-model T8) because the target-role permissions were
  never supplied.

Corollary: a trust policy is NOT an identity policy. Do not run identity rules
on it, and do not emit an identity-style broad-`Resource` finding. Trust
policies commonly omit `Resource` entirely; its absence is normal, not a
finding.

---

## 1. The confused-deputy problem (state it plainly)

The confused deputy is a privilege-escalation pattern where an entity that
lacks permission to an action coerces a more-privileged entity (the "deputy")
into performing it on its behalf [3]. In the cross-account role context: a
third party (for example a SaaS vendor) is given permission to assume a role
in your account. If that third party can be tricked into assuming your role
while acting for a different customer, your resources are exposed [3][4].

The documented mitigation is `sts:ExternalId`. The role owner and the third
party agree on an external ID; the third party sends it on every
`sts:AssumeRole` call, and the trust policy requires it via a
`StringEquals` condition [3][4]. AWS is explicit that the external ID:

- "must be unique among a third party's customers" and is generated and
  controlled by the third party, not the customer [4].
- exists specifically "to address and prevent the confused deputy problem"
  [3][5].

**How the analyzer must talk about ExternalId (polarity matters):**

- Presence of `sts:ExternalId` is a **constraint** (a confused-deputy
  mitigation). It LOWERS severity/exploitability of a cross-account trust.
- NEVER report "missing ExternalId" as if absence were itself a finding on
  every cross-account trust. Absence is context, not a rule violation.
- NEVER describe ExternalId as authentication or a secret. It is not a
  credential; it is a per-customer correlation value that mitigates a
  specific confused-deputy scenario [3][4]. It can even appear in logs. Do not
  call it "secrecy" or "auth."

---

## 2. Principal types

The `Principal` element names who is trusted. All syntax below is from the AWS
`Principal` reference [2]. The analyzer parses `Principal` into these typed
forms.

### 2.1 Anonymous / public (`*`)

```
"Principal": "*"
"Principal": { "AWS": "*" }
```

These two are equivalent and mean **all principals, including anonymous
(public) access** [2]. AWS "strongly recommends" against a wildcard principal
with an `Allow` effect unless public access is intended, and calls this out as
"especially true for IAM role trust policies, because they allow other
principals to become a principal in your account" [2].

- Analyzer classification: **anonymous** -> PUBLIC-TRUST, severity **critical**.

### 2.2 AWS account and root

```
"Principal": { "AWS": "arn:aws:iam::123456789012:root" }
"Principal": { "AWS": "123456789012" }
```

The account ARN (`...:root`) and the bare 12-digit account ID behave
identically: both delegate trust to the entire account, and the `...:root`
form does NOT limit trust to only the root user [2]. An administrator in the
trusted account must then grant one of its identities permission to assume the
role [2].

- Analyzer classification: **aws-account** (bare id) or **aws-root**
  (`:root` ARN). Cross-account when the account differs from the role's own.

### 2.3 IAM user ARN

```
"Principal": { "AWS": "arn:aws:iam::123456789012:user/user-name" }
```

Names a specific IAM user. A wildcard cannot be used to mean "all users" and
cannot match part of a name/ARN [2]. When saved, a user ARN transforms to the
user's unique principal ID to resist delete-and-recreate escalation [2].

- Analyzer classification: **aws-principal-arn** (user).

### 2.4 IAM role ARN and role-session ARN

```
"Principal": { "AWS": "arn:aws:iam::123456789012:role/role-name" }
"Principal": { "AWS": "arn:aws:sts::123456789012:assumed-role/role-name/session-name" }
"Principal": { "AWS": "arn:aws:sts::123456789012:federated-user/user-name" }
```

A role ARN, an assumed-role session ARN, or an STS federated-user session ARN
[2]. As with users, a specific role ARN transforms to the role's unique
principal ID on save; deleting and recreating the role breaks the trust [2].

- Analyzer classification: **aws-principal-arn** (role / session).

### 2.5 Service principal

```
"Principal": { "Service": "lambda.amazonaws.com" }
"Principal": { "Service": [ "ecs.amazonaws.com", "elasticloadbalancing.amazonaws.com" ] }
```

An AWS service that may assume the role (a "service role") [2]. Multiple
services go in an array under a single `Service` key, not multiple `Service`
keys [2]. `"Service": "*"` is not valid in a trust policy [2]. For trust
policies AWS recommends the non-regionalized `service.amazonaws.com` form [2].

- Analyzer classification: **service** -> normal AWS service trust,
  **informational**. Never infer an escalation path from a service trust
  alone (this is the negative control, acceptance-suite test 18).

### 2.6 Federated - OIDC

```
"Principal": { "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
```

Used with `sts:AssumeRoleWithWebIdentity`. The value is the ARN of an
OIDC provider added to the account (for example GitHub Actions'
`token.actions.githubusercontent.com`), or one of the four built-in providers
(`cognito-identity.amazonaws.com`, `www.amazon.com`, `graph.facebook.com`,
`accounts.google.com`) [2]. OIDC federated principals are only valid in role
trust policies [2].

- Analyzer classification: **federated-oidc**. Subject scope drives severity
  (see 4.4).

### 2.7 Federated - SAML

```
"Principal": { "Federated": "arn:aws:iam::123456789012:saml-provider/provider-name" }
```

Used with `sts:AssumeRoleWithSAML`; the value is the ARN of a SAML provider in
the account [2].

- Analyzer classification: **federated-saml**.

### 2.8 CanonicalUser

```
"Principal": { "CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be" }
```

An S3 canonical user ID. This is a resource-policy (S3) principal form, not a
normal role-trust principal [2]. In the role-trust family it is an unusual
shape.

- Analyzer classification: **canonical-user** (recognized type).

### 2.9 NotPrincipal (fail closed)

`NotPrincipal` is a distinct element (everyone EXCEPT the listed principals)
and is an expansion trap. Until a family-aware evaluator exists it stays
rejected with `UNSUPPORTED_NOTPRINCIPAL` (Phase-5 / IAM-801). It is never
silently treated as `Principal`.

### 2.10 Unknown / unmodeled principal types (fail closed)

Any `Principal` shape not in 2.1-2.8 keeps the family AMBIGUOUS / unsupported
and is surfaced in coverage ("unsupported != safe"). The analyzer does not
guess.

---

## 3. The trust (STS) action set

A trust policy grants `sts:` actions that govern how the role is assumed. The
v1 modeled set:

| Action | Meaning | Notes |
|---|---|---|
| `sts:AssumeRole` | Assume the role with AWS-identity or account principals [6] | The core trust grant. |
| `sts:AssumeRoleWithWebIdentity` | Assume via an OIDC web-identity token [2][7] | Pairs with a `Federated` OIDC principal. |
| `sts:AssumeRoleWithSAML` | Assume via a SAML assertion [2] | Pairs with a `Federated` SAML principal. |
| `sts:TagSession` | Permit passing session tags on assume [8] | Required in the trust policy when the caller/IdP passes session tags; without it the assume fails [8]. Not itself an escalation. |
| `sts:SetSourceIdentity` | Permit setting a source identity on the session [9] | Required in the trust policy for the role to accept a source identity; without it the AssumeRole* call fails [9]. An accountability/traceability control, not an escalation. |

Presence of a trust action (any of the above) is what makes a statement a
trust statement. `sts:TagSession` / `sts:SetSourceIdentity` appearing ALONGSIDE
an assume action is normal and expected; they are not on their own a
privilege grant and must not be scored as one.

---

## 4. Condition keys, WITH POLARITY

Polarity is the crux. The same key can be a constraint (narrows who/when) or
an expansion (broadens it), depending on the operator. The classifier only
classifies the policy text; it must NEVER assert that a specific runtime
AWS request would be allowed or denied.

Rule of thumb:
- A negated or wildcarded operator on an otherwise-constraining key is an
  **EXPANSION** and RAISES the finding.
- A positive-match constraining key LOWERS path-exploitability.
- Any key not in this v1 set is **unsupported: reduces confidence** and is
  surfaced in coverage - never silently credited as protective.

### 4.1 sts:ExternalId

AWS: "Use this key to require that a principal provide a specific identifier
when assuming an IAM role"; its "primary function ... is to address and
prevent the confused deputy problem" [5].

- `StringEquals sts:ExternalId "<value>"` -> **constraint**
  (confused-deputy mitigation). Lowers a cross-account trust toward low/medium.
- It is a per-customer correlation value, unique among the third party's
  customers [4]. Not auth, not a secret.
- Do not report it as "missing."

### 4.2 aws:PrincipalOrgID

AWS: "Use this key to compare the identifier of the organization in AWS
Organizations to which the requesting principal belongs with the identifier
specified in the policy" [10]. Present only if the principal is a member of an
organization; anonymous requests do not include it [10].

- `StringEquals aws:PrincipalOrgID "o-xxxx"` -> **constraint**: confines trust
  to principals inside the named org. Lowers exploitability.
- `StringNotEquals aws:PrincipalOrgID "o-xxxx"` -> **EXPANSION**: this permits
  principals OUTSIDE the named org (subject to other request context). This is
  a dangerous-polarity finding, severity **critical** (acceptance-suite
  test 10). Classify the operator as expansion/exclusion, NOT as a protective
  org restriction. NEVER produce "aws:PrincipalOrgID is missing" remediation
  when the key is present with expanding polarity - explain it is present with
  dangerous polarity.

### 4.3 Confused-deputy / request-context constraints for service principals

- `aws:SourceArn` compares the ARN of the service/resource that caused the
  call; available when the call "is made directly by an AWS service principal"
  [11]. -> **constraint** (confused-deputy mitigation for service trust).
- `aws:SourceAccount` compares the account that initiated the request; only
  available when the call is made directly by a service principal [11]. Listed
  as a sensitive key - wildcards in it have no valid use case [11].
  -> **constraint**.
- `aws:MultiFactorAuthPresent` checks whether MFA validated the temporary
  credentials [11]; present only when temporary credentials are used, and NOT
  present for federated identities or long-term access-key requests [11].
  -> **constraint** (with the availability caveat above; do not treat its
  absence as proof of anything).
- `aws:SourceIp` compares the requester's public IP to the policy value; only
  public IP ranges, and not present when a VPC endpoint is used [11].
  -> **constraint**.

For all four: a positive match is a constraint that LOWERS exploitability; a
negated form (`StringNotEquals`, `ArnNotEquals`, `NotIpAddress`, or MFA
required to be false) inverts the polarity and RAISES the finding.

### 4.4 OIDC federation: aud and sub

Defined by naming the provider host followed by a claim, for example
`token.actions.githubusercontent.com:aud` and
`token.actions.githubusercontent.com:sub` [7].

- **aud** (audience). For GitHub Actions the audience is
  `sts.amazonaws.com` [7]. A positive `aud` check is a valid **constraint** -
  recognize it, do not flag it as missing.
- **sub** (subject) drives severity because it scopes WHICH workloads may
  assume the role:
  - `repo:example-org/*` (or an absent `sub`) = org-wide repository trust ->
    **broad** -> HIGH (acceptance-suite test 17).
  - `repo:example-org/repo-name:ref:refs/heads/main` (repo + branch, or repo +
    environment/tag) = **tight** -> low/medium; does not fire the high
    expansion finding [7].
  - Remediation: constrain `sub` to the intended repository and
    branch/environment.
  - Do NOT claim "every repository can assume this role." Assuming the role
    also requires a matching OIDC token and workflow context, which is out of
    scope. State the trust is broadly SCOPED, not that assumption is confirmed.

### 4.5 SAML federation: saml:aud

AWS: `saml:aud` is "an endpoint URL to which SAML assertions are presented,"
sourced from the assertion's `SAML Recipient` field [12].

- A positive `saml:aud` check is a valid **constraint** for SAML federated
  trust, analogous to OIDC `aud`. Absence of subject-scoping conditions on a
  SAML federated principal is treated like a broad OIDC subject (higher),
  by analogy; SAML attribute conditions (for example `saml:sub`) that narrow
  the subject are constraints.

---

## 5. Trust severity model (coherent and documented)

Severity reflects the trust relationship only; the target role's privileges
remain unknown on every row.

| Trust shape | Severity | Rationale |
|---|---|---|
| Principal `*` / `{"AWS":"*"}` + trust action (public) | **critical** | Unrestricted, anonymous role trust [2]. |
| `aws:PrincipalOrgID` with `StringNotEquals` (org-exclusion expansion) | **critical** | Dangerous polarity: trusts principals outside the named org [10]. |
| Unconditioned external cross-account / root / external principal-ARN | **high** | Any principal in the trusted account can assume; no confused-deputy constraint [2]. |
| OIDC/SAML with broad subject (`repo:org/*` or absent sub) | **high** | Org-wide federated subject scope [7]. |
| External **account-bounded** principal + `sts:ExternalId` (or SourceArn/SourceAccount) | **low/medium** | Confused-deputy constraint present [3][4]. Applies only when the principal is bounded to one account. |
| External **broad** wildcard-ARN principal (`arn:aws:iam::*:role/*`, spans every account) + `sts:ExternalId` (or SourceArn/SourceAccount) | **high** | The confused-deputy correlation value bounds HOW the call is made, not WHICH/HOW-MANY of the unbounded principal set is trusted; breadth stays high (constraint lowers only path-exploitability) [3][4]. |
| OIDC/SAML with tight subject (repo + ref/env) | **low/medium** | Subject scoped to a specific workload [7]. |
| Service principal trust (e.g. `lambda.amazonaws.com`), no expanding condition | **informational** | Normal AWS service trust; negative control [2]. |
| Anything outside the v1 condition-key set | n/a to severity | **unsupported: reduces confidence**; surfaced in coverage, never credited as protective. |

Modifiers:
- A constraining condition (4.1, 4.3, 4.5, positive 4.4) lowers
  path-exploitability one band.
- An expanding/negated condition (4.2 NotEquals, negated 4.3, absent 4.4 sub)
  raises the finding.
- Every row carries the limitation: **the assumed role's permissions are out
  of scope / unknown.**

---

## 6. Graph representation

Trust origin is the **external principal(s)** that may assume the role:

```
[External principal(s)] --can-assume--> [This role: target privileges UNKNOWN]
```

- The origin node represents the external/anonymous/federated principals that
  are trusted, NOT "the principal subject of this policy."
- The `can-assume` edge carries the exact supporting evidence (statement,
  principal, trust action, conditions) and a certainty class.
- The target node explicitly marks the role's privileges as unknown /
  out-of-scope.
- Reuse the existing typed edges; do NOT reintroduce a generic `can-write`
  aggregation (that Phase-7 defect must stay fixed).

---

## 7. Fail-closed rules (never analyze a shape we do not model)

- `NotPrincipal` -> `UNSUPPORTED_NOTPRINCIPAL` (expansion trap; stays rejected).
- Unknown/unmodeled `Principal` type -> family stays AMBIGUOUS / unsupported.
- Mixed identity + trust document -> `AMBIGUOUS_POLICY_SHAPE`.
- Never run identity rules on a trust policy; never emit an identity-style
  broad-`Resource` finding on a trust policy.
- Never assert a runtime AWS allow/deny - the analyzer classifies policy text,
  it does not simulate STS.
- "Unsupported != safe": unmodeled conditions/elements are surfaced in the
  coverage summary and reduce confidence; they are never silently ignored and
  never counted as protection.

---

## Sources

All URLs are current AWS documentation, verified for this reference.

1. IAM roles - terms and concepts (trust policy defines which principals can
   assume the role):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html
2. AWS JSON policy elements: Principal (all Principal types, syntax, and the
   `*` public-access warning):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
3. The confused deputy problem:
   https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
4. Access to AWS accounts owned by third parties (external ID unique per
   customer, controlled by the third party):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html
5. IAM and AWS STS condition context keys - `sts:ExternalId` description:
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html
6. AWS STS AssumeRole API reference:
   https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
7. IAM/STS condition keys - AWS OIDC federation (`...:aud`, `...:sub`, GitHub
   Actions `token.actions.githubusercontent.com` example):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html
8. Pass session tags in AWS STS (`sts:TagSession` required in the trust policy
   to pass session tags):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html
9. Monitor and control actions taken with assumed roles
   (`sts:SetSourceIdentity` required in the trust policy for source identity):
   https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html
10. Global condition keys - `aws:PrincipalOrgID`:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
11. Global condition keys - `aws:SourceArn`, `aws:SourceAccount`,
    `aws:MultiFactorAuthPresent`, `aws:SourceIp`:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html
12. IAM/STS condition keys - SAML-based federation (`saml:aud`):
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html
