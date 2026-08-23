# IAM Blast Radius — Complex Acceptance Test Suite

## Purpose

This document defines adversarial and regression tests for a client-side AWS IAM policy analyzer. Each case includes the policy family, input document, expected findings, expected non-findings, confidence boundaries, and evidence or graph assertions.

These are normative acceptance tests for potential blast-radius analysis. They do not require the tool to calculate a principal's complete effective permissions across every AWS policy layer.

## Analyzer contract assumed by these tests

The analyzer should require an explicit policy family:

- Identity policy
- Resource policy
- Role trust policy
- Permissions boundary
- SCP or RCP
- Session policy

Unknown or mixed policy shapes should produce a blocking coverage warning. Unsupported elements should never be silently interpreted as ordinary grants.

Every finding should expose at least:

- Stable rule identifier
- Severity
- Policy-evidence confidence
- Path-exploitability confidence, when applicable
- Exact contributing statement indexes and Sids
- Exact actions and resources contributed by each statement
- Relevant conditions and their interpreted effect
- Why the capability matters
- What the policy does not prove
- Remediation

Severity names below are recommended defaults. A different severity is acceptable only when the tool documents a consistent scoring model and preserves the expected capability and uncertainty.

---

## Test 1 — Cross-statement PassRole to EC2

**Policy family:** Identity policy  
**Purpose:** Detect a compound escalation path whose permissions are distributed across statements.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassWorkloadRoles",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/workload/*"
    },
    {
      "Sid": "LaunchInstances",
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": "*"
    }
  ]
}
```

### Expected result

- **Critical or high:** potential PassRole-to-EC2 execution path.
- Policy evidence: **high**.
- Path exploitability: **medium**, because the permissions of passable roles and practical instance execution are unknown.
- Explain that `iam:PassRole` is role-scoped while `ec2:RunInstances` is broadly resource-scoped.
- Recommend `iam:PassedToService = ec2.amazonaws.com`, tighter role ARNs, and workload-creation constraints.

### Evidence assertions

- `iam:PassRole` must be attributed only to statement 0 / `PassWorkloadRoles`.
- `ec2:RunInstances` must be attributed only to statement 1 / `LaunchInstances`.
- No synthetic statement may claim that both actions appeared together.
- A graph may correlate the evidence, but each edge must retain the original evidence objects.

---

## Test 2 — PassRole condition permits Lambda, not EC2

**Policy family:** Identity policy  
**Purpose:** Verify service-condition semantics and prevent a false EC2 path.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassOnlyToLambda",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/lambda/*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "lambda.amazonaws.com"
        }
      }
    },
    {
      "Sid": "CreateLambda",
      "Effect": "Allow",
      "Action": "lambda:CreateFunction",
      "Resource": "*"
    },
    {
      "Sid": "LaunchEC2",
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": "*"
    }
  ]
}
```

### Expected result

- Detect a potential Lambda PassRole path.
- Do **not** report an EC2 PassRole path.
- Show `iam:PassedToService` as a path selector that excludes EC2.
- Do not report "missing `iam:PassedToService`" remediation.
- Retain medium exploitability because the target role's permissions remain unknown.

---

## Test 3 — Separate Lambda execution techniques

**Policy family:** Identity policy  
**Purpose:** Ensure alternative escalation techniques are not represented as one AND-list.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/lambda/AdminAutomationRole"
    },
    {
      "Sid": "CreateFunction",
      "Effect": "Allow",
      "Action": "lambda:CreateFunction",
      "Resource": "*"
    },
    {
      "Sid": "ReplaceExistingCode",
      "Effect": "Allow",
      "Action": "lambda:UpdateFunctionCode",
      "Resource": "arn:aws:lambda:us-west-2:123456789012:function:billing-admin"
    }
  ]
}
```

### Expected result

- Path A: `iam:PassRole` **AND** `lambda:CreateFunction` can create code under the passable role.
- Path B: `lambda:UpdateFunctionCode` can replace code executed by the existing function role; this path does not require `iam:PassRole`.
- Do not emit one prerequisite list claiming all three actions are jointly required.
- Path B must state that the existing function role and invocation path are outside the supplied context.

---

## Test 4 — Managed-policy version escalation

**Policy family:** Identity policy  
**Purpose:** Detect an IAM escalation primitive without an action wildcard.

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Sid": "ControlPolicyVersions",
    "Effect": "Allow",
    "Action": [
      "iam:CreatePolicyVersion",
      "iam:SetDefaultPolicyVersion"
    ],
    "Resource": "arn:aws:iam::123456789012:policy/application/*"
  }
}
```

### Expected result

- **Critical or high:** managed-policy version manipulation.
- Explain that a new permissive version can become the default for principals already attached to an in-scope managed policy.
- Do not claim administrator access without attachment and target-principal context.
- Verify that an object-valued `Statement` is normalized identically to a one-element array.

---

## Test 5 — Access-key creation for another user

**Policy family:** Identity policy  
**Purpose:** Detect credential creation and persistence.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateKeysForAutomationUsers",
      "Effect": "Allow",
      "Action": "iam:CreateAccessKey",
      "Resource": "arn:aws:iam::123456789012:user/automation/*"
    }
  ]
}
```

### Expected result

- **Critical or high:** create long-lived credentials for another IAM user.
- Explain that impact depends on which users match the ARN and their effective permissions.
- Graph edge type should represent credential creation or impersonation, not generic resource write.

---

## Test 6 — Broad cross-account AssumeRole

**Policy family:** Identity policy  
**Purpose:** Preserve the difference between permission to call STS and actual role reachability.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeAnyDeploymentRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/deployment/*"
    }
  ]
}
```

### Expected result

- **Critical or high:** broad cross-account role-assumption capability.
- Policy evidence: **high** that the identity policy allows the request.
- Path exploitability: **medium or low** because target trust policies are absent.
- Graph target must be labeled potentially reachable with unknown privileges.
- Do not state that arbitrary roles can actually be assumed.

---

## Test 7 — S3 data access constrained through KMS

**Policy family:** Identity policy  
**Purpose:** Model data access and contextual KMS restrictions without overclaiming.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadProductionExports",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::production-exports",
        "arn:aws:s3:::production-exports/*"
      ]
    },
    {
      "Sid": "DecryptOnlyThroughS3",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:us-west-2:123456789012:key/11111111-2222-3333-4444-555555555555",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "s3.us-west-2.amazonaws.com"
        }
      }
    }
  ]
}
```

### Expected result

- Report access to objects in the named S3 bucket.
- Sensitivity inferred from `production-exports` should have **medium** confidence, unless the tool uses a neutral "data-read capability" title.
- Report KMS decryption as constrained to S3 in `us-west-2`.
- Do not describe KMS access as unrestricted or wildcard-scoped.
- Do not claim that every object is decryptable; S3 encryption configuration and the KMS key policy are absent.

---

## Test 8 — Explicit Deny completely blocks an allowed action

**Policy family:** Identity policy  
**Purpose:** Verify same-document explicit-deny handling.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowTermination",
      "Effect": "Allow",
      "Action": "ec2:TerminateInstances",
      "Resource": "*"
    },
    {
      "Sid": "DenyTermination",
      "Effect": "Deny",
      "Action": "ec2:TerminateInstances",
      "Resource": "*"
    }
  ]
}
```

### Expected result

- Do not emit an actionable EC2 termination capability.
- Show that the allow is blocked by an exact overlapping explicit deny in the supplied document.
- It is acceptable to retain an informational record explaining the suppressed grant.
- Do not count the suppressed permission in risk totals or graph edges.

---

## Test 9 — Partial Deny narrows but does not eliminate destruction

**Policy family:** Identity policy  
**Purpose:** Prevent an over-broad deny from suppressing remaining dangerous scope.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeleteAllObjects",
      "Effect": "Allow",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::*/*"
    },
    {
      "Sid": "ProtectAuditArchive",
      "Effect": "Deny",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::audit-archive/*"
    }
  ]
}
```

### Expected result

- **High:** broad S3 object-deletion capability remains.
- Record that `audit-archive/*` is explicitly excluded by the deny.
- Do not claim that the deny neutralizes deletion across other buckets.
- Graph and finding resources should describe the residual broad scope rather than only `*`.

---

## Test 10 — Negated organization condition expands trust

**Policy family:** Role trust policy  
**Purpose:** Distinguish constraining and expanding condition operators.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TrustOutsideOrganization",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
```

### Expected result

- **Critical:** the trust policy permits principals outside the named organization, subject to other request context.
- Classify `StringNotEquals` as an expansion or exclusion selector, not as a protective organization restriction.
- Do not produce remediation saying that `aws:PrincipalOrgID` is missing; explain that it is present with dangerous polarity.

---

## Test 11 — Case-insensitive action matching and scalar normalization

**Policy family:** Identity policy  
**Purpose:** Verify IAM action casing and JSON shape normalization.

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Sid": "OddCasing",
    "Effect": "Allow",
    "Action": [
      "IAM:passrole",
      "EC2:runinstances"
    ],
    "Resource": "*"
  }
}
```

### Expected result

- Detect the same PassRole-to-EC2 path as canonical action casing.
- Preserve original text for evidence display while using normalized values for matching.
- Treat scalar `Statement` and scalar `Resource` as valid policy shapes.

---

## Test 12 — Wildcard action expansion

**Policy family:** Identity policy  
**Purpose:** Detect dangerous primitives hidden behind action wildcards.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BroadIAMAdministration",
      "Effect": "Allow",
      "Action": "iam:*",
      "Resource": "*"
    }
  ]
}
```

### Expected result

- **Critical:** IAM administrative control or equivalent broad escalation surface.
- Match important covered primitives such as policy attachment, policy-version manipulation, credential creation, role creation, and role-policy modification.
- Avoid flooding the table with dozens of redundant rows. Present one primary finding with structured techniques or subsumed risk factors.
- Do not expand the action against an unversioned handwritten list without exposing the rule-catalog version.

---

## Test 13 — Allow with NotAction

**Policy family:** Identity policy  
**Purpose:** Fail safely when a complement set grants nearly every AWS action.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EverythingExceptIAM",
      "Effect": "Allow",
      "NotAction": "iam:*",
      "Resource": "*"
    }
  ]
}
```

### Expected result

- If complement semantics are supported: **Critical**, near-administrative capability, excluding only the named actions within applicable-resource semantics.
- If unsupported: produce a **blocking coverage warning** and no normal "analysis complete" success state.
- Never interpret `NotAction` as though the listed actions were allowed actions.

---

## Test 14 — Allow with NotResource

**Policy family:** Identity policy  
**Purpose:** Prevent unsafe analysis of complement resource scope.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadEveryBucketExceptAudit",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "NotResource": "arn:aws:s3:::audit-archive/*"
    }
  ]
}
```

### Expected result

- If supported: report broad S3 read capability excluding the named resource.
- If unsupported: emit a blocking coverage warning.
- Never treat the `NotResource` ARN as the resource being granted.

---

## Test 15 — Public role trust

**Policy family:** Role trust policy  
**Purpose:** Detect unrestricted trust independently from identity-policy semantics.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicTrust",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Expected result

- **Critical:** unrestricted role trust.
- Explain that the role's permissions are not provided and must remain unknown.
- Do not evaluate this as an identity policy or create a finding for broad `Resource`; trust policies commonly omit `Resource`.
- Graph origin should represent external principals, not "principal subject of this policy."

---

## Test 16 — Third-party trust protected by ExternalId

**Policy family:** Role trust policy  
**Purpose:** Recognize a relevant confused-deputy constraint.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VendorAccess",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "customer-7f6af74e"
        }
      }
    }
  ]
}
```

### Expected result

- Report cross-account trust as an informational or low/medium capability, depending on the scoring model.
- Recognize `sts:ExternalId` as a constraint.
- Do not report "missing ExternalId."
- Do not describe ExternalId as authentication or secrecy; it mitigates a confused-deputy scenario and should be unique per customer.
- The target role's permissions remain out of scope.

---

## Test 17 — Over-broad GitHub Actions OIDC trust

**Policy family:** Role trust policy  
**Purpose:** Detect federated subject expansion.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GitHubOIDC",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:example-org/*"
        }
      }
    }
  ]
}
```

### Expected result

- **High:** organization-wide repository trust or broad federated subject scope.
- Recognize the audience check as a valid constraint.
- Identify `repo:example-org/*` as broader than a repository plus protected branch or environment binding.
- Recommend constraining `sub` to the intended repository and branch/environment.
- Do not claim that every repository can assume the role unless the matching token and workflow context exist.

---

## Test 18 — Normal AWS service trust

**Policy family:** Role trust policy  
**Purpose:** Establish a negative control.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LambdaServiceTrust",
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Expected result

- No public-trust or external-account finding.
- It is acceptable to show an informational service-trust relationship.
- Do not infer the role's permissions or a privilege-escalation path from the trust policy alone.

---

## Test 19 — SCP deny guardrail

**Policy family:** SCP or RCP  
**Purpose:** Prevent a deny-only control policy from being treated as an identity grant.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeavingOrganization",
      "Effect": "Deny",
      "Action": "organizations:LeaveOrganization",
      "Resource": "*"
    },
    {
      "Sid": "DenyUnapprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*",
        "route53:*",
        "support:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "us-east-1",
            "us-west-2"
          ]
        }
      }
    }
  ]
}
```

### Expected result

- Do not report allowed capabilities from `NotAction`.
- Report guardrails: organization departure denied and regional access constrained, with global-service exceptions.
- State that SCPs set permission ceilings and do not grant permissions.
- If SCP semantics are unsupported, block analysis rather than falling back to identity-policy rules.

---

## Test 20 — Mixed policy family

**Policy family selected:** Identity policy  
**Purpose:** Reject a document containing trust-policy elements under the wrong mode.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IdentityGrant",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example/*"
    },
    {
      "Sid": "TrustElement",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Expected result

- Block normal analysis with a mixed/invalid policy-family warning.
- Identify statement 1 and its `Principal` element as incompatible with identity-policy mode.
- Do not silently discard the trust statement.
- Do not combine the two statements into an attack path.

---

## Test 21 — Policy variables prevent exact resource resolution

**Policy family:** Identity policy  
**Purpose:** Preserve uncertainty when ARNs contain runtime variables.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "UserScopedHomeDirectory",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::company-home/${aws:username}/*"
    }
  ]
}
```

### Expected result

- Report a variable-scoped S3 read capability.
- Do not resolve `${aws:username}` without request or principal context.
- Do not classify the resource as literal, wildcard-global, or definitely single-user.
- Preserve the policy variable exactly in evidence and exports.

---

## Test 22 — Malformed and structurally invalid inputs

**Policy family:** Identity policy  
**Purpose:** Verify parser and schema failure behavior.

### Input A — malformed JSON

```json
{
  "Version": "2012-10-17",
  "Statement": [
}
```

### Expected result A

- Block analysis.
- Report a JSON syntax error with line and column when available.
- Produce no findings, risk score, or graph from partially parsed input.

### Input B — missing Effect and Action

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Incomplete",
      "Resource": "*"
    }
  ]
}
```

### Expected result B

- Block analysis with statement-specific schema errors.
- Do not interpret the statement as Allow.

### Input C — unsupported version

```json
{
  "Version": "2008-10-17",
  "Statement": {
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
  }
}
```

### Expected result C

- Warn or block according to documented version support.
- Never silently rewrite the version to `2012-10-17`.

---

## Test 23 — Duplicate and subsumed findings

**Policy family:** Identity policy  
**Purpose:** Test deduplication without hiding underlying risk factors.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EverythingNeededForLambdaEscalation",
      "Effect": "Allow",
      "Action": [
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction"
      ],
      "Resource": "*"
    }
  ]
}
```

### Expected result

- One primary Lambda PassRole path, not four repetitive top-level rows.
- Wildcard PassRole scope and wildcard Lambda scope should remain visible as risk factors or subsumed findings.
- Risk-summary metrics must distinguish primary findings from underlying broad grants.
- Counts in JSON, Markdown, and the browser UI must agree.

---

## Test 24 — Graph semantic typing

**Policy family:** Identity policy  
**Purpose:** Ensure unlike capabilities are not merged into a generic write edge.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MixedCapabilities",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "kms:Decrypt",
        "iam:PassRole",
        "s3:DeleteObject"
      ],
      "Resource": "*"
    }
  ]
}
```

### Expected result

- `ec2:DescribeInstances`: read or enumerate capability.
- `kms:Decrypt`: cryptographic use or decrypt capability.
- `iam:PassRole`: delegation capability.
- `s3:DeleteObject`: destructive mutation capability.
- Do not aggregate all four under `can-write`.
- Each edge must link back to statement 0 while retaining only the action relevant to that edge.
- `iam:PassRole` alone must not create an execution path without a compatible service execution primitive.

---

## Cross-test invariants

These assertions should hold for every successful analysis:

1. **Policy family is explicit.** No heuristic family detection silently changes semantics.
2. **Evidence is immutable.** Every displayed action, resource, condition, Sid, and statement index maps back to the normalized input.
3. **AND and OR are explicit.** Compound paths cannot use a flat list when multiple alternative techniques exist.
4. **Unknown is visible.** Missing trust policies, target-role permissions, resource policies, boundaries, SCPs, session policies, or workload execution context reduce exploitability confidence.
5. **Denies are not grants.** Deny statements and SCPs must never generate positive capability edges.
6. **Conditions have polarity.** `Equals`, `Like`, `NotEquals`, `NotLike`, `IfExists`, `Null`, set operators, and multivalued keys must not all be labeled generically as restrictions.
7. **No semantic edge reuse.** Reads, writes, deletes, decrypts, credential creation, delegation, assumption, and service execution use distinct graph semantics.
8. **Deduplication is explainable.** Subsumed findings remain accessible and summary labels identify what is being counted.
9. **Exports agree.** Browser, JSON, and Markdown outputs contain the same finding set, severities, confidence, and evidence.
10. **Invalid input fails closed.** Partial results are not presented as complete analysis.
11. **Original input stays local.** Import, analysis, visualization, and export operate without network transmission.
12. **Determinism holds.** Reanalyzing the same policy with the same rule-catalog version produces byte-equivalent semantic JSON after excluding timestamps or presentation-only identifiers.

## Suggested automated-test representation

Each case can be converted into a fixture with explicit semantic assertions:

```json
{
  "id": "passrole-ec2-cross-statement",
  "family": "identity",
  "input": "fixtures/passrole-ec2-cross-statement.json",
  "expect": {
    "blockingWarnings": [],
    "findings": [
      {
        "ruleId": "PASSROLE-EC2",
        "severity": ["critical", "high"],
        "policyEvidence": "high",
        "pathExploitability": "medium",
        "evidence": [
          {
            "statementIndex": 0,
            "sid": "PassWorkloadRoles",
            "actions": ["iam:PassRole"]
          },
          {
            "statementIndex": 1,
            "sid": "LaunchInstances",
            "actions": ["ec2:RunInstances"]
          }
        ]
      }
    ],
    "forbidFindings": ["PASSROLE-LAMBDA"],
    "forbidSyntheticEvidence": true
  }
}
```

Prefer semantic assertions over snapshots of rendered HTML. Use separate UI tests for expansion behavior, keyboard navigation, responsive table layout, graph selection, and download controls.

## Exit criteria

The analyzer is ready for broader public testing when:

- All blocking and negative-control cases pass.
- Compound paths retain exact cross-statement provenance.
- Conditions and explicit denies affect results predictably.
- Unsupported constructs cannot yield an unqualified success state.
- JSON, Markdown, table, summary, and graph remain semantically consistent.
- Every high or critical finding includes a precise limitation statement that prevents effective-permission overclaims.
