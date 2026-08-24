# IAM Blast Radius — Advanced Acceptance Test Suite II

## Purpose

This is a non-duplicative extension to `iam-blast-radius-complex-test-suite.md`. It adds advanced tests for resource-policy authority, permissions boundaries, session policies, service-role execution paths, subtle condition behavior, IAM policy grammar, parser hardening, AWS partitions, and denial-policy semantics.

The expected results describe **potential capability from the selected policy family and supplied context**. They do not authorize claims about complete AWS effective permissions.

## Required result vocabulary

Each test may expect one of four outcomes:

- **Finding:** a supported capability or risk was established from the supplied policy.
- **Constraint:** a supported condition or deny measurably narrows a capability.
- **Coverage warning:** analysis can continue, but an element cannot be interpreted precisely.
- **Blocking warning:** normal findings, summary scores, and graphs must not be presented as complete.

Recommended severities are included where meaningful. Stable rule identifiers shown in examples are suggestions; implementations may use different IDs if mappings remain deterministic and documented.

---

## Test 25 — AWS account principal is account delegation

**Policy family:** Role trust policy  
**Purpose:** Prevent the common mistake of interpreting an account-root ARN as only the root user.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DelegateToPartnerAccount",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Expected result

- **High or medium:** cross-account trust delegated to account `111122223333`.
- Explain that the account ARN delegates authority to the account; it does not restrict assumption to that account's root user.
- State that an administrator in the trusted account must still delegate permission to an identity there.
- Do not label the principal as `root user only`.
- Target-role permissions remain unknown.

---

## Test 26 — Service principal without confused-deputy constraints

**Policy family:** Resource policy  
**Resource context:** SNS topic `arn:aws:sns:us-west-2:123456789012:security-events`  
**Purpose:** Detect service-principal trust without source binding.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEventBridgePublish",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:us-west-2:123456789012:security-events"
    }
  ]
}
```

### Expected result

- **High or medium:** cross-service publish permission lacks source binding.
- Identify missing `aws:SourceArn` and `aws:SourceAccount` as potential confused-deputy exposure, subject to service support.
- Do not describe the topic as publicly writable; the principal is an AWS service, not `*`.
- Graph origin should be the EventBridge service principal.

---

## Test 27 — Properly source-bound service principal

**Policy family:** Resource policy  
**Resource context:** Same SNS topic as Test 26  
**Purpose:** Negative control for confused-deputy detection.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowOneEventRule",
      "Effect": "Allow",
      "Principal": {
        "Service": "events.amazonaws.com"
      },
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:us-west-2:123456789012:security-events",
      "Condition": {
        "ArnEquals": {
          "aws:SourceArn": "arn:aws:events:us-west-2:123456789012:rule/security-alerts"
        },
        "StringEquals": {
          "aws:SourceAccount": "123456789012"
        }
      }
    }
  ]
}
```

### Expected result

- Report a constrained service-publish relationship as informational or low severity.
- Do not report missing source-binding conditions.
- Preserve that the two condition operators are combined with logical AND.
- Do not infer whether the referenced EventBridge rule exists.

---

## Test 28 — TLS-only Deny does not make public S3 access private

**Policy family:** Resource policy  
**Resource context:** S3 bucket policy  
**Purpose:** Ensure a transport constraint is not mistaken for an identity constraint.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::public-downloads/*"
    },
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::public-downloads",
        "arn:aws:s3:::public-downloads/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

### Expected result

- **Critical or high:** public object-read capability remains over secure transport.
- Record the deny as a transport constraint only.
- Do not claim the deny suppresses `PublicRead` entirely.
- If S3 Block Public Access configuration is absent, state that actual exposure depends on that external control.

---

## Test 29 — NotPrincipal Deny and permissions-boundary hazard

**Policy family:** Resource policy  
**Purpose:** Detect a documented semantic trap that cannot be modeled as an ordinary exclusion.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEveryoneExceptBreakGlass",
      "Effect": "Deny",
      "NotPrincipal": {
        "AWS": [
          "arn:aws:iam::123456789012:root",
          "arn:aws:iam::123456789012:role/BreakGlass"
        ]
      },
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::audit-archive",
        "arn:aws:s3:::audit-archive/*"
      ]
    }
  ]
}
```

### Expected result

- Produce a **high-confidence semantic warning** about `Deny` plus `NotPrincipal`.
- Explain that IAM principals with permissions boundaries can be denied regardless of the listed exclusion.
- Recommend `ArnNotEquals` with `aws:PrincipalArn` instead.
- If `NotPrincipal` semantics are not implemented, block analysis rather than showing an ordinary deny graph.

---

## Test 30 — Permissions boundary Allow is a ceiling, not a grant

**Policy family:** Permissions boundary  
**Purpose:** Prevent identity-policy interpretation of boundary allows.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "MaximumApplicationPermissions",
      "Effect": "Allow",
      "Action": [
        "s3:*",
        "dynamodb:*"
      ],
      "Resource": "*"
    }
  ]
}
```

### Expected result

- Report a broad **maximum-permissions envelope** for S3 and DynamoDB.
- Do not create positive capability edges such as `can delete bucket` or `can read table`.
- State that identity policies must independently allow an action and effective permissions are intersected with the boundary.
- Wildcards may be reported as boundary breadth, not as proven access.

---

## Test 31 — Session-policy Allow is a session restriction

**Policy family:** Session policy  
**Purpose:** Keep session policies distinct from ordinary grants.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SessionScope",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::incident-evidence/*"
    }
  ]
}
```

### Expected result

- Report that the session is capped to the listed S3 read scope within this policy.
- Do not assert that the session can read the bucket.
- Explain that the parent identity or role permissions and the session policy are intersected.
- Do not generate a data-exfiltration graph edge without the parent identity policy context.

---

## Test 32 — Same-account direct IAM-user resource grant

**Policy family:** Resource policy  
**Resource context:** S3 bucket policy in account `123456789012`  
**Purpose:** Test a resource-policy grant whose evaluation differs from an identity-policy grant.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DirectUserGrant",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:user/Alice"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::finance-reports/*"
    }
  ]
}
```

### Expected result

- Report a direct same-account user grant.
- Explain that an implicit deny in the user's identity policy or permissions boundary does not necessarily limit this direct resource-policy grant; an applicable explicit deny still does.
- Do not generalize this behavior to role ARNs or cross-account principals.
- If the analyzer lacks account/resource context, lower confidence and state the missing assumption.

---

## Test 33 — Direct role-session ARN grant

**Policy family:** Resource policy  
**Purpose:** Distinguish an IAM role principal from an assumed-role session principal.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DirectSessionGrant",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:sts::123456789012:assumed-role/IncidentResponder/session-2026-08"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::incident-evidence/*"
    }
  ]
}
```

### Expected result

- Identify the principal as one exact assumed-role session, not the underlying role ARN.
- Report direct session access with a caveat that same-account resource-policy grants to session principals have distinct boundary/session-policy behavior.
- Explicit denies remain applicable.
- Do not collapse the ARN to `arn:aws:iam::123456789012:role/IncidentResponder`.

---

## Test 34 — Full IAM role takeover chain

**Policy family:** Identity policy  
**Purpose:** Detect a compound path that changes both role permissions and trust before assuming it.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ModifyTargetRole",
      "Effect": "Allow",
      "Action": [
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy"
      ],
      "Resource": "arn:aws:iam::123456789012:role/automation/DeploymentRole"
    },
    {
      "Sid": "AssumeTargetRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/automation/DeploymentRole"
    }
  ]
}
```

### Expected result

- **Critical:** potential role takeover.
- Path expression: `iam:PutRolePolicy` **AND** `iam:UpdateAssumeRolePolicy` **AND** `sts:AssumeRole` on the same role.
- Explain that the principal can potentially grant permissions to the role, modify its trust, and then assume it.
- Preserve evidence from both statements; do not attribute all three actions to one statement.
- Do not require `iam:PassRole` for this technique.

---

## Test 35 — Attach AdministratorAccess to a named user

**Policy family:** Identity policy  
**Purpose:** Detect policy attachment without assuming that the target is the caller.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AttachPolicyToBuildUser",
      "Effect": "Allow",
      "Action": "iam:AttachUserPolicy",
      "Resource": "arn:aws:iam::123456789012:user/build-automation",
      "Condition": {
        "ArnEquals": {
          "iam:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
      }
    }
  ]
}
```

### Expected result

- **Critical:** ability to attach `AdministratorAccess` to the named user.
- Policy evidence: high; self-escalation confidence: low or medium because the caller's relationship to that user is unknown.
- Do not phrase this as definite self-administration.
- Graph should target `build-automation`, not an anonymous administrator node.

---

## Test 36 — Add a user to a privileged group

**Policy family:** Identity policy  
**Purpose:** Detect indirect privilege assignment.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ManageAdminGroupMembership",
      "Effect": "Allow",
      "Action": "iam:AddUserToGroup",
      "Resource": "arn:aws:iam::123456789012:group/PlatformAdmins"
    }
  ]
}
```

### Expected result

- **High:** ability to add a user to a potentially privileged group.
- Group privilege inferred from `PlatformAdmins`: medium confidence.
- Do not claim the group actually has administrator permissions without group-policy context.
- Explain that the target user is supplied in the API request and is not resource-scoped by this ARN in the same way as the group.

---

## Test 37 — CloudFormation service-role execution

**Policy family:** Identity policy  
**Purpose:** Detect infrastructure execution through a passable CloudFormation role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassCloudFormationAdminRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/cfn/AdminProvisioner",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "cloudformation.amazonaws.com"
        }
      }
    },
    {
      "Sid": "CreateStacks",
      "Effect": "Allow",
      "Action": [
        "cloudformation:CreateStack",
        "cloudformation:DescribeStacks"
      ],
      "Resource": "*"
    }
  ]
}
```

### Expected result

- **Critical:** potential CloudFormation service-role execution path.
- Identify `CreateStack`, not `DescribeStacks`, as the execution primitive.
- Recognize `iam:PassedToService` as a valid CloudFormation selector.
- State that the role's actual permissions and template behavior are unknown.
- Note that subsequent stack operators may be able to use an attached service role, so role attachment has persistence implications.

---

## Test 38 — ECS task-role execution with two passable roles

**Policy family:** Identity policy  
**Purpose:** Model task role and execution role separately.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassEcsRoles",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": [
        "arn:aws:iam::123456789012:role/ecs/AppTaskRole",
        "arn:aws:iam::123456789012:role/ecs/AppExecutionRole"
      ],
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "ecs-tasks.amazonaws.com"
        }
      }
    },
    {
      "Sid": "DefineAndRunTasks",
      "Effect": "Allow",
      "Action": [
        "ecs:RegisterTaskDefinition",
        "ecs:RunTask"
      ],
      "Resource": "*"
    }
  ]
}
```

### Expected result

- **Critical:** potential attacker-controlled ECS task execution.
- Distinguish the application task role from the task execution role; do not merge their privileges.
- The primary credential-exposure path should target the task role.
- The execution role can affect image pulls, logs, secrets retrieval, and startup behavior, but should not automatically be presented as application credentials.
- Preserve `RegisterTaskDefinition` and `RunTask` as jointly relevant actions.

---

## Test 39 — CodeBuild project creation and execution

**Policy family:** Identity policy  
**Purpose:** Detect build-code execution under a service role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassCodeBuildRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/codebuild/ReleaseBuilder",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "codebuild.amazonaws.com"
        }
      }
    },
    {
      "Sid": "CreateAndRunBuild",
      "Effect": "Allow",
      "Action": [
        "codebuild:CreateProject",
        "codebuild:StartBuild"
      ],
      "Resource": "*"
    }
  ]
}
```

### Expected result

- **Critical:** potential CodeBuild execution under the passable service role.
- Path should require project configuration/control plus build execution; do not treat `StartBuild` alone as proof of attacker-controlled code.
- State that source, environment override permissions, network access, and service-role permissions affect exploitability.
- Do not label the path as Lambda or generic compute.

---

## Test 40 — Partial wildcard action matching

**Policy family:** Identity policy  
**Purpose:** Expand supported wildcard patterns without requiring `service:*`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AttachAnyPolicy",
      "Effect": "Allow",
      "Action": "iam:Attach*Policy",
      "Resource": "*"
    }
  ]
}
```

### Expected result

- **Critical or high:** broad managed-policy attachment capability.
- Match covered actions such as `AttachUserPolicy`, `AttachRolePolicy`, and `AttachGroupPolicy` using the versioned rule catalog.
- Do not invent nonexistent actions or claim that all IAM APIs are allowed.
- Export both the original wildcard and any matched concrete primitives.

---

## Test 41 — ForAllValues without a Null presence check

**Policy family:** Identity policy  
**Purpose:** Detect vacuous truth when a multivalued request key is absent.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowTaggingApprovedKeys",
      "Effect": "Allow",
      "Action": "ec2:CreateTags",
      "Resource": "*",
      "Condition": {
        "ForAllValues:StringEquals": {
          "aws:TagKeys": [
            "environment",
            "cost-center"
          ]
        }
      }
    }
  ]
}
```

### Expected result

- Report that the set condition constrains present tag keys.
- Warn that `ForAllValues` may evaluate true when the context key is absent or empty.
- Recommend adding `"Null": {"aws:TagKeys": "false"}` when key presence is required.
- Do not classify every `ForAllValues` condition as strictly narrowing.

---

## Test 42 — IfExists on Allow broadens applicability

**Policy family:** Identity policy  
**Purpose:** Verify missing-key behavior for an Allow statement.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EC2WithOptionalInstanceType",
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
        "StringEqualsIfExists": {
          "ec2:InstanceType": "t3.micro"
        }
      }
    }
  ]
}
```

### Expected result

- **Critical or high:** broad EC2 action wildcard remains.
- Explain that the instance-type value is checked only when that context key is present; actions without the key can still match.
- Classify `IfExists` as conditional applicability, not a universal resource constraint.
- Do not summarize this policy as `EC2 access limited to t3.micro`.

---

## Test 43 — Negated IfExists in a Deny matches missing keys

**Policy family:** SCP or RCP  
**Purpose:** Verify the particularly strict behavior of negated `IfExists` under Deny.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
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

- Report a potentially over-broad regional deny.
- Explain that a negated `IfExists` condition in a Deny can still deny requests when the key is absent, affecting global services unless exceptions exist.
- Do not interpret this as a grant outside or inside the regions.
- Recommend explicit global-service exceptions or a documented regional-control pattern.

---

## Test 44 — Duplicate JSON keys

**Policy family:** Identity policy  
**Purpose:** Prevent last-key-wins parser behavior from hiding permissions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DuplicateAction",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Action": "iam:*",
      "Resource": "*"
    }
  ]
}
```

### Expected result

- Block analysis with a duplicate-key error that identifies `Action` and the statement location.
- Do not silently keep either the first or last value.
- Produce no normal findings, score, or graph.
- Preserve the original text so the duplicate can be highlighted in the editor.

---

## Test 45 — Unicode-confusable action name

**Policy family:** Identity policy  
**Purpose:** Prevent Unicode normalization from converting lookalike text into a real IAM action.

The first character in the action below is Cyrillic small letter `і` (`U+0456`), not ASCII `i`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ConfusableAction",
      "Effect": "Allow",
      "Action": "іam:PassRole",
      "Resource": "*"
    }
  ]
}
```

### Expected result

- Do not match `iam:PassRole`.
- Emit an invalid or unknown service/action warning with the non-ASCII code point identified.
- Do not normalize homoglyphs into valid AWS identifiers.
- A blocking warning is preferred because the policy is not safely analyzable as written.

---

## Test 46 — Prototype-pollution property names

**Policy family:** Identity policy  
**Purpose:** Verify safe object handling in a browser-only implementation.

```json
{
  "Version": "2012-10-17",
  "__proto__": {
    "polluted": true
  },
  "constructor": {
    "prototype": {
      "polluted": true
    }
  },
  "Statement": [
    {
      "Sid": "SafeRead",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::example/*"
    }
  ]
}
```

### Expected result

- Reject or ignore unknown top-level elements according to strict schema policy, with a visible warning.
- No global, rule-catalog, finding, graph, or export object may acquire a `polluted` property.
- Parsing must use data-safe structures rather than recursively merging untrusted keys into application objects.
- Reanalysis of a clean policy after this test must be unaffected.

---

## Test 47 — GovCloud partition support

**Policy family:** Identity policy  
**Purpose:** Ensure ARN parsing is not hard-coded to the commercial `aws` partition.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassGovCloudRole",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws-us-gov:iam::123456789012:role/workloads/AppRole"
    },
    {
      "Sid": "RunGovCloudInstance",
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": "*"
    }
  ]
}
```

### Expected result

- Detect the PassRole-to-EC2 pattern.
- Preserve `aws-us-gov` throughout findings, evidence, graph nodes, and exports.
- Do not rewrite the ARN to the commercial partition.
- Flag partition mismatches only when compared resources actually use conflicting partitions.

---

## Test 48 — Wildcard inside a Principal ARN

**Policy family:** Role trust policy  
**Purpose:** Reject an invalid principal pattern rather than expanding it.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InvalidRolePattern",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::123456789012:role/application/*"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Expected result

- Block or clearly mark the statement invalid; IAM principal ARNs cannot generally use a partial wildcard to represent multiple role principals.
- Do not expand this into trust for every role in the path.
- Suggest using `Principal: "*"` plus an appropriate `aws:PrincipalArn` condition only when that pattern is valid for the intended policy and threat model.

---

## Test 49 — Multiple condition operators: AND across keys, OR within values

**Policy family:** Resource policy  
**Purpose:** Verify boolean composition.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RestrictedArtifactRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::release-artifacts/*",
      "Condition": {
        "StringEquals": {
          "aws:SourceVpce": [
            "vpce-0123456789abcdef0",
            "vpce-0fedcba9876543210"
          ],
          "aws:PrincipalTag/environment": "production"
        }
      }
    }
  ]
}
```

### Expected result

- Explain that either listed VPC endpoint may match, while the production principal tag must also match.
- Model OR across the two values for the same key and AND across distinct condition keys.
- Report broad principal syntax constrained by network and principal-tag selectors.
- Do not simplify the condition to `VPC endpoint OR production tag`.

---

## Test 50 — Action/resource type mismatch

**Policy family:** Identity policy  
**Purpose:** Avoid claiming access from a resource ARN that cannot authorize the requested resource type.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IncorrectObjectReadScope",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::documents"
    }
  ]
}
```

### Expected result

- Warn that `s3:GetObject` requires object-resource scope such as `arn:aws:s3:::documents/*`; the bucket ARN alone does not identify objects.
- Do not report confirmed object-read capability.
- If the analyzer lacks action-to-resource-type metadata, issue a coverage warning and lower policy-evidence confidence.
- Remediation must distinguish bucket actions from object actions.

---

## Test 51 — KMS account-principal delegation statement

**Policy family:** Resource policy  
**Resource context:** KMS key policy in account `111122223333`  
**Purpose:** Avoid classifying the standard account-delegation statement as public access or root-user-only access.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableIAMUserPermissions",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111122223333:root"
      },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
```

### Expected result

- Identify broad KMS authority delegated to the owning account.
- Do not call the key public.
- Do not say that only the root user can administer the key.
- Explain that KMS key-policy and IAM-policy interaction requires service-specific semantics; absent identity policies, individual reachable principals are unknown.
- `Resource: "*"` in a key policy refers to the key to which the policy is attached; it must not create a graph node for every KMS key in the account.

---

## Test 52 — RCP confused-deputy guardrail

**Policy family:** RCP  
**Purpose:** Interpret a deny-only organization control without manufacturing grants.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceServiceSourceOrganization",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:SourceOrgID": "o-exampleorgid"
        },
        "Null": {
          "aws:SourceAccount": "false"
        },
        "Bool": {
          "aws:PrincipalIsAWSService": "true"
        }
      }
    }
  ]
}
```

### Expected result

- Report a resource-control guardrail targeting requests made by AWS service principals with source-account context.
- Do not report S3 permissions or public access.
- Explain that a corresponding Allow must exist elsewhere.
- Preserve the interaction of `StringNotEqualsIfExists`, `Null`, and `Bool`; do not evaluate each as an independent deny.
- If RCP semantics are unsupported, block analysis.

---

## Test 53 — Mismatched SourceArn and SourceAccount

**Policy family:** Resource policy  
**Purpose:** Detect an internally inconsistent confused-deputy constraint.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudTrailWriteWithMismatchedAccounts",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::central-cloudtrail/AWSLogs/111122223333/*",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "111122223333"
        },
        "ArnLike": {
          "aws:SourceArn": "arn:aws:cloudtrail:*:444455556666:trail/*"
        }
      }
    }
  ]
}
```

### Expected result

- Warn that the source-account condition and account component of `aws:SourceArn` disagree.
- Do not praise the policy as correctly source-bound.
- Classify the statement as likely ineffective or misconfigured, subject to service request-context behavior.
- Do not turn the mismatch into a public-write finding.

---

## Test 54 — Client-side resource exhaustion limits

**Policy family:** Identity policy  
**Purpose:** Ensure untrusted policy input cannot freeze the browser or create unbounded output.

### Generated input

Generate a valid policy containing:

- 10,000 statements.
- Each statement has 100 action strings and 100 resource strings.
- Conditions are nested to the maximum JSON depth accepted by the parser.
- Sids and ARN strings are near the configured per-field length limit.
- Many statements are semantic duplicates designed to maximize graph-edge and finding generation.

### Expected result

- Enforce documented input-byte, statement-count, collection-size, nesting-depth, graph-node, graph-edge, and finding-count limits.
- Abort safely with a blocking size/complexity warning before expensive graph layout.
- Keep the UI responsive and allow the user to clear the input.
- Do not truncate and then label the partial result `analysis complete`.
- Do not transmit the input or fall back to server-side processing.
- A smaller policy just below each limit must analyze successfully, establishing boundary behavior.

---

## Advanced cross-test invariants

1. **Resource-policy context is explicit.** The analyzer must know the attached resource type and ARN when service semantics depend on them.
2. **Account principals are not root-user principals.** Account ARN and account ID forms delegate authority to the account.
3. **Policy family changes edge meaning.** Boundary, session, SCP, and RCP Allows do not become ordinary capability grants.
4. **Service principals are not public principals.** Missing confused-deputy protection is distinct from `Principal: "*"`.
5. **Direct principal types remain distinct.** IAM user, IAM role, assumed-role session, federated session, account, and service principals must not collapse into one generic node.
6. **Service execution techniques are typed.** CloudFormation, ECS, and CodeBuild paths retain their distinct prerequisites and uncertainty.
7. **Conditions are evaluated as expressions.** AND/OR composition, negation, set operators, `IfExists`, and missing-key behavior must survive normalization and export.
8. **Resource types are action-aware.** A syntactically valid ARN does not prove that it can authorize the action.
9. **Attached-resource wildcards are contextual.** `Resource: "*"` in a KMS key policy is not equivalent to wildcard scope in an identity policy.
10. **Parser behavior is security behavior.** Duplicate keys, Unicode confusables, hostile property names, excessive depth, and excessive cardinality fail safely.
11. **Partitions are data.** Commercial, GovCloud, and China ARNs must be preserved and compared without hard-coded `arn:aws:` assumptions.
12. **No partial-success ambiguity.** Any cap, unsupported semantic element, or invalid structure that can change high-risk conclusions prevents a normal success state.

## Suggested fixture schema additions

The first suite proposed semantic fixtures. These advanced cases benefit from additional fields:

```json
{
  "id": "cloudformation-passrole-service-execution",
  "family": "identity",
  "resourceContext": null,
  "expect": {
    "status": "complete",
    "findings": [
      {
        "ruleId": "PASSROLE-CLOUDFORMATION",
        "severity": ["critical", "high"],
        "policyEvidence": "high",
        "pathExploitability": "medium",
        "expression": {
          "allOf": [
            "iam:PassRole",
            "cloudformation:CreateStack"
          ]
        },
        "selectors": {
          "iam:PassedToService": [
            "cloudformation.amazonaws.com"
          ]
        }
      }
    ],
    "forbidClaims": [
      "target role permissions known",
      "effective permissions proven"
    ]
  }
}
```

For parser tests, use:

```json
{
  "id": "duplicate-json-action-key",
  "family": "identity",
  "expect": {
    "status": "blocked",
    "errorCode": "DUPLICATE_JSON_KEY",
    "findings": [],
    "graph": null,
    "riskSummary": null
  }
}
```

## Acceptance threshold

This extension passes when:

- Tests 25–54 produce the expected complete, warning, or blocked state.
- No resource-policy test is silently analyzed as an identity policy.
- Service-role findings use exact prerequisites and preserve cross-statement evidence.
- Boundaries, session policies, SCPs, and RCPs never manufacture granted capabilities.
- Parser-security cases leave subsequent analyses unaffected.
- Browser, Markdown, and JSON exports agree on status, evidence, conditions, and uncertainty.

## AWS reference basis

The expected semantics are grounded in current AWS documentation:

- [IAM Principal element and AWS account principals](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)
- [IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html)
- [Permissions boundaries and session-policy intersections](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [IAM condition operators, set operators, and IfExists](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)
- [Single-valued and multivalued context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html)
- [NotPrincipal semantics and limitations](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notprincipal.html)
- [Cross-service confused-deputy prevention](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
- [Passing roles to AWS services](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)
- [CloudFormation service roles](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html)
- [CodeBuild service-role security](https://docs.aws.amazon.com/codebuild/latest/userguide/setting-up-service-role.html)
