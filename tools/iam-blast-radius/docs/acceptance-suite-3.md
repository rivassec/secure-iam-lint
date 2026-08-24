# IAM Blast Radius — Regression and Gap-Hunting Suite III

## Mission

This suite retests the fixes and design claims exposed by Suites I and II, then attacks the adjacent assumptions most likely to hide regressions or false confidence.

It contains **46 tests, numbered 55–100**, organized into six campaigns:

1. Strict parser and import equivalence
2. Required policy-family selection
3. IAM role-takeover correlation
4. Principal validation
5. IAM and ECS semantic precision
6. False-positive control, state isolation, rendering safety, and boundary performance

## Result states

- `COMPLETE`: supported semantics were fully evaluated.
- `COMPLETE_WITH_WARNINGS`: findings are usable, with bounded non-blocking limitations.
- `BLOCKED`: input, family, or unsupported semantics can materially change the conclusion; no normal risk score or graph is allowed.
- `TOO_LARGE`: size or complexity cap fired before expensive analysis.

Any blocked result must export its status and warnings. It must not say `analysis complete`.

---

# Campaign A — Strict parser and import equivalence

## Test 55 — Duplicate Action hides dangerous permission when dangerous value comes first

**Family:** Identity  
**Targets:** Duplicate-key fix; analyzer-evasion resistance

```text
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DangerousFirst",
    "Effect": "Allow",
    "Action": "iam:*",
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}
```

### Expected

- `BLOCKED` with `DUPLICATE_JSON_KEY`.
- Error identifies statement 0 and both `Action` occurrences.
- No IAM or S3 finding, score, summary, or graph is produced.
- This must not become a benign S3 result through last-key-wins parsing.

---

## Test 56 — Duplicate Action with dangerous value last

**Family:** Identity  
**Targets:** Ensure duplicate handling is independent of value order

```text
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DangerousLast",
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Action": "iam:*",
    "Resource": "*"
  }]
}
```

### Expected

- Same blocked result as Test 55.
- The engine must not continue merely because the retained value would generate a high-risk finding.
- Duplicate rejection is a syntax invariant, not a risk-dependent heuristic.

---

## Test 57 — Escaped and literal keys decode to the same member name

**Family:** Identity  
**Targets:** Pre-parser canonicalization differential

```text
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "\u0041ction": "iam:*",
    "Resource": "*"
  }]
}
```

### Expected

- `BLOCKED` with `DUPLICATE_JSON_KEY` after JSON string escape decoding.
- `Action` and `\u0041ction` must be treated as the same key.
- Do not detect duplicates with a regex that only compares raw source spelling.

---

## Test 58 — Duplicate nested condition key

**Family:** Identity  
**Targets:** Recursive duplicate detection

```text
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::reports/*",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalOrgID": "o-approved",
        "aws:PrincipalOrgID": "o-attacker"
      }
    }
  }]
}
```

### Expected

- `BLOCKED`; duplicate detection must cover every object depth.
- Error path identifies `Statement[0].Condition.StringEquals.aws:PrincipalOrgID`.
- No organization-constrained finding is emitted.

---

## Test 59 — Condition keys duplicated with different capitalization

**Family:** Identity  
**Targets:** IAM condition-key case-insensitivity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::reports/*",
    "Condition": {
      "StringEquals": {
        "aws:PrincipalOrgID": "o-one",
        "AWS:PrincipalOrgId": "o-two"
      }
    }
  }]
}
```

### Expected

- `BLOCKED` or a high-confidence validation error for duplicate condition keys with different case.
- Do not evaluate the two entries as independent AND conditions.
- Preserve original spellings in the error.

---

## Test 60 — Duplicate Sids

**Family:** Identity  
**Targets:** Evidence identity and export stability

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RepeatedSid",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::one/*"
    },
    {
      "Sid": "RepeatedSid",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "*"
    }
  ]
}
```

### Expected

- Validation error or blocking warning for non-unique Sids, according to the selected family.
- Statement indexes remain distinct even when Sids collide.
- Graph IDs, finding IDs, DOM IDs, and export records must not overwrite one another.

---

## Test 61 — Comments and trailing commas remain invalid JSON

**Family:** Identity  
**Targets:** Parser consistency

```text
{
  // This is JSONC, not JSON.
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*",
  }]
}
```

### Expected

- `BLOCKED` with a location-aware syntax error.
- Do not remove comments or trailing commas unless the UI explicitly advertises JSONC support.
- File import and pasted input behave identically.

---

## Test 62 — UTF-8 byte-order mark

**Family:** Identity  
**Targets:** Documented preprocessing

### Input

A valid UTF-8 policy prefixed with bytes `EF BB BF`.

### Expected

- Either accept by stripping exactly one leading UTF-8 BOM or reject with a clear syntax error.
- Paste and file import must use the same rule.
- Do not strip embedded `U+FEFF` characters elsewhere in strings.
- Document the selected behavior and regression-test it.

---

## Test 63 — Paste/import/parser parity

**Family:** Identity  
**Targets:** Alternate ingestion paths

### Procedure

Run Tests 55–62 through:

1. Textarea paste
2. `.json` file import
3. Programmatic test harness entrypoint

### Expected

- Identical status, error code, location, and absence/presence of findings.
- No ingestion path may bypass duplicate detection, size checks, family selection, or normalization.
- The imported filename must not influence policy-family selection.

---

# Campaign B — Required policy-family selection

## Test 64 — No family selected

**Selected family:** None

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "*"
  }]
}
```

### Expected

- Analyze control is disabled or analysis returns `BLOCKED: POLICY_FAMILY_REQUIRED`.
- Do not default to identity based on shape.
- No risk result appears until the user makes an explicit selection.

---

## Test 65 — Boundary selected for an Allow-heavy policy

**Selected family:** Permissions boundary

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "MaximumPermissions",
    "Effect": "Allow",
    "Action": ["s3:*", "dynamodb:*"],
    "Resource": "*"
  }]
}
```

### Expected

- No `can-read`, `can-write`, `can-delete`, or data-exfiltration graph edge.
- Report a broad maximum-permissions envelope or block if boundary semantics remain unsupported.
- Exported family is `permissions-boundary`.
- Switching the same bytes to Identity must produce a materially different result.

---

## Test 66 — Session policy selected

**Selected family:** Session

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::incident-evidence/*"
  }]
}
```

### Expected

- No positive capability edge unless parent role/identity context is also supplied and modeled.
- Report a session ceiling or block as unsupported.
- Do not silently relabel the family as Identity because the document is byte-compatible.

---

## Test 67 — Identity mode rejects Principal

**Selected family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::public/*"
  }]
}
```

### Expected

- `BLOCKED: UNSUPPORTED_PRINCIPAL` or equivalent family-shape error.
- Do not discard `Principal` and analyze the remainder as an identity grant.

---

## Test 68 — Trust mode rejects Resource

**Selected family:** Role trust

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "111122223333"},
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::123456789012:role/Target"
  }]
}
```

### Expected

- Block with a trust-policy syntax error for `Resource`.
- Trust policies apply to their attached role; the supplied Resource must not become a second role target.

---

## Test 69 — Unsupported resource policy selected

**Selected family:** Resource

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::public/*"
  }]
}
```

### Expected

- If resource policies remain deferred: `BLOCKED: UNSUPPORTED_POLICY_FAMILY`.
- No public-access finding may be presented as a supported result.
- The warning names the selected family and preserves input for later correction.

---

## Test 70 — Family switching clears prior analysis

### Procedure

1. Analyze Test 65 as Identity and confirm broad capability findings.
2. Change only the selector to Permissions boundary.
3. Do not edit the policy text.

### Expected

- Previous findings, summary counts, selected graph edge, evidence drawer, and export payload are invalidated immediately.
- The user must reanalyze, or the tool automatically reanalyzes under the new family.
- No Identity result remains visible beneath a Boundary label.

---

## Test 71 — Family and status survive every export

### Procedure

Export successful, warned, blocked, and too-large cases as JSON and Markdown.

### Expected

- Every export includes selected family, analysis status, rule-catalog version, and blocking/non-blocking warnings.
- A blocked export cannot contain a graph described as authoritative.
- Browser, JSON, and Markdown status values agree.

---

# Campaign C — IAM role-takeover correlation

## Test 72 — Exact same-role takeover

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ModifyRole",
      "Effect": "Allow",
      "Action": ["iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole"
    },
    {
      "Sid": "AssumeRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole"
    }
  ]
}
```

### Expected

- One primary **critical** role-takeover path.
- Required expression uses all three primitives on the same role.
- The two generic high findings may be subsumed, but their evidence remains accessible.

---

## Test 73 — Different target roles must not correlate

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
      "Resource": "arn:aws:iam::123456789012:role/RoleA"
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/RoleB"
    }
  ]
}
```

### Expected

- No compound takeover path.
- Separate modification and assumption capabilities may remain.
- Do not correlate solely because both resources are IAM roles in the same account.

---

## Test 74 — Wildcard modifier overlaps exact assumable role

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
      "Resource": "arn:aws:iam::123456789012:role/deployment/*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/deployment/Prod"
    }
  ]
}
```

### Expected

- Detect the overlap and emit a critical or high takeover path.
- Evidence identifies the concrete intersecting role `deployment/Prod`.
- Do not generalize the path to roles outside `deployment/*`.

---

## Test 75 — Mutually exclusive conditions prevent correlation

**Family:** Identity  
**Supplied subject context:** principal account `123456789012`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole",
      "Condition": {"StringEquals": {"aws:PrincipalAccount": "123456789012"}}
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole",
      "Condition": {"StringEquals": {"aws:PrincipalAccount": "999900001111"}}
    }
  ]
}
```

### Expected

- Do not emit a compound path because the supplied subject context cannot satisfy the assumption statement.
- Report the modification capability and mark the assumption grant nonmatching for the supplied context.
- Preserve both condition expressions.

---

## Test 76 — Exact Deny removes one prerequisite

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole"
    },
    {
      "Effect": "Deny",
      "Action": "iam:UpdateAssumeRolePolicy",
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole"
    }
  ]
}
```

### Expected

- No full takeover path.
- Do not hide remaining `PutRolePolicy` and `AssumeRole` capabilities.
- Risk summary must not count the suppressed critical path.

---

## Test 77 — AttachRolePolicy alternative to PutRolePolicy

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AttachAdministratorPolicy",
      "Effect": "Allow",
      "Action": "iam:AttachRolePolicy",
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole",
      "Condition": {
        "ArnEquals": {
          "iam:PolicyARN": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
      }
    },
    {
      "Sid": "ControlAndAssumeRole",
      "Effect": "Allow",
      "Action": ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole"
    }
  ]
}
```

### Expected

- Critical takeover path using policy attachment as the permission-modification primitive.
- Do not require `PutRolePolicy` when `AttachRolePolicy` plus an administrator policy is available.
- Preserve the `iam:PolicyARN` evidence.

---

## Test 78 — Role modification without AssumeRole

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
    "Resource": "arn:aws:iam::123456789012:role/DeploymentRole"
  }]
}
```

### Expected

- High role-control/persistence finding.
- No complete self-assumption path.
- Explain that another principal or service might later use the modified role, but that reachability is not supplied.

---

## Test 79 — Cross-statement evidence integrity

### Procedure

Run Test 72 and inspect the finding, graph edges, expanded evidence, JSON, and Markdown.

### Expected

- `PutRolePolicy` and `UpdateAssumeRolePolicy` map only to statement 0.
- `sts:AssumeRole` maps only to statement 1.
- No synthetic statement claims all actions appeared together.
- Statement indexes, Sids, actions, resources, and conditions agree across every representation.

---

## Test 80 — Duplicate permission statements do not duplicate paths

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ModifyOne",
      "Effect": "Allow",
      "Action": ["iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole"
    },
    {
      "Sid": "ModifyTwo",
      "Effect": "Allow",
      "Action": ["iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole"
    },
    {
      "Sid": "Assume",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::123456789012:role/DeploymentRole"
    }
  ]
}
```

### Expected

- One primary takeover path, with both equivalent modification statements available as evidence alternatives.
- Do not emit two identical critical rows or duplicate graph edges.
- Deduplication must not discard statement-level evidence.

---

# Campaign D — Principal validation

## Test 81 — Asterisk inside role Principal ARN

**Family:** Role trust

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:role/application/*"},
    "Action": "sts:AssumeRole"
  }]
}
```

### Expected

- `BLOCKED: UNSUPPORTED_WILDCARD_IN_PRINCIPAL`.
- Do not turn the partial wildcard into a valid trust edge.

---

## Test 82 — Question-mark wildcard inside user Principal ARN

**Family:** Role trust

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:user/deployer?"},
    "Action": "sts:AssumeRole"
  }]
}
```

### Expected

- Same blocked validation outcome as Test 81.
- Validation must cover both `*` and `?`.

---

## Test 83 — One invalid member poisons a Principal array

**Family:** Role trust

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": [
        "arn:aws:iam::123456789012:role/ValidRole",
        "arn:aws:iam::123456789012:role/invalid-*"
      ]
    },
    "Action": "sts:AssumeRole"
  }]
}
```

### Expected

- Block the statement or entire analysis according to validation policy.
- Do not silently drop the invalid principal and report a complete result for only `ValidRole`.
- Error path identifies array index 1.

---

## Test 84 — Short-form account principal remains valid

**Family:** Role trust

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "111122223333"},
    "Action": "sts:AssumeRole"
  }]
}
```

### Expected

- Valid cross-account delegation finding.
- Normalize for comparison if desired, but preserve original short form in evidence.
- Do not misclassify a 12-digit account ID as an invalid ARN.

---

## Test 85 — Principal star narrowed by PrincipalArn condition

**Family:** Resource policy, or `BLOCKED` if still unsupported

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::deployments/*",
    "Condition": {
      "ArnLike": {
        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/deployment/*"
      }
    }
  }]
}
```

### Expected

- If resource-policy semantics are supported, represent broad principal syntax narrowed by an ARN condition.
- Do not reject the wildcard in the **condition value** as a partial Principal ARN wildcard.
- Do not call the bucket anonymous/public without accounting for the condition.
- If the family remains deferred, fail closed.

---

# Campaign E — IAM and ECS semantic precision

## Test 86 — AddUserToGroup targets group membership, not direct policy administration

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AddMembers",
    "Effect": "Allow",
    "Action": "iam:AddUserToGroup",
    "Resource": "arn:aws:iam::123456789012:group/PlatformAdmins"
  }]
}
```

### Expected

- Dedicated group-membership privilege-assignment finding.
- Group privilege inferred from name: medium confidence.
- Explain that the API request selects the user and the policy Resource scopes the group.
- Do not label this `AttachUserPolicy`, `PutUserPolicy`, or direct policy administration.

---

## Test 87 — ECS task role and execution role are separate nodes

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": [
        "arn:aws:iam::123456789012:role/ecs/AppTaskRole",
        "arn:aws:iam::123456789012:role/ecs/AppExecutionRole"
      ],
      "Condition": {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}}
    },
    {
      "Effect": "Allow",
      "Action": ["ecs:RegisterTaskDefinition", "ecs:RunTask"],
      "Resource": "*"
    }
  ]
}
```

### Expected

- Critical ECS execution path.
- Separate graph nodes and evidence for task role and execution role.
- Application credential path targets `AppTaskRole`.
- Execution-role discussion is limited to ECS startup/service operations and does not claim application credential exposure.

---

## Test 88 — Only execution role is passable

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/ecs/AppExecutionRole"
    },
    {
      "Effect": "Allow",
      "Action": ["ecs:RegisterTaskDefinition", "ecs:RunTask"],
      "Resource": "*"
    }
  ]
}
```

### Expected

- Report potential ECS task execution and execution-role influence.
- Do not claim application code receives execution-role credentials.
- Do not invent an unknown task-role edge unless explicitly labeled as absent context rather than passable.

---

## Test 89 — Only task role is passable

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::123456789012:role/ecs/AppTaskRole"
    },
    {
      "Effect": "Allow",
      "Action": ["ecs:RegisterTaskDefinition", "ecs:RunTask"],
      "Resource": "*"
    }
  ]
}
```

### Expected

- Critical or high application task-role execution path.
- Target permissions remain unknown.
- Do not require an execution role when the task definition/workload may not need one; represent that missing operational context explicitly.

---

## Test 90 — RegisterTaskDefinition without RunTask

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:PassRole", "ecs:RegisterTaskDefinition"],
    "Resource": "*"
  }]
}
```

### Expected

- High task-definition staging or configuration capability.
- No confirmed code-execution path because task launch is absent.
- Explain that another actor or scheduler could later run the definition, without claiming that it will happen.

---

## Test 91 — Cross-account PassRole target

**Family:** Identity  
**Subject account context:** `123456789012`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::999900001111:role/ForeignRole"
    },
    {
      "Effect": "Allow",
      "Action": "ec2:RunInstances",
      "Resource": "*"
    }
  ]
}
```

### Expected

- Do not report a viable direct PassRole-to-EC2 path using the foreign-account role.
- Warn that `iam:PassRole` can directly pass roles only to services in the same account as the role.
- If subject-account context is unavailable, lower confidence and request/contextualize the missing account rather than asserting viability.

---

# Campaign F — False-positive control and application safety

## Test 92 — IAM ListRoles legitimately requires Resource star

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "iam:ListRoles",
    "Resource": "*"
  }]
}
```

### Expected

- Informational IAM enumeration capability.
- Do not emit a remediable wildcard-resource finding; `ListRoles` does not support resource-level permissions.
- Do not recommend replacing `*` with a role ARN.

---

## Test 93 — EC2 DescribeInstances legitimately uses Resource star

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "ec2:DescribeInstances",
    "Resource": "*"
  }]
}
```

### Expected

- Informational enumeration/read capability.
- No generic broad-write edge.
- No wildcard-resource remediation that AWS cannot implement for this action.

---

## Test 94 — S3 ListAllMyBuckets legitimately uses Resource star

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "s3:ListAllMyBuckets",
    "Resource": "*"
  }]
}
```

### Expected

- Informational account-level S3 enumeration.
- Do not call this object-read, data exfiltration, or destructive access.
- Do not suggest an S3 bucket ARN as remediation.

---

## Test 95 — Mixed actions require per-action resource evaluation

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:ListRoles", "iam:PassRole"],
    "Resource": "*"
  }]
}
```

### Expected

- Treat `Resource: "*"` as required/normal for `ListRoles`.
- Treat wildcard scope as dangerous and remediable for `iam:PassRole`.
- Do not assign one resource-scope conclusion to the whole statement.
- Only `iam:PassRole` contributes to delegation/escalation findings.

---

## Test 96 — ForAllValues with explicit Null protection

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "ec2:CreateTags",
    "Resource": "*",
    "Condition": {
      "ForAllValues:StringEquals": {
        "aws:TagKeys": ["environment", "cost-center"]
      },
      "Null": {
        "aws:TagKeys": "false"
      }
    }
  }]
}
```

### Expected

- Recognize the presence check and suppress the missing/empty-key warning from Test 41.
- Preserve both conditions as jointly required.
- Do not claim the policy controls tag values; it controls tag keys.

---

## Test 97 — Empty ForAnyValue condition never matches

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "ec2:CreateTags",
    "Resource": "*",
    "Condition": {
      "ForAnyValue:StringEquals": {
        "aws:TagKeys": []
      }
    }
  }]
}
```

### Expected

- Report the statement as ineffective/no-match or issue a validation warning.
- Do not create an EC2 tagging capability or wildcard-resource finding.
- Empty-array handling must occur before graph generation.

---

## Test 98 — Dangerous-to-safe state isolation

### Procedure

1. Analyze `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}` as Identity.
2. Replace it with `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*"}]}`.
3. Analyze again.

### Expected

- All critical findings, graph nodes, edge selection, evidence panels, summary counts, and exports from the first run disappear.
- Second result contains only the current informational enumeration capability.
- Browser back/forward, clear analysis, and repeated execution do not resurrect stale state.

---

## Test 99 — Rendering and export injection

**Family:** Identity

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "SafeDisplay123",
    "Effect": "Allow",
    "Action": "s3:GetObject",
    "Resource": [
      "arn:aws:s3:::example/<img src=x onerror=alert(1)>",
      "arn:aws:s3:::example/[click](javascript:alert(1))",
      "arn:aws:s3:::example/```html<script>alert(1)</script>```"
    ]
  }]
}
```

### Expected

- No JavaScript execution, DOM insertion, external request, broken table, or malformed graph.
- UI renders policy-controlled strings as text.
- Markdown export escapes or safely fences untrusted values so they cannot create active links or executable HTML in common renderers.
- JSON export preserves exact strings.
- If ARN validation blocks first, the validation error rendering must still be injection-safe.

---

## Test 100 — Exact limits, determinism, and early-abort ordering

### Generated fixtures

For every configured limit—input bytes, statement count, actions per statement, resources per statement, nesting depth, findings, graph nodes, and graph edges—generate:

- `limit - 1`
- `limit`
- `limit + 1`
- A tiny input with extreme semantic fan-out
- A large input with no findings
- The same oversized input previously used for Test 54

### Expected

- Boundary behavior is documented and consistent: define whether exactly-at-limit is accepted.
- Over-limit input returns `TOO_LARGE` or a specific complexity code before rule matching and graph layout.
- Under-limit cases remain responsive and deterministic.
- Repeating the same input and family yields semantically identical JSON after excluding explicitly documented volatile fields.
- An early parser error takes precedence over semantic findings.
- An input-size rejection takes precedence over JSON parsing if the byte cap is designed as the first gate.
- No network request, server fallback, partial graph, or `analysis complete` message occurs.

---

# Test execution matrix

Run every applicable case across these surfaces:

| Surface | Required assertions |
| --- | --- |
| Textarea paste | Status, warnings, findings, state clearing |
| JSON file import | Same semantics as paste; filename has no semantic effect |
| Browser UI | Escaped rendering, keyboard access, responsive table, no stale state |
| JSON export | Family, status, catalog version, exact evidence, deterministic structure |
| Markdown export | Same findings and warnings; safe rendering of untrusted strings |
| Graph | Typed edges, no stale nodes, no synthetic evidence, bounded layout |
| Offline/network monitor | Zero policy-content transmission and zero fallback requests |

# Failure classification

Classify failures by consequence:

- **P0 — Trust-breaking:** silent parser ambiguity, wrong family semantics, stale results under a new family, XSS, or presenting partial analysis as complete.
- **P1 — Material analytical error:** false critical path, missed viable takeover, invalid Principal accepted, deny/condition incorrectly changes reachability.
- **P2 — Precision defect:** wrong IAM/ECS technique name, role types merged, required wildcard presented as remediable.
- **P3 — Presentation/export drift:** correct engine result but inconsistent table, graph, JSON, or Markdown evidence.

# Release gate

Do not close the prior gaps merely because their original single fixtures pass. This suite passes only when:

1. All duplicate-key variants fail before normal parsing regardless of order, depth, escape spelling, or ingestion path.
2. Family selection is mandatory, exported, state-safe, and semantically authoritative.
3. Role-takeover correlation requires compatible actions, overlapping role scope, simultaneously satisfiable conditions, and unsuppressed permissions.
4. Partial Principal wildcards are rejected across strings and arrays without rejecting valid account principals or condition patterns.
5. ECS task and execution roles remain distinct throughout findings and graph construction.
6. Required wildcard resources do not generate impossible remediation.
7. Every UI and export surface preserves source evidence and safely renders attacker-controlled strings.
8. Limit behavior is deterministic, early, and produces no partial-success ambiguity.

# AWS reference basis

- [IAM Access Analyzer policy validation checks](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html)
- [IAM JSON policy grammar](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html)
- [IAM Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html)
- [IAM Resource element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html)
- [Passing a role to an AWS service](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)
- [IAM condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)
- [AWS Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html)
- [IAM actions, resource types, and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsidentityandaccessmanagementiam.html)
- [Amazon S3 actions, resource types, and condition keys](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazons3.html)
