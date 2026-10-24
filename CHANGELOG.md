# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Nothing yet.

## [1.3.0] - 2026-10-21

### Added

- **Pulumi input.** `iam-br --input pulumi <file>` and the Action input `pulumi-json`
  scan every IAM policy in a `pulumi preview --json` or `pulumi stack export`. Each
  policy's family and attached resource come from its resource type (classic AWS
  types and the verified aws-native types). Findings are keyed `<urn>#<property>`
  in JSON and SARIF `logicalLocations`, with the program's source line when it is
  inside the project. The tool never runs Pulumi or calls AWS.
  - A default preview reports `scanScope: "delta"` (Action output `scan-scope`):
    exit 0 then means "no new risk in this change", not "stack clean". Use
    `--show-sames` or a stack export for a full scan.
  - The report lists the asserted subject account, each provider's account and
    partition with the evidence behind them, per-role `groups[]` (trust, inline,
    attached policies, `can-assume` edges) and `unresolvedEdges[]`. Groups are
    informational and never change a verdict.
  - Baselines work with Pulumi input, keyed per `<urn>#<property>` (inline policies
    by name): a resource or stack rename shows as one stale and one new entry.
- **TRUST-SAME-ACCOUNT** (low; medium for the account root): a role trust whose
  principals are all valid ARNs in the role's own account, proven by the role's ARN
  (`--resource-arn` / `resource-arn`, or the Pulumi stack). `--subject-account`
  alone never proves it. The JSON report echoes `subjectAccountAsserted`.
- **Action catalog:** sns, events, logs, config, lambda and cloudformation are
  snapshotted for Deny statements, so AWS Control Tower guardrail SCPs no longer
  fail on unknown actions (on a real Control Tower organization, most guardrail
  statements now read clean, with no new highs). All iam reference actions are snapshotted.
  ecr, codeartifact, scheduler and eks are snapshotted for Deny statements too.
  cognito-identity is snapshotted, and its credential-exchange flow (`GetId`,
  `GetCredentialsForIdentity`, `GetOpenIdToken`) is known in an Allow;
  `GetOpenIdTokenForDeveloperIdentity` and `SetIdentityPoolRoles` stay fail-closed.
- **Known in an Allow:** the CI/ECS role basics, logs `CreateLogGroup`,
  `CreateLogStream`, `PutLogEvents` and the log-group/stream/filter `Describe*`
  listings, plus ecr `GetAuthorizationToken`, `BatchCheckLayerAvailability`,
  `GetDownloadUrlForLayer` and `BatchGetImage`. Log-data reads (`GetLogEvents`,
  `FilterLogEvents`, queries) stay unknown (exit 3).
- **Pulumi:** `aws:ssoadmin/permissionSetInlinePolicy`, `aws:ecr/registryPolicy`,
  `aws:ecr/repositoryCreationTemplate`, `aws:cloudwatch/logResourcePolicy` and
  `aws:dynamodb/resourcePolicy` are mapped; a resource policy with no single
  attached resource fails closed.
- **Pulumi:** `--provider-account <provider>=<account>` and the `provider-accounts`
  input name the account of a provider the stack can't prove (for example one
  configured only by profile). It is cross-checked against the stack, a mismatch
  fails closed, and it never proves a same-account trust on its own.
- **Resource policies on ECR repositories, Secrets Manager secrets and DynamoDB
  tables** are analyzed (`--resource-type ecr-repository | secretsmanager-secret |
  dynamodb-table`, or via the Pulumi mapping). Public, cross-account, same-account
  and confused-deputy findings apply, plus RESOURCE-DATA-EXPOSURE (a public read,
  write or delete) and RESOURCE-POLICY-TAKEOVER (a grant that can rewrite the
  resource policy). An unclassified action keeps the policy at exit 3. On these
  three services an org- or account-scoped `*` is cross-account (not public), an
  exact `aws:PrincipalArn` pin lowers a cross-account grant to medium,
  `aws:SourceOrgID` counts as a service source binding, and a `ForAllValues` guard
  on a service-only source key (absent for IAM callers, so it constrains nothing)
  is called out as vacuous.
- **`--trusted-account-id <id>`** (repeatable or a comma list) and the Action input
  `trusted-account-ids`: a role trust whose principals are all exact role, user or
  assumed-role ARNs in a listed account is TRUST-CROSS-ACCOUNT medium instead of high.
  Account-root principals, wildcards and mixed or unlisted principals stay high; the
  list is the only source of trust and is never inferred. The JSON report echoes
  `trustedAccountIdsAsserted`.
- **Pulumi role grouping carries the trust audience into the role's policies:** a role
  assumable by every identity of a Cognito identity pool has its data read, write and
  delete findings raised to at least high, unless every resource is scoped per user by
  `${cognito-identity.amazonaws.com:sub}`; whatever the bucket is called, S3 object
  read, write or delete on a whole bucket or `*` reports **POPULATION-SCALE-DATA-ACCESS**
  (high). A Cognito trust is population-scale unless an exact `:sub` pin narrows it.
- **TRUST-POD-IDENTITY-UNBOUND** (low): an unbound `pods.eks.amazonaws.com` statement
  next to a pinned IRSA `sub` lets any same-account Pod Identity association bind the
  role, bypassing the pin; only an exact `aws:SourceArn` pin to EKS cluster ARNs binds
  it. With Pulumi input it is medium when the role can write IAM.
- The GitHub OIDC `repository_id` claim is modeled as a single-repository pin: with a
  branch pin the trust is low, with any ref high, never internet-open critical.
- **RESOURCE-INERT-STATEMENT** (info): a resource-policy statement that grants only
  AWS service principals but requires a principal-only key (`aws:PrincipalOrgID`,
  `aws:PrincipalArn`, ...) never matches a service call, so it grants nothing and is
  no longer reported as confused deputy.
- The condition keys `kms:GrantIsForAWSResource` and `kms:CallerAccount` are modeled
  for the AWS-managed key-policy shapes, and `kms:ListGrants` is a known read.

### Security

- **The Pulumi adapter fails closed (exit 3), naming the URN and property,** on:
  preview unknowns (`PULUMI_UNKNOWN`) and secrets (`PULUMI_SECRET`, never read or
  echoed), on mapped and unmapped properties alike; duplicate JSON keys, URNs or
  inline policy names; unknown operations, malformed entries and size, count or depth
  limits; unmapped IAM types and policy documents (JSON or YAML text) in properties
  it doesn't analyze; an unresolved, ambiguous or mismatched account or partition;
  and ambiguous resource joins. It never builds a placeholder ARN.
- Only IAM resources (always in the caller's account) or provider config prove a
  stack's account; imported, read or ARN-adoptable resources (SNS, SQS, KMS, Lambda
  and others) never do, and prior-state outputs are reused only for in-place updates
  on the same provider.
- **Lambda permissions:** a grant to the public, another account, or a service with
  no `sourceArn`/`sourceAccount` exits 3 (`PULUMI_UNMODELED_PERMISSION`).
- A wildcard `aws:SourceOrgID` / `aws:SourceOrgPaths` value (`o-*`, `*/*`) is no
  longer credited as a source binding. An exact `aws:PrincipalArn` pin lowers only a
  read-only cross-account grant in the pinned principal's own account. A vacuous
  `ForAllValues` source guard no longer escalates a scoped `*` to public.
- In an Allow, actions of the Deny-only services, iam tag/untag actions and the
  account-wide IAM dumps (`GetAccountAuthorizationDetails`, credential reports)
  stay unknown (exit 3) until a finding models them.

### Changed

- **Behavior change:** read-only wildcards in the Deny-only services
  (`lambda:Get*`, `lambda:List*`, `cloudformation:Describe*`, `config:Describe*`)
  and `iam:Get*` on `*` now exit 3 instead of 0, because they reach data-plane reads
  (log events, Lambda environment variables, templates) or account-wide IAM dumps.
  A read-only policy that was green on v1.2.0 may fail closed on v1.3.0.
- A same-account trust that v1.2.0 reported as TRUST-CROSS-ACCOUNT high is
  TRUST-SAME-ACCOUNT when the role ARN is supplied. Baseline ids include severity,
  so an accepted cross-account finding re-fires once as the new finding.
- `gate:no-network` matches network API names as whole words.
- **Calibrations from a real-estate triage:** log-ingestion writes
  (`CreateLogGroup`/`CreateLogStream`/`PutLogEvents`) on a broad scope are
  WILDCARD-RESOURCE medium; reads and writes on the CodePipeline artifact store
  `codepipeline-<region>-*` are medium, only for the AWS artifact-store actions
  (bucket configuration, lifecycle, versioning and retention writes stay high); `sqs:DeleteMessage`/`DeleteMessageBatch` are a
  consumer ack, not destructive (`DeleteQueue`/`PurgeQueue` stay destructive). Any other
  action, a `logs:` wildcard, or a delete keeps the high.
- **Renamed:** across the resource family, a `Principal "*"` scoped by a positive
  principal condition (`aws:PrincipalOrgID`, `aws:PrincipalAccount`,
  `aws:PrincipalArn`, `aws:PrincipalTag`, `kms:CallerAccount`, ...) is
  RESOURCE-CROSS-ACCOUNT instead of PUBLIC-ACCESS, with the same severity; scoped to
  the owner's own account by `aws:PrincipalAccount`, it is RESOURCE-SAME-ACCOUNT-GRANT
  high (it grants every principal in the account directly; the `:root` form stays
  medium).
  Baseline ids include the rule id, so an accepted PUBLIC-ACCESS on such a policy
  re-fires once as the new finding.
- A `2008-10-17` policy without policy variables is analyzed as `2012-10-17` (its
  only semantic difference is `${...}`); one with a variable still fails closed.
- A `Principal "*"` trust pinned by an exact `ArnEquals`/`StringEquals` on
  `aws:PrincipalArn` to concrete principal ARNs is reported as those named
  principals (TRUST-CROSS-ACCOUNT, or TRUST-SAME-ACCOUNT with the role ARN), not
  TRUST-PUBLIC. Like operators, wildcards, `IfExists` and set operators stay public.
- Pulumi component resources (`custom: false`) are no longer backstopped; the child
  resources they create are analyzed on their own.

### Known limitations

- Source-bound, org-scoped and own-account Lambda permissions are listed in the
  Pulumi report's `unanalyzed[]`, not analyzed.
- `aws-native:events:EventBusPolicy` is not mapped; a policy statement in it fails
  closed (exit 3).
- A baseline can accept an engine coverage gap (for example `UNKNOWN_ACTION`), as
  in v1.2.0; `analysis-status: partial` stays visible. Pulumi adapter states are
  never accepted.
- `kms:RevokeGrant` stays unknown in an Allow (a permissions change with no
  detector), so a key policy whose grant statement allows it still exits 3.
- DynamoDB stream policies, and a wildcard ARN as the attached resource, stay
  unsupported (exit 3).
- Without `trusted-account-ids`, an exact cross-account role trust stays
  TRUST-CROSS-ACCOUNT high: an in-org role can't be told apart from a vendor's.
- A bare identity policy can't know its role's trust, so the Cognito population-scale
  raise applies only with Pulumi input.
- SARIF paths are relative to the Pulumi project; a project in a repo subdirectory
  does not map to files in code scanning yet.

### Round 8, lane B: condition keys

- **Org keys (F-3).** `aws:ResourceOrgID`, `aws:ResourceOrgPaths` and
  `aws:PrincipalOrgPaths` are modeled, so an org gate no longer fails the run closed
  (exit 3). A positive, literal `aws:ResourceOrgID` (or `ForAnyValue` org path) on a
  wildcard-account `sts:AssumeRole` keeps ASSUME-ROLE-EXPANSION at its severity and
  names the org condition as the bound. `IfExists`, negated, globbed (`o-*`) and
  `${...}` org values are not credited.
  - The `*OrgPaths` keys are multivalued: without `ForAnyValue`/`ForAllValues` they
    stay UNSUPPORTED_CONDITION.
  - Resource policies: `aws:PrincipalOrgPaths` narrows a `"*"` grant only when its
    org segment is a literal org id; `o-*/...` stays public.
  - Role trust: `aws:PrincipalOrgPaths` is not credited; the trust keeps its ungated
    severity.
- **Trial condition keys (E-2).** Modeled as gates that can only narrow an Allow, so
  findings are unchanged and the run no longer fails closed on them:
  `iam:AWSServiceName`, `sts:AWSServiceName`, `ec2:AuthorizedService`,
  `acm-pca:TemplateArn`, `aws:RequestTag/<k>`, `aws:ResourceTag/<k>`,
  `ec2:ResourceTag/<k>` and `kms:EncryptionContext:<k>` (selectors, never credited);
  `ec2:Subnet`, `ec2:CreateAction` and `elasticloadbalancing:CreateAction`
  (constraints, credited only under a positive match); and the GitHub OIDC
  `token.actions.githubusercontent.com:ref` claim (never credited: a ref does not pin a
  repository). A tag or encryption-context key with an empty suffix, and a `:ref` claim
  on any other provider, stay unsupported.

## [1.2.0] - 2026-10-21

### Added

- **Baseline mode**: `baseline` / `baseline-output` Action inputs and CLI options
  accept a reviewed findings file so known findings don't fail the gate; acceptance
  dies on any identity change (file, rule, severity, principals, condition values).
  Format version 2; see the fingerprint entry below.
- **DB-AUTH** finding: `rds-db:connect` is IAM database auth (credential-equivalent);
  high unless every resource pins a concrete `dbuser:<cluster>/<user>`.
- **PASSROLE-UNSCOPED** finding: `iam:PassRole` on `*` (or any all-roles pattern)
  reports even without a companion launch action - it combines with whatever compute
  permission the holder has elsewhere.
- **OBJECT-ACL-WRITE** finding: `s3:PutObjectAcl` / `s3:PutObjectVersionAcl` can set
  objects public or grant them cross-account unless the bucket enforces
  BucketOwnerEnforced (which a policy can't show); high on `bucket/*` or broader,
  medium on a single named object.
- Condition modeling: `s3:ResourceAccount` / `aws:ResourceAccount` (a negated
  account guard is called out as covering same-account resources too) and the
  Cognito `cognito-identity.amazonaws.com:amr` sign-in state.
- Action catalog refresh (service coverage incl. `kinesis`, `rds-db`, `eks-auth`);
  unmodeled write/permissions actions from the AWS reference stay withheld so an
  Allow on them remains fail-closed `UNKNOWN_ACTION`.
- China-partition service principals: documented `.amazonaws.com.cn` spellings for
  `ec2` and `datapipeline`; under `aws-cn` the matcher considers both spellings for
  every service.

### Security

- **SCP/RCP guardrails that do nothing no longer read CLEAN.** A Deny whose
  NotAction matches every action, a negated region `*Like` matching every region,
  and an RCP org perimeter that admits any organization now report high. Inverted
  region/org fences and MFA/SecureTransport-gated Denies are high (were medium or
  undetected).
- An open GitHub or Cognito federated trust (sub missing or `*`/`repo:*`, no pool
  id) is critical, so it also fails `--threshold critical`.
- **SCP/RCP Denies are judged only by what the guardrail evaluator models.** Any
  other AND'd condition key, an unknown operator or a negated set-qualified
  operator exits 3 instead of reading CLEAN. Denies that never fire (value unions
  matching every region, action or principal; `Null "true"` on always-present
  keys; contradictory `Bool` values; NotResource/Resource scopes that match
  nothing; a carve-out of the subject account; plain `Bool
  aws:MultiFactorAuthPresent "false"`) report high, as do `${...}` org values,
  `Null aws:PrincipalOrgID "false"` and an inverted confused-deputy template. An
  RCP whose Principal isn't `"*"` exits 3.
- A Deny of only the catalogued actions no longer suppresses a wildcard grant
  (`ssm:GetParameter*`, `cloudtrail:Stop*`, `ec2:*` + PassRole, `iam:Create*`); it
  narrows the finding unless it covers the whole grant in each service.
  `ArnLike`/`ArnEquals` on `iam:PassedToService` is not a certain Deny.
- Resource policies: a Numeric, Date or Binary condition on a principal scoping
  key no longer counts as a pin; `Principal *` under it is critical.
- A NotAction + NotResource Deny no longer fences a broad grant whose actions the
  NotAction spares (`Deny NotAction s3:GetObjectVersion` no longer suppresses
  DATA-EXFIL for `s3:GetObject*` on `*`).
- An RCP Deny with a positive comparator on any org key (including
  `aws:PrincipalOrgPaths`) is an inverted perimeter (high); a confused-deputy RCP
  with a positive `aws:SourceAccount` is limited to that account (high).
- Guardrail Denies that never fire for the subject account report high: an
  own-account `aws:PrincipalArn` carve-out, a pin to a foreign account, a Resource
  that can't match (asserted partition mismatch, a region the fence allows), and
  contradictory string conditions on one key. An unknown literal partition, or an
  RCP whose actions all fall outside the services RCPs govern, exits 3.
- A Deny pinned to principal values no request carries reports high: a literal
  `*` under StringEquals on `aws:PrincipalArn` (a mistyped root deny), or an sts
  assumed-role ARN. A cross-region Copy/Replicate Deny pinned to the allowed
  region exits 3 instead of reading as a no-op.

### Changed

- **SARIF fingerprints are now `iamBlastRadius/semanticIdentity/v2`** (breaking for
  dismissed alerts and baselines, once). The statement position is no longer part of
  a finding's identity, so inserting a statement above an accepted finding no longer
  re-opens it; identical findings in one file are told apart by an occurrence
  ordinal. `UNKNOWN_ACTION` / `UNSUPPORTED_CONDITION` fingerprints now include the
  full sorted offending set (dismissing one no longer covers a different one). The
  hash is SHA-256 truncated to 128 bits (was non-cryptographic cyrb53).
- Trust findings carry their trusted principals, and the SARIF fingerprint and
  baseline id bind to them: accepting a trust never covers a different account.
- Under `aws-cn`, an `iam:PassedToService` deny covering only one spelling (e.g.
  `StringNotEquals ec2.amazonaws.com.cn`) is no longer credited: the PassRole
  path reports and the scan fails closed (exit 3), since AWS may send either.
- `iam:PassedToService` matching is operator-correct (`(Not)Equals` compares
  literally; only `Like`/`Arn*` expand wildcards) and partition-aware: the
  matcher tests the spellings the asserted partition can send (`aws-cn` may
  use `<svc>.amazonaws.com.cn`, varying per service), and an unasserted or
  unrecognized partition is never coerced to `aws` before matching.
- `UNSUPPORTED_CONDITION` identities (fingerprints and baseline ids) include a
  canonical serialization of the affected statements' Condition blocks, so an
  acceptance never survives a condition-value edit.
- **Baseline file format is version 2.** Version 1 baselines are refused (exit `2`)
  with a message to regenerate; keys follow the same identity change. `baseline-output`
  warns when it writes `critical` entries.
- **DATA-EXFIL severity scales with resource breadth**: a single named secret or
  parameter is `medium`; `*`, account-wide patterns, path reads and anything
  ambiguous (variables, wildcard accounts, `NotResource`) stay `high`.
- Release version bumped to `1.2.0` (`package.json` and
  `VERSION_MANIFEST.releaseVersion`).
- Admin-equivalent IAM grants that can target the caller (attach, put or version
  a policy on `*` or a self-scoped resource) are critical. Baseline ids include
  severity, so a baseline that accepted one of these at high re-fires once.
- The Cognito authenticated-role trust finding (medium) tells the reviewer to
  check the role's attached policies, which reach every signed-in pool user.

### Fixed

- Resource policies can exit 0 when every part is modeled (KMS owner delegation,
  same-account grants, own-account-bound service grants, deny-only policies).
  Anything unmodeled (NotPrincipal, Allow NotAction/NotResource, unknown condition
  operators, CanonicalUser/Federated principals, foreign-service actions) stays
  exit 3 and is located by JSON path. An unknown condition operator is no longer
  credited as narrowing.
- Resource-side self-reference conditions (`aws:PrincipalArn == ${aws:PrincipalArn}`)
  and other no-op `*` conditions are critical with a tautology note; a real
  account/org/ARN pin stays high. Unbound service-principal grants are high.
- A NotPrincipal statement in a resource policy fails closed on its own instead of
  hiding the other statements' findings.
- Public and federated trusts with `sts:*`, `*`, `sts:AssumeRole*` or NotAction are
  analyzed (were blocked with no findings). An explicitly chosen identity family is
  no longer misread as an SCP. `scp-rcp` accepts FullAWSAccess and named-action
  Deny SCPs.
- `aws:PrincipalIsAWSService` and `aws:SourceOrgID` are modeled in RCPs; the AWS
  perimeter template reads CLEAN and its inversion reports high.
- Denies are judged against the concrete actions a finding needs (`Allow *` +
  `Deny iam:*,sts:*` no longer reports IAM/STS escalations); a same-scope Deny
  suppresses OBJECT-ACL-WRITE / RESOURCE-POLICY-WRITE; PassRole no longer reports
  for user/group ARNs or service-certain PassedToService Denies.
- Catalog: snapshot/AMI sharing, OIDC/SAML provider changes, IAM tagging,
  `kms:ScheduleKeyDeletion` and `ec2:ModifyInstanceAttribute` now name their risk;
  PassRole + `iam:AddRoleToInstanceProfile` reports PASSROLE-EC2.
- Trust: `${*}`/`${?}`/`${$}` are literal characters; PrincipalArn pins under
  IfExists/ForAllValues are not bypassable for `sts:AssumeRole`; tautology checks
  compare the literal value; the Cognito aud + amr pattern is credited.
- A broad session policy rates high like a permissions boundary. A resource
  context that doesn't match the policy's ARNs fails closed. All surfaces list the
  same family tokens.
- A resource statement naming a Resource outside the attached resource is
  reported per statement (exit 3) without dropping the other findings; a Deny on
  another resource no longer blocks analysis.
- A partial `aws:PrincipalAccount` carve-out such as `["1*","4*"]` is no longer
  read as matching every account.

## [1.1.0] - 2026-10-09

### Added

- **COMPUTE-SESSION-TAKEOVER** escalation detector (13th family): names the "gain
  code-execution on an EXISTING role-bearing compute resource, then use its role"
  primitive - `ssm:SendCommand` / `ssm:StartSession`,
  `ec2-instance-connect:SendSSHPublicKey` /
  `ec2-instance-connect:SendSerialConsoleSSHPublicKey`, and
  `sagemaker:CreatePresignedNotebookInstanceUrl` (Rhino method 28). Needs no
  `iam:PassRole` and no code change; fires at high. Previously these were caught
  fail-closed only by the incomplete-coverage backstop; now they surface as a named
  finding. The privesc benchmark's SSM / EC2-Instance-Connect / existing-SageMaker
  -notebook cases move from backstop to named accordingly.
- **GitHub Action: `node24` runtime.** `action.yml` now declares `runs.using: node24`
  (was `node20`, which GitHub is retiring). The Action is still a plain ESM entry
  point (`action/index.mjs`) with no build step, bundled `dist`, or runtime npm
  dependencies; the Node runtime is provided by the runner. GitHub.com-hosted
  runners are the supported baseline. The npm package's `engines.node` is unchanged.
- **Action self-test coverage** (`.github/workflows/action-selftest.yml`): new cases
  assert both the step outcome and the `exit-code` output for an internal error
  (exit `4`, via an unreadable policy file), a mixed valid + malformed `paths` list
  (exit `3`, never `0`), an omitted `partition` on a verdict that depends on it
  (exit `3`, with an asserted-partition control at exit `1`), and one fixture per
  policy family (identity, role-trust, resource with and without `resource-arn`,
  permissions-boundary, session, SCP, RCP).
- **README "GitHub Action" section** for the GitHub Marketplace listing: usage
  (`rivassec/secure-iam-lint@v1` and a full-commit-SHA pin), required permissions,
  inputs/outputs, the exit-code contract (exit `3` is fail-closed, never a green
  check), and the supported-runner statement.
- **SARIF upload guidance**: README and `ACTION.md` now show a least-privilege
  pattern - a read-only `scan` job and a separate `upload` job that alone holds
  `security-events: write`, skips fork pull requests, never uses
  `pull_request_target`, pins `upload-sarif` by commit SHA, and keeps the check
  failed when the scan fails.

### Changed

- Release version bumped to `1.1.0` (`package.json` and
  `VERSION_MANIFEST.releaseVersion`).

## [1.0.0] - 2026-08-29

First stable release. `package.json` is at `1.0.0`; the `v1.0.0` git tag - which
marks the release and makes the compare/tag links below resolve - is pending.

### Added

- **Browser-pure analyzer** (`analyze()`): pastes an AWS IAM policy and computes
  its *potential* blast radius - privilege-escalation paths, role-assumption
  reach, and data exposure - entirely client-side under a strict
  Content-Security-Policy that blocks the page from making network requests
  (`connect-src 'none'`) and loads no third-party scripts.
- **Node CLI** (`iam-br`) and a headless `scan()` API sharing the same engine,
  with policy-family selection (identity / resource / role-trust / scp-rcp /
  session / permissions-boundary) and exit codes suitable for CI gating.
- **SARIF exporter** and a **GitHub Action** for CI integration.
- Escalation-path detection (12 families) and capability rules, graded by
  certainty, reporting the AWS evaluation layers rather than asserting effective
  permissions.

### Security

- **Fail-closed guarantee**: `analyze()` / `scan()` never read CLEAN on a policy
  that carries a real capability; when a verdict cannot be determined the engine
  reports incomplete coverage, and the browser is never more permissive than the
  CLI (enforced by a determinism + parity fuzzer).
- Hardened through a multi-round adversarial security review that found and fixed
  a series of fail-open classes, including: unicode / case-fold / homoglyph
  action-token spoofs; de-spoofed Deny / condition-key suppression; bypassable
  `iam:PassedToService` qualifiers; cross-account resource-policy-write grants;
  standalone compute-code-overwrite escalation; and cataloged-but-silent IAM
  actions. Each fix ships with a regression test.
- CI supply-chain hardening: CodeQL SAST, ClusterFuzzLite fuzzing, OpenSSF
  Scorecard, Dependabot, a committed fail-open-lint gate (guard-target +
  active-hotspot baseline), and npm publish with build provenance via trusted
  publishing (OIDC, no long-lived token).
- Independently validated on three axes: a security-mutation harness reintroduces
  each fixed fail-open into the engine and confirms the test suite catches it
  (9/9 killed); a ground-truth benchmark grades the analyzer against the published
  Rhino Security Labs privilege-escalation catalog - all 28 numbered methods fail
  closed, none read CLEAN; and a differential-oracle harness cross-checks the
  engine against AWS's own `iam:SimulateCustomPolicy` evaluator - an offline
  self-check runs in CI, and pointed at a real AWS account it verifies the engine
  never reads CLEAN on a policy AWS reports as allowing the action.

[Unreleased]: https://github.com/rivassec/secure-iam-lint/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/rivassec/secure-iam-lint/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/rivassec/secure-iam-lint/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/rivassec/secure-iam-lint/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rivassec/secure-iam-lint/releases/tag/v1.0.0
