# Candidate detectors (tracked, not yet built)

These are real privilege-escalation primitives the engine already **fails closed**
on (the CLI never reads CLEAN - they are caught by the incomplete-coverage
backstop) but does not yet surface as a **named** finding. They are recorded by the
privesc benchmark (`audit/benchmark/`) so they can never silently regress to CLEAN.
Each is a precision / UX upgrade (a named, actionable finding), not a fail-closed
fix. Listed with enough design to implement cleanly in a focused change.

## 1. COMPUTE-SESSION-TAKEOVER (highest value)

**Primitive.** Gain interactive code-execution on an EXISTING compute resource that
already has an attached IAM role, and thereby obtain/use that role - no iam:PassRole,
no code overwrite. Same outcome as COMPUTE-CODE-OVERWRITE (exec as an existing
resource's role) but by *accessing* the resource rather than *mutating* its code.

**Actions.**
- `ssm:SendCommand` - run commands on an EC2 instance as the instance role.
- `ssm:StartSession` - interactive shell on an instance as the instance role.
- `ec2-instance-connect:SendSSHPublicKey` - push a key, SSH in, read the instance
  role from IMDS. (Consider `ec2-instance-connect:SendSerialConsoleSSHPublicKey` too.)
- `sagemaker:CreatePresignedNotebookInstanceUrl` - open an existing notebook and run
  code as its execution role (Rhino repo method 28).

**Severity.** high (mirrors COMPUTE-CODE-OVERWRITE: a standalone direct code-exec
primitive; elevation depends on the target role's power, which is out of scope ->
policyEvidence high / pathExploitability medium).

**Why not fold into COMPUTE-CODE-OVERWRITE.** That finding's title/why is
"overwrite existing compute code/config." `ssm:SendCommand` is not an overwrite; a
shared finding id would emit misleading text. A distinct id keeps the finding
honest.

**Implementation checklist.**
1. `escalation-catalogs.js`: add an `ESCALATIONS['COMPUTE-SESSION-TAKEOVER']` entry
   (id, order, title, ruleVersion, docRef).
2. `escalation-families.js`: add the action list + a `detectComputeSessionTakeover`
   mirroring `detectComputeCodeOverwrite` MINUS the PassRole dedup (these do not pair
   with PassRole). Emit high; `technique: 'access-existing-compute-session'`.
3. `escalation.js`: import + add to the `DETECTORS` array.
4. `tests/fixture-matrix.test.js`: add an `APPLICABILITY` entry - kind set
   `['positive','negative','boundary','deny','condition','hostile']` (same as
   COMPUTE-CODE-OVERWRITE) - and author the witnessing fixtures under `fixtures/`
   (positive per action; negative = a read-only ssm/sagemaker action; deny = a
   same-policy Deny removes it; condition = a conditioned grant; hostile = a positive
   witness with HTML/JS in a Sid/ARN riding through as inert data).
5. Golden: re-capture only if a corpus policy uses these actions (none today).
6. Benchmark: flip `SECOND_TIER` ssm/eic entries and `PART2` method 28 from
   `finding: null` to `finding: 'COMPUTE-SESSION-TAKEOVER'`.

## 2. PassRole to AWS Batch

**Primitive.** `iam:PassRole` + `batch:RegisterJobDefinition` (jobRoleArn) [+
`batch:SubmitJob`] - a container runs with the passed job role.

**Subtlety.** Batch runs on ECS, so the job role is assumed via
`ecs-tasks.amazonaws.com`, not a clean `batch.amazonaws.com` principal. Adding a
`PASS_ROLE_SERVICES` entry needs the right principal for the conditional-PassRole
(iam:PassedToService) case; the unconditional case would fire regardless. Resolve
the principal before adding, or the conditional path may mis-key.

## 3. CodeStar (methods 23-25) - intentionally NOT planned

`codestar:CreateProjectFromTemplate`, `codestar:CreateProject` (+PassRole /
+AssociateTeamMember). AWS **deprecated and closed CodeStar in 2024**. Caught by the
backstop (never CLEAN); a named detector for a removed service is not warranted.
Kept in the benchmark for completeness (`PART2`, `deprecated: true`) only.
