#!/usr/bin/env node
// AWS differential oracle: cross-check the engine against AWS's OWN policy evaluator.
//
// The engine models blast radius from policy text. AWS IAM is the ground truth for
// whether a policy actually grants an action. `iam:SimulateCustomPolicy` evaluates a
// set of policy DOCUMENTS you supply (it does NOT read the account's real IAM or any
// resource) and returns allowed / explicitDeny / implicitDeny per action - a pure,
// read-only policy-evaluation call. This harness feeds each benchmark policy to AWS,
// asks it which of the policy's dangerous actions are ALLOWED, and asserts the
// engine's verdict is consistent:
//
//   FAIL-CLOSED CHECK (primary): if AWS says a dangerous action is ALLOWED, the engine
//     must NOT read CLEAN on that policy. An AWS-confirmed grant the engine calls clean
//     is a real fail-open backed by AWS ground truth.
//   FALSE-POSITIVE CHECK (advisory): if the engine names an action in a finding but AWS
//     says that action is DENIED by the same policy, that is a candidate false positive.
//     Reported, not failed: the engine models potential blast radius and may over-warn
//     on purpose (e.g. unknown subject account), so this is a review signal.
//
// SAFETY: read-only. SimulateCustomPolicy evaluates the SUPPLIED policy JSON only; it
// creates/modifies nothing and reads no account state. Still, it is an API call in
// whatever account the profile points at, so you pick the profile explicitly.
//
// Usage (from tools/iam-blast-radius/):
//   node audit/oracle/aws-differential.mjs --profile <name> [--region us-east-1]
//   node audit/oracle/aws-differential.mjs --dry-run     # offline: canned AWS response, exercises the diff logic
//
// Requires the AWS CLI on PATH for real runs. Exit 0 iff no fail-closed violation.

import { execFileSync } from 'node:child_process';
import { analyze } from '../../../../content/tools/iam-blast-radius/engine/analyze.js';
import { CORPUS, SECOND_TIER, PART2, SUBJECT_ACCOUNT } from '../benchmark/corpus.mjs';

const argv = process.argv.slice(2);
const opt = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
const DRY_RUN = argv.includes('--dry-run');
const PROFILE = opt('--profile');
const REGION = opt('--region') || 'us-east-1';

// Actions we treat as "dangerous" to cross-check (the escalation/capability verbs the
// benchmark policies exercise). We only assert the fail-closed direction on these.
const DANGEROUS = /(:PassRole|:CreateAccessKey|:CreateLoginProfile|:UpdateLoginProfile|:Attach.*Policy|:Put.*Policy|:AddUserToGroup|:UpdateAssumeRolePolicy|:CreatePolicyVersion|:SetDefaultPolicyVersion|:RunInstances|:CreateFunction|:UpdateFunctionCode|:UpdateFunctionConfiguration|:CreateProject|:UpdateProject|:CreateJob|:UpdateJob|:UpdateDevEndpoint|:CreateStack|:UpdateStack|:CreatePipeline|:RunTask|:RegisterTaskDefinition|:CreateNotebookInstance|:CreatePresignedNotebookInstanceUrl|:AssumeRole|:AddPermission|:PutTargets|:SendCommand|:StartSession|:SendSSHPublicKey|:CreateProjectFromTemplate|:AssociateTeamMember|:SubmitJob|:RegisterJobDefinition)/;

// Map each dangerous action to the resource(s) of the statement that grants it, so
// SimulateCustomPolicy evaluates the action against the scope the policy actually
// grants (simulating against a mismatched resource would wrongly read as denied).
function dangerousActionResources(statements) {
  const map = new Map(); // action -> Set(resources)
  for (const s of statements) {
    if (s.Effect !== 'Allow') continue;
    const resources = [].concat(s.Resource || []);
    for (const a of [].concat(s.Action || [])) {
      if (!DANGEROUS.test(a)) continue;
      if (!map.has(a)) map.set(a, new Set());
      for (const r of resources) map.get(a).add(r);
    }
  }
  return map;
}

// SimulateCustomPolicy needs concrete ARNs. A bare "*" resource -> omit --resource-arns
// (evaluate the action unconstrained). A wildcard ARN (role/deploy-*) -> substitute a
// concrete instance that the wildcard matches, so the grant still evaluates as allowed.
function concretize(resources) {
  const arns = [];
  for (const r of resources) {
    if (r === '*') continue; // unconstrained -> omit
    arns.push(String(r).replace(/\*/g, 'x'));
  }
  return arns;
}

// Real AWS call: iam:SimulateCustomPolicy for ONE action against its own resources.
// Returns 'allowed' | 'explicitDeny' | 'implicitDeny'.
function awsSimulateAction(policyDoc, action, resources) {
  if (DRY_RUN) {
    for (const s of policyDoc.Statement) {
      if (s.Effect === 'Deny' && [].concat(s.Action || []).includes(action)) return 'explicitDeny';
    }
    return 'allowed';
  }
  const args = [
    'iam', 'simulate-custom-policy',
    '--policy-input-list', JSON.stringify(policyDoc),
    '--action-names', action,
    '--region', REGION, '--output', 'json',
  ];
  const arns = concretize(resources);
  if (arns.length) args.push('--resource-arns', ...arns);
  if (PROFILE) args.push('--profile', PROFILE);
  const raw = execFileSync('aws', args, { encoding: 'utf8', maxBuffer: 8 << 20 });
  const parsed = JSON.parse(raw);
  // If simulated against multiple resources, the grant holds if ANY resource is allowed.
  let decision = 'implicitDeny';
  for (const r of parsed.EvaluationResults || []) {
    if (r.EvalDecision === 'allowed') return 'allowed';
    if (r.EvalDecision === 'explicitDeny') decision = 'explicitDeny';
  }
  return decision;
}

const CASES = [...CORPUS, ...SECOND_TIER, ...PART2];
const CTX = { subjectAccount: SUBJECT_ACCOUNT, partition: 'aws' };

if (!DRY_RUN && !PROFILE && !process.env.AWS_PROFILE) {
  console.error('Refusing to guess an AWS account. Pass --profile <name> (read-only ' +
    'SimulateCustomPolicy) or --dry-run for the offline logic check.');
  process.exit(2);
}

console.log(`AWS differential oracle: ${CASES.length} policies` + (DRY_RUN ? ' (DRY RUN, canned AWS)' : ` (profile ${PROFILE || process.env.AWS_PROFILE}, region ${REGION})`) + '\n');

const failClosedViolations = [];
const falsePositiveCandidates = [];

for (const c of CASES) {
  const policyDoc = { Version: '2012-10-17', Statement: c.statements };
  const actionRes = dangerousActionResources(c.statements);
  const actions = [...actionRes.keys()];
  if (actions.length === 0) continue;

  const awsDecision = {};
  try {
    for (const a of actions) awsDecision[a] = awsSimulateAction(policyDoc, a, [...actionRes.get(a)]);
  } catch (e) {
    console.error(`  ${c.id}: AWS simulate failed: ${String(e.message).split('\n')[0]}`);
    process.exit(3);
  }

  const res = analyze(JSON.stringify(policyDoc), CTX);
  const clean = (res.findings || []).length === 0 && !res.coverage?.summary?.incomplete;
  const findingActions = new Set((res.findings || []).flatMap((f) => f.actions || (f.escalation && f.escalation.actions) || []));

  const awsAllowed = actions.filter((a) => awsDecision[a] === 'allowed');

  // Primary: AWS confirms a dangerous action is allowed, but the engine reads CLEAN.
  if (awsAllowed.length > 0 && clean) {
    failClosedViolations.push({ id: c.id, awsAllowed });
  }
  // Advisory: engine names an action AWS says is explicitly denied by the same policy.
  for (const a of findingActions) {
    if (awsDecision[a] === 'explicitDeny') falsePositiveCandidates.push({ id: c.id, action: a });
  }

  const nf = (res.findings || []).length;
  const verdict = clean ? 'CLEAN' : nf ? `flagged(${nf})` : 'incomplete-coverage';
  console.log(`  ${c.id.padEnd(38)} aws-allowed=${awsAllowed.length}/${actions.length}  engine=${verdict}`);
}

console.log(`\nFail-closed violations (AWS says allowed, engine CLEAN): ${failClosedViolations.length}`);
for (const v of failClosedViolations) console.log(`  VIOLATION ${v.id}: AWS allows [${v.awsAllowed.join(', ')}] but engine read CLEAN`);
console.log(`False-positive candidates (engine names an AWS-denied action): ${falsePositiveCandidates.length}`);
for (const v of falsePositiveCandidates) console.log(`  review ${v.id}: engine cites ${v.action}, AWS explicitDeny`);

process.exit(failClosedViolations.length ? 1 : 0);
