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

function policyActions(statements) {
  const out = new Set();
  for (const s of statements) {
    for (const a of [].concat(s.Action || [])) if (DANGEROUS.test(a)) out.add(a);
  }
  return [...out];
}

// Real AWS call: iam:SimulateCustomPolicy over the supplied policy doc + action list.
// Returns a map action -> 'allowed' | 'explicitDeny' | 'implicitDeny'.
function awsSimulate(policyDoc, actions) {
  if (DRY_RUN) {
    // Canned response: AWS "allows" every dangerous action a naive read of the policy
    // grants (Effect Allow, no Deny). Exercises the diff logic without network.
    const denied = new Set();
    for (const s of policyDoc.Statement) {
      if (s.Effect === 'Deny') for (const a of [].concat(s.Action || [])) denied.add(a);
    }
    return Object.fromEntries(actions.map((a) => [a, denied.has(a) ? 'explicitDeny' : 'allowed']));
  }
  const args = [
    'iam', 'simulate-custom-policy',
    '--policy-input-list', JSON.stringify(JSON.stringify(policyDoc)),
    '--action-names', ...actions,
    '--resource-arns', '*',
    '--region', REGION, '--output', 'json',
  ];
  if (PROFILE) args.push('--profile', PROFILE);
  const raw = execFileSync('aws', args, { encoding: 'utf8', maxBuffer: 8 << 20 });
  const parsed = JSON.parse(raw);
  const map = {};
  for (const r of parsed.EvaluationResults || []) map[r.EvalActionName] = r.EvalDecision;
  return map;
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
  const actions = policyActions(c.statements);
  if (actions.length === 0) continue;

  let awsDecision;
  try {
    awsDecision = awsSimulate(policyDoc, actions);
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
