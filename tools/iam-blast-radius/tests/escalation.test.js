// Unit tests for IAM-005: privilege-escalation path engine.
// Runs on node's built-in runner: `node --test`.
//
// Acceptance (prd.json IAM-005):
//   - pass-role/ + assume-role/ positive fixtures detected; negatives
//     (PassRole alone) NOT flagged
//   - IAM critic 100 on escalation semantics - encoded as: no false path on
//     negative/boundary fixtures, no missed path on positive fixtures, and
//     iam:PassedToService / Resource relationships respected
//   - reliability critic >=95 - deterministic, deep-frozen, never throws
//   - security critic no high/critical - hostile input inert; no prototype
//     pollution; capability-not-effective + target-unknown caveats on every
//     finding
//
// Canonical finding shape (docs/architecture.md) plus escalation enrichment:
// escalation.{technique,service,requiredActions,targetPermissions} and an
// evidence[] array.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import {
  analyzeEscalations,
  analyzeEscalationsFromText,
  ESCALATIONS,
  ESCALATION_IDS,
} from '../../../content/tools/iam-blast-radius/engine/escalation.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const CONFIDENCES = new Set(['high', 'medium', 'low']);
const CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 };
const ESCALATION_ID_SET = new Set(ESCALATION_IDS);

// Escalation categories whose fixtures carry escalation-id expectations.
const ESCALATION_CATEGORIES = [
  'pass-role',
  'assume-role',
  'policy-version',
  'attach-policy',
  'credential-creation',
];

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

function loadFixtures(category) {
  const dir = join(fixturesDir, category);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `${category}/${f}`, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
}

function idsOf(findings) {
  return findings.map((f) => f.id);
}

// Assert the canonical shape + escalation enrichment on every finding.
function assertEscalationShape(f, ctx) {
  for (const field of [
    'id', 'severity', 'title', 'statementSid', 'actions', 'resources',
    'policyEvidence', 'pathExploitability', 'why', 'limit', 'remediation',
    'ruleVersion', 'docRef',
  ]) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(f, field),
      `${ctx}: finding ${f.id} missing required field "${field}"`,
    );
  }
  assert.ok(ESCALATION_ID_SET.has(f.id), `${ctx}: unknown escalation id ${f.id}`);
  assert.ok(SEVERITIES.has(f.severity), `${ctx}: bad severity ${f.severity}`);
  // IAM-104: single confidence replaced by two orthogonal signals.
  assert.ok(!('confidence' in f), `${ctx}: legacy confidence field must be gone`);
  assert.ok(CONFIDENCES.has(f.policyEvidence), `${ctx}: bad policyEvidence ${f.policyEvidence}`);
  assert.ok(CONFIDENCES.has(f.pathExploitability), `${ctx}: bad pathExploitability ${f.pathExploitability}`);
  // Compound/target-unknown escalation paths never assert exploitability above
  // the strength of the policy evidence (evidence >= exploitability).
  assert.ok(
    CONFIDENCE_RANK[f.policyEvidence] >= CONFIDENCE_RANK[f.pathExploitability],
    `${ctx}: ${f.id} pathExploitability (${f.pathExploitability}) must not exceed policyEvidence (${f.policyEvidence})`,
  );
  assert.ok(typeof f.title === 'string' && f.title.length > 0, `${ctx}: empty title`);
  assert.ok(typeof f.statementSid === 'string' && f.statementSid.length > 0, `${ctx}: empty statementSid`);
  assert.ok(Array.isArray(f.actions) && f.actions.length > 0, `${ctx}: actions must be a non-empty array`);
  assert.ok(Array.isArray(f.resources), `${ctx}: resources must be an array`);
  assert.ok('conditions' in f, `${ctx}: conditions field must be present (null allowed)`);
  assert.ok(typeof f.why === 'string' && f.why.length > 0, `${ctx}: empty why`);
  // Truthfulness: capability-not-effective AND target-unknown caveats present.
  assert.ok(typeof f.limit === 'string' && /not effective access/i.test(f.limit), `${ctx}: limit must carry the capability-not-effective caveat`);
  assert.ok(/unknown/i.test(f.limit), `${ctx}: limit must state target-role permissions are unknown`);
  assert.ok(typeof f.remediation === 'string' && f.remediation.length > 0, `${ctx}: empty remediation`);
  assert.equal(f.ruleVersion, ESCALATIONS[f.id].ruleVersion, `${ctx}: ruleVersion mismatch`);
  assert.ok(/^https:\/\//.test(f.docRef), `${ctx}: docRef must be an https URL`);
  // Escalation enrichment.
  assert.ok(f.escalation && typeof f.escalation === 'object', `${ctx}: missing escalation enrichment`);
  assert.ok(typeof f.escalation.technique === 'string' && f.escalation.technique.length > 0, `${ctx}: empty technique`);
  assert.equal(f.escalation.targetPermissions, 'unknown', `${ctx}: targetPermissions must be 'unknown', never inferred`);
  assert.ok(Array.isArray(f.escalation.requiredActions) && f.escalation.requiredActions.length > 0, `${ctx}: requiredActions must be non-empty`);
  assert.ok(Array.isArray(f.evidence) && f.evidence.length > 0, `${ctx}: evidence must be a non-empty array`);
  for (const ev of f.evidence) {
    assert.ok(typeof ev.statementIndex === 'number', `${ctx}: evidence missing statementIndex`);
    assert.ok(typeof ev.role === 'string', `${ctx}: evidence missing role`);
  }
}

// ---------------------------------------------------------------------------
// Fixture-driven assertions across every escalation category.
// ---------------------------------------------------------------------------

for (const category of ESCALATION_CATEGORIES) {
  for (const { file, data } of loadFixtures(category)) {
    const exp = data.expect || {};
    test(`fixture ${file}: escalation findings match expectations`, () => {
      const r = analyzeEscalationsFromText(fixtureText(data));
      assert.equal(r.ok, true, `${file}: analyze not ok: ${JSON.stringify(r.errors)}`);
      const actual = idsOf(r.findings);
      const actualSet = new Set(actual);

      for (const f of r.findings) assertEscalationShape(f, file);

      if (Array.isArray(exp.findingIds)) {
        for (const id of exp.findingIds) {
          if (!ESCALATION_ID_SET.has(id)) continue; // non-escalation ids ignored
          assert.ok(actualSet.has(id), `${file}: expected escalation ${id}, got ${JSON.stringify(actual)}`);
        }
      }
      if (Array.isArray(exp.notFindingIds)) {
        for (const id of exp.notFindingIds) {
          if (!ESCALATION_ID_SET.has(id)) continue;
          assert.ok(!actualSet.has(id), `${file}: escalation ${id} must NOT be produced, got ${JSON.stringify(actual)}`);
        }
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Coverage guards: acceptance names pass-role/ + assume-role/ explicitly, and
// the story requires >=5 escalation families each with a positive fixture.
// Fail (not skip) if coverage vanishes.
// ---------------------------------------------------------------------------

test('acceptance: pass-role/ positive fixtures are detected', () => {
  const fixtures = loadFixtures('pass-role');
  assert.ok(fixtures.length > 0, 'pass-role/ has no fixtures');
  const positives = fixtures.filter(({ data }) => (data.expect.findingIds || []).length > 0);
  assert.ok(positives.length > 0, 'pass-role/ has no positive fixture');
  for (const { file, data } of positives) {
    const r = analyzeEscalationsFromText(fixtureText(data));
    for (const id of data.expect.findingIds) {
      if (!ESCALATION_ID_SET.has(id)) continue;
      assert.ok(idsOf(r.findings).includes(id), `${file}: expected ${id}`);
    }
  }
});

test('acceptance: PassRole ALONE is never flagged as an escalation', () => {
  const fixtures = loadFixtures('pass-role');
  const alone = fixtures.find(({ file }) => /alone-negative/.test(file));
  assert.ok(alone, 'pass-role/ missing the PassRole-alone negative fixture');
  const r = analyzeEscalationsFromText(fixtureText(alone.data));
  assert.deepEqual(idsOf(r.findings), [], 'PassRole alone must produce no escalation');
});

test('acceptance: iam:PassedToService is respected (mismatch -> no path)', () => {
  const fixtures = loadFixtures('pass-role');
  const mismatch = fixtures.find(({ file }) => /mismatch/.test(file));
  assert.ok(mismatch, 'pass-role/ missing the PassedToService-mismatch boundary fixture');
  const r = analyzeEscalationsFromText(fixtureText(mismatch.data));
  const ids = idsOf(r.findings);
  assert.ok(!ids.includes('PASSROLE-LAMBDA'), 'PassRole pinned to ec2 must not open a Lambda path');
  assert.ok(!ids.includes('PASSROLE-EC2'), 'no ec2 execution action -> no ec2 path');
});

test('acceptance: assume-role/ positive fixtures are detected; scoped assume is not', () => {
  const fixtures = loadFixtures('assume-role');
  assert.ok(fixtures.length > 0, 'assume-role/ has no fixtures');
  const trust = fixtures.find(({ file }) => /update-assume-role-policy-positive/.test(file));
  const wildcard = fixtures.find(({ file }) => /assume-role-wildcard-positive/.test(file));
  const scoped = fixtures.find(({ file }) => /scoped-negative/.test(file));
  assert.ok(trust && wildcard && scoped, 'assume-role/ missing expected fixtures');
  assert.ok(idsOf(analyzeEscalationsFromText(fixtureText(trust.data)).findings).includes('TRUST-POLICY-MODIFY'));
  assert.ok(idsOf(analyzeEscalationsFromText(fixtureText(wildcard.data)).findings).includes('ASSUME-ROLE-EXPANSION'));
  assert.deepEqual(idsOf(analyzeEscalationsFromText(fixtureText(scoped.data)).findings), []);
});

test('story: at least 5 escalation families each have a positive fixture producing them', () => {
  const producedIds = new Set();
  for (const category of ESCALATION_CATEGORIES) {
    for (const { data } of loadFixtures(category)) {
      const r = analyzeEscalationsFromText(fixtureText(data));
      if (r.ok) for (const f of r.findings) producedIds.add(f.id);
    }
  }
  assert.ok(producedIds.size >= 5, `expected >=5 escalation families with fixtures, got ${producedIds.size}: ${[...producedIds].sort()}`);
  assert.ok(producedIds.size <= ESCALATION_IDS.length, 'produced ids must be a subset of the catalog');
  // Catalog itself stays within the story bound of 5-10 escalation paths.
  assert.ok(ESCALATION_IDS.length >= 5 && ESCALATION_IDS.length <= 10, `catalog must define 5-10 paths, has ${ESCALATION_IDS.length}`);
});

// ---------------------------------------------------------------------------
// PassRole family direct assertions.
// ---------------------------------------------------------------------------

// IAM-102: a compound PassRole + service-execution path crosses a privilege
// boundary, so it is CRITICAL. IAM-104: both perms are present in the policy ->
// policyEvidence high; the passed role's power is unknown -> pathExploitability
// medium (never above the evidence).
test('PassRole (pinned to lambda) + lambda:CreateFunction -> PASSROLE-LAMBDA (critical, confirmed)', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Sid: 'pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::1:role/app-*', Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } },
      { Sid: 'run', Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'PASSROLE-LAMBDA');
  assert.ok(f, 'expected PASSROLE-LAMBDA');
  assert.equal(f.severity, 'critical');
  assert.equal(f.policyEvidence, 'high');
  assert.equal(f.pathExploitability, 'medium');
  assert.equal(f.escalation.service, 'lambda');
  // Evidence spans both the pass and the execute statements.
  const roles = f.evidence.map((e) => e.role).sort();
  assert.deepEqual(roles, ['execute', 'pass']);
});

// IAM-105: a compound PassRole->service path exposes a present/absent
// risk-factor checklist reflecting the grants + scope conditions that make it
// up. Single-action primitives carry null riskFactors.
test('PASSROLE-LAMBDA exposes a risk-factor checklist (IAM-105)', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Sid: 'pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::1:role/app-*', Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } },
      { Sid: 'run', Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'PASSROLE-LAMBDA');
  assert.ok(Array.isArray(f.riskFactors) && f.riskFactors.length > 0, 'checklist present');
  const by = (k) => f.riskFactors.find((rf) => rf.key === k);
  assert.equal(by('pass-role').present, true, 'iam:PassRole granted');
  assert.equal(by('lambda:CreateFunction').present, true, 'exec action granted');
  assert.equal(by('exec-resource-wildcard').present, true, 'exec Resource is "*"');
  // Pinned to lambda via iam:PassedToService -> the restriction IS present.
  assert.equal(by('passed-to-service-restriction').present, true, 'PassedToService restriction present');
  for (const rf of f.riskFactors) {
    assert.equal(typeof rf.label, 'string');
    assert.equal(typeof rf.present, 'boolean');
  }
});

test('unpinned PassRole path marks the PassedToService restriction ABSENT (IAM-105)', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::1:role/*' },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'PASSROLE-EC2');
  const by = (k) => f.riskFactors.find((rf) => rf.key === k);
  assert.equal(by('passed-to-service-restriction').present, false, 'no PassedToService -> absent');
  assert.equal(by('pass-role-resource-wildcard').present, true, 'PassRole scoped to role/* is broad');
});

test('single-action escalation primitives carry null riskFactors (IAM-105)', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'iam:CreatePolicyVersion', Resource: '*' }],
  }));
  const f = r.findings.find((x) => x.id === 'POLICY-VERSION');
  assert.ok(f, 'expected POLICY-VERSION');
  assert.equal(f.riskFactors, null, 'primitive has no compound checklist');
});

test('PassRole ALONE (no service-execution action) -> no finding', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::1:role/app-*' }],
  }));
  assert.deepEqual(idsOf(r.findings), []);
});

test('service-execution action ALONE (no PassRole) -> no finding', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' }],
  }));
  assert.ok(!idsOf(r.findings).includes('PASSROLE-LAMBDA'));
});

test('unpinned PassRole (no PassedToService) + ec2:RunInstances -> PASSROLE-EC2 (critical)', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'PASSROLE-EC2');
  assert.ok(f, 'expected PASSROLE-EC2');
  assert.equal(f.severity, 'critical'); // IAM-102: compound path is critical
});

// IAM-103 wording precision on the PassRole family.
test('PassRole+service why is precise: potential execution + PassedToService phrasing', () => {
  const unpinned = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  }));
  const f = unpinned.findings.find((x) => x.id === 'PASSROLE-EC2');
  assert.ok(f, 'expected PASSROLE-EC2');
  // Definitive "gaining the role's permissions" claim must be gone.
  assert.ok(!/gaining the role/i.test(f.why), 'must not definitively claim gaining the role permissions');
  assert.ok(/potentially obtaining execution/i.test(f.why), 'must use potential-execution wording');
  // Unpinned PassRole wording is about restricting supported services, not
  // "can pass a role to this service".
  assert.ok(/does not use iam:PassedToService to restrict/i.test(f.why), 'must use precise PassedToService wording');
  assert.ok(!/it can pass a role to this service/i.test(f.why), 'old overstated PassedToService phrasing must be gone');
});

test('ASSUME-ROLE-EXPANSION why is cross-account accurate (not "many roles in the account")', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::*:role/*' }],
  }));
  const f = r.findings.find((x) => x.id === 'ASSUME-ROLE-EXPANSION');
  assert.ok(f, 'expected ASSUME-ROLE-EXPANSION');
  assert.ok(!/many roles in the account/i.test(f.why), 'must drop the single-account "many roles in the account" claim');
  assert.ok(/arbitrary AWS accounts/i.test(f.why), 'must state roles can span arbitrary accounts');
  assert.ok(/trust policies/i.test(f.why), 'must condition reachability on trust policies');
});

test('ASSUME-ROLE-EXPANSION why does NOT claim cross-account reach for a single-account role-name wildcard', () => {
  // arn:aws:iam::111122223333:role/* is broad WITHIN one account, not across.
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::111122223333:role/*' }],
  }));
  const f = r.findings.find((x) => x.id === 'ASSUME-ROLE-EXPANSION');
  assert.ok(f, 'expected ASSUME-ROLE-EXPANSION');
  assert.ok(!/arbitrary AWS accounts/i.test(f.why), 'must NOT claim arbitrary AWS accounts for a concrete-account grant');
  assert.ok(!/spans every account/i.test(f.why), 'must NOT claim it spans every account');
  assert.ok(/account 111122223333/i.test(f.why), 'must confine the scope to the named account');
  assert.ok(/within that account/i.test(f.why), 'must scope the reach to that one account');
  assert.ok(/trust policies/i.test(f.why), 'must condition reachability on trust policies');
});

test('ASSUME-ROLE-EXPANSION why confines a partial role-name wildcard (role/app-*) to its account', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::111122223333:role/app-*' }],
  }));
  const f = r.findings.find((x) => x.id === 'ASSUME-ROLE-EXPANSION');
  assert.ok(f, 'expected ASSUME-ROLE-EXPANSION');
  assert.ok(!/arbitrary AWS accounts/i.test(f.why), 'must NOT claim cross-account reach');
  assert.ok(/account 111122223333/i.test(f.why), 'must confine the scope to the named account');
});

test('PassRole pinned to a different service does not open a path for the granted action', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { StringEquals: { 'iam:PassedToService': 'ec2.amazonaws.com' } } },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
    ],
  }));
  const ids = idsOf(r.findings);
  assert.ok(!ids.includes('PASSROLE-LAMBDA'));
  assert.ok(!ids.includes('PASSROLE-EC2'));
});

test('iam:* + lambda:* is recognized as PASSROLE-LAMBDA (service wildcards grant the combo)', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: ['iam:*', 'lambda:*'], Resource: '*' }],
  }));
  assert.ok(idsOf(r.findings).includes('PASSROLE-LAMBDA'));
});

test('a bare "*" action surfaces every escalation path it contains (de-facto admin)', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
  }));
  // Action:"*" grants EVERY action, so it necessarily grants iam:PassRole +
  // every service-execution action, sts:AssumeRole over all roles, and every
  // direct-IAM self-administration primitive. Reporting zero escalation paths
  // for full admin (while a strictly narrower iam:* yields several) understates
  // the blast radius - a truthfulness harm (threat-model T8), so "*" must
  // surface the paths it contains rather than stay silent.
  const ids = new Set(idsOf(r.findings));
  for (const want of [
    'PASSROLE-LAMBDA', 'PASSROLE-EC2', 'PASSROLE-SERVICE',
    'POLICY-VERSION', 'ATTACH-POLICY', 'PUT-INLINE-POLICY',
    'TRUST-POLICY-MODIFY', 'CREDENTIAL-CREATION', 'ASSUME-ROLE-EXPANSION',
  ]) {
    assert.ok(ids.has(want), `"*" must surface ${want}; got [${[...ids].join(', ')}]`);
  }
  // The compound PassRole paths and the all-roles AssumeRole are critical; the
  // standalone direct-IAM primitives are high. None is understated.
  const bySeverity = (id) => r.findings.filter((f) => f.id === id).map((f) => f.severity);
  assert.ok(bySeverity('PASSROLE-LAMBDA').every((s) => s === 'critical'), 'PassRole path critical');
  assert.ok(bySeverity('ASSUME-ROLE-EXPANSION').every((s) => s === 'critical'), 'all-roles AssumeRole critical');
  assert.ok(bySeverity('ATTACH-POLICY').every((s) => s === 'high'), 'attach-policy primitive high');
});

// ---------------------------------------------------------------------------
// Single-action / broad-scope families.
// ---------------------------------------------------------------------------

test('iam:CreatePolicyVersion -> POLICY-VERSION', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'iam:CreatePolicyVersion', Resource: 'arn:aws:iam::1:policy/p' }],
  }));
  assert.ok(idsOf(r.findings).includes('POLICY-VERSION'));
});

// IAM-102: attach/put-policy-to-self are standalone direct-IAM primitives, so
// they are HIGH, not critical (critical is reserved for compound paths).
test('iam:AttachRolePolicy -> ATTACH-POLICY (high); iam:PutRolePolicy -> PUT-INLINE-POLICY (high)', () => {
  const attach = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'iam:AttachRolePolicy', Resource: '*' }],
  }));
  const af = attach.findings.find((f) => f.id === 'ATTACH-POLICY');
  assert.ok(af);
  assert.equal(af.severity, 'high');

  const put = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'iam:PutRolePolicy', Resource: '*' }],
  }));
  const pf = put.findings.find((f) => f.id === 'PUT-INLINE-POLICY');
  assert.ok(pf);
  assert.equal(pf.severity, 'high');
});

test('iam:UpdateAssumeRolePolicy -> TRUST-POLICY-MODIFY', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'iam:UpdateAssumeRolePolicy', Resource: '*' }],
  }));
  assert.ok(idsOf(r.findings).includes('TRUST-POLICY-MODIFY'));
});

test('iam:CreateAccessKey -> CREDENTIAL-CREATION', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'iam:CreateAccessKey', Resource: 'arn:aws:iam::1:user/*' }],
  }));
  assert.ok(idsOf(r.findings).includes('CREDENTIAL-CREATION'));
});

test('sts:AssumeRole on "*" -> ASSUME-ROLE-EXPANSION (evidence high, exploitability medium: target unknown); scoped single role -> none', () => {
  const broad = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: '*' }],
  }));
  const bf = broad.findings.find((f) => f.id === 'ASSUME-ROLE-EXPANSION');
  assert.ok(bf);
  // IAM-104: the grant + wildcard scope are plainly in the policy (evidence
  // high); which roles are reachable and how privileged is unknown, so the
  // expansion is only POTENTIAL (exploitability medium).
  assert.equal(bf.policyEvidence, 'high');
  assert.equal(bf.pathExploitability, 'medium');

  const scoped = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::1:role/one' }],
  }));
  assert.ok(!idsOf(scoped.findings).includes('ASSUME-ROLE-EXPANSION'));
});

// ---------------------------------------------------------------------------
// Deny statements never open a path.
// ---------------------------------------------------------------------------

test('a Deny on the escalation action does not itself create a path', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Deny', Action: ['iam:PassRole', 'lambda:CreateFunction'], Resource: '*' }],
  }));
  assert.deepEqual(idsOf(r.findings), []);
});

// ---------------------------------------------------------------------------
// Condition lowers confidence but never suppresses a path.
// ---------------------------------------------------------------------------

test('a non-confirming Condition drops escalation confidence and annotates the limit', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{
      Effect: 'Allow', Action: 'iam:UpdateAssumeRolePolicy', Resource: '*',
      Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } },
    }],
  }));
  const f = r.findings.find((x) => x.id === 'TRUST-POLICY-MODIFY');
  assert.ok(f);
  // A gating Condition weakens BOTH signals one notch: evidence high->medium,
  // exploitability medium->low.
  assert.equal(f.policyEvidence, 'medium');
  assert.equal(f.pathExploitability, 'low');
  assert.ok(/Condition/.test(f.limit));
  assert.notEqual(f.conditions, null);
});

// ---------------------------------------------------------------------------
// Same-policy explicit-Deny precedence (AWS: explicit Deny overrides Allow).
// ---------------------------------------------------------------------------

test('unconditional in-scope Deny of an escalation action suppresses the path', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:AttachRolePolicy', Resource: '*' },
      { Effect: 'Deny', Action: 'iam:AttachRolePolicy', Resource: '*' },
    ],
  }));
  // Explicit Deny overrides Allow: the capability does not exist -> no finding,
  // and the engine must not assert "Grants iam:Attach...Policy".
  assert.deepEqual(idsOf(r.findings), []);
});

test('unconditional Deny on "*" suppresses even a scoped Allow', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PutRolePolicy', Resource: 'arn:aws:iam::1:role/app' },
      { Effect: 'Deny', Action: 'iam:PutRolePolicy', Resource: '*' },
    ],
  }));
  assert.ok(!idsOf(r.findings).includes('PUT-INLINE-POLICY'));
});

test('a CONDITIONAL Deny does not suppress but reduces confidence and annotates the limit', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:AttachRolePolicy', Resource: '*' },
      {
        Effect: 'Deny', Action: 'iam:AttachRolePolicy', Resource: '*',
        Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } },
      },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'ATTACH-POLICY');
  assert.ok(f, 'conditional Deny must NOT suppress the path (would be a false deny)');
  // A possibly-blocking Deny weakens BOTH signals one notch: attach-policy is
  // evidence high / exploitability high, so both drop to medium.
  assert.equal(f.policyEvidence, 'medium');
  assert.equal(f.pathExploitability, 'medium');
  assert.ok(/Deny/.test(f.limit), 'limit must note the possibly-blocking Deny');
});

test('a Deny of a DIFFERENT action leaves the path intact', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:AttachRolePolicy', Resource: '*' },
      { Effect: 'Deny', Action: 'iam:CreateAccessKey', Resource: '*' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'ATTACH-POLICY');
  assert.ok(f);
  assert.equal(f.policyEvidence, 'high'); // unrelated Deny -> no downgrade
  assert.equal(f.pathExploitability, 'high');
});

test('an unconditional Deny of iam:PassRole removes the whole PassRole path', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
      { Effect: 'Deny', Action: 'iam:PassRole', Resource: '*' },
    ],
  }));
  assert.ok(!idsOf(r.findings).includes('PASSROLE-LAMBDA'));
});

test('an unconditional Deny of every execution action removes the PassRole path', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
      { Effect: 'Deny', Action: 'lambda:CreateFunction', Resource: '*' },
    ],
  }));
  assert.ok(!idsOf(r.findings).includes('PASSROLE-LAMBDA'));
});

test('a Deny covering ONE exec statement does not hide a path granted by ANOTHER exec statement', () => {
  // Multi-statement regression: S0 PassRole->lambda; S1 lambda:CreateFunction on
  // function:foo; S2 lambda:UpdateFunctionCode on function:bar; S3 Deny
  // lambda:CreateFunction on function:foo (full coverage of S1 only). S1 is fully
  // removed, but S0+S2 is a live, un-denied Lambda escalation path. Suppressing on
  // the first-selected exec statement alone would be a false-safe / false negative
  // (threat-model T8). PASSROLE-LAMBDA must still be reported, anchored on the
  // surviving statement, and must NOT claim the denied lambda:CreateFunction.
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Sid: 'pass', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } },
      { Sid: 'create', Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: 'arn:aws:lambda:us-east-1:111122223333:function:foo' },
      { Sid: 'update', Effect: 'Allow', Action: 'lambda:UpdateFunctionCode', Resource: 'arn:aws:lambda:us-east-1:111122223333:function:bar' },
      { Sid: 'deny', Effect: 'Deny', Action: 'lambda:CreateFunction', Resource: 'arn:aws:lambda:us-east-1:111122223333:function:foo' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'PASSROLE-LAMBDA');
  assert.ok(f, 'PASSROLE-LAMBDA must survive: S0+S2 is an un-denied Lambda path');
  // The definitively-denied exec action must not be claimed as a live grant.
  assert.ok(!f.actions.includes('lambda:CreateFunction'), 'denied exec action must not be claimed as granted');
  assert.ok(f.actions.includes('lambda:UpdateFunctionCode'), 'the surviving exec action must anchor the path');
  // The surviving path (S0 pass + S2 exec) is un-denied on both legs, so it is
  // reported at full evidence - the Deny only removed the S1 branch. Path
  // exploitability stays medium (the passed role's power is still unknown).
  assert.equal(f.policyEvidence, 'high', 'the surviving path is un-denied on both legs -> not downgraded');
  assert.equal(f.pathExploitability, 'medium');
});

test('a Deny covering ONE PassRole grant does not hide a path via ANOTHER permitting PassRole grant', () => {
  // Symmetric case on the pass side: S0 PassRole->lambda pinned but Denied by S3;
  // S1 PassRole unpinned (permits lambda) un-denied; S2 lambda:CreateFunction.
  // The path survives via S1+S2.
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Sid: 'pass-pinned', Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::1:role/pinned', Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } },
      { Sid: 'pass-open', Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::1:role/open' },
      { Sid: 'run', Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
      { Sid: 'deny-pinned', Effect: 'Deny', Action: 'iam:PassRole', Resource: 'arn:aws:iam::1:role/pinned' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'PASSROLE-LAMBDA');
  assert.ok(f, 'PASSROLE-LAMBDA must survive via the un-denied PassRole grant');
});

test('a Deny covering ALL exec statements still suppresses the PassRole path', () => {
  // Control for the multi-statement fix: when EVERY exec candidate is fully,
  // in-scope denied, the path genuinely does not exist -> suppressed.
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: 'arn:aws:lambda:us-east-1:1:function:foo' },
      { Effect: 'Allow', Action: 'lambda:UpdateFunctionCode', Resource: 'arn:aws:lambda:us-east-1:1:function:bar' },
      { Effect: 'Deny', Action: ['lambda:CreateFunction', 'lambda:UpdateFunctionCode'], Resource: '*' },
    ],
  }));
  assert.ok(!idsOf(r.findings).includes('PASSROLE-LAMBDA'), 'every exec statement denied -> path suppressed');
});

test('a NotAction-Deny does NOT suppress a broad iam:* escalation grant (path survives, downgraded)', () => {
  // Allow iam:* + Deny NotAction:iam:CreateAccessKey. The Deny denies everything
  // EXCEPT iam:CreateAccessKey, so that credential-creation primitive SURVIVES
  // and CREDENTIAL-CREATION must still be reported. A NotAction-Deny can never
  // fully cover the broad iam:* grant token (the preserved action stays allowed),
  // so suppressing the path would be a false-safe / false negative (T8).
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:*', Resource: '*' },
      { Effect: 'Deny', NotAction: 'iam:CreateAccessKey', Resource: '*' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'CREDENTIAL-CREATION');
  assert.ok(f, 'CREDENTIAL-CREATION must survive a NotAction-Deny that preserves iam:CreateAccessKey');
  // Narrowed, not blocked: both signals downgraded one notch and the Deny noted.
  // CREDENTIAL-CREATION bases evidence high / exploitability medium (target
  // principal's privileges unknown, IAM-104 F1), so the narrow drops them to
  // medium / low respectively.
  assert.equal(f.policyEvidence, 'medium', 'a possibly-blocking Deny narrows -> evidence downgraded');
  assert.equal(f.pathExploitability, 'low');
  assert.ok(/Deny/.test(f.limit), 'limit must note the possibly-blocking Deny');
});

test('control: a POSITIVE-action Deny of iam:* DOES suppress the iam:* escalation grants', () => {
  // Contrast: Allow iam:* + Deny iam:* (positive Action) covers the whole grant,
  // so every iam:* escalation path is genuinely blocked and suppressed.
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:*', Resource: '*' },
      { Effect: 'Deny', Action: 'iam:*', Resource: '*' },
    ],
  }));
  const ids = idsOf(r.findings);
  assert.ok(!ids.includes('CREDENTIAL-CREATION'), 'a positive iam:* Deny fully covers the grant -> suppressed');
  assert.ok(!ids.includes('ATTACH-POLICY'));
  assert.ok(!ids.includes('PUT-INLINE-POLICY'));
});

test('a Deny of ONE of several attach actions keeps the path via the others', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: ['iam:AttachRolePolicy', 'iam:AttachUserPolicy'], Resource: '*' },
      { Effect: 'Deny', Action: 'iam:AttachRolePolicy', Resource: '*' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'ATTACH-POLICY');
  assert.ok(f, 'path still exists via the non-denied action');
  // The definitively-denied action must be dropped from the asserted grants.
  assert.ok(!f.actions.includes('iam:AttachRolePolicy'), 'denied action must not be claimed as granted');
  assert.ok(f.actions.includes('iam:AttachUserPolicy'));
  assert.equal(f.policyEvidence, 'medium'); // narrowed -> downgraded
  assert.equal(f.pathExploitability, 'medium');
});

// ---------------------------------------------------------------------------
// iam:PassedToService operator semantics (allowlist vs denylist vs uncertain).
// ---------------------------------------------------------------------------

test('StringNotEquals iam:PassedToService is a DENYLIST (pass to any service except the listed)', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { StringNotEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } } },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  }));
  const ids = idsOf(r.findings);
  // Correct AWS semantics: may pass to any service EXCEPT lambda.
  assert.ok(!ids.includes('PASSROLE-LAMBDA'), 'StringNotEquals=lambda must BLOCK the Lambda path (not open it)');
  assert.ok(ids.includes('PASSROLE-EC2'), 'StringNotEquals=lambda must permit the EC2 path');
});

test('StringNotLike iam:PassedToService denylist blocks the matching service', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { StringNotLike: { 'iam:PassedToService': 'ec2.*' } } },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
    ],
  }));
  const ids = idsOf(r.findings);
  assert.ok(!ids.includes('PASSROLE-EC2'), 'StringNotLike ec2.* must block the EC2 path');
  assert.ok(ids.includes('PASSROLE-LAMBDA'), 'StringNotLike ec2.* must permit the Lambda path');
});

test('StringEquals iam:PassedToService remains an ALLOWLIST (regression guard)', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { StringEquals: { 'iam:PassedToService': 'ec2.amazonaws.com' } } },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  }));
  const ids = idsOf(r.findings);
  assert.ok(ids.includes('PASSROLE-EC2'));
  assert.ok(!ids.includes('PASSROLE-LAMBDA'));
});

test('Null iam:PassedToService is UNCERTAIN: path kept but confidence reduced and annotated', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { Null: { 'iam:PassedToService': 'true' } } },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'PASSROLE-LAMBDA');
  assert.ok(f, 'unresolved operator must not silently drop the path (false negative)');
  // An unresolved PassedToService operator is a gate: evidence high->medium and
  // exploitability medium->low. Evidence must not stay at high.
  assert.notEqual(f.policyEvidence, 'high', 'unresolved operator must not be asserted at high policy evidence');
  assert.equal(f.policyEvidence, 'medium');
  assert.equal(f.pathExploitability, 'low');
  assert.ok(/uncertain/i.test(f.limit), 'limit must flag the unresolved PassedToService operator');
});

test('ForAnyValue:StringEquals is normalized to allowlist semantics', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*', Condition: { 'ForAnyValue:StringEquals': { 'iam:PassedToService': 'lambda.amazonaws.com' } } },
      { Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  }));
  const ids = idsOf(r.findings);
  assert.ok(ids.includes('PASSROLE-LAMBDA'));
  assert.ok(!ids.includes('PASSROLE-EC2'), 'allowlist pinned to lambda must block ec2');
});

// ---------------------------------------------------------------------------
// ASSUME-ROLE-EXPANSION broad/scoped discriminator boundaries.
// ---------------------------------------------------------------------------

test('partial-wildcard role path (role/app-*) is broad -> ASSUME-ROLE-EXPANSION', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::1:role/app-*' }],
  }));
  assert.ok(idsOf(r.findings).includes('ASSUME-ROLE-EXPANSION'), 'a wildcarded role path reaches many roles and must be flagged');
});

test('a "?" wildcard in the role path is broad -> ASSUME-ROLE-EXPANSION', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::1:role/app-?' }],
  }));
  assert.ok(idsOf(r.findings).includes('ASSUME-ROLE-EXPANSION'));
});

test('NotResource-scoped AssumeRole is broad (inverse scope) -> ASSUME-ROLE-EXPANSION', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', NotResource: 'arn:aws:iam::1:role/break-glass' }],
  }));
  assert.ok(idsOf(r.findings).includes('ASSUME-ROLE-EXPANSION'));
});

test('AssumeRole with no Resource/NotResource is unspecified/broad -> ASSUME-ROLE-EXPANSION', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole' }],
  }));
  assert.ok(idsOf(r.findings).includes('ASSUME-ROLE-EXPANSION'));
});

// ---------------------------------------------------------------------------
// IAM-102 severity model: critical is reserved for compound privilege-boundary
// crossings. Broad AssumeRole (effectively all roles) is critical; a partial
// role-name wildcard stays high; standalone single-action primitives stay high.
// ---------------------------------------------------------------------------

test('ASSUME-ROLE-EXPANSION over all roles (arn:...:*:role/*) is critical', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::*:role/*' }],
  }));
  const f = r.findings.find((x) => x.id === 'ASSUME-ROLE-EXPANSION');
  assert.ok(f, 'expected ASSUME-ROLE-EXPANSION');
  assert.equal(f.severity, 'critical');
  // Severity is orthogonal to both certainty signals. Evidence is high (the
  // grant + all-roles scope are in the policy); exploitability is medium (which
  // roles are reachable and how privileged they are is unknown).
  assert.equal(f.policyEvidence, 'high');
  assert.equal(f.pathExploitability, 'medium');
});

test('ASSUME-ROLE-EXPANSION over all roles in ONE account (role/*) is still critical', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::111122223333:role/*' }],
  }));
  const f = r.findings.find((x) => x.id === 'ASSUME-ROLE-EXPANSION');
  assert.ok(f);
  assert.equal(f.severity, 'critical'); // role-name axis fully open -> all roles
});

test('ASSUME-ROLE-EXPANSION on a bare "*" resource is critical', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: '*' }],
  }));
  const f = r.findings.find((x) => x.id === 'ASSUME-ROLE-EXPANSION');
  assert.ok(f);
  assert.equal(f.severity, 'critical');
});

test('ASSUME-ROLE-EXPANSION with a PARTIAL role-name wildcard (role/app-*) stays high', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', Resource: 'arn:aws:iam::111122223333:role/app-*' }],
  }));
  const f = r.findings.find((x) => x.id === 'ASSUME-ROLE-EXPANSION');
  assert.ok(f, 'a wildcarded role path is still flagged');
  assert.equal(f.severity, 'high'); // many roles, but not ALL -> not critical
});

test('ASSUME-ROLE-EXPANSION with NotResource (inverse, ~all roles) is critical', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRole', NotResource: 'arn:aws:iam::1:role/break-glass' }],
  }));
  const f = r.findings.find((x) => x.id === 'ASSUME-ROLE-EXPANSION');
  assert.ok(f);
  assert.equal(f.severity, 'critical');
});

test('standalone single-action escalation primitives stay high (not critical)', () => {
  const cases = [
    ['POLICY-VERSION', { Effect: 'Allow', Action: 'iam:CreatePolicyVersion', Resource: 'arn:aws:iam::1:policy/p' }],
    ['TRUST-POLICY-MODIFY', { Effect: 'Allow', Action: 'iam:UpdateAssumeRolePolicy', Resource: '*' }],
    ['CREDENTIAL-CREATION', { Effect: 'Allow', Action: 'iam:CreateAccessKey', Resource: 'arn:aws:iam::1:user/*' }],
  ];
  for (const [id, stmt] of cases) {
    const r = analyzeEscalationsFromText(JSON.stringify({ Statement: [stmt] }));
    const f = r.findings.find((x) => x.id === id);
    assert.ok(f, `expected ${id}`);
    assert.equal(f.severity, 'high', `${id} must stay high (standalone primitive)`);
  }
});

// ---------------------------------------------------------------------------
// Determinism + frozen output.
// ---------------------------------------------------------------------------

test('analyzeEscalations is deterministic and deeply frozen', () => {
  const text = JSON.stringify({
    Statement: [
      { Sid: 'a', Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
      { Sid: 'b', Effect: 'Allow', Action: ['lambda:CreateFunction', 'ec2:RunInstances'], Resource: '*' },
      { Sid: 'c', Effect: 'Allow', Action: 'iam:AttachRolePolicy', Resource: '*' },
    ],
  });
  const a = analyzeEscalations(modelFromText(text).model);
  const b = analyzeEscalations(modelFromText(text).model);
  assert.deepEqual(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(b)));
  assert.ok(Object.isFrozen(a));
  assert.ok(Object.isFrozen(a.findings));
  if (a.findings.length > 0) {
    assert.ok(Object.isFrozen(a.findings[0]));
    assert.ok(Object.isFrozen(a.findings[0].actions));
    assert.ok(Object.isFrozen(a.findings[0].escalation));
  }
});

test('findings are ordered by anchor statement index then escalation order', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Effect: 'Allow', Action: 'iam:AttachRolePolicy', Resource: '*' },
      { Effect: 'Allow', Action: 'iam:CreateAccessKey', Resource: 'arn:aws:iam::1:user/*' },
    ],
  }));
  const seq = r.findings.map((f) => [f.statementIndex, ESCALATIONS[f.id].order]);
  const sorted = [...seq].sort((x, y) => (x[0] - y[0]) || (x[1] - y[1]));
  assert.deepEqual(seq, sorted);
});

// ---------------------------------------------------------------------------
// Hostile / malformed input never throws (threat-model T5), no pollution (T3),
// XSS payloads pass through inert (T1).
// ---------------------------------------------------------------------------

test('analyzeEscalations never throws on a bad model', () => {
  assert.doesNotThrow(() => {
    const r = analyzeEscalations(null);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.code === 'NO_MODEL'));
  });
  assert.doesNotThrow(() => {
    const r = analyzeEscalations({ statements: 'nope' });
    assert.equal(r.ok, false);
  });
});

test('analyzeEscalationsFromText surfaces validation errors and never throws', () => {
  for (const { file, data } of [...loadFixtures('malformed'), ...loadFixtures('adversarial')]) {
    assert.doesNotThrow(() => {
      const r = analyzeEscalationsFromText(fixtureText(data));
      assert.ok(typeof r.ok === 'boolean', `${file}: missing ok`);
      assert.ok(Array.isArray(r.findings), `${file}: missing findings`);
      if (data.expect && data.expect.valid === false) {
        assert.equal(r.ok, false, `${file}: expected validation failure`);
        assert.deepEqual(r.findings, [], `${file}: rejected input must yield no findings`);
      }
    }, `${file}: analyzeEscalationsFromText threw`);
  }
});

test('empty policy produces no escalation findings', () => {
  const r = analyzeEscalations({ statements: [] });
  assert.equal(r.ok, true);
  assert.deepEqual(r.findings, []);
});

test('XSS-laden SID/ARN pass through escalation findings as inert strings', () => {
  const r = analyzeEscalationsFromText(JSON.stringify({
    Statement: [
      { Sid: '<img src=x onerror=alert(1)>', Effect: 'Allow', Action: 'iam:AttachRolePolicy', Resource: 'arn:aws:iam::1:role/<svg/onload=alert(1)>' },
    ],
  }));
  const f = r.findings.find((x) => x.id === 'ATTACH-POLICY');
  assert.ok(f);
  assert.equal(f.statementSid, '<img src=x onerror=alert(1)>');
  assert.equal(typeof f.statementSid, 'string');
});

test('analyzing input does not pollute Object.prototype', () => {
  analyzeEscalationsFromText(
    '{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"__proto__":{"polluted":true}}}}]}',
  );
  assert.equal(({}).polluted, undefined);
});

// ---------------------------------------------------------------------------
// safe/ fixtures must produce zero escalation findings (no false paths).
// ---------------------------------------------------------------------------

test('safe/ fixtures produce zero escalation findings', () => {
  const fixtures = loadFixtures('safe');
  assert.ok(fixtures.length > 0, 'safe/ has no fixtures');
  for (const { file, data } of fixtures) {
    const r = analyzeEscalationsFromText(fixtureText(data));
    assert.equal(r.ok, true, `${file}: analyze not ok`);
    assert.deepEqual(idsOf(r.findings), [], `${file}: safe fixture produced escalation findings`);
  }
});
