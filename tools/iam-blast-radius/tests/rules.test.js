// Unit tests for IAM-004: risk-rule catalog (wildcard, direct-IAM, destructive,
// exfil, detection-impairment). Runs on node's built-in runner: `node --test`.
//
// Acceptance (prd.json IAM-004):
//   - wildcard/ fixtures produce expected findings; safe/ produce none
//   - every finding has all required fields
//   - IAM critic 100 (no false allow/deny) - encoded as: no false positive on
//     safe / negative fixtures, no false negative on positive fixtures
//   - reliability critic >=95 - deterministic, frozen, never throws
//
// Canonical finding shape (docs/architecture.md): id, severity, title,
// statementSid, actions, resources, conditions, confidence, why, limit,
// remediation, ruleVersion, docRef.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import {
  analyzeRules,
  analyzeRulesFromText,
  RULES,
  RULE_IDS,
} from '../../../content/tools/iam-blast-radius/engine/rules.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const CONFIDENCES = new Set(['high', 'medium', 'low']);
const RULE_ID_SET = new Set(RULE_IDS);

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

// Assert the canonical shape on every finding. Load-bearing for the "every
// finding has all required fields" acceptance criterion.
function assertFindingShape(f, ctx) {
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
  assert.ok(RULE_ID_SET.has(f.id), `${ctx}: unknown rule id ${f.id}`);
  assert.ok(SEVERITIES.has(f.severity), `${ctx}: bad severity ${f.severity}`);
  // IAM-104: the single confidence field is replaced by two orthogonal signals.
  assert.ok(!('confidence' in f), `${ctx}: legacy confidence field must be gone`);
  assert.ok(CONFIDENCES.has(f.policyEvidence), `${ctx}: bad policyEvidence ${f.policyEvidence}`);
  assert.ok(CONFIDENCES.has(f.pathExploitability), `${ctx}: bad pathExploitability ${f.pathExploitability}`);
  assert.ok(typeof f.title === 'string' && f.title.length > 0, `${ctx}: empty title`);
  assert.ok(typeof f.statementSid === 'string' && f.statementSid.length > 0, `${ctx}: empty statementSid`);
  assert.ok(Array.isArray(f.actions) && f.actions.length > 0, `${ctx}: actions must be a non-empty array`);
  assert.ok(Array.isArray(f.resources), `${ctx}: resources must be an array`);
  assert.ok('conditions' in f, `${ctx}: conditions field must be present (null allowed)`);
  assert.ok(typeof f.why === 'string' && f.why.length > 0, `${ctx}: empty why`);
  assert.ok(typeof f.limit === 'string' && /not effective access/i.test(f.limit), `${ctx}: limit must carry the capability-not-effective caveat`);
  assert.ok(typeof f.remediation === 'string' && f.remediation.length > 0, `${ctx}: empty remediation`);
  assert.equal(f.ruleVersion, RULES[f.id].ruleVersion, `${ctx}: ruleVersion mismatch`);
  assert.ok(/^https:\/\/docs\.aws\.amazon\.com\//.test(f.docRef), `${ctx}: docRef must be an AWS docs URL`);
}

// ---------------------------------------------------------------------------
// Fixture-driven assertions across every rule category.
// ---------------------------------------------------------------------------

const RULE_CATEGORIES = [
  'wildcard', 'safe', 'direct-iam', 'destructive', 'exfil', 'detection',
  'notaction-allow',
];

for (const category of RULE_CATEGORIES) {
  for (const { file, data } of loadFixtures(category)) {
    const exp = data.expect || {};
    const carries =
      Array.isArray(exp.findingIds) ||
      Array.isArray(exp.notFindingIds) ||
      Array.isArray(exp.exactFindingIds) ||
      category === 'safe';
    if (!carries) continue;

    test(`fixture ${file}: rule findings match expectations`, () => {
      const r = analyzeRulesFromText(fixtureText(data));
      assert.equal(r.ok, true, `${file}: analyze not ok: ${JSON.stringify(r.errors)}`);
      const actual = idsOf(r.findings);
      const actualSet = new Set(actual);

      // Every finding is well-formed regardless of the assertion style.
      for (const f of r.findings) assertFindingShape(f, file);

      // safe/ must produce NO findings at all (acceptance: "safe produce none").
      if (category === 'safe') {
        assert.deepEqual(actual, [], `${file}: safe fixture produced findings ${JSON.stringify(actual)}`);
      }

      // Positive: required rule ids present.
      if (Array.isArray(exp.findingIds)) {
        for (const id of exp.findingIds) {
          if (!RULE_ID_SET.has(id)) continue; // escalation ids belong to IAM-005
          assert.ok(actualSet.has(id), `${file}: expected finding ${id}, got ${JSON.stringify(actual)}`);
        }
      }
      // Negative: forbidden rule ids absent.
      if (Array.isArray(exp.notFindingIds)) {
        for (const id of exp.notFindingIds) {
          if (!RULE_ID_SET.has(id)) continue;
          assert.ok(!actualSet.has(id), `${file}: finding ${id} must NOT be produced, got ${JSON.stringify(actual)}`);
        }
      }
      // Exact (strongest): the full set of rule ids equals this list.
      if (Array.isArray(exp.exactFindingIds)) {
        assert.deepEqual(
          [...actualSet].sort(),
          [...exp.exactFindingIds].sort(),
          `${file}: exact rule-id set mismatch`,
        );
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Coverage guard: the fixture-driven loop only asserts when a fixture carries
// expectations, and loadFixtures() returns [] for a missing directory. Either
// way the acceptance assertions could VANISH while the suite still reports
// green. IAM-004 acceptance names wildcard/ and safe/ explicitly, and every
// rule family must ship positive + negative fixtures. Fail (not skip) if a
// category loses its coverage.
// ---------------------------------------------------------------------------

test('acceptance: wildcard/ has a positive fixture producing wildcard findings', () => {
  const fixtures = loadFixtures('wildcard');
  assert.ok(fixtures.length > 0, 'wildcard/ has no fixtures');
  const anyPositive = fixtures.some(({ data }) => {
    const r = analyzeRulesFromText(fixtureText(data));
    return r.ok && r.findings.some((f) => f.id === 'WILDCARD-ACTION' || f.id === 'WILDCARD-RESOURCE');
  });
  assert.ok(anyPositive, 'wildcard/ produced no WILDCARD-ACTION/WILDCARD-RESOURCE finding on any fixture');
});

test('acceptance: safe/ fixtures exist and produce zero findings', () => {
  const fixtures = loadFixtures('safe');
  assert.ok(fixtures.length > 0, 'safe/ has no fixtures');
  for (const { file, data } of fixtures) {
    const r = analyzeRulesFromText(fixtureText(data));
    assert.equal(r.ok, true, `${file}: analyze not ok`);
    assert.deepEqual(idsOf(r.findings), [], `${file}: safe fixture produced findings`);
  }
});

test('every rule family has at least one positive and one negative fixture', () => {
  // Map each rule id to the categories whose positive fixtures should emit it.
  const positiveByRule = {
    'WILDCARD-ACTION': ['wildcard', 'direct-iam'],
    'WILDCARD-RESOURCE': ['wildcard', 'direct-iam', 'detection'],
    'DIRECT-IAM-ADMIN': ['direct-iam'],
    'DATA-EXFIL': ['exfil'],
    'KMS-DECRYPT': ['exfil'],
    'DESTRUCTIVE-ACTION': ['destructive'],
    'DETECTION-IMPAIRMENT': ['detection'],
    'NOTACTION-ALLOW': ['notaction-allow'],
  };
  for (const id of RULE_IDS) {
    const cats = positiveByRule[id] || [];
    let seen = false;
    for (const cat of cats) {
      for (const { data } of loadFixtures(cat)) {
        const r = analyzeRulesFromText(fixtureText(data));
        if (r.ok && r.findings.some((f) => f.id === id)) seen = true;
      }
    }
    assert.ok(seen, `rule ${id} has no positive fixture producing it`);
  }
});

// ---------------------------------------------------------------------------
// Wildcard rule direct assertions.
// ---------------------------------------------------------------------------

// IAM-102 severity model: a standalone wildcard-action grant is HIGH, not
// critical - critical is reserved for compound escalation paths.
test('Action "*" is a high WILDCARD-ACTION; Resource "*" adds WILDCARD-RESOURCE', () => {
  const r = analyzeRulesFromText('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}');
  const ids = idsOf(r.findings);
  assert.deepEqual([...new Set(ids)].sort(), ['WILDCARD-ACTION', 'WILDCARD-RESOURCE']);
  const wa = r.findings.find((f) => f.id === 'WILDCARD-ACTION');
  assert.equal(wa.severity, 'high');
  // "*" must not additionally trip the concrete sub-rules (noise / double count).
  assert.ok(!ids.includes('DIRECT-IAM-ADMIN'));
  assert.ok(!ids.includes('DESTRUCTIVE-ACTION'));
  assert.ok(!ids.includes('DATA-EXFIL'));
  assert.ok(!ids.includes('DETECTION-IMPAIRMENT'));
});

test('service wildcard "s3:*" is high severity WILDCARD-ACTION', () => {
  const r = analyzeRulesFromText('{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b/*"}]}');
  const wa = r.findings.find((f) => f.id === 'WILDCARD-ACTION');
  assert.ok(wa);
  assert.equal(wa.severity, 'high');
});

test('WILDCARD-RESOURCE does not fire on a read-only wildcard-resource grant', () => {
  const r = analyzeRulesFromText('{"Statement":[{"Effect":"Allow","Action":["ec2:DescribeInstances"],"Resource":"*"}]}');
  assert.deepEqual(idsOf(r.findings), []);
});

test('WILDCARD-RESOURCE fires (medium) on Allow+NotResource with a write', () => {
  const r = analyzeRulesFromText(
    '{"Statement":[{"Effect":"Allow","Action":"s3:PutObject","NotResource":"arn:aws:s3:::keep/*"}]}',
  );
  const wr = r.findings.find((f) => f.id === 'WILDCARD-RESOURCE');
  assert.ok(wr, 'NotResource on an Allow with a write should flag WILDCARD-RESOURCE');
  assert.equal(wr.severity, 'medium');
});

// ---------------------------------------------------------------------------
// Direct IAM admin.
// ---------------------------------------------------------------------------

// IAM-102 severity model: direct-IAM single-action administration is HIGH, not
// critical - critical is reserved for compound escalation paths.
test('iam:* trips DIRECT-IAM-ADMIN (high) as well as WILDCARD-ACTION', () => {
  const r = analyzeRulesFromText('{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::1:role/x"}]}');
  const ids = idsOf(r.findings);
  assert.ok(ids.includes('DIRECT-IAM-ADMIN'));
  assert.ok(ids.includes('WILDCARD-ACTION'));
  assert.equal(r.findings.find((f) => f.id === 'DIRECT-IAM-ADMIN').severity, 'high');
});

test('iam:PutUserPolicy / iam:AttachRolePolicy / iam:CreatePolicyVersion each trip DIRECT-IAM-ADMIN', () => {
  for (const action of ['iam:PutUserPolicy', 'iam:AttachRolePolicy', 'iam:CreatePolicyVersion', 'iam:CreateAccessKey']) {
    const r = analyzeRulesFromText(
      JSON.stringify({ Statement: [{ Effect: 'Allow', Action: action, Resource: 'arn:aws:iam::1:role/x' }] }),
    );
    assert.ok(idsOf(r.findings).includes('DIRECT-IAM-ADMIN'), `${action} should trip DIRECT-IAM-ADMIN`);
  }
});

test('iam read-only actions do NOT trip DIRECT-IAM-ADMIN', () => {
  const r = analyzeRulesFromText(
    '{"Statement":[{"Effect":"Allow","Action":["iam:GetRole","iam:ListPolicies"],"Resource":"arn:aws:iam::1:role/x"}]}',
  );
  assert.ok(!idsOf(r.findings).includes('DIRECT-IAM-ADMIN'));
});

// ---------------------------------------------------------------------------
// Destructive / exfil / detection separation.
// ---------------------------------------------------------------------------

test('destructive verbs trip DESTRUCTIVE-ACTION but security-service deletes go to DETECTION-IMPAIRMENT', () => {
  const destructive = analyzeRulesFromText(
    '{"Statement":[{"Effect":"Allow","Action":["ec2:TerminateInstances","s3:DeleteObject"],"Resource":"arn:aws:s3:::b/*"}]}',
  );
  assert.ok(idsOf(destructive.findings).includes('DESTRUCTIVE-ACTION'));

  const detection = analyzeRulesFromText(
    '{"Statement":[{"Effect":"Allow","Action":"cloudtrail:DeleteTrail","Resource":"arn:aws:cloudtrail:us-east-1:1:trail/t"}]}',
  );
  const ids = idsOf(detection.findings);
  assert.ok(ids.includes('DETECTION-IMPAIRMENT'), 'cloudtrail:DeleteTrail -> DETECTION-IMPAIRMENT');
  assert.ok(!ids.includes('DESTRUCTIVE-ACTION'), 'security-service delete must not double-flag as generic destructive');
});

test('DATA-EXFIL: s3:GetObject fires only with a broad resource; secrets fire always', () => {
  const broad = analyzeRulesFromText('{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}');
  assert.ok(idsOf(broad.findings).includes('DATA-EXFIL'));
  const scoped = analyzeRulesFromText('{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}');
  assert.ok(!idsOf(scoped.findings).includes('DATA-EXFIL'));
  const secret = analyzeRulesFromText(
    '{"Statement":[{"Effect":"Allow","Action":"secretsmanager:GetSecretValue","Resource":"arn:aws:secretsmanager:us-east-1:1:secret:x"}]}',
  );
  assert.ok(idsOf(secret.findings).includes('DATA-EXFIL'));
});

// ---------------------------------------------------------------------------
// IAM-103: kms:Decrypt is a DISTINCT decryption capability, not a secret read.
// ---------------------------------------------------------------------------

test('kms:Decrypt fires KMS-DECRYPT, NOT DATA-EXFIL, and is not called a secret read', () => {
  const r = analyzeRulesFromText(
    '{"Statement":[{"Effect":"Allow","Action":"kms:Decrypt","Resource":"arn:aws:kms:us-east-1:1:key/abcd"}]}',
  );
  const ids = idsOf(r.findings);
  assert.ok(ids.includes('KMS-DECRYPT'), 'kms:Decrypt must produce KMS-DECRYPT');
  assert.ok(!ids.includes('DATA-EXFIL'), 'kms:Decrypt must NOT be lumped into DATA-EXFIL');
  const kms = r.findings.find((f) => f.id === 'KMS-DECRYPT');
  // Must NOT claim it reads/retrieves secret material.
  assert.ok(!/reads?\s+secret material/i.test(kms.why), 'KMS-DECRYPT must not claim it reads secret material');
  assert.ok(/decrypt/i.test(kms.why), 'KMS-DECRYPT why must describe decryption');
  assert.ok(/not\b.*(enumerate|retrieve)/i.test(kms.why), 'KMS-DECRYPT why must state it does not enumerate/retrieve secrets');
});

test('secretsmanager + kms:Decrypt in one statement split into DATA-EXFIL and KMS-DECRYPT', () => {
  const r = analyzeRulesFromText(
    '{"Statement":[{"Effect":"Allow","Action":["secretsmanager:GetSecretValue","kms:Decrypt"],"Resource":["arn:aws:secretsmanager:us-east-1:1:secret:x","arn:aws:kms:us-east-1:1:key/abcd"]}]}',
  );
  const ids = new Set(idsOf(r.findings));
  assert.ok(ids.has('DATA-EXFIL'), 'secretsmanager read -> DATA-EXFIL');
  assert.ok(ids.has('KMS-DECRYPT'), 'kms:Decrypt -> KMS-DECRYPT');
  // DATA-EXFIL's why must no longer mention KMS.
  const exfil = r.findings.find((f) => f.id === 'DATA-EXFIL');
  assert.ok(!/kms/i.test(exfil.why), 'DATA-EXFIL why must no longer mention KMS');
});

// ---------------------------------------------------------------------------
// IAM-103: wildcard-resource wording is neutral (no non-read classification).
// ---------------------------------------------------------------------------

test('WILDCARD-RESOURCE why is neutral: broadly resource-scoped, no non-read claim', () => {
  const r = analyzeRulesFromText(
    '{"Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}',
  );
  const wr = r.findings.find((f) => f.id === 'WILDCARD-RESOURCE');
  assert.ok(wr, 'expected a WILDCARD-RESOURCE finding');
  assert.ok(/broadly resource-scoped/i.test(wr.why), 'why must use neutral broadly-resource-scoped wording');
  assert.ok(!/non-read/i.test(wr.why), 'why must not classify the action as non-read');
});

// ---------------------------------------------------------------------------
// A Condition lowers BOTH certainty signals but never suppresses a finding.
// ---------------------------------------------------------------------------

test('a Condition drops finding confidence to medium and annotates the limit', () => {
  const r = analyzeRulesFromText(
    JSON.stringify({
      Statement: [
        {
          Effect: 'Allow',
          Action: '*',
          Resource: '*',
          Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'true' } },
        },
      ],
    }),
  );
  const wa = r.findings.find((f) => f.id === 'WILDCARD-ACTION');
  assert.ok(wa);
  // A Condition is a runtime gate: a direct-capability rule finding starts at
  // evidence high / exploitability high, so both drop to medium.
  assert.equal(wa.policyEvidence, 'medium');
  assert.equal(wa.pathExploitability, 'medium');
  assert.ok(/Condition/.test(wa.limit));
  assert.notEqual(wa.conditions, null);
});

// ---------------------------------------------------------------------------
// Truthfulness: never claims effective permissions.
// ---------------------------------------------------------------------------

test('every finding limit says capability, not effective access', () => {
  const r = analyzeRulesFromText('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}');
  for (const f of r.findings) {
    assert.ok(/not effective access/i.test(f.limit));
    assert.ok(!/effective permission(s)? (are|is) granted/i.test(f.why));
  }
});

// ---------------------------------------------------------------------------
// Determinism + frozen output.
// ---------------------------------------------------------------------------

test('analyzeRules is deterministic and deeply frozen', () => {
  const text = JSON.stringify({
    Statement: [
      { Sid: 'a', Effect: 'Allow', Action: ['s3:GetObject'], Resource: '*' },
      { Sid: 'b', Effect: 'Allow', Action: 'iam:*', Resource: '*' },
    ],
  });
  const a = analyzeRules(modelFromText(text).model);
  const b = analyzeRules(modelFromText(text).model);
  assert.deepEqual(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(b)));
  assert.ok(Object.isFrozen(a));
  assert.ok(Object.isFrozen(a.findings));
  if (a.findings.length > 0) {
    assert.ok(Object.isFrozen(a.findings[0]));
    assert.ok(Object.isFrozen(a.findings[0].actions));
  }
});

test('findings are ordered by statement index then rule order', () => {
  const r = analyzeRulesFromText(
    JSON.stringify({
      Statement: [
        { Effect: 'Allow', Action: 'iam:*', Resource: '*' },
        { Effect: 'Allow', Action: 'ec2:TerminateInstances', Resource: 'arn:aws:ec2:us-east-1:1:instance/*' },
      ],
    }),
  );
  const seq = r.findings.map((f) => [f.statementIndex, RULES[f.id].order]);
  const sorted = [...seq].sort((x, y) => (x[0] - y[0]) || (x[1] - y[1]));
  assert.deepEqual(seq, sorted);
});

// ---------------------------------------------------------------------------
// Hostile / malformed input never throws.
// ---------------------------------------------------------------------------

test('analyzeRules never throws on a bad model', () => {
  assert.doesNotThrow(() => {
    const r = analyzeRules(null);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.code === 'NO_MODEL'));
  });
  assert.doesNotThrow(() => {
    const r = analyzeRules({ statements: 'nope' });
    assert.equal(r.ok, false);
  });
});

test('analyzeRulesFromText surfaces validation errors and never throws', () => {
  for (const { file, data } of [...loadFixtures('malformed'), ...loadFixtures('adversarial')]) {
    assert.doesNotThrow(() => {
      const r = analyzeRulesFromText(fixtureText(data));
      // Either rejected before analysis, or analyzed with inert findings.
      assert.ok(typeof r.ok === 'boolean', `${file}: missing ok`);
      assert.ok(Array.isArray(r.findings), `${file}: missing findings`);
      if (data.expect && data.expect.valid === false) {
        assert.equal(r.ok, false, `${file}: expected validation failure`);
        assert.deepEqual(r.findings, [], `${file}: rejected input must yield no findings`);
      }
    }, `${file}: analyzeRulesFromText threw`);
  }
});

test('empty policy produces no findings', () => {
  const r = analyzeRules({ statements: [] });
  assert.equal(r.ok, true);
  assert.deepEqual(r.findings, []);
});

// ---------------------------------------------------------------------------
// XSS payloads in policy fields pass through as inert data (threat-model T1).
// ---------------------------------------------------------------------------

test('XSS-laden SID/ARN pass through findings as inert strings', () => {
  const r = analyzeRulesFromText(
    JSON.stringify({
      Statement: [
        {
          Sid: '<img src=x onerror=alert(1)>',
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: '*',
        },
      ],
    }),
  );
  const f = r.findings.find((x) => x.id === 'DATA-EXFIL');
  assert.ok(f);
  // Data is preserved verbatim (no execution, no markup interpretation): the
  // rule engine only ever compares strings, it never renders them.
  assert.equal(f.statementSid, '<img src=x onerror=alert(1)>');
  assert.equal(typeof f.statementSid, 'string');
});

// Object.prototype must never be polluted by analyzing hostile input.
test('analyzing input does not pollute Object.prototype', () => {
  analyzeRulesFromText(
    '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"__proto__":{"polluted":true}}}}]}',
  );
  assert.equal(({}).polluted, undefined);
});
