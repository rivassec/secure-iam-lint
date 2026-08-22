// Unit tests for IAM-003: evaluator - Allow/Deny/NotAction/NotResource semantics.
// Runs on node's built-in runner: `node --test tests/`.
//
// Acceptance (prd.json IAM-003):
//   - explicit-deny/ fixtures: deny wins
//   - not-action/ + not-resource/ semantics correct
//   - IAM critic: no false allow/deny
//   - never claims effective permissions from a single policy

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';
import {
  evaluate,
  decide,
  explainStatement,
  DECISION,
  CERTAINTY,
  CAPABILITY_CAVEAT,
} from '../../../content/tools/iam-blast-radius/engine/evaluator.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(here, '..', 'fixtures');

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

function loadFixtures(category) {
  const dir = join(fixturesDir, category);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => ({ file: `${category}/${f}`, data: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
}

function modelOf(fx) {
  const r = modelFromText(fixtureText(fx));
  assert.equal(r.ok, true, `fixture failed to model: ${JSON.stringify(r.errors)}`);
  return r.model;
}

// ---------------------------------------------------------------------------
// Fixture-driven: explicit-deny / not-action / not-resource decide() assertions.
// ---------------------------------------------------------------------------

for (const category of ['explicit-deny', 'not-action', 'not-resource', 'safe', 'policy-variable']) {
  for (const { file, data } of loadFixtures(category)) {
    // denyWinsFor: shorthand assertion that each action is explicitly denied.
    if (data.expect && Array.isArray(data.expect.denyWinsFor)) {
      test(`fixture ${file}: deny wins for listed actions`, () => {
        const model = modelOf(data);
        for (const action of data.expect.denyWinsFor) {
          const d = decide(model, { action, resource: '*' });
          assert.equal(d.ok, true);
          assert.equal(
            d.decision,
            DECISION.EXPLICIT_DENY,
            `${file}: expected explicit-deny for ${action}, got ${d.decision}`,
          );
          assert.equal(d.certainty, CERTAINTY.BLOCKED_BY_DENY);
        }
      });
    }
    // decide: explicit {action, resource?, decision} expectations.
    if (data.expect && Array.isArray(data.expect.decide)) {
      test(`fixture ${file}: decide() matches expected decisions`, () => {
        const model = modelOf(data);
        for (const c of data.expect.decide) {
          const req = { action: c.action };
          if (typeof c.resource === 'string') req.resource = c.resource;
          const d = decide(model, req);
          assert.equal(d.ok, true, `${file}: decide not ok for ${c.action}`);
          assert.equal(
            d.decision,
            c.decision,
            `${file}: ${c.action} on ${c.resource || '(any)'} expected ${c.decision}, got ${d.decision}`,
          );
          // Truthfulness invariant: never an unqualified "allowed"/"denied".
          assert.equal(d.caveat, CAPABILITY_CAVEAT);
        }
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Coverage guard: the fixture-driven loop above only registers a test when a
// fixture carries expect.decide / expect.denyWinsFor, and loadFixtures()
// returns [] for a missing/mispathed directory. Either way the acceptance
// assertions can VANISH while the suite still reports green - a false-green
// that would let a false allow/deny through undetected. IAM-003 acceptance
// requires the explicit-deny / not-action / not-resource fixtures to be
// exercised, so assert here that each category actually contributes at least
// one checkable decide/denyWins expectation. This test fails (not silently
// skips) if a directory disappears or a fixture loses its expect block.

const ACCEPTANCE_CATEGORIES = ['explicit-deny', 'not-action', 'not-resource'];

function countDecideExpectations(category) {
  let fixtures = 0;
  let expectations = 0;
  for (const { data } of loadFixtures(category)) {
    fixtures++;
    if (data.expect && Array.isArray(data.expect.decide)) {
      expectations += data.expect.decide.length;
    }
    if (data.expect && Array.isArray(data.expect.denyWinsFor)) {
      expectations += data.expect.denyWinsFor.length;
    }
  }
  return { fixtures, expectations };
}

for (const category of ACCEPTANCE_CATEGORIES) {
  test(`acceptance category ${category}/ is actually exercised (non-vacuous)`, () => {
    const { fixtures, expectations } = countDecideExpectations(category);
    assert.ok(
      fixtures > 0,
      `${category}/ has no fixtures - the fixture-driven assertions for this acceptance category would silently register zero tests`,
    );
    assert.ok(
      expectations > 0,
      `${category}/ has fixtures but no expect.decide/expect.denyWinsFor expectations - the acceptance semantics are not being asserted`,
    );
  });
}

// ---------------------------------------------------------------------------
// Explicit-Deny precedence.
// ---------------------------------------------------------------------------

test('unconditional Deny overrides an Allow on the same action', () => {
  const m = modelFromText(
    JSON.stringify({
      Statement: [
        { Effect: 'Allow', Action: 's3:*', Resource: '*' },
        { Effect: 'Deny', Action: 's3:DeleteObject', Resource: '*' },
      ],
    }),
  ).model;
  const d = decide(m, { action: 's3:DeleteObject', resource: '*' });
  assert.equal(d.decision, DECISION.EXPLICIT_DENY);
  assert.equal(d.explicitDeny, true);
  assert.equal(d.certainty, CERTAINTY.BLOCKED_BY_DENY);
});

test('Deny wins even when the Allow is listed AFTER the Deny (order independent)', () => {
  const m = modelFromText(
    JSON.stringify({
      Statement: [
        { Effect: 'Deny', Action: 's3:DeleteObject', Resource: '*' },
        { Effect: 'Allow', Action: 's3:*', Resource: '*' },
      ],
    }),
  ).model;
  assert.equal(decide(m, { action: 's3:DeleteObject', resource: '*' }).decision, DECISION.EXPLICIT_DENY);
});

test('conditional Deny does NOT produce a definitive deny (no false deny)', () => {
  const m = modelFromText(
    JSON.stringify({
      Statement: [
        { Effect: 'Allow', Action: 's3:*', Resource: '*' },
        {
          Effect: 'Deny',
          Action: 's3:DeleteObject',
          Resource: '*',
          Condition: { Bool: { 'aws:MultiFactorAuthPresent': 'false' } },
        },
      ],
    }),
  ).model;
  const d = decide(m, { action: 's3:DeleteObject', resource: '*' });
  assert.equal(d.decision, DECISION.CONDITIONAL);
  assert.equal(d.explicitDeny, false);
  assert.equal(d.conditionalDeny, true);
  assert.equal(d.allow, true);
  assert.equal(d.certainty, CERTAINTY.CONDITIONALLY_REACHABLE);
});

// ---------------------------------------------------------------------------
// NotAction semantics: applies to EVERYTHING EXCEPT the listed actions.
// ---------------------------------------------------------------------------

test('Allow NotAction iam:* grants s3 (not excluded) but not iam (excluded)', () => {
  const m = modelFromText('{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}').model;
  assert.equal(decide(m, { action: 's3:GetObject', resource: '*' }).decision, DECISION.ALLOWED_BY_POLICY);
  assert.equal(decide(m, { action: 'ec2:RunInstances', resource: '*' }).decision, DECISION.ALLOWED_BY_POLICY);
  assert.equal(decide(m, { action: 'iam:CreateUser', resource: '*' }).decision, DECISION.NOT_GRANTED_BY_POLICY);
});

test('Deny NotAction denies everything except the listed actions', () => {
  const m = modelFromText('{"Statement":[{"Effect":"Deny","NotAction":"s3:*","Resource":"*"}]}').model;
  // s3 is excluded from the deny -> deny does not apply -> not granted (no Allow).
  assert.equal(decide(m, { action: 's3:GetObject', resource: '*' }).decision, DECISION.NOT_GRANTED_BY_POLICY);
  // ec2 is NOT excluded -> deny applies.
  assert.equal(decide(m, { action: 'ec2:RunInstances', resource: '*' }).decision, DECISION.EXPLICIT_DENY);
});

test('capability view labels NotAction as a broad grant', () => {
  const view = evaluate(modelFromText('{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}').model);
  assert.equal(view.statements[0].actionMode, 'NotAction');
  assert.ok(view.statements[0].summary.includes('every action EXCEPT'));
  assert.ok(view.statements[0].caveats.some((c) => /EVERY action EXCEPT/.test(c)));
});

// ---------------------------------------------------------------------------
// NotResource semantics: applies to every resource EXCEPT the listed ones.
// ---------------------------------------------------------------------------

test('Deny NotResource denies outside the sandbox, spares the sandbox', () => {
  const m = modelFromText(
    JSON.stringify({
      Statement: [
        {
          Effect: 'Deny',
          Action: 's3:*',
          NotResource: ['arn:aws:s3:::sandbox', 'arn:aws:s3:::sandbox/*'],
        },
      ],
    }),
  ).model;
  // Outside the sandbox -> deny applies.
  assert.equal(
    decide(m, { action: 's3:DeleteObject', resource: 'arn:aws:s3:::prod/x' }).decision,
    DECISION.EXPLICIT_DENY,
  );
  // Inside the sandbox -> excluded from the deny -> deny does not apply.
  assert.equal(
    decide(m, { action: 's3:DeleteObject', resource: 'arn:aws:s3:::sandbox/x' }).decision,
    DECISION.NOT_GRANTED_BY_POLICY,
  );
});

test('capability view labels NotResource on Deny correctly', () => {
  const view = evaluate(
    modelFromText('{"Statement":[{"Effect":"Deny","Action":"s3:*","NotResource":"arn:aws:s3:::keep"}]}').model,
  );
  assert.equal(view.statements[0].resourceMode, 'NotResource');
  assert.ok(view.statements[0].summary.includes('every resource EXCEPT'));
});

// Allow + NotResource is the tool's own self-identified WORST over-grant:
// it grants the action(s) on EVERY resource except the listed ones. Both
// directions of decide() and the capability caveat must be exercised.
test('Allow NotResource grants outside the excluded set, not inside it', () => {
  const m = modelFromText(
    JSON.stringify({
      Statement: [
        {
          Effect: 'Allow',
          Action: 's3:*',
          NotResource: ['arn:aws:s3:::locked', 'arn:aws:s3:::locked/*'],
        },
      ],
    }),
  ).model;
  // Outside the excluded set -> the Allow covers it.
  assert.equal(
    decide(m, { action: 's3:GetObject', resource: 'arn:aws:s3:::open/x' }).decision,
    DECISION.ALLOWED_BY_POLICY,
  );
  // Inside the excluded set -> the Allow does not apply -> not granted here.
  assert.equal(
    decide(m, { action: 's3:GetObject', resource: 'arn:aws:s3:::locked/secret' }).decision,
    DECISION.NOT_GRANTED_BY_POLICY,
  );
});

test('capability view flags NotResource on an Allow as the broad over-grant', () => {
  const view = evaluate(
    modelFromText('{"Statement":[{"Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::locked/*"}]}').model,
  );
  assert.equal(view.statements[0].resourceMode, 'NotResource');
  assert.ok(view.statements[0].summary.includes('every resource EXCEPT'));
  assert.ok(
    view.statements[0].caveats.some((c) => /EVERY resource EXCEPT/.test(c) && /far broader than intended/.test(c)),
    'Allow+NotResource must carry the "far broader than intended" over-grant caveat',
  );
});

// ---------------------------------------------------------------------------
// IAM policy variables (${...}): resolved at runtime, so a variable-scoped
// statement can NEVER yield a definitive ALLOWED_BY_POLICY / EXPLICIT_DENY.
// These guard the two constructible false conclusions from a literal matcher.
// ---------------------------------------------------------------------------

test('variable in a shadowing Deny Resource yields CONDITIONAL, not a false allow', () => {
  const m = modelFromText(
    JSON.stringify({
      Statement: [
        { Effect: 'Allow', Action: 's3:*', Resource: '*' },
        { Effect: 'Deny', Action: 's3:*', Resource: 'arn:aws:s3:::${aws:username}-private/*' },
      ],
    }),
  ).model;
  const d = decide(m, { action: 's3:GetObject', resource: 'arn:aws:s3:::alice-private/secret' });
  assert.equal(d.decision, DECISION.CONDITIONAL, 'literal matcher would falsely ALLOW this');
  assert.notEqual(d.decision, DECISION.ALLOWED_BY_POLICY);
  assert.equal(d.allow, true);
  assert.equal(d.conditionalDeny, true);
  assert.equal(d.policyVariable, true);
  assert.ok(/policy variables/i.test(d.explanation));
});

test('variable in NotResource on a Deny yields CONDITIONAL, not a false deny', () => {
  const m = modelFromText(
    '{"Statement":[{"Effect":"Deny","Action":"s3:*","NotResource":"arn:aws:s3:::${aws:username}/*"}]}',
  ).model;
  const d = decide(m, { action: 's3:GetObject', resource: 'arn:aws:s3:::alice/report' });
  assert.equal(d.decision, DECISION.CONDITIONAL, 'literal matcher would falsely DENY this');
  assert.notEqual(d.decision, DECISION.EXPLICIT_DENY);
  assert.equal(d.explicitDeny, false);
  assert.equal(d.conditionalDeny, true);
  assert.equal(d.policyVariable, true);
});

test('variable in an Allow Resource degrades to CONDITIONAL (never definitive allow)', () => {
  const m = modelFromText(
    '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::${aws:username}-bucket/*"}]}',
  ).model;
  // Matching action, variable resource -> uncertain -> conditional.
  const d1 = decide(m, { action: 's3:GetObject', resource: 'arn:aws:s3:::alice-bucket/file' });
  assert.equal(d1.decision, DECISION.CONDITIONAL);
  assert.equal(d1.conditionalAllow, true);
  assert.equal(d1.policyVariable, true);
  // Concrete non-matching action -> still certainly not granted (variable only
  // affects the resource dimension, action pattern is concrete).
  const d2 = decide(m, { action: 's3:DeleteObject', resource: 'arn:aws:s3:::alice-bucket/file' });
  assert.equal(d2.decision, DECISION.NOT_GRANTED_BY_POLICY);
});

test('a variable-free policy keeps its definitive behavior (no over-conditionalizing)', () => {
  const m = modelFromText(
    JSON.stringify({
      Statement: [
        { Effect: 'Allow', Action: 's3:*', Resource: '*' },
        { Effect: 'Deny', Action: 's3:*', Resource: 'arn:aws:s3:::alice-private/*' },
      ],
    }),
  ).model;
  const d = decide(m, { action: 's3:GetObject', resource: 'arn:aws:s3:::alice-private/secret' });
  assert.equal(d.decision, DECISION.EXPLICIT_DENY);
  assert.equal(d.policyVariable, false);
});

test('capability view flags a policy-variable statement', () => {
  const view = evaluate(
    modelFromText('{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::${aws:username}-bucket/*"}]}').model,
  );
  assert.equal(view.statements[0].policyVariable, true);
  assert.ok(view.statements[0].caveats.some((c) => /IAM policy variables/.test(c)));
});

// ---------------------------------------------------------------------------
// Resource scoping in decide().
// ---------------------------------------------------------------------------

test('Allow scoped to a resource does not grant a different resource', () => {
  const m = modelFromText(
    '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a/*"}]}',
  ).model;
  assert.equal(
    decide(m, { action: 's3:GetObject', resource: 'arn:aws:s3:::a/file' }).decision,
    DECISION.ALLOWED_BY_POLICY,
  );
  assert.equal(
    decide(m, { action: 's3:GetObject', resource: 'arn:aws:s3:::b/file' }).decision,
    DECISION.NOT_GRANTED_BY_POLICY,
  );
});

test('omitting resource in the request leaves resource-scoped grants CONDITIONAL', () => {
  const m = modelFromText(
    '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a/*"}]}',
  ).model;
  const d = decide(m, { action: 's3:GetObject' });
  assert.equal(d.decision, DECISION.CONDITIONAL);
  assert.equal(d.conditionalAllow, true);
});

test('wildcard action patterns match case-insensitively', () => {
  const m = modelFromText('{"Statement":[{"Effect":"Allow","Action":"S3:Get*","Resource":"*"}]}').model;
  assert.equal(decide(m, { action: 's3:GetObject', resource: '*' }).decision, DECISION.ALLOWED_BY_POLICY);
});

test('resource matching is case-sensitive (ARNs)', () => {
  const m = modelFromText(
    '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::MyBucket/*"}]}',
  ).model;
  assert.equal(
    decide(m, { action: 's3:GetObject', resource: 'arn:aws:s3:::mybucket/x' }).decision,
    DECISION.NOT_GRANTED_BY_POLICY,
  );
});

// ---------------------------------------------------------------------------
// Truthfulness: never effective permissions; safe policies produce no deny.
// ---------------------------------------------------------------------------

test('every decision carries the capability-not-effective caveat', () => {
  const m = modelFromText('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}').model;
  const d = decide(m, { action: 's3:GetObject', resource: '*' });
  assert.equal(d.caveat, CAPABILITY_CAVEAT);
  assert.ok(/single policy cannot establish effective/.test(d.caveat));
});

test('allowed-by-policy explanation never claims effective access', () => {
  const m = modelFromText('{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}').model;
  const d = decide(m, { action: 's3:GetObject', resource: '*' });
  assert.equal(d.decision, DECISION.ALLOWED_BY_POLICY);
  assert.ok(/on its own/.test(d.explanation));
  assert.ok(!/effectively (allowed|granted)/i.test(d.explanation));
});

test('not-granted is framed as per-policy implicit deny, not effective deny', () => {
  const m = modelFromText('{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}').model;
  const d = decide(m, { action: 'iam:CreateUser', resource: '*' });
  assert.equal(d.decision, DECISION.NOT_GRANTED_BY_POLICY);
  assert.ok(/other attached policies/.test(d.explanation));
  assert.ok(!/effectively denied/i.test(d.explanation));
});

test('evaluate() reports allow/deny counts and explicit-deny flag', () => {
  const view = evaluate(
    modelFromText(
      JSON.stringify({
        Statement: [
          { Effect: 'Allow', Action: 's3:*', Resource: '*' },
          { Effect: 'Deny', Action: 's3:DeleteObject', Resource: '*' },
        ],
      }),
    ).model,
  );
  assert.equal(view.ok, true);
  assert.equal(view.allowCount, 1);
  assert.equal(view.denyCount, 1);
  assert.equal(view.hasExplicitDeny, true);
  assert.equal(view.statements.length, 2);
});

test('conditional Deny does not set hasExplicitDeny', () => {
  const view = evaluate(
    modelFromText(
      JSON.stringify({
        Statement: [
          {
            Effect: 'Deny',
            Action: 's3:*',
            Resource: '*',
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          },
        ],
      }),
    ).model,
  );
  assert.equal(view.hasExplicitDeny, false);
});

// ---------------------------------------------------------------------------
// Determinism + frozen output.
// ---------------------------------------------------------------------------

test('evaluate() is deterministic and frozen', () => {
  const text = JSON.stringify({
    Statement: [
      { Sid: 's', Effect: 'Allow', Action: ['s3:*', 'ec2:*'], Resource: '*' },
      { Effect: 'Deny', Action: 'iam:*', Resource: '*' },
    ],
  });
  const a = evaluate(modelFromText(text).model);
  const b = evaluate(modelFromText(text).model);
  assert.deepEqual(JSON.parse(JSON.stringify(a)), JSON.parse(JSON.stringify(b)));
  assert.ok(Object.isFrozen(a));
  assert.ok(Object.isFrozen(a.statements));
});

test('decide() is deterministic', () => {
  const m = modelFromText('{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}').model;
  const a = decide(m, { action: 's3:GetObject', resource: '*' });
  const b = decide(m, { action: 's3:GetObject', resource: '*' });
  assert.deepEqual(a, b);
});

// ---------------------------------------------------------------------------
// Hostile / malformed input never throws.
// ---------------------------------------------------------------------------

test('decide() never throws on a bad model or request', () => {
  assert.doesNotThrow(() => {
    const r1 = decide(null, { action: 's3:GetObject' });
    assert.equal(r1.ok, false);
    assert.ok(r1.errors.some((e) => e.code === 'NO_MODEL'));
  });
  assert.doesNotThrow(() => {
    const r2 = decide({ statements: [] }, { action: 42 });
    assert.equal(r2.ok, false);
    assert.ok(r2.errors.some((e) => e.code === 'BAD_REQUEST'));
  });
  assert.doesNotThrow(() => {
    const r3 = decide({ statements: [] }, null);
    assert.equal(r3.ok, false);
  });
});

test('evaluate() never throws on a bad model', () => {
  assert.doesNotThrow(() => {
    const r = evaluate(undefined);
    assert.equal(r.ok, false);
    assert.ok(r.errors.some((e) => e.code === 'NO_MODEL'));
  });
});

test('empty policy grants nothing', () => {
  const m = { statements: [] };
  assert.equal(decide(m, { action: 's3:GetObject', resource: '*' }).decision, DECISION.NOT_GRANTED_BY_POLICY);
  assert.equal(evaluate(m).statements.length, 0);
});

test('XSS-laden SID/ARN pass through decide/evaluate as inert data', () => {
  const m = modelFromText(
    JSON.stringify({
      Statement: [
        {
          Sid: '<img src=x onerror=alert(1)>',
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::<script>/*',
        },
      ],
    }),
  ).model;
  const view = evaluate(m);
  assert.equal(view.statements[0].sid, '<img src=x onerror=alert(1)>');
  const d = decide(m, { action: 's3:GetObject', resource: 'arn:aws:s3:::<script>/evil' });
  assert.equal(d.decision, DECISION.ALLOWED_BY_POLICY);
});

// ---------------------------------------------------------------------------
// explainStatement() direct unit coverage.
// ---------------------------------------------------------------------------

test('explainStatement flags a statement with no resource scope', () => {
  const m = modelFromText('{"Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}').model;
  const ex = explainStatement(m.statements[0]);
  assert.equal(ex.resourceMode, 'none');
  assert.ok(ex.caveats.some((c) => /resource scope cannot be determined/.test(c)));
});

test('explainStatement marks conditional statements', () => {
  const m = modelFromText(
    '{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}',
  ).model;
  const ex = explainStatement(m.statements[0]);
  assert.equal(ex.conditional, true);
  assert.ok(ex.caveats.some((c) => /Condition block/.test(c)));
});
