// IAM-804 (Phase 8): federated OIDC/SAML role-trust subject-scope expansion.
//
// A Federated trust Principal (an OIDC provider such as GitHub Actions'
// token.actions.githubusercontent.com, or a SAML provider) delegates
// assume-role to workloads that present a matching web-identity/SAML token. The
// SUBJECT scope drives severity (docs/trust-policy-semantics.md 4.4/4.5,
// acceptance-suite test 17):
//
//   - an org-wide subject (repo:example-org/*) OR an absent subject condition
//     = BROAD -> HIGH federated-subject expansion.
//   - a subject bound to a specific repository + ref/branch/environment (OIDC)
//     or a specific subject attribute (SAML saml:sub) = TIGHT -> low/medium; it
//     must NOT fire the high expansion finding.
//   - the audience check (OIDC ...:aud, SAML saml:aud) is a valid CONSTRAINT and
//     is recognized (never flagged "missing"); it does not by itself lower a
//     broad-subject finding.
//
// Load-bearing invariants this suite pins (threat-model T8): the finding never
// claims every repository/workload can actually assume the role (that needs the
// matching token + workflow context, which is out of scope), and the assumed
// role's own permissions are always out of scope / unknown. Classification is
// text-only - never a runtime STS allow/deny.
//
// The engine behavior lives in engine/trust.js (findingsForStatement federated
// branch) + engine/conditions.js (federation aud/sub classification). This suite
// drives the committed fixtures/trust-federated/ corpus through the full
// analyze() pipeline (the authoritative findings table), the same path the
// browser worker uses. Runs on node's built-in runner: `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze, SEVERITY_ORDER } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const here = dirname(fileURLToPath(import.meta.url));
const fedDir = join(here, '..', 'fixtures', 'trust-federated');

function fixtureText(fx) {
  if (typeof fx.policyRaw === 'string') return fx.policyRaw;
  return JSON.stringify(fx.policy);
}

function loadFixtures() {
  if (!existsSync(fedDir)) return [];
  return readdirSync(fedDir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ file: `trust-federated/${f}`, data: JSON.parse(readFileSync(join(fedDir, f), 'utf8')) }));
}

const FIXTURES = loadFixtures();

// "no more severe than" using the engine's own SEVERITY_ORDER (0 = most severe).
function severityAtMost(sev, cap) {
  return SEVERITY_ORDER[sev] >= SEVERITY_ORDER[cap];
}

test('trust-federated corpus is present and well-formed (OIDC + SAML, broad + tight)', () => {
  assert.ok(FIXTURES.length >= 4, `expected >=4 federated fixtures, found ${FIXTURES.length}`);
  const providers = new Set();
  const scopes = new Set();
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy object`);
    assert.ok(data.federatedExpect && typeof data.federatedExpect === 'object', `${file}: has a federatedExpect`);
    providers.add(data.federatedExpect.provider);
    scopes.add(data.federatedExpect.subjectScope);
  }
  assert.ok(providers.has('oidc') && providers.has('saml'), 'covers both OIDC and SAML');
  assert.ok(scopes.has('broad') && scopes.has('tight'), 'covers both broad and tight subject scopes');
});

test('analyze() satisfies every federated fixture contract', () => {
  for (const { file, data } of FIXTURES) {
    const fe = data.federatedExpect;
    const result = analyze(fixtureText(data));

    // A supported role-trust policy must analyze cleanly and never fail closed.
    assert.equal(result.ok, true, `${file}: expected a clean analysis; got ${JSON.stringify(result.errors)}`);
    assert.ok(!(result.coverage && result.coverage.blocked), `${file}: role-trust must not fail closed`);

    const ids = result.findings.map((f) => f.id);
    // Positive/negative id contracts from the generic fixture schema.
    for (const want of (data.expect && data.expect.findingIds) || []) {
      assert.ok(ids.includes(want), `${file}: MUST find ${want}; got [${ids.join(', ')}]`);
    }
    for (const forbid of (data.expect && data.expect.notFindingIds) || []) {
      assert.ok(!ids.includes(forbid), `${file}: MUST NOT find ${forbid}; got [${ids.join(', ')}]`);
    }

    const fed = result.findings.find((f) => f.id === fe.findingId);
    assert.ok(fed, `${file}: expected finding ${fe.findingId}; got [${ids.join(', ')}]`);

    // Severity: exact for the broad (high) case, a cap for the tight boundary.
    if (fe.severity) {
      assert.equal(fed.severity, fe.severity, `${file}: severity ${fed.severity} != expected ${fe.severity}`);
    }
    if (fe.maxSeverity) {
      assert.ok(severityAtMost(fed.severity, fe.maxSeverity),
        `${file}: severity ${fed.severity} exceeds cap ${fe.maxSeverity}`);
    }
    if (fe.notSeverity) {
      assert.notEqual(fed.severity, fe.notSeverity,
        `${file}: tight subject must NOT reach ${fe.notSeverity}, got ${fed.severity}`);
    }

    // policyEvidence is high (the trust grant is literally in the policy);
    // pathExploitability is capped below it (assuming/using the role needs the
    // out-of-scope target-role privileges + a matching token/workflow context).
    assert.equal(fed.policyEvidence, 'high', `${file}: policyEvidence high`);
    assert.ok(['low', 'medium'].includes(fed.pathExploitability),
      `${file}: pathExploitability below policyEvidence, got ${fed.pathExploitability}`);

    // The assumed role's permissions are ALWAYS out of scope / unknown (T8).
    assert.equal(fed.trust && fed.trust.targetPermissions, 'unknown',
      `${file}: target-role permissions must be unknown`);
    assert.match(fed.limit, /out of scope|unknown/i, `${file}: limit states target perms out of scope`);
    // Never an inherited-power / effective-permissions overclaim.
    assert.doesNotMatch(fed.why, /inherits the role's? (power|permissions)/i,
      `${file}: must not claim the assumer inherits the role's power`);

    // The audience (aud) check is recognized as a valid constraint, never "missing".
    if (fe.audRecognizedAsConstraint) {
      assert.match(fed.why, /audience \(aud\) check is a valid constraint/i,
        `${file}: aud recognized as a constraint`);
      assert.doesNotMatch(fed.why + fed.remediation, /missing.{0,20}aud/i,
        `${file}: never reports aud as missing`);
    }

    // Broad OIDC: recommends constraining the subject; never claims every repo
    // can actually assume the role.
    if (fe.recommendsConstrainingSub) {
      assert.match(fed.remediation, /\bsub(ject)?\b/i, `${file}: recommends constraining sub`);
      assert.match(fed.remediation, /branch|environment|ref/i,
        `${file}: recommends binding to a branch/environment/ref`);
    }
    if (fe.mustNotClaimEveryRepoCanAssume) {
      assert.doesNotMatch(fed.why, /every (repository|repo|workload) can assume/i,
        `${file}: must not claim every repository/workload can assume the role`);
    }
  }
});

test('federated findings expose per-statement evidence that maps back to the trust statement (provenance)', () => {
  for (const { file, data } of FIXTURES) {
    const result = analyze(fixtureText(data));
    const fed = result.findings.find((f) => f.id === data.federatedExpect.findingId);
    assert.ok(fed, `${file}: federated finding present`);
    assert.ok(Array.isArray(fed.evidence) && fed.evidence.length >= 1, `${file}: has evidence`);
    // A trust policy carries no Resource; its absence is normal, not a finding.
    assert.deepEqual(fed.resources, [], `${file}: no Resource on a trust finding`);
    // Every action attributed to the finding is a real trust action from the
    // analyzed statement (no synthetic attribution).
    const stmt = data.policy.Statement[fed.statementIndex] || data.policy.Statement[0];
    const declared = [].concat(stmt.Action || []).map((a) => String(a).toLowerCase());
    for (const ev of fed.evidence) {
      for (const a of ev.actions) {
        assert.ok(declared.includes(String(a).toLowerCase()),
          `${file}: attributed action ${a} must appear in its statement`);
      }
    }
  }
});

test('determinism: re-analyzing a federated fixture yields byte-identical findings', () => {
  for (const { file, data } of FIXTURES) {
    const a = analyze(fixtureText(data));
    const b = analyze(fixtureText(data));
    assert.equal(JSON.stringify(a.findings), JSON.stringify(b.findings), `${file}: deterministic findings`);
  }
});
