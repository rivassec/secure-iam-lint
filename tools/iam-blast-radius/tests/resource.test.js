// IAM-1201 (Phase 12): resource-policy family acceptance + resource-context input.
// Runs on node's built-in runner: `node --test`.
//
// The resource family is now ACCEPTED, gated on the explicit attached-resource
// context (type + ARN - the "resource-policy context is explicit" invariant,
// docs/resource-policy-semantics.md section 10). This suite drives the real
// analyze() pipeline through the fixtures/resource/ corpus and asserts:
//   - family=resource + a valid, modeled attached-resource context is ACCEPTED
//     and routed to the resource evaluator (never the identity rules): not
//     blocked, no identity findings, coverage records the detected service +
//     principal types, and coverage is INCOMPLETE (RESOURCE_ANALYSIS_INCOMPLETE)
//     because the service-specific finding rules are foundational.
//   - a MISSING required context fails closed (RESOURCE_CONTEXT_REQUIRED).
//   - a valid ARN for an UNMODELED service fails closed (UNSUPPORTED_RESOURCE_SHAPE).
// Plus unit coverage for the ARN parser + service detector (partition-preserving,
// bucket-vs-object typing) and the context validator.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { analysisStatus } from '../../../content/tools/iam-blast-radius/engine/report.js';
import {
  parseArn,
  serviceForArn,
  parseResourceContext,
  analyzeResource,
  enumeratePrincipals,
  RESOURCE_SERVICES,
  MODELED_RESOURCE_SERVICES,
  RESOURCE_CODES,
  RESOURCE_IDS,
} from '../../../content/tools/iam-blast-radius/engine/resource.js';

const here = dirname(fileURLToPath(import.meta.url));
const fxDir = join(here, '..', 'fixtures', 'resource');

function fixtureText(fx) {
  return typeof fx.policyRaw === 'string' ? fx.policyRaw : JSON.stringify(fx.policy);
}

const FIXTURES = readdirSync(fxDir)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => ({ file: f, data: JSON.parse(readFileSync(join(fxDir, f), 'utf8')) }));

// ---------------------------------------------------------------------------
// Fixture-driven acceptance (accepted + context-required + unmodeled).
// ---------------------------------------------------------------------------

test('fixtures/resource corpus is present and well-formed', () => {
  assert.ok(FIXTURES.length >= 3, `expected >=3 resource fixtures, found ${FIXTURES.length}`);
  for (const { file, data } of FIXTURES) {
    assert.ok(data.policy && typeof data.policy === 'object', `${file}: has a policy`);
    assert.ok(data.options && typeof data.options === 'object', `${file}: has analyze options`);
    assert.ok(data.expectResource && typeof data.expectResource === 'object', `${file}: has expectResource`);
  }
});

for (const { file, data } of FIXTURES) {
  test(`resource fixture ${file}: analyze() matches the resource contract`, () => {
    const e = data.expectResource;
    let res;
    assert.doesNotThrow(() => { res = analyze(fixtureText(data), data.options); }, `${file}: analyze threw`);

    assert.equal(res.ok, e.ok, `${file}: ok`);
    const cov = res.coverage;
    assert.ok(cov && typeof cov === 'object', `${file}: coverage present`);
    assert.equal(cov.blocked, e.blocked, `${file}: blocked`);
    assert.equal(cov.supported, e.supported, `${file}: supported`);
    assert.equal(res.family, e.family, `${file}: result.family`);
    if (typeof e.status === 'string') {
      assert.equal(analysisStatus(res), e.status, `${file}: analysis status`);
    }
    if (typeof e.incomplete === 'boolean') {
      assert.equal(cov.summary.incomplete, e.incomplete, `${file}: coverage incomplete`);
    }

    const codes = (cov.summary && cov.summary.codes) || [];
    for (const c of e.codes || []) {
      assert.ok(codes.includes(c), `${file}: expected code ${c}; got [${codes.join(', ')}]`);
    }
    for (const c of e.notCodes || []) {
      assert.ok(!codes.includes(c), `${file}: must NOT emit code ${c}`);
    }

    if (e.noFindings) {
      assert.equal(res.findings.length, 0, `${file}: no findings`);
      assert.equal(res.graph.nodes.length, 0, `${file}: no graph nodes`);
      assert.equal(res.graph.edges.length, 0, `${file}: no graph edges`);
    }
    for (const bad of e.notFindingIds || []) {
      assert.ok(!res.findings.some((f) => f.id === bad), `${file}: finding ${bad} must be absent`);
    }

    // IAM-1202: expected resource finding ids present (principal-centric findings).
    for (const want of e.findingIds || []) {
      assert.ok(res.findings.some((f) => f.id === want), `${file}: expected resource finding ${want}`);
    }
    // Expected severities (never overstate/understate the evidence).
    for (const [id, sev] of Object.entries(e.findingSeverities || {})) {
      const f = res.findings.find((x) => x.id === id);
      assert.ok(f, `${file}: finding ${id} present for severity check`);
      assert.equal(f.severity, sev, `${file}: ${id} severity`);
    }
    // Every resource finding carries the potential-blast-radius-not-effective caveat.
    for (const f of res.findings) {
      assert.ok(
        typeof f.limit === 'string' && /not effective access/i.test(f.limit),
        `${file}: resource finding ${f.id} lacks the capability-not-effective caveat`,
      );
      assert.ok(RESOURCE_IDS.includes(f.id), `${file}: ${f.id} is not a resource-family finding id`);
    }
    // Required substrings in a finding's rationale (transport-only, BPA, account id).
    for (const [id, needles] of Object.entries(e.whyIncludes || {})) {
      const f = res.findings.find((x) => x.id === id);
      assert.ok(f, `${file}: finding ${id} present for why check`);
      for (const needle of needles) {
        assert.ok(String(f.why).includes(needle), `${file}: ${id} why must mention "${needle}"`);
      }
    }
    // Graph: the ORIGIN is the external/anonymous principal, NOT the policy subject,
    // and access edges are the typed can-access-resource edge (no generic can-write).
    if (Array.isArray(e.graphEdgeTypes)) {
      const types = [...new Set(res.graph.edges.map((x) => x.type))].sort();
      assert.deepEqual(types, e.graphEdgeTypes.slice().sort(), `${file}: graph edge types`);
      assert.ok(!res.graph.nodes.some((n) => n.id === 'principal'), `${file}: resource graph must not root at the policy subject`);
      for (const edge of res.graph.edges) {
        const fromNode = res.graph.nodes.find((n) => n.id === edge.from);
        assert.ok(fromNode, `${file}: edge origin node ${edge.from} exists`);
        assert.notEqual(fromNode.type, 'Principal', `${file}: origin must be external/service/anonymous, not the subject`);
        const toNode = res.graph.nodes.find((n) => n.id === edge.to);
        assert.equal(toNode.type, 'Resource', `${file}: access edge targets the attached resource node`);
      }
    }
    if (Array.isArray(e.graphOriginTypes)) {
      const originTypes = [...new Set(res.graph.edges.map((x) => {
        const n = res.graph.nodes.find((nn) => nn.id === x.from);
        return n ? n.type : null;
      }).filter(Boolean))].sort();
      assert.deepEqual(originTypes, e.graphOriginTypes.slice().sort(), `${file}: graph origin node types`);
    }

    // Accepted (not blocked) -> the resource evaluator recorded the attached
    // resource context + the principal types it named.
    if (!e.blocked) {
      const rc = cov.summary.resourceContext;
      assert.ok(rc && typeof rc === 'object', `${file}: resourceContext recorded in coverage`);
      if (e.service) assert.equal(rc.service, e.service, `${file}: detected service`);
      if (Array.isArray(e.principalTypes)) {
        assert.deepEqual(rc.principalTypes.slice().sort(), e.principalTypes.slice().sort(), `${file}: principal types`);
      }
      if (typeof e.anonymousPresent === 'boolean') {
        assert.equal(rc.anonymousPresent, e.anonymousPresent, `${file}: anonymousPresent`);
      }
    }
  });
}

// A resource policy accepted with context must NEVER surface an identity-style
// finding (the routing-not-to-identity-rules invariant). It MAY surface resource-
// family findings (RESOURCE_IDS) - IAM-1202 adds PUBLIC-ACCESS / RESOURCE-CROSS-
// ACCOUNT - but every finding it emits must be a resource-family id, never a
// rules.js/escalation.js identity id.
test('accepted resource analysis never emits an identity finding', () => {
  const accepted = FIXTURES.filter(({ data }) => data.expectResource && data.expectResource.blocked === false);
  assert.ok(accepted.length >= 1, 'at least one accepted resource fixture');
  for (const { file, data } of accepted) {
    const res = analyze(fixtureText(data), data.options);
    for (const f of res.findings) {
      assert.ok(
        RESOURCE_IDS.includes(f.id),
        `${file}: accepted resource policy produced non-resource finding ${f.id} (must route to the resource evaluator, not identity)`,
      );
    }
  }
});

// Determinism: identical input + options -> byte-identical result.
test('resource analysis is deterministic', () => {
  for (const { file, data } of FIXTURES) {
    const a = JSON.stringify(analyze(fixtureText(data), data.options));
    const b = JSON.stringify(analyze(fixtureText(data), data.options));
    assert.equal(a, b, `${file}: deterministic`);
  }
});

// ---------------------------------------------------------------------------
// Unit: ARN parser + service detection (partition-preserving, bucket vs object).
// ---------------------------------------------------------------------------

test('parseArn: parses valid ARNs and preserves the partition', () => {
  const a = parseArn('arn:aws:s3:::my-bucket/key');
  assert.equal(a.partition, 'aws');
  assert.equal(a.service, 's3');
  assert.equal(a.resource, 'my-bucket/key');
  const gov = parseArn('arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/abc');
  assert.equal(gov.partition, 'aws-us-gov', 'GovCloud partition preserved, not rewritten');
  assert.equal(gov.service, 'kms');
});

test('parseArn: rejects non-ARN strings', () => {
  for (const bad of ['', 'not-an-arn', 'arn:aws:s3', 'arn::::::', 42, null, undefined]) {
    assert.equal(parseArn(bad), null, `${String(bad)} is not a valid ARN`);
  }
});

test('serviceForArn: s3 bucket vs object, sns/sqs/kms, and generic', () => {
  assert.equal(serviceForArn(parseArn('arn:aws:s3:::b')), RESOURCE_SERVICES.S3_BUCKET);
  assert.equal(serviceForArn(parseArn('arn:aws:s3:::b/key')), RESOURCE_SERVICES.S3_OBJECT);
  assert.equal(serviceForArn(parseArn('arn:aws:s3:::b/*')), RESOURCE_SERVICES.S3_OBJECT);
  assert.equal(serviceForArn(parseArn('arn:aws:sns:us-east-1:111122223333:t')), RESOURCE_SERVICES.SNS);
  assert.equal(serviceForArn(parseArn('arn:aws:sqs:us-east-1:111122223333:q')), RESOURCE_SERVICES.SQS);
  assert.equal(serviceForArn(parseArn('arn:aws:kms:us-east-1:111122223333:key/abc')), RESOURCE_SERVICES.KMS_KEY);
  assert.equal(serviceForArn(parseArn('arn:aws:kms:us-east-1:111122223333:alias/x')), RESOURCE_SERVICES.GENERIC);
  assert.equal(serviceForArn(parseArn('arn:aws:lambda:us-east-1:111122223333:function:f')), RESOURCE_SERVICES.GENERIC);
});

test('MODELED_RESOURCE_SERVICES excludes generic', () => {
  assert.ok(!MODELED_RESOURCE_SERVICES.has(RESOURCE_SERVICES.GENERIC));
  for (const svc of ['s3-bucket', 's3-object', 'sns', 'sqs', 'kms-key']) {
    assert.ok(MODELED_RESOURCE_SERVICES.has(svc), `${svc} is modeled`);
  }
});

// ---------------------------------------------------------------------------
// Unit: context validation.
// ---------------------------------------------------------------------------

test('parseResourceContext: missing/empty/invalid -> RESOURCE_CONTEXT_REQUIRED', () => {
  for (const ctx of [null, undefined, {}, { arn: '' }, { arn: '   ' }, { arn: 'nope' }, { type: 's3-bucket' }]) {
    const r = parseResourceContext(ctx);
    assert.equal(r.ok, false, `${JSON.stringify(ctx)} -> not ok`);
    assert.equal(r.code, RESOURCE_CODES.RESOURCE_CONTEXT_REQUIRED, `${JSON.stringify(ctx)} -> context-required`);
  }
});

test('parseResourceContext: unmodeled service -> UNSUPPORTED_RESOURCE_SHAPE', () => {
  const r = parseResourceContext({ arn: 'arn:aws:lambda:us-east-1:123456789012:function:f' });
  assert.equal(r.ok, false);
  assert.equal(r.code, RESOURCE_CODES.UNSUPPORTED_RESOURCE_SHAPE);
  assert.equal(r.service, RESOURCE_SERVICES.GENERIC);
});

test('parseResourceContext: modeled services accepted', () => {
  const s3 = parseResourceContext({ type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  assert.equal(s3.ok, true);
  assert.equal(s3.service, RESOURCE_SERVICES.S3_OBJECT);
  const kms = parseResourceContext({ arn: 'arn:aws:kms:us-east-1:111122223333:key/abc' });
  assert.equal(kms.ok, true);
  assert.equal(kms.service, RESOURCE_SERVICES.KMS_KEY);
  assert.equal(kms.account, '111122223333');
});

// ---------------------------------------------------------------------------
// Unit: principal enumeration + the evaluator never invents findings.
// ---------------------------------------------------------------------------

test('enumeratePrincipals: classifies distinct principal types, flags anonymous', () => {
  const model = {
    statements: [
      { principal: { anyPrincipal: true, byType: {} } },
      { principal: { anyPrincipal: false, byType: { Service: ['events.amazonaws.com'] } } },
      { principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::111122223333:root'] } } },
    ],
  };
  const p = enumeratePrincipals(model);
  assert.equal(p.anonymousPresent, true);
  assert.ok(p.types.includes('anonymous'));
  assert.ok(p.types.includes('service'));
  assert.ok(p.types.includes('aws-root'));
});

test('analyzeResource: accepted context -> ok, incomplete coverage note, records context', () => {
  // A bare principal-only statement (no Allow/actions) yields no grant finding but
  // still records the attached-resource context and stays incomplete.
  const model = { statements: [{ principal: { anyPrincipal: true, byType: {} } }] };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  assert.equal(res.ok, true);
  assert.equal(res.findings.length, 0, 'a non-Allow principal-only statement is not a grant');
  assert.equal(res.coverage.incomplete, true, 'accepted resource analysis is incomplete');
  assert.equal(res.coverage.service, RESOURCE_SERVICES.S3_OBJECT);
  assert.ok(res.coverage.anonymousPresent, 'anonymous principal surfaced');
  assert.ok(res.context && res.context.service === RESOURCE_SERVICES.S3_OBJECT, 'validated context returned for the graph');
});

test('analyzeResource: REJECTED context fails closed at the boundary (ok:false, parser code, rejected note)', () => {
  // The module boundary must honor "missing/invalid resource-context fails closed"
  // on its own - not just rely on the orchestrator gate. A rejected context must
  // yield ok:false, NO findings, the parser's ACTUAL failure code, and a note that
  // says the context was REJECTED - never one claiming it was accepted/routed/recorded.
  const model = {
    statements: [{
      index: 0, sid: 'Pub', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::b/*'],
      principal: { anyPrincipal: true, byType: {} },
    }],
  };
  // (a) missing context + (b) blank/invalid ARN -> RESOURCE_CONTEXT_REQUIRED.
  for (const ctx of [null, undefined, { arn: '' }, { arn: 'not-an-arn' }]) {
    const res = analyzeResource(model, ctx);
    assert.equal(res.ok, false, `${JSON.stringify(ctx)} -> ok:false`);
    assert.equal(res.findings.length, 0, 'no findings on a rejected context');
    assert.equal(res.context, null, 'no validated context recorded');
    assert.equal(res.coverage.code, RESOURCE_CODES.RESOURCE_CONTEXT_REQUIRED, 'parser code surfaced, not INCOMPLETE');
    assert.ok(/REJECTED/.test(res.coverage.note), 'note states the context was rejected');
    assert.ok(!/accepted and routed/.test(res.coverage.note), 'note does not claim the policy was accepted/routed');
    assert.ok(!/context is recorded/.test(res.coverage.note), 'note does not claim the context was recorded');
    assert.ok(Array.isArray(res.errors) && res.errors[0] && res.errors[0].code === RESOURCE_CODES.RESOURCE_CONTEXT_REQUIRED, 'error carries the parser code');
  }
  // (c) a valid ARN for an UNMODELED service -> UNSUPPORTED_RESOURCE_SHAPE, same fail-closed.
  const unsupported = analyzeResource(model, { arn: 'arn:aws:dynamodb:us-east-1:123456789012:table/t' });
  assert.equal(unsupported.ok, false);
  assert.equal(unsupported.coverage.code, RESOURCE_CODES.UNSUPPORTED_RESOURCE_SHAPE, 'unsupported shape code surfaced');
  assert.ok(/REJECTED/.test(unsupported.coverage.note));
  assert.ok(!/accepted and routed/.test(unsupported.coverage.note));
});

// ---------------------------------------------------------------------------
// IAM-1202: principal-centric public-access + transport-vs-identity + external.
// ---------------------------------------------------------------------------

test('analyzeResource: anonymous "*" Allow -> PUBLIC-ACCESS critical', () => {
  const model = {
    statements: [{
      index: 0, sid: 'PublicRead', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::b/*'], condition: null,
      principal: { anyPrincipal: true, byType: {} },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  const pub = res.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.ok(pub, 'PUBLIC-ACCESS emitted for an anonymous principal');
  assert.equal(pub.severity, 'critical');
  assert.equal(pub.policyEvidence, 'high');
  assert.ok(/not effective access/i.test(pub.limit), 'carries the not-effective caveat');
  assert.ok(pub.resource.anonymous, 'resource enrichment flags anonymous');
});

test('analyzeResource: {AWS:"*"} is equivalent to Principal "*" -> PUBLIC-ACCESS', () => {
  const model = {
    statements: [{
      index: 0, sid: 'PublicWrite', effect: 'Allow', actions: ['sqs:SendMessage'],
      resources: ['arn:aws:sqs:us-east-1:123456789012:q'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['*'] } },
    }],
  };
  const res = analyzeResource(model, { arn: 'arn:aws:sqs:us-east-1:123456789012:q' });
  assert.ok(res.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'AWS:* is anonymous public access');
});

test('analyzeResource: transport-only Deny does NOT suppress PUBLIC-ACCESS (test 28)', () => {
  const model = {
    statements: [
      {
        index: 0, sid: 'PublicRead', effect: 'Allow', actions: ['s3:GetObject'],
        resources: ['arn:aws:s3:::public-downloads/*'], condition: null,
        principal: { anyPrincipal: true, byType: {} },
      },
      {
        index: 1, sid: 'DenyInsecureTransport', effect: 'Deny', actions: ['s3:*'],
        resources: ['arn:aws:s3:::public-downloads', 'arn:aws:s3:::public-downloads/*'],
        condition: { Bool: { 'aws:SecureTransport': 'false' } },
        principal: { anyPrincipal: true, byType: {} },
      },
    ],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::public-downloads/*' });
  const pub = res.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.ok(pub, 'the transport Deny must not suppress the public grant');
  assert.ok(/TRANSPORT constraint/.test(pub.why), 'classified as transport-only');
  assert.ok(/does NOT make this public grant private/.test(pub.why), 'does not neutralize the public Allow');
  assert.ok(/Block Public Access/.test(pub.why), 'states the S3 BPA external-control dependency');
  assert.ok(pub.resource.transportOnlyDeny, 'resource enrichment records the transport-only Deny');
});

test('analyzeResource: an identity-shaped Deny (no SecureTransport) is NOT transport-only', () => {
  // A Deny gated on a real identity condition must not be misclassified transport-only.
  const model = {
    statements: [{
      index: 0, sid: 'PublicRead', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::b/*'], condition: null,
      principal: { anyPrincipal: true, byType: {} },
    }, {
      index: 1, sid: 'DenyOutsideOrg', effect: 'Deny', actions: ['s3:*'],
      resources: ['arn:aws:s3:::b/*'],
      condition: { StringNotEquals: { 'aws:PrincipalOrgID': 'o-abc' } },
      principal: { anyPrincipal: true, byType: {} },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  const pub = res.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.ok(pub, 'public grant still surfaced');
  assert.equal(pub.resource.transportOnlyDeny, false, 'org Deny is not transport-only');
  assert.ok(!/TRANSPORT constraint/.test(pub.why), 'no transport-only note for a non-transport Deny');
});

test('analyzeResource: "*" narrowed by aws:PrincipalArn is NOT unconditioned anonymous (test 85)', () => {
  // suite-3 test 85: Principal "*" narrowed by an ArnLike aws:PrincipalArn
  // condition restricts use to AUTHENTICATED principals matching a role path, so
  // anonymous/unauthenticated reach is exactly what the condition excludes. The
  // finding must not claim "anyone / including anonymous", must not be the
  // unconditioned-critical public finding, and must keep the condition value valid.
  const model = {
    statements: [{
      index: 0, sid: 'ScopedByArn', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::deployments/*'],
      condition: { ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/deployment/*' } },
      principal: { anyPrincipal: true, byType: {} },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::deployments/*' });
  const pub = res.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.ok(pub, 'a "*" grant still surfaces (fail closed toward surfacing)');
  // Not the unconditioned-critical public framing.
  assert.notEqual(pub.severity, 'critical', 'a principal-scoped "*" is not unconditioned-critical');
  assert.equal(pub.severity, 'high');
  assert.ok(!/anyone can/i.test(pub.why), 'does not assert "anyone can" reach');
  assert.ok(!/including anonymous/i.test(pub.why), 'drops the including-anonymous claim');
  assert.ok(/NARROWED|narrowed/.test(pub.why), 'describes the "*" as narrowed by the condition');
  assert.ok(/aws:PrincipalArn/.test(pub.why), 'names the principal-scoping condition key');
  // The condition VALUE (with its wildcard) is preserved verbatim, not rejected.
  assert.deepEqual(pub.conditions, model.statements[0].condition, 'condition value preserved');
  assert.deepEqual(pub.resource.principalScopedBy, ['aws:PrincipalArn'], 'records the scoping key');
  // pathExploitability stays capped for a conditioned grant.
  assert.equal(pub.pathExploitability, 'medium');
  // No S3 Block-Public-Access "public grant" narrative (it is not a public grant).
  assert.ok(!/Block Public Access/.test(pub.why), 'no BPA public-grant note for a scoped grant');
});

test('analyzeResource: "*" scoped by aws:PrincipalTag is narrowed, not anonymous public (test 49)', () => {
  // adversarial-critic IAM-1202 iteration 4 finding 1: a principal-IDENTITY key
  // (aws:PrincipalTag, aws:userid, aws:PrincipalOrgPaths, aws:PrincipalType) gating a
  // "*" Allow with a POSITIVE operator excludes anonymous callers (who carry no such
  // key), exactly like aws:PrincipalOrgID. It must be reported NARROWED/high, never
  // the unconditioned-critical "anyone including anonymous" public finding. Suite-2
  // test 49 also ANDs a network selector (aws:SourceVpce); it stays narrowed/high.
  const model = {
    statements: [{
      index: 0, sid: 'RestrictedArtifactRead', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::release-artifacts/*'],
      condition: {
        StringEquals: {
          'aws:SourceVpce': ['vpce-0123456789abcdef0', 'vpce-0fedcba9876543210'],
          'aws:PrincipalTag/environment': 'production',
        },
      },
      principal: { anyPrincipal: true, byType: {} },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::release-artifacts/*' });
  const pub = res.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.ok(pub, 'a "*" grant still surfaces (fail closed toward surfacing)');
  assert.notEqual(pub.severity, 'critical', 'a principal-tag-scoped "*" is not unconditioned-critical');
  assert.equal(pub.severity, 'high');
  assert.ok(!/anyone can/i.test(pub.why), 'does not assert "anyone can" reach');
  assert.ok(!/including anonymous/i.test(pub.why), 'drops the including-anonymous claim');
  assert.ok(/NARROWED|narrowed/.test(pub.why), 'describes the "*" as narrowed by the condition');
  assert.ok(/aws:PrincipalTag\/environment/.test(pub.why), 'names the principal-tag scoping key');
  assert.deepEqual(pub.resource.principalScopedBy, ['aws:PrincipalTag/environment'], 'records only the principal-identity key (not the network selector) as scoping');
  assert.ok(!/Block Public Access/.test(pub.why), 'no BPA public-grant note for a scoped grant');
});

test('analyzeResource: aws:userid also counts as principal-scoping (narrowed, not public)', () => {
  const model = {
    statements: [{
      index: 0, sid: 'ScopedByUserId', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::b/*'],
      condition: { StringEquals: { 'aws:userid': 'AIDACKCEVSQ6C2EXAMPLE' } },
      principal: { anyPrincipal: true, byType: {} },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  const pub = res.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.equal(pub.severity, 'high', 'aws:userid narrows the anonymous "*"');
  assert.deepEqual(pub.resource.principalScopedBy, ['aws:userid']);
  assert.ok(!/including anonymous/i.test(pub.why));
});

test('analyzeResource: NEGATED principal condition is an EXPANSION, stays critical public (not narrowed)', () => {
  // adversarial-critic IAM-1202 iteration 4 finding 2: StringNotEquals aws:PrincipalOrgID
  // on a "*" Allow permits every principal OUTSIDE the org (an exclusion/expansion),
  // and a negated match also succeeds when the key is absent, so anonymous callers are
  // NOT excluded. It must NOT be credited as narrowing (no downgrade to high, no
  // "restricts to authenticated principals / anonymous excluded" claim) and must stay
  // critical, mirroring the trust family's TRUST-ORG-EXPANSION severity.
  const model = {
    statements: [{
      index: 0, sid: 'ExcludeOrg', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::b/*'],
      condition: { StringNotEquals: { 'aws:PrincipalOrgID': 'o-abc123' } },
      principal: { anyPrincipal: true, byType: {} },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  const pub = res.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.ok(pub, 'the "*" grant still surfaces');
  assert.equal(pub.severity, 'critical', 'a negated principal condition does NOT narrow - stays critical');
  assert.deepEqual(pub.resource.principalScopedBy, [], 'a negated operator credits NO scoping key');
  assert.ok(/EXCLUSION|negated/i.test(pub.why), 'names the exclusion/negation hazard');
  assert.ok(/outside the named organization|OUTSIDE/i.test(pub.why), 'explains the everyone-except semantics');
  // Must not make the affirmative narrowed claim (the wording the narrowed branch uses).
  assert.ok(!/is NARROWED by a principal-scoping condition/.test(pub.why), 'does not use the narrowed-branch claim');
  assert.ok(!/anonymous, unauthenticated callers are exactly what the condition excludes/.test(pub.why), 'does not claim anonymous is excluded');
  assert.ok(!/narrowed by a principal condition/i.test(pub.title), 'not the narrowed title');
});

test('analyzeResource: ArnNotEquals aws:PrincipalArn (allow-everyone-except) stays critical, not narrowed', () => {
  const model = {
    statements: [{
      index: 0, sid: 'ExcludeOneRole', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::b/*'],
      condition: { ArnNotEquals: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/blocked' } },
      principal: { anyPrincipal: true, byType: {} },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  const pub = res.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.equal(pub.severity, 'critical', 'ArnNotEquals is an exclusion, not a narrowing');
  assert.deepEqual(pub.resource.principalScopedBy, []);
  assert.ok(!/narrowed by a principal condition/i.test(pub.title), 'not the narrowed title');
});

test('analyzeResource: aws:SecureTransport does NOT count as principal-scoping (still public)', () => {
  // Guard: a transport/network selector must not be mistaken for a principal
  // condition. A "*" Allow conditioned only on aws:SecureTransport stays public.
  const model = {
    statements: [{
      index: 0, sid: 'PublicOverTls', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::b/*'],
      condition: { Bool: { 'aws:SecureTransport': 'true' } },
      principal: { anyPrincipal: true, byType: {} },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  const pub = res.findings.find((f) => f.id === 'PUBLIC-ACCESS');
  assert.ok(pub, 'public grant surfaced');
  assert.equal(pub.severity, 'critical', 'transport condition does not narrow the principal');
  assert.ok(/including anonymous/i.test(pub.why), 'still framed as anonymous/public');
  assert.deepEqual(pub.resource.principalScopedBy, [], 'transport key is not principal-scoping');
});

test('analyzeResource: named external-account principal -> RESOURCE-CROSS-ACCOUNT high (S3, hedged)', () => {
  const model = {
    statements: [{
      index: 0, sid: 'Partner', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::finance-reports/*'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::999988887777:role/PartnerRole'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::finance-reports/*' });
  const x = res.findings.find((f) => f.id === 'RESOURCE-CROSS-ACCOUNT');
  assert.ok(x, 'named external principal enumerated');
  assert.equal(x.severity, 'high');
  assert.ok(!res.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'a named external principal is not public');
  assert.ok(/999988887777/.test(x.why), 'names the principal account');
});

// Regression for the iteration-2 blocking finding (resource.js:483): S3 bucket/
// object ARNs carry NO account id, so the analyzer cannot know the bucket owner's
// account and MUST NOT assert a same-vs-cross-account relationship - a routine
// same-account S3 grant would otherwise be mislabeled external. The named grant is
// still surfaced (fail closed toward surfacing) but the account relationship is
// HEDGED, never asserted.
test('analyzeResource: S3 ARN has no account -> cross-account is HEDGED, not asserted', () => {
  const model = {
    statements: [{
      index: 0, sid: 'Named', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::finance-reports/*'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::999988887777:role/PartnerRole'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::finance-reports/*' });
  const x = res.findings.find((f) => f.id === 'RESOURCE-CROSS-ACCOUNT');
  assert.ok(x, 'named external-account principal is still surfaced');
  assert.ok(/potentially cross-account/.test(x.why), 'account relationship hedged as indeterminate');
  assert.ok(/does not include an account id/.test(x.why), 'states the S3 ARN carries no account');
  assert.ok(!/This is a cross-account grant/.test(x.why), 'must NOT assert a confirmed cross-account relationship on S3 evidence');
  assert.ok(/undetermined/i.test(x.title), 'title reflects the undetermined account relationship');
});

// The confident cross-account claim is reserved for a resource ARN that DOES carry
// an owning account (SNS/SQS/KMS) where the principal's account is known to differ.
test('analyzeResource: account-bearing resource ARN -> CONFIRMED cross-account wording', () => {
  const model = {
    statements: [{
      index: 0, sid: 'Partner', effect: 'Allow', actions: ['sns:Publish'],
      resources: ['arn:aws:sns:us-east-1:123456789012:events'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::999988887777:role/PartnerRole'] } },
    }],
  };
  const res = analyzeResource(model, { arn: 'arn:aws:sns:us-east-1:123456789012:events' });
  const x = res.findings.find((f) => f.id === 'RESOURCE-CROSS-ACCOUNT');
  assert.ok(x, 'confirmed cross-account grant surfaced');
  assert.equal(x.severity, 'high');
  assert.ok(/This is a cross-account grant/.test(x.why), 'confident wording when both accounts are known and differ');
  assert.ok(!/potentially cross-account/.test(x.why), 'not hedged when the relationship is confirmed');
});

// A KNOWN same-account grant on an account-bearing ARN is now reported as a direct
// RESOURCE-SAME-ACCOUNT-GRANT (IAM-1204), NOT flagged cross-account - the account
// comparison routes it to the same-account finding (complements the KMS same-account
// test below, on SQS).
test('analyzeResource: account-bearing resource ARN, same account -> RESOURCE-SAME-ACCOUNT-GRANT (IAM-1204)', () => {
  const model = {
    statements: [{
      index: 0, sid: 'SameAcct', effect: 'Allow', actions: ['sqs:SendMessage'],
      resources: ['arn:aws:sqs:us-east-1:123456789012:q'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::123456789012:role/App'] } },
    }],
  };
  const res = analyzeResource(model, { arn: 'arn:aws:sqs:us-east-1:123456789012:q' });
  const sa = res.findings.find((f) => f.id === 'RESOURCE-SAME-ACCOUNT-GRANT');
  assert.ok(sa, 'same-account grant reported as a direct resource grant');
  assert.equal(sa.severity, 'medium');
  assert.ok(!res.findings.some((f) => f.id === 'RESOURCE-CROSS-ACCOUNT'), 'not flagged cross-account');
  assert.ok(/123456789012/.test(sa.why), 'names the owning account');
  assert.ok(/implicit deny/i.test(sa.why), 'explains resource-vs-identity (implicit deny does not limit)');
  assert.ok(/EXPLICIT Deny/.test(sa.why), 'explicit deny still applies');
});

test('analyzeResource: same-account principal reported as direct grant, not cross-account (KMS)', () => {
  // KMS key in account 111122223333; a role in the SAME account -> a direct
  // same-account grant (IAM-1204), never cross-account.
  const model = {
    statements: [{
      index: 0, sid: 'SameAcct', effect: 'Allow', actions: ['kms:Decrypt'],
      resources: ['*'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::111122223333:role/App'] } },
    }],
  };
  const res = analyzeResource(model, { arn: 'arn:aws:kms:us-east-1:111122223333:key/abc' });
  const sa = res.findings.find((f) => f.id === 'RESOURCE-SAME-ACCOUNT-GRANT');
  assert.ok(sa, 'same-account KMS grant surfaced as a direct grant');
  assert.ok(!res.findings.some((f) => f.id === 'RESOURCE-CROSS-ACCOUNT'), 'not cross-account');
  assert.ok(/IAM role/.test(sa.why), 'principal typed as an IAM role');
});

// IAM-1204 test 32: same-account IAM-USER grant on an S3 bucket policy. S3 ARNs
// carry no account, so the owning account is supplied explicitly in the context.
test('analyzeResource: same-account IAM-user grant with explicit owner account (test 32)', () => {
  const model = {
    statements: [{
      index: 0, sid: 'DirectUserGrant', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::finance-reports/*'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::123456789012:user/Alice'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-bucket', arn: 'arn:aws:s3:::finance-reports', account: '123456789012' });
  const sa = res.findings.find((f) => f.id === 'RESOURCE-SAME-ACCOUNT-GRANT');
  assert.ok(sa, 'direct same-account user grant reported');
  assert.equal(sa.severity, 'medium');
  assert.equal(sa.policyEvidence, 'high');
  assert.ok(/IAM user/.test(sa.why), 'typed as an IAM user, not generalized to a role');
  assert.ok(/not generalized/i.test(sa.why), 'does not generalize to other principal types / cross-account');
  assert.ok(!res.findings.some((f) => f.id === 'RESOURCE-CROSS-ACCOUNT'), 'a same-account grant is not cross-account');
  assert.ok(!res.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'a named principal is not public');
});

// IAM-1204 test 33: an assumed-role SESSION principal is identified as ONE exact
// session and NEVER collapsed to the underlying role ARN.
test('analyzeResource: assumed-role session principal identified as one session, not the role (test 33)', () => {
  const sessionArn = 'arn:aws:sts::123456789012:assumed-role/IncidentResponder/session-2026-08';
  const model = {
    statements: [{
      index: 0, sid: 'DirectSessionGrant', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::incident-evidence/*'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: [sessionArn] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::incident-evidence/*', account: '123456789012' });
  const sa = res.findings.find((f) => f.id === 'RESOURCE-SAME-ACCOUNT-GRANT');
  assert.ok(sa, 'direct same-account session grant reported');
  assert.ok(/assumed-role session/.test(sa.why), 'typed as an assumed-role session');
  assert.ok(/ONE\s+exact session/.test(sa.why), 'identified as one exact session');
  assert.ok(/NOT collapsed to the underlying role/.test(sa.why), 'not collapsed to the role ARN');
  // The exact session ARN is preserved verbatim in evidence, never the role ARN.
  const ev = sa.evidence[0].principals.map((p) => p.value);
  assert.ok(ev.includes(sessionArn), 'session ARN preserved verbatim');
  assert.ok(!ev.includes('arn:aws:iam::123456789012:role/IncidentResponder'), 'never rewritten to the role ARN');
});

// IAM-1204: an EXTERNAL principal on an account-bearing resource whose owner account
// is supplied explicitly is still confirmed cross-account (not swallowed by the
// same-account split).
test('analyzeResource: explicit owner account, different principal account -> cross-account', () => {
  const model = {
    statements: [{
      index: 0, sid: 'Partner', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::finance-reports/*'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::999988887777:role/PartnerRole'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::finance-reports/*', account: '123456789012' });
  const x = res.findings.find((f) => f.id === 'RESOURCE-CROSS-ACCOUNT');
  assert.ok(x, 'external principal is cross-account');
  assert.ok(/This is a cross-account grant/.test(x.why), 'confirmed cross-account (both accounts known and differ)');
  assert.ok(!res.findings.some((f) => f.id === 'RESOURCE-SAME-ACCOUNT-GRANT'), 'not same-account');
});

// IAM-1204 test 50 (resource context): an S3 object action on a bucket-only ARN is
// an action/resource-type mismatch, not confirmed object read.
test('analyzeResource: s3:GetObject on a bucket-only ARN -> RESOURCE-ACTION-RESOURCE-MISMATCH (test 50)', () => {
  const model = {
    statements: [{
      index: 0, sid: 'IncorrectObjectReadScope', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::documents'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::123456789012:user/Alice'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-bucket', arn: 'arn:aws:s3:::documents', account: '123456789012' });
  const mm = res.findings.find((f) => f.id === 'RESOURCE-ACTION-RESOURCE-MISMATCH');
  assert.ok(mm, 'bucket-only object action flagged as a mismatch');
  assert.equal(mm.severity, 'low');
  assert.equal(mm.policyEvidence, 'low', 'object access is unconfirmed');
  assert.ok(/does NOT confirm object read/i.test(mm.why), 'does not report confirmed object read');
  assert.ok(/object-scoped resource/.test(mm.why), 'explains object-scope requirement');
  assert.ok(/not effective access/i.test(mm.limit), 'carries the caveat');
});

test('analyzeResource: s3:GetObject on an OBJECT-scoped ARN -> no mismatch', () => {
  const model = {
    statements: [{
      index: 0, sid: 'CorrectObjectRead', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::documents/*'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::123456789012:user/Alice'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::documents/*', account: '123456789012' });
  assert.ok(!res.findings.some((f) => f.id === 'RESOURCE-ACTION-RESOURCE-MISMATCH'), 'object-scoped resource is not a mismatch');
});

test('analyzeResource: a BUCKET action (s3:ListBucket) on a bucket ARN -> no mismatch', () => {
  const model = {
    statements: [{
      index: 0, sid: 'ListOnly', effect: 'Allow', actions: ['s3:ListBucket'],
      resources: ['arn:aws:s3:::documents'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::123456789012:user/Alice'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-bucket', arn: 'arn:aws:s3:::documents', account: '123456789012' });
  assert.ok(!res.findings.some((f) => f.id === 'RESOURCE-ACTION-RESOURCE-MISMATCH'), 'a bucket action on a bucket ARN is correct');
});

// Without an explicit owner account, an S3 same-account-looking grant stays HEDGED
// as cross-account (undetermined) - the analyzer never assumes same-account (guardrail).
test('analyzeResource: S3 without owner account -> same-account NOT assumed (hedged cross-account)', () => {
  const model = {
    statements: [{
      index: 0, sid: 'Named', effect: 'Allow', actions: ['s3:GetObject'],
      resources: ['arn:aws:s3:::finance-reports/*'], condition: null,
      principal: { anyPrincipal: false, byType: { AWS: ['arn:aws:iam::123456789012:user/Alice'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::finance-reports/*' });
  assert.ok(!res.findings.some((f) => f.id === 'RESOURCE-SAME-ACCOUNT-GRANT'), 'never assumes same-account without the owning account');
  const x = res.findings.find((f) => f.id === 'RESOURCE-CROSS-ACCOUNT');
  assert.ok(x, 'still surfaced (fail closed toward surfacing)');
  assert.ok(/potentially cross-account/.test(x.why), 'hedged as undetermined');
});

// ---------------------------------------------------------------------------
// IAM-1203: confused-deputy on resource policies (service principals).
// ---------------------------------------------------------------------------

test('analyzeResource: service principal without source binding -> RESOURCE-CONFUSED-DEPUTY (test 26), NOT public', () => {
  // A service principal is confused-deputy territory (IAM-1203), not public write.
  const model = {
    statements: [{
      index: 0, sid: 'Svc', effect: 'Allow', actions: ['sns:Publish'],
      resources: ['arn:aws:sns:us-west-2:123456789012:t'], condition: null,
      principal: { anyPrincipal: false, byType: { Service: ['events.amazonaws.com'] } },
    }],
  };
  const res = analyzeResource(model, { arn: 'arn:aws:sns:us-west-2:123456789012:t' });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.ok(cd, 'a service principal without source binding is a confused-deputy exposure');
  assert.equal(cd.severity, 'medium', 'unbound service grant is medium');
  assert.equal(cd.policyEvidence, 'high');
  assert.ok(/not effective access/i.test(cd.limit), 'carries the not-effective caveat');
  assert.ok(/NO source binding/.test(cd.why), 'names the missing source binding');
  assert.ok(/events\.amazonaws\.com/.test(cd.why), 'names the service principal');
  assert.ok(/NOT public/i.test(cd.why), 'explicitly not public write');
  assert.ok(!res.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'a service principal is not "*"');
  assert.equal(cd.resource.sourceBinding.state, 'unbound');
  assert.deepEqual(cd.resource.principalTypes, ['service']);
});

test('analyzeResource: properly source-bound service principal -> negative control info (test 27)', () => {
  const model = {
    statements: [{
      index: 0, sid: 'Bound', effect: 'Allow', actions: ['sns:Publish'],
      resources: ['arn:aws:sns:us-west-2:123456789012:t'],
      condition: {
        ArnEquals: { 'aws:SourceArn': 'arn:aws:events:us-west-2:123456789012:rule/security-alerts' },
        StringEquals: { 'aws:SourceAccount': '123456789012' },
      },
      principal: { anyPrincipal: false, byType: { Service: ['events.amazonaws.com'] } },
    }],
  };
  const res = analyzeResource(model, { arn: 'arn:aws:sns:us-west-2:123456789012:t' });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.ok(cd, 'source-bound service grant still reported as a (negative) control');
  assert.equal(cd.severity, 'info', 'source-bound is a negative control, informational');
  assert.ok(/NEGATIVE control/.test(cd.why), 'framed as a negative control');
  assert.ok(!/NO source binding/.test(cd.why), 'no missing-source-binding warning');
  assert.ok(/does NOT infer whether the referenced source resource actually exists/.test(cd.why), 'does not infer source-resource existence');
  assert.equal(cd.resource.sourceBinding.state, 'source-bound');
  assert.deepEqual(cd.resource.sourceBinding.boundKeys, ['aws:SourceAccount', 'aws:SourceArn']);
});

test('analyzeResource: mismatched SourceArn/SourceAccount -> inconsistent warning (test 53), not praised, not public-write', () => {
  const model = {
    statements: [{
      index: 0, sid: 'Mismatch', effect: 'Allow', actions: ['s3:PutObject'],
      resources: ['arn:aws:s3:::central-cloudtrail/AWSLogs/111122223333/*'],
      condition: {
        StringEquals: { 'aws:SourceAccount': '111122223333' },
        ArnLike: { 'aws:SourceArn': 'arn:aws:cloudtrail:*:444455556666:trail/*' },
      },
      principal: { anyPrincipal: false, byType: { Service: ['cloudtrail.amazonaws.com'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::central-cloudtrail/AWSLogs/111122223333/*' });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.ok(cd, 'mismatched binding surfaced');
  assert.equal(cd.severity, 'medium');
  assert.ok(/inconsistent/i.test(cd.why), 'names the inconsistency');
  assert.ok(/111122223333/.test(cd.why) && /444455556666/.test(cd.why), 'names both disagreeing accounts');
  assert.ok(/NOT a correctly source-bound control/.test(cd.why), 'not praised as source-bound');
  assert.ok(/NOT public write/.test(cd.why), 'not a public-write finding');
  assert.ok(!res.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'never public-access');
  assert.equal(cd.resource.sourceBinding.state, 'mismatched');
  assert.equal(cd.resource.sourceBinding.sourceArnAccount, '444455556666');
  assert.equal(cd.resource.sourceBinding.sourceAccount, '111122223333');
});

test('analyzeResource: multi-account SourceArn all disagreeing with SourceAccount -> mismatched (IAM-1204), not praised', () => {
  // A two-value SourceArn list pins accounts 444455556666 and 777788889999; neither
  // matches the SourceAccount 111122223333. commonSourceAccount() collapses a multi-
  // account list to null, so the single-common mismatch guard used to skip this and
  // mis-credit it as a clean source-bound negative control. It must be mismatched.
  const model = {
    statements: [{
      index: 0, sid: 'MultiMismatch', effect: 'Allow', actions: ['s3:PutObject'],
      resources: ['arn:aws:s3:::b/*'],
      condition: {
        StringEquals: { 'aws:SourceAccount': '111122223333' },
        ArnLike: { 'aws:SourceArn': ['arn:aws:cloudtrail:*:444455556666:trail/a', 'arn:aws:cloudtrail:*:777788889999:trail/b'] },
      },
      principal: { anyPrincipal: false, byType: { Service: ['cloudtrail.amazonaws.com'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.ok(cd, 'multi-account mismatched binding surfaced');
  assert.equal(cd.severity, 'medium', 'inconsistent binding is medium, not an info negative control');
  assert.equal(cd.resource.sourceBinding.state, 'mismatched');
  assert.ok(/inconsistent/i.test(cd.why), 'names the inconsistency');
  assert.ok(/NOT a correctly source-bound control/.test(cd.why), 'not praised as source-bound');
  assert.ok(!/NEGATIVE control/.test(cd.why), 'not framed as a negative control');
  assert.ok(/111122223333/.test(cd.why), 'names SourceAccount');
  assert.ok(/444455556666/.test(cd.why) && /777788889999/.test(cd.why), 'names every disagreeing SourceArn account');
  assert.ok(!res.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'never public-access');
});

test('analyzeResource: multi-account SourceArn where ONE account matches SourceAccount -> stays source-bound', () => {
  // If any resolvable SourceArn account agrees with SourceAccount, the binding is not
  // internally inconsistent; the conservative classification is a source-bound control.
  const model = {
    statements: [{
      index: 0, sid: 'OneMatches', effect: 'Allow', actions: ['s3:PutObject'],
      resources: ['arn:aws:s3:::b/*'],
      condition: {
        StringEquals: { 'aws:SourceAccount': '111122223333' },
        ArnLike: { 'aws:SourceArn': ['arn:aws:cloudtrail:*:111122223333:trail/a', 'arn:aws:cloudtrail:*:777788889999:trail/b'] },
      },
      principal: { anyPrincipal: false, byType: { Service: ['cloudtrail.amazonaws.com'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.ok(cd, 'binding surfaced');
  assert.equal(cd.severity, 'info', 'a matching SourceArn account keeps this a source-bound negative control');
  assert.equal(cd.resource.sourceBinding.state, 'source-bound');
});

test('analyzeResource: multi-account SourceAccount all disagreeing with SourceArn -> mismatched (symmetry), not praised', () => {
  // The mirror of the multi-account-SourceArn case: aws:SourceAccount is a two-value
  // array whose EVERY value disagrees with the single SourceArn account. commonSource
  // Account() collapses the multi-valued SourceAccount to null, so an asymmetric guard
  // (SourceArn set vs a single SourceAccount value) skipped this and mis-credited it as
  // a clean source-bound negative control. Detected symmetrically (set vs set), it is a
  // mismatched, internally-inconsistent binding - medium, never an info negative control.
  const model = {
    statements: [{
      index: 0, sid: 'AcctSideMismatch', effect: 'Allow', actions: ['s3:PutObject'],
      resources: ['arn:aws:s3:::central/AWSLogs/*'],
      condition: {
        StringEquals: { 'aws:SourceAccount': ['111122223333', '222233334444'] },
        ArnLike: { 'aws:SourceArn': 'arn:aws:cloudtrail:*:444455556666:trail/a' },
      },
      principal: { anyPrincipal: false, byType: { Service: ['cloudtrail.amazonaws.com'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::central/AWSLogs/*' });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.ok(cd, 'account-side multi-value mismatch surfaced');
  assert.equal(cd.severity, 'medium', 'inconsistent binding is medium, not an info negative control');
  assert.equal(cd.resource.sourceBinding.state, 'mismatched');
  assert.ok(/inconsistent/i.test(cd.why), 'names the inconsistency');
  assert.ok(/NOT a correctly source-bound control/.test(cd.why), 'not praised as source-bound');
  assert.ok(!/NEGATIVE control/.test(cd.why), 'not framed as a negative control');
  assert.ok(/444455556666/.test(cd.why), 'names the SourceArn account');
  assert.ok(/111122223333/.test(cd.why) && /222233334444/.test(cd.why), 'names every disagreeing SourceAccount value');
  assert.ok(!res.findings.some((f) => f.id === 'PUBLIC-ACCESS'), 'never public-access');
});

test('analyzeResource: agreeing multi-value SourceAccount is NOT falsely flagged mismatch', () => {
  // If any SourceAccount value agrees with the SourceArn account, the sets intersect,
  // so it is NOT internally inconsistent and must stay a source-bound negative control.
  const model = {
    statements: [{
      index: 0, sid: 'AcctSideAgree', effect: 'Allow', actions: ['s3:PutObject'],
      resources: ['arn:aws:s3:::b/*'],
      condition: {
        StringEquals: { 'aws:SourceAccount': ['111122223333', '444455556666'] },
        ArnLike: { 'aws:SourceArn': 'arn:aws:cloudtrail:*:444455556666:trail/a' },
      },
      principal: { anyPrincipal: false, byType: { Service: ['cloudtrail.amazonaws.com'] } },
    }],
  };
  const res = analyzeResource(model, { type: 's3-object', arn: 'arn:aws:s3:::b/*' });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.ok(cd, 'binding surfaced');
  assert.equal(cd.severity, 'info', 'an intersecting SourceAccount set keeps this a source-bound negative control');
  assert.equal(cd.resource.sourceBinding.state, 'source-bound');
});

test('analyzeResource: a bypassable (IfExists) source binding does NOT count -> still exposure', () => {
  // A StringEqualsIfExists aws:SourceAccount passes when the key is absent, so it is
  // trivially evaded and must NOT be credited as a real confused-deputy binding.
  const model = {
    statements: [{
      index: 0, sid: 'Bypassable', effect: 'Allow', actions: ['sqs:SendMessage'],
      resources: ['arn:aws:sqs:us-east-1:123456789012:q'],
      condition: { StringEqualsIfExists: { 'aws:SourceAccount': '123456789012' } },
      principal: { anyPrincipal: false, byType: { Service: ['s3.amazonaws.com'] } },
    }],
  };
  const res = analyzeResource(model, { arn: 'arn:aws:sqs:us-east-1:123456789012:q' });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.ok(cd, 'confused-deputy finding present');
  assert.equal(cd.severity, 'medium', 'a bypassable binding leaves the exposure standing');
  assert.equal(cd.resource.sourceBinding.state, 'unbound');
  assert.ok(cd.resource.sourceBinding.bypassedKeys.includes('aws:SourceAccount'), 'records the bypassed key');
  assert.ok(/does NOT bind the source/.test(cd.why), 'explains why the present key does not bind');
});

test('analyzeResource: a match-all SourceArn value does NOT bind -> still exposure', () => {
  const model = {
    statements: [{
      index: 0, sid: 'MatchAll', effect: 'Allow', actions: ['sns:Publish'],
      resources: ['arn:aws:sns:us-west-2:123456789012:t'],
      condition: { ArnLike: { 'aws:SourceArn': 'arn:aws:*:*:*:*' } },
      principal: { anyPrincipal: false, byType: { Service: ['events.amazonaws.com'] } },
    }],
  };
  const res = analyzeResource(model, { arn: 'arn:aws:sns:us-west-2:123456789012:t' });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.equal(cd.severity, 'medium', 'a match-all SourceArn pins nothing');
  assert.equal(cd.resource.sourceBinding.state, 'unbound');
});

test('analyzeResource: source-bound via aws:SourceOrgID -> negative control info', () => {
  const model = {
    statements: [{
      index: 0, sid: 'OrgBound', effect: 'Allow', actions: ['sns:Publish'],
      resources: ['arn:aws:sns:us-west-2:123456789012:t'],
      condition: { StringEquals: { 'aws:SourceOrgID': 'o-exampleorgid' } },
      principal: { anyPrincipal: false, byType: { Service: ['events.amazonaws.com'] } },
    }],
  };
  const res = analyzeResource(model, { arn: 'arn:aws:sns:us-west-2:123456789012:t' });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.equal(cd.severity, 'info', 'an org-source binding is a confused-deputy mitigation');
  assert.equal(cd.resource.sourceBinding.state, 'source-bound');
});

test('analyzeResource: confused-deputy graph origin is the SERVICE principal (test 26)', () => {
  const res = analyze(JSON.stringify({
    Version: '2012-10-17',
    Statement: [{
      Sid: 'Svc', Effect: 'Allow', Principal: { Service: 'events.amazonaws.com' },
      Action: 'sns:Publish', Resource: 'arn:aws:sns:us-west-2:123456789012:t',
    }],
  }), {
    family: 'resource', requireExplicitFamily: true,
    resourceContext: { type: 'sns', arn: 'arn:aws:sns:us-west-2:123456789012:t' },
  });
  const cd = res.findings.find((f) => f.id === 'RESOURCE-CONFUSED-DEPUTY');
  assert.ok(cd, 'confused-deputy finding present via the full pipeline');
  assert.ok(res.graph.edges.length >= 1, 'a can-access edge is drawn');
  const edge = res.graph.edges.find((x) => x.type === 'can-access-resource');
  assert.ok(edge, 'edge is can-access-resource');
  const origin = res.graph.nodes.find((n) => n.id === edge.from);
  assert.equal(origin.type, 'Service', 'graph origin is the calling service, not the policy subject');
  assert.ok(!res.graph.nodes.some((n) => n.type === 'Principal'), 'no identity Principal root');
});
