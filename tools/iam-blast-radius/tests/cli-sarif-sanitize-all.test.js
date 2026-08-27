// IAM Blast Radius - SARIF output-injection + size-amplification CLASS (S2-sarif-
// sanitize-all).
//
// The CONFIRMED gap: evidence[].condition was emitted VERBATIM (row.condition =
// e.condition) while every sibling field went through a neutralizer. A Condition is a
// NESTED object whose OPERATOR + key names AND leaf values are all attacker-controlled
// (a fork PR owns the whole policy JSON), and it was uncapped PER-FIELD, so:
//   (1) a markdown/control payload in a condition key OR value reached a rendered SARIF
//       property un-neutralized, and
//   (2) a large Condition per statement could amplify a policy into a multi-hundred-KB
//       SARIF and breach GitHub's ~10MB upload limit -> silently drop findings.
//
// These tests pin the fix (recursive key+value markdown-inert neutralization, per-leaf +
// aggregate + depth bounds, cycle-safety, a bounded conditionSummary on breach) AND the
// wider sweep (artifactLocation.uri, analyzer-state properties.path), while proving the
// load-bearing fingerprint input (findingIdentity over RAW conditions) is UNTOUCHED.
//
// Neutralization is MARKDOWN-INERT (the same treatment the free-prose note gets): the
// characters are KEPT but every ASCII-punctuation char is backslash-escaped, so a
// consumer that renders the field as markdown gets literals - no link/image/code span.
// The checkable invariant is therefore "no UNescaped markdown boundary survives", not
// "the bracket characters are gone".

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import {
  buildSarifLog, formatSarif, findingIdentity, FINGERPRINT_KEY,
} from '../../../cli/sarif.mjs';

const MANIFEST = { ruleVersion: '1' };

// C0/C1 control chars (backtick is NOT a control char; markdown-inert KEEPS it, escaped).
const CONTROL = /[\u0000-\u001F\u007F-\u009F]/;

// Assert a rendered string is markdown-inert + control-free: no control char, no
// unescaped link/image boundary "](", and no backtick that could open a code span
// (every backtick must be backslash-escaped).
function assertInert(s, label) {
  assert.equal(typeof s, 'string', `${label}: is a string`);
  assert.ok(!CONTROL.test(s), `${label}: no control chars`);
  assert.ok(!s.includes(']('), `${label}: no unescaped markdown link/image boundary`);
  assert.ok(!/(^|[^\\])`/.test(s), `${label}: no unescaped backtick (no code span can open)`);
}

// Remove backtick inline-code spans. A SECURITY-finding message.text wraps its Sid/actions
// in a code span (inert in GitHub markdown), which legitimately contains raw `](` etc.; a
// payload that leaked into a BARE properties field would appear OUTSIDE any span. Stripping
// spans first lets a whole-document assertion target only the live (bare) surfaces.
function stripCodeSpans(s) {
  return s.replace(/`[^`]*`/g, '');
}

// A scan-shaped result carrying ONE security finding whose single evidence row holds the
// given Condition object. Feeds buildSarifLog directly (a hostile/oversize Condition
// arriving through scan() would trip the input-size fail-closed guard before a finding
// is produced, so the adapter's own bound is proven at buildSarifLog - mirroring the
// existing sid/action oversize tests). `conditionsForHash` lets a test keep the finding's
// own `conditions` (the fingerprint-hash input) distinct from the evidence condition.
function evidenceResult(condition, { conditionsForHash = null } = {}) {
  return {
    analysisStatus: 'complete',
    findings: [{
      id: 'PASSROLE-SERVICE',
      severity: 'high',
      title: 'PassRole to a service',
      statementSid: 'S',
      statementIndex: 0,
      actions: ['iam:PassRole'],
      resources: ['arn:aws:iam::999988887777:role/app'],
      conditions: conditionsForHash,
      evidence: [{ statementIndex: 0, condition }],
    }],
    family: 'identity',
  };
}

function evidenceRow(result) {
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const sec = log.runs[0].results.find((r) => r.properties && Array.isArray(r.properties.evidence));
  assert.ok(sec, 'a security finding with evidence is present');
  return { log, ev: sec.properties.evidence[0], sec };
}

// =============================================================================
// (a) condition VALUES and KEYS are neutralized recursively.
// =============================================================================

test('S2: a markdown/backtick/newline payload in a condition VALUE is rendered inert', () => {
  const { ev } = evidenceRow(evidenceResult({
    StringEquals: { 'iam:PassedToService': '[x](javascript:alert(1))`bt`\nsecond' },
  }));
  // StringEquals carries no punctuation so its key is unchanged; the value is escaped.
  const val = Object.values(ev.condition.StringEquals)[0];
  assertInert(val, 'condition value');
  assert.ok(val.includes('\\[x\\]'), 'punctuation is backslash-escaped (markdown-inert)');
  assert.ok(!/[\r\n]/.test(val), 'newline collapsed to a space');
});

test('S2: a markdown/backtick payload in a condition KEY (operator + key names) is rendered inert', () => {
  const { ev } = evidenceRow(evidenceResult({
    '[oplink](javascript:1)': { '[keylink](javascript:2)`bt`': 'v' },
  }));
  const opKey = Object.keys(ev.condition)[0];
  assertInert(opKey, 'operator key');
  const innerKey = Object.keys(ev.condition[opKey])[0];
  assertInert(innerKey, 'condition key');
});

test('S2: nested array VALUES in a condition are neutralized element-by-element', () => {
  const { ev } = evidenceRow(evidenceResult({
    StringEquals: { 'aws:PrincipalOrgID': ['[a](javascript:1)', 'ok', '![img](x)'] },
  }));
  const arr = Object.values(ev.condition.StringEquals)[0];
  assert.ok(Array.isArray(arr) && arr.length === 3, 'array shape + count preserved');
  arr.forEach((el, i) => assertInert(el, `array element ${i}`));
});

test('S2: a benign condition rides through with structure preserved (no false mangling)', () => {
  const { ev } = evidenceRow(evidenceResult({
    StringEquals: { 'iam:PassedToService': 'ec2.amazonaws.com' },
  }));
  assert.ok(ev.condition && ev.condition.StringEquals, 'operator + nesting preserved');
  assert.equal(ev.conditionTruncated, undefined, 'a small benign condition is not truncated');
  const val = Object.values(ev.condition.StringEquals)[0];
  assert.ok(val.includes('ec2') && val.includes('amazonaws'), 'value content preserved (punct escaped)');
});

// =============================================================================
// (b) per-leaf length cap + (c) aggregate node/char cap + depth + cycle bounds.
// =============================================================================

test('S2: a near-1MB scripted condition VALUE is per-leaf capped + inert and never bloats the SARIF', () => {
  const huge = `[x](javascript:alert(1))${'A'.repeat(1024 * 1024)}`;
  const result = evidenceResult({ StringEquals: { 'aws:X': huge } });
  const { ev } = evidenceRow(result);
  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  // A single leaf is bounded by the PER-LEAF cap (ellipsized), so the condition is still
  // emitted (not aggregate-truncated) but stays tiny + inert; the 1MB blob never lands.
  const val = Object.values(ev.condition.StringEquals)[0];
  assert.ok(val.length < 300, `leaf capped (${val.length})`);
  assertInert(val, 'capped leaf');
  assert.ok(!serialized.includes('A'.repeat(1000)), 'the 1MB blob never lands in the SARIF');
  assert.ok(serialized.length < 20 * 1024, `SARIF stays small (${serialized.length} bytes)`);
});

test('S2: MANY condition entries are AGGREGATE-capped -> conditionTruncated + bounded summary, raw object dropped', () => {
  const cond = { StringEquals: {} };
  for (let i = 0; i < 5000; i++) cond.StringEquals[`aws:Key${i}`] = `[x](javascript:1)val-${i}`;
  const result = evidenceResult(cond);
  const { ev } = evidenceRow(result);
  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  assert.equal(ev.conditionTruncated, true, 'aggregate breach is flagged truncated');
  assert.equal(ev.condition, undefined, 'the raw object is NOT emitted when truncated');
  assert.ok(typeof ev.conditionSummary === 'string' && ev.conditionSummary.length <= 483,
    `bounded conditionSummary (${ev.conditionSummary.length})`);
  assertInert(ev.conditionSummary, 'conditionSummary');
  assert.ok(serialized.length < 20 * 1024, `5000 entries do not amplify (${serialized.length} bytes)`);
});

test('S2: a FLAT-ROOT aggregate breach yields a conditionSummary bounded AS RENDERED (escape cannot 2x it)', () => {
  // A flat root object trips the aggregate cap with partial children ALREADY attached, so
  // the surviving `value` is a large partial (unlike a nested breach, where the parent
  // discards the partial and the summary collapses to "{}"). JSON.stringify of that partial
  // is punctuation-dense; inertLeaf(raw, 480) escapes AFTER slicing, which can ~double the
  // emitted length past the documented cap. inertSummary must hard-clamp the RENDERED string.
  const cond = {};
  for (let i = 0; i < 400; i++) cond[`aws:Key${i}`] = `[x](javascript:1)val-${i}`;
  const { ev } = evidenceRow(evidenceResult(cond));
  assert.equal(ev.conditionTruncated, true, 'flat-root aggregate breach is flagged truncated');
  assert.equal(ev.condition, undefined, 'the raw object is NOT emitted when truncated');
  // The documented bound (MAX_CONDITION_SUMMARY_LEN 480) + a clean 3-char ellipsis. Before
  // the fix this path emitted ~734 chars, silently violating the suite's own <= 483 claim.
  assert.ok(ev.conditionSummary.length <= 483,
    `conditionSummary bounded AS RENDERED (${ev.conditionSummary.length})`);
  assertInert(ev.conditionSummary, 'flat-root conditionSummary');
});

test('S2: a condition nested past MAX_DEPTH is bounded (truncated), not walked unboundedly', () => {
  // ~200 nested single-key objects (validate.js MAX_DEPTH is 64).
  let cond = { leaf: 'ok' };
  for (let i = 0; i < 200; i++) cond = { StringEquals: cond };
  const { ev } = evidenceRow(evidenceResult(cond));
  assert.equal(ev.conditionTruncated, true, 'over-deep condition is flagged truncated');
  assert.equal(ev.condition, undefined, 'raw object not emitted');
});

test('S2: a CYCLIC condition object is handled defensively (truncated, no throw)', () => {
  const cond = { StringEquals: {} };
  cond.StringEquals.self = cond; // cycle - the evidence condition ONLY (never the hash input)
  // conditionsForHash stays null so the untouchable stableStringify/findingIdentity path
  // (which has no cycle guard by contract) is never handed a cyclic object.
  let ev;
  assert.doesNotThrow(() => { ev = evidenceRow(evidenceResult(cond)).ev; }, 'no throw on a cycle');
  assert.equal(ev.conditionTruncated, true, 'cyclic condition is flagged truncated');
});

test('S2: no unescaped markdown boundary / backtick from a hostile condition survives in the serialized SARIF', () => {
  const result = evidenceResult({
    '[op](javascript:1)': { '[k](javascript:2)': ['[v](javascript:3)', 'x`bt`'] },
  });
  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  assert.ok(!serialized.includes(']('), 'no unescaped "](": no link can form from the condition');
  assert.ok(!serialized.includes('`bt`'), 'a backtick pair cannot ride through raw');
});

// =============================================================================
// End-to-end: a hostile condition through the REAL engine (scan) is neutralized.
// =============================================================================

test('S2: end-to-end - a scripted Condition on a real PassRole escalation is neutralized in SARIF', () => {
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'Pass', Effect: 'Allow', Action: 'iam:PassRole',
        Resource: 'arn:aws:iam::999988887777:role/app',
        // A non-gating condition whose operator/key/value all carry a markdown payload;
        // it attaches as escalation evidence without blocking the EC2 route.
        Condition: { StringEquals: { '[keylink](javascript:1)': '[x](javascript:alert(1))`bt`' } },
      },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  });
  const result = scan({ text, family: 'identity', subjectAccount: '999988887777' });
  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const withEv = log.runs[0].results.find((r) => r.properties
    && Array.isArray(r.properties.evidence)
    && r.properties.evidence.some((e) => e.condition));
  assert.ok(withEv, 'an escalation finding carries a condition through to SARIF');
  const cond = withEv.properties.evidence.find((e) => e.condition).condition;
  const opKey = Object.keys(cond)[0];
  assertInert(opKey, 'e2e operator key');
  assertInert(Object.values(cond[opKey])[0], 'e2e condition value');
  assert.ok(!serialized.includes(']('), 'no live markdown link survives end-to-end');
  assert.ok(!serialized.includes('`bt`'), 'no raw backtick pair survives end-to-end');
});

// =============================================================================
// Fingerprint invariant: findingIdentity (RAW conditions -> partialFingerprints hash) is
// UNCHANGED. Neutralization is display-only and must not touch the hash input, or every
// dismissed alert on every consumer repo would auto-un-suppress.
// =============================================================================

test('S2: partialFingerprints hash the RAW condition, unaffected by neutralization', () => {
  const raw = { StringEquals: { 'iam:PassedToService': '[x](javascript:alert(1))ec2.amazonaws.com' } };
  const f = {
    id: 'PASSROLE-SERVICE', severity: 'high', title: 't', statementSid: 'S', statementIndex: 0,
    actions: ['iam:PassRole'], resources: ['r'], conditions: raw,
    escalation: { service: 'ec2', technique: 'RunInstances' },
  };
  const log = buildSarifLog({ findings: [f], family: 'identity' }, { file: 'p.json' }, MANIFEST);
  const fp = log.runs[0].results[0].partialFingerprints[FINGERPRINT_KEY];
  // The identity STRING is built from the RAW condition (still carries the live payload):
  // this proves the hash input is untouched by the SARIF-render neutralizer.
  const identity = findingIdentity(f, 'identity');
  assert.ok(identity.includes('[x](javascript:alert(1))'), 'findingIdentity uses the RAW condition');
  assert.equal(typeof fp, 'string');
  assert.ok(fp.length >= 16, 'a fingerprint is still emitted');
});

test('S2: distinct escalation routes still get DISTINCT fingerprints (condition + service split preserved)', () => {
  const base = {
    id: 'PASSROLE-SERVICE', severity: 'high', title: 't', statementSid: 'S', statementIndex: 0,
    actions: ['iam:PassRole'], resources: ['r'], conditions: { StringEquals: { 'aws:X': 'a' } },
    escalation: { service: 'ec2', technique: 'RunInstances' },
  };
  const differentValue = { ...base, conditions: { StringEquals: { 'aws:X': 'b' } } };
  const differentService = { ...base, escalation: { service: 'glue', technique: 'CreateDevEndpoint' } };
  const fp = (f) => buildSarifLog({ findings: [f], family: 'identity' }, {}, MANIFEST)
    .runs[0].results[0].partialFingerprints[FINGERPRINT_KEY];
  assert.notEqual(fp(base), fp(differentValue), 'a different condition VALUE -> different fingerprint');
  assert.notEqual(fp(base), fp(differentService), 'a different target service -> different fingerprint');
});

// =============================================================================
// (d) the wider sweep: artifactLocation.uri and analyzer-state properties.path.
// =============================================================================

test('S2: artifactLocation.uri strips control chars but preserves a legitimate path', () => {
  const result = evidenceResult({ StringEquals: { 'aws:X': 'a' } });
  // A benign path is byte-identical (no over-escaping of "/" or ".").
  const clean = buildSarifLog(result, { file: 'policies/app.json' }, MANIFEST);
  assert.equal(clean.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    'policies/app.json');
  // A path carrying control chars / a newline is stripped.
  const hostile = buildSarifLog(result, { file: 'a b\ncd.json' }, MANIFEST);
  const uri = hostile.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  assert.ok(!CONTROL.test(uri), `no control chars in uri: ${JSON.stringify(uri)}`);
});

// R5-uri-trunc: a URI longer than MAX_URI_LEN (2048) is sliced to a still-VALID path with NO
// truncation marker mutated into the location string, and the slice is recorded on a SEPARATE
// properties.uriTruncated flag - on BOTH the security-finding row and the analyzer-state row.
test('R5: over-length artifact URI -> sliced-but-unmutated location + properties.uriTruncated flag', () => {
  const MAX_URI_LEN = 2048;
  const result = evidenceResult({ StringEquals: { 'aws:X': 'a' } });
  // A deep repo-relative path of ASCII segments, well past the 2048 cap. All chars survive
  // neutralization (no control/non-ASCII), so length alone drives the truncation.
  const longUri = `${'seg/'.repeat(700)}app.json`;
  assert.ok(longUri.length > MAX_URI_LEN, 'fixture URI exceeds the cap');
  const log = buildSarifLog(result, { file: longUri }, MANIFEST);
  const sec = log.runs[0].results.find((r) => r.properties && r.properties.category === 'security');
  assert.ok(sec, 'a security finding is present');
  const uri = sec.locations[0].physicalLocation.artifactLocation.uri;
  // Sliced to exactly the cap; NO marker/ellipsis appended (still a valid path prefix, no "...").
  assert.equal(uri.length, MAX_URI_LEN, 'location URI sliced to MAX_URI_LEN');
  assert.equal(uri, longUri.slice(0, MAX_URI_LEN), 'location URI is an unmodified prefix of the input path');
  assert.ok(!uri.includes('...'), 'no truncation marker mutated into the location URI');
  assert.equal(sec.properties.uriTruncated, true, 'truncation recorded on a SEPARATE properties flag');

  // The URI is excluded from findingIdentity, so slicing must not churn the fingerprint.
  const short = buildSarifLog(result, { file: 'policies/app.json' }, MANIFEST);
  const secShort = short.runs[0].results.find((r) => r.properties && r.properties.category === 'security');
  assert.equal(sec.partialFingerprints[FINGERPRINT_KEY], secShort.partialFingerprints[FINGERPRINT_KEY],
    'fingerprint is unaffected by URI truncation');
});

test('R5: a normal-length artifact URI sets NO uriTruncated flag (finding + analyzer-state rows)', () => {
  // Security finding row: no flag on a short path.
  const result = evidenceResult({ StringEquals: { 'aws:X': 'a' } });
  const log = buildSarifLog(result, { file: 'policies/app.json' }, MANIFEST);
  const sec = log.runs[0].results.find((r) => r.properties && r.properties.category === 'security');
  assert.ok(sec, 'a security finding is present');
  assert.equal('uriTruncated' in sec.properties, false, 'no uriTruncated flag on a normal URI');

  // Analyzer-state row: a fail-closed policy, short path -> no flag either.
  const failText = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:x",'
    + '"Action":"s3:y","Resource":"*"}]}';
  const stateResult = scan({ text: failText, family: 'identity' });
  const stateLog = buildSarifLog(stateResult, { file: 'p.json' }, MANIFEST);
  const states = stateLog.runs[0].results.filter((r) => r.properties && r.properties.category === 'analysis-state');
  assert.ok(states.length >= 1, 'the policy fails closed with an analyzer-state result');
  for (const st of states) {
    assert.equal('uriTruncated' in st.properties, false, 'no uriTruncated flag on a normal analyzer-state URI');
  }
});

test('R5: analyzer-state row also carries uriTruncated on an over-length URI', () => {
  const MAX_URI_LEN = 2048;
  const failText = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:x",'
    + '"Action":"s3:y","Resource":"*"}]}';
  const stateResult = scan({ text: failText, family: 'identity' });
  const longUri = `${'seg/'.repeat(700)}p.json`;
  assert.ok(longUri.length > MAX_URI_LEN, 'fixture URI exceeds the cap');
  const log = buildSarifLog(stateResult, { file: longUri }, MANIFEST);
  const states = log.runs[0].results.filter((r) => r.properties && r.properties.category === 'analysis-state');
  assert.ok(states.length >= 1, 'a fail-closed analyzer-state result is present');
  for (const st of states) {
    const uri = st.locations[0].physicalLocation.artifactLocation.uri;
    assert.equal(uri.length, MAX_URI_LEN, 'analyzer-state location URI sliced to MAX_URI_LEN');
    assert.ok(!uri.includes('...'), 'no marker mutated into the analyzer-state location URI');
    assert.equal(st.properties.uriTruncated, true, 'analyzer-state row records the slice on a separate flag');
  }
});

test('S2: an analyzer-state path carrying attacker key names is rendered inert (no live link in properties.path)', () => {
  // A duplicate object key fails closed in validate.js; its path/message can interpolate
  // attacker key names. The duplicate Action here carries a markdown-link spelling.
  const text = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",'
    + '"Action":"[x](javascript:1)","Resource":"*"}]}';
  const result = scan({ text, family: 'identity' });
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  const states = log.runs[0].results.filter((r) => r.properties && r.properties.category === 'analysis-state');
  assert.ok(states.length >= 1, 'the policy fails closed with an analyzer-state result');
  for (const st of states) {
    if (st.properties.path != null) assertInert(st.properties.path, 'properties.path');
    assertInert(st.message.text, 'analyzer-state message.text');
  }
  assert.ok(!serialized.includes(']('), 'no unescaped "](": no link forms anywhere in the SARIF');
});

// =============================================================================
// (d) SIBLING policy-derived BARE property fields: evidence Sid / role / actions /
// resources AND top-level properties.statementSid. These are emitted un-wrapped (NOT
// code-span-wrapped), so a backtick-only strip is inert and a live `[x](url)` / `![x](url)`
// / `<url>` would render in a consumer's alert detail. They must be markdown-INERT, like
// condition/note. Regression for the Iteration-2 BLOCKER.
// =============================================================================

// Assert a BARE properties string is markdown-inert: no control char and no UNESCAPED
// link boundary / image / autolink / backtick.
function assertBareInert(s, label) {
  assert.equal(typeof s, 'string', `${label}: is a string`);
  assert.ok(!CONTROL.test(s), `${label}: no control chars`);
  assert.ok(!s.includes(']('), `${label}: no unescaped inline-link boundary "]("`);
  assert.ok(!/(^|[^\\])!\[/.test(s), `${label}: no unescaped image "!["`);
  assert.ok(!/(^|[^\\])`/.test(s), `${label}: no unescaped backtick`);
  assert.ok(!/<https?:/i.test(s), `${label}: no unescaped "<url>" autolink`);
}

// A synthetic PassRole-service escalation finding whose top-level Sid AND whose single
// evidence row's Sid / role / actions / resources ALL carry markdown payloads.
function bareFieldResult() {
  return {
    analysisStatus: 'complete',
    findings: [{
      id: 'PASSROLE-SERVICE', severity: 'critical', title: 'PassRole to a service',
      statementSid: 'PASS [click](https://evil.example/pwn)', statementIndex: 0,
      actions: ['iam:PassRole'], resources: ['arn:aws:iam::123456789012:role/app'],
      conditions: null,
      escalation: { technique: 'passrole-service-execution', service: 'ecs', targetPermissions: 'unknown' },
      evidence: [{
        statementIndex: 0,
        statementSid: 'EXEC <https://evil.example/auto>',
        role: 'svc-![x](https://evil.example/track.png)',
        actions: ['iam:PassRole', '[a](javascript:alert(1))'],
        resources: ['arn:aws:iam::123456789012:role/svc-![x](https://evil.example/track.png)'],
        condition: null, note: 'ok',
      }],
    }],
    family: 'identity',
  };
}

test('S2: bare evidence Sid/role/actions/resources + top-level statementSid are markdown-inert', () => {
  const result = bareFieldResult();
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const sec = log.runs[0].results.find((r) => r.properties && r.properties.category === 'security');
  assert.ok(sec, 'a security finding is present');
  assertBareInert(sec.properties.statementSid, 'top-level properties.statementSid');
  const ev = sec.properties.evidence[0];
  assertBareInert(ev.statementSid, 'evidence.statementSid');
  assertBareInert(ev.role, 'evidence.role');
  ev.actions.forEach((a, i) => assertBareInert(a, `evidence.actions[${i}]`));
  ev.resources.forEach((r, i) => assertBareInert(r, `evidence.resources[${i}]`));
  // The serialized SARIF carries NO live link/image/autolink anywhere - the invariant the
  // old suite exercised only against a hostile CONDITION, now against hostile bare fields.
  // message.text legitimately wraps its Sid in an INERT backtick code span (GitHub renders
  // nothing inside it), so strip code spans before the global check - a payload leaking
  // into a BARE field would appear OUTSIDE a span and still trip it.
  const serialized = stripCodeSpans(formatSarif(result, { file: 'p.json' }, MANIFEST));
  assert.ok(!serialized.includes(']('), 'no unescaped "](" outside a code span');
  assert.ok(!/(^|[^\\])!\[/.test(serialized), 'no unescaped image "!["');
  assert.ok(!/[^\\]<https?:/i.test(serialized), 'no unescaped "<url>" autolink');
});

test('S2: end-to-end - a real PassRole escalation with payloads in Sid/resource/action is inert in SARIF', () => {
  // Mirrors the Iteration-2 BLOCKER repro: [x](url) in a Sid, ![x](url) in a resource, and
  // <url> in a second statement's Sid, on a real PassRole -> ECS escalation.
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'PASS [click](https://evil.example/pwn)', Effect: 'Allow', Action: 'iam:PassRole',
        Resource: 'arn:aws:iam::123456789012:role/svc-![x](https://evil.example/track.png)',
      },
      { Sid: 'EXEC <https://evil.example/auto>', Effect: 'Allow', Action: 'ecs:RunTask', Resource: '*' },
    ],
  });
  const result = scan({ text, family: 'identity', subjectAccount: '123456789012' });
  // Fail-closed: a real escalation must NOT report clean.
  assert.notEqual(result.exitCode, 0, 'a PassRole escalation does not exit 0');
  // Strip inert backtick code spans (message.text wraps its Sid in one) before the global
  // no-live-markdown assertions - a payload leaking into a BARE field is outside a span.
  const serialized = stripCodeSpans(formatSarif(result, { file: 'p.json' }, MANIFEST));
  assert.ok(!serialized.includes(']('), 'no unescaped "](" survives end-to-end');
  assert.ok(!/(^|[^\\])!\[/.test(serialized), 'no unescaped image "![" survives end-to-end');
  assert.ok(!/[^\\]<https?:/i.test(serialized), 'no unescaped "<url>" autolink survives end-to-end');
  assert.ok(!serialized.includes('](https://evil'), 'the evil link is not live');
});

test('S2: an oversized evidence action/resource LIST is count-capped with a truthful marker', () => {
  const many = [];
  for (let i = 0; i < 500; i++) many.push(`s3:Action${i}`);
  const result = {
    analysisStatus: 'complete',
    findings: [{
      id: 'PASSROLE-SERVICE', severity: 'high', title: 't', statementSid: 'S', statementIndex: 0,
      actions: ['iam:PassRole'], resources: ['r'], conditions: null,
      evidence: [{ statementIndex: 0, actions: many, resources: many.slice(), condition: null }],
    }],
    family: 'identity',
  };
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const ev = log.runs[0].results[0].properties.evidence[0];
  // 32-token cap + a marker: the list cannot amplify the SARIF with 500 tokens.
  assert.ok(ev.actions.length <= 33, `actions count-capped (${ev.actions.length})`);
  assert.ok(ev.resources.length <= 33, `resources count-capped (${ev.resources.length})`);
  assert.equal(ev.actions[ev.actions.length - 1], '(list truncated)', 'truncation is marked, not silent');
  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  assert.ok(serialized.length < 20 * 1024, `500-token lists do not amplify (${serialized.length} bytes)`);
});

// =============================================================================
// Unicode bidi / zero-width spoofing: RLO/LRI/ZWSP etc. can reorder or hide/split an
// ARN/Sid/condition token so a hostile value renders benign in a consumer's alert detail.
// They are NOT markdown punctuation, so the ASCII-punctuation escape never touches them;
// the shared leaf sanitizers must STRIP them. Regression for the Iteration-2 BLOCKER.
// =============================================================================

// The bidi / zero-width / format code points that must NEVER survive into the SARIF.
const BIDI_ZW = /[\u00AD\u061C\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/;

test('S2: bidi/zero-width control chars never survive into any SARIF sink', () => {
  // A payload in EVERY reached sink: condition key + value, note, artifact uri (file name),
  // a bare Sid, and a bare resource.
  const RLO = '\u202E'; const LRI = '\u2066'; const ZWSP = '\u200B';
  const PDI = '\u2069'; const BOM = '\uFEFF'; const SHY = '\u00AD';
  const result = {
    analysisStatus: 'complete',
    findings: [{
      id: 'PASSROLE-SERVICE', severity: 'critical', title: 't',
      statementSid: `Adm${ZWSP}in${RLO}nimda`, statementIndex: 0,
      actions: ['iam:PassRole'], resources: ['r'], conditions: null,
      evidence: [{
        statementIndex: 0,
        statementSid: `s${BOM}id`,
        role: `role${SHY}x`,
        actions: [`iam:Pass${ZWSP}Role`],
        resources: [`arn:aws:iam::1:role/${RLO}gpj.nimda${PDI}`],
        condition: { [`Str${ZWSP}ingEquals`]: { [`${RLO}yek`]: `v${LRI}al${ZWSP}ue` } },
        note: `runs ${RLO}esrever${PDI} as role`,
      }],
    }],
    family: 'identity',
  };
  const serialized = formatSarif(result, { file: `policy${RLO}${ZWSP}.json` }, MANIFEST);
  assert.ok(!BIDI_ZW.test(serialized),
    'no bidi/zero-width code point survives anywhere in the serialized SARIF');
  // Spot-check the individual sinks too.
  const sec = buildSarifLog(result, { file: `policy${RLO}${ZWSP}.json` }, MANIFEST).runs[0].results[0];
  assert.ok(!BIDI_ZW.test(sec.properties.statementSid), 'top-level statementSid stripped');
  assert.ok(!BIDI_ZW.test(sec.locations[0].physicalLocation.artifactLocation.uri), 'artifact uri stripped');
  const ev = sec.properties.evidence[0];
  assert.ok(!BIDI_ZW.test(JSON.stringify(ev)), 'evidence row (condition keys+values, note, tokens) stripped');
});

// ---------------------------------------------------------------------------
// Codepoint-EXACT regression (Iteration-3 BLOCKER): the shared CONTROL_AND_FORMAT set
// was an INCOMPLETE enumeration - it stripped the bidi embeddings/overrides/isolates
// but OMITTED the implicit bidi directional MARKS (U+061C, U+200E, U+200F) and most of
// the invisible-format block (U+2061-U+2065 invisible math ops, U+206A-U+206F deprecated
// format). Those are neither ASCII punctuation nor \s, so the markdown-inert escape and
// the whitespace-collapse never touched them - they landed byte-for-byte in the SARIF and
// could reorder/hide/split an ARN or account in a maintainer's markdown-rendered alert.
// A markdown-boundary-only assertion cannot catch this class, so each code point is
// checked EXACTLY: removed (not merely visually inert) from a condition key AND value, a
// Sid, an evidence resource, and the analyzer-state path, in the serialized SARIF.
const NEWLY_COVERED = [
  0x061C, // ARABIC LETTER MARK (implicit bidi)
  0x200E, 0x200F, // LEFT-TO-RIGHT / RIGHT-TO-LEFT MARK (implicit bidi)
  0x2061, 0x2062, 0x2063, 0x2064, 0x2065, // invisible math operators (zero-width)
  0x206A, 0x206B, 0x206C, 0x206D, 0x206E, 0x206F, // deprecated format (zero-width)
];

test('S2: every newly-covered bidi/zero-width code point is STRIPPED from every SARIF sink (codepoint-exact)', () => {
  for (const cp of NEWLY_COVERED) {
    const M = String.fromCodePoint(cp);
    const hex = cp.toString(16).toUpperCase().padStart(4, '0');
    // A CRITICAL PassRole->EC2 escalation carrying the mark in a condition key AND value,
    // a Sid, and an evidence resource, so the mark reaches message.text + every properties sink.
    const result = {
      analysisStatus: 'complete',
      findings: [{
        id: 'PASSROLE-SERVICE', severity: 'critical', title: 't',
        statementSid: `Adm${M}in`, statementIndex: 0,
        actions: ['iam:PassRole'], resources: ['r'], conditions: null,
        evidence: [{
          statementIndex: 0,
          statementSid: `s${M}id`,
          role: `role${M}x`,
          actions: [`iam:Pass${M}Role`],
          resources: [`arn:aws:iam::999988887777:role/${M}app`],
          condition: { [`Str${M}ingEquals`]: { [`k${M}ey`]: `ec2${M}.amazonaws.com` } },
          note: `passes ${M} to service`,
        }],
      }],
      family: 'identity',
    };
    const serialized = formatSarif(result, { file: `p${M}.json` }, MANIFEST);
    assert.ok(!serialized.includes(M),
      `U+${hex} must not survive anywhere in the serialized SARIF`);
    const sec = buildSarifLog(result, { file: `p${M}.json` }, MANIFEST).runs[0].results[0];
    assert.ok(!sec.message.text.includes(M), `U+${hex} stripped from message.text`);
    assert.ok(!sec.properties.statementSid.includes(M), `U+${hex} stripped from properties.statementSid`);
    assert.ok(!sec.locations[0].physicalLocation.artifactLocation.uri.includes(M), `U+${hex} stripped from artifact uri`);
    const ev = sec.properties.evidence[0];
    // condition keys AND values (recursive), resources, role, note, evidence Sid.
    assert.ok(!JSON.stringify(ev).includes(M), `U+${hex} stripped from the whole evidence row`);
    const opKey = Object.keys(ev.condition)[0];
    assert.ok(!opKey.includes(M), `U+${hex} stripped from condition operator key`);
    const innerKey = Object.keys(ev.condition[opKey])[0];
    assert.ok(!innerKey.includes(M), `U+${hex} stripped from condition inner key`);
    assert.ok(!Object.values(ev.condition[opKey])[0].includes(M), `U+${hex} stripped from condition value`);
  }
});

// =============================================================================
// (e) DOCUMENT-level aggregate cap (iteration 4). The per-condition-block + per-field caps
// each bound ONE evidence row and are re-created FRESH per row, so they never bound the SUM
// across a whole document. A VALID, within-limits policy (< MAX_BYTES, <= MAX_STATEMENTS)
// that fans out to thousands of findings can still sum past GitHub's ~10 MB SARIF upload cap
// -> GitHub SILENTLY DROPS every finding from the Security tab (a total fail-OPEN). The
// builder now threads ONE document budget across ALL rows and fails CLOSED: it sheds evidence
// (the amplifier) first, then drops whole finding rows only if bare rows still overflow, and
// ALWAYS appends a truthful SARIF_OUTPUT_TRUNCATED analyzer-state result announcing it.
// =============================================================================

// A VALID admin/escalation policy of N distinct statements, each a wildcard grant carrying a
// small-but-nonzero Condition. Well under validate.js MAX_BYTES (1 MiB) and MAX_STATEMENTS
// (1000), yet it fans out to thousands of real blocking findings whose evidence rows each
// copy the statement condition - the exact within-limits amplifier the story describes.
function adminFanoutPolicy(n) {
  const st = [];
  for (let i = 0; i < n; i += 1) {
    st.push({
      Effect: 'Allow',
      Action: '*',
      Resource: '*',
      Condition: { StringLike: { [`aws:PrincipalTag/x${i}`]: 'y'.repeat(300) } },
    });
  }
  return JSON.stringify({ Version: '2012-10-17', Statement: st });
}

test('S2: a within-limits admin fan-out policy cannot amplify the SARIF past a safe bound', () => {
  // 780 statements: ~0.31 MB input (well under the 1 MiB / 1000-statement limits) that the
  // OLD builder amplified to ~10.3 MB - over GitHub's ~10 MB cap. It is ACCEPTED by scan
  // (exit 3, thousands of real blocking findings), so this is a real within-limits input.
  const text = adminFanoutPolicy(780);
  const result = scan({ text, family: 'identity' });
  const findingCount = (result.findings || []).length;
  assert.ok(findingCount > 5000, `the policy really does fan out to thousands of findings (${findingCount})`);

  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  // The whole point: comfortably below GitHub's ~10 MB SARIF upload cap, regardless of how
  // many findings a within-limits policy produces. (The un-capped builder emitted ~10.3 MB.)
  assert.ok(serialized.length < 9 * 1024 * 1024,
    `SARIF stays under a safe bound below GitHub's ~10 MB cap (${serialized.length} bytes)`);

  // Truncated, NOT silently dropped: a single truthful fail-closed analyzer-state announces it.
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const results = log.runs[0].results;
  const trunc = results.filter((r) => r.ruleId === 'analysis.SARIF_OUTPUT_TRUNCATED');
  assert.equal(trunc.length, 1, 'exactly one SARIF_OUTPUT_TRUNCATED state signals the truncation');

  // The truncation state carries the load-bearing fail-closed shape and is NEVER a vuln.
  const t = trunc[0];
  assert.equal(t.kind, 'fail', 'truncation state kind=fail');
  assert.equal(t.level, 'error', 'truncation state level=error');
  assert.equal(t.properties.category, 'analysis-state', 'category analysis-state');
  assert.equal(t.properties.failClosed, true, 'failClosed:true');
  assert.equal('security-severity' in t.properties, false, 'a truncation state NEVER carries a security-severity');
  const rule = log.runs[0].tool.driver.rules.find((r) => r.id === 'analysis.SARIF_OUTPUT_TRUNCATED');
  assert.ok(rule, 'a reportingDescriptor exists for the truncation state');
  assert.equal('security-severity' in rule.properties, false, 'the truncation RULE never carries a security-severity');
  assert.equal(typeof t.ruleIndex, 'number', 'the truncation state resolves to its rule via ruleIndex');
  assertInert(t.message.text, 'truncation message');

  // The security signal is preserved: security findings still ride in the doc, each with a
  // partialFingerprint (DO-NOT-TOUCH). Evidence may be shed but the FINDING stays PRESENT.
  const sec = results.filter((r) => r.properties && r.properties.category === 'security');
  assert.ok(sec.length > 0, 'security findings are NOT silently dropped wholesale');
  assert.ok(sec.every((r) => r.partialFingerprints && Object.keys(r.partialFingerprints).length === 1),
    'every emitted security finding still carries its fingerprint');
});

test('S2: the document cap is deterministic (same policy -> byte-identical SARIF)', () => {
  const text = adminFanoutPolicy(780);
  const a = formatSarif(scan({ text, family: 'identity' }), { file: 'p.json' }, MANIFEST);
  const b = formatSarif(scan({ text, family: 'identity' }), { file: 'p.json' }, MANIFEST);
  assert.equal(a, b, 'the truncation decision (which rows/evidence are shed) is deterministic');
});

test('S2: a small policy is unaffected by the document cap (no truncation, no evidence shed)', () => {
  // One admin statement -> a handful of findings, far under the budget: nothing is trimmed.
  const result = scan({ text: adminFanoutPolicy(1), family: 'identity' });
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const results = log.runs[0].results;
  assert.equal(results.filter((r) => r.ruleId === 'analysis.SARIF_OUTPUT_TRUNCATED').length, 0,
    'no truncation state on a small policy');
  const sec = results.filter((r) => r.properties && r.properties.category === 'security');
  assert.ok(sec.some((r) => r.properties.evidence), 'evidence rides through untrimmed on a small policy');
  assert.ok(sec.every((r) => r.properties.evidenceElided === undefined), 'no evidenceElided marker on a small policy');
});

// =============================================================================
// (e2) DOCUMENT-level amplification on the ANALYZER-STATE row type (S2, iteration 5). The
// iteration-4 document budget bounded only SECURITY-FINDING rows; the analyzer-state loop
// emitted EVERY result.analysisStates row unconditionally, only ADDING to the byte tally.
// But that row count is attacker-controlled and UNBOUNDED within validate() limits:
// validate.findDuplicateKeys emits one DUPLICATE_JSON_KEY error PER duplicate condition key
// (uncapped), and scan()->errorStates maps each 1:1 to a state. A single-statement policy
// (< MAX_BYTES, depth ~5, statements=1 - fully within limits) whose Condition repeats one key
// N times therefore fanned out to N state rows and serialized PAST GitHub's ~10 MB cap, with
// NO SARIF_OUTPUT_TRUNCATED emitted - a SILENT, total fail-OPEN (worse than a finding overflow,
// which at least announced itself). The fix charges state rows against the SAME document byte
// budget, type-agnostically, and announces the truncation. These tests would FAIL on the
// iteration-4 code (10+ MB serialized, no truncation state) and pass now.
// =============================================================================

// A VALID single-statement identity policy whose Condition.StringEquals block repeats one key
// name N times. findDuplicateKeys emits one DUPLICATE_JSON_KEY error per duplicate (uncapped).
// Under MAX_BYTES (1 MiB) and MAX_STATEMENTS for the N used here, so it is a real within-limits
// input the engine ACCEPTS (ok:false -> exit 3, fail-closed on the dropped grants).
function duplicateKeyStatePolicy(n) {
  const entries = [];
  for (let i = 0; i < n; i += 1) entries.push('"aws:PrincipalOrgID":"o-abc123"');
  return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject",`
    + `"Resource":"*","Condition":{"StringEquals":{${entries.join(',')}}}}]}`;
}

test('S2 iter5: an unbounded analyzer-state fan-out cannot amplify the SARIF past a safe bound', () => {
  // ~0.34 MB input (well under 1 MiB), one statement, depth ~5 - fully within engine limits -
  // yet 10,499 DUPLICATE_JSON_KEY states. The un-capped loop serialized this to ~10.2 MB with
  // NO truncation state (silent fail-OPEN). The fix bounds it.
  const text = duplicateKeyStatePolicy(10500);
  assert.ok(Buffer.byteLength(text, 'utf8') < 1024 * 1024, 'input is within the engine byte limit');
  const result = scan({ text, family: 'identity' });
  assert.equal(result.exitCode, 3, 'the policy fails CLOSED (exit 3) on the dropped duplicate grants');
  assert.ok((result.analysisStates || []).length > 5000,
    `the policy really does fan out to thousands of analyzer-states (${result.analysisStates.length})`);

  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  const byteSize = Buffer.byteLength(serialized, 'utf8');
  assert.ok(byteSize <= MAX_SARIF_BYTES,
    `analyzer-state rows must be bounded by the byte budget; got ${byteSize} bytes`);
  assert.ok(byteSize < 9 * 1024 * 1024, `SARIF stays comfortably below GitHub's ~10 MB cap (${byteSize} bytes)`);

  // Truncated, NOT silently dropped: the fail-closed analysis-state CATEGORY survives via a
  // truthful SARIF_OUTPUT_TRUNCATED state carrying the load-bearing shape (never a vuln score).
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const results = log.runs[0].results;
  const trunc = results.filter((r) => r.ruleId === 'analysis.SARIF_OUTPUT_TRUNCATED');
  assert.equal(trunc.length, 1, 'exactly one SARIF_OUTPUT_TRUNCATED state announces the state truncation');
  const t = trunc[0];
  assert.equal(t.kind, 'fail');
  assert.equal(t.level, 'error');
  assert.equal(t.properties.category, 'analysis-state');
  assert.equal(t.properties.failClosed, true);
  assert.equal('security-severity' in t.properties, false, 'a truncation state NEVER carries a security-severity');
  assertInert(t.message.text, 'state-truncation message');
  assert.ok(/elided entirely/.test(t.message.text), 'the message truthfully reports elided analyzer-states');
  // The fail-closed signal is present in the SARIF (some states + the truncation notice), so the
  // consumer never sees a clean check for a fail-closed policy.
  assert.ok(results.some((r) => r.properties && r.properties.category === 'analysis-state'),
    'the fail-closed analysis-state category survives in the emitted SARIF');
});

test('S2 iter5: the analyzer-state cap is deterministic (same policy -> byte-identical SARIF)', () => {
  const text = duplicateKeyStatePolicy(12000);
  const a = formatSarif(scan({ text, family: 'identity' }), { file: 'p.json' }, MANIFEST);
  const b = formatSarif(scan({ text, family: 'identity' }), { file: 'p.json' }, MANIFEST);
  assert.equal(a, b, 'which state rows are shed is deterministic');
});

test('S2 iter5: security findings are charged BEFORE analyzer-states, so a state fan-out cannot drop genuine findings', () => {
  // Synthetic result: a handful of REAL security findings PLUS a huge analyzer-state fan-out
  // (the scenario-3 shape where incomplete states ride on ok:true results and COEXIST with
  // findings). Findings are charged first; the states truncate. The findings - the security
  // signal - MUST all survive, each with its fingerprint (DO-NOT-TOUCH).
  const findings = [];
  for (let i = 0; i < 5; i += 1) {
    findings.push({ id: 'WILDCARD-ACTION', severity: 'critical', title: 'Admin wildcard',
      statementIndex: i, actions: ['*'], resources: ['*'] });
  }
  const analysisStates = [];
  for (let i = 0; i < 40000; i += 1) {
    analysisStates.push({ analysisState: 'incomplete', code: 'UNSUPPORTED_CONDITION',
      message: `unsupported condition at statement ${i}`, path: `/Statement/${i}/Condition` });
  }
  const result = { findings, analysisStates, family: 'identity' };
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const results = log.runs[0].results;

  const sec = results.filter((r) => r.properties && r.properties.category === 'security');
  assert.equal(sec.length, 5, 'all 5 genuine security findings survive the state fan-out');
  assert.ok(sec.every((r) => r.partialFingerprints && Object.keys(r.partialFingerprints).length === 1),
    'every security finding keeps its fingerprint');
  const trunc = results.filter((r) => r.ruleId === 'analysis.SARIF_OUTPUT_TRUNCATED');
  assert.equal(trunc.length, 1, 'the state truncation is announced');
  const byteSize = Buffer.byteLength(formatSarif(result, { file: 'p.json' }, MANIFEST), 'utf8');
  assert.ok(byteSize <= MAX_SARIF_BYTES, `bounded even with findings + huge state fan-out (${byteSize} bytes)`);
});

test('S2 iter5: a small fail-closed policy emits ALL its analyzer-states with no truncation', () => {
  // Two duplicate keys -> a handful of states, far under the budget: nothing is trimmed.
  const result = scan({ text: duplicateKeyStatePolicy(3), family: 'identity' });
  assert.equal(result.exitCode, 3, 'still fails closed');
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const results = log.runs[0].results;
  assert.equal(results.filter((r) => r.ruleId === 'analysis.SARIF_OUTPUT_TRUNCATED').length, 0,
    'no truncation state on a small fail-closed policy');
  const states = results.filter((r) => r.properties && r.properties.category === 'analysis-state');
  assert.equal(states.length, result.analysisStates.length, 'every analyzer-state is emitted for a small policy');
});

// =============================================================================
// (f) EMPTY containers are CHARGED against the aggregate condition budget. An earlier walker
// charged only keys + scalar leaves, so an array/object of thousands of EMPTY containers
// summed to ZERO against the node/char budget and slipped past the aggregate cap - the same
// amplification class, one spelling deeper. Every container now costs a node + its brackets.
// =============================================================================

test('S2: an ARRAY of thousands of EMPTY objects is aggregate-capped (containers are charged)', () => {
  const arr = [];
  for (let i = 0; i < 5000; i += 1) arr.push({});
  const result = evidenceResult({ StringEquals: { 'aws:x': arr } });
  const { ev } = evidenceRow(result);
  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  assert.equal(ev.conditionTruncated, true, 'empty-container fan-out trips the aggregate cap');
  assert.equal(ev.condition, undefined, 'the raw 5000-container array is NOT emitted');
  assert.ok(typeof ev.conditionSummary === 'string' && ev.conditionSummary.length <= 483,
    `bounded conditionSummary (${(ev.conditionSummary || '').length})`);
  assert.ok(serialized.length < 20 * 1024, `5000 empty containers do not amplify (${serialized.length} bytes)`);
});

test('S2: an OBJECT with thousands of EMPTY-object values is aggregate-capped (containers are charged)', () => {
  const inner = {};
  for (let i = 0; i < 5000; i += 1) inner[`aws:Key${i}`] = {};
  const result = evidenceResult({ StringEquals: inner });
  const { ev } = evidenceRow(result);
  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  assert.equal(ev.conditionTruncated, true, 'empty-object-valued fan-out trips the aggregate cap');
  assert.equal(ev.condition, undefined, 'the raw object is NOT emitted');
  assert.ok(serialized.length < 40 * 1024, `5000 empty-object values do not amplify (${serialized.length} bytes)`);
});

test('S2: newly-covered marks are stripped from the analyzer-state path/message (fail-closed sink)', () => {
  const ALM = String.fromCodePoint(0x061C);
  const LRM = String.fromCodePoint(0x200E);
  // A duplicate object key fails closed in validate.js; its path/message interpolate the
  // attacker key name, which carries the implicit bidi marks.
  const text = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Get${ALM}Object","Action":"s3:Put${LRM}Object","Resource":"*"}]}`;
  const result = scan({ text, family: 'identity' });
  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);
  assert.ok(!serialized.includes(ALM) && !serialized.includes(LRM),
    'no implicit bidi mark survives in the analyzer-state SARIF');
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const states = log.runs[0].results.filter((r) => r.properties && r.properties.category === 'analysis-state');
  assert.ok(states.length >= 1, 'the duplicate-key policy fails closed with an analyzer-state result');
  for (const st of states) {
    if (st.properties.path != null) { assert.ok(!st.properties.path.includes(ALM) && !st.properties.path.includes(LRM), 'marks stripped from properties.path'); }
    assert.ok(!st.message.text.includes(ALM) && !st.message.text.includes(LRM), 'marks stripped from analyzer-state message.text');
  }
});

// ---------------------------------------------------------------------------
// Iteration-6 BLOCKER 1 (bidi/zero-width spoof, incomplete-enumeration class, one
// spelling deeper). The prior CONTROL_AND_FORMAT was a hand-enumerated BMP range and
// falsely claimed to be "codepoint-exhaustive"; 11 invisible/zero-width/format code
// points survived un-stripped into EVERY SARIF sink - none caught by \s or the ASCII-
// punctuation escape. The fix strips by Unicode GENERAL_CATEGORY (\p{Cc}\p{Cf} with the
// `u` flag, so the astral tag block is covered) plus the specific non-Cc/Cf invisibles.
// Each formerly-surviving code point is checked EXACTLY: removed (not merely inert) from
// message.text, properties.statementSid, the artifact uri, and the evidence row.
const ITER6_INVISIBLES = [
  0x180E, // MONGOLIAN VOWEL SEPARATOR (Cf; removed from \s in ES2018)
  0x115F, 0x1160, 0x3164, 0xFFA0, // Hangul fillers (category Lo, render blank)
  0xFFF9, 0xFFFB, // INTERLINEAR ANNOTATION ANCHOR / TERMINATOR (Cf)
  0xE0001, 0xE0041, // tag block (Cf, ASTRAL; hidden-text smuggling)
  0xFE0F, // VARIATION SELECTOR-16 (category Mn, zero-width)
  0x2800, // BRAILLE PATTERN BLANK (category So, renders blank)
];

test('S2 iter6: every formerly-surviving invisible/format code point is STRIPPED from every SARIF sink (codepoint-exact)', () => {
  for (const cp of ITER6_INVISIBLES) {
    const M = String.fromCodePoint(cp);
    const hex = cp.toString(16).toUpperCase().padStart(4, '0');
    const result = {
      analysisStatus: 'complete',
      findings: [{
        id: 'PASSROLE-SERVICE', severity: 'critical', title: 't',
        statementSid: `Adm${M}in`, statementIndex: 0,
        actions: ['iam:PassRole'], resources: ['r'], conditions: null,
        evidence: [{
          statementIndex: 0,
          statementSid: `s${M}id`,
          role: `role${M}x`,
          actions: [`iam:Pass${M}Role`],
          resources: [`arn:aws:iam::999988887777:role/${M}app`],
          condition: { [`Str${M}ingEquals`]: { [`k${M}ey`]: `ec2${M}.amazonaws.com` } },
          note: `passes ${M} to service`,
        }],
      }],
      family: 'identity',
    };
    const serialized = formatSarif(result, { file: `p${M}.json` }, MANIFEST);
    assert.ok(!serialized.includes(M),
      `U+${hex} must not survive anywhere in the serialized SARIF`);
    const sec = buildSarifLog(result, { file: `p${M}.json` }, MANIFEST).runs[0].results[0];
    assert.ok(!sec.message.text.includes(M), `U+${hex} stripped from message.text`);
    assert.ok(!sec.properties.statementSid.includes(M), `U+${hex} stripped from properties.statementSid`);
    assert.ok(!sec.locations[0].physicalLocation.artifactLocation.uri.includes(M), `U+${hex} stripped from artifact uri`);
    assert.ok(!JSON.stringify(sec.properties.evidence[0]).includes(M), `U+${hex} stripped from evidence row`);
  }
});

test('S2 iter6: a zero-width HIDE/SPLIT of an ARN account number cannot smuggle into the SARIF end-to-end', () => {
  // U+180E (a Cf zero-width format char) inserted into the account number of a PassRole
  // ->EC2 escalation, so the rendered ARN would visually read as a benign account while
  // the underlying value differs - the exact hide/split spoof the strip prevents. Driven
  // through the REAL engine (scan), not a synthetic finding.
  const ZW = String.fromCodePoint(0x180E);
  const text = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Sid: `Pass${ZW}Role`, Effect: 'Allow', Action: 'iam:PassRole',
        Resource: `arn:aws:iam::9999${ZW}88887777:role/app`,
        Condition: { StringEquals: { [`iam:${ZW}PassedToService`]: `ec2${ZW}.amazonaws.com` } },
      },
      { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
    ],
  });
  const result = scan({ text, family: 'identity', subjectAccount: '999988887777' });
  assert.ok((result.findings || []).length > 0, 'the escalation is still reported (fail-closed on risk)');
  const serialized = formatSarif(result, { file: `policy${ZW}.json` }, MANIFEST);
  assert.ok(!serialized.includes(ZW), 'U+180E does not survive anywhere in the serialized SARIF');
});

// ---------------------------------------------------------------------------
// Iteration-6 BLOCKER 2 (output-size amplification: code-units vs bytes). The document
// budget is NAMED in bytes (MAX_SARIF_BYTES = 8 MiB, targeting GitHub's ~10 MB cap) but
// was enforced via JSON.stringify(...).length = UTF-16 CODE UNITS. A within-limits
// multibyte fan-out (CJK, ~3 UTF-8 bytes/code unit) stayed under the code-unit budget so
// NO truncation fired, yet serialized to >10 MB of real bytes. The fix denominates the
// budget + estimateRowBytes in UTF-8 bytes, so the ceiling the constant names is the
// ceiling enforced. This test would FAIL on the old code (~10.4 MB serialized while the
// tool believed it fit) and passes now (serialized bytes bounded, truncation announced).
const MAX_SARIF_BYTES = 8 * 1024 * 1024; // mirrors cli/sarif.mjs (internal constant)

test('S2 iter6: the size budget is denominated in UTF-8 BYTES, not code units (multibyte fan-out stays under the byte cap)', () => {
  const cjkSid = String.fromCodePoint(0x4E00).repeat(128); // U+4E00: 1 code unit, 3 UTF-8 bytes
  const statements = [];
  for (let i = 0; i < 1000; i += 1) {
    statements.push({ Sid: `${cjkSid}${i}`, Effect: 'Allow', Action: '*', Resource: '*' });
  }
  const text = JSON.stringify({ Version: '2012-10-17', Statement: statements });
  // Within engine input limits: well under MAX_BYTES (1 MiB) and MAX_STATEMENTS.
  assert.ok(Buffer.byteLength(text, 'utf8') < 1024 * 1024, 'input is within the engine byte limit');
  const result = scan({ text, family: 'identity' });
  assert.notEqual(result.exitCode, 2, 'input is accepted (not a usage error)');
  const serialized = formatSarif(result, { file: 'p.json' }, MANIFEST);

  const byteSize = Buffer.byteLength(serialized, 'utf8');
  const codeUnits = serialized.length;
  // The multibyte payload makes bytes materially exceed code units - the exact gap the old
  // code-unit budget ignored.
  assert.ok(byteSize > codeUnits, 'the payload is genuinely multibyte (bytes > code units)');
  // The REGRESSION assertion: the REAL serialized UTF-8 byte size honours the byte budget.
  // Old code produced ~10.4 MB here while emitting a "fit" verdict; this is the failing case.
  assert.ok(byteSize <= MAX_SARIF_BYTES,
    `serialized SARIF must stay within the byte budget; got ${byteSize} bytes`);
  // ...and the trim is ANNOUNCED (fail-closed), never silent.
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const trunc = log.runs[0].results.filter((r) => r.ruleId === 'analysis.SARIF_OUTPUT_TRUNCATED');
  assert.equal(trunc.length, 1, 'a truncation analyzer-state is emitted when the byte budget binds');
});

// ---------------------------------------------------------------------------
// Round-3 BLOCKER (bidi/zero-width spoof, incomplete-enumeration class, one spelling
// DEEPER still). Iteration-6 added \p{Cc}\p{Cf} + a HAND-LIST of the non-Cc/Cf invisibles.
// The hunter found the next spelling: default-ignorable code points that are NEITHER Cc/Cf
// NOR on the hand-list survived VERBATIM into every SARIF sink -
//   U+034F COMBINING GRAPHEME JOINER   (category Mn, Default_Ignorable)
//   U+17B4 / U+17B5 Khmer inherent vowels (category Mn, Default_Ignorable, render blank)
//   U+E0000 reserved tag-block base    (category Cn, Default_Ignorable)
// none caught by \s or the ASCII-punctuation escape - so a hostile ARN/account could be
// zero-width HIDDEN/SPLIT or a grapheme REORDERED in a maintainer's markdown-rendered alert.
// The class fix stops HAND-LISTING and matches the Unicode PROPERTY the class IS:
// CONTROL_AND_FORMAT = \p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point} + U+2800 (the one
// spoofing blank that is category So, not default-ignorable). \p{Default_Ignorable_Code_
// Point} subsumes CGJ, the Khmer vowels, EVERY Hangul filler + variation selector, the
// whole U+2060-206F block (incl. the reserved U+2065), the tag-block base, and any FUTURE
// default-ignorable assignment - closing the regress at the property level. Each formerly-
// surviving code point is checked EXACTLY (removed, not merely inert) from every SARIF sink.
const ROUND3_DEFAULT_IGNORABLE = [
  0x034F, // COMBINING GRAPHEME JOINER
  0x17B4, 0x17B5, // Khmer inherent vowels (render blank)
  0x2065, // reserved inside the invisible-format block (unassigned Cn, default-ignorable)
  0xE0000, // reserved tag-block base (unassigned Cn, default-ignorable)
  0x1BCA0, 0x1BCA3, // SHORTHAND FORMAT controls (astral Cf) - property covers them too
];

test('S2 round3: default-ignorable code points a hand-list missed are STRIPPED from every SARIF sink (codepoint-exact)', () => {
  for (const cp of ROUND3_DEFAULT_IGNORABLE) {
    const M = String.fromCodePoint(cp);
    const hex = cp.toString(16).toUpperCase().padStart(4, '0');
    const result = {
      analysisStatus: 'complete',
      findings: [{
        id: 'PASSROLE-SERVICE', severity: 'critical', title: 't',
        statementSid: `Adm${M}in`, statementIndex: 0,
        actions: ['iam:PassRole'], resources: ['r'], conditions: null,
        evidence: [{
          statementIndex: 0,
          statementSid: `s${M}id`,
          role: `role${M}x`,
          actions: [`iam:Pass${M}Role`],
          resources: [`arn:aws:iam::999988887777:role/${M}app`],
          condition: { [`Str${M}ingEquals`]: { [`k${M}ey`]: `ec2${M}.amazonaws.com` } },
          note: `passes ${M} to service`,
        }],
      }],
      family: 'identity',
    };
    const serialized = formatSarif(result, { file: `p${M}.json` }, MANIFEST);
    assert.ok(!serialized.includes(M),
      `U+${hex} must not survive anywhere in the serialized SARIF`);
    const sec = buildSarifLog(result, { file: `p${M}.json` }, MANIFEST).runs[0].results[0];
    assert.ok(!sec.message.text.includes(M), `U+${hex} stripped from message.text`);
    assert.ok(!sec.properties.statementSid.includes(M), `U+${hex} stripped from properties.statementSid`);
    assert.ok(!sec.locations[0].physicalLocation.artifactLocation.uri.includes(M), `U+${hex} stripped from artifact uri`);
    assert.ok(!JSON.stringify(sec.properties.evidence[0]).includes(M), `U+${hex} stripped from evidence row`);
  }
});

test('S2 round3 / S4 iter-3: benign ASCII evidence rides through; non-ASCII is charset-clamped at the SARIF display sink (no ASCII over-strip, no false-positive truncation)', () => {
  // Real ARNs, service principals, and tag keys ride through with only punctuation
  // backslash-escaped, never truncated (the S2 no-over-strip / no-false-truncation guard).
  // REVISED for S4-unicode-spoof iteration 3 (BLOCKER 1): international NON-ASCII content is
  // now charset-clamped to U+FFFD at the DISPLAY sink. The strong-RTL bidi-reorder mechanism
  // (CVE-2021-42574) has no complete, non-enumerable regex - an RTL-SCRIPT blocklist fails
  // open on the next script - so the sinks enforce the AWS-grammar ASCII charset (the
  // reviewer-sanctioned option). This clamps benign LTR non-ASCII too, but ONLY on the
  // human-facing PROJECTION: the RAW condition still feeds partialFingerprints unchanged
  // (see 'S2: partialFingerprints hash the RAW condition, unaffected by neutralization'), so
  // finding IDENTITY is byte-for-byte stable - the load-bearing S2 contract is intact.
  const result = evidenceResult({
    StringEquals: {
      'aws:PrincipalOrgID': ['o-abc123', 'ec2.amazonaws.com', 'arn:aws:iam::123456789012:role/App-Prod_1'],
      // International letters + a DECOMPOSED combining accent (U+0301), explicit \u escapes
      // so the source stays ASCII and the clamp assertion is unambiguous.
      'aws:PrincipalTag/team': 'cafe\u0301 resume\u0301 \u65e5\u672c\u8a9e U\u0308ber N\u0303on\u0303o',
    },
  });
  const { ev } = evidenceRow(result);
  assert.equal(ev.conditionTruncated, undefined, 'a benign condition is not truncated (no false-positive truncation)');
  // Condition KEYS are markdown-inert (punctuation backslash-escaped), so index by VALUE
  // shape, not by the raw key name. 'StringEquals' is punctuation-free and survives verbatim.
  const vals = Object.values(ev.condition.StringEquals);
  const arr = vals.find((v) => Array.isArray(v));
  const team = vals.find((v) => typeof v === 'string');
  // ASCII evidence preserved verbatim (only punctuation escaped) - the no-over-strip guard.
  assert.ok(arr && arr.some((v) => v.includes('ec2') && v.includes('amazonaws')), 'service principal preserved');
  assert.ok(arr.some((v) => v.includes('123456789012')), 'ARN account preserved');
  // ASCII letters WITHIN the international value survive as inert text...
  for (const frag of ['cafe', 'resume', 'ber', 'on']) {
    assert.ok(team.includes(frag), `ASCII letters preserved (${frag})`);
  }
  // ...but every non-ASCII letter + combining mark is charset-clamped (NOT preserved).
  for (const cp of ['\u65e5', '\u672c', '\u8a9e', '\u0301', '\u0308', '\u0303']) {
    assert.ok(!team.includes(cp), `non-ASCII U+${cp.codePointAt(0).toString(16)} clamped at the display sink`);
  }
  // The ONLY non-ASCII code point that may survive is the U+FFFD neutralization marker.
  for (const ch of team) {
    const c = ch.codePointAt(0);
    assert.ok(c < 0x80 || ch === '\uFFFD', `only ASCII (+ U+FFFD) survives; leaked U+${c.toString(16)}`);
  }
});
