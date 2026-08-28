// Tests for the SARIF 2.1.0 adapter (Phase 15, story P15-sarif).
//
// cli/sarif.mjs is a PURE projection of a scan() result into a SARIF 2.1.0 log: no
// I/O, no Node APIs, deterministic. These tests pin:
//   - the SARIF 2.1.0 STRUCTURE (required fields; no external validator dependency),
//   - the finding-TYPE -> reportingDescriptor + result mapping (ruleId = type),
//   - severity -> level + security-severity (info omits it),
//   - properties.certainty / evidence / policyFamily and the location model,
//   - partialFingerprints on NORMALIZED SEMANTIC identity (stable across whitespace,
//     key order, and artifact path; never message text / uri),
//   - GOLDEN determinism (same input -> byte-identical SARIF), and
//   - the ADVERSARIAL separation: an analyzer-state (fail-closed) result carries NO
//     security-severity and cannot be mistaken for a vulnerability, and a fail-closed
//     run's SARIF COINCIDES with scan() exit code 3.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan, EXIT } from '../../../cli/scan.mjs';
import {
  buildSarifLog, formatSarif, findingIdentity, stateIdentity,
  SARIF_SEVERITY, FINGERPRINT_KEY, artifactUri,
} from '../../../cli/sarif.mjs';

const MANIFEST = { ruleVersion: '1' };

// --- Inline fixtures ----------------------------------------------------------

const ADMIN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{ Sid: 'AdminAll', Effect: 'Allow', Action: 'iam:*', Resource: '*' }],
});

// The SAME admin policy, but with different whitespace AND different object key
// order. Semantically identical -> the finding fingerprint MUST be identical.
const ADMIN_IDENTITY_REORDERED = `{
    "Statement": [
       { "Resource": "*", "Action": "iam:*", "Effect": "Allow", "Sid": "AdminAll" }
    ],
    "Version"  :  "2012-10-17"
}`;

const CLEAN_IDENTITY = JSON.stringify({
  Version: '2012-10-17',
  Statement: [{
    Effect: 'Allow', Action: 'ec2:DescribeInstances',
    Resource: 'arn:aws:ec2:us-east-1:111122223333:instance/i-0abc',
  }],
});

// PassRole pinned to a concrete account, NO subject account -> unknown viability ->
// analysisStatus partial, exit 3, an analyzer-state result. Also carries evidence.
const PASSROLE_UNKNOWN = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: 'arn:aws:iam::999988887777:role/app' },
    { Effect: 'Allow', Action: 'ec2:RunInstances', Resource: '*' },
  ],
});

const MALFORMED = '{ not valid json';

// A synthetic scan-shaped result feeds buildSarifLog directly, so the severity
// matrix does not depend on the engine emitting each severity.
function syntheticResult({ severity, family = 'identity', analysisStates = [] }) {
  return {
    analysisStatus: 'complete',
    analysisStates,
    findings: [{
      id: `RULE-${String(severity).toUpperCase()}`,
      severity,
      title: `A ${severity} finding`,
      statementSid: 'S1',
      statementIndex: 0,
      actions: ['svc:Action'],
      resources: ['arn:aws:svc:::thing'],
      conditions: null,
    }],
    findingsCount: 1,
    blockingCount: 1,
    exitCode: 1,
    family,
  };
}

// =============================================================================
// SARIF 2.1.0 structural validation (no external schema dependency).
// =============================================================================

const VALID_LEVELS = new Set(['error', 'warning', 'note', 'none']);

// A minimal SARIF 2.1.0 required-field validator. Returns a list of problems.
function sarifStructuralProblems(log) {
  const problems = [];
  const req = (cond, msg) => { if (!cond) problems.push(msg); };
  req(log && typeof log === 'object', 'log is an object');
  req(log && log.version === '2.1.0', 'version === 2.1.0');
  req(log && Array.isArray(log.runs), 'runs is an array');
  for (const run of (log.runs || [])) {
    req(run && run.tool && run.tool.driver, 'run.tool.driver present');
    const driver = run.tool && run.tool.driver;
    req(driver && typeof driver.name === 'string' && driver.name.length > 0, 'driver.name non-empty');
    req(driver && Array.isArray(driver.rules), 'driver.rules is an array');
    const ruleIds = new Set();
    for (const rule of (driver.rules || [])) {
      req(rule && typeof rule.id === 'string' && rule.id.length > 0, 'rule.id non-empty string');
      ruleIds.add(rule && rule.id);
    }
    req(Array.isArray(run.results), 'run.results is an array');
    for (const r of (run.results || [])) {
      req(r && typeof r.ruleId === 'string' && r.ruleId.length > 0, 'result.ruleId non-empty');
      req(r && r.message && typeof r.message.text === 'string' && r.message.text.length > 0,
        'result.message.text non-empty');
      req(r && VALID_LEVELS.has(r.level), `result.level valid (${r && r.level})`);
      req(r && Array.isArray(r.locations) && r.locations.length >= 1, 'result.locations >= 1');
      const uri = r && r.locations && r.locations[0]
        && r.locations[0].physicalLocation
        && r.locations[0].physicalLocation.artifactLocation
        && r.locations[0].physicalLocation.artifactLocation.uri;
      req(typeof uri === 'string' && uri.length > 0, 'artifactLocation.uri non-empty');
      if (typeof r.ruleIndex === 'number') {
        req(r.ruleIndex >= 0 && r.ruleIndex < (driver.rules || []).length, 'ruleIndex in range');
      }
    }
  }
  return problems;
}

test('SARIF envelope is a structurally valid SARIF 2.1.0 log (findings + analyzer-state)', () => {
  for (const [text, family] of [[ADMIN_IDENTITY, 'identity'], [PASSROLE_UNKNOWN, 'identity'], [MALFORMED, 'identity'], [CLEAN_IDENTITY, 'identity']]) {
    const result = scan({ text, family, threshold: 'high' });
    const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
    const problems = sarifStructuralProblems(log);
    assert.deepEqual(problems, [], `structural problems for ${family}: ${problems.join('; ')}`);
  }
});

test('parseable SARIF: formatSarif emits pretty JSON with a trailing newline', () => {
  const result = scan({ text: ADMIN_IDENTITY, family: 'identity' });
  const s = formatSarif(result, { file: 'p.json' }, MANIFEST);
  assert.ok(s.endsWith('\n'));
  const parsed = JSON.parse(s);
  assert.equal(parsed.version, '2.1.0');
  assert.deepEqual(sarifStructuralProblems(parsed), []);
});

// =============================================================================
// Finding TYPE -> reportingDescriptor + result mapping (ruleId = finding type).
// =============================================================================

test('every security result ruleId resolves to a reportingDescriptor of the SAME finding type', () => {
  const result = scan({ text: ADMIN_IDENTITY, family: 'identity' });
  const log = buildSarifLog(result, {}, MANIFEST);
  const driver = log.runs[0].tool.driver;
  const ruleById = new Map(driver.rules.map((r) => [r.id, r]));
  const security = log.runs[0].results.filter((r) => r.properties.category === 'security');
  assert.ok(security.length >= 1);
  for (const r of security) {
    // ruleId is the finding TYPE and has a descriptor.
    assert.ok(ruleById.has(r.ruleId), `descriptor exists for ${r.ruleId}`);
    // ruleIndex points at that descriptor.
    assert.equal(driver.rules[r.ruleIndex].id, r.ruleId);
    // the descriptor is a security rule.
    assert.equal(ruleById.get(r.ruleId).properties.category, 'security');
  }
});

test('a reportingDescriptor is emitted per finding TYPE, not per instance', () => {
  // Two statements each triggering the SAME wildcard type would still be one rule.
  const twoWild = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'A', Effect: 'Allow', Action: 's3:*', Resource: '*' },
      { Sid: 'B', Effect: 'Allow', Action: 'ec2:*', Resource: '*' },
    ],
  });
  const result = scan({ text: twoWild, family: 'identity' });
  const log = buildSarifLog(result, {}, MANIFEST);
  const rules = log.runs[0].tool.driver.rules;
  const ids = rules.map((r) => r.id);
  // No duplicate rule ids even if multiple results share a type.
  assert.equal(ids.length, new Set(ids).size, 'rule ids are unique');
});

// =============================================================================
// Severity -> level + security-severity (info omits security-severity).
// =============================================================================

test('severity maps to the documented level + security-severity; info omits it', () => {
  const expected = {
    critical: { level: 'error', ss: '9.0' },
    high: { level: 'error', ss: '7.0' },
    medium: { level: 'warning', ss: '5.0' },
    low: { level: 'note', ss: '2.0' },
    info: { level: 'note', ss: null },
  };
  for (const [sev, exp] of Object.entries(expected)) {
    const log = buildSarifLog(syntheticResult({ severity: sev }), {}, MANIFEST);
    const res = log.runs[0].results[0];
    assert.equal(res.level, exp.level, `level for ${sev}`);
    if (exp.ss === null) {
      assert.ok(!('security-severity' in res.properties), `${sev} omits security-severity`);
    } else {
      assert.equal(res.properties['security-severity'], exp.ss, `security-severity for ${sev}`);
    }
    // The rule descriptor mirrors the mapping.
    const rule = log.runs[0].tool.driver.rules[0];
    assert.equal(rule.defaultConfiguration.level, exp.level);
    if (exp.ss === null) assert.ok(!('security-severity' in rule.properties));
    else assert.equal(rule.properties['security-severity'], exp.ss);
  }
});

test('an UNRECOGNIZED severity token FAILS CLOSED to the highest band (error/critical), never note/info (defense in depth)', () => {
  // Not reachable today (every engine producer emits one of the five valid literals),
  // but a producer bug or a future out-of-enum token must NEVER be silently downgraded
  // below a code-scanning severity threshold - an under-reported finding is a hidden
  // risk. The raw token is still preserved verbatim in properties.severity.
  for (const bad of ['definitely-not-a-severity', 'SEVERE', 'urgent']) {
    const log = buildSarifLog(syntheticResult({ severity: bad }), {}, MANIFEST);
    const res = log.runs[0].results[0];
    assert.equal(res.level, 'error', `unrecognized "${bad}" -> error, not note`);
    assert.equal(res.properties['security-severity'], '9.0', `unrecognized "${bad}" -> critical band`);
    assert.equal(res.properties.severity, String(bad).toLowerCase(), 'raw token preserved for the record');
    const rule = log.runs[0].tool.driver.rules[0];
    assert.equal(rule.defaultConfiguration.level, 'error', 'the rule descriptor also fails closed to error');
    assert.equal(rule.properties['security-severity'], '9.0');
  }
});

test('SARIF_SEVERITY table exactly matches the design doc mapping', () => {
  assert.deepEqual(SARIF_SEVERITY.critical, { level: 'error', securitySeverity: '9.0' });
  assert.deepEqual(SARIF_SEVERITY.high, { level: 'error', securitySeverity: '7.0' });
  assert.deepEqual(SARIF_SEVERITY.medium, { level: 'warning', securitySeverity: '5.0' });
  assert.deepEqual(SARIF_SEVERITY.low, { level: 'note', securitySeverity: '2.0' });
  assert.deepEqual(SARIF_SEVERITY.info, { level: 'note', securitySeverity: null });
});

// =============================================================================
// properties: certainty / evidence / policyFamily, and the location model.
// =============================================================================

test('security result carries policyFamily and the certainty the finding already reported', () => {
  const result = scan({ text: ADMIN_IDENTITY, family: 'identity' });
  const log = buildSarifLog(result, {}, MANIFEST);
  const res = log.runs[0].results.find((r) => r.properties.category === 'security');
  assert.equal(res.properties.policyFamily, 'identity');
  // certainty is preserved exactly from the finding's own signals (never re-derived).
  assert.equal(typeof res.properties.certainty, 'object');
  const f = result.findings[0];
  if (f.policyEvidence != null) assert.equal(res.properties.certainty.policyEvidence, f.policyEvidence);
  if (f.pathExploitability != null) assert.equal(res.properties.certainty.pathExploitability, f.pathExploitability);
});

test('escalation finding surfaces its evidence rows in properties.evidence', () => {
  const result = scan({ text: PASSROLE_UNKNOWN, family: 'identity' });
  const log = buildSarifLog(result, {}, MANIFEST);
  const sec = log.runs[0].results.find((r) => r.properties.category === 'security');
  assert.ok(sec, 'a security finding is present');
  assert.ok(Array.isArray(sec.properties.evidence) && sec.properties.evidence.length >= 1,
    'evidence rows are present');
  // jsonPointer points at the anchoring statement.
  assert.equal(sec.properties.jsonPointer, '/Statement/0');
});

test('location model: default uri is "stdin"; --artifact-uri overrides; file path used otherwise', () => {
  assert.equal(artifactUri({}), 'stdin');
  assert.equal(artifactUri({ file: 'policies/app.json' }), 'policies/app.json');
  assert.equal(artifactUri({ artifactUri: 'pasted-policy.json' }), 'pasted-policy.json');
  // artifact-uri wins over file.
  assert.equal(artifactUri({ file: 'a.json', artifactUri: 'b.json' }), 'b.json');

  const result = scan({ text: ADMIN_IDENTITY, family: 'identity' });
  const log = buildSarifLog(result, { artifactUri: 'policies/app.json' }, MANIFEST);
  const uri = log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  assert.equal(uri, 'policies/app.json');
});

// =============================================================================
// partialFingerprints on normalized SEMANTIC identity.
// =============================================================================

test('partialFingerprints are stable across whitespace AND object key order', () => {
  const a = scan({ text: ADMIN_IDENTITY, family: 'identity' });
  const b = scan({ text: ADMIN_IDENTITY_REORDERED, family: 'identity' });
  const fpA = buildSarifLog(a, {}, MANIFEST).runs[0].results[0].partialFingerprints[FINGERPRINT_KEY];
  const fpB = buildSarifLog(b, {}, MANIFEST).runs[0].results[0].partialFingerprints[FINGERPRINT_KEY];
  assert.equal(typeof fpA, 'string');
  assert.ok(fpA.length >= 16);
  assert.equal(fpA, fpB, 'same semantic identity -> same fingerprint');
});

test('partialFingerprints do NOT depend on the artifact uri (repo-relative vs absolute)', () => {
  const result = scan({ text: ADMIN_IDENTITY, family: 'identity' });
  const rel = buildSarifLog(result, { file: 'policies/app.json' }, MANIFEST);
  const abs = buildSarifLog(result, { file: '/abs/tmp/x/policies/app.json' }, MANIFEST);
  assert.equal(
    rel.runs[0].results[0].partialFingerprints[FINGERPRINT_KEY],
    abs.runs[0].results[0].partialFingerprints[FINGERPRINT_KEY],
    'fingerprint is independent of the artifact path',
  );
});

test('findingIdentity ignores message text and captures type/family/statement/action/resource', () => {
  const base = {
    id: 'T', severity: 'high', title: 'title one',
    statementIndex: 0, statementSid: 'S', actions: ['s3:GetObject'],
    resources: ['arn:aws:s3:::b/*'], conditions: null,
  };
  const idBase = findingIdentity(base, 'identity');
  // Same semantic identity, DIFFERENT title/message -> identical identity string.
  const differentTitle = { ...base, title: 'a completely different label' };
  assert.equal(findingIdentity(differentTitle, 'identity'), idBase);
  // Action case + order do not matter (normalized: lowercased + sorted).
  const reorderedActions = { ...base, actions: ['S3:GETOBJECT'] };
  assert.equal(findingIdentity(reorderedActions, 'identity'), idBase);
  // A different resource DOES change identity.
  const differentResource = { ...base, resources: ['arn:aws:s3:::other/*'] };
  assert.notEqual(findingIdentity(differentResource, 'identity'), idBase);
  // A different family DOES change identity.
  assert.notEqual(findingIdentity(base, 'resource'), idBase);
});

test('condition key ORDER does not change findingIdentity, but condition VALUES do', () => {
  const c1 = { StringEquals: { 'aws:PrincipalTag/team': 'x', 'aws:SourceVpc': 'vpc-1' } };
  const c2 = { StringEquals: { 'aws:SourceVpc': 'vpc-1', 'aws:PrincipalTag/team': 'x' } };
  const f1 = { id: 'T', statementIndex: 0, statementSid: 'S', actions: ['a'], resources: ['r'], conditions: c1 };
  const f2 = { id: 'T', statementIndex: 0, statementSid: 'S', actions: ['a'], resources: ['r'], conditions: c2 };
  assert.equal(findingIdentity(f1, 'identity'), findingIdentity(f2, 'identity'));
  const f3 = { ...f1, conditions: { StringEquals: { 'aws:SourceVpc': 'vpc-2' } } };
  assert.notEqual(findingIdentity(f3, 'identity'), findingIdentity(f1, 'identity'));
});

// =============================================================================
// GOLDEN determinism: same input -> byte-identical SARIF.
// =============================================================================

test('golden: SARIF output is byte-identical across repeated builds (deterministic)', () => {
  const result = scan({ text: ADMIN_IDENTITY, family: 'identity' });
  const one = formatSarif(result, { file: 'policies/app.json' }, MANIFEST);
  const two = formatSarif(result, { file: 'policies/app.json' }, MANIFEST);
  assert.equal(one, two);
});

test('golden: the admin-identity SARIF pins the load-bearing fields', () => {
  const result = scan({ text: ADMIN_IDENTITY, family: 'identity' });
  const log = buildSarifLog(result, { file: 'policies/app.json' }, MANIFEST);
  // Envelope.
  assert.equal(log.version, '2.1.0');
  assert.equal(log.$schema, 'https://json.schemastore.org/sarif-2.1.0.json');
  assert.equal(log.runs.length, 1);
  const driver = log.runs[0].tool.driver;
  assert.equal(driver.name, 'IAM Blast Radius');
  assert.equal(driver.semanticVersion, '1');
  // The primary finding type.
  const rule = driver.rules.find((r) => r.id === 'DIRECT-IAM-ADMIN');
  assert.ok(rule, 'DIRECT-IAM-ADMIN descriptor present');
  assert.equal(rule.properties.category, 'security');
  assert.equal(rule.properties['security-severity'], '7.0');
  assert.equal(rule.defaultConfiguration.level, 'error');
  // The result row.
  const res = log.runs[0].results.find((r) => r.ruleId === 'DIRECT-IAM-ADMIN');
  assert.ok(res);
  assert.equal(res.level, 'error');
  assert.equal(res.properties.category, 'security');
  assert.equal(res.properties.severity, 'high');
  assert.equal(res.properties['security-severity'], '7.0');
  assert.equal(res.properties.policyFamily, 'identity');
  assert.equal(res.properties.jsonPointer, '/Statement/0');
  assert.equal(res.locations[0].physicalLocation.artifactLocation.uri, 'policies/app.json');
  assert.ok(FINGERPRINT_KEY in res.partialFingerprints);
  // Run-level verdict mirror.
  assert.equal(log.runs[0].properties.analysisStatus, 'complete');
  assert.equal(log.runs[0].properties.exitCode, 1);
});

test('golden: a clean policy yields zero results and zero rules', () => {
  const result = scan({ text: CLEAN_IDENTITY, family: 'identity' });
  const log = buildSarifLog(result, {}, MANIFEST);
  assert.deepEqual(log.runs[0].results, []);
  assert.deepEqual(log.runs[0].tool.driver.rules, []);
  assert.equal(log.runs[0].properties.analysisStatus, 'complete');
  assert.equal(log.runs[0].properties.exitCode, 0);
});

// =============================================================================
// ADVERSARIAL: analyzer-state separation + fail-closed coincides with exit 3.
// =============================================================================

test('adversarial: an analyzer-state result carries NO security-severity and is not a vuln', () => {
  const result = scan({ text: MALFORMED, family: 'identity' });
  assert.equal(result.exitCode, EXIT.FAIL_CLOSED);
  const log = buildSarifLog(result, {}, MANIFEST);
  const states = log.runs[0].results.filter((r) => r.properties.category === 'analysis-state');
  assert.ok(states.length >= 1, 'a fail-closed analyzer-state result is present');
  for (const r of states) {
    assert.equal(r.kind, 'fail');
    assert.equal(r.level, 'error');
    assert.equal(r.properties.failClosed, true);
    assert.ok(!('security-severity' in r.properties), 'analyzer-state result has NO security-severity');
    assert.ok(!('certainty' in r.properties), 'analyzer-state result has NO certainty/vuln metadata');
    assert.ok(r.ruleId.startsWith('analysis.'), 'analyzer-state ruleId is namespaced');
  }
  // The analyzer-state RULE descriptor also carries NO security-severity.
  const analysisRules = log.runs[0].tool.driver.rules.filter((r) => r.properties.category === 'analysis-state');
  assert.ok(analysisRules.length >= 1);
  for (const rule of analysisRules) {
    assert.ok(!('security-severity' in rule.properties), 'analyzer-state RULE has NO security-severity');
  }
});

test('adversarial: a fail-closed run has NO security-category results (all could-not-analyze)', () => {
  const result = scan({ text: MALFORMED, family: 'identity' });
  const log = buildSarifLog(result, {}, MANIFEST);
  const security = log.runs[0].results.filter((r) => r.properties.category === 'security');
  assert.equal(security.length, 0, 'a malformed input yields no security findings');
});

test('adversarial: a fail-closed SARIF coincides with scan exit code 3', () => {
  for (const [text, family] of [[MALFORMED, 'identity'], [PASSROLE_UNKNOWN, 'identity']]) {
    const result = scan({ text, family });
    assert.equal(result.exitCode, EXIT.FAIL_CLOSED, `${family} fails closed`);
    const log = buildSarifLog(result, {}, MANIFEST);
    const states = log.runs[0].results.filter((r) => r.properties.category === 'analysis-state');
    assert.ok(states.length >= 1, 'fail-closed SARIF carries >= 1 analyzer-state result');
    // The run-level mirror shows a non-complete status + exit 3.
    assert.notEqual(log.runs[0].properties.analysisStatus, 'complete');
    assert.equal(log.runs[0].properties.exitCode, 3);
  }
});

test('adversarial: analyzer-state fingerprints key on state identity, not message text', () => {
  const s1 = { analysisState: 'malformed', code: 'REJECTED', path: 'Statement[0]', message: 'one wording' };
  const s2 = { analysisState: 'malformed', code: 'REJECTED', path: 'Statement[0]', message: 'a totally different wording' };
  assert.equal(stateIdentity(s1), stateIdentity(s2), 'message text does not change state identity');
  const s3 = { analysisState: 'unsupported', code: 'REJECTED', path: 'Statement[0]' };
  assert.notEqual(stateIdentity(s3), stateIdentity(s1), 'analysisState changes state identity');
});

// =============================================================================
// The adapter is PURE: no Node APIs / network / eval in the SARIF module source.
// =============================================================================

test('cli/sarif.mjs uses no Node built-ins, network, eval, or dynamic import', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const { dirname, join } = await import('node:path');
  const here = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(join(here, '..', '..', '..', 'cli', 'sarif.mjs'), 'utf8');
  const banned = [
    /from\s+['"]node:/,
    /require\(/,
    /\bfetch\s*\(/,
    /XMLHttpRequest/,
    /\beval\s*\(/,
    /new\s+Function/,
    /import\s*\(/,        // dynamic import
    /\bprocess\./,
    /\bBuffer\b/,
  ];
  for (const re of banned) {
    assert.ok(!re.test(src), `sarif.mjs must not contain ${re}`);
  }
});
