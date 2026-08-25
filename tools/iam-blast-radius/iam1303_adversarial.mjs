// Scratch adversarial harness for IAM-1303. Read-only against the engine.
import { analyze } from '../../content/tools/iam-blast-radius/engine/analyze.js';

function grantSmells(findings) {
  // Any finding whose text implies a positive capability/grant is suspicious for
  // an SCP/RCP family. Collect the tell-tale signals.
  const hits = [];
  for (const f of findings) {
    const blob = JSON.stringify(f).toLowerCase();
    const bad = [];
    if (/"severity":"critical"/.test(JSON.stringify(f).toLowerCase())) bad.push('sev=critical');
    if (f.escalation) bad.push('has-escalation');
    if (/can-read|can-write|can-pass|data-exfil|public|publicly|is publicly/.test(blob)
        && !/not public access|widest subject|never public/.test(blob)) bad.push('public/capability-word');
    if (/\bgrants\b(?!\s+nothing)/.test(blob)) bad.push('grants-word');
    if (bad.length) hits.push({ id: f.id, title: f.title, bad });
  }
  return hits;
}

function summary(label, text, options) {
  const r = analyze(text, options);
  const out = {
    label,
    ok: r.ok,
    family: r.family,
    blocked: r.coverage ? r.coverage.blocked : undefined,
    blockingCodes: r.coverage && r.coverage.blockingCodes ? r.coverage.blockingCodes.map(b => b.code) : (r.errors||[]).map(e=>e.code),
    nFindings: r.findings.length,
    edges: r.counts.edges,
    nodes: r.counts.nodes,
    findingIds: r.findings.map(f => f.id),
    findingSeverities: r.findings.map(f => f.severity),
    grantSmells: grantSmells(r.findings),
  };
  return { r, out };
}

const cases = [];

// 1. SCP: FullAWSAccess Allow + region Deny (negated IfExists, NO carve-out) -> hazard, no grant
cases.push(['1_scp_fullaccess_plus_region_deny_negifexists_nocarveout',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'FullAccess', Effect: 'Allow', Action: '*', Resource: '*' },
      { Sid: 'RegionLock', Effect: 'Deny', Action: '*', Resource: '*',
        Condition: { StringNotEqualsIfExists: { 'aws:RequestedRegion': ['us-east-1','us-west-2'] } } },
    ],
  }), { family: 'scp-rcp' }]);

// 2. SCP Deny NotAction:[iam:*, cloudfront:*] region deny (negated IfExists WITH carve-out) -> no hazard, carve-out not "allowed"
cases.push(['2_scp_deny_notaction_carveout_region',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'FullAccess', Effect: 'Allow', Action: '*', Resource: '*' },
      { Sid: 'RegionLock', Effect: 'Deny', NotAction: ['iam:*','cloudfront:*','route53:*','support:*'], Resource: '*',
        Condition: { StringNotEqualsIfExists: { 'aws:RequestedRegion': 'us-east-1' } } },
    ],
  }), { family: 'scp' }]);

// 3. SCP org guardrail: Deny organizations:LeaveOrganization
cases.push(['3_scp_org_guardrail',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: '*', Resource: '*' },
      { Sid: 'NoLeave', Effect: 'Deny', Action: ['organizations:LeaveOrganization'], Resource: '*' },
    ],
  }), { family: 'scp-rcp' }]);

// 4. RCP confused-deputy Deny with Principal:* + s3:* -> must NOT be public/S3 grant
cases.push(['4_rcp_confused_deputy',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'ConfusedDeputy', Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*',
        Condition: {
          StringNotEqualsIfExists: { 'aws:SourceOrgID': 'o-abc123' },
          Bool: { 'aws:PrincipalIsAWSService': 'true' },
          Null: { 'aws:SourceAccount': 'false' },
        } },
    ],
  }), { family: 'rcp' }]);

// 5a. Genuinely-unmodelled SCP/RCP sub-shape: explicit scp-rcp on a SCOPED Allow (not a ceiling) -> fail closed
cases.push(['5a_scp_selected_on_scoped_allow',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [ { Effect: 'Allow', Action: ['s3:GetObject'], Resource: 'arn:aws:s3:::b/*' } ],
  }), { family: 'scp-rcp' }]);

// 5b. explicit scp-rcp on an ordinary resource GRANT (principal-bearing, no org-scope cond) -> fail closed, NOT public
cases.push(['5b_scp_selected_on_resource_grant',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [ { Effect: 'Allow', Principal: '*', Action: 's3:*', Resource: 'arn:aws:s3:::b/*' } ],
  }), { family: 'rcp' }]);

// 6. AUTO-DETECT on an SCP shape -> must fail closed (blocked), NOT identity, zero findings
cases.push(['6_autodetect_scp_shape',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: '*', Resource: '*' },
      { Effect: 'Deny', Action: '*', Resource: '*',
        Condition: { StringNotEqualsIfExists: { 'aws:RequestedRegion': 'us-east-1' } } },
    ],
  }), undefined]);

// 7. AUTO-DETECT on an RCP shape -> must fail closed (blocked as resource), NOT S3/public
cases.push(['7_autodetect_rcp_shape',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*',
        Condition: { StringNotEqualsIfExists: { 'aws:SourceOrgID': 'o-abc' }, Bool: { 'aws:PrincipalIsAWSService': 'true' } } },
    ],
  }), undefined]);

// 8. FAIL-OPEN PROBE: no-principal all-Deny NotAction:[iam:*] with NO org/region signal, AUTO-DETECT.
//    Design says this stays identity; identity engine must NOT report iam:* as an allowed grant.
cases.push(['8_autodetect_deny_notaction_iam_no_signal',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [ { Effect: 'Deny', NotAction: ['iam:*'], Resource: '*' } ],
  }), undefined]);

// 9. RCP with INVERTED org-scope operator (StringEquals) -> hazard medium, still not a grant
cases.push(['9_rcp_inverted_orgscope',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Deny', Principal: '*', Action: '*', Resource: '*',
        Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-abc' } } },
    ],
  }), { family: 'rcp' }]);

// 10. RCP explicit selection but plain org-perimeter deny NotAction carve-out
cases.push(['10_rcp_orgperimeter_notaction',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Deny', Principal: '*', NotAction: ['iam:*'], Resource: '*',
        Condition: { StringNotEqualsIfExists: { 'aws:PrincipalOrgID': 'o-abc' } } },
    ],
  }), { family: 'rcp' }]);

// 11. SCP explicit on RCP-shaped doc (principal-bearing deny w/ org cond) -> should route to RCP evaluator
cases.push(['11_scp_family_on_rcp_shape',
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Deny', Principal: '*', Action: '*', Resource: '*',
        Condition: { StringNotEqualsIfExists: { 'aws:SourceOrgID': 'o-x' }, Bool: { 'aws:PrincipalIsAWSService': 'true' } } },
    ],
  }), { family: 'scp' }]);

// 12. legacy version SCP -> must fail closed on version even w/ scp family
cases.push(['12_scp_legacy_version',
  JSON.stringify({
    Version: '2008-10-17',
    Statement: [
      { Effect: 'Allow', Action: '*', Resource: '*' },
      { Effect: 'Deny', Action: ['organizations:LeaveOrganization'], Resource: '*' },
    ],
  }), { family: 'scp-rcp' }]);

for (const [label, text, options] of cases) {
  const { out } = summary(label, text, options);
  console.log('\n=== ' + label + ' ===');
  console.log(JSON.stringify(out, null, 1));
}
