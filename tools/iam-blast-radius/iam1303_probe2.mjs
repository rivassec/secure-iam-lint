import { analyze } from '../../content/tools/iam-blast-radius/engine/analyze.js';

function show(label, text, options) {
  const r = analyze(text, options);
  console.log('\n=== ' + label + ' ===');
  console.log('family=', r.family, 'blocked=', r.coverage && r.coverage.blocked, 'nFindings=', r.findings.length, 'edges=', r.counts.edges, 'nodes=', r.counts.nodes);
  console.log('graph.nodes=', JSON.stringify(r.graph.nodes));
  console.log('graph.edges=', JSON.stringify(r.graph.edges));
  for (const f of r.findings) {
    console.log('FINDING', f.id, '| sev=', f.severity, '| hazard=', f.hazard, '| actions=', JSON.stringify(f.actions), '| excludedActions=', JSON.stringify(f.excludedActions), '| negatedIfExists=', f.negatedIfExists);
  }
}

// Case 8 deep: all-Deny NotAction:[iam:*] no signal, auto-detect -> what is the edge?
show('8deep_deny_notaction_iam_autodetect',
  JSON.stringify({ Version: '2012-10-17',
    Statement: [ { Effect: 'Deny', NotAction: ['iam:*'], Resource: '*' } ] }), undefined);

// Case 1 deep: hazard details
show('1deep_scp_region_hazard',
  JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Action: '*', Resource: '*' },
    { Effect: 'Deny', Action: '*', Resource: '*', Condition: { StringNotEqualsIfExists: { 'aws:RequestedRegion': 'us-east-1' } } } ] }),
  { family: 'scp-rcp' });

// Probe A: RCP where confused-deputy but principalIsAwsService given as boolean false (JSON bool)
show('A_rcp_isawsservice_boolfalse',
  JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'Deny', Principal: '*', Action: '*', Resource: '*',
      Condition: { StringNotEqualsIfExists: { 'aws:SourceOrgID': 'o-x' }, Bool: { 'aws:PrincipalIsAWSService': false } } } ] }),
  { family: 'rcp' });

// Probe B: SCP explicit selection, mixed FullAccess Allow + Deny WITHOUT any org/region signal
//   isScpShape needs a guardrail signal; without it -> not scp shape -> fail closed.
show('B_scp_selected_fullaccess_plus_plain_deny',
  JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Action: '*', Resource: '*' },
    { Effect: 'Deny', Action: ['s3:DeleteBucket'], Resource: '*' } ] }),
  { family: 'scp-rcp' });

// Probe C: SCP with an unrecognized Effect value smuggled? model rejects -> fail. Use "allow" lowercase.
show('C_scp_bad_effect',
  JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'allow', Action: '*', Resource: '*' } ] }),
  { family: 'scp-rcp' });

// Probe D: RCP shape but one statement is an Allow (deny-only violated) under explicit rcp
//   isRcpShape requires all Deny -> false -> not scp/rcp shape -> fail closed (mixed? ambiguous?)
show('D_rcp_selected_with_allow_stmt',
  JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Principal: '*', Action: '*', Resource: '*' },
    { Effect: 'Deny', Principal: '*', Action: '*', Resource: '*',
      Condition: { StringNotEqualsIfExists: { 'aws:SourceOrgID': 'o-x' } } } ] }),
  { family: 'rcp' });

// Probe E: RCP confused-deputy but Principal is a specific ARN, not "*" -> still no S3/public, wildcardPrincipalSubject absent
show('E_rcp_specific_principal',
  JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'Deny', Principal: { AWS: 'arn:aws:iam::111122223333:root' }, Action: 's3:*', Resource: '*',
      Condition: { StringNotEqualsIfExists: { 'aws:SourceOrgID': 'o-x' }, Bool: { 'aws:PrincipalIsAWSService': 'true' } } } ] }),
  { family: 'rcp' });

// Probe F: SCP with NotAction:[iam:*] on the DENY as the org signal? iam:* is not organizations:* so not a signal.
//   All-deny no-principal, NotAction iam:*, no region cond -> not scp shape -> IDENTITY under scp-explicit -> fail closed
show('F_scp_selected_deny_notaction_iam_only',
  JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'Deny', NotAction: ['iam:*'], Resource: '*' } ] }),
  { family: 'scp-rcp' });
