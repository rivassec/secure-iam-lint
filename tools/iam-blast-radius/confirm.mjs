import { analyze } from '/Users/oliver/dev/devsecops-notes/content/tools/iam-blast-radius/engine/analyze.js';
// Deny NotAction carve-out semantics (SCP)
const scp=analyze(JSON.stringify({Version:'2012-10-17',Statement:[
  {Effect:'Allow',Action:'*',Resource:'*'},
  {Effect:'Deny',NotAction:['iam:*','cloudfront:*'],Resource:'*',Condition:{StringNotEqualsIfExists:{'aws:RequestedRegion':'us-east-1'}}}]}),{family:'scp'});
const g=scp.findings.find(f=>f.id==='SCP-GUARDRAIL');
console.log('SCP carve-out: actions(=DENIED)=',JSON.stringify(g.actions),' excludedActions(=CARVE-OUT)=',JSON.stringify(g.excludedActions));
console.log('  why-contains "not a set of allowed"? ', /NOT a set of allowed actions/i.test(g.why));
// RCP public wording
const rcp=analyze(JSON.stringify({Version:'2012-10-17',Statement:[
  {Effect:'Deny',Principal:'*',Action:'s3:*',Resource:'*',Condition:{StringNotEqualsIfExists:{'aws:SourceOrgID':'o-x'},Bool:{'aws:PrincipalIsAWSService':'true'}}}]}),{family:'rcp'});
const rg=rcp.findings[0];
console.log('RCP wildcard-principal: wildcardPrincipalSubject=',rg.wildcardPrincipalSubject,' denyOnly=',rg.denyOnly);
console.log('  why contains "NOT public access"? ',/NOT public access/i.test(rg.why),' | contains bare "publicly"? ',/publicly/i.test(rg.why));
console.log('  any finding field claims s3 public/write? ',/public access or a grant/i.test(rg.why));
