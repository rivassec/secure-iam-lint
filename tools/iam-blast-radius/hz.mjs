import { analyze } from '/Users/oliver/dev/devsecops-notes/content/tools/iam-blast-radius/engine/analyze.js';
function h(label, notActions){
  const text = JSON.stringify({Version:'2012-10-17',Statement:[
    {Effect:'Allow',Action:'*',Resource:'*'},
    {Effect:'Deny',NotAction:notActions,Resource:'*',Condition:{StringNotEqualsIfExists:{'aws:RequestedRegion':'us-east-1'}}}
  ]});
  const r=analyze(text,{family:'scp-rcp'});
  const g=r.findings.find(f=>f.id==='SCP-GUARDRAIL');
  console.log(label,'| hazard=',g.hazard,'| sev=',g.severity,'| title=',g.title);
}
h('carveout=iam:* (real global)      ',['iam:*']);
h('carveout=iam:CreateUser (1 action)',['iam:CreateUser']);
h('carveout=s3:* (non-global only)   ',['s3:*']);
h('carveout=iam:*+s3:*               ',['iam:*','s3:*']);
const t2=JSON.stringify({Version:'2012-10-17',Statement:[
  {Effect:'Allow',Action:'*',Resource:'*'},
  {Effect:'Deny',Action:'*',Resource:'*',Condition:{StringNotEqualsIfExists:{'aws:RequestedRegion':'us-east-1'}}}]});
const g2=analyze(t2,{family:'scp-rcp'}).findings.find(f=>f.id==='SCP-GUARDRAIL');
console.log('no-carveout Action:* deny            | hazard=',g2.hazard,'| sev=',g2.severity);
