import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
// Same N,M but make notResources[0] BROAD so classifyResource(!==NARROW) short-circuits .some at element 0.
function build(N, M, broadFirst){
  const actions=[]; for(let i=0;i<N;i++) actions.push('s3:GetObject');
  const notRes=[];
  for(let i=0;i<M;i++) notRes.push(`arn:aws:s3:::approved-bkt-${i}/keep/*`);
  if(broadFirst) notRes[0]='arn:aws:s3:::*';   // BROAD -> .some short-circuits immediately
  return JSON.stringify({Version:'2012-10-17',Statement:[
    {Sid:'Broad',Effect:'Allow',Action:actions,Resource:'*'},
    {Sid:'Fence',Effect:'Deny',Action:'s3:*',NotResource:notRes}]});
}
for(const broadFirst of [false, true]){
  const N=3000,M=3000; const text=build(N,M,broadFirst);
  const t0=process.hrtime.bigint(); const res=analyze(text); const t1=process.hrtime.bigint();
  console.log(`broadFirst=${broadFirst} N=${N} M=${M} time=${(Number(t1-t0)/1e6).toFixed(0)}ms findings=${res.findings?res.findings.length:'-'} incomplete=${res.coverage?.summary?.incomplete}`);
}
