import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
function build(N, M){
  const actions=[]; for(let i=0;i<N;i++) actions.push('s3:GetObject');
  const notRes=[]; for(let i=0;i<M;i++) notRes.push(`arn:aws:s3:::approved-bkt-${i}/keep/*`);
  return JSON.stringify({Version:'2012-10-17',Statement:[
    {Sid:'Broad',Effect:'Allow',Action:actions,Resource:'*'},
    {Sid:'Fence',Effect:'Deny',Action:'s3:*',NotResource:notRes}]});
}
for(const [N,M] of [[3000,50],[50,3000],[3000,3000],[1000,3000],[3000,1000]]){
  const text=build(N,M); const bytes=Buffer.byteLength(text);
  const t0=process.hrtime.bigint(); const res=analyze(text); const t1=process.hrtime.bigint();
  console.log(`N=${N} M=${M} bytes=${bytes} time=${(Number(t1-t0)/1e6).toFixed(0)}ms ok=${res.ok} findings=${res.findings?res.findings.length:'-'} incomplete=${res.coverage?.summary?.incomplete}`);
}
