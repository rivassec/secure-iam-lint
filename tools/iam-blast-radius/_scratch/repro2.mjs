import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

function build(N, M, distinct) {
  const actions = [];
  // a small pool of genuinely-distinct short bulk patterns matching s3:GetObject
  const pool = ['s3:GetObject','s3:GetObjec*','s3:GetObj*','s3:Get*','s3:G*','s3:*Object','s3:*bject','s3:Ge*ct','s3:GetObjec?','s3:G?tObject'];
  for (let i = 0; i < N; i++) actions.push(distinct ? pool[i % pool.length] : 's3:GetObject');
  const notRes = [];
  for (let i = 0; i < M; i++) notRes.push(`arn:aws:s3:::approved-bkt-${i}/keep/*`);
  return JSON.stringify({ Version:'2012-10-17', Statement:[
    { Sid:'Broad', Effect:'Allow', Action:actions, Resource:'*' },
    { Sid:'Fence', Effect:'Deny', Action:'s3:*', NotResource:notRes },
  ]});
}

for (const [N,M] of [[500,500],[2000,2000],[5000,5000],[9990,9990]]) {
  const text = build(N, M, false); // duplicate 's3:GetObject'
  const bytes = Buffer.byteLength(text);
  if (bytes > 1024*1024) { console.log(`N=${N} M=${M} bytes=${bytes} SKIP(>1MiB)`); continue; }
  const t0 = process.hrtime.bigint();
  const res = analyze(text);
  const t1 = process.hrtime.bigint();
  const f = res.findings && res.findings[0];
  console.log(`N=${N} M=${M} bytes=${bytes} time=${(Number(t1-t0)/1e6).toFixed(1)}ms ok=${res.ok} findings=${res.findings?res.findings.length:'n/a'} f0.actions=${f?f.actions.length:'-'} incomplete=${res.coverage?.summary?.incomplete}`);
}
