import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

function buildPolicy(N, M) {
  // Stmt0: N distinct globs all matching s3:GetObject (trailing-star padding), Resource '*'
  const actions = [];
  for (let i = 0; i < N; i++) actions.push('s3:GetObject' + '*'.repeat(i + 1));
  // Stmt1: Deny s3:* NotResource of M narrow concrete ARNs
  const notRes = [];
  for (let i = 0; i < M; i++) notRes.push(`arn:aws:s3:::approved-data-bucket-${i}/keep/*`);
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Sid: 'Broad', Effect: 'Allow', Action: actions, Resource: '*' },
      { Sid: 'Fence', Effect: 'Deny', Action: 's3:*', NotResource: notRes },
    ],
  });
}

for (const [N, M] of [[50,50],[200,200],[500,500],[2000,2000],[5000,5000],[9990,9990]]) {
  const text = buildPolicy(N, M);
  const bytes = Buffer.byteLength(text);
  const t0 = process.hrtime.bigint();
  // Browser default budget: no workLimit override, no wall-clock deadline armed.
  const res = analyze(text);
  const t1 = process.hrtime.bigint();
  const ms = Number(t1 - t0) / 1e6;
  console.log(
    `N=${N} M=${M} bytes=${bytes} time=${ms.toFixed(1)}ms ok=${res.ok} ` +
    `findings=${res.findings ? res.findings.length : 'n/a'} ` +
    `incomplete=${res.coverage && res.coverage.summary ? res.coverage.summary.incomplete : 'n/a'}`
  );
}
