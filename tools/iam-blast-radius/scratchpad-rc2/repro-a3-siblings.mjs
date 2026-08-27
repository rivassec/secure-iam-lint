import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
const SUBJECT = '123456789012';
function policy(statements) { return JSON.stringify({ Version: '2012-10-17', Statement: statements }); }
function isClean(r) {
  return !!(r && r.ok === true && Array.isArray(r.findings) && r.findings.length === 0
    && !(r.coverage && r.coverage.summary && r.coverage.summary.incomplete));
}
const cases = [
  { name: 'rds-data:ExecuteStatement empty-account cluster', action: 'rds-data:ExecuteStatement', resource: 'arn:aws:rds:us-east-1::cluster:orders' },
  { name: 'kinesis:GetRecords empty-account stream (unregistered action; sanity)', action: 'kinesis:GetRecords', resource: 'arn:aws:kinesis:us-east-1::stream/orders' },
];
for (const c of cases) {
  const text = policy([{ Effect: 'Allow', Action: c.action, Resource: c.resource }]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  const ids = r.ok ? r.findings.map((f) => f.id) : ['<fail>'];
  const incomplete = !!(r.coverage && r.coverage.summary && r.coverage.summary.incomplete);
  console.log(`[${c.name}] ok=${r.ok} clean=${isClean(r)} incomplete=${incomplete} findings=${JSON.stringify(ids)}`);
}
