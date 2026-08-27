// Isolate residual (a) without any masking finding: a dynamodb whole-container
// Scan/Query on an ARN with an EMPTY account segment (same shape as a canonical
// S3 bucket ARN, which the engine already treats as "account unresolvable, not
// narrowable"). concreteResourceAccount() returns null (empty !== 12-digit),
// hasWildcard('') is false so it is NOT flagged BROAD by the high-order check,
// and the resourceId (table/orders) is concrete + dynamodb is MODELED, so
// classifyResource returns NARROW -> WILDCARD-RESOURCE's resourceIsBroad guard
// never fires. Neutral name + no ${...} variable -> DATA-READ's sensitivity/
// variable gate never fires either. So nothing should mask the gap:
// classifyContainerReads' account-UNRESOLVABLE branch is reached but the
// undetResources collection is gated to arn.service === 's3' (rules.js ~1162),
// so this cross-account-UNDETERMINED whole-container read is dropped.
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const SUBJECT = '123456789012';
function policy(statements) { return JSON.stringify({ Version: '2012-10-17', Statement: statements }); }
function isClean(r) {
  return !!(r && r.ok === true
    && Array.isArray(r.findings) && r.findings.length === 0
    && !(r.coverage && r.coverage.summary && r.coverage.summary.incomplete));
}

const cases = [
  { name: 'dynamodb:Scan empty-account table/orders', action: 'dynamodb:Scan', resource: 'arn:aws:dynamodb:us-east-1::table/orders' },
  { name: 'dynamodb:Query empty-account table/orders', action: 'dynamodb:Query', resource: 'arn:aws:dynamodb:us-east-1::table/orders' },
];

for (const c of cases) {
  const text = policy([{ Effect: 'Allow', Action: c.action, Resource: c.resource }]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  const ids = r.ok ? r.findings.map((f) => f.id) : ['<parse/blocked fail>'];
  const incomplete = !!(r.coverage && r.coverage.summary && r.coverage.summary.incomplete);
  console.log(`[${c.name}]\n  ok=${r.ok} clean=${isClean(r)} incomplete=${incomplete} findings=${JSON.stringify(ids)}`);
}

// S3 control (same empty-account/account-less shape): should surface UNDETERMINED.
{
  const text = policy([{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::orders/*' }]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  const ids = r.ok ? r.findings.map((f) => f.id) : ['<parse/blocked fail>'];
  console.log(`[S3 control] ok=${r.ok} clean=${isClean(r)} findings=${JSON.stringify(ids)}`);
}
