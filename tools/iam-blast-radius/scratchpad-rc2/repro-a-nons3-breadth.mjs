// Residual (a): classifyContainerReads' account-UNRESOLVABLE whole-container
// surfacing (rules.js ~1159-1167) is gated to arn.service === 's3'. A
// dynamodb/kinesis/rds-data whole-container read whose ARN account is a
// wildcard (so concreteResourceAccount() returns null, same as an S3 bucket
// ARN) should also be UNDETERMINED-surfaced but instead reads CLEAN.
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';

const SUBJECT = '123456789012';

function policy(statements) {
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}
function isClean(r) {
  return !!(r && r.ok === true
    && Array.isArray(r.findings) && r.findings.length === 0
    && !(r.coverage && r.coverage.summary && r.coverage.summary.incomplete));
}

const cases = [
  { name: 'dynamodb:Scan wildcard-account table', action: 'dynamodb:Scan', resource: 'arn:aws:dynamodb:*:*:table/*' },
  { name: 'dynamodb:Query wildcard-account table', action: 'dynamodb:Query', resource: 'arn:aws:dynamodb:*:*:table/orders' },
  { name: 'kinesis:GetRecords wildcard-account stream', action: 'kinesis:GetRecords', resource: 'arn:aws:kinesis:*:*:stream/*' },
  { name: 'rds-data:ExecuteStatement wildcard-account cluster', action: 'rds-data:ExecuteStatement', resource: 'arn:aws:rds:*:*:cluster:*' },
];

for (const c of cases) {
  const text = policy([{ Effect: 'Allow', Action: c.action, Resource: c.resource }]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  const ids = r.ok ? r.findings.map((f) => f.id) : ['<parse/blocked fail>'];
  console.log(`[${c.name}] ok=${r.ok} clean=${isClean(r)} findings=${JSON.stringify(ids)}`);
}

// Control: the same shape on S3 (should already surface CROSS-ACCOUNT-DATA-READ-UNDETERMINED).
{
  const text = policy([{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::some-bucket/*' }]);
  const r = analyze(text, { subjectAccount: SUBJECT });
  const ids = r.ok ? r.findings.map((f) => f.id) : ['<parse/blocked fail>'];
  console.log(`[S3 control: bare bucket/* GetObject] ok=${r.ok} clean=${isClean(r)} findings=${JSON.stringify(ids)}`);
}
