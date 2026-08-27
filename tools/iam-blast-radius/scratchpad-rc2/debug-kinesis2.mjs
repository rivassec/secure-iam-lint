import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
function policy(statements) { return JSON.stringify({ Version: '2012-10-17', Statement: statements }); }
const SUBJECT='123456789012', OTHER='999999999999';
const r1 = analyze(policy([{ Effect:'Allow', Action:'kinesis:GetRecords', Resource:`arn:aws:kinesis:us-east-1:${OTHER}:stream/*` }]), {subjectAccount:SUBJECT});
console.log('concrete-other-account:', JSON.stringify(r1.findings.map(f=>f.id)), r1.coverage.summary.unrecognizedActions);
const r2 = analyze(policy([{ Effect:'Allow', Action:'kinesis:GetRecords', Resource:'arn:aws:kinesis:us-east-1::stream/*' }]), {subjectAccount:SUBJECT});
console.log('empty-account:', JSON.stringify(r2.findings.map(f=>f.id)), r2.coverage.summary.unrecognizedActions, 'incomplete=', r2.coverage.summary.incomplete);
