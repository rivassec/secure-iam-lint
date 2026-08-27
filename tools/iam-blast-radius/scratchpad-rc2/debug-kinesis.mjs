import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
function policy(statements) { return JSON.stringify({ Version: '2012-10-17', Statement: statements }); }
const text = policy([{ Effect: 'Allow', Action: 'kinesis:GetRecords', Resource: 'arn:aws:kinesis:*:*:stream/*' }]);
const r = analyze(text, { subjectAccount: '123456789012' });
console.log(JSON.stringify(r, null, 2));
