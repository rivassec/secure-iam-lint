import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
function policy(statements) { return JSON.stringify({ Version: '2012-10-17', Statement: statements }); }
const textA = policy([
  { Effect: 'Allow', Action: 's3:GetObject', Resource: ['arn:aws:s3:::bucket-a/*', 'arn:aws:s3:::bucket-b/*'] },
]);
const rA = analyze(textA, { subjectAccount: '123456789012' });
console.log(JSON.stringify(rA.findings, null, 2));
