import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { findingIdentity } from '../../../cli/sarif.mjs';
function policy(statements) { return JSON.stringify({ Version: '2012-10-17', Statement: statements }); }

const textA = policy([
  { Effect: 'Allow', Action: 's3:GetObject', Resource: ['arn:aws:s3:::bucket-a/*', 'arn:aws:s3:::bucket-b/*'] },
]);
// Single resource token containing a RAW NEWLINE byte reproducing A's two-item
// joined form (JSON strings can encode \n directly; S3 keys permit it).
const textB = policy([
  { Effect: 'Allow', Action: 's3:GetObject', Resource: ['arn:aws:s3:::bucket-a/*\narn:aws:s3:::bucket-b/*'] },
]);

const rA = analyze(textA, { subjectAccount: '123456789012' });
const rB = analyze(textB, { subjectAccount: '123456789012' });
const fA = rA.findings.find((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
const fB = rB.findings.find((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
const idA = findingIdentity(fA, rA.family);
const idB = findingIdentity(fB, rB.family);
console.log('newline-variant collide:', idA === idB);
