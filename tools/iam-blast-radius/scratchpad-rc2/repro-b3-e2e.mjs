import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { findingIdentity } from '../../../cli/sarif.mjs';

function policy(statements) { return JSON.stringify({ Version: '2012-10-17', Statement: statements }); }

// Finding A: bare bucket-list account-less read on TWO distinct buckets.
const textA = policy([
  { Effect: 'Allow', Action: 's3:GetObject', Resource: ['arn:aws:s3:::bucket-a/*', 'arn:aws:s3:::bucket-b/*'] },
]);
// Finding B: bare bucket-list account-less read on ONE resource token that is
// itself the literal joined string of A's two resources (S3 object keys permit
// a raw '|' byte; no charset restriction is applied anywhere in parse/model).
const textB = policy([
  { Effect: 'Allow', Action: 's3:GetObject', Resource: ['arn:aws:s3:::bucket-a/*|arn:aws:s3:::bucket-b/*'] },
]);

const rA = analyze(textA, { subjectAccount: '123456789012' });
const rB = analyze(textB, { subjectAccount: '123456789012' });

const fA = rA.findings.find((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');
const fB = rB.findings.find((f) => f.id === 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED');

console.log('finding A resources:', fA && fA.resources);
console.log('finding B resources:', fB && fB.resources);

const idA = findingIdentity(fA, rA.family);
const idB = findingIdentity(fB, rB.family);
console.log('identity strings equal (fingerprint collision):', idA === idB);
