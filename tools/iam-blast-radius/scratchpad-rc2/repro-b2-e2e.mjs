import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { findingIdentity } from '../../../cli/sarif.mjs';

function policy(statements) { return JSON.stringify({ Version: '2012-10-17', Statement: statements }); }

// Real broad DATA-EXFIL grant with two distinct object-key-bearing resources,
// one of which contains a literal '|' byte in the S3 object-key segment (S3 keys
// permit almost any UTF-8 byte; the engine applies no charset restriction).
const textA = policy([
  { Effect: 'Allow', Action: 's3:GetObject', Resource: ['arn:aws:s3:::bucket-a/*', 'arn:aws:s3:::bucket-b/*'] },
]);
const textB = policy([
  { Effect: 'Allow', Action: 's3:GetObject', Resource: ['arn:aws:s3:::bucket-a/*|arn:aws:s3:::bucket-b/*'] },
]);

const rA = analyze(textA, { subjectAccount: '123456789012' });
const rB = analyze(textB, { subjectAccount: '123456789012' });

const fA = rA.findings.find((f) => f.id === 'DATA-EXFIL');
const fB = rB.findings.find((f) => f.id === 'DATA-EXFIL');

console.log('finding A resources:', fA && fA.resources);
console.log('finding B resources:', fB && fB.resources);

const idA = findingIdentity(fA, rA.family);
const idB = findingIdentity(fB, rB.family);
console.log('identity A === identity B:', idA === idB);
if (idA === idB) console.log(idA);
