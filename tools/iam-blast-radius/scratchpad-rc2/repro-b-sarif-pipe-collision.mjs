// Residual (b): findingIdentity()'s POSITIVE actions/resources/principals lists
// (cli/sarif.mjs lines 210-212) use a plain, non-injective list.join('|'), while
// the excludedActions/excludedResources lists (same file, ~245-248) were fixed to
// use the injective joinExcluded() escaper (S2-R2-sarif-identity). A resource (or
// action/principal) token containing a literal '|' character can forge one
// finding's joined list into colliding with a DIFFERENT finding's joined list -
// the exact collision class the excluded-list fix closed, left open on the
// positive side. This lets a fork-PR-controlled ARN auto-suppress a distinct,
// still-live finding via SARIF fingerprint-based dismissal on re-scan.
import { findingIdentity } from '../../../cli/sarif.mjs';

function baseFinding(overrides) {
  return {
    id: 'DATA-EXFIL',
    statementIndex: 0,
    actions: ['s3:GetObject'],
    resources: [],
    ...overrides,
  };
}

// Finding A: TWO distinct, legitimate resources.
const findingA = baseFinding({
  resources: ['arn:aws:s3:::bucket-a', 'arn:aws:s3:::bucket-b'],
});

// Finding B: ONE resource whose value is itself the literal string
// "bucket-a-resource|arn:aws:s3:::bucket-b" (a crafted S3 object-key-bearing ARN
// containing a raw pipe byte - S3 keys permit almost any UTF-8 byte, and the
// engine performs no character restriction on Resource element text).
const findingB = baseFinding({
  resources: ['arn:aws:s3:::bucket-a|arn:aws:s3:::bucket-b'],
});

const idA = findingIdentity(findingA, 'identity');
const idB = findingIdentity(findingB, 'identity');

console.log('identity A:\n' + idA);
console.log('---');
console.log('identity B:\n' + idB);
console.log('---');
console.log('COLLIDE (identity strings equal):', idA === idB);
