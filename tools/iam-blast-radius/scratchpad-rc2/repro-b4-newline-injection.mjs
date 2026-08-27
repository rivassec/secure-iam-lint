// Stronger variant of residual (b): a raw newline in an attacker-controlled
// resource string can inject a FORGED extra "key=value" line into the
// multi-line identity string (parts.join('\n') at sarif.mjs:249), letting a
// resource-scoped finding's identity mimic fields (principals/condition/
// viability/escService/escTechnique) it does not actually have.
import { findingIdentity } from '../../../cli/sarif.mjs';

const findingReal = {
  id: 'DATA-EXFIL',
  statementIndex: 0,
  actions: ['s3:getobject'],
  resources: ['arn:aws:s3:::victim-bucket/*'],
  principal: { AWS: ['arn:aws:iam::999999999999:root'] },
};

// Forged finding: same id/stmtIndex/actions, an INNOCUOUS-looking single
// resource string that embeds a literal newline + a forged "principals=..."
// line reproducing the REAL finding's principal encoding, plus the blank
// trailer lines so everything after realigns.
const forgedResource =
  'arn:aws:s3:::decoy-bucket/*\nprincipals=AWS=arn:aws:iam::999999999999:root\ncondition=\nviability=\nescService=\nescTechnique=';

const findingForged = {
  id: 'DATA-EXFIL',
  statementIndex: 0,
  actions: ['s3:getobject'],
  resources: [forgedResource],
  // no principal at all on the forged finding
};

const idReal = findingIdentity(findingReal, 'identity');
const idForged = findingIdentity(findingForged, 'identity');
console.log('--- real ---');
console.log(idReal);
console.log('--- forged ---');
console.log(idForged);
console.log('COLLIDE:', idReal === idForged);
