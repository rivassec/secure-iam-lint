// Built-in abuse-case sample policies (IAM-505).
//
// A small, curated set of FICTIONAL IAM policies the user can load from the UI
// with one keystroke/click. They exist to demonstrate the analyzer honestly:
//   - at least one OBVIOUS escalation (a compound PassRole path), and
//   - "scary-but-neutralized" samples where a dangerous-looking grant produces
//     NO escalation finding because the context neutralizes it - an explicit
//     Deny, a permissions-boundary shape, or an unsupported/incomplete shape the
//     analyzer fails closed on. This is the negative-corpus intent surfaced in
//     the UI (threat-model T8: never overstate certainty).
//
// Design notes (immutable-contract compliant):
//   - Data only. No network, no DOM, no side effects. app.js reads SAMPLES and
//     builds the loader buttons with safe DOM (createElement + textContent).
//   - Fictional + deterministic: every ARN uses the AWS documentation example
//     account 111122223333, so a loaded sample is reproducible and references no
//     real account.
//   - A UI sample is NOT a substitute for a regression fixture. Each sample here
//     has a matching engine fixture under tools/iam-blast-radius/fixtures/samples/
//     whose policy is asserted byte-identical to the one below, so the loadable
//     sample and the tested behavior can never silently drift apart.

// Recursively freeze a plain-data value so a sample policy is immutable (the
// engine is deterministic; a frozen sample cannot be mutated between loads).
function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
    Object.freeze(value);
  }
  return value;
}

export const SAMPLES = deepFreeze([
  {
    id: 'escalation-passrole-lambda',
    label: 'PassRole then Lambda (escalation)',
    kind: 'escalation',
    description:
      'iam:PassRole scoped to Lambda plus lambda:CreateFunction - a compound ' +
      'privilege-escalation path the analyzer flags as critical.',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'AllowLambdaDeployment',
          Effect: 'Allow',
          Action: ['iam:PassRole'],
          Resource: ['arn:aws:iam::111122223333:role/app-*'],
          Condition: { StringEquals: { 'iam:PassedToService': 'lambda.amazonaws.com' } },
        },
        {
          Sid: 'CreateFn',
          Effect: 'Allow',
          Action: ['lambda:CreateFunction', 'lambda:UpdateFunctionCode'],
          Resource: '*',
        },
      ],
    },
  },
  {
    id: 'neutralized-explicit-deny',
    label: 'Broad read, denied (neutralized)',
    kind: 'neutralized',
    description:
      'A broad s3:GetObject on * that a conflicting explicit Deny fully ' +
      'suppresses. Explicit Deny wins, so there is no object-read capability to ' +
      'report - dangerous-looking, but neutralized.',
    policy: {
      Version: '2012-10-17',
      Statement: [
        { Sid: 'AllowRead', Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
        { Sid: 'DenyRead', Effect: 'Deny', Action: 's3:GetObject', Resource: '*' },
      ],
    },
  },
  {
    id: 'neutralized-permissions-boundary',
    label: 'Broad services, no PassRole (neutralized)',
    kind: 'neutralized',
    description:
      'Permissions-boundary-shaped: broad service wildcards but deliberately no ' +
      'iam:PassRole and no IAM administration. Broad scope, but no ' +
      'privilege-escalation path - the wildcards are high, not critical.',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'WorkloadServices',
          Effect: 'Allow',
          Action: ['s3:*', 'ec2:*', 'lambda:*', 'logs:*', 'sqs:*', 'dynamodb:*'],
          Resource: '*',
        },
      ],
    },
  },
  {
    id: 'neutralized-unsupported-notprincipal',
    label: 'NotPrincipal shape, unsupported (neutralized)',
    kind: 'neutralized',
    description:
      'A dangerous-looking resource policy using NotPrincipal. The analyzer ' +
      'models identity-policy semantics only, so it fails closed and reports a ' +
      'blocking coverage state. Unsupported does not mean safe - it means no ' +
      'conclusion.',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenyExceptTrustedOrg',
          Effect: 'Deny',
          NotPrincipal: { AWS: 'arn:aws:iam::111122223333:root' },
          Action: 's3:*',
          Resource: 'arn:aws:s3:::locked-bucket/*',
        },
      ],
    },
  },
]);

export default SAMPLES;
