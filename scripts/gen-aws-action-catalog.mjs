#!/usr/bin/env node
// Regenerate content/tools/iam-blast-radius/engine/catalog-aws-ref.js from the AWS
// Service Authorization Reference (machine-readable JSON published by AWS at
// https://servicereference.us-east-1.amazonaws.com/).
//
// DEV-ONLY: this script talks to the network; the generated module does not. The
// engine never fetches anything at runtime (architecture invariant 1) - it imports
// the committed, generated data. Run it deliberately to refresh the snapshot, review
// the diff, bump ACTION_CATALOG_VERSION/DATE in catalog.js, and commit both files:
//
//   node scripts/gen-aws-action-catalog.mjs
//
// Access level is derived from the reference annotations, most-privileged first
// (an action annotated both IsWrite and IsPermissionManagement, e.g.
// s3:PutObjectAcl, is "Permissions management", matching the curated PutBucketAcl).
// An action with NO resource types can only be granted on Resource "*"; a READ-level
// one is emitted into AWS_REF_REQUIRES_WILDCARD so its mandatory "*" is not treated
// as an avoidable over-scope (see catalog.js REQUIRES_WILDCARD_RESOURCE).

import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const BASE = 'https://servicereference.us-east-1.amazonaws.com/v1';

// Services snapshotted in full. Chosen from real-world policies the curated slice
// (datapipeline / license-manager: region-deny SCP entries)
// failed on: S3 data-plane/bucket config, EC2 (region-deny SCPs exempt concrete
// ec2:Describe* calls), and the global / account-level / billing services a region-deny
// SCP exempts via NotAction (AWS Organizations example SCP). Keep this list explicit -
// adding a service changes which actions read as "known".
// sns/events/logs/config/lambda/cloudformation/iam: Control Tower guardrail SCP actions.
const SERVICES = [
  's3', 'ec2', 'datapipeline', 'license-manager',
  'consolidatedbilling', 'freetier', 'invoicing', 'payments', 'purchase-orders',
  'savingsplans', 'sustainability', 'tag', 'tax',
  'account', 'acm', 'aws-marketplace', 'aws-marketplace-management', 'aws-portal',
  'billing', 'budgets', 'ce', 'cloudfront', 'cur', 'directconnect', 'fms',
  'globalaccelerator', 'health', 'importexport', 'networkmanager', 'organizations',
  'pricing', 'route53', 'route53domains', 'route53-recovery-cluster',
  'route53-recovery-control-config', 'route53-recovery-readiness', 'shield', 'sso',
  'support', 'trustedadvisor', 'waf', 'waf-regional', 'wafv2', 'wellarchitected',
  'sns', 'events', 'logs', 'config', 'lambda', 'cloudformation', 'iam',
  'ecr', 'codeartifact', 'scheduler', 'eks',
  'cognito-identity',
  // v1.3.0 r8: ECR Public (CI image pulls/pushes; trial snapshot gap).
  'ecr-public',
  // r8 E-1: AWS Load Balancer Controller (reads known; writes withheld until modeled).
  'elasticloadbalancing',
];

function accessLevel(action) {
  const p = (action.Annotations && action.Annotations.Properties) || {};
  if (p.IsPermissionManagement) return 'PERMISSIONS';
  if (p.IsTaggingOnly) return 'TAGGING';
  if (p.IsWrite) return 'WRITE';
  if (p.IsList) return 'LIST';
  return 'READ';
}

// Every IAM service prefix AWS publishes (the reference index), with no actions. Used
// ONLY to recognize a whole-service `svc:*` carve-out in a Deny statement's NotAction
// (catalog.js unrecognizedActions): its meaning ("every action of this real service")
// does not depend on the action list. Nothing else treats these as known.
const indexRes = await fetch(`https://servicereference.us-east-1.amazonaws.com/`);
if (!indexRes.ok) throw new Error(`index: HTTP ${indexRes.status}`);
const prefixes = (await indexRes.json()).map((e) => String(e.service).toLowerCase());
if (prefixes.length < 300) throw new Error(`index: only ${prefixes.length} services`);
for (const p of prefixes) if (!/^[a-z0-9-]+$/.test(p)) throw new Error(`index: odd prefix ${p}`);

const data = {};
const requiresWildcard = [];
for (const svc of SERVICES) {
  const res = await fetch(`${BASE}/${svc}/${svc}.json`);
  if (!res.ok) throw new Error(`${svc}: HTTP ${res.status}`);
  const doc = await res.json();
  if (!Array.isArray(doc.Actions) || doc.Actions.length === 0) {
    throw new Error(`${svc}: no Actions in reference document`);
  }
  data[svc] = {};
  for (const a of [...doc.Actions].sort((x, y) => x.Name.localeCompare(y.Name))) {
    if (!/^[A-Za-z0-9]+$/.test(a.Name)) throw new Error(`${svc}: odd action name ${a.Name}`);
    const level = accessLevel(a);
    data[svc][a.Name] = level;
    const hasResources = Array.isArray(a.Resources) && a.Resources.length > 0;
    if (level === 'READ' && !hasResources) requiresWildcard.push(`${svc}:${a.Name}`.toLowerCase());
  }
}

// Canaries: a reference schema change (renamed annotation fields, a dropped property)
// would otherwise silently classify most actions as READ. Fail the generation instead.
const CANARIES = {
  's3:GetObject': 'READ', 's3:PutObject': 'WRITE', 's3:ListBucket': 'LIST',
  's3:PutBucketPolicy': 'PERMISSIONS', 's3:PutObjectTagging': 'TAGGING', 'ec2:DescribeInstances': 'LIST',
};
for (const [action, want] of Object.entries(CANARIES)) {
  const [svc, name] = action.split(':');
  const got = data[svc] && data[svc][name];
  if (got !== want) throw new Error(`canary ${action}: expected ${want}, got ${got}`);
}

// Quote a property name unless it is a plain identifier (an action name can start with a digit).
const prop = (name) => (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(name) ? name : JSON.stringify(name));

const today = new Date().toISOString().slice(0, 10);
const lines = [
  '// GENERATED by scripts/gen-aws-action-catalog.mjs - do not edit by hand.',
  `// Source: AWS Service Authorization Reference (${BASE}), fetched ${today}.`,
  '//',
  '// Pure committed data (no imports, no runtime network). catalog.js merges it UNDER',
  '// the curated CATALOG_DATA: a curated entry always wins on overlap.',
  '',
  `export const AWS_REF_DATE = '${today}';`,
  '',
  'export const AWS_REF_ACTIONS = Object.freeze({',
];
for (const svc of SERVICES) {
  lines.push(`  '${svc}': Object.freeze({`);
  for (const [name, level] of Object.entries(data[svc])) lines.push(`    ${prop(name)}: '${level}',`);
  lines.push('  }),');
}
lines.push('});', '');
lines.push('// READ-level actions with no resource types (grantable only on Resource "*").');
lines.push('export const AWS_REF_REQUIRES_WILDCARD = Object.freeze(new Set([');
for (const k of requiresWildcard.sort()) lines.push(`  '${k}',`);
lines.push(']));', '');
lines.push('// Every published IAM service prefix (see gen script: Deny NotAction `svc:*` only).');
lines.push('export const AWS_SERVICE_PREFIXES = Object.freeze(new Set([');
for (const p of [...new Set(prefixes)].sort()) lines.push(`  '${p}',`);
lines.push(']));', '');

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'content', 'tools', 'iam-blast-radius', 'engine', 'catalog-aws-ref.js');
writeFileSync(out, lines.join('\n'));
const total = Object.values(data).reduce((n, s) => n + Object.keys(s).length, 0);
console.log(`wrote ${out}: ${SERVICES.length} services, ${total} actions, ${requiresWildcard.length} wildcard-only reads, ${prefixes.length} prefixes`);
