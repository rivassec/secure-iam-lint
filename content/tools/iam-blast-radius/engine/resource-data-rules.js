// resource-data-rules.js - ECR repository / Secrets Manager secret / DynamoDB table per-service rules (R6-1).
import { accountOfEntry, hasTransportOnlyDeny } from './resource-shared.js';
import { classifyPrincipals } from './trust.js';
import { makeResourceFinding, summarizeEntries } from './resource-finding.js';
import { principalScopingAnalysis, vacuousSourceGuards } from './resource-conditions.js';
import { globMatch } from './glob.js';
import { DOC_CROSS_ACCOUNT, DOC_PRINCIPAL, RESOURCE_SERVICE_LABELS, RESOURCE_SERVICES } from './resource-catalogs.js';

// Action classes per service (lowercased names). Names from the AWS Service Authorization
// Reference (ecr: catalog-aws-ref.js snapshot; secretsmanager/dynamodb: AWS docs).
// read = data read, write = data/config change, destructive = deletes data or the resource,
// policy = rewrites the resource policy, meta = metadata only.
const C = (o) => Object.freeze(new Map(Object.entries(o).flatMap(([cls, names]) => names.map((n) => [n.toLowerCase(), cls]))));
export const DATA_ACTION_CLASSES = Object.freeze({
  ecr: C({
    read: ['BatchGetImage', 'GetDownloadUrlForLayer', 'BatchCheckLayerAvailability'],
    meta: ['DescribeImages', 'DescribeRepositories', 'ListImages', 'DescribeImageScanFindings',
      'DescribeImageReplicationStatus', 'DescribeImageSigningStatus', 'GetRepositoryPolicy',
      'GetLifecyclePolicy', 'GetLifecyclePolicyPreview', 'ListTagsForResource',
      'BatchGetRepositoryScanningConfiguration', 'GetImageCopyStatus',
      // Account-level; ignored in a repository policy, so harmless there.
      'GetAuthorizationToken'],
    write: ['PutImage', 'InitiateLayerUpload', 'UploadLayerPart', 'CompleteLayerUpload', 'ReplicateImage',
      'BatchImportUpstreamImage', 'PutImageTagMutability', 'PutImageScanningConfiguration', 'PutLifecyclePolicy',
      'StartImageScan', 'StartLifecyclePolicyPreview', 'UpdateImageStorageClass', 'TagResource', 'UntagResource'],
    destructive: ['BatchDeleteImage', 'DeleteRepository', 'DeleteLifecyclePolicy'],
    policy: ['SetRepositoryPolicy', 'DeleteRepositoryPolicy'],
  }),
  secretsmanager: C({
    read: ['GetSecretValue', 'BatchGetSecretValue'],
    meta: ['DescribeSecret', 'ListSecretVersionIds', 'GetResourcePolicy', 'ValidateResourcePolicy', 'ListSecrets'],
    write: ['PutSecretValue', 'UpdateSecret', 'UpdateSecretVersionStage', 'RotateSecret', 'CancelRotateSecret',
      'RestoreSecret', 'ReplicateSecretToRegions', 'RemoveRegionsFromReplication', 'StopReplicationToReplica',
      'TagResource', 'UntagResource'],
    destructive: ['DeleteSecret'],
    policy: ['PutResourcePolicy', 'DeleteResourcePolicy'],
  }),
  dynamodb: C({
    read: ['GetItem', 'BatchGetItem', 'Query', 'Scan', 'ConditionCheckItem', 'PartiQLSelect',
      'ExportTableToPointInTime', 'GetRecords', 'GetShardIterator'],
    meta: ['DescribeTable', 'DescribeTimeToLive', 'DescribeContinuousBackups', 'DescribeContributorInsights',
      'DescribeKinesisStreamingDestination', 'DescribeStream', 'ListStreams', 'ListTagsOfResource',
      'GetResourcePolicy'],
    write: ['PutItem', 'UpdateItem', 'DeleteItem', 'BatchWriteItem', 'PartiQLInsert', 'PartiQLUpdate',
      'PartiQLDelete', 'UpdateTable', 'UpdateTimeToLive', 'UpdateContinuousBackups', 'CreateBackup',
      'RestoreTableToPointInTime', 'TagResource', 'UntagResource'],
    destructive: ['DeleteTable'],
    policy: ['PutResourcePolicy', 'DeleteResourcePolicy'],
  }),
  // r8: log-group actions (logs: snapshot). Delivery, account and integration actions stay
  // unclassified (fail closed).
  logs: C({
    read: ['GetLogEvents', 'FilterLogEvents', 'GetLogRecord', 'StartQuery', 'GetQueryResults', 'StartLiveTail',
      'Unmask', 'GetLogGroupFields', 'GetLogFields'],
    meta: ['DescribeLogGroups', 'DescribeLogStreams', 'DescribeMetricFilters', 'DescribeSubscriptionFilters',
      'DescribeResourcePolicies', 'DescribeQueries', 'DescribeFieldIndexes', 'ListTagsForResource',
      'ListTagsLogGroup', 'GetDataProtectionPolicy', 'StopQuery', 'StopLiveTail'],
    write: ['CreateLogStream', 'PutLogEvents', 'CreateLogGroup', 'PutRetentionPolicy', 'DeleteRetentionPolicy',
      'PutMetricFilter', 'PutSubscriptionFilter', 'CreateExportTask', 'AssociateKmsKey', 'DisassociateKmsKey',
      'PutDataProtectionPolicy', 'PutLogGroupDeletionProtection', 'PutIndexPolicy', 'PutTransformer',
      'TagResource', 'UntagResource', 'TagLogGroup', 'UntagLogGroup'],
    destructive: ['DeleteLogGroup', 'DeleteLogStream', 'DeleteSubscriptionFilter', 'DeleteMetricFilter',
      'DeleteDataProtectionPolicy', 'DeleteIndexPolicy', 'DeleteTransformer'],
    policy: ['PutResourcePolicy', 'DeleteResourcePolicy'],
  }),
});

// Service token -> action namespace.
export const DATA_SERVICE_NS = Object.freeze({
  [RESOURCE_SERVICES.ECR_REPOSITORY]: 'ecr',
  [RESOURCE_SERVICES.SECRET]: 'secretsmanager',
  [RESOURCE_SERVICES.DYNAMODB_TABLE]: 'dynamodb',
  [RESOURCE_SERVICES.LOGS]: 'logs',
});

const ALL_CLASSES = Object.freeze(['read', 'write', 'destructive', 'policy', 'meta']);

// Classes an action token reaches in namespace ns: [] = not this service, null = an
// unclassified concrete action (fail closed). A wildcard reaches every class (worst case).
export function actionClasses(action, ns) {
  const a = String(action).trim().toLowerCase();
  if (a === '*') return ALL_CLASSES;
  const i = a.indexOf(':');
  if (i < 0) return null;
  const svc = a.slice(0, i);
  const name = a.slice(i + 1);
  if (!globMatch(svc, ns)) return [];
  if (/[*?]/.test(svc) || /[*?]/.test(name)) return ALL_CLASSES;
  const cls = DATA_ACTION_CLASSES[ns].get(name);
  return cls ? [cls] : null;
}

const VECTOR = Object.freeze({
  ecr: { read: 'pull every image in the repository (and any secrets baked into it)',
    write: 'PUSH or overwrite images (a supply-chain injection point for whatever deploys from it)',
    destructive: 'DELETE images or the repository' },
  secretsmanager: { read: 'READ the secret value', write: 'overwrite or rotate the secret value',
    destructive: 'DELETE the secret' },
  dynamodb: { read: 'READ or export every item in the table', write: 'write, overwrite or delete items',
    destructive: 'DELETE the table' },
  logs: { read: 'READ the log events (and any secrets or personal data logged in them)',
    write: 'write forged log events, or copy the logs out (subscription filter, export task)',
    destructive: 'DELETE log groups, streams or their filters' },
});

// ECR / Secrets Manager / DynamoDB per-service rules. Pure; additive to the generic findings.
export function dataPerServiceRules(model, ctx) {
  const out = [];
  const service = ctx && typeof ctx.service === 'string' ? ctx.service : null;
  const ns = DATA_SERVICE_NS[service];
  if (!ns) return out;
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  const attachedArn = ctx.arn || null;
  const serviceLabel = RESOURCE_SERVICE_LABELS[service] || 'attached resource';
  const resourceAccount = ctx.ownerAccount != null && /^\d{12}$/.test(String(ctx.ownerAccount))
    ? String(ctx.ownerAccount) : null;
  const transportOnlyDeny = hasTransportOnlyDeny(model);
  const externalTypes = new Set(['aws-account', 'aws-root', 'aws-principal-arn']);

  for (const stmt of statements) {
    if (!stmt || stmt.effect !== 'Allow' || stmt.notPrincipal != null) continue;
    const c = classifyPrincipals(stmt.principal);
    const actions = Array.isArray(stmt.actions) ? stmt.actions : [];
    const reached = new Set();
    const policyVia = [];
    for (const a of actions) {
      const cls = actionClasses(a, ns) || [];
      for (const k of cls) reached.add(k);
      if (cls.includes('policy')) policyVia.push(a);
    }
    const anonEntries = c.entries.filter((e) => e.type === 'anonymous');
    const externalEntries = c.entries.filter((e) => {
      if (!externalTypes.has(e.type)) return false;
      const acct = accountOfEntry(e);
      return !(resourceAccount !== null && acct !== null && acct === resourceAccount);
    });

    // (a) Public data-plane exposure: a genuinely public "*" naming a data action.
    if (anonEntries.length > 0) {
      const { scopingKeys, expansionKeys } = principalScopingAnalysis(stmt.condition, service, vacuousSourceGuards(stmt));
      const scoped = expansionKeys.length === 0 && scopingKeys.length > 0;
      const vectors = ['read', 'write', 'destructive'].filter((k) => reached.has(k)).map((k) => VECTOR[ns][k]);
      if (!scoped && vectors.length > 0) {
        out.push(makeResourceFinding(stmt, anonEntries, {
          id: 'RESOURCE-DATA-EXPOSURE',
          severity: 'high',
          title: `Public grant on this ${serviceLabel} exposes its data`,
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why: `This ${serviceLabel} grants Principal "*" ${actions.join(', ')}, so anyone can ` +
            `${vectors.join('; ')}. This names the vector in addition to the generic public-access ` +
            'finding; it reports the direct resource-policy grant, not proven effective access.',
          remediation: 'Remove Principal "*" and name the specific accounts, roles or source-bound ' +
            'services that need access, or scope it with aws:PrincipalOrgID / aws:PrincipalArn.',
          docRef: DOC_PRINCIPAL,
          service,
          attachedArn,
          transportOnlyDeny,
          principalScopedBy: [],
        }));
      }
    }

    // (b) Resource-policy takeover: the grantee can rewrite this resource's policy.
    if (policyVia.length > 0) {
      const via = policyVia.join(', ');
      const why = (who) => `This ${serviceLabel} grants ${who} ${via}, which lets the grantee REWRITE ` +
        `the ${serviceLabel}'s own resource policy and grant itself (or anyone) any further access. ` +
        'This reports the direct resource-policy grant only; it does NOT prove the takeover is effective.';
      if (anonEntries.length > 0) {
        out.push(makeResourceFinding(stmt, anonEntries, {
          id: 'RESOURCE-POLICY-TAKEOVER',
          severity: 'critical',
          title: `Public grant of a ${serviceLabel} policy-control action (resource-policy takeover)`,
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why: why('Principal "*"'),
          remediation: 'Never grant resource-policy actions (or a wildcard that includes them) to ' +
            'Principal "*". Keep policy management with an administrative role in the owning account.',
          docRef: DOC_PRINCIPAL,
          service,
          attachedArn,
          transportOnlyDeny,
        }));
      }
      if (externalEntries.length > 0) {
        out.push(makeResourceFinding(stmt, externalEntries, {
          id: 'RESOURCE-POLICY-TAKEOVER',
          severity: 'high',
          title: `Cross-account grant of a ${serviceLabel} policy-control action (resource-policy takeover)`,
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why: why(`a principal outside (or not confirmed inside) the owning account (${summarizeEntries(externalEntries)})`),
          remediation: 'Do not grant resource-policy actions to an external principal; keep policy ' +
            'management inside the owning account.',
          docRef: DOC_CROSS_ACCOUNT,
          service,
          attachedArn,
          transportOnlyDeny,
        }));
      }
    }
  }
  return out;
}
