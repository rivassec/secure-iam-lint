// IAM Blast Radius - small versioned curated action catalog (IAM-507).
//
// A SMALL, CURATED, DATED SNAPSHOT of AWS action existence + access-level
// annotation - NOT the full AWS service-reference build (~400 services / 18k+
// actions). It covers the services the rules already reason about (iam, sts, s3,
// lambda, ec2, kms, secretsmanager, cloudtrail/guardduty/config, ecs, glue,
// codebuild, sagemaker, datapipeline, cloudformation, ssm, plus the handful of
// data-store services the destructive/exfil fixtures exercise). Its purpose is
// NOT to authorize or evaluate anything - the rules keep doing that. Its only
// job is to answer "is this a real, known action?" so that an action the
// snapshot does not recognize is reported as an "unknown action" in the coverage
// summary (threat-model T8 / IAM-502: a clean parse is not complete coverage;
// unsupported does NOT mean safe).
//
// Design constraints (immutable contract):
//   - NO runtime network (architecture invariant 1 / connect-src 'none'). The
//     snapshot is committed data; nothing is fetched. A later phase may replace
//     this hand-curated map with a generated / sharded catalog WITHOUT touching
//     rules.js or escalation.js - callers depend only on the CatalogProvider
//     interface below (version/date/hasService/hasAction/lookup), never on the
//     data shape.
//   - Deterministic (invariant 8): the version + date are committed constants,
//     never Date.now(); the same model always yields the same unknown-action set.
//   - Pure + dependency-free: no DOM, no eval/Function. Hostile action strings
//     are only ever lowercased and compared, never interpreted as code.
//
// The catalog VERSION is a dated snapshot tag so a downloaded report or a
// screenshot ties back to exactly which action set was consulted. It is distinct
// from the RULE-catalog version (coverage.js RULE_VERSION): the rules can change
// cadence independently of the action snapshot.

// The one canonical IAM wildcard matcher (glob.js is a leaf module - no imports -
// so this introduces no cycle and no 'node:' leak into the browser engine graph).
// Used ONLY to answer "does this wildcard action pattern expand to at least one
// action the snapshot knows?" (S2-airtight-incomplete fix (a)); it never evaluates
// or authorizes anything.
import { globMatch } from './glob.js';
import { UNMODELED_ESCALATION } from './catalog-unmodeled.js';
// Generated full-service snapshot (scripts/gen-aws-action-catalog.mjs) for the S3
// and global/account-level services real-world policies hit. Pure data module.
import { AWS_REF_ACTIONS, AWS_REF_REQUIRES_WILDCARD, AWS_SERVICE_PREFIXES } from './catalog-aws-ref.js';

// AWS access levels (from the service-authorization reference vocabulary). Used
// as annotation only; the rules do not (yet) consume it, but every catalog entry
// carries it so a finding/evidence consumer can later show "Write" vs "Read"
// without a second lookup, and so the snapshot is a genuine catalog, not a bare
// allowlist.
export const ACCESS_LEVELS = Object.freeze({
  LIST: 'List',
  READ: 'Read',
  WRITE: 'Write',
  PERMISSIONS: 'Permissions management',
  TAGGING: 'Tagging',
});

const L = ACCESS_LEVELS;

// Dated snapshot identity. Bump both when the curated set below changes.
export const ACTION_CATALOG_VERSION = '2026.10.21.5';
export const ACTION_CATALOG_DATE = '2026-10-21';

// The curated snapshot: service -> { actionName: accessLevel }. Keys use the
// canonical AWS casing for readability; lookups are case-insensitive (AWS treats
// the service prefix and action name case-insensitively), so a policy that
// writes "iam:passrole" or "S3:GetObject" still resolves. This is intentionally a
// small, representative slice per service (the actions the rules reason about
// plus the most common neighbours), NOT an exhaustive enumeration.
const CATALOG_DATA = Object.freeze({
  // v1.3.0 r5: CI/ECS role actions known in an Allow (levels from the AWS reference).
  logs: {
    CreateLogGroup: L.WRITE,
    CreateLogStream: L.WRITE,
    PutLogEvents: L.WRITE,
    DescribeLogGroups: L.LIST,
    DescribeLogStreams: L.LIST,
    DescribeMetricFilters: L.LIST,
    DescribeSubscriptionFilters: L.LIST,
  },
  // R7: SQS ack/visibility/attributes; message reads and producers stay unknown (fail closed).
  sqs: {
    GetQueueAttributes: L.READ,
    GetQueueUrl: L.READ,
    DeleteMessage: L.WRITE,
    DeleteMessageBatch: L.WRITE,
    ChangeMessageVisibility: L.WRITE,
    ChangeMessageVisibilityBatch: L.WRITE,
    DeleteQueue: L.WRITE,
    PurgeQueue: L.WRITE,
  },
  // Cognito pool roles: the identity credential-exchange flow (trial finding T-1).
  'cognito-identity': {
    GetId: L.WRITE,
  },
  ecr: {
    GetAuthorizationToken: L.READ,
    BatchCheckLayerAvailability: L.READ,
    GetDownloadUrlForLayer: L.READ,
    BatchGetImage: L.READ,
  },
  iam: {
    // Permissions-management surface (self-escalation primitives).
    AttachGroupPolicy: L.PERMISSIONS,
    AttachRolePolicy: L.PERMISSIONS,
    AttachUserPolicy: L.PERMISSIONS,
    DetachRolePolicy: L.PERMISSIONS,
    DetachUserPolicy: L.PERMISSIONS,
    PutGroupPolicy: L.PERMISSIONS,
    PutRolePolicy: L.PERMISSIONS,
    PutUserPolicy: L.PERMISSIONS,
    DeleteRolePolicy: L.PERMISSIONS,
    DeleteUserPolicy: L.PERMISSIONS,
    CreatePolicy: L.PERMISSIONS,
    CreatePolicyVersion: L.PERMISSIONS,
    DeletePolicyVersion: L.PERMISSIONS,
    SetDefaultPolicyVersion: L.PERMISSIONS,
    UpdateAssumeRolePolicy: L.PERMISSIONS,
    PassRole: L.WRITE,
    // Identity/credential write surface.
    CreateUser: L.WRITE,
    CreateRole: L.WRITE,
    DeleteRole: L.WRITE,
    CreateAccessKey: L.WRITE,
    UpdateAccessKey: L.WRITE,
    CreateLoginProfile: L.WRITE,
    UpdateLoginProfile: L.WRITE,
    AddUserToGroup: L.WRITE,
    CreateServiceLinkedRole: L.WRITE,
    // F15: federation-provider and ABAC-tag writes (DIRECT-IAM-ADMIN).
    CreateOpenIDConnectProvider: L.WRITE,
    UpdateOpenIDConnectProviderThumbprint: L.WRITE,
    AddClientIDToOpenIDConnectProvider: L.WRITE,
    CreateSAMLProvider: L.WRITE,
    UpdateSAMLProvider: L.WRITE,
    TagRole: L.TAGGING,
    TagUser: L.TAGGING,
    // T2-3: needs iam:PassRole; with it, an instance-profile role swap (PASSROLE-EC2).
    AddRoleToInstanceProfile: L.WRITE,
    // Read/List surface (common enumeration).
    GetRole: L.READ,
    GetRolePolicy: L.READ,
    GetPolicy: L.READ,
    GetPolicyVersion: L.READ,
    GetLoginProfile: L.READ,
    GetUser: L.READ,
    ListRoles: L.LIST,
    ListUsers: L.LIST,
    ListPolicies: L.LIST,
    ListPolicyVersions: L.LIST,
    ListAccessKeys: L.LIST,
    ListAttachedRolePolicies: L.LIST,
    ListRolePolicies: L.LIST,
  },
  sts: {
    AssumeRole: L.WRITE,
    AssumeRoleWithSAML: L.WRITE,
    AssumeRoleWithWebIdentity: L.WRITE,
    GetCallerIdentity: L.READ,
    GetSessionToken: L.READ,
    GetFederationToken: L.WRITE, // mints federated session credentials (AWS: Write)
  },
  s3: {
    GetObject: L.READ,
    GetObjectVersion: L.READ,
    GetObjectAcl: L.READ,
    GetBucketPolicy: L.READ,
    PutObject: L.WRITE,
    DeleteObject: L.WRITE,
    DeleteObjectVersion: L.WRITE,
    CreateBucket: L.WRITE,
    DeleteBucket: L.WRITE,
    PutBucketPolicy: L.PERMISSIONS,
    PutBucketAcl: L.PERMISSIONS,
    ListBucket: L.LIST,
    ListAllMyBuckets: L.LIST,
  },
  lambda: {
    CreateFunction: L.WRITE,
    UpdateFunctionCode: L.WRITE,
    UpdateFunctionConfiguration: L.WRITE,
    DeleteFunction: L.WRITE,
    InvokeFunction: L.WRITE,
    AddPermission: L.PERMISSIONS,
    GetFunction: L.READ,
    ListFunctions: L.LIST,
  },
  ec2: {
    RunInstances: L.WRITE,
    TerminateInstances: L.WRITE,
    StartInstances: L.WRITE,
    StopInstances: L.WRITE,
    CreateTags: L.TAGGING,
    DeleteTags: L.TAGGING,
    DeleteVolume: L.WRITE,
    CreateVolume: L.WRITE,
    AuthorizeSecurityGroupIngress: L.WRITE,
    DescribeInstances: L.LIST,
    DescribeRegions: L.LIST,
    DescribeSecurityGroups: L.LIST,
    DescribeTags: L.READ,
    DescribeVolumes: L.LIST,
  },
  kms: {
    // Cryptographic operations are "Write" in the AWS authorization reference.
    Decrypt: L.WRITE,
    Encrypt: L.WRITE,
    GenerateDataKey: L.WRITE,
    ReEncryptFrom: L.WRITE,
    ReEncryptTo: L.WRITE,
    CreateGrant: L.PERMISSIONS,
    PutKeyPolicy: L.PERMISSIONS,
    ScheduleKeyDeletion: L.WRITE, // F15: DESTRUCTIVE-ACTION
    DescribeKey: L.READ,
    ListKeys: L.LIST,
    ListGrants: L.LIST, // r5: read-only; RevokeGrant stays unknown (no detector)
  },
  kinesis: {
    // G9: kinesis:Put* includes PutResourcePolicy (cross-account stream grant).
    PutRecord: L.WRITE,
    PutRecords: L.WRITE,
    PutResourcePolicy: L.PERMISSIONS,
  },
  secretsmanager: {
    GetSecretValue: L.READ,
    DescribeSecret: L.READ,
    PutSecretValue: L.WRITE,
    CreateSecret: L.WRITE,
    DeleteSecret: L.WRITE,
    ListSecrets: L.LIST,
  },
  ssm: {
    GetParameter: L.READ,
    GetParameters: L.READ,
    GetParametersByPath: L.READ,
    PutParameter: L.WRITE,
    DescribeParameters: L.LIST,
  },
  cloudtrail: {
    StopLogging: L.WRITE,
    StartLogging: L.WRITE,
    DeleteTrail: L.WRITE,
    UpdateTrail: L.WRITE,
    CreateTrail: L.WRITE,
    PutEventSelectors: L.WRITE,
    LookupEvents: L.READ,
    DescribeTrails: L.READ,
  },
  guardduty: {
    DeleteDetector: L.WRITE,
    UpdateDetector: L.WRITE,
    CreateDetector: L.WRITE,
    DeletePublishingDestination: L.WRITE,
    StopMonitoringMembers: L.WRITE,
    ListDetectors: L.LIST,
  },
  config: {
    StopConfigurationRecorder: L.WRITE,
    StartConfigurationRecorder: L.WRITE,
    DeleteConfigurationRecorder: L.WRITE,
    DeleteDeliveryChannel: L.WRITE,
    PutConfigurationRecorder: L.WRITE,
    DescribeConfigurationRecorders: L.LIST,
  },
  ecs: {
    RegisterTaskDefinition: L.WRITE,
    RunTask: L.WRITE,
    StartTask: L.WRITE,
    CreateService: L.WRITE,
    DescribeTasks: L.READ,
  },
  glue: {
    CreateDevEndpoint: L.WRITE,
    CreateJob: L.WRITE,
    UpdateJob: L.WRITE,
    StartJobRun: L.WRITE,
  },
  codebuild: {
    CreateProject: L.WRITE,
    UpdateProject: L.WRITE,
    StartBuild: L.WRITE,
  },
  datapipeline: {
    CreatePipeline: L.WRITE,
    PutPipelineDefinition: L.WRITE,
    ActivatePipeline: L.WRITE,
  },
  cloudformation: {
    CreateStack: L.WRITE,
    UpdateStack: L.WRITE,
    DeleteStack: L.WRITE,
    DescribeStacks: L.READ,
  },
  sagemaker: {
    CreateNotebookInstance: L.WRITE,
    CreateProcessingJob: L.WRITE,
    CreateTrainingJob: L.WRITE,
  },
  dynamodb: {
    GetItem: L.READ,
    PutItem: L.WRITE,
    DeleteItem: L.WRITE,
    Query: L.READ,
    Scan: L.READ,
    DeleteTable: L.WRITE,
    CreateTable: L.WRITE,
  },
  rds: {
    DeleteDBInstance: L.WRITE,
    CreateDBInstance: L.WRITE,
    // F15: snapshot sharing (RESOURCE-POLICY-WRITE).
    ModifyDBSnapshotAttribute: L.WRITE,
    ModifyDBClusterSnapshotAttribute: L.WRITE,
    DescribeDBInstances: L.LIST,
    DescribeDBClusters: L.LIST,
  },
  // IAM database authentication: connect mints a DB auth token (G4).
  'rds-db': {
    connect: L.WRITE,
  },
  // EKS Pod Identity credential vend (G5).
  'eks-auth': {
    AssumeRoleForPodIdentity: L.WRITE,
  },
});

// READ-level actions that AWS grants ONLY on Resource "*": they have NO
// resource-level permission support (no ARN resource types in the service
// authorization reference), so a correct least-privilege policy MUST write
// Resource "*" for them. Their mandatory wildcard is service-mandated, not an
// avoidable over-scope, so it must NEVER be treated as a decidably-scopable read
// that flips coverage incomplete (that would be a false positive - see the
// aws-required-wildcard-resource-not-penalized + read-only-wildcard-resource
// negative fixtures). This is DISTINCT from the genuinely resource-scopable
// reads (iam:GetRole, s3:GetObject, dynamodb:GetItem, kms:DescribeKey,
// secretsmanager:DescribeSecret) whose Resource "*" IS an over-broad,
// account-wide scope the rule catalog is blind to and which MUST flip incomplete.
// Keys are lowercased "service:action". Conservative/fail-closed by construction:
// only actions AWS is known to require "*" for are listed; every other READ stays
// treated as scopable (so an omission fails CLOSED to incomplete, never open).
const REQUIRES_WILDCARD_RESOURCE = Object.freeze(new Set([
  'sts:getcalleridentity',
  'sts:getsessiontoken',
  'ec2:describetags',
  'cloudtrail:lookupevents',
  'cloudtrail:describetrails',
  'ecr:getauthorizationtoken',
]));

// Case-insensitive index: lowercased service -> Map(lowercased action -> {name,
// service, accessLevel}). Built once from CATALOG_DATA at module load and frozen
// in spirit (never mutated). Keeping the canonical-cased name lets lookup() echo
// the real action name even when the policy used odd casing.
function buildIndex(data) {
  const index = new Map();
  for (const service of Object.keys(data)) {
    const svcLower = service.toLowerCase();
    const actions = new Map();
    const set = data[service];
    for (const action of Object.keys(set)) {
      actions.set(action.toLowerCase(), {
        service: svcLower,
        name: action,
        accessLevel: set[action],
      });
    }
    index.set(svcLower, actions);
  }
  return index;
}

// Reference actions that EXIST but that no detector models, so "known" would turn an
// exit 3 into a clean exit 0 on a real escalation (generated list, see
// scripts/gen-unmodeled-escalation.mjs). Keep an action here until a detector covers it.
const UNMODELED_SET = new Set(UNMODELED_ESCALATION);
// Snapshotted in v1.3.0 for guardrail Denies only: their reference actions stay withheld in an Allow.
export const DENY_ONLY_SERVICES = new Set(['sns', 'events', 'logs', 'config', 'lambda', 'cloudformation',
  'ecr', 'codeartifact', 'scheduler', 'eks']);
// Fail closed in an Allow until a finding models them: ABAC tag writes and account-wide IAM dumps.
const ALLOW_WITHHELD = (full) => /^iam:(?:un)?tag/.test(full) ||
  ['iam:getaccountauthorizationdetails', 'iam:getcredentialreport', 'iam:generatecredentialreport',
    // Mints an OpenID token for any identity in the pool (assume its roles as anyone).
    'cognito-identity:getopenidtokenfordeveloperidentity'].includes(full);

// Merge the generated AWS-reference snapshot UNDER the curated data: an action the
// curated map already names keeps its curated access level (the rules were tuned
// against it); the reference only ADDS actions the curated slice lacks. Returns the
// lowercased "service:action" keys that came from the reference (so their
// wildcard-only bit is taken from the reference and never overrides a curated action)
// and the keys WITHHELD from the index: a reference Permissions-management action on a
// service outside the curated slice, or one in UNMODELED_ESCALATION. Existence is not
// modeling, so a withheld action stays unrecognized in an Allow (fail closed) and is
// accepted only inside a Deny (see unrecognizedActions).
function mergeReference(index, refData) {
  const added = new Set();
  const withheld = new Set();
  const curatedServices = new Set(index.keys());
  for (const service of Object.keys(refData)) {
    const svcLower = service.toLowerCase();
    if (!index.has(svcLower)) index.set(svcLower, new Map());
    const actions = index.get(svcLower);
    const set = refData[service];
    for (const action of Object.keys(set)) {
      const key = action.toLowerCase();
      if (actions.has(key)) continue;
      const accessLevel = ACCESS_LEVELS[set[action]];
      if (!accessLevel) continue; // unknown level token: leave the action unknown (fail closed)
      const full = `${svcLower}:${key}`;
      if (UNMODELED_SET.has(full) || DENY_ONLY_SERVICES.has(svcLower) || ALLOW_WITHHELD(full)
        || (accessLevel === ACCESS_LEVELS.PERMISSIONS && !curatedServices.has(svcLower))) {
        withheld.add(full);
        continue;
      }
      actions.set(key, { service: svcLower, name: action, accessLevel });
      added.add(full);
    }
  }
  return { added, withheld };
}

const INDEX = buildIndex(CATALOG_DATA);
const { added: REFERENCE_KEYS, withheld: WITHHELD } = mergeReference(INDEX, AWS_REF_ACTIONS);
const WITHHELD_BY_SERVICE = new Map();
for (const key of WITHHELD) {
  const colon = key.indexOf(':');
  const svc = key.slice(0, colon);
  if (!WITHHELD_BY_SERVICE.has(svc)) WITHHELD_BY_SERVICE.set(svc, []);
  WITHHELD_BY_SERVICE.get(svc).push(key.slice(colon + 1));
}

function requiresWildcardKey(key) {
  return REQUIRES_WILDCARD_RESOURCE.has(key)
    || (REFERENCE_KEYS.has(key) && AWS_REF_REQUIRES_WILDCARD.has(key));
}

// Split an action token into { service, action } (both lowercased) or null when
// the token is not a well-formed "service:action". A bare "*" is NOT split here
// (callers treat it as a wildcard, not a concrete action).
function splitAction(token) {
  const s = String(token);
  const colon = s.indexOf(':');
  if (colon <= 0 || colon === s.length - 1) return null;
  return {
    service: s.slice(0, colon).toLowerCase(),
    action: s.slice(colon + 1).toLowerCase(),
  };
}

/**
 * Is this action token a wildcard/pattern rather than a single concrete action?
 * The all-actions "*", a service wildcard "s3:*", and any prefixed pattern
 * ("s3:Get*", "iam:*") are patterns - existence-checking them against a curated
 * snapshot is meaningless, so they are never reported as an "unknown ACTION". But
 * see classifyWildcard() below: a wildcard on an unknown/unmodeled SERVICE, or one
 * whose pattern expands to no known action of a known service, is still UNSUPPORTED
 * (unsupported != safe) and is routed to coverage incomplete by unrecognizedActions.
 *
 * @param {string} token raw action string from the policy
 * @returns {boolean}
 */
export function isWildcardAction(token) {
  return String(token).includes('*') || String(token).includes('?');
}

// Does the action-part pattern of a service-scoped wildcard (e.g. "Send*", "*",
// "Get*") match at least one CATALOGUED action of the given (already lowercased,
// known) service? Uses the canonical IAM wildcard semantics (globMatch) against the
// lowercased snapshot action names. Fail-closed: an unknown service never reaches
// here (caller checks knownService first), and a pattern matching nothing returns
// false so the wildcard is treated as unsupported.
function serviceWildcardMatchesKnownAction(svcLower, actionPatternLower) {
  const svc = INDEX.get(svcLower);
  if (!svc) return false;
  for (const knownAction of svc.keys()) {
    if (globMatch(actionPatternLower, knownAction)) return true;
  }
  return false;
}

// The default, shipped CatalogProvider. A later generated/sharded catalog can be
// dropped in by implementing this same interface; nothing outside this module
// depends on CATALOG_DATA's shape.
export const defaultCatalog = Object.freeze({
  version: ACTION_CATALOG_VERSION,
  date: ACTION_CATALOG_DATE,
  /** @returns {boolean} is the service known to the snapshot? */
  hasService(service) {
    return INDEX.has(String(service).toLowerCase());
  },
  /** @returns {boolean} is service:action a known concrete action? */
  hasAction(service, action) {
    const svc = INDEX.get(String(service).toLowerCase());
    return !!svc && svc.has(String(action).toLowerCase());
  },
  /**
   * Resolve one action token. Wildcards resolve to { wildcard:true } (never
   * "unknown"); a concrete token resolves to a known entry (with accessLevel) or
   * knownService:false / known:false. Never throws.
   *
   * @param {string} token raw action string
   * `requiresWildcardResource` is true only for a KNOWN action AWS grants solely
   * on Resource "*" (no resource-level permission support); false otherwise
   * (wildcards/unknowns default false so callers never assume a required wildcard
   * for something the snapshot cannot vouch for).
   *
   * @returns {{input:string, wildcard:boolean, known:boolean,
   *            knownService:boolean, service:(string|null), name:(string|null),
   *            accessLevel:(string|null), requiresWildcardResource:boolean}}
   */
  lookup(token) {
    const input = String(token);
    if (isWildcardAction(input)) {
      return Object.freeze({
        input, wildcard: true, known: false, knownService: false,
        service: null, name: null, accessLevel: null,
        requiresWildcardResource: false,
      });
    }
    const parts = splitAction(input);
    if (!parts) {
      return Object.freeze({
        input, wildcard: false, known: false, knownService: false,
        service: null, name: null, accessLevel: null,
        requiresWildcardResource: false,
      });
    }
    const svc = INDEX.get(parts.service);
    if (!svc) {
      return Object.freeze({
        input, wildcard: false, known: false, knownService: false,
        service: parts.service, name: null, accessLevel: null,
        requiresWildcardResource: false,
      });
    }
    const entry = svc.get(parts.action);
    if (!entry && WITHHELD.has(`${parts.service}:${parts.action}`)) {
      return Object.freeze({
        input, wildcard: false, known: false, knownService: true, withheld: true,
        service: parts.service, name: null, accessLevel: null,
        requiresWildcardResource: false,
      });
    }
    if (!entry) {
      return Object.freeze({
        input, wildcard: false, known: false, knownService: true,
        service: parts.service, name: null, accessLevel: null,
        requiresWildcardResource: false,
      });
    }
    return Object.freeze({
      input, wildcard: false, known: true, knownService: true,
      service: entry.service, name: entry.name, accessLevel: entry.accessLevel,
      requiresWildcardResource: requiresWildcardKey(`${entry.service}:${parts.action}`),
    });
  },
  /**
   * Does this KNOWN action require Resource "*" (no resource-level permission
   * support)? False for wildcards, unknowns, and every resource-scopable action.
   * @param {string} token raw action string
   * @returns {boolean}
   */
  requiresWildcardResource(token) {
    return this.lookup(token).requiresWildcardResource === true;
  },
  /**
   * Classify a WILDCARD action token (one containing '*'/'?') for COVERAGE.
   * A wildcard cannot be existence-checked like a concrete action, but the
   * snapshot can still tell whether it is ANALYZABLE:
   *   - allServices: no service segment (the bare all-actions "*") - the broadest
   *     wildcard, owned by the rule catalog; NOT a concrete-but-unknown service, so
   *     it is never a coverage "unknown" here (supported:true).
   *   - a KNOWN service whose action-part pattern expands to >=1 catalogued action
   *     (s3:Get*, s3:*): analyzable -> supported:true (unchanged from before).
   *   - EVERYTHING ELSE - a wildcard on an unknown/unmodeled service (sqs:Send*,
   *     bedrock:Invoke*), or a known-service pattern that expands to NO catalogued
   *     action (s3:Zzz*): UNSUPPORTED (unsupported != safe). supported:false, so
   *     unrecognizedActions() routes it to coverage.summary.incomplete.
   * Never throws. Callers pass a token isWildcardAction() already accepted.
   *
   * A pattern (other than "svc:*") that expands to a WITHHELD action is not `supported`
   * (an Allow of it is unmodeled); `exemptableInDeny` marks it as harmless inside a Deny.
   *
   * @param {string} token raw wildcard action string
   * @returns {{wildcard:true, allServices:boolean, service:(string|null),
   *            knownService:boolean, matchesKnownAction:boolean,
   *            matchesWithheld:boolean, supported:boolean, exemptableInDeny:boolean}}
   */
  classifyWildcard(token) {
    const parts = splitAction(String(token));
    if (!parts) {
      // No well-formed "service:action" split - the bare "*" (or any no-service
      // form). The all-actions wildcard is the rule catalog's to own, not an
      // unknown SERVICE, so it does not flip coverage incomplete on its own.
      return Object.freeze({
        wildcard: true, allServices: true, service: null,
        knownService: false, matchesKnownAction: false, matchesWithheld: false,
        supported: true, exemptableInDeny: false,
      });
    }
    const knownService = INDEX.has(parts.service);
    const matchesKnownAction = knownService
      && serviceWildcardMatchesKnownAction(parts.service, parts.action);
    const matchesWithheld = (WITHHELD_BY_SERVICE.get(parts.service) || [])
      .some((a) => globMatch(parts.action, a));
    return Object.freeze({
      wildcard: true, allServices: false, service: parts.service,
      knownService, matchesKnownAction, matchesWithheld,
      // Whole-service "svc:*" is owned by WILDCARD-ACTION (never clean), so it stays supported.
      supported: knownService && matchesKnownAction && (!matchesWithheld || parts.action === '*'),
      exemptableInDeny: matchesWithheld,
    });
  },
});

/**
 * Resolve one action token against a catalog (default: the shipped snapshot).
 * Thin wrapper so callers can pass a replacement provider.
 *
 * @param {string} token
 * @param {object} [catalog] a CatalogProvider (defaults to defaultCatalog)
 * @returns {object} the lookup record (see defaultCatalog.lookup)
 */
export function lookupAction(token, catalog) {
  return (catalog || defaultCatalog).lookup(token);
}

// A whole-service `svc:*` carve-out in a DENY statement's NotAction ("deny everything
// except all of <svc>", the region-deny SCP shape) on a REAL AWS service prefix. Its
// meaning does not depend on which of the service's actions the snapshot lists, so it is
// analyzable even for a service the snapshot carries no actions for. Deliberately narrow:
// only the exact `svc:*` form, only NotAction, only Effect "Deny"; a partial pattern
// (svc:Get*), an Allow statement, or an Action-list wildcard still needs catalogued
// actions, and an unpublished prefix (madeupsvc:*) stays unknown.
// Real prefixes missing from the AWS index (discovery-marketplace: Control Tower SCP).
const UNPUBLISHED_PREFIXES = Object.freeze(new Set(['discovery-marketplace']));
function isDenyServiceCarveOut(stmt, token) {
  if (!stmt || stmt.effect !== 'Deny') return false;
  const m = /^([A-Za-z0-9-]+):\*$/.exec(String(token));
  if (!m) return false;
  const prefix = m[1].toLowerCase();
  return AWS_SERVICE_PREFIXES.has(prefix) || UNPUBLISHED_PREFIXES.has(prefix);
}

/**
 * Collect the sorted, de-duplicated set of actions in a model the catalog cannot
 * vouch for ("unknown actions"). Two classes are reported:
 *   - a CONCRETE token the snapshot does not recognize (sqs:SendMessage), and
 *   - a WILDCARD token that is UNSUPPORTED per classifyWildcard: a wildcard on an
 *     unknown/unmodeled service (sqs:Send*, bedrock:Invoke*) or a known-service
 *     pattern that expands to no catalogued action. A wildcard that IS analyzable
 *     (a known-service pattern matching >=1 action, e.g. s3:Get*, or the bare
 *     all-actions "*") is NOT reported - unchanged from before.
 * This is the S2-airtight-incomplete fix (a): a wildcard token is no longer
 * blanket-skipped as "uncheckable"; an unsupported one is unsupported, not safe.
 * Scans both Action and NotAction across every statement. Deterministic; never
 * throws.
 *
 * Reported verbatim in the coverage summary (coverage.js unrecognizedActions),
 * which marks coverage incomplete - an action the snapshot cannot vouch for means
 * the analysis could not fully reason about that grant (unsupported != safe).
 *
 * @param {object|null} model normalized model (from buildModel)
 * @param {object} [catalog] a CatalogProvider (defaults to defaultCatalog)
 * @returns {Array<string>} sorted unique unknown action tokens
 */
export function unrecognizedActions(model, catalog) {
  const cat = catalog || defaultCatalog;
  const out = new Set();
  const statements = model && Array.isArray(model.statements) ? model.statements : [];
  for (const stmt of statements) {
    const actions = [];
    if (stmt && Array.isArray(stmt.actions)) actions.push(...stmt.actions);
    if (stmt && Array.isArray(stmt.notActions)) {
      for (const token of stmt.notActions) {
        // Shipped-snapshot data only: a replacement provider keeps its own semantics.
        if (!(cat === defaultCatalog && isDenyServiceCarveOut(stmt, token))) actions.push(token);
      }
    }
    for (const token of actions) {
      if (isWildcardAction(token)) {
        // A wildcard on an unknown service, or one that expands to no known
        // action, cannot be vouched for by the snapshot: route it to incomplete
        // exactly like an unknown concrete action. A supported known-service
        // wildcard (s3:Get*) and the all-actions "*" are analyzable and skipped.
        // Guarded so a replacement CatalogProvider lacking classifyWildcard still
        // works (it then behaves as the pre-fix blanket-skip for wildcards).
        if (typeof cat.classifyWildcard === 'function') {
          const c = cat.classifyWildcard(token);
          if (!c.supported && !(c.exemptableInDeny === true && stmt.effect === 'Deny')) {
            out.add(String(token));
          }
        }
        continue;
      }
      const res = cat.lookup(token);
      if (!res.known && !(res.withheld === true && stmt.effect === 'Deny')) out.add(String(token));
    }
  }
  return [...out].sort();
}

export default defaultCatalog;
