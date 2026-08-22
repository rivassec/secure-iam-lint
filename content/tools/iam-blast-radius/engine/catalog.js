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
export const ACTION_CATALOG_VERSION = '2026.08.22';
export const ACTION_CATALOG_DATE = '2026-08-22';

// The curated snapshot: service -> { actionName: accessLevel }. Keys use the
// canonical AWS casing for readability; lookups are case-insensitive (AWS treats
// the service prefix and action name case-insensitively), so a policy that
// writes "iam:passrole" or "S3:GetObject" still resolves. This is intentionally a
// small, representative slice per service (the actions the rules reason about
// plus the most common neighbours), NOT an exhaustive enumeration.
const CATALOG_DATA = Object.freeze({
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
    GetFederationToken: L.READ,
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
    DescribeKey: L.READ,
    ListKeys: L.LIST,
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
    DescribeDBInstances: L.LIST,
  },
});

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

const INDEX = buildIndex(CATALOG_DATA);

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
 * snapshot is meaningless, so they are never reported as "unknown". Only fully
 * concrete tokens are catalog-checkable.
 *
 * @param {string} token raw action string from the policy
 * @returns {boolean}
 */
export function isWildcardAction(token) {
  return String(token).includes('*');
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
   * @returns {{input:string, wildcard:boolean, known:boolean,
   *            knownService:boolean, service:(string|null), name:(string|null),
   *            accessLevel:(string|null)}}
   */
  lookup(token) {
    const input = String(token);
    if (isWildcardAction(input)) {
      return Object.freeze({
        input, wildcard: true, known: false, knownService: false,
        service: null, name: null, accessLevel: null,
      });
    }
    const parts = splitAction(input);
    if (!parts) {
      return Object.freeze({
        input, wildcard: false, known: false, knownService: false,
        service: null, name: null, accessLevel: null,
      });
    }
    const svc = INDEX.get(parts.service);
    if (!svc) {
      return Object.freeze({
        input, wildcard: false, known: false, knownService: false,
        service: parts.service, name: null, accessLevel: null,
      });
    }
    const entry = svc.get(parts.action);
    if (!entry) {
      return Object.freeze({
        input, wildcard: false, known: false, knownService: true,
        service: parts.service, name: null, accessLevel: null,
      });
    }
    return Object.freeze({
      input, wildcard: false, known: true, knownService: true,
      service: entry.service, name: entry.name, accessLevel: entry.accessLevel,
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

/**
 * Collect the sorted, de-duplicated set of CONCRETE actions in a model that the
 * catalog does not recognize ("unknown actions"). Wildcards/patterns are never
 * reported (they are not single actions to exist-check). Scans both Action and
 * NotAction across every statement. Deterministic; never throws.
 *
 * Reported verbatim in the coverage summary (coverage.js unrecognizedActions),
 * which marks coverage incomplete - an action the snapshot cannot vouch for means
 * the analysis could not fully reason about that grant (unsupported != safe).
 *
 * @param {object|null} model normalized model (from buildModel)
 * @param {object} [catalog] a CatalogProvider (defaults to defaultCatalog)
 * @returns {Array<string>} sorted unique unknown concrete action tokens
 */
export function unrecognizedActions(model, catalog) {
  const cat = catalog || defaultCatalog;
  const out = new Set();
  const statements = model && Array.isArray(model.statements) ? model.statements : [];
  for (const stmt of statements) {
    const actions = [];
    if (stmt && Array.isArray(stmt.actions)) actions.push(...stmt.actions);
    if (stmt && Array.isArray(stmt.notActions)) actions.push(...stmt.notActions);
    for (const token of actions) {
      if (isWildcardAction(token)) continue;
      const res = cat.lookup(token);
      if (!res.known) out.add(String(token));
    }
  }
  return [...out].sort();
}

export default defaultCatalog;
