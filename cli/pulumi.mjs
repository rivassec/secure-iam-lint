// IAM Blast Radius - Pulumi input adapter (v1.3.0, P1-P5 + P7).
//
// Reads the JSON a consumer's CI produced with `pulumi preview --json` or
// `pulumi stack export` and scans every IAM policy property it carries through the
// existing fail-closed scan(). It never runs Pulumi and never calls AWS.
//
// The file is attacker-influenced end to end (a fork PR owns the program), so every
// shape this adapter does not model is an explicit exit-3 state, never a skip:
// unknown preview values, secrets, malformed or duplicate entries, unsupported policy
// types, unresolvable account / partition / resource context. Pure: no Node built-ins.
import { scan, EXIT, ANALYSIS_STATUS, ANALYSIS_STATE, DEFAULT_BUDGET_MS } from './scan.mjs';
import { LIMITS } from '../content/tools/iam-blast-radius/engine/validate.js';
import { applyBaseline } from './baseline.mjs';

// Preview placeholder for a value not known until apply (whole property collapses to it).
export const PULUMI_UNKNOWN = '04da6b54-80e4-46f7-96ec-b56ff0331ba9';
// Secret envelope key in a stack export; "[secret]" is the preview's masked form.
export const PULUMI_ENVELOPE_ID = '4dabf18193072939515e22adb298388d';
const SECRET_TEXT = '[secret]';

export const PULUMI_LIMITS = Object.freeze({
  MAX_BYTES: 32 * 1024 * 1024, // whole preview/export file
  MAX_DEPTH: 128, // outer document nesting
  MAX_RESOURCES: 20000, // steps / resources
  MAX_POLICY_BYTES: LIMITS.MAX_BYTES, // one embedded policy document
  MAX_INLINE: 500, // inline policies on one resource
  MAX_WALK_NODES: 200000, // content-scan budget for the whole file
});

// Ops whose newState is analyzed; ops skipped as leaving the stack. Anything else: exit 3.
const ANALYZE_OPS = new Set(['same', 'create', 'update', 'replace', 'create-replacement', 'import', 'read', 'refresh']);
const SKIP_OPS = new Set(['delete', 'delete-replaced', 'discard', 'discard-replaced']);

const IDENTITY = 'identity';
const TRUST = 'role-trust';
const RESOURCE = 'resource';
const SCP = 'scp-rcp';

const S3_BUCKET_TYPES = ['aws:s3/bucketV2:BucketV2', 'aws:s3/bucket:Bucket', 'aws-native:s3:Bucket'];
const SQS_QUEUE_TYPES = ['aws:sqs/queue:Queue', 'aws-native:sqs:Queue'];
const ROLE_TYPES = new Set(['aws:iam/role:Role', 'aws-native:iam:Role']);

// Type -> policy properties (verified against the pulumi-aws and pulumi-aws-native schemas,
// 2026-10-21). `inline` = an array of { nameKey, docKey } policies; `ctx` = how the attached
// resource of a resource policy is found; `orgType` = organizations policy type field.
const TYPE_MAP = Object.freeze({
  'aws:iam/role:Role': [
    { prop: 'assumeRolePolicy', family: TRUST, required: true },
    { inline: 'inlinePolicies', nameKey: 'name', docKey: 'policy', family: IDENTITY },
  ],
  'aws:iam/policy:Policy': [{ prop: 'policy', family: IDENTITY, required: true }],
  'aws:iam/rolePolicy:RolePolicy': [{ prop: 'policy', family: IDENTITY, required: true }],
  'aws:iam/userPolicy:UserPolicy': [{ prop: 'policy', family: IDENTITY, required: true }],
  'aws:iam/groupPolicy:GroupPolicy': [{ prop: 'policy', family: IDENTITY, required: true }],
  'aws:s3/bucketPolicy:BucketPolicy': [{ prop: 'policy', family: RESOURCE, required: true, ctx: { kind: 's3', field: 'bucket' } }],
  'aws:s3/bucket:Bucket': [{ prop: 'policy', family: RESOURCE, ctx: { kind: 's3-self' } }],
  'aws:organizations/policy:Policy': [{ prop: 'content', family: SCP, required: true, orgType: 'type' }],
  'aws:kms/key:Key': [{ prop: 'policy', family: RESOURCE, ctx: { kind: 'self', type: 'kms-key' } }],
  'aws:sqs/queuePolicy:QueuePolicy': [{ prop: 'policy', family: RESOURCE, required: true, ctx: { kind: 'sqs-url', field: 'queueUrl' } }],
  'aws:sqs/queue:Queue': [{ prop: 'policy', family: RESOURCE, ctx: { kind: 'self', type: 'sqs' } }],
  'aws:sns/topicPolicy:TopicPolicy': [{ prop: 'policy', family: RESOURCE, required: true, ctx: { kind: 'arn', field: 'arn', type: 'sns' } }],
  'aws:sns/topic:Topic': [{ prop: 'policy', family: RESOURCE, ctx: { kind: 'self', type: 'sns' } }],
  'aws:ecr/repositoryPolicy:RepositoryPolicy': [{ prop: 'policy', family: RESOURCE, required: true, ctx: { kind: 'ecr-name', field: 'repository' } }],
  'aws:secretsmanager/secretPolicy:SecretPolicy': [{ prop: 'policy', family: RESOURCE, required: true, ctx: { kind: 'arn', field: 'secretArn', type: 'secretsmanager' } }],
  'aws:secretsmanager/secret:Secret': [{ prop: 'policy', family: RESOURCE, ctx: { kind: 'self', type: 'secretsmanager' } }],
  'aws-native:iam:Role': [
    { prop: 'assumeRolePolicyDocument', family: TRUST, required: true },
    { inline: 'policies', nameKey: 'policyName', docKey: 'policyDocument', family: IDENTITY },
  ],
  'aws-native:iam:User': [{ inline: 'policies', nameKey: 'policyName', docKey: 'policyDocument', family: IDENTITY }],
  'aws-native:iam:Group': [{ inline: 'policies', nameKey: 'policyName', docKey: 'policyDocument', family: IDENTITY }],
  'aws-native:iam:ManagedPolicy': [{ prop: 'policyDocument', family: IDENTITY, required: true }],
  'aws-native:iam:RolePolicy': [{ prop: 'policyDocument', family: IDENTITY }],
  'aws-native:iam:UserPolicy': [{ prop: 'policyDocument', family: IDENTITY }],
  'aws-native:iam:GroupPolicy': [{ prop: 'policyDocument', family: IDENTITY }],
  'aws-native:s3:BucketPolicy': [{ prop: 'policyDocument', family: RESOURCE, required: true, ctx: { kind: 's3', field: 'bucket' } }],
  'aws-native:kms:Key': [{ prop: 'keyPolicy', family: RESOURCE, ctx: { kind: 'self', type: 'kms-key' } }],
  'aws-native:sns:TopicPolicy': [{ prop: 'policyDocument', family: RESOURCE, required: true, ctx: { kind: 'arn-list', field: 'topics', type: 'sns' } }],
  'aws-native:sns:TopicInlinePolicy': [{ prop: 'policyDocument', family: RESOURCE, required: true, ctx: { kind: 'arn', field: 'topicArn', type: 'sns' } }],
  'aws-native:ecr:Repository': [{ prop: 'repositoryPolicyText', family: RESOURCE, ctx: { kind: 'self', type: 'ecr' } }],
  'aws-native:secretsmanager:ResourcePolicy': [{ prop: 'resourcePolicy', family: RESOURCE, required: true, ctx: { kind: 'arn', field: 'secretId', type: 'secretsmanager' } }],
  'aws-native:sqs:QueueInlinePolicy': [{ prop: 'policyDocument', family: RESOURCE, required: true, ctx: { kind: 'sqs-url', field: 'queue' } }],
  'aws-native:organizations:Policy': [{ prop: 'content', family: SCP, required: true, orgType: 'type' }],
});

// IAM types with no policy document (schema-derived); any other unmapped IAM type is exit 3.
const IAM_NO_DOCUMENT = new Set([
  'aws:iam/accessKey:AccessKey', 'aws:iam/accountAlias:AccountAlias', 'aws:iam/accountPasswordPolicy:AccountPasswordPolicy',
  'aws:iam/group:Group', 'aws:iam/groupMembership:GroupMembership', 'aws:iam/groupPoliciesExclusive:GroupPoliciesExclusive',
  'aws:iam/groupPolicyAttachment:GroupPolicyAttachment', 'aws:iam/groupPolicyAttachmentsExclusive:GroupPolicyAttachmentsExclusive',
  'aws:iam/instanceProfile:InstanceProfile', 'aws:iam/openIdConnectProvider:OpenIdConnectProvider',
  'aws:iam/organizationsFeatures:OrganizationsFeatures', 'aws:iam/outboundWebIdentityFederation:OutboundWebIdentityFederation',
  'aws:iam/policyAttachment:PolicyAttachment', 'aws:iam/rolePoliciesExclusive:RolePoliciesExclusive',
  'aws:iam/rolePolicyAttachment:RolePolicyAttachment', 'aws:iam/rolePolicyAttachmentsExclusive:RolePolicyAttachmentsExclusive',
  'aws:iam/samlProvider:SamlProvider', 'aws:iam/securityTokenServicePreferences:SecurityTokenServicePreferences',
  'aws:iam/serverCertificate:ServerCertificate', 'aws:iam/serviceLinkedRole:ServiceLinkedRole',
  'aws:iam/serviceSpecificCredential:ServiceSpecificCredential', 'aws:iam/signingCertificate:SigningCertificate',
  'aws:iam/sshKey:SshKey', 'aws:iam/user:User', 'aws:iam/userGroupMembership:UserGroupMembership',
  'aws:iam/userLoginProfile:UserLoginProfile', 'aws:iam/userPoliciesExclusive:UserPoliciesExclusive',
  'aws:iam/userPolicyAttachment:UserPolicyAttachment', 'aws:iam/userPolicyAttachmentsExclusive:UserPolicyAttachmentsExclusive',
  'aws:iam/virtualMfaDevice:VirtualMfaDevice',
  'aws-native:iam:InstanceProfile', 'aws-native:iam:OidcProvider', 'aws-native:iam:SamlProvider',
  'aws-native:iam:ServerCertificate', 'aws-native:iam:ServiceLinkedRole', 'aws-native:iam:VirtualMfaDevice',
]);

// A property whose name says it holds a policy document (content-scan backstop).
const DOC_KEY_RE = /(polic(y|ies)|policydocument|policytext)$/i;
// R2-1/F-3: policy shape = a Statement (any case) whose entries carry Effect + Action/NotAction,
// or a bare statement (Effect + Principal/Action). WAFv2 `statement` objects carry no Effect.
const IAM_VERSIONS = new Set(['2012-10-17', '2008-10-17']);
const isStatement = (x) => isObj(x) && own(x, 'Effect') && (own(x, 'Action') || own(x, 'NotAction'));
const keyCI = (o, k) => Object.keys(o).find((x) => x.toLowerCase() === k);
function isPolicyShaped(o) {
  if (!isObj(o)) return false;
  const sk = keyCI(o, 'statement');
  if (sk) {
    const s = o[sk];
    if ((Array.isArray(s) ? s.some(isStatement) : isStatement(s)) || IAM_VERSIONS.has(o.Version)) return true;
  }
  return own(o, 'Effect') && ['Principal', 'NotPrincipal', 'Action', 'NotAction'].some((k) => own(o, k));
}
const docKey = (k) => k != null && (DOC_KEY_RE.test(k) || k.toLowerCase() === 'statement')
  && !/(arn|arns|name|names|id|ids|type)$/i.test(k);

// Region -> partition. Unknown region: unresolved (exit 3), never defaulted to aws.
const COMMERCIAL_REGION_RE = /^(us|eu|ap|ca|sa|me|af|il|mx)-(east|west|north|south|central|northeast|northwest|southeast|southwest)-\d{1,2}$/;
export function partitionForRegion(region) {
  const r = typeof region === 'string' ? region.trim() : '';
  if (r === '') return null;
  if (/^cn-[a-z]+-\d{1,2}$/.test(r)) return 'aws-cn';
  if (/^us-gov-[a-z]+-\d{1,2}$/.test(r)) return 'aws-us-gov';
  if (/^us-isob-[a-z]+-\d{1,2}$/.test(r)) return 'aws-iso-b';
  if (/^us-iso-[a-z]+-\d{1,2}$/.test(r)) return 'aws-iso';
  if (/^eu-isoe-[a-z]+-\d{1,2}$/.test(r)) return 'aws-iso-e';
  if (/^us-isof-[a-z]+-\d{1,2}$/.test(r)) return 'aws-iso-f';
  if (COMMERCIAL_REGION_RE.test(r)) return 'aws';
  return null;
}
const KNOWN_PARTITIONS = new Set(['aws', 'aws-us-gov', 'aws-cn', 'aws-iso', 'aws-iso-b', 'aws-iso-e', 'aws-iso-f']);

const own = (o, k) => o != null && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// --- Strict JSON: rejects duplicate keys and over-deep nesting (JSON.parse is last-wins). ---

/**
 * Parse JSON text, rejecting duplicate object keys and nesting deeper than maxDepth.
 * @param {string} text
 * @param {number} maxDepth
 * @returns {{ok:true, value:*}|{ok:false, code:string, path:string}}
 */
export function parseJsonStrict(text, maxDepth) {
  const s = String(text);
  const n = s.length;
  let i = 0;
  const path = [];
  const fail = (code) => { const e = new Error(code); e.jsonCode = code; throw e; };
  const ws = () => {
    while (i < n) {
      const c = s.charCodeAt(i);
      if (c === 32 || c === 9 || c === 10 || c === 13) i += 1; else break;
    }
  };
  const str = () => {
    const start = i;
    i += 1;
    while (i < n) {
      const c = s.charCodeAt(i);
      if (c === 34) { i += 1; return JSON.parse(s.slice(start, i)); }
      if (c === 92) i += 2;
      else if (c < 32) fail('SYNTAX');
      else i += 1;
    }
    return fail('SYNTAX');
  };
  const NUM = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
  const value = (depth) => {
    if (depth > maxDepth) fail('TOO_DEEP');
    ws();
    const c = s[i];
    if (c === '{') {
      i += 1;
      const o = {};
      const seen = new Set();
      ws();
      if (s[i] === '}') { i += 1; return o; }
      for (;;) {
        ws();
        if (s[i] !== '"') fail('SYNTAX');
        const k = str();
        if (seen.has(k)) { path.push(k); fail('DUPLICATE_KEY'); }
        seen.add(k);
        ws();
        if (s[i] !== ':') fail('SYNTAX');
        i += 1;
        path.push(k);
        const v = value(depth + 1);
        path.pop();
        Object.defineProperty(o, k, { value: v, enumerable: true, writable: true, configurable: true });
        ws();
        if (s[i] === ',') { i += 1; continue; }
        if (s[i] === '}') { i += 1; return o; }
        fail('SYNTAX');
      }
    }
    if (c === '[') {
      i += 1;
      const a = [];
      ws();
      if (s[i] === ']') { i += 1; return a; }
      for (;;) {
        path.push(String(a.length));
        a.push(value(depth + 1));
        path.pop();
        ws();
        if (s[i] === ',') { i += 1; continue; }
        if (s[i] === ']') { i += 1; return a; }
        fail('SYNTAX');
      }
    }
    if (c === '"') return str();
    if (s.startsWith('true', i)) { i += 4; return true; }
    if (s.startsWith('false', i)) { i += 5; return false; }
    if (s.startsWith('null', i)) { i += 4; return null; }
    NUM.lastIndex = i;
    const m = NUM.exec(s);
    if (!m) fail('SYNTAX');
    i += m[0].length;
    return Number(m[0]);
  };
  try {
    const v = value(0);
    ws();
    if (i !== n) fail('SYNTAX');
    return { ok: true, value: v };
  } catch (e) {
    const code = e && e.jsonCode ? e.jsonCode : 'SYNTAX';
    const pointer = `/${path.map((p) => String(p).replace(/~/g, '~0').replace(/\//g, '~1')).join('/')}`;
    const truncatedPath = pointer.slice(0, 200); // diagnostic only
    return { ok: false, code, path: truncatedPath };
  }
}

// Stable JSON (sorted keys) so an object-valued policy serializes deterministically.
function stableStringify(v) {
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(',')}]`;
  if (isObj(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

// Does a value (or any nested key/value) carry the unknown sentinel or a secret? Bounded.
function taint(v, depth = 0) {
  if (depth > PULUMI_LIMITS.MAX_DEPTH) return 'deep';
  if (isStr(v)) {
    if (v.includes(PULUMI_UNKNOWN)) return 'unknown';
    if (v.includes(SECRET_TEXT) || v.includes(PULUMI_ENVELOPE_ID)) return 'secret';
    return null;
  }
  if (Array.isArray(v)) {
    for (const x of v) { const t = taint(x, depth + 1); if (t) return t; }
    return null;
  }
  if (isObj(v)) {
    let found = null;
    for (const k of Object.keys(v)) {
      if (k === PULUMI_ENVELOPE_ID || k.includes(SECRET_TEXT)) return 'secret';
      if (k.includes(PULUMI_UNKNOWN)) found = found || 'unknown';
      const t = taint(v[k], depth + 1);
      if (t === 'secret') return 'secret';
      found = found || t;
    }
    return found;
  }
  return null;
}

function state(analysisState, code, message, path) {
  return Object.freeze({ analysisState, code, message, path: path == null ? null : String(path) });
}

const MSG = Object.freeze({
  PULUMI_UNKNOWN: 'The value is not known until `pulumi up` (preview unknown). It was not analyzed; unknown does NOT mean safe. Scan a stack export, or a preview of a stack whose referenced resources already exist.',
  PULUMI_SECRET: 'The value is a Pulumi secret. It was not read and not analyzed; a secret policy cannot be vouched for.',
  PULUMI_PROPERTY_MISSING: 'A required policy property is missing, so the resource could not be analyzed.',
  PULUMI_PROPERTY_INVALID: 'A policy property has a type this adapter does not accept (expected a JSON string or object), so it was not analyzed.',
  PULUMI_POLICY_MALFORMED: 'An embedded policy document is not valid JSON, so it was not analyzed.',
  PULUMI_DUPLICATE_KEY: 'A JSON object repeats a key; a reader that keeps the first value and one that keeps the last disagree, so it fails closed.',
  PULUMI_TOO_DEEP: 'The JSON nests deeper than the adapter limit, so it was not analyzed.',
  PULUMI_LIMIT: 'An input exceeds the adapter size or count limit, so it was not fully analyzed.',
  PULUMI_MALFORMED: 'The Pulumi document does not have the structure this adapter reads, so it could not be analyzed.',
  PULUMI_AMBIGUOUS_SHAPE: 'The document has both or neither of "steps" (preview) and "deployment" (stack export), so it could not be analyzed.',
  PULUMI_UNKNOWN_OP: 'A preview step uses an operation this adapter does not model, so its resource was not analyzed.',
  PULUMI_MISSING_STATE: 'A preview step that changes or keeps a resource carries no newState, so the resource could not be analyzed.',
  PULUMI_DUPLICATE_URN: 'Two entries share a URN with different contents, so which one applies is ambiguous.',
  PULUMI_DUPLICATE_ID: 'Two inline policies on one resource share a name, so which one applies is ambiguous.',
  PULUMI_UNSUPPORTED_TYPE: 'The resource carries a policy document in a type or property this adapter does not analyze. Unsupported does NOT mean safe.',
  PULUMI_PENDING_OPERATIONS: 'The stack export records pending operations (an interrupted update), so the state may not match the cloud.',
  PULUMI_ACCOUNT_UNRESOLVED: 'The AWS account of these resources is neither supplied (subject-account) nor proven by the stack, so account-aware checks cannot be trusted.',
  PULUMI_ACCOUNT_MISMATCH: 'The supplied subject-account differs from the account the stack proves for these resources.',
  PULUMI_ACCOUNT_AMBIGUOUS: 'Resources behind one provider carry ARNs from more than one account, so the account is ambiguous.',
  PULUMI_PARTITION_UNRESOLVED: 'The provider region does not map to a known AWS partition, so the partition is not assumed.',
  PULUMI_PARTITION_MISMATCH: 'The supplied partition differs from the partition the stack proves for these resources, or the resource and provider regions disagree.',
  PULUMI_CONTEXT_AMBIGUOUS: 'More than one resource in the stack matches the resource this policy is attached to.',
  PULUMI_UNMODELED_PERMISSION: 'A Lambda permission grants invoke to the public, another account, or a service with no source binding. It is not modeled yet; unsupported does NOT mean safe.',
});
const st = (code, path, kind = ANALYSIS_STATE.INCOMPLETE) => state(kind, code, MSG[code] || 'Pulumi input could not be fully analyzed.', path);

// --- Location: untrusted sourcePosition -> a safe project-relative URI + line. ----------

const SRC_RE = /^project:\/\/\/([^#?\u0000-\u001f\u007f]{1,512})#(\d{1,7})(?:,(\d{1,7}))?$/;
/**
 * Accept only project:///<relative path>#line[,col] with no traversal, absolute form or
 * control/format characters. Never opens the file. Returns null when unsafe.
 * @param {*} pos
 * @returns {{uri:string, startLine:number, startColumn:(number|undefined)}|null}
 */
export function safeSourcePosition(pos) {
  if (!isStr(pos)) return null;
  const m = SRC_RE.exec(pos);
  if (!m) return null;
  const raw = m[1];
  if (raw.startsWith('/') || raw.includes('\\') || /^[A-Za-z]:/.test(raw)) return null;
  let decoded;
  try { decoded = decodeURIComponent(raw); } catch { return null; }
  if (/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/.test(decoded)) return null;
  if (decoded.startsWith('/') || decoded.includes('\\')) return null;
  if (decoded.split('/').some((seg) => seg === '..' || seg === '.' || seg === '')) return null;
  const line = Number(m[2]);
  const col = m[3] != null ? Number(m[3]) : undefined;
  if (line < 1) return null;
  return { uri: raw, startLine: line, startColumn: col && col > 0 ? col : undefined };
}

// --- Reading the document into items ----------------------------------------------------

function itemFromStep(step, index, states) {
  if (!isObj(step) || !isStr(step.op) || !isStr(step.urn) || step.urn === '') {
    states.push(st('PULUMI_MALFORMED', `steps[${index}]`, ANALYSIS_STATE.MALFORMED));
    return null;
  }
  const op = step.op;
  if (SKIP_OPS.has(op)) return { skip: true, urn: step.urn };
  if (!ANALYZE_OPS.has(op)) { states.push(st('PULUMI_UNKNOWN_OP', step.urn, ANALYSIS_STATE.UNSUPPORTED)); return null; }
  const ns = step.newState;
  if (!isObj(ns)) { states.push(st('PULUMI_MISSING_STATE', step.urn, ANALYSIS_STATE.MALFORMED)); return null; }
  if (!isStr(ns.type) || ns.type === '' || (ns.urn !== undefined && ns.urn !== step.urn)) {
    states.push(st('PULUMI_MALFORMED', step.urn, ANALYSIS_STATE.MALFORMED));
    return null;
  }
  const old = isObj(step.oldState) ? step.oldState : null;
  if ((ns.inputs !== undefined && !isObj(ns.inputs)) || (ns.outputs !== undefined && !isObj(ns.outputs))
    || (old && old.outputs !== undefined && !isObj(old.outputs))) {
    states.push(st('PULUMI_MALFORMED', step.urn, ANALYSIS_STATE.MALFORMED));
    return null;
  }
  const provider = isStr(ns.provider) ? ns.provider : (old && isStr(old.provider) ? old.provider : null);
  // G-01: prior outputs describe the new resource only for an in-place op on the same provider.
  const oldUsable = !!old && op !== 'replace' && op !== 'create-replacement'
    && (!isStr(old.provider) || providerUrnOf(old.provider) === providerUrnOf(provider));
  return {
    urn: step.urn,
    op,
    type: ns.type,
    inputs: ns.inputs || {},
    outputs: ns.outputs || (oldUsable && old.outputs) || {},
    id: isStr(ns.id) ? ns.id : (oldUsable && isStr(old.id) ? old.id : null),
    provider,
    sourcePosition: ns.sourcePosition,
    external: op === 'read' || ns.external === true,
    protectChanged: !!(old && old.protect) !== !!ns.protect,
  };
}

function itemFromResource(r, index, states) {
  if (!isObj(r) || !isStr(r.urn) || r.urn === '' || !isStr(r.type) || r.type === '') {
    states.push(st('PULUMI_MALFORMED', `deployment.resources[${index}]`, ANALYSIS_STATE.MALFORMED));
    return null;
  }
  if (r.delete === true) return { skip: true, urn: r.urn }; // pending delete after a replace
  if ((r.inputs !== undefined && !isObj(r.inputs)) || (r.outputs !== undefined && !isObj(r.outputs))) {
    states.push(st('PULUMI_MALFORMED', r.urn, ANALYSIS_STATE.MALFORMED));
    return null;
  }
  return {
    urn: r.urn,
    op: 'state',
    type: r.type,
    inputs: r.inputs || {},
    outputs: r.outputs || {},
    id: isStr(r.id) ? r.id : null,
    provider: isStr(r.provider) ? r.provider : null,
    sourcePosition: r.sourcePosition,
    external: r.external === true,
    protectChanged: false,
  };
}

// Provider reference "<provider urn>::<id>" -> provider urn.
function providerUrnOf(ref) {
  if (!isStr(ref)) return null;
  const i = ref.lastIndexOf('::');
  return i > 0 ? ref.slice(0, i) : null;
}

const ARN_ACCOUNT_RE = /^arn:([a-z-]+):[a-z0-9-]+:[a-z0-9-]*:(\d{12}):/;
// F-4/G-02: types whose `arn` output is their own ARN, computed in the provider's account.
// Others (EventTarget, TopicSubscription...) can echo or point at another account's ARN.
const OWN_ARN_TYPES = new Set([
  'aws:iam/role:Role', 'aws:iam/user:User', 'aws:iam/group:Group', 'aws:iam/policy:Policy',
  'aws:iam/instanceProfile:InstanceProfile', 'aws:sqs/queue:Queue', 'aws:sns/topic:Topic', 'aws:kms/key:Key',
  'aws:lambda/function:Function', 'aws:secretsmanager/secret:Secret', 'aws:ecr/repository:Repository',
  'aws:dynamodb/table:Table',
  'aws-native:iam:Role', 'aws-native:iam:User', 'aws-native:iam:Group', 'aws-native:iam:ManagedPolicy',
  'aws-native:iam:InstanceProfile', 'aws-native:sqs:Queue', 'aws-native:sns:Topic', 'aws-native:kms:Key',
  'aws-native:lambda:Function', 'aws-native:secretsmanager:Secret', 'aws-native:ecr:Repository',
  'aws-native:dynamodb:Table',
]);

// Per provider: region-derived partition and account evidence from the stack itself.
function providerFacts(items) {
  const facts = new Map();
  const get = (urn) => {
    if (!facts.has(urn)) facts.set(urn, { region: null, regionGiven: false, accounts: new Set(), arnPartitions: new Set(), configAccounts: new Set() });
    return facts.get(urn);
  };
  for (const it of items) {
    if (!it.type.startsWith('pulumi:providers:')) continue;
    const f = get(it.urn);
    const region = it.inputs.region;
    if (region !== undefined) { f.regionGiven = true; f.region = isStr(region) && !taint(region) ? region : null; }
    const allowed = it.inputs.allowedAccountIds;
    if (Array.isArray(allowed) && allowed.length === 1 && isStr(allowed[0]) && /^\d{12}$/.test(allowed[0])) f.configAccounts.add(allowed[0]);
    const roles = [];
    if (isObj(it.inputs.assumeRole)) roles.push(it.inputs.assumeRole.roleArn);
    if (Array.isArray(it.inputs.assumeRoles)) for (const r of it.inputs.assumeRoles) if (isObj(r)) roles.push(r.roleArn);
    for (const ra of roles) {
      const m = isStr(ra) ? ARN_ACCOUNT_RE.exec(ra) : null;
      if (m) f.configAccounts.add(m[2]);
    }
  }
  for (const it of items) {
    // A read/external resource may live in another account: never account evidence.
    if (it.type.startsWith('pulumi:providers:') || it.external) continue;
    if (!OWN_ARN_TYPES.has(it.type) || own(it.inputs, 'arn')) continue; // an echoed arn proves nothing
    const p = providerUrnOf(it.provider);
    if (!p) continue;
    const arn = it.outputs.arn;
    const m = isStr(arn) ? ARN_ACCOUNT_RE.exec(arn) : null;
    if (m) { const f = get(p); f.accounts.add(m[2]); f.arnPartitions.add(m[1]); }
  }
  return facts;
}

// Resolve { account, partition, accountProven, states } for one resource.
function resolveScope(it, facts, opts, globalSeen, globalStates) {
  const states = [];
  const pUrn = providerUrnOf(it.provider);
  const f = pUrn ? facts.get(pUrn) : null;
  const where = pUrn || it.urn;
  // Partition.
  let derivedPart = null;
  if (f && f.regionGiven) {
    derivedPart = partitionForRegion(f.region);
    if (!derivedPart && !globalSeen.has(`part:${where}`)) { globalSeen.add(`part:${where}`); globalStates.push(st('PULUMI_PARTITION_UNRESOLVED', where)); }
  }
  if (f && f.arnPartitions.size > 0) {
    const arnPart = f.arnPartitions.size === 1 ? [...f.arnPartitions][0] : null;
    if (!arnPart || (derivedPart && arnPart !== derivedPart)) states.push(st('PULUMI_PARTITION_MISMATCH', where));
    derivedPart = derivedPart || arnPart;
  }
  const resRegion = it.inputs.region;
  if (isStr(resRegion) && !taint(resRegion)) {
    const rp = partitionForRegion(resRegion);
    if (!rp || (derivedPart && rp !== derivedPart)) states.push(st('PULUMI_PARTITION_MISMATCH', it.urn));
    derivedPart = derivedPart || rp;
  }
  const explicitPart = isStr(opts.partition) && KNOWN_PARTITIONS.has(opts.partition.trim()) ? opts.partition.trim() : null;
  if (explicitPart && derivedPart && explicitPart !== derivedPart) states.push(st('PULUMI_PARTITION_MISMATCH', where));
  const partition = explicitPart || derivedPart || null;
  // Account: proven by ARNs the stack manages, or by the provider's own config.
  const evidence = new Set([...(f ? f.accounts : []), ...(f ? f.configAccounts : [])]);
  let derivedAcct = null;
  if (evidence.size > 1) {
    if (!globalSeen.has(`amb:${where}`)) { globalSeen.add(`amb:${where}`); globalStates.push(st('PULUMI_ACCOUNT_AMBIGUOUS', where)); }
  } else if (evidence.size === 1) derivedAcct = [...evidence][0];
  const explicitAcct = isStr(opts.subjectAccount) && /^\d{12}$/.test(opts.subjectAccount.trim()) ? opts.subjectAccount.trim() : null;
  if (explicitAcct && derivedAcct && explicitAcct !== derivedAcct) states.push(st('PULUMI_ACCOUNT_MISMATCH', where));
  const account = explicitAcct || derivedAcct || null;
  if (!account && evidence.size <= 1 && !globalSeen.has(`acct:${where}`)) {
    globalSeen.add(`acct:${where}`);
    globalStates.push(st('PULUMI_ACCOUNT_UNRESOLVED', where));
  }
  return { account, partition, accountProven: !!derivedAcct && evidence.size === 1 && (!explicitAcct || explicitAcct === derivedAcct), states };
}

// Per-provider account/partition and the evidence behind them (R2-2), for reviewers.
function providerSummary(facts, opts) {
  return [...facts.keys()].sort().map((urn) => {
    const s = resolveScope({ provider: `${urn}::x`, urn, inputs: {} }, facts, opts, new Set(), []);
    const f = facts.get(urn);
    return { urn, account: s.account, accountProven: s.accountProven, partition: s.partition,
      evidence: { arnAccounts: [...f.accounts].sort(), configAccounts: [...f.configAccounts].sort(), region: f.region } };
  });
}

// Lambda permissions (option d): exit 3 only for risky shapes; source-bound service grants are listed.
const PERMISSION_TYPES = new Set(['aws:lambda/permission:Permission',
  'aws:lambda/layerVersionPermission:LayerVersionPermission', 'aws-native:lambda:Permission']);
const SERVICE_PRINCIPAL_RE = /^[a-z0-9.-]+\.amazonaws\.com(?:\.cn)?$/;
// Returns { state } (exit 3) or { reason } (listed in unanalyzed[]).
function permissionVerdict(it, scope) {
  const f = it.inputs;
  for (const k of ['principal', 'sourceAccount', 'sourceArn', 'principalOrgId', 'organizationId']) {
    const t = taint(f[k]);
    if (t) return { state: t === 'secret' ? 'PULUMI_SECRET' : 'PULUMI_UNKNOWN' };
  }
  const p = f.principal;
  const risky = { state: 'PULUMI_UNMODELED_PERMISSION' };
  if (!concrete(p)) return risky;
  if (SERVICE_PRINCIPAL_RE.test(p)) {
    return concrete(f.sourceArn) || concrete(f.sourceAccount) ? { reason: 'service-principal-source-bound' } : risky;
  }
  if (concrete(f.principalOrgId) || concrete(f.organizationId)) return { reason: 'org-scoped' };
  const acct = /^\d{12}$/.test(p) ? p : (ARN_ACCOUNT_RE.exec(p) || [])[2];
  const ownAcct = scope.accountProven ? scope.account : null;
  if (ownAcct && acct === ownAcct) return { reason: 'own-account-principal' };
  if (ownAcct && p === '*' && f.sourceAccount === ownAcct) return { reason: 'source-account-bound' };
  return risky;
}

// --- Resource context (P4): exact join to the REFERENCED resource ------------------------

const S3_NAME_RE = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const SQS_URL_RE = /^https:\/\/sqs\.([a-z0-9-]+)\.amazonaws\.com(?:\.cn)?\/(\d{12})\/([A-Za-z0-9_-]{1,80}(?:\.fifo)?)$/;

function concrete(v) { return isStr(v) && v !== '' && !taint(v); }
function names(it, keys) {
  const out = new Set();
  for (const k of keys) {
    for (const src of [it.inputs, it.outputs]) if (concrete(src[k])) out.add(src[k]);
  }
  if (concrete(it.id)) out.add(it.id);
  return out;
}
function matchOne(items, types, keys, value) {
  const hits = items.filter((x) => types.includes(x.type) && names(x, keys).has(value));
  return hits;
}
function ownArn(it, service) {
  const a = it.outputs.arn;
  return concrete(a) && a.startsWith('arn:') && a.split(':')[2] === service ? a : null;
}

// Returns { context, states } for a resource policy document.
function resolveContext(it, ctx, items, scope) {
  const states = [];
  const fieldVal = ctx.field ? it.inputs[ctx.field] : undefined;
  if (ctx.field && fieldVal !== undefined && taint(fieldVal)) {
    states.push(st(taint(fieldVal) === 'secret' ? 'PULUMI_SECRET' : 'PULUMI_UNKNOWN', `${it.urn}#${ctx.field}`));
    return { context: { type: ctxType(ctx) }, states };
  }
  const s3 = (name, matched) => {
    if (matched) { const a = ownArn(matched, 's3'); if (a) return a; }
    if (isStr(name) && S3_NAME_RE.test(name) && scope.partition) return `arn:${scope.partition}:s3:::${name}`;
    return null;
  };
  let arn = null;
  let account;
  switch (ctx.kind) {
    case 's3': {
      if (concrete(fieldVal) && /^arn:[a-z-]+:s3:::[^/]+$/.test(fieldVal)) { arn = fieldVal; break; }
      const hits = matchOne(items, S3_BUCKET_TYPES, ['bucket', 'bucketName'], fieldVal);
      if (hits.length > 1) { states.push(st('PULUMI_CONTEXT_AMBIGUOUS', it.urn)); break; }
      arn = s3(fieldVal, hits[0]);
      // S3 ARNs carry no account: vouch for the owner only when the bucket is in this stack.
      if (hits.length === 1 && scope.accountProven) account = scope.account;
      break;
    }
    case 's3-self': {
      const name = concrete(it.inputs.bucket) ? it.inputs.bucket : (concrete(it.outputs.bucket) ? it.outputs.bucket : null);
      arn = s3(name, it);
      if (scope.accountProven) account = scope.account;
      break;
    }
    case 'self':
      arn = ownArn(it, ctx.type === 'kms-key' ? 'kms' : ctx.type);
      break;
    case 'arn':
      if (concrete(fieldVal) && fieldVal.startsWith('arn:')) arn = fieldVal;
      break;
    case 'arn-list':
      if (Array.isArray(fieldVal) && fieldVal.length === 1 && concrete(fieldVal[0]) && fieldVal[0].startsWith('arn:')) arn = fieldVal[0];
      else if (Array.isArray(fieldVal) && fieldVal.length > 1) states.push(st('PULUMI_CONTEXT_AMBIGUOUS', it.urn));
      break;
    case 'sqs-url': {
      if (!concrete(fieldVal)) break;
      const hits = matchOne(items, SQS_QUEUE_TYPES, ['url', 'queueUrl'], fieldVal);
      if (hits.length > 1) { states.push(st('PULUMI_CONTEXT_AMBIGUOUS', it.urn)); break; }
      if (hits.length === 1) arn = ownArn(hits[0], 'sqs');
      if (!arn) {
        const m = SQS_URL_RE.exec(fieldVal);
        const p = m ? partitionForRegion(m[1]) : null;
        if (m && p && (!scope.partition || scope.partition === p)) arn = `arn:${p}:sqs:${m[1]}:${m[2]}:${m[3]}`;
      }
      break;
    }
    case 'ecr-name': {
      if (!concrete(fieldVal)) break;
      const hits = matchOne(items, ['aws:ecr/repository:Repository'], ['name'], fieldVal);
      if (hits.length > 1) { states.push(st('PULUMI_CONTEXT_AMBIGUOUS', it.urn)); break; }
      if (hits.length === 1) arn = ownArn(hits[0], 'ecr');
      break;
    }
    default: break;
  }
  const context = { type: ctxType(ctx) };
  if (arn) context.arn = arn;
  if (account) context.account = account;
  return { context, states };
}
function ctxType(ctx) {
  if (ctx.kind === 's3' || ctx.kind === 's3-self') return 's3-bucket';
  if (ctx.kind === 'sqs-url') return 'sqs';
  if (ctx.kind === 'ecr-name') return 'ecr';
  return ctx.type;
}

// The role's own ARN for a trust document: from state, else built only from stack-proven facts.
function roleArnFor(it, scope) {
  const a = it.outputs.arn;
  if (concrete(a) && /^arn:[a-z-]+:iam::\d{12}:role\//.test(a)) return a;
  if (!scope.accountProven || !scope.partition) return null;
  const name = it.type === 'aws-native:iam:Role' ? it.inputs.roleName : it.inputs.name;
  const p = it.inputs.path === undefined ? '/' : it.inputs.path;
  if (!concrete(name) || !isStr(p) || taint(p) || !p.startsWith('/') || !p.endsWith('/')) return null;
  return `arn:${scope.partition}:iam::${scope.account}:role${p}${name}`;
}

// --- Policy value -> text (or a fail-closed state) --------------------------------------

function policyText(v, label, required) {
  if (v === undefined) return required ? { state: st('PULUMI_PROPERTY_MISSING', label, ANALYSIS_STATE.MALFORMED) } : { absent: true };
  const t = taint(v);
  if (t === 'secret') return { state: st('PULUMI_SECRET', label) };
  if (t === 'unknown') return { state: st('PULUMI_UNKNOWN', label) };
  if (t === 'deep') return { state: st('PULUMI_TOO_DEEP', label, ANALYSIS_STATE.MALFORMED) };
  if (isStr(v)) {
    if (v.trim() === '') return required ? { state: st('PULUMI_PROPERTY_MISSING', label, ANALYSIS_STATE.MALFORMED) } : { absent: true };
    if (v.length > PULUMI_LIMITS.MAX_POLICY_BYTES) return { state: st('PULUMI_LIMIT', label) };
    const p = parseJsonStrict(v, LIMITS.MAX_DEPTH);
    if (!p.ok) {
      const code = p.code === 'DUPLICATE_KEY' ? 'PULUMI_DUPLICATE_KEY' : p.code === 'TOO_DEEP' ? 'PULUMI_TOO_DEEP' : 'PULUMI_POLICY_MALFORMED';
      return { state: st(code, label, ANALYSIS_STATE.MALFORMED) };
    }
    return { text: v };
  }
  if (isObj(v)) {
    const text = stableStringify(v);
    if (text.length > PULUMI_LIMITS.MAX_POLICY_BYTES) return { state: st('PULUMI_LIMIT', label) };
    return { text };
  }
  return { state: st('PULUMI_PROPERTY_INVALID', label, ANALYSIS_STATE.MALFORMED) };
}

// Label for an inline policy: bracketed name, JSON-quoted when it could be misread.
function inlineLabel(base, name, index) {
  if (!concrete(name)) return `${base}[#${index}]`;
  return /^[A-Za-z0-9+=,.@_-]{1,128}$/.test(name) ? `${base}[${name}]` : `${base}[${JSON.stringify(name)}]`;
}

// Content-scan backstop (F-1..F-5): a policy in a property nothing analyzed. Decodes JSON strings,
// reports secrets/unknowns under policy-named keys, and fails closed past the depth/node budget.
// Returns [{ path, code }].
function findUnanalyzedDocs(inputs, consumed, budget) {
  const hits = [];
  const walk = (v, path, key, depth) => {
    if (budget.n <= 0 || depth > 32) { budget.exhausted = true; return; }
    budget.n -= 1;
    if (docKey(key)) {
      const tt = taint(v);
      if (tt === 'secret' || tt === 'unknown') { hits.push({ path, code: tt === 'secret' ? 'PULUMI_SECRET' : 'PULUMI_UNKNOWN' }); return; }
      if (tt === 'deep') { budget.exhausted = true; return; }
    }
    if (isStr(v)) {
      const s = v.trimStart();
      if (s[0] !== '{' && s[0] !== '[') return;
      const p = parseJsonStrict(v, 32);
      if (p.ok) walk(p.value, path, key, depth + 1);
      else if (/statement/i.test(v) && /effect/i.test(v)) hits.push({ path, code: 'PULUMI_UNSUPPORTED_TYPE' });
      return;
    }
    if (Array.isArray(v)) { v.forEach((x, i) => walk(x, `${path}[${i}]`, key, depth + 1)); return; }
    if (isObj(v)) {
      if (isPolicyShaped(v)) { hits.push({ path, code: 'PULUMI_UNSUPPORTED_TYPE' }); return; }
      for (const k of Object.keys(v).sort()) walk(v[k], path ? `${path}.${k}` : k, k, depth + 1);
    }
  };
  for (const k of Object.keys(inputs).sort()) if (!consumed.has(k)) walk(inputs[k], k, k, 0);
  return hits;
}

/**
 * Turn a Pulumi preview / stack export text into scannable documents plus adapter states.
 * Pure and deterministic. Returns { usage } for input that is not Pulumi JSON at all.
 * @param {string} text
 * @param {object} [opts] { subjectAccount, partition }
 */
export function extractPulumiDocuments(text, opts = {}) {
  const globalStates = [];
  const out = { kind: null, scanScope: 'delta', scannedUrns: [], documents: [], unanalyzed: [], providers: [],
    groups: [], unresolvedEdges: [], states: globalStates };
  if (opts.oversize === true) { globalStates.push(st('PULUMI_LIMIT', 'pulumi-input')); return out; }
  if (!isStr(text) || text.trim() === '') return { usage: { reason: 'MISSING_INPUT', message: 'No Pulumi JSON supplied (input is missing or empty).' } };
  if (text.length > PULUMI_LIMITS.MAX_BYTES) { globalStates.push(st('PULUMI_LIMIT', 'pulumi-input')); return out; }
  const parsed = parseJsonStrict(text, PULUMI_LIMITS.MAX_DEPTH);
  if (!parsed.ok) {
    const code = parsed.code === 'DUPLICATE_KEY' ? 'PULUMI_DUPLICATE_KEY' : parsed.code === 'TOO_DEEP' ? 'PULUMI_TOO_DEEP' : 'PULUMI_MALFORMED';
    globalStates.push(st(code, parsed.code === 'SYNTAX' ? 'pulumi-input' : parsed.path, ANALYSIS_STATE.MALFORMED));
    return out;
  }
  const doc = parsed.value;
  if (!isObj(doc)) return { usage: { reason: 'NOT_PULUMI_JSON', message: 'The input is not a Pulumi preview (--json) or stack export document.' } };
  const hasSteps = own(doc, 'steps');
  const hasDep = own(doc, 'deployment');
  if (hasSteps === hasDep) {
    const pulumiShaped = hasSteps || ['changeSummary', 'checkpoint', 'duration'].some((k) => own(doc, k));
    if (!pulumiShaped) return { usage: { reason: 'NOT_PULUMI_JSON', message: 'The input is not a Pulumi preview (--json) or stack export document.' } };
    globalStates.push(st('PULUMI_AMBIGUOUS_SHAPE', 'pulumi-input', ANALYSIS_STATE.MALFORMED));
    return out;
  }
  out.kind = hasSteps ? 'preview' : 'export';
  let raw;
  if (hasSteps) {
    if (!Array.isArray(doc.steps)) { globalStates.push(st('PULUMI_MALFORMED', 'steps', ANALYSIS_STATE.MALFORMED)); return out; }
    raw = doc.steps;
  } else {
    const dep = doc.deployment;
    if (!isObj(dep) || (dep.resources != null && !Array.isArray(dep.resources))) {
      globalStates.push(st('PULUMI_MALFORMED', 'deployment', ANALYSIS_STATE.MALFORMED));
      return out;
    }
    raw = dep.resources || [];
    if (Array.isArray(dep.pending_operations) && dep.pending_operations.length > 0) globalStates.push(st('PULUMI_PENDING_OPERATIONS', 'deployment.pending_operations'));
    out.scanScope = 'full';
  }
  if (raw.length > PULUMI_LIMITS.MAX_RESOURCES) { globalStates.push(st('PULUMI_LIMIT', hasSteps ? 'steps' : 'deployment.resources')); return out; }

  // Items, deduplicated by URN (identical repeats collapse; differing repeats fail closed).
  const byUrn = new Map();
  const dupUrns = new Set();
  raw.forEach((r, i) => {
    const it = hasSteps ? itemFromStep(r, i, globalStates) : itemFromResource(r, i, globalStates);
    if (!it || it.skip) return;
    const prev = byUrn.get(it.urn);
    if (prev) {
      if (stableStringify([prev.type, prev.inputs, prev.outputs]) !== stableStringify([it.type, it.inputs, it.outputs])) dupUrns.add(it.urn);
      return;
    }
    byUrn.set(it.urn, it);
  });
  for (const u of [...dupUrns].sort()) { globalStates.push(st('PULUMI_DUPLICATE_URN', u, ANALYSIS_STATE.MALFORMED)); byUrn.delete(u); }
  const items = [...byUrn.values()].sort((a, b) => cmp(a.urn, b.urn));
  out.scannedUrns = items.map((x) => x.urn);
  // Full preview scope only when unchanged resources are listed (--show-sames); a protect-only
  // change also emits a `same` step, so it does not count.
  if (hasSteps && items.some((x) => x.op === 'same' && x.type !== 'pulumi:pulumi:Stack' && !x.protectChanged)) out.scanScope = 'full';

  const facts = providerFacts(items);
  out.providers = providerSummary(facts, opts);
  const seen = new Set();
  const budget = { n: PULUMI_LIMITS.MAX_WALK_NODES, exhausted: false };
  for (const it of items) {
    if (it.type.startsWith('pulumi:providers:') || it.type === 'pulumi:pulumi:Stack') continue;
    if (PERMISSION_TYPES.has(it.type)) {
      const v = permissionVerdict(it, resolveScope(it, facts, opts, new Set(), []));
      if (v.state) globalStates.push(st(v.state, it.urn, v.state === 'PULUMI_UNMODELED_PERMISSION' ? ANALYSIS_STATE.UNSUPPORTED : ANALYSIS_STATE.INCOMPLETE));
      else out.unanalyzed.push({ urn: it.urn, type: it.type, reason: v.reason });
      continue;
    }
    const entries = TYPE_MAP[it.type];
    const consumed = new Set();
    if (!entries) {
      if ((it.type.startsWith('aws:iam/') || it.type.startsWith('aws-native:iam:')) && !IAM_NO_DOCUMENT.has(it.type)) {
        globalStates.push(st('PULUMI_UNSUPPORTED_TYPE', it.urn, ANALYSIS_STATE.UNSUPPORTED));
        continue;
      }
    }
    const scope = entries ? resolveScope(it, facts, opts, seen, globalStates) : null;
    const location = safeSourcePosition(it.sourcePosition);
    const pushDoc = (property, family, res, extraStates, context) => {
      out.documents.push({
        artifact: `${it.urn}#${property}`,
        urn: it.urn,
        property,
        type: it.type,
        family,
        op: it.op,
        managed: it.external ? 'external' : 'program',
        location,
        text: res.text || null,
        subjectAccount: scope.account,
        partition: scope.partition,
        resourceContext: context,
        states: [...scope.states, ...extraStates, ...(res.state ? [res.state] : [])],
      });
    };
    for (const e of entries || []) {
      if (e.inline) {
        consumed.add(e.inline);
        const arr = it.inputs[e.inline];
        if (arr === undefined) continue;
        const t = taint(arr);
        if (!Array.isArray(arr) || t) {
          pushDoc(e.inline, e.family, { state: t ? st(t === 'secret' ? 'PULUMI_SECRET' : 'PULUMI_UNKNOWN', `${it.urn}#${e.inline}`) : st('PULUMI_PROPERTY_INVALID', `${it.urn}#${e.inline}`, ANALYSIS_STATE.MALFORMED) }, []);
          continue;
        }
        if (arr.length > PULUMI_LIMITS.MAX_INLINE) { pushDoc(e.inline, e.family, { state: st('PULUMI_LIMIT', `${it.urn}#${e.inline}`) }, []); continue; }
        const labels = new Map();
        arr.forEach((entry, idx) => {
          if (!isObj(entry)) { pushDoc(`${e.inline}[#${idx}]`, e.family, { state: st('PULUMI_PROPERTY_INVALID', `${it.urn}#${e.inline}[#${idx}]`, ANALYSIS_STATE.MALFORMED) }, []); return; }
          const label = inlineLabel(e.inline, entry[e.nameKey], idx);
          const res = policyText(entry[e.docKey], `${it.urn}#${label}`, false);
          if (res.absent) return;
          const extra = [];
          if (!concrete(entry[e.nameKey])) extra.push(st('PULUMI_PROPERTY_INVALID', `${it.urn}#${label}`, ANALYSIS_STATE.MALFORMED));
          if (labels.has(label)) extra.push(st('PULUMI_DUPLICATE_ID', `${it.urn}#${label}`, ANALYSIS_STATE.MALFORMED));
          labels.set(label, true);
          pushDoc(label, e.family, res, extra);
        });
        continue;
      }
      consumed.add(e.prop);
      let family = e.family;
      if (e.orgType) {
        consumed.add(e.orgType);
        const ty = it.inputs[e.orgType];
        if (ty !== undefined && taint(ty)) { pushDoc(e.prop, family, { state: st('PULUMI_UNKNOWN', `${it.urn}#${e.orgType}`) }, []); continue; }
        if (ty !== undefined && !isStr(ty)) { pushDoc(e.prop, family, { state: st('PULUMI_PROPERTY_INVALID', `${it.urn}#${e.orgType}`, ANALYSIS_STATE.MALFORMED) }, []); continue; }
        // Only SCPs and RCPs are IAM documents; tag/backup/... policies are not.
        if (ty !== undefined && ty !== 'SERVICE_CONTROL_POLICY' && ty !== 'RESOURCE_CONTROL_POLICY') continue;
        family = SCP;
      }
      const res = policyText(it.inputs[e.prop], `${it.urn}#${e.prop}`, e.required);
      if (res.absent) continue;
      let context;
      const extra = [];
      if (e.ctx && e.ctx.field) consumed.add(e.ctx.field);
      if (res.state) {
        // Unknown/secret policy: nothing to analyze, so no context lookup either.
      } else if (e.ctx) {
        const rc = resolveContext(it, e.ctx, items, scope);
        context = rc.context;
        extra.push(...rc.states);
      } else if (family === TRUST && ROLE_TYPES.has(it.type)) {
        const arn = roleArnFor(it, scope);
        if (arn) context = { type: 'iam-role', arn };
      }
      pushDoc(e.prop, family, res, extra, context);
    }
    for (const h of findUnanalyzedDocs(it.inputs, consumed, budget)) {
      globalStates.push(st(h.code, `${it.urn}#${h.path}`,
        h.code === 'PULUMI_UNSUPPORTED_TYPE' ? ANALYSIS_STATE.UNSUPPORTED : ANALYSIS_STATE.INCOMPLETE));
    }
  }
  if (budget.exhausted) globalStates.push(st('PULUMI_LIMIT', 'pulumi-input'));
  out.documents.sort((a, b) => cmp(a.artifact, b.artifact));
  Object.assign(out, buildGroups(items, out.documents));
  globalStates.sort((a, b) => cmp(`${a.code}\u0000${a.path}`, `${b.code}\u0000${b.path}`));
  return out;
}

// --- P9 grouping: informational only, never changes a verdict ---------------------------

const ROLE_POLICY_TYPES = new Set(['aws:iam/rolePolicy:RolePolicy', 'aws-native:iam:RolePolicy']);
const ATTACH_TYPES = new Set(['aws:iam/rolePolicyAttachment:RolePolicyAttachment']);
const POLICY_TYPES = new Set(['aws:iam/policy:Policy', 'aws-native:iam:ManagedPolicy']);
const AWS_MANAGED_RE = /^arn:[a-z-]+:iam::aws:policy\//;
const TRUST_PROPS = new Set(['assumeRolePolicy', 'assumeRolePolicyDocument']);
const edgeKey = (e) => `${e.kind}\u0000${e.from}\u0000${e.to == null ? '' : e.to}`;

// A reference resolves only to exactly one same-provider candidate; else an explicit reason.
function resolveRef(cands, ref, prov, keysOf) {
  if (ref === undefined) return { reason: 'missing' };
  const tt = taint(ref);
  if (tt) return { reason: tt === 'secret' ? 'secret' : 'unknown' };
  if (!concrete(ref)) return { reason: 'invalid' };
  const hits = cands.filter((c) => providerUrnOf(c.provider) === prov && keysOf(c).includes(ref));
  if (hits.length === 1) return { to: hits[0].urn };
  return { reason: hits.length === 0 ? 'no-match' : 'ambiguous' };
}
const roleKeys = (r) => [r.inputs.name, r.inputs.roleName, r.outputs.name, r.outputs.roleName, r.id, r.outputs.arn].filter(concrete);
const policyKeys = (p) => [p.outputs.arn].filter(concrete);

function trustPrincipals(text) {
  const p = parseJsonStrict(text, 32);
  if (!p.ok || !isObj(p.value)) return [];
  const sts = Array.isArray(p.value.Statement) ? p.value.Statement : [p.value.Statement];
  const out = [];
  for (const s of sts) {
    if (!isObj(s) || s.Effect !== 'Allow' || !isObj(s.Principal)) continue;
    const a = s.Principal.AWS;
    for (const v of (Array.isArray(a) ? a : [a])) if (isStr(v)) out.push(v);
  }
  return out;
}

function buildGroups(items, documents) {
  const roles = items.filter((it) => ROLE_TYPES.has(it.type));
  const policies = items.filter((it) => POLICY_TYPES.has(it.type));
  const docsOf = (urn) => documents.filter((d) => d.urn === urn).map((d) => d.artifact);
  const groups = new Map(roles.map((r) => [r.urn, {
    role: r.urn, type: r.type, provider: providerUrnOf(r.provider), documents: docsOf(r.urn), edges: [],
  }]));
  const unresolved = [];
  const link = (edge, roleUrn, extraDocs) => {
    if (edge.to == null) { unresolved.push(edge); return; }
    const g = groups.get(roleUrn);
    if (!g) return;
    g.edges.push(edge);
    for (const a of extraDocs || []) if (!g.documents.includes(a)) g.documents.push(a);
  };
  for (const it of items) {
    const prov = providerUrnOf(it.provider);
    if (ROLE_POLICY_TYPES.has(it.type)) {
      const r = resolveRef(roles, it.inputs.role !== undefined ? it.inputs.role : it.inputs.roleName, prov, roleKeys);
      link(r.to ? { kind: 'role-policy', from: it.urn, to: r.to } : { kind: 'role-policy', from: it.urn, to: null, unresolved: true, reason: r.reason },
        r.to, docsOf(it.urn));
    } else if (ATTACH_TYPES.has(it.type)) {
      const r = resolveRef(roles, it.inputs.role, prov, roleKeys);
      link(r.to ? { kind: 'attachment-role', from: it.urn, to: r.to } : { kind: 'attachment-role', from: it.urn, to: null, unresolved: true, reason: r.reason }, r.to);
      const arn = it.inputs.policyArn;
      if (concrete(arn) && AWS_MANAGED_RE.test(arn)) {
        if (r.to) link({ kind: 'attachment-policy', from: it.urn, to: arn, external: 'aws-managed' }, r.to);
        else unresolved.push({ kind: 'attachment-policy', from: it.urn, to: arn, external: 'aws-managed', unresolved: true, reason: 'role-unresolved' });
      } else {
        const pr = resolveRef(policies, arn, prov, policyKeys);
        const edge = pr.to ? { kind: 'attachment-policy', from: it.urn, to: pr.to } : { kind: 'attachment-policy', from: it.urn, to: null, unresolved: true, reason: pr.reason };
        if (pr.to && r.to) link(edge, r.to, docsOf(pr.to));
        else if (pr.to) unresolved.push({ ...edge, unresolved: true, reason: 'role-unresolved' });
        else unresolved.push(edge);
      }
    }
  }
  // can-assume: a trust principal that is exactly another same-provider role's ARN (G1 input).
  for (const r of roles) {
    const trust = documents.find((d) => d.urn === r.urn && TRUST_PROPS.has(d.property) && d.text);
    if (!trust) continue;
    const prov = providerUrnOf(r.provider);
    for (const p of trustPrincipals(trust.text)) {
      const hits = roles.filter((o) => o.urn !== r.urn && providerUrnOf(o.provider) === prov && concrete(o.outputs.arn) && o.outputs.arn === p);
      if (hits.length === 1) link({ kind: 'can-assume', from: hits[0].urn, to: r.urn }, r.urn);
    }
  }
  const sortEdges = (a) => a.sort((x, y) => cmp(edgeKey(x), edgeKey(y)));
  const out = [...groups.values()].sort((a, b) => cmp(a.role, b.role));
  for (const g of out) { g.documents.sort(); sortEdges(g.edges); }
  return { groups: out, unresolvedEdges: sortEdges(unresolved) };
}

// --- Aggregate scan ---------------------------------------------------------------------

const RANK = { 0: 0, 1: 1, 2: 2, 3: 3, 4: 4 };
const worse = (a, b) => ((RANK[a] ?? 4) >= (RANK[b] ?? 4) ? a : b);

function failClosedResult(states, family) {
  const malformed = states.some((s) => s.analysisState === ANALYSIS_STATE.MALFORMED);
  return Object.freeze({
    analysisStatus: malformed ? ANALYSIS_STATUS.FAILED : ANALYSIS_STATUS.PARTIAL,
    analysisStates: Object.freeze(states.slice()),
    findings: Object.freeze([]),
    blockingCount: 0,
    findingsCount: 0,
    exitCode: EXIT.FAIL_CLOSED,
    reason: states[0] ? states[0].code : 'PULUMI_INCOMPLETE',
    family: family || null,
    coverage: null,
    engineOk: false,
  });
}

// Adapter states on an analyzed document keep its findings but force exit 3.
function withStates(result, states) {
  if (states.length === 0) return result;
  return Object.freeze({
    ...result,
    analysisStatus: result.analysisStatus === ANALYSIS_STATUS.COMPLETE ? ANALYSIS_STATUS.PARTIAL : result.analysisStatus,
    analysisStates: Object.freeze([...states, ...(result.analysisStates || [])]),
    exitCode: worse(result.exitCode, EXIT.FAIL_CLOSED),
    reason: (result.exitCode === EXIT.INTERNAL) ? result.reason : states[0].code,
  });
}

// Run verdict from the documents plus file-level states (any state forces exit 3).
function aggregate(meta, documents) {
  const states = meta.analysisStates || [];
  let exitCode = EXIT.CLEAN;
  for (const d of documents) exitCode = worse(exitCode, d.result.exitCode);
  if (states.length > 0) exitCode = worse(exitCode, EXIT.FAIL_CLOSED);
  const findingsCount = documents.reduce((n, d) => n + (d.result.findingsCount || 0), 0);
  const blockingCount = documents.reduce((n, d) => n + (d.result.blockingCount || 0), 0);
  const failed = states.some((s) => s.analysisState === ANALYSIS_STATE.MALFORMED)
    || documents.some((d) => d.result.analysisStatus === ANALYSIS_STATUS.FAILED);
  const analysisStatus = exitCode === EXIT.CLEAN || exitCode === EXIT.FINDINGS
    ? ANALYSIS_STATUS.COMPLETE : (failed ? ANALYSIS_STATUS.FAILED : ANALYSIS_STATUS.PARTIAL);
  let reason = exitCode === EXIT.CLEAN ? 'CLEAN' : exitCode === EXIT.FINDINGS ? 'FINDINGS_AT_OR_ABOVE_THRESHOLD' : null;
  if (reason == null) {
    const worst = documents.find((d) => d.result.exitCode === exitCode);
    reason = (exitCode === EXIT.FAIL_CLOSED && states[0]) ? states[0].code
      : (worst ? worst.result.reason : 'PULUMI_INCOMPLETE');
  }
  if (exitCode === EXIT.CLEAN && documents.some((d) => d.result.reason === 'CLEAN_WITH_BASELINE')) reason = 'CLEAN_WITH_BASELINE';
  return Object.freeze({ ...meta, analysisStatus, exitCode, reason, findingsCount, blockingCount, documents });
}

// P8: a document's baseline URI. JSON keeps (urn, property) unambiguous whatever they contain.
export function pulumiBaselineUri(d) {
  return `pulumi:${JSON.stringify([String(d.urn), String(d.property)])}`;
}

/**
 * Attach baseline keys to every document (always, so SARIF publishes them) and apply an
 * opt-in baseline per document, then re-aggregate. File-level states are never accepted.
 * @param {object} result scanPulumi() result
 * @param {Map<string,object>|null} accepted parseBaseline().keys, or null
 * @param {string} threshold
 */
export function applyPulumiBaseline(result, accepted, threshold) {
  if (!result || !Array.isArray(result.documents) || result.exitCode === EXIT.USAGE || result.exitCode === EXIT.INTERNAL) return result;
  const documents = result.documents.map((d) => Object.freeze({ ...d, result: applyBaseline(d.result, pulumiBaselineUri(d), accepted, threshold) }));
  const used = new Set();
  const mismatched = new Set();
  for (const d of documents) {
    for (const k of d.result.baseline.used) used.add(k);
    for (const k of d.result.baseline.mismatched) mismatched.add(k);
  }
  const { analysisStatus: _s, exitCode: _e, reason: _r, findingsCount: _f, blockingCount: _b, documents: _d, ...meta } = result;
  const agg = aggregate(meta, documents);
  const applied = accepted instanceof Map;
  return Object.freeze({
    ...agg,
    baseline: Object.freeze({
      applied,
      used: Object.freeze([...used].sort()),
      mismatched: Object.freeze([...mismatched].sort()),
      stale: Object.freeze(applied ? [...accepted.keys()].filter((k) => !used.has(k)).sort() : []),
    }),
  });
}

/**
 * Scan every IAM policy in a Pulumi preview (--json) or stack export.
 * Never throws; any unexpected error is INTERNAL (exit 4), never 0.
 * @param {object} input { text, subjectAccount, partition, threshold, budgetMs }
 */
export function scanPulumi(input) {
  const inp = input || {};
  try {
    const ext = extractPulumiDocuments(inp.text, inp);
    if (ext.usage) {
      return Object.freeze({
        input: 'pulumi', kind: null, scanScope: null, scannedUrns: [], documents: [],
        analysisStatus: ANALYSIS_STATUS.FAILED,
        analysisStates: [state(ANALYSIS_STATE.MALFORMED, ext.usage.reason, ext.usage.message, null)],
        exitCode: EXIT.USAGE, reason: ext.usage.reason, findingsCount: 0, blockingCount: 0,
      });
    }
    const documents = ext.documents.map((d) => {
      let result;
      if (d.text == null) {
        result = failClosedResult(d.states, d.family);
      } else {
        result = withStates(scan({
          text: d.text,
          family: d.family,
          subjectAccount: d.subjectAccount || undefined,
          partition: d.partition || undefined,
          threshold: inp.threshold,
          budgetMs: Number.isFinite(inp.budgetMs) ? inp.budgetMs : DEFAULT_BUDGET_MS,
          resourceContext: d.resourceContext,
        }), d.states);
      }
      const meta = {};
      for (const k of ['artifact', 'urn', 'property', 'type', 'family', 'op', 'managed', 'location']) meta[k] = d[k];
      return Object.freeze({ ...meta, result });
    });
    return aggregate({
      input: 'pulumi',
      kind: ext.kind,
      scanScope: ext.scanScope,
      scannedUrns: ext.scannedUrns,
      unanalyzed: ext.unanalyzed,
      providers: ext.providers,
      groups: ext.groups,
      unresolvedEdges: ext.unresolvedEdges,
      analysisStates: ext.states,
    }, documents);
  } catch {
    return Object.freeze({
      input: 'pulumi', kind: null, scanScope: null, scannedUrns: [], documents: [],
      analysisStatus: ANALYSIS_STATUS.FAILED,
      analysisStates: [state(ANALYSIS_STATE.INTERNAL, 'INTERNAL', 'Pulumi adapter failed unexpectedly.', null)],
      exitCode: EXIT.INTERNAL, reason: 'INTERNAL', findingsCount: 0, blockingCount: 0,
    });
  }
}

/**
 * SARIF/aggregate units: one per document plus one carrying the file-level states.
 * @param {object} result scanPulumi() result
 * @param {string} fallbackUri physical location when sourcePosition is unusable
 */
export function pulumiUnits(result, fallbackUri) {
  const fb = isStr(fallbackUri) && fallbackUri.trim() !== '' ? fallbackUri.trim() : 'Pulumi.yaml';
  const units = (result.documents || []).map((d) => ({
    file: d.location ? d.location.uri : fb,
    baselineUri: pulumiBaselineUri(d),
    sarif: {
      file: d.location ? d.location.uri : fb,
      logicalLocation: d.artifact,
      startLine: d.location ? d.location.startLine : undefined,
      startColumn: d.location ? d.location.startColumn : undefined,
      runProperties: { scanScope: result.scanScope, artifact: d.artifact, managed: d.managed },
    },
    result: d.result,
  }));
  if ((result.analysisStates || []).length > 0) {
    units.push({ file: fb, baselineUri: 'pulumi-input', sarif: { file: fb, logicalLocation: 'pulumi-input', runProperties: { scanScope: result.scanScope } }, result: failClosedResult(result.analysisStates, null) });
  }
  return units;
}

export default scanPulumi;
