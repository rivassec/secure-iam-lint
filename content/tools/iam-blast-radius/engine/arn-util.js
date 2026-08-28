// arn-util.js - resource-family ARN parsing (parseArn/serviceForArn/parseResourceContext).
// Extracted from resource.js (behavior-preserving pure move). NOTE: this parseArn returns
// {...resource} and accepts empty resource segments; it is a DIFFERENT parser from
// resource-arn.js's parseArn ({...resourceId}, rejects empty) - see docs/POST-V1-ISSUES.md.
import { MODELED_RESOURCE_SERVICES, RESOURCE_CODES, RESOURCE_SERVICES } from './resource-catalogs.js';

/**
 * Parse an AWS ARN into its components without hard-coding the commercial `aws`
 * partition (suite-2 test 47: GovCloud / China partitions are preserved).
 * Returns null when the value is not a syntactically valid ARN.
 *
 * ARN grammar: arn:partition:service:region:account-id:resource
 * The resource segment may itself contain ':' (e.g. key/... , type:id), so it is
 * everything after the fifth ':'.
 *
 * @param {string} value
 * @returns {{partition:string,service:string,region:string,account:string,resource:string}|null}
 */
export function parseArn(value) {
  if (typeof value !== 'string') return null;
  const s = value.trim();
  if (s.length === 0) return null;
  const parts = s.split(':');
  // arn : partition : service : region : account : resource(+)
  if (parts.length < 6) return null;
  if (parts[0] !== 'arn') return null;
  const partition = parts[1];
  const service = parts[2];
  if (partition.length === 0 || service.length === 0) return null;
  return {
    partition,
    service,
    region: parts[3],
    account: parts[4],
    resource: parts.slice(5).join(':'),
  };
}

/**
 * Classify the attached-resource SERVICE from a parsed ARN. Deterministic; never
 * throws. s3 splits into bucket vs object scope by the presence of an object key
 * ('/'), consistent with the bucket-vs-object typing in section 2.1. A KMS ARN is
 * a key policy only for a `key/...` resource; anything else recognized-but-not-
 * modeled classifies 'generic'.
 *
 * @param {{service:string,resource:string}} arn parsed ARN (from parseArn)
 * @returns {string} one of RESOURCE_SERVICES
 */
export function serviceForArn(arn) {
  if (!arn || typeof arn !== 'object') return RESOURCE_SERVICES.GENERIC;
  const svc = String(arn.service || '').toLowerCase();
  const resource = String(arn.resource || '');
  if (svc === 's3') {
    // Object ARNs carry a key after the bucket name (bucket/key or bucket/*);
    // a bucket-only ARN has no '/'.
    return resource.includes('/') ? RESOURCE_SERVICES.S3_OBJECT : RESOURCE_SERVICES.S3_BUCKET;
  }
  if (svc === 'sns') return RESOURCE_SERVICES.SNS;
  if (svc === 'sqs') return RESOURCE_SERVICES.SQS;
  if (svc === 'kms') {
    return /^key\//i.test(resource) ? RESOURCE_SERVICES.KMS_KEY : RESOURCE_SERVICES.GENERIC;
  }
  return RESOURCE_SERVICES.GENERIC;
}

/**
 * Validate and normalize the explicit attached-resource context supplied with a
 * resource-family analysis. The context is REQUIRED (the "resource-policy context
 * is explicit" invariant): a resource policy with no attached-resource context
 * cannot be analyzed and fails closed.
 *
 * Shape: { type?: string, arn: string }. The ARN is authoritative for service
 * detection; `type` is an optional UI hint recorded for evidence.
 *
 * @param {{type?:string, arn?:string}|null|undefined} context
 * @returns {{ok:boolean, code?:string, message?:string, service?:string,
 *            arn?:string, type?:(string|null), partition?:string, region?:string,
 *            account?:string, resourceId?:string}}
 */
export function parseResourceContext(context) {
  const ctx = (context && typeof context === 'object') ? context : null;
  const arnRaw = ctx && typeof ctx.arn === 'string' ? ctx.arn.trim() : '';
  const typeHint = ctx && typeof ctx.type === 'string' && ctx.type.length > 0
    ? ctx.type
    : null;
  // IAM-1204: the OWNING account of the attached resource may be supplied
  // explicitly (the "resource-policy context is explicit" invariant). This is
  // load-bearing for S3, whose bucket/object ARNs (arn:aws:s3:::bucket[/key])
  // structurally carry NO account id, so same-account vs cross-account cannot be
  // decided from the ARN alone. Only a bare 12-digit account id is accepted; any
  // other value is ignored (never guessed).
  const explicitAccount = ctx && typeof ctx.account === 'string' && /^\d{12}$/.test(ctx.account.trim())
    ? ctx.account.trim()
    : null;

  if (arnRaw.length === 0) {
    return {
      ok: false,
      code: RESOURCE_CODES.RESOURCE_CONTEXT_REQUIRED,
      message:
        'Resource-based policy analysis requires the attached-resource context ' +
        '(the resource type and ARN this policy is attached to). "Who can act on ' +
        'this resource" is only meaningful relative to a known attached resource, ' +
        'so the analyzer never guesses it. Supply the attached resource ARN and ' +
        'analyze again.',
    };
  }

  const arn = parseArn(arnRaw);
  if (!arn) {
    return {
      ok: false,
      code: RESOURCE_CODES.RESOURCE_CONTEXT_REQUIRED,
      message:
        `The attached-resource context "${arnRaw}" is not a valid ARN ` +
        '(expected arn:partition:service:region:account:resource). Supply the ' +
        'ARN of the resource this policy is attached to and analyze again.',
    };
  }

  const service = serviceForArn(arn);
  if (!MODELED_RESOURCE_SERVICES.has(service)) {
    return {
      ok: false,
      code: RESOURCE_CODES.UNSUPPORTED_RESOURCE_SHAPE,
      service,
      arn: arnRaw,
      type: typeHint,
      message:
        `The attached resource "${arnRaw}" is a resource-based-policy shape this ` +
        'analyzer does not yet model (only Amazon S3, SNS, SQS, and KMS key ' +
        'policies are modeled in this release). Analysis stops rather than apply ' +
        'S3/KMS-specific reasoning to a service whose semantics are unmodeled - ' +
        'unsupported does NOT mean safe.',
    };
  }

  // The owning account used for same-vs-cross-account classification: the explicit
  // context account wins (needed for S3), else the ARN's own account field (SNS /
  // SQS / KMS carry it), else null (undetermined -> the analyzer hedges and never
  // assumes same-account).
  const arnAccount = /^\d{12}$/.test(String(arn.account)) ? String(arn.account) : null;
  const ownerAccount = explicitAccount || arnAccount;

  return {
    ok: true,
    service,
    arn: arnRaw,
    type: typeHint || service,
    partition: arn.partition,
    region: arn.region,
    account: arn.account,
    ownerAccount,
    resourceId: arn.resource,
  };
}

/**
 * Enumerate the principal TYPES named across a resource policy's statements, as
 * inert evidence for the coverage panel/export (WHO the policy names). Reuses the
 * trust family's principal classifier so a service principal, an account/root
 * principal, a specific user/role/session ARN, a federated principal, a canonical
 * user, and anonymous "*" are each identified distinctly and never collapsed
 * (resource-policy-semantics.md section 3). Deterministic, sorted, deduped.
 *
 * @param {object} model normalized model
 * @returns {{types:string[], anonymousPresent:boolean, unknownTypes:string[]}}
 */
