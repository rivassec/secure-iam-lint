// IAM Blast Radius - shared Resource-ARN parser + breadth classifier
// (S1-breadth-classify).
//
// ONE semantic classifier, used by BOTH the rules engine (rules.js breadth
// predicate `isBroadArnResource`) AND the masked-grant fail-closed net
// (masked-grant.js `isUndecidableResourceValue`). It REPLACES two accreted,
// separately-drifting mechanisms:
//
//   1. rules.js's enumerative `isBroadArnResource` (a growing chain of
//      startsWith('*')/segment checks + a fixed semantic probe battery that could
//      only ever PROVE a value BROAD, never NARROW), and
//   2. masked-grant.js's shallow `startsWith('arn:')` "is this arn-shaped" gate.
//
// Those two gates decided breadth from DIFFERENT, shallow signals, so they could
// "agree wrongly": a value like "arn:" / "arn:aws" / " arn:aws:s3:::bucket/*"
// (leading space) / a suffix-glob "*.pem" read as arn-shaped-and-narrow by one and
// not-undecidable by the other, and returned a bare CLEAN on a real bulk read - a
// DATA-EXFIL fail-OPEN (threat-model T8). Deciding breadth from ONE shared grammar
// closes that class: every non-"*"/non-well-formed-ARN value is now uniformly
// MALFORMED (routed to coverage.summary.incomplete), and every well-formed ARN gets
// one deterministic BROAD/NARROW verdict both surfaces read.
//
// classifyResource(value) -> one of RESOURCE_CLASS:
//   BROAD      matches all / nearly-all resources of a service, or spans the
//              account/partition boundary: the bare "*", a wildcard in the
//              partition/service/account segments, a whole-collection identifier
//              wildcard (role/*, accesspoint/*/object/*), a bucket-name-segment
//              wildcard (my-bucket-*/...), or a no-delimiter typed-resource glob
//              (function*, role*) that swallows the type/id boundary.
//   NARROW     pins a concrete resource, optionally with a wildcard only in a
//              SUB-PATH / key AFTER a concrete top-level name
//              (my-bucket/prefix/*, role/deployment/*, role/app-*).
//   MALFORMED  neither "*" nor a well-formed 6-segment ARN (partition + service +
//              resourceId all non-empty), OR carries leading/trailing whitespace,
//              OR (HYBRID default) would only be NARROW under the UNVERIFIED
//              typed-grammar assumption for a service the engine does not model.
//              Per the AWS IAM grammar a Resource element MUST be "*" or an ARN, so
//              anything else is undeployable (MalformedPolicyDocument) and the
//              engine cannot decide its scope. FAIL CLOSED: masked-grant.js routes
//              a MALFORMED value to coverage.summary.incomplete - never a
//              fabricated confident finding, never a bare CLEAN.
//
// Vanilla ES module. No network APIs. No eval/Function. No DOM. No 'node:' imports.
// Deterministic: same value -> same class, every run (no Date/Math.random). Pure
// string comparison of inert policy data; never interpreted as code or markup, and
// never compiled into a regex from input (so no ReDoS surface here).

import { globMatch, withoutBudget } from './glob.js';

export const RESOURCE_CLASS = Object.freeze({
  BROAD: 'BROAD',
  NARROW: 'NARROW',
  MALFORMED: 'MALFORMED',
});

// The two IAM Resource-ARN wildcards: '*' (any run of chars, incl. empty) and '?'
// (exactly one char). A leading one makes a segment unbounded from its head.
const ANY_WILDCARD = /[*?]/;
function hasWildcard(s) {
  return ANY_WILDCARD.test(String(s));
}
function leadingWildcard(s) {
  return /^[*?]/.test(String(s));
}

// S3-on-Outposts collection keywords whose identifier is CONTENT WITHIN a single
// named parent (outpost/<id>/bucket/<name>/object/<key>), not a collection of
// top-level resources. A terminal wildcard on one of these scopes to that one named
// parent's keys and stays NARROW. Every OTHER collection keyword (bucket,
// accesspoint) names the whole collection when wildcarded at the leaf, so it is
// BROAD. Frozen so the set is stable and shared (deterministic, no per-call alloc).
const OUTPOST_CONTENT_LEAF_KEYWORDS = Object.freeze(new Set(['object']));

// Services whose ARN resource-id grammar legitimately BEGINS with '/': the leading
// slash is PART of the grammar, not an empty-leading-segment malformation. API
// Gateway names resources as arn:aws:apigateway:<region>::/restapis/<id>/stages/<name>
// (empty account, resource-id "/restapis/..."), a common, deployable form. For these
// the leading '/' is stripped and the remainder classified under the typed grammar,
// so a concrete API (/restapis/<id>/...) reads NARROW while a whole-collection
// wildcard (/restapis/*, /*) still reads BROAD. EVERY OTHER service keeps the
// fail-closed empty-leading-segment guard below (a leading delimiter there is
// undeployable and its scope undecidable -> MALFORMED). Kept as a set so a second
// such service slots in without re-spelling the rule.
const LEADING_SLASH_SERVICES = Object.freeze(new Set(['apigateway']));

// AWS services whose Resource-ARN grammar the engine MODELS. For a service OUTSIDE
// this set the typed-grammar assumption (a resource id is "type/id" or "type:id") is
// UNVERIFIED, so a would-be-NARROW verdict - which relies on reading the id under
// that grammar - is downgraded to MALFORMED/incomplete rather than reported as
// confidently narrow (the Oliver-approved HYBRID default). A BROAD signal (wildcard
// high in the ARN, whole-collection identifier wildcard) still fires regardless of
// membership: fail-closed is never withheld for an unknown service.
//
// s3 / s3-outposts / sns / sqs have their OWN dedicated handling below (they are
// modeled) and are treated as known there. This set is the modeled TYPED (type/id)
// services. It covers every service the fixtures and rule/escalation catalogs use,
// plus the common AWS services, so no legitimately-scoped ARN is misread as
// undecidable; a genuinely exotic service is the only thing the HYBRID downgrades.
const MODELED_TYPED_SERVICES = Object.freeze(new Set([
  'iam', 'lambda', 'kms', 'secretsmanager', 'ssm', 'ec2', 'dynamodb', 'sts',
  'cloudtrail', 'guardduty', 'config', 'events', 'ecr', 'logs', 'cloudwatch',
  'cloudformation', 'glue', 'sagemaker', 'codebuild', 'datapipeline', 'states',
  'ecs', 'eks', 'rds', 'elasticloadbalancing', 'autoscaling', 'route53', 'acm',
  'athena', 'redshift', 'elasticache', 'es', 'opensearch', 'firehose', 'kinesis',
  'batch', 'efs', 'fsx', 'backup', 'organizations', 'account', 'apigateway',
  'execute-api', 'sso', 'identitystore', 'access-analyzer', 'signin', 'wafv2',
  'network-firewall', 'elasticbeanstalk', 'appsync', 'mq', 'transfer',
]));

// --- Semantic boundary-crossing PROBE battery --------------------------------
// A value that is NOT a well-formed ARN can still be a decidedly BROAD GLOB rather
// than an undecidable literal: "?*" / "*/*" / "**" / "*:*" / "arn*" / a truncated
// wildcard ARN ("arn:aws:?*", "arn:aws:*") each match essentially every resource
// across services and accounts. We decide this SEMANTICALLY - interpret the value as
// an AWS resource glob (case-sensitive; '*' = any run incl. empty, '?' = exactly one
// char) and test what it MATCHES against a fixed battery of diverse, concrete,
// canonical probe ARNs spanning multiple ACCOUNTS and SERVICES. A value matching
// probes across >= 2 DISTINCT ACCOUNTS reaches across the account/service boundary and
// is BROAD; a suffix/infix glob ("*.pem", "*-prod") or a bare literal matches < 2 and
// is undecidable -> MALFORMED. Spelling-agnostic: any NEW glob spelling of the same
// boundary-crossing class matches the same probes, so it cannot be re-spelled around.
//
// This is the ONE place the tool judges a non-ARN glob broad; the must-warn corpus
// locks these boundary-crossing globs as mandatory DATA-EXFIL findings, so the probe
// battery is load-bearing, not decorative. Frozen: fixed, shared, deterministic, no
// per-call allocation. S3 object ARNs encode the owning account in the (globally
// unique) bucket name, so the two S3 probes are tagged as two DISTINCT accounts.
const BROADNESS_PROBES = Object.freeze([
  Object.freeze({ arn: 'arn:aws:s3:::probe-alpha-bucket/data/report.csv', account: 'A' }),
  Object.freeze({ arn: 'arn:aws:s3:::probe-bravo-bucket/logs/2026/app.log', account: 'B' }),
  Object.freeze({ arn: 'arn:aws:iam::100000000001:role/platform/probe-role', account: '100000000001' }),
  Object.freeze({ arn: 'arn:aws:kms:us-east-1:100000000002:key/1111aaaa-2222-bbbb-3333-cccc4444dddd', account: '100000000002' }),
  Object.freeze({ arn: 'arn:aws:sqs:eu-west-1:100000000003:probe-order-queue', account: '100000000003' }),
  Object.freeze({ arn: 'arn:aws:s3:us-east-1:100000000004:accesspoint/probe-ap/object/reports/q1.csv', account: '100000000004' }),
  Object.freeze({ arn: 'probe-non-arn-resource', account: 'N' }),
]);

// Read `value` as an AWS resource glob and count how many DISTINCT probe accounts it
// matches; >= 2 means it crosses the account/service boundary -> broad. Uses the
// shared ReDoS-safe linear matcher, WITHOUT charging the work budget: the fixed
// 7-probe check runs in both the budget-armed rules path and post-analysis coverage
// enrichment, and must neither trip a borderline analysis's ceiling nor re-throw when
// an analysis has already aborted (glob.js withoutBudget). Deterministic; never throws.
function globReachesMultipleAccounts(value) {
  return withoutBudget(() => {
    const accounts = new Set();
    for (const probe of BROADNESS_PROBES) {
      if (globMatch(String(value), probe.arn)) {
        accounts.add(probe.account);
        if (accounts.size >= 2) return true;
      }
    }
    return false;
  });
}

/**
 * Parse an AWS ARN string into its 6 canonical segments.
 *
 * arn : partition : service : region : account : resource(+)   (resource may hold ':')
 *
 * Returns a frozen { partition, service, region, account, resourceId } for a
 * WELL-FORMED ARN (leading 'arn', at least 6 colon segments, and partition +
 * service + resourceId all NON-EMPTY), or null otherwise. Region and account MAY be
 * empty (a canonical S3 bucket ARN, arn:aws:s3:::bucket/key, has both empty).
 *
 * Does NOT trim: a value with leading/trailing whitespace is malformed and the
 * classifier rejects it BEFORE parsing (leading space also makes seg[0] !== 'arn').
 * Pure and deterministic; never throws.
 *
 * @param {*} value the Resource/NotResource element value
 * @returns {{partition:string, service:string, region:string, account:string,
 *            resourceId:string}|null}
 */
export function parseArn(value) {
  const s = String(value == null ? '' : value);
  if (s.length === 0) return null;
  const seg = s.split(':');
  if (seg.length < 6) return null;
  if (seg[0] !== 'arn') return null;
  const partition = seg[1];
  const service = seg[2];
  const region = seg[3];
  const account = seg[4];
  const resourceId = seg.slice(5).join(':');
  if (partition.length === 0 || service.length === 0 || resourceId.length === 0) {
    return null;
  }
  return Object.freeze({ partition, service, region, account, resourceId });
}

// Typed (type/id) resource-identifier breadth. `known` is whether the owning
// service's typed grammar is MODELED (drives the HYBRID would-be-NARROW downgrade).
//   - No delimiter: a bare resource token. A wildcard swallows the whole type/id
//     boundary and matches every resource of that shape (function*, role*) -> BROAD.
//     A concrete bare token pins one resource -> NARROW (known) / MALFORMED (unknown).
//   - Delimited "type/id" or "type:id":
//       * a wildcard in the TYPE keyword matches many resource types -> BROAD;
//       * the FIRST identifier token bare/leading-wildcard names the whole
//         collection of that type (role/*, accesspoint/*/object/*) -> BROAD;
//       * a concrete-prefix name family (role/app-*) or a wildcard only in the
//         SUB-PATH after a concrete top-level name (role/deployment/*) -> NARROW
//         (known) / MALFORMED (unknown).
function classifyTyped(resourceId, known) {
  const firstDelim = resourceId.search(/[/:]/);
  if (firstDelim === -1) {
    if (hasWildcard(resourceId)) return RESOURCE_CLASS.BROAD;
    // A fully-concrete bare token pins one resource regardless of grammar -> NARROW.
    return RESOURCE_CLASS.NARROW;
  }
  const type = resourceId.slice(0, firstDelim);
  const rest = resourceId.slice(firstDelim + 1);
  const name = rest.split(/[/:]/)[0];
  if (hasWildcard(type)) return RESOURCE_CLASS.BROAD;
  if (leadingWildcard(name)) return RESOURCE_CLASS.BROAD;
  // Would-be NARROW. The HYBRID downgrade applies ONLY when the narrowness actually
  // depends on the unverified typed grammar - i.e. there is a wildcard whose
  // confinement to a concrete-prefix name (role/app-*) or sub-path (role/deployment/*)
  // we are ASSUMING. For an UNMODELED service that assumption is unverified, so route
  // to MALFORMED/incomplete rather than confidently narrow. A fully-concrete id (no
  // wildcard anywhere) is one resource regardless of grammar and stays NARROW.
  if (!known && hasWildcard(resourceId)) return RESOURCE_CLASS.MALFORMED;
  return RESOURCE_CLASS.NARROW;
}

// Plain-S3 / regional-S3 breadth. S3 bucket names are a GLOBALLY-UNIQUE, ACCOUNT-LESS
// namespace, so ANY wildcard in the bucket-name (head) segment spans many buckets
// across potentially different owning accounts -> BROAD, whether the wildcard is
// leading ("*-logs/*") or interior/suffix ("my-bucket-*/*.pem"). A region and/or
// account decorating a bucket ARN is itself malformed and must NEVER be read as a
// NARROWING signal, so the head-wildcard verdict is decided by SERVICE, not by whether
// the region/account segments are empty.
//
// A concrete head with EMPTY region+account is a plain bucket name; any deeper
// wildcard is object-key scoped -> NARROW. A concrete head WITH a region/account is a
// typed S3 resource (accesspoint/job/storage-lens); defer to the typed grammar so a
// whole-collection first-identifier wildcard (accesspoint/*/object/*) is caught while
// a concrete one (accesspoint/my-ap/object/*) stays narrow.
function classifyS3(arn) {
  const head = arn.resourceId.split(/[/:]/)[0];
  if (hasWildcard(head)) return RESOURCE_CLASS.BROAD;
  if (arn.region === '' && arn.account === '') return RESOURCE_CLASS.NARROW;
  return classifyTyped(arn.resourceId, true);
}

// S3-on-Outposts nests named resource-collections rather than a flat "type/id": the
// collection keyword alternates with its identifier at each level -
//   outpost/<outpost-id>/bucket/<bucket-id>/object/<key>
//   outpost/<outpost-id>/accesspoint/<ap>/object/<key>
// A leading wildcard on ANY NON-LEAF collection identifier widens the whole subtree
// beneath it -> BROAD. A leading wildcard on the TERMINAL identifier is broad too
// UNLESS it is a content-leaf key (object/<key>) scoped within a concretely-named
// parent collection (that one bucket's object keys, the least-privilege shape). A
// concrete-prefix identifier (bucket/my-bucket-*) is account+outpost-scoped and stays
// NARROW - only a LEADING wildcard names the whole collection. s3-outposts is a
// modeled service, so NARROW here is confident.
function classifyOutposts(resourceId) {
  const idParts = resourceId.split(/[/:]/);
  // Identifier segments sit at odd indices (keyword, id, keyword, id, ...).
  for (let i = 1; i < idParts.length; i += 2) {
    if (!leadingWildcard(idParts[i])) continue;
    const isLeaf = i >= idParts.length - 2;
    if (!isLeaf) return RESOURCE_CLASS.BROAD;
    const keyword = String(idParts[i - 1] || '').toLowerCase();
    if (!OUTPOST_CONTENT_LEAF_KEYWORDS.has(keyword)) return RESOURCE_CLASS.BROAD;
  }
  return RESOURCE_CLASS.NARROW;
}

/**
 * Classify a single Resource / NotResource element value as BROAD, NARROW, or
 * MALFORMED. Pure, deterministic, never throws. This is the single breadth oracle
 * for the whole engine (rules breadth + masked-grant undecidability).
 *
 * @param {*} value the element value (inert policy data)
 * @returns {string} one of RESOURCE_CLASS
 */
export function classifyResource(value) {
  const raw = String(value == null ? '' : value);
  const v = raw.trim();
  const cls = classifyTrimmed(v);
  // Leading/trailing whitespace: AWS rejects it, and an un-trimmed value slipped the
  // old startsWith('arn:') gate (" arn:aws:s3:::bucket/*" read CLEAN). Whitespace must
  // never RESCUE a value into a confident NARROW/clean, so a would-be-NARROW (or a
  // still-MALFORMED) trimmed value is MALFORMED. But a genuinely BROAD trimmed value
  // is broad regardless of the whitespace (" arn:aws:s3:::*" is still all-buckets), so
  // it keeps firing - the must-warn corpus locks that. Fail closed either way.
  if (raw !== v && cls !== RESOURCE_CLASS.BROAD) return RESOURCE_CLASS.MALFORMED;
  return cls;
}

// Classify an ALREADY-TRIMMED value. classifyResource() layers the leading/trailing
// whitespace rule on top.
function classifyTrimmed(v) {
  // An empty element is undeployable per the grammar; fail closed (never CLEAN).
  if (v === '') return RESOURCE_CLASS.MALFORMED;
  // The bare star is the widest possible, unambiguously decided broad scope.
  if (v === '*') return RESOURCE_CLASS.BROAD;

  const arn = parseArn(v);
  if (!arn) {
    // Not "*" and not a well-formed ARN. Two sub-cases, decided SEMANTICALLY:
    //   - a boundary-crossing GLOB that matches diverse canonical resources across
    //     >= 2 accounts ("?*", "*/*", "**", "*:*", "arn*", "arn:aws:?*", "arn:aws:*")
    //     is decidedly BROAD - the must-warn corpus locks these as DATA-EXFIL; or
    //   - a suffix/infix glob ("*.pem", "*-prod"), a bare literal, a URL, or a
    //     truncated "arn:" / "arn:aws" is undeployable per the AWS IAM grammar and its
    //     concrete scope cannot be established -> MALFORMED (masked-grant routes it to
    //     coverage.incomplete; overstating certainty on an undecidable value is itself
    //     a threat-model T8 harm). This is the ONE probe-based broad test in the
    //     engine, shared by rules + masked-grant so the two cannot disagree.
    return globReachesMultipleAccounts(v)
      ? RESOURCE_CLASS.BROAD
      : RESOURCE_CLASS.MALFORMED;
  }

  const service = arn.service.toLowerCase();
  // A wildcard in a HIGH-ORDER segment (partition / service / account) spans
  // essentially every ARN, or every account in the partition, regardless of how the
  // resource identifier is scoped -> BROAD. A concrete-prefixed identifier does NOT
  // re-narrow a wildcard account back to one account.
  if (hasWildcard(arn.partition) || hasWildcard(service) || hasWildcard(arn.account)) {
    return RESOURCE_CLASS.BROAD;
  }

  // LEADING-SLASH-GRAMMAR services (API Gateway): the leading '/' is the grammar,
  // NOT an empty-leading-segment malformation. Strip ONE leading '/' and classify
  // the remainder under the typed grammar so /restapis/<id>/... is read
  // type='restapis', id='<id>' (concrete -> NARROW; whole-collection /restapis/* or
  // /* -> BROAD), instead of being rejected by the empty-leading-segment guard
  // below. Decided BEFORE that guard, and only when the resource-id actually begins
  // with '/', so a colon-leading (or otherwise malformed) apigateway id still fails
  // closed. Placed AFTER the high-order partition/service/account wildcard check, so
  // a genuinely broad ARN is never traded away for this narrower reading.
  if (LEADING_SLASH_SERVICES.has(service) && arn.resourceId.charCodeAt(0) === 47 /* '/' */) {
    return classifyTyped(arn.resourceId.slice(1), true);
  }

  // EMPTY LEADING SEGMENT in the resource-id (resourceId begins with '/' or ':').
  // The resource-TYPE keyword (typed services) / bucket-NAME head (S3) / first
  // collection keyword (outposts) is the EMPTY string, which shifts the real
  // identifier one position over: every service classifier below reads the head/type
  // token as "" (concrete, no wildcard) and the REAL whole-collection keyword as a
  // mere name, so a whole-collection wildcard ('/role/*', '/*', ':role/*') is mis-read
  // NARROW -> bare CLEAN - and even a HIGH-severity bulk read (s3:GetObject @
  // 'arn:aws:s3:::/*') is downgraded to clean. Per the AWS ARN grammar a resource
  // head/type is non-empty, so a leading delimiter is undeployable and its scope is
  // undecidable. Fail CLOSED to MALFORMED (-> coverage.incomplete via masked-grant),
  // NEVER NARROW. Decided ONCE here, centrally, so it covers EVERY downstream
  // classifier (typed / s3 / s3-outposts / sns-sqs) with no per-function reoccurrence
  // to re-spell around. Placed AFTER the high-order partition/service/account wildcard
  // check so a genuinely broad ARN ('arn:aws:iam::*:/role/*') still fires - the
  // high-order BROAD signal is never traded away for MALFORMED.
  if (/^[/:]/.test(arn.resourceId)) return RESOURCE_CLASS.MALFORMED;

  if (service === 's3-outposts') return classifyOutposts(arn.resourceId);
  if (service === 's3') return classifyS3(arn);
  if (service === 'sns' || service === 'sqs') {
    // A flat, ACCOUNT-SCOPED resource NAME (topic / queue). A leading wildcard spans
    // the whole account's topics/queues -> BROAD; a concrete or concrete-prefixed
    // name (my-topic, my-topic-*) is a within-account family -> NARROW.
    if (leadingWildcard(arn.resourceId)) return RESOURCE_CLASS.BROAD;
    return RESOURCE_CLASS.NARROW;
  }
  return classifyTyped(arn.resourceId, MODELED_TYPED_SERVICES.has(service));
}

export default classifyResource;
