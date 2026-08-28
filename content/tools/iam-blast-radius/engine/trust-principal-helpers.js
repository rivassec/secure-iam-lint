// trust-principal-helpers.js - low-level trust-policy predicates: glob/account/ARN narrowing tests + err/deepFreeze/statementSid utils. Extracted (behavior-preserving; self-contained).

export function isAllGlobOrEmpty(v) {
  const s = String(v);
  return s === '' || /^[*?]+$/.test(s);
}

export function hasGlob(s) {
  return s.includes('*') || s.includes('?');
}

// An account-id key (aws:SourceAccount / aws:PrincipalAccount) is a full 12-digit
// number; any wildcard leaves the account unpinned, so a globbed value does not
// narrow. An org-id key (aws:PrincipalOrgID) is o-<body>; a wildcard in the body
// ("o-*") matches every organization, so it does not narrow either. Only a
// complete literal value narrows these keys.
export function accountOrOrgValueNarrows(value) {
  const s = String(value);
  if (s === '') return false;
  return !hasGlob(s);
}

// Whether an ARN's account segment (field index 4:
// arn:partition:service:region:ACCOUNT:resource) is PINNED to a single concrete
// account id. "arn:aws:iam::123456789012:role/app-*" pins account 123456789012;
// "arn:aws:iam::*:role/*" and "arn:aws:*:*:*:*" pin nothing (span every account).
// Shared by arnValueNarrows() (a condition-value narrowing test) and
// principalValueIsBroad() (a Principal-breadth test) so both agree on what
// "bounded to one account" means.
export function arnAccountPinned(s) {
  const segs = String(s).split(':');
  const account = segs.length > 4 ? segs[4] : '';
  return account !== '' && !hasGlob(account);
}

// The CONCRETE account id an ARN pins in its account segment (field index 4), or
// null when that segment is empty or wildcarded. Used by the cross-account foreign-
// scope check (S3-trust-calibration 3): a tight aws:PrincipalArn whose pinned
// account is not one of the named Principal's accounts is itself a cross-account
// ARN and must not narrow the trust WITHIN the trusted account.
export function arnPinnedAccount(s) {
  const segs = String(s).split(':');
  const account = segs.length > 4 ? segs[4] : '';
  return account !== '' && !hasGlob(account) ? account : null;
}

// The set of concrete AWS account ids the named external Principal(s) pin, plus
// whether EVERY account-bearing principal resolved to a concrete account. An
// account/root Principal pins its account; a specific principal-ARN pins its
// account segment; a canonical-user pins none (so `complete` is false). Used to
// decide whether a tight aws:PrincipalArn condition value is SAME-account (a
// genuine sub-account narrowing) or FOREIGN (a cross-account ARN that must not
// lower the finding). When `complete` is false and the account is not found, the
// caller conservatively treats the tight value as foreign (fail closed).
export function namedPrincipalAccounts(principals) {
  const set = new Set();
  let complete = true;
  for (const e of (principals && Array.isArray(principals.entries) ? principals.entries : [])) {
    if (e.type === 'aws-account') {
      set.add(String(e.value));
    } else if (e.type === 'aws-root') {
      const m = /^arn:[^:]*:iam::(\d{12}):root$/i.exec(String(e.value));
      if (m) set.add(m[1]); else complete = false;
    } else if (e.type === 'aws-principal-arn') {
      const acct = arnPinnedAccount(e.value);
      if (acct) set.add(acct); else complete = false;
    } else if (e.type === 'canonical-user') {
      complete = false;
    }
    // federated / service / anonymous entries pin no AWS account for this purpose.
  }
  return { set, complete };
}

// Common AWS ARN resource-TYPE keywords. In an ARN resource of the form
// "<type>/<id>" or "<type>:<id>", the LEADING token is a resource-type CATEGORY
// (role, secret, function, trail, ...), not a specific resource. A value whose
// only surviving literal is such a category keyword - e.g. arn:aws:iam::*:role/*
// (every role in every account) or arn:aws:secretsmanager:*:*:secret:* (every
// secret in every account) - bounds NOTHING (not which account, not which
// resource) and is therefore NOT a confused-deputy scope. Only a concrete
// resource IDENTIFIER narrows. Kept lowercase; matched case-insensitively.
export const ARN_RESOURCE_TYPE_KEYWORDS = new Set([
  'role', 'user', 'group', 'policy', 'instance-profile', 'mfa',
  'server-certificate', 'saml-provider', 'oidc-provider', 'assumed-role',
  'federated-user', 'secret', 'function', 'layer', 'trail', 'key', 'alias',
  'topic', 'queue', 'table', 'instance', 'volume', 'snapshot',
  'security-group', 'subnet', 'vpc', 'stream', 'parameter', 'stack',
  'cluster', 'db', 'rule', 'log-group', 'event-bus', 'pipeline', 'project',
  'repository', 'distribution', 'certificate', 'domain', 'application',
]);

// An ARN key (aws:SourceArn / aws:PrincipalArn) narrows only when a globbed value
// still pins an identifying component. The account segment is the primary
// identifier; if it is a concrete id the ARN narrows. If the account is
// wildcarded/empty, the ARN narrows only when the resource part still pins a
// concrete resource IDENTIFIER (e.g. arn:aws:s3:::specific-bucket). It does NOT
// narrow when the only surviving literal is a bare resource-TYPE keyword before
// the wildcard: arn:aws:iam::*:role/* and arn:aws:secretsmanager:*:*:secret:*
// name a CATEGORY across every account (adversarial-critic IAM-804 iteration 2:
// the resource-literal fallback credited these as confused-deputy constraints and
// slammed a whole-account external trust high->low, stamping a vacuous condition
// into the evidence as a real mitigation - a wrong-provenance under-claim, the
// same class already fixed for pure wildcards). "arn:aws:*:*:*:*" and
// "arn:aws:iam::*:*" pin nothing identifying either, so none of these narrow.
export function arnValueNarrows(value) {
  const s = String(value);
  if (s === '') return false;
  if (!hasGlob(s)) return true; // a fully literal ARN narrows
  if (arnAccountPinned(s)) return true;
  const segs = s.split(':');
  const resource = segs.length > 5 ? segs.slice(5).join(':') : '';
  // Tokenize the resource on path ('/') and sub-resource (':') separators, and
  // require a concrete resource IDENTIFIER token: one that carries a literal
  // (survives wildcard stripping) and is NOT merely a leading resource-TYPE
  // keyword. arn:aws:iam::*:role/* -> ['role','*']: 'role' is a category keyword
  // in first position, '*' is pure wildcard -> nothing concrete -> does not
  // narrow. arn:aws:s3:::specific-bucket/* -> ['specific-bucket','*']:
  // 'specific-bucket' is a concrete id -> narrows.
  const tokens = resource.split(/[/:]/);
  return tokens.some((t, i) => {
    const literal = t.replace(/[*?]/g, '').trim();
    if (literal.length === 0) return false; // a pure-wildcard token pins nothing
    // A bare resource-TYPE keyword in the leading position is a category, not an
    // identifier; it only narrows if a later concrete token accompanies it.
    if (i === 0 && ARN_RESOURCE_TYPE_KEYWORDS.has(literal.toLowerCase())) return false;
    return true;
  });
}

// Whether the NAMED Principal already pins this trust to specific AWS account(s),
// so a wildcard in a condition ARN's ACCOUNT segment (field 4) contributes NO
// breadth: AWS evaluates Principal AND Condition, so the account is fixed by the
// Principal, not by the condition (adversarial iteration-2 findings 3/4). Only an
// account/root Principal or an account-PINNED principal-ARN pins the account; an
// anonymous "*" or an org-wide (non-account-pinned) principal ARN pins nothing.
// Requires EVERY named principal to be account-bounded (`.every`): if any is
// public/org-wide, the account is not universally pinned and a condition account
// wildcard still widens (conservative - never under-claims). Takes a classified
// principal (classifyPrincipals output).
export function principalPinsAccount(principals) {
  if (!principals || principals.anonymous) return false;
  const ext = principals.entries.filter((e) =>
    e.type === 'aws-root' || e.type === 'aws-account' || e.type === 'aws-principal-arn');
  if (ext.length === 0) return false;
  return ext.every((e) => {
    if (e.type === 'aws-root' || e.type === 'aws-account') return true;
    return arnAccountPinned(e.value);
  });
}

// Breadth of a positive aws:PrincipalArn scoping VALUE, INTERSECTED with the named
// Principal (AWS evaluates Principal AND Condition). A glob in an ARN segment the
// Principal already pins - notably the ACCOUNT (field 4) - contributes NO breadth:
// it is fixed by the Principal, not the condition. The value is BROAD only when a
// glob survives in a segment the Principal does NOT pin: the resource IDENTIFIER
// (matches a SET of principals within the account), the account when the Principal
// itself is unpinned/public, or partition/service/region (never pinned by a
// Principal). Uses hasGlob (both '*' AND '?') so a '?'-globbed resource such as
// role/admin? - which matches admin1, adminA, ... - is broad, consistent with the
// OIDC-subject fix (line ~495) and conditions.js (adversarial iteration-2
// finding 4; the pre-fix `values.some(v => v.includes('*'))` missed '?'). When the
// Principal pins the account, arn:aws:iam::*:role/deploy intersects to the single
// role arn:aws:iam::<pinned>:role/deploy - NOT broad (finding 3).
export function principalArnValueIsBroad(value, principalPins) {
  const segs = String(value).split(':');
  // A well-formed ARN has 6 colon-separated fields
  // (arn:partition:service:region:account:resource). FEWER means the value is
  // TRUNCATED/malformed: the account (field 4) and resource (field 5+) segments
  // this breadth test reasons about do not exist, so the value is UNDECIDABLE.
  // An undecidable principal must fail CLOSED (mark broad) - never be silently
  // truncated (segs.slice(0,4) / the old `segs.length > N ? ... : ''` guards) into
  // a spurious NARROW scope. Repro (S7-lows-and-orphan item 4): a public "*" trust
  // scoped by aws:PrincipalArn "arn:aws:iam" (3 fields, no glob) is credited as
  // narrowing by arnValueNarrows (glob-free) and, pre-fix, principalArnValueIsBroad
  // returned false (account='' resource='' pinned nothing) -> the finding was
  // DOWNGRADED critical->medium and mislabeled "a specific principal" (T8
  // overstated certainty). Marking it broad keeps a public trust surfaced at high.
  if (segs.length < 6) return true;
  const account = segs[4];
  const resource = segs.slice(5).join(':');
  const beforeAccount = segs.slice(0, 4); // arn, partition, service, region
  // A value that pins NEITHER an account NOR any resource identifier (both segments
  // empty, e.g. "arn:aws:iam::::") is likewise undecidable -> broad (fail closed).
  if (account === '' && resource === '') return true;
  if (hasGlob(resource)) return true; // a globbed resource identifier -> a SET
  if (hasGlob(account) && !principalPins) return true; // account not pinned by Principal
  if (beforeAccount.some((s) => hasGlob(s))) return true; // partition/service/region glob
  return false;
}

// Dispatch the narrowing test for the trust-relevant scoping keys. Any other key
// (e.g. sts:ExternalId, an OIDC sub) narrows unless it is the empty string or a
// value made entirely of glob metacharacters ('*'/'?', e.g. "*", "?*", "*?") -
// a partial ExternalId carrying a literal still forces the caller to present a
// matching correlation value, so it stays a (weaker) confused-deputy constraint.
export function valueNarrowsKey(key, value) {
  switch (key) {
    case 'aws:sourceaccount':
    case 'aws:principalaccount':
    case 'aws:principalorgid':
      return accountOrOrgValueNarrows(value);
    case 'aws:sourcearn':
    case 'aws:principalarn':
      return arnValueNarrows(value);
    default:
      return !isAllGlobOrEmpty(value);
  }
}

// An all-addresses IP/CIDR range constrains nothing (defect 2: IpAddress
// aws:SourceIp 0.0.0.0/0 - or the IPv6 equivalent - is not a real constraint).
export function isAllAddressIp(v) {
  const s = String(v).trim().toLowerCase();
  return s === '*' || s === '0.0.0.0/0' || s === '0/0' ||
    s === '::/0' || s === '::0/0' || s === '::0' || s === '::';
}

export function err(code, message, path) {
  return { code, message, path: path === undefined ? null : path };
}

export function deepFreeze(value) {
  if (value === null || typeof value !== 'object') return value;
  if (Object.isFrozen(value)) return value;
  Object.freeze(value);
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item);
  } else {
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

export function statementSid(stmt) {
  return typeof stmt.sid === 'string' && stmt.sid.length > 0
    ? stmt.sid
    : `(index ${stmt.index})`;
}

// A statement is a TRUST statement iff it names a Principal and every one of its
// actions is a trust action. (The family gate already guarantees the document is
// role-trust-shaped; this per-statement check keeps analysis grounded.) Exported
// so graph.js can find same-policy trust Deny statements (IAM-806) without
// re-deriving the shape test.
