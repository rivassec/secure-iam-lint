// resource-s3-rules.js - S3 bucket-policy per-service rules (public/cross-account/BPA-decoy/request-property analysis). Extracted (behavior-preserving).
import { accountOfEntry, hasTransportOnlyDeny } from './resource-shared.js';
import { classifyPrincipals } from './trust.js';
import { makeResourceFinding, summarizeEntries } from './resource-finding.js';
import { principalScopingAnalysis, NETWORK_SELECTOR_KEYS } from './resource-conditions.js';
import { DOC_CROSS_ACCOUNT, DOC_S3_BPA, DOC_S3_POLICY_KEYS, RESOURCE_SERVICE_LABELS, RESOURCE_SERVICES } from './resource-catalogs.js';

export const S3_BUCKET_CONTROL_ACTIONS = Object.freeze(new Set([
  'putbucketpolicy', 'deletebucketpolicy', 'putbucketacl',
  'putbucketpublicaccessblock',
]));

export function isS3BucketControlAction(action) {
  const m = /^s3:(.+)$/.exec(String(action).toLowerCase());
  return m ? S3_BUCKET_CONTROL_ACTIONS.has(m[1]) : false;
}

// Request-property condition keys: they constrain the REQUEST (its transport, TLS
// version, or the object's server-side-encryption header), NOT which principal may
// act (section 1.3). A Deny gated only on these keys is exactly like the
// aws:SecureTransport Deny of test 28 - good hygiene, but it never makes a public
// "*" Allow private. Lowercased. aws:SecureTransport is shared with the generic
// transport-only recognition; s3:TlsVersion and s3:x-amz-server-side-encryption are
// the S3-specific additions this per-service rule recognizes (trap 3).
export const S3_REQUEST_PROPERTY_KEYS = Object.freeze(new Set([
  'aws:securetransport', 's3:tlsversion', 's3:x-amz-server-side-encryption',
]));

// s3:ResourceAccount / aws:ResourceAccount pin the BUCKET-OWNER account, not the
// caller's identity (section 1.4), so they never narrow a "*" principal to
// authenticated callers. Lowercased.
export const S3_RESOURCE_ACCOUNT_KEYS = Object.freeze(new Set([
  's3:resourceaccount', 'aws:resourceaccount',
]));

// A single Condition block is REQUEST-PROPERTY-only when every key it names is a
// request-property key (transport / TLS / SSE). Mirrors isTransportOnlyCondition's
// fail-closed shape: an unrecognized key makes it "not request-property-only", so a
// real identity constraint is never understated. Case-insensitive.
export function isRequestPropertyOnlyCondition(condition) {
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return false;
  const ops = Object.keys(condition);
  if (ops.length === 0) return false;
  for (const op of ops) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object') return false;
    for (const key of Object.keys(inner)) {
      if (!S3_REQUEST_PROPERTY_KEYS.has(String(key).toLowerCase())) return false;
    }
  }
  return true;
}

// The request-property keys named by any Deny statement whose condition is
// request-property-ONLY, deduped, sorted, original-cased. Such a Deny never
// privatizes a public Allow (section 1.3). Empty when no such Deny is present.
export function collectRequestPropertyDenyKeys(statements) {
  const keys = new Set();
  for (const s of statements) {
    if (!s || s.effect !== 'Deny') continue;
    if (!isRequestPropertyOnlyCondition(s.condition)) continue;
    const cond = s.condition;
    for (const op of Object.keys(cond)) {
      const inner = cond[op];
      if (!inner || typeof inner !== 'object') continue;
      for (const key of Object.keys(inner)) keys.add(key);
    }
  }
  return [...keys].sort();
}

// The S3-specific NON-principal condition keys present on a single statement that a
// reader might mistake for narrowing a "*" grant, split by role: network selectors
// (aws:SourceIp / SourceVpc / SourceVpce - anonymous WITHIN that network) and
// resource-account keys (s3:ResourceAccount / aws:ResourceAccount - the bucket owner,
// not the caller). Deduped, sorted, original-cased. Never includes a principal-
// identity key (those genuinely narrow and are handled by the generic path).
export function s3NonPrincipalDecoyKeys(condition) {
  const network = new Set();
  const resourceAccount = new Set();
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) {
    return { network: [], resourceAccount: [] };
  }
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    for (const key of Object.keys(inner)) {
      const kl = String(key).toLowerCase();
      if (NETWORK_SELECTOR_KEYS.has(kl)) network.add(key);
      else if (S3_RESOURCE_ACCOUNT_KEYS.has(kl)) resourceAccount.add(key);
    }
  }
  return { network: [...network].sort(), resourceAccount: [...resourceAccount].sort() };
}

// S3 per-service finding rules (IAM-1402). Pure, deterministic, dependency-free;
// returns a fresh array; never throws; additive to the generic findings.
export function s3PerServiceRules(model, ctx) {
  const out = [];
  const service = ctx && typeof ctx.service === 'string' ? ctx.service : null;
  if (service !== RESOURCE_SERVICES.S3_BUCKET && service !== RESOURCE_SERVICES.S3_OBJECT) {
    return out;
  }
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  const attachedArn = ctx && ctx.arn ? ctx.arn : null;
  const serviceLabel = RESOURCE_SERVICE_LABELS[service] || 'Amazon S3 bucket';
  // The bucket's OWNING account (explicit context account; S3 ARNs carry none), used
  // to distinguish a confirmed in-account admin grant from a cross-account takeover.
  const resourceAccount = ctx && ctx.ownerAccount != null && /^\d{12}$/.test(String(ctx.ownerAccount))
    ? String(ctx.ownerAccount)
    : null;
  const transportOnlyDeny = hasTransportOnlyDeny(model);

  // Model-level request-property-only Denys (SSE / TLS / SecureTransport). A Deny on
  // any of these constrains the request, not WHO may act, so it never privatizes a
  // public Allow (section 1.3; generalizes test 28 to the S3-specific keys, trap 3).
  const requestPropertyDenyKeys = collectRequestPropertyDenyKeys(statements);

  // The Block-Public-Access fail-closed caveat carried on every S3 public/broad
  // per-service finding (section 1.5): BPA is a separate external control that is not
  // part of the policy and is not supplied - the analyzer never assumes it on or off.
  const pabCaveat =
    ' Whether this grant is actually reachable ALSO depends on S3 Block Public ' +
    'Access (BPA), a separate account/bucket/access-point/org-level control that ' +
    'overrides a public bucket policy and is enforced regardless of how the resource ' +
    'was created. BPA is not part of this policy document and is not supplied here; ' +
    'the analyzer never assumes BPA is on or off, and unsupported context does not ' +
    'mean the resource is exposure-free.';

  const externalTypes = new Set(['aws-account', 'aws-root', 'aws-principal-arn']);

  for (const stmt of statements) {
    if (!stmt || stmt.effect !== 'Allow') continue;
    const c = classifyPrincipals(stmt.principal);
    const actions = Array.isArray(stmt.actions) ? stmt.actions : [];

    // (c) Bucket-CONTROL takeover. A bucket-control action granted to an anonymous
    // "*" or to a principal outside the bucket-owning account is a resource-policy
    // TAKEOVER / self-expansion primitive, ranked above a data-plane action. It is
    // NEVER over-claimed as proven effective takeover (a cross-account grant still
    // needs the caller's own account to allow it).
    const controlActions = actions.filter(isS3BucketControlAction);
    if (controlActions.length > 0) {
      const anonEntries = c.entries.filter((e) => e.type === 'anonymous');
      if (anonEntries.length > 0) {
        out.push(makeResourceFinding(stmt, anonEntries, {
          id: 'S3-BUCKET-POLICY-TAKEOVER',
          severity: 'critical',
          title: 'Public grant of an S3 bucket-policy control action (resource-policy takeover)',
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why:
            `The resource policy grants Principal "*" the bucket-CONTROL action(s) ` +
            `${controlActions.join(', ')} on this ${serviceLabel}. These are not ` +
            'data-plane actions: s3:PutBucketPolicy / s3:DeleteBucketPolicy / ' +
            's3:PutBucketAcl / s3:PutBucketPublicAccessBlock let the grantee REWRITE ' +
            'the bucket\'s own resource policy, ACLs, or public-access-block settings - ' +
            'a resource-policy TAKEOVER / self-expansion primitive with a far higher ' +
            'blast radius than a single object read or write, because the grantee can ' +
            'rewrite the policy to grant itself (or anyone) any further access. ' +
            'Granting it to "*" means any principal, including anonymous callers, ' +
            'could take over the bucket policy. This reports the direct resource-policy ' +
            'grant only; it does NOT prove the takeover is effective.' + pabCaveat,
          remediation:
            'Never grant bucket-control actions (s3:PutBucketPolicy, s3:PutBucketAcl, ' +
            's3:PutBucketPublicAccessBlock, s3:DeleteBucketPolicy) to Principal "*". ' +
            'Restrict them to a specific administrative role in the bucket-owning ' +
            'account and manage the bucket policy through change-controlled automation ' +
            'rather than a broad in-policy grant.',
          docRef: DOC_S3_BPA,
          service,
          attachedArn,
          transportOnlyDeny,
        }));
      }
      const externalEntries = c.entries.filter((e) => {
        if (!externalTypes.has(e.type)) return false;
        const acct = accountOfEntry(e);
        // Exclude a CONFIRMED same-account principal (owner known AND principal
        // account known and equal): an in-account admin grant is not a takeover
        // exposure. An external or account-undetermined principal fails closed here.
        return !(resourceAccount !== null && acct !== null && acct === resourceAccount);
      });
      if (externalEntries.length > 0) {
        const who = summarizeEntries(externalEntries);
        out.push(makeResourceFinding(stmt, externalEntries, {
          id: 'S3-BUCKET-POLICY-TAKEOVER',
          severity: 'high',
          title: 'Cross-account grant of an S3 bucket-policy control action (resource-policy takeover)',
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why:
            `The resource policy grants a principal outside (or not confirmed inside) ` +
            `the bucket-owning account (${who}) the bucket-CONTROL action(s) ` +
            `${controlActions.join(', ')} on this ${serviceLabel}. These are not ` +
            'data-plane actions: they let the grantee REWRITE the bucket\'s own ' +
            'resource policy, ACLs, or public-access-block settings (resource-policy ' +
            'TAKEOVER / self-expansion), a far higher blast radius than an object read ' +
            'or write - the grantee could rewrite the policy to grant itself or anyone ' +
            'any further access. This is a cross-account grant, so it is a NECESSARY ' +
            'but not SUFFICIENT condition: the caller\'s own account must ALSO allow ' +
            'the action, and this reports the direct resource-policy grant only - it ' +
            'does NOT prove the takeover is effective.' + pabCaveat,
          remediation:
            'Do not grant bucket-control actions (s3:PutBucketPolicy, s3:PutBucketAcl, ' +
            's3:PutBucketPublicAccessBlock, s3:DeleteBucketPolicy) to an external or ' +
            'cross-account principal. Keep bucket-policy management inside the ' +
            'bucket-owning account, scoped to a specific administrative role.',
          docRef: DOC_CROSS_ACCOUNT,
          service,
          attachedArn,
          transportOnlyDeny,
        }));
      }
    }

    // (a)/(b) Public "*" NOT narrowed by a decoy condition/Deny. Fires ONLY when a
    // genuinely-public "*" grant (not narrowed by a principal-IDENTITY key - that is
    // the generic "narrowed" finding) carries an S3-specific NON-principal condition
    // or a request-property Deny that could be MISREAD as narrowing it: a network
    // selector, s3:ResourceAccount, or an SSE/TLS/SecureTransport Deny. It states
    // plainly that the decoy does NOT privatize/narrow the grant - the "*" still
    // reaches anonymous callers. It never downgrades the generic critical
    // PUBLIC-ACCESS finding.
    if (c.anonymous) {
      const { scopingKeys, expansionKeys } = principalScopingAnalysis(stmt.condition, service);
      const principalScoped = expansionKeys.length === 0 && scopingKeys.length > 0;
      if (!principalScoped) {
        const decoys = s3NonPrincipalDecoyKeys(stmt.condition);
        const hasDecoy = decoys.network.length > 0 || decoys.resourceAccount.length > 0
          || requestPropertyDenyKeys.length > 0;
        if (hasDecoy) {
          const anonEntries = c.entries.filter((e) => e.type === 'anonymous');
          let why =
            `This ${serviceLabel} grants Principal "*" permission to ` +
            `${actions.join(', ')}, and it carries an S3-specific condition or Deny ` +
            'that could be MISREAD as restricting the grant to authenticated ' +
            'principals - but it does not. The "*" still reaches ANONYMOUS, ' +
            'unauthenticated callers (S3 object access can be made by unauthenticated ' +
            'HTTP clients).';
          if (decoys.network.length > 0) {
            why +=
              ` A network selector (${decoys.network.join(', ')}) scopes the grant to a ` +
              'network range, but a network selector is NOT a principal-identity ' +
              'constraint: any caller - including an anonymous, unauthenticated one - ' +
              'whose request originates from that network range is still permitted. S3 ' +
              'may classify such a policy as no longer open to the whole internet, but ' +
              'that is not the same as restricting access to authenticated principals.';
          }
          if (decoys.resourceAccount.length > 0) {
            why +=
              ` A resource-account key (${decoys.resourceAccount.join(', ')}) pins the ` +
              'BUCKET-OWNER account, not the caller\'s identity, so it does not exclude ' +
              'anonymous callers and does not narrow WHO may act.';
          }
          if (requestPropertyDenyKeys.length > 0) {
            why +=
              ` A request-property Deny (${requestPropertyDenyKeys.join(', ')}) ` +
              'constrains the REQUEST (its transport, TLS version, or the object\'s ' +
              'server-side-encryption header) - exactly like an aws:SecureTransport ' +
              'Deny (test 28) - and does NOT constrain WHO may act, so it does not make ' +
              'this public grant private.';
          }
          why += pabCaveat;
          out.push(makeResourceFinding(stmt, anonEntries, {
            id: 'S3-PUBLIC-NOT-NARROWED',
            severity: 'high',
            title: 'S3 public "*" grant not narrowed by its network / resource-account / request-property condition',
            policyEvidence: 'high',
            pathExploitability: 'medium',
            why,
            remediation:
              'Do not rely on a network selector (aws:SourceIp / aws:SourceVpc / ' +
              'aws:SourceVpce), a resource-account key (s3:ResourceAccount), or a ' +
              'request-property Deny (aws:SecureTransport / s3:TlsVersion / ' +
              's3:x-amz-server-side-encryption) to make a Principal "*" grant private - ' +
              'none of them restrict WHO may act. Remove Principal "*" and name the ' +
              'specific principals, or add a principal-identity condition ' +
              '(aws:PrincipalOrgID / aws:PrincipalArn / aws:PrincipalAccount). Verify S3 ' +
              'Block Public Access as well.',
            docRef: DOC_S3_POLICY_KEYS,
            service,
            attachedArn,
            transportOnlyDeny,
            // Deliberately empty: this "*" is NOT narrowed to authenticated
            // principals, so no principal-scoping key is credited (the graph must not
            // read an anonymous origin as condition-scoped).
            principalScopedBy: [],
          }));
        }
      }
    }
  }
  return out;
}
