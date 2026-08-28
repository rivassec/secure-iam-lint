// resource-kms-rules.js - KMS key-policy per-service rules (viaService/grant/anonymous/account-delegation analysis). Extracted (behavior-preserving).
import { accountOfEntry, hasTransportOnlyDeny } from './resource-shared.js';
import { classifyPrincipals } from './trust.js';
import { makeResourceFinding, summarizeEntries, S3_OBJECT_ACTIONS } from './resource-finding.js';
import { principalScopingAnalysis, NETWORK_SELECTOR_KEYS } from './resource-conditions.js';
import { DOC_KMS_CONDITIONS, DOC_KMS_GRANTS, DOC_KMS_KEY_POLICY, RESOURCE_SERVICE_LABELS, RESOURCE_SERVICES } from './resource-catalogs.js';
import { S3_BUCKET_CONTROL_ACTIONS } from './resource-s3-rules.js';

export const KMS_VIA_SERVICE_KEY = 'kms:viaservice';
export const KMS_GRANT_IS_FOR_AWS_RESOURCE_KEY = 'kms:grantisforawsresource';

// The lowercased KMS action name after the "kms:" prefix, or null for a non-KMS or
// wildcarded action (kms:* / kms:Generate* / "*" is never guessed into a specific
// dangerous-action classification - a full "*" already surfaces via the generic
// branches, mirroring S3_OBJECT_ACTIONS / S3_BUCKET_CONTROL_ACTIONS).
export function kmsActionName(action) {
  const m = /^kms:([a-z0-9]+)$/i.exec(String(action));
  return m ? m[1].toLowerCase() : null;
}

// The KMS channel/network decoy keys on a statement's condition (kms:ViaService and
// the aws:Source* network selectors). A "*" narrowed ONLY by these is still
// account-open. Deduped, sorted, original-cased.
export function kmsChannelDecoyKeys(condition) {
  const viaService = new Set();
  const network = new Set();
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) {
    return { viaService: [], network: [] };
  }
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    for (const key of Object.keys(inner)) {
      const kl = String(key).toLowerCase();
      if (kl === KMS_VIA_SERVICE_KEY) viaService.add(key);
      else if (NETWORK_SELECTOR_KEYS.has(kl)) network.add(key);
    }
  }
  return { viaService: [...viaService].sort(), network: [...network].sort() };
}

// True when a condition names kms:GrantIsForAWSResource (any operator). Presence-only
// annotation on a CreateGrant finding; never credited as a full mitigation.
export function namesGrantIsForAwsResource(condition) {
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return false;
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    for (const key of Object.keys(inner)) {
      if (String(key).toLowerCase() === KMS_GRANT_IS_FOR_AWS_RESOURCE_KEY) return true;
    }
  }
  return false;
}

// Whether the key policy contains an account / account-root delegation Allow (the
// "Enable IAM User Permissions"-style statement). Its presence means IAM identity
// policies CAN govern the key; its absence (with no anonymous "*") is the
// silent-key-policy inversion (grounding 3.5).
export function kmsHasAccountDelegation(statements) {
  return statements.some((s) => {
    if (!s || s.effect !== 'Allow') return false;
    const c = classifyPrincipals(s.principal);
    return c.entries.some((e) => e.type === 'aws-account' || e.type === 'aws-root');
  });
}

// Whether the key policy contains any anonymous "*" Allow (every AWS identity in
// every account). When present, no principal is "silent" about the key, so the
// silent-policy inversion warning does not apply.
export function kmsHasAnonymousAllow(statements) {
  return statements.some(
    (s) => s && s.effect === 'Allow' && classifyPrincipals(s.principal).anonymous,
  );
}

// KMS key-policy per-service finding rules (IAM-1403). Pure, deterministic,
// dependency-free; returns a fresh array; never throws; additive to the generic
// findings. Scoped to the kms-key token ONLY.
export function kmsPerServiceRules(model, ctx) {
  const out = [];
  const service = ctx && typeof ctx.service === 'string' ? ctx.service : null;
  if (service !== RESOURCE_SERVICES.KMS_KEY) return out;
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  const attachedArn = ctx && ctx.arn ? ctx.arn : null;
  const serviceLabel = RESOURCE_SERVICE_LABELS[service] || 'AWS KMS key';
  // The key's OWNING account (KMS key ARNs carry it in field 4, or an explicit
  // context account). Distinguishes a confirmed in-account grant from cross-account.
  const resourceAccount = ctx && ctx.ownerAccount != null && /^\d{12}$/.test(String(ctx.ownerAccount))
    ? String(ctx.ownerAccount)
    : null;
  const transportOnlyDeny = hasTransportOnlyDeny(model);
  const externalTypes = new Set(['aws-account', 'aws-root', 'aws-principal-arn']);

  for (const stmt of statements) {
    if (!stmt || stmt.effect !== 'Allow') continue;
    const c = classifyPrincipals(stmt.principal);
    const actions = Array.isArray(stmt.actions) ? stmt.actions : [];
    const names = actions.map(kmsActionName).filter((n) => n !== null);
    const anonEntries = c.entries.filter((e) => e.type === 'anonymous');
    // External or account-undetermined named principals (exclude a CONFIRMED
    // same-account principal: owner known AND principal account known and equal).
    const externalEntries = c.entries.filter((e) => {
      if (!externalTypes.has(e.type)) return false;
      const acct = accountOfEntry(e);
      return !(resourceAccount !== null && acct !== null && acct === resourceAccount);
    });

    // (a) kms:CreateGrant = onward-DELEGATION primitive (grounding 3.4, trap 5). To
    // "*" or a cross-account / account-undetermined principal, the grantee can create
    // grants letting OTHER principals in any account/org (incl. AWS services) use the
    // key, and need not hold the permission itself. Ranked above ordinary key use;
    // NEVER over-claimed as decrypt or effective access.
    if (names.includes('creategrant')) {
      const narrowNote = namesGrantIsForAwsResource(stmt.condition)
        ? ' A kms:GrantIsForAWSResource condition is present, which can narrow ' +
          'kms:CreateGrant to grants created by AWS services on the caller\'s behalf; ' +
          'confirm its operator and value (Bool true) actually constrain the grant.'
        : '';
      const delegWhy = (who) =>
        `The resource policy grants kms:CreateGrant on this ${serviceLabel} to ${who}. ` +
        'kms:CreateGrant is an onward-DELEGATION primitive, not mere key use: a ' +
        'principal that can create grants can issue grants allowing OTHER principals - ' +
        'in your own account or in a different account or organization, including AWS ' +
        'services - to use this key, and those principals need not already hold the ' +
        'permission. Its blast radius is much like kms:PutKeyPolicy. This reports the ' +
        'delegation capability read from the key policy only: it does NOT by itself ' +
        'turn ciphertext into plaintext and does NOT establish that the resulting ' +
        'access is granted - and because the grantee is outside (or not confirmed ' +
        'inside) the key\'s owning account, a request from that account must also be ' +
        'allowed by its own IAM policies.' + narrowNote;
      if (anonEntries.length > 0) {
        out.push(makeResourceFinding(stmt, anonEntries, {
          id: 'KMS-CREATE-GRANT-DELEGATION',
          severity: 'high',
          title: 'kms:CreateGrant granted to every AWS account (onward key-use delegation)',
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why: delegWhy('Principal "*" (every AWS identity in every account)'),
          remediation:
            'Do not grant kms:CreateGrant to Principal "*" or a broad principal. ' +
            'Restrict it to the specific administrative role that manages grants, and ' +
            'where AWS services must create grants on your behalf add ' +
            'kms:GrantIsForAWSResource (Bool true). Treat kms:CreateGrant as a ' +
            'key-control action on par with kms:PutKeyPolicy.',
          docRef: DOC_KMS_GRANTS,
          service,
          attachedArn,
          transportOnlyDeny,
          anonymousReach: false,
        }));
      }
      if (externalEntries.length > 0) {
        out.push(makeResourceFinding(stmt, externalEntries, {
          id: 'KMS-CREATE-GRANT-DELEGATION',
          severity: 'high',
          title: 'kms:CreateGrant granted cross-account (onward key-use delegation)',
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why: delegWhy(
            `a principal outside (or not confirmed inside) the key's owning account ` +
            `(${summarizeEntries(externalEntries)})`,
          ),
          remediation:
            'Do not grant kms:CreateGrant to an external or cross-account principal ' +
            'unless the delegation is required. Scope it to a specific role, and where ' +
            'AWS services must create grants add kms:GrantIsForAWSResource (Bool true). ' +
            'Treat kms:CreateGrant as a key-control action on par with kms:PutKeyPolicy.',
          docRef: DOC_KMS_GRANTS,
          service,
          attachedArn,
          transportOnlyDeny,
        }));
      }
    }

    // (b) kms:PutKeyPolicy = key-policy TAKEOVER / self-expansion (grounding 3.4). To
    // "*" (critical) or a cross-account / account-undetermined principal (high). Never
    // fires for a CONFIRMED same-account principal; never over-claimed as effective.
    if (names.includes('putkeypolicy')) {
      if (anonEntries.length > 0) {
        out.push(makeResourceFinding(stmt, anonEntries, {
          id: 'KMS-KEY-POLICY-TAKEOVER',
          severity: 'critical',
          title: 'kms:PutKeyPolicy granted to every AWS account (key-policy takeover)',
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why:
            `The resource policy grants kms:PutKeyPolicy on this ${serviceLabel} to ` +
            'Principal "*" (every AWS identity in every account). kms:PutKeyPolicy ' +
            'rewrites the key\'s OWN policy - a key-policy TAKEOVER / self-expansion ' +
            'primitive: the grantee can replace the policy to grant itself (or anyone) ' +
            'any further access to the key, a far higher blast radius than a single ' +
            'decrypt. This reports the direct grant only; it does NOT prove the ' +
            'takeover is in effect.',
          remediation:
            'Never grant kms:PutKeyPolicy to Principal "*". Restrict key-policy ' +
            'management to a specific administrative role in the key\'s owning account.',
          docRef: DOC_KMS_GRANTS,
          service,
          attachedArn,
          transportOnlyDeny,
          anonymousReach: false,
        }));
      }
      if (externalEntries.length > 0) {
        out.push(makeResourceFinding(stmt, externalEntries, {
          id: 'KMS-KEY-POLICY-TAKEOVER',
          severity: 'high',
          title: 'kms:PutKeyPolicy granted cross-account (key-policy takeover)',
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why:
            `The resource policy grants kms:PutKeyPolicy on this ${serviceLabel} to a ` +
            `principal outside (or not confirmed inside) the key's owning account ` +
            `(${summarizeEntries(externalEntries)}). kms:PutKeyPolicy rewrites the ` +
            'key\'s OWN policy (key-policy TAKEOVER / self-expansion): the grantee ' +
            'could replace the policy to grant itself or anyone any further access. ' +
            'This is cross-account, so the caller\'s own account must also allow it, ' +
            'and this reports the direct grant only - it does NOT prove the takeover ' +
            'is in effect.',
          remediation:
            'Do not grant kms:PutKeyPolicy to an external or cross-account principal. ' +
            'Keep key-policy management inside the owning account, scoped to a specific ' +
            'administrative role.',
          docRef: DOC_KMS_GRANTS,
          service,
          attachedArn,
          transportOnlyDeny,
        }));
      }
    }

    // (c) A genuinely-broad KMS "*" grant narrowed ONLY by kms:ViaService (or a
    // network selector) - NOT by a principal-identity / account key - is still
    // account-open (trap 2). State the channel selector narrows the request VECTOR,
    // not WHO may act; never downgrade the generic "*" over-grant.
    if (c.anonymous) {
      const { scopingKeys, expansionKeys } = principalScopingAnalysis(stmt.condition, service);
      const principalScoped = expansionKeys.length === 0 && scopingKeys.length > 0;
      if (!principalScoped) {
        const decoys = kmsChannelDecoyKeys(stmt.condition);
        if (decoys.viaService.length > 0 || decoys.network.length > 0) {
          let why =
            `This ${serviceLabel} grants Principal "*" permission to ` +
            `${actions.join(', ')}, and it carries a condition that could be MISREAD ` +
            'as restricting the grant to a specific account or to authenticated ' +
            'principals - but it does not. On KMS, "*" is every AWS identity in every ' +
            'account (KMS has no unauthenticated path), and the following key does not ' +
            'narrow WHO may act:';
          if (decoys.viaService.length > 0) {
            why +=
              ` kms:ViaService (${decoys.viaService.join(', ')}) pins the SERVICE ` +
              'CHANNEL a request must flow through (for example requests made via a ' +
              'service in a Region), not the caller\'s identity - so the key stays open ' +
              'to any account\'s principals whose requests flow through that service.';
          }
          if (decoys.network.length > 0) {
            why +=
              ` A network selector (${decoys.network.join(', ')}) scopes the request ` +
              'to a network path, not to authenticated principals.';
          }
          why +=
            ' Only kms:CallerAccount, aws:PrincipalAccount, or aws:PrincipalOrgID ' +
            'would pin WHO may use the key. This does not downgrade the "*" over-grant.';
          out.push(makeResourceFinding(stmt, anonEntries, {
            id: 'KMS-VIASERVICE-NOT-SCOPING',
            severity: 'high',
            title: 'KMS "*" grant not narrowed by its service-channel / network condition',
            policyEvidence: 'high',
            pathExploitability: 'medium',
            why,
            remediation:
              'Do not rely on kms:ViaService or a network selector to restrict WHO may ' +
              'use a Principal "*" key grant - they pin the request channel/path, not ' +
              'the caller. Add kms:CallerAccount (or aws:PrincipalAccount / ' +
              'aws:PrincipalOrgID) to scope the account, or name the specific ' +
              'principals in the key policy.',
            docRef: DOC_KMS_CONDITIONS,
            service,
            attachedArn,
            transportOnlyDeny,
            principalScopedBy: [],
            anonymousReach: false,
          }));
        }
      }
    }
  }

  // (d) The KMS silent-key-policy inversion (grounding 3.5, tests 115/127). A key
  // policy that OMITS the account-delegation statement AND grants no anonymous "*"
  // means IAM identity policies CANNOT govern the key (inverted vs S3): only the
  // key-policy-named principals can use it, and per-principal effective access is
  // fail-closed UNKNOWN from the key policy alone. Emitted ONCE, policy-level, and
  // surfaced (never dropped) so an empty/near-empty analysis is never read as "safe".
  if (statements.length > 0 && !kmsHasAccountDelegation(statements) && !kmsHasAnonymousAllow(statements)) {
    // Anchor to the first Allow statement (else the first statement) for evidence.
    const anchor = statements.find((s) => s && s.effect === 'Allow') || statements[0];
    const grantsPutKeyPolicy = statements.some(
      (s) => s && s.effect === 'Allow' &&
        (Array.isArray(s.actions) ? s.actions : []).some((a) => kmsActionName(a) === 'putkeypolicy'),
    );
    const putKeyPolicyNote = grantsPutKeyPolicy
      ? ' Note the granted kms:PutKeyPolicy is a key-policy-takeover primitive: it ' +
        'rewrites the key\'s own policy, so a named principal holding it can expand ' +
        'access to the key.'
      : '';
    out.push(makeResourceFinding(anchor, [], {
      id: 'KMS-SILENT-POLICY-UNKNOWN',
      severity: 'info',
      policyEvidence: 'high',
      pathExploitability: 'low',
      title: 'KMS key policy omits account delegation - IAM cannot govern the key (effective access UNKNOWN)',
      why:
        'This KMS key policy does NOT include the account-delegation ("Enable IAM ' +
        'User Permissions") statement (an Allow to the owning account / account-root ' +
        'principal) and grants no "*". This INVERTS the S3 rule: unlike an S3 bucket ' +
        '(where an absent bucket policy still lets the account\'s IAM policies grant ' +
        'access), a KMS key policy does NOT let the owning account\'s IAM identity ' +
        'policies govern the key unless this delegation statement is present - without ' +
        'it IAM allow policies are ineffective (an IAM Deny still applies). So ONLY ' +
        'the principals named in this key policy can use the key, and for any ' +
        'principal the policy is silent about, effective access is fail-closed ' +
        'UNKNOWN from the key policy alone: whether an IAM policy grants use of the ' +
        'key cannot be determined here. This is surfaced rather than dropped - the ' +
        'absence of a broad finding does NOT mean the key is safe or unreachable.' +
        putKeyPolicyNote,
      remediation:
        'Confirm this omission is intentional. If the owning account\'s IAM policies ' +
        'are meant to govern the key, add the standard account-delegation statement ' +
        '(Allow the account-root principal kms:* on Resource "*"). To reason about ' +
        'per-principal access, review the key policy together with the identity ' +
        'policies of every principal it names; the key policy alone is not sufficient.',
      docRef: DOC_KMS_KEY_POLICY,
      service,
      attachedArn,
      transportOnlyDeny,
    }));
  }

  return out;
}
