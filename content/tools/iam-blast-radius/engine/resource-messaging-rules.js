// resource-messaging-rules.js - SNS/SQS per-service rules (public/cross-account access + data-plane vectors). Extracted (behavior-preserving).
import { accountOfEntry, hasTransportOnlyDeny } from './resource-shared.js';
import { classifyPrincipals } from './trust.js';
import { makeResourceFinding, summarizeEntries } from './resource-finding.js';
import { principalScopingAnalysis } from './resource-conditions.js';
import { DOC_CROSS_ACCOUNT, DOC_SNS_ACCESS, DOC_SQS_ACCESS, RESOURCE_SERVICE_LABELS, RESOURCE_SERVICES } from './resource-catalogs.js';

export const MESSAGING_DATA_PLANE_VECTORS = Object.freeze({
  'sns:subscribe':
    'anyone can attach their own endpoint as a subscriber and EXFILTRATE every ' +
    'message published to the topic thereafter',
  'sns:publish':
    'anyone can INJECT arbitrary messages into the topic, which are then fanned out ' +
    'to every subscriber',
  'sqs:receivemessage':
    'anyone can DRAIN/read the messages in the queue',
  'sqs:sendmessage':
    'anyone can INJECT/poison the queue with arbitrary messages',
  'sqs:deletemessage':
    'anyone can DELETE messages from the queue (denying them to legitimate consumers)',
});

// Messaging policy-CONTROL actions (lowercased action name after the ns: prefix): the
// grantee can rewrite the topic/queue access policy or its attributes - a
// resource-policy TAKEOVER / self-expansion primitive. Per namespace so an sns action
// is never matched against the sqs set (and vice-versa). Wildcards (sns:* / sqs:* /
// "*") are handled separately as a superset that INCLUDES these, mirroring how the S3
// and KMS rules never guess a control-plane takeover from an opaque wildcard yet the
// story asks a messaging service-wildcard to be named as including queue/topic control.
export const SNS_CONTROL_ACTIONS = Object.freeze(new Set([
  'addpermission', 'removepermission', 'settopicattributes',
]));
export const SQS_CONTROL_ACTIONS = Object.freeze(new Set([
  'addpermission', 'removepermission', 'setqueueattributes',
]));

// The {ns, name} of a messaging action, or null for a non-sns/sqs or wildcarded
// action. A full-service wildcard (sns:* / sqs:*) and the global "*" are reported via
// isMessagingServiceWildcard(); a specific action name is matched exactly.
export function messagingActionParts(action) {
  const m = /^(sns|sqs):([a-z0-9]+)$/i.exec(String(action));
  return m ? { ns: m[1].toLowerCase(), name: m[2].toLowerCase() } : null;
}

// True when an action is a full messaging-service wildcard for this service (sns:* on
// an SNS topic, sqs:* on an SQS queue) or the global "*". Such a wildcard LITERALLY
// includes the policy-control actions (AddPermission / SetTopicAttributes /
// SetQueueAttributes), so naming it as including topic/queue control is a fact about
// the wildcard's superset, not a guess about an opaque action.
export function isMessagingServiceWildcard(action, ns) {
  const a = String(action).trim().toLowerCase();
  return a === '*' || a === `${ns}:*`;
}

// The control-action set for a messaging namespace.
export function messagingControlSet(ns) {
  return ns === 'sns' ? SNS_CONTROL_ACTIONS : SQS_CONTROL_ACTIONS;
}

// Whether a statement's condition names aws:SourceOwner (any operator). Presence-only:
// the deprecated legacy source-binding key (chiefly SNS). Case-insensitive.
export function namesSourceOwner(condition) {
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) return false;
  for (const op of Object.keys(condition)) {
    const inner = condition[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) continue;
    for (const key of Object.keys(inner)) {
      if (String(key).toLowerCase() === 'aws:sourceowner') return true;
    }
  }
  return false;
}

// Shared SNS/SQS messaging per-service finding rules (IAM-1404). Pure, deterministic,
// dependency-free; returns a fresh array; never throws; additive to the generic
// findings. Scoped to the sns / sqs tokens ONLY.
export function messagingPerServiceRules(model, ctx) {
  const out = [];
  const service = ctx && typeof ctx.service === 'string' ? ctx.service : null;
  if (service !== RESOURCE_SERVICES.SNS && service !== RESOURCE_SERVICES.SQS) return out;
  const ns = service === RESOURCE_SERVICES.SNS ? 'sns' : 'sqs';
  const statements = (model && Array.isArray(model.statements)) ? model.statements : [];
  const attachedArn = ctx && ctx.arn ? ctx.arn : null;
  const serviceLabel = RESOURCE_SERVICE_LABELS[service] || (ns === 'sns' ? 'Amazon SNS topic' : 'Amazon SQS queue');
  const resourceLabel = ns === 'sns' ? 'topic' : 'queue';
  // The resource's OWNING account (explicit context account, else the SNS/SQS ARN's
  // account). Distinguishes a confirmed in-account grant from a cross-account takeover.
  const resourceAccount = ctx && ctx.ownerAccount != null && /^\d{12}$/.test(String(ctx.ownerAccount))
    ? String(ctx.ownerAccount)
    : null;
  const transportOnlyDeny = hasTransportOnlyDeny(model);
  const externalTypes = new Set(['aws-account', 'aws-root', 'aws-principal-arn']);
  const controlSet = messagingControlSet(ns);

  for (const stmt of statements) {
    if (!stmt || stmt.effect !== 'Allow') continue;
    const c = classifyPrincipals(stmt.principal);
    const actions = Array.isArray(stmt.actions) ? stmt.actions : [];
    const anonEntries = c.entries.filter((e) => e.type === 'anonymous');
    // External or account-undetermined named principals (exclude a CONFIRMED
    // same-account principal: owner known AND principal account known and equal).
    const externalEntries = c.entries.filter((e) => {
      if (!externalTypes.has(e.type)) return false;
      const acct = accountOfEntry(e);
      return !(resourceAccount !== null && acct !== null && acct === resourceAccount);
    });
    const serviceEntries = c.entries.filter((e) => e.type === 'service');

    // (a) Public data-plane exposure. Fires ONLY when a genuinely-public "*" grant
    // (anonymous, not narrowed by a principal-identity key - that is the generic
    // "narrowed" high finding) names a dangerous messaging data-plane action. Names
    // the specific vector (exfiltrate / inject / drain / poison). Additive to the
    // generic critical PUBLIC-ACCESS: it never downgrades or suppresses it.
    if (c.anonymous) {
      const { scopingKeys, expansionKeys } = principalScopingAnalysis(stmt.condition, service);
      const principalScoped = expansionKeys.length === 0 && scopingKeys.length > 0;
      if (!principalScoped) {
        const vectors = [];
        for (const a of actions) {
          const parts = messagingActionParts(a);
          if (!parts || parts.ns !== ns) continue;
          const desc = MESSAGING_DATA_PLANE_VECTORS[`${parts.ns}:${parts.name}`];
          if (desc) vectors.push({ action: a, desc });
        }
        if (vectors.length > 0) {
          const vectorList = vectors
            .map((v) => `${v.action} to Principal "*" means ${v.desc}`)
            .join('; ');
          out.push(makeResourceFinding(stmt, anonEntries, {
            id: 'MESSAGING-PUBLIC-EXPOSURE',
            severity: 'high',
            title: `Public messaging grant on this ${serviceLabel} exposes a data-plane vector`,
            policyEvidence: 'high',
            pathExploitability: 'medium',
            why:
              `This ${serviceLabel} grants Principal "*" a dangerous messaging ` +
              `data-plane action, so ${vectorList}. On ${ns === 'sqs' ? 'Amazon SQS a ' +
                'Principal "*" grant is "all users (anonymous users)" per AWS, i.e. ' +
                'genuinely anonymous public access' : 'Amazon SNS a Principal "*" grant ' +
                'is a public wildcard-principal grant'} - anyone can perform the action ` +
              'on the attached resource. This names the specific blast-radius vector ' +
              'in addition to the generic public-access finding; it does NOT downgrade ' +
              'that finding, and it reports the direct resource-policy grant only, not ' +
              'proven effective access.',
            remediation:
              `Remove Principal "*" from this ${resourceLabel} policy and name the ` +
              'specific accounts, roles, or (source-bound) services that must use the ' +
              `${resourceLabel}. If a broad audience is genuinely intended, scope it ` +
              'with a principal-identity condition (aws:PrincipalOrgID, ' +
              'aws:PrincipalArn, aws:PrincipalAccount) - a network/transport condition ' +
              'does not restrict WHO may act.',
            docRef: ns === 'sns' ? DOC_SNS_ACCESS : DOC_SQS_ACCESS,
            service,
            attachedArn,
            transportOnlyDeny,
            // This "*" is genuinely anonymous (not narrowed), so no principal-scoping
            // key is credited; the anonymous reach flag stays true (structural default).
            principalScopedBy: [],
          }));
        }
      }
    }

    // (b) Policy-CONTROL takeover. A messaging control action (AddPermission /
    // RemovePermission / SetTopicAttributes / SetQueueAttributes), or a full-service
    // sns:*/sqs:*/"*" wildcard that INCLUDES them, granted to an anonymous "*"
    // (critical) or to a principal outside (or not confirmed inside) the owning
    // account (high), is a topic/queue-policy TAKEOVER / self-expansion primitive.
    // Ranked above a data-plane action; NEVER over-claimed as effective takeover.
    const explicitControl = actions.filter((a) => {
      const parts = messagingActionParts(a);
      return parts && parts.ns === ns && controlSet.has(parts.name);
    });
    const wildcardControl = actions.some((a) => isMessagingServiceWildcard(a, ns));
    if (explicitControl.length > 0 || wildcardControl) {
      const controlNames = ns === 'sns'
        ? 'sns:AddPermission / sns:RemovePermission / sns:SetTopicAttributes'
        : 'sqs:AddPermission / sqs:RemovePermission / sqs:SetQueueAttributes';
      const includedVia = explicitControl.length > 0
        ? `the ${resourceLabel}-policy control action(s) ${explicitControl.join(', ')}`
        : `a full-service ${ns}:* (or "*") wildcard, which INCLUDES the ` +
          `${resourceLabel}-policy control actions (${controlNames})`;
      if (anonEntries.length > 0) {
        out.push(makeResourceFinding(stmt, anonEntries, {
          id: 'MESSAGING-POLICY-TAKEOVER',
          severity: 'critical',
          title: `Public grant of a messaging ${resourceLabel}-policy control action (resource-policy takeover)`,
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why:
            `This ${serviceLabel} grants Principal "*" ${includedVia}. These are not ` +
            `data-plane actions: ${controlNames} let the grantee REWRITE the ` +
            `${resourceLabel}'s own access policy or attributes - a resource-policy ` +
            'TAKEOVER / self-expansion primitive with a far higher blast radius than a ' +
            'single publish/subscribe/send/receive, because the grantee can rewrite the ' +
            'policy to grant itself (or anyone) any further access. Granting it to "*" ' +
            'means any principal could take over the ' + resourceLabel + ' policy. This ' +
            'reports the direct resource-policy grant only; it does NOT prove the ' +
            'takeover is effective.',
          remediation:
            `Never grant ${resourceLabel}-policy control actions (${controlNames}) - or ` +
            `a ${ns}:* / "*" wildcard that includes them - to Principal "*". Restrict ` +
            'them to a specific administrative role in the resource-owning account.',
          docRef: ns === 'sns' ? DOC_SNS_ACCESS : DOC_SQS_ACCESS,
          service,
          attachedArn,
          transportOnlyDeny,
        }));
      }
      if (externalEntries.length > 0) {
        const who = summarizeEntries(externalEntries);
        out.push(makeResourceFinding(stmt, externalEntries, {
          id: 'MESSAGING-POLICY-TAKEOVER',
          severity: 'high',
          title: `Cross-account grant of a messaging ${resourceLabel}-policy control action (resource-policy takeover)`,
          policyEvidence: 'high',
          pathExploitability: 'medium',
          why:
            `This ${serviceLabel} grants a principal outside (or not confirmed inside) ` +
            `the resource-owning account (${who}) ${includedVia}. These are not ` +
            `data-plane actions: they let the grantee REWRITE the ${resourceLabel}'s ` +
            'own access policy or attributes (resource-policy TAKEOVER / self-expansion), ' +
            'a far higher blast radius than a single send/receive/publish/subscribe - the ' +
            'grantee could rewrite the policy to grant itself or anyone any further ' +
            'access. This is a cross-account grant, so it is a NECESSARY but not ' +
            'SUFFICIENT condition: the caller\'s own account must ALSO allow the action, ' +
            'and this reports the direct resource-policy grant only - it does NOT prove ' +
            'the takeover is effective.',
          remediation:
            `Do not grant ${resourceLabel}-policy control actions (${controlNames}) - or ` +
            `a ${ns}:* / "*" wildcard that includes them - to an external or ` +
            'cross-account principal. Keep policy management inside the resource-owning ' +
            'account, scoped to a specific administrative role.',
          docRef: DOC_CROSS_ACCOUNT,
          service,
          attachedArn,
          transportOnlyDeny,
        }));
      }
    }

    // (c) Deprecated aws:SourceOwner legacy source binding. When a SERVICE principal
    // grant carries aws:SourceOwner, the generic RESOURCE-CONFUSED-DEPUTY already
    // treats it as source-bound (a present binding, not a missing one). This additive
    // note recognizes it as a LEGACY (deprecated) key and recommends migrating to
    // aws:SourceArn / aws:SourceAccount (chiefly an SNS consideration). Info; never a
    // missing-binding warning and never a public-write claim (a service is not "*").
    if (serviceEntries.length > 0 && namesSourceOwner(stmt.condition)) {
      const svcWho = summarizeEntries(serviceEntries);
      out.push(makeResourceFinding(stmt, serviceEntries, {
        id: 'MESSAGING-DEPRECATED-SOURCE-OWNER',
        severity: 'info',
        title: 'Service grant uses the deprecated aws:SourceOwner legacy source binding',
        policyEvidence: 'high',
        pathExploitability: 'low',
        why:
          `This ${serviceLabel} grants an AWS service principal (${svcWho}) with an ` +
          'aws:SourceOwner condition. aws:SourceOwner IS a present (legacy) ' +
          'confused-deputy source binding - so this is NOT a missing source binding, and ' +
          'the service principal is NOT public write (a service is not "*") - but it is ' +
          'DEPRECATED: AWS states new services can integrate with Amazon SNS only through ' +
          'aws:SourceArn and aws:SourceAccount, though existing integrations retain ' +
          'backward compatibility. The binding still governs only the confused-deputy ' +
          'vector and does not by itself establish that the overall grant is safe or ' +
          'effective.',
        remediation:
          'Migrate the source binding from the deprecated aws:SourceOwner to ' +
          'aws:SourceArn (ArnEquals / ArnLike, scoped to the specific calling source ' +
          'resource) and/or aws:SourceAccount (StringEquals, the source account). Keep ' +
          'the binding in sync with the intended calling source.',
        docRef: DOC_SNS_ACCESS,
        service,
        attachedArn,
        transportOnlyDeny,
      }));
    }
  }

  return out;
}
