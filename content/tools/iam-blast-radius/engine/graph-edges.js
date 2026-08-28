// graph-edges.js - finding->edge mapping (RULE_MAP, ESCALATION_MAP) + the per-technique edge builders (role-takeover, self-IAM-modify, wildcard-resource, passrole/ecs-passrole, deny edges, redundant-delegation pruning). Extracted (behavior-preserving).
import { certaintyFromEvidence, classifyCapability, evidenceFromFinding, findingWithActions, findStatement, firstResource, passRoleCertainty } from './graph-helpers.js';
import { CERTAINTY, EDGE_TYPES, LANES, NODE_TYPES, PRINCIPAL_ID } from './graph-catalogs.js';

export const RULE_MAP = {
  'WILDCARD-ACTION': (f, b, certainty) => {
    const key = f.actions.length ? String(f.actions[0]) : '*';
    b.addEdge({
      toId: `actiongroup:${key}`,
      toType: NODE_TYPES.ACTION_GROUP,
      toLabel: `Actions: ${key}`,
      type: EDGE_TYPES.ALLOWS,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: `allows ${key}`,
      lane: LANES.SCOPE,
    });
  },
  'WILDCARD-RESOURCE': (f, b, certainty, model) => wildcardResourceEdges(f, b, certainty, model),
  'DIRECT-IAM-ADMIN': (f, b, certainty) => {
    // IAM-705 (acceptance test 5): credential creation (iam:CreateAccessKey /
    // iam:Create*LoginProfile / iam:Update*LoginProfile) is an impersonation
    // primitive, NOT a self-policy modification - it mints credentials for a
    // principal, it does not rewrite a policy. A DIRECT-IAM-ADMIN finding whose
    // ONLY actions are credential creation therefore must not draw the
    // can-modify(policy:self) edge; the CREDENTIAL-CREATION escalation already
    // draws the credential-target impersonation edge. A wildcard (iam:* / *) or any
    // genuine policy-editing action keeps the self-modify edge.
    if (isCredentialOnlyAdmin(f)) return;
    selfIamModify(f, b, 'direct IAM administration', certainty);
  },
  'NOTACTION-ALLOW': (f, b, certainty) => {
    b.addEdge({
      toId: 'actiongroup:not-action',
      toType: NODE_TYPES.ACTION_GROUP,
      toLabel: 'Actions: every action except a listed few (NotAction)',
      type: EDGE_TYPES.ALLOWS,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'allows all-but-listed',
      lane: LANES.SCOPE,
    });
  },
  'DATA-EXFIL': (f, b, certainty) => {
    b.addEdge({
      toId: 'datastore:sensitive-data',
      toType: NODE_TYPES.DATA_STORE,
      toLabel: 'Sensitive data (secrets / objects)',
      type: EDGE_TYPES.CAN_READ,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'reads sensitive data',
      lane: LANES.DATA_ACCESS,
    });
  },
  // IAM-706: a resource-scoped read whose sensitivity is INFERRED from naming, or
  // whose ARN is policy-variable scoped. Mirrors DATA-EXFIL's data-access lane
  // `can-read` edge so a DATA-READ finding is never silently edgeless, but the
  // target node PRESERVES the finding's actual resource scope (DATA-EXFIL is a
  // broad/unscoped bulk read, keyed to a single generic sensitive-data node),
  // and its certainty stays the deny-aware base passed in (CONTEXT_REQUIRED for
  // the rule's `medium` policyEvidence) - a scoped, inferred read must never
  // claim a confirmed bulk-exfil reach (threat-model T8).
  'DATA-READ': (f, b, certainty) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `datastore:scoped-read:${key}`,
      toType: NODE_TYPES.DATA_STORE,
      toLabel: `Data (scoped read): ${key}`,
      type: EDGE_TYPES.CAN_READ,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can read scoped data',
      lane: LANES.DATA_ACCESS,
    });
  },
  // S2-crossaccount-scoped-surface (B): a whole-container read on a resource in
  // another account. Mirrors DATA-READ's data-access lane can-read edge, but the
  // target node names the cross-account resource scope so the account crossing is
  // visible; certainty stays the deny-aware base passed in.
  'CROSS-ACCOUNT-DATA-READ': (f, b, certainty) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `datastore:cross-account-read:${key}`,
      toType: NODE_TYPES.DATA_STORE,
      toLabel: `Data (cross-account read): ${key}`,
      type: EDGE_TYPES.CAN_READ,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can read cross-account data',
      lane: LANES.DATA_ACCESS,
    });
  },
  // S2-crossaccount-scoped-surface (iteration-5): a whole-container S3 read whose
  // owning account is UNDETERMINABLE (a bare bucket ARN). Draws the same can-read
  // data-access edge so the read is never silently edgeless, but the node names it as
  // account-UNDETERMINED so the graph never implies a confirmed crossing (T8). The
  // rule's `pathExploitability: 'low'` maps the certainty down to CONTEXT_REQUIRED.
  'CROSS-ACCOUNT-DATA-READ-UNDETERMINED': (f, b, certainty) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `datastore:cross-account-undetermined-read:${key}`,
      toType: NODE_TYPES.DATA_STORE,
      toLabel: `Data (read, owning account undetermined): ${key}`,
      type: EDGE_TYPES.CAN_READ,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can read data whose owning account is undetermined',
      lane: LANES.DATA_ACCESS,
    });
  },
  'KMS-DECRYPT': (f, b, certainty) => {
    b.addEdge({
      toId: 'datastore:kms-decrypt',
      toType: NODE_TYPES.DATA_STORE,
      toLabel: 'KMS-decryptable ciphertext',
      // Decryption of caller-supplied ciphertext for usable keys (IAM-103). This
      // is its OWN edge type `can-decrypt` (IAM-202), distinct from a plain
      // `can-read` data read: it turns ciphertext into plaintext, it does NOT
      // enumerate or retrieve secret material.
      type: EDGE_TYPES.CAN_DECRYPT,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can decrypt ciphertext',
      lane: LANES.DATA_ACCESS,
    });
  },
  'DESTRUCTIVE-ACTION': (f, b, certainty) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      type: EDGE_TYPES.CAN_DESTROY,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can destroy',
      lane: LANES.SCOPE,
    });
  },
  'DETECTION-IMPAIRMENT': (f, b, certainty) => {
    b.addEdge({
      toId: 'service:detection',
      toType: NODE_TYPES.SERVICE,
      toLabel: 'Security telemetry (CloudTrail / GuardDuty / Config)',
      type: EDGE_TYPES.CAN_MODIFY,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can stop/delete telemetry',
      lane: LANES.SCOPE,
    });
  },
  // IAM-1005: adding a user to a group assigns privilege INDIRECTLY through the
  // group. The edge targets the group Resource node (the group is what the ARN
  // scopes; the added user is a request parameter, not resource-scoped), and its
  // certainty stays potential - the group's real permissions are unknown.
  'GROUP-MEMBERSHIP': (f, b) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Group: ${key}`,
      type: EDGE_TYPES.CAN_MODIFY,
      // A group whose actual policies are unknown -> the assignment's reach is a
      // potential, name-inferred one, never confirmed from this policy.
      certainty: CERTAINTY.POTENTIALLY_REACHABLE,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can add a user to this group',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  },
};

// Escalation (escalation.js) mappings.
export const ESCALATION_MAP = {
  'PASSROLE-LAMBDA': (f, b) => passRoleEdges(f, b),
  'PASSROLE-EC2': (f, b) => passRoleEdges(f, b),
  'PASSROLE-SERVICE': (f, b) => passRoleEdges(f, b),
  // Escalation findings arrive with same-policy Deny already folded into
  // policyEvidence by escalation.js (fully-blocked paths are suppressed there), so
  // their edge certainty comes straight from policyEvidence.
  'POLICY-VERSION': (f, b) =>
    selfIamModify(f, b, 'managed-policy version manipulation', certaintyFromEvidence(f.policyEvidence)),
  'ATTACH-POLICY': (f, b) =>
    selfIamModify(f, b, 'attach managed policy', certaintyFromEvidence(f.policyEvidence)),
  'PUT-INLINE-POLICY': (f, b) =>
    selfIamModify(f, b, 'write inline policy', certaintyFromEvidence(f.policyEvidence)),
  'TRUST-POLICY-MODIFY': (f, b) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `role:${key}`,
      toType: NODE_TYPES.ROLE,
      toLabel: `Role: ${key}`,
      type: EDGE_TYPES.CAN_MODIFY,
      certainty: certaintyFromEvidence(f.policyEvidence),
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can rewrite trust policy',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  },
  'CREDENTIAL-CREATION': (f, b) => {
    b.addEdge({
      toId: 'principal:credential-target',
      toType: NODE_TYPES.PRINCIPAL,
      toLabel: 'Target principal (credential recipient)',
      type: EDGE_TYPES.CAN_MODIFY,
      certainty: certaintyFromEvidence(f.policyEvidence),
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can mint credentials for',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  },
  'ASSUME-ROLE-EXPANSION': (f, b) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `role:${key}`,
      toType: NODE_TYPES.ROLE,
      toLabel: `Role: ${key}`,
      type: EDGE_TYPES.CAN_ASSUME,
      // The reachable roles (and their power) are genuinely not known from this
      // policy: a broad wildcard scope is a POTENTIAL expansion, not a confirmed
      // one, regardless of how unconditional the sts:AssumeRole grant is.
      certainty: CERTAINTY.POTENTIALLY_REACHABLE,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can assume (broad role scope)',
      lane: LANES.IDENTITY_EXPANSION,
    });
  },
  // S2-crossaccount-scoped-surface (A): a scoped sts:AssumeRole whose target role is
  // in a DIFFERENT account. Draws a can-assume edge to the concrete cross-account
  // role node, at potentially-reachable certainty - the assume depends on the target
  // role's (out-of-scope) trust policy, so it is a POTENTIAL cross-account transition,
  // never a confirmed one.
  'CROSS-ACCOUNT-ASSUME-ROLE': (f, b) => {
    const key = firstResource(f);
    b.addEdge({
      toId: `role:${key}`,
      toType: NODE_TYPES.ROLE,
      toLabel: `Role: ${key}`,
      type: EDGE_TYPES.CAN_ASSUME,
      certainty: CERTAINTY.POTENTIALLY_REACHABLE,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'can assume (cross-account role)',
      lane: LANES.IDENTITY_EXPANSION,
    });
  },
  // IAM-902: the modify-then-assume role-takeover chain renders as same-role typed
  // edges - the principal can MODIFY the role (grant it permissions + rewrite its
  // trust) and can ASSUME it - both pointing at the one role node, so the takeover
  // linkage is explicit and no generic can-write aggregation is used.
  'ROLE-TAKEOVER': (f, b) => roleTakeoverEdges(f, b),
};

// IAM-902: draw the role-takeover linkage with per-statement evidence (IAM-701).
// A can-modify edge (the grant-permissions + modify-trust legs) and a can-assume
// edge (the assume leg) both target the SAME role node, so the same-role
// modify-then-assume chain is visible as two distinctly-typed edges. Each edge
// carries ONLY its own leg's statement + actions, never the finding's combined
// action list re-attributed to the anchor.
export function roleTakeoverEdges(f, b) {
  const role = firstResource(f);
  const roleId = `role:${role}`;
  const ev = Array.isArray(f.evidence) ? f.evidence : [];
  const modifyEv = ev.filter((e) => e && (e.role === 'grant-permissions' || e.role === 'modify-trust'));
  const assumeEv = ev.filter((e) => e && e.role === 'assume');
  // Modify leg(s): the grant/trust grants are literally in the policy -> the edge
  // is confirmed-by-policy (a gating Condition already lowered policyEvidence).
  for (const leg of modifyEv) {
    b.addEdge({
      toId: roleId,
      toType: NODE_TYPES.ROLE,
      toLabel: `Role: ${role}`,
      type: EDGE_TYPES.CAN_MODIFY,
      certainty: certaintyFromEvidence(f.policyEvidence),
      finding: edgeEvidenceCarrier(f, leg),
      statementIndex: leg.statementIndex,
      label: 'can grant permissions to / rewrite the trust policy of this role',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  }
  // Assume leg(s): assuming the re-trusted role is a POLICY-SUPPORTED transition -
  // the grant is present, but the actual elevation depends on what the modify leg
  // writes onto the role and any permission boundary / SCP capping it (out of scope).
  for (const leg of assumeEv) {
    b.addEdge({
      toId: roleId,
      toType: NODE_TYPES.ROLE,
      toLabel: `Role: ${role}`,
      type: EDGE_TYPES.CAN_ASSUME,
      certainty: CERTAINTY.POLICY_SUPPORTED,
      finding: edgeEvidenceCarrier(f, leg),
      statementIndex: leg.statementIndex,
      label: 'can assume this role once its trust policy permits it',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  }
}

// IAM credential-creation actions (impersonation primitives). A DIRECT-IAM-ADMIN
// finding whose actions are EXACTLY (case-insensitively) these - and nothing that
// edits a policy - represents credential minting, not self-policy modification, so
// it must not draw the can-modify(policy:self) edge (IAM-705, acceptance test 5).
// Concrete tokens only: a wildcard like "iam:*" is not in this set (it also grants
// policy-editing actions), so a wildcard admin grant keeps the self-modify edge.
export const CREDENTIAL_ONLY_ADMIN_ACTIONS = new Set([
  'iam:createaccesskey',
  'iam:createloginprofile',
  'iam:updateloginprofile',
]);
export function isCredentialOnlyAdmin(f) {
  const actions = Array.isArray(f.actions) ? f.actions : [];
  return (
    actions.length > 0 &&
    actions.every((a) => CREDENTIAL_ONLY_ADMIN_ACTIONS.has(String(a).toLowerCase()))
  );
}

// IAM self-administration primitives (direct-admin rule + policy escalations) all
// point at a single Policy node: the principal can rewrite its own permissions.
export function selfIamModify(f, b, label, certainty) {
  b.addEdge({
    toId: 'policy:self',
    toType: NODE_TYPES.POLICY,
    toLabel: 'IAM permissions (self-administration)',
    type: EDGE_TYPES.CAN_MODIFY,
    certainty,
    finding: f,
    statementIndex: f.statementIndex,
    label,
    // IAM self-administration is a privilege-escalation primitive.
    lane: LANES.PRIVILEGE_ESCALATION,
  });
}

// WILDCARD-RESOURCE broad-scope grant -> per-capability typed edges (IAM-702).
// The finding covers a statement whose actions have a broad resource scope
// (Resource "*" or a NotResource fence). Rather than aggregate every action into
// one generic `can-write` edge (which merges unlike capabilities - reads,
// decrypts, delegation, destroys - into one meaningless edge), split the actions
// by capability and draw ONE distinctly-typed edge per capability kind:
//   read       -> can-read     (to the broad resource node)
//   destroy    -> can-destroy  (to the broad resource node; merges with any
//                               DESTRUCTIVE-ACTION edge on the same resource so a
//                               destroy is can-destroy, NOT also can-write)
//   decrypt    -> can-decrypt  (to the shared kms-decrypt datastore; merges with
//                               any KMS-DECRYPT edge - decryption is not a write)
//   delegation -> can-pass     (iam:PassRole to a passable-role pivot; a
//                               delegation edge only. It does NOT create an
//                               execution path - no compatible service-execution
//                               primitive is asserted here, so no can-execute-as.
//                               A later dedup drops this generic pivot when a
//                               compound PassRole path already draws a specific
//                               per-service pivot for the same grant.)
//   write      -> can-write    (genuine broad mutation: create/update/put/"*"/etc)
// Each edge's evidence carries ONLY its own capability's actions, so no action is
// attributed to an edge it does not belong to (provenance, IAM-701/702).
//
// An Allow+NotAction statement is a complement grant ("everything except a listed
// few"); its finding `actions` are the EXCLUDED set, not a concrete granted list,
// so per-action capability typing would be meaningless. For that shape we keep
// the single broad-scope `can-write` edge (unchanged legacy behavior; complement
// semantics are handled elsewhere) rather than typing the exclusion list.
export function wildcardResourceEdges(f, b, certainty, model) {
  const key = firstResource(f);
  const stmt = findStatement(model, f.statementIndex);
  const isNotAction = !!(stmt && Array.isArray(stmt.notActions) && stmt.notActions.length > 0);
  if (isNotAction) {
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      type: EDGE_TYPES.CAN_WRITE,
      certainty,
      finding: f,
      statementIndex: f.statementIndex,
      label: 'broad write scope (all-but-listed)',
      lane: LANES.SCOPE,
    });
    return;
  }

  // Group the granted actions by capability, preserving order + determinism.
  // Type edges from the STATEMENT's full action set, not the finding's `actions`:
  // IAM-1006 narrows the WILDCARD-RESOURCE finding row to the remediable (non-read)
  // actions, but the graph is the full per-action capability view and must still
  // draw the can-read edge for an enumeration/read action in the same statement
  // (acceptance test 24). Falls back to the finding actions if the statement is
  // unavailable. The NotAction complement path returned above.
  const typedActions = stmt && Array.isArray(stmt.actions)
    ? stmt.actions
    : (Array.isArray(f.actions) ? f.actions : []);
  const groups = { read: [], destroy: [], decrypt: [], delegation: [], write: [] };
  for (const a of typedActions) {
    groups[classifyCapability(a)].push(a);
  }

  if (groups.read.length > 0) {
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      type: EDGE_TYPES.CAN_READ,
      certainty,
      finding: findingWithActions(f, groups.read),
      statementIndex: f.statementIndex,
      label: 'broad read scope',
      lane: LANES.SCOPE,
    });
  }
  if (groups.destroy.length > 0) {
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      type: EDGE_TYPES.CAN_DESTROY,
      certainty,
      finding: findingWithActions(f, groups.destroy),
      statementIndex: f.statementIndex,
      label: 'can destroy',
      lane: LANES.SCOPE,
    });
  }
  if (groups.decrypt.length > 0) {
    b.addEdge({
      toId: 'datastore:kms-decrypt',
      toType: NODE_TYPES.DATA_STORE,
      toLabel: 'KMS-decryptable ciphertext',
      type: EDGE_TYPES.CAN_DECRYPT,
      certainty,
      finding: findingWithActions(f, groups.decrypt),
      statementIndex: f.statementIndex,
      label: 'can decrypt ciphertext',
      lane: LANES.DATA_ACCESS,
    });
  }
  if (groups.delegation.length > 0) {
    b.addEdge({
      toId: 'role:passable',
      toType: NODE_TYPES.ROLE,
      toLabel: 'Passable role [unknown privileges]',
      toExtra: { unknownPrivileges: true },
      type: EDGE_TYPES.CAN_PASS,
      certainty,
      finding: findingWithActions(f, groups.delegation),
      statementIndex: f.statementIndex,
      label: 'can pass a role (delegation)',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  }
  if (groups.write.length > 0) {
    b.addEdge({
      toId: `resource:${key}`,
      toType: NODE_TYPES.RESOURCE,
      toLabel: `Resource: ${key}`,
      type: EDGE_TYPES.CAN_WRITE,
      certainty,
      finding: findingWithActions(f, groups.write),
      statementIndex: f.statementIndex,
      label: 'broad write scope',
      lane: LANES.SCOPE,
    });
  }
}

// PassRole escalations encode the PRIVILEGE TRANSITION, not just the service
// sequence (IAM-107). The graph walks the actual pivot:
//
//   Principal --can-pass (iam:PassRole)--> Passable role [unknown privileges]
//            --can-execute-as (service action)--> Service execution
//                                                 (potential privilege-boundary crossing)
//
// The intermediate ROLE node is the crux: the analyzer KNOWS the principal can
// pass a role to the service and make the service run as it (both grants are in
// the policy text), but it does NOT know that role's actual permissions - so
// whether this crosses a privilege boundary is genuinely unknown from this
// policy alone (threat-model T8: never overclaim). `unknownPrivileges` marks
// that node so the renderer can visually separate what is known (the two edges)
// from what is not (the role's power); `boundaryCrossing` marks the service node
// as the potential crossing point. The passed-role ARN(s) ride in the edge
// evidence (`resources`). Both edges take the PassRole transition certainty
// (IAM-202): even with both grants unconditional the transition is
// `policy-supported`, never `confirmed-by-policy`, because a usable target role
// / accepting trust config is an out-of-scope precondition this policy cannot
// prove. A gating Condition (already folded into policyEvidence by
// escalation.js) weakens it further.
export function passRoleEdges(f, b) {
  const svc = f.escalation && f.escalation.service ? String(f.escalation.service) : 'service';
  const certainty = passRoleCertainty(f.policyEvidence);
  const roleId = `role:passable:${svc}`;
  const svcId = `service:${svc}`;
  // IAM-701: attach PER-STATEMENT evidence to each transition edge. A compound
  // PassRole path is distributed across statements (the PassRole grant in one,
  // the service-execution action in another); the finding's evidence[] already
  // holds the correct per-statement records (role 'pass' / 'execute'). The
  // edges MUST carry those same records, not the finding's combined action list
  // re-attributed to the anchor statement - otherwise the can-execute-as edge
  // would claim the exec action came from the PassRole statement (the provenance
  // defect this story fixes). Each edge therefore takes only the actions +
  // statement of its own leg.
  const passEv = Array.isArray(f.evidence) ? f.evidence.find((e) => e && e.role === 'pass') : null;
  const execEv = Array.isArray(f.evidence) ? f.evidence.find((e) => e && e.role === 'execute') : null;
  const passFinding = edgeEvidenceCarrier(f, passEv);
  const execFinding = edgeEvidenceCarrier(f, execEv);
  // IAM-1005: ECS renders the task role and the execution role as SEPARATE nodes
  // (never merged). The task role is the application-credential path (can-pass ->
  // task role -> can-execute-as -> ECS execution); the execution role is startup/
  // pull/logs/secrets influence only (a can-pass edge, NO application can-execute-as
  // edge, no invented task-role node when only the execution role is passable).
  if (svc === 'ecs' && f.escalation && f.escalation.ecs
    && (f.escalation.ecs.taskRoles.length > 0 || f.escalation.ecs.executionRoles.length > 0
      || f.escalation.ecs.hasLaunch === false)) {
    ecsPassRoleEdges(f, b, svc, svcId, certainty, passEv, execEv, passFinding, execFinding);
    return;
  }
  // Hop 1 (KNOWN): the principal can pass a role to the service.
  b.addEdge({
    toId: roleId,
    toType: NODE_TYPES.ROLE,
    toLabel: 'Passable role [unknown privileges]',
    toExtra: { unknownPrivileges: true },
    type: EDGE_TYPES.CAN_PASS,
    certainty,
    finding: passFinding,
    statementIndex: passEv ? passEv.statementIndex : f.statementIndex,
    label: `can pass a role to ${svc}`,
    lane: LANES.PRIVILEGE_ESCALATION,
  });
  // Hop 2 (KNOWN grant, UNKNOWN reach): the service executes as that passed
  // role - a potential privilege-boundary crossing whose blast radius depends on
  // the role's (unknown) privileges. Source is the passable-role pivot from hop 1.
  b.addEdge({
    fromId: roleId,
    toId: svcId,
    toType: NODE_TYPES.SERVICE,
    toLabel: `Service: ${svc} execution`,
    toExtra: { boundaryCrossing: true },
    type: EDGE_TYPES.CAN_EXECUTE_AS,
    certainty,
    finding: execFinding,
    statementIndex: execEv ? execEv.statementIndex : f.statementIndex,
    label: `executes as the passed role (potential privilege-boundary crossing)`,
    lane: LANES.PRIVILEGE_ESCALATION,
  });
}

// IAM-1005: ECS-specific transition edges keeping the task role and execution role
// as distinct nodes (suite-2 test 38, suite-3 tests 87/88/89/90). The application
// task role is the credential-exposure path (can-pass -> task role -> can-execute-as
// -> ECS execution, only when a launch action is present); the execution role gets
// a can-pass edge only (startup/pull/logs/secrets influence), never an application
// can-execute-as edge, and no task-role node is invented when only the execution
// role is passable.
export function ecsPassRoleEdges(f, b, svc, svcId, certainty, passEv, execEv, passFinding, execFinding) {
  const ecs = f.escalation.ecs;
  const hasLaunch = ecs.hasLaunch !== false;
  const passStmtIndex = passEv ? passEv.statementIndex : f.statementIndex;
  const execStmtIndex = execEv ? execEv.statementIndex : f.statementIndex;
  // The application-credential path uses the TASK role; an unclassified role is
  // treated conservatively as a possible task role (same as the finding severity).
  const taskCapable = ecs.taskRoles.length > 0 || ecs.unknownRoles.length > 0;
  const hasExec = ecs.executionRoles.length > 0;

  if (taskCapable) {
    const taskRoleId = 'role:passable:ecs:task';
    b.addEdge({
      toId: taskRoleId,
      toType: NODE_TYPES.ROLE,
      toLabel: 'Passable ECS task role [unknown privileges]',
      toExtra: { unknownPrivileges: true, ecsRole: 'task' },
      type: EDGE_TYPES.CAN_PASS,
      certainty,
      finding: passFinding,
      statementIndex: passStmtIndex,
      label: 'can pass the application task role to ECS',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
    // Only a launch action (RunTask/StartTask) actually runs the task and yields
    // the task role's credentials. Staging alone (RegisterTaskDefinition) draws no
    // execution edge - this principal cannot launch it (test 90).
    if (hasLaunch) {
      b.addEdge({
        fromId: taskRoleId,
        toId: svcId,
        toType: NODE_TYPES.SERVICE,
        toLabel: `Service: ${svc} execution`,
        toExtra: { boundaryCrossing: true },
        type: EDGE_TYPES.CAN_EXECUTE_AS,
        certainty,
        finding: execFinding,
        statementIndex: execStmtIndex,
        label: 'application code obtains the task role (potential privilege-boundary crossing)',
        lane: LANES.PRIVILEGE_ESCALATION,
      });
    }
  }

  if (hasExec) {
    // Execution-role influence only: image pulls, log delivery, secret injection at
    // startup. NO application can-execute-as edge (the app does not receive these
    // credentials), so the node is distinct from the task-role credential path.
    b.addEdge({
      toId: 'role:passable:ecs:execution',
      toType: NODE_TYPES.ROLE,
      toLabel: 'Passable ECS execution role [startup: image pull / logs / secrets]',
      toExtra: { unknownPrivileges: true, ecsRole: 'execution' },
      type: EDGE_TYPES.CAN_PASS,
      certainty,
      finding: passFinding,
      statementIndex: passStmtIndex,
      label: 'can pass the ECS execution role (startup influence, not application credentials)',
      lane: LANES.PRIVILEGE_ESCALATION,
    });
  }
}

// IAM-701: build a finding-shaped evidence carrier for ONE transition edge from a
// single per-statement escalation evidence record. evidenceFromFinding() reads
// {id, statementSid, statementIndex, actions, resources, conditions}; the
// escalation evidence record stores its condition under `condition` (singular),
// so it is remapped to `conditions` here. Falls back to the whole finding when a
// leg's evidence record is somehow absent (defensive; escalation.js always emits
// both a 'pass' and an 'execute' record for a compound path).
export function edgeEvidenceCarrier(finding, ev) {
  if (!ev) return finding;
  return {
    id: finding.id,
    statementSid: typeof ev.statementSid === 'string' ? ev.statementSid : finding.statementSid,
    statementIndex: typeof ev.statementIndex === 'number' ? ev.statementIndex : finding.statementIndex,
    actions: Array.isArray(ev.actions) ? ev.actions.slice() : [],
    resources: Array.isArray(ev.resources) ? ev.resources.slice() : [],
    conditions: ev.condition === undefined ? null : ev.condition,
  };
}

// --- Model Deny statements -> `denies` edges (blocked-by-deny) ----------------
// Findings only cover the Allow side (a Deny never grants blast radius, so it is
// not a finding). But the graph should still SHOW same-policy Denies, since an
// explicit Deny is the single most decisive fact about reachability. Each Deny
// statement becomes one `denies` edge to an ActionGroup node describing what it
// blocks. An unconditional Deny is `blocked-by-deny`; a conditional one is only
// `context-required` (it may not fire).
export function addDenyEdges(model, b) {
  for (const stmt of model.statements) {
    if (stmt.effect !== 'Deny') continue;
    const usesNotAction = stmt.notActions.length > 0;
    const actions = usesNotAction ? stmt.notActions : stmt.actions;
    const key = usesNotAction ? `not-action#${stmt.index}` : `deny#${stmt.index}`;
    const conditioned = stmt.condition !== null && stmt.condition !== undefined;
    const label = usesNotAction
      ? 'denied: every action except a listed few (NotAction)'
      : `denied: ${actions.join(', ') || '(none)'}`;
    // Synthesize a finding-shaped evidence carrier so the edge carries the same
    // {statementSid, statementIndex, actions, resources, condition} shape.
    const pseudo = {
      id: 'DENY',
      statementSid:
        typeof stmt.sid === 'string' && stmt.sid.length > 0 ? stmt.sid : `(index ${stmt.index})`,
      statementIndex: stmt.index,
      actions: actions.slice(),
      resources:
        stmt.resources.length > 0
          ? stmt.resources.slice()
          : stmt.notResources.length > 0
            ? stmt.notResources.slice()
            : ['(no Resource/NotResource specified)'],
      conditions: stmt.condition,
    };
    b.addEdge({
      toId: `actiongroup:${key}`,
      toType: NODE_TYPES.ACTION_GROUP,
      toLabel: label,
      type: EDGE_TYPES.DENIES,
      certainty: conditioned
        ? CERTAINTY.CONTEXT_REQUIRED
        : CERTAINTY.BLOCKED_BY_DENY,
      finding: pseudo,
      statementIndex: stmt.index,
      label: usesNotAction ? 'denies all-but-listed' : 'denies',
      lane: LANES.EXPLICIT_DENY,
    });
  }
}

// Drop the generic `role:passable` delegation edge (from a standalone broad
// iam:PassRole) when a specific per-service passable-role pivot
// (`role:passable:<svc>`, drawn by a compound PassRole escalation) already
// represents the same delegation. Operates on the builder's node/edge Maps
// BEFORE ordering/freezing. Removes the now-orphan generic node too. Pure,
// deterministic, never throws.
export function dropRedundantGenericDelegation(nodes, edges) {
  const GENERIC = 'role:passable';
  const genericEdgeId = `${PRINCIPAL_ID}|${EDGE_TYPES.CAN_PASS}|${GENERIC}`;
  if (!edges.has(genericEdgeId)) return;
  let hasSpecific = false;
  for (const e of edges.values()) {
    if (e.type === EDGE_TYPES.CAN_PASS && e.to.startsWith(`${GENERIC}:`)) {
      hasSpecific = true;
      break;
    }
  }
  if (!hasSpecific) return;
  edges.delete(genericEdgeId);
  // Remove the orphan node only if no surviving edge still references it.
  let referenced = false;
  for (const e of edges.values()) {
    if (e.from === GENERIC || e.to === GENERIC) {
      referenced = true;
      break;
    }
  }
  if (!referenced) nodes.delete(GENERIC);
}

// --- Public entry points -----------------------------------------------------

/**
 * Build the graph data structure from a normalized model and its findings.
 * Never throws.
 *
 * @param {object} model normalized, frozen model from buildModel()
 * @param {Array<object>} findings rule + escalation findings (canonical shape)
 * @returns {{ok:boolean, errors:Array<{code:string,message:string,path:?string}>,
 *            graph:{nodes:Array, edges:Array, truncated:boolean,
 *                   limits:{maxNodes:number, maxEdges:number}}}}
 */
