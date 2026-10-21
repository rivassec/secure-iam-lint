// guardrail-deny.js - what the SCP/RCP evaluators model in a guardrail Deny.
// In a Deny every AND'd condition narrows when the Deny fires, so an unevaluated key
// is fail-OPEN there (unlike an identity Allow). Each family gets its own allow-list
// of (key, operator) shapes; anything else is unmodeled (exit 3).
import { parseOperator } from './conditions.js';
import { globMatch } from './glob.js';
import { substitutePolicyVars } from './trust-conditions.js';
import { KNOWN_PARTITIONS } from './escalation-reachability.js';

const STRING_OPS = new Set(['stringequals', 'stringnotequals', 'stringequalsignorecase',
  'stringnotequalsignorecase', 'stringlike', 'stringnotlike']);
const ARN_OPS = new Set(['arnequals', 'arnnotequals', 'arnlike', 'arnnotlike']);
const BOOL_VALUES = new Set(['true', 'false']);

const REGION = 'aws:requestedregion';
const MFA = 'aws:multifactorauthpresent';
const P_ARN = 'aws:principalarn';
const P_ACCT = 'aws:principalaccount';
const P_ORG = 'aws:principalorgid';
const P_ORG_PATHS = 'aws:principalorgpaths';
const S_ORG = 'aws:sourceorgid';
const S_ORG_PATHS = 'aws:sourceorgpaths';
const S_ACCT = 'aws:sourceaccount';
const IS_SVC = 'aws:principalisawsservice';
const ORG_KEYS = new Set([P_ORG, P_ORG_PATHS, S_ORG, S_ORG_PATHS]);
const SOURCE_KEYS = new Set([S_ORG, S_ORG_PATHS, S_ACCT]);

// Probes every real value of a key matches; matching all of them matches everything.
export const PROBE_REGIONS = ['us-east-1', 'eu-west-2', 'ap-southeast-1', 'cn-north-1',
  'us-gov-west-1', 'il-central-1', 'us-isob-east-1'];
const PROBE_ROLES = ['arn:aws:iam::111122223333:role/zzqj3cafe',
  'arn:aws:iam::444455556666:role/aws-reserved/sso.amazonaws.com/aw9kxbolt'];
// One account per leading digit, so a partial glob union is not "every account" (B-07).
const PROBE_ACCOUNTS = ['111122223333', '444455556666',
  ...'02356789'.split('').map((d) => `${d}12345678901`)];
const PROBE_PRINCIPALS = PROBE_ROLES.concat(['arn:aws:iam::111122223333:user/zzqj3cafe'],
  PROBE_ACCOUNTS.filter((a) => a !== '111122223333').map((a) => `arn:aws:iam::${a}:root`));
// Every principal shape in the subject account (B-04).
const subjectRoles = (a) => [`arn:aws:iam::${a}:role/zzqj3cafe`,
  `arn:aws:iam::${a}:role/aws-reserved/sso.amazonaws.com/aw9kxbolt`];
const subjectPrincipals = (a) => subjectRoles(a).concat([`arn:aws:iam::${a}:user/zzqj3cafe`,
  `arn:aws:iam::${a}:root`]);
// Services RCPs govern (docs/scp-rcp-semantics.md); others are out of RCP scope (B-08).
const RCP_SERVICES = new Set(['s3', 'sqs', 'kms', 'sts', 'secretsmanager', 'logs', 'ecr',
  'dynamodb', 'cognito-identity', 'aoss']);
const PROBE_SERVICES = ['s3', 'iam', 'ec2', 'kms', 'sqs'];

const lc = (v) => String(v).toLowerCase();
const valuesOf = (raw) => (Array.isArray(raw) ? raw : [raw]).map((v) => String(v));

// Does the value list (OR'd) match every probe? Like/Arn ops glob; Equals is literal.
// A ${...} value is caller-chosen, so it reads as '*' under any operator.
function unionMatchesAll(base, vals, probes) {
  const glob = base.endsWith('like') || ARN_OPS.has(base);
  const pats = vals.map((v) => (v.includes('${') || glob
    ? { g: true, v: lc(substitutePolicyVars(v)) } : { g: false, v: lc(v) }));
  return probes.every((p) => pats.some((x) => (x.g ? globMatch(x.v, lc(p)) : x.v === lc(p))));
}
// Any key: a negated match whose value is all-glob or a variable never fires.
const matchAllValue = (e) => e.negated && (e.base.endsWith('like') || ARN_OPS.has(e.base) || STRING_OPS.has(e.base)) &&
  e.vals.some((v) => v.includes('${') || ((e.base.endsWith('like') || ARN_OPS.has(e.base)) && /^[*]+$/.test(v)));

function entriesOf(cond) {
  const out = [];
  if (!cond || typeof cond !== 'object') return out;
  for (const op of Object.getOwnPropertyNames(cond)) {
    const inner = cond[op];
    if (!inner || typeof inner !== 'object' || Array.isArray(inner)) {
      out.push({ op: String(op), key: '', bad: true });
      continue;
    }
    const p = parseOperator(op);
    for (const key of Object.getOwnPropertyNames(inner)) {
      out.push({ op: String(op), key: String(key), k: lc(key), ...p,
        negated: p.base.includes('not'), vals: valuesOf(inner[key]) });
    }
  }
  return out;
}

const label = (e) => `${e.op} ${e.key}`.trim();
const isBoolEntry = (e) => e.base === 'bool' && !e.setOperator &&
  e.vals.length === 1 && BOOL_VALUES.has(lc(e.vals[0]));
const isNullEntry = (e) => e.base === 'null' && !e.setOperator && !e.ifExists &&
  e.vals.length === 1 && BOOL_VALUES.has(lc(e.vals[0]));
const isStringEntry = (e) => STRING_OPS.has(e.base) && (!e.setOperator || !e.negated);
const isPrincipalEntry = (e) => (STRING_OPS.has(e.base) || ARN_OPS.has(e.base)) && !e.setOperator;

// One Bool key under two operators with different values can never hold (B7);
// nor a positive Equals whose every value a negated entry on the key rules out (B-05).
const POS_EQ = new Set(['stringequals', 'stringequalsignorecase', 'arnequals']);
function contradiction(entries) {
  const seen = new Map();
  for (const e of entries) {
    if (e.base !== 'bool' || e.vals.length !== 1) continue;
    const v = lc(e.vals[0]);
    if (seen.has(e.k) && seen.get(e.k) !== v) return e.key;
    seen.set(e.k, v);
  }
  for (const p of entries) {
    if (p.bad || p.setOperator || !POS_EQ.has(p.base) || p.vals.some((v) => v.includes('${'))) continue;
    for (const n of entries) {
      if (n.bad || n.k !== p.k || n.setOperator || !n.negated || n.vals.some((v) => v.includes('${'))) continue;
      if (!(STRING_OPS.has(n.base) || ARN_OPS.has(n.base))) continue;
      // D-04: an IgnoreCase pin admits other casings a case-sensitive negation spares.
      if (p.base.includes('ignorecase') && !n.base.includes('ignorecase')) continue;
      const glob = n.base.endsWith('like') || ARN_OPS.has(n.base);
      const norm = n.base.includes('ignorecase') ? lc : String;
      const hit = (v) => n.vals.some((x) => (glob ? globMatch(norm(x), norm(v)) : norm(x) === norm(v)));
      if (p.vals.length > 0 && p.vals.every(hit)) return p.key;
    }
  }
  return null;
}

function arnParts(r) {
  const m = /^arn:([^:]*):([^:]*):([^:]*):([^:]*):/.exec(lc(r));
  return m ? { part: m[1], svc: m[2], region: m[3], acct: m[4] } : null;
}
// The region values a negated RequestedRegion fence leaves allowed (the Deny fires outside them).
function allowedRegionPatterns(entries) {
  const e = entries.find((x) => !x.bad && x.k === REGION && x.negated && STRING_OPS.has(x.base) &&
    !x.setOperator && x.vals.every((v) => !v.includes('${')));
  return e ? { glob: e.base.endsWith('like'), vals: e.vals.map(lc) } : null;
}
function actionServices(stmt) {
  const out = new Set();
  for (const a of (stmt.actions || [])) {
    const s = lc(a);
    const svc = s === '*' ? '*' : s.split(':')[0];
    if (/[*?]/.test(svc)) PROBE_SERVICES.filter((p) => globMatch(svc, p)).forEach((p) => out.add(p));
    else out.add(svc);
  }
  if ((stmt.notActions || []).length > 0) PROBE_SERVICES.forEach((p) => out.add(p));
  return [...out];
}
const probeArn = (svc) => (svc === 's3' || svc === 'iam'
  ? `arn:aws:${svc}::${svc === 'iam' ? '111122223333' : ''}:zzqj3cafe`
  : `arn:aws:${svc}:us-east-1:111122223333:zzqj3cafe`);

// Can this Resource ARN match a request? true / false / null (unsure). B-03.
function resourceReach(p, svcs, ctx) {
  if (!svcs.some((s) => globMatch(p.svc, s))) return false;
  if (!/[*?]/.test(p.part)) {
    if (ctx.partition && p.part !== ctx.partition) return false;
    if (!KNOWN_PARTITIONS.has(p.part)) return null;
  }
  const lit = (s) => s !== '' && !/[*?$]/.test(s);
  if ((p.svc === 's3' && lit(p.region) && p.acct === '') || (p.svc === 'iam' && lit(p.region))) return false;
  const ar = ctx.allowedRegions;
  if (ar && lit(p.region) && ar.vals.some((v) => (ar.glob ? globMatch(v, p.region) : v === p.region))) {
    return ctx.crossRegion ? null : false; // D-03: a copy is requested in the destination region
  }
  return true;
}

// Scope that matches nothing: NotResource covering every denied service, or a
// Resource list none of which can match a denied action (V1-1, V1-5, V1-6, B-03).
function scopeIssue(stmt, unmodeled, ctx = {}) {
  const nr = stmt.notResources || [];
  const svcs = actionServices(stmt);
  if (nr.length > 0) {
    const pats = nr.map((r) => lc(r));
    if (svcs.length > 0 && svcs.every((s) => pats.some((p) => globMatch(p, probeArn(s))))) return 'notresource';
    unmodeled.push('NotResource');
    return null;
  }
  const res = stmt.resources || [];
  if (res.length === 0) { unmodeled.push('Resource (empty)'); return null; }
  if (res.includes('*') || svcs.includes('*')) return null;
  const parts = res.map(arnParts);
  if (parts.some((p) => p === null)) { unmodeled.push('Resource'); return null; }
  if (!parts.some((p) => svcs.some((s) => globMatch(p.svc, s)))) return 'resource-service';
  const crossRegion = (stmt.actions || []).some((a) => /:(\*|.*[?*].*|copy.*|replicate.*)$/i.test(String(a)));
  const reach = parts.map((p) => resourceReach(p, svcs, { ...ctx, crossRegion }));
  if (reach.some((r) => r === true)) return null;
  if (reach.some((r) => r === null)) { unmodeled.push('Resource (partition or region)'); return null; }
  return 'resource-unreachable';
}

// SCP Deny: region lock, MFA gate, principal carve-outs. Returns
// { unmodeled[], vacuous, bypassGate }.
export function scpDenyShape(stmt, opts = {}) {
  const out = { unmodeled: [], vacuous: null, bypassGate: null, roleCarveOut: false };
  const entries = entriesOf(stmt.condition);
  const acct = opts.subjectAccount && /^\d{12}$/.test(String(opts.subjectAccount))
    ? String(opts.subjectAccount) : null;
  for (const e of entries) {
    if (e.bad) { out.unmodeled.push(label(e)); continue; }
    const v0 = e.vals.length === 1 ? lc(e.vals[0]) : null;
    if (e.k === REGION) {
      if (isNullEntry(e)) { if (v0 === 'true') out.vacuous = out.vacuous || 'null-present'; continue; }
      if (e.negated && STRING_OPS.has(e.base) && unionMatchesAll(e.base, e.vals, PROBE_REGIONS)) {
        out.vacuous = out.vacuous || 'region';
      }
      if (!isStringEntry(e)) out.unmodeled.push(label(e));
      continue;
    }
    if (e.k === MFA) {
      if (!isBoolEntry(e)) { out.unmodeled.push(label(e)); continue; }
      // Absent for long-term keys: plain Bool false skips them (V3-04).
      if (v0 === 'false' && !e.ifExists) out.bypassGate = e.key;
      continue;
    }
    if (e.k === P_ARN || e.k === P_ACCT) {
      if (isNullEntry(e)) { if (v0 === 'true') out.vacuous = out.vacuous || 'null-present'; continue; }
      const known = STRING_OPS.has(e.base) || ARN_OPS.has(e.base);
      if (!isPrincipalEntry(e) || (e.k === P_ACCT && ARN_OPS.has(e.base))) out.unmodeled.push(label(e));
      if (!known) continue;
      if (!e.negated) {
        const glob = e.base.endsWith('like') || ARN_OPS.has(e.base);
        // D-01: Equals is literal, and no principal holds * or ?. D-02: PrincipalArn
        // of a role session is the role ARN, never assumed-role/.
        const never = (v) => !v.includes('${') && ((!glob && /[*?]/.test(v)) ||
          (e.k === P_ARN && /^arn:[^:]*:sts::[^:]*:assumed-role\//i.test(v)));
        if (!e.setOperator && e.vals.length > 0 && e.vals.every(never)) {
          out.vacuous = out.vacuous || 'principal-shape';
          continue;
        }
        // B-04: a positive pin outside the subject account never governs it.
        if (acct && !e.setOperator && !e.vals.some((v) => v.includes('${'))) {
          const acctOf = (v) => (e.k === P_ACCT ? v : (v.split(':')[4] ?? '*'));
          const hits = e.vals.some((v) => (glob ? globMatch(lc(acctOf(v)), acct) : acctOf(v) === acct));
          if (!hits) out.vacuous = out.vacuous || 'principal-foreign';
        }
        continue;
      }
      const probes = e.k === P_ARN ? (acct ? subjectPrincipals(acct) : PROBE_PRINCIPALS) : (acct ? [acct] : PROBE_ACCOUNTS);
      if (unionMatchesAll(e.base, e.vals, probes)) out.vacuous = out.vacuous || 'principal';
      else if (e.k === P_ARN && unionMatchesAll(e.base, e.vals, acct ? subjectRoles(acct) : PROBE_ROLES)) out.roleCarveOut = true;
      continue;
    }
    if (matchAllValue(e)) out.vacuous = out.vacuous || 'principal';
    out.unmodeled.push(label(e));
  }
  const c = contradiction(entries);
  if (c) out.vacuous = out.vacuous || 'contradiction';
  const scope = scopeIssue(stmt, out.unmodeled,
    { partition: opts.partition, allowedRegions: allowedRegionPatterns(entries) });
  if (scope) out.vacuous = out.vacuous || scope;
  return out;
}

const CONCRETE = {
  [P_ORG]: /^o-[a-z0-9]{10,32}$/,
  [S_ORG]: /^o-[a-z0-9]{10,32}$/,
  [P_ORG_PATHS]: /^o-[a-z0-9]{10,32}\/[a-z0-9\-/]*$/,
  [S_ORG_PATHS]: /^o-[a-z0-9]{10,32}\/[a-z0-9\-/]*$/,
  [S_ACCT]: /^\d{12}$/,
};

function orgValueOpen(e) {
  return e.vals.some((v) => v.includes('${')) ||
    (e.base === 'stringnotlike' && e.vals.some((v) => {
      const s = lc(v);
      return e.k.endsWith('orgpaths') ? !/^o-[a-z0-9]{10,32}\//.test(s) || /[*?]/.test(s.split('/')[0]) : /[*?]/.test(s);
    }));
}

// RCP Deny: the AWS org perimeter and confused-deputy templates only. Returns
// { unmodeled[], vacuous, admitsAnyOrg, inverted, sourcePolarity }.
export function rcpDenyShape(stmt, opts = {}) {
  const out = { unmodeled: [], vacuous: null, admitsAnyOrg: false, inverted: false,
    sourcePolarity: null };
  const entries = entriesOf(stmt.condition);
  const keys = new Set(entries.map((e) => e.k));
  const hasOrg = [...keys].some((k) => ORG_KEYS.has(k));
  const hasSource = [...keys].some((k) => SOURCE_KEYS.has(k) && k !== S_ACCT);
  for (const e of entries) {
    if (e.bad) { out.unmodeled.push(label(e)); continue; }
    const v0 = e.vals.length === 1 ? lc(e.vals[0]) : null;
    if (ORG_KEYS.has(e.k) || e.k === S_ACCT) {
      if (isNullEntry(e)) {
        if (e.k === S_ACCT) {
          if (!hasSource) out.unmodeled.push(label(e));
          // Null true exempts every call that carries source context (B14f).
          else if (v0 === 'true') out.sourcePolarity = 'null-source-account';
        } else if (v0 === 'true') out.admitsAnyOrg = true; // fires only outside any org (B10)
        else out.inverted = true; // denies every org member, admits the rest (V3-05)
        continue;
      }
      if (!isStringEntry(e) || (e.k === S_ACCT && !hasSource)) { out.unmodeled.push(label(e)); continue; }
      // A positive comparator fires only for the named org/account: inverted (B-01, B-02).
      if (!e.negated) {
        if (e.k === S_ACCT) out.sourcePolarity = out.sourcePolarity || 'positive-source-account';
        else out.inverted = true;
        continue;
      }
      if (e.negated && (orgValueOpen(e) || (e.k === S_ACCT && e.vals.some((v) => /[*?$]/.test(v))))) {
        out.admitsAnyOrg = true;
        continue;
      }
      // Only concrete ids are modeled (an 'o-*' literal under Equals stays exit 3).
      const re = CONCRETE[e.k];
      if (e.negated && !e.vals.every((v) => re.test(lc(v)))) out.unmodeled.push(label(e));
      continue;
    }
    if (e.k === IS_SVC) {
      if (!isBoolEntry(e) || !hasOrg) { out.unmodeled.push(label(e)); continue; }
      if (hasSource && !keys.has(P_ORG) && v0 === 'false') out.sourcePolarity = 'service-false';
      continue;
    }
    if (matchAllValue(e)) out.vacuous = out.vacuous || 'principal';
    out.unmodeled.push(label(e));
  }
  if (!(stmt.principal && stmt.principal.anyPrincipal)) out.unmodeled.push('Principal (an RCP requires "*")');
  const lit = (stmt.actions || []).map((a) => lc(a).split(':')[0]);
  if ((stmt.notActions || []).length === 0 && lit.length > 0 &&
    lit.every((s) => !/[*?]/.test(s) && !RCP_SERVICES.has(s))) out.unmodeled.push('Action (service outside RCP scope)');
  const c = contradiction(entries);
  if (c) out.vacuous = 'contradiction';
  const scope = scopeIssue(stmt, out.unmodeled, { partition: opts.partition });
  if (scope) out.vacuous = out.vacuous || scope;
  return out;
}
