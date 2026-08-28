// escalation-scope.js - resource-scope + assume-scope breadth helpers.
// Extracted from escalation.js (behavior-preserving refactor).
import { globMatch, chargeWork } from './glob.js';
import { hasPolicyVariable } from './escalation-action-grants.js';

export function resourceScope(stmt) {
  if (stmt.resources.length > 0) return stmt.resources;
  if (stmt.notResources.length > 0) return stmt.notResources;
  return ['(no Resource/NotResource specified)'];
}

// Is a resource pattern "broad" for role assumption? True for a bare "*", a
// NotResource inverse, an unspecified scope, or an ARN that wildcards the role
// path (e.g. arn:aws:iam::*:role/*). A single concrete role ARN is NOT broad.
export function resourceListIsBroadForAssume(stmt) {
  if (stmt.notResources.length > 0) return true;
  if (stmt.resources.length === 0) return true; // unspecified scope
  return stmt.resources.some((r) => {
    if (r === '*') return true;
    // A wildcard in the role-name portion of the ARN reaches many roles.
    return r.includes('*') || r.includes('?');
  });
}

// IAM-102 severity discriminator: does an AssumeRole grant reach "effectively
// ALL roles" - i.e. all roles across ARBITRARY accounts? Critical is reserved
// for that boundary-crossing scope. Two axes must BOTH be unconstrained:
//   (1) account axis arbitrary   - the grant is not pinned to concrete
//       account id(s): a NotResource inverse, an unspecified scope, a bare "*",
//       a non-ARN pattern, or an ARN whose account field is wildcarded/empty
//       (this is exactly assumeAccountReach().arbitrary).
//   (2) role-name axis fully open - a NotResource inverse, an unspecified
//       scope, a bare "*", the bare shorthand "role/*", or a role ARN whose
//       role-name path segment is exactly "*".
// A grant pinned to a CONCRETE account - even arn:aws:iam::111122223333:role/*
// (all roles in ONE account) - is broad but BOUNDED to that account, so it is
// NOT effectively-all-roles and stays `high`, never critical: asserting critical
// would claim reach the account-pinned ARN does not support (threat-model T8,
// IAM-301 negative corpus). A PARTIAL role-name wildcard (role/app-*, role/app-?)
// reaches many roles but not all, so it too stays `high`.
export function assumeScopeIsAllRoles(stmt) {
  // Account axis must be arbitrary first: a concrete-account grant is bounded.
  if (!assumeAccountReach(stmt).arbitrary) return false;
  if (stmt.notResources.length > 0) return true; // inverse: ~all roles
  if (stmt.resources.length === 0) return true; // unspecified: unconstrained
  return stmt.resources.some((r) => {
    if (r === '*') return true;
    if (r === 'role/*') return true; // bare shorthand
    const marker = ':role/';
    const idx = r.lastIndexOf(marker);
    if (idx === -1) return false;
    return r.slice(idx + marker.length) === '*'; // role-name segment is exactly "*"
  });
}

// A broad-for-assume grant is not necessarily cross-account. Determine whether
// the resource set can reach roles in accounts OTHER than ones it names.
// Returns { arbitrary, accounts }:
//   arbitrary=true  -> a NotResource inverse, an unspecified scope, a bare "*",
//                      a non-ARN pattern, or an ARN whose account field is
//                      wildcarded/empty is present -> reach is not confined to
//                      named accounts (may span arbitrary AWS accounts).
//   arbitrary=false -> every resource pins a concrete account; `accounts` lists
//                      the distinct account IDs the grant is confined to.
// Only the arbitrary case may carry the "arbitrary AWS accounts" claim; a grant
// like arn:aws:iam::111122223333:role/* is broad within ONE account, not across.
export function assumeAccountReach(stmt) {
  if (stmt.notResources.length > 0) return { arbitrary: true, accounts: [] };
  if (stmt.resources.length === 0) return { arbitrary: true, accounts: [] };
  const accounts = new Set();
  for (const r of stmt.resources) {
    if (r === '*') return { arbitrary: true, accounts: [] };
    // ARN layout: arn:partition:service:region:account:resource
    const parts = r.split(':');
    if (parts.length < 6) return { arbitrary: true, accounts: [] }; // not a full ARN
    const account = parts[4];
    if (account === '' || account.includes('*') || account.includes('?')) {
      return { arbitrary: true, accounts: [] };
    }
    accounts.add(account);
  }
  return { arbitrary: false, accounts: [...accounts] };
}

// True if a resource pattern is a bare "*" (or the account/path-spanning
// "arn:...:*" form is NOT treated as full here; only a literal "*" fully covers).
export function isStarResource(r) {
  return r === '*';
}

// A grant token is "broad" when it is a wildcard pattern ('*', 'service:*', or
// any pattern containing '*' / '?') - i.e. it matches more than one concrete
// action. A NotAction-Deny ("deny everything EXCEPT the listed actions") can
// NEVER fully cover a broad grant token: at least one NotAction-preserved action
// falls within the broad grant and stays ALLOWED, so such a Deny can only NARROW
// the grant, never remove it. (Reporting it as fully blocked would be a false
// deny - it renders a still-reachable capability as definitively blocked, a
// truthfulness harm; docs/architecture.md #6, threat-model T8.) A CONCRETE grant
// token, by contrast, is either preserved by the NotAction list -> the Deny does
// not apply -> or fully denied -> genuine full coverage.
export function grantTokenIsBroad(action) {
  const a = String(action);
  return a.includes('*') || a.includes('?');
}
