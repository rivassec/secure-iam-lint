// escalation-statement.js - statement Sid/label helper. Extracted (behavior-preserving).

export function statementSid(stmt) {
  return typeof stmt.sid === 'string' && stmt.sid.length > 0
    ? stmt.sid
    : `(index ${stmt.index})`;
}
