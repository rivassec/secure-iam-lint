# Post-v1.0.0 tracked issues

Deliberately deferred past v1.0.0 (agreed with owner 2026-08-28). Not bugs blocking release; do NOT fix during the behavior-preserving refactor.

## ISSUE 1: two divergent `parseArn` implementations (same name, different behavior)

`engine/arn-util.js` `parseArn` (used internally by resource.js + family.js via re-export) and `engine/resource-arn.js` `parseArn` (used by rules.js, analyze.js, masked-grant.js) are NOT the same function despite sharing a name. They have drifted:

| aspect | arn-util.js parseArn | resource-arn.js parseArn |
|---|---|---|
| result field for the resource segment | `resource` | `resourceId` |
| empty resource segment (`arn:aws:s3:::`) | ACCEPTED | REJECTED (`resourceId.length === 0` -> null) |
| non-string / null input | `typeof !== 'string'` -> null | coerced via `String(value == null ? '' : value)` |
| return value | plain object | `Object.freeze(...)` |

Because callers read different field names (`.resource` vs `.resourceId`) and rely on different empty-segment handling, collapsing them is a BEHAVIOR CHANGE, not a pure move - it was explicitly kept out of the v1.0.0 refactor.

Reconciliation task (post-v1.0.0, do deliberately with tests):
1. Decide the canonical semantics (field name; empty-resource policy; input coercion; frozen-vs-plain).
2. Add a differential/corpus test over real fixtures, golden policies, malformed ARNs, and partition variants to characterize both current behaviors first.
3. Migrate all callers to the canonical function + field name.
4. Delete the loser; keep one `parseArn`.

Owner decision on record: leave both as-is for v1.0.0, track here. (File as a GitHub issue when convenient - held pending owner's manual step.)
