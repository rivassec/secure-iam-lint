# IAM Blast Radius - shipped-file coverage matrix

Shipped files: 72  |  lint hotspots feed: present

| file | exp | imp | callers | entrypoints | tests | browser | node: |
|------|----:|----:|--------:|-------------|------:|:-------:|-------|
| content/tools/iam-blast-radius/engine/analyze-format.js | 15 | 1 | 2 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/analyze-results.js | 9 | 11 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/analyze.js | 4 | 20 | 4 | action, browser-analyze, cli | 92 | Y | - |
| content/tools/iam-blast-radius/engine/arn-util.js | 3 | 1 | 5 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/catalog-aws-ref.js | 3 | 0 | 1 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/catalog-unmodeled.js | 1 | 0 | 1 | action, browser-analyze, cli | 1 | Y | - |
| content/tools/iam-blast-radius/engine/catalog.js | 8 | 3 | 3 | action, browser-analyze, cli | 6 | Y | - |
| content/tools/iam-blast-radius/engine/conditions.js | 11 | 1 | 12 | action, browser-analyze, cli | 4 | Y | - |
| content/tools/iam-blast-radius/engine/correlate.js | 2 | 1 | 1 | action, browser-analyze, cli | 1 | Y | - |
| content/tools/iam-blast-radius/engine/coverage.js | 9 | 2 | 5 | action, browser-analyze, cli | 3 | Y | - |
| content/tools/iam-blast-radius/engine/envelope.js | 3 | 1 | 2 | action, browser-analyze, cli | 1 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-action-grants.js | 3 | 1 | 7 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-catalogs.js | 16 | 0 | 5 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-conditions.js | 5 | 1 | 8 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-consts.js | 5 | 0 | 2 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-deny.js | 6 | 4 | 8 | action, browser-analyze, cli | 1 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-families.js | 9 | 7 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-finding.js | 8 | 7 | 3 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-reachability.js | 32 | 4 | 3 | action, browser-analyze, cli | 1 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-scope.js | 6 | 2 | 5 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-statement.js | 1 | 0 | 2 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/escalation-takeover.js | 1 | 7 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/escalation.js | 8 | 23 | 4 | action, browser-analyze, cli | 13 | Y | - |
| content/tools/iam-blast-radius/engine/family.js | 10 | 1 | 3 | action, browser-analyze, cli | 7 | Y | - |
| content/tools/iam-blast-radius/engine/format-control.js | 9 | 0 | 5 | action, browser-analyze, cli, sarif | 4 | Y | - |
| content/tools/iam-blast-radius/engine/glob.js | 10 | 0 | 24 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/graph-catalogs.js | 10 | 0 | 6 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/graph-edges.js | 12 | 2 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/graph-helpers.js | 15 | 3 | 4 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/graph-resource.js | 3 | 4 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/graph-result.js | 5 | 1 | 3 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/graph-trust.js | 5 | 6 | 2 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/graph.js | 3 | 16 | 2 | action, browser-analyze, cli | 3 | Y | - |
| content/tools/iam-blast-radius/engine/masked-grant.js | 4 | 2 | 1 | action, browser-analyze, cli | 3 | Y | - |
| content/tools/iam-blast-radius/engine/model.js | 3 | 3 | 4 | action, browser-analyze, cli | 16 | Y | - |
| content/tools/iam-blast-radius/engine/parse.js | 2 | 0 | 1 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/rcp.js | 3 | 1 | 2 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/render-graph.js | 9 | 1 | 1 | browser-analyze | 3 | Y | - |
| content/tools/iam-blast-radius/engine/report.js | 4 | 2 | 1 | browser-analyze | 22 | Y | - |
| content/tools/iam-blast-radius/engine/resource-arn.js | 4 | 1 | 6 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/resource-catalogs.js | 20 | 0 | 7 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/resource-conditions.js | 9 | 3 | 4 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/resource-finding.js | 5 | 2 | 4 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/resource-kms-rules.js | 8 | 6 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/resource-messaging-rules.js | 8 | 5 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/resource-principal-classification.js | 4 | 1 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/resource-s3-rules.js | 8 | 5 | 2 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/resource-shared.js | 4 | 2 | 4 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/resource-source-binding.js | 7 | 3 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/resource.js | 4 | 23 | 3 | action, browser-analyze, cli | 9 | Y | - |
| content/tools/iam-blast-radius/engine/rules-catalog.js | 2 | 0 | 2 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/rules-classify.js | 34 | 2 | 3 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/rules-detectors.js | 19 | 7 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/rules-finding.js | 11 | 6 | 2 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/rules.js | 4 | 13 | 3 | action, browser-analyze, cli | 7 | Y | - |
| content/tools/iam-blast-radius/engine/scp.js | 3 | 1 | 2 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/trust-catalogs.js | 14 | 0 | 5 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/trust-classify.js | 6 | 3 | 3 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/trust-conditions.js | 7 | 2 | 1 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/trust-deny.js | 6 | 5 | 2 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/trust-findings.js | 7 | 2 | 1 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/trust-principal-helpers.js | 15 | 0 | 4 | action, browser-analyze, cli | 0 | Y | - |
| content/tools/iam-blast-radius/engine/trust.js | 2 | 14 | 8 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/validate.js | 3 | 0 | 6 | action, browser-analyze, cli, sarif | 27 | Y | - |
| content/tools/iam-blast-radius/engine/version.js | 4 | 3 | 3 | action, browser-analyze, cli | 1 | Y | - |
| content/tools/iam-blast-radius/app.js | 1 | 8 | 0 | browser-analyze | 1 | Y | - |
| content/tools/iam-blast-radius/worker.js | 0 | 1 | 0 | browser-analyze | 3 | Y | - |
| cli/baseline.mjs | 10 | 2 | 2 | action, cli | 1 | - | node:crypto |
| cli/iam-br.mjs | 15 | 5 | 0 | cli | 13 | - | node:fs node:path node:url |
| cli/sarif.mjs | 12 | 2 | 3 | action, cli, sarif | 13 | - | - |
| cli/scan.mjs | 8 | 2 | 3 | action, cli | 57 | - | - |
| action/index.mjs | 5 | 21 | 0 | action | 18 | - | node:crypto node:fs node:path node:url |

## Orphan report

### Untested shipped files (36)
- content/tools/iam-blast-radius/engine/analyze-format.js
- content/tools/iam-blast-radius/engine/analyze-results.js
- content/tools/iam-blast-radius/engine/arn-util.js
- content/tools/iam-blast-radius/engine/escalation-action-grants.js
- content/tools/iam-blast-radius/engine/escalation-catalogs.js
- content/tools/iam-blast-radius/engine/escalation-conditions.js
- content/tools/iam-blast-radius/engine/escalation-consts.js
- content/tools/iam-blast-radius/engine/escalation-families.js
- content/tools/iam-blast-radius/engine/escalation-finding.js
- content/tools/iam-blast-radius/engine/escalation-scope.js
- content/tools/iam-blast-radius/engine/escalation-statement.js
- content/tools/iam-blast-radius/engine/escalation-takeover.js
- content/tools/iam-blast-radius/engine/graph-catalogs.js
- content/tools/iam-blast-radius/engine/graph-edges.js
- content/tools/iam-blast-radius/engine/graph-helpers.js
- content/tools/iam-blast-radius/engine/graph-resource.js
- content/tools/iam-blast-radius/engine/graph-result.js
- content/tools/iam-blast-radius/engine/graph-trust.js
- content/tools/iam-blast-radius/engine/resource-catalogs.js
- content/tools/iam-blast-radius/engine/resource-conditions.js
- content/tools/iam-blast-radius/engine/resource-finding.js
- content/tools/iam-blast-radius/engine/resource-kms-rules.js
- content/tools/iam-blast-radius/engine/resource-messaging-rules.js
- content/tools/iam-blast-radius/engine/resource-principal-classification.js
- content/tools/iam-blast-radius/engine/resource-s3-rules.js
- content/tools/iam-blast-radius/engine/resource-shared.js
- content/tools/iam-blast-radius/engine/resource-source-binding.js
- content/tools/iam-blast-radius/engine/rules-catalog.js
- content/tools/iam-blast-radius/engine/rules-classify.js
- content/tools/iam-blast-radius/engine/rules-detectors.js
- content/tools/iam-blast-radius/engine/rules-finding.js
- content/tools/iam-blast-radius/engine/trust-catalogs.js
- content/tools/iam-blast-radius/engine/trust-classify.js
- content/tools/iam-blast-radius/engine/trust-deny.js
- content/tools/iam-blast-radius/engine/trust-findings.js
- content/tools/iam-blast-radius/engine/trust-principal-helpers.js

### Browser-reachable files importing node: builtins (0)
(none)

