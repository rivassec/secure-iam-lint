# IAM Blast Radius - shipped-file coverage matrix

Shipped files: 30  |  lint hotspots feed: present

| file | exp | imp | callers | entrypoints | tests | browser | node: |
|------|----:|----:|--------:|-------------|------:|:-------:|-------|
| content/tools/iam-blast-radius/engine/analyze.js | 11 | 16 | 4 | action, browser-analyze, cli | 78 | Y | - |
| content/tools/iam-blast-radius/engine/catalog.js | 8 | 1 | 2 | action, browser-analyze, cli | 4 | Y | - |
| content/tools/iam-blast-radius/engine/conditions.js | 9 | 1 | 6 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/correlate.js | 2 | 0 | 1 | action, browser-analyze, cli | 1 | Y | - |
| content/tools/iam-blast-radius/engine/coverage.js | 9 | 2 | 4 | action, browser-analyze, cli | 3 | Y | - |
| content/tools/iam-blast-radius/engine/envelope.js | 3 | 1 | 1 | action, browser-analyze, cli | 1 | Y | - |
| content/tools/iam-blast-radius/engine/escalation.js | 11 | 3 | 4 | action, browser-analyze, cli | 12 | Y | - |
| content/tools/iam-blast-radius/engine/family.js | 10 | 1 | 3 | action, browser-analyze, cli | 7 | Y | - |
| content/tools/iam-blast-radius/engine/format-control.js | 9 | 0 | 5 | action, browser-analyze, cli, sarif | 2 | Y | - |
| content/tools/iam-blast-radius/engine/glob.js | 10 | 0 | 9 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/graph.js | 11 | 4 | 1 | action, browser-analyze, cli | 3 | Y | - |
| content/tools/iam-blast-radius/engine/masked-grant.js | 4 | 2 | 1 | action, browser-analyze, cli | 3 | Y | - |
| content/tools/iam-blast-radius/engine/model.js | 3 | 3 | 4 | action, browser-analyze, cli | 15 | Y | - |
| content/tools/iam-blast-radius/engine/parse.js | 2 | 0 | 1 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/rcp.js | 3 | 1 | 1 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/render-graph.js | 9 | 1 | 1 | browser-analyze | 3 | Y | - |
| content/tools/iam-blast-radius/engine/report.js | 4 | 2 | 1 | browser-analyze | 22 | Y | - |
| content/tools/iam-blast-radius/engine/resource-arn.js | 4 | 1 | 3 | action, browser-analyze, cli | 1 | Y | - |
| content/tools/iam-blast-radius/engine/resource.js | 13 | 3 | 2 | action, browser-analyze, cli | 9 | Y | - |
| content/tools/iam-blast-radius/engine/rules.js | 9 | 5 | 2 | action, browser-analyze, cli | 6 | Y | - |
| content/tools/iam-blast-radius/engine/scp.js | 3 | 1 | 1 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/trust.js | 13 | 2 | 3 | action, browser-analyze, cli | 2 | Y | - |
| content/tools/iam-blast-radius/engine/validate.js | 3 | 0 | 6 | action, browser-analyze, cli, sarif | 26 | Y | - |
| content/tools/iam-blast-radius/engine/version.js | 4 | 3 | 3 | action, browser-analyze, cli | 1 | Y | - |
| content/tools/iam-blast-radius/app.js | 1 | 8 | 0 | browser-analyze | 1 | Y | - |
| content/tools/iam-blast-radius/worker.js | 0 | 1 | 0 | browser-analyze | 3 | Y | - |
| cli/iam-br.mjs | 14 | 4 | 0 | cli | 8 | - | node:fs node:path node:url |
| cli/sarif.mjs | 10 | 2 | 2 | action, cli, sarif | 5 | - | - |
| cli/scan.mjs | 7 | 2 | 2 | action, cli | 33 | - | - |
| action/index.mjs | 29 | 4 | 0 | action | 12 | - | node:crypto node:fs node:path node:url |

## Orphan report

### Untested shipped files (0)
(none)

### Browser-reachable files importing node: builtins (0)
(none)

