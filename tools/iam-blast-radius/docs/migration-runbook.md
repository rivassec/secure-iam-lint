# Own-repo migration runbook - REPURPOSE rivassec/secure-iam-lint

Status: runbook (not yet executed). Execute AFTER Phase 14 is deployed + green.
Strategy: PARALLEL STANDUP, then SWAP. The blog keeps serving today's tool
(frozen at Phase 14) the whole time; the live site is never in a broken state.
ASCII only. Nothing here runs until Oliver approves.

DECISION (2026-08-24): do NOT create a new repo. REPURPOSE the existing
`rivassec/secure-iam-lint` (abandoned 2025 Python IAM-policy linter, created
2025-04-11) as the tool's home, and ship the tool UNDER THE secure-iam-lint NAME
(repo + CLI binary + GitHub Action + Marketplace listing all = secure-iam-lint).
Preserve the old Python: tag its current HEAD `v0-python-legacy` (and/or a
`legacy/python` branch) BEFORE overwriting main - repurpose, never erase.
No `gh repo create` and no repo-creation gate; the interactive gate is now the
first big content push to the existing public repo (confirm with Oliver).
Web tool: KEEP the live URL /tools/iam-blast-radius/ stable (don't break the
just-published blog post + Search Console indexing); update only the on-page
heading to "secure-iam-lint". Moving the URL is optional and only if Oliver
accepts an indexing reset.

## Preconditions
- Phase 14 merged to main, deployed, CI green, live-verified.
- Working tree clean on main.
- Local git identity = rivassec@rivassec.com (already set in this repo).
- gh active account is oliveratprimer; rivassec is logged in (inactive).

## Source of truth today (two dirs, one tool)
- `content/tools/iam-blast-radius/` - shipped web build (served verbatim).
- `tools/iam-blast-radius/` - engine dev tree: docs, prd.json, progress.md,
  ralph/, fixtures/, tests/, CI.
Note: the shipped `engine/*.js` under content/ is the SAME engine the tests
under tools/ import (`../../../content/tools/iam-blast-radius/engine/*.js`). The
new repo unifies these so there is ONE engine copy.

## Target layout (new repo root)
    iam-blast-radius/
      engine/            # the analysis engine (from content/.../engine)
      web/               # index.html, styles.css, app.js, worker.js (the static shell)
      cli/               # Phase 15: iam-br.mjs + scan module
      action/            # Phase 16: index.mjs
      action.yml         # Phase 16: at ROOT (Marketplace requirement)
      tests/             # node --test + e2e
      fixtures/
      docs/              # architecture, threat-model, semantics, plans, this runbook
      ralph/             # the build workflows
      prd.json  progress.md
      package.json       # type:module, bin:iam-br, no runtime deps
      .github/workflows/ # tool CI + action self-tests
      LICENSE  README.md

## Phase A - stand up the new repo (blog untouched)

1. History-preserving split. `git-filter-repo` is not installed; use subtree
   split per path, into a fresh repo, then reconcile the two prefixes:

       cd /Users/oliver/dev/devsecops-notes
       git subtree split -P content/tools/iam-blast-radius -b split-web
       git subtree split -P tools/iam-blast-radius        -b split-dev

   Then build the new repo by importing both split branches and moving files
   into the target layout in a first restructure commit (history from BOTH
   splits is preserved as ancestry). (Alternative if history fidelity across the
   merge matters more: `pip install --user git-filter-repo` and filter both
   paths in one pass - decide at execution time; subtree is the zero-install path.)

2. Create the repo (INTERACTIVE GATE - confirm with Oliver):

       gh auth switch --user rivassec
       gh repo create rivassec/iam-blast-radius --public \
         --description "Client-side AWS IAM policy blast-radius analyzer + CI action" \
         --disable-wiki
       gh auth switch --user oliveratprimer     # restore work context immediately

3. Push (SSH key, rivassec identity - independent of gh active account):

       git remote add origin git@github.com:rivassec/iam-blast-radius.git
       git push -u origin main

4. Stand up CI in the new repo: node >= 22 for `node --test` (node 20 can't
   expand the tests glob - known gotcha), the deterministic gates (no-network,
   no-unsafe-DOM, csp_audit, fixtures-parse, shipped-tree-hygiene), Playwright
   3-browser. Confirm green.

5. Build Phase 15 (CLI/SARIF) and Phase 16 (Action) IN THE NEW REPO. The blog is
   still serving the frozen Phase-14 tool; no deploy pressure.

## Phase B - swap the blog to consume the new repo (deliberate, reversible)

Chosen mechanism: VENDOR-SYNC (not submodule) - keeps the blog's no-build,
strict-CSP, ship-verbatim simplicity.

6. Add a pinned-tag vendor step to the blog: a small script (run in
   deploy.yml BEFORE the Pelican build, or committed output) that copies the
   `web/` + `engine/` build from a PINNED tag of rivassec/iam-blast-radius into
   `content/tools/iam-blast-radius/`. Pin by tag/SHA, never a moving branch, so
   the served bytes are reproducible and the CSP guarantee is unchanged.

7. Parity check BEFORE cutover: diff the vendored bytes against the current
   in-repo shipped tree - they must be identical at the Phase-14 tag (proves the
   split lost nothing). Any Phase-15 engine refactor that changed the web build
   is an intentional, reviewed delta at this point.

8. Cut over: land the vendor step, deploy the blog, purge Cloudflare (dynamic
   file list, ~/.orvtec.cloudflare.txt), curl-verify rivassec.com/tools/
   iam-blast-radius/ serves the vendored build (check the nav + a known finding).

9. Remove the now-duplicated dev tree (`tools/iam-blast-radius/`) from the blog
   repo once the new repo owns it; keep only the vendored `content/tools/...`
   output that the site serves. Update the blog post link if the tool URL is
   unchanged (it is - same path), no change needed.

## Rollback
At any point before step 9, revert is trivial: the in-repo copy still exists and
still deploys. If the vendored build misbehaves, drop the vendor step and the
blog falls back to the committed in-repo tool (Phase 14). After step 9, rollback
= re-add the tool dir from the tagged commit. Because Phase A never touches the
blog, there is no window where the live site depends on unproven code.

## Post-migration
- Update memory `project_iam_blast_radius_tool.md`: new repo is source of truth;
  blog vendor-syncs from a pinned tag.
- The Cloudflare CSP Response Header Transform Rule and the purge-on-deploy stay
  on the blog side (they govern the served path, which is unchanged).
- Move the CSP/deploy gotchas doc-references to the new repo's README.
