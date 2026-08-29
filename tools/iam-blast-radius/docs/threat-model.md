# IAM Blast Radius - Threat Model (immutable contract)

The tool analyzes attacker-controlled IAM JSON in the victim's browser. The
policy text is HOSTILE. The security critic blocks any story that violates
this file.

## Assets
- The user's pasted/imported policy content (must never leave the device).
- The integrity of the user's browser session (no XSS, no code exec).

## Trust boundary
Everything after page load runs locally. There is no backend. There are no
credentials. There is no server to attack. The adversary is the *content*.

## Threats and required controls

T1. **DOM XSS via policy fields** (SIDs, ARNs, condition values contain
`<script>`, `<img onerror>`, SVG payloads).
-> Build DOM with `createElement`+`textContent` only. Never `innerHTML`/
`insertAdjacentHTML`/`outerHTML` from input. Never set `href`/`src`/`style`/
event attributes from input. SVG graph text via `textContent` on SVG text
nodes, numeric attributes only, never inject markup.

T2. **Code injection** -> No `eval`, `new Function`, `setTimeout(string)`,
dynamic `<script>`, or remote `import()`. CSP `script-src 'self'` backs this.

T3. **Prototype pollution** via `__proto__`/`constructor`/`prototype` keys in
parsed JSON -> Reject these keys in validation; parse with a reviver or use
`Object.create(null)` maps; never deep-merge input into objects.

T4. **Data exfiltration** of the analyzed policy -> Zero network egress
(architecture invariant 1). CSP `connect-src 'none'` (Cloudflare header) +
code-level absence of network APIs. No `localStorage`/`IndexedDB`/cookies for
policy content. Explicit "Clear analysis" button; clear in-memory state on
`pagehide`/navigation. No service worker caching analyzed content.

T5. **Resource exhaustion / DoS** (multi-MB policies, thousands of
statements, deep nesting, circular refs) -> Enforce limits BEFORE parse:
max input bytes, max JSON depth, max statements/actions/resources, max graph
nodes. Run analysis in a Web Worker with a wall-clock budget; terminate on
overrun and report gracefully. Reject circular structures.

T6. **Unsafe export** -> Prefer JSON/Markdown export. If HTML export is
offered, escape all interpolated policy values. Downloads via Blob only.

**Output-surface neutralization contract (which surfaces are display-safe).** A
policy-derived value is HOSTILE (T1) and can carry invisible / bidi-reordering /
homograph code points (see `engine/format-control.js`). Every HUMAN-FACING trust
surface neutralizes it: the browser DOM findings table, the SVG graph, the
Markdown export, and the SARIF report all run values through
`neutralizeForDisplay` (format-control removal + non-ASCII charset clamp) so a
Trojan-Source spoof cannot ride into a reviewer's eyes.

The CLI `--format json` output is the DELIBERATE exception: it is a
**BYTE-FAITHFUL machine artifact, NOT a display surface.** It emits the engine's
finding strings verbatim (no neutralization) so downstream tooling that keys on
partialFingerprints / ARNs / action names receives the EXACT bytes of the
analyzed policy - neutralizing them would corrupt the machine contract and could
change a fingerprint. Hostile Unicode/bidi therefore rides through the JSON
INERT: it is never executed, never interpolated into a page, and cannot escalate
into XSS or code exec (it is data in a JSON string). The residual risk is purely
VISUAL, and only if a human treats the raw JSON as a display surface: a
`cat report.json` in a bidi-aware terminal could render a spoofed grant. A human
reviewing findings MUST use `--format sarif` (or the browser tool / a renderer
that neutralizes), and MUST NOT trust raw `cat report.json` as a visual review
surface. Machines consume `--format json`; humans read `--format sarif`. This is
why the JSON path is intentionally NOT in the neutralization list above.

T7. **Supply chain** -> Minimal, self-hosted, pinned deps. The SHIPPED tool
(engine + app + worker + CLI + Action) has ZERO runtime dependencies and NO
build step (architecture invariants 2 + 7): what is committed is what runs, so
there is no build-time transform and no transitive-runtime compromise surface.
Dev-only tooling (test/e2e/fuzz) has its top-level versions exact-pinned in
`package.json` (no `^`/`~`), and its transitive tree is locked in
`package-lock.json` (committed to git, no longer gitignored). CI therefore
installs them with `npm ci`, which fails CLOSED on any lockfile/`package.json`
drift instead of silently resolving new transitive versions the way `npm install`
would. This tooling never ships to consumers: the shipped artifact has zero
runtime dependencies, so even an un-pinned dev dep could not reach a consumer's
build or runtime.
Controls ENFORCED in CI today (`.github/workflows/security.yml` + `ci.yml`):
- GH Actions pinned to full commit SHAs; the `zizmor` unpinned-uses audit gates
  it (any un-pinned `uses:` fails the Security workflow).
- `gitleaks` scans the full git history for secrets.
- `actionlint` lints every workflow.
- `OSV-Scanner` (pinned, checksum-verified binary) scans every committed lockfile
  for known-CVE advisories; the job exit gates. This covers the dev-only tree
  (the shipped artifact has zero runtime dependencies).
NOT yet implemented as a per-push CI gate (tracked; this file must NOT claim it as
present until a `security.yml`/`ci.yml` gate runs it): SBOM generation (a CycloneDX
SBOM IS emitted on a tagged release via `release.yml`, but that is a release artifact,
not a push gate) and an automated license allowlist. These cover only the dev-only
deps (the shipped artifact has none), so they rank below the zero-runtime-dep +
no-build guarantees above.

T8. **Misleading conclusions as a security harm** -> The tool must not claim
effective permissions from insufficient context. Overstated certainty is a
blocking finding (a user could wrongly clear a real risk). Distinguish
confirmed / conditional / potential / blocked / unknown.

**"complete" / "CLEAN" is NOT an affirmative safety claim.** A `complete`
coverage verdict, or a zero-finding pass, means the analyzable surface was
analyzed and nothing at-or-above the reporting bar fired - it never means
"analyzed and proven safe". Two classes of SCOPED-but-real capability are, by the
HYBRID design decision, DELIBERATELY not surfaced, and their silence must not be
read as safety:
- **Same-account scoped role assumption** (`sts:AssumeRole` to a specific role in
  the analyzed principal's OWN account) - the routine, intended use of AssumeRole.
- **Same-account scoped container/object reads** (a bucket / table / stream /
  database read scoped to a named resource in the analyzed principal's own
  account), and any single concrete object read - routine least privilege.
These are intentionally QUIET to avoid false-positive noise. The CROSS-ACCOUNT
counterparts (a scoped `sts:AssumeRole` into another account; a whole-container
read of another account's resource - INCLUDING a broad/wildcard-resource-id read
such as `...:999999999999:stream/*`, which is a strictly-broader capability than a
concrete one and must never read CLEAN while the narrower read fires) ARE surfaced
at LOW/INFO, but ONLY when the subject account is KNOWN. The subject account is an
OPTIONAL input the operator supplies on EITHER surface - the browser's
"Analyzed principal's account ID" field (identity / auto families) or the CLI /
Action `--subject-account` / `subject-account:` input - so cross-account surfacing
is NOT a CLI-only capability: given the same subject account, the browser worker and
the CLI produce the same CROSS-ACCOUNT findings (the browser forwards it through
`worker.js` -> `analyze({ subjectAccount })`, the same option the CLI injects).
When the subject account is UNKNOWN (left blank on both surfaces) the tool cannot
distinguish same- from cross-account and stays conservative (quiet) - again, silence
there is "not determinable from this policy", never "safe". Cross-account
exploitability additionally depends on the target's trust policy / resource policy
and the target role's permissions, none of which a single identity policy contains,
so these are LOW/INFO capabilities, never confirmed escalations.

**S3 canonical bucket ARNs are account-blind - surfaced, never silently cleared.** A
canonical S3 bucket ARN (`arn:aws:s3:::bucket/*`, or a bucket-list target) carries NO
account field, so - unlike a DynamoDB / Kinesis / RDS-Data ARN, or an S3
access-point / outpost ARN, all of which DO carry an account - the owning account of a
whole-bucket read cannot be resolved from the ARN alone. The tool therefore CANNOT
clear such a read as same-account, and (with a KNOWN subject account) it must not read
CLEAN: a neutrally-named whole-bucket read whose owner is unresolvable is surfaced at
INFO as an account-UNDETERMINED read (`CROSS-ACCOUNT-DATA-READ-UNDETERMINED`) - the
archetypal exfil primitive is never allowed to silently clear. This is deliberately
DISTINCT from the confirmed `CROSS-ACCOUNT-DATA-READ`: the crossing is UNPROVEN (the
owner is unknown, not known-to-differ), so it is stated as undetermined, never as a
confirmed cross-account grant (T8: no overstated certainty). The owner is RECOVERED -
and the read then classified same-account (quiet) or cross-account (confirmed) - when
the policy makes it derivable: an account-bearing S3 access-point ARN, or an explicit
`aws:ResourceAccount` / `s3:ResourceAccount` equality condition pinning a single
account. Two S3 whole-bucket cases stay QUIET by the same rules as the other stores: a
single concrete OBJECT read (`bucket/key`) is not a whole-container read, and any
DIRECTLY-GRANTED whole-bucket read (the Allow's own scope) with the subject account
UNKNOWN cannot be compared - a scoped-to-one-bucket read is routine least privilege, so
absent a subject it stays quiet. A sensitivity-token or policy-variable bare-bucket read
is already surfaced (non-clean) by the same-account `DATA-READ` path, so it is not
additionally reported here.

**A whole-container read SURVIVING a NotResource-Deny fence is surfaced from
`isWholeContainerRead` alone - subject-account-INDEPENDENT (R1).** The
DIRECTLY-GRANTED-and-subject-unknown QUIET rule above does NOT extend to the residual of
a broad read a Deny narrowed. A broad exfil Allow (`s3:GetObject` on `*`) is a LOUD
`DATA-EXFIL` that never needed a subject account; when a same-policy NotResource Deny
fences it down to a proven-NARROW spared set (`denyFencesToNarrow`), `DATA-EXFIL` is
correctly SUPPRESSED - but the PROVEN SURVIVING spared resource is a capability in its
own right, and letting it read CLEAN would let an author widen `DATA-EXFIL` away simply
by adding a Deny (the R1 fail-open: `{Allow s3:GetObject *}` + `{Deny s3:GetObject
NotResource:[bucket/*]}` read exit-0/complete/findings[] while the same spared scope
granted directly surfaced). So a WHOLE-CONTAINER read the fence leaves standing is
surfaced whether or not a subject account is supplied - as
`CROSS-ACCOUNT-DATA-READ-UNDETERMINED` (account-blind S3 bucket, owner unknown) or, when
a subject IS supplied and the spared owner is resolvable-and-differing, as the confirmed
`CROSS-ACCOUNT-DATA-READ`. It is NEVER re-emitted as `DATA-EXFIL` (that id is
Deny-exempt and would be instantly re-suppressed). The QUIET boundary holds within the
fenced case exactly as elsewhere: a spared SINGLE OBJECT (`bucket/key`), a
same-account-resolvable spared whole bucket (account-bearing ARN, or an
`aws:ResourceAccount`/`s3:ResourceAccount`-pinned owner equal to a known subject), and an
unrelated-service / conditional (non-definitive) Deny that never fences the read at all
each stay quiet. The surviving-spared classification reuses the SAME
whole-container/account oracle as the directly-granted path, invoked from a
pipeline-level post-pass that has the Deny set in scope (the rule catalog is
Deny-unaware when it emits findings), so the two paths cannot drift.

## CSP (route header, Cloudflare - see DEPLOY.md)
```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none';
frame-ancestors 'none'; form-action 'none'; worker-src 'self'; manifest-src 'self'
```
A `<meta>` CSP in index.html is a weaker fallback (cannot enforce
frame-ancestors); the code-level no-network guarantee is the real control.

## Out of scope (MVP)
Live AWS calls, credential handling, server-side anything, Terraform/HCL
(later milestone), managed-policy catalogs (later).
