// Golden-corpus manifest (ORACLE-FIRST fail-closed audit harness).
//
// Each entry describes ONE corpus policy file under ./corpus and the fail-closed
// PROPERTY its class must satisfy. The manifest is the single source of truth shared
// by golden-oracle.test.js (property assertions), packaging.test.js (real-invocation
// fixtures), and capture.mjs / diff.mjs (the SECONDARY snapshot channel).
//
// CLASS taxonomy (what the oracle asserts, derived from BEHAVIOUR not a snapshot):
//   risky     - at least one finding at/above `threshold`; CLI exit != 0; NEVER clean.
//   clean     - genuinely narrow/routine; CLI exit 0 (nothing at/above threshold).
//   quiet     - a deliberately-silent SCOPED capability (same-account assume/read);
//               CLI exit 0 AND zero findings. Silence here is "not surfaced by
//               design", never "proven safe".
//   malformed - rejected before/at model build; analysisStatus != complete; exit 3;
//               NEVER clean.
//
// `threshold` defaults to 'high' (the CLI/scan default). A case may pin a different
// threshold when its risk surfaces below high by design (e.g. the cross-account
// whole-bucket read is an INFO capability - surfaced, never silently cleared).
//
// `knownOpen` marks a case that hits one of the SIX confirmed fail-open bugs. Its
// oracle assertion is registered as a node:test `todo` so the suite stays green today
// while DOCUMENTING the open fail-open; fixing the bug flips the todo to a real pass.
// See ./README.md for the bug<->case map.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
export const CORPUS_DIR = join(here, 'corpus');

export const CLASS = Object.freeze({
  RISKY: 'risky',
  CLEAN: 'clean',
  QUIET: 'quiet',
  MALFORMED: 'malformed',
});

// Raw policy text for a corpus file, byte-faithful (BOM/unicode preserved).
export function corpusText(file) {
  return readFileSync(join(CORPUS_DIR, file), 'utf8');
}

// The corpus. ~15 KILLER cases spanning the fail-open taxonomy, deliberately small
// and expandable. Behaviour of every entry was verified against the real CLI/engine
// when authored; `expectedExit` records that ground truth so a drift is visible.
export const CASES = Object.freeze([
  {
    id: 'admin-full',
    file: '01-admin-full.json',
    family: 'identity',
    klass: CLASS.RISKY,
    expectedExit: 1,
    note: 'Action:* Resource:* - de-facto AdministratorAccess; must surface, never clean.',
  },
  {
    id: 'broad-notresource-nonexistent',
    file: '02-broad-notresource-nonexistent.json',
    family: 'identity',
    klass: CLASS.RISKY,
    expectedExit: 1,
    note: 's3:* with a NONEXISTENT NotResource carve-out = de-facto s3-wide; gates on the service-wildcard finding.',
  },
  {
    id: 'resource-star-kms-putkeypolicy',
    file: '03-resource-star-kms-putkeypolicy.json',
    family: 'identity',
    klass: CLASS.RISKY,
    expectedExit: 1,
    note: 'kms:PutKeyPolicy on Resource:* - a dangerous non-read on every key.',
  },
  {
    id: 'narrow-clean',
    file: '04-narrow-clean.json',
    family: 'identity',
    klass: CLASS.CLEAN,
    expectedExit: 0,
    note: 'ec2:DescribeInstances on ONE concrete instance ARN - genuine least privilege.',
  },
  {
    id: 'broad-read-wildcard',
    file: '05-readonly-wildcard.json',
    family: 'identity',
    klass: CLASS.RISKY,
    expectedExit: 1,
    note: 'Read actions on Resource:* - the tool scores an account-wide read HIGH (broad-read blast radius).',
  },
  {
    id: 'notaction-broad',
    file: '06-notaction-broad.json',
    family: 'identity',
    klass: CLASS.RISKY,
    expectedExit: 1,
    note: 'NotAction:[iam:*] Resource:* = everything-except-IAM, near-admin; must surface.',
  },
  {
    id: 'wildcard-arn-write',
    file: '07-wildcard-arn-write.json',
    family: 'identity',
    klass: CLASS.RISKY,
    expectedExit: 1,
    note: 'ec2:* on Resource:[arn:aws:*] - a wildcard-ARN variant, account/partition-wide write.',
  },
  {
    id: 'crossaccount-bucket-read',
    file: '08-crossaccount-bucket-read.json',
    family: 'identity',
    klass: CLASS.RISKY,
    threshold: 'info',
    subjectAccount: '111122223333',
    surfacesFinding: true,
    expectedExit: 1,
    note: 'Whole-bucket read of a foreign-named bucket with a KNOWN subject account. '
      + 'S3 bucket ARNs are account-blind so this is CROSS-ACCOUNT-DATA-READ-UNDETERMINED at INFO - '
      + 'surfaced, NEVER silently cleared. Pinned to threshold info because that is where it gates.',
  },
  {
    id: 'sameaccount-scoped-quiet',
    file: '09-sameaccount-scoped-quiet.json',
    family: 'identity',
    klass: CLASS.QUIET,
    subjectAccount: '111122223333',
    expectedExit: 0,
    note: 'sts:AssumeRole to a NAMED role in the principal OWN account - the routine, intended use; deliberately quiet.',
  },
  {
    id: 'malformed-json',
    file: '10-malformed-json.json',
    family: 'identity',
    klass: CLASS.MALFORMED,
    expectedExit: 3,
    note: 'Truncated JSON - engine ok:false; fails closed, never clean.',
  },
  {
    id: 'empty-statement',
    file: '11-empty-statement.json',
    family: 'identity',
    klass: CLASS.CLEAN,
    expectedExit: 0,
    note: 'Statement:[] - a valid document that grants nothing; exit 0 (nothing to surface).',
  },
  {
    id: 'proto-pollution',
    file: '12-proto-pollution.json',
    family: 'identity',
    klass: CLASS.MALFORMED,
    expectedExit: 3,
    note: '__proto__/constructor keys - validator must REJECT (threat-model T3); fails closed, and must not pollute Object.prototype.',
  },
  {
    id: 'unicode-bom-admin',
    file: '13-unicode-bom-admin.json',
    family: 'identity',
    klass: CLASS.RISKY,
    expectedExit: 1,
    note: 'BOM prefix + non-ASCII/zero-width Sid on a FULL-ADMIN grant - hostile Unicode must NOT suppress the finding.',
  },
  {
    id: 'huge-near-caps',
    file: '14-huge-near-caps.json',
    family: 'identity',
    klass: CLASS.RISKY,
    // The work/wall-clock budget may abort this before completion (exit 3) OR it may
    // complete with findings (exit 1); EITHER is fail-closed. The oracle asserts the
    // invariant that holds across both: exit != 0 and NEVER a clean pass.
    expectedExit: 3,
    exitAny: true,
    note: 'A near-caps admin+broad-read policy - exercises the DoS budget. Must fail closed, '
      + 'never a clean exit-0 having "analyzed" a runaway.',
  },
  {
    id: 'normal-multi-statement',
    file: '15-normal-multi-statement.json',
    family: 'identity',
    klass: CLASS.CLEAN,
    expectedExit: 0,
    note: 'A realistic scoped-read + explicit-deny + describe policy - stays clean (nothing at/above threshold).',
  },
  {
    id: 'notresource-write-severity',
    file: '16-notresource-write-severity.json',
    family: 'identity',
    klass: CLASS.RISKY,
    expectedExit: 1,
    // FIXED (story S3-rules-breadth B, syntax-keyed-severity). A broad NotResource
    // WRITE grant fires WILDCARD-RESOURCE; severity now keys on EFFECTIVE breadth, so a
    // NotResource-only broad non-read is HIGH (reaches every resource except a listed
    // few, as account-wide as "*") and gates at the default 'high' threshold -> exit 1.
    // Formerly scored 'medium' (severity keyed on the empty stmt.resources) and read
    // CLEAN: "write to every bucket except one" slipped the gate. The release gate
    // re-verifies it stays fixed.
    note: 's3:PutObject with a NotResource carve-out = write to every bucket except one; gates at high.',
  },
  {
    id: 'vacuous-notresource-deny-exfil',
    file: '17-vacuous-notresource-deny-exfil.json',
    family: 'identity',
    klass: CLASS.RISKY,
    expectedExit: 1,
    surfacesFinding: true,
    // FIXED (story S3-rules-breadth A, vacuous-Deny-suppression). A broad Allow
    // (s3:GetObject Resource:*) with a Deny whose NotResource is arn:aws:s3:::*/*
    // denies every resource EXCEPT all S3 objects = denies NOTHING. The Deny's SPARED
    // set is BROAD (classifyResource===BROAD), so it removes no part of the broad
    // Allow's reach and must NOT be credited as a narrowing fence: DATA-EXFIL fires
    // and coverage stays honest. Formerly the vacuous Deny suppressed DATA-EXFIL and
    // left coverage complete -> exit 0 CLEAN on the archetypal exfil primitive. The
    // release gate re-verifies it stays fixed.
    note: 's3:GetObject Resource:* with a vacuous NotResource:arn:aws:s3:::*/* Deny = denies nothing; '
      + 'DATA-EXFIL must surface, never suppressed.',
  },
  {
    id: 'undecidable-notresource-deny-exfil',
    file: '18-undecidable-notresource-deny-exfil.json',
    family: 'identity',
    klass: CLASS.RISKY,
    expectedExit: 1,
    surfacesFinding: true,
    // FIXED (story S3-rules-breadth A, vacuous-Deny-suppression, MALFORMED spared-set
    // variant). A broad Allow (s3:GetObject Resource:*) with a Deny whose NotResource is
    // a bare non-ARN token ('not-an-arn'). classifyResource() reports that value
    // MALFORMED (undecidable breadth - narrowness would rest on the UNVERIFIED grammar
    // the HYBRID default refuses to trust), NOT NARROW. Crediting a Deny as a narrowing
    // fence SUPPRESSES a finding, so the spared set must be PROVEN narrow; an
    // undecidable spared element is not. The old denyFencesToNarrow rejected only a
    // BROAD spared element, so a MALFORMED spared set slipped through, was credited as a
    // fence, dropped DATA-EXFIL and left coverage complete -> exit 0 CLEAN on the
    // archetypal exfil primitive. Fix: fence only when EVERY spared element is a NARROW
    // verdict (fail closed on BROAD and MALFORMED alike). The release gate re-verifies
    // it stays fixed.
    note: 's3:GetObject Resource:* with an UNDECIDABLE NotResource:not-an-arn Deny (spared set not '
      + 'provably narrow); DATA-EXFIL must surface, never suppressed.',
  },
  {
    id: 'passrole-defaulted-partition-unknown',
    file: '19-passrole-defaulted-partition-unknown.json',
    family: 'identity',
    klass: CLASS.RISKY,
    subjectAccount: '111122223333',
    surfacesFinding: true,
    // The subject account is KNOWN but NO partition is supplied (the browser forwards
    // subjectAccount but never a partition). A same-account aws-us-gov role therefore
    // cannot be confidently classified same- vs cross-partition, so the PassRole path is
    // UNKNOWN-viability: scan() fails closed (analysisStatus partial, exit 3); analyze()
    // (the browser) surfaces it as a CRITICAL PASSROLE-EC2 finding with
    // requiredUnknowns:['subjectPartition'], NEVER a confident PARTITION_MISMATCH medium.
    // exitAny: the fail-closed exit is 3 (partial), not a completed exit-1 finding set -
    // like the DoS-budget case, the invariant that holds is exit != 0 AND never clean.
    expectedExit: 3,
    exitAny: true,
    // FIXED (story S5-partition-parity, bug: defaulted-subject-partition-confident-demote).
    // The engine treated an ABSENT (defaulted-to-'aws') subject partition as a confidently
    // known partition, so analyze() CONFIDENTLY demoted this same-account cross-partition
    // PassRole to medium (PARTITION_MISMATCH) and, at the default high threshold, read
    // CLEAN - while scan()'s partitionProvided guard correctly failed closed at exit 3.
    // analyze() (browser) was therefore MORE permissive than scan() (CLI) for byte-identical
    // no-partition input (threat-model T8, browser==CLI parity). Fix (in the shared engine,
    // the single source of truth): an absent partition is DEFAULTED, not confidently
    // supplied, and fails closed as unknown-viability exactly like a non-canonical token.
    // The P4 parity property + the release gate re-verify it stays fixed.
    note: 'iam:PassRole to an aws-us-gov same-account role + ec2:RunInstances, subject account '
      + 'KNOWN but partition NOT supplied. UNKNOWN-viability: scan fails closed (exit 3); '
      + 'analyze surfaces CRITICAL PASSROLE-EC2 + requiredUnknowns:[subjectPartition], never a '
      + 'confident cross-partition demotion. Browser must never be more permissive than the CLI.',
  },
  {
    id: 'public-trust-malformed-principalarn-scope',
    file: '20-public-trust-malformed-principalarn-scope.json',
    family: 'role-trust',
    klass: CLASS.RISKY,
    expectedExit: 1,
    surfacesFinding: true,
    // FIXED (story S7-lows-and-orphan item 4, bug: truncated-principalarn-narrows-fail-open).
    // A public Principal "*" AssumeRole trust "scoped" by a MALFORMED aws:PrincipalArn value
    // ("arn:aws:iam" - 3 ARN fields, pins NO account and NO resource). arnValueNarrows()
    // credits a glob-free value as narrowing, and principalArnValueIsBroad() USED to read the
    // account/resource segments with truncating `segs.length > N ? ... : ''` guards, so the
    // undecidable value returned "not broad" (tight): TRUST-PUBLIC was DOWNGRADED
    // critical->medium, mislabeled "a specific principal", and at the default 'high' threshold
    // read CLEAN (exit 0) on a wide-open trust (T8 overstated certainty / fail-open). Fix: an
    // undecidable/truncated principal ARN fails CLOSED (mark broad), so TRUST-PUBLIC stays HIGH
    // and gates -> exit 1. The release gate re-verifies it stays fixed.
    note: 'Public "*" AssumeRole trust scoped by a MALFORMED aws:PrincipalArn ("arn:aws:iam"); '
      + 'the undecidable value must NOT silently narrow a public trust to a clean medium - '
      + 'TRUST-PUBLIC must surface at high, never read clean.',
  },
  {
    id: 'notresource-deny-fences-surviving-whole-bucket',
    file: '21-notresource-deny-fences-surviving-whole-bucket.json',
    family: 'identity',
    klass: CLASS.RISKY,
    threshold: 'info',
    surfacesFinding: true,
    expectedExit: 1,
    // FIXED (story S1-R1-deny-fence-surviving, bug: deny-fence-surviving-spared-resource).
    // A broad exfil Allow (s3:GetObject Resource:*) fenced by a same-policy Deny whose
    // NotResource spares ONE whole bucket (arn:aws:s3:::acme-competitor-bucket/*). The fence
    // correctly removes the broad exfil reach (denyFencesToNarrow proves the spared set
    // NARROW; DATA-EXFIL is suppressed; the coverage net stays quiet) - but NOTHING then
    // inspected the PROVEN SURVIVING spared resource, so a live whole-bucket read (the
    // archetypal exfil primitive) read exit0/complete/findings:[] - a fail-OPEN (T8). NO
    // --subject-account is supplied, so this also proves the surfacing is subject-account-
    // INDEPENDENT: a canonical S3 bucket ARN is account-blind, so the surviving read is
    // CROSS-ACCOUNT-DATA-READ-UNDETERMINED at INFO whether or not a subject is known. The
    // derived id is NEVER DATA-EXFIL (ruleFindingDenySuppressed's bulk-fence exemption is
    // hardcoded id===DATA-EXFIL and would re-suppress it). Pinned to threshold info because
    // that is where the INFO finding gates. The release gate re-verifies it stays fixed.
    note: 's3:GetObject Resource:* fenced by a Deny NotResource:acme-competitor-bucket/* = a '
      + 'surviving WHOLE-BUCKET read on an account-blind S3 ARN; must surface '
      + 'CROSS-ACCOUNT-DATA-READ-UNDETERMINED at info on a DEFAULT scan, never silently cleared.',
  },
  {
    id: 'notresource-deny-fences-surviving-sensitive-bucket',
    file: '22-notresource-deny-fences-surviving-sensitive-bucket.json',
    family: 'identity',
    klass: CLASS.RISKY,
    threshold: 'info',
    surfacesFinding: true,
    expectedExit: 1,
    // FIXED (story S1-R1-deny-fence-surviving, iteration 2). The iteration-1 fix closed R1
    // only for NEUTRALLY-named spared buckets: classifyContainerReads dropped any account-
    // less S3 spared bucket matching a sensitivity token (or carrying a ${...} variable) on
    // the premise it "already surfaces via the DATA-READ path". That premise holds ONLY for
    // ruleDataReadScoped (NARROW Allow, DATA-READ fall-through runs); the surviving-spared
    // caller's Allow is BROAD, so ruleDataReadScoped early-returns and DATA-READ never fires
    // -> a sensitively-named spared bucket (production-secrets/*, the HIGHEST-value exfil
    // target) read exit0/complete/findings:[] - a fail-OPEN, and a strict inversion of the
    // direct-grant behaviour (a direct grant of production-secrets/* surfaces DATA-READ). Fix:
    // classifyContainerReads collects sensitivity-token/variable account-less S3 buckets into
    // the undetermined set for the fence caller (opts.collectSensitiveVariable). NO
    // --subject-account is supplied (S3 ARNs are account-blind, so surfacing is subject-
    // INDEPENDENT). Pinned to threshold info. The release gate re-verifies it stays fixed.
    note: 's3:GetObject Resource:* fenced by a Deny NotResource:production-secrets/* = a '
      + 'surviving WHOLE-BUCKET read on a SENSITIVELY-NAMED account-blind S3 ARN; the highest-'
      + 'value exfil target must surface CROSS-ACCOUNT-DATA-READ-UNDETERMINED at info on a '
      + 'DEFAULT scan, never silently cleared (R1 iteration-2 fail-open).',
  },
  {
    id: 'notresource-deny-fences-uncovered-bucket-clean',
    file: '23-notresource-deny-fences-uncovered-bucket-clean.json',
    family: 'identity',
    klass: CLASS.CLEAN,
    threshold: 'info',
    expectedExit: 0,
    // OVER-CORRECTION guard (story S1-R1-deny-fence-surviving, iteration 3, bug:
    // surviving-spared-not-intersected-with-allow). The broad Allow is an ARN-WILDCARD
    // (arn:aws:s3:::prod-*/*), NOT the bare "*" the other R1 fixtures use. The Deny spares
    // arn:aws:s3:::acme-competitor-bucket/*, which the Allow NEVER grants: the prod-* objects
    // are DENIED (not in the spared set) and the spared competitor bucket is not granted by
    // the Allow -> AWS net = ZERO readable. This is a VALID, deployable, effectively-SAFE
    // policy. survivingSparedContainerReads used to classify the RAW NotResource union
    // (without intersecting the broad Allow's own scope), fabricating a
    // CROSS-ACCOUNT-DATA-READ-UNDETERMINED finding on a bucket the policy grants no access to
    // (threat-model T8: truthfulness). Fix: intersect the proven-surviving spared set with the
    // Allow's own resource patterns (case-sensitive ARN globMatch), so a spared resource
    // outside the grant is dropped and this input reports CLEAN. Pinned to threshold info (the
    // band the fabricated finding gated at) so the release gate proves the false positive is
    // GONE at that threshold, not merely below the default gate.
    note: 's3:GetObject on ARN-wildcard arn:aws:s3:::prod-*/* fenced by a Deny sparing an '
      + 'UNCOVERED bucket (acme-competitor-bucket/*) = ZERO net readable; must stay CLEAN, never '
      + 'a fabricated surviving-spared finding on a bucket the Allow never grants.',
  },
  {
    id: 'notresource-deny-fences-double-fenced-clean',
    file: '24-notresource-deny-fences-double-fenced-clean.json',
    family: 'identity',
    klass: CLASS.CLEAN,
    threshold: 'info',
    expectedExit: 0,
    // OVER-CORRECTION guard (story S1-R1-deny-fence-surviving, iteration 4, bug:
    // surviving-spared-is-union-not-net-of-whole-deny-set). TWO NotResource fences on the
    // SAME action spare DIFFERENT buckets: FenceA spares bucket-a/*, FenceB spares
    // bucket-b/*. Under AWS explicit-Deny precedence reading bucket-a/obj is DENIED by
    // FenceB (bucket-a is not-bucket-b, so its NotResource matches -> the Deny applies) and
    // reading bucket-b/obj is DENIED by FenceA - so the NET readable set is ZERO. This is a
    // valid, deployable, effectively-SAFE policy. survivingSparedContainerReads used to
    // UNION the two fences' spared sets and report BOTH buckets, a double false positive on
    // a net-unreadable policy (threat-model T8 noise that trains reviewers to ignore the
    // derived id). Fix: the surviving set is the fence's spared set MINUS everything the
    // rest of the Deny set removes - here the INTERSECTION of the two fences' spared sets =
    // empty. Also closes the fence + explicit-Resource-Deny and fence + blanket-Deny
    // variants (covered by the unit regression). Pinned to threshold info (the band the
    // fabricated finding gated at) so the release gate proves the false positive is GONE at
    // that threshold, not merely below the default gate.
    note: 'TWO NotResource fences sparing DIFFERENT buckets (bucket-a/* and bucket-b/*) = each '
      + 'fence denies the other fence\'s spare, so NET readable is ZERO; must stay CLEAN, never a '
      + 'UNION of the spared sets fabricating a surviving-spared finding on a net-unreadable policy.',
  },
  {
    id: 'notresource-deny-fences-subset-action-explicit-allow',
    file: '25-notresource-deny-fences-subset-action-explicit-allow.json',
    family: 'identity',
    klass: CLASS.RISKY,
    threshold: 'info',
    subjectAccount: '123456789012',
    surfacesFinding: true,
    expectedExit: 1,
    // OVER-CORRECTION guard (story S1-R1-deny-fence-surviving, iteration 5, bug:
    // surviving-spared-subset-action-duplicate-report). The spared bucket
    // (acme-competitor-bucket/*) is ALSO an explicit resource of the broad Allow AND the
    // Deny fences only a STRICT ACTION-SUBSET (s3:GetObject) of the Allow's reads
    // ([s3:GetObject, s3:ListBucket]). With a KNOWN subject, ruleDataReadScoped surfaces the
    // Allow's OWN leg on that bucket with the FULL read set, while the surviving-spared
    // post-pass derives the SAME bucket on the FENCED subset - ONE surviving capability, but
    // the analyze.js dedup keyed identity on exact action-set equality so the subset row
    // slipped it: TWO CROSS-ACCOUNT-DATA-READ-UNDETERMINED rows / TWO SARIF alerts (distinct
    // fingerprints) for one bucket, so dismissing one code-scanning alert left the other. Fix:
    // the dedup is SUBSET-aware - a derived finding sharing (id, statementIndex) with a table
    // finding that covers all its resources AND all its actions is dropped as already-covered,
    // keeping exactly ONE (broader) row. The risk still SURFACES (RISKY, exit 1 at info); the
    // no-duplicate invariant is asserted by the golden oracle + release gate. Pinned to
    // threshold info (where the read gates) and subject KNOWN (the condition the duplicate
    // required).
    note: 'Broad+explicit Allow [s3:GetObject, s3:ListBucket] on ["*", acme-competitor-bucket/*] '
      + 'with a Deny fencing only s3:GetObject on that same bucket; must surface the surviving '
      + 'read at info as EXACTLY ONE CROSS-ACCOUNT-DATA-READ-UNDETERMINED row, never two '
      + '(subset-action duplicate-report).',
  },
  {
    id: 'notresource-complement-allow-deny-fences-surviving-whole-bucket',
    file: '26-notresource-complement-allow-deny-fences-surviving-whole-bucket.json',
    family: 'identity',
    klass: CLASS.RISKY,
    threshold: 'info',
    surfacesFinding: true,
    expectedExit: 1,
    // FIXED (story S1-R1-deny-fence-surviving, iteration 6, bug: surviving-spared-blind-to-
    // complement-allow). The broad read is expressed as a NotResource COMPLEMENT Allow
    // ({Allow s3:GetObject NotResource:excluded/*}) instead of Resource:"*": it grants the
    // action on EVERY resource EXCEPT its carve-out. A same-policy NotResource Deny then
    // fences it down to exactly acme-competitor-bucket/* (granted by the Allow - not under
    // excluded/*; spared by the Deny) - a live whole-bucket read. survivingSparedContainerReads
    // bailed on stmt.resources.length===0 and the broad-uncovered NotResource net skipped the
    // fence-narrowed action (survivingBroadReadActions returns [] for it), so the surviving read
    // read exit0/complete/findings:[] at EVERY threshold - while the semantically-identical
    // Resource:"*" form (case 21) surfaced CROSS-ACCOUNT-DATA-READ-UNDETERMINED. Fix: the
    // post-pass handles the complement shape too (grant tested via the Allow's own carve-out;
    // finding rendered via a shim so the surviving bucket is named). NO --subject-account is
    // supplied, so this also proves the complement surfacing is subject-account-INDEPENDENT.
    // Pinned to threshold info (where the INFO finding gates). The release gate re-verifies fixed.
    note: 's3:GetObject via a NotResource-COMPLEMENT Allow fenced by a Deny NotResource:'
      + 'acme-competitor-bucket/* = a surviving WHOLE-BUCKET read on an account-blind S3 ARN; '
      + 'must surface CROSS-ACCOUNT-DATA-READ-UNDETERMINED at info on a DEFAULT scan exactly as '
      + 'the Resource:"*" form does, never silently cleared (R1 iteration-6 complement fail-open).',
  },
  {
    id: 'notresource-complement-allow-excludes-spared-clean',
    file: '27-notresource-complement-allow-excludes-spared-clean.json',
    family: 'identity',
    klass: CLASS.CLEAN,
    threshold: 'info',
    expectedExit: 0,
    // OVER-CORRECTION guard (story S1-R1-deny-fence-surviving, iteration 6). The complement
    // Allow's carve-out IS the spared bucket: the Allow grants everything EXCEPT
    // acme-competitor-bucket/*, and the Deny spares ONLY acme-competitor-bucket/* (denies
    // everything else). The one resource the Deny leaves readable is the one the Allow refuses
    // to grant -> AWS net = ZERO readable, a valid effectively-SAFE policy. The complement-aware
    // grant test (allowGrantsSparedResource) drops a spared bucket the Allow's own NotResource
    // entirely excludes, so this stays a genuine CLEAN pass with ZERO fabricated findings - the
    // complement fail-open fix did not become a fail-into-noise regression. Pinned to threshold
    // info (the band the surviving-spared finding gates at) so the release gate proves it is
    // clean at that threshold, not merely below the default gate.
    note: 'A NotResource-COMPLEMENT Allow whose carve-out IS the spared bucket '
      + '(acme-competitor-bucket/*, excluded by the Allow AND the only bucket the Deny spares) '
      + '= ZERO net readable; must stay CLEAN, never a fabricated surviving-spared finding on a '
      + 'bucket the complement Allow excludes.',
  },
]);

// The four selectable severities the CLI threshold gate ranks (most severe first),
// plus the 'info' floor. Local copy so the manifest does not import engine internals.
export const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);

// scan() input for a case (the CLI in-process core). Threshold defaults to the CLI
// default ('high') unless the case pins one.
export function scanInputFor(c) {
  const inp = { text: corpusText(c.file), family: c.family };
  if (c.threshold) inp.threshold = c.threshold;
  if (c.subjectAccount) inp.subjectAccount = c.subjectAccount;
  return inp;
}

// analyze() options for a case (the BROWSER path), mirroring what scan() forwards.
export function analyzeOptionsFor(c) {
  const opts = { family: c.family, requireExplicitFamily: true };
  if (c.subjectAccount) opts.subjectAccount = c.subjectAccount;
  return opts;
}
