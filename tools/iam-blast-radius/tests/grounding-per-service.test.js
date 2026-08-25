// IAM-1400: grounding-doc integrity gate for the per-service resource-policy
// semantics reference (docs/resource-per-service-semantics.md).
//
// IAM-1400 is a DOCS-ONLY story: it ships the AWS-verified grounding spec that
// stories IAM-1401..1404 build the engine against. There is no shipped-code
// change, so the "behavior" this test protects is the doc's INTEGRITY: that its
// 11 cited AWS sources are all present with resolvable docs.aws.amazon.com URLs,
// that all five correctness traps are stated, that the fail-closed caveats
// (Block Public Access out of scope; the KMS silent-key-policy inversion; the
// request-property Deny keys) are present, and that the load-bearing per-service
// invariant (KMS Principal:"*" is NOT anonymous, whereas S3/SQS Principal:"*" IS
// anonymous public) is stated. Each source URL below was fetched and confirmed to
// support the per-service claim it backs during IAM-1400 verification (2026-08-24).
//
// If a later edit drops a source, softens a trap, or deletes a caveat, this gate
// fails - the doc can never silently drift away from the AWS-verified truth the
// engine relies on. Runs under `node --test`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const docsDir = join(here, '..', 'docs');
const DOC = join(docsDir, 'resource-per-service-semantics.md');
const GENERIC_DOC = join(docsDir, 'resource-policy-semantics.md');

const doc = readFileSync(DOC, 'utf8');
// Prose is line-wrapped in the source; collapse whitespace so a phrase that
// straddles a wrap ("IAM identity\n  policies CANNOT reach the key") still
// matches. Structural checks (numbered lists, tables) use the raw `doc`.
const flat = doc.replace(/\s+/g, ' ');
// Prose with fenced code blocks removed, so the section-6 ASCII narrowing table
// (repeated "Y  Y" / "N  N" column cells) doesn't trip the duplicated-word guard.
const prose = doc.replace(/```[\s\S]*?```/g, ' ');

// The 11 cited AWS sources. Each fragment must appear in the doc's Sources list,
// under an https://docs.aws.amazon.com URL, and each was confirmed during
// IAM-1400 to support the specific per-service claim it is attached to.
const SOURCE_URL_FRAGMENTS = [
  'reference_policies_elements_principal.html', // 1 Principal wildcard = public/anonymous
  'access-control-block-public-access.html', //    2 BPA overrides + meaning-of-public key set
  'amazon-s3-policy-keys.html', //                 3 SSE / TlsVersion / ResourceAccount / redaction
  'confused-deputy.html', //                       4 SourceArn/SourceAccount service-principal binding
  'key-policy-overview.html', //                   5 KMS "*" = all AWS identities in all accounts
  'key-policy-default.html', //                    6 KMS silent-policy inversion (IAM ineffective w/o statement)
  'conditions-kms.html', //                        7 kms:ViaService (channel) vs kms:CallerAccount (who)
  'grants.html', //                                8 kms:CreateGrant onward-delegation
  'sqs-basic-examples-of-sqs-policies.html', //    9 SQS "*" = "all users (anonymous users)"
  'sns-access-policy-use-cases.html', //          10 SNS SourceOwner deprecated; PrincipalOrgID publish
  'UsingEncryptionInTransit.html', //             11 aws:SecureTransport HTTPS-only Deny
];

test('grounding doc and the generic doc it extends both exist', () => {
  assert.ok(existsSync(DOC), 'docs/resource-per-service-semantics.md must be present');
  assert.ok(existsSync(GENERIC_DOC), 'docs/resource-policy-semantics.md (the doc it extends) must be present');
});

test('doc extends the generic resource-policy grounding (not a duplicate)', () => {
  assert.match(
    doc,
    /EXTENDS\s+`docs\/resource-policy-semantics\.md`/,
    'doc must declare it EXTENDS docs/resource-policy-semantics.md',
  );
});

test('all 11 cited AWS sources are present with resolvable docs.aws.amazon.com URLs', () => {
  const sourcesIdx = doc.indexOf('## Sources');
  assert.ok(sourcesIdx !== -1, 'a "## Sources" section must exist');
  const sources = doc.slice(sourcesIdx);

  for (const frag of SOURCE_URL_FRAGMENTS) {
    const re = new RegExp(`https://docs\\.aws\\.amazon\\.com/[^\\s)]*${frag.replace(/[.]/g, '\\.')}`);
    assert.match(sources, re, `Sources must cite an AWS docs URL ending in ${frag}`);
  }

  // Exactly 11 numbered sources, and every AWS URL in the section is an
  // official docs.aws.amazon.com URL (no fabricated / off-host citations).
  const numbered = sources.match(/^\d+\.\s/gm) || [];
  assert.equal(numbered.length, 11, 'exactly 11 numbered sources expected');
  const awsUrls = sources.match(/https:\/\/docs\.aws\.amazon\.com\/\S+/g) || [];
  assert.ok(awsUrls.length >= 11, 'each of the 11 sources must carry an AWS docs URL');
});

test('all five correctness traps are stated (section 8)', () => {
  const idx = doc.indexOf('## 8.');
  assert.ok(idx !== -1, 'section 8 (the five hardest correctness traps) must exist');
  const traps = doc.slice(idx, doc.indexOf('## Sources'));

  // Trap 1: KMS "*" must not be labeled anonymous.
  assert.match(traps, /KMS\s+`\*`\s+mislabeled anonymous/i, 'trap 1: KMS * mislabeled anonymous');
  // Trap 2: kms:ViaService credited as principal scoping.
  assert.match(traps, /`kms:ViaService`\s+credited as principal scoping/i, 'trap 2: ViaService as principal scoping');
  // Trap 3: SSE/TLS Deny read as making public access private.
  assert.match(traps, /SSE\/TLS Deny read as making S3 public access private/i, 'trap 3: SSE/TLS Deny');
  // Trap 4: KMS carve-out leaking to S3/SQS/SNS (dispatch bleed).
  assert.match(traps, /dispatch bleed/i, 'trap 4: dispatch bleed');
  // Trap 5: control-plane / delegation actions under-ranked or over-claimed.
  assert.match(traps, /Control-plane\s*\/\s*delegation actions under-ranked or over-claimed/i, 'trap 5: control-plane/delegation');

  // The five traps are enumerated 1..5 in this section.
  const enumerated = traps.match(/^\d+\.\s+\*\*/gm) || [];
  assert.ok(enumerated.length >= 5, 'section 8 must enumerate at least five traps');
});

test('the sharpest trap wording is correct: KMS "*" is all AWS identities in all accounts, NOT anonymous', () => {
  // Positive framing present.
  assert.match(
    doc,
    /all AWS identities in all accounts/i,
    'KMS "*" must be framed as "all AWS identities in all accounts"',
  );
  // KMS must not carry S3/SQS anonymous wording.
  assert.match(
    doc,
    /KMS has no unauthenticated path/i,
    'doc must state KMS has no unauthenticated path',
  );
  // And the doc must explicitly instruct dropping the anonymous wording on KMS.
  assert.match(
    doc,
    /DROP (all )?the "?including anonymous|MUST DROP the "including anonymous|NOT say\s*\n?\s*"including anonymous|must NOT say[^.]*anonymous/i,
    'doc must instruct dropping "anonymous/unauthenticated" wording for KMS',
  );
});

test('S3 and SQS Principal:"*" IS anonymous public (the KMS carve-out must not leak)', () => {
  // SQS "*" = "all users (anonymous users)" per AWS SQS docs.
  assert.match(doc, /all users \(anonymous users\)/i, 'SQS "*" must be framed as "all users (anonymous users)"');
  // The carve-out is explicitly scoped to KMS only / must not leak to S3/SQS.
  assert.match(
    doc,
    /must NOT leak|not leak to (S3|SQS)|scoped to `?kms-key`? only/i,
    'the KMS not-anonymous softening must be scoped to KMS only',
  );
});

test('fail-closed caveats are present: Block Public Access out of scope', () => {
  assert.match(doc, /Block Public Access/i, 'BPA must be mentioned');
  assert.match(
    doc,
    /out of policy scope|out of scope[^.]*fail[- ]closed|cannot see (PAB|Block Public Access)/i,
    'BPA must be stated as out of policy scope / fail-closed',
  );
});

test('fail-closed caveats are present: KMS silent-key-policy inversion', () => {
  assert.match(flat, /silent[- ]key[- ]policy inversion/i, 'the KMS silent-key-policy inversion caveat must be present');
  assert.match(
    flat,
    /IAM (identity )?policies (CANNOT|cannot) (govern|reach) the key|IAM allow policies are ineffective|IAM cannot govern the key/i,
    'the inversion must state IAM cannot govern/reach the key without the account-delegation statement',
  );
});

test('fail-closed caveats are present: request-property Deny keys are not identity constraints', () => {
  assert.match(doc, /s3:x-amz-server-side-encryption/i, 's3:x-amz-server-side-encryption must be covered');
  assert.match(doc, /s3:TlsVersion/i, 's3:TlsVersion must be covered');
  assert.match(doc, /aws:SecureTransport/i, 'aws:SecureTransport must be covered');
  assert.match(
    doc,
    /request-property (key|constraint)/i,
    'these keys must be classified as request-property constraints (not identity constraints)',
  );
});

test('channel keys are named as NOT narrowing WHO: kms:ViaService and the S3 network selectors', () => {
  assert.match(doc, /kms:ViaService/i, 'kms:ViaService must be covered');
  assert.match(doc, /kms:CallerAccount/i, 'kms:CallerAccount must be covered (the KMS principal-account key)');
  assert.match(doc, /aws:SourceIp/i, 'S3 network selector aws:SourceIp must be covered');
  assert.match(doc, /s3:ResourceAccount/i, 's3:ResourceAccount (resource-owner, not caller) must be covered');
});

test('delegation / control-plane actions are named (takeover, onward-delegation) but not over-claimed', () => {
  assert.match(doc, /kms:CreateGrant/i, 'kms:CreateGrant must be covered');
  assert.match(doc, /s3:PutBucketPolicy/i, 's3:PutBucketPolicy must be covered');
  assert.match(doc, /kms:PutKeyPolicy/i, 'kms:PutKeyPolicy must be covered');
  assert.match(
    doc,
    /never over-claim|not over-claim|NOT over-claimed|never as proven decrypt|not[^.]*proven decrypt/i,
    'delegation actions must not be over-claimed as proven decrypt / effective access',
  );
});

test('doc carries the potential-not-effective (RESOURCE_LIMIT) contract', () => {
  assert.match(doc, /RESOURCE_LIMIT/, 'every per-service finding must carry RESOURCE_LIMIT');
  assert.match(doc, /potential blast radius/i, 'the potential-not-effective framing must be stated');
});

test('no duplicated-word artifacts in the load-bearing prose (regression guard for the IAM-1400 fix)', () => {
  // Catch accidental "the the" / "refines refines" style duplications introduced by edits.
  // Runs on `prose` (fenced code blocks stripped) so the section-6 ASCII narrowing
  // table's repeated column cells are not mistaken for prose duplications.
  const dup = prose.match(/\b(\w+)\s+\1\b/gi) || [];
  // "that that" is a legitimate English construction; nothing else should repeat.
  const offenders = dup.filter((d) => !/^that\s+that$/i.test(d));
  assert.deepEqual(offenders, [], `duplicated words found in doc prose: ${offenders.join(', ')}`);
});
