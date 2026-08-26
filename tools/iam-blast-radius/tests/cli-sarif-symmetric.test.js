// Regression tests for story S5-sarif-symmetric.
//
// THREAT (two disjoint fail-OPEN classes the S4 Sid work left half-closed):
//
//  1. ANTI-INJECTION ASYMMETRY. The S4 fix neutralized the SECURITY-finding message
//     (code-span-wrapped Sid + Action) but left two DISJOINT sinks emitting attacker
//     text verbatim: the analyzer-state branch printed s.message raw, and the SARIF
//     evidence rows (properties.evidence) passed every field EXCEPT the Sid verbatim -
//     including the engine-authored ACTION_RESOURCE_TYPE_MISMATCH `note`, which
//     interpolates raw Action names + Resource ARNs (engine/rules.js). GitHub renders
//     message.text as MARKDOWN in its Security tab, so a crafted Action such as
//     `s3:GetObject[CLICK](https://evil)` rendered as a LIVE link in a maintainer's
//     alert view. FIX: route EVERY message.text and EVERY evidence field through the
//     same neutralization (sanitizeStateMessage for engine free-prose; the Sid token
//     treatment for token-like fields), so NO message.text - security, analyzer-state,
//     named or not-yet-written - can carry a live link/image/autolink. The CLASS, not
//     the two named instances.
//
//  2. FINGERPRINT COLLISION / SUPPRESSION. findingIdentity omitted an escalation path's
//     target SERVICE + TECHNIQUE. Several PassRole routes share ONE finding TYPE
//     (id=PASSROLE-SERVICE covers ecs/glue/cloudformation/sagemaker/codebuild/
//     datapipeline); when the exec statement grants a wildcard action they also share the
//     anchor position, the normalized action list ("*"), and the resource - so all six
//     routes hashed to ONE partialFingerprint. A maintainer dismissing one code-scanning
//     alert would then SUPPRESS every other route (a fail-OPEN on a real escalation path).
//     FIX: fold service + technique (tool-controlled enums, never attacker free-text) into
//     the identity, so distinct routes stay distinct and can only SPLIT, never MERGE.

import test from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../../../cli/scan.mjs';
import {
  buildSarifLog, formatSarif, findingIdentity, FINGERPRINT_KEY,
} from '../../../cli/sarif.mjs';

const MANIFEST = { ruleVersion: '1' };

const CONTROL_AND_BACKTICK = /[\u0000-\u001F\u007F-\u009F`]/;

// Strip inline-code spans: a SECURITY-finding message wraps every attacker token in a
// backtick code span, which makes the token inert (GitHub does not render markdown
// inside a code span). Removing the spans leaves only tool prose, which must carry NO
// live link syntax. An analyzer-state message has no code spans (its backticks are
// backslash-escaped away), so this is a no-op there and the escaped text is checked
// directly.
function stripInlineCode(s) {
  return s.replace(/`[^`]*`/g, '');
}

// The load-bearing invariant: NO live markdown link / image / autolink can form in a
// rendered message.text. After removing inert code spans, none of the link-forming
// sequences may appear UNescaped: an inline/reference-link `](`, an image `![`, a
// `<url>` autolink, or a bare-URL / www autolink. A backslash-escaped form (`\]\(`,
// `\!\[`, `https\:\/\/`) renders as literal punctuation and is inert, so it must NOT
// match. Applied to EVERY message.text a run emits.
function assertNoLiveMarkdown(msg, label) {
  assert.equal(typeof msg, 'string');
  const bare = stripInlineCode(msg);
  assert.ok(!/\]\(/.test(bare), `${label}: an inline-link "](" sequence survives outside a code span`);
  assert.ok(!/!\[/.test(bare), `${label}: an image "![" sequence survives outside a code span`);
  assert.ok(!/<https?:/i.test(bare), `${label}: a "<url>" autolink survives`);
  assert.ok(!/https?:\/\//i.test(bare), `${label}: a bare-URL autolink scheme survives`);
  assert.ok(!/\bwww\.\w/i.test(bare), `${label}: a www autolink survives`);
  // A rendered line cannot be broken / ANSI-injected either.
  assert.ok(!/[\r\n]/.test(msg), `${label}: a newline survives into message.text`);
}

// A battery of HOSTILE policies, each carrying a markdown-link / image / autolink payload
// in a different attacker-controlled field, routed through the WHOLE scan -> SARIF path.
// Between them they light up BOTH result branches (security findings AND analyzer-state
// fail-closed results), so the invariant is proven on every message.text a run emits.
const HOSTILE_POLICIES = [
  {
    label: 'hostile Sid (security-finding message)',
    family: 'identity',
    text: JSON.stringify({
      Version: '2012-10-17',
      Statement: [{
        Sid: '[click](https://evil.example/s) ![img](x) <https://evil.example/a> www.evil.example',
        Effect: 'Allow', Action: 'iam:*', Resource: '*',
      }],
    }),
  },
  {
    label: 'hostile Action (security-finding message)',
    family: 'identity',
    text: JSON.stringify({
      Version: '2012-10-17',
      Statement: [{
        Sid: 'S', Effect: 'Allow',
        Action: 's3:GetObject[pwn](javascript:alert(document.domain))', Resource: '*',
      }],
    }),
  },
  {
    label: 'ACTION_RESOURCE_TYPE_MISMATCH note (analyzer-state message)',
    family: 'identity',
    // The story's headline example: an object-level S3 action scoped to a bucket-only
    // ARN trips the mismatch NOTE, which interpolates the raw Action verbatim. The note
    // becomes an analyzer-state message.text.
    text: JSON.stringify({
      Version: '2012-10-17',
      Statement: [{
        Sid: 'S', Effect: 'Allow',
        Action: 's3:GetObject[CLICK](https://evil.example/x)',
        Resource: 'arn:aws:s3:::my-bucket',
      }],
    }),
  },
  {
    label: 'duplicate condition-key markdown link (analyzer-state message)',
    family: 'identity',
    text: `{
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
        "Condition": { "StringEquals": {
          "[click-me](https://evil.example/x)": "a",
          "[CLICK-ME](https://evil.example/x)": "b" } } }]
    }`,
  },
];

test('S5: NO live markdown link/image/autolink survives into ANY message.text (the class)', () => {
  for (const p of HOSTILE_POLICIES) {
    const result = scan({ text: p.text, family: p.family });
    const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
    const results = log.runs[0].results;
    assert.ok(results.length >= 1, `${p.label}: at least one SARIF result is emitted`);
    for (const r of results) {
      assertNoLiveMarkdown(r.message.text, `${p.label} [${r.properties.category}/${r.ruleId}]`);
    }
  }
});

test('S5: the mismatch-note policy fails CLOSED (does not silently pass on a hostile Action)', () => {
  // The story's headline payload must never yield a clean pass.
  const result = scan({
    text: HOSTILE_POLICIES[2].text, family: 'identity',
  });
  assert.notEqual(result.exitCode, 0, 'a policy carrying the mismatch does not exit 0');
  assert.ok(result.analysisStatus !== 'complete' || result.exitCode !== 0,
    'analysis is not reported as a clean complete pass');
});

// --- evidence rows: EVERY field is neutralized (symmetric with the Sid) --------------

// Feed a synthetic escalation finding straight into buildSarifLog so the evidence-row
// projection is exercised with a fully hostile evidence row (a real scan would trip the
// input guards first; this proves the adapter's own neutralization).
function syntheticEvidenceRow(evidenceRow) {
  const finding = {
    id: 'PASSROLE-SERVICE', severity: 'critical', title: 't',
    statementIndex: 0, statementSid: 'S',
    actions: ['iam:PassRole'], resources: ['*'], conditions: null,
    escalation: { technique: 'passrole-service-execution', service: 'lambda', targetPermissions: 'unknown' },
    evidence: [evidenceRow],
  };
  const log = buildSarifLog({ findings: [finding], family: 'identity' }, { file: 'p.json' }, MANIFEST);
  const sec = log.runs[0].results.find((r) => r.properties.category === 'security');
  assert.ok(sec && Array.isArray(sec.properties.evidence) && sec.properties.evidence.length === 1);
  return sec.properties.evidence[0];
}

test('S5: a hostile evidence NOTE is markdown-inert (no live link/image/autolink)', () => {
  const row = syntheticEvidenceRow({
    statementIndex: 0, role: 'pass', actions: ['iam:PassRole'], resources: ['*'], condition: null,
    note: 'runs [pwn](https://evil.example/p) as ![i](x) via <https://evil.example/q> and www.evil.example',
  });
  const bare = stripInlineCode(row.note);
  assert.ok(!/\]\(/.test(bare), 'no inline-link "](" in the evidence note');
  assert.ok(!/!\[/.test(bare), 'no image "![" in the evidence note');
  assert.ok(!/https?:\/\//i.test(bare), 'no bare-URL autolink in the evidence note');
  assert.ok(!/<https?:/i.test(bare), 'no "<url>" autolink in the evidence note');
  assert.ok(!/\bwww\.\w/i.test(bare), 'no www autolink in the evidence note');
  // The alphabetic prose still reads.
  assert.ok(/runs/.test(row.note) && /via/.test(row.note), 'the human-readable prose survives');
});

test('S5: hostile evidence Sid / role / actions / resources are stripped of control chars + backticks', () => {
  const row = syntheticEvidenceRow({
    statementIndex: 0,
    statementSid: 'sid[31m`x`\nline2',
    role: 'pass`role`',
    actions: ['iam:PassRole', 's3:Get`bt`\nObject', 'ctl'],
    resources: ['arn:aws:s3:::b`x`', 'r \nnl'],
    condition: null, note: 'ok',
  });
  assert.ok(!CONTROL_AND_BACKTICK.test(row.statementSid), 'evidence Sid: no control chars / backticks');
  assert.ok(!CONTROL_AND_BACKTICK.test(row.role), 'evidence role: no control chars / backticks');
  for (const a of row.actions) assert.ok(!CONTROL_AND_BACKTICK.test(a), `evidence action clean: ${a}`);
  for (const r of row.resources) assert.ok(!CONTROL_AND_BACKTICK.test(r), `evidence resource clean: ${r}`);
});

test('S5: a 10KB evidence token is length-capped (no hostile blow-up in properties)', () => {
  const big = 'A'.repeat(10 * 1024);
  const row = syntheticEvidenceRow({
    statementIndex: 0, role: 'pass', actions: [big], resources: [big], condition: null, note: big,
  });
  assert.ok(row.actions[0].length <= 128 + 3, 'evidence action capped');
  assert.ok(row.resources[0].length <= 128 + 3, 'evidence resource capped');
  assert.ok(row.note.length < 1200, `evidence note bounded (${row.note.length})`);
});

test('S5: a benign evidence row rides through readably (no over-correction)', () => {
  const row = syntheticEvidenceRow({
    statementIndex: 0, role: 'pass', actions: ['iam:PassRole'],
    resources: ['arn:aws:iam::123456789012:role/app'], condition: null,
    note: 'runs code as the passed role via lambda',
  });
  assert.equal(row.role, 'pass');
  assert.deepEqual(row.actions, ['iam:PassRole']);
  assert.deepEqual(row.resources, ['arn:aws:iam::123456789012:role/app']);
  assert.ok(/runs code as the passed role via lambda/.test(row.note), 'benign note prose survives');
});

// --- distinct escalation routes get distinct fingerprints (no suppression) -----------

// An UNPINNED PassRole + a wildcard-action exec statement: every service in the
// SERVICE_EXEC table sees the granted PATTERN "*", so the six PASSROLE-SERVICE routes
// (ecs/glue/cloudformation/sagemaker/codebuild/datapipeline) share the anchor position,
// the normalized action list, AND the resource. Only the service/technique separates
// them - the exact case the collision would suppress.
const WILDCARD_PASSROLE = JSON.stringify({
  Version: '2012-10-17',
  Statement: [
    { Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' },
    { Effect: 'Allow', Action: '*', Resource: '*' },
  ],
});

test('S5: distinct PassRole SERVICE routes get DISTINCT partialFingerprints (no suppression)', () => {
  const result = scan({ text: WILDCARD_PASSROLE, family: 'identity' });
  const log = buildSarifLog(result, { file: 'p.json' }, MANIFEST);
  const rows = log.runs[0].results.filter((r) => r.ruleId === 'PASSROLE-SERVICE');
  assert.ok(rows.length >= 2, `several PASSROLE-SERVICE routes are present (${rows.length})`);
  const fps = rows.map((r) => r.partialFingerprints[FINGERPRINT_KEY]);
  assert.equal(new Set(fps).size, rows.length,
    'every distinct service route has a distinct fingerprint (dismissing one cannot suppress the rest)');
});

test('S5: findingIdentity separates routes that differ ONLY in escalation service or technique', () => {
  const base = {
    id: 'PASSROLE-SERVICE', severity: 'critical', title: 't',
    statementIndex: 0, statementSid: 'S', actions: ['iam:PassRole', '*'], resources: ['*'], conditions: null,
    escalation: { technique: 'passrole-service-execution', service: 'glue', targetPermissions: 'unknown' },
  };
  const diffService = { ...base, escalation: { ...base.escalation, service: 'cloudformation' } };
  const diffTechnique = { ...base, escalation: { ...base.escalation, technique: 'replace-existing-function-code' } };
  assert.notEqual(findingIdentity(diffService, 'identity'), findingIdentity(base, 'identity'),
    'a different target service changes the identity');
  assert.notEqual(findingIdentity(diffTechnique, 'identity'), findingIdentity(base, 'identity'),
    'a different technique changes the identity');
  // No over-correction: identical service + technique + structure -> identical identity.
  const same = { ...base, escalation: { ...base.escalation }, title: 'a totally different label' };
  assert.equal(findingIdentity(same, 'identity'), findingIdentity(base, 'identity'),
    'same semantic route -> same identity (title/message do not matter)');
});

// --- determinism holds under hostile input -------------------------------------------

test('S5: SARIF is byte-identical across builds for every hostile policy + the wildcard route', () => {
  for (const p of [...HOSTILE_POLICIES, { label: 'wildcard passrole', family: 'identity', text: WILDCARD_PASSROLE }]) {
    const result = scan({ text: p.text, family: p.family });
    assert.equal(
      formatSarif(result, { file: 'p.json' }, MANIFEST),
      formatSarif(result, { file: 'p.json' }, MANIFEST),
      `${p.label}: SARIF is deterministic`,
    );
  }
});
