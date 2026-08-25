// Tests for the Action documentation (Phase 16, story P16-docs).
//
// ACTION.md is the consumer-facing contract for the GitHub Action. These tests
// pin it to the ACTUAL contract so the docs cannot silently drift from behavior:
//   - every input/output declared in action.yml is documented,
//   - the full 0/1/2/3/4 exit-code contract is documented (esp. that 3 is
//     fail-closed could-not-analyze and fails the check),
//   - the input limits documented match the engine's enforced LIMITS,
//   - the load-bearing consumer guidance is present (default contents: read,
//     opt-in security-events: write, SHA pinning, pull_request_target warning,
//     "potential blast radius, not effective permissions"),
//   - all seven supported families are listed,
//   - the doc is ASCII-only and README links to it,
//   - no Marketplace publishing steps leaked in (Oliver's manual step).
//
// A doc that stops matching the shipped action.yml / engine limits FAILS here.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// LIMITS is imported from the browser-safe engine directly, so the documented
// caps are tied to the real source of truth, not a hand-copied number.
import { LIMITS } from '../../../content/tools/iam-blast-radius/engine/validate.js';

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const ACTION_MD = readFileSync(REPO_ROOT + 'ACTION.md', 'utf8');
const README_MD = readFileSync(REPO_ROOT + 'README.md', 'utf8');
const ACTION_YML = readFileSync(REPO_ROOT + 'action.yml', 'utf8');

// Extract the top-level key names under a `section:` block in action.yml. Keys are
// indented exactly two spaces; the block ends at the next column-0 line.
function topLevelKeys(yml, section) {
  const lines = yml.split('\n');
  const start = lines.findIndex((l) => l === section + ':');
  assert.notEqual(start, -1, `action.yml is missing a '${section}:' section`);
  const keys = [];
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '' || line.startsWith('#')) continue;
    if (!line.startsWith(' ')) break; // dedent to column 0 ends the block
    const m = /^ {2}([a-z0-9-]+):/.exec(line);
    if (m) keys.push(m[1]);
  }
  return keys;
}

test('every action.yml input is documented in ACTION.md', () => {
  const inputs = topLevelKeys(ACTION_YML, 'inputs');
  assert.ok(inputs.length >= 6, `expected >=6 inputs, parsed ${inputs.length}`);
  for (const name of inputs) {
    assert.ok(
      ACTION_MD.includes('`' + name + '`'),
      `ACTION.md does not document input \`${name}\``,
    );
  }
});

test('every action.yml output is documented in ACTION.md', () => {
  const outputs = topLevelKeys(ACTION_YML, 'outputs');
  assert.ok(outputs.length >= 5, `expected >=5 outputs, parsed ${outputs.length}`);
  for (const name of outputs) {
    assert.ok(
      ACTION_MD.includes('`' + name + '`'),
      `ACTION.md does not document output \`${name}\``,
    );
  }
});

test('the full 0/1/2/3/4 exit-code contract is documented', () => {
  for (const code of ['0', '1', '2', '3', '4']) {
    assert.ok(
      ACTION_MD.includes('`' + code + '`'),
      `ACTION.md does not document exit code ${code}`,
    );
  }
  // The load-bearing invariant: exit 3 is fail-closed could-not-analyze and must
  // be described as failing the check, distinct from a clean 0.
  assert.match(ACTION_MD, /fail[- ]closed/i);
  assert.match(ACTION_MD, /could[- ]not[- ]analyze/i);
  assert.match(ACTION_MD, /worst[- ]exit[- ]code/i);
});

test('exit-code table assigns a bad/unsupported family to exit 3, not exit 2', () => {
  // Only a MISSING/empty --family is a usage error (exit 2); a present-but-invalid
  // family token fails closed (exit 3, reason FAMILY_BLOCKED). The exit-2 row must
  // not claim a "bad" family, and must stay consistent with the families section
  // which says an out-of-set token "fails closed with exit `3`".
  const lines = ACTION_MD.split('\n');
  const exit2Row = lines.find((l) => /^\|\s*`2`\s*\|/.test(l));
  assert.ok(exit2Row, 'ACTION.md has no exit `2` table row');
  assert.doesNotMatch(
    exit2Row,
    /bad[^|]*\bfamily\b/i,
    'exit `2` row must not describe a bad/unsupported family as a usage error',
  );
  assert.match(
    exit2Row,
    /missing\/empty `family`/,
    'exit `2` row must reference only a missing/empty family',
  );
  const exit3Row = lines.find((l) => /^\|\s*`3`\s*\|/.test(l));
  assert.ok(exit3Row, 'ACTION.md has no exit `3` table row');
  assert.match(
    exit3Row,
    /family/i,
    'exit `3` row must state that a bad/unsupported family token fails closed',
  );
  // Self-consistency with the families section (a token outside the set fails
  // closed with exit 3, never guessed).
  assert.match(ACTION_MD, /fails closed with exit `3`/);
});

test('documented input limits match the engine LIMITS', () => {
  for (const value of [
    LIMITS.MAX_BYTES,
    LIMITS.MAX_DEPTH,
    LIMITS.MAX_STATEMENTS,
    LIMITS.MAX_ACTIONS,
    LIMITS.MAX_RESOURCES,
  ]) {
    assert.ok(
      ACTION_MD.includes(String(value)),
      `ACTION.md does not document the enforced limit ${value}`,
    );
  }
});

test('core positioning and permissions guidance are present', () => {
  assert.match(ACTION_MD, /potential blast radius/i);
  assert.match(ACTION_MD, /not\s+effective permissions/i);
  assert.match(ACTION_MD, /contents: read/);
  assert.match(ACTION_MD, /security-events: write/);
});

test('security guidance: SHA pinning and pull_request_target warning', () => {
  assert.match(ACTION_MD, /\bSHA\b/);
  assert.match(ACTION_MD, /pull_request_target/);
  // Both example workflows exist: one uploads SARIF, one does not.
  assert.match(ACTION_MD, /github\/codeql-action\/upload-sarif/);
});

test('all seven supported families are documented', () => {
  for (const family of [
    'identity',
    'role-trust',
    'resource',
    'permissions-boundary',
    'session',
    'scp',
    'rcp',
  ]) {
    assert.ok(
      ACTION_MD.includes('`' + family + '`'),
      `ACTION.md does not document family \`${family}\``,
    );
  }
});

test('ACTION.md is ASCII-only', () => {
  const nonAscii = [...ACTION_MD].find((ch) => ch.charCodeAt(0) > 0x7f);
  assert.equal(
    nonAscii,
    undefined,
    nonAscii ? `ACTION.md contains non-ASCII character U+${nonAscii.charCodeAt(0).toString(16)}` : '',
  );
});

test('no Marketplace publishing steps leaked into ACTION.md', () => {
  // Publishing to the Marketplace is a manual maintainer step, deliberately kept
  // out of the consumer docs.
  assert.doesNotMatch(ACTION_MD, /marketplace/i);
});

test('README links to ACTION.md', () => {
  assert.match(README_MD, /\(ACTION\.md\)/);
});
