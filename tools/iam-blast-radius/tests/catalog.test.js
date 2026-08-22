// Unit + integration tests for IAM-507: small versioned curated action catalog
// + unknown-action reporting. Runs on node's built-in runner: `node --test`.
//
// Acceptance (prd.json IAM-507):
//   - unknown actions surface in coverage with the catalog version
//   - no runtime network (grep gate covers shipped JS; nothing to assert here)
//   - the catalog is swappable behind an interface
//   - deterministic; the version is a dated snapshot visible in UI + exports
//
// The coverage panel's DOM rendering of the version + unknown actions is a
// browser assertion (tests/e2e/ui-shell.spec.js); this suite covers the pure
// catalog data + the analyze()/export carriage off-browser.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  defaultCatalog,
  lookupAction,
  unrecognizedActions,
  isWildcardAction,
  ACTION_CATALOG_VERSION,
  ACTION_CATALOG_DATE,
  ACCESS_LEVELS,
} from '../../../content/tools/iam-blast-radius/engine/catalog.js';
import { analyze } from '../../../content/tools/iam-blast-radius/engine/analyze.js';
import { toJSON, toMarkdown } from '../../../content/tools/iam-blast-radius/engine/report.js';
import { modelFromText } from '../../../content/tools/iam-blast-radius/engine/model.js';

// ---------------------------------------------------------------------------
// The provider interface.
// ---------------------------------------------------------------------------

test('catalog exposes a dated snapshot version + date', () => {
  assert.equal(defaultCatalog.version, ACTION_CATALOG_VERSION);
  assert.equal(defaultCatalog.date, ACTION_CATALOG_DATE);
  // A dated snapshot tag (YYYY.MM.DD) and an ISO date, both committed constants.
  assert.match(ACTION_CATALOG_VERSION, /^\d{4}\.\d{2}\.\d{2}$/);
  assert.match(ACTION_CATALOG_DATE, /^\d{4}-\d{2}-\d{2}$/);
});

test('hasService / hasAction resolve case-insensitively', () => {
  assert.equal(defaultCatalog.hasService('iam'), true);
  assert.equal(defaultCatalog.hasService('IAM'), true);
  assert.equal(defaultCatalog.hasService('madeupsvc'), false);
  assert.equal(defaultCatalog.hasAction('iam', 'PassRole'), true);
  assert.equal(defaultCatalog.hasAction('IAM', 'passrole'), true);
  assert.equal(defaultCatalog.hasAction('iam', 'NotARealAction'), false);
});

test('lookup: known concrete action carries service + name + access level', () => {
  const r = lookupAction('iam:PassRole');
  assert.equal(r.known, true);
  assert.equal(r.knownService, true);
  assert.equal(r.wildcard, false);
  assert.equal(r.service, 'iam');
  assert.equal(r.name, 'PassRole');
  assert.equal(r.accessLevel, ACCESS_LEVELS.WRITE);

  // Odd casing still resolves and echoes the canonical name.
  const r2 = lookupAction('S3:getobject');
  assert.equal(r2.known, true);
  assert.equal(r2.name, 'GetObject');
  assert.equal(r2.accessLevel, ACCESS_LEVELS.READ);
});

test('lookup: unknown action on a KNOWN service is knownService but not known', () => {
  const r = lookupAction('iam:TotallyMadeUpAction');
  assert.equal(r.known, false);
  assert.equal(r.knownService, true);
  assert.equal(r.service, 'iam');
  assert.equal(r.name, null);
  assert.equal(r.accessLevel, null);
});

test('lookup: unknown service is neither known nor knownService', () => {
  const r = lookupAction('fakesvc:DoThing');
  assert.equal(r.known, false);
  assert.equal(r.knownService, false);
  assert.equal(r.service, 'fakesvc');
});

test('lookup: wildcards resolve to wildcard:true, never "unknown"', () => {
  for (const w of ['*', 's3:*', 's3:Get*', 'iam:*']) {
    const r = lookupAction(w);
    assert.equal(r.wildcard, true, `${w} is a wildcard`);
    assert.equal(r.known, false, `${w} is not "known" (nothing to exist-check)`);
    assert.equal(isWildcardAction(w), true, `${w} isWildcardAction`);
  }
  assert.equal(isWildcardAction('iam:PassRole'), false);
});

test('lookup: malformed (no service:action) token is unknown, never throws', () => {
  const r = lookupAction('notanaction');
  assert.equal(r.wildcard, false);
  assert.equal(r.known, false);
  assert.equal(r.knownService, false);
  assert.doesNotThrow(() => lookupAction(''));
  assert.doesNotThrow(() => lookupAction(':'));
  assert.doesNotThrow(() => lookupAction('s3:'));
});

// ---------------------------------------------------------------------------
// unrecognizedActions(model): the coverage feed.
// ---------------------------------------------------------------------------

function modelOf(policy) {
  const m = modelFromText(JSON.stringify(policy));
  assert.equal(m.ok, true, 'model built');
  return m.model;
}

test('unrecognizedActions: reports concrete unknowns, skips wildcards, sorts + dedups', () => {
  const model = modelOf({
    Statement: [
      { Effect: 'Allow', Action: ['s3:GetObject', 's3:*', 'fakesvc:DoThing'], Resource: '*' },
      { Effect: 'Allow', Action: ['iam:MadeUp', 'fakesvc:DoThing', 'iam:PassRole'], Resource: '*' },
    ],
  });
  // s3:GetObject + iam:PassRole known; s3:* wildcard skipped; fakesvc:DoThing
  // (deduped) + iam:MadeUp unknown. Sorted.
  assert.deepEqual(unrecognizedActions(model), ['fakesvc:DoThing', 'iam:MadeUp']);
});

test('unrecognizedActions: scans NotAction too', () => {
  const model = modelOf({
    Statement: [{ Effect: 'Deny', NotAction: ['iam:GhostAction'], Resource: '*' }],
  });
  assert.deepEqual(unrecognizedActions(model), ['iam:GhostAction']);
});

test('unrecognizedActions: a fully-recognized policy yields none', () => {
  const model = modelOf({
    Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 'kms:Decrypt', 'sts:AssumeRole'], Resource: '*' }],
  });
  assert.deepEqual(unrecognizedActions(model), []);
});

test('unrecognizedActions: deterministic + tolerant of null model', () => {
  const model = modelOf({ Statement: [{ Effect: 'Allow', Action: 'zzz:One', Resource: '*' }] });
  assert.deepEqual(unrecognizedActions(model), unrecognizedActions(model));
  assert.doesNotThrow(() => unrecognizedActions(null));
  assert.deepEqual(unrecognizedActions(null), []);
});

test('catalog is swappable behind the interface (a replacement provider is honored)', () => {
  // A stub provider that knows exactly one action; drop-in replacement, no
  // dependency on the shipped data shape.
  const stub = {
    version: 'stub-1',
    date: '2000-01-01',
    hasService: (s) => String(s).toLowerCase() === 'only',
    hasAction: (s, a) => String(s).toLowerCase() === 'only' && String(a).toLowerCase() === 'thing',
    lookup: (t) => {
      const s = String(t);
      if (s.includes('*')) return { input: s, wildcard: true, known: false };
      return { input: s, wildcard: false, known: s.toLowerCase() === 'only:thing' };
    },
  };
  const model = modelOf({
    Statement: [{ Effect: 'Allow', Action: ['only:Thing', 'iam:PassRole'], Resource: '*' }],
  });
  // Under the stub, iam:PassRole is unknown and only:Thing is known - the
  // opposite of the shipped catalog. Proves the caller depends only on the
  // interface.
  assert.deepEqual(unrecognizedActions(model, stub), ['iam:PassRole']);
  assert.equal(lookupAction('only:Thing', stub).known, true);
});

// ---------------------------------------------------------------------------
// analyze() integration: unknown actions surface in coverage + exports.
// ---------------------------------------------------------------------------

const UNKNOWN_ACTION_POLICY = JSON.stringify({
  Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 'madeupsvc:Frobnicate'], Resource: '*' }],
});

test('analyze(): an unknown action surfaces in coverage with the catalog version', () => {
  const res = analyze(UNKNOWN_ACTION_POLICY);
  assert.equal(res.ok, true);
  const s = res.coverage.summary;
  assert.deepEqual(s.unrecognizedActions, ['madeupsvc:Frobnicate']);
  // Unknown action marks coverage incomplete (unsupported != safe).
  assert.equal(s.incomplete, true);
  // The dated action-catalog version travels in the summary (visible in UI/exports).
  assert.equal(s.versions.catalogVersion, ACTION_CATALOG_VERSION);
  // The rule catalog version stays independent.
  assert.equal(s.versions.ruleVersion, '1');
});

test('analyze(): a fully-recognized policy reports no unknown actions + stays complete', () => {
  const res = analyze(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/key' }],
  }));
  assert.equal(res.ok, true);
  assert.deepEqual(res.coverage.summary.unrecognizedActions, []);
  assert.equal(res.coverage.summary.incomplete, false);
  assert.equal(res.coverage.summary.versions.catalogVersion, ACTION_CATALOG_VERSION);
});

test('exports carry the unknown action + the dated catalog version', () => {
  const res = analyze(UNKNOWN_ACTION_POLICY);

  const json = JSON.parse(toJSON(res));
  assert.deepEqual(json.coverage.summary.unrecognizedActions, ['madeupsvc:Frobnicate']);
  assert.equal(json.coverage.summary.versions.catalogVersion, ACTION_CATALOG_VERSION);

  const md = toMarkdown(res);
  assert.match(md, /Unrecognized actions: madeupsvc:Frobnicate/);
  assert.match(md, new RegExp(`Action-catalog version: ${ACTION_CATALOG_VERSION.replace(/\./g, '\\.')}`));
});

test('unknown actions never suppress a finding (unsupported != safe)', () => {
  // A broad exfil grant alongside an unknown action: the finding still fires and
  // coverage is incomplete.
  const res = analyze(JSON.stringify({
    Statement: [{ Effect: 'Allow', Action: ['s3:GetObject', 'ghostsvc:Peek'], Resource: '*' }],
  }));
  assert.equal(res.coverage.summary.incomplete, true);
  assert.ok(res.findings.some((f) => f.id === 'DATA-EXFIL'), 'the broad read still fires');
  assert.ok(res.coverage.summary.unrecognizedActions.includes('ghostsvc:Peek'));
});
