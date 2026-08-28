// Item 6 (app-sec panel): the grep-based no-eval/no-network CI gates are advisory - a
// determined author can obfuscate past a text scan (global['ev'+'al'], computed member,
// string concat). This test adds a RUNTIME tripwire that does not care how the call is
// spelled: it runs real analyses under `node --disallow-code-generation-from-strings`
// (eval / new Function / vm string-compile THROW at runtime) plus `--disable-proto=throw`
// (a __proto__ assignment THROWS), across every policy family so the main engine paths
// are exercised. If any exercised path relied on dynamic code generation or prototype
// mutation, the child process would abort and this test fails. It does NOT prove the
// absence statically - it covers the exercised paths - so it is paired with the extended
// static grep gates (package.json gate:no-unsafe*) as belt-and-suspenders.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', '..', '..', 'cli', 'iam-br.mjs');
const HARDEN = ['--disallow-code-generation-from-strings', '--disable-proto=throw'];

// Representative policy per family - each exercises that analyzer's main path.
const CASES = {
  identity: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: ['iam:*', 's3:*'], Resource: '*' }] },
  trust: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 'sts:AssumeRole' }] },
  scp: { Version: '2012-10-17', Statement: [{ Effect: 'Deny', Action: 'iam:*', Resource: '*', Condition: { StringNotEquals: { 'aws:PrincipalOrgID': 'o-x' } } }] },
  rcp: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:*', Resource: '*' }] },
};

for (const [family, policy] of Object.entries(CASES)) {
  test(`analysis of a ${family} policy runs clean under --disallow-code-generation-from-strings --disable-proto=throw (no dynamic code / proto mutation on the exercised path)`, () => {
    const r = spawnSync('node', [...HARDEN, CLI, '--family', family], {
      input: JSON.stringify(policy), encoding: 'utf8',
    });
    // A dynamic-code / proto violation aborts the process with a distinctive message.
    assert.doesNotMatch(String(r.stderr || ''), /Code generation from strings disallowed|EvalError|proto.*throw|Cannot assign to read only|prototype/i,
      `no dynamic-code / proto-mutation error for ${family}: ${r.stderr}`);
    // It must still produce a well-formed analysis (a valid fail-closed exit code, never a
    // crash/segfault). 0 clean / 1 findings / 2 usage / 3 could-not-analyze / 4 internal.
    assert.ok([0, 1, 2, 3].includes(r.status), `${family}: expected a normal analysis exit code, got ${r.status} (stderr: ${r.stderr})`);
    assert.notEqual(r.status, null, `${family}: process must not be killed by a signal`);
  });
}

test('the hardening flags actually bite (control): eval IS blocked under the same flags', () => {
  const r = spawnSync('node', [...HARDEN, '-e', 'eval("1+1")'], { encoding: 'utf8' });
  assert.notEqual(r.status, 0, 'eval must be refused under --disallow-code-generation-from-strings');
  assert.match(String(r.stderr || ''), /Code generation from strings disallowed|EvalError/,
    'the guard must reject eval - proves the flag is in effect, not a no-op');
});
