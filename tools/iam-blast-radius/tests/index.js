// Test aggregator / directory entry point.
//
// The deterministic gate invokes `node --test tests/`. Node v22.14.0 does NOT
// recursively scan a directory passed as a positional argument to `--test`;
// instead it resolves the path as a single module. For a directory, Node's
// module resolution loads its `index.js`. This file is that entry point: it
// discovers every sibling `*.test.js` and imports it, so each file's top-level
// `test(...)` registrations run inside this one runner process.
//
// `node --test tests/`            -> resolves here, runs every suite
// `node --test "tests/**/*.test.js"` -> still works (glob hits the files directly;
//                                       this aggregator is skipped by the `.test.js` filter)
//
// New test files need no wiring: dropping a `*.test.js` beside this file is
// enough. Import order is sorted for determinism.

import { readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

const testFiles = readdirSync(here)
  .filter((f) => f.endsWith('.test.js'))
  .sort();

for (const file of testFiles) {
  await import(pathToFileURL(join(here, file)).href);
}
