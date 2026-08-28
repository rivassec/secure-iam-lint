#!/bin/bash -eu
# ClusterFuzzLite build script: compile the Jazzer.js parity fuzz target.
#
# The dev harness (tools/iam-blast-radius) owns @jazzer.js/core + is where the
# fuzz target lives; install its deps there so node resolves them.
cd "$SRC/secure-iam-lint/tools/iam-blast-radius"
# npm ci installs EXACTLY the committed package-lock.json (integrity-hash pinned),
# and fails closed on any drift - the pinned form (no unpinned `npm install`).
npm ci --no-audit --no-fund

# Compile from the REPO ROOT so the whole tree (content/, cli/, tools/) lands in
# $OUT and the target's relative imports resolve at runtime. The shipped ESM
# modules under content/ and cli/ are EXCLUDED from Jazzer.js instrumentation:
# its Babel transform cannot parse the pure-ESM sources (they run fine under
# Node's own loader). The target still drives them via dynamic import() and checks
# the analyze()==scan() safety-parity invariant on every mutated input.
cd "$SRC"
compile_javascript_fuzzer \
  secure-iam-lint \
  tools/iam-blast-radius/tests/fuzz/analyze.fuzz.cjs \
  -e content/ -e cli/

# Seed the fuzzer with a couple of real policies so it starts from valid JSON.
if [ -d "$SRC/secure-iam-lint/tools/iam-blast-radius/tests/fuzz/corpus" ]; then
  zip -j "$OUT/analyze.fuzz_seed_corpus.zip" \
    "$SRC/secure-iam-lint/tools/iam-blast-radius/tests/fuzz/corpus/"* || true
fi
