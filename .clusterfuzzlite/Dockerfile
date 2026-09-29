# ClusterFuzzLite build environment for the JavaScript (Jazzer.js) fuzz target.
# The base image ships Jazzer.js + the compile_javascript_fuzzer helper.
# Pinned by digest (was :latest) for reproducible builds; Dependabot (docker
# ecosystem, /.clusterfuzzlite) bumps the digest so it does not go stale.
FROM gcr.io/oss-fuzz-base/base-builder-javascript@sha256:98bfcd008b1f07ff3ab640946146878778a4b34c5aac7017d418841007b35d0e

# Copy the whole repo: the fuzz target (tools/iam-blast-radius/tests/fuzz) imports
# the shipped engine (content/) and CLI adapter (cli/) by relative path, so both
# must be present in the build tree.
COPY . $SRC/secure-iam-lint
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/secure-iam-lint
