# ClusterFuzzLite build environment for the JavaScript (Jazzer.js) fuzz target.
# The base image ships Jazzer.js + the compile_javascript_fuzzer helper.
# Pinned by digest (was :latest) for reproducible builds; Dependabot (docker
# ecosystem, /.clusterfuzzlite) bumps the digest so it does not go stale.
FROM gcr.io/oss-fuzz-base/base-builder-javascript@sha256:e1b544f0fd3de5c9efe25221f9f47ceb5508ea415df3e50a90d96f42d1b5e51f

# Copy the whole repo: the fuzz target (tools/iam-blast-radius/tests/fuzz) imports
# the shipped engine (content/) and CLI adapter (cli/) by relative path, so both
# must be present in the build tree.
COPY . $SRC/secure-iam-lint
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/secure-iam-lint
