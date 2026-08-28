# ClusterFuzzLite build environment for the JavaScript (Jazzer.js) fuzz target.
# The base image ships Jazzer.js + the compile_javascript_fuzzer helper.
FROM gcr.io/oss-fuzz-base/base-builder-javascript

# Copy the whole repo: the fuzz target (tools/iam-blast-radius/tests/fuzz) imports
# the shipped engine (content/) and CLI adapter (cli/) by relative path, so both
# must be present in the build tree.
COPY . $SRC/secure-iam-lint
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/secure-iam-lint
