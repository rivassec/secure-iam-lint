# ClusterFuzzLite build environment for the JavaScript (Jazzer.js) fuzz target.
# The base image ships Jazzer.js + the compile_javascript_fuzzer helper.
# Pinned by digest (was :latest) for reproducible builds; Dependabot (docker
# ecosystem, /.clusterfuzzlite) bumps the digest so it does not go stale.
FROM gcr.io/oss-fuzz-base/base-builder-javascript@sha256:fff2fe5f532ffcd3fcea7c54cc1db18951b364b64aa37c415348ce8ba17cde34

# The base ships Node 20.20.2 (EOL; CVE-2026-111497 is unfixed there). Install a fixed
# Node from nodejs.org, checked against the SHASUMS256.txt value for that tarball
# (v24.22.1, linux-x64), and put it FIRST on PATH so `npm ci` and the build use it.
# Bump NODE_VERSION and NODE_SHA256 together. Runtime is the runner image's Node.
ARG NODE_VERSION=24.22.1
ARG NODE_SHA256=eb6728e77c576a35162c122c45ccadf224d89ff00abc8dae46cc2897c6002d7c
RUN set -eux; \
    curl -fsSL -o /tmp/node.tgz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.gz"; \
    echo "${NODE_SHA256}  /tmp/node.tgz" | sha256sum -c -; \
    mkdir -p /opt/node; \
    tar -xzf /tmp/node.tgz -C /opt/node --strip-components=1; \
    rm /tmp/node.tgz
ENV PATH=/opt/node/bin:$PATH

# Copy the whole repo: the fuzz target (tools/iam-blast-radius/tests/fuzz) imports
# the shipped engine (content/) and CLI adapter (cli/) by relative path, so both
# must be present in the build tree.
COPY . $SRC/secure-iam-lint
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/secure-iam-lint
