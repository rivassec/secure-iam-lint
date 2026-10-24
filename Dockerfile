# secure-iam-lint CLI image. No runtime dependencies and no build step: copy the
# shipped files only. Base is pinned by digest (multi-arch index of node:24.22.1-alpine);
# Dependabot (docker ecosystem, /) bumps it. Runs as non-root; needs no network.
#   docker run --rm --network none -v "$PWD:/work:ro" -w /work IMAGE --family identity policy.json
FROM node:24.22.1-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53

WORKDIR /app
COPY package.json LICENSE ./
COPY cli/ ./cli/
COPY action/ ./action/
COPY content/tools/iam-blast-radius/engine/ ./content/tools/iam-blast-radius/engine/

# Root-owned, read-only to the runtime user. `node` (uid 1000) ships in the base image.
USER node
ENTRYPOINT ["node", "/app/cli/iam-br.mjs"]
