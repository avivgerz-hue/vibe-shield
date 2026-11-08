# syntax=docker/dockerfile:1
#
# vibe-shield :: MCP server image
# -------------------------------
# Glama (and other MCP directories) introspect a server by building this image
# and driving `initialize` + `tools/list` over stdin/stdout. That places three
# hard requirements on the build:
#
#   1. Nothing but JSON-RPC may reach stdout. All diagnostics go to stderr.
#   2. The image must be listening immediately — no compile step at startup.
#      `dist/` is committed, so it is copied in already built.
#   3. `package.json` must be present. `packageVersion()` walks up from the
#      compiled output to find it, and falls back to a hard-coded "1.0.0"
#      without it. Shipping the image without this file makes the directory
#      report the wrong version.
#
# Runtime dependencies are zero, so `npm ci --omit=dev` installs nothing and
# `--ignore-scripts` guarantees the `prepare` lifecycle can never run a build
# inside the image.

FROM node:22-alpine AS runtime

# dumb-init gives PID 1 correct signal forwarding and zombie reaping. An MCP
# client that closes stdin expects the server to exit; without a proper init
# layer a killed container can linger until the client times out.
RUN apk add --no-cache dumb-init

ENV NODE_ENV=production \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false

WORKDIR /app

# Manifests first so the dependency layer is reused when only source changes.
# `npm ci --omit=dev --ignore-scripts` is a no-op today (no runtime deps) but
# keeps the image correct if a dependency is ever added.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
 && npm cache clean --force \
 && rm -rf /root/.npm

# Prebuilt CLI. `dist/` is committed, so no TypeScript toolchain is needed.
COPY dist ./dist

# Documentation surfaced by MCP clients and the agent skill.
COPY SKILL.md README.md SECURITY.md LICENSE ./

# Run unprivileged. node:22-alpine ships a `node` user (uid 1000) for this.
USER node

# Mount point for the project being scanned, e.g.
#   docker run -i --rm -v "$PWD":/workspace vibe-shield mcp
#   docker run   --rm -v "$PWD":/workspace vibe-shield scan /workspace
WORKDIR /workspace

# stdio transport: the client talks JSON-RPC over stdin/stdout, so the image
# must be run with `-i` (stdin attached).
ENTRYPOINT ["dumb-init", "--", "node", "/app/dist/bin/vibe-shield.js", "mcp"]
