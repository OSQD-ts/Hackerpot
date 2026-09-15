# syntax=docker/dockerfile:1

# --- build stage: compile TypeScript to dist/ -------------------------------
FROM node:22-alpine AS builder
WORKDIR /app

# Install all deps (including dev) for the build.
COPY package.json package-lock.json ./
RUN npm ci

# Build the library + the standalone entrypoint. `npm run build` first bundles the
# dashboard's browser code (scripts/build-client.mjs) and emits the element's type
# declarations (tsconfig.element.json), so both have to be in the builder stage.
COPY tsconfig.json tsconfig.element.json tsup.config.ts ./
COPY scripts/build-client.mjs ./scripts/build-client.mjs
COPY src ./src
RUN npm run build

# --- runtime stage: production deps + compiled output only ------------------
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=4004 \
    HOST=0.0.0.0

# Only production dependencies end up in the final image.
#
# --ignore-scripts: nothing in the runtime dependency tree needs a lifecycle script to
# function (ssh2's is an optional native `cpu-features` accelerator; without it ssh2
# uses its pure-JS path), so running arbitrary install code here buys nothing and hands
# every transitive dependency a shell in the image build. The builder stage above still
# runs scripts, because esbuild's postinstall is what fetches its binary.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

COPY --from=builder /app/dist ./dist

# Ship the default config. Override it with a bind mount (or point
# HACKERPOT_CONFIG elsewhere); environment variables still win over the file.
COPY hackerpot.toml ./hackerpot.toml

# Run as the unprivileged built-in "node" user.
#
# /data is created and owned HERE, not left to Docker. A named volume mounted at a path
# that does not exist in the image is created root-owned, so the container — running as
# uid 1000 — could not write to it: every hit log write failed with EACCES, the audit
# log the compose file advertises never received a single record, and the startup banner
# still reported `store: file(/data/hits.jsonl, …)` as though it were working. Docker
# seeds a fresh named volume from the image path's ownership, so creating it here is
# what makes the mount writable.
RUN mkdir -p /data && chown -R node:node /app /data
USER node

# Default location for the hit log, matching docker-compose.yml's `hitlog:/data` mount.
VOLUME ["/data"]

EXPOSE 4004
# The dashboard, when [dashboard] is enabled or the container runs `dashboard`
# (see docker-compose.yml). The management API is 9500.
EXPOSE 9501

# TCP connect check — deliberately not an HTTP request, so the healthcheck
# never registers as a honeypot hit or trips the scanner-signature detector.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('net').connect(Number(process.env.PORT)||4004,'127.0.0.1').on('connect',function(){this.end();process.exit(0)}).on('error',()=>process.exit(1))"

# The command line: `serve` by default, or any other command (`dashboard`, `check`, …).
CMD ["node", "dist/standalone.js"]
