# ─── InfiniPot single-container image ────────────────────────────────────────
# One container, one process, SQLite on disk. No external DB service required.

FROM node:20-bookworm-slim AS build

ENV NODE_ENV=production
WORKDIR /app

# Build toolchain for native better-sqlite3
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 make g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
RUN npm install --include=dev

COPY . .
RUN npm run build && npm prune --omit=dev

# ─── runtime stage ───────────────────────────────────────────────────────────
FROM node:20-bookworm-slim AS runtime

ENV NODE_ENV=production
ENV PORT=3000
WORKDIR /app

# Runtime base (better-sqlite3 ships its own binary)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user
RUN useradd -m -d /home/infinipot -s /bin/bash infinipot

COPY --from=build --chown=infinipot:infinipot /app/node_modules ./node_modules
COPY --from=build --chown=infinipot:infinipot /app/dist ./dist
COPY --from=build --chown=infinipot:infinipot /app/server ./server
COPY --from=build --chown=infinipot:infinipot /app/package.json ./package.json
COPY --from=build --chown=infinipot:infinipot /app/index.html ./index.html

COPY --chmod=755 --chown=infinipot:infinipot docker-entrypoint.sh ./docker-entrypoint.sh

# Persisted data location (SQLite, uploads, and access CSV mirror) lives under /data
RUN mkdir -p /data/uploads /data/logs \
    && chown -R infinipot:infinipot /data

ENV DATABASE_FILE=/data/infinipot.sqlite
ENV ACCESS_LOG_CSV_DIR=/data/logs

USER infinipot

EXPOSE 3000

ENTRYPOINT ["tini", "--", "./docker-entrypoint.sh"]
CMD ["node", "server/index.js"]
