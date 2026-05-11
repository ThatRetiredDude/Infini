# ─── InfiniPot single-container image ────────────────────────────────────────
# One container, one process, SQLite on disk. No external DB service required.

FROM node:20-bookworm-slim AS build

ENV NODE_ENV=production
WORKDIR /app

# Build deps for better-sqlite3 + sharp
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

# Runtime libs only (sharp needs libvips, better-sqlite3 ships its own binary)
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

# Persisted data location (SQLite + uploads + AI debug log) lives under /data
RUN mkdir -p /data/uploads /data/logs /data/ai-debug \
    && chown -R infinipot:infinipot /data

ENV DATABASE_FILE=/data/infinipot.sqlite
ENV ACCESS_LOG_CSV_DIR=/data/logs
ENV AI_DEBUG_LOG_DIR=/data/ai-debug

USER infinipot

EXPOSE 3000

ENTRYPOINT ["tini", "--"]
CMD ["node", "server/index.js"]
