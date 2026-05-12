# ─── Infini single-container image ────────────────────────────────────────
# Node app + optional Cowrie (SSH/Telnet honeypot, GPL-2.0 — see docs).

FROM node:20-bookworm-slim AS build

ENV NODE_ENV=production
WORKDIR /app

# Build toolchain for native better-sqlite3
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 make g++ ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
RUN npm install --include=dev --legacy-peer-deps --legacy-peer-deps

COPY . .
RUN npm run build && npm prune --omit=dev

# ─── runtime stage ───────────────────────────────────────────────────────────
FROM node:20-bookworm-slim AS runtime

ENV NODE_ENV=production
ENV PORT=3000
WORKDIR /app

ARG COWRIE_VERSION=v2.6.1

# Runtime: tini + git + Python venv for Cowrie honeypot (bundled under /opt/cowrie-install)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates tini git python3 python3-venv \
        build-essential libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 --branch "${COWRIE_VERSION}" https://github.com/cowrie/cowrie.git /opt/cowrie-install \
    && cd /opt/cowrie-install \
    && python3 -m venv venv \
    && ./venv/bin/pip install --no-cache-dir --upgrade pip \
    && ./venv/bin/pip install --no-cache-dir -r requirements.txt

# Non-root runtime user
RUN useradd -m -d /home/infini -s /bin/bash infini \
    && chown -R infini:infini /opt/cowrie-install

COPY --from=build --chown=infini:infini /app/node_modules ./node_modules
COPY --from=build --chown=infini:infini /app/dist ./dist
COPY --from=build --chown=infini:infini /app/server ./server
COPY --from=build --chown=infini:infini /app/package.json ./package.json
COPY --from=build --chown=infini:infini /app/index.html ./index.html

COPY --chmod=755 --chown=infini:infini docker-entrypoint.sh ./docker-entrypoint.sh
COPY --chmod=755 --chown=infini:infini docker-start.sh ./docker-start.sh

# Persisted data: SQLite, uploads, access CSV mirror, Cowrie state
RUN mkdir -p /data/uploads /data/logs /data/cowrie \
    && chown -R infini:infini /data

ENV DATABASE_FILE=/data/infini.sqlite
ENV ACCESS_LOG_CSV_DIR=/data/logs
ENV COWRIE_HOME=/data/cowrie
ENV COWRIE_INSTALL_DIR=/opt/cowrie-install

USER infini

EXPOSE 3000 2222 2223

ENTRYPOINT ["tini", "--", "./docker-entrypoint.sh"]
CMD ["./docker-start.sh", "node", "server/index.js"]
