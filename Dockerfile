# ── Build stage (compila sodium-native) ──────────────────────
FROM node:20-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 make g++ && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ── Runtime stage (imagem limpa) ─────────────────────────────
FROM node:20-slim

WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
COPY src/ ./src/

EXPOSE 3600

RUN mkdir -p /app/certs && chown node:node /app/certs

USER node

CMD ["node", "src/server/index.js"]
