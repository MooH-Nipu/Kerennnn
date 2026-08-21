# ── Stage 1: build frontend ────────────────────────────────────────────────────
FROM node:24-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# ── Stage 2: production runtime ────────────────────────────────────────────────
FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev

COPY --chown=node:node server.js ./
COPY --chown=node:node api/ ./api/
COPY --chown=node:node --from=builder /app/dist ./dist
RUN mkdir -p /app/data && chown node:node /app/data

USER node
EXPOSE 3000
CMD ["node", "server.js"]
