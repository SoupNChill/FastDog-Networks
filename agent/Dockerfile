FROM node:20-bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/SoupNChill/FastDog-Networks" \
      org.opencontainers.image.version="0.1.2" \
      org.opencontainers.image.description="Outbound agent for connecting a verified hostname to a local web service"
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY index.js backoff.js heartbeat.js ./agent/
USER node
ENTRYPOINT ["node", "agent/index.js"]
