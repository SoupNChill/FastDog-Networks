FROM node:20-bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/SoupNChill/FastDog-Networks" \
      org.opencontainers.image.version="0.1.2" \
      org.opencontainers.image.description="Outbound agent for connecting a verified hostname to a local web service"
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force
COPY index.js backoff.js heartbeat.js config.js state.js protocol.js bootstrap.js edge-pins.json ./agent/
# Credential state volume mount point, owned by node (1000:1000) with a harmless seed file, so Docker's default
# empty-volume population copies this ownership and mode. No root entrypoint or runtime ownership change is needed.
RUN install -d -o node -g node -m 0700 /var/lib/fastdog-agent \
 && install -o node -g node -m 0600 /dev/null /var/lib/fastdog-agent/.fastdog-agent-volume
USER node
ENTRYPOINT ["node", "agent/index.js"]
