FROM --platform=linux/amd64 openbao/openbao:2.7.1 AS openbao

FROM --platform=linux/amd64 node:22-bookworm-slim
WORKDIR /app
COPY --from=openbao /usr/bin/bao /usr/local/bin/bao
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY src ./src
COPY cloudflare-sandbox/entrypoint.sh ./entrypoint.sh
RUN chmod 0755 ./entrypoint.sh && mkdir -p /var/lib/zerocreds/connect-pending /var/lib/zerocreds/agent-tokens
ENV HOME=/var/lib/zerocreds PORT=3456 ZEROCREDS_PENDING_DIR=/var/lib/zerocreds/connect-pending ZEROCREDS_TOKENS_DIR=/var/lib/zerocreds/agent-tokens ZEROCREDS_SIGNING_KEY_FILE=/var/lib/zerocreds/signing-key.pem ZEROCREDS_DESTINATIONS_FILE=/var/lib/zerocreds/destinations.json
EXPOSE 3456
ENTRYPOINT ["/app/entrypoint.sh"]
