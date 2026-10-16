#!/bin/sh
set -eu

: "${OPENBAO_ROOT_TOKEN:?OPENBAO_ROOT_TOKEN is required}"
: "${ZEROCREDS_ADMIN_TOKEN:?ZEROCREDS_ADMIN_TOKEN is required}"
: "${ZEROCREDS_WALLET_SERVICE_TOKEN:?ZEROCREDS_WALLET_SERVICE_TOKEN is required}"
: "${ZEROCREDS_WALLET_DESTINATION_NAME:=wallet_sandbox}"
: "${ZEROCREDS_WALLET_WORKER_URL:?ZEROCREDS_WALLET_WORKER_URL is required}"
: "${ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON:?ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON is required}"
: "${ZEROCREDS_BASE_URL:?ZEROCREDS_BASE_URL is required}"

export BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN="$OPENBAO_ROOT_TOKEN"
bao server -dev -dev-listen-address=127.0.0.1:8200 -dev-root-token-id="$OPENBAO_ROOT_TOKEN" >/tmp/openbao.log 2>&1 &
bao_pid=$!
trap 'kill "$bao_pid" 2>/dev/null || true' EXIT INT TERM

ready=0
for _ in $(seq 1 60); do
  if bao status >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if [ "$ready" != 1 ]; then cat /tmp/openbao.log >&2; exit 1; fi
bao secrets enable -path=zc_wallet_sandbox kv-v2 >/dev/null

umask 077
cat > /tmp/wallet-writer.hcl <<'EOF'
path "zc_wallet_sandbox/data/owners/+/connections/*" {
  capabilities = ["create", "update"]
}
path "zc_wallet_sandbox/data/owners/+/probes/*" {
  capabilities = ["create", "update"]
}
EOF
cat > /tmp/wallet-metadata.hcl <<'EOF'
path "zc_wallet_sandbox/metadata/owners/+/probes/*" {
  capabilities = ["read", "delete"]
}
EOF
bao policy write wallet-writer /tmp/wallet-writer.hcl >/dev/null
bao policy write wallet-metadata /tmp/wallet-metadata.hcl >/dev/null
writer_token="$(bao token create -policy=wallet-writer -orphan -ttl=720h -field=token)"
metadata_token="$(bao token create -policy=wallet-metadata -orphan -ttl=720h -field=token)"
cat > "$ZEROCREDS_DESTINATIONS_FILE" <<EOF
{"$ZEROCREDS_WALLET_DESTINATION_NAME":{"type":"vault","address":"http://127.0.0.1:8200","token":"$writer_token","path":"zc_wallet_sandbox/data/owners/bootstrap/connections/placeholder","preflight_path_prefix":"zc_wallet_sandbox/data/owners/bootstrap/probes","preflight_metadata_token":"$metadata_token"}}
EOF
printf '%s' "$ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON" > /var/lib/zerocreds/assertion-issuers.json
printf '{}' > /var/lib/zerocreds/wallet-clients.json

export ZEROCREDS_ALLOW_PRIVATE_DESTINATIONS=1
export ZEROCREDS_WALLET_ASSERTION_ISSUERS_FILE=/var/lib/zerocreds/assertion-issuers.json
export ZEROCREDS_WALLET_CLIENTS_FILE=/var/lib/zerocreds/wallet-clients.json
export ZEROCREDS_WALLET_WORKER_URL ZEROCREDS_WALLET_SERVICE_TOKEN
export ZEROCREDS_BASE_URL ZEROCREDS_ADMIN_TOKEN
unset OPENBAO_ROOT_TOKEN BAO_TOKEN ZEROCREDS_WALLET_ASSERTION_ISSUERS_JSON
exec node src/server.js
